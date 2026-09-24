//! Owning the IR camera for one attempt: open, illuminate, meter on the face,
//! hand frames to the engine, close. The camera is only streaming while an
//! attempt runs, which is the idle gating the design asks for.

use crate::config::Config;
use anyhow::{anyhow, Context, Result};
use faceauth_camera::calib::{AutoExposure, Exposure, Metering, Window};
use faceauth_camera::{Camera, Frame, Illuminator};
use faceauth_engine::{Face, Grey};
use std::path::Path;
use std::time::Duration;

pub struct IrCapture {
    cam: Camera,
    pub illuminator: Option<Illuminator>,
    frame: Frame,
    pub frames: u64,
    ae: AutoExposure,
    /// The setting in force (a copy of the stepper's, kept as a field
    /// because the attempt reads it on every scored frame).
    pub exposure: Exposure,
    /// What the meter saw at the last exposure step.
    pub metering: Metering,
    window: Option<Window>,
    orientation: [bool; 3],
    ae_enabled: bool,
    /// What this camera is, for binding templates to it. On IPU3 the
    /// sensor's ACPI firmware node ("ipu3:acpi:\_SB_.PCI0.I2C3.CAM3"), which
    /// the firmware fixes; the entity name carries the I2C adapter number,
    /// which the kernel assigns at probe and can shift. On a UVC node the
    /// driver, the bus path and the USB vendor and product ids; the card
    /// string is the device's own claim about itself and is logged only.
    pub identity: String,
}

/// The USB vendor and product ids of the device behind a video node, from
/// sysfs (`/sys/class/video4linux/<node>/device/../idVendor`): the interface
/// is the node's device, the USB device its parent.
fn usb_ids(video: &Path) -> Option<(String, String)> {
    let node = video.file_name()?.to_str()?;
    let dev = std::path::Path::new("/sys/class/video4linux")
        .join(node)
        .join("device")
        .join("..");
    let read = |n: &str| {
        std::fs::read_to_string(dev.join(n))
            .ok()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
    };
    Some((read("idVendor")?, read("idProduct")?))
}

/// The identity templates bind to on an IPU3 sensor: the ACPI path of the
/// sensor's firmware node, read through the subdev's sysfs entry
/// (`<class>/<v4l-subdevN>/device/firmware_node/path`). The firmware names
/// the sensor's place on the board, so it survives a kernel that numbers
/// the I2C adapters differently. Without a firmware node (a board without
/// ACPI camera descriptions) the media entity name is the identity, as
/// before, and the log says so.
fn ipu3_identity(sysfs_class: &Path, subdev: &Path, entity_name: &str) -> String {
    let acpi = subdev
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|node| {
            std::fs::read_to_string(
                sysfs_class
                    .join(node)
                    .join("device")
                    .join("firmware_node")
                    .join("path"),
            )
            .ok()
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && !s.chars().any(|c| c.is_control()));
    match acpi {
        Some(path) => format!("ipu3:acpi:{}", path),
        None => {
            log::warn!(
                "{}: no firmware node in sysfs; templates bind to the entity name {:?}",
                subdev.display(),
                entity_name
            );
            format!("ipu3:{}", entity_name)
        }
    }
}

/// The identity templates bind to on `ir`, read from the live sysfs tree:
/// what `open` records in `IrCapture::identity` for that sensor, for a
/// caller that has probed the graph but is not streaming (the doctor's
/// binding check, the development enrolment).
pub fn ipu3_identity_of(ir: &faceauth_camera::ipu3::Ipu3Sensor) -> String {
    ipu3_identity(Path::new("/sys/class/video4linux"), &ir.subdev, &ir.name)
}

impl IrCapture {
    /// Resolve the IR camera (config override, else the IPU3 graph's front IR
    /// sensor), configure it, and start streaming with the illuminator off.
    pub fn open(cfg: &Config) -> Result<Self> {
        Self::open_at(cfg, None)
    }

    /// As `open`, starting from a remembered exposure instead of the default,
    /// so a short look needs no settling time.
    pub fn open_at(cfg: &Config, seed: Option<Exposure>) -> Result<Self> {
        let (video, subdev, width, height, pixelformat, identity) =
            match (&cfg.ir_video, &cfg.ir_subdev) {
                (Some(v), Some(s)) => {
                    // Explicit UVC-style node: take the node's current format.
                    let vd = faceauth_camera::v4l2::VideoDevice::open(v)?;
                    let fmts = vd.formats()?;
                    let pf = fmts
                        .iter()
                        .map(|(f, _)| *f)
                        .find(|f| faceauth_camera::Decoder::for_pixelformat(*f).is_some())
                        .ok_or_else(|| anyhow!("{}: no decodable format", v.display()))?;
                    let (driver, card, bus) = vd.driver_and_card().unwrap_or_default();
                    // The card string is the device's own claim about itself
                    // (any USB device can present any name), so it is logged
                    // and never part of the identity templates bind to. The
                    // identity is the physical bus path plus the vendor and
                    // product ids from sysfs; a device on the enrolled port that
                    // says it is the enrolled model still cannot prove it, which
                    // the README's "Not defended" list says.
                    let ids = usb_ids(v)
                        .map(|(vid, pid)| format!("{}:{}", vid, pid))
                        .unwrap_or_else(|| "no-usb-ids".into());
                    let identity = format!("uvc:{}:{}:{}", driver, bus, ids);
                    log::info!(
                        "IR camera {}: driver {} card {:?} bus {} ids {} (identity {})",
                        v.display(),
                        driver,
                        card,
                        bus,
                        ids,
                        identity
                    );
                    (v.clone(), s.clone(), 640, 480, pf, identity)
                }
                _ => {
                    let g = faceauth_camera::ipu3::probe()?.ok_or_else(|| {
                        anyhow!("no IPU3 camera graph and no ir_video configured")
                    })?;
                    let ir = g
                        .ir_sensor()
                        .ok_or_else(|| anyhow!("no front IR sensor on the IPU3 graph"))?;
                    let (w, h) = g.configure(ir, None)?;
                    let identity = ipu3_identity_of(ir);
                    (
                        ir.video.clone(),
                        ir.subdev.clone(),
                        w,
                        h,
                        ir.pixelformat,
                        identity,
                    )
                }
            };
        let mut cam = Camera::open(&video, &subdev, width, height, pixelformat, 6)
            .context("open IR camera")?;
        // Nothing here multiplies the frame by a digital gain, so the loop
        // must not climb one: at 4.0 a dark spell would spend seven steps
        // (2.8 s) unwinding a gain the sensor never saw.
        cam.limits.dgain_max = 1.0;
        // The gate runs whenever the sensor can strobe; there is no switch
        // for it (H15).
        let illuminator = Illuminator::open(&subdev)?;
        let start = seed.unwrap_or(Exposure {
            exposure: 500.min(cam.limits.exposure.1),
            gain: cam.limits.gain.map(|g| g.0).unwrap_or(0),
            dgain: 1.0,
        });
        cam.set_exposure(start)?;
        cam.start()?;
        let ae = AutoExposure::new(start, cam.limits);
        Ok(IrCapture {
            cam,
            illuminator,
            frame: Frame::new(0, 0),
            frames: 0,
            ae,
            exposure: start,
            metering: Metering::default(),
            window: None,
            orientation: cfg.ir_orientation,
            ae_enabled: true,
            identity,
        })
    }

    pub fn freeze_exposure(&mut self, frozen: bool) {
        self.ae_enabled = !frozen;
    }

    /// The exposure and gain as the sensor reports them now, not as they
    /// were last written: what a strobe gate compares between pairs (J19).
    /// A sensor without a gain control reports 0 for it.
    pub fn read_back(&self) -> Result<(i32, i32)> {
        let exposure = self.cam.controls.get(self.cam.sensor.exposure.id)?;
        let gain = match &self.cam.sensor.gain {
            Some(g) => self.cam.controls.get(g.id)?,
            None => 0,
        };
        Ok((exposure, gain))
    }

    /// The V4L2 sequence number of the last frame `next` returned. A gap
    /// between two consecutive frames means the driver dropped frames in
    /// between, which a strobe gate pairing lit with unlit frames must
    /// know about.
    pub fn sequence(&self) -> u32 {
        self.frame.sequence
    }

    /// Block for the next frame and return it oriented as 8-bit grey (linear,
    /// 10-bit shifted down: a fixed mapping so consecutive frames are comparable).
    pub fn next(&mut self, timeout: Duration) -> Result<Option<Grey>> {
        if !self.cam.capture(&mut self.frame, timeout)? {
            return Ok(None);
        }
        self.frames += 1;
        if self.ae_enabled {
            let w = self
                .window
                .unwrap_or_else(|| Window::centre(self.frame.width, self.frame.height))
                .clamp(self.frame.width, self.frame.height);
            if let Some(next) = self.ae.observe(&self.frame.px, self.frame.width, w) {
                self.cam.set_exposure(next)?;
                self.ae.exposure = next;
                self.exposure = next;
            }
            self.metering = self.ae.metering;
        }
        // One pass from the 10-bit buffer to the oriented 8-bit frame. The
        // 8-bit copy that was oriented in a second pass cost a second 300 kB
        // allocation and a third more time on every frame the camera
        // delivers (320 against 220 us, engine `bench_frame`).
        let f = &self.frame;
        let [t, fx, fy] = self.orientation;
        Ok(Some(Grey::from_u10_oriented(
            &f.px, f.width, f.height, t, fx, fy,
        )))
    }

    /// Meter on this face from now on (box in oriented coordinates).
    pub fn meter_on(&mut self, face: &Face) {
        self.window = Some(metering_window(
            face.bbox,
            self.frame.width,
            self.frame.height,
            self.orientation,
        ));
    }

    pub fn stop(mut self) -> Result<()> {
        if let Some(i) = &self.illuminator {
            let _ = i.set(false);
        }
        self.cam.stop()
    }
}

/// The raw-frame window under a face box given in oriented coordinates:
/// the orientation (transpose, flip x, flip y) is undone on the box's two
/// corners and the result normalised to a non-empty rectangle inside the
/// raw frame of `raw_w` x `raw_h`.
fn metering_window(bbox: [f32; 4], raw_w: usize, raw_h: usize, orientation: [bool; 3]) -> Window {
    let (rw, rh) = (raw_w as f32, raw_h as f32);
    let [bx, by, bw, bh] = bbox;
    let (ox0, oy0, ox1, oy1) = (
        bx.max(0.0),
        by.max(0.0),
        (bx + bw).max(0.0),
        (by + bh).max(0.0),
    );
    let [t, fx, fy] = orientation;
    // Undo the orientation: oriented (ox, oy) came from raw (x, y).
    let back = |ox: f32, oy: f32| -> (f32, f32) {
        let (ow, oh) = if t { (rh, rw) } else { (rw, rh) };
        let (mut x, mut y) = (ox, oy);
        if fx {
            x = ow - 1.0 - x;
        }
        if fy {
            y = oh - 1.0 - y;
        }
        if t {
            (y, x)
        } else {
            (x, y)
        }
    };
    let (ax, ay) = back(ox0, oy0);
    let (bx2, by2) = back(ox1, oy1);
    let (x0, x1) = (ax.min(bx2).max(0.0) as usize, ax.max(bx2).max(0.0) as usize);
    let (y0, y1) = (ay.min(by2).max(0.0) as usize, ay.max(by2).max(0.0) as usize);
    Window {
        x0,
        y0,
        x1: x1.max(x0 + 1),
        y1: y1.max(y0 + 1),
    }
    .clamp(raw_w, raw_h)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The metering window lands on the raw pixels under the oriented box:
    /// the same pixels come back after orienting the frame both ways.
    #[test]
    fn meter_on_maps_the_oriented_box_back_to_raw_pixels() {
        let (raw_w, raw_h) = (640usize, 480usize);
        for &orientation in &[
            [false, false, false],
            [true, false, false],
            [false, true, true],
            [true, true, true],
        ] {
            let [t, fx, fy] = orientation;
            let mut raw = vec![0u16; raw_w * raw_h];
            // A bright block at a known raw place; everything else dark.
            let (bx0, by0, bx1, by1) = (100usize, 200usize, 180usize, 300usize);
            for y in by0..by1 {
                for x in bx0..bx1 {
                    raw[y * raw_w + x] = 1000;
                }
            }
            // Find the block in the oriented frame the way the detector sees it.
            let g = Grey::from_u10_oriented(&raw, raw_w, raw_h, t, fx, fy);
            let (mut ox0, mut oy0, mut ox1, mut oy1) = (usize::MAX, usize::MAX, 0, 0);
            for y in 0..g.height {
                for x in 0..g.width {
                    if g.data[y * g.width + x] > 200 {
                        ox0 = ox0.min(x);
                        oy0 = oy0.min(y);
                        ox1 = ox1.max(x + 1);
                        oy1 = oy1.max(y + 1);
                    }
                }
            }
            let bbox = [
                ox0 as f32,
                oy0 as f32,
                (ox1 - ox0) as f32,
                (oy1 - oy0) as f32,
            ];
            let w = metering_window(bbox, raw_w, raw_h, orientation);
            // The window covers the block, within a pixel at the flipped edges.
            assert!(w.x0 <= bx0 && w.x1 + 1 >= bx1, "{:?}: {:?}", orientation, w);
            assert!(w.y0 <= by0 && w.y1 + 1 >= by1, "{:?}: {:?}", orientation, w);
            assert!(w.x1 - w.x0 <= (bx1 - bx0) + 2 && w.y1 - w.y0 <= (by1 - by0) + 2);
            let m = faceauth_camera::calib::meter(&raw, raw_w, 0, w);
            assert!(
                m.mean > 0.9,
                "{:?}: the window meters the block: {:?}",
                orientation,
                m
            );
        }
    }

    /// A box partly off the frame still gives a non-empty window inside it.
    #[test]
    fn a_box_off_the_edge_still_meters_inside_the_frame() {
        let w = metering_window([-50.0, -50.0, 30.0, 30.0], 640, 480, [false, false, false]);
        assert!(w.x1 > w.x0 && w.y1 > w.y0);
        assert!(w.x1 <= 640 && w.y1 <= 480);
        let w = metering_window(
            [600.0, 470.0, 200.0, 200.0],
            640,
            480,
            [false, false, false],
        );
        assert!(w.x1 > w.x0 && w.y1 > w.y0 && w.x1 <= 640 && w.y1 <= 480);
    }

    /// The IPU3 identity is the sensor's ACPI path from sysfs, so a shift
    /// in I2C adapter numbering (and so in the entity name) does not
    /// unbind every template; without a firmware node the entity name
    /// stands in.
    #[test]
    fn ipu3_identity_binds_to_the_firmware_node() {
        let root = std::env::temp_dir().join(format!("faceauth-sysfs-{}", std::process::id()));
        let node = root
            .join("v4l-subdev6")
            .join("device")
            .join("firmware_node");
        std::fs::create_dir_all(&node).unwrap();
        std::fs::write(node.join("path"), "\\_SB_.PCI0.I2C3.CAM3\n").unwrap();
        let id = ipu3_identity(&root, Path::new("/dev/v4l-subdev6"), "ov7251 3-0060");
        assert_eq!(id, "ipu3:acpi:\\_SB_.PCI0.I2C3.CAM3");
        // The same sensor with the adapter renumbered gives the same identity.
        let again = ipu3_identity(&root, Path::new("/dev/v4l-subdev6"), "ov7251 5-0060");
        assert_eq!(again, id);
        // No firmware node: the entity name, as before.
        let bare = ipu3_identity(&root, Path::new("/dev/v4l-subdev9"), "ov7251 3-0060");
        assert_eq!(bare, "ipu3:ov7251 3-0060");
        let _ = std::fs::remove_dir_all(&root);
    }
}
