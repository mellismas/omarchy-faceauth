//! Owning the IR camera for one attempt: open, illuminate, meter on the face,
//! hand frames to the engine, close. The camera is only streaming while an
//! attempt runs, which is the idle gating the design asks for.

use crate::config::Config;
use anyhow::{anyhow, Context, Result};
use faceauth_camera::calib::{self, Exposure, Metering, Smoother, Window, AE_TARGET};
use faceauth_camera::{Camera, Frame, Illuminator};
use faceauth_engine::{Face, Grey};
use std::path::Path;
use std::time::{Duration, Instant};

pub struct IrCapture {
    cam: Camera,
    pub illuminator: Option<Illuminator>,
    frame: Frame,
    pub frames: u64,
    smoother: Smoother,
    pub exposure: Exposure,
    pub metering: Metering,
    last_step: Instant,
    window: Option<Window>,
    orientation: [bool; 3],
    ae_enabled: bool,
    /// What this camera is, for binding templates to it: the IPU3 sensor
    /// entity ("ipu3:ov7251 3-0060") or the UVC driver, card and bus path.
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
                    (
                        ir.video.clone(),
                        ir.subdev.clone(),
                        w,
                        h,
                        ir.pixelformat,
                        format!("ipu3:{}", ir.name),
                    )
                }
            };
        let mut cam = Camera::open(&video, &subdev, width, height, pixelformat, 6)
            .context("open IR camera")?;
        let illuminator = if cfg.liveness {
            Illuminator::open(&subdev)?
        } else {
            None
        };
        let start = seed.unwrap_or(Exposure {
            exposure: 500.min(cam.limits.exposure.1),
            gain: cam.limits.gain.map(|g| g.0).unwrap_or(0),
            dgain: 1.0,
        });
        cam.set_exposure(start)?;
        cam.start()?;
        Ok(IrCapture {
            cam,
            illuminator,
            frame: Frame::new(0, 0),
            frames: 0,
            smoother: Smoother::default(),
            exposure: start,
            metering: Metering::default(),
            last_step: Instant::now(),
            window: None,
            orientation: cfg.ir_orientation,
            ae_enabled: true,
            identity,
        })
    }

    pub fn freeze_exposure(&mut self, frozen: bool) {
        self.ae_enabled = !frozen;
    }

    /// Block for the next frame and return it oriented as 8-bit grey (linear,
    /// 10-bit shifted down: a fixed mapping so consecutive frames are comparable).
    pub fn next(&mut self, timeout: Duration) -> Result<Option<Grey>> {
        if !self.cam.capture(&mut self.frame, timeout)? {
            return Ok(None);
        }
        self.frames += 1;
        if self.ae_enabled && self.last_step.elapsed() >= Duration::from_millis(400) {
            self.last_step = Instant::now();
            let w = self
                .window
                .unwrap_or_else(|| Window::centre(self.frame.width, self.frame.height))
                .clamp(self.frame.width, self.frame.height);
            let mut m = calib::meter(&self.frame.px, self.frame.width, 0, w);
            if m.mean > 0.95 {
                m.clip = m.clip.max(0.2);
            }
            let sm = Metering {
                mean: self.smoother.push(m.mean),
                clip: m.clip,
            };
            self.metering = sm;
            let f = calib::ae_factor(sm, AE_TARGET);
            if f != 1.0 {
                let next = self.exposure.step(f, &self.cam.limits);
                self.cam.set_exposure(next)?;
                self.exposure = next;
            }
        }
        let f = &self.frame;
        let mut g8 = Grey::new(f.width, f.height);
        for (o, &v) in g8.data.iter_mut().zip(&f.px) {
            *o = (v >> 2) as u8;
        }
        let [t, fx, fy] = self.orientation;
        Ok(Some(g8.oriented(t, fx, fy)))
    }

    /// Meter on this face from now on (box in oriented coordinates).
    pub fn meter_on(&mut self, face: &Face) {
        let (rw, rh) = (self.frame.width as f32, self.frame.height as f32);
        let [bx, by, bw, bh] = face.bbox;
        let (ox0, oy0, ox1, oy1) = (
            bx.max(0.0),
            by.max(0.0),
            (bx + bw).max(0.0),
            (by + bh).max(0.0),
        );
        let [t, fx, fy] = self.orientation;
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
        self.window = Some(Window {
            x0,
            y0,
            x1: x1.max(x0 + 1),
            y1: y1.max(y0 + 1),
        });
    }

    pub fn stop(mut self) -> Result<()> {
        if let Some(i) = &self.illuminator {
            let _ = i.set(false);
        }
        self.cam.stop()
    }
}

#[cfg(test)]
mod tests {
    // Orientation round trip is covered by faceauth_engine::image tests; the
    // inverse mapping here is exercised on hardware by the metering settling on
    // the face (README, engine live run).
}
