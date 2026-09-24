//! Camera capture for Omarchy FaceAuth.
//!
//! Two backends share one frame type:
//! - [`ipu3`]: Intel IPU3/CIO2 MIPI sensors (the Surface line and other Intel
//!   laptops), with the packed 10-bit unpack and the media graph set up here.
//! - plain V4L2 capture nodes (UVC webcams and IR cameras), through [`Camera`]
//!   with the format negotiated from what the node offers.
//!
//! The exposure and colour loops live in [`calib`] and are pure functions of
//! the frame; [`Camera`] applies their output through V4L2 controls, and the
//! IR illuminator is a control on the IR sensor ([`Illuminator`]).

pub mod calib;
pub mod ipu3;
pub mod media;
pub mod sys;
pub mod unpack;
pub mod v4l2;

use anyhow::{anyhow, Context, Result};
use calib::{Exposure, ExposureLimits};
use std::path::{Path, PathBuf};
use std::time::Duration;
use v4l2::{ControlInfo, Controls, VideoDevice};

/// One captured frame on the 10-bit scale, row-major, no padding.
#[derive(Clone, Debug)]
pub struct Frame {
    pub width: usize,
    pub height: usize,
    pub sequence: u32,
    pub px: Vec<u16>,
}

impl Frame {
    pub fn new(width: usize, height: usize) -> Self {
        Frame {
            width,
            height,
            sequence: 0,
            px: vec![0; width * height],
        }
    }
}

/// How the node's bytes become 10-bit samples.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decoder {
    Ipu3Packed10,
    Grey8,
    YuyvLuma,
    Y10,
    Y16,
}

impl Decoder {
    pub fn for_pixelformat(f: u32) -> Option<Decoder> {
        use sys::*;
        Some(match f {
            V4L2_PIX_FMT_IPU3_Y10
            | V4L2_PIX_FMT_IPU3_SBGGR10
            | V4L2_PIX_FMT_IPU3_SGBRG10
            | V4L2_PIX_FMT_IPU3_SGRBG10
            | V4L2_PIX_FMT_IPU3_SRGGB10 => Decoder::Ipu3Packed10,
            V4L2_PIX_FMT_GREY => Decoder::Grey8,
            V4L2_PIX_FMT_YUYV => Decoder::YuyvLuma,
            V4L2_PIX_FMT_Y10 => Decoder::Y10,
            V4L2_PIX_FMT_Y16 => Decoder::Y16,
            _ => return None,
        })
    }

    pub fn decode(self, src: &[u8], f: &mut Frame) -> bool {
        match self {
            Decoder::Ipu3Packed10 => unpack::unpack_ipu3_10(src, f.width, f.height, &mut f.px),
            Decoder::Grey8 => unpack::unpack_grey8(src, f.width, f.height, &mut f.px),
            Decoder::YuyvLuma => unpack::unpack_yuyv_luma(src, f.width, f.height, &mut f.px),
            Decoder::Y10 => unpack::unpack_y16(src, f.width, f.height, 0, &mut f.px),
            Decoder::Y16 => unpack::unpack_y16(src, f.width, f.height, 6, &mut f.px),
        }
    }
}

/// The sensor controls an exposure loop drives, resolved once by name.
#[derive(Clone, Debug)]
pub struct SensorControls {
    pub exposure: ControlInfo,
    pub gain: Option<ControlInfo>,
}

/// A streaming camera: a capture node plus the controls of the sensor behind it.
pub struct Camera {
    pub video: VideoDevice,
    pub controls: Controls,
    pub sensor: SensorControls,
    pub decoder: Decoder,
    pub limits: ExposureLimits,
    applied: Option<Exposure>,
}

impl Camera {
    /// Open a node and a control interface (the sensor subdev for IPU3, or the
    /// node itself for UVC), negotiate `pixelformat` at `width`x`height`.
    pub fn open(
        video: impl AsRef<Path>,
        controls: impl AsRef<Path>,
        width: u32,
        height: u32,
        pixelformat: u32,
        buffers: u32,
    ) -> Result<Self> {
        let mut vd = VideoDevice::open(&video)?;
        let fmt = vd.set_format(width, height, pixelformat)?;
        let decoder = Decoder::for_pixelformat(fmt.pixelformat)
            .ok_or_else(|| anyhow!("no decoder for {}", sys::fourcc_str(fmt.pixelformat)))?;
        vd.request_buffers(buffers)?;
        let controls = Controls::open(&controls)?;
        let list = controls.list()?;
        let find = |keys: &[&str]| {
            keys.iter()
                .find_map(|k| list.iter().find(|c| c.key() == *k).cloned())
        };
        let exposure = find(&["exposure", "exposure_absolute", "exposure_time_absolute"])
            .ok_or_else(|| anyhow!("{}: no exposure control", controls.path().display()))?;
        let gain = find(&["analogue_gain", "gain"]);
        // Digital gain is a multiplier the caller applies to the frame; a
        // caller that never does must set `limits.dgain_max` to 1.0 or the
        // loop climbs a gain that changes nothing on the sensor.
        let limits = ExposureLimits {
            exposure: (exposure.min.max(1), exposure.max),
            gain: gain.as_ref().map(|g| (g.min, g.max)),
            dgain_max: 4.0,
        };
        Ok(Camera {
            video: vd,
            controls,
            sensor: SensorControls { exposure, gain },
            decoder,
            limits,
            applied: None,
        })
    }

    pub fn width(&self) -> usize {
        self.video.format().map(|f| f.width as usize).unwrap_or(0)
    }
    pub fn height(&self) -> usize {
        self.video.format().map(|f| f.height as usize).unwrap_or(0)
    }

    pub fn start(&mut self) -> Result<()> {
        self.video.stream_on()
    }
    pub fn stop(&mut self) -> Result<()> {
        self.video.stream_off()
    }

    /// Block for the next frame and decode it into `f` (resized as needed).
    /// `Ok(false)` on timeout, and for a frame the node delivered short.
    pub fn capture(&self, f: &mut Frame, timeout: Duration) -> Result<bool> {
        let (w, h) = (self.width(), self.height());
        if f.width != w || f.height != h {
            *f = Frame::new(w, h);
        }
        let Some(fr) = self.video.next_frame(timeout)? else {
            return Ok(false);
        };
        if !self.decoder.decode(fr.data(), f) {
            // A payload shorter than the format is one bad frame, not the
            // end of the attempt: the next poll brings the next one.
            log::warn!(
                "{}: short frame {} ({} bytes) skipped",
                self.video.path().display(),
                fr.sequence,
                fr.bytesused
            );
            return Ok(false);
        }
        f.sequence = fr.sequence;
        Ok(true)
    }

    /// Read the sensor's current exposure and gain.
    pub fn exposure(&self) -> Result<Exposure> {
        let exposure = self.controls.get(self.sensor.exposure.id)? as i64;
        let gain = match &self.sensor.gain {
            Some(g) => self.controls.get(g.id)? as i64,
            None => 0,
        };
        Ok(Exposure {
            exposure,
            gain,
            dgain: self.applied.map(|a| a.dgain).unwrap_or(1.0),
        })
    }

    /// Write exposure and gain to the sensor (only the fields that changed).
    /// Digital gain is the caller's to apply to the frame.
    pub fn set_exposure(&mut self, e: Exposure) -> Result<()> {
        let prev = self.applied;
        if prev.map(|p| p.exposure != e.exposure).unwrap_or(true) {
            self.controls
                .set(self.sensor.exposure.id, e.exposure as i32)?;
        }
        if let Some(g) = &self.sensor.gain {
            if prev.map(|p| p.gain != e.gain).unwrap_or(true) {
                self.controls.set(g.id, e.gain as i32)?;
            }
        }
        self.applied = Some(e);
        Ok(())
    }
}

/// The IR illuminator, as the `strobe_output_enable` and
/// `strobe_frame_pattern` controls the patched ov7251 driver adds to the
/// IR sensor. Both are needed: every gate writes a pattern, so a sensor
/// with the standard strobe enable alone is one without an illuminator
/// this crate can drive, and `open` says so by returning `None`. That is
/// what makes the daemon's "liveness gate unavailable" refusal fire
/// instead of an error out of the first `set_pattern`.
pub struct Illuminator {
    controls: Controls,
    enable: ControlInfo,
    pattern: ControlInfo,
}

/// The two strobe controls out of a sensor's control list, or `None` when
/// either is missing.
pub fn strobe_controls(list: &[ControlInfo]) -> Option<(ControlInfo, ControlInfo)> {
    let find = |key: &str| list.iter().find(|c| c.key() == key).cloned();
    Some((find("strobe_output_enable")?, find("strobe_frame_pattern")?))
}

/// Does the sensor behind `controls_path` have the two strobe controls?
/// Reads the control list and writes nothing: an `Illuminator` switches
/// the strobe off when it is dropped, so a probe made by constructing one
/// (as `doctor` once did) would turn the light off under a running gate.
pub fn has_strobe(controls_path: impl AsRef<Path>) -> Result<bool> {
    let controls = Controls::open(controls_path)?;
    Ok(strobe_controls(&controls.list()?).is_some())
}

impl Illuminator {
    /// `Ok(None)` when the sensor lacks either strobe control: the machine
    /// has no illuminator this crate can drive and the caller decides what
    /// that means (the daemon refuses by default).
    pub fn open(controls_path: impl AsRef<Path>) -> Result<Option<Self>> {
        let controls = Controls::open(controls_path)?;
        let Some((enable, pattern)) = strobe_controls(&controls.list()?) else {
            return Ok(None);
        };
        Ok(Some(Illuminator {
            controls,
            enable,
            pattern,
        }))
    }

    /// Always true for an open illuminator; kept for callers that report it.
    pub fn has_pattern(&self) -> bool {
        true
    }

    /// Light every frame (pattern 0xff) or none.
    pub fn set(&self, on: bool) -> Result<()> {
        if on {
            self.controls.set(self.pattern.id, 0xff)?;
        }
        self.controls.set(self.enable.id, on as i32)?;
        Ok(())
    }

    /// Light frames per an 8-frame bitmask (0xaa alternates lit/unlit), for
    /// the ambient-subtraction liveness check.
    pub fn set_pattern(&self, pattern: u8) -> Result<()> {
        self.controls.set(self.pattern.id, pattern as i32)?;
        self.controls.set(self.enable.id, 1)?;
        Ok(())
    }

    pub fn is_on(&self) -> Result<bool> {
        Ok(self.controls.get(self.enable.id)? != 0)
    }
}

impl Drop for Illuminator {
    fn drop(&mut self) {
        let _ = self.controls.set(self.enable.id, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn control(name: &str, id: u32) -> ControlInfo {
        ControlInfo {
            id,
            name: name.into(),
            type_: 1,
            min: 0,
            max: 255,
            step: 1,
            default: 0,
            flags: 0,
        }
    }

    /// A sensor with the strobe enable alone is not an illuminator: the
    /// gates need the pattern too.
    #[test]
    fn an_illuminator_needs_both_strobe_controls() {
        let both = [
            control("Exposure", 1),
            control("Strobe Output Enable", 2),
            control("Strobe Frame Pattern", 3),
        ];
        let (enable, pattern) = strobe_controls(&both).unwrap();
        assert_eq!((enable.id, pattern.id), (2, 3));
        let enable_only = [control("Exposure", 1), control("Strobe Output Enable", 2)];
        assert!(strobe_controls(&enable_only).is_none());
        let pattern_only = [control("Strobe Frame Pattern", 3)];
        assert!(strobe_controls(&pattern_only).is_none());
        assert!(strobe_controls(&[]).is_none());
    }
}

/// What a probe found, for `faceauth doctor` and for choosing a backend.
#[derive(Debug)]
pub struct Probe {
    pub ipu3: Option<ipu3::Ipu3Graph>,
    pub video_nodes: Vec<(PathBuf, String, String, Vec<String>)>,
}

pub fn probe() -> Result<Probe> {
    let ipu3 = ipu3::probe().context("IPU3 probe")?;
    let mut video_nodes = Vec::new();
    let mut paths: Vec<PathBuf> = std::fs::read_dir("/dev")
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("video"))
                        .unwrap_or(false)
                })
                .collect()
        })
        .unwrap_or_default();
    paths.sort();
    for p in paths {
        let Ok(vd) = VideoDevice::open(&p) else {
            continue;
        };
        let Ok((driver, card, _)) = vd.driver_and_card() else {
            continue;
        };
        let fmts = vd
            .formats()
            .unwrap_or_default()
            .into_iter()
            .map(|(f, _)| sys::fourcc_str(f))
            .collect();
        video_nodes.push((p, driver, card, fmts));
    }
    Ok(Probe { ipu3, video_nodes })
}
