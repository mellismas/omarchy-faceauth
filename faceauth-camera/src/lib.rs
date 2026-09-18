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

use anyhow::{anyhow, bail, Context, Result};
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
        Frame { width, height, sequence: 0, px: vec![0; width * height] }
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
            V4L2_PIX_FMT_IPU3_Y10 | V4L2_PIX_FMT_IPU3_SBGGR10 | V4L2_PIX_FMT_IPU3_SGBRG10 | V4L2_PIX_FMT_IPU3_SGRBG10 | V4L2_PIX_FMT_IPU3_SRGGB10 => Decoder::Ipu3Packed10,
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
    pub fn open(video: impl AsRef<Path>, controls: impl AsRef<Path>, width: u32, height: u32, pixelformat: u32, buffers: u32) -> Result<Self> {
        let mut vd = VideoDevice::open(&video)?;
        let fmt = vd.set_format(width, height, pixelformat)?;
        let decoder = Decoder::for_pixelformat(fmt.pixelformat).ok_or_else(|| anyhow!("no decoder for {}", sys::fourcc_str(fmt.pixelformat)))?;
        vd.request_buffers(buffers)?;
        let controls = Controls::open(&controls)?;
        let list = controls.list()?;
        let find = |keys: &[&str]| keys.iter().find_map(|k| list.iter().find(|c| c.key() == *k).cloned());
        let exposure = find(&["exposure", "exposure_absolute", "exposure_time_absolute"])
            .ok_or_else(|| anyhow!("{}: no exposure control", controls.path().display()))?;
        let gain = find(&["analogue_gain", "gain"]);
        let limits = ExposureLimits {
            exposure: (exposure.min.max(1), exposure.max),
            gain: gain.as_ref().map(|g| (g.min, g.max)),
            dgain_max: 4.0,
        };
        Ok(Camera { video: vd, controls, sensor: SensorControls { exposure, gain }, decoder, limits, applied: None })
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
    /// `Ok(false)` on timeout.
    pub fn capture(&self, f: &mut Frame, timeout: Duration) -> Result<bool> {
        let (w, h) = (self.width(), self.height());
        if f.width != w || f.height != h {
            *f = Frame::new(w, h);
        }
        let Some(fr) = self.video.next_frame(timeout)? else { return Ok(false) };
        if !self.decoder.decode(fr.data(), f) {
            bail!("{}: short frame ({} bytes)", self.video.path().display(), fr.bytesused);
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
        Ok(Exposure { exposure, gain, dgain: self.applied.map(|a| a.dgain).unwrap_or(1.0) })
    }

    /// Write exposure and gain to the sensor (only the fields that changed).
    /// Digital gain is the caller's to apply to the frame.
    pub fn set_exposure(&mut self, e: Exposure) -> Result<()> {
        let prev = self.applied;
        if prev.map(|p| p.exposure != e.exposure).unwrap_or(true) {
            self.controls.set(self.sensor.exposure.id, e.exposure as i32)?;
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

/// The IR illuminator, as the `strobe_output_enable` control on the IR sensor
/// (kernel patch 2 in the pack) plus the optional `strobe_frame_pattern`.
pub struct Illuminator {
    controls: Controls,
    enable: ControlInfo,
    pattern: Option<ControlInfo>,
}

impl Illuminator {
    /// `Ok(None)` when the sensor has no strobe control: the machine has no
    /// driver-controlled illuminator and the caller runs on ambient light.
    pub fn open(controls_path: impl AsRef<Path>) -> Result<Option<Self>> {
        let controls = Controls::open(controls_path)?;
        let list = controls.list()?;
        let Some(enable) = list.iter().find(|c| c.key() == "strobe_output_enable").cloned() else { return Ok(None) };
        let pattern = list.iter().find(|c| c.key() == "strobe_frame_pattern").cloned();
        Ok(Some(Illuminator { controls, enable, pattern }))
    }

    pub fn has_pattern(&self) -> bool {
        self.pattern.is_some()
    }

    /// Light every frame (pattern 0xff) or none.
    pub fn set(&self, on: bool) -> Result<()> {
        if on {
            if let Some(p) = &self.pattern {
                self.controls.set(p.id, 0xff)?;
            }
        }
        self.controls.set(self.enable.id, on as i32)?;
        Ok(())
    }

    /// Light frames per an 8-frame bitmask (0xaa alternates lit/unlit), for
    /// the ambient-subtraction liveness check.
    pub fn set_pattern(&self, pattern: u8) -> Result<()> {
        let p = self.pattern.as_ref().ok_or_else(|| anyhow!("sensor has no strobe_frame_pattern control"))?;
        self.controls.set(p.id, pattern as i32)?;
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
        .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.path()).filter(|p| p.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with("video")).unwrap_or(false)).collect())
        .unwrap_or_default();
    paths.sort();
    for p in paths {
        let Ok(vd) = VideoDevice::open(&p) else { continue };
        let Ok((driver, card, _)) = vd.driver_and_card() else { continue };
        let fmts = vd.formats().unwrap_or_default().into_iter().map(|(f, _)| sys::fourcc_str(f)).collect();
        video_nodes.push((p, driver, card, fmts));
    }
    Ok(Probe { ipu3, video_nodes })
}
