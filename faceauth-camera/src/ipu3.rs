//! Intel IPU3 (CIO2) pipeline: sensor -> ipu3-csi2 N -> ipu3-cio2 N -> /dev/videoX.
//!
//! The graph is resolved by entity name, never by device number: numbers move
//! between boots and module reloads. Sensors are classified by the media-bus
//! code they produce: `Y10` is an IR camera, a 10-bit Bayer code is RGB.

use crate::media::{Entity, MediaDevice};
use crate::sys::*;
use crate::v4l2::Subdev;
use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SensorKind {
    Infrared,
    Colour,
}

/// `V4L2_CID_CAMERA_ORIENTATION`, when the sensor reports it (from ACPI _PLD).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Orientation {
    Front,
    Back,
    External,
}

#[derive(Clone, Debug)]
pub struct Ipu3Sensor {
    pub kind: SensorKind,
    pub orientation: Option<Orientation>,
    pub name: String,
    pub sensor: Entity,
    pub csi2: Entity,
    pub cio2: Entity,
    pub port: u32,
    pub subdev: PathBuf,
    pub video: PathBuf,
    pub width: u32,
    pub height: u32,
    pub mbus_code: u32,
    pub pixelformat: u32,
}

#[derive(Debug)]
pub struct Ipu3Graph {
    pub media: PathBuf,
    pub sensors: Vec<Ipu3Sensor>,
}

/// Find the IPU3 media device and every sensor hanging off it.
pub fn probe() -> Result<Option<Ipu3Graph>> {
    for path in MediaDevice::enumerate() {
        let md = match MediaDevice::open(&path) {
            Ok(m) => m,
            Err(_) => continue,
        };
        let (driver, _, _) = md.info()?;
        if driver != "ipu3-cio2" {
            continue;
        }
        let entities = md.entities()?;
        let mut sensors = Vec::new();
        // Walk from the sensors: the kernel reports outgoing links only, so a
        // sensor is any entity with a link into an "ipu3-csi2 N" pad 0.
        for sensor in entities.iter().filter(|e| !e.name.starts_with("ipu3-")) {
            let links = md.links(sensor)?;
            let Some((csi2, _link)) = links.iter().find_map(|l| {
                entities
                    .iter()
                    .find(|e| {
                        e.id == l.sink_entity && l.sink_pad == 0 && e.name.starts_with("ipu3-csi2 ")
                    })
                    .map(|e| (e, l))
            }) else {
                continue;
            };
            let port: u32 = csi2.name["ipu3-csi2 ".len()..].trim().parse().unwrap_or(99);
            let Some(cio2) = entities
                .iter()
                .find(|e| e.name == format!("ipu3-cio2 {}", port))
            else {
                continue;
            };
            let subdev = sensor
                .dev_node()
                .ok_or_else(|| anyhow!("{}: no subdev node", sensor.name))?;
            let video = cio2
                .dev_node()
                .ok_or_else(|| anyhow!("{}: no video node", cio2.name))?;
            let sd = Subdev::open(&subdev)?;
            let (w, h, code) = sd.get_format(0)?;
            let orientation = match sd
                .controls
                .find("camera_orientation")?
                .map(|c| sd.controls.get(c.id))
            {
                Some(Ok(0)) => Some(Orientation::Front),
                Some(Ok(1)) => Some(Orientation::Back),
                Some(Ok(2)) => Some(Orientation::External),
                _ => None,
            };
            let (kind, pixelformat) = match code {
                MEDIA_BUS_FMT_Y10_1X10 => (SensorKind::Infrared, V4L2_PIX_FMT_IPU3_Y10),
                MEDIA_BUS_FMT_SBGGR10_1X10 => (SensorKind::Colour, V4L2_PIX_FMT_IPU3_SBGGR10),
                MEDIA_BUS_FMT_SGRBG10_1X10 => (SensorKind::Colour, V4L2_PIX_FMT_IPU3_SGRBG10),
                0x3009 => (SensorKind::Colour, V4L2_PIX_FMT_IPU3_SGBRG10), // MEDIA_BUS_FMT_SGBRG10_1X10
                0x300f => (SensorKind::Colour, V4L2_PIX_FMT_IPU3_SRGGB10), // MEDIA_BUS_FMT_SRGGB10_1X10
                other => {
                    log::warn!(
                        "{}: unknown media-bus code 0x{:04x}, skipped",
                        sensor.name,
                        other
                    );
                    continue;
                }
            };
            sensors.push(Ipu3Sensor {
                kind,
                orientation,
                name: sensor.name.clone(),
                sensor: sensor.clone(),
                csi2: csi2.clone(),
                cio2: cio2.clone(),
                port,
                subdev,
                video,
                width: w,
                height: h,
                mbus_code: code,
                pixelformat,
            });
        }
        sensors.sort_by_key(|s| s.port);
        return Ok(Some(Ipu3Graph {
            media: path,
            sensors,
        }));
    }
    Ok(None)
}

impl Ipu3Graph {
    /// The IR sensor to authenticate with: a front one if orientation is known.
    pub fn ir_sensor(&self) -> Option<&Ipu3Sensor> {
        self.pick(SensorKind::Infrared)
    }

    /// The colour sensor facing the user, or none if only a back camera exists.
    pub fn colour_sensor(&self) -> Option<&Ipu3Sensor> {
        self.pick(SensorKind::Colour)
    }

    fn pick(&self, kind: SensorKind) -> Option<&Ipu3Sensor> {
        let of_kind = || self.sensors.iter().filter(|s| s.kind == kind);
        of_kind()
            .find(|s| s.orientation == Some(Orientation::Front))
            .or_else(|| of_kind().find(|s| s.orientation.is_none()))
    }
}

impl Ipu3Graph {
    /// Enable the sensor's link into its CSI-2 receiver and propagate the
    /// sensor's format through both receiver pads. Idempotent.
    ///
    /// `size` overrides the sensor's current mode (the RGB sensor on the
    /// reference machine must run at 1296x972: its 2592x972 default overruns
    /// the link).
    pub fn configure(&self, s: &Ipu3Sensor, size: Option<(u32, u32)>) -> Result<(u32, u32)> {
        let md = MediaDevice::open(&self.media)?;
        let links = md.links(&s.sensor)?;
        let link = links
            .iter()
            .find(|l| l.sink_entity == s.csi2.id && l.sink_pad == 0)
            .ok_or_else(|| anyhow!("{} -> {}: link not found", s.name, s.csi2.name))?;
        if !link.enabled() {
            md.setup_link(link, true)
                .with_context(|| format!("enable {} -> {}", s.name, s.csi2.name))?;
        }
        let sd = Subdev::open(&s.subdev)?;
        let (w, h) = size.unwrap_or((s.width, s.height));
        let (w, h, code) = sd.set_format(0, w, h, s.mbus_code)?;
        if code != s.mbus_code {
            bail!(
                "{}: sensor changed media-bus code to 0x{:04x}",
                s.name,
                code
            );
        }
        let csi = Subdev::open(
            s.csi2
                .dev_node()
                .ok_or_else(|| anyhow!("{}: no subdev node", s.csi2.name))?,
        )?;
        csi.set_format(0, w, h, code)?;
        csi.set_format(1, w, h, code)?;
        Ok((w, h))
    }
}
