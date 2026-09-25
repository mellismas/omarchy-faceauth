//! Helpers the store tests share: the camera test templates are bound to,
//! a template on it, and a scratch path per test.

use super::templates::Template;
use std::path::PathBuf;

/// The camera every test template is bound to unless a test says otherwise.
pub(super) const CAM: &str = "ipu3:acpi:\\_SB_.PCI0.I2C3.CAM3";

pub(super) fn tmpl(e: Vec<f32>, created: u64, device: &str) -> Template {
    Template {
        embedding: e,
        quality: 0.9,
        face_width: 80.0,
        created,
        label: "enrol".into(),
        device: device.to_string(),
        yaw: None,
        nose_pitch: None,
    }
}

pub(super) fn temp(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("faceauth-store-{}-{}", name, std::process::id()))
}
