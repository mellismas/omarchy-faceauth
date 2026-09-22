//! Daemon configuration: `/etc/faceauth/config.toml`, every key optional.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Where the model weights live.
    pub models_dir: PathBuf,
    /// Where templates live (one JSON per user, root 0600).
    pub store_dir: PathBuf,
    /// The Unix socket the PAM module and the CLI talk to.
    pub socket: PathBuf,
    /// Cosine similarity at or above which a frame matches.
    pub accept_threshold: f32,
    /// Frames that must match within one attempt.
    pub required_matches: usize,
    /// Longest an attempt may run, in seconds.
    pub attempt_timeout: f32,
    /// Detector score below which a frame is not a face.
    pub min_detection: f32,
    /// Explicit IR camera choice (video node); empty = detect.
    pub ir_video: Option<PathBuf>,
    /// Explicit IR sensor subdevice; empty = detect.
    pub ir_subdev: Option<PathBuf>,
    /// Frame orientation for the IR sensor: transpose, flip_x, flip_y.
    pub ir_orientation: [bool; 3],
    /// Run the flash-response liveness gate (needs the strobe control).
    pub liveness: bool,
    /// Refuse to authenticate when the gate cannot run (no strobe control).
    /// Setting this false accepts that a print can pass on that camera.
    pub liveness_required: bool,
    /// The presence watch (auto-lock when the enrolled user leaves).
    pub presence: crate::presence::PresenceConfig,
    /// Omarchy tree the running shell was launched from (for the consent
    /// window and notifications); default: /etc/omarchy.conf, else the package.
    pub omarchy_path: Option<String>,
    /// Seconds the scan waits for a face during a consent request (the window
    /// is up; the user may not be looking yet).
    pub consent_scan_seconds: f32,
    /// Seconds the nod is read for after each match of a sudo or polkit
    /// consent request. When it passes unanswered the camera drops to the
    /// presence rhythm and an attentive face re-arms a fresh scan; the
    /// request itself has no deadline. Clamped to 10..3600.
    pub consent_seconds: f32,
    /// Nods required.
    pub consent_nods: usize,
    /// Write each consent round's per-frame gesture recording (head pose,
    /// landmarks, image motion; never images) to `<store_dir>/gestures/`,
    /// root-only, newest sixty kept. Off by default; calibration turns it on.
    /// Nothing per-frame ever goes to the journal.
    pub gesture_trace: bool,
    /// Recognise gestures but never act on them: the window waits until it
    /// is answered or the requester gives up. For recording a calibration
    /// battery to each gesture's rest.
    pub gesture_record_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            models_dir: PathBuf::from("/usr/share/faceauth/models"),
            store_dir: PathBuf::from("/var/lib/faceauth"),
            socket: PathBuf::from("/run/faceauth/sock"),
            accept_threshold: 0.70,
            required_matches: 2,
            attempt_timeout: 6.0,
            min_detection: 0.6,
            ir_video: None,
            ir_subdev: None,
            // The reference machine (Surface Book 2): transpose plus both flips.
            ir_orientation: [true, true, true],
            liveness: true,
            liveness_required: true,
            presence: Default::default(),
            omarchy_path: None,
            consent_scan_seconds: 20.0,
            consent_seconds: 90.0,
            consent_nods: 2,
            gesture_trace: false,
            gesture_record_only: false,
        }
    }
}

impl Config {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let p = path.as_ref();
        if !p.exists() {
            return Ok(Config::default());
        }
        let text = std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
        toml::from_str(&text).with_context(|| format!("parse {}", p.display()))
    }
}
