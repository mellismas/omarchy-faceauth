//! Daemon configuration: `/etc/faceauth/config.toml`, every key optional.

use anyhow::{bail, Context, Result};
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
        Self::from_text(&text, &p.display().to_string())
    }

    /// Parse `text` (named `origin` in messages), warn on every key the
    /// daemon does not know, naming the table it landed in, and refuse a
    /// value that would switch a check off.
    pub fn from_text(text: &str, origin: &str) -> Result<Self> {
        let cfg: Config = toml::from_str(text).with_context(|| format!("parse {}", origin))?;
        for line in unknown_keys(text) {
            log::warn!("{}: {}", origin, line);
        }
        cfg.validate().with_context(|| format!("{}: refusing to start", origin))?;
        Ok(cfg)
    }

    /// A value that disables a check is a configuration error, not a
    /// setting: the daemon refuses to start on it, and every PAM stack it
    /// sits in falls to the password, which is the safe direction (F3).
    pub fn validate(&self) -> Result<()> {
        if self.required_matches < 1 {
            bail!("required_matches = {} would accept the first scored frame whatever its score; it must be 1 or more", self.required_matches);
        }
        if self.accept_threshold.is_nan() || self.accept_threshold <= 0.0 || self.accept_threshold > 1.0 {
            bail!("accept_threshold = {} is outside (0, 1]; at or below 0 every face matches", self.accept_threshold);
        }
        if self.min_detection.is_nan() || self.min_detection <= 0.0 || self.min_detection > 1.0 {
            bail!("min_detection = {} is outside (0, 1]", self.min_detection);
        }
        if !positive(self.attempt_timeout) {
            bail!("attempt_timeout = {} must be positive", self.attempt_timeout);
        }
        if self.consent_nods < 1 {
            bail!("consent_nods = {} would approve without a nod; it must be 1 or more", self.consent_nods);
        }
        if !positive(self.consent_scan_seconds) || !positive(self.consent_seconds) {
            bail!("consent_scan_seconds and consent_seconds must be positive");
        }
        let pr = &self.presence;
        if pr.lock_command.is_empty() || pr.lock_command[0].is_empty() {
            bail!("[presence] lock_command is empty: the walk-away lock would have nothing to run");
        }
        if !positive(pr.tick_seconds) || !positive(pr.away_seconds) {
            bail!("[presence] tick_seconds and away_seconds must be positive");
        }
        if pr.enabled && pr.user.is_empty() {
            bail!("[presence] enabled = true needs a user");
        }
        Ok(())
    }
}

/// A finite number above zero (NaN is not).
fn positive(v: f32) -> bool {
    v.is_finite() && v > 0.0
}

/// Keys in `text` the daemon has no field for, each described with the
/// table it sits in, so a hardening line appended under `[presence]` by
/// mistake is named rather than dropped without a word.
pub fn unknown_keys(text: &str) -> Vec<String> {
    let Ok(doc) = toml::from_str::<toml::Table>(text) else { return Vec::new() };
    let Ok(toml::Value::Table(known)) = toml::Value::try_from(every_key()) else { return Vec::new() };
    let mut out = Vec::new();
    walk_unknown(&doc, &known, "", &mut out);
    out
}

/// The default config with every optional field filled in, so that the
/// serialised form names every key the daemon reads. A `None` serialises to
/// nothing at all, and the walk below would otherwise call `omarchy_path`
/// or `ir_video` unknown on a machine that sets them.
fn every_key() -> Config {
    Config {
        ir_video: Some(PathBuf::from("/dev/video0")),
        ir_subdev: Some(PathBuf::from("/dev/v4l-subdev0")),
        omarchy_path: Some("/usr/share/omarchy".into()),
        ..Config::default()
    }
}

fn walk_unknown(doc: &toml::Table, known: &toml::Table, table: &str, out: &mut Vec<String>) {
    for (k, v) in doc {
        match known.get(k) {
            None => {
                let place = if table.is_empty() { "the top level".to_string() } else { format!("[{}]", table) };
                let hint = if table.is_empty() { String::new() } else if toml::Value::try_from(every_key()).ok().and_then(|c| c.get(k).cloned()).is_some() { " (a top-level key; it must come before any [table] line)".to_string() } else { String::new() };
                out.push(format!("unknown key {:?} in {}; ignored{}", k, place, hint));
            }
            Some(toml::Value::Table(kt)) => {
                if let toml::Value::Table(dt) = v {
                    let name = if table.is_empty() { k.clone() } else { format!("{}.{}", table, k) };
                    walk_unknown(dt, kt, &name, out);
                }
            }
            Some(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misplaced_and_misspelt_keys_are_named() {
        let text = "accept_threshold = 0.70\nacept_threshold = 0.9\n[presence]\nenabled = false\naccept_threshold = 0.85\nrequired_matches = 3\nmodee = \"secure\"\n";
        let warnings = unknown_keys(text);
        assert_eq!(warnings.len(), 4, "{:?}", warnings);
        assert!(warnings.iter().any(|w| w.contains("\"acept_threshold\" in the top level")), "{:?}", warnings);
        assert!(warnings.iter().any(|w| w.contains("\"accept_threshold\" in [presence]") && w.contains("top-level key")), "{:?}", warnings);
        assert!(warnings.iter().any(|w| w.contains("\"modee\" in [presence]") && !w.contains("top-level")), "{:?}", warnings);
        assert!(Config::from_text(text, "test").is_ok(), "unknown keys warn; they do not refuse");
        assert!(unknown_keys("").is_empty());
        assert!(unknown_keys("omarchy_path = \"/x\"\nir_video = \"/dev/video2\"\nir_subdev = \"/dev/v4l-subdev8\"\n").is_empty(), "optional keys are known keys");
    }

    #[test]
    fn a_value_that_disables_a_check_refuses_to_start() {
        for bad in ["required_matches = 0", "accept_threshold = 0.0", "accept_threshold = -1.0", "accept_threshold = 1.5", "consent_nods = 0", "min_detection = 0", "[presence]\nlock_command = []", "[presence]\nlock_command = [\"\"]", "[presence]\naway_seconds = 0", "[presence]\nenabled = true\nuser = \"\""] {
            let e = Config::from_text(bad, "test").err().map(|e| format!("{:#}", e)).unwrap_or_default();
            assert!(e.contains("refusing to start"), "{:?} should refuse: {}", bad, e);
        }
        for good in ["", "required_matches = 1", "accept_threshold = 1.0", "[presence]\nmode = \"secure\"", "[presence]\nmode = \"default\""] {
            Config::from_text(good, "test").unwrap_or_else(|e| panic!("{:?} should load: {:#}", good, e));
        }
        let e = Config::from_text("[presence]\nmode = \"paranoid\"", "test").unwrap_err();
        assert!(format!("{:#}", e).contains("parse"), "an unknown mode is a parse error: {:#}", e);
        assert_eq!(Config::from_text("[presence]\nmode = \"secure\"", "test").unwrap().presence.mode, crate::presence::PresenceMode::Secure);
    }
}
