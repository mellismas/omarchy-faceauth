//! Daemon configuration: `/etc/faceauth/config.toml`, every key optional.
//! Only what an administrator can usefully change is a key; what the
//! system fixes is a constant here (H15).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Where templates live (one file per user, root 0600). Fixed: the unit's
/// sandbox makes only this directory writable and the removal script
/// looks here, so any other value would make every save fail.
pub const STORE_DIR: &str = "/var/lib/faceauth";
/// The Unix socket the PAM module, the CLI and the shell's windows talk
/// to. Fixed: the PAM lines, the windows and the CLI all name it, so a
/// changed key would break them without a word.
pub const SOCKET: &str = "/run/faceauth/sock";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Where the model weights live. The omarchy-faceauth-models package
    /// installs them under the default; nothing here downloads anything.
    pub models_dir: PathBuf,
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
    /// The flash-response liveness gate runs whenever the sensor has the
    /// strobe controls. Without them it cannot run, and the daemon refuses
    /// to authenticate unless this is false, which accepts that a print
    /// can pass on that camera.
    pub liveness_required: bool,
    /// The presence watch (auto-lock when the enrolled user leaves).
    pub presence: crate::presence::PresenceConfig,
    /// How often the lock screen probes for a face while its panel is blank.
    pub unlock: UnlockConfig,
    /// Seconds the scan waits for a face during a consent request (the window
    /// is up; the user may not be looking yet).
    pub consent_scan_seconds: f32,
    /// Seconds the nod is read for after each match of a sudo or polkit
    /// consent request. When it passes unanswered the camera drops to the
    /// presence rhythm and an attentive face re-arms a fresh scan; the
    /// request itself has no deadline. Never under 10.
    pub consent_seconds: f32,
    /// Write each consent round's per-frame gesture recording (the head's
    /// angles from the face mesh and the detector box; never images) to
    /// `<store_dir>/gestures/<user>/`, root-only, newest sixty kept. Off by
    /// default, and the key exists only in dev-tools builds: the package
    /// warns on it as unknown (H2). Nothing per-frame ever goes to the
    /// journal.
    #[cfg(feature = "dev-tools")]
    pub gesture_trace: bool,
    /// Recognise gestures but never act on them: the window waits until it
    /// is answered or the requester gives up. For recording a battery of
    /// rounds to each gesture's rest. Development builds only, like
    /// `gesture_trace`.
    #[cfg(feature = "dev-tools")]
    pub gesture_record_only: bool,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            models_dir: PathBuf::from("/usr/share/faceauth/models"),
            accept_threshold: 0.70,
            required_matches: 2,
            attempt_timeout: 6.0,
            min_detection: 0.6,
            ir_video: None,
            ir_subdev: None,
            // The reference machine (Surface Book 2): transpose plus both flips.
            ir_orientation: [true, true, true],
            liveness_required: true,
            presence: Default::default(),
            unlock: Default::default(),
            consent_scan_seconds: 20.0,
            consent_seconds: 90.0,
            #[cfg(feature = "dev-tools")]
            gesture_trace: false,
            #[cfg(feature = "dev-tools")]
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
        cfg.validate()
            .with_context(|| format!("{}: refusing to start", origin))?;
        Ok(cfg)
    }

    /// A value that disables a check is a configuration error, not a
    /// setting: the daemon refuses to start on it, and every PAM stack it
    /// sits in falls to the password, which is the safe direction (F3).
    pub fn validate(&self) -> Result<()> {
        if self.required_matches < 1 {
            bail!("required_matches = {} would accept the first scored frame whatever its score; it must be 1 or more", self.required_matches);
        }
        if self.accept_threshold.is_nan()
            || self.accept_threshold <= 0.0
            || self.accept_threshold > 1.0
        {
            bail!(
                "accept_threshold = {} is outside (0, 1]; at or below 0 every face matches",
                self.accept_threshold
            );
        }
        if self.min_detection.is_nan() || self.min_detection <= 0.0 || self.min_detection > 1.0 {
            bail!("min_detection = {} is outside (0, 1]", self.min_detection);
        }
        if !positive(self.attempt_timeout) {
            bail!(
                "attempt_timeout = {} must be positive",
                self.attempt_timeout
            );
        }
        if !positive(self.consent_scan_seconds) || !positive(self.consent_seconds) {
            bail!("consent_scan_seconds and consent_seconds must be positive");
        }
        let pr = &self.presence;
        let away_ok = match pr.away_seconds {
            crate::presence::AwayTime::Seconds(s) => positive(s),
            crate::presence::AwayTime::Word(_) => true,
        };
        if !positive(pr.tick_seconds) || !away_ok || !positive(pr.secure_away_seconds) {
            bail!("[presence] tick_seconds, away_seconds and secure_away_seconds must be positive (away_seconds may also be \"never\")");
        }
        if pr.enabled && pr.user.is_empty() {
            bail!("[presence] enabled = true needs a user");
        }
        let (u, b) = (&self.unlock, &self.unlock.battery_probe_seconds);
        if ![u.probe_seconds, b.performance, b.balanced, b.power_saver]
            .into_iter()
            .all(positive)
        {
            bail!(
                "[unlock] probe_seconds and every battery_probe_seconds interval must be positive"
            );
        }
        Ok(())
    }
}

/// `[unlock]`: how often the lock screen probes for a face while its panel
/// is blank. The daemon itself reads none of it: it hands the intervals to
/// the lock screen in every probe reply, and the lock screen picks one from
/// its own power state, since the daemon does not read the power profile.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct UnlockConfig {
    /// Seconds between probes on mains power.
    pub probe_seconds: f32,
    /// Seconds between probes on battery, one interval per power profile.
    pub battery_probe_seconds: BatteryProbeSeconds,
}

impl Default for UnlockConfig {
    fn default() -> Self {
        UnlockConfig {
            probe_seconds: 2.0,
            battery_probe_seconds: BatteryProbeSeconds::default(),
        }
    }
}

/// The lock screen's probe interval on battery for each power profile it
/// can report, in seconds: a longer one where the profile asks for less.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct BatteryProbeSeconds {
    pub performance: f32,
    pub balanced: f32,
    #[serde(rename = "power-saver")]
    pub power_saver: f32,
}

impl Default for BatteryProbeSeconds {
    fn default() -> Self {
        BatteryProbeSeconds {
            performance: 3.0,
            balanced: 5.0,
            power_saver: 8.0,
        }
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
    let Ok(doc) = toml::from_str::<toml::Table>(text) else {
        return Vec::new();
    };
    let Ok(toml::Value::Table(known)) = toml::Value::try_from(every_key()) else {
        return Vec::new();
    };
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
        ..Config::default()
    }
}

fn walk_unknown(doc: &toml::Table, known: &toml::Table, table: &str, out: &mut Vec<String>) {
    for (k, v) in doc {
        match known.get(k) {
            None => {
                let place = if table.is_empty() {
                    "the top level".to_string()
                } else {
                    format!("[{}]", table)
                };
                let hint = if table.is_empty() {
                    String::new()
                } else if toml::Value::try_from(every_key())
                    .ok()
                    .and_then(|c| c.get(k).cloned())
                    .is_some()
                {
                    " (a top-level key; it must come before any [table] line)".to_string()
                } else {
                    String::new()
                };
                out.push(format!("unknown key {:?} in {}; ignored{}", k, place, hint));
            }
            Some(toml::Value::Table(kt)) => {
                if let toml::Value::Table(dt) = v {
                    let name = if table.is_empty() {
                        k.clone()
                    } else {
                        format!("{}.{}", table, k)
                    };
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
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("\"acept_threshold\" in the top level")),
            "{:?}",
            warnings
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("\"accept_threshold\" in [presence]")
                    && w.contains("top-level key")),
            "{:?}",
            warnings
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("\"modee\" in [presence]") && !w.contains("top-level")),
            "{:?}",
            warnings
        );
        assert!(
            Config::from_text(text, "test").is_ok(),
            "unknown keys warn; they do not refuse"
        );
        assert!(unknown_keys("").is_empty());
        assert!(
            unknown_keys("ir_video = \"/dev/video2\"\nir_subdev = \"/dev/v4l-subdev8\"\n")
                .is_empty(),
            "optional keys are known keys"
        );
    }

    /// The shipped `packaging/config.toml` is the defaults, spelled out and
    /// commented out: it parses to `Config::default()`, so a changed default
    /// reaches every install through the package, and it names every key
    /// the daemon reads, so an administrator can find each one.
    #[test]
    fn the_shipped_config_is_the_defaults_and_names_every_key() {
        let text = include_str!("../../packaging/config.toml");
        let shipped = Config::from_text(text, "packaging/config.toml").unwrap();
        assert_eq!(
            toml::to_string(&shipped).unwrap(),
            toml::to_string(&Config::default()).unwrap(),
            "the shipped file must not set a value"
        );
        assert!(unknown_keys(text).is_empty(), "{:?}", unknown_keys(text));
        let toml::Value::Table(known) = toml::Value::try_from(every_key()).unwrap() else {
            panic!("config serialises as a table");
        };
        let named = |key: &str| {
            text.lines().any(|l| {
                let l = l.trim_start_matches(['#', ' ']);
                l.starts_with(key) && l[key.len()..].trim_start().starts_with('=')
            })
        };
        for (k, v) in &known {
            match v {
                toml::Value::Table(sub) => {
                    assert!(text.contains(&format!("[{}]", k)), "table [{}] missing", k);
                    for sk in sub.keys() {
                        assert!(
                            named(sk),
                            "[{}] key {} is not named in the shipped file",
                            k,
                            sk
                        );
                    }
                }
                _ => assert!(named(k), "key {} is not named in the shipped file", k),
            }
        }
    }

    /// `[unlock]`: the lock screen's probe intervals ship at 2 s on mains
    /// and 3, 5 and 8 s on battery by power profile. Each may be set on its
    /// own; a zero, negative or unreadable one refuses to start, and a
    /// misspelt profile is named like any unknown key.
    #[test]
    fn the_unlock_cadence_defaults_parse_and_refuse_bad_values() {
        let c = Config::default();
        assert_eq!(c.unlock.probe_seconds, 2.0);
        assert_eq!(
            c.unlock.battery_probe_seconds,
            BatteryProbeSeconds {
                performance: 3.0,
                balanced: 5.0,
                power_saver: 8.0
            }
        );
        let c = Config::from_text(
            "[unlock]\nprobe_seconds = 1.5\nbattery_probe_seconds = { balanced = 4, power-saver = 10.0 }",
            "test",
        )
        .unwrap();
        assert_eq!(c.unlock.probe_seconds, 1.5);
        assert_eq!(
            c.unlock.battery_probe_seconds,
            BatteryProbeSeconds {
                performance: 3.0,
                balanced: 4.0,
                power_saver: 10.0
            }
        );
        let c = Config::from_text(
            "[unlock.battery_probe_seconds]\nperformance = 2.5\n",
            "test",
        )
        .unwrap();
        assert_eq!(c.unlock.battery_probe_seconds.performance, 2.5);
        assert_eq!(c.unlock.probe_seconds, 2.0);
        for bad in [
            "[unlock]\nprobe_seconds = 0",
            "[unlock]\nprobe_seconds = -2.0",
            "[unlock]\nprobe_seconds = nan",
            "[unlock]\nbattery_probe_seconds = { performance = 0 }",
            "[unlock]\nbattery_probe_seconds = { balanced = -1.0 }",
            "[unlock]\nbattery_probe_seconds = { power-saver = 0.0 }",
        ] {
            let e = Config::from_text(bad, "test")
                .err()
                .map(|e| format!("{:#}", e))
                .unwrap_or_default();
            assert!(
                e.contains("refusing to start"),
                "{:?} should refuse: {}",
                bad,
                e
            );
        }
        assert!(Config::from_text("[unlock]\nprobe_seconds = \"fast\"", "test").is_err());
        let warned = unknown_keys("[unlock]\nbattery_probe_seconds = { power_saver = 8.0 }\n");
        assert_eq!(warned.len(), 1, "{:?}", warned);
        assert!(warned[0].contains("power_saver"), "{:?}", warned);
    }

    #[test]
    fn a_value_that_disables_a_check_refuses_to_start() {
        for bad in [
            "required_matches = 0",
            "accept_threshold = 0.0",
            "accept_threshold = -1.0",
            "accept_threshold = 1.5",
            "min_detection = 0",
            "[presence]\naway_seconds = 0",
            "[presence]\naway_seconds = -1.0",
            "[presence]\nsecure_away_seconds = 0",
            "[presence]\nenabled = true\nuser = \"\"",
        ] {
            let e = Config::from_text(bad, "test")
                .err()
                .map(|e| format!("{:#}", e))
                .unwrap_or_default();
            assert!(
                e.contains("refusing to start"),
                "{:?} should refuse: {}",
                bad,
                e
            );
        }
        for good in [
            "",
            "required_matches = 1",
            "accept_threshold = 1.0",
            "[presence]\nmode = \"secure\"",
            "[presence]\nmode = \"default\"",
            "[presence]\naway_seconds = \"never\"\nsecure_away_seconds = 30.0",
            // Keys the daemon no longer has (the lock command and the
            // state file, H16 and H17; the fixed paths, the gate switch,
            // the nod count and the watch's tuning knobs, H15): a config
            // naming one warns and is otherwise ignored, like any unknown
            // key.
            "[presence]\nlock_command = [\"/usr/bin/faceauth-lock-session\", \"\"]\nstate_file = \"/run/faceauth/presence.json\"",
            "socket = \"/tmp/x\"\nstore_dir = \"/tmp/y\"\nliveness = false\nomarchy_path = \"/x\"\nconsent_nods = 3\n[presence]\nidentify_every = 1\nbattery_identify_every = 1\nrequire_attention = true\nmax_yaw = 0.1\nmax_roll_degrees = 5.0",
        ] {
            Config::from_text(good, "test")
                .unwrap_or_else(|e| panic!("{:?} should load: {:#}", good, e));
        }
        let warned = unknown_keys("[presence]\nlock_command = [\"x\"]\nstate_file = \"y\"\n");
        assert_eq!(warned.len(), 2, "{:?}", warned);
        assert!(
            warned.iter().all(|w| w.contains("[presence]")),
            "{:?}",
            warned
        );
        let warned = unknown_keys("liveness = false\nsocket = \"/x\"\n");
        assert_eq!(warned.len(), 2, "{:?}", warned);
        // The gate is not a switch any more: a config that says `liveness
        // = false` gets the gate anyway, and only the warning says why.
        let cfg = Config::from_text("liveness = false", "test").unwrap();
        assert!(cfg.liveness_required);
        let e = Config::from_text("[presence]\nmode = \"paranoid\"", "test").unwrap_err();
        assert!(
            format!("{:#}", e).contains("parse"),
            "an unknown mode is a parse error: {:#}",
            e
        );
        assert_eq!(
            Config::from_text("[presence]\nmode = \"secure\"", "test")
                .unwrap()
                .presence
                .mode,
            crate::presence::PresenceMode::Secure
        );
    }
}
