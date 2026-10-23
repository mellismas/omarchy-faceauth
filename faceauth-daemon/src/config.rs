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
/// The lock screen's reserved channel (round 7, B): a socket of its own,
/// outside the connection limits, at most two open per user.
pub const LOCK_SOCKET: &str = "/run/faceauth/lock.sock";
/// The most `max_connections` may be: what the unit's TasksMax holds
/// (packaging/faceauth.service; serve.rs's test pins the two).
pub const MAX_CONNECTIONS_CAP: usize = 128;

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
    /// Milliseconds the lock screen's latch outlives the unlock the daemon
    /// sees: from the lock screen's first ask for the key (or its word that
    /// it is up) until this long after the session is seen unlocked, the
    /// consent card takes no touch of the key and no stack's key line runs,
    /// so a touch while locked can only unlock. Longer covers more of the
    /// lock screen's two-second gap between asks; a parked card comes back
    /// this much later after an unlock. At most 30000.
    pub key_unlock_hold_ms: u64,
    /// Connections the daemon serves at once, as systemd's
    /// `MaxConnections=`; the rest are refused at once, and every user is
    /// latched for a hold (no approval opens while the places are full).
    /// At most `MAX_CONNECTIONS_CAP`. The lock screen's channel is not
    /// counted.
    pub max_connections: usize,
    /// Connections one account may hold at once, as systemd's
    /// `MaxConnectionsPerSource=`. Unset: `max_connections` over the
    /// enrolled users, never under a floor (`server/limits.rs`). A refusal
    /// here latches that account alone.
    pub max_connections_per_source: Option<usize>,
    /// Write each consent round's per-frame gesture recording (the head's
    /// angles from the face mesh and the detector box; never images) to
    /// `<store_dir>/gestures/<user>/`, root-only, newest sixty kept. Off by
    /// default, and the key exists only in dev-tools builds: the package
    /// warns on it as unknown (H2). Nothing per-frame ever goes to the
    /// journal.
    #[cfg(feature = "dev-tools")]
    pub gesture_trace: bool,
    /// Recognize gestures but never act on them: the window waits until it
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
            ir_orientation: faceauth_engine::profile::OV7251_SURFACE_BOOK_2.orientation,
            liveness_required: true,
            presence: Default::default(),
            unlock: Default::default(),
            consent_scan_seconds: 20.0,
            consent_seconds: 90.0,
            key_unlock_hold_ms: crate::consent::DEFAULT_HOLD_MS,
            max_connections: 64,
            max_connections_per_source: None,
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
        let mut cfg = if p.exists() {
            let text =
                std::fs::read_to_string(p).with_context(|| format!("read {}", p.display()))?;
            Self::from_text(&text, &p.display().to_string())?
        } else {
            Config::default()
        };
        // The canonical path goes back into the config so every later open
        // (each model file at load) uses the path that was checked, not one
        // a symlink could swap under it in between.
        cfg.models_dir = check_models_dir(&cfg.models_dir)
            .with_context(|| format!("{}: models_dir; refusing to start", p.display()))?;
        Ok(cfg)
    }

    /// Parse `text` (named `origin` in messages), warn on every key the
    /// daemon does not know, naming the table it landed in, bring the
    /// battery tick into its range, and refuse a value that would switch
    /// a check off.
    pub fn from_text(text: &str, origin: &str) -> Result<Self> {
        let mut cfg: Config = toml::from_str(text).with_context(|| format!("parse {}", origin))?;
        for line in unknown_keys(text) {
            log::warn!("{}: {}", origin, line);
        }
        if let Some(w) = cfg.presence.clamp_battery_tick() {
            log::warn!("{}: [presence] {}", origin, w);
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
        if self.max_connections == 0 || self.max_connections > MAX_CONNECTIONS_CAP {
            bail!(
                "max_connections = {} is outside 1 to {}; the unit's TasksMax holds no more",
                self.max_connections,
                MAX_CONNECTIONS_CAP
            );
        }
        if self.max_connections_per_source == Some(0) {
            bail!("max_connections_per_source = 0 would refuse everyone");
        }
        if self.key_unlock_hold_ms > 30_000 {
            bail!(
                "key_unlock_hold_ms = {} is over 30000; the card would wait that long after every unlock",
                self.key_unlock_hold_ms
            );
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
            probe_seconds: 1.0,
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
            performance: 2.0,
            balanced: 3.0,
            power_saver: 5.0,
        }
    }
}

/// The models directory is read by a root daemon that serves sudo and
/// polkit, and nothing checks the weights' hashes at load: whoever can
/// write the directory, or any directory above it, chooses the model that
/// decides who is recognized. So the directory and every ancestor must be
/// root-owned and writable by nobody else, and so must every file in it:
/// `sudo cp -a` keeps the user's ownership on the weights, and a file the
/// user owns is rewritten in place whatever the directory's mode says.
/// `faceauth models fetch` writes to the user's data directory by default,
/// which fails here on purpose; a development daemon points `models_dir` at
/// a root-owned copy installed with `install -o root -m 644`. Returns the
/// canonical path, which the caller uses from then on.
pub fn check_models_dir(dir: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    let dir = std::fs::canonicalize(dir).with_context(|| format!("resolve {}", dir.display()))?;
    for p in dir.ancestors() {
        let md = std::fs::metadata(p).with_context(|| format!("stat {}", p.display()))?;
        models_dir_component_ok(p, md.uid(), md.mode())?;
    }
    check_models_files(&dir)?;
    Ok(dir)
}

/// Every entry of the models directory, without following symlinks: a
/// symlink is refused outright (it points wherever its owner likes), and
/// anything else must be root's and not writable by group or others.
pub fn check_models_files(dir: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    for entry in std::fs::read_dir(dir).with_context(|| format!("read {}", dir.display()))? {
        let path = entry?.path();
        let md =
            std::fs::symlink_metadata(&path).with_context(|| format!("stat {}", path.display()))?;
        if md.file_type().is_symlink() {
            bail!(
                "{} is a symlink: a root daemon loads only regular files it can vouch for",
                path.display()
            );
        }
        models_dir_component_ok(&path, md.uid(), md.mode())?;
    }
    Ok(())
}

/// One path component of the models directory: owner root, no write bit
/// for group or others. The error names the path, owner and mode.
pub fn models_dir_component_ok(p: &Path, uid: u32, mode: u32) -> Result<()> {
    if uid != 0 {
        bail!(
            "{} is owned by uid {}, not root: a root daemon loads only models from a root-owned directory; install omarchy-faceauth-models, or point models_dir at a root-owned copy",
            p.display(),
            uid
        );
    }
    if mode & 0o022 != 0 {
        bail!(
            "{} has mode {:04o}, writable by group or others: a root daemon loads only models nobody else can replace",
            p.display(),
            mode & 0o7777
        );
    }
    Ok(())
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
/// serialized form names every key the daemon reads. A `None` serializes to
/// nothing at all, and the walk below would otherwise call `ir_video` or
/// `ir_subdev` unknown on a machine that sets them.
fn every_key() -> Config {
    Config {
        ir_video: Some(PathBuf::from("/dev/video0")),
        ir_subdev: Some(PathBuf::from("/dev/v4l-subdev0")),
        max_connections_per_source: Some(16),
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
            panic!("config serializes as a table");
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

    /// Round 7 (C): the connection limits are settings, as systemd's
    /// socket's are: 64 places, a per-source share computed from the
    /// enrolled users unless set, and neither past what the unit's
    /// TasksMax holds.
    #[test]
    fn the_connection_limits_are_settings() {
        let d = Config::default();
        assert_eq!(d.max_connections, 64);
        assert_eq!(d.max_connections_per_source, None, "computed");
        let c = Config::from_text(
            "max_connections = 32\nmax_connections_per_source = 8\n",
            "test",
        )
        .unwrap();
        assert_eq!(
            (c.max_connections, c.max_connections_per_source),
            (32, Some(8))
        );
        assert!(unknown_keys("max_connections = 32\nmax_connections_per_source = 8\n").is_empty());
        for bad in [
            "max_connections = 0\n",
            &format!("max_connections = {}\n", MAX_CONNECTIONS_CAP + 1),
            "max_connections_per_source = 0\n",
        ] {
            assert!(Config::from_text(bad, "test").is_err(), "{}", bad);
        }
    }

    /// Round 4: the lock screen's hold is a setting, 500 ms unless set,
    /// read from the top level and refused past 30 s.
    #[test]
    fn the_key_unlock_hold_is_a_setting() {
        // Round 7 (B): shipped at 500, now that the lock screen's channel
        // holds the latch for the whole lock.
        assert_eq!(Config::default().key_unlock_hold_ms, 500);
        assert_eq!(
            Config::default().key_unlock_hold_ms,
            crate::consent::DEFAULT_HOLD_MS
        );
        let c = Config::from_text("key_unlock_hold_ms = 2500\n", "test").unwrap();
        assert_eq!(c.key_unlock_hold_ms, 2500);
        assert_eq!(
            Config::from_text("key_unlock_hold_ms = 0\n", "test")
                .unwrap()
                .key_unlock_hold_ms,
            0
        );
        assert!(Config::from_text("key_unlock_hold_ms = 30001\n", "test").is_err());
        assert!(Config::from_text("key_unlock_hold_ms = -1\n", "test").is_err());
        assert!(unknown_keys("key_unlock_hold_ms = 1000\n").is_empty());
    }

    /// `[unlock]`: the lock screen's probe intervals ship at 1 s on mains
    /// and 2, 3 and 5 s on battery by power profile (round 19: Mike, after
    /// timing a sit-down, wanted the lock to see him sooner). Each may be
    /// set on its own; a zero, negative or unreadable one refuses to start,
    /// and a misspelt profile is named like any unknown key.
    #[test]
    fn the_unlock_cadence_defaults_parse_and_refuse_bad_values() {
        let c = Config::default();
        assert_eq!(c.unlock.probe_seconds, 1.0);
        assert_eq!(
            c.unlock.battery_probe_seconds,
            BatteryProbeSeconds {
                performance: 2.0,
                balanced: 3.0,
                power_saver: 5.0
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
                performance: 2.0,
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
        assert_eq!(c.unlock.probe_seconds, 1.0);
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

#[cfg(test)]
mod models_dir_tests {
    use super::*;

    /// The daemon refuses a models directory (or any directory above it)
    /// that is not root's or that others can write; the error names the
    /// path and the offending owner or mode.
    #[test]
    fn models_dir_must_be_root_owned_and_not_writable_by_others() {
        let p = Path::new("/home/a/.local/share/faceauth/models");
        assert!(models_dir_component_ok(p, 0, 0o040755).is_ok());
        assert!(models_dir_component_ok(p, 0, 0o040700).is_ok());
        let e = models_dir_component_ok(p, 1000, 0o040755)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains(p.to_str().unwrap()) && e.contains("uid 1000"),
            "{}",
            e
        );
        assert!(e.contains("omarchy-faceauth-models"), "{}", e);
        let e = models_dir_component_ok(p, 0, 0o040775)
            .unwrap_err()
            .to_string();
        assert!(e.contains("0775"), "{}", e);
        assert!(models_dir_component_ok(Path::new("/tmp"), 0, 0o041777).is_err());
        assert!(models_dir_component_ok(p, 0, 0o040757).is_err());
    }

    /// The installed location passes on a stock system; a directory under a
    /// user's home fails on the home component even when the leaf is root's.
    #[test]
    fn the_check_walks_every_ancestor() {
        if std::fs::metadata("/usr/share").is_ok() {
            assert!(check_models_dir(Path::new("/usr/share")).is_ok());
        }
        let home = std::env::var_os("HOME").map(PathBuf::from);
        if let Some(h) = home.filter(|h| h.starts_with("/home")) {
            assert!(check_models_dir(&h).is_err(), "{}", h.display());
        }
        assert!(check_models_dir(Path::new("/nonexistent/faceauth/models")).is_err());
    }

    /// The files are checked too, not only the directory: a weight the user
    /// owns (what `sudo cp -a` leaves) is refused by name, and a symlink is
    /// refused without being followed. An empty directory has nothing to
    /// refuse.
    #[test]
    fn the_files_in_the_directory_must_be_root_owned_too() {
        let base = std::env::temp_dir().join(format!("faceauth-models-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        assert!(check_models_files(&base).is_ok());
        let weight = base.join("glintr100.onnx");
        std::fs::write(&weight, b"x").unwrap();
        let e = check_models_files(&base).unwrap_err().to_string();
        assert!(e.contains("glintr100.onnx") && e.contains("uid"), "{}", e);
        std::fs::remove_file(&weight).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", &weight).unwrap();
        let e = check_models_files(&base).unwrap_err().to_string();
        assert!(e.contains("symlink"), "{}", e);
        let _ = std::fs::remove_dir_all(&base);
    }
}
