//! The `[presence]` config and the watch's two modes. The mode can be
//! switched while the daemon runs, so the one in force is kept apart from
//! the config it started with.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PresenceConfig {
    pub enabled: bool,
    /// Whose presence: the user whose templates are matched.
    pub user: String,
    /// How strict the watch is; see `PresenceMode`. The starting mode; the
    /// watched user may switch it at run time over the socket.
    pub mode: PresenceMode,
    pub tick_seconds: f32,
    /// On battery (no mains supply online) the tick stretches to this.
    /// Zero keeps the mains cadence. Clamped as the config loads, 0 to
    /// `BATTERY_TICK_MAX_SECONDS` (D3).
    pub battery_tick_seconds: f32,
    /// Default mode: the away time, how many seconds the clock may run with
    /// nobody holding it before the session is locked, or "never", when the
    /// default mode never locks the session by time.
    pub away_seconds: AwayTime,
    /// Secure mode: the away time in seconds. A number only: secure mode
    /// promises that only a verified face keeps the session open, so an
    /// empty chair always locks.
    pub secure_away_seconds: f32,
    /// Default mode: the obscured face lock time, how long a face that is
    /// partly covered or turned away (a hand on the chin, a look down) keeps
    /// the session open after the last clear sighting while the same shape
    /// stays in the chair. "never", the shipped value, locks only when the
    /// chair changes; a number is minutes, at least 1.
    pub obscured_face_lock: ObscuredFaceLock,
    /// Secure mode: the same, in minutes, 1 to 10. Secure mode promises that
    /// only a verified face keeps the session open, so this is bounded.
    pub secure_obscured_face_lock: u32,
}

/// The default mode's away time: a number of seconds, or the word "never".
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AwayTime {
    Seconds(f32),
    Word(LockWord),
}

/// The default mode's obscured face lock time: a number of minutes, or the
/// word "never".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ObscuredFaceLock {
    Minutes(u32),
    Word(LockWord),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockWord {
    Never,
}

/// Secure mode's obscured face lock time, in minutes: the shipped value and the
/// range a config may set (outside it the value is clamped, with a warning).
pub const SECURE_OBSCURED_LOCK_MINUTES: u32 = 2;
pub const SECURE_OBSCURED_LOCK_RANGE: (u32, u32) = (1, 10);

/// The longest battery tick a config may set. The walk-away watch and a
/// waiting consent card look at the chair once a tick on battery, so a
/// longer one would leave a user who left unnoticed for minutes (D3).
pub const BATTERY_TICK_MAX_SECONDS: f32 = 60.0;

impl PresenceConfig {
    /// The away time in `mode`: how long the clock may run with nobody
    /// holding it before the session locks. None is never, which only the
    /// default mode can be; the secure mode always has one. Validation keeps
    /// the seconds positive; a number too large for a Duration reads as the
    /// longest one.
    pub fn away_for(&self, mode: PresenceMode) -> Option<Duration> {
        let seconds = |s: f32| Duration::try_from_secs_f32(s).unwrap_or(Duration::MAX);
        match mode {
            PresenceMode::Secure => Some(seconds(self.secure_away_seconds)),
            PresenceMode::Default => match self.away_seconds {
                AwayTime::Word(LockWord::Never) => None,
                AwayTime::Seconds(s) => Some(seconds(s)),
            },
        }
    }

    /// The obscured face lock time in `mode`, from the last clear sighting;
    /// None is never.
    pub fn obscured_lock_for(&self, mode: PresenceMode) -> Option<Duration> {
        let minutes = |m: u32| Duration::from_secs(u64::from(m) * 60);
        match mode {
            PresenceMode::Secure => Some(minutes(
                self.secure_obscured_face_lock
                    .clamp(SECURE_OBSCURED_LOCK_RANGE.0, SECURE_OBSCURED_LOCK_RANGE.1),
            )),
            PresenceMode::Default => match self.obscured_face_lock {
                ObscuredFaceLock::Word(LockWord::Never) => None,
                ObscuredFaceLock::Minutes(m) => Some(minutes(m.max(1))),
            },
        }
    }

    /// Warnings for lock times the watch clamps, for the start-up log.
    pub fn obscured_lock_warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        let (lo, hi) = SECURE_OBSCURED_LOCK_RANGE;
        if !(lo..=hi).contains(&self.secure_obscured_face_lock) {
            w.push(format!(
                "secure_obscured_face_lock = {} is outside {} to {} minutes; using {}",
                self.secure_obscured_face_lock,
                lo,
                hi,
                self.secure_obscured_face_lock.clamp(lo, hi)
            ));
        }
        if self.obscured_face_lock == ObscuredFaceLock::Minutes(0) {
            w.push("obscured_face_lock = 0 is under 1 minute; using 1".into());
        }
        w
    }

    /// Bring `battery_tick_seconds` into 0 to `BATTERY_TICK_MAX_SECONDS`,
    /// as the config loads: a negative or unreadable value is 0, the mains
    /// cadence, and a longer one is the maximum (D3). The warning for the
    /// start-up log, when the value changed.
    pub fn clamp_battery_tick(&mut self) -> Option<String> {
        let was = self.battery_tick_seconds;
        let tick = if was.is_nan() {
            0.0
        } else {
            was.clamp(0.0, BATTERY_TICK_MAX_SECONDS)
        };
        if tick == was {
            return None;
        }
        self.battery_tick_seconds = tick;
        Some(format!(
            "battery_tick_seconds = {} is outside 0 to {} seconds; using {}{}",
            was,
            BATTERY_TICK_MAX_SECONDS,
            tick,
            if tick == 0.0 {
                " (the mains cadence)"
            } else {
                ""
            }
        ))
    }
}

impl Default for PresenceConfig {
    fn default() -> Self {
        PresenceConfig {
            enabled: false,
            user: String::new(),
            mode: PresenceMode::Default,
            tick_seconds: 5.0,
            battery_tick_seconds: 10.0,
            away_seconds: AwayTime::Seconds(20.0),
            secure_away_seconds: 20.0,
            obscured_face_lock: ObscuredFaceLock::Word(LockWord::Never),
            secure_obscured_face_lock: SECURE_OBSCURED_LOCK_MINUTES,
        }
    }
}

/// How strict the walk-away watch is.
///
/// `Default`: any face turned to the screen holds the lock off, whoever it
/// belongs to; the session locks once nobody has held it for
/// `away_seconds`, and never by time when that is "never". The enrolled user holds the clock whatever they are
/// looking at; a face whose identity check failed (twice running, so one
/// flaky read does not change the rule) has to be looking at the screen
/// to hold the clock. A hidden face (none found, or one found that neither
/// passes nor looks at the screen, with the same shape in the chair) holds
/// the clock for a while.
///
/// `Secure`: identity is checked on every tick and only a face that passes
/// holds the clock. The first failed check locks the session at once, an
/// empty chair locks after `secure_away_seconds`, and no other face holds the
/// clock, not one the gate read no signal from. The one allowance both
/// modes share is the hidden face: the user's own hand over it, or a look
/// down at a phone, with the same shape still in the chair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceMode {
    Default,
    Secure,
}

impl PresenceMode {
    pub fn parse(s: &str) -> Option<PresenceMode> {
        match s {
            "default" => Some(PresenceMode::Default),
            "secure" => Some(PresenceMode::Secure),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            PresenceMode::Default => "default",
            PresenceMode::Secure => "secure",
        }
    }
}

/// The mode in force, set from the config when the watch starts and
/// changed at run time by the watched user over the socket (it does not
/// persist; the config sets the starting mode at every start).
static MODE: AtomicU8 = AtomicU8::new(0);

pub fn presence_mode() -> PresenceMode {
    if MODE.load(Ordering::SeqCst) == 1 {
        PresenceMode::Secure
    } else {
        PresenceMode::Default
    }
}

pub fn set_presence_mode(mode: PresenceMode) {
    MODE.store(
        if mode == PresenceMode::Secure { 1 } else { 0 },
        Ordering::SeqCst,
    );
}

/// Why the secure mode is not offered on a camera without the strobe
/// controls: the refusal of a switch to it, and the watch's warning when
/// the config asks for it there.
pub const SECURE_NEEDS_STROBE: &str = "secure mode needs a camera whose IR light faceauth can flash, and this camera cannot; the walk-away lock runs in default mode";

/// Why a switch to the secure mode waits: the camera has not been opened
/// since faceauth started, so whether it can hold the secure mode is not
/// known yet. The watch's first look finds out within a tick.
pub const SECURE_NOT_KNOWN: &str = "the camera has not been opened since faceauth started, so whether it can hold secure mode is not known yet; try again in a few seconds";

/// The mode a watch runs in on a camera of `tier`, or one not opened yet
/// (None). The secure mode's promise, that only the user's own face holds
/// the clock, rests on the flash gate, so it is offered only where the
/// tier says so (`Tier::secure_available`): elsewhere the watch runs in the
/// default mode, and says so. Lowering it is the camera's limit, never a
/// setting.
pub fn mode_for_camera(mode: PresenceMode, tier: Option<crate::tier::Tier>) -> PresenceMode {
    match (mode, tier) {
        (PresenceMode::Secure, Some(t)) if !t.secure_available() => PresenceMode::Default,
        (mode, _) => mode,
    }
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    #[test]
    fn the_mode_switch_is_read_by_name() {
        assert_eq!(PresenceMode::parse("secure"), Some(PresenceMode::Secure));
        assert_eq!(PresenceMode::parse("default"), Some(PresenceMode::Default));
        assert_eq!(PresenceMode::parse("Secure"), None);
        set_presence_mode(PresenceMode::Secure);
        assert_eq!(presence_mode(), PresenceMode::Secure);
        set_presence_mode(PresenceMode::Default);
        assert_eq!(presence_mode(), PresenceMode::Default);
    }

    /// The secure mode runs only on a camera the flash gate can run on: on
    /// one without the strobe controls the watch runs in the default mode.
    /// Before the camera has been opened nothing is known, and the mode
    /// stands until the first look finds out.
    #[test]
    fn the_secure_mode_needs_a_camera_that_can_strobe() {
        use crate::tier::Tier::{NoFlash, RandomFlash};
        use PresenceMode::{Default, Secure};
        assert_eq!(mode_for_camera(Secure, Some(NoFlash)), Default);
        assert_eq!(mode_for_camera(Secure, Some(RandomFlash)), Secure);
        assert_eq!(mode_for_camera(Secure, None), Secure);
        for tier in [Some(NoFlash), Some(RandomFlash), None] {
            assert_eq!(mode_for_camera(Default, tier), Default);
        }
        assert!(SECURE_NEEDS_STROBE.contains("default"));
    }
}

#[cfg(test)]
mod partial_tests {
    use super::*;

    /// The default mode ships with "never", the secure mode with two
    /// minutes; secure is bounded 1 to 10 minutes, the default takes
    /// "never" or minutes from 1.
    #[test]
    fn obscured_face_lock_defaults_parse_and_clamp() {
        let c = PresenceConfig::default();
        assert_eq!(c.obscured_lock_for(PresenceMode::Default), None);
        assert_eq!(
            c.obscured_lock_for(PresenceMode::Secure),
            Some(Duration::from_secs(120))
        );
        assert!(c.obscured_lock_warnings().is_empty());
        let parse = |t: &str| -> PresenceConfig { toml::from_str(t).unwrap() };
        let c = parse("obscured_face_lock = 30\nsecure_obscured_face_lock = 5");
        assert_eq!(
            c.obscured_lock_for(PresenceMode::Default),
            Some(Duration::from_secs(1800))
        );
        assert_eq!(
            c.obscured_lock_for(PresenceMode::Secure),
            Some(Duration::from_secs(300))
        );
        let c = parse("obscured_face_lock = \"never\"");
        assert_eq!(c.obscured_lock_for(PresenceMode::Default), None);
        let c = parse("obscured_face_lock = 0\nsecure_obscured_face_lock = 60");
        assert_eq!(
            c.obscured_lock_for(PresenceMode::Default),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            c.obscured_lock_for(PresenceMode::Secure),
            Some(Duration::from_secs(600))
        );
        assert_eq!(c.obscured_lock_warnings().len(), 2);
        assert!(toml::from_str::<PresenceConfig>("obscured_face_lock = \"forever\"").is_err());
    }
}

#[cfg(test)]
mod away_tests {
    use super::*;

    /// The away time is per mode. The default mode takes a number of
    /// seconds or "never"; the secure mode takes seconds only, since it
    /// promises that only a verified face keeps the session open.
    /// Both ship at 20 s, and an older config's single away time becomes
    /// the default mode's.
    #[test]
    fn the_away_time_is_per_mode_and_only_the_default_mode_takes_never() {
        let s = Duration::from_secs;
        let c = PresenceConfig::default();
        assert_eq!(c.away_for(PresenceMode::Default), Some(s(20)));
        assert_eq!(c.away_for(PresenceMode::Secure), Some(s(20)));
        let parse = |t: &str| toml::from_str::<PresenceConfig>(t);
        for text in ["away_seconds = 45.0", "away_seconds = 45"] {
            let c = parse(text).unwrap();
            assert_eq!(c.away_seconds, AwayTime::Seconds(45.0), "{}", text);
            assert_eq!(c.away_for(PresenceMode::Default), Some(s(45)));
            assert_eq!(c.away_for(PresenceMode::Secure), Some(s(20)));
        }
        let c = parse("away_seconds = \"never\"\nsecure_away_seconds = 30.0").unwrap();
        assert_eq!(c.away_seconds, AwayTime::Word(LockWord::Never));
        assert_eq!(c.away_for(PresenceMode::Default), None);
        assert_eq!(c.away_for(PresenceMode::Secure), Some(s(30)));
        assert!(
            toml::to_string(&c)
                .unwrap()
                .contains("away_seconds = \"never\""),
            "\"never\" is written back as it was read"
        );
        for bad in [
            "away_seconds = \"soon\"",
            "away_seconds = \"Never\"",
            "secure_away_seconds = \"never\"",
        ] {
            assert!(parse(bad).is_err(), "{} should not parse", bad);
        }
        for refused in [
            "[presence]\naway_seconds = 0",
            "[presence]\naway_seconds = -5.0",
            "[presence]\nsecure_away_seconds = 0",
            "[presence]\nsecure_away_seconds = -1.0",
            "[presence]\nsecure_away_seconds = \"never\"",
        ] {
            assert!(
                crate::config::Config::from_text(refused, "test").is_err(),
                "{} should refuse",
                refused
            );
        }
        crate::config::Config::from_text("[presence]\naway_seconds = \"never\"", "test").unwrap();
    }
}

#[cfg(test)]
mod battery_tick_tests {
    use super::*;

    /// D3: the battery tick is brought into 0 to 60 seconds as the config
    /// loads. A negative or unreadable value is the mains cadence, a
    /// longer one the maximum, and a value in range stays as written.
    #[test]
    fn the_battery_tick_is_clamped_as_the_config_loads() {
        let tick = |t: &str| {
            crate::config::Config::from_text(&format!("[presence]\n{}", t), "test")
                .unwrap()
                .presence
                .battery_tick_seconds
        };
        assert_eq!(tick(""), 10.0, "the shipped value");
        for (text, want) in [
            ("battery_tick_seconds = 300", BATTERY_TICK_MAX_SECONDS),
            ("battery_tick_seconds = 1e30", BATTERY_TICK_MAX_SECONDS),
            ("battery_tick_seconds = inf", BATTERY_TICK_MAX_SECONDS),
            ("battery_tick_seconds = -5.0", 0.0),
            ("battery_tick_seconds = nan", 0.0),
            ("battery_tick_seconds = 0", 0.0),
            ("battery_tick_seconds = 30.5", 30.5),
            ("battery_tick_seconds = 60", 60.0),
        ] {
            assert_eq!(tick(text), want, "{}", text);
        }
        let mut c = PresenceConfig {
            battery_tick_seconds: 120.0,
            ..Default::default()
        };
        let w = c
            .clamp_battery_tick()
            .expect("a warning for the start-up log");
        assert!(w.contains("using 60"), "{}", w);
        assert_eq!(
            c.clamp_battery_tick(),
            None,
            "a value in range is not a warning"
        );
    }
}
