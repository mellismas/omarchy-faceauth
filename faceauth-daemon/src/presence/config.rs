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
    /// Zero keeps the mains cadence.
    pub battery_tick_seconds: f32,
    /// Seconds without the user before the session is locked.
    pub away_seconds: f32,
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

impl PresenceConfig {
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
}

impl Default for PresenceConfig {
    fn default() -> Self {
        PresenceConfig {
            enabled: false,
            user: String::new(),
            mode: PresenceMode::Default,
            tick_seconds: 5.0,
            battery_tick_seconds: 10.0,
            away_seconds: 20.0,
            obscured_face_lock: ObscuredFaceLock::Word(LockWord::Never),
            secure_obscured_face_lock: SECURE_OBSCURED_LOCK_MINUTES,
        }
    }
}

/// How strict the walk-away watch is.
///
/// `Default`: any face turned to the screen holds the lock off, whoever it
/// belongs to; the session locks once nobody has held it for
/// `away_seconds`. The enrolled user holds the clock whatever they are
/// looking at; a face whose identity check failed (twice running, so one
/// flaky read does not change the rule) has to be looking at the screen
/// to hold the clock. A hidden face (none found, or one found that neither
/// passes nor looks at the screen, with the same shape in the chair) holds
/// the clock for a while.
///
/// `Secure`: identity is checked on every tick and only a face that passes
/// holds the clock. The first failed check locks the session at once, an
/// empty chair locks after `away_seconds`, and no other face holds the
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
}

#[cfg(test)]
mod partial_tests {
    use super::*;

    /// Mike, 2026-09-24: the default mode ships with "never", the secure
    /// mode with two minutes; secure is bounded 1 to 10 minutes, the default
    /// takes "never" or minutes from 1.
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
