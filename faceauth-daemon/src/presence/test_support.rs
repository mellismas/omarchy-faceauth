//! Helpers the watch and lock tests share: observations, a config, and a
//! driver that runs the watch until it asks for the lock.

use super::config::{PresenceConfig, PresenceMode};
use super::observe::Observation;
use super::watch::Watch;
use std::time::{Duration, Instant};

pub(super) fn obs(face: bool, identity: Option<bool>) -> Observation {
    obs_at(face, true, identity)
}

pub(super) fn obs_at(face: bool, attentive: bool, identity: Option<bool>) -> Observation {
    Observation {
        face,
        attentive,
        frame: None,
        bbox: if face {
            Some([10.0, 10.0, 80.0, 80.0])
        } else {
            None
        },
        identity,
        near_miss: false,
    }
}

pub(super) fn cfg() -> PresenceConfig {
    PresenceConfig {
        user: "alice".into(),
        away_seconds: 20.0,
        ..Default::default()
    }
}

/// Drive the watch through `looks`, five seconds apart, and return the
/// tick (from 1) at which it first asked for the lock.
pub(super) fn first_lock(
    w: &mut Watch,
    t0: Instant,
    looks: &[Observation],
    mode: PresenceMode,
) -> Option<usize> {
    for (i, o) in looks.iter().enumerate() {
        let now = t0 + Duration::from_secs(5 * (i as u64 + 1));
        let step = w.step(o, now, mode);
        if step.lock {
            return Some(i + 1);
        }
    }
    None
}
