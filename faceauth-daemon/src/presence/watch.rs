//! The watch's judgement, tick by tick: who is holding the away clock,
//! when a hidden face still counts, and when the session should lock. It
//! takes observations rather than frames, so the tests can drive it
//! through a whole sitting.

use super::config::{PresenceConfig, PresenceMode};
use super::observe::Observation;
#[cfg(test)]
use super::test_support::{cfg, first_lock, obs, obs_at};
use faceauth_engine::Grey;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// Ticks between identity checks in the default mode (detection alone
/// runs every tick, on mains and on battery). The secure mode checks
/// identity on every tick.
pub const IDENTIFY_EVERY: u32 = 3;

/// The default mode's tick. Mike, 2026-09-24: secure mode looks every five
/// seconds, the default mode less often; the default mode only needs to see
/// that someone is there within the away time.
pub const DEFAULT_MODE_TICK_SECONDS: f32 = 10.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Present,
    Away,
    Stranger,
    Unknown,
}

/// The watch's state between ticks, and the rules that move it: what
/// `run` drives from the camera, kept apart from it so the rules can be
/// exercised on made-up observations.
pub(crate) struct Watch {
    cfg: PresenceConfig,
    pub(crate) state: State,
    last_seen: Option<Instant>,
    last_full: Option<Instant>,
    partial_logged: bool,
    /// The frame and face box of the last sighting whose identity passed.
    reference: Option<(Grey, [f32; 4])>,
    pub(crate) locked_by_presence: bool,
    /// Whether the last identity checks passed. True until a check fails
    /// (twice running in the default mode, once in the secure mode); a
    /// passing check restores it.
    identity_ok: bool,
    identity_fails: u32,
}

/// What one tick decided.
pub(crate) struct Step {
    pub(crate) state: State,
    /// Lock the session now (the away transition, or an earlier lock that
    /// failed and is retried).
    pub(crate) lock: bool,
    pub(crate) away_for: Option<f32>,
}

impl Watch {
    pub(crate) fn new(cfg: PresenceConfig) -> Watch {
        Watch {
            cfg,
            state: State::Unknown,
            last_seen: None,
            last_full: None,
            partial_logged: false,
            reference: None,
            locked_by_presence: false,
            identity_ok: true,
            identity_fails: 0,
        }
    }

    /// A consent window that ran, or a face match, since the last tick: the
    /// user was at the desk then, and the away clock restarts from it.
    pub(crate) fn note_recent(&mut self, at: Instant) {
        if self.last_seen.map(|l| at > l).unwrap_or(true) {
            self.last_seen = Some(at);
            if self.state != State::Present {
                log::info!("presence: consent or match since the last tick; clock restarts");
            }
        }
    }

    /// The session is locked (by this watch, or by a consent request whose
    /// lock this watch takes over): the camera is left to the lock screen
    /// until `SessionLock::resumed` says it is open again.
    pub(crate) fn locked(&mut self) {
        self.locked_by_presence = true;
        self.state = State::Away;
    }

    /// The session unlocked, by a face match newer than the lock or by
    /// other means. A fresh absence clock either way: after a face the
    /// user is present; after a password nobody has been seen yet, and the
    /// next identity check decides.
    pub(crate) fn resumed(&mut self, now: Instant, by_face: bool) {
        self.locked_by_presence = false;
        self.last_seen = Some(now);
        self.identity_ok = true;
        self.identity_fails = 0;
        self.state = if by_face {
            State::Present
        } else {
            State::Unknown
        };
    }

    /// One look's worth of the rules.
    pub(crate) fn step(&mut self, obs: &Observation, now: Instant, mode: PresenceMode) -> Step {
        let cfg = &self.cfg;
        if let Some(id) = obs.identity {
            if id {
                self.identity_fails = 0;
                self.identity_ok = true;
            } else {
                self.identity_fails += 1;
                // Default: two checks running, so one flaky read does not
                // turn the user into a stranger. Secure: one is enough.
                let strikes = if mode == PresenceMode::Secure { 1 } else { 2 };
                if self.identity_fails >= strikes {
                    self.identity_ok = false;
                }
            }
        }
        // Who holds the clock this look (Q9). Default: any face turned to
        // the screen, so a laptop handed over stays open while it is looked
        // at; the enrolled user holds it whatever they look at, since a
        // check confirmed them and reading a paper beside the screen is
        // not leaving. Secure: only a face that passed this tick's
        // identity check; an unchecked face, or one the gate read no
        // signal from, holds nothing.
        let seen = obs.face
            && match mode {
                PresenceMode::Default => self.identity_ok || obs.attentive,
                PresenceMode::Secure => obs.identity == Some(true),
            };
        // A hidden face may still be the user in the chair: a hand or a
        // sheet over the face leaves the shape under the last face box,
        // standing up replaces it with the wall. Hidden covers a face the
        // detector lost and one it still finds but cannot read (a hand on
        // the chin or a look down at a phone fits no attentive pose and
        // embeds as nobody), so the hold runs for any look that holds
        // nothing, in both modes: the secure mode's first-miss lock is for
        // a chair whose shape has changed, not for the user's own hand.
        // Leaning on a hand or leaning in to read keeps the face turned to
        // the screen while it scores just under the line, or leaves the
        // strobe no signal to read; those are hidden too. Only a face turned
        // to the screen that misses by a wide margin is someone else looking
        // at the session, and the shape under it holds nothing.
        let stranger = obs.face && obs.attentive && obs.identity == Some(false) && !obs.near_miss;
        let hidden = !stranger;
        let held_by_shape = if !seen
            && hidden
            && partial_holds(now, self.last_full, cfg.obscured_lock_for(mode))
        {
            let sim = match (self.reference.as_ref(), obs.frame.as_ref()) {
                (Some(r), Some(f)) => same_shape(r, f),
                _ => 0.0,
            };
            if sim >= SAME_SHAPE {
                if !self.partial_logged {
                    log::info!("presence: the user's face is not seen but the same shape is in the chair ({:.2}); the clock is held", sim);
                    self.partial_logged = true;
                }
                true
            } else {
                if !self.partial_logged {
                    // Logged once per episode so the threshold can be set from
                    // what real hands and sheets score. A scene similarity, not
                    // a match score.
                    log::info!("presence: the user's face is not seen and the shape under the last box differs ({:.2} < {}); the clock runs", sim, SAME_SHAPE);
                    self.partial_logged = true;
                }
                false
            }
        } else {
            false
        };
        // Secure: the first failed check is the lock, whatever the clock
        // says, unless the shape holds. The check runs on every tick there,
        // so a stranger who sits down is out within one tick.
        let missed = mode == PresenceMode::Secure
            && obs.face
            && obs.identity == Some(false)
            && !held_by_shape;
        if held_by_shape {
            self.last_seen = Some(now);
        }
        if seen {
            self.last_seen = Some(now);
            self.last_full = Some(now);
            self.partial_logged = false;
            // The shape reference comes only from a look whose identity
            // passed: a stranger's torso must not become the shape that
            // holds the clock for a hidden face (C1).
            if obs.identity == Some(true) {
                if let (Some(f), Some(b)) = (obs.frame.as_ref(), obs.bbox) {
                    self.reference = Some((f.clone(), b));
                }
            }
        } else if !held_by_shape && (self.state == State::Present || self.state == State::Stranger)
        {
            log::info!("presence: nobody holds the clock this look (face {}, identity {:?}, frame {}, last full sighting {})", obs.face, obs.identity, obs.frame.is_some(), self.last_full.map(|t| format!("{:.0}s ago", now.duration_since(t).as_secs_f32())).unwrap_or_else(|| "never".into()));
        }
        let away_for = self.last_seen.map(|t| now.duration_since(t).as_secs_f32());
        // A face holding the clock whose check failed is reported as a
        // stranger (default mode only; the secure mode has locked by now),
        // so the shell can say who is keeping the session open.
        let next = if missed {
            State::Away
        } else if seen {
            if self.identity_ok {
                State::Present
            } else {
                State::Stranger
            }
        } else if away_for.map(|s| s >= cfg.away_seconds).unwrap_or(false) {
            State::Away
        } else if held_by_shape {
            self.state // the user, face hidden: what the shell shows stays
        } else if obs.face && !self.identity_ok {
            State::Stranger
        } else if self.state == State::Unknown {
            State::Unknown
        } else {
            self.state // in the away window: keep the previous state
        };
        if next != self.state {
            log::info!(
                "presence: {:?} -> {:?}{}",
                self.state,
                next,
                away_for
                    .map(|s| format!(" (unseen {:.0}s)", s))
                    .unwrap_or_default()
            );
        }
        // Lock on the away transition, and keep trying every tick while away
        // until it succeeds: a failed lock must not leave the machine open.
        let lock = next == State::Away && !self.locked_by_presence;
        if next == State::Present {
            self.locked_by_presence = false;
        }
        self.state = next;
        Step {
            state: next,
            lock,
            away_for,
        }
    }
}

/// Does this tick check identity? Identity is the dear part of a tick (the
/// embedder costs several times the detector). The secure mode pays it on
/// every tick, since one failed check is the lock there and a stranger
/// must be out within a tick. The default mode pays it on its cadence
/// while present, and every other tick while a face is there that has not
/// been confirmed.
pub(crate) fn identify_this_tick(mode: PresenceMode, tick: u32, every: u32, state: State) -> bool {
    mode == PresenceMode::Secure
        || tick.is_multiple_of(every.max(1))
        || (state != State::Present && tick.is_multiple_of(2))
}

/// Seconds between looks: the configured tick (the battery tick on
/// battery), and in the default mode never under
/// `DEFAULT_MODE_TICK_SECONDS`.
pub fn tick_for(cfg: &PresenceConfig, mode: PresenceMode, on_battery: bool) -> f32 {
    let base = if on_battery && cfg.battery_tick_seconds > 0.0 {
        cfg.battery_tick_seconds
    } else {
        cfg.tick_seconds
    };
    if mode == PresenceMode::Default {
        base.max(DEFAULT_MODE_TICK_SECONDS)
    } else {
        base
    }
}

/// How alike the region under the last face box must look, against the
/// frame of the last full sighting, for "still there, face hidden".
/// Measured 2026-09-22: a hand over part of the face 1.00, a sheet over it
/// 0.95, the face fully covered 0.79, the chair empty -0.34.
pub const SAME_SHAPE: f32 = 0.60;

/// Is the person still in the chair? No face cleared the threshold, but the
/// shoulders and torso under where the face was look as they did at the
/// last full sighting. A hand over the face leaves them alone; standing up
/// replaces them with the wall.
pub fn same_shape(reference: &(Grey, [f32; 4]), frame: &Grey) -> f32 {
    let r = faceauth_engine::motion::below(reference.1, frame.width, frame.height);
    faceauth_engine::motion::similarity(&reference.0, frame, r)
}

/// Does a hidden-face sighting at `now` hold off the away clock? Only after
/// a clear sighting, and within `limit` of it (None: no limit).
pub fn partial_holds(now: Instant, last_full: Option<Instant>, limit: Option<Duration>) -> bool {
    last_full
        .map(|t| limit.is_none_or(|l| now.duration_since(t) < l))
        .unwrap_or(false)
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    /// The live cadence, as `run` computes it: the user passes identity
    /// checks for three ticks and leaves; from tick 4 on a stranger (an
    /// attentive face that fails every check it gets) or nobody is in
    /// view. Returns the seconds from the user's last sighting to the lock,
    /// or None when 200 ticks pass without one.
    fn live_cadence(mode: PresenceMode, stranger: bool, tick_s: f32) -> Option<f32> {
        let cfg = PresenceConfig {
            tick_seconds: tick_s,
            ..cfg()
        };
        let mut w = Watch::new(cfg.clone());
        let t0 = Instant::now();
        for tick in 1u32..200 {
            let now = t0 + Duration::from_secs_f32(tick_s * tick as f32);
            let identify = identify_this_tick(mode, tick, IDENTIFY_EVERY, w.state);
            let user_here = tick <= 3;
            let face = user_here || stranger;
            let identity = if identify && face {
                Some(user_here)
            } else {
                None
            };
            if w.step(&obs(face, identity), now, mode).lock {
                return Some(tick_s * (tick - 3) as f32);
            }
        }
        None
    }

    /// Q9: in the default mode any attentive face holds the lock off, so a
    /// stranger who sits down stays unlocked past away_seconds and for as
    /// long as they look at the screen. They are reported as a stranger
    /// once two checks have failed.
    #[test]
    fn default_mode_a_stranger_present_past_away_seconds_stays_unlocked() {
        let mut w = Watch::new(cfg());
        let t0 = Instant::now();
        let mut looks = vec![obs(true, Some(true))];
        looks.extend((0..12).map(|_| obs(true, Some(false))));
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            None,
            "default: a face looking at the screen holds the clock, whoever it is"
        );
        assert_eq!(w.state, State::Stranger);
        assert!(!w.locked_by_presence);
    }

    /// Q9: the secure mode checks identity on every tick and locks on the
    /// first failed check, so a stranger is out within one tick of sitting
    /// down, whatever the away clock says.
    #[test]
    fn secure_mode_locks_within_one_tick_of_the_first_failed_check() {
        let mut w = Watch::new(cfg());
        let t0 = Instant::now();
        let looks = vec![obs(true, Some(true)), obs(true, Some(false))];
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            Some(2),
            "secure: the first failed check is the lock"
        );
        assert_eq!(w.state, State::Away);
        // With the live cadence the check runs on every tick, so the lock
        // comes one tick after the user's last sighting, on mains and on
        // battery alike; the default mode never locks on the stranger.
        assert_eq!(live_cadence(PresenceMode::Secure, true, 5.0), Some(5.0));
        assert_eq!(live_cadence(PresenceMode::Secure, true, 10.0), Some(10.0));
        assert_eq!(live_cadence(PresenceMode::Default, true, 5.0), None);
        assert_eq!(live_cadence(PresenceMode::Default, true, 10.0), None);
    }

    /// An empty chair locks after away_seconds in both modes, from the
    /// user's last sighting: with the live cadence that is the away time to
    /// the second, on mains and on battery.
    #[test]
    fn an_empty_chair_locks_after_away_seconds_in_both_modes() {
        for mode in [PresenceMode::Default, PresenceMode::Secure] {
            let mut w = Watch::new(cfg());
            let t0 = Instant::now();
            let mut looks = vec![obs(true, Some(true))];
            looks.extend((0..8).map(|_| obs(false, None)));
            // Seen at tick 1 (5 s); the clock runs out at 25 s, tick 5.
            assert_eq!(
                first_lock(&mut w, t0, &looks, mode),
                Some(5),
                "{:?}: an empty chair locks at away_seconds",
                mode
            );
            assert_eq!(w.state, State::Away);
            assert_eq!(live_cadence(mode, false, 5.0), Some(20.0), "{:?}", mode);
            assert_eq!(live_cadence(mode, false, 10.0), Some(20.0), "{:?}", mode);
        }
    }

    /// The secure mode identifies on every tick; the default mode on its
    /// cadence while present and every other tick while unconfirmed.
    #[test]
    fn the_secure_mode_checks_identity_on_every_tick() {
        for tick in 1..=12 {
            assert!(identify_this_tick(
                PresenceMode::Secure,
                tick,
                3,
                State::Present
            ));
            assert!(identify_this_tick(
                PresenceMode::Secure,
                tick,
                3,
                State::Unknown
            ));
            assert_eq!(
                identify_this_tick(PresenceMode::Default, tick, 3, State::Present),
                tick % 3 == 0
            );
            assert_eq!(
                identify_this_tick(PresenceMode::Default, tick, 3, State::Unknown),
                tick % 3 == 0 || tick % 2 == 0
            );
        }
    }

    /// Default mode, the attention rule: the enrolled user is held to the
    /// attention setting (off by default), so reading a paper beside the
    /// screen does not lock the desk; a face whose checks failed has to be
    /// looking at the screen to hold the clock. One failed check is
    /// tolerated before that applies.
    #[test]
    fn default_mode_a_stranger_holds_the_clock_only_while_attentive() {
        let t0 = Instant::now();
        // The user, confirmed, then turned away for a minute: still present.
        let mut looks = vec![obs(true, Some(true))];
        looks.extend(
            (0..12).map(|i| obs_at(true, false, if i % 3 == 2 { Some(true) } else { None })),
        );
        let mut w = Watch::new(cfg());
        assert_eq!(first_lock(&mut w, t0, &looks, PresenceMode::Default), None);
        assert_eq!(w.state, State::Present);
        // A stranger turned away: after the second failed check the face no
        // longer holds the clock, and the lock comes at away_seconds from
        // the last look that did (tick 2, the tolerated first miss).
        let looks = vec![
            obs(true, Some(true)),
            obs_at(true, false, Some(false)),
            obs_at(true, false, Some(false)),
            obs_at(true, false, None),
            obs_at(true, false, None),
            obs_at(true, false, None),
            obs_at(true, false, None),
        ];
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            Some(6),
            "default: a stranger not looking at the screen holds nothing"
        );
        // The same stranger looking at the screen holds it.
        let looks = vec![
            obs(true, Some(true)),
            obs_at(true, true, Some(false)),
            obs_at(true, true, Some(false)),
            obs_at(true, true, None),
            obs_at(true, true, None),
            obs_at(true, true, None),
            obs_at(true, true, None),
        ];
        let mut w = Watch::new(cfg());
        assert_eq!(first_lock(&mut w, t0, &looks, PresenceMode::Default), None);
        assert_eq!(w.state, State::Stranger);
    }

    /// Secure mode: only a face that passed this tick's check holds the
    /// clock. An unchecked face (the gate read no signal) holds nothing,
    /// and is not a lock either: the away clock decides.
    #[test]
    fn secure_mode_an_unconfirmed_face_neither_holds_nor_locks() {
        let mut w = Watch::new(cfg());
        let t0 = Instant::now();
        let mut looks = vec![obs(true, Some(true))];
        looks.extend((0..8).map(|_| obs(true, None)));
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            Some(5),
            "secure: an unconfirmed face lets the clock run out"
        );
    }

    /// A hidden face (no face found) holds the clock in both modes, and
    /// only with a matching shape. Without a reference frame there is no
    /// shape, so the hold does not apply and the clock runs.
    #[test]
    fn a_hidden_face_holds_the_clock_in_both_modes_and_only_with_a_shape() {
        let mut frame = Grey::new(120, 120);
        frame
            .data
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i % 251) as u8);
        let seen = Observation {
            face: true,
            attentive: true,
            frame: Some(frame.clone()),
            bbox: Some([20.0, 10.0, 40.0, 40.0]),
            identity: Some(true),
            near_miss: false,
        };
        let hidden = Observation {
            face: false,
            attentive: false,
            frame: Some(frame.clone()),
            bbox: None,
            identity: None,
            near_miss: false,
        };
        let mut looks = vec![seen.clone()];
        looks.extend((0..8).map(|_| hidden.clone()));
        let t0 = Instant::now();
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            None,
            "default: the same shape under the box holds the clock"
        );
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            None,
            "secure: the same shape holds it too"
        );
        // The reference is taken only from a look whose identity passed: a
        // sighting between checks holds the clock itself but leaves no
        // shape to hold it for a hidden face (C1), so a stranger's torso
        // never becomes the reference.
        let unchecked = Observation {
            identity: None,
            near_miss: false,
            ..seen.clone()
        };
        let mut looks = vec![unchecked];
        looks.extend((0..8).map(|_| hidden.clone()));
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            Some(5)
        );
        let stranger = Observation {
            identity: Some(false),
            near_miss: false,
            ..seen.clone()
        };
        let mut looks = vec![seen.clone(), stranger.clone(), stranger];
        looks.extend((0..8).map(|_| hidden.clone()));
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            None,
            "the reference from the user's own sighting still holds for the hidden face"
        );
    }

    /// A face the detector still finds but that neither passes its check
    /// nor looks at the screen (a hand on the chin: the mesh reads no
    /// attentive pose and the crop embeds as nobody) is hidden too, and the
    /// same shape holds the clock in both modes. Before the mesh the five
    /// points called that face attentive and it held on its own.
    #[test]
    fn a_partly_hidden_face_holds_the_clock_through_the_shape_in_both_modes() {
        let mut frame = Grey::new(120, 120);
        frame
            .data
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i % 251) as u8);
        let seen = Observation {
            face: true,
            attentive: true,
            frame: Some(frame.clone()),
            bbox: Some([20.0, 10.0, 40.0, 40.0]),
            identity: Some(true),
            near_miss: false,
        };
        let chin = |identity| Observation {
            face: true,
            attentive: false,
            frame: Some(frame.clone()),
            bbox: Some([20.0, 10.0, 40.0, 40.0]),
            identity,
            near_miss: false,
        };
        // Between checks the look carries no verdict; on a check the
        // covered crop fails. Neither holds by itself.
        let mut looks = vec![seen.clone()];
        looks.extend((0..8).map(|i| chin(if i % 3 == 2 { Some(false) } else { None })));
        let t0 = Instant::now();
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            None,
            "default: the shape under the box holds for a face the mesh cannot read"
        );
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            None,
            "secure: the user's own hand over the face is not a stranger"
        );
        // A different scene under the box (the user left, someone else's
        // torso, or the wall) holds nothing.
        let mut other = Grey::new(120, 120);
        other.data.iter_mut().for_each(|v| *v = 200);
        let mut looks = vec![seen];
        looks.extend((0..14).map(|i| Observation {
            frame: Some(other.clone()),
            ..chin(if i % 3 == 2 { Some(false) } else { None })
        }));
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            Some(10),
            "default: two failed checks, then the clock runs out"
        );
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            Some(4),
            "secure: the first failed check on a changed chair locks at once"
        );
    }

    /// A face turned to the screen that fails its check is a stranger
    /// looking at the session, not a hidden user, whatever the shape under
    /// it: the secure mode locks on the first such check and the default
    /// mode runs its clock once the two strikes are in.
    #[test]
    fn an_attentive_face_that_fails_its_check_gets_no_shape_hold() {
        let mut frame = Grey::new(120, 120);
        frame
            .data
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i % 251) as u8);
        let seen = Observation {
            face: true,
            attentive: true,
            frame: Some(frame.clone()),
            bbox: Some([20.0, 10.0, 40.0, 40.0]),
            identity: Some(true),
            near_miss: false,
        };
        let stranger = Observation {
            identity: Some(false),
            near_miss: false,
            ..seen.clone()
        };
        let mut looks = vec![seen];
        looks.extend((0..8).map(|_| stranger.clone()));
        let t0 = Instant::now();
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            Some(2),
            "secure: the first failed check on a face looking at the screen locks"
        );
    }

    /// Secure mode, the user leaning on a hand or leaning in to read: the
    /// face stays turned to the screen, the check just misses or the strobe
    /// reads nothing, and the same shape in the chair holds the clock. A
    /// face that misses by a wide margin is a stranger and locks at once,
    /// shape or not; a near miss over a changed chair holds nothing.
    #[test]
    fn secure_mode_holds_a_near_miss_or_an_unread_face_through_the_shape() {
        let mut frame = Grey::new(120, 120);
        frame
            .data
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i % 251) as u8);
        let seen = Observation {
            face: true,
            attentive: true,
            frame: Some(frame.clone()),
            bbox: Some([20.0, 10.0, 40.0, 40.0]),
            identity: Some(true),
            near_miss: false,
        };
        let near = Observation {
            identity: Some(false),
            near_miss: true,
            ..seen.clone()
        };
        let unread = Observation {
            identity: None,
            ..seen.clone()
        };
        let t0 = Instant::now();
        for (what, look) in [("near miss", &near), ("no signal", &unread)] {
            let mut looks = vec![seen.clone()];
            looks.extend((0..8).map(|_| look.clone()));
            let mut w = Watch::new(cfg());
            assert_eq!(
                first_lock(&mut w, t0, &looks, PresenceMode::Secure),
                None,
                "secure: a {} with the same shape holds",
                what
            );
        }
        let far = Observation {
            identity: Some(false),
            near_miss: false,
            ..seen.clone()
        };
        let mut looks = vec![seen.clone(), far];
        looks.extend((0..4).map(|_| unread.clone()));
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            Some(2),
            "secure: a wide miss on a face turned to the screen locks at once"
        );
        let mut other = Grey::new(120, 120);
        other.data.iter_mut().for_each(|v| *v = 200);
        let mut looks = vec![seen.clone()];
        looks.extend((0..4).map(|_| Observation {
            frame: Some(other.clone()),
            ..near.clone()
        }));
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            Some(2),
            "secure: a near miss over a changed chair locks"
        );
    }

    /// Secure mode looks every tick (5 s, 10 s on battery); the default mode
    /// looks every 10 s.
    #[test]
    fn the_default_mode_looks_less_often_than_the_secure_mode() {
        let c = PresenceConfig::default();
        assert_eq!(tick_for(&c, PresenceMode::Secure, false), 5.0);
        assert_eq!(tick_for(&c, PresenceMode::Secure, true), 10.0);
        assert_eq!(tick_for(&c, PresenceMode::Default, false), 10.0);
        assert_eq!(tick_for(&c, PresenceMode::Default, true), 10.0);
    }
}

#[cfg(test)]
mod partial_tests {
    use super::*;

    #[test]
    fn a_partial_face_holds_the_clock_only_after_a_full_sighting_and_only_for_the_hold() {
        let now = Instant::now();
        let two = Some(Duration::from_secs(120));
        assert!(
            !partial_holds(now, None, two),
            "never seen in full: a weak blob is not the user"
        );
        assert!(!partial_holds(now, None, None));
        assert!(partial_holds(now, Some(now - Duration::from_secs(30)), two));
        assert!(!partial_holds(
            now,
            Some(now - Duration::from_secs(121)),
            two
        ));
        assert!(
            partial_holds(now, Some(now - Duration::from_secs(4 * 3600)), None),
            "no limit holds as long as the shape does"
        );
    }
}
