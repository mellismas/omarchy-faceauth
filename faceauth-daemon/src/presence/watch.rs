//! The watch's judgment, tick by tick: who is holding the away clock,
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

/// The default mode's tick. The secure mode looks every five seconds, the
/// default mode less often: it only needs to see that someone is there
/// within the away time.
pub const DEFAULT_MODE_TICK_SECONDS: f32 = 10.0;

/// How long after a check confirmed the user a side view (a face in the
/// chair turned past every enrolled look, which no check can read) holds
/// the default mode's clock. Someone reading a second screen turns back to
/// this one now and then, and the next check there renews it; someone
/// else turned that way after the user left holds it no longer than this.
/// A judgment, not a measurement.
pub const SIDE_VIEW_HOLD: Duration = Duration::from_secs(10 * 60);

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
/// exercised on made-up observations. A consent card runs a copy of the
/// live one on its own looks while it holds the camera, so its away clock
/// holds wherever the watch's would (`in_consent`).
#[derive(Clone)]
pub(crate) struct Watch {
    /// Who the journal lines are from: the watch itself, or its copy
    /// under a consent card.
    who: &'static str,
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
    /// When a check last confirmed the user (a passing check of the
    /// watch's, a consent card's match, or a face unlock); None until one
    /// has. A side view holds the clock only for `SIDE_VIEW_HOLD` after it.
    last_confirmed: Option<Instant>,
}

/// What one tick decided.
pub(crate) struct Step {
    pub(crate) state: State,
    /// Lock the session now (the away transition, or an earlier lock that
    /// failed and is retried).
    pub(crate) lock: bool,
    pub(crate) away_for: Option<f32>,
    /// Whether this look held the away clock: the face counted as the
    /// user's, or the same shape stood in for a hidden one.
    pub(crate) held: bool,
    /// Whether it was the shape alone that held it.
    pub(crate) by_shape: bool,
}

impl Watch {
    pub(crate) fn new(cfg: PresenceConfig) -> Watch {
        Watch {
            who: "presence",
            cfg,
            state: State::Unknown,
            last_seen: None,
            last_full: None,
            partial_logged: false,
            reference: None,
            locked_by_presence: false,
            identity_ok: true,
            identity_fails: 0,
            last_confirmed: None,
        }
    }

    /// This watch as a consent card's copy: the same state and rules, its
    /// journal lines marked as the card's.
    pub(crate) fn in_consent(mut self) -> Watch {
        self.who = "presence, under a consent card";
        self
    }

    /// A consent window that ran, or a face match, since the last tick: the
    /// user was at the desk then, and the away clock restarts from it.
    pub(crate) fn note_recent(&mut self, at: Instant) {
        if self.last_seen.map(|l| at > l).unwrap_or(true) {
            self.last_seen = Some(at);
            if self.state != State::Present {
                log::info!(
                    "{}: consent or match since the last tick; clock restarts",
                    self.who
                );
            }
        }
    }

    /// The user identified at `at` where the watch did not look (a consent
    /// card's scan matched them), at `frame` and `bbox`: the clock, the last
    /// full sighting and the shape reference move there, and the identity
    /// is good, as a passing check of the watch's own would leave them. So
    /// the shape hold for a hidden face runs from the latest real sighting,
    /// not from the last one the watch itself made.
    pub(crate) fn sighted(&mut self, at: Instant, frame: &Grey, bbox: [f32; 4]) {
        if self.last_full.is_none_or(|t| at > t) {
            self.last_full = Some(at);
            self.reference = Some((frame.clone(), bbox));
            self.identity_ok = true;
            self.identity_fails = 0;
            self.partial_logged = false;
            self.last_confirmed = Some(at);
        }
        if self.last_seen.is_none_or(|t| at > t) {
            self.last_seen = Some(at);
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
        // A face unlock confirmed the user; a password confirmed nobody at
        // the camera, so side views hold nothing until a check does.
        self.last_confirmed = by_face.then_some(now);
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
                self.last_confirmed = Some(now);
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
        // A side view (a face turned past every enrolled look, which no
        // check can read) holds as the user's only for `SIDE_VIEW_HOLD`
        // after a check confirmed them: the user reading a second screen,
        // not whoever sits down turned that way once they have gone.
        let side_view_holds = !obs.side_view
            || self
                .last_confirmed
                .is_some_and(|t| now.duration_since(t) < SIDE_VIEW_HOLD);
        let seen = obs.face
            && match mode {
                PresenceMode::Default => (self.identity_ok && side_view_holds) || obs.attentive,
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
        // at the session, and the shape under it holds nothing. A face the
        // mesh read no pose from arrives attentive when its check missed
        // wide (`observe::facing_the_session`), so it lands here too: the
        // shape tells a person from the wall, not one person from another.
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
                    log::info!("{}: the user's face is not seen but the same shape is in the chair ({:.2}); the clock is held", self.who, sim);
                    self.partial_logged = true;
                }
                true
            } else {
                if !self.partial_logged {
                    // Logged once per episode so the threshold can be set from
                    // what real hands and sheets score. A scene similarity, not
                    // a match score.
                    log::info!("{}: the user's face is not seen and the shape under the last box differs ({:.2} < {}); the clock runs", self.who, sim, SAME_SHAPE);
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
            log::info!("{}: nobody holds the clock this look (face {}, identity {:?}, frame {}, last full sighting {})", self.who, obs.face, obs.identity, obs.frame.is_some(), self.last_full.map(|t| format!("{:.0}s ago", now.duration_since(t).as_secs_f32())).unwrap_or_else(|| "never".into()));
        }
        let unseen = self.last_seen.map(|t| now.duration_since(t));
        let away_for = unseen.map(|d| d.as_secs_f32());
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
        } else if unseen
            .zip(cfg.away_for(mode))
            .map(|(u, limit)| u >= limit)
            .unwrap_or(false)
        {
            // The away time of the mode in force. The default mode set to
            // "never" has none: an empty chair there never goes away by time.
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
                "{}: {:?} -> {:?}{}",
                self.who,
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
            held: seen || held_by_shape,
            by_shape: held_by_shape && !seen,
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
    use crate::presence::{AwayTime, LockWord};

    /// A consent card's match is a sighting of the watch's too. Two and a
    /// half minutes after the watch last checked the user, past the secure
    /// mode's window for holding a hidden face by its shape, a near miss
    /// (a hand on the chin) locks; with the card's match of a moment ago
    /// fed in, its frame the shape reference, the same near miss is held.
    #[test]
    fn a_card_match_moves_the_watchs_shape_window() {
        let t0 = Instant::now();
        let mut frame = Grey::new(120, 120);
        frame
            .data
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i % 251) as u8);
        let bbox = [20.0, 10.0, 40.0, 40.0];
        let at_the_desk = |identity: Option<bool>, near_miss: bool| Observation {
            face: true,
            attentive: true,
            frame: Some(frame.clone()),
            bbox: Some(bbox),
            identity,
            near_miss,
            side_view: false,
        };
        let mut w = Watch::new(cfg());
        assert!(
            w.step(&at_the_desk(Some(true), false), t0, PresenceMode::Secure)
                .held
        );
        let later = t0 + Duration::from_secs(150);
        let near_miss = at_the_desk(Some(false), true);
        let mut lapsed = w.clone();
        assert!(lapsed.step(&near_miss, later, PresenceMode::Secure).lock);
        w.sighted(later - Duration::from_secs(1), &frame, bbox);
        let s = w.step(&near_miss, later, PresenceMode::Secure);
        assert!(s.held && !s.lock);
    }

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

    /// An empty chair locks after the away time of the mode in force, from
    /// the user's last sighting: `away_seconds` in the default mode and
    /// `secure_away_seconds` in the secure mode. With the live cadence that
    /// is the away time to the second, on mains and on battery.
    #[test]
    fn an_empty_chair_locks_after_each_modes_away_time() {
        for (mode, lock_tick) in [(PresenceMode::Default, 5), (PresenceMode::Secure, 7)] {
            let mut w = Watch::new(PresenceConfig {
                secure_away_seconds: 30.0,
                ..cfg()
            });
            let t0 = Instant::now();
            let mut looks = vec![obs(true, Some(true))];
            looks.extend((0..10).map(|_| obs(false, None)));
            // Seen at tick 1 (5 s); the default clock (20 s) runs out at
            // 25 s, tick 5, and the secure one (30 s) at 35 s, tick 7.
            assert_eq!(
                first_lock(&mut w, t0, &looks, mode),
                Some(lock_tick),
                "{:?}: an empty chair locks at its mode's away time",
                mode
            );
            assert_eq!(w.state, State::Away);
            assert_eq!(live_cadence(mode, false, 5.0), Some(20.0), "{:?}", mode);
            assert_eq!(live_cadence(mode, false, 10.0), Some(20.0), "{:?}", mode);
        }
    }

    /// The default mode's away time may be "never". An empty chair then
    /// never locks, however long it stays empty; the secure mode, which
    /// has no "never", still locks it on its own time.
    #[test]
    fn default_mode_set_to_never_leaves_an_empty_chair_unlocked() {
        let never = PresenceConfig {
            away_seconds: AwayTime::Word(LockWord::Never),
            ..cfg()
        };
        let t0 = Instant::now();
        let mut looks = vec![obs(true, Some(true))];
        looks.extend((0..2000).map(|_| obs(false, None)));
        let mut w = Watch::new(never.clone());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            None,
            "default, never: nearly three hours of an empty chair and no lock"
        );
        assert_ne!(w.state, State::Away);
        assert!(!w.locked_by_presence);
        let mut w = Watch::new(never);
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            Some(5),
            "secure: the empty chair locks at secure_away_seconds"
        );
    }

    /// The away time is read for the mode in force on every tick, so a
    /// switch at run time takes the other mode's time at once, measured
    /// from the same last sighting.
    #[test]
    fn a_mode_switch_at_run_time_takes_the_other_away_time() {
        let t0 = Instant::now();
        let at = |tick: u64| t0 + Duration::from_secs(5 * tick);
        // Default 60 s, secure 20 s: unseen for 20 s is not away in the
        // default mode, and the switch to secure locks on the next tick.
        let mut w = Watch::new(PresenceConfig {
            away_seconds: AwayTime::Seconds(60.0),
            secure_away_seconds: 20.0,
            ..cfg()
        });
        assert!(
            !w.step(&obs(true, Some(true)), at(1), PresenceMode::Default)
                .lock
        );
        for tick in 2..=5 {
            let step = w.step(&obs(false, None), at(tick), PresenceMode::Default);
            assert!(!step.lock, "default, tick {}", tick);
        }
        assert!(w.step(&obs(false, None), at(6), PresenceMode::Secure).lock);
        // Default "never": no lock for as long as the default mode is in
        // force; switched to secure, a chair empty past the secure time
        // locks at once.
        let mut w = Watch::new(PresenceConfig {
            away_seconds: AwayTime::Word(LockWord::Never),
            ..cfg()
        });
        assert!(
            !w.step(&obs(true, Some(true)), at(1), PresenceMode::Default)
                .lock
        );
        for tick in 2..=100 {
            let step = w.step(&obs(false, None), at(tick), PresenceMode::Default);
            assert!(!step.lock, "default, never, tick {}", tick);
        }
        assert!(
            w.step(&obs(false, None), at(101), PresenceMode::Secure)
                .lock
        );
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

    /// Default mode, the attention rule: the enrolled user holds the clock
    /// whatever they look at, so reading a paper beside the screen does not
    /// lock the desk; a face whose checks failed has to be
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
            side_view: false,
        };
        let hidden = Observation {
            face: false,
            attentive: false,
            frame: Some(frame.clone()),
            bbox: None,
            identity: None,
            near_miss: false,
            side_view: false,
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
            side_view: false,
        };
        let chin = |identity| Observation {
            face: true,
            attentive: false,
            frame: Some(frame.clone()),
            bbox: Some([20.0, 10.0, 40.0, 40.0]),
            identity,
            near_miss: false,
            side_view: false,
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
            side_view: false,
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
            side_view: false,
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
mod side_view_tests {
    use super::*;

    /// A side view: a face in the chair, turned past every enrolled look,
    /// read as no check, with no frame for the shape to hold on.
    fn side() -> Observation {
        Observation {
            side_view: true,
            ..obs_at(true, false, None)
        }
    }

    /// The user confirmed, then reading a second screen: the side views
    /// hold the clock for `SIDE_VIEW_HOLD` after that check and no longer,
    /// then the away time runs. Someone else turned the same way after the
    /// user left holds it no longer than that either.
    #[test]
    fn a_side_view_holds_only_for_a_while_after_a_confirmed_check() {
        let t0 = Instant::now();
        let mut w = Watch::new(cfg());
        w.step(&obs_at(true, true, Some(true)), t0, PresenceMode::Default);
        let hold = SIDE_VIEW_HOLD.as_secs();
        let mut first_lock = None;
        for s in (10..hold + 120).step_by(10) {
            if w.step(&side(), t0 + Duration::from_secs(s), PresenceMode::Default)
                .lock
            {
                first_lock = Some(s);
                break;
            }
        }
        let at = first_lock.expect("the side views stop holding");
        assert!(
            at > hold,
            "held through the hold ({} s): locked at {} s",
            hold,
            at
        );
        assert!(
            at <= hold + 30,
            "the away time runs from the end of the hold: {} s",
            at
        );
    }

    /// No check has confirmed anyone: a watch just started (someone faced
    /// the screen, so the clock runs, but no check has read them), or a
    /// session unlocked by password. Side views hold nothing then, and the
    /// away time runs as it would for an empty chair.
    #[test]
    fn a_side_view_holds_nothing_without_a_confirmed_check() {
        let t0 = Instant::now();
        let mut w = Watch::new(cfg());
        w.step(&obs_at(true, true, None), t0, PresenceMode::Default);
        let mut locked_at = None;
        for s in (10..120).step_by(10) {
            if w.step(&side(), t0 + Duration::from_secs(s), PresenceMode::Default)
                .lock
            {
                locked_at = Some(s);
                break;
            }
        }
        assert!(
            locked_at.is_some_and(|s| s <= 40),
            "never confirmed: {:?}",
            locked_at
        );
        let mut w = Watch::new(cfg());
        w.step(&obs_at(true, true, Some(true)), t0, PresenceMode::Default);
        w.resumed(t0 + Duration::from_secs(5), false);
        let mut locked_at = None;
        for s in (10..120).step_by(10) {
            if w.step(&side(), t0 + Duration::from_secs(s), PresenceMode::Default)
                .lock
            {
                locked_at = Some(s);
                break;
            }
        }
        assert!(
            locked_at.is_some_and(|s| s <= 40),
            "after a password: {:?}",
            locked_at
        );
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
