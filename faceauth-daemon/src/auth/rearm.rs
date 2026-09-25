//! The waits between rounds of a consent request: the rearm gate that
//! decides look by look whether the nods may arm again, the hold, and the
//! away clock that ends a request once its user has left.

use super::consent_flow::Round;
#[cfg(test)]
use crate::consent::Answer;
use crate::consent::ConsentState;
use anyhow::Result;
use std::time::{Duration, Instant};

/// Whether the nods may be armed again while a request waits, decided
/// look by look (Q8). The nods arm on the enrolled face attentive at the
/// camera, the lock screen's rule; after a nod window passed unanswered
/// they arm only once that face has been away from the card for a look
/// and is back, so a face that merely stays in view is not a re-arm and
/// there is no standing nod loop. An attentive face is asked its identity
/// before it arms: a stranger at the desk never re-arms a scan.
pub struct RearmGate {
    need_away: bool,
    away_seen: bool,
    /// How many failed identity checks in a row count a face as not the
    /// user for the away clock: one in secure mode, two in default.
    strikes: u32,
    identity_fails: u32,
}

/// What one look decided.
#[derive(Debug, PartialEq)]
pub enum Looked {
    /// Nothing to arm; the away clock ran if the user was not seen.
    Wait { user_seen: bool },
    /// An attentive face whose identity this look did not check: look
    /// again with the identity check before arming on it.
    Identify,
    /// The enrolled face is attentive at the camera and was away: arm.
    Arm,
}

impl RearmGate {
    pub fn new(need_away: bool, mode: crate::presence::PresenceMode) -> Self {
        RearmGate {
            need_away,
            away_seen: false,
            strikes: if mode == crate::presence::PresenceMode::Secure {
                1
            } else {
                2
            },
            identity_fails: 0,
        }
    }

    /// Feed one look: a face seen, attentive, and the identity check's
    /// verdict when one ran.
    pub fn look(&mut self, face: bool, attentive: bool, identity: Option<bool>) -> Looked {
        match identity {
            Some(true) => self.identity_fails = 0,
            Some(false) => self.identity_fails += 1,
            None => {}
        }
        let user_seen = face && self.identity_fails < self.strikes;
        let attentive_user = face && attentive && identity != Some(false);
        if !attentive_user {
            self.away_seen = true;
            return Looked::Wait { user_seen };
        }
        if self.need_away && !self.away_seen {
            return Looked::Wait { user_seen };
        }
        if identity == Some(true) {
            Looked::Arm
        } else {
            Looked::Identify
        }
    }
}

/// Whether a look should check identity: every third look for the away
/// clock, and every look once the clock is past half of `lost_after`, so
/// a user who is there is confirmed before the clock runs out and a
/// stranger is found out within one look of it.
fn identity_due(looks: u32, seen: &std::cell::Cell<Instant>, lost_after: Option<Duration>) -> bool {
    looks.is_multiple_of(3)
        || lost_after
            .map(|l| seen.get().elapsed() > l / 2)
            .unwrap_or(false)
}

/// The away clock, read after a look: a passing identity look is the user
/// seen and restarts it; past `lost_after` without one, the user left.
fn away_clock(
    o: &crate::presence::Observation,
    seen: &std::cell::Cell<Instant>,
    lost_after: Option<Duration>,
    where_: &str,
) -> Option<Round> {
    if o.identity == Some(true) {
        seen.set(Instant::now());
        return None;
    }
    let l = lost_after?;
    if seen.get().elapsed() <= l {
        return None;
    }
    log::info!(
        "consent: {} for {:.0}s while {}; the user left",
        if o.face { "not the user" } else { "nobody" },
        l.as_secs_f32(),
        where_
    );
    Some(Round::FaceLost)
}

/// A hold as a loop over injectable parts: no scan until `until`, one look
/// at the presence rhythm meanwhile for the away clock. Ends with `None`
/// when the hold is over or the window answered, with `FaceLost` when the
/// user has not been seen for `lost_after`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn hold_wait(
    look: &mut dyn FnMut(bool) -> Result<crate::presence::Observation>,
    state: &ConsentState,
    user: &str,
    until: Instant,
    seen: &std::cell::Cell<Instant>,
    lost_after: Option<Duration>,
    tick: Duration,
) -> Option<Round> {
    let mut looks = 0u32;
    while Instant::now() < until {
        for _ in 0..10 {
            std::thread::sleep(tick);
            if state.answered(user) {
                return None;
            }
            if Instant::now() >= until {
                return None;
            }
        }
        if lost_after.is_none() {
            continue;
        }
        looks += 1;
        let o = match look(identity_due(looks, seen, lost_after)) {
            Ok(o) => o,
            Err(e) => {
                log::warn!("consent: look during a hold: {}", e);
                continue;
            }
        };
        if let Some(r) = away_clock(&o, seen, lost_after, "the face checks were paused") {
            return Some(r);
        }
    }
    None
}

/// The attention wait as a loop over injectable parts, so a test can drive
/// it without a camera. Ends with `None` when the request is re-armed (an
/// answer in the slot, or the gate's `Arm`), with a round when the user
/// left for `lost_after` (the request's own clock in `seen`) or the
/// session locked.
#[allow(clippy::too_many_arguments)]
pub(crate) fn attention_wait(
    look: &mut dyn FnMut(bool) -> Result<crate::presence::Observation>,
    state: &ConsentState,
    user: &str,
    locked: &dyn Fn() -> bool,
    beat: &dyn Fn(),
    mut gate: RearmGate,
    lost_after: Option<Duration>,
    seen: &std::cell::Cell<Instant>,
    tick: Duration,
) -> Option<Round> {
    let mut last_beat = Instant::now();
    let mut looks = 0u32;
    loop {
        for _ in 0..10 {
            std::thread::sleep(tick);
            // The card's "Ready to nod": taken here, it re-arms the nods;
            // the scan ahead is not to read it as an answer.
            if state.take_rearm(user) {
                log::info!("consent: the card says ready to nod; scanning");
                return None;
            }
            // A password, a dismissal or a hang-up: the scan start takes
            // it before touching the camera.
            if state.answered(user) {
                return None;
            }
        }
        if locked() {
            log::info!("consent: the session locked while waiting; the request parks");
            return Some(Round::SessionLocked);
        }
        if last_beat.elapsed() >= crate::consent::HEARTBEAT {
            last_beat = Instant::now();
            beat();
        }
        looks += 1;
        // The identity check costs the strobe and the embedder, so it runs
        // every third look for the away clock (every look once the clock
        // is half spent), and on demand before an arm: the face that
        // re-arms the nods is checked to be the user.
        let mut o = match look(identity_due(looks, seen, lost_after)) {
            Ok(o) => o,
            Err(e) => {
                log::warn!("consent: look while waiting: {}", e);
                continue;
            }
        };
        let mut decision = gate.look(o.face, o.attentive, o.identity);
        if decision == Looked::Identify {
            o = match look(true) {
                Ok(o) => o,
                Err(e) => {
                    log::warn!("consent: identity look while waiting: {}", e);
                    continue;
                }
            };
            decision = gate.look(o.face, o.attentive, o.identity);
            // Asked and still unchecked (the secure mode's gate read no
            // signal): not an arm, and a look the clock counts.
            if decision == Looked::Identify {
                decision = Looked::Wait { user_seen: false };
            }
        }
        match decision {
            Looked::Arm => {
                log::info!(
                    "consent: the user turned to the camera after {} looks; scanning",
                    looks
                );
                return None;
            }
            Looked::Identify => continue,
            // The gate's `user_seen` decides the arm; the away clock runs
            // on the request's own record of the user, which only a
            // passing identity look refreshes (E2).
            Looked::Wait { .. } => {
                if let Some(r) = away_clock(&o, seen, lost_after, "waiting") {
                    return Some(r);
                }
            }
        }
    }
}

#[cfg(test)]
mod rearm_tests {
    use super::*;
    use crate::presence::{Observation, PresenceMode};

    fn obs(face: bool, attentive: bool, identity: Option<bool>) -> Observation {
        Observation {
            face,
            attentive,
            identity,
            near_miss: false,
            frame: None,
            bbox: None,
        }
    }

    /// Q8: after a nod window passed unanswered a face that stays in view
    /// does not re-arm the nods; the same face away for a look and back,
    /// checked to be the user, does.
    #[test]
    fn a_face_that_stays_in_view_does_not_re_arm_after_a_timeout() {
        let mut g = RearmGate::new(true, PresenceMode::Default);
        for _ in 0..50 {
            assert_eq!(g.look(true, true, None), Looked::Wait { user_seen: true });
            assert_eq!(
                g.look(true, true, Some(true)),
                Looked::Wait { user_seen: true }
            );
        }
        assert_eq!(
            g.look(true, false, None),
            Looked::Wait { user_seen: true },
            "turned away: the away clock does not run on the user"
        );
        assert_eq!(
            g.look(true, true, None),
            Looked::Identify,
            "back and attentive: who is it?"
        );
        assert_eq!(g.look(true, true, Some(true)), Looked::Arm);
    }

    /// Before any nod window (a scan that failed, a confirm that could not
    /// read the strobe) an attentive enrolled face re-arms at once.
    #[test]
    fn without_the_away_rule_an_attentive_user_re_arms_at_once() {
        let mut g = RearmGate::new(false, PresenceMode::Default);
        assert_eq!(g.look(true, true, None), Looked::Identify);
        assert_eq!(g.look(true, true, Some(true)), Looked::Arm);
        let mut g = RearmGate::new(false, PresenceMode::Default);
        assert_eq!(
            g.look(false, false, None),
            Looked::Wait { user_seen: false }
        );
        assert_eq!(g.look(true, false, None), Looked::Wait { user_seen: true });
    }

    /// A stranger never re-arms a scan: an attentive face that fails the
    /// identity check waits, and after the mode's strikes it is nobody for
    /// the away clock (one strike in secure mode, two in default).
    #[test]
    fn a_stranger_never_re_arms_and_counts_as_nobody_after_the_strikes() {
        let mut g = RearmGate::new(false, PresenceMode::Default);
        assert_eq!(g.look(true, true, None), Looked::Identify);
        assert_eq!(
            g.look(true, true, Some(false)),
            Looked::Wait { user_seen: true }
        );
        assert_eq!(
            g.look(true, true, Some(false)),
            Looked::Wait { user_seen: false }
        );
        assert_eq!(
            g.look(true, true, None),
            Looked::Identify,
            "still asked, never armed"
        );
        assert_eq!(
            g.look(true, true, Some(false)),
            Looked::Wait { user_seen: false }
        );
        let mut g = RearmGate::new(false, PresenceMode::Secure);
        assert_eq!(
            g.look(true, true, Some(false)),
            Looked::Wait { user_seen: false }
        );
        assert_eq!(
            g.look(true, true, Some(true)),
            Looked::Arm,
            "a passing check clears the strikes"
        );
    }

    /// A consent state of the test's own, with `user`'s request live.
    fn live(user: &str) -> ConsentState {
        let st = ConsentState::new();
        std::mem::forget(st.test_live(1000, user));
        st
    }

    /// A2: a round driven past its first timeout with an attentive face
    /// opens no second nod window until a re-arm answer arrives.
    #[test]
    fn the_wait_ends_only_on_a_re_arm_answer_while_the_face_stays() {
        let user = "rearm-wait-test";
        let st = live(user);
        let mut n = 0u32;
        let st_ref = &st;
        let mut look = move |identify: bool| {
            n += 1;
            if n == 6 {
                st_ref.push_answer(user, Answer::Rearm);
            }
            assert!(n < 12, "the wait never ended");
            Ok(obs(true, true, identify.then_some(true)))
        };
        let beats = std::cell::Cell::new(0u32);
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| beats.set(beats.get() + 1),
            RearmGate::new(true, PresenceMode::Default),
            Some(Duration::from_secs(20)),
            &fresh(),
            Duration::ZERO,
        );
        assert!(r.is_none(), "the answer re-arms the request");
        assert!(
            !st.answered(user),
            "the re-arm answer is consumed, not left for the scan"
        );
    }

    /// A2: the face away for a look and back, checked to be the user,
    /// re-arms without a click.
    #[test]
    fn the_wait_ends_when_the_user_is_back_at_the_card() {
        let user = "rearm-back-test";
        let st = live(user);
        let mut n = 0u32;
        let mut identity_looks = 0u32;
        let mut look = |identify: bool| {
            n += 1;
            if identify {
                identity_looks += 1;
            }
            // Ten looks with the user watching another monitor, then back.
            Ok(if n <= 10 {
                obs(true, false, identify.then_some(true))
            } else {
                obs(true, true, identify.then_some(true))
            })
        };
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| {},
            RearmGate::new(true, PresenceMode::Default),
            Some(Duration::from_secs(20)),
            &fresh(),
            Duration::ZERO,
        );
        assert!(r.is_none());
        assert!(
            (11..=13).contains(&n),
            "re-armed as soon as the face was back: {} looks",
            n
        );
    }

    /// D2: the wait parks the request when the session locks.
    #[test]
    fn the_wait_parks_when_the_session_locks() {
        let user = "rearm-lock-test";
        let st = live(user);
        let mut look = |identify: bool| Ok(obs(true, true, identify.then_some(true)));
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| true,
            &|| {},
            RearmGate::new(true, PresenceMode::Default),
            None,
            &fresh(),
            Duration::ZERO,
        );
        assert!(matches!(r, Some(Round::SessionLocked)));
    }

    /// C1 on this lane: nobody, or a stranger past the strikes, for the
    /// away time ends the wait with the user gone.
    #[test]
    fn the_wait_ends_with_the_user_gone_after_the_away_time() {
        let user = "rearm-gone-test";
        let st = live(user);
        let mut look = |identify: bool| Ok(obs(true, true, identify.then_some(false)));
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| {},
            RearmGate::new(false, PresenceMode::Secure),
            Some(Duration::ZERO),
            &fresh(),
            Duration::ZERO,
        );
        assert!(matches!(r, Some(Round::FaceLost)));
    }

    /// E2: a stranger who sits down while a card is up does not hold the
    /// lock off. The request's clock last saw the user before the away
    /// time; the stranger's first look is asked its identity, fails, and
    /// the wait ends with the user gone: away time plus one look.
    #[test]
    fn a_stranger_at_the_card_is_locked_out_at_the_away_time() {
        let user = "e2-stranger-test";
        let st = live(user);
        let mut n = 0u32;
        let mut asked = 0u32;
        let mut look = |identify: bool| {
            n += 1;
            if identify {
                asked += 1;
            }
            Ok(obs(true, true, identify.then_some(false)))
        };
        let seen = ago(21);
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| {},
            RearmGate::new(false, PresenceMode::Default),
            Some(Duration::from_secs(20)),
            &seen,
            Duration::ZERO,
        );
        assert!(matches!(r, Some(Round::FaceLost)), "the stranger is nobody");
        assert_eq!(n, 1, "one look past the away time");
        assert_eq!(asked, 1, "and that look checked identity");
        assert!(
            seen.get().elapsed() >= Duration::from_secs(21),
            "a failed check never refreshes the clock"
        );
    }

    /// E2: the same stale clock with the user in the chair is refreshed by
    /// the passing identity look, and the wait goes on.
    #[test]
    fn a_passing_identity_look_refreshes_the_request_clock() {
        let user = "e2-user-test";
        let st = live(user);
        let mut n = 0u32;
        let st_ref = &st;
        let mut look = move |identify: bool| {
            n += 1;
            if n == 4 {
                st_ref.push_answer(user, Answer::Dismiss);
            }
            assert!(n < 8, "the wait never ended");
            // Reading at the card, not attentive: no arm, only the clock.
            Ok(obs(true, false, identify.then_some(true)))
        };
        let seen = ago(21);
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| {},
            RearmGate::new(true, PresenceMode::Default),
            Some(Duration::from_secs(20)),
            &seen,
            Duration::ZERO,
        );
        assert!(r.is_none(), "the answer ends the wait, not the clock");
        assert!(seen.get().elapsed() < Duration::from_secs(1));
    }

    /// E2, secure mode: a face the gate cannot read is asked again and
    /// again but counts for the clock, so it cannot hold a request open.
    #[test]
    fn an_unchecked_face_in_secure_mode_does_not_hold_the_request() {
        let user = "e2-unchecked-test";
        let st = live(user);
        let mut n = 0u32;
        let mut look = |_identify: bool| {
            n += 1;
            assert!(n < 10, "the wait never ended");
            Ok(obs(true, true, None))
        };
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| {},
            RearmGate::new(false, PresenceMode::Secure),
            Some(Duration::from_secs(20)),
            &ago(21),
            Duration::ZERO,
        );
        assert!(matches!(r, Some(Round::FaceLost)));
    }

    /// E2: a hold watches the chair. A stranger there (or nobody) past the
    /// away time ends the round with the user gone; the user's own face
    /// keeps the clock and the hold runs to its end.
    #[test]
    fn a_hold_ends_with_the_user_gone_when_a_stranger_sits_through_it() {
        let user = "e2-hold-test";
        let st = live(user);
        let mut n = 0u32;
        let mut look = |identify: bool| {
            n += 1;
            Ok(obs(true, true, identify.then_some(false)))
        };
        let r = hold_wait(
            &mut look,
            &st,
            user,
            Instant::now() + Duration::from_secs(30),
            &ago(21),
            Some(Duration::from_secs(20)),
            Duration::ZERO,
        );
        assert!(matches!(r, Some(Round::FaceLost)));
        assert_eq!(n, 1, "one look past the away time");
    }

    #[test]
    fn a_hold_with_the_user_in_view_runs_to_its_end() {
        let user = "e2-hold-user-test";
        let st = live(user);
        let mut n = 0u32;
        let mut look = |identify: bool| {
            n += 1;
            Ok(obs(true, false, identify.then_some(true)))
        };
        let seen = ago(21);
        let r = hold_wait(
            &mut look,
            &st,
            user,
            Instant::now() + Duration::from_millis(30),
            &seen,
            Some(Duration::from_secs(20)),
            Duration::ZERO,
        );
        assert!(r.is_none(), "the hold ended by itself");
        assert!(n >= 1, "the chair was looked at");
        assert!(seen.get().elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_hold_ends_early_on_an_answer_and_looks_only_with_a_watch() {
        let user = "e2-hold-answer-test";
        let st = live(user);
        let n = std::cell::Cell::new(0u32);
        let mut look = |identify: bool| {
            n.set(n.get() + 1);
            Ok(obs(false, false, identify.then_some(false)))
        };
        // No presence watch, no looks: the hold is the old plain wait.
        let r = hold_wait(
            &mut look,
            &st,
            user,
            Instant::now() + Duration::from_millis(20),
            &ago(21),
            None,
            Duration::ZERO,
        );
        assert!(r.is_none());
        assert_eq!(n.get(), 0);
        st.push_answer(user, Answer::Dismiss);
        let r = hold_wait(
            &mut look,
            &st,
            user,
            Instant::now() + Duration::from_secs(30),
            &ago(21),
            Some(Duration::from_secs(20)),
            Duration::ZERO,
        );
        assert!(r.is_none(), "the answer ends the hold before any look");
        assert_eq!(n.get(), 0);
    }

    fn fresh() -> std::cell::Cell<Instant> {
        std::cell::Cell::new(Instant::now())
    }

    /// A request clock that last saw the user this many seconds ago.
    fn ago(secs: u64) -> std::cell::Cell<Instant> {
        std::cell::Cell::new(
            Instant::now()
                .checked_sub(Duration::from_secs(secs))
                .expect("the machine has been up longer than that"),
        )
    }
}
