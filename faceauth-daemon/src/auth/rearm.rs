//! The waits between rounds of a consent request: the rearm gate that
//! decides look by look whether the nods may arm again, the hold, and the
//! away clock that ends a request once its user has left.

use super::consent_flow::Round;
#[cfg(test)]
use crate::consent::Answer;
use crate::consent::ConsentState;
use crate::presence::{Observation, PresenceConfig, PresenceMode, Watch};
use anyhow::Result;
use std::cell::{Cell, RefCell};
use std::time::{Duration, Instant};

/// A consent request's record of its user at the card (E2): when it last
/// saw them, the request's away clock, and the presence watch's own rules
/// for who holds that clock between sightings. The card holds the camera,
/// so the watch cannot tick meanwhile; the round runs a copy of it on its
/// own looks instead (`presence::Watch::step`), and never ends with the
/// user gone where the watch would have held the clock: the shape of a
/// user in a bright room or turned to a second screen holds it, as it
/// holds the watch's. It reads as the clock itself (`get`, `set`).
pub struct UserSeen {
    at: Cell<Instant>,
    watch: RefCell<Watch>,
    mode: Cell<PresenceMode>,
}

impl UserSeen {
    /// The clock started at `at`, and a watch that has seen nothing yet.
    pub(crate) fn new(at: Instant) -> UserSeen {
        UserSeen {
            at: Cell::new(at),
            watch: RefCell::new(Watch::new(PresenceConfig::default()).in_consent()),
            mode: Cell::new(PresenceMode::Default),
        }
    }

    /// Take up the live watch as it stands, in `mode`, at the start of a
    /// round: its record of the user, its shape reference and its verdict
    /// on the face. With no watch running, one of `cfg` that has seen
    /// nothing.
    pub(crate) fn follow_watch(&self, cfg: &PresenceConfig, mode: PresenceMode) {
        let w = crate::presence::watch_copy().unwrap_or_else(|| Watch::new(cfg.clone()));
        *self.watch.borrow_mut() = w.in_consent();
        self.mode.set(mode);
    }

    /// The user identified at `at` by a scan match, at `frame` and `bbox`:
    /// the request's clock and the copy's record of the user move there,
    /// the shape reference included, as a passing look of the watch's
    /// would move them (`Watch::sighted`).
    pub(crate) fn sighted(&self, at: Instant, frame: &faceauth_engine::Grey, bbox: [f32; 4]) {
        self.at.set(at);
        self.watch.borrow_mut().sighted(at, frame, bbox);
    }

    /// Whether this look, taken at `now` with its identity `asked` or not,
    /// holds the clock by the watch's rules, and whether the watch would
    /// lock the session on it: the secure mode locks on the first failed
    /// check, unless the shape holds. The shape stands in for a hidden face
    /// only on a look that asked who it is, as every look of the watch's
    /// own does in the secure mode: on a look that did not, an attentive
    /// stranger reads as hidden. A look that holds restarts the request's
    /// clock.
    fn judge(&self, o: &Observation, now: Instant, asked: bool) -> Judged {
        let mut w = self.watch.borrow_mut();
        w.note_recent(self.at.get());
        let step = w.step(o, now, self.mode.get());
        let held = step.held && (asked || !step.by_shape);
        if held {
            self.at.set(now);
        }
        Judged {
            held,
            lock: step.lock,
        }
    }

    /// Does every look ask who it is? In the secure mode, as the watch's
    /// own looks do on every tick.
    fn identify_every_look(&self) -> bool {
        self.mode.get() == PresenceMode::Secure
    }
}

/// What the watch's rules make of one look under a card.
struct Judged {
    held: bool,
    lock: bool,
}

impl std::ops::Deref for UserSeen {
    type Target = Cell<Instant>;
    fn deref(&self) -> &Cell<Instant> {
        &self.at
    }
}

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

/// How a wait keeps time. The card's answer slot is read every `tick`,
/// and the chair is looked at every `look_every`, or every
/// `battery_look_every` while `on_battery` says the machine runs on its
/// battery, so a card left waiting on battery keeps the camera and its
/// light off most of the time (D3). The heartbeat and the session lock are
/// read from the ticks, not the looks, so neither waits on a battery
/// look. `now` and `sleep` are the clock: the real one in the daemon, a
/// stepped one in the tests, so a test can run a wait for longer than a
/// test may take (D1).
pub(crate) struct Pace<'a> {
    pub tick: Duration,
    pub look_every: Duration,
    pub battery_look_every: Duration,
    pub on_battery: &'a dyn Fn() -> bool,
    pub now: &'a dyn Fn() -> Instant,
    pub sleep: &'a dyn Fn(Duration),
}

impl Pace<'_> {
    /// Reads of the answer slot before the next look: the look interval
    /// for the power source in use now, in ticks, and at least one.
    fn ticks_to_look(&self) -> u32 {
        let every = if (self.on_battery)() {
            self.battery_look_every
        } else {
            self.look_every
        };
        let ticks = every.as_micros() / self.tick.as_micros().max(1);
        ticks.clamp(1, u32::MAX as u128) as u32
    }

    /// Re-send the card through `beat` once `HEARTBEAT` has passed since
    /// `last_beat`. Read every tick, so the card hears from the daemon on
    /// time whatever the look interval (D1, D3).
    fn beat_due(&self, last_beat: &mut Instant, beat: &dyn Fn()) {
        let now = (self.now)();
        if now.saturating_duration_since(*last_beat) >= crate::consent::HEARTBEAT {
            *last_beat = now;
            beat();
        }
    }

    /// Whether the session lock is due a check: every `look_every`, the
    /// mains rhythm, whatever the power source. Each check runs a helper
    /// in the user's manager, so it keeps the nod window's two seconds
    /// rather than the slot's 200 ms, and a battery look no longer holds
    /// the camera over a locked session for its whole interval (D3).
    fn lock_check_due(&self, last_check: &mut Instant) -> bool {
        let now = (self.now)();
        if now.saturating_duration_since(*last_check) < self.look_every {
            return false;
        }
        *last_check = now;
        true
    }
}

impl Pace<'static> {
    /// The daemon's pace for the waits of a consent request: the slot
    /// every 200 ms and a look every two seconds on mains; on battery a
    /// look every `battery_tick_seconds`, the presence watch's own battery
    /// tick, never oftener than on mains. Zero keeps the mains cadence, as
    /// it does for the watch.
    pub(crate) fn live(battery_tick_seconds: f32) -> Pace<'static> {
        let look_every = Duration::from_secs(2);
        let battery_look_every = Duration::try_from_secs_f32(battery_tick_seconds)
            .unwrap_or(Duration::ZERO)
            .max(look_every);
        Pace {
            tick: Duration::from_millis(200),
            look_every,
            battery_look_every,
            on_battery: &crate::presence::on_battery_now,
            now: &Instant::now,
            sleep: &std::thread::sleep,
        }
    }
}

/// Whether a look should check identity: every third look for the away
/// clock, and every look once the clock is past half of `lost_after`, so
/// a user who is there is confirmed before the clock runs out and a
/// stranger is found out within one look of it.
fn identity_due(looks: u32, now: Instant, seen: &UserSeen, lost_after: Option<Duration>) -> bool {
    looks.is_multiple_of(3)
        || lost_after
            .map(|l| now.saturating_duration_since(seen.get()) > l / 2)
            .unwrap_or(false)
        || seen.identify_every_look()
}

/// The away clock, read after a look at `now` that `asked` who it is or
/// not: a look that holds the clock by the watch's rules
/// (`UserSeen::judge`) is the user there and restarts it. With a watch on
/// for the user, the user has left where the watch would lock (the secure
/// mode's first failed check), and past `lost_after` without a look that
/// held.
fn away_clock(
    o: &Observation,
    now: Instant,
    seen: &UserSeen,
    lost_after: Option<Duration>,
    asked: bool,
    where_: &str,
) -> Option<Round> {
    let judged = seen.judge(o, now, asked);
    if judged.held {
        return None;
    }
    let l = lost_after?;
    if judged.lock {
        log::info!(
            "consent: {} while {}; the watch locks here, so the user left",
            if o.face { "not the user" } else { "nobody" },
            where_
        );
        return Some(Round::FaceLost);
    }
    if now.saturating_duration_since(seen.get()) <= l {
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

/// Whether a request's user has left after a scan that scored no frame,
/// with a walk-away watch on. The scan scoring nothing says nothing about
/// who is at the desk: in a bright room every pair reads no signal with
/// the user sitting there. So the user has left only when the request's
/// own away clock (`seen`) has run out and the watch's own look, asked the
/// face's identity, holds nothing by the watch's rules: nobody there, a
/// changed chair, or a stranger the watch would not hold for. A look that
/// fails decides nothing; the wait after the scan looks again (E2).
pub(crate) fn gone_after_unscored(
    look: &mut dyn FnMut(bool) -> Result<Observation>,
    seen: &UserSeen,
    lost_after: Duration,
    now: Instant,
) -> bool {
    if now.saturating_duration_since(seen.get()) <= lost_after {
        return false;
    }
    match look(true) {
        Ok(o) => away_clock(
            &o,
            now,
            seen,
            Some(lost_after),
            true,
            "the scan scored nothing",
        )
        .is_some(),
        Err(e) => {
            log::warn!("consent: look after a scan that scored nothing: {}", e);
            false
        }
    }
}

/// A hold as a loop over injectable parts: no scan until `until`, one look
/// at the presence rhythm meanwhile for the away clock. Ends with `None`
/// when the hold is over or the window answered, with `FaceLost` when the
/// user has not been seen for `lost_after`, with `SessionLocked` when the
/// session locked under the card. `beat` re-sends the card now and then: a
/// hold runs for minutes, and a card nobody has spoken to for five of
/// them hides itself (D1). The nods are not armed in a hold, so neither is
/// the key.
#[allow(clippy::too_many_arguments)]
pub(crate) fn hold_wait(
    look: &mut dyn FnMut(bool) -> Result<crate::presence::Observation>,
    state: &ConsentState,
    user: &str,
    locked: &dyn Fn() -> bool,
    until: Instant,
    seen: &UserSeen,
    lost_after: Option<Duration>,
    beat: &dyn Fn(),
    pace: &Pace,
) -> Option<Round> {
    state.key_off(user, false);
    let mut last_beat = (pace.now)();
    let mut last_lock_check = (pace.now)();
    let mut looks = 0u32;
    while (pace.now)() < until {
        for _ in 0..pace.ticks_to_look() {
            (pace.sleep)(pace.tick);
            if state.answered(user) {
                return None;
            }
            if (pace.now)() >= until {
                return None;
            }
            // A hold lasts minutes; a lock under the card parks the
            // request, so nothing behind the lock screen can answer it.
            if pace.lock_check_due(&mut last_lock_check) && locked() {
                log::info!("consent: the session locked during a hold; the request parks");
                return Some(Round::SessionLocked);
            }
            pace.beat_due(&mut last_beat, beat);
        }
        if lost_after.is_none() {
            continue;
        }
        looks += 1;
        let asked = identity_due(looks, (pace.now)(), seen, lost_after);
        let o = match look(asked) {
            Ok(o) => o,
            Err(e) => {
                log::warn!("consent: look during a hold: {}", e);
                continue;
            }
        };
        if let Some(r) = away_clock(
            &o,
            (pace.now)(),
            seen,
            lost_after,
            asked,
            "the face checks were paused",
        ) {
            return Some(r);
        }
    }
    None
}

/// The attention wait as a loop over injectable parts, so a test can drive
/// it without a camera. Ends with `None` when the request is re-armed (an
/// answer in the slot, or the gate's `Arm`), with a round when the user
/// left for `lost_after` (the request's own clock in `seen`) or the
/// session locked. `beat` re-sends the card now and then (D1); `pace`
/// sets the looks, slower on battery, while the lock and the heartbeat
/// keep their own time between them (D3).
#[allow(clippy::too_many_arguments)]
pub(crate) fn attention_wait(
    look: &mut dyn FnMut(bool) -> Result<crate::presence::Observation>,
    state: &ConsentState,
    user: &str,
    locked: &dyn Fn() -> bool,
    beat: &dyn Fn(),
    mut gate: RearmGate,
    lost_after: Option<Duration>,
    seen: &UserSeen,
    pace: &Pace,
) -> Option<Round> {
    // The nods are disarmed while this waits, and the key with them.
    state.key_off(user, false);
    let mut last_beat = (pace.now)();
    let mut last_lock_check = (pace.now)();
    let mut looks = 0u32;
    loop {
        for _ in 0..pace.ticks_to_look() {
            (pace.sleep)(pace.tick);
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
            // The session lock is read on the mains rhythm between the
            // looks, however far apart they are: the lock screen needs the
            // camera the round is holding (D3).
            if pace.lock_check_due(&mut last_lock_check) && locked() {
                log::info!("consent: the session locked while waiting; the request parks");
                return Some(Round::SessionLocked);
            }
            pace.beat_due(&mut last_beat, beat);
        }
        looks += 1;
        // The identity check costs the strobe and the embedder, so it runs
        // every third look for the away clock (every look once the clock
        // is half spent, and every look in the secure mode, as the watch
        // does), and on demand before an arm: the face that re-arms the
        // nods is checked to be the user.
        let mut asked = identity_due(looks, (pace.now)(), seen, lost_after);
        let mut o = match look(asked) {
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
            asked = true;
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
            // on the request's own record of the user, which a look
            // restarts only where the watch's rules would hold (E2).
            Looked::Wait { .. } => {
                if let Some(r) = away_clock(&o, (pace.now)(), seen, lost_after, asked, "waiting") {
                    return Some(r);
                }
            }
        }
    }
}

#[cfg(test)]
mod rearm_tests {
    use super::*;
    use faceauth_engine::Grey;

    fn obs(face: bool, attentive: bool, identity: Option<bool>) -> Observation {
        Observation {
            face,
            attentive,
            identity,
            near_miss: false,
            side_view: false,
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
            &at_once(),
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
            &at_once(),
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
            &at_once(),
        );
        assert!(matches!(r, Some(Round::SessionLocked)));
    }

    /// C: a hold parks the request when the session locks under the card,
    /// so nothing behind the lock screen can answer it, a key touch
    /// included.
    #[test]
    fn a_hold_parks_when_the_session_locks() {
        let user = "rearm-hold-lock-test";
        let st = live(user);
        let r = hold_wait(
            &mut |identify| Ok(obs(true, true, identify.then_some(true))),
            &st,
            user,
            &|| true,
            Instant::now() + Duration::from_secs(30),
            &fresh(),
            None,
            &|| {},
            &at_once(),
        );
        assert!(matches!(r, Some(Round::SessionLocked)));
    }

    /// B: the key is armed only while the nods are. A hold and the wait for
    /// attention each turn off any key watch on the request as they begin,
    /// so a check still out is stopped and a touch then answers nothing.
    #[test]
    fn a_hold_and_the_wait_for_attention_turn_the_key_off() {
        let user = "rearm-key-off-test";
        let st = live(user);
        st.arm_key_for_test(user).unwrap();
        let r = hold_wait(
            &mut |identify| Ok(obs(true, true, identify.then_some(true))),
            &st,
            user,
            &|| false,
            Instant::now() + Duration::from_millis(30),
            &fresh(),
            None,
            &|| {},
            &at_once(),
        );
        assert!(r.is_none(), "the hold ran to its end");
        assert_eq!(st.key_armed_now(user), None, "no key during a hold");
        st.arm_key_for_test(user).unwrap();
        let st_ref = &st;
        let mut look = |identify: bool| {
            assert_eq!(
                st_ref.key_armed_now(user),
                None,
                "no key while waiting for attention"
            );
            st_ref.push_answer(user, Answer::Rearm);
            Ok(obs(true, true, identify.then_some(true)))
        };
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| {},
            RearmGate::new(true, PresenceMode::Default),
            None,
            &fresh(),
            &at_once(),
        );
        assert!(r.is_none(), "Ready to nod ends the wait");
        assert_eq!(st.key_armed_now(user), None);
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
            &secure(fresh()),
            &at_once(),
        );
        assert!(matches!(r, Some(Round::FaceLost)));
    }

    /// E2: a stranger who sits down while a card is up does not hold the
    /// lock off in the secure mode. The request's clock last saw the user
    /// before the away time; the stranger's first look is asked its
    /// identity, fails, and the wait ends with the user gone: away time
    /// plus one look. (In the default mode a face turned to the screen
    /// holds the clock, as it holds the watch's: a laptop handed over stays
    /// open while it is looked at, Q9.)
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
        let seen = secure(ago(21));
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| {},
            RearmGate::new(false, PresenceMode::Secure),
            Some(Duration::from_secs(20)),
            &seen,
            &at_once(),
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
            &at_once(),
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
            &secure(ago(21)),
            &at_once(),
        );
        assert!(matches!(r, Some(Round::FaceLost)));
    }

    /// A walk-away watch and a bright room: the scan reads no signal from
    /// the user at the desk and scores nothing. That alone is never the
    /// user gone: inside the away time nothing is looked at, and past it
    /// the chair is looked at once and judged by the watch's own rules.
    /// The user identified there keeps the session and restarts the clock;
    /// nobody there, or a stranger, is the user gone; and a look that
    /// failed decides nothing. The watch's hold for a face it could not
    /// check is in the next test.
    #[test]
    fn a_scan_that_scored_nothing_with_the_user_at_the_desk_is_not_the_user_gone() {
        let away = Duration::from_secs(20);
        assert!(
            !gone_after_unscored(
                &mut |_| panic!("inside the away time nothing is looked at"),
                &fresh(),
                away,
                Instant::now()
            ),
            "a user matched a moment ago"
        );
        let seen = ago(21);
        let mut asked = 0;
        let mut at_the_desk = |identify: bool| {
            asked += 1;
            assert!(identify, "the look asks who it is");
            Ok(obs(true, true, Some(true)))
        };
        assert!(!gone_after_unscored(
            &mut at_the_desk,
            &seen,
            away,
            Instant::now()
        ));
        assert_eq!(asked, 1);
        assert!(
            seen.get().elapsed() < Duration::from_secs(1),
            "the user seen restarts the clock"
        );
        for (who, o) in [
            ("nobody", obs(false, false, None)),
            ("a stranger", obs(true, true, Some(false))),
        ] {
            assert!(
                gone_after_unscored(
                    &mut |_| Ok(o.clone()),
                    &secure(ago(21)),
                    away,
                    Instant::now()
                ),
                "{} past the away time",
                who
            );
        }
        assert!(
            !gone_after_unscored(
                &mut |_| Err(anyhow::anyhow!("camera busy")),
                &ago(21),
                away,
                Instant::now()
            ),
            "a look that failed decides nothing"
        );
    }

    /// The consent lane defers to the watch's hold rules, the shape hold
    /// included, and never locks where the watch would hold the clock. A
    /// watch that last saw the user (their frame the shape reference) holds
    /// it for the user in a secure-mode bright room, whose face the look
    /// cannot check, and for the user turned to a second screen, whose
    /// check fails, in either mode. A chair the user has left, the shape
    /// under the box gone, is still the user gone at the away time.
    #[test]
    fn the_consent_lane_holds_the_clock_wherever_the_watch_would() {
        let away = Duration::from_secs(20);
        let mut frame = Grey::new(120, 120);
        frame
            .data
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i % 251) as u8);
        let mut empty = frame.clone();
        empty.data.iter_mut().for_each(|v| *v = 200);
        let look = |face: bool, attentive: bool, identity: Option<bool>, f: &Grey| Observation {
            face,
            attentive,
            frame: Some(f.clone()),
            bbox: face.then_some([20.0, 10.0, 40.0, 40.0]),
            identity,
            near_miss: false,
            side_view: false,
        };
        // The watch as it stood: the user seen and checked 25 s ago, and
        // the request's clock run out since.
        let watched = |mode: PresenceMode| {
            let seen = ago(25);
            seen.mode.set(mode);
            assert!(
                seen.judge(&look(true, true, Some(true), &frame), seen.get(), true)
                    .held
            );
            seen.set(Instant::now().checked_sub(Duration::from_secs(21)).unwrap());
            seen
        };
        let cases = [
            (
                "secure, a bright room: the face read no signal",
                PresenceMode::Secure,
                look(true, true, None, &frame),
                false,
            ),
            (
                "secure, turned to a second screen: the check failed",
                PresenceMode::Secure,
                look(true, false, Some(false), &frame),
                false,
            ),
            (
                "default, turned to a second screen: the check failed",
                PresenceMode::Default,
                look(true, false, Some(false), &frame),
                false,
            ),
            (
                "secure, the chair empty",
                PresenceMode::Secure,
                look(false, false, None, &empty),
                true,
            ),
            (
                "default, the chair empty",
                PresenceMode::Default,
                look(false, false, None, &empty),
                true,
            ),
        ];
        for (what, mode, o, gone) in cases {
            let seen = watched(mode);
            assert_eq!(
                gone_after_unscored(&mut |_| Ok(o.clone()), &seen, away, Instant::now()),
                gone,
                "{}",
                what
            );
            assert_eq!(
                seen.get().elapsed() < Duration::from_secs(1),
                !gone,
                "{}: a look the watch holds restarts the clock",
                what
            );
        }
    }

    /// Secure mode under a card: someone else who sits in the user's place
    /// through a cooldown hold, their shoulders the same shape as the
    /// user's, is out within the away time and one look, not held to the
    /// hold's end. Every look asks who it is, as the watch's do; the shape
    /// stands in only for a face whose check was asked; and the watch's
    /// lock on the first failed check is honored under the card too.
    #[test]
    fn a_stranger_in_the_same_shape_is_locked_out_of_a_secure_hold() {
        let user = "rr2-secure-hold";
        let st = live(user);
        let clock = std::cell::Cell::new(Instant::now());
        let t0 = clock.get();
        let now = || clock.get();
        let sleep = |d: Duration| clock.set(clock.get() + d);
        let pace = stepped(&now, &sleep, &mains);
        let mut frame = Grey::new(120, 120);
        frame
            .data
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i % 251) as u8);
        let at_the_desk = |identity: Option<bool>| Observation {
            face: true,
            attentive: true,
            frame: Some(frame.clone()),
            bbox: Some([20.0, 10.0, 40.0, 40.0]),
            identity,
            near_miss: false,
            side_view: false,
        };
        // The user seen and checked as the hold began.
        let seen = secure(UserSeen::new(t0));
        assert!(seen.judge(&at_the_desk(Some(true)), t0, true).held);
        let (mut looks, mut unasked) = (0, 0);
        let mut look = |identify: bool| {
            looks += 1;
            unasked += !identify as u32;
            Ok(at_the_desk(identify.then_some(false)))
        };
        let away = Duration::from_secs(20);
        let r = hold_wait(
            &mut look,
            &st,
            user,
            &|| false,
            t0 + Duration::from_secs(90),
            &seen,
            Some(away),
            &|| {},
            &pace,
        );
        assert!(
            matches!(r, Some(Round::FaceLost)),
            "the hold ran to its end"
        );
        assert!(
            clock.get() - t0 <= away + pace.look_every,
            "out after {:?}",
            clock.get() - t0
        );
        // The secure mode's lock on the first failed check, which the
        // watch makes on its own tick, is made under the card too: out at
        // the first look, not at the away time.
        assert_eq!(looks, 1, "out at the first failed check");
        assert!(clock.get() - t0 <= pace.look_every);
        assert_eq!(unasked, 0, "a look in the secure mode skipped the check");

        // The shape holds a hidden face only on a look that asked who it
        // is, in either mode: unasked, the same chair holds nothing.
        for mode in [PresenceMode::Default, PresenceMode::Secure] {
            let seen = UserSeen::new(t0);
            seen.mode.set(mode);
            assert!(seen.judge(&at_the_desk(Some(true)), t0, true).held);
            let hidden = Observation {
                face: false,
                attentive: false,
                bbox: None,
                identity: None,
                ..at_the_desk(None)
            };
            let later = t0 + Duration::from_secs(5);
            assert!(
                !seen.judge(&hidden, later, false).held,
                "{:?}: unasked",
                mode
            );
            assert!(seen.judge(&hidden, later, true).held, "{:?}: asked", mode);
        }
    }

    /// Secure mode, a long card: the watch last checked the user two and a
    /// half minutes ago, past the window a hidden face is held by its shape
    /// in; the scan matched them just now. A near miss at the card (a hand
    /// on the chin) is held by the shape from that match, not locked; a
    /// stranger's clear miss after the match still locks at once.
    #[test]
    fn a_near_miss_after_a_scan_match_holds_and_a_strangers_miss_still_locks() {
        let user = "rr3-near-miss";
        let st = live(user);
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
        let matched_now = || {
            let long_ago = Instant::now()
                .checked_sub(Duration::from_secs(150))
                .unwrap();
            let seen = secure(UserSeen::new(long_ago));
            assert!(
                seen.judge(&at_the_desk(Some(true), false), long_ago, true)
                    .held
            );
            seen.sighted(Instant::now(), &frame, bbox);
            seen
        };
        let away = Some(Duration::from_secs(20));
        let seen = matched_now();
        let r = hold_wait(
            &mut |_| Ok(at_the_desk(Some(false), true)),
            &st,
            user,
            &|| false,
            Instant::now() + Duration::from_millis(30),
            &seen,
            away,
            &|| {},
            &at_once(),
        );
        assert!(
            r.is_none(),
            "the user's near miss was locked: {:?}",
            r.is_some()
        );
        let mut looks = 0;
        let r = hold_wait(
            &mut |_| {
                looks += 1;
                Ok(at_the_desk(Some(false), false))
            },
            &st,
            user,
            &|| false,
            Instant::now() + Duration::from_secs(30),
            &matched_now(),
            away,
            &|| {},
            &at_once(),
        );
        assert!(matches!(r, Some(Round::FaceLost)));
        assert_eq!(looks, 1, "a stranger's miss locks at once");
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
            &|| false,
            Instant::now() + Duration::from_secs(30),
            &secure(ago(21)),
            Some(Duration::from_secs(20)),
            &|| {},
            &at_once(),
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
            &|| false,
            Instant::now() + Duration::from_millis(30),
            &seen,
            Some(Duration::from_secs(20)),
            &|| {},
            &at_once(),
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
            &|| false,
            Instant::now() + Duration::from_millis(20),
            &ago(21),
            None,
            &|| {},
            &at_once(),
        );
        assert!(r.is_none());
        assert_eq!(n.get(), 0);
        st.push_answer(user, Answer::Dismiss);
        let r = hold_wait(
            &mut look,
            &st,
            user,
            &|| false,
            Instant::now() + Duration::from_secs(30),
            &ago(21),
            Some(Duration::from_secs(20)),
            &|| {},
            &at_once(),
        );
        assert!(r.is_none(), "the answer ends the hold before any look");
        assert_eq!(n.get(), 0);
    }

    /// The card's safety net: a pending card no daemon has spoken to for
    /// this long hides itself (Consent.qml's `autoClose` on a pending
    /// state).
    const CARD_SAFETY_NET: Duration = Duration::from_secs(300);

    /// D1: a pending card outlives the window's five-minute safety net for
    /// as long as the request waits. Twelve minutes of the attention wait,
    /// and a hold of eight (the longest), on a clock that moves only when
    /// the wait sleeps: the card is re-sent at least every `HEARTBEAT` and
    /// a look, so no gap between two sends reaches the net.
    #[test]
    fn a_pending_card_outlives_the_safety_net_while_heartbeats_arrive() {
        let user = "d1-heartbeat-test";
        let st = live(user);
        let clock = std::cell::Cell::new(Instant::now());
        let t0 = clock.get();
        let now = || clock.get();
        let sleep = |d: Duration| clock.set(clock.get() + d);
        let pace = stepped(&now, &sleep, &|| false);
        let sends = std::cell::RefCell::new(vec![t0]);
        let beat = || sends.borrow_mut().push(clock.get());
        let st_ref = &st;
        let mut look = |identify: bool| {
            if clock.get() - t0 >= Duration::from_secs(12 * 60) {
                st_ref.push_answer(user, Answer::Dismiss);
            }
            // At the card, reading: never an arm, never the user gone.
            Ok(obs(true, false, identify.then_some(true)))
        };
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &beat,
            RearmGate::new(true, PresenceMode::Default),
            None,
            &fresh(),
            &pace,
        );
        assert!(r.is_none(), "the answer ended the wait");
        let ended = clock.get();
        assert!(ended - t0 > CARD_SAFETY_NET * 2);
        let mut shown = sends.borrow().clone();
        shown.push(ended);
        let longest = shown.windows(2).map(|w| w[1] - w[0]).max().unwrap();
        assert!(
            longest <= crate::consent::HEARTBEAT + pace.look_every && longest < CARD_SAFETY_NET,
            "the card went {:?} without a send",
            longest
        );
        assert!(matches!(st.poll(user), Some(Answer::Dismiss)));

        let t1 = clock.get();
        sends.replace(vec![t1]);
        let r = hold_wait(
            &mut |_| panic!("no watch, no looks"),
            &st,
            user,
            &|| false,
            t1 + Duration::from_secs(8 * 60),
            &fresh(),
            None,
            &beat,
            &pace,
        );
        assert!(r.is_none(), "the hold ran to its end");
        let ended = clock.get();
        assert!(ended - t1 >= Duration::from_secs(8 * 60));
        let mut shown = sends.borrow().clone();
        shown.push(ended);
        let longest = shown.windows(2).map(|w| w[1] - w[0]).max().unwrap();
        assert!(
            longest <= crate::consent::HEARTBEAT + pace.look_every && longest < CARD_SAFETY_NET,
            "the card went {:?} without a send during the hold",
            longest
        );
    }

    /// D3: while a card waits, the chair is looked at every
    /// `battery_tick_seconds` on battery and every two seconds on mains,
    /// switching at the next look when the power source changes; the
    /// answer slot is read every 200 ms either way.
    #[test]
    fn the_attention_wait_looks_at_the_battery_tick_on_battery() {
        let user = "d3-battery-test";
        let st = live(user);
        let clock = std::cell::Cell::new(Instant::now());
        let t0 = clock.get();
        let now = || clock.get();
        let sleep = |d: Duration| clock.set(clock.get() + d);
        let battery = std::cell::Cell::new(true);
        let on_battery = || battery.get();
        let pace = stepped(&now, &sleep, &on_battery);
        let tick = crate::presence::PresenceConfig::default().battery_tick_seconds;
        assert_eq!(pace.battery_look_every, Duration::from_secs_f32(tick));
        let mut at = Vec::new();
        let st_ref = &st;
        let mut look = |identify: bool| {
            at.push((clock.get() - t0).as_secs_f32());
            match at.len() {
                4 => battery.set(false),
                8 => st_ref.push_answer(user, Answer::Dismiss),
                _ => {}
            }
            Ok(obs(true, false, identify.then_some(true)))
        };
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| {},
            RearmGate::new(true, PresenceMode::Default),
            None,
            &fresh(),
            &pace,
        );
        assert!(r.is_none());
        let t = |x: f32| (x * 10.0).round() / 10.0;
        let at: Vec<f32> = at.into_iter().map(t).collect();
        assert_eq!(
            at,
            [tick, 2.0 * tick, 3.0 * tick, 4.0 * tick]
                .into_iter()
                .chain((1..=4).map(|k| 4.0 * tick + 2.0 * k as f32))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            t((clock.get() - t0).as_secs_f32()),
            t(4.0 * tick + 8.2),
            "the answer was read at the next 200 ms tick"
        );
        // The daemon's own pace takes the configured battery tick, and
        // never looks oftener on battery than on mains.
        let live = Pace::live(tick);
        assert_eq!(live.battery_look_every, Duration::from_secs_f32(tick));
        assert_eq!(live.look_every, Duration::from_secs(2));
        assert_eq!(live.tick, Duration::from_millis(200));
        assert_eq!(Pace::live(0.0).battery_look_every, live.look_every);
        assert_eq!(Pace::live(1.0).battery_look_every, live.look_every);
    }

    /// D3: on battery the looks are a minute apart, and the session lock
    /// is still read every two seconds between them: a session that locks
    /// under a waiting card parks the request within one mains rhythm, with
    /// no look taken, and the lock helper runs no oftener than that.
    #[test]
    fn a_lock_under_a_waiting_card_is_read_between_battery_looks() {
        let user = "d3-lock-test";
        let st = live(user);
        let clock = std::cell::Cell::new(Instant::now());
        let t0 = clock.get();
        let now = || clock.get();
        let sleep = |d: Duration| clock.set(clock.get() + d);
        let pace = Pace {
            battery_look_every: Duration::from_secs(60),
            ..stepped(&now, &sleep, &|| true)
        };
        let checks = std::cell::Cell::new(0u32);
        let locked = || {
            checks.set(checks.get() + 1);
            clock.get() - t0 >= Duration::from_secs(21)
        };
        let r = attention_wait(
            &mut |_| panic!("the session locked before the first battery look"),
            &st,
            user,
            &locked,
            &|| {},
            RearmGate::new(true, PresenceMode::Default),
            None,
            &fresh(),
            &pace,
        );
        assert!(matches!(r, Some(Round::SessionLocked)));
        let parked = clock.get() - t0;
        assert!(
            parked >= Duration::from_secs(21)
                && parked <= Duration::from_secs(21) + pace.look_every,
            "parked {:?} after the lock at 21 s",
            parked
        );
        assert!(
            checks.get() <= 11,
            "the lock helper ran {} times in {:?}",
            checks.get(),
            parked
        );
    }

    /// D3: the heartbeat keeps its own time. With the looks ten minutes
    /// apart (longer than any config may set), a waiting card and a hold
    /// are still re-sent within `HEARTBEAT` and one 200 ms tick, far
    /// inside the card's five-minute safety net.
    #[test]
    fn the_heartbeat_is_on_time_whatever_the_look_interval() {
        let user = "d3-heartbeat-test";
        let st = live(user);
        let clock = std::cell::Cell::new(Instant::now());
        let t0 = clock.get();
        let now = || clock.get();
        let sleep = |d: Duration| clock.set(clock.get() + d);
        let pace = Pace {
            battery_look_every: Duration::from_secs(600),
            ..stepped(&now, &sleep, &|| true)
        };
        let sends = std::cell::RefCell::new(vec![t0]);
        let beat = || sends.borrow_mut().push(clock.get());
        let longest = |ended: Instant| {
            let mut shown = sends.borrow().clone();
            shown.push(ended);
            shown.windows(2).map(|w| w[1] - w[0]).max().unwrap()
        };
        let st_ref = &st;
        let mut look = |identify: bool| {
            if clock.get() - t0 >= Duration::from_secs(12 * 60) {
                st_ref.push_answer(user, Answer::Dismiss);
            }
            Ok(obs(true, false, identify.then_some(true)))
        };
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &beat,
            RearmGate::new(true, PresenceMode::Default),
            None,
            &fresh(),
            &pace,
        );
        assert!(r.is_none(), "the answer ended the wait");
        let gap = longest(clock.get());
        assert!(
            gap <= crate::consent::HEARTBEAT + pace.tick,
            "the waiting card went {:?} without a send",
            gap
        );
        assert!(matches!(st.poll(user), Some(Answer::Dismiss)));

        let t1 = clock.get();
        sends.replace(vec![t1]);
        let r = hold_wait(
            &mut |identify| Ok(obs(true, false, identify.then_some(true))),
            &st,
            user,
            &|| false,
            t1 + Duration::from_secs(8 * 60),
            &fresh(),
            Some(Duration::from_secs(20 * 60)),
            &beat,
            &pace,
        );
        assert!(r.is_none(), "the hold ran to its end");
        let gap = longest(clock.get());
        assert!(
            gap <= crate::consent::HEARTBEAT + pace.tick,
            "the card went {:?} without a send during the hold",
            gap
        );
    }

    /// The daemon's rhythm on a clock the test steps: the slot every
    /// 200 ms, a look every two seconds on mains and every presence
    /// battery tick on battery.
    fn stepped<'a>(
        now: &'a dyn Fn() -> Instant,
        sleep: &'a dyn Fn(Duration),
        on_battery: &'a dyn Fn() -> bool,
    ) -> Pace<'a> {
        let live = Pace::live(crate::presence::PresenceConfig::default().battery_tick_seconds);
        Pace {
            tick: live.tick,
            look_every: live.look_every,
            battery_look_every: live.battery_look_every,
            on_battery,
            now,
            sleep,
        }
    }

    fn mains() -> bool {
        false
    }

    fn no_sleep(_: Duration) {}

    /// Every look at once, on the real clock.
    fn at_once() -> Pace<'static> {
        Pace {
            tick: Duration::ZERO,
            look_every: Duration::ZERO,
            battery_look_every: Duration::ZERO,
            on_battery: &mains,
            now: &Instant::now,
            sleep: &no_sleep,
        }
    }

    fn fresh() -> UserSeen {
        UserSeen::new(Instant::now())
    }

    /// A request clock that last saw the user this many seconds ago.
    fn ago(secs: u64) -> UserSeen {
        UserSeen::new(
            Instant::now()
                .checked_sub(Duration::from_secs(secs))
                .expect("the machine has been up longer than that"),
        )
    }

    /// The same, with the watch's rules in the secure mode.
    fn secure(seen: UserSeen) -> UserSeen {
        seen.mode.set(PresenceMode::Secure);
        seen
    }
}
