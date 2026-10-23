//! A consent request across camera rounds. It parks without the camera
//! while the user is away and the session is locked, so the lock screen can
//! use the camera meanwhile.

use crate::auth::{consent_denied, Authenticator, Outcome, Refusal};
use crate::lockgate::{Verdict, WaitBudget, UNKNOWN_LIMIT};
use std::time::{Duration, Instant};

/// The longest a consent request waits for the camera before it answers
/// "busy": below `lockgate::LIVENESS`, so the module is told of it rather
/// than giving up on a daemon it takes for hung.
use crate::lockgate::CAMERA_WAIT;

/// A request that has waited on an unknown lock state for
/// `UNKNOWN_LIMIT`: its answer, an error the module reads as no answer, so
/// sudo and polkit alike go on to their key line, which falls to the
/// password on the same doubt. None while the doubt is shorter.
pub(super) fn unknown_too_long(
    state: &crate::consent::ConsentState,
    user: &str,
) -> Option<Outcome> {
    (state.doubt_for(user) >= UNKNOWN_LIMIT).then(|| Outcome::Error {
        message: format!(
            "the session's lock state has read as unknown for {} s; use the password",
            UNKNOWN_LIMIT.as_secs()
        ),
    })
}

/// A consent request's wait budget (round 8, Codex 1, Opus F1): the time
/// it has spent, in all, waiting on a verdict that is neither unlocked nor
/// a positive lock, never reset, so a lock channel opened and closed over
/// and over cannot hold it off the password. Once it reaches
/// `UNKNOWN_LIMIT` the request ends as an error, which both lanes pass on
/// as no answer, and the user's key line goes on to the password too
/// (`ConsentState::note_budget_spent`).
#[derive(Default)]
pub(super) struct Park {
    budget: WaitBudget,
}

impl Park {
    /// One verdict at `now` (since the request began): the request's
    /// answer once its budget is spent.
    pub(super) fn look(
        &mut self,
        state: &crate::consent::ConsentState,
        user: &str,
        v: Verdict,
        now: Duration,
    ) -> Option<Outcome> {
        let spent = self.budget.observe(v, now);
        if !matches!(v, Verdict::Unknown | Verdict::Held) || spent < UNKNOWN_LIMIT {
            return None;
        }
        state.note_budget_spent(user);
        Some(Outcome::Error {
            message: format!(
                "the session's lock state has kept the request waiting for {} s; use the password",
                UNKNOWN_LIMIT.as_secs()
            ),
        })
    }
}

/// When a parked request looks at the lock again (fix round 8, Codex and
/// Opus L1): every 2 s while it holds steady, every 500 ms while it reads
/// anything else, and at once when the user's lock channels change (the
/// lock screen's graceful close at the unlock). Between looks the park
/// waits on the consent record's changes, not on a timer.
pub(super) struct Cadence {
    at: Instant,
    verdict: Verdict,
    channels: usize,
}

/// The steady-lock interval, and the one for everything else.
const STEADY_LOOK: Duration = Duration::from_secs(2);
const UNSTEADY_LOOK: Duration = Duration::from_millis(500);

impl Cadence {
    pub(super) fn new(at: Instant, verdict: Verdict, channels: usize) -> Cadence {
        Cadence {
            at,
            verdict,
            channels,
        }
    }

    /// Whether a look is due at `now`, with `channels` open now.
    pub(super) fn due(&self, now: Instant, channels: usize) -> bool {
        let every = if self.verdict == Verdict::Locked {
            STEADY_LOOK
        } else {
            UNSTEADY_LOOK
        };
        channels != self.channels || now.saturating_duration_since(self.at) >= every
    }

    /// A look at `now` said `verdict`, with `channels` open.
    pub(super) fn looked(&mut self, now: Instant, verdict: Verdict, channels: usize) {
        *self = Cadence::new(now, verdict, channels);
    }
}

/// The end of a request whose requester left (`Refusal::Gone`), as its
/// lane takes it: sudo's line ends there, the requester being gone; polkit's
/// is a refusal, so its stack ends (`auth_err=die`) rather than going on to
/// its key line for a request polkitd has given up, whose helper is still
/// there to ask (live test 1, 2026-10-13).
pub(super) fn gone_now(caller: &crate::consent::CallerInfo, elapsed_ms: u64) -> Outcome {
    crate::auth::refused(caller, Refusal::Gone, elapsed_ms)
}

/// Drive a consent request through as many camera rounds as it needs. When
/// the user leaves mid-request the session is locked and the request parks
/// without the camera (so the lock screen can use it), until the user is back
/// (a face match on the lock screen), the session unlocks by other means,
/// or a password or a dismissal arrives from the window.
pub(super) fn consent_rounds<'a>(
    take: &dyn Fn() -> Option<std::sync::MutexGuard<'a, Authenticator>>,
    user: &str,
    caller: crate::consent::CallerInfo,
) -> Outcome {
    use crate::auth::Round;
    use crate::consent::{Answer, Gesture, CONSENT};
    use crate::presence::SESSION_LOCK;
    let gone = || CONSENT.requester_gone(user);
    // The session this request's lock question is about, and its wait
    // budget, kept from its first look to its last (round 8).
    let bind = caller.bind.clone();
    let t0 = Instant::now();
    let mut park = Park::default();
    let verdict = || crate::consent::lock_verdict(user, &bind);
    // A request that arrives while the session is locked waits, unseen and
    // without the camera (the lock screen owns it), until the unlock. The
    // window is not summoned at all: hiding a pending window would make it
    // answer with a dismissal.
    let mut already_locked = verdict() != Verdict::Unlocked;
    // The lock screen may hold the camera as the request starts (it locked
    // a moment ago and is scanning): wait a little for it rather than
    // answer "busy" at once, but no longer than `CAMERA_WAIT`, so a camera
    // held elsewhere still leaves the password in reach in time (round 6,
    // item 12).
    let begin_by = Instant::now() + CAMERA_WAIT;
    let mut session = loop {
        // A request whose requester left while it waited its turn never
        // brings a card up.
        if gone() {
            return gone_now(&caller, 0);
        }
        match take() {
            Some(mut a) => match a.consent_begin(user, caller, !already_locked) {
                Ok(s) => break s,
                Err(o) => return o,
            },
            None => {
                if let Some(o) = unknown_too_long(&CONSENT, user) {
                    return o;
                }
                if Instant::now() > begin_by {
                    return Outcome::Error {
                        message: "busy".into(),
                    };
                }
                std::thread::sleep(Duration::from_millis(300));
                let v = verdict();
                if let Some(o) = park.look(&CONSENT, user, v, t0.elapsed()) {
                    return o;
                }
                already_locked = v != Verdict::Unlocked;
            }
        }
    };
    if already_locked {
        log::info!("consent: request from pid {} arrived while the session is locked; parked until the unlock", session.caller.pid);
    }
    let mut camera_busy_since: Option<Instant> = None;
    loop {
        if gone() {
            log::info!(
                "consent: the requester went away after {:.0}s; window closed",
                session.started.elapsed().as_secs_f32()
            );
            return gone_now(
                &session.caller,
                session.started.elapsed().as_millis() as u64,
            );
        }
        if !already_locked {
            let round = match take() {
                Some(mut a) => {
                    camera_busy_since = None;
                    a.consent_round(&mut session)
                }
                None => {
                    // The camera is taken (the lock screen, most likely): wait
                    // a little and try again rather than giving up, for up to
                    // `CAMERA_WAIT` (round 6, item 12).
                    if camera_busy_since.get_or_insert_with(Instant::now).elapsed() > CAMERA_WAIT {
                        return Outcome::Error {
                            message: "busy".into(),
                        };
                    }
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            };
            match round {
                Round::Done(o) => return o,
                Round::FaceLost => {}
                // Locked by other means under the card: adopt the lock and
                // park, without locking again or announcing a lock (D2).
                Round::SessionLocked => already_locked = true,
            }
        }
        // A parked request takes no key approval: whatever key check is
        // still out answers nothing, and a touch already waiting in the
        // slot, or a PIN, is dropped, and the user is latched, so the card
        // takes no touch until the daemon sees the unlock and the hold
        // passes. The lock screen takes the key itself.
        CONSENT.latch_lock_screen(user);
        // Lock the session, or take over a lock made by other means, then
        // park. One lock for the daemon: the presence watch sees the same
        // record and waits for the same unlock, so it never locks twice.
        let lock_time = if already_locked {
            SESSION_LOCK.adopt(Instant::now())
        } else {
            let omarchy_path = crate::consent::omarchy_path();
            match SESSION_LOCK.lock(&session.dialog.cfg.presence.user, &omarchy_path) {
                Ok(t) => {
                    log::info!("consent: user left with a request pending; session locked");
                    t
                }
                Err(e) => {
                    log::warn!("consent: lock command: {}", e);
                    Instant::now()
                }
            }
        };
        if !already_locked {
            let _ = session.dialog.show("locked", "Locked while you were away. Unlock, then look at the camera or type your password.", &session.caller);
        }
        already_locked = false;
        // Park: no camera. Wake on a face match newer than the lock, on the
        // session unlocking by any means, or on an answer from the window.
        let mut last_beat = Instant::now();
        let mut v = verdict();
        let mut cadence = Cadence::new(Instant::now(), v, CONSENT.channels_open(user));
        loop {
            // Parked on a lock state nobody can read: after `UNKNOWN_LIMIT`
            // the request ends and the stack goes to the password, never
            // to the key (Opus N1).
            if let Some(o) = unknown_too_long(&CONSENT, user) {
                log::warn!("consent: the lock state has read as unknown too long; the request falls to the password");
                return o;
            }
            // Churn cannot start the wait over either (round 8): the
            // request's whole budget of waits on no positive lock. The lock
            // is looked at on the park's cadence (fix round 8).
            let channels = CONSENT.channels_open(user);
            if cadence.due(Instant::now(), channels) {
                v = verdict();
                cadence.looked(Instant::now(), v, channels);
            }
            if let Some(o) = park.look(&CONSENT, user, v, t0.elapsed()) {
                log::warn!("consent: the request has waited its budget on no positive lock; it falls to the password");
                return o;
            }
            // The card, if one is up behind the lock, is re-sent now and
            // then so its own safety net does not hide it (D1).
            if last_beat.elapsed() >= crate::consent::HEARTBEAT {
                last_beat = Instant::now();
                session.dialog.heartbeat(&session.caller);
            }
            if let Some(ans) = CONSENT.poll(user) {
                // Nothing to arm behind a lock; the unlock re-arms. A key
                // touch or a finger never answers a card behind the lock
                // screen.
                if matches!(ans, Answer::Rearm | Answer::Key | Answer::Fingerprint) {
                    continue;
                }
                if matches!(ans, crate::consent::Answer::Gone) {
                    log::info!("consent: the requester went away while the session was locked; window closed");
                    return gone_now(
                        &session.caller,
                        session.started.elapsed().as_millis() as u64,
                    );
                }
                let g = match ans {
                    Answer::Password(pw) => Gesture::Password(pw),
                    Answer::Dismiss => Gesture::Dismissed,
                    Answer::Gone | Answer::Rearm | Answer::Key | Answer::Fingerprint => {
                        Gesture::Gone
                    }
                };
                let ms = session.started.elapsed().as_millis() as u64;
                loop {
                    if let Some(mut a) = take() {
                        let o = a.consent_finish(
                            &mut session,
                            Some(g),
                            Outcome::NoFace { elapsed_ms: ms },
                        );
                        // Unapproved behind the lock: sudo skips its FIDO2
                        // line, so the unlock touch stays with the lock.
                        return crate::auth::parked(&session.caller, o);
                    }
                }
            }
            let matched = match take() {
                Some(a) => a.last_match.get(user).is_some_and(|m| *m > lock_time),
                None => false,
            };
            let how =
                SESSION_LOCK.resumed(Instant::now(), matched, Duration::from_secs(2), &|| {
                    v != Verdict::Unlocked
                });
            if let Some(how) = how {
                log::info!(
                    "consent: user back after the lock ({}); the request resumes",
                    how
                );
                // The unlock is the user back at the card: the request's
                // away clock starts over, or the next round would end
                // with the user gone before its first look (E2). The key
                // generation moves on too: nothing from before the park
                // counts at the card it returns to.
                session.user_seen_at.set(Instant::now());
                CONSENT.key_off(user, true);
                // A card last read before the lock is a card the user has
                // not read since: its acknowledgment is dropped, never
                // restamped, and this show waits for a fresh one, from
                // which the key waits a whole dwell (the nods count from
                // the next scan's match). A
                // card that does not come back (the shell gone, no fresh
                // acknowledgment) is one nobody sees: the request ends
                // unapproved, as one parked behind the lock does, and the
                // key is never re-armed for it.
                session.dialog.reset_ack();
                if let Err(e) = session.dialog.show(
                    "scanning",
                    "Welcome back. Look at the camera.",
                    &session.caller,
                ) {
                    log::warn!(
                        "consent: the card did not come back after the unlock: {}",
                        e
                    );
                    return crate::auth::parked(
                        &session.caller,
                        consent_denied(
                            Refusal::NoWindow,
                            session.started.elapsed().as_millis() as u64,
                        ),
                    );
                }
                break;
            }
            // Wait for the record to change (a channel, an answer, a
            // latch) or the next cheap check, not on a fixed poll.
            CONSENT.wait_change(UNSTEADY_LOOK);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockgate::{Desktop, LockState, Verdict};

    /// Opus N1: a request parked on a lock state nobody can read ends once
    /// the doubt has lasted `UNKNOWN_LIMIT`, as an error, which lane_answer
    /// passes to both lanes as no answer, so the stack goes on to the key
    /// line and the password; a positive lock keeps it parked.
    #[test]
    fn a_park_on_an_unknown_lock_state_ends_in_time() {
        use crate::lockgate::Origin;
        let st: &'static crate::consent::ConsentState =
            Box::leak(Box::new(crate::consent::ConsentState::new()));
        let user = "rounds-unknown-user";
        assert_eq!(
            st.judge(user, LockState::Unknown, Desktop::Some),
            Verdict::Unknown
        );
        assert!(unknown_too_long(st, user).is_none());
        st.backdate_doubt(user, UNKNOWN_LIMIT);
        let o = unknown_too_long(st, user).expect("past the limit");
        assert!(matches!(o, Outcome::Error { .. }));
        for via in ["sudo", "polkit"] {
            let a =
                crate::auth::lane_answer(via, o.clone(), &|| (Verdict::Unknown, Origin::Desktop));
            assert!(!matches!(a, Outcome::Refused { .. }), "{}: {:?}", via, a);
        }
        st.channel_open(user);
        assert_eq!(
            st.judge(user, LockState::Locked, Desktop::Some),
            Verdict::Locked
        );
        assert!(
            unknown_too_long(st, user).is_none(),
            "a positive lock waits"
        );
        assert!(CAMERA_WAIT < crate::lockgate::LIVENESS);
    }

    /// Round 8 (Codex 1, Opus F1): a parked request's wait budget is
    /// cumulative. Churn between unknown, held and unlocked (a channel
    /// opened and closed over and over) never starts it over; a positive
    /// lock is waited on freely; once it is spent the request ends as an
    /// error, and the user's key line goes on to the password.
    #[test]
    fn a_parks_wait_budget_is_cumulative_under_churn() {
        let st: &'static crate::consent::ConsentState =
            Box::leak(Box::new(crate::consent::ConsentState::new()));
        let user = "rounds-churn-user";
        let mut park = Park::default();
        let ms = Duration::from_millis;
        let mut t = Duration::ZERO;
        let mut cycles = 0;
        let ended = 'churn: loop {
            for (v, d) in [
                (Verdict::Unknown, ms(2000)),
                (Verdict::Held, ms(500)),
                (Verdict::Unlocked, ms(3000)),
                (Verdict::Locked, ms(30_000)),
            ] {
                if let Some(o) = park.look(st, user, v, t) {
                    break 'churn o;
                }
                t += d;
            }
            cycles += 1;
            assert!(cycles < 10, "the budget never ran out");
        };
        assert!(matches!(ended, Outcome::Error { .. }));
        assert_eq!(cycles, 4, "four cycles of 2.5 s counted");
        assert!(
            t > Duration::from_secs(100),
            "the lock and unlocked stretches did not count"
        );
        assert!(st.budget_spent(user), "the key line hears of it");
        assert!(!st.budget_spent("rounds-churn-other"));
    }

    /// Fix round 8 (Codex, Opus L1): a parked request looks at the lock
    /// every 2 s while it holds steady, sooner while it reads anything
    /// else, and at once when the user's channels change (the lock
    /// screen's graceful close at the unlock); between looks it waits on
    /// the consent record's changes rather than polling.
    #[test]
    fn a_park_looks_on_a_cadence_and_on_channel_changes() {
        let ms = Duration::from_millis;
        let t0 = Instant::now();
        let mut c = Cadence::new(t0, Verdict::Locked, 1);
        assert!(!c.due(t0 + ms(1900), 1), "a steady lock: not yet");
        assert!(c.due(t0 + ms(2000), 1), "every 2 s");
        assert!(c.due(t0 + ms(100), 0), "the channel closed: at once");
        c.looked(t0 + ms(2000), Verdict::Unknown, 1);
        assert!(!c.due(t0 + ms(2400), 1));
        assert!(c.due(t0 + ms(2500), 1), "not steady: every 500 ms");
        // The wait wakes on the record's changes.
        let st: &'static crate::consent::ConsentState =
            Box::leak(Box::new(crate::consent::ConsentState::new()));
        let w = std::thread::spawn(move || {
            let t = Instant::now();
            st.wait_change(Duration::from_secs(5));
            t.elapsed()
        });
        std::thread::sleep(ms(50));
        let _ = st.channel_open("rounds-wake-user");
        assert!(w.join().unwrap() < ms(1000), "woken by the channel");
    }

    /// Live test 1 (2026-10-13): a request whose requester left ends
    /// polkit's stack: a refusal, which the module answers PAM_AUTH_ERR
    /// (polkit's `auth_err=die`), so its key line never runs a check for a
    /// request polkitd has given up. The lane's gate passes it as it is,
    /// whatever the lock reads. Sudo's stays the gone denial.
    #[test]
    fn a_gone_request_ends_polkits_stack_before_its_key_line() {
        use crate::consent::CallerInfo;
        use crate::lockgate::Origin;
        let caller = |via: &str| CallerInfo {
            via: via.into(),
            ..Default::default()
        };
        let gone = |o: &Outcome| match o {
            Outcome::Refused { reason, .. } | Outcome::ConsentDenied { reason, .. } => {
                Refusal::parse(reason) == Some(Refusal::Gone)
            }
            _ => false,
        };
        let polkit = gone_now(&caller("polkit"), 5);
        assert!(
            matches!(polkit, Outcome::Refused { .. }) && gone(&polkit),
            "{:?}",
            polkit
        );
        for verdict in [Verdict::Unlocked, Verdict::Locked, Verdict::Unknown] {
            assert_eq!(
                crate::auth::lane_answer("polkit", polkit.clone(), &|| (verdict, Origin::Desktop)),
                polkit,
                "{:?}",
                verdict
            );
        }
        let sudo = gone_now(&caller("sudo"), 5);
        assert!(
            matches!(sudo, Outcome::ConsentDenied { .. }) && gone(&sudo),
            "{:?}",
            sudo
        );
    }
}
