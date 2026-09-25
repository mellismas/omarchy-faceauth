//! A consent request across camera rounds. It parks without the camera
//! while the user is away and the session is locked, so the lock screen can
//! use the camera meanwhile.

use crate::auth::{consent_denied, Authenticator, Outcome, Refusal};
use std::time::{Duration, Instant};

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
    // A request that arrives while the session is locked waits, unseen and
    // without the camera (the lock screen owns it), until the unlock. The
    // window is not summoned at all: hiding a pending window would make it
    // answer with a dismissal.
    let mut already_locked = crate::consent::session_locked(user);
    // The lock screen may hold the camera as the request starts (it locked
    // a moment ago and is scanning): wait for it rather than answer "busy",
    // which the module would turn into the caller's password prompt.
    let begin_by = Instant::now() + Duration::from_secs(20);
    let mut session = loop {
        match take() {
            Some(mut a) => match a.consent_begin(user, caller, !already_locked) {
                Ok(s) => break s,
                Err(o) => return o,
            },
            None => {
                if gone() {
                    return consent_denied(Refusal::Gone, 0);
                }
                if Instant::now() > begin_by {
                    return Outcome::Error {
                        message: "busy".into(),
                    };
                }
                std::thread::sleep(Duration::from_millis(300));
                already_locked = crate::consent::session_locked(user);
            }
        }
    };
    if already_locked {
        log::info!("consent: request from pid {} arrived while the session is locked; parked until the unlock", session.caller.pid);
    }
    loop {
        if gone() {
            log::info!(
                "consent: the requester went away after {:.0}s; window closed",
                session.started.elapsed().as_secs_f32()
            );
            return consent_denied(Refusal::Gone, session.started.elapsed().as_millis() as u64);
        }
        if !already_locked {
            let round = match take() {
                Some(mut a) => a.consent_round(&mut session),
                None => {
                    // The camera is taken (the lock screen, most likely): wait
                    // a little and try again rather than giving up.
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
        loop {
            // The card, if one is up behind the lock, is re-sent now and
            // then so its own safety net does not hide it (D1).
            if last_beat.elapsed() >= crate::consent::HEARTBEAT {
                last_beat = Instant::now();
                session.dialog.heartbeat(&session.caller);
            }
            if let Some(ans) = CONSENT.poll(user) {
                // Nothing to arm behind a lock; the unlock re-arms.
                if matches!(ans, Answer::Rearm) {
                    continue;
                }
                if matches!(ans, crate::consent::Answer::Gone) {
                    log::info!("consent: the requester went away while the session was locked; window closed");
                    return consent_denied(
                        Refusal::Gone,
                        session.started.elapsed().as_millis() as u64,
                    );
                }
                let g = match ans {
                    Answer::Password(pw) => Gesture::Password(pw),
                    Answer::Dismiss => Gesture::Dismissed,
                    Answer::Gone | Answer::Rearm => Gesture::Gone,
                };
                let ms = session.started.elapsed().as_millis() as u64;
                loop {
                    if let Some(mut a) = take() {
                        return a.consent_finish(
                            &mut session,
                            Some(g),
                            Outcome::NoFace { elapsed_ms: ms },
                        );
                    }
                }
            }
            let matched = match take() {
                Some(a) => a.last_match.get(user).is_some_and(|m| *m > lock_time),
                None => false,
            };
            let how =
                SESSION_LOCK.resumed(Instant::now(), matched, Duration::from_secs(2), &|| {
                    crate::consent::session_locked(user)
                });
            if let Some(how) = how {
                log::info!(
                    "consent: user back after the lock ({}); the request resumes",
                    how
                );
                // The unlock is the user back at the card: the request's
                // away clock starts over, or the next round would end
                // with the user gone before its first look (E2).
                session.user_seen_at.set(Instant::now());
                let _ = session.dialog.show(
                    "scanning",
                    "Welcome back. Look at the camera.",
                    &session.caller,
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }
}
