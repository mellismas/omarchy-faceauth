//! One connection from its request line to its reply: the request's
//! fields, who is asking, what they may ask for, and which lane (a plain
//! look, a consent request, the enrolment walk-through, a presence query)
//! answers it.

use super::acl::{apply_socket_acl, refresh_socket_acl};
use super::admit::{admit_plain_look, is_own_pid, lid_closed};
use super::backoff::{is_explicit_no, refusal_standing, refused};
use super::locality::{active_graphical_session, locality, pidfd_open, LiveProcs, Locality};
use super::presence::presence_query;
use super::read::read_request;
use super::rounds::consent_rounds;
use super::serve::Slot;
use super::{reply, user_uid};
use crate::auth::{consent_denied, Authenticator, Outcome, Refusal};
use anyhow::{Context, Result};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde::Deserialize;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a request waits for the camera before answering "busy".
pub(super) const BUSY_WAIT: Duration = Duration::from_millis(1500);
/// How long the enrolment walk-through waits: a presence look that
/// identifies and strobes holds the camera for about two seconds, and the
/// person has just clicked Enrol, so waiting out one tick beats "busy".
const ENROL_WAIT: Duration = Duration::from_secs(6);

/// A request line. Unknown fields are refused rather than dropped: a
/// misspelt answer field would otherwise read as a plain look (A3).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    user: String,
    /// true: a presence probe (one short look, detector only) instead of an attempt.
    #[serde(default)]
    probe: bool,
    /// Root only, development builds only: a pose sweep of this many
    /// seconds, scored per frame. The package has no such field, so the
    /// request is refused as unknown there (H2).
    #[cfg(feature = "dev-tools")]
    #[serde(default)]
    sweep_seconds: Option<f32>,
    /// true: is the daemon up, with models loaded and this user enrolled?
    #[serde(default)]
    ping: bool,
    /// Some: enrol this user with the given label.
    #[serde(default)]
    enroll: Option<String>,
    /// With `enroll`: keep only frames in this pose (see `auth::POSES`).
    #[serde(default)]
    enroll_pose: Option<String>,
    /// Root only: the enrolment walk-through (see `enrol`); the reply is
    /// the outcome when it ends.
    #[serde(default)]
    enrol_session: Option<crate::enrol::Start>,
    /// From the user's window: stream the session's frames on this
    /// connection until it ends.
    #[serde(default)]
    enrol_watch: bool,
    /// From the user's window: "continue", "redo" or "cancel".
    #[serde(default)]
    enrol_control: Option<String>,
    #[serde(default)]
    seconds: Option<f32>,
    #[serde(default)]
    count: Option<usize>,
    /// Delete this user's templates (own user, or root for anyone).
    #[serde(default)]
    delete_templates: bool,
    /// An elevation: open the consent window, require the nod.
    #[serde(default)]
    consent: bool,
    /// From the consent window: the typed password for the pending request.
    #[serde(default)]
    consent_password: Option<String>,
    /// From the consent window: dismiss the pending request.
    #[serde(default)]
    consent_dismiss: bool,
    /// From the consent window: it has drawn the request the token names.
    #[serde(default)]
    consent_ack: bool,
    /// From the consent window: the user pressed "Ready to nod" after a nod
    /// window passed unanswered, so the nods may be armed again.
    #[serde(default)]
    consent_rearm: bool,
    /// From the consent window: with the approval of this request, turn
    /// passwordless sudo on for this many minutes.
    #[serde(default)]
    consent_passwordless: Option<u32>,
    /// From the consent window: the token the daemon put in its payload.
    #[serde(default)]
    consent_token: Option<String>,
    /// From the polkit agent: what the request it is about to serve is.
    #[serde(default)]
    context_action: Option<String>,
    #[serde(default)]
    context_message: Option<String>,
    /// Sent by the agent and read by nothing: the cookie names polkit's
    /// own session, which the daemon has no use for. Accepted so the
    /// agent's line is not refused as unknown.
    #[serde(default)]
    #[allow(dead_code)]
    context_cookie: Option<String>,
    /// From the polkit agent: polkitd's caller and subject pids, when its
    /// Quickshell exposes the request's details.
    #[serde(default)]
    context_caller_pid: Option<i32>,
    #[serde(default)]
    context_subject_pid: Option<i32>,
    /// From the watched user: switch the presence watch to "default" or
    /// "secure" until the next restart.
    #[serde(default)]
    presence_mode: Option<String>,
}

pub(super) fn handle(
    mut stream: UnixStream,
    auth: &Mutex<Authenticator>,
    slot: &Slot,
) -> Result<()> {
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let cred = getsockopt(&stream, PeerCredentials).context("peer credentials")?;
    // A face line on a stack the daemon itself runs (system-auth, through
    // the password check) would have it ask itself and wait forever: any
    // request from this daemon's own pid is answered "error" before a byte
    // is read, so that stack falls through (B6).
    if is_own_pid(cred.pid(), std::process::id()) {
        log::warn!("request from this daemon's own pid {}: refused; a face line is on a stack the daemon runs itself", cred.pid());
        return reply(
            &mut stream,
            &Outcome::Error {
                message: "the daemon does not ask itself".into(),
            },
        );
    }
    // Bounded read before anything else: a peer that never sends a newline
    // cannot grow this, one that dribbles cannot stretch it, and the error
    // never echoes the peer's bytes back.
    let Some(mut line) = read_request(&mut stream)? else {
        return reply(
            &mut stream,
            &Outcome::Error {
                message: "bad request".into(),
            },
        );
    };
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let parsed: std::result::Result<Request, _> = serde_json::from_str(line.trim());
    // The line may carry a password; its bytes are not left in freed memory (F12).
    crate::consent::wipe_string(&mut line);
    let mut req: Request = match parsed {
        Ok(r) => r,
        Err(_) => {
            return reply(
                &mut stream,
                &Outcome::Error {
                    message: "bad request".into(),
                },
            )
        }
    };
    // Root is never a face: sudo, polkit and the lock screen authenticate
    // the person at the keyboard, and root is only the privilege that writes
    // the store. Nothing enrols, matches, probes or calibrates uid 0.
    if user_uid(&req.user) == Some(0) {
        log::warn!(
            "uid {} asked about root: refused, root is never authenticated by face",
            cred.uid()
        );
        return reply(
            &mut stream,
            &Outcome::Error {
                message: "root is never authenticated by face".into(),
            },
        );
    }
    if !may_ask(cred.uid(), user_uid(&req.user)) {
        log::warn!("uid {} asked about {}: refused", cred.uid(), req.user);
        return reply(
            &mut stream,
            &Outcome::Error {
                message: "not permitted".into(),
            },
        );
    }
    // Face authentication is local by definition: the camera sees whoever is
    // at the machine, which says nothing about a caller reaching it over the
    // network. Every request, the probes and window answers included, must
    // come from a caller shown to be local; anything unprovable is remote,
    // and the caller's PAM stack falls through to its password.
    let peer_pidfd = getsockopt(&stream, nix::sys::socket::sockopt::PeerPidfd).ok();
    let agent = match locality(cred.pid(), peer_pidfd.as_ref(), &req.user) {
        Locality::Local(agent) => agent,
        Locality::Remote(why) => {
            log::warn!(
                "request for {} from pid {} (uid {}) refused: {}",
                req.user,
                cred.pid(),
                cred.uid(),
                why
            );
            return reply(
                &mut stream,
                &Outcome::Error {
                    message: format!("face authentication is local only: {}", why),
                },
            );
        }
    };
    // The peer as a kernel fact, for a polkit agent's context: its pid and
    // the pidfs id systemd writes into the helper instance it connects.
    let peer = peer_pidfd
        .as_ref()
        .and_then(|fd| nix::sys::stat::fstat(fd).ok())
        .map(|st| crate::consent::AgentPeer {
            pid: cred.pid(),
            id: st.st_ino,
        });
    // The camera is in the lid. With it closed there is nobody to nod, so a
    // consent request is answered before the camera is taken and the caller's
    // stack falls through to its password at once. Only consent: the lock
    // screen has its own presence handling and retries on its own timer.
    if req.consent && lid_closed() {
        log::info!(
            "consent request for {} from pid {} with the lid closed: falls through to the password",
            req.user,
            cred.pid()
        );
        return reply(
            &mut stream,
            &Outcome::Error {
                message: "the lid is closed".into(),
            },
        );
    }
    // Take the camera, or say "busy" instead of queueing behind another
    // attempt: the callers (PAM, the lock screen) retry on their own terms.
    let take_for = |wait: Duration| -> Option<std::sync::MutexGuard<'_, Authenticator>> {
        let deadline = Instant::now() + wait;
        loop {
            match auth.try_lock() {
                Ok(g) => return Some(g),
                Err(std::sync::TryLockError::Poisoned(p)) => return Some(p.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => {
                    if Instant::now() > deadline {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    };
    let take = || take_for(BUSY_WAIT);
    // The polkit agent, before its helper's PAM request arrives, says what
    // the request is. Queued per user in arrival order, single use, only
    // from a local caller (the gate above), and served only to a request
    // whose helper was connected by this very peer: the agent process must
    // send it itself, over its own connection.
    if let Some(action) = &req.context_action {
        let clip = crate::consent::clip;
        let ctx = crate::consent::PolkitContext {
            action: clip(action),
            message: clip(req.context_message.as_deref().unwrap_or("")),
            agent: peer,
            caller_pid: req.context_caller_pid,
            subject_pid: req.context_subject_pid,
            at: Instant::now(),
        };
        log::info!(
            "polkit context from uid {} pid {}: {} {} (caller pid {:?}, subject pid {:?})",
            cred.uid(),
            cred.pid(),
            ctx.action,
            ctx.message,
            ctx.caller_pid,
            ctx.subject_pid
        );
        if let Ok(mut m) = crate::consent::CONTEXTS.lock() {
            let q = m.entry(cred.uid()).or_default();
            q.push_back(ctx);
            while q.len() > 8 {
                q.pop_front();
            }
        }
        return reply(&mut stream, &Outcome::Noted);
    }
    // Answers to a pending consent request must not wait for the camera lock:
    // the consent flow holds it. They go into the live record, whose own
    // lock is held for microseconds.
    if req.consent_password.is_some()
        || req.consent_dismiss
        || req.consent_ack
        || req.consent_rearm
        || req.consent_passwordless.is_some()
    {
        let consent = &crate::consent::CONSENT;
        // Only the window the daemon summoned holds the token; a process
        // that merely reaches the socket cannot cancel or answer a request.
        // The token is the whole check: it exists exactly while a request
        // of this user's is live and has a window.
        if !consent.token_matches(&req.user, req.consent_token.as_deref()) {
            log::warn!(
                "consent answer for {} from uid {} pid {} without the request's token: refused",
                req.user,
                cred.uid(),
                cred.pid()
            );
            return reply(
                &mut stream,
                &Outcome::Error {
                    message: "no pending request".into(),
                },
            );
        }
        if req.consent_ack {
            consent.ack(&req.user, req.consent_token.as_deref());
            log::info!(
                "consent window for {} (uid {}, pid {}) acknowledged the request",
                req.user,
                cred.uid(),
                cred.pid()
            );
            return reply(&mut stream, &Outcome::Noted);
        }
        if let Some(minutes) = req.consent_passwordless {
            // The rider record decides: the token must be the card's own
            // request, the lane sudo, and the enrolled face in the nod
            // window now. The card greys its button on the same signal, so
            // a program driving the socket gets no more than the button.
            let armed = consent.arm_passwordless(
                &req.user,
                req.consent_token.as_deref().unwrap_or(""),
                minutes,
            );
            match &armed {
                Ok(()) => log::info!(
                    "consent window for {} (uid {}): passwordless sudo for {} min armed on this request's approval",
                    req.user,
                    cred.uid(),
                    minutes
                ),
                Err(why) => log::warn!(
                    "consent window for {} (uid {}, pid {}): passwordless sudo for {} min refused: {}",
                    req.user,
                    cred.uid(),
                    cred.pid(),
                    minutes,
                    why
                ),
            }
            let o = match armed {
                Ok(()) => Outcome::Noted,
                Err(why) => Outcome::Error {
                    message: why.into(),
                },
            };
            return reply(&mut stream, &o);
        }
        let answer = if req.consent_dismiss {
            crate::consent::Answer::Dismiss
        } else if req.consent_rearm {
            crate::consent::Answer::Rearm
        } else {
            crate::consent::Answer::Password(crate::consent::Secret::new(
                req.consent_password.take().unwrap_or_default(),
            ))
        };
        if let Err(why) = consent.answer(&req.user, req.consent_token.as_deref(), answer) {
            return reply(
                &mut stream,
                &Outcome::Error {
                    message: why.into(),
                },
            );
        }
        log::info!(
            "consent answer for {} from uid {}: {}",
            req.user,
            cred.uid(),
            if req.consent_dismiss {
                "dismiss"
            } else if req.consent_rearm {
                "ready to nod"
            } else {
                "password"
            }
        );
        return reply(&mut stream, &Outcome::Noted);
    }
    // The watched user reads ("query") or switches the presence watch's
    // mode for this run of the daemon: local (the gate above), and only
    // that user, for their own watch. It does not persist; the config sets
    // the mode at every start. Both forms answer with the state.
    if let Some(mode) = &req.presence_mode {
        let outcome = presence_query(cred.uid(), cred.pid(), &req.user, mode);
        return reply(&mut stream, &outcome);
    }
    if req.ping {
        let outcome = match take() {
            Some(a) => a.ping(&req.user),
            None => Outcome::Error {
                message: "busy".into(),
            },
        };
        return reply(&mut stream, &outcome);
    }
    // Enrolment and deletion change who can unlock the machine: only root may
    // ask (the setup command runs them under sudo, behind the password), so no
    // unprivileged process, and nothing reaching a locked session over ssh,
    // can enrol a new face or erase the enrolled one.
    if (req.enroll.is_some() || req.delete_templates) && cred.uid() != 0 {
        log::warn!(
            "uid {} asked to change templates for {}: refused",
            cred.uid(),
            req.user
        );
        return reply(
            &mut stream,
            &Outcome::Error {
                message: "not permitted: enrolment and deletion require root".into(),
            },
        );
    }
    if let Some(start) = &req.enrol_session {
        if cred.uid() != 0 {
            return reply(
                &mut stream,
                &Outcome::Error {
                    message: "not permitted: enrolment requires root".into(),
                },
            );
        }
        log::info!(
            "enrolment walk-through for {} (label {:?}, from {:?})",
            req.user,
            start.label,
            start.start_at
        );
        // The session holds the camera for as long as the person takes.
        let outcome = match take_for(ENROL_WAIT) {
            Some(mut a) => {
                // The window and its control calls run as the session user,
                // who on a first enrolment has no template and so no ACL
                // entry. Grant before the summon inside run, because the
                // window connects once and never retries. The grant is made
                // from the guard's own fields: refresh_socket_acl would lock
                // the authenticator this thread already holds.
                let mut users = a.store.enrolled_users();
                if !users.contains(&req.user) {
                    users.push(req.user.clone());
                }
                apply_socket_acl(Path::new(crate::config::SOCKET), &users);
                crate::enrol::run(&mut a, &req.user, start)
            }
            None => Outcome::Error {
                message: "busy".into(),
            },
        };
        log::info!("enrolment walk-through for {}: {:?}", req.user, outcome);
        // Every outcome: back to the template-only list, which keeps the
        // user after a finished enrolment and drops the session grant after
        // a failed or cancelled one. The guard was dropped with the match.
        refresh_socket_acl(auth);
        return reply(&mut stream, &outcome);
    }
    if req.enrol_watch || req.enrol_control.is_some() {
        // The session's own user (or root) may watch it and steer it.
        if cred.uid() != 0 && !crate::enrol::active_for(&req.user, cred.uid()) {
            return reply(
                &mut stream,
                &Outcome::Error {
                    message: "no enrolment session for you is running".into(),
                },
            );
        }
        if let Some(word) = &req.enrol_control {
            if matches!(word.as_str(), "continue" | "redo" | "cancel") {
                crate::enrol::control(word);
                return reply(&mut stream, &Outcome::Noted);
            }
            return reply(
                &mut stream,
                &Outcome::Error {
                    message: "unknown control".into(),
                },
            );
        }
        // The stream: lines until the session ends. The writer drops this
        // connection when a write fails, so a closed window costs nothing.
        // The stream: lines until the session ends. The connection goes
        // to the session's writer and this thread returns at once (H11):
        // the writer drops the connection when a write fails, so a closed
        // window costs nothing, and no thread sleeps for the session.
        stream.set_read_timeout(None)?;
        crate::enrol::add_watcher(stream);
        return Ok(());
    }
    if let Some(label) = &req.enroll {
        log::info!(
            "enrolment for {} (uid {}, label {:?})",
            req.user,
            cred.uid(),
            label
        );
        let outcome = match take() {
            Some(mut a) => a.enroll(
                &req.user,
                label,
                req.seconds.unwrap_or(12.0).clamp(4.0, 20.0),
                req.count.unwrap_or(10),
                req.enroll_pose.as_deref(),
            ),
            None => Outcome::Error {
                message: "busy".into(),
            },
        };
        log::info!("enrolment for {}: {:?}", req.user, outcome);
        if matches!(outcome, Outcome::Enrolled { .. }) {
            refresh_socket_acl(auth);
        }
        return reply(&mut stream, &outcome);
    }
    if req.delete_templates {
        let outcome = match take() {
            Some(a) => match a.store.delete(&req.user) {
                Ok(true) => Outcome::Deleted,
                Ok(false) => Outcome::NotEnrolled,
                Err(e) => Outcome::Error {
                    message: e.to_string(),
                },
            },
            None => Outcome::Error {
                message: "busy".into(),
            },
        };
        log::info!(
            "templates for {} deleted by uid {}: {:?}",
            req.user,
            cred.uid(),
            outcome
        );
        refresh_socket_acl(auth);
        return reply(&mut stream, &outcome);
    }
    if req.probe {
        let outcome = match take() {
            Some(mut a) => a.probe(&req.user),
            None => Outcome::Error {
                message: "busy".into(),
            },
        };
        log::debug!("probe for {}: {:?}", req.user, outcome);
        return reply(&mut stream, &outcome);
    }
    #[cfg(feature = "dev-tools")]
    if let Some(seconds) = req.sweep_seconds {
        // Scores per frame: root only, like every other reply that carries them.
        if cred.uid() != 0 {
            log::warn!(
                "uid {} asked for a pose sweep of {}: refused",
                cred.uid(),
                req.user
            );
            return reply(
                &mut stream,
                &Outcome::Error {
                    message: "not permitted: a sweep requires root".into(),
                },
            );
        }
        log::info!(
            "pose sweep for {} ({:.0}s) by pid {}",
            req.user,
            seconds,
            cred.pid()
        );
        let outcome = match take() {
            Some(mut a) => a.sweep(&req.user, seconds),
            None => Outcome::Error {
                message: "busy".into(),
            },
        };
        return reply(&mut stream, &outcome);
    }
    log::info!(
        "attempt for {} (uid {}, pid {}{})",
        req.user,
        cred.uid(),
        cred.pid(),
        if req.consent { ", consent" } else { "" }
    );
    let outcome = if req.consent {
        let uid = user_uid(&req.user).unwrap_or(cred.uid());
        // The window goes to the user's graphical session. If that session
        // is not the one in the foreground on its seat (sudo on a text
        // console while the desktop runs on another VT), nobody can see it
        // or nod at it, and the request would re-arm forever (B2).
        if !active_graphical_session(&LiveProcs, uid) {
            log::info!("consent for {}: no active graphical session to ask in; falls through to the password", req.user);
            return reply(&mut stream, &consent_denied(Refusal::NoSession, 0));
        }
        // One consent request at a time, and the rest of the same user's
        // wait their turn in arrival order rather than falling to the
        // password: a request has no deadline, so the queue only ever
        // drains by the user answering (or requesters going away). The
        // place is taken before the slot is released, so the bound on a
        // user's requests is what a runaway loop meets, not the slots.
        let consent = &crate::consent::CONSENT;
        let place = match consent.join(uid) {
            Ok(p) => p,
            Err(crate::consent::NoTurn::OtherUser(h)) => {
                log::info!("consent for {}: uid {}'s request holds the window; this one falls through to the password", req.user, h);
                return reply(&mut stream, &consent_denied(Refusal::OtherUser, 0));
            }
            Err(_) => {
                log::info!("consent for {}: {} requests already live or waiting; this one falls through to the password", req.user, crate::consent::CONSENT_PER_UID);
                return reply(&mut stream, &consent_denied(Refusal::TooMany, 0));
            }
        };
        slot.release();
        let caller = crate::consent::CallerInfo::from_pid(cred.pid(), uid, agent);
        if let Some((left, first)) = refusal_standing(uid, Instant::now()) {
            log::info!(
                "consent for {}: refused a moment ago; the refusal stands for {}s more, no window for pid {}",
                req.user,
                left.as_secs(),
                cred.pid()
            );
            if first {
                crate::consent::notify(
                    &req.user,
                    "Refused a moment ago",
                    &format!(
                        "Requests are refused without asking for {} more seconds.\n{}\n{}",
                        left.as_secs().max(1),
                        caller.command,
                        caller.parents
                    ),
                );
            }
            // The same answer the no itself gave: sudo falls to its
            // password, polkit's agent cancels.
            let o = crate::auth::refused(&caller, Refusal::RefusedRecently, 0);
            return reply(&mut stream, &o);
        }
        // polkitd named the requesting process: it has to be local too, not
        // only the agent that is serving it. A pkexec from an SSH shell
        // served by a text agent is refused at the agent; one that reached
        // the desktop's agent by other means is refused here.
        if let Some(rp) = caller.requester {
            let pidfd = pidfd_open(rp);
            match locality(rp, pidfd.as_ref(), &req.user) {
                Locality::Local(_) => {}
                Locality::Remote(why) => {
                    log::warn!(
                        "consent for {}: polkit requester pid {} refused: {}",
                        req.user,
                        rp,
                        why
                    );
                    return reply(
                        &mut stream,
                        &Outcome::Error {
                            message: format!("face authentication is local only: {}", why),
                        },
                    );
                }
            }
        }
        // The requester may not wait for an answer (sudo interrupted, the
        // polkit helper gone): a dup of its socket goes into the live
        // record, and every wait loop polls it for the hang-up, so the
        // request ends and its window comes down within a frame wherever
        // it is. No thread blocks on it.
        let requester = std::os::fd::OwnedFd::from(stream.try_clone()?);
        // The window shows one request at a time; the one waiting is
        // announced so it is not a silent hang. The turn is held for the
        // whole request, parked spells included, so a later request never
        // opens its window over an earlier one.
        let on_wait = || {
            log::info!(
                "consent: request from pid {} waits its turn behind another",
                cred.pid()
            );
            crate::consent::notify(
                &req.user,
                "Another request is waiting",
                &format!(
                    "{}\n{}\nIt gets the window after the one on screen is answered.",
                    caller.command, caller.parents
                ),
            );
        };
        let _turn = match consent.take_turn(place, &req.user, Some(requester), &on_wait) {
            Ok(t) => t,
            Err(crate::consent::NoTurn::Gone) => {
                return reply(&mut stream, &consent_denied(Refusal::Gone, 0));
            }
            Err(e) => {
                log::info!(
                    "consent for {}: lost its place while waiting ({:?}); falls through to the password",
                    req.user,
                    e
                );
                return reply(&mut stream, &consent_denied(Refusal::OtherUser, 0));
            }
        };
        let outcome = consent_rounds(&take, &req.user, caller);
        if is_explicit_no(&outcome) {
            let d = refused(uid, Instant::now());
            log::info!(
                "consent for {}: the refusal stands for {}s",
                req.user,
                d.as_secs()
            );
        }
        outcome
    } else {
        // Elevation is never passive: sudo and polkit run their PAM stacks
        // as root, and a face line on them without `consent` (a typo, a
        // pasted lock-screen example) must not turn a look into root. The
        // lock screen, the only plain-look caller, runs as the user (A3).
        match admit_plain_look(cred.uid()) {
            Ok(()) => match take() {
                Some(mut a) => a.authenticate(&req.user),
                None => Outcome::Error {
                    message: "busy".into(),
                },
            },
            Err(why) => {
                log::warn!(
                    "plain look for {} from pid {} (uid 0) refused: {}",
                    req.user,
                    cred.pid(),
                    why
                );
                Outcome::Error {
                    message: why.into(),
                }
            }
        }
    };
    // Scores go to root peers only, and not to the journal (readable by
    // wheel on Omarchy): the info line carries the redacted outcome.
    log::info!("attempt for {}: {:?}", req.user, outcome.clone().redacted());
    log::debug!("attempt for {}: {:?}", req.user, outcome);
    let outcome = if cred.uid() == 0 {
        outcome
    } else {
        outcome.redacted()
    };
    reply(&mut stream, &outcome)
}

/// May a caller running as `peer_uid` ask about the user whose uid is
/// `user_uid`? Root may ask about anyone, everyone else about themselves
/// only, and nobody but root about a user the system does not know. Every
/// request passes this, so the probe's `likely` is only ever about the
/// caller's own face, or answered to root; anyone else gets "not permitted".
fn may_ask(peer_uid: u32, user_uid: Option<u32>) -> bool {
    peer_uid == 0 || user_uid.map(|u| u == peer_uid).unwrap_or(false)
}

#[cfg(test)]
mod ask_tests {
    use super::may_ask;

    /// A probe, like every request, is answered for the caller's own user or
    /// for root: another user's `likely` is refused with the request.
    #[test]
    fn a_caller_asks_only_about_themselves_unless_root() {
        assert!(may_ask(1000, Some(1000)), "the caller's own face");
        assert!(!may_ask(1000, Some(1001)), "another user's face");
        assert!(!may_ask(1000, None), "a user the system does not know");
        assert!(may_ask(0, Some(1001)), "root asks about anyone");
    }
}

#[cfg(test)]
mod plain_look_tests {
    use super::*;

    /// A3: a misspelt field does not degrade a request to a plain look;
    /// the line is refused.
    #[test]
    fn a_request_with_an_unknown_field_is_refused() {
        assert!(serde_json::from_str::<Request>(r#"{"user":"alice","consent":true}"#).is_ok());
        assert!(serde_json::from_str::<Request>(r#"{"user":"alice","consnet":true}"#).is_err());
        assert!(serde_json::from_str::<Request>(
            r#"{"user":"alice","consent_dismis":true,"consent_token":"t"}"#
        )
        .is_err());
    }
}
