//! One connection from its request line to its reply: the request's
//! fields, who is asking, what they may ask for, and which lane (a plain
//! look, a consent request, the enrollment walk-through, a presence query)
//! answers it.

use super::acl::{apply_socket_acl, refresh_socket_acl, OnDrop};
use super::admit::{
    admit_key_fallback, admit_key_unlock, admit_plain_look, is_own_pid, lid_closed,
};
use super::backoff::{is_explicit_no, refusal_standing, refused};
use super::locality::{
    active_graphical_session, bind_of_pid, locality, origin_of_pid, LiveProcs, Locality,
};
use super::presence::presence_query;
use super::read::{read_request, take_password};
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
/// How long the enrollment walk-through waits: a presence look that
/// identifies and strobes holds the camera for about two seconds, and the
/// person has just clicked Enroll, so waiting out one tick beats "busy".
const ENROL_WAIT: Duration = Duration::from_secs(6);

/// A request line. Unknown fields are refused rather than dropped: a
/// misspelt answer field would otherwise read as a plain look (A3).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    user: String,
    /// true: a presence probe instead of an attempt: one short look without
    /// the flash, answering whether a face is there and whether it is
    /// likely this user, never with a score.
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
    /// Some: enroll this user with the given label.
    #[serde(default)]
    enroll: Option<String>,
    /// With `enroll`: the looks to take, in order, each keeping only
    /// frames in its pose (see `auth::POSES`); none takes one look in any
    /// pose. They run in one request, the camera open throughout (A6).
    #[serde(default)]
    enroll_poses: Vec<String>,
    /// Root only: the enrollment walk-through (see `enroll`); the reply is
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
    /// Root only: delete this user's templates.
    #[serde(default)]
    delete_templates: bool,
    /// An elevation: open the consent window, require the nod.
    #[serde(default)]
    consent: bool,
    /// From the lock screen's key lane (pam_faceauth's `key-unlock`): one
    /// check of the user's security key while the session is locked.
    #[serde(default)]
    key_unlock: bool,
    /// From a sudo or polkit stack's key line (pam_faceauth's
    /// `key-fallback`): one check of the user's security key, with the
    /// key's PIN in `consent_password` when the line asks for one.
    #[serde(default)]
    key_fallback: bool,
    /// With `key_fallback`: only ask whether the key line may run now
    /// (`KeyReady` or `KeyWait`), starting no check.
    #[serde(default)]
    key_ready: bool,
    /// From the lock screen: is its key lane there? Answered without the
    /// camera, and the lock screen's word that it is up.
    #[serde(default)]
    key_lane: bool,
    /// From the lock screen's fingerprint lane (pam_faceauth's
    /// `fprint-unlock`): one check of the user's finger while the session
    /// is locked.
    #[serde(default)]
    fprint_unlock: bool,
    /// From the lock screen: does its fingerprint lane go through the
    /// daemon? Answered without the camera or the reader.
    #[serde(default)]
    fprint_lane: bool,
    /// From the consent window: the typed password for the pending request.
    /// A `Secret` from the parse on, so it is wiped on every way out of the
    /// request, the refusals before the answer is taken included (F12).
    #[serde(default, deserialize_with = "secret")]
    consent_password: Option<crate::consent::Secret>,
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
    /// From the consent window: the password field carries the security
    /// key's PIN, not the account password.
    #[serde(default)]
    consent_key_pin: bool,
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
    /// From the polkit agent: polkitd's cookie for the request, which ties
    /// the context to the helper's PAM request through the cookie prompt
    /// (round 16c).
    #[serde(default)]
    context_cookie: Option<String>,
    /// From the polkit agent: the cookie prompt it answers, which must be
    /// `lockgate::POLKIT_COOKIE_PROMPT` itself (round 17, Opus F3: a shell
    /// that knows another prompt text is never asked this one).
    #[serde(default)]
    context_cookie_prompt: Option<String>,
    /// From polkit's PAM module, after `need_cookie`: what the agent
    /// answered to the cookie prompt ("" for nothing usable). A `Secret`
    /// (round 17, Opus F3): it is the answer to a prompt, wiped on every
    /// way out.
    #[serde(default, deserialize_with = "secret")]
    polkit_cookie: Option<crate::consent::Secret>,
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

/// What a request line asks for, one variant per operation. The wire keeps
/// the flat fields above, which the PAM module, the CLI and the Omarchy
/// windows send as they are, rather than an `"op"` tag: `Request::op`
/// reads the operation from them in a fixed order, so a line that names
/// two is read as the first of them. Two checks in `handle` still answer
/// before that operation runs: the lid check, for any line with `consent`
/// set, and the root check, for a non-root line naming `enroll` or
/// `delete_templates`, whichever operation after a ping it is read as.
enum Op {
    /// From the polkit agent: what the request it is about to serve is.
    Context {
        action: String,
        message: Option<String>,
        caller_pid: Option<i32>,
        subject_pid: Option<i32>,
        cookie: Option<String>,
        cookie_prompt: bool,
    },
    /// From the consent window, with the token the daemon put in its payload.
    Answer {
        token: Option<String>,
        answer: WindowAnswer,
    },
    /// From the watched user: "query", "default" or "secure".
    PresenceMode(String),
    Ping,
    /// Root only: the enrollment walk-through.
    EnrolSession(crate::enrol::Start),
    /// From the user's window: "continue", "redo" or "cancel".
    EnrolControl(String),
    /// From the user's window: the session's frames, until it ends.
    EnrolWatch,
    /// Root only: a terminal enrollment.
    Enroll {
        label: String,
        poses: Vec<String>,
        seconds: Option<f32>,
        count: Option<usize>,
    },
    /// Root only: delete the user's templates.
    Delete,
    /// The lock screen's one cheap look.
    Probe,
    /// Root only, development builds only: a pose sweep of this many seconds.
    #[cfg(feature = "dev-tools")]
    Sweep(f32),
    /// An elevation: the consent window and the nod.
    Consent,
    /// The lock screen's security key: one check while the session is
    /// locked, for its `omarchy-lock-fido2` stack.
    KeyUnlock,
    /// A sudo or polkit stack's key line: one check of the key, with its
    /// PIN when the line asks for one; or, with `ready`, only whether it
    /// may run now.
    KeyFallback {
        pin: Option<crate::consent::Secret>,
        ready: bool,
    },
    /// The lock screen asks whether its key lane is there.
    KeyLane,
    /// The lock screen's fingerprint: one check while the session is
    /// locked, for its `omarchy-lock-fingerprint` stack.
    FprintUnlock,
    /// The lock screen asks whether its fingerprint lane goes through the
    /// daemon.
    FprintLane,
    /// A plain look: one attempt, for the lock screen's PAM stack.
    Look,
}

/// What the consent window said.
enum WindowAnswer {
    /// It has drawn the request the token names.
    Ack,
    /// With this request's approval, passwordless sudo for this many minutes.
    Passwordless(u32),
    Dismiss,
    /// "Ready to nod".
    Rearm,
    /// The security key's PIN, for the next key check of this request.
    KeyPin(Option<crate::consent::Secret>),
    Password(crate::consent::Secret),
}

impl Op {
    /// The operation's name, for `request_op`.
    fn name(&self) -> &'static str {
        match self {
            Op::Context { .. } => "context",
            Op::Answer { .. } => "answer",
            Op::PresenceMode(_) => "presence_mode",
            Op::Ping => "ping",
            Op::EnrolSession(_) => "enrol_session",
            Op::EnrolControl(_) => "enrol_control",
            Op::EnrolWatch => "enrol_watch",
            Op::Enroll { .. } => "enroll",
            Op::Delete => "delete_templates",
            Op::Probe => "probe",
            #[cfg(feature = "dev-tools")]
            Op::Sweep(_) => "sweep",
            Op::Consent => "consent",
            Op::KeyUnlock => "key_unlock",
            Op::KeyFallback { ready: false, .. } => "key_fallback",
            Op::KeyFallback { ready: true, .. } => "key_ready",
            Op::KeyLane => "key_lane",
            Op::FprintUnlock => "fprint_unlock",
            Op::FprintLane => "fprint_lane",
            Op::Look => "look",
        }
    }
}

/// What the daemon reads a request line as: the operation's name, or None
/// when the line does not parse. A line that parses may still be refused
/// before its operation runs (a request about root, one about another
/// user, a remote caller, the lid and root checks of `handle`). The PAM
/// module's tests hold its two request shapes to this, the daemon's own
/// parse.
pub fn request_op(line: &str) -> Option<&'static str> {
    let mut line = line.to_string();
    let op = parse(&mut line).map(|mut r| r.op().name());
    crate::consent::wipe_string(&mut line);
    op
}

impl Request {
    /// The operation the line asks for, its fields taken out of the line.
    fn op(&mut self) -> Op {
        if let Some(action) = self.context_action.take() {
            return Op::Context {
                action,
                message: self.context_message.take(),
                caller_pid: self.context_caller_pid,
                subject_pid: self.context_subject_pid,
                cookie: self.context_cookie.take(),
                cookie_prompt: self.context_cookie_prompt.as_deref()
                    == Some(crate::lockgate::POLKIT_COOKIE_PROMPT),
            };
        }
        // Before the window's answers: the line's password field carries
        // the key's PIN here, never an answer to a card.
        if self.key_fallback {
            return Op::KeyFallback {
                pin: self.consent_password.take(),
                ready: self.key_ready,
            };
        }
        let answer = if self.consent_ack {
            Some(WindowAnswer::Ack)
        } else if let Some(minutes) = self.consent_passwordless {
            Some(WindowAnswer::Passwordless(minutes))
        } else if self.consent_dismiss {
            Some(WindowAnswer::Dismiss)
        } else if self.consent_rearm {
            Some(WindowAnswer::Rearm)
        } else if self.consent_key_pin {
            Some(WindowAnswer::KeyPin(self.consent_password.take()))
        } else {
            self.consent_password.take().map(WindowAnswer::Password)
        };
        if let Some(answer) = answer {
            return Op::Answer {
                token: self.consent_token.take(),
                answer,
            };
        }
        if let Some(mode) = self.presence_mode.take() {
            return Op::PresenceMode(mode);
        }
        if self.key_lane {
            return Op::KeyLane;
        }
        if self.fprint_lane {
            return Op::FprintLane;
        }
        if self.ping {
            return Op::Ping;
        }
        if let Some(start) = self.enrol_session.take() {
            return Op::EnrolSession(start);
        }
        if let Some(word) = self.enrol_control.take() {
            return Op::EnrolControl(word);
        }
        if self.enrol_watch {
            return Op::EnrolWatch;
        }
        if let Some(label) = self.enroll.take() {
            return Op::Enroll {
                label,
                poses: std::mem::take(&mut self.enroll_poses),
                seconds: self.seconds,
                count: self.count,
            };
        }
        if self.delete_templates {
            return Op::Delete;
        }
        if self.probe {
            return Op::Probe;
        }
        #[cfg(feature = "dev-tools")]
        if let Some(seconds) = self.sweep_seconds {
            return Op::Sweep(seconds);
        }
        if self.consent {
            Op::Consent
        } else if self.key_unlock {
            Op::KeyUnlock
        } else if self.fprint_unlock {
            Op::FprintUnlock
        } else {
            Op::Look
        }
    }
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
    let read_from = Instant::now();
    let Some(mut line) = read_request(&mut stream)? else {
        // A place held to the request deadline without a line is a place
        // kept from everyone else: counted as a refusal (round 6, item 10).
        if read_from.elapsed() >= super::read::REQUEST_DEADLINE {
            super::serve::note_stall(
                &crate::consent::CONSENT,
                slot.source(),
                &super::serve::name_of_uid,
            );
        }
        return reply(
            &mut stream,
            &Outcome::Error {
                message: "bad request".into(),
            },
        );
    };
    let parsed = parse(&mut line);
    // The line may carry a password; its bytes are not left in freed memory
    // (F12), whichever way the request ends from here.
    crate::consent::wipe_string(&mut line);
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut req: Request = match parsed {
        Some(r) => r,
        None => {
            return reply(
                &mut stream,
                &Outcome::Error {
                    message: "bad request".into(),
                },
            )
        }
    };
    // A consent line's every answer goes back through `lane_answer`, the
    // refusals before its operation runs included, so while the session
    // reads as locked sudo's answer is a parked refusal and polkit's a
    // refusal that ends its stack. The lane is read from the peer once,
    // here.
    let consent_line = req.consent;
    let via = if consent_line {
        crate::consent::caller_lane(cred.pid())
    } else {
        String::new()
    };
    let asked_about = req.user.clone();
    // Whose session the request comes from (round 6, item 7): the caller,
    // or for polkit the agent that connected its helper, once the locality
    // check below has pinned it.
    let origin_pid = std::cell::Cell::new(cred.pid());
    // Which session the request's lock question is about (round 8, Codex
    // 3): sudo's own logind session, or the session of the agent that
    // connected polkit's helper; ambiguous for anything that names none.
    let bind = bind_of_pid(cred.pid(), user_uid(&req.user));
    let gate = |o: Outcome| -> Outcome {
        if consent_line {
            crate::auth::lane_answer(&via, o, &|| {
                (
                    crate::consent::lock_verdict(&asked_about, &bind),
                    origin_of_pid(origin_pid.get()),
                )
            })
        } else {
            o
        }
    };
    // Root is never a face: sudo, polkit and the lock screen authenticate
    // the person at the keyboard, and root is only the privilege that writes
    // the store. Nothing enrolls, matches or probes uid 0.
    if user_uid(&req.user) == Some(0) {
        log::warn!(
            "uid {} asked about root: refused, root is never authenticated by face",
            cred.uid()
        );
        return reply(
            &mut stream,
            &gate(Outcome::Error {
                message: "root is never authenticated by face".into(),
            }),
        );
    }
    if !may_ask(cred.uid(), user_uid(&req.user)) {
        log::warn!("uid {} asked about {}: refused", cred.uid(), req.user);
        return reply(
            &mut stream,
            &gate(Outcome::Error {
                message: "not permitted".into(),
            }),
        );
    }
    // Face authentication is local by definition: the camera sees whoever is
    // at the machine, which says nothing about a caller reaching it over the
    // network. Every request, the probes and window answers included, must
    // come from a caller shown to be local; anything unprovable is remote,
    // and the caller's PAM stack falls through to its password.
    let peer_pidfd = getsockopt(&stream, nix::sys::socket::sockopt::PeerPidfd).ok();
    let agent = match locality(cred.pid(), peer_pidfd.as_ref(), &req.user) {
        Locality::Local(agent) => {
            if let Some(a) = &agent {
                origin_pid.set(a.pid);
            }
            agent
        }
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
                &gate(Outcome::Error {
                    message: format!("face authentication is local only: {}", why),
                }),
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
            &gate(Outcome::Error {
                message: "the lid is closed".into(),
            }),
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
    // Enrollment and deletion change who can unlock the machine: a line that
    // names either is checked for root before any operation after a ping
    // runs, whichever of them the line is read as.
    let changes_templates = req.enroll.is_some() || req.delete_templates;
    match req.op() {
        // The polkit agent, before its helper's PAM request arrives, says what
        // the request is. Queued per user in arrival order, single use, only
        // from a local caller (the gate above), and served only to a request
        // whose helper was connected by this very peer: the agent process must
        // send it itself, over its own connection.
        Op::Context {
            action,
            message,
            caller_pid,
            subject_pid,
            cookie,
            cookie_prompt,
        } => {
            // The cookie is kept only in the form polkitd gives it, and never
            // logged. An agent that answers the cookie prompt says so with
            // each context; its requests are then matched by cookie alone.
            let cookie = cookie.filter(|c| crate::lockgate::polkit_cookie_ok(c));
            if let (true, Some(_), Some(p)) = (cookie_prompt, &cookie, peer) {
                crate::consent::note_cookie_agent(cred.uid(), p);
            } else if let Some(p) = peer {
                crate::consent::forget_cookie_agent(p);
            }
            let clip = crate::consent::clip;
            let ctx = crate::consent::PolkitContext {
                action: clip(&action),
                message: clip(message.as_deref().unwrap_or("")),
                agent: peer,
                caller_pid,
                subject_pid,
                at: Instant::now(),
                at_boot: crate::consent::boottime_now(),
                cookie,
                cookie_prompt,
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
            reply(&mut stream, &Outcome::Noted)
        }
        // Answers to a pending consent request must not wait for the camera lock:
        // the consent flow holds it. They go into the live record, whose own
        // lock is held for microseconds.
        Op::Answer { token, answer } => {
            let consent = &crate::consent::CONSENT;
            // Only the window the daemon summoned holds the token; a process
            // that merely reaches the socket cannot cancel or answer a request.
            // The token is the whole check: it exists exactly while a request
            // of this user's is live and has a window.
            if !consent.token_matches(&req.user, token.as_deref()) {
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
            let (answer, said) = match answer {
                WindowAnswer::Ack => {
                    consent.ack(&req.user, token.as_deref());
                    log::info!(
                        "consent window for {} (uid {}, pid {}) acknowledged the request",
                        req.user,
                        cred.uid(),
                        cred.pid()
                    );
                    return reply(&mut stream, &Outcome::Noted);
                }
                WindowAnswer::Passwordless(minutes) => {
                    // The rider record decides: the token must be the card's own
                    // request, the lane sudo, and the enrolled face in the nod
                    // window now. The card grays its button on the same signal, so
                    // a program driving the socket gets no more than the button.
                    let armed = consent.arm_passwordless(
                        &req.user,
                        token.as_deref().unwrap_or(""),
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
                WindowAnswer::KeyPin(pin) => {
                    // The key's PIN goes into the live record for the next
                    // key check alone, as a `Secret`, and is never logged.
                    // Refused unless the key is armed on this request and
                    // its lane asks for a PIN.
                    let kept = match pin {
                        Some(pin) => consent.set_key_pin(&req.user, token.as_deref(), pin),
                        None => Err("no PIN"),
                    };
                    let o = match kept {
                        Ok(()) => {
                            log::info!(
                                "consent window for {} (uid {}): a PIN for the security key",
                                req.user,
                                cred.uid()
                            );
                            Outcome::Noted
                        }
                        Err(why) => {
                            log::warn!(
                                "consent window for {} (uid {}, pid {}): a PIN for the security key refused: {}",
                                req.user,
                                cred.uid(),
                                cred.pid(),
                                why
                            );
                            Outcome::Error {
                                message: why.into(),
                            }
                        }
                    };
                    return reply(&mut stream, &o);
                }
                WindowAnswer::Dismiss => (crate::consent::Answer::Dismiss, "dismiss"),
                WindowAnswer::Rearm => (crate::consent::Answer::Rearm, "ready to nod"),
                WindowAnswer::Password(pw) => (crate::consent::Answer::Password(pw), "password"),
            };
            if let Err(why) = consent.answer(&req.user, token.as_deref(), answer) {
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
                said
            );
            reply(&mut stream, &Outcome::Noted)
        }
        // A local caller (the gate above) reads the presence watch's mode
        // ("query") for their own user, root for anyone; only the watched
        // user switches it, for their own watch and this run of the daemon.
        // A switch does not persist; the config sets the mode at every
        // start. Both forms answer with the state.
        Op::PresenceMode(mode) => {
            let outcome = presence_query(cred.uid(), cred.pid(), &req.user, &mode);
            reply(&mut stream, &outcome)
        }
        Op::Ping => {
            let outcome = match take() {
                Some(a) => a.ping(&req.user),
                None => Outcome::Error {
                    message: "busy".into(),
                },
            };
            reply(&mut stream, &outcome)
        }
        // Only root may enroll or delete (the setup command runs them under
        // sudo, behind the password), so no unprivileged process, and nothing
        // reaching a locked session over ssh, can enroll a new face or erase
        // the enrolled one.
        _ if changes_templates && cred.uid() != 0 => {
            log::warn!(
                "uid {} asked to change templates for {}: refused",
                cred.uid(),
                req.user
            );
            reply(
                &mut stream,
                &Outcome::Error {
                    message: "not permitted: enrollment and deletion require root".into(),
                },
            )
        }
        Op::EnrolSession(start) => {
            if cred.uid() != 0 {
                return reply(
                    &mut stream,
                    &Outcome::Error {
                        message: "not permitted: enrollment requires root".into(),
                    },
                );
            }
            log::info!(
                "enrollment walk-through for {} (label {:?}, from {:?})",
                req.user,
                start.label,
                start.start_at
            );
            // Every outcome: back to the template-only list, which keeps the
            // user after a finished enrollment and drops the session grant after
            // a failed or canceled one. Armed before the grant so a panic in
            // the walk-through, which unwinds past the explicit drop below,
            // revokes it too (the authenticator's guard drops first and the
            // refresh recovers its poisoned lock).
            let revoke = OnDrop::new(|| refresh_socket_acl(auth));
            // The session holds the camera for as long as the person takes.
            let outcome = match take_for(ENROL_WAIT) {
                Some(mut a) => {
                    // The window and its control calls run as the session user,
                    // who on a first enrollment has no template and so no ACL
                    // entry. Grant before the summon inside run, because the
                    // window connects once and never retries. The grant is made
                    // from the guard's own fields: refresh_socket_acl would lock
                    // the authenticator this thread already holds. A setfacl
                    // failure here makes the socket root-only for the whole
                    // walk-through: the window cannot connect, and the
                    // walk-through fails closed rather than on a stale list.
                    let mut users = a.store.enrolled_users();
                    if !users.contains(&req.user) {
                        users.push(req.user.clone());
                    }
                    apply_socket_acl(Path::new(crate::config::SOCKET), &users);
                    crate::enrol::run(&mut a, &req.user, &start)
                }
                None => Outcome::Error {
                    message: "busy".into(),
                },
            };
            log::info!("enrollment walk-through for {}: {:?}", req.user, outcome);
            // The guard was dropped with the match; refresh before the reply,
            // so the caller's next request sees the new list.
            drop(revoke);
            reply(&mut stream, &outcome)
        }
        op @ (Op::EnrolControl(_) | Op::EnrolWatch) => {
            // The session's own user (or root) may watch it and steer it.
            if cred.uid() != 0 && !crate::enrol::active_for(&req.user, cred.uid()) {
                return reply(
                    &mut stream,
                    &Outcome::Error {
                        message: "no enrollment session for you is running".into(),
                    },
                );
            }
            if let Op::EnrolControl(word) = op {
                if matches!(word.as_str(), "continue" | "redo" | "cancel") {
                    crate::enrol::control(&word);
                    return reply(&mut stream, &Outcome::Noted);
                }
                return reply(
                    &mut stream,
                    &Outcome::Error {
                        message: "unknown control".into(),
                    },
                );
            }
            // The stream: lines until the session ends. The connection goes
            // to the session's writer and this thread returns at once (H11):
            // the writer drops the connection when a write fails, so a closed
            // window costs nothing, and no thread sleeps for the session.
            stream.set_read_timeout(None)?;
            crate::enrol::add_watcher(stream);
            Ok(())
        }
        Op::Enroll {
            label,
            poses,
            seconds,
            count,
        } => {
            log::info!(
                "enrollment for {} (uid {}, label {:?})",
                req.user,
                cred.uid(),
                label
            );
            // The terminal that asked may go away (Ctrl-C): the looks end at
            // once and nothing is stored (A6).
            let requester = std::os::fd::OwnedFd::from(stream.try_clone()?);
            let terminal_gone = || crate::consent::peer_gone(&requester);
            // Its prompts wait for the face to be learned: told on the same
            // connection, before the outcome.
            let mut progress = stream.try_clone()?;
            let mut learned = || {
                let _ = reply(&mut progress, &Outcome::Learned);
            };
            let outcome = match take() {
                Some(mut a) => crate::enrol::run_terminal(
                    &mut a,
                    &req.user,
                    &label,
                    seconds.unwrap_or(12.0).clamp(4.0, 20.0),
                    count.unwrap_or(10),
                    &poses,
                    &terminal_gone,
                    &mut learned,
                ),
                None => Outcome::Error {
                    message: "busy".into(),
                },
            };
            log::info!("enrollment for {}: {:?}", req.user, outcome);
            if matches!(outcome, Outcome::Enrolled { .. }) {
                refresh_socket_acl(auth);
            }
            reply(&mut stream, &outcome)
        }
        Op::Delete => {
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
            reply(&mut stream, &outcome)
        }
        Op::Probe => {
            let outcome = match take() {
                Some(mut a) => a.probe(&req.user),
                None => Outcome::Error {
                    message: "busy".into(),
                },
            };
            log::debug!("probe for {}: {:?}", req.user, outcome);
            reply(&mut stream, &outcome)
        }
        #[cfg(feature = "dev-tools")]
        Op::Sweep(seconds) => {
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
            reply(&mut stream, &outcome)
        }
        // The lock screen's key: the daemon's own sandboxed check of the
        // user's key, only while the compositor says the session is locked
        // and only for the user's own lock screen. Its touch unlocks and
        // nothing else: the user's cards are off the key meanwhile
        // (`KeyLane::unlock`).
        Op::KeyUnlock => {
            let t0 = Instant::now();
            let admitted = admit_key_unlock(cred.uid(), user_uid(&req.user), || {
                active_graphical_session(&LiveProcs, cred.uid())
            });
            let Ok(()) = admitted.inspect_err(|why| {
                log::warn!(
                    "key unlock for {} from pid {} (uid {}) refused: {}",
                    req.user,
                    cred.pid(),
                    cred.uid(),
                    why
                )
            }) else {
                return reply(
                    &mut stream,
                    &Outcome::Error {
                        message: admitted.unwrap_err().into(),
                    },
                );
            };
            // The lock screen stops asking by ending its PAM transaction,
            // which hangs up this connection.
            let asker = std::os::fd::OwnedFd::from(stream.try_clone()?);
            let gone = || crate::consent::peer_gone(&asker);
            let (consent, key) = (&crate::consent::CONSENT, &crate::consent::KEY);
            let ended = key.unlock(consent, &req.user, &bind, &gone);
            let (outcome, watch) = match &ended {
                crate::consent::Unlocked::Touched => {
                    log::info!(
                        "key unlock for {}: the key was touched; the lock screen unlocks",
                        req.user
                    );
                    let o = Outcome::Match {
                        score: None,
                        frames: 0,
                        elapsed_ms: t0.elapsed().as_millis() as u64,
                    };
                    (o, true)
                }
                crate::consent::Unlocked::No { why, hung_up } => {
                    log::info!("key unlock for {}: {}", req.user, why);
                    let o = Outcome::Error {
                        message: why.clone(),
                    };
                    (o, *hung_up)
                }
            };
            let sent = reply(&mut stream, &outcome);
            // The latch ends only on an unlock the daemon sees: after a
            // touch, or the lock screen hanging up, it looks for it now.
            if watch {
                key.watch_for_unlock(consent, &req.user, &bind);
            }
            sent
        }
        // The lock screen's fingerprint: the daemon's own sandboxed check of
        // the user's finger, admitted as the key's unlock is (the user's own
        // lock screen, in the active graphical session), and run as it is
        // (`FprintLane::unlock`): its match unlocks and nothing else. The
        // line hears the daemon is at work every `BEAT` and each status the
        // check reports, which the module passes to the lock screen.
        Op::FprintUnlock => {
            let t0 = Instant::now();
            let admitted = admit_key_unlock(cred.uid(), user_uid(&req.user), || {
                active_graphical_session(&LiveProcs, cred.uid())
            });
            let Ok(()) = admitted.inspect_err(|why| {
                log::warn!(
                    "fingerprint unlock for {} from pid {} (uid {}) refused: {}",
                    req.user,
                    cred.pid(),
                    cred.uid(),
                    why
                )
            }) else {
                return reply(
                    &mut stream,
                    &Outcome::Error {
                        message: admitted.unwrap_err().into(),
                    },
                );
            };
            let asker = std::os::fd::OwnedFd::from(stream.try_clone()?);
            let beat_at = std::cell::Cell::new(Instant::now());
            let gone = || {
                if beat_at.get().elapsed() >= crate::lockgate::BEAT {
                    beat_at.set(Instant::now());
                    crate::consent::send_beat(&asker);
                }
                crate::consent::peer_gone(&asker)
            };
            let said = |st| crate::consent::send_fprint_status(&asker, st);
            let (consent, fprint) = (&crate::consent::CONSENT, &crate::consent::FPRINT);
            let ended = fprint.unlock(consent, &req.user, &bind, &gone, &said);
            let (outcome, watch) = match &ended {
                crate::consent::Unlocked::Touched => {
                    log::info!(
                        "fingerprint unlock for {}: the finger matched; the lock screen unlocks",
                        req.user
                    );
                    let o = Outcome::Match {
                        score: None,
                        frames: 0,
                        elapsed_ms: t0.elapsed().as_millis() as u64,
                    };
                    (o, true)
                }
                crate::consent::Unlocked::No { why, hung_up } => {
                    log::info!("fingerprint unlock for {}: {}", req.user, why);
                    let o = Outcome::Error {
                        message: why.clone(),
                    };
                    (o, *hung_up)
                }
            };
            let sent = reply(&mut stream, &outcome);
            // The latch ends only on an unlock the daemon sees, as after
            // the key's.
            if watch {
                crate::consent::KEY.watch_for_unlock(consent, &req.user, &bind);
            }
            sent
        }
        // The lock screen asks whether its fingerprint lane goes through the
        // daemon, as it asks about the key's: no camera and no reader, so
        // neither a busy camera nor a busy reader takes the lane away.
        Op::FprintLane => {
            let o = match admit_key_unlock(cred.uid(), user_uid(&req.user), || true) {
                Ok(()) => fprint_lane_reply(crate::consent::FPRINT.unlock_offer(&req.user)),
                Err(why) => Outcome::Error {
                    message: why.into(),
                },
            };
            reply(&mut stream, &o)
        }
        // A sudo or polkit stack's key line: the daemon's sandboxed check,
        // for the root PAM stack of a sudo or polkit request, never while
        // the session reads as locked or the lock screen holds the key,
        // and stopped when either changes.
        Op::KeyFallback { pin, ready } => {
            let lane = crate::consent::caller_lane(cred.pid());
            if let Err(why) = admit_key_fallback(cred.uid(), &lane) {
                log::warn!(
                    "key fallback for {} from pid {} (uid {}, {}) refused: {}",
                    req.user,
                    cred.pid(),
                    cred.uid(),
                    lane,
                    why
                );
                return reply(
                    &mut stream,
                    &Outcome::Error {
                        message: why.into(),
                    },
                );
            }
            // Only the one verdict's unlocked runs the key (R1); a request
            // from a text console or a remote login does not wait behind a
            // lock it cannot see (round 6, item 7).
            let uid = user_uid(&req.user).unwrap_or(cred.uid());
            // The notice of a touch goes to the desktops the user had when
            // the line began, or to none (fix round 10, Codex 6).
            let desktops = crate::consent::Pin::take(&req.user).ok();
            let who = crate::consent::Asker::new(origin_of_pid(origin_pid.get()), bind.clone());
            let (consent, key) = (&crate::consent::CONSENT, &crate::consent::KEY);
            use crate::consent::Fallback;
            let ended = if ready {
                match key.fallback_gate(consent, &req.user, &lane, &who) {
                    Ok(_) => {
                        return reply(&mut stream, &Outcome::KeyReady);
                    }
                    Err(f) => f,
                }
            } else {
                let t0 = Instant::now();
                let asker = std::os::fd::OwnedFd::from(stream.try_clone()?);
                // Every look at the requester also tells it, each `BEAT`,
                // that the check is still under way (round 6, item 12).
                let beat_at = std::cell::Cell::new(Instant::now());
                let gone = || {
                    if beat_at.get().elapsed() >= crate::lockgate::BEAT {
                        beat_at.set(Instant::now());
                        crate::consent::send_beat(&asker);
                    }
                    crate::consent::peer_gone(&asker)
                };
                match key.fallback(consent, &req.user, &lane, pin, &gone, &who) {
                    Fallback::Touched => {
                        let caller = crate::consent::CallerInfo::from_pid_asked(
                            cred.pid(),
                            uid,
                            agent,
                            crate::consent::Asked::Skip,
                        );
                        log::info!(
                            "consent granted (security key, {}'s key line) for {}: {} [{}]",
                            lane,
                            req.user,
                            caller.command,
                            caller.parents
                        );
                        if let Some(desktops) = &desktops {
                            crate::consent::notify(
                                desktops,
                                "Root access granted by security key",
                                &format!("{}\n{}", caller.command, caller.parents),
                            );
                        }
                        return reply(
                            &mut stream,
                            &Outcome::Match {
                                score: None,
                                frames: 0,
                                elapsed_ms: t0.elapsed().as_millis() as u64,
                            },
                        );
                    }
                    other => other,
                }
            };
            let outcome = match ended {
                Fallback::Wait(kind, why) => {
                    log::info!(
                        "key fallback for {} ({}): waits ({}): {}",
                        req.user,
                        lane,
                        kind,
                        why
                    );
                    Outcome::KeyWait {
                        state: kind.into(),
                        reason: why,
                    }
                }
                Fallback::No(why) => {
                    log::info!("key fallback for {} ({}): {}", req.user, lane, why);
                    Outcome::Error { message: why }
                }
                // Answered above.
                Fallback::Touched => Outcome::Error {
                    message: "approved".into(),
                },
            };
            reply(&mut stream, &outcome)
        }
        // The lock screen asks whether its key lane is there, at each lock
        // and every few seconds while it is up: no camera, so a busy camera
        // never takes the lane away, and the ask latches the user, so their
        // card is off the key while the lock screen is up.
        Op::KeyLane => {
            let o = match admit_key_unlock(cred.uid(), user_uid(&req.user), || true) {
                Ok(()) => key_lane_reply(crate::consent::KEY.unlock_offer(&req.user)),
                Err(why) => Outcome::Error {
                    message: why.into(),
                },
            };
            reply(&mut stream, &o)
        }
        op @ (Op::Consent | Op::Look) => {
            let elevation = matches!(op, Op::Consent);
            log::info!(
                "attempt for {} (uid {}, pid {}{})",
                req.user,
                cred.uid(),
                cred.pid(),
                if elevation { ", consent" } else { "" }
            );
            // A polkit request from an agent that answers the cookie prompt
            // comes back with the request's cookie first, so its card shows
            // the context with that cookie and no other (round 16c).
            if elevation
                && req.polkit_cookie.is_none()
                && crate::consent::caller_lane(cred.pid()) == "polkit"
            {
                if let Some(a) = agent {
                    if crate::consent::speaks_cookies(a, Duration::from_millis(1500)) {
                        log::info!("consent for {} from polkit helper pid {}: asking its agent for the request's cookie", req.user, cred.pid());
                        return reply(&mut stream, &Outcome::NeedCookie);
                    }
                }
            }
            let outcome = if elevation {
                let uid = user_uid(&req.user).unwrap_or(cred.uid());
                // Every way the request ends below comes back out of this
                // block to one gate, `lane_answer`, before the reply: a
                // sudo request whose card never showed, or one unapproved
                // while the session is locked, skips sudo's FIDO2 line,
                // and polkit's ends while locked, so a touch meant for
                // another card or for the lock screen never approves it.
                let o = 'request: {
                    // The window goes to the user's graphical session. If that session
                    // is not the one in the foreground on its seat (sudo on a text
                    // console while the desktop runs on another VT), nobody can see it
                    // or nod at it, and the request would re-arm forever (B2).
                    if !active_graphical_session(&LiveProcs, uid) {
                        log::info!("consent for {}: no active graphical session to ask in; falls through to the password", req.user);
                        break 'request consent_denied(Refusal::NoSession, 0);
                    }
                    // The request's notices go to the desktops the user has
                    // now, as its work begins, or to none (fix round 10,
                    // Codex 6); its card takes its own pin when it is made.
                    let desktops = crate::consent::Pin::take(&req.user).ok();
                    // One consent request at a time, and the rest of the same user's
                    // wait their turn in arrival order rather than falling to the
                    // password: a request has no deadline, so the queue only ever
                    // drains by the user answering (or requesters going away). The
                    // place is taken before the slot is released, so the bound on a
                    // user's requests is what a runaway loop meets, not the slots.
                    let consent = &crate::consent::CONSENT;
                    let place = match consent.join(uid) {
                        Ok(p) => p,
                        Err(e) => {
                            match &e {
                            crate::consent::NoTurn::OtherUser(h) => log::info!("consent for {}: uid {}'s request holds the window; this one falls through to the password", req.user, h),
                            _ => log::info!("consent for {}: {} requests already live or waiting; this one falls through to the password", req.user, crate::consent::CONSENT_PER_UID),
                        }
                            break 'request consent_denied(no_place(&e), 0);
                        }
                    };
                    slot.release();
                    let asked = match req.polkit_cookie.as_deref() {
                        Some(c) => crate::consent::Asked::Cookie(c),
                        None => crate::consent::Asked::Unasked,
                    };
                    let mut caller =
                        crate::consent::CallerInfo::from_pid_asked(cred.pid(), uid, agent, asked);
                    caller.bind = bind.clone();
                    // The card's kill names a pinned process, or none (round 19).
                    caller.pin_kill(peer);
                    if let Some((left, first)) = refusal_standing(uid, Instant::now()) {
                        log::info!(
                        "consent for {}: refused a moment ago; the refusal stands for {}s more, no window for pid {}",
                        req.user,
                        left.as_secs(),
                        cred.pid()
                    );
                        if let (true, Some(desktops)) = (first, &desktops) {
                            crate::consent::notify(
                                desktops,
                                "Refused a moment ago",
                                &format!(
                                "Requests are refused without asking for {} more seconds.\n{}\n{}",
                                left.as_secs().max(1),
                                caller.command,
                                caller.parents
                            ),
                            );
                        }
                        // The same answer the no itself gave: polkit's agent
                        // cancels; sudo goes to its password, past its FIDO2
                        // line, since no card was shown for this request.
                        break 'request crate::auth::refused(&caller, Refusal::RefusedRecently, 0);
                    }
                    // polkitd named the requesting process: it has to be local too, not
                    // only the agent that is serving it. A pkexec from an SSH shell
                    // served by a text agent is refused at the agent; one that reached
                    // the desktop's agent by other means is refused here. Its pidfd,
                    // the one the check pinned, stays with the request: polkit's
                    // helper holds the socket and outlives a request polkitd gives
                    // up, so the requester's exit is what ends it (live test 1).
                    let mut requester_process = None;
                    if let Some(rp) = caller.requester {
                        // The pidfd the requester was read through
                        // (`CallerInfo::polkit`), not a new one by pid.
                        let pidfd = caller
                            .requester_fd
                            .as_ref()
                            .and_then(|f| f.try_clone().ok());
                        match locality(rp, pidfd.as_ref(), &req.user) {
                            Locality::Local(_) => requester_process = pidfd,
                            Locality::Remote(why) => {
                                log::warn!(
                                    "consent for {}: polkit requester pid {} refused: {}",
                                    req.user,
                                    rp,
                                    why
                                );
                                break 'request Outcome::Error {
                                    message: format!("face authentication is local only: {}", why),
                                };
                            }
                        }
                    }
                    // The requester may not wait for an answer (sudo interrupted, the
                    // polkit helper gone): a dup of its socket goes into the live
                    // record, and every wait loop polls it for the hang-up, so the
                    // request ends and its window comes down within a frame wherever
                    // it is. No thread blocks on it.
                    let requester = match stream.try_clone() {
                        Ok(s) => std::os::fd::OwnedFd::from(s),
                        Err(e) => {
                            break 'request Outcome::Error {
                                message: format!("no handle on the requester: {}", e),
                            }
                        }
                    };
                    // The window shows one request at a time; the one waiting is
                    // announced so it is not a silent hang. The turn is held for the
                    // whole request, parked spells included, so a later request never
                    // opens its window over an earlier one.
                    let on_wait = || {
                        log::info!(
                            "consent: request from pid {} waits its turn behind another",
                            cred.pid()
                        );
                        let Some(desktops) = &desktops else {
                            return;
                        };
                        crate::consent::notify(
                            desktops,
                            "Another request is waiting",
                            &format!(
                                "{}\n{}\nIt gets the window after the one on screen is answered.",
                                caller.command, caller.parents
                            ),
                        );
                    };
                    let _turn = match consent.take_turn_watching(
                        place,
                        &req.user,
                        Some(requester),
                        requester_process,
                        &on_wait,
                    ) {
                        Ok(t) => t,
                        Err(e) => {
                            // Behind cards never shown, this request's key
                            // line goes on to the password at once, so the
                            // queue's wait and the line's together stay
                            // inside the password deadline (fix round 10).
                            if matches!(e, crate::consent::NoTurn::Stalled) {
                                consent.note_budget_spent(&req.user);
                            }
                            if !matches!(e, crate::consent::NoTurn::Gone) {
                                log::info!(
                                "consent for {}: lost its place while waiting ({:?}); falls through to the password",
                                req.user,
                                e
                            );
                            }
                            break 'request lost_place_outcome(&caller, &e);
                        }
                    };
                    let outcome = consent_rounds(&take, &req.user, caller);
                    // The answer goes out after one more lock question
                    // (`lane_answer`): the line hears the daemon is at
                    // work first (round 6, item 12).
                    crate::consent::send_beat(&stream);
                    if is_explicit_no(&outcome) {
                        let d = refused(uid, Instant::now());
                        log::info!(
                            "consent for {}: the refusal stands for {}s",
                            req.user,
                            d.as_secs()
                        );
                    }
                    outcome
                };
                gate(o)
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
    }
}

/// The request on `line`, or None for a line that is not one. The password
/// comes out of the line by hand before the parse, which would otherwise
/// un-escape it into a buffer nothing wipes (F12); the field the parse
/// fills holds the spaces it left, and the password taken by hand replaces
/// it. A line that is not an object, or has a top-level key written with
/// an escape, is refused by the hand scan before the parse runs; a parse
/// that still finds the field where the hand did not is refused too.
fn parse(line: &mut String) -> Option<Request> {
    let password = take_password(line).ok()?;
    let mut req: Request = serde_json::from_str(line.trim()).ok()?;
    if password.is_none() && req.consent_password.is_some() {
        return None;
    }
    req.consent_password = password;
    Some(req)
}

/// A password field read straight into a `Secret`, so no plain copy of it
/// outlives the request (F12). What it reads is the spaces `take_password`
/// left in the line, which the password taken by hand then replaces.
fn secret<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<crate::consent::Secret>, D::Error> {
    Ok(Option::<String>::deserialize(d)?.map(crate::consent::Secret::new))
}

/// May a caller running as `peer_uid` ask about the user whose uid is
/// `user_uid`? Root may ask about anyone, everyone else about themselves
/// only, and nobody but root about a user the system does not know. Every
/// request passes this, so the probe's `likely` is only ever about the
/// caller's own face, or answered to root; anyone else gets "not permitted".
/// The lock screen's `key_lane` answer, from the offer as it stands. It
/// takes no camera, so it answers while a request or a scan holds the
/// camera. Round 7 (B): it shows the lane and no longer latches; the lock
/// screen's reserved channel does that.
fn key_lane_reply(offer: Result<crate::consent::KeyPolicy, crate::consent::KeyOff>) -> Outcome {
    match offer {
        Ok(_) => Outcome::KeyLane {
            available: true,
            reason: None,
        },
        Err(why) => Outcome::KeyLane {
            available: false,
            reason: Some(why.to_string()),
        },
    }
}

/// The lock screen's `fprint_lane` answer, from the offer as it stands,
/// as `key_lane_reply` gives the key's.
fn fprint_lane_reply(offer: Result<(), crate::consent::FprintOff>) -> Outcome {
    match offer {
        Ok(()) => Outcome::FprintLane {
            available: true,
            reason: None,
        },
        Err(why) => Outcome::FprintLane {
            available: false,
            reason: Some(why.to_string()),
        },
    }
}

/// The refusal for a consent request that found no place in the queue.
fn no_place(e: &crate::consent::NoTurn) -> Refusal {
    match e {
        crate::consent::NoTurn::OtherUser(_) => Refusal::OtherUser,
        _ => Refusal::TooMany,
    }
}

/// The end of a consent request that lost its place while waiting.
/// A requester gone ends it as one gone while live does (round 16b, Codex
/// 2): polkit's stack ends instead of going on to its key line.
fn lost_place_outcome(caller: &crate::consent::CallerInfo, e: &crate::consent::NoTurn) -> Outcome {
    match e {
        crate::consent::NoTurn::Gone => super::rounds::gone_now(caller, 0),
        _ => consent_denied(lost_place(e), 0),
    }
}

/// The refusal for a consent request that lost its place while waiting.
fn lost_place(e: &crate::consent::NoTurn) -> Refusal {
    match e {
        crate::consent::NoTurn::Gone => Refusal::Gone,
        // The request ahead never showed its card (fix round 10).
        crate::consent::NoTurn::Stalled => Refusal::NoWindow,
        _ => Refusal::OtherUser,
    }
}

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

    /// F12: a password on the line is a `Secret` from the parse on, which
    /// wipes itself on every way out of the request, the refusals before
    /// the answer is taken included.
    #[test]
    fn a_password_is_a_secret_from_the_parse_on() {
        let mut req: Request = serde_json::from_str(
            r#"{"user":"alice","consent_password":"hunter2","consent_token":"t"}"#,
        )
        .unwrap();
        let pw = req.consent_password.take().expect("the password");
        assert_eq!(&*pw, "hunter2");
        assert_eq!(format!("{:?}", pw), "Secret(..)");
        let req: Request = serde_json::from_str(r#"{"user":"alice"}"#).unwrap();
        assert!(req.consent_password.is_none());
    }

    /// F12: the request's password is the one taken out of the line by
    /// hand, `"` and `\` included, and the line keeps none of it; a key
    /// spelled with escapes, which the hand scan does not read, is refused
    /// rather than handed to the parser's own un-escaping.
    #[test]
    fn the_request_password_is_taken_by_hand_and_an_escaped_key_is_refused() {
        let mut line =
            r#"{"user":"alice","consent_password":"a\"b\\c","consent_token":"t"}"#.to_string();
        let mut req = parse(&mut line).expect("a request");
        assert_eq!(&*req.consent_password.take().unwrap(), "a\"b\\c");
        assert!(!line.contains(r#"a\"b\\c"#), "{}", line);
        assert_eq!(req.consent_token.as_deref(), Some("t"));
        let mut escaped = r#"{"user":"alice","consent\u005fpassword":"x"}"#.to_string();
        assert!(parse(&mut escaped).is_none());
        let mut positional =
            r#"["alice",false,false,null,null,false,false,null,null,null,null,false,false,"p\"w"]"#
                .to_string();
        assert!(parse(&mut positional).is_none());
        assert!(parse(&mut r#"{"user":"alice"}"#.to_string())
            .is_some_and(|r| r.consent_password.is_none()));
    }

    /// E: the security key's PIN rides in the password's field, so it is
    /// taken out of the line by hand and is a `Secret` from the parse on,
    /// and the flag beside it makes it a PIN for the key, never a password
    /// answer.
    #[test]
    fn a_key_pin_is_taken_like_the_password_and_answers_nothing() {
        let mut line =
            r#"{"user":"alice","consent_password":"12\"34","consent_key_pin":true,"consent_token":"t"}"#
                .to_string();
        let mut req = parse(&mut line).expect("a request");
        assert!(!line.contains("12"), "{}", line);
        match req.op() {
            Op::Answer {
                token,
                answer: WindowAnswer::KeyPin(Some(pin)),
            } => {
                assert_eq!(&*pin, "12\"34");
                assert_eq!(token.as_deref(), Some("t"));
            }
            _ => panic!("a key PIN is read as the key's PIN"),
        }
        assert_eq!(
            request_op(r#"{"user":"alice","consent_key_pin":true,"consent_token":"t"}"#),
            Some("answer"),
            "a PIN flag with no PIN is still an answer, never a look"
        );
    }
}

#[cfg(test)]
mod fprint_lane_tests {
    use super::*;
    use crate::consent::FprintOff;

    /// The lock screen's fingerprint lane question answers as the key's
    /// does, says why when the lane is not there, and both of the lock
    /// screen's fingerprint lines read as their own operations.
    #[test]
    fn the_fingerprint_lane_answers_as_the_key_lane_does() {
        assert_eq!(
            serde_json::to_string(&fprint_lane_reply(Ok(()))).unwrap(),
            r#"{"result":"fprint_lane","available":true}"#
        );
        let o = fprint_lane_reply(Err(FprintOff::Withheld(
            "a pam_fprintd line in /etc/pam.d/sudo reads the reader outside faceauthd".into(),
        )));
        assert!(serde_json::to_string(&o)
            .unwrap()
            .starts_with(r#"{"result":"fprint_lane","available":false,"reason":"a pam_fprintd"#));
        assert_eq!(
            request_op(r#"{"user":"alice","fprint_unlock":true}"#),
            Some("fprint_unlock")
        );
        assert_eq!(
            request_op(r#"{"user":"alice","fprint_lane":true}"#),
            Some("fprint_lane")
        );
        assert_eq!(
            request_op(r#"{"user":"alice","consent":true,"fprint_unlock":true}"#),
            Some("consent"),
            "a line that names two is read as the first in the fixed order"
        );
        assert_eq!(
            request_op(r#"{"user":"alice","key_unlock":true,"fprint_unlock":true}"#),
            Some("key_unlock")
        );
    }
}

#[cfg(test)]
mod key_lane_tests {
    use super::*;
    use crate::consent::{KeyOff, KeyPolicy};

    /// Round 4 (Codex 2, Opus N2): the lock screen's key lane question
    /// takes no camera (the function has no authenticator to take, so a
    /// request or a scan holding the camera cannot make it answer busy),
    /// says why when the lane is not there. Round 7 (B): latching is the
    /// lock screen's reserved channel's, not the check-ins'.
    #[test]
    fn the_key_lane_answers_without_the_camera() {
        let camera = Mutex::new(());
        let _held = camera.lock().unwrap();
        let o = key_lane_reply(Ok(KeyPolicy::default()));
        assert_eq!(
            serde_json::to_string(&o).unwrap(),
            r#"{"result":"key_lane","available":true}"#
        );
        let o = key_lane_reply(Err(KeyOff::Withheld(
            "a pam_u2f line in /etc/pam.d/sudo reads the key outside faceauthd".into(),
        )));
        assert!(matches!(
            &o,
            Outcome::KeyLane { available: false, reason: Some(r) } if r.contains("pam_u2f")
        ));
        assert!(serde_json::to_string(&o)
            .unwrap()
            .starts_with(r#"{"result":"key_lane","available":false,"#));
    }
}

#[cfg(test)]
mod gate_tests {
    use super::*;
    use crate::consent::{ConsentState, NoTurn, CONSENT_PER_UID};

    /// Round 3's 1: a pile-up made while the session is locked never
    /// reaches a key line. Same-user code starts 33 sudo requests: 32 take
    /// places (and park), and the 33rd finds none. It meets the gate as
    /// every other end does: a parked refusal on sudo, past the FIDO2
    /// line, and a refusal on polkit. So do another user's request on the
    /// window and a place lost while waiting; a requester gone stays gone.
    #[test]
    fn a_pile_up_while_locked_never_reaches_the_key() {
        let st: &'static ConsentState = Box::leak(Box::default());
        let uid = 4242;
        let places: Vec<_> = (0..CONSENT_PER_UID)
            .map(|_| st.join(uid).expect("a place"))
            .collect();
        assert_eq!(places.len(), 32);
        let e = st.join(uid).expect_err("the 33rd finds none");
        assert!(matches!(e, NoTurn::TooMany));
        let other = st.join(uid + 1).expect_err("another user's request");
        assert!(matches!(other, NoTurn::OtherUser(4242)));
        let locked = || {
            (
                crate::lockgate::Verdict::Locked,
                crate::lockgate::Origin::Desktop,
            )
        };
        for o in [
            consent_denied(no_place(&e), 0),
            consent_denied(no_place(&other), 0),
            consent_denied(lost_place(&NoTurn::OtherUser(1)), 0),
            consent_denied(lost_place(&NoTurn::TooMany), 0),
            consent_denied(lost_place(&NoTurn::Stalled), 0),
        ] {
            assert!(
                matches!(
                    crate::auth::lane_answer("sudo", o.clone(), &locked),
                    Outcome::RefusedParked { .. }
                ),
                "{:?}",
                o
            );
            assert!(
                matches!(
                    crate::auth::lane_answer("polkit", o.clone(), &locked),
                    Outcome::Refused { .. }
                ),
                "{:?}",
                o
            );
        }
        let gone = consent_denied(lost_place(&NoTurn::Gone), 0);
        assert_eq!(
            crate::auth::lane_answer("sudo", gone.clone(), &locked),
            gone
        );
        drop(places);
        assert!(st.join(uid).is_ok(), "the places come back");
    }

    /// Round 16b (Codex 2): a request whose requester left while it waited
    /// in the queue ends polkit's stack, as one that left while live does
    /// (`rounds::gone_now`), rather than go on to its key line; sudo's and
    /// every other lost place answer as before.
    #[test]
    fn a_request_whose_requester_left_in_the_queue_ends_polkits_stack() {
        use crate::consent::{CallerInfo, NoTurn};
        let caller = |via: &str| CallerInfo {
            via: via.into(),
            ..Default::default()
        };
        let polkit = lost_place_outcome(&caller("polkit"), &NoTurn::Gone);
        assert!(matches!(polkit, Outcome::Refused { .. }), "{:?}", polkit);
        for verdict in [
            crate::lockgate::Verdict::Unlocked,
            crate::lockgate::Verdict::Locked,
        ] {
            let look = || (verdict, crate::lockgate::Origin::Desktop);
            assert_eq!(
                crate::auth::lane_answer("polkit", polkit.clone(), &look),
                polkit
            );
        }
        assert_eq!(
            lost_place_outcome(&caller("sudo"), &NoTurn::Gone),
            consent_denied(Refusal::Gone, 0)
        );
        for via in ["sudo", "polkit"] {
            assert_eq!(
                lost_place_outcome(&caller(via), &NoTurn::Stalled),
                consent_denied(Refusal::NoWindow, 0)
            );
        }
    }
}

#[cfg(test)]
mod op_tests {
    use super::request_op;

    /// H22: every line a client sends reads as its operation: the PAM
    /// module's three, the CLI's, the enrollment window's watch and the polkit
    /// agent's context with and without polkitd's pids.
    #[test]
    fn each_clients_line_reads_as_its_operation() {
        for (line, op) in [
            (r#"{"user":"alice"}"#, "look"),
            (r#"{"user":"alice","consent":true}"#, "consent"),
            (r#"{"user":"alice","key_unlock":true}"#, "key_unlock"),
            (r#"{"user":"alice","key_fallback":true}"#, "key_fallback"),
            (
                r#"{"user":"alice","key_fallback":true,"consent_password":"1234"}"#,
                "key_fallback",
            ),
            (r#"{"user":"alice","key_lane":true}"#, "key_lane"),
            (
                r#"{"user":"alice","key_fallback":true,"key_ready":true}"#,
                "key_ready",
            ),
            (r#"{"user":"alice","key_unlock":false}"#, "look"),
            (r#"{"user":"alice","probe":false}"#, "look"),
            (r#"{"user":"alice","probe":true}"#, "probe"),
            (r#"{"user":"alice","ping":true}"#, "ping"),
            (
                r#"{"user":"alice","consent_ack":true,"consent_token":"t"}"#,
                "answer",
            ),
            (
                r#"{"user":"alice","consent_rearm":true,"consent_token":"t"}"#,
                "answer",
            ),
            (
                r#"{"user":"alice","consent_passwordless":15,"consent_token":"t"}"#,
                "answer",
            ),
            (
                r#"{"user":"alice","consent_dismiss":true,"consent_token":"t"}"#,
                "answer",
            ),
            (
                r#"{"user":"alice","consent_password":"pw","consent_token":"t"}"#,
                "answer",
            ),
            (
                r#"{"user":"alice","presence_mode":"query"}"#,
                "presence_mode",
            ),
            (
                r#"{"user":"alice","enrol_session":{"label":"desk","start_at":null}}"#,
                "enrol_session",
            ),
            (
                r#"{"user":"alice","enrol_control":"continue"}"#,
                "enrol_control",
            ),
            (r#"{"user":"alice","enrol_watch":true}"#, "enrol_watch"),
            (
                r#"{"user":"alice","enroll":"desk","seconds":6.0,"count":4,"enroll_poses":["centre","left"]}"#,
                "enroll",
            ),
            (
                r#"{"user":"alice","delete_templates":true}"#,
                "delete_templates",
            ),
            (
                r#"{"user":"alice","context_action":"org.freedesktop.policykit.exec","context_message":"m","context_cookie":"c"}"#,
                "context",
            ),
            (
                r#"{"user":"alice","context_action":"a","context_message":"m","context_cookie":"c","context_caller_pid":42,"context_subject_pid":43}"#,
                "context",
            ),
        ] {
            assert_eq!(request_op(&format!("{}\n", line)), Some(op), "{}", line);
        }
        assert_eq!(request_op(r#"{"user":"alice","op":"look"}"#), None);
    }

    /// Round 16c: an agent's context line carries polkitd's cookie and its
    /// word that it answers the cookie prompt, and polkit's PAM module's
    /// consent line the agent's answer; all three are read off the wire.
    #[test]
    fn the_cookie_fields_are_read_off_the_wire() {
        use super::{parse, Op};
        let mut line = r#"{"user":"alice","context_action":"a","context_message":"m","context_cookie":"1-ab-2-3","context_cookie_prompt":"faceauth: polkit cookie challenge "}"#.to_string();
        match parse(&mut line).map(|mut r| r.op()) {
            Some(Op::Context {
                cookie,
                cookie_prompt,
                ..
            }) => {
                assert_eq!(cookie.as_deref(), Some("1-ab-2-3"));
                assert!(cookie_prompt);
            }
            _ => panic!("a context"),
        }
        let mut line = r#"{"user":"alice","context_action":"a","context_message":"m"}"#.to_string();
        match parse(&mut line).map(|mut r| r.op()) {
            Some(Op::Context {
                cookie,
                cookie_prompt,
                ..
            }) => assert!(
                cookie.is_none() && !cookie_prompt,
                "an agent that says nothing"
            ),
            _ => panic!("a context"),
        }
        // Round 17 (Opus F3): only the prompt's own text marks the agent; a
        // shell that knows another text, or says only "true", is not asked.
        // Round 18: round 17's text is another text, so a shell that answers
        // only that exact prompt is never asked the challenge.
        for other in [
            "\"faceauth: polkit cookie\"",
            "\"faceauth: polkit request cookie\"",
            "\"faceauth: polkit cookie challenge\"",
            "\"true\"",
        ] {
            let mut line = format!(
                r#"{{"user":"alice","context_action":"a","context_message":"m","context_cookie":"1-ab-2-3","context_cookie_prompt":{}}}"#,
                other
            );
            match parse(&mut line).map(|mut r| r.op()) {
                Some(Op::Context { cookie_prompt, .. }) => assert!(!cookie_prompt, "{}", other),
                _ => panic!("a context"),
            }
        }
        let mut line = r#"{"user":"alice","context_action":"a","context_message":"m","context_cookie_prompt":true}"#.to_string();
        assert!(
            parse(&mut line).is_none(),
            "the old word alone is no context line"
        );
        // Round 18: the question is the prompt's text and a fresh challenge,
        // and the answer the tag, that same challenge and a space, then a
        // cookie or nothing. Round 17's answer, the tag and a cookie, is one
        // a password that starts with the tag could make, and is none.
        let ch = "0123456789abcdef0123456789abcdef";
        assert_eq!(
            crate::lockgate::polkit_cookie_question(ch),
            format!("faceauth: polkit cookie challenge {ch}")
        );
        assert_eq!(
            crate::lockgate::polkit_cookie_answer(&format!("faceauth-cookie {ch} 1-ab-2-3"), ch),
            Some("1-ab-2-3")
        );
        assert_eq!(
            crate::lockgate::polkit_cookie_answer(&format!("faceauth-cookie {ch} "), ch),
            Some("")
        );
        let another = "fedcba9876543210fedcba9876543210";
        for bad in [
            "1-ab-2-3".to_string(),
            "hunter2".to_string(),
            "faceauth-cookie 1-ab-2-3".to_string(),
            "faceauth-cookie ".to_string(),
            format!("faceauth-cookie {another} 1-ab-2-3"),
            format!("faceauth-cookie {ch}1-ab-2-3"),
            format!("faceauth-cookie {ch}"),
            format!("faceauth-cookie {ch} hunter 2"),
            format!("faceauth-cookie  {ch} 1-ab-2-3"),
            format!("Faceauth-cookie {ch} 1-ab-2-3"),
            String::new(),
        ] {
            assert_eq!(
                crate::lockgate::polkit_cookie_answer(&bad, ch),
                None,
                "{:?}",
                bad
            );
        }
        // A challenge not of its form is none, so no answer can carry it:
        // an empty one would leave only round 17's check.
        let upper = ch.to_uppercase();
        let short = &ch[1..];
        let not_hex = "g".repeat(32);
        for wrong in ["", short, upper.as_str(), not_hex.as_str()] {
            assert_eq!(
                crate::lockgate::polkit_cookie_answer(
                    &format!("faceauth-cookie {wrong} 1-ab-2-3"),
                    wrong
                ),
                None,
                "{:?}",
                wrong
            );
        }
        let mut line = r#"{"user":"alice","consent":true,"polkit_cookie":"1-ab-2-3"}"#.to_string();
        let req = parse(&mut line).expect("a consent line");
        assert_eq!(req.polkit_cookie.as_deref(), Some("1-ab-2-3"));
        assert!(crate::lockgate::polkit_cookie_ok("1-ab-2-3"));
        for bad in ["", "a b", "x\"y", "pässword", &"1".repeat(257)] {
            assert!(!crate::lockgate::polkit_cookie_ok(bad), "{:?}", bad);
        }
    }

    /// H22: a line that names two operations is read as the first of them
    /// in a fixed order, the order the handler has always taken them in.
    /// (The lid and root checks in `handle` answer some such lines before
    /// that operation runs, as they always did.)
    #[test]
    fn a_line_naming_two_operations_is_read_as_the_first() {
        for (line, op) in [
            (
                r#"{"user":"a","context_action":"x","consent_ack":true}"#,
                "context",
            ),
            (
                r#"{"user":"a","consent_dismiss":true,"presence_mode":"query"}"#,
                "answer",
            ),
            (
                r#"{"user":"a","presence_mode":"query","ping":true}"#,
                "presence_mode",
            ),
            (r#"{"user":"a","ping":true,"enroll":"x"}"#, "ping"),
            (
                r#"{"user":"a","enroll":"x","enrol_session":{"label":"x","start_at":null}}"#,
                "enrol_session",
            ),
            (
                r#"{"user":"a","enrol_watch":true,"enrol_control":"redo"}"#,
                "enrol_control",
            ),
            (
                r#"{"user":"a","enrol_watch":true,"enroll":"x"}"#,
                "enrol_watch",
            ),
            (
                r#"{"user":"a","delete_templates":true,"enroll":"x"}"#,
                "enroll",
            ),
            (
                r#"{"user":"a","probe":true,"delete_templates":true}"#,
                "delete_templates",
            ),
            (r#"{"user":"a","consent":true,"probe":true}"#, "probe"),
            (
                r#"{"user":"a","consent":true,"key_unlock":true}"#,
                "consent",
            ),
            (r#"{"user":"a","key_unlock":true,"probe":true}"#, "probe"),
            (
                r#"{"user":"a","key_fallback":true,"consent_ack":true,"consent_token":"t"}"#,
                "key_fallback",
            ),
            (
                r#"{"user":"a","key_fallback":true,"consent":true}"#,
                "key_fallback",
            ),
        ] {
            assert_eq!(request_op(line), Some(op), "{}", line);
        }
    }
}
