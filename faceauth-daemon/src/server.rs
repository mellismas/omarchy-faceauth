//! The Unix socket the PAM module talks to. One JSON request per connection,
//! one JSON reply, newline-terminated.
//!
//! Request:  {"user": "alice"}
//! Reply:    {"result": "match", "score": 0.93, "frames": 2, "elapsed_ms": 1800}
//!           {"result": "no_match" | "no_face" | "denied" | "not_enrolled" | "error", ...}
//!
//! Authorisation is by peer credentials: a connection may ask about its own
//! uid's user, or anything if it is root. Attempts are serialised; a second
//! request while one runs waits its turn (the camera is one resource).

use crate::auth::{Authenticator, Outcome};
use anyhow::{Context, Result};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde::Deserialize;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Longest request line accepted, before any authorisation.
const MAX_REQUEST: u64 = 4096;
/// Connections handled at once; the rest are refused immediately.
const MAX_CONNECTIONS: usize = 8;
/// How long a request waits for the camera before answering "busy".
const BUSY_WAIT: Duration = Duration::from_millis(1500);
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
/// The consent answer slot and the pending set, cloned from the authenticator
/// at start so answer requests never need the camera lock.
static ANSWERS: std::sync::LazyLock<crate::consent::Answers> = std::sync::LazyLock::new(Default::default);
static PENDING: std::sync::LazyLock<Arc<Mutex<std::collections::HashSet<String>>>> = std::sync::LazyLock::new(Default::default);

/// Wire the authenticator's answer slot and pending set to the server's statics.
pub fn attach(auth: &mut Authenticator) {
    auth.answers = Arc::clone(&ANSWERS);
    auth.pending = Arc::clone(&PENDING);
}

#[derive(Deserialize)]
struct Request {
    user: String,
    /// true: a presence probe (one short look, detector only) instead of an attempt.
    #[serde(default)]
    probe: bool,
    /// true: is the daemon up, with models loaded and this user enrolled?
    #[serde(default)]
    ping: bool,
    /// Some: enrol this user with the given label.
    #[serde(default)]
    enroll: Option<String>,
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
    /// Seconds the caller will wait for the consent verdict; the window stays
    /// up for the whole of it minus a margin, and never longer.
    #[serde(default)]
    budget: Option<f32>,
    /// From the consent window: the typed password for the pending request.
    #[serde(default)]
    consent_password: Option<String>,
    /// From the consent window: dismiss the pending request.
    #[serde(default)]
    consent_dismiss: bool,
}

pub fn serve(auth: Arc<Mutex<Authenticator>>, socket: &Path) -> Result<()> {
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket).with_context(|| format!("bind {}", socket.display()))?;
    // World-connectable; the peer-credential check below is the access control.
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o666))?;
    log::info!("listening on {}", socket.display());
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                log::warn!("accept: {}", e);
                continue;
            }
        };
        if ACTIVE.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
            let mut s = stream;
            let _ = reply(&mut s, &Outcome::Error { message: "busy".into() });
            continue;
        }
        let auth = Arc::clone(&auth);
        std::thread::spawn(move || {
            if let Err(e) = handle(stream, &auth) {
                log::warn!("connection: {}", e);
            }
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

fn handle(mut stream: UnixStream, auth: &Mutex<Authenticator>) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let cred = getsockopt(&stream, PeerCredentials).context("peer credentials")?;
    // Bounded read before anything else: a peer that never sends a newline
    // cannot grow this, and the error never echoes the peer's bytes back.
    let mut line = String::new();
    let mut reader = BufReader::new(stream.try_clone()?).take(MAX_REQUEST);
    reader.read_line(&mut line)?;
    if !line.ends_with('\n') {
        return reply(&mut stream, &Outcome::Error { message: "bad request".into() });
    }
    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(_) => return reply(&mut stream, &Outcome::Error { message: "bad request".into() }),
    };
    let allowed = cred.uid() == 0 || user_uid(&req.user).map(|u| u == cred.uid()).unwrap_or(false);
    if !allowed {
        log::warn!("uid {} asked about {}: refused", cred.uid(), req.user);
        return reply(&mut stream, &Outcome::Error { message: "not permitted".into() });
    }
    // Take the camera, or say "busy" instead of queueing behind another
    // attempt: the callers (PAM, the lock screen) retry on their own terms.
    let take = || -> Option<std::sync::MutexGuard<'_, Authenticator>> {
        let deadline = Instant::now() + BUSY_WAIT;
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
    // Answers to a pending consent request must not wait for the camera lock:
    // the consent flow holds it. They go through the shared answer slot.
    if req.consent_password.is_some() || req.consent_dismiss {
        // No lock: read the shared handles through a short-lived try_lock on
        // the authenticator is impossible while consent runs, so they live in
        // the server's own copies (see `serve`).
        let (answers, pending) = (&ANSWERS, &PENDING);
        let is_pending = pending.lock().map(|p| p.contains(&req.user)).unwrap_or(false);
        if !is_pending {
            return reply(&mut stream, &Outcome::Error { message: "no pending request".into() });
        }
        let answer = if req.consent_dismiss { crate::consent::Answer::Dismiss } else { crate::consent::Answer::Password(req.consent_password.clone().unwrap_or_default()) };
        if let Ok(mut m) = answers.lock() {
            m.insert(req.user.clone(), answer);
        }
        log::info!("consent answer for {} from uid {}: {}", req.user, cred.uid(), if req.consent_dismiss { "dismiss" } else { "password" });
        return reply(&mut stream, &Outcome::Pong { version: env!("CARGO_PKG_VERSION").into(), model: String::new(), templates: 0 });
    }
    if req.ping {
        let outcome = match take() {
            Some(a) => a.ping(&req.user),
            None => Outcome::Error { message: "busy".into() },
        };
        return reply(&mut stream, &outcome);
    }
    // Enrolment and deletion change who can unlock the machine: only root may
    // ask (the setup command runs them under sudo, behind the password), so no
    // unprivileged process, and nothing reaching a locked session over ssh,
    // can enrol a new face or erase the enrolled one.
    if req.enroll.is_some() || req.delete_templates {
        if cred.uid() != 0 {
            log::warn!("uid {} asked to change templates for {}: refused", cred.uid(), req.user);
            return reply(&mut stream, &Outcome::Error { message: "not permitted: enrolment and deletion require root".into() });
        }
    }
    if let Some(label) = &req.enroll {
        log::info!("enrolment for {} (uid {}, label {:?})", req.user, cred.uid(), label);
        let outcome = match take() {
            Some(mut a) => a.enroll(&req.user, label, req.seconds.unwrap_or(12.0).clamp(4.0, 20.0), req.count.unwrap_or(10)),
            None => Outcome::Error { message: "busy".into() },
        };
        log::info!("enrolment for {}: {:?}", req.user, outcome);
        return reply(&mut stream, &outcome);
    }
    if req.delete_templates {
        let outcome = match take() {
            Some(a) => match a.store.delete(&req.user) {
                Ok(true) => Outcome::Deleted,
                Ok(false) => Outcome::NotEnrolled,
                Err(e) => Outcome::Error { message: e.to_string() },
            },
            None => Outcome::Error { message: "busy".into() },
        };
        log::info!("templates for {} deleted by uid {}: {:?}", req.user, cred.uid(), outcome);
        return reply(&mut stream, &outcome);
    }
    if req.probe {
        let outcome = match take() {
            Some(mut a) => a.probe(),
            None => Outcome::Error { message: "busy".into() },
        };
        log::debug!("probe for {}: {:?}", req.user, outcome);
        return reply(&mut stream, &outcome);
    }
    log::info!("attempt for {} (uid {}, pid {}{})", req.user, cred.uid(), cred.pid(), if req.consent { ", consent" } else { "" });
    let outcome = match take() {
        Some(mut a) => {
            if req.consent {
                let uid = user_uid(&req.user).unwrap_or(cred.uid());
                let caller = crate::consent::CallerInfo::from_pid(cred.pid(), uid);
                a.authenticate_with_consent(&req.user, caller, req.budget)
            } else {
                a.authenticate(&req.user)
            }
        }
        None => Outcome::Error { message: "busy".into() },
    };
    log::info!("attempt for {}: {:?}", req.user, outcome);
    reply(&mut stream, &outcome)
}

fn reply(stream: &mut UnixStream, o: &Outcome) -> Result<()> {
    let mut s = serde_json::to_string(o)?;
    s.push('\n');
    stream.write_all(s.as_bytes())?;
    Ok(())
}

fn user_uid(name: &str) -> Option<u32> {
    nix::unistd::User::from_name(name).ok().flatten().map(|u| u.uid.as_raw())
}

/// Client side, shared by the CLI and (in C form) the PAM module.
pub fn ask(socket: &Path, user: &str, timeout: Duration) -> Result<Outcome> {
    request(socket, user, false, timeout)
}

pub fn probe(socket: &Path, user: &str, timeout: Duration) -> Result<Outcome> {
    request(socket, user, true, timeout)
}

fn request(socket: &Path, user: &str, probe: bool, timeout: Duration) -> Result<Outcome> {
    send(socket, serde_json::json!({ "user": user, "probe": probe }), timeout)
}

pub fn consent_answer(socket: &Path, user: &str, password: Option<&str>, dismiss: bool) -> Result<Outcome> {
    let body = match password {
        Some(pw) => serde_json::json!({ "user": user, "consent_password": pw }),
        None => serde_json::json!({ "user": user, "consent_dismiss": dismiss }),
    };
    send(socket, body, Duration::from_secs(3))
}

pub fn ask_consent(socket: &Path, user: &str, timeout: Duration) -> Result<Outcome> {
    send(socket, serde_json::json!({ "user": user, "consent": true, "budget": timeout.as_secs_f32() }), timeout)
}

pub fn ping(socket: &Path, user: &str) -> Result<Outcome> {
    send(socket, serde_json::json!({ "user": user, "ping": true }), Duration::from_secs(3))
}

pub fn enroll(socket: &Path, user: &str, label: &str, seconds: f32, count: usize) -> Result<Outcome> {
    send(socket, serde_json::json!({ "user": user, "enroll": label, "seconds": seconds, "count": count }), Duration::from_secs_f32(seconds + 15.0))
}

pub fn delete_templates(socket: &Path, user: &str) -> Result<Outcome> {
    send(socket, serde_json::json!({ "user": user, "delete_templates": true }), Duration::from_secs(3))
}

pub fn send(socket: &Path, body: serde_json::Value, timeout: Duration) -> Result<Outcome> {
    let mut stream = UnixStream::connect(socket).with_context(|| format!("connect {}", socket.display()))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let req = body.to_string() + "\n";
    stream.write_all(req.as_bytes())?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    Ok(serde_json::from_str(line.trim()).context("parse reply")?)
}
