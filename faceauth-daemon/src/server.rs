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
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
        let auth = Arc::clone(&auth);
        std::thread::spawn(move || {
            if let Err(e) = handle(stream, &auth) {
                log::warn!("connection: {}", e);
            }
        });
    }
    Ok(())
}

fn handle(mut stream: UnixStream, auth: &Mutex<Authenticator>) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let cred = getsockopt(&stream, PeerCredentials).context("peer credentials")?;
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => return reply(&mut stream, &Outcome::Error { message: format!("bad request: {}", e) }),
    };
    let allowed = cred.uid() == 0 || user_uid(&req.user).map(|u| u == cred.uid()).unwrap_or(false);
    if !allowed {
        log::warn!("uid {} asked about {}: refused", cred.uid(), req.user);
        return reply(&mut stream, &Outcome::Error { message: "not permitted".into() });
    }
    if req.ping {
        let outcome = auth.lock().unwrap_or_else(|p| p.into_inner()).ping(&req.user);
        return reply(&mut stream, &outcome);
    }
    if let Some(label) = &req.enroll {
        log::info!("enrolment for {} (uid {}, label {:?})", req.user, cred.uid(), label);
        let outcome = {
            let mut a = auth.lock().unwrap_or_else(|p| p.into_inner());
            a.enroll(&req.user, label, req.seconds.unwrap_or(12.0), req.count.unwrap_or(10))
        };
        log::info!("enrolment for {}: {:?}", req.user, outcome);
        return reply(&mut stream, &outcome);
    }
    if req.delete_templates {
        let outcome = match auth.lock().unwrap_or_else(|p| p.into_inner()).store.delete(&req.user) {
            Ok(true) => Outcome::Error { message: "deleted".into() },
            Ok(false) => Outcome::NotEnrolled,
            Err(e) => Outcome::Error { message: e.to_string() },
        };
        log::info!("templates for {} deleted by uid {}: {:?}", req.user, cred.uid(), outcome);
        return reply(&mut stream, &outcome);
    }
    if req.probe {
        let outcome = {
            let mut a = auth.lock().unwrap_or_else(|p| p.into_inner());
            a.probe()
        };
        log::debug!("probe for {}: {:?}", req.user, outcome);
        return reply(&mut stream, &outcome);
    }
    log::info!("attempt for {} (uid {}, pid {})", req.user, cred.uid(), cred.pid());
    let outcome = {
        let mut a = auth.lock().unwrap_or_else(|p| p.into_inner());
        a.authenticate(&req.user)
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
