//! The client side of the socket, used by the CLI. The PAM module speaks
//! the same protocol in C.

use crate::auth::Outcome;
use anyhow::{Context, Result};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Client side, shared by the CLI and (in C form) the PAM module.
pub fn ask(socket: &Path, user: &str, timeout: Duration) -> Result<Outcome> {
    request(socket, user, false, timeout)
}

pub fn probe(socket: &Path, user: &str, timeout: Duration) -> Result<Outcome> {
    request(socket, user, true, timeout)
}

/// Root: a pose sweep, scored per frame (dev-tools builds).
#[cfg(feature = "dev-tools")]
pub fn sweep(socket: &Path, user: &str, seconds: f32) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "sweep_seconds": seconds }),
        Some(Duration::from_secs_f32(seconds + 15.0)),
    )
}

fn request(socket: &Path, user: &str, probe: bool, timeout: Duration) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "probe": probe }),
        Some(timeout),
    )
}

/// From the consent window: it has drawn the request `token` names.
pub fn consent_ack(socket: &Path, user: &str, token: Option<&str>) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "consent_ack": true, "consent_token": token }),
        Some(Duration::from_secs(3)),
    )
}

/// From the consent window: with this request's approval, passwordless
/// sudo for `minutes`.
/// From the window: the user pressed "Ready to nod".
pub fn consent_rearm(socket: &Path, user: &str, token: Option<&str>) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "consent_rearm": true, "consent_token": token }),
        None,
    )
}

pub fn consent_passwordless(
    socket: &Path,
    user: &str,
    minutes: u32,
    token: Option<&str>,
) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "consent_passwordless": minutes, "consent_token": token }),
        Some(Duration::from_secs(3)),
    )
}

pub fn consent_answer(
    socket: &Path,
    user: &str,
    password: Option<&str>,
    dismiss: bool,
    token: Option<&str>,
) -> Result<Outcome> {
    let body = match password {
        Some(pw) => {
            serde_json::json!({ "user": user, "consent_password": pw, "consent_token": token })
        }
        None => {
            serde_json::json!({ "user": user, "consent_dismiss": dismiss, "consent_token": token })
        }
    };
    send(socket, body, Some(Duration::from_secs(3)))
}

/// A consent request: the reply comes when the user answers the window, or
/// never (the daemon ends it only if this socket hangs up). No deadline.
pub fn ask_consent(socket: &Path, user: &str) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "consent": true }),
        None,
    )
}

/// From the watched user: switch the presence watch to "default" or
/// "secure" until the daemon restarts, or "query" to read it. Answered
/// with `Outcome::PresenceMode`.
pub fn presence_mode(socket: &Path, user: &str, mode: &str) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "presence_mode": mode }),
        Some(Duration::from_secs(3)),
    )
}

pub fn ping(socket: &Path, user: &str) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "ping": true }),
        Some(Duration::from_secs(3)),
    )
}

/// Root: the enrolment walk-through; returns when it ends.
pub fn enrol_session(
    socket: &Path,
    user: &str,
    label: &str,
    start_at: Option<&str>,
) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "enrol_session": { "label": label, "start_at": start_at } }),
        Some(Duration::from_secs(16 * 60)),
    )
}

/// From the user's window: steer the running session.
pub fn enrol_control(socket: &Path, user: &str, word: &str) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "enrol_control": word }),
        Some(Duration::from_secs(3)),
    )
}

pub fn enroll(
    socket: &Path,
    user: &str,
    label: &str,
    seconds: f32,
    count: usize,
    pose: Option<&str>,
) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "enroll": label, "seconds": seconds, "count": count, "enroll_pose": pose }),
        Some(Duration::from_secs_f32(seconds + 15.0)),
    )
}

pub fn delete_templates(socket: &Path, user: &str) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "delete_templates": true }),
        Some(Duration::from_secs(3)),
    )
}

pub fn send(socket: &Path, body: serde_json::Value, timeout: Option<Duration>) -> Result<Outcome> {
    let mut stream =
        UnixStream::connect(socket).with_context(|| format!("connect {}", socket.display()))?;
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let req = body.to_string() + "\n";
    stream.write_all(req.as_bytes())?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    serde_json::from_str(line.trim()).context("parse reply")
}
