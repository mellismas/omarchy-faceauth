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
use anyhow::{bail, Context, Result};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::os::fd::AsFd;
use serde::Deserialize;
use std::io::{BufRead, BufReader, Read, Write};
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
/// Held by the consent request whose turn it is; the others wait on it.
static CONSENT_TURN: Mutex<()> = Mutex::new(());
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
    /// From the consent window: the token the daemon put in its payload.
    #[serde(default)]
    consent_token: Option<String>,
    /// From the polkit agent: what the request it is about to serve is.
    #[serde(default)]
    context_action: Option<String>,
    #[serde(default)]
    context_message: Option<String>,
    #[serde(default)]
    context_cookie: Option<String>,
}

/// Who may connect: root, and the enrolled users, by ACL on the socket
/// (mode 0660 plus a read-write entry per enrolled uid). Any other account
/// is refused by the kernel before a byte is read. No group, so no re-login
/// at setup: enrolment itself grants access, deletion revokes it.
pub fn apply_socket_acl(socket: &Path, users: &[String]) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660)) {
        log::warn!("socket mode: {}", e);
        return;
    }
    let mut spec = String::from("u::rw,g::rw,o::-");
    for u in users {
        if let Some(uid) = user_uid(u) {
            spec.push_str(&format!(",u:{}:rw", uid));
        }
    }
    match std::process::Command::new("/usr/bin/setfacl").arg("--set").arg(&spec).arg(socket).env_clear().env("PATH", "/usr/bin:/bin").output() {
        Ok(o) if o.status.success() => log::info!("socket open to root and {} enrolled user(s): {}", users.len(), users.join(" ")),
        Ok(o) => log::warn!("setfacl: {} {}; socket stays root-only", o.status, String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => log::warn!("setfacl: {}; socket stays root-only", e),
    }
}

fn refresh_socket_acl(auth: &Mutex<Authenticator>) {
    if let Ok(a) = auth.lock() {
        apply_socket_acl(&a.cfg.socket, &a.store.enrolled_users());
    }
}

pub fn serve(auth: Arc<Mutex<Authenticator>>, socket: &Path) -> Result<()> {
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket).with_context(|| format!("bind {}", socket.display()))?;
    // World-connectable; the peer-credential check below is the access control.
    {
        let users = auth.lock().map(|a| a.store.enrolled_users()).unwrap_or_default();
        apply_socket_acl(socket, &users);
    }
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
    // Face authentication is local by definition: the camera sees whoever is
    // at the machine, which says nothing about a caller reaching it over the
    // network. Every request, the probes and window answers included, must
    // come from a caller shown to be local; anything unprovable is remote,
    // and the caller's PAM stack falls through to its password.
    let peer_pidfd = getsockopt(&stream, nix::sys::socket::sockopt::PeerPidfd).ok();
    match locality(cred.pid(), peer_pidfd.as_ref(), &req.user) {
        Locality::Local => {}
        Locality::Remote(why) => {
            log::warn!("request for {} from pid {} (uid {}) refused: {}", req.user, cred.pid(), cred.uid(), why);
            return reply(&mut stream, &Outcome::Error { message: format!("face authentication is local only: {}", why) });
        }
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
    // The polkit agent, before its helper's PAM request arrives, says what
    // the request is. Queued per user in arrival order, from the agent's
    // own uid, single use, and only from a local caller (the gate above).
    if let Some(action) = &req.context_action {
        let clip = |s: &str| s.chars().filter(|c| !c.is_control()).take(300).collect::<String>();
        let ctx = crate::consent::PolkitContext { action: clip(action), message: clip(req.context_message.as_deref().unwrap_or("")), cookie: clip(req.context_cookie.as_deref().unwrap_or("")), uid: cred.uid(), at: Instant::now() };
        log::info!("polkit context from the agent (uid {}, pid {}): {} {}", cred.uid(), cred.pid(), ctx.action, ctx.message);
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
        // Only the window the daemon summoned holds the token; a process
        // that merely reaches the socket cannot cancel or answer a request.
        if !crate::consent::Dialog::token_matches(&req.user, req.consent_token.as_deref()) {
            log::warn!("consent answer for {} from uid {} pid {} without the request's token: refused", req.user, cred.uid(), cred.pid());
            return reply(&mut stream, &Outcome::Error { message: "no pending request".into() });
        }
        let answer = if req.consent_dismiss { crate::consent::Answer::Dismiss } else { crate::consent::Answer::Password(req.consent_password.clone().unwrap_or_default()) };
        if let Ok(mut m) = answers.lock() {
            m.insert(req.user.clone(), answer);
        }
        log::info!("consent answer for {} from uid {}: {}", req.user, cred.uid(), if req.consent_dismiss { "dismiss" } else { "password" });
        return reply(&mut stream, &Outcome::Pong { version: env!("CARGO_PKG_VERSION").into(), model: String::new(), templates: 0, sealed: false, unbound: 0 });
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
                Err(e) => Outcome::Error { message: e.to_string() },
            },
            None => Outcome::Error { message: "busy".into() },
        };
        log::info!("templates for {} deleted by uid {}: {:?}", req.user, cred.uid(), outcome);
        refresh_socket_acl(auth);
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
    let outcome = if req.consent {
        let uid = user_uid(&req.user).unwrap_or(cred.uid());
        let caller = crate::consent::CallerInfo::from_pid(cred.pid(), uid);
        // The requester may not wait for an answer (sudo interrupted, the
        // polkit helper gone): a hang-up on its socket ends the request and
        // takes the window down with it.
        let probe = stream.try_clone()?;
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let active = Arc::new(std::sync::atomic::AtomicBool::new(true));
        {
            // A watcher blocks on the request socket; a hang-up drops a
            // "gone" answer into the slot every wait loop polls, so the
            // window comes down within a frame wherever the request is.
            let (flag, active, user) = (Arc::clone(&flag), Arc::clone(&active), req.user.clone());
            std::thread::spawn(move || {
                use nix::sys::socket::{recv, MsgFlags};
                use std::os::fd::AsRawFd;
                let mut b = [0u8; 1];
                loop {
                    match recv(probe.as_raw_fd(), &mut b, MsgFlags::MSG_PEEK) {
                        Ok(0) => break,
                        // A signal (the daemon reaps the window's helper
                        // processes) interrupts the wait; it is not a hang-up.
                        Err(nix::errno::Errno::EINTR) => continue,
                        // The request socket carries the handler's five-second
                        // read timeout, which the clone shares: an idle period
                        // is not a hang-up either.
                        Err(nix::errno::Errno::EAGAIN) => continue,
                        Err(e) => {
                            log::warn!("consent: request socket: {}", e);
                            break;
                        }
                        Ok(_) => std::thread::sleep(Duration::from_millis(200)), // unexpected extra bytes; not our concern
                    }
                }
                if active.load(std::sync::atomic::Ordering::SeqCst) {
                    flag.store(true, std::sync::atomic::Ordering::SeqCst);
                    if let Ok(mut m) = ANSWERS.lock() {
                        m.insert(user, crate::consent::Answer::Gone);
                    }
                }
            });
        }
        let gone = || flag.load(std::sync::atomic::Ordering::SeqCst);
        // One consent request at a time, and the rest wait their turn rather
        // than falling to the password: a request has no deadline, so the
        // queue only ever drains by the user answering (or requesters going
        // away). The turn is held for the whole request, parked spells
        // included, so a later request never opens its window over an
        // earlier one.
        let _turn = {
            let mut waited = false;
            loop {
                match CONSENT_TURN.try_lock() {
                    Ok(g) => break g,
                    Err(std::sync::TryLockError::Poisoned(p)) => break p.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => {
                        if gone() {
                            active.store(false, std::sync::atomic::Ordering::SeqCst);
                            let _ = ANSWERS.lock().map(|mut m| m.remove(&req.user));
                            return reply(&mut stream, &Outcome::ConsentDenied { reason: "requester gone".into(), elapsed_ms: 0 });
                        }
                        if !waited {
                            waited = true;
                            log::info!("consent: request from pid {} waits its turn behind another", cred.pid());
                        }
                        std::thread::sleep(Duration::from_millis(300));
                    }
                }
            }
        };
        let outcome = consent_rounds(&take, &req.user, caller, req.budget, &gone);
        active.store(false, std::sync::atomic::Ordering::SeqCst);
        // A hang-up noticed after the verdict must not haunt the next request.
        if let Ok(mut m) = ANSWERS.lock() {
            if matches!(m.get(&req.user), Some(crate::consent::Answer::Gone)) {
                m.remove(&req.user);
            }
        }
        outcome
    } else {
        match take() {
            Some(mut a) => a.authenticate(&req.user),
            None => Outcome::Error { message: "busy".into() },
        }
    };
    // Scores go to root peers only, and not to the journal (readable by
    // wheel on Omarchy): the info line carries the redacted outcome.
    log::info!("attempt for {}: {:?}", req.user, outcome.clone().redacted());
    log::debug!("attempt for {}: {:?}", req.user, outcome);
    let outcome = if cred.uid() == 0 { outcome } else { outcome.redacted() };
    reply(&mut stream, &outcome)
}

/// Where a request comes from, as far as the daemon can prove it.
pub enum Locality {
    Local,
    Remote(String),
}

/// A positive, fail-closed check: a caller is local when the daemon can show
/// it is, and remote otherwise (any read error, timeout or unfamiliar shape).
///
/// 1. Any `sshd` or `sshd-session` in the parent chain: remote.
/// 2. Root in `/system.slice/`: local (the daemon's own helpers, root's cron).
/// 3. In a logind session scope (`session-N.scope`): local only if logind
///    says that session is not remote and is on a seat.
/// 4. Inside the target user's own manager (`user-<uid>.slice/user@<uid>.service`,
///    where every desktop app and the lock screen's PAM helper lives, with no
///    session scope of its own): local only if that user has a live session on
///    a seat that logind does not mark remote.
/// 5. Anything else: remote.
///
/// The concession in step 4, written here rather than discovered later: a
/// same-uid process inside the user manager counts as local whenever the
/// user has a local session, and provenance cannot tell a same-uid remote
/// shell that asked the manager to fork for it (`systemd-run --user`) from a
/// local one. What stands between that and root is the consent window, which
/// names the requester, and the nod, which a remote shell cannot produce.
///
/// `pidfd`, when the kernel gives one (SO_PEERPIDFD), is checked after the
/// reads: a caller that exits before its /proc is read is not local.
fn locality(pid: i32, pidfd: Option<&std::os::fd::OwnedFd>, target_user: &str) -> Locality {
    match locality_inner(pid, target_user) {
        Ok(l) => {
            if let (Locality::Local, Some(fd)) = (&l, pidfd) {
                if process_exited(fd) {
                    return Locality::Remote("caller exited before it could be verified".into());
                }
            }
            l
        }
        Err(e) => Locality::Remote(format!("cannot verify the caller: {}", e)),
    }
}

fn locality_inner(pid: i32, target_user: &str) -> Result<Locality> {
    // 1. Ancestry. The chain must reach init; a break means the caller (or a
    // parent) vanished mid-read, which is not a demonstration of anything.
    let mut p = pid;
    for _ in 0..128 {
        let pp = crate::consent::ppid_of(p).ok_or_else(|| anyhow::anyhow!("process {} unreadable", p))?;
        if pp <= 1 {
            break;
        }
        let comm = crate::consent::comm_of(pp);
        if is_ssh_comm(&comm) {
            return Ok(Locality::Remote(format!("started under {} (pid {})", comm, pp)));
        }
        p = pp;
    }
    let status = std::fs::read_to_string(format!("/proc/{}/status", pid)).context("read caller status")?;
    let real_uid: u32 = status.lines().find_map(|l| l.strip_prefix("Uid:")).and_then(|v| v.split_whitespace().next()).and_then(|s| s.parse().ok()).ok_or_else(|| anyhow::anyhow!("no uid in status"))?;
    let cgroup = std::fs::read_to_string(format!("/proc/{}/cgroup", pid)).context("read caller cgroup")?;
    let path = cgroup.lines().find_map(|l| l.splitn(3, ':').nth(2)).ok_or_else(|| anyhow::anyhow!("no cgroup path"))?.to_string();
    // 2. Root's own services.
    if real_uid == 0 && path.starts_with("/system.slice/") {
        return Ok(Locality::Local);
    }
    // 3. A logind session of its own.
    if let Some(id) = session_id_from_cgroup(&cgroup) {
        return Ok(match session_is_local(&id)? {
            true => Locality::Local,
            false => Locality::Remote(format!("logind session {} is remote or seatless", id)),
        });
    }
    // 4. The target user's manager.
    let target_uid = user_uid(target_user).ok_or_else(|| anyhow::anyhow!("unknown user {}", target_user))?;
    if path.starts_with(&format!("/user.slice/user-{}.slice/user@{}.service/", target_uid, target_uid)) {
        let sessions = loginctl(&["show-user", &target_uid.to_string(), "-p", "Sessions", "--value"])?;
        for id in sessions.split_whitespace() {
            if session_is_local(id)? {
                return Ok(Locality::Local);
            }
        }
        return Ok(Locality::Remote(format!("{} has no local session on a seat", target_user)));
    }
    Ok(Locality::Remote(format!("caller in {} is not a session of {}", path.trim(), target_user)))
}

/// Does logind put this session on a seat, not remote, as a user session?
fn session_is_local(id: &str) -> Result<bool> {
    let out = loginctl(&["show-session", id, "-p", "Remote", "-p", "Seat", "-p", "Class"])?;
    let get = |k: &str| out.lines().find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('='))).unwrap_or("").trim().to_string();
    Ok(get("Remote") == "no" && !get("Seat").is_empty() && get("Class") == "user")
}

fn loginctl(args: &[&str]) -> Result<String> {
    let out = std::process::Command::new("/usr/bin/timeout")
        .args(["-k", "2", "5", "/usr/bin/loginctl"])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .context("run loginctl")?;
    if !out.status.success() {
        bail!("loginctl {}: {} {}", args.join(" "), out.status, String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A pidfd polls readable once its process has exited.
fn process_exited(fd: &std::os::fd::OwnedFd) -> bool {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
    match poll(&mut fds, PollTimeout::ZERO) {
        Ok(n) if n > 0 => true,
        Ok(_) => false,
        Err(_) => true,
    }
}

/// OpenSSH's per-connection processes: `sshd` up to 9.7, `sshd-session`
/// from 9.8 (and `sshd-auth` during authentication, never an ancestor of a
/// shell, listed for completeness).
fn is_ssh_comm(comm: &str) -> bool {
    matches!(comm.trim(), "sshd" | "sshd-session" | "sshd-auth")
}

/// The logind session id from a cgroup listing (`session-3.scope`,
/// `session-c1.scope`), if the process is in one.
fn session_id_from_cgroup(cgroup: &str) -> Option<String> {
    for line in cgroup.lines() {
        for part in line.split('/') {
            if let Some(rest) = part.strip_prefix("session-") {
                if let Some(id) = rest.strip_suffix(".scope") {
                    if !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric()) {
                        return Some(id.to_string());
                    }
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod locality_tests {
    use super::*;

    #[test]
    fn ssh_process_names() {
        assert!(is_ssh_comm("sshd"));
        assert!(is_ssh_comm("sshd-session"));
        assert!(!is_ssh_comm("bash"));
        assert!(!is_ssh_comm("sshd-agent"));
    }

    #[test]
    fn session_ids_from_cgroups() {
        assert_eq!(session_id_from_cgroup("0::/user.slice/user-1000.slice/session-3.scope\n"), Some("3".into()));
        assert_eq!(session_id_from_cgroup("0::/user.slice/user-1000.slice/session-c1.scope"), Some("c1".into()));
        // The desktop's app scope and systemd-run --user: no logind session of their own.
        assert_eq!(session_id_from_cgroup("0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-graphical.slice/app-Hyprland-xdg\\x2dterminal\\x2dexec-af100da6.scope"), None);
        assert_eq!(session_id_from_cgroup("0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-p193148-i205978.service"), None);
        assert_eq!(session_id_from_cgroup("0::/system.slice/faceauth.service"), None);
        assert_eq!(session_id_from_cgroup("0::/user.slice/session-.scope"), None);
    }

    #[test]
    fn a_vanished_caller_is_not_local() {
        // A pid that cannot exist: every read fails, and failure is remote.
        match locality(i32::MAX - 1, None, "root") {
            Locality::Remote(why) => assert!(why.contains("cannot verify"), "{}", why),
            Locality::Local => panic!("an unreadable caller must not be local"),
        }
    }

    #[test]
    fn a_process_that_exited_is_not_local() {
        use std::os::fd::FromRawFd;
        let child = std::process::Command::new("/bin/true").spawn().unwrap();
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) };
        assert!(raw >= 0, "pidfd_open");
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as i32) };
        let mut child = child;
        child.wait().unwrap();
        assert!(process_exited(&fd));
    }

    /// This test process is local when the developer is at the machine and
    /// remote over SSH; either way the answer must be the true one.
    #[test]
    fn this_test_process_is_classified() {
        let me = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let r = locality(std::process::id() as i32, None, &me);
        if std::env::var_os("SSH_CONNECTION").is_some() {
            assert!(matches!(r, Locality::Remote(_)), "running over SSH should be remote");
        } else if std::path::Path::new("/run/systemd/seats/seat0").exists() {
            match r {
                Locality::Local => {}
                Locality::Remote(why) => panic!("a shell on the console should be local: {}", why),
            }
        }
    }
}

/// Drive a consent request through as many camera rounds as it needs. When
/// the user leaves mid-request the session is locked and the request parks
/// without the camera (so the lock screen can use it), until the user is back
/// (a face match on the lock screen), a password or a dismissal arrives from
/// the window, or the caller's budget runs out.
fn consent_rounds<'a>(take: &dyn Fn() -> Option<std::sync::MutexGuard<'a, Authenticator>>, user: &str, caller: crate::consent::CallerInfo, budget: Option<f32>, gone: &dyn Fn() -> bool) -> Outcome {
    use crate::auth::Round;
    use crate::consent::{Answer, Gesture};
    // A request that arrives while the session is locked waits, unseen and
    // without the camera (the lock screen owns it), until the unlock. The
    // window is not summoned at all: hiding a pending window would make it
    // answer with a dismissal.
    let mut already_locked = crate::consent::session_locked(user);
    let mut session = match take() {
        Some(mut a) => match a.consent_begin(user, caller, budget, !already_locked) {
            Ok(s) => s,
            Err(o) => return o,
        },
        None => return Outcome::Error { message: "busy".into() },
    };
    if already_locked {
        log::info!("consent: request from pid {} arrived while the session is locked; parked until the unlock", session.caller.pid);
    }
    loop {
        if gone() {
            log::info!("consent: the requester went away after {:.0}s; window closed", session.started.elapsed().as_secs_f32());
            return Outcome::ConsentDenied { reason: "requester gone".into(), elapsed_ms: session.started.elapsed().as_millis() as u64 };
        }
        if !already_locked {
            let round = match take() {
                Some(mut a) => a.consent_round(&mut session),
                None => {
                    // The camera is taken (the lock screen, most likely): wait
                    // a little and try again rather than giving up.
                    if session.started.elapsed().as_secs_f32() > session.total {
                        return Outcome::ConsentDenied { reason: "no answer".into(), elapsed_ms: session.started.elapsed().as_millis() as u64 };
                    }
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                }
            };
            let Round::FaceLost = round else {
                let Round::Done(o) = round else { unreachable!() };
                return o;
            };
        }
        // Lock the session (unless it already is), then park.
        let lock_time = Instant::now();
        let (lock_cmd, lock_user) = {
            let cfg = &session.dialog.cfg.presence;
            (cfg.lock_command.clone(), cfg.user.clone())
        };
        if already_locked {
            // Somebody else locked it; adopt the lock so the presence watch
            // does not lock again and the resume logic below applies.
            if let Some(mut a) = take() {
                a.session_locked_at = Some(lock_time);
            }
            session.locked_at = Some(lock_time);
        } else if session.locked_at.is_none() && !lock_cmd.is_empty() {
            // Hand the lock to the presence watch first so it does not lock too.
            if let Some(mut a) = take() {
                a.session_locked_at = Some(lock_time);
            }
            let args: Vec<String> = lock_cmd.iter().skip(1).map(|a| if a.is_empty() { lock_user.clone() } else { a.clone() }).collect();
            match std::process::Command::new(&lock_cmd[0]).args(&args).env("PATH", "/usr/local/bin:/usr/bin:/bin").output() {
                Ok(o) if o.status.success() => {
                    log::info!("consent: user left with a request pending; session locked");
                    session.locked_at = Some(lock_time);
                }
                Ok(o) => log::warn!("consent: lock command exited {}: {}", o.status, String::from_utf8_lossy(&o.stderr).trim()),
                Err(e) => log::warn!("consent: lock command: {}", e),
            }
        }
        if !already_locked {
            let _ = session.dialog.show("locked", "Locked while you were away. Unlock, then look at the camera or type your password.", &session.caller, session.total);
        }
        already_locked = false;
        // Park: no camera. Wake on a face match newer than the lock, on the
        // session unlocking by any means, on an answer from the window, or
        // when the budget is out.
        let mut last_lock_check = Instant::now();
        loop {
            if session.started.elapsed().as_secs_f32() > session.total - 2.0 {
                let ms = session.started.elapsed().as_millis() as u64;
                return match take() {
                    Some(mut a) => a.consent_finish(&mut session, Some(Gesture::Timeout), Outcome::NoFace { elapsed_ms: ms }),
                    None => Outcome::ConsentDenied { reason: "no answer".into(), elapsed_ms: ms },
                };
            }
            let answer = ANSWERS.lock().ok().and_then(|mut m| m.remove(user));
            if let Some(ans) = answer {
                if matches!(ans, crate::consent::Answer::Gone) {
                    log::info!("consent: the requester went away while the session was locked; window closed");
                    return Outcome::ConsentDenied { reason: "requester gone".into(), elapsed_ms: session.started.elapsed().as_millis() as u64 };
                }
                let g = match ans {
                    Answer::Password(pw) => Gesture::Password(pw),
                    Answer::Dismiss => Gesture::Dismissed,
                    Answer::Gone => Gesture::Gone,
                };
                let ms = session.started.elapsed().as_millis() as u64;
                loop {
                    if let Some(mut a) = take() {
                        return a.consent_finish(&mut session, Some(g), Outcome::NoFace { elapsed_ms: ms });
                    }
                }
            }
            let mut back = match take() {
                Some(a) => a.last_match.get(user).map(|m| *m > lock_time).unwrap_or(false),
                None => false,
            };
            if !back && last_lock_check.elapsed() > Duration::from_secs(2) {
                last_lock_check = Instant::now();
                back = !crate::consent::session_locked(user);
            }
            if back {
                log::info!("consent: user back after the lock; the request resumes");
                if let Some(mut a) = take() {
                    a.session_locked_at = None;
                }
                session.locked_at = None;
                let _ = session.dialog.show("scanning", "Welcome back. Look at the camera.", &session.caller, session.total);
                break;
            }
            if gone() {
                log::info!("consent: the requester went away while the session was locked; window closed");
                return Outcome::ConsentDenied { reason: "requester gone".into(), elapsed_ms: session.started.elapsed().as_millis() as u64 };
            }
            std::thread::sleep(Duration::from_millis(300));
        }
    }
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
    send(socket, serde_json::json!({ "user": user, "probe": probe }), Some(timeout))
}

pub fn consent_answer(socket: &Path, user: &str, password: Option<&str>, dismiss: bool, token: Option<&str>) -> Result<Outcome> {
    let body = match password {
        Some(pw) => serde_json::json!({ "user": user, "consent_password": pw, "consent_token": token }),
        None => serde_json::json!({ "user": user, "consent_dismiss": dismiss, "consent_token": token }),
    };
    send(socket, body, Some(Duration::from_secs(3)))
}

/// From the polkit agent: what the request it is about to serve is.
pub fn consent_context(socket: &Path, user: &str, action: &str, message: &str, cookie: &str) -> Result<Outcome> {
    send(socket, serde_json::json!({ "user": user, "context_action": action, "context_message": message, "context_cookie": cookie }), Some(Duration::from_secs(3)))
}

/// A consent request: the reply comes when the user answers the window, or
/// never (the daemon ends it only if this socket hangs up). No deadline.
pub fn ask_consent(socket: &Path, user: &str) -> Result<Outcome> {
    send(socket, serde_json::json!({ "user": user, "consent": true }), None)
}

pub fn ping(socket: &Path, user: &str) -> Result<Outcome> {
    send(socket, serde_json::json!({ "user": user, "ping": true }), Some(Duration::from_secs(3)))
}

pub fn enroll(socket: &Path, user: &str, label: &str, seconds: f32, count: usize) -> Result<Outcome> {
    send(socket, serde_json::json!({ "user": user, "enroll": label, "seconds": seconds, "count": count }), Some(Duration::from_secs_f32(seconds + 15.0)))
}

pub fn delete_templates(socket: &Path, user: &str) -> Result<Outcome> {
    send(socket, serde_json::json!({ "user": user, "delete_templates": true }), Some(Duration::from_secs(3)))
}

pub fn send(socket: &Path, body: serde_json::Value, timeout: Option<Duration>) -> Result<Outcome> {
    let mut stream = UnixStream::connect(socket).with_context(|| format!("connect {}", socket.display()))?;
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let req = body.to_string() + "\n";
    stream.write_all(req.as_bytes())?;
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line)?;
    Ok(serde_json::from_str(line.trim()).context("parse reply")?)
}
