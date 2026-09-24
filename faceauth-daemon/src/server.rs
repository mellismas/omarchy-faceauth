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

use crate::auth::{consent_denied, Authenticator, Outcome, Refusal};
use anyhow::{bail, Context, Result};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use serde::Deserialize;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

/// Longest request line accepted, before any authorisation.
const MAX_REQUEST: u64 = 4096;
/// Connections handled at once; the rest are refused immediately.
const MAX_CONNECTIONS: usize = 8;
/// How often the idle thread looks, and how long the recognition model may sit
/// unused before it is released.
const MODEL_IDLE_TICK: Duration = Duration::from_secs(60);
const MODEL_IDLE_RELEASE: Duration = Duration::from_secs(600);
/// How long a request waits for the camera before answering "busy".
const BUSY_WAIT: Duration = Duration::from_millis(1500);
static ACTIVE: AtomicUsize = AtomicUsize::new(0);
/// Who has templates, kept beside the socket ACL: set at start and again
/// after every enrolment and deletion, the same moments the ACL changes.
/// The bar widget's presence poll reads it instead of the store, so a poll
/// never waits on the authenticator while an enrolment walk-through or a
/// consent request holds it. Parked polls each kept a connection slot for
/// as long as the session ran, and after eight the window's own Continue,
/// Redo and Cancel were answered "busy" (C5).
static ENROLLED: RwLock<Vec<String>> = RwLock::new(Vec::new());
/// After the user says no (a shake, a dismissal, a confirm that refused)
/// the no stands for a while, per user, whoever asks: sudo retries a failed
/// authentication three times from the same process, polkit asks again
/// through a fresh helper, and a program can run either again at once. A
/// request in that time is refused without a window, so a refusal cannot
/// be worn down by asking until a tired nod gets through (A5).
static REFUSALS: Mutex<Vec<(u32, Backoff)>> = Mutex::new(Vec::new());

/// The first refusal stands this long; each refusal that follows within
/// `BACKOFF_QUIET` of the last doubles it, up to `BACKOFF_MAX_DOUBLINGS`.
const BACKOFF: Duration = Duration::from_secs(60);
const BACKOFF_MAX_DOUBLINGS: u32 = 3;
const BACKOFF_QUIET: Duration = Duration::from_secs(600);

/// One user's standing refusal.
#[derive(Clone, Copy, Debug, Default)]
struct Backoff {
    until: Option<Instant>,
    /// When the last no was said.
    last: Option<Instant>,
    /// Doublings earned by repeated refusals.
    level: u32,
    /// The user has been told once for this spell.
    notified: bool,
}

impl Backoff {
    /// The user said no now: how long requests are refused for.
    fn refuse(&mut self, now: Instant) -> Duration {
        let repeat = self
            .last
            .is_some_and(|l| now.duration_since(l) < BACKOFF_QUIET);
        self.level = if repeat {
            (self.level + 1).min(BACKOFF_MAX_DOUBLINGS)
        } else {
            0
        };
        let length = BACKOFF * 2u32.pow(self.level);
        self.until = Some(now + length);
        self.last = Some(now);
        self.notified = false;
        length
    }

    /// How much longer the refusal stands, if it does.
    fn standing(&self, now: Instant) -> Option<Duration> {
        self.until
            .filter(|u| *u > now)
            .map(|u| u.saturating_duration_since(now))
    }
}

/// The refusal standing for this uid now, and whether this is the first
/// request refused by it (the one that gets a notice).
fn refusal_standing(uid: u32, now: Instant) -> Option<(Duration, bool)> {
    let mut r = REFUSALS.lock().ok()?;
    r.retain(|(_, b)| {
        b.until.is_some_and(|u| u > now)
            || b.last
                .is_some_and(|l| now.duration_since(l) < BACKOFF_QUIET)
    });
    let (_, b) = r.iter_mut().find(|(u, _)| *u == uid)?;
    let left = b.standing(now)?;
    let first = !std::mem::replace(&mut b.notified, true);
    Some((left, first))
}

/// The user said no to a request of this uid's: start or lengthen the
/// standing refusal.
fn refused(uid: u32, now: Instant) -> Duration {
    let Ok(mut r) = REFUSALS.lock() else {
        return Duration::ZERO;
    };
    if let Some((_, b)) = r.iter_mut().find(|(u, _)| *u == uid) {
        return b.refuse(now);
    }
    let mut b = Backoff::default();
    let d = b.refuse(now);
    r.push((uid, b));
    d
}

/// Was this the user saying no? A shake, a dismissal or a refused confirm;
/// not a timeout, a wrong password or a request that fell through.
fn is_explicit_no(o: &Outcome) -> bool {
    match o {
        Outcome::Refused { reason, .. } | Outcome::ConsentDenied { reason, .. } => {
            Refusal::parse(reason).is_some_and(|r| r.is_explicit_no())
        }
        _ => false,
    }
}
/// The daemon's config, for the presence query answered while the
/// authenticator is busy with another request (its mutex is held for a
/// whole consent round).
static CFG: std::sync::OnceLock<crate::config::Config> = std::sync::OnceLock::new();

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

/// The setfacl spec for the socket: root through the owner and group
/// entries, one read-write entry per listed uid, nothing for anyone else.
/// Pure, so the tests can check who a given list admits.
fn acl_spec(uids: &[u32]) -> String {
    let mut spec = String::from("u::rw,g::rw,o::-");
    for uid in uids {
        spec.push_str(&format!(",u:{}:rw", uid));
    }
    spec
}

/// Who may connect: root, the enrolled users, and the user whose enrolment
/// walk-through is running, by ACL on the socket (mode 0660 plus a
/// read-write entry per uid). Any other account is refused by the kernel
/// before a byte is read. No group, so no re-login at setup: the
/// walk-through grants its own user for its duration (the window and its
/// control calls run as that user, who has no template yet), a finished
/// enrolment keeps the grant, and the refresh after any other outcome or
/// a deletion revokes it.
pub fn apply_socket_acl(socket: &Path, users: &[String]) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660)) {
        log::warn!("socket mode: {}", e);
        return;
    }
    let uids: Vec<u32> = users.iter().filter_map(|u| user_uid(u)).collect();
    let spec = acl_spec(&uids);
    match std::process::Command::new("/usr/bin/setfacl")
        .arg("--set")
        .arg(&spec)
        .arg(socket)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
    {
        Ok(o) if o.status.success() => log::info!(
            "socket open to root and {} user(s): {}",
            users.len(),
            users.join(" ")
        ),
        Ok(o) => log::warn!(
            "setfacl: {} {}; socket stays root-only",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => log::warn!("setfacl: {}; socket stays root-only", e),
    }
}

fn refresh_socket_acl(auth: &Mutex<Authenticator>) {
    if let Ok(a) = auth.lock() {
        let users = a.store.enrolled_users();
        apply_socket_acl(Path::new(crate::config::SOCKET), &users);
        set_enrolled(users);
    }
}

fn set_enrolled(users: Vec<String>) {
    match ENROLLED.write() {
        Ok(mut e) => *e = users,
        Err(p) => *p.into_inner() = users,
    }
}

/// Is `user` enrolled, by the list kept at the last enrolment or deletion?
/// No lock but the list's own, so it answers at once during a walk-through.
fn is_enrolled(user: &str) -> bool {
    match ENROLLED.read() {
        Ok(e) => e.iter().any(|u| u == user),
        Err(p) => p.into_inner().iter().any(|u| u == user),
    }
}

pub fn serve(auth: Arc<Mutex<Authenticator>>, socket: &Path) -> Result<()> {
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let _ = std::fs::remove_file(socket);
    let listener =
        UnixListener::bind(socket).with_context(|| format!("bind {}", socket.display()))?;
    // World-connectable; the peer-credential check below is the access control.
    {
        let users = auth
            .lock()
            .map(|a| a.store.enrolled_users())
            .unwrap_or_default();
        apply_socket_acl(socket, &users);
        set_enrolled(users);
    }
    if let Ok(a) = auth.lock() {
        let _ = CFG.set(a.cfg.clone());
    }
    // The recognition model is the daemon's one large allocation, about
    // 250 MB resident. After ten minutes without an embed it is dropped and
    // the pages handed back; the next attempt reloads it in under half a
    // second. The presence watch keeps it warm by using it, so a watched
    // user never pays the reload, and try_lock keeps this off any request's
    // critical path.
    {
        let auth = Arc::clone(&auth);
        std::thread::Builder::new()
            .name("model-idle".into())
            .spawn(move || loop {
                std::thread::sleep(MODEL_IDLE_TICK);
                if let Ok(mut a) = auth.try_lock() {
                    if a.pipeline.embedder.is_loaded()
                        && a.pipeline.embedder.idle_for() > MODEL_IDLE_RELEASE
                    {
                        a.pipeline.embedder.release();
                    }
                }
            })
            .context("spawn the model idle thread")?;
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
            let _ = reply(
                &mut s,
                &Outcome::Error {
                    message: "busy".into(),
                },
            );
            continue;
        }
        let auth = Arc::clone(&auth);
        // The slot is given back on every exit, a panic's unwind included:
        // a handler that dies must not hold a slot for the daemon's life.
        // A consent request gives it back early, once admitted (see handle).
        let slot = Slot::new();
        let spawned = std::thread::Builder::new()
            .name("request".into())
            .spawn(move || {
                if let Err(e) = handle(stream, &auth, &slot) {
                    log::warn!("connection: {}", e);
                }
            });
        if let Err(e) = spawned {
            // The thread was not started, so the slot moved nowhere and was
            // dropped with the closure; the peer is told, not left hanging.
            log::warn!("cannot start a request thread: {}", e);
        }
    }
    Ok(())
}

/// One of the `MAX_CONNECTIONS` places, given back once: on drop, or
/// earlier by `release`. A consent request releases it once admitted: the
/// request lives as long as the user takes to answer, and the places are
/// for the short requests (answers, the window's acknowledgement, probes)
/// that must keep getting through meanwhile (B4).
struct Slot {
    held: std::sync::atomic::AtomicBool,
}

impl Slot {
    fn new() -> Slot {
        Slot {
            held: std::sync::atomic::AtomicBool::new(true),
        }
    }

    fn release(&self) {
        if self.held.swap(false, Ordering::SeqCst) {
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.release();
    }
}

/// The whole request line must arrive within this, however slowly its
/// bytes come: a peer feeding one byte per read timeout would otherwise
/// hold a connection slot for as long as it liked.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// Read one line of at most `MAX_REQUEST` bytes within `REQUEST_DEADLINE`.
fn read_request(stream: &mut UnixStream) -> Result<Option<String>> {
    use std::io::Read;
    let start = Instant::now();
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let left = REQUEST_DEADLINE.saturating_sub(start.elapsed());
        if left.is_zero() {
            return Ok(None);
        }
        stream.set_read_timeout(Some(left))?;
        match stream.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
                }
                if buf.len() as u64 >= MAX_REQUEST {
                    return Ok(None);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None)
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

fn handle(mut stream: UnixStream, auth: &Mutex<Authenticator>, slot: &Slot) -> Result<()> {
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
    let allowed = cred.uid() == 0
        || user_uid(&req.user)
            .map(|u| u == cred.uid())
            .unwrap_or(false);
    if !allowed {
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
        let outcome = match take() {
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
            Some(mut a) => a.probe(),
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

/// May this peer ask for a plain look (a match with no window and no
/// nod)? Only a caller running as the user: a root peer is an elevation
/// stack, and an elevation needs consent.
fn admit_plain_look(peer_uid: u32) -> std::result::Result<(), &'static str> {
    if peer_uid == 0 {
        Err("a root caller needs consent")
    } else {
        Ok(())
    }
}

/// Whether every lid the firmware reports is closed, read the way
/// `omarchy-hw-laptop-closed` reads it. No lid at all (a desktop) is open.
fn lid_closed() -> bool {
    lid_closed_in(std::path::Path::new("/proc/acpi/button/lid"))
}

fn lid_closed_in(dir: &std::path::Path) -> bool {
    let Ok(lids) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut seen = false;
    for lid in lids.flatten() {
        let Ok(state) = std::fs::read_to_string(lid.path().join("state")) else {
            continue;
        };
        seen = true;
        if !state.contains("closed") {
            return false;
        }
    }
    seen
}

/// Is the peer this very process? Its own PAM stack, if a face line is on
/// it, connects back with the daemon's pid (B6).
fn is_own_pid(peer_pid: i32, own: u32) -> bool {
    peer_pid == own as i32
}

/// May `peer_uid`, asking about `user`, switch the watch on `watched` to
/// `mode`? Only the watched user, for their own watch, while one runs.
/// `"query"` asks without switching: Ok(None), allowed for any user asking
/// about themselves (the uid check above the call already holds).
fn presence_mode_change(
    peer_uid: u32,
    user: &str,
    watched: &crate::presence::PresenceConfig,
    mode: &str,
) -> std::result::Result<Option<crate::presence::PresenceMode>, String> {
    if mode == "query" {
        return Ok(None);
    }
    let Some(m) = crate::presence::PresenceMode::parse(mode) else {
        return Err(format!(
            "unknown presence mode {:?}; \"default\", \"secure\" or \"query\"",
            mode
        ));
    };
    if !watched.enabled || watched.user.is_empty() {
        return Err("the presence watch is off".into());
    }
    if user != watched.user || user_uid(&watched.user) != Some(peer_uid) {
        return Err("only the watched user may set the presence mode".into());
    }
    Ok(Some(m))
}

/// Answer a presence mode request (a read, or a switch) from `peer_uid`.
/// Everything it needs is in the statics: the config, the mode in force and
/// the enrolled list. It takes no authenticator on purpose, so the bar
/// widget's poll is answered in microseconds however long the camera is
/// held, and its connection slot is back at once (C5).
fn presence_query(peer_uid: u32, peer_pid: i32, user: &str, mode: &str) -> Outcome {
    let watched = CFG.get().map(|c| c.presence.clone()).unwrap_or_default();
    // "Watching" is what the bar widget and the key binding show up for,
    // so it also needs the user enrolled: a watch configured for a user
    // with no templates never locks for them and offers nothing to switch.
    let enrolled = is_enrolled(user);
    match presence_mode_change(peer_uid, user, &watched, mode) {
        Ok(Some(_)) if !enrolled => Outcome::Error {
            message: format!("{} is not enrolled", user),
        },
        Ok(Some(m)) => {
            crate::presence::set_presence_mode(m);
            log::info!(
                "presence: mode set to {} by uid {} pid {}",
                m.name(),
                peer_uid,
                peer_pid
            );
            presence_state(&watched, user, enrolled)
        }
        Ok(None) => presence_state(&watched, user, enrolled),
        Err(why) => {
            log::warn!(
                "presence mode request from uid {} for {} refused: {}",
                peer_uid,
                user,
                why
            );
            Outcome::Error { message: why }
        }
    }
}

/// The state a presence mode request answers with: the mode in force,
/// whether the daemon's watch is on for `user`, and if it is, what the
/// watch last decided. The decision goes only with `watching`, so it
/// reaches root and the watched user and nobody else (H16).
fn presence_state(
    watched: &crate::presence::PresenceConfig,
    user: &str,
    enrolled: bool,
) -> Outcome {
    let watching = watched.enabled && watched.user == user && enrolled;
    let last = if watching {
        crate::presence::snapshot()
    } else {
        None
    };
    Outcome::PresenceMode {
        mode: crate::presence::presence_mode().name().into(),
        watching,
        state: last.map(|s| s.state),
        away_for: last.and_then(|s| s.away_for),
    }
}

/// Where a request comes from, as far as the daemon can prove it.
pub enum Locality {
    /// Local; for polkit's helper, with the agent that connected it.
    Local(Option<crate::consent::AgentPeer>),
    Remote(String),
}

/// A positive, fail-closed check: a caller is local when the daemon can show
/// it is, and remote otherwise (any read error, timeout or unfamiliar shape).
///
/// 1. Any `sshd` or `sshd-session` in the parent chain: remote.
/// 2. Root in `/system.slice/`: only polkit's authentication helper is
///    followed, and no other root service is local. On polkit 127 the helper
///    is socket-activated per connection, and systemd names the instance
///    after the peer that connected it (`<n>-<cookie>-<pid>_<pidfd id>-<uid>`,
///    from SO_PEERCRED and the peer's pidfs inode): the agent that is serving
///    the request. The check moves to that agent, pinned by its pidfd id, and
///    the answer is the agent's. Omarchy's shell is in the user's session;
///    `pkexec` from an SSH shell, which registers its own text agent, is
///    under `sshd-session` and refused. The helper itself is never local.
/// 3. In a logind session scope (`session-N.scope`): local only if logind
///    says that session is the target user's, not remote, and on a seat.
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
    match locality_inner(&LiveProcs, pid, target_user) {
        Ok(Locality::Local(agent)) => match pidfd {
            // The /proc reads above were of a live process only if it is
            // still the same process now; without a pidfd to prove that,
            // a reused pid could have been laundered into local.
            None => Locality::Remote("no peer pidfd to pin the caller".into()),
            Some(fd) if process_exited(fd) => {
                Locality::Remote("caller exited before it could be verified".into())
            }
            Some(_) => Locality::Local(agent),
        },
        Ok(l) => l,
        Err(e) => Locality::Remote(format!("cannot verify the caller: {}", e)),
    }
}

/// What the locality check reads: /proc and logind for the daemon, a table
/// for the tests.
pub(crate) trait ProcView {
    fn ppid(&self, pid: i32) -> Option<i32>;
    fn comm(&self, pid: i32) -> String;
    fn real_uid(&self, pid: i32) -> Option<u32>;
    /// The cgroup listing as `/proc/<pid>/cgroup` prints it.
    fn cgroup(&self, pid: i32) -> Option<String>;
    /// The pidfs inode of a live process (what systemd writes into a
    /// socket-activated instance name); None when the process is gone.
    fn pidfd_id(&self, pid: i32) -> Option<u64>;
    fn user_uid(&self, name: &str) -> Option<u32>;
    /// logind's session ids for a uid, whitespace separated.
    fn user_sessions(&self, uid: u32) -> Result<String>;
    /// logind's view of a session: (uid, remote, seat, class).
    fn session(&self, id: &str) -> Result<(Option<u32>, bool, String, String)>;
    /// logind's Type and Active for a session ("wayland", true).
    fn session_kind(&self, id: &str) -> Result<(String, bool)>;
}

/// Does the user have a graphical session that is in the foreground on its
/// seat right now? That is where the window goes; anywhere else it cannot
/// be seen or nodded at.
fn active_graphical_session(v: &dyn ProcView, uid: u32) -> bool {
    let Ok(sessions) = v.user_sessions(uid) else {
        return false;
    };
    for id in sessions.split_whitespace() {
        if let Ok((kind, active)) = v.session_kind(id) {
            if active && (kind == "wayland" || kind == "x11") {
                return true;
            }
        }
    }
    false
}

struct LiveProcs;

/// A pidfd for a live process, or None when it is gone.
fn pidfd_open(pid: i32) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if raw < 0 {
        return None;
    }
    Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as i32) })
}

impl ProcView for LiveProcs {
    fn ppid(&self, pid: i32) -> Option<i32> {
        crate::consent::ppid_of(pid)
    }
    fn comm(&self, pid: i32) -> String {
        crate::consent::comm_of(pid)
    }
    fn real_uid(&self, pid: i32) -> Option<u32> {
        crate::consent::real_uid_of(pid)
    }
    fn cgroup(&self, pid: i32) -> Option<String> {
        crate::consent::read_proc(pid, "cgroup")
    }
    fn pidfd_id(&self, pid: i32) -> Option<u64> {
        nix::sys::stat::fstat(&pidfd_open(pid)?)
            .ok()
            .map(|st| st.st_ino)
    }
    fn user_uid(&self, name: &str) -> Option<u32> {
        user_uid(name)
    }
    fn user_sessions(&self, uid: u32) -> Result<String> {
        loginctl(&["show-user", &uid.to_string(), "-p", "Sessions", "--value"])
    }
    fn session(&self, id: &str) -> Result<(Option<u32>, bool, String, String)> {
        let out = loginctl(&[
            "show-session",
            id,
            "-p",
            "User",
            "-p",
            "Remote",
            "-p",
            "Seat",
            "-p",
            "Class",
        ])?;
        let get = |k: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
                .unwrap_or("")
                .trim()
                .to_string()
        };
        Ok((
            get("User").parse().ok(),
            get("Remote") != "no",
            get("Seat"),
            get("Class"),
        ))
    }
    fn session_kind(&self, id: &str) -> Result<(String, bool)> {
        let out = loginctl(&["show-session", id, "-p", "Type", "-p", "Active"])?;
        let get = |k: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
                .unwrap_or("")
                .trim()
                .to_string()
        };
        Ok((get("Type"), get("Active") == "yes"))
    }
}

fn locality_inner(v: &dyn ProcView, pid: i32, target_user: &str) -> Result<Locality> {
    locality_of(v, pid, target_user, false)
}

fn locality_of(
    v: &dyn ProcView,
    pid: i32,
    target_user: &str,
    via_helper: bool,
) -> Result<Locality> {
    // 1. Ancestry. The chain must reach init; a break means the caller (or a
    // parent) vanished mid-read, which is not a demonstration of anything.
    let mut p = pid;
    let mut reached_init = false;
    for _ in 0..128 {
        let pp = v
            .ppid(p)
            .ok_or_else(|| anyhow::anyhow!("process {} unreadable", p))?;
        if pp <= 1 {
            reached_init = true;
            break;
        }
        let comm = v.comm(pp);
        if is_ssh_comm(&comm) {
            return Ok(Locality::Remote(format!(
                "started under {} (pid {})",
                comm, pp
            )));
        }
        p = pp;
    }
    if !reached_init {
        // A chain deeper than any real desktop's is not something this
        // check has looked all the way through; it does not vouch for it.
        return Ok(Locality::Remote(
            "ancestry deeper than 128 without reaching init".into(),
        ));
    }
    let real_uid = v
        .real_uid(pid)
        .ok_or_else(|| anyhow::anyhow!("no uid for process {}", pid))?;
    let cgroup = v
        .cgroup(pid)
        .ok_or_else(|| anyhow::anyhow!("no cgroup for process {}", pid))?;
    let path = cgroup
        .lines()
        .find_map(|l| l.splitn(3, ':').nth(2))
        .ok_or_else(|| anyhow::anyhow!("no cgroup path"))?
        .to_string();
    let target_uid = v
        .user_uid(target_user)
        .ok_or_else(|| anyhow::anyhow!("unknown user {}", target_user))?;
    // 2. Root's services: only polkit's helper, and only through to the
    // agent that connected it.
    if real_uid == 0 && path.starts_with("/system.slice/") {
        let unit = path.trim().rsplit('/').next().unwrap_or("").to_string();
        let Some(instance) = polkit_helper_instance(&unit) else {
            return Ok(Locality::Remote(format!(
                "root service {} is not a session",
                unit
            )));
        };
        if via_helper {
            return Ok(Locality::Remote(
                "a polkit helper connected by another polkit helper".into(),
            ));
        }
        let Some((agent, id)) = helper_peer(instance) else {
            return Ok(Locality::Remote(format!(
                "polkit helper instance {} does not name its agent",
                instance
            )));
        };
        let Some(id) = id else {
            return Ok(Locality::Remote(format!(
                "polkit helper instance {} carries no pidfd id to pin its agent",
                instance
            )));
        };
        if v.pidfd_id(agent) != Some(id) {
            return Ok(Locality::Remote(format!(
                "the agent (pid {}) that connected polkit helper {} is gone",
                agent, instance
            )));
        }
        log::debug!(
            "locality: polkit helper {} was connected by agent pid {}; checking the agent",
            instance,
            agent
        );
        return match locality_of(v, agent, target_user, true)? {
            Locality::Local(_) => Ok(Locality::Local(Some(crate::consent::AgentPeer {
                pid: agent,
                id,
            }))),
            Locality::Remote(why) => Ok(Locality::Remote(format!(
                "polkit agent pid {}: {}",
                agent, why
            ))),
        };
    }
    // 3. A logind session of its own, which must be the target user's.
    if let Some(id) = session_id_from_cgroup(&cgroup) {
        let (uid, remote, seat, class) = v.session(&id)?;
        if uid != Some(target_uid) {
            return Ok(Locality::Remote(format!(
                "logind session {} is not {}'s",
                id, target_user
            )));
        }
        return Ok(match !remote && !seat.is_empty() && class == "user" {
            true => Locality::Local(None),
            false => Locality::Remote(format!("logind session {} is remote or seatless", id)),
        });
    }
    // 4. The target user's manager.
    if path.starts_with(&format!(
        "/user.slice/user-{}.slice/user@{}.service/",
        target_uid, target_uid
    )) {
        let sessions = v.user_sessions(target_uid)?;
        for id in sessions.split_whitespace() {
            match v.session(id) {
                Ok((_, remote, seat, class)) if !remote && !seat.is_empty() && class == "user" => {
                    return Ok(Locality::Local(None))
                }
                Ok(_) => {}
                // A session in the list that logind no longer knows: the
                // daemon's own `systemd-run --machine` calls (a notice, the
                // window) each open a session for an instant, and a request
                // arriving in that instant (sudo's retry) lists it. It says
                // nothing about the caller; the other sessions do.
                Err(e) if e.to_string().contains("known") => {
                    log::debug!("locality: session {} vanished while checking: {}", id, e)
                }
                Err(e) => return Err(e),
            }
        }
        return Ok(Locality::Remote(format!(
            "{} has no local session on a seat",
            target_user
        )));
    }
    Ok(Locality::Remote(format!(
        "caller in {} is not a session of {}",
        path.trim(),
        target_user
    )))
}

/// The instance of a `polkit-agent-helper@<instance>.service` unit name.
fn polkit_helper_instance(unit: &str) -> Option<&str> {
    unit.strip_prefix("polkit-agent-helper@")?
        .strip_suffix(".service")
        .filter(|i| !i.is_empty())
}

/// The peer systemd wrote into a socket-activated instance name,
/// `<n>-<cookie>-<pid>_<pidfd id>-<uid>` (or `<n>-<cookie>-<pid>-<uid>` from
/// a systemd without pidfd ids): the pid and the id. Anything else is None.
fn helper_peer(instance: &str) -> Option<(i32, Option<u64>)> {
    let parts: Vec<&str> = instance.split('-').collect();
    if parts.len() != 4 || !parts.iter().all(|p| !p.is_empty()) {
        return None;
    }
    parts[0].parse::<u64>().ok()?;
    parts[1].parse::<u64>().ok()?;
    parts[3].parse::<u32>().ok()?;
    match parts[2].split_once('_') {
        Some((pid, id)) => Some((pid.parse().ok()?, Some(id.parse().ok()?))),
        None => Some((parts[2].parse().ok()?, None)),
    }
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
        bail!(
            "loginctl {}: {} {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
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
/// `session-c1.scope`), if the process is directly in one. Only the
/// canonical position counts: `/user.slice/user-<uid>.slice/session-<id>.scope`
/// and nothing below it. The user's own manager (`user@<uid>.service`) is
/// delegated, so a component of that name anywhere under it is the user's
/// to create; it names nothing (F8).
fn session_id_from_cgroup(cgroup: &str) -> Option<String> {
    let path = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    let parts: Vec<&str> = path.split('/').collect();
    let ["", "user.slice", slice, scope] = parts.as_slice() else {
        return None;
    };
    let uid = slice.strip_prefix("user-")?.strip_suffix(".slice")?;
    if uid.is_empty() || !uid.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let id = scope.strip_prefix("session-")?.strip_suffix(".scope")?;
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(id.to_string())
}

#[cfg(test)]
mod root_tests {
    use super::user_uid;

    #[test]
    fn root_resolves_to_uid_zero_so_the_gate_can_refuse_it() {
        assert_eq!(user_uid("root"), Some(0));
        assert_eq!(user_uid("no-such-user-faceauth-test"), None);
    }
}

#[cfg(test)]
mod socket_acl_tests {
    use super::acl_spec;

    /// The list a walk-through applies is the template-only list plus the
    /// session user, so a first-time user can connect the window and press
    /// Continue; the list applied afterwards is built from the templates
    /// alone, so a failed session leaves that user with no entry.
    #[test]
    fn a_session_admits_its_user_and_the_template_list_after_a_failure_does_not() {
        let enrolled = [1000u32, 1001];
        let session_uid = 1002u32;
        let mut session = enrolled.to_vec();
        session.push(session_uid);
        let spec = acl_spec(&session);
        assert!(spec.contains(",u:1002:rw"), "session spec: {}", spec);
        assert!(spec.contains(",u:1000:rw") && spec.contains(",u:1001:rw"));
        let after_failure = acl_spec(&enrolled);
        assert!(
            !after_failure.contains("1002"),
            "after failure: {}",
            after_failure
        );
        assert!(after_failure.contains(",u:1000:rw") && after_failure.contains(",u:1001:rw"));
    }

    /// Root keeps access through the owner and group entries; nobody else
    /// gets in on an empty list.
    #[test]
    fn an_empty_list_is_root_only() {
        assert_eq!(acl_spec(&[]), "u::rw,g::rw,o::-");
    }
}

#[cfg(test)]
mod plain_look_tests {
    use super::*;

    /// A3: a plain look is admitted from a caller running as the user (the
    /// lock screen) and refused from root (an elevation stack whose face
    /// line lacks `consent`).
    #[test]
    fn a_root_peer_gets_no_plain_look() {
        assert_eq!(admit_plain_look(0), Err("a root caller needs consent"));
        assert_eq!(admit_plain_look(1000), Ok(()));
    }

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

#[cfg(test)]
mod backoff_tests {
    use super::*;

    /// A5: after the user says no, requests are refused without a window
    /// for a minute, whoever asks; repeats double it, up to a bound, and a
    /// quiet spell forgets the doubling.
    #[test]
    fn a_refusal_stands_for_a_minute_and_repeats_double_it() {
        let base = Instant::now();
        let t = |secs: u64| base + Duration::from_secs(secs);
        let mut b = Backoff::default();
        assert_eq!(b.standing(t(0)), None);
        assert_eq!(b.refuse(t(0)), Duration::from_secs(60));
        assert_eq!(
            b.standing(t(10)),
            Some(Duration::from_secs(50)),
            "a second requester, another pid, gets no window"
        );
        assert_eq!(b.standing(t(61)), None);
        assert_eq!(b.refuse(t(70)), Duration::from_secs(120));
        assert_eq!(b.refuse(t(200)), Duration::from_secs(240));
        assert_eq!(b.refuse(t(500)), Duration::from_secs(480));
        assert_eq!(
            b.refuse(t(1000)),
            Duration::from_secs(480),
            "the doubling is capped"
        );
        assert_eq!(
            b.refuse(t(1000 + 601)),
            Duration::from_secs(60),
            "ten quiet minutes forget the escalation"
        );
    }

    /// The per-uid table: one notice per spell, and only the user's own
    /// explicit no starts one.
    #[test]
    fn the_table_notifies_once_per_spell_and_reads_only_an_explicit_no() {
        let uid = 4_000_000_001u32;
        let now = Instant::now();
        assert!(refusal_standing(uid, now).is_none());
        refused(uid, now);
        assert_eq!(
            refusal_standing(uid, now).map(|(_, first)| first),
            Some(true)
        );
        assert_eq!(
            refusal_standing(uid, now).map(|(_, first)| first),
            Some(false)
        );
        assert!(
            refusal_standing(uid + 1, now).is_none(),
            "another user is not refused"
        );
        assert!(refusal_standing(uid, now + Duration::from_secs(61)).is_none());
        for (o, no) in [
            (
                Outcome::ConsentDenied {
                    reason: "shaken".into(),
                    elapsed_ms: 0,
                },
                true,
            ),
            (
                Outcome::Refused {
                    reason: "dismissed".into(),
                    elapsed_ms: 0,
                },
                true,
            ),
            (
                Outcome::ConsentDenied {
                    reason: "confirm: not live".into(),
                    elapsed_ms: 0,
                },
                true,
            ),
            (
                Outcome::ConsentDenied {
                    reason: "no answer".into(),
                    elapsed_ms: 0,
                },
                false,
            ),
            (
                Outcome::ConsentDenied {
                    reason: "wrong password".into(),
                    elapsed_ms: 0,
                },
                false,
            ),
            (
                Outcome::ConsentDenied {
                    reason: "refused a moment ago".into(),
                    elapsed_ms: 0,
                },
                false,
            ),
            (
                Outcome::Match {
                    score: None,
                    frames: 1,
                    elapsed_ms: 0,
                },
                false,
            ),
        ] {
            assert_eq!(is_explicit_no(&o), no, "{:?}", o);
        }
        if let Ok(mut r) = REFUSALS.lock() {
            r.retain(|(u, _)| *u != uid);
        }
    }
}

#[cfg(test)]
mod request_read_tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn a_whole_line_is_read() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(b"{\"user\":\"x\"}\n").unwrap();
        assert_eq!(
            read_request(&mut b).unwrap().as_deref(),
            Some("{\"user\":\"x\"}\n")
        );
    }

    #[test]
    fn a_line_over_the_limit_or_without_a_newline_is_refused() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&vec![b'x'; MAX_REQUEST as usize + 10]).unwrap();
        assert_eq!(read_request(&mut b).unwrap(), None);
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(b"no newline").unwrap();
        drop(a);
        assert_eq!(read_request(&mut b).unwrap(), None);
    }

    /// The deadline is for the whole line: bytes that keep arriving do not
    /// keep resetting it.
    #[test]
    fn dribbled_bytes_do_not_stretch_the_deadline() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            for _ in 0..40 {
                if a.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        });
        let start = Instant::now();
        assert_eq!(read_request(&mut b).unwrap(), None);
        let took = start.elapsed();
        assert!(
            took >= REQUEST_DEADLINE - Duration::from_millis(100)
                && took < REQUEST_DEADLINE + Duration::from_secs(1),
            "took {:?}",
            took
        );
        drop(b);
        writer.join().unwrap();
    }
}

#[cfg(test)]
mod lid_tests {
    use super::lid_closed_in;

    struct Lids(std::path::PathBuf);
    impl Lids {
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for Lids {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn lids(states: &[&str]) -> Lids {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("faceauth-lid-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for (i, st) in states.iter().enumerate() {
            let p = d.join(format!("LID{}", i));
            std::fs::create_dir(&p).unwrap();
            std::fs::write(p.join("state"), format!("state:      {}\n", st)).unwrap();
        }
        Lids(d)
    }

    #[test]
    fn a_closed_lid_is_closed() {
        assert!(lid_closed_in(lids(&["closed"]).path()));
    }

    #[test]
    fn an_open_lid_a_missing_lid_and_an_unreadable_one_are_open() {
        assert!(!lid_closed_in(lids(&["open"]).path()));
        assert!(!lid_closed_in(lids(&[]).path()));
        assert!(!lid_closed_in(std::path::Path::new("/nonexistent/lid")));
        let d = lids(&["closed"]);
        std::fs::remove_file(d.path().join("LID0/state")).unwrap();
        assert!(!lid_closed_in(d.path()));
    }

    #[test]
    fn two_lids_are_closed_only_when_both_are() {
        assert!(!lid_closed_in(lids(&["closed", "open"]).path()));
        assert!(lid_closed_in(lids(&["closed", "closed"]).path()));
    }
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
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/user-1000.slice/session-3.scope\n"),
            Some("3".into())
        );
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/user-1000.slice/session-c1.scope"),
            Some("c1".into())
        );
        // The desktop's app scope and systemd-run --user: no logind session of their own.
        assert_eq!(session_id_from_cgroup("0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-graphical.slice/app-Hyprland-xdg\\x2dterminal\\x2dexec-af100da6.scope"), None);
        assert_eq!(session_id_from_cgroup("0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-p193148-i205978.service"), None);
        assert_eq!(
            session_id_from_cgroup("0::/system.slice/faceauth.service"),
            None
        );
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/session-.scope"),
            None
        );
    }

    /// A session-shaped component the user made inside their delegated
    /// manager names no session; only the canonical position does (F8,
    /// poc_authz_2 inverted).
    #[test]
    fn a_forged_session_component_under_the_user_manager_names_nothing() {
        assert_eq!(
            session_id_from_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/session-c1.scope/evil\n"
            ),
            None
        );
        assert_eq!(
            session_id_from_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/session-c1.scope\n"
            ),
            None
        );
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/user-1000.slice/session-3.scope/sub\n"),
            None,
            "nothing below the scope either"
        );
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/session-3.scope\n"),
            None
        );
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/user-x.slice/session-3.scope\n"),
            None
        );
        assert_eq!(
            session_id_from_cgroup("1:name=systemd:/user.slice/user-1000.slice/session-3.scope\n"),
            None,
            "only the unified hierarchy line"
        );
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/user-1000.slice/session-3.scope\n"),
            Some("3".into())
        );
    }

    /// A request from the daemon's own pid is refused whatever it asks (B6).
    #[test]
    fn the_daemon_refuses_its_own_pid() {
        let me = std::process::id();
        assert!(is_own_pid(me as i32, me));
        assert!(!is_own_pid(me as i32 + 1, me));
        assert!(!is_own_pid(1, me));
    }

    /// The presence mode switch is the watched user's alone, for their own
    /// watch, while a watch runs.
    #[test]
    fn only_the_watched_user_switches_the_presence_mode() {
        use crate::presence::{PresenceConfig, PresenceMode};
        let me = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let my_uid = user_uid(&me).unwrap_or(0);
        let watched = PresenceConfig {
            enabled: true,
            user: me.clone(),
            ..Default::default()
        };
        assert_eq!(
            presence_mode_change(my_uid, &me, &watched, "secure"),
            Ok(Some(PresenceMode::Secure))
        );
        assert_eq!(
            presence_mode_change(my_uid, &me, &watched, "default"),
            Ok(Some(PresenceMode::Default))
        );
        assert!(presence_mode_change(my_uid, &me, &watched, "paranoid")
            .unwrap_err()
            .contains("unknown"));
        assert!(presence_mode_change(my_uid + 1, &me, &watched, "secure")
            .unwrap_err()
            .contains("only the watched user"));
        assert!(presence_mode_change(my_uid, "someone-else", &watched, "secure").is_err());
        let off = PresenceConfig {
            enabled: false,
            ..watched.clone()
        };
        assert!(presence_mode_change(my_uid, &me, &off, "secure")
            .unwrap_err()
            .contains("off"));
        // The read form changes nothing and is answered whether or not the
        // watch is on, with `watching` saying which.
        assert_eq!(
            presence_mode_change(my_uid + 1, &me, &off, "query"),
            Ok(None)
        );
        assert!(matches!(
            presence_state(&watched, &me, true),
            Outcome::PresenceMode { watching: true, .. }
        ));
        assert!(matches!(
            presence_state(&off, &me, true),
            Outcome::PresenceMode {
                watching: false,
                ..
            }
        ));
        assert!(matches!(
            presence_state(&watched, "someone-else", true),
            Outcome::PresenceMode {
                watching: false,
                ..
            }
        ));
        // A watch configured for a user with no templates is not "watching":
        // the widget and the binding stay away until enrolment.
        assert!(matches!(
            presence_state(&watched, &me, false),
            Outcome::PresenceMode {
                watching: false,
                ..
            }
        ));
        // The watch's decision rides on the answer only with `watching`,
        // so another user asking about themselves never learns whether
        // the owner is at the desk (H16).
        assert!(matches!(
            presence_state(&watched, "someone-else", true),
            Outcome::PresenceMode {
                state: None,
                away_for: None,
                ..
            }
        ));
        let before_a_tick = presence_state(&watched, &me, true);
        assert!(matches!(
            before_a_tick,
            Outcome::PresenceMode {
                watching: true,
                state: None,
                ..
            }
        ));
        let json = serde_json::to_string(&before_a_tick).unwrap();
        assert!(
            !json.contains("state"),
            "no decision yet, no field: {}",
            json
        );
    }

    /// A process table the check reads instead of /proc and logind.
    struct Table {
        procs: std::collections::HashMap<i32, (i32, &'static str, u32, &'static str, Option<u64>)>,
        sessions: std::collections::HashMap<
            &'static str,
            (Option<u32>, bool, &'static str, &'static str),
        >,
        kinds: std::collections::HashMap<&'static str, (&'static str, bool)>,
        user_sessions: &'static str,
    }
    impl Table {
        fn new() -> Table {
            let mut t = Table {
                procs: Default::default(),
                sessions: Default::default(),
                kinds: Default::default(),
                user_sessions: "3",
            };
            t.kinds.insert("3", ("wayland", true));
            t.kinds.insert("7", ("tty", false));
            t.kinds.insert("9", ("tty", true));
            t.sessions.insert("3", (Some(1000), false, "seat0", "user"));
            t.sessions.insert("7", (Some(1000), true, "", "user"));
            t.sessions.insert("9", (Some(1001), false, "seat0", "user"));
            t.procs
                .insert(1, (0, "systemd", 0, "0::/init.scope\n", Some(1)));
            t
        }
        fn add(
            &mut self,
            pid: i32,
            ppid: i32,
            comm: &'static str,
            uid: u32,
            cgroup: &'static str,
        ) -> &mut Table {
            self.procs
                .insert(pid, (ppid, comm, uid, cgroup, Some(pid as u64 * 10)));
            self
        }
    }
    impl ProcView for Table {
        fn ppid(&self, pid: i32) -> Option<i32> {
            self.procs.get(&pid).map(|p| p.0)
        }
        fn comm(&self, pid: i32) -> String {
            self.procs
                .get(&pid)
                .map(|p| p.1.to_string())
                .unwrap_or_default()
        }
        fn real_uid(&self, pid: i32) -> Option<u32> {
            self.procs.get(&pid).map(|p| p.2)
        }
        fn cgroup(&self, pid: i32) -> Option<String> {
            self.procs.get(&pid).map(|p| p.3.to_string())
        }
        fn pidfd_id(&self, pid: i32) -> Option<u64> {
            self.procs.get(&pid).and_then(|p| p.4)
        }
        fn user_uid(&self, name: &str) -> Option<u32> {
            match name {
                "mike" => Some(1000),
                "other" => Some(1001),
                _ => None,
            }
        }
        fn user_sessions(&self, _uid: u32) -> Result<String> {
            Ok(self.user_sessions.to_string())
        }
        fn session(&self, id: &str) -> Result<(Option<u32>, bool, String, String)> {
            self.sessions
                .get(id)
                .map(|s| (s.0, s.1, s.2.to_string(), s.3.to_string()))
                .ok_or_else(|| anyhow::anyhow!("No session '{}' known", id))
        }
        fn session_kind(&self, id: &str) -> Result<(String, bool)> {
            self.kinds
                .get(id)
                .map(|k| (k.0.to_string(), k.1))
                .ok_or_else(|| anyhow::anyhow!("No session '{}' known", id))
        }
    }

    /// The window can only be answered in a graphical session that is in
    /// the foreground on its seat (B2).
    #[test]
    fn a_window_needs_an_active_graphical_session() {
        let mut t = Table::new();
        assert!(active_graphical_session(&t, 1000));
        // The desktop is on another VT while a text console is in front.
        t.kinds.insert("3", ("wayland", false));
        t.user_sessions = "3 9";
        assert!(!active_graphical_session(&t, 1000));
        // Only a tty session at all.
        t.user_sessions = "9";
        assert!(!active_graphical_session(&t, 1000));
        t.user_sessions = "";
        assert!(!active_graphical_session(&t, 1000));
    }

    const HELPER: &str = "0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@306-8263-500_5000-1000.service\n";
    const SHELL: &str = "0::/user.slice/user-1000.slice/user@1000.service/session.slice/wayland-wm@hyprland.desktop.service\n";
    const SSH: &str = "0::/user.slice/user-1000.slice/session-7.scope\n";

    fn remote(r: Result<Locality>) -> String {
        match r.unwrap() {
            Locality::Remote(why) => why,
            Locality::Local(_) => panic!("expected remote"),
        }
    }

    /// The desktop case: the helper's agent is the shell in the user's session.
    #[test]
    fn a_polkit_helper_is_as_local_as_the_agent_that_connected_it() {
        let mut t = Table::new();
        t.add(500, 1, "quickshell", 1000, SHELL)
            .add(600, 1, "polkit-agent-he", 0, HELPER);
        match locality_inner(&t, 600, "mike").unwrap() {
            Locality::Local(agent) => assert_eq!(
                agent,
                Some(crate::consent::AgentPeer { pid: 500, id: 5000 })
            ),
            Locality::Remote(why) => panic!("{}", why),
        }
    }

    /// pkexec over SSH registers its own text agent inside the SSH session;
    /// the helper it connects must not be local (A1).
    #[test]
    fn a_polkit_helper_connected_from_an_ssh_session_is_remote() {
        let mut t = Table::new();
        t.add(400, 1, "sshd-session", 1000, SSH)
            .add(500, 400, "pkexec", 0, SSH)
            .add(600, 1, "polkit-agent-he", 0, HELPER);
        let why = remote(locality_inner(&t, 600, "mike"));
        assert!(
            why.contains("agent pid 500") && why.contains("sshd-session"),
            "{}",
            why
        );
    }

    /// The agent named by the instance is pinned by its pidfd id: a reused
    /// pid, a gone agent, or an instance without the id is not followed.
    #[test]
    fn a_polkit_helper_whose_agent_cannot_be_pinned_is_remote() {
        let mut t = Table::new();
        t.add(600, 1, "polkit-agent-he", 0, HELPER);
        assert!(remote(locality_inner(&t, 600, "mike")).contains("is gone"));
        t.add(500, 1, "quickshell", 1000, SHELL);
        t.procs.get_mut(&500).unwrap().4 = Some(5001);
        assert!(remote(locality_inner(&t, 600, "mike")).contains("is gone"));
        t.add(601, 1, "polkit-agent-he", 0, "0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@306-8263-500-1000.service\n");
        assert!(remote(locality_inner(&t, 601, "mike")).contains("no pidfd id"));
        t.add(602, 1, "polkit-agent-he", 0, "0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@garbage.service\n");
        assert!(remote(locality_inner(&t, 602, "mike")).contains("does not name its agent"));
    }

    /// Root in system.slice is no longer local on its own.
    #[test]
    fn a_root_service_that_is_not_the_polkit_helper_is_remote() {
        let mut t = Table::new();
        t.add(700, 1, "cron", 0, "0::/system.slice/cronie.service\n");
        assert!(remote(locality_inner(&t, 700, "mike")).contains("not a session"));
    }

    /// A session scope is local only when it is the target user's session.
    #[test]
    fn another_users_seated_session_is_not_local_for_the_target_user() {
        let mut t = Table::new();
        t.add(
            800,
            1,
            "sudo",
            1001,
            "0::/user.slice/user-1001.slice/session-9.scope\n",
        );
        assert!(matches!(
            locality_inner(&t, 800, "other").unwrap(),
            Locality::Local(None)
        ));
        assert!(remote(locality_inner(&t, 800, "mike")).contains("not mike's"));
    }

    #[test]
    fn helper_instance_names_are_parsed_strictly() {
        assert_eq!(
            helper_peer("306-8263-3747358_3757126-1000"),
            Some((3747358, Some(3757126)))
        );
        assert_eq!(helper_peer("23-1-42-0"), Some((42, None)));
        assert_eq!(helper_peer("23"), None);
        assert_eq!(helper_peer("a-b-c-d"), None);
        assert_eq!(helper_peer("306-8263-3747358_x-1000"), None);
        assert_eq!(
            polkit_helper_instance("polkit-agent-helper@23.service"),
            Some("23")
        );
        assert_eq!(polkit_helper_instance("polkit.service"), None);
    }

    #[test]
    fn a_caller_without_a_pidfd_is_not_local() {
        let me = std::env::var("USER").unwrap_or_else(|_| "root".into());
        match locality(std::process::id() as i32, None, &me) {
            Locality::Remote(why) => assert!(why.contains("pidfd"), "{}", why),
            Locality::Local(_) => panic!("no pidfd must not be local"),
        }
    }

    #[test]
    fn a_vanished_caller_is_not_local() {
        // A pid that cannot exist: every read fails, and failure is remote.
        match locality(i32::MAX - 1, None, "root") {
            Locality::Remote(why) => assert!(why.contains("cannot verify"), "{}", why),
            Locality::Local(_) => panic!("an unreadable caller must not be local"),
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
        // With a pidfd of this very process, as the daemon would hold for a peer.
        use std::os::fd::FromRawFd;
        let raw =
            unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id() as libc::pid_t, 0) };
        assert!(raw >= 0, "pidfd_open");
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as i32) };
        let r = locality(std::process::id() as i32, Some(&fd), &me);
        if std::env::var_os("SSH_CONNECTION").is_some() {
            assert!(
                matches!(r, Locality::Remote(_)),
                "running over SSH should be remote"
            );
        } else if std::path::Path::new("/run/systemd/seats/seat0").exists() {
            match r {
                Locality::Local(_) => {}
                Locality::Remote(why) => panic!("a shell on the console should be local: {}", why),
            }
        }
    }
}

/// Drive a consent request through as many camera rounds as it needs. When
/// the user leaves mid-request the session is locked and the request parks
/// without the camera (so the lock screen can use it), until the user is back
/// (a face match on the lock screen), the session unlocks by other means,
/// or a password or a dismissal arrives from the window.
fn consent_rounds<'a>(
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

fn reply(stream: &mut UnixStream, o: &Outcome) -> Result<()> {
    let mut s = serde_json::to_string(o)?;
    s.push('\n');
    stream.write_all(s.as_bytes())?;
    Ok(())
}

fn user_uid(name: &str) -> Option<u32> {
    nix::unistd::User::from_name(name)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
}

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

#[cfg(test)]
mod queue_tests {
    use super::*;

    /// A slot is given back exactly once, whether released early or dropped.
    #[test]
    fn a_slot_is_given_back_once() {
        let before = ACTIVE.load(Ordering::SeqCst);
        ACTIVE.fetch_add(1, Ordering::SeqCst);
        let s = Slot::new();
        s.release();
        assert_eq!(ACTIVE.load(Ordering::SeqCst), before);
        drop(s);
        assert_eq!(
            ACTIVE.load(Ordering::SeqCst),
            before,
            "the drop after a release takes nothing more"
        );
        ACTIVE.fetch_add(1, Ordering::SeqCst);
        drop(Slot::new());
        assert_eq!(ACTIVE.load(Ordering::SeqCst), before);
    }

    /// The bar widget's presence poll is answered while the authenticator
    /// is held for the length of an enrolment walk-through (C5). The query
    /// takes no authenticator at all (its signature is the guarantee); this
    /// holds a lock for the walk-through's whole run on the calling thread
    /// and expects the reply, with the enrolled list read from the static,
    /// well inside the busy wait a locked request would have spent.
    #[test]
    fn a_presence_query_answers_while_the_authenticator_is_held() {
        let user = "c5-poll-user";
        set_enrolled(vec![user.to_string()]);
        let walk_through: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
        let held = walk_through.lock().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let poll = std::thread::spawn(move || {
            let started = Instant::now();
            let outcome = presence_query(1000, 1, user, "query");
            tx.send((outcome, started.elapsed())).unwrap();
        });
        let (outcome, took) = rx
            .recv_timeout(BUSY_WAIT)
            .expect("the poll was answered while the walk-through held its lock");
        assert!(
            matches!(outcome, Outcome::PresenceMode { .. }),
            "a state reply, not busy: {:?}",
            outcome
        );
        assert!(
            took < BUSY_WAIT / 2,
            "answered at once, not after a wait: {:?}",
            took
        );
        // The list is what the poll reads: a deleted user stops "watching"
        // without the store being asked.
        assert!(is_enrolled(user));
        set_enrolled(Vec::new());
        assert!(!is_enrolled(user));
        drop(held);
        poll.join().unwrap();
    }

    /// Three same-uid requests take the window in arrival order; another
    /// user's is refused while one is live (B1); a request past the bound
    /// waits nowhere (B4); a requester that hangs up while waiting never
    /// gets the window (H9, H11).
    #[test]
    fn same_user_requests_take_the_window_in_arrival_order() {
        use crate::consent::{ConsentState, NoTurn};
        let st: &'static ConsentState = Box::leak(Box::new(ConsentState::new()));
        let order = Arc::new(Mutex::new(Vec::new()));
        let first = st.join(1000).unwrap();
        let held = st.take_turn(first, "alice", None, &|| {}).unwrap();
        assert_eq!(st.join(1001).unwrap_err(), NoTurn::OtherUser(1000));
        // Three more of alice's, joined a moment apart, each on its own
        // thread as the daemon runs them.
        let mut threads = Vec::new();
        for n in 1..=3u32 {
            let place = st.join(1000).unwrap();
            let order = Arc::clone(&order);
            threads.push(std::thread::spawn(move || {
                let turn = st.take_turn(place, "alice", None, &|| {}).unwrap();
                order.lock().unwrap().push(n);
                std::thread::sleep(Duration::from_millis(50));
                drop(turn);
            }));
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            st.join(1001).unwrap_err(),
            NoTurn::OtherUser(1000),
            "refused while alice's is live"
        );
        drop(held);
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(*order.lock().unwrap(), vec![1, 2, 3]);
        assert!(st.live_user().is_none(), "the last turn freed the window");
        let _b = st
            .join(1001)
            .expect("free for another user once alice is done");
        // The bound: one past it waits nowhere; a freed place is a place taken.
        let st2: &'static ConsentState = Box::leak(Box::new(ConsentState::new()));
        let places: Vec<_> = (0..crate::consent::CONSENT_PER_UID)
            .map(|i| {
                st2.join(1000)
                    .unwrap_or_else(|e| panic!("place {}: {:?}", i, e))
            })
            .collect();
        const {
            assert!(
                crate::consent::CONSENT_PER_UID >= 20,
                "twenty agent sessions calling sudo at once must all queue"
            )
        };
        assert_eq!(st2.join(1000).unwrap_err(), NoTurn::TooMany);
        drop(places);
        let _p = st2.join(1000).expect("a place freed is a place taken");
        // A requester that hangs up while waiting is Gone, not served.
        let st3: &'static ConsentState = Box::leak(Box::new(ConsentState::new()));
        let live = st3.test_live(1000, "alice");
        let (a, b) = UnixStream::pair().unwrap();
        let place = st3.join(1000).unwrap();
        let waiter = std::thread::spawn(move || {
            st3.take_turn(place, "alice", Some(b.into()), &|| {})
                .map(|_| ())
        });
        std::thread::sleep(Duration::from_millis(100));
        drop(a);
        assert_eq!(waiter.join().unwrap().unwrap_err(), NoTurn::Gone);
        drop(live);
    }

    /// The hang-up is read off the request socket itself: dropping the
    /// requester's end reads as gone at the next poll, a peer that is alive
    /// and silent does not, and a live record with no requester never
    /// reads as gone (H11).
    #[test]
    fn a_dropped_requester_reads_as_gone_and_a_silent_one_does_not() {
        use crate::consent::{peer_gone, Answer, ConsentState};
        let (a, b) = UnixStream::pair().unwrap();
        let b: std::os::fd::OwnedFd = b.into();
        assert!(!peer_gone(&b), "alive and silent");
        drop(a);
        assert!(peer_gone(&b), "hung up");
        let st: &'static ConsentState = Box::leak(Box::new(ConsentState::new()));
        let place = st.join(1000).unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        let _turn = st
            .take_turn(place, "alice", Some(b.into()), &|| {})
            .unwrap();
        assert!(!st.requester_gone("alice"));
        assert!(st.poll("alice").is_none());
        drop(a);
        assert!(st.requester_gone("alice"));
        assert!(matches!(st.poll("alice"), Some(Answer::Gone)));
        assert!(
            st.answered("alice"),
            "a hang-up counts as an answer waiting"
        );
    }
}
