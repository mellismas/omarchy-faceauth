//! `pam_faceauth.so`: the smallest possible PAM module.
//!
//! It asks `faceauthd` over its Unix socket, and maps the answer. A line is
//! one of five kinds, by its argument.
//!
//! A plain look (no kind word: the lock screen's face lane): a match is
//! PAM_SUCCESS; anything else, any failure, PAM_IGNORE.
//!
//! A `consent` line (sudo's and polkit's face line):
//!
//! - match                        -> PAM_SUCCESS
//! - refused                      -> PAM_AUTH_ERR (a head shake, a dismissed
//!   window, a confirm after the nods that failed, or a request inside the
//!   refusal one of those left standing; the daemon sends it on the polkit
//!   lane, where `auth_err=die` ends the stack and the agent cancels the
//!   request, and answers sudo with `consent_denied` instead, which this
//!   module ignores, so sudo goes on to its key line and its password)
//! - consent_denied, anything else the daemon decided -> PAM_IGNORE
//! - refused_parked, the daemon's error, and every failure to get the
//!   daemon's answer at all (no daemon, a peer that is not root, a reply
//!   broken off or malformed, a name it cannot send, a remote host, a
//!   panic) -> PAM_AUTHINFO_UNAVAIL. Under Omarchy's controls that reads as
//!   an ignore too: the next line is the stack's `key-fallback` line, which
//!   goes through the daemon as well, so nothing the face line leaves
//!   reaches the key while the screen is locked and faceauthd runs; with
//!   faceauthd down it is stock pam_u2f's line (below).
//!
//! A `key-fallback` line (the stack's own key line, under the face line,
//! in place of pam_u2f while face is set up): the daemon runs its own
//! sandboxed key check, on the policy this line's words mirror. The line
//! first asks, on a short connection, whether it may run now; while the
//! screen is locked, the lock screen's hold runs or the card on screen has
//! the key, the daemon says to wait, and the line says once that the key
//! comes after the unlock and asks again a second later, holding no
//! connection between asks, with no deadline. Once it may run, with
//! `pinverification=1` the module asks for the key's PIN over the PAM
//! conversation (sudo's terminal), with no connection open, and hands it
//! to the daemon for one check on a fresh connection; with `cue` it says
//! to touch the key. A match is PAM_SUCCESS and every other answer
//! PAM_AUTH_ERR: the stack goes on to the password.
//!
//! With faceauthd down (its socket missing, or nothing listening on it:
//! no other failure), the key-fallback line is stock Omarchy's pam_u2f
//! line, locked screen and text console included (fix round 10, item 6,
//! Mike's ruling; `key_line`): the package's `faceauth-keycheck` runs the
//! check on the same private stack, as root and outside the daemon's
//! sandbox, as pam_u2f runs under stock Omarchy, with no lock question and
//! no wait for an unlock, and is killed the moment the daemon answers
//! again; a touch counts only while it is still down.
//!
//! A `key-unlock` line (the lock screen's key lane): the daemon runs the
//! same check while the session is locked. A match is PAM_SUCCESS and every
//! other answer, no daemon included, PAM_AUTH_ERR, never an ignore that
//! lets another line run.
//!
//! A `fprint-unlock` line (the lock screen's fingerprint lane, first in
//! `omarchy-lock-fingerprint` while face is set up): the daemon runs its
//! own sandboxed fingerprint check while the session is locked, as the
//! key-unlock line's, and the module passes each status the daemon sends
//! on to the lock screen's conversation, as pam_fprintd's own message
//! would come (an informational "place your finger", an error for a finger
//! that did not match), so the lock screen's lane sees the reader reached
//! as it does on stock Omarchy. A match is PAM_SUCCESS. With faceauthd down
//! (as the key-fallback line reads it: the socket missing or refusing with
//! its runtime directory gone) the line answers PAM_IGNORE, so the stack's
//! next line, stock Omarchy's pam_fprintd, runs as it does without face
//! authentication (Mike's 10/12 ruling); every other answer, a daemon
//! restarting included, is PAM_AUTH_ERR.
//!
//! No camera, no models, no templates, no image data in this process. The
//! module never sees a password: the only thing it asks for is the
//! security key's PIN, on a key-fallback line whose policy needs one, which
//! goes to the daemon on its socket (or, with the daemon down, to the key
//! check's stdin) and is wiped. Lockout is structurally
//! impossible from here: every failure on a look or a consent line lets the
//! stack go on to the password.
//!
//! Module arguments (in the PAM line), and no others:
//!
//! - `socket=/run/faceauth/sock`: where the daemon listens.
//! - `consent`: the elevation argument, for sudo and polkit. The daemon opens
//!   a window naming the command and the requester, and the request is
//!   approved by two nods, by the password typed into that window or by a
//!   touch of the key; sitting in front of the machine never elevates
//!   anything by itself. The window waits until it is answered, so
//!   `timeout=` is ignored on a consent line (the module logs that it was).
//! - `timeout=8`: seconds to wait for the daemon's reply on a plain look (the
//!   lock screen, where looking at the machine is the act).
//! - `key-fallback`, with `cue`, `pinverification=0|1` and
//!   `userverification=0|1` mirrored from the pam_u2f line it replaced: the
//!   stack's key line. `userverification=` is the daemon's to read.
//! - `key-unlock`: the lock screen's key lane.
//!
//! The key lines wait up to `KEY_WAIT` for the daemon's answer to a
//! check, whose own check ends sooner; `timeout=` is ignored on them. Any other word is ignored and
//! logged: a misspelt `consent` must not pass in silence, and the daemon
//! refuses the plain look it would leave from a root caller. Two kind words
//! on one line ask nothing and fail.
//!
//! The daemon trusts an effective-uid-0 peer with its root-only requests
//! (enrollment, deletion), and under sudo and polkit this module runs as
//! root. It therefore builds exactly five request shapes, the plain look,
//! the consent request, the key fallback, its ask whether it may run and
//! the key unlock, in one place (`request_line`), and a test pins each to
//! its exact fields and to the daemon's own parse of it.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::{Duration, Instant};

/// The one lock verdict (R1), the same source the daemon compiles
/// (`faceauth_daemon::lockgate`), included rather than linked: the module
/// links nothing but libc.
#[path = "../../faceauth-daemon/src/lockgate.rs"]
#[allow(dead_code)]
mod lockgate;
use lockgate::{Verdict, WaitBudget};

const PAM_SUCCESS: c_int = 0;
/// PAM_CONV: the application's conversation function.
const PAM_CONV: c_int = 5;
const PAM_SERVICE: c_int = 1;
/// PAM_RHOST: set by network services (sshd) to the remote host name.
const PAM_RHOST: c_int = 4;
const PAM_IGNORE: c_int = 25;
const PAM_AUTH_ERR: c_int = 7;
const PAM_AUTHINFO_UNAVAIL: c_int = 9;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;

const DEFAULT_SOCKET: &str = "/run/faceauth/sock";
const DEFAULT_TIMEOUT: u64 = 8;
const MAX_REPLY: usize = 4096;
/// How long a key line waits for the daemon: at least the longest the
/// daemon takes to answer a touch (`consent::KEY_REPLY_WITHIN`, 63 s: two
/// lock questions, the wait for a card's check to stop, the check's own
/// deadline and one lock question past it), which a test holds it to.
const KEY_WAIT: Duration = Duration::from_secs(65);
/// The longest PIN a FIDO2 key takes is 63 bytes.
const PIN_MAX: usize = 63;

/// With faceauthd down, the package's own helpers: the lock question, run
/// as the user (`faceauth-lockstate`, one bit back), and the key check
/// (`faceauth-keycheck`, the daemon's own helper, on the same private
/// stacks). Each is run only when root's and closed to other writers.
const KEYCHECK_HELPER: &str = "/usr/lib/faceauth/faceauth-keycheck";
/// `faceauth-keycheck`'s answer for a touch.
const KEY_TOUCHED: u8 = 42;
/// What a key line says, once, while it waits for the unlock.
const WAIT_TEXT: &str =
    "The screen is locked. Your security key will be offered after you unlock it.";

/// The module's waits, in one place, so the tests drive the same control
/// flow on a faster clock; `Timing::REAL` in use. With the daemon's own
/// bounds, every wait that is not the user's own (a card on screen, a PIN
/// prompt) or a positive lock on the desktop the request comes from ends
/// in time for the password line within about 15 s (round 6, item 12;
/// `the_real_timing_keeps_the_password_within_reach` holds the sums).
#[derive(Clone, Copy, Debug)]
struct Timing {
    /// The longest gap between two lines from the daemon on a consent or
    /// key line before the module takes it for hung.
    liveness: Duration,
    /// Between two looks while a key line waits.
    tick: Duration,
    /// How long an unknown lock state is waited on.
    unknown_limit: Duration,
    /// How often a direct check's watch looks at the socket and the lock.
    still_tick: Duration,
    /// A direct check's window for a touch.
    fallback_deadline: Duration,
}

impl Timing {
    const REAL: Timing = Timing {
        liveness: lockgate::LIVENESS,
        tick: Duration::from_secs(1),
        unknown_limit: lockgate::UNKNOWN_LIMIT,
        still_tick: Duration::from_millis(250),
        fallback_deadline: lockgate::FALLBACK_DEADLINE,
    };
}

#[repr(C)]
pub struct pam_handle_t {
    _private: [u8; 0],
}

/// Linux-PAM's `struct pam_message`.
#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

/// Linux-PAM's `struct pam_response`.
#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

/// Linux-PAM's `struct pam_conv`.
#[repr(C)]
struct PamConv {
    conv: Option<
        unsafe extern "C" fn(
            c_int,
            *mut *const PamMessage,
            *mut *mut PamResponse,
            *mut c_void,
        ) -> c_int,
    >,
    appdata_ptr: *mut c_void,
}

// Linked, not merely declared: a host that loads libpam privately (Python's
// ctypes does) resolves these only through the module's own DT_NEEDED.
#[link(name = "pam")]
extern "C" {
    fn pam_get_user(
        pamh: *mut pam_handle_t,
        user: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
    fn pam_get_item(pamh: *const pam_handle_t, item_type: c_int, item: *mut *const c_void)
        -> c_int;
    fn pam_syslog(pamh: *const pam_handle_t, priority: c_int, fmt: *const c_char, ...);
}

extern "C" {
    fn syslog(priority: c_int, fmt: *const c_char, ...);
}

/// The request a line sends.
#[derive(Debug, PartialEq, Clone, Copy)]
enum Ask {
    Look,
    Consent,
    KeyFallback,
    KeyUnlock,
    /// The lock screen's fingerprint lane.
    FprintUnlock,
    /// Not a line's kind: the key-fallback line's question whether it may
    /// run now, on a short connection of its own.
    KeyReady,
}

impl Ask {
    /// A key line: the daemon's key check, whose every failure fails.
    fn key(self) -> bool {
        matches!(self, Ask::KeyFallback | Ask::KeyUnlock | Ask::KeyReady)
    }
}

struct Args {
    socket: String,
    timeout: Duration,
    /// Elevation: the daemon opens the window and requires the nod. No
    /// conversation with the caller at all, since the caller cannot be trusted
    /// to relay a yes.
    consent: bool,
    /// The stack's own key line, run by the daemon.
    key_fallback: bool,
    /// The lock screen's key lane: the daemon asks the security key.
    key_unlock: bool,
    /// The lock screen's fingerprint lane: the daemon asks the reader.
    fprint_unlock: bool,
    /// On a key-fallback line: say to touch the key.
    cue: bool,
    /// On a key-fallback line: the line says `pinverification=1`.
    pin: bool,
    /// On a key-fallback line: the line says `pinverification=0`.
    pin_off: bool,
}

const LOG_AUTHPRIV_INFO: c_int = (10 << 3) | 6;

/// One line to the auth log per decision, for measuring the stack around
/// us. Through `pam_syslog`, which prefixes the module and the service
/// (`pam_faceauth(sudo:auth)`), so the log says which stack decided. Never
/// includes a password or a PIN.
fn log(pamh: *const pam_handle_t, msg: &str) {
    let Ok(c) = std::ffi::CString::new(msg) else {
        return;
    };
    let fmt = b"%s\0";
    if pamh.is_null() {
        // No transaction (a test): the plain syslog, with the name by hand.
        let tagged = b"pam_faceauth: %s\0";
        // SAFETY: format string with one %s and a matching C string argument.
        unsafe {
            syslog(
                LOG_AUTHPRIV_INFO,
                tagged.as_ptr() as *const c_char,
                c.as_ptr(),
            )
        };
        return;
    }
    // SAFETY: pamh is the handle PAM gave us; one %s, one C string argument.
    unsafe {
        pam_syslog(
            pamh,
            LOG_AUTHPRIV_INFO,
            fmt.as_ptr() as *const c_char,
            c.as_ptr(),
        )
    };
}

/// Names go into the auth log; strip anything that could forge a line.
fn sanitise(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(64).collect()
}

fn parse_args(pamh: *const pam_handle_t, argc: c_int, argv: *const *const c_char) -> Args {
    let mut a = Args {
        socket: DEFAULT_SOCKET.to_string(),
        timeout: Duration::from_secs(DEFAULT_TIMEOUT),
        consent: false,
        key_fallback: false,
        key_unlock: false,
        fprint_unlock: false,
        cue: false,
        pin: false,
        pin_off: false,
    };
    let mut timeout_given = false;
    if argv.is_null() {
        return a;
    }
    for i in 0..argc.max(0) as usize {
        // SAFETY: PAM passes argc valid C strings.
        let s = unsafe {
            let p = *argv.add(i);
            if p.is_null() {
                continue;
            }
            CStr::from_ptr(p).to_string_lossy().into_owned()
        };
        if let Some(v) = s.strip_prefix("socket=") {
            a.socket = v.to_string();
        } else if let Some(v) = s.strip_prefix("timeout=") {
            if let Ok(t) = v.parse::<u64>() {
                a.timeout = Duration::from_secs(t.clamp(1, 600));
                timeout_given = true;
            }
        } else if s == "consent" {
            a.consent = true;
        } else if s == "key-fallback" {
            a.key_fallback = true;
        } else if s == "key-unlock" {
            a.key_unlock = true;
        } else if s == "fprint-unlock" {
            a.fprint_unlock = true;
        } else if s == "cue" {
            a.cue = true;
        } else if s == "pinverification=1" {
            a.pin = true;
        } else if s == "pinverification=0" {
            a.pin_off = true;
        } else if matches!(s.as_str(), "userverification=0" | "userverification=1") {
            // The daemon reads the key line's policy from the stack itself.
        } else {
            // A word the module does not know is dropped, and said so: a
            // misspelt `consent` must not pass in silence. The daemon
            // refuses the plain look it would leave from a root caller.
            log(
                pamh,
                &format!("unknown argument {:?} ignored", sanitise(&s)),
            );
        }
    }
    if (a.key_fallback || a.key_unlock || a.fprint_unlock) && timeout_given {
        log(
            pamh,
            "timeout= is ignored on a key or fingerprint line; the daemon bounds its own check",
        );
    }
    if a.consent && timeout_given {
        // A consent line waits for the user, without limit: the window sits
        // there until it is answered. `timeout=` bounds a plain look only.
        log(
            pamh,
            "timeout= is ignored on a consent line; the window waits until it is answered",
        );
    }
    a
}

/// The line's own `pinverification=`, if it says one.
fn line_pin(a: &Args) -> Option<bool> {
    match (a.pin, a.pin_off) {
        (true, false) => Some(true),
        (false, true) => Some(false),
        _ => None,
    }
}

/// Whether the key-fallback line asks for the PIN (round 8, Codex 6): the
/// effective policy, the line's word else pam_u2f.conf's default, read as
/// the daemon reads it (`lockgate::u2f_conf_words`). A file the daemon
/// refuses withholds the key there, so nothing is asked for.
fn wants_pin(line: Option<bool>, conf: Option<&str>) -> bool {
    let conf = match conf {
        Some(text) => match lockgate::u2f_conf_words(text) {
            Ok(w) => w.pin,
            Err(_) => return false,
        },
        None => None,
    };
    line.or(conf) == Some(true)
}

/// pam_u2f.conf's text, when there is one pam_u2f would read.
fn u2f_conf_text() -> Option<String> {
    use std::io::Read;
    let f = std::fs::File::open(lockgate::U2F_CONF).ok()?;
    let mut text = String::new();
    f.take(lockgate::U2F_CONF_MAX as u64 + 1)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

/// The line's kind, or None for two kind words on one line.
fn ask_of(a: &Args) -> Option<Ask> {
    kind_from(a.consent, a.key_fallback, a.key_unlock, a.fprint_unlock)
}

/// The kind from its four words, or None for more than one.
fn kind_from(consent: bool, fallback: bool, unlock: bool, fprint: bool) -> Option<Ask> {
    match (consent, fallback, unlock, fprint) {
        (false, false, false, false) => Some(Ask::Look),
        (true, false, false, false) => Some(Ask::Consent),
        (false, true, false, false) => Some(Ask::KeyFallback),
        (false, false, true, false) => Some(Ask::KeyUnlock),
        (false, false, false, true) => Some(Ask::FprintUnlock),
        _ => None,
    }
}

/// Is the process on the other end of `stream` running as root?
fn peer_is_root(stream: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a valid socket fd, a correctly sized out-buffer and its length.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut c_void,
            &mut len,
        )
    };
    rc == 0 && cred.uid == 0
}

/// What the daemon said, as far as this module cares.
#[derive(Debug, PartialEq, Clone, Copy)]
enum Said {
    Match,
    Refused,
    RefusedParked,
    /// The daemon's error reply.
    Error,
    /// No answer from the daemon at all: a peer that is not root, a reply
    /// broken off or malformed, a request that could not be built or sent.
    Unreachable,
    /// The daemon is down: its runtime directory is gone (the service
    /// stopped, or failed for good), so its socket is missing. The one
    /// failure that sends a key-fallback line to the key itself, as stock
    /// pam_u2f (fix round 10, item 6). A socket missing or refusing in a
    /// runtime directory that is still there is a daemon restarting, which
    /// is `Unreachable` (fix round 11).
    Down,
    /// A key-fallback line may not run now: wait and ask again. The kind:
    /// `Locked` for a positive lock, `Held` for the hold after an unlock,
    /// `Unknown` for no answer.
    Wait(Verdict),
    /// The card on screen has the key: the user's own work, waited on for
    /// free for a while (round 8, Opus L6).
    CardWait,
    /// A key-fallback line may run now.
    Ready,
    /// polkit's request: the daemon wants the request's cookie from the
    /// agent (`lockgate::polkit_cookie_question`) before it shows a card
    /// (round 16c). Never a final answer.
    NeedCookie,
    /// The PAM caller's own requester hung up while the line waited:
    /// polkit's agent closed its helper's socket, so nobody is left to hear
    /// an answer (live test 1, 2026-10-13; round 16, Opus N3). The line
    /// ends with an auth error, which ends polkit's stack.
    Abandoned,
    Other,
}

/// The connection polkit's helper holds to the agent that started it, its
/// standard input (polkit-agent-helper@.service: `StandardInput=socket`, or
/// a pipe from an agent that spawns the helper itself). A cancelling agent
/// only closes it (polkit 127 src/polkitagent/polkitagentsession.c,
/// `kill_helper`; Quickshell's agent cancels through
/// `polkit_agent_session_cancel`), and the helper, waiting inside this
/// module, never reads it; so the line watches it for the hang-up and ends
/// the request then, its card with it.
#[derive(Clone, Copy, Debug)]
struct Agent(c_int);

impl Agent {
    /// Has the agent hung up its end? POLLRDHUP or POLLHUP, an error, or a
    /// descriptor no longer open. Nothing is read.
    fn hung_up(self) -> bool {
        let mut fds = [libc::pollfd {
            fd: self.0,
            events: libc::POLLRDHUP | libc::POLLHUP,
            revents: 0,
        }];
        // SAFETY: one pollfd, and no wait.
        match unsafe { libc::poll(fds.as_mut_ptr(), 1, 0) } {
            0 => false,
            n if n > 0 => {
                fds[0].revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                    != 0
            }
            _ => std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR),
        }
    }
}

/// How a wait on the daemon and the agent together ended.
#[derive(Debug, PartialEq)]
enum Woke {
    /// The daemon has something to read (or hung up, which the read says).
    Daemon,
    /// The agent hung up.
    Agent,
    /// Neither, within the wait.
    Neither,
}

/// Wait up to `wait` for the daemon's connection `daemon` to have a line,
/// or the agent to hang up, whichever comes first; the agent wins a tie.
fn wait_daemon_or_agent(daemon: c_int, agent: Agent, wait: Duration) -> Woke {
    let by = Instant::now() + wait;
    loop {
        let left = by.saturating_duration_since(Instant::now());
        let mut fds = [
            libc::pollfd {
                fd: daemon,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: agent.0,
                events: libc::POLLRDHUP | libc::POLLHUP,
                revents: 0,
            },
        ];
        let ms = left.as_millis().min(c_int::MAX as u128) as c_int;
        // SAFETY: two pollfds, and a bounded wait.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, ms) };
        if n < 0 {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                && !left.is_zero()
            {
                continue;
            }
            return Woke::Neither;
        }
        if fds[1].revents & (libc::POLLRDHUP | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
        {
            return Woke::Agent;
        }
        if fds[0].revents != 0 {
            return Woke::Daemon;
        }
        return Woke::Neither;
    }
}

/// polkit's helper's connection to its agent: on polkit's stack alone
/// (`polkit-1`), its standard input when that is a socket or a pipe. Never
/// sudo's, whose standard input is the user's terminal.
fn polkit_agent(pamh: *const pam_handle_t) -> Option<Agent> {
    if pam_service(pamh).as_deref().and_then(lane_of_service) != Some("polkit") {
        return None;
    }
    // SAFETY: an all-zero stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a descriptor number and an out-parameter.
    if unsafe { libc::fstat(0, &mut st) } != 0 {
        return None;
    }
    matches!(st.st_mode & libc::S_IFMT, libc::S_IFSOCK | libc::S_IFIFO).then_some(Agent(0))
}

/// A connection to the daemon's socket, made without blocking (round 8,
/// Codex 2): a daemon that never accepts, its backlog full, is no answer
/// at once rather than a hang; a socket missing or refusing is down only
/// when the runtime directory it lives in is gone too (fix round 11).
fn connect_to(socket: &Path) -> Result<UnixStream, Said> {
    lockgate::connect_nonblocking(socket).map_err(|e| match e.raw_os_error() {
        Some(libc::EAGAIN) => Said::Unreachable,
        _ => connect_kind(e.kind(), runtime_dir_present(socket)),
    })
}

/// Whether the directory the socket lives in (`/run/faceauth`, the unit's
/// `RuntimeDirectory=`) is still there. The unit keeps it across an
/// automatic restart (`RuntimeDirectoryPreserve=restart`): systemd
/// removes it only once the unit is inactive or failed with no restart
/// and no job pending (systemd v262 src/core/unit.c,
/// `unit_release_resources`; src/core/service.c, `service_will_restart`
/// counts the auto-restart states as restarting). So it is gone after
/// `systemctl stop` and after a failure that is not restarted, and there
/// through a crash and its restart, and through `systemctl restart`. Only
/// root can make it (`/run` is root's).
fn runtime_dir_present(socket: &Path) -> bool {
    socket
        .parent()
        .is_some_and(|d| dir_seen(std::fs::symlink_metadata(d).map(|_| ())))
}

/// What an lstat of the runtime directory says for "down": only "not
/// found" is gone; any other failure is "can't tell" and counts as there,
/// so it goes to the password, never to the stock key (fix round 12, Opus).
fn dir_seen(lstat: std::io::Result<()>) -> bool {
    !matches!(lstat, Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// A failed connection to the daemon's socket: down only for a socket
/// missing or refusing with its runtime directory gone (the service
/// stopped or failed for good); a daemon restarting (the directory still
/// there) and anything else are no answer, which goes to the password.
fn connect_kind(kind: std::io::ErrorKind, runtime_dir: bool) -> Said {
    match kind {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused if !runtime_dir => {
            Said::Down
        }
        _ => Said::Unreachable,
    }
}

/// Bytes wiped before they are freed: the key's PIN, and the request line
/// that carried it.
struct Wiped(Vec<u8>);

impl Drop for Wiped {
    fn drop(&mut self) {
        // SAFETY: the pointer and length are the vector's own.
        unsafe { libc::explicit_bzero(self.0.as_mut_ptr() as *mut c_void, self.0.len()) };
    }
}

/// A JSON string's contents for `s`: the escapes the daemon's hand parse
/// of the password field reads (`server/read.rs`: `unescape`).
fn json_escape(s: &str, out: &mut Vec<u8>) {
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => {
                let mut b = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut b).as_bytes());
            }
        }
    }
}

/// The only place a request to the daemon is built. Four shapes exist: the
/// plain look, the consent request, the key fallback (with the key's PIN
/// in the password field when the line asks for one) and the key unlock.
/// The name goes in verbatim, so a name that would need escaping (a quote,
/// a backslash, a control character) is refused here rather than rewritten
/// into a different name: the daemon must be asked about PAM_USER or about
/// nobody. The line is wiped when dropped.
fn request_line(user: &str, ask: Ask, pin: Option<&str>) -> Option<Wiped> {
    if user.is_empty()
        || user.len() > 256
        || user
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
    {
        return None;
    }
    let mut out = Vec::with_capacity(96 + 6 * PIN_MAX);
    out.extend_from_slice(b"{\"user\":\"");
    out.extend_from_slice(user.as_bytes());
    out.push(b'"');
    match ask {
        Ask::Consent => out.extend_from_slice(b",\"consent\":true"),
        Ask::KeyUnlock => out.extend_from_slice(b",\"key_unlock\":true"),
        Ask::FprintUnlock => out.extend_from_slice(b",\"fprint_unlock\":true"),
        Ask::KeyReady => out.extend_from_slice(b",\"key_fallback\":true,\"key_ready\":true"),
        Ask::KeyFallback => {
            out.extend_from_slice(b",\"key_fallback\":true");
            if let Some(pin) = pin {
                out.extend_from_slice(b",\"consent_password\":\"");
                json_escape(pin, &mut out);
                out.push(b'"');
            }
        }
        Ask::Look => {}
    }
    out.extend_from_slice(b"}\n");
    Some(Wiped(out))
}

/// A consent request carrying the agent's answer to the cookie prompt:
/// `cookie` when it has a cookie's form (`lockgate::polkit_cookie_ok`),
/// else "" (the agent gave nothing usable), so whatever the agent sent is
/// never passed on as it is.
fn consent_line_with_cookie(user: &str, cookie: &str) -> Option<Wiped> {
    let mut out = request_line(user, Ask::Consent, None)?;
    let cookie = if lockgate::polkit_cookie_ok(cookie) {
        cookie
    } else {
        ""
    };
    // "...}\n" becomes "...,"polkit_cookie":"<cookie>"}\n"; a cookie of that
    // form needs no escaping.
    out.0.truncate(out.0.len() - 2);
    out.0.extend_from_slice(b",\"polkit_cookie\":\"");
    out.0.extend_from_slice(cookie.as_bytes());
    out.0.extend_from_slice(b"\"}\n");
    Some(out)
}

/// A fresh challenge for one cookie question (round 18): 16 bytes from the
/// kernel's random source as 32 lowercase hex characters
/// (`lockgate::polkit_challenge_ok`). getrandom(2) needs no device, and is in
/// the system calls polkit's helper may make (`@system-service` takes in
/// `@default`). None when the kernel gives none.
fn fresh_challenge() -> Option<String> {
    let mut b = [0u8; 16];
    let mut got = 0;
    while got < b.len() {
        // SAFETY: the pointer and length are the unfilled rest of `b`.
        let n = unsafe { libc::getrandom(b[got..].as_mut_ptr().cast(), b.len() - got, 0) };
        if n < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if n <= 0 {
            return None;
        }
        got += n as usize;
    }
    Some(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// One message to the application through the PAM conversation: the
/// answer for a prompt (wiped when dropped), an empty one for a notice;
/// None when there is no conversation or it failed.
fn converse(pamh: *const pam_handle_t, style: c_int, text: &str) -> Option<Wiped> {
    if pamh.is_null() {
        return None;
    }
    let msg_text = std::ffi::CString::new(text).ok()?;
    let mut item: *const c_void = std::ptr::null();
    // SAFETY: pamh is PAM's handle; item is a valid out-pointer.
    if unsafe { pam_get_item(pamh, PAM_CONV, &mut item) } != PAM_SUCCESS || item.is_null() {
        return None;
    }
    // SAFETY: PAM_CONV is a `struct pam_conv` PAM owns for the handle's life.
    let conv = unsafe { &*(item as *const PamConv) };
    let f = conv.conv?;
    let msg = PamMessage {
        msg_style: style,
        msg: msg_text.as_ptr(),
    };
    let mut msgs: [*const PamMessage; 1] = [&msg];
    let mut resp: *mut PamResponse = std::ptr::null_mut();
    // SAFETY: one message, a valid out-pointer for the response array, and
    // the application's own data pointer.
    let rc = unsafe { f(1, msgs.as_mut_ptr(), &mut resp, conv.appdata_ptr) };
    let mut answer = Wiped(Vec::new());
    if !resp.is_null() {
        // SAFETY: the application allocated one response with malloc; its
        // text, when there is one, is a NUL-terminated malloc'd string. Both
        // are this module's to free, and the text is wiped first.
        unsafe {
            let r = (*resp).resp;
            if !r.is_null() {
                let bytes = CStr::from_ptr(r).to_bytes();
                answer.0.extend_from_slice(bytes);
                libc::explicit_bzero(r as *mut c_void, bytes.len());
                libc::free(r as *mut c_void);
            }
            libc::free(resp as *mut c_void);
        }
    }
    (rc == PAM_SUCCESS).then_some(answer)
}

/// The key's PIN, asked for on the conversation (sudo's terminal). None
/// for no conversation, no answer, an empty one, one too long for a key,
/// or one that is not UTF-8.
fn ask_pin(pamh: *const pam_handle_t) -> Option<Wiped> {
    let pin = converse(pamh, PAM_PROMPT_ECHO_OFF, "Security key PIN: ")?;
    (!pin.0.is_empty() && pin.0.len() <= PIN_MAX && std::str::from_utf8(&pin.0).is_ok())
        .then_some(pin)
}

/// A connection to the daemon, checked to be root's: the socket lives under
/// a root-owned runtime directory, so nobody else can put a listener there,
/// and this check is the belt to that suspender. A peer that is not root is
/// not the daemon, and its answers are nobody's.
fn connect_daemon(pamh: *const pam_handle_t, socket: &Path) -> Result<UnixStream, Said> {
    let stream = connect_to(socket)?;
    if !peer_is_root(&stream) {
        log(
            pamh,
            "the socket's peer is not root; not the daemon, ignoring it",
        );
        return Err(Said::Unreachable);
    }
    Ok(stream)
}

/// The whole conversation with the daemon: what it said, or `Unreachable`
/// for every way of not getting its answer. A key-fallback line has its own
/// (`key_line`), which also runs the key itself while faceauthd is down.
fn daemon_says(
    pamh: *const pam_handle_t,
    socket: &Path,
    user: &str,
    timeout: Duration,
    ask: Ask,
    cue: bool,
    want_pin: bool,
) -> Said {
    if request_line(user, ask, None).is_none() {
        log(pamh, "user name would need escaping; not asking the daemon");
        return Said::Unreachable;
    }
    if ask == Ask::FprintUnlock {
        return fprint_unlock_line(
            &|| connect_daemon(pamh, socket),
            user,
            Timing::REAL,
            &|style, text| {
                let _ = converse(pamh, style, text);
            },
        );
    }
    let agent = polkit_agent(pamh);
    if ask == Ask::KeyFallback {
        let env = PamEnv::new(pamh, socket, user, cue, agent);
        return key_line(&env, user, want_pin, Timing::REAL);
    }
    // On polkit's stack alone the daemon may want the request's cookie,
    // which only the agent can say; it is asked through polkit's helper.
    let polkit = pam_service(pamh).as_deref().and_then(lane_of_service) == Some("polkit");
    // Asked with the echo off (round 17, Codex 1): an agent that showed it
    // by mistake would not show what was typed into it.
    let cookie_of = |question: &str| converse(pamh, PAM_PROMPT_ECHO_OFF, question);
    ask_daemon(
        &|| connect_daemon(pamh, socket).ok(),
        user,
        timeout,
        ask,
        Timing::REAL,
        agent,
        if polkit { Some(&cookie_of) } else { None },
    )
}

/// The daemon's word that it is still at work on a waiting request
/// (round 6, item 12).
fn is_pending(line: &str) -> bool {
    line.trim() == "{\"result\":\"pending\"}"
}

/// What the lock screen hears for each status of the daemon's fingerprint
/// check: pam_fprintd's own words and styles, untranslated, so its lane
/// takes an informational message for the reader reached and an error for
/// a finger that did not match, as it takes pam_fprintd's.
const FPRINT_PLACE: &str = "Place your finger on the fingerprint reader";
const FPRINT_RETRY: &str = "Failed to match fingerprint";

/// A status line of the daemon's fingerprint check, as its style and the
/// text to pass on; None for any other line. Only the exact lines count.
fn fprint_status_of(line: &str) -> Option<(c_int, &'static str)> {
    match line.trim() {
        "{\"result\":\"fprint_status\",\"status\":\"place\"}" => {
            Some((PAM_TEXT_INFO, FPRINT_PLACE))
        }
        "{\"result\":\"fprint_status\",\"status\":\"retry\"}" => {
            Some((PAM_ERROR_MSG, FPRINT_RETRY))
        }
        _ => None,
    }
}

/// The `fprint-unlock` line: the request on a connection checked to be the
/// daemon's (`connect`), `Down` when faceauthd is down, and the daemon's
/// answer, each line read with the patience of a waiting line
/// (`timing.liveness`: the daemon beats every `BEAT` while its check
/// runs), its keepalives skipped and its status lines passed to `say` as
/// the conversation's messages.
fn fprint_unlock_line(
    connect: &dyn Fn() -> Result<UnixStream, Said>,
    user: &str,
    timing: Timing,
    say: &dyn Fn(c_int, &str),
) -> Said {
    let Some(req) = request_line(user, Ask::FprintUnlock, None) else {
        return Said::Unreachable;
    };
    let mut stream = match connect() {
        Ok(s) => s,
        Err(said) => return said,
    };
    if stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .is_err()
        || stream.write_all(&req.0).is_err()
    {
        return Said::Unreachable;
    }
    let mut reader = BufReader::new(stream);
    loop {
        if reader
            .get_ref()
            .set_read_timeout(Some(timing.liveness))
            .is_err()
        {
            return Said::Unreachable;
        }
        let mut line = String::new();
        let read = reader.by_ref().take(MAX_REPLY as u64).read_line(&mut line);
        if read.is_err() || line.trim().is_empty() {
            return Said::Unreachable;
        }
        if is_pending(&line) {
            continue;
        }
        if let Some((style, text)) = fprint_status_of(&line) {
            say(style, text);
            continue;
        }
        return classify(&line, Ask::FprintUnlock);
    }
}

/// One request on its own connection, and the daemon's answer to it:
/// lines read with `per_line` patience each, the daemon's keepalives
/// (`is_pending`) skipped. No line within `per_line` is no answer: the
/// daemon is taken for hung. Given up as no answer once `within` has
/// passed since it began, however the daemon keeps saying it is at work,
/// and `Abandoned` the moment `agent` hangs up; the connection closes as it
/// returns, which the daemon takes for its requester gone.
fn exchange_within(
    mut stream: UnixStream,
    req: &Wiped,
    per_line: Duration,
    ask: Ask,
    within: Option<Duration>,
    agent: Option<Agent>,
) -> Said {
    let by = within.map(|w| Instant::now() + w);
    if stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .is_err()
        || stream.write_all(&req.0).is_err()
    {
        return Said::Unreachable;
    }
    let mut reader = BufReader::new(stream);
    loop {
        let wait = match by {
            Some(by) => per_line.min(by.saturating_duration_since(Instant::now())),
            None => per_line,
        };
        if wait.is_zero() || reader.get_ref().set_read_timeout(Some(wait)).is_err() {
            return Said::Unreachable;
        }
        // With nothing buffered, wait on the daemon and the agent together:
        // a hang-up of the agent's ends the line at once. With a line
        // buffered, the agent is asked first all the same (round 16b, Codex
        // 3).
        if let Some(agent) = agent {
            if agent.hung_up() {
                return Said::Abandoned;
            }
            if reader.buffer().is_empty() {
                use std::os::fd::AsRawFd;
                match wait_daemon_or_agent(reader.get_ref().as_raw_fd(), agent, wait) {
                    Woke::Agent => return Said::Abandoned,
                    Woke::Daemon => {}
                    Woke::Neither => return Said::Unreachable,
                }
            }
        }
        let mut line = String::new();
        let read = reader.by_ref().take(MAX_REPLY as u64).read_line(&mut line);
        if read.is_err() || line.trim().is_empty() {
            return Said::Unreachable;
        }
        if !is_pending(&line) {
            // An answer counts only while someone is there to hear it.
            if agent.is_some_and(Agent::hung_up) {
                return Said::Abandoned;
            }
            return classify(&line, ask);
        }
    }
}

/// How the cookie question reaches polkit's agent: the question in, the
/// agent's answer out (the PAM conversation, or a test's fake agent).
type CookieOf<'a> = &'a dyn Fn(&str) -> Option<Wiped>;

/// The conversation with the daemon over `connect`, which hands back a
/// connection checked to be the daemon's, for a look, a consent line and
/// the lock screen's key line. A consent line waits as long as the daemon
/// keeps saying it is at work (a card on screen waits for its user), and
/// no longer than `liveness` past its last word. The key-fallback line has
/// its own (`key_line`).
fn ask_daemon(
    connect: &dyn Fn() -> Option<UnixStream>,
    user: &str,
    timeout: Duration,
    ask: Ask,
    timing: Timing,
    agent: Option<Agent>,
    cookie_of: Option<CookieOf<'_>>,
) -> Said {
    let Some(req) = request_line(user, ask, None) else {
        return Said::Unreachable;
    };

    let Some(stream) = connect() else {
        return Said::Unreachable;
    };
    // A key unlock is bounded by the daemon's own check; a plain look by
    // its `timeout=`.
    let per_line = match ask {
        // The fingerprint line has its own exchange (`fprint_unlock_line`).
        Ask::Consent | Ask::KeyFallback | Ask::KeyReady | Ask::FprintUnlock => timing.liveness,
        Ask::KeyUnlock => KEY_WAIT,
        Ask::Look => timeout,
    };
    match exchange_within(stream, &req, per_line, ask, None, agent) {
        // The daemon wants the request's cookie: asked of the agent once,
        // through the conversation, with a challenge of this question's own
        // (round 18), then the request again with it. Only polkit's stack
        // has a `cookie_of`; anywhere else this is no answer.
        Said::NeedCookie => {
            let Some(cookie_of) = cookie_of else {
                return Said::Unreachable;
            };
            let Some(challenge) = fresh_challenge() else {
                return Said::Unreachable;
            };
            // No answer: the agent hung up during the prompt, which ends the
            // request, or it said nothing; and an answer without the tag and
            // this challenge is not the agent's (something typed into a
            // prompt it showed by mistake, a password that starts with the
            // tag included, since the challenge did not exist before the
            // question), and goes nowhere. Neither asks again (round 17,
            // Codex 1, Opus F2).
            let Some(answer) = cookie_of(&lockgate::polkit_cookie_question(&challenge)) else {
                return if agent.is_some_and(Agent::hung_up) {
                    Said::Abandoned
                } else {
                    Said::Unreachable
                };
            };
            let Some(cookie) = std::str::from_utf8(&answer.0)
                .ok()
                .and_then(|a| lockgate::polkit_cookie_answer(a, &challenge))
            else {
                return Said::Unreachable;
            };
            let Some(again) = consent_line_with_cookie(user, cookie) else {
                return Said::Unreachable;
            };
            let Some(stream) = connect() else {
                return Said::Unreachable;
            };
            match exchange_within(stream, &again, per_line, ask, None, agent) {
                Said::NeedCookie => Said::Unreachable,
                other => other,
            }
        }
        other => other,
    }
}

/// What a key-fallback line needs from the world: the daemon's socket,
/// the conversation, a clock, and while faceauthd is down the key check
/// itself. `PamEnv` in use; the tests' fakes drive the same control flow
/// (`key_line`).
trait KeyEnv {
    /// A connection to the daemon, checked to be root's; `Down` for a
    /// socket missing or refusing, `Unreachable` for anything else.
    fn connect(&self) -> Result<UnixStream, Said>;
    fn ask_pin(&self) -> Option<Wiped>;
    /// Say, once, that the key waits for the unlock.
    fn tell_wait(&self);
    /// Say, once, to touch the key (on `cue`).
    fn cue(&self);
    fn sleep(&self, d: Duration);
    /// A monotonic clock.
    fn now(&self) -> Duration;
    /// Whether the key may be run directly at all (root, sudo's or
    /// polkit's stack, a user who is not root, the check's helper root's).
    fn direct_ok(&self) -> bool;
    /// One stock key check, its conversation (pam_u2f's own PIN prompts and
    /// cue) passed through to the PAM caller, stopped when `still` says no.
    fn check(&self, still: &dyn Fn() -> bool) -> Ended;
    /// polkit's agent, watched for its hang-up while the line waits.
    fn agent(&self) -> Option<Agent> {
        None
    }
}

/// The key-fallback line (round 5's A and B, round 6's 1, 2, 6, 7, 9).
///
/// Each turn asks the daemon first: a connection is the probe. With the
/// daemon there, the line asks on a short connection whether it may run
/// (`key_ready`); while the daemon says to wait (`key_wait`) it says so
/// once and asks again a tick later, holding no connection between asks.
/// Once it may run it asks for the PIN, if its line asks for one, with no
/// connection open, says to touch the key, and sends the check on a fresh
/// connection, waiting on the daemon's keepalives; a check stopped for a
/// lock waits again, keeping the PIN.
///
/// With the daemon truly down (its socket missing or refusing, and nothing
/// else), the line is stock Omarchy's pam_u2f line (fix round 10, item 6,
/// Mike's ruling): it asks for the PIN if its line asks for one, says to
/// touch the key and runs its private stack's check itself, with the
/// line's mirrored policy and the check's own touch window, then goes on
/// to the password. It asks nothing about the session's lock, logind's
/// records or where the request comes from, and waits for no unlock: a
/// hidden sudo can take a touch while the screen is locked during an
/// outage, as it can on stock Omarchy. "Down" is still asked every turn
/// and during the check: the check is stopped the moment the daemon
/// answers again, and a touch counts only if the daemon is still down at
/// that instant, so two checks never share the key; the line then goes
/// back to the daemon, keeping the PIN.
///
/// Every wait the daemon asks for on a verdict that is neither unlocked
/// nor a positive lock, and every check such a verdict cut off, is charged
/// to one wait budget for the whole line, never reset (round 8, Codex 1,
/// Opus F1), so churn between unknown, held and unlocked cannot hold it off
/// the password; once `unknown_limit` is spent it goes to the password, and
/// a check under way is given up then too, a direct one included when the
/// daemon went down after the line had waited on it. A positive lock is
/// waited on without a deadline, and the user's own PIN prompt costs
/// nothing.
fn key_line(env: &dyn KeyEnv, user: &str, want_pin: bool, timing: Timing) -> Said {
    let Some(ready) = request_line(user, Ask::KeyReady, None) else {
        return Said::Unreachable;
    };
    let told = std::cell::Cell::new(false);
    let mut cued = false;
    let mut pin: Option<Wiped> = None;
    let mut budget = WaitBudget::default();
    // One look charged to the budget: whether it is spent on a wait.
    let spent_on = |budget: &mut WaitBudget, v: Verdict, now: Duration| {
        budget.observe(v, now) >= timing.unknown_limit
            && matches!(v, Verdict::Unknown | Verdict::Held)
    };
    let left = |budget: &WaitBudget| timing.unknown_limit.saturating_sub(budget.spent());
    // A card on screen holding the key is free for `unknown_limit` of such
    // waits in all, then counts (round 8, Opus L6).
    let card_spent = |budget: &mut WaitBudget, now: Duration| {
        budget.observe_card(now, timing.unknown_limit) >= timing.unknown_limit
    };
    // A wait on the hold after an unlock is short: asked four times as
    // often, so approvals open about one hold after a real unlock.
    let wait = |env: &dyn KeyEnv, kind: Verdict| {
        if !told.replace(true) {
            env.tell_wait();
        }
        env.sleep(if kind == Verdict::Held {
            timing.tick / 4
        } else {
            timing.tick
        });
    };
    let abandoned = || env.agent().is_some_and(Agent::hung_up);
    loop {
        // A wait behind a positive lock has no deadline; polkit's agent
        // hanging up ends it (round 16, Opus N3).
        if abandoned() {
            return Said::Abandoned;
        }
        match env.connect() {
            Ok(stream) => {
                match exchange_within(
                    stream,
                    &ready,
                    timing.liveness,
                    Ask::KeyReady,
                    None,
                    env.agent(),
                ) {
                    Said::Ready => {
                        let _ = budget.observe(Verdict::Unlocked, env.now());
                    }
                    Said::Wait(kind) => {
                        if spent_on(&mut budget, kind, env.now()) {
                            return Said::Unreachable;
                        }
                        wait(env, kind);
                        continue;
                    }
                    Said::CardWait => {
                        if card_spent(&mut budget, env.now()) {
                            return Said::Unreachable;
                        }
                        wait(env, Verdict::Locked);
                        continue;
                    }
                    other => return other,
                }
                if budget.spent() >= timing.unknown_limit {
                    return Said::Unreachable;
                }
                if want_pin && pin.is_none() {
                    match env.ask_pin() {
                        Some(p) => pin = Some(p),
                        None => return Said::Unreachable,
                    }
                }
                let pin_text = pin.as_ref().and_then(|p| std::str::from_utf8(&p.0).ok());
                let Some(req) = request_line(user, Ask::KeyFallback, pin_text) else {
                    return Said::Unreachable;
                };
                let stream = match env.connect() {
                    Ok(s) => s,
                    // Gone between the two: the direct key, next turn.
                    Err(Said::Down) => continue,
                    Err(e) => return e,
                };
                if !cued {
                    cued = true;
                    env.cue();
                }
                let started = env.now();
                // A check is given up when the budget runs out; with none
                // spent yet, the daemon's own deadline bounds it.
                let cap = (budget.spent() > Duration::ZERO).then(|| left(&budget));
                match exchange_within(
                    stream,
                    &req,
                    timing.liveness,
                    Ask::KeyFallback,
                    cap,
                    env.agent(),
                ) {
                    Said::Wait(kind) => {
                        budget.owe(env.now().saturating_sub(started));
                        if spent_on(&mut budget, kind, env.now()) {
                            return Said::Unreachable;
                        }
                        wait(env, kind);
                    }
                    Said::CardWait => {
                        if card_spent(&mut budget, env.now()) {
                            return Said::Unreachable;
                        }
                        wait(env, Verdict::Locked);
                    }
                    other => return other,
                }
            }
            Err(Said::Down) => {
                // faceauthd is down: stock Omarchy's key line (fix round
                // 10, item 6). No lock gate, no compositor, no logind, and
                // no prompt or cue of the module's own: pam_u2f's own go
                // through to the caller (fix round 11, Codex 4).
                if !env.direct_ok() {
                    return Said::Unreachable;
                }
                // The time since the daemon's last answer, and a capped
                // check that was stopped, settle into the budget now; the
                // outage itself is no wait and costs nothing.
                if budget.observe(Verdict::Unlocked, env.now()) >= timing.unknown_limit {
                    return Said::Unreachable;
                }
                let started = env.now();
                // The check's own window bounds it; a line that already
                // waited on the daemon keeps only what is left of its
                // budget, so the two together stay inside the password
                // deadline.
                let by = (budget.spent() > Duration::ZERO).then(|| started + left(&budget));
                let down = || matches!(env.connect(), Err(Said::Down));
                let still = || by.is_none_or(|by| env.now() < by) && down() && !abandoned();
                match env.check(&still) {
                    // Only while the daemon is still down: two checks never
                    // share the key.
                    // A touch that polkit's agent's hang-up raced is
                    // no approval (round 16b, Codex 3).
                    Ended::Code(_) if abandoned() => return Said::Abandoned,
                    Ended::Code(code) if code == KEY_TOUCHED && down() => return Said::Match,
                    Ended::Code(code) if code == KEY_TOUCHED => {
                        budget.owe(env.now().saturating_sub(started));
                    }
                    Ended::Stopped => {
                        budget.owe(env.now().saturating_sub(started));
                    }
                    _ => return Said::Other,
                }
            }
            Err(other) => return other,
        }
    }
}

/// The lane the key check runs on for this PAM service: sudo's stacks
/// (`sudo-i` includes sudo's) and polkit's, and no other.
fn lane_of_service(service: &str) -> Option<&'static str> {
    match service {
        "sudo" | "sudo-i" => Some("sudo"),
        "polkit-1" => Some("polkit"),
        _ => None,
    }
}

/// How a helper run ended.
#[derive(Debug, PartialEq)]
enum Ended {
    /// Its one-byte answer.
    Code(u8),
    /// No answer: killed at its deadline, not started, or not one byte.
    Failed,
    /// Killed because `still` said no.
    Stopped,
}

/// Run the stock check and carry its conversation (fix round 11, Codex
/// 4): lines on the child's stdout, `Q <style> <hex>` for a message, each
/// handed to `relay` and answered on its stdin (`A <hex>`, or `N` for no
/// answer), and `R <code>` for the answer. `still` is asked every `tick`
/// outside a prompt; the child is killed the moment it says no
/// (`Stopped`), and at `limit` (`Failed`), counted without the time
/// `relay` took, which is the user's own (a PIN being typed). A line too
/// long, or one that is none of these, is no answer.
#[cfg(test)]
fn run_converse(
    cmd: std::process::Command,
    limit: Duration,
    tick: Duration,
    still: &dyn Fn() -> bool,
    relay: &mut dyn FnMut(c_int, &[u8]) -> Option<Wiped>,
) -> Ended {
    run_converse_full(cmd, limit, tick, still, &|| false, HELPER_WITHIN, relay)
}

/// The longest a stock check may run in all, prompt time included: the
/// helper's own deadline (60 s, `faceauth-keycheck`) and a margin (fix
/// round 12, Codex 2, Opus N2).
const HELPER_WITHIN: Duration = Duration::from_secs(65);

/// `run_converse`, and while a prompt waits on the user the child is
/// watched on a thread of its own (fix round 12, Codex 2, Opus N2): it is
/// killed the moment `back` says faceauthd is back, or at `overall` from
/// the start, prompt time included, so a prompt the caller holds open never
/// holds the key's lease; a run killed so is `Failed` once the prompt
/// returns, and the line goes to the password. `back` runs on that thread,
/// so it reads nothing of the PAM handle.
fn run_converse_full(
    mut cmd: std::process::Command,
    limit: Duration,
    tick: Duration,
    still: &dyn Fn() -> bool,
    back: &(dyn Fn() -> bool + Sync),
    overall: Duration,
    relay: &mut dyn FnMut(c_int, &[u8]) -> Option<Wiped>,
) -> Ended {
    use std::os::fd::AsRawFd;
    use std::process::Stdio;
    const LINE_MAX: usize = 4096;
    // The answers go down a socket, not a pipe, sent with MSG_NOSIGNAL: a
    // helper that died meanwhile is a failed send, never a SIGPIPE in the
    // PAM caller, whose disposition is not this module's to know.
    let Ok((to, theirs)) = UnixStream::pair() else {
        return Ended::Failed;
    };
    cmd.stdin(Stdio::from(std::os::fd::OwnedFd::from(theirs)))
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let Some((mut child, pidfd)) = spawn_with_pidfd(&mut cmd) else {
        return Ended::Failed;
    };
    let Some(mut from) = child.stdout.take() else {
        kill_pid(&pidfd);
        reap(&pidfd);
        return Ended::Failed;
    };
    let send = |bytes: &[u8]| -> bool {
        let mut sent = 0;
        while sent < bytes.len() {
            // SAFETY: a send on a socket this function owns, of a slice and
            // its length; MSG_NOSIGNAL raises no SIGPIPE.
            let n = unsafe {
                libc::send(
                    to.as_raw_fd(),
                    bytes[sent..].as_ptr().cast(),
                    bytes.len() - sent,
                    libc::MSG_NOSIGNAL,
                )
            };
            if n <= 0 {
                return false;
            }
            sent += n as usize;
        }
        true
    };
    let t0 = Instant::now();
    let hard_by = t0 + overall;
    let mut paused = Duration::ZERO;
    let mut next_look = t0 + tick;
    let mut line: Vec<u8> = Vec::new();
    let ended = 'run: loop {
        let now = Instant::now();
        let by = (t0 + limit + paused).min(hard_by);
        if now >= by {
            break Ended::Failed;
        }
        if now >= next_look {
            next_look = now + tick;
            if !still() {
                break Ended::Stopped;
            }
        }
        let wait = next_look.min(by).saturating_duration_since(now);
        let mut fds = [libc::pollfd {
            fd: from.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: one valid pollfd for the call, its count, a timeout.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 1, wait.as_millis().min(60_000) as c_int) };
        if n <= 0 {
            continue;
        }
        let mut buf = [0u8; 256];
        let k = match from.read(&mut buf) {
            Ok(0) => break Ended::Failed,
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break Ended::Failed,
        };
        for &b in &buf[..k] {
            if b != b'\n' {
                if line.len() >= LINE_MAX {
                    break 'run Ended::Failed;
                }
                line.push(b);
                continue;
            }
            let text = std::mem::take(&mut line);
            let mut words = text.splitn(3, |&c| c == b' ');
            match (words.next(), words.next(), words.next()) {
                (Some(b"R"), Some(code), None) => {
                    match std::str::from_utf8(code)
                        .ok()
                        .and_then(|c| c.parse::<u8>().ok())
                    {
                        Some(code) => break 'run Ended::Code(code),
                        None => break 'run Ended::Failed,
                    }
                }
                (Some(b"Q"), Some(style), Some(hex)) => {
                    let style = std::str::from_utf8(style)
                        .ok()
                        .and_then(|s| s.parse::<c_int>().ok());
                    let msg = std::str::from_utf8(hex).ok().and_then(lockgate::hex_decode);
                    let (Some(style), Some(msg)) = (style, msg) else {
                        break 'run Ended::Failed;
                    };
                    let asked = Instant::now();
                    let killed = std::sync::atomic::AtomicBool::new(false);
                    let done = std::sync::atomic::AtomicBool::new(false);
                    let answer = std::thread::scope(|scope| {
                        let watch = scope.spawn(|| {
                            use std::sync::atomic::Ordering::SeqCst;
                            while !done.load(SeqCst) {
                                if back() || Instant::now() >= hard_by {
                                    kill_pid(&pidfd);
                                    killed.store(true, SeqCst);
                                    return;
                                }
                                std::thread::sleep(tick);
                            }
                        });
                        let answer = relay(style, &msg);
                        done.store(true, std::sync::atomic::Ordering::SeqCst);
                        let _ = watch.join();
                        answer
                    });
                    paused += asked.elapsed();
                    if killed.load(std::sync::atomic::Ordering::SeqCst) {
                        drop(answer);
                        break 'run Ended::Failed;
                    }
                    let mut reply = match &answer {
                        Some(a) => format!("A {}\n", lockgate::hex_encode(&a.0)).into_bytes(),
                        None => b"N\n".to_vec(),
                    };
                    let sent = send(&reply);
                    reply.iter_mut().for_each(|b| *b = 0);
                    if !sent {
                        break 'run Ended::Failed;
                    }
                }
                _ => break 'run Ended::Failed,
            }
        }
    };
    if !matches!(ended, Ended::Code(_)) {
        kill_pid(&pidfd);
    }
    drop(to);
    reap(&pidfd);
    ended
}

/// Start `cmd` with its pidfd taken atomically (fix round 13, Codex 1):
/// the child opens a pidfd on itself between fork and exec, the last thing
/// it does before its exec, and passes it up a socket, so the descriptor
/// names that child and nothing else, whoever reaped it or reused its pid
/// since. A pidfd opened after the spawn by the child's pid could name
/// another process: a caller that ignores SIGCHLD has the kernel reap the
/// child the moment it exits, and anything of the caller's may reap it
/// first. As std does for its own pidfd spawn (unstable as of 1.98):
/// library/std/src/sys/process/unix/unix.rs, `send_pidfd`, `recv_pidfd`.
/// None when it did not start, or started and sent none, which cannot
/// happen (a failed send fails the child's pre-exec, and so its spawn): that
/// child is never signalled by pid, and ends by itself (its answers' end
/// closes, its own deadline, the parent-death signal).
fn spawn_with_pidfd(
    cmd: &mut std::process::Command,
) -> Option<(std::process::Child, std::os::fd::OwnedFd)> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    let mut pair = [-1 as c_int; 2];
    // SAFETY: socketpair fills the two-element array it is given.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } != 0
    {
        return None;
    }
    // SAFETY: socketpair returned two new descriptors that nothing else
    // owns; each OwnedFd is the only owner of its own.
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) };
    let up = theirs.as_raw_fd();
    // SAFETY: send_own_pidfd makes only async-signal-safe calls, on a
    // descriptor the child inherited open and the parent keeps open past
    // the spawn; close-on-exec, it is gone once the child runs the helper.
    unsafe { cmd.pre_exec(move || send_own_pidfd(up)) };
    let spawned = cmd.spawn();
    drop(theirs);
    let child = spawned.ok()?;
    recv_pidfd(&ours).map(|pidfd| (child, pidfd))
}

/// The room a control message with one descriptor takes.
const ONE_FD_SPACE: usize =
    // SAFETY: CMSG_SPACE is arithmetic on its argument.
    unsafe { libc::CMSG_SPACE(std::mem::size_of::<c_int>() as u32) } as usize;

/// A control message buffer for one descriptor, aligned as its header.
#[repr(C)]
union OneFd {
    buf: [u8; ONE_FD_SPACE],
    _align: libc::cmsghdr,
}

/// Between fork and exec: a pidfd on this process, sent up `sock` with
/// one byte, then closed here. Async-signal-safe: syscalls on the stack.
fn send_own_pidfd(sock: c_int) -> std::io::Result<()> {
    let last = std::io::Error::last_os_error;
    // SAFETY: getpid and pidfd_open take values and no pointers.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    if pidfd < 0 {
        return Err(last());
    }
    let pidfd = pidfd as c_int;
    // SAFETY: every pointer is to this frame's stack, valid for the call:
    // one byte of payload and a control buffer sized for one descriptor
    // (`OneFd`), filled through the CMSG macros.
    let sent = unsafe {
        let mut byte = *b"P";
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control: OneFd = std::mem::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = std::ptr::addr_of_mut!(control.buf).cast();
        msg.msg_controllen = ONE_FD_SPACE as _;
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        (*hdr).cmsg_level = libc::SOL_SOCKET;
        (*hdr).cmsg_type = libc::SCM_RIGHTS;
        (*hdr).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<c_int>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            (&pidfd as *const c_int).cast::<u8>(),
            libc::CMSG_DATA(hdr),
            std::mem::size_of::<c_int>(),
        );
        libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL)
    };
    let err = last();
    // SAFETY: the pidfd this function opened, closed once.
    unsafe { libc::close(pidfd) };
    if sent == 1 {
        Ok(())
    } else {
        Err(err)
    }
}

/// The pidfd the child sent up `sock` before its exec (`send_own_pidfd`):
/// there already when the spawn returns, so never waited for; None for
/// anything but one descriptor in one message.
fn recv_pidfd(sock: &std::os::fd::OwnedFd) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    // SAFETY: every pointer is to this frame's stack, valid for the call,
    // with the lengths of what it points to; the descriptor copied out is
    // one the kernel just installed in this process, owned by no one else.
    unsafe {
        let mut byte = [0u8];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control: OneFd = std::mem::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = std::ptr::addr_of_mut!(control.buf).cast();
        msg.msg_controllen = ONE_FD_SPACE as _;
        let n = libc::recvmsg(
            sock.as_raw_fd(),
            &mut msg,
            libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
        );
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        if n != 1 || hdr.is_null() {
            return None;
        }
        let mut fd: c_int = -1;
        if (*hdr).cmsg_level == libc::SOL_SOCKET
            && (*hdr).cmsg_type == libc::SCM_RIGHTS
            && (*hdr).cmsg_len as usize
                == libc::CMSG_LEN(std::mem::size_of::<c_int>() as u32) as usize
        {
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(hdr),
                (&mut fd as *mut c_int).cast::<u8>(),
                std::mem::size_of::<c_int>(),
            );
        }
        if fd < 0 {
            return None;
        }
        let fd = OwnedFd::from_raw_fd(fd);
        (msg.msg_flags & libc::MSG_CTRUNC == 0).then_some(fd)
    }
}

/// Stop the child through its own pidfd, from any thread: a pidfd names
/// one process for its life, never one that reused its pid. SIGTERM
/// (round 19): the key helper answers it by cancelling the key's wait, so
/// the key stops blinking with the check, and then exits; `reap` kills
/// what has not ended by `STOP_GRACE`.
fn kill_pid(pidfd: &std::os::fd::OwnedFd) {
    signal_pid(pidfd, libc::SIGTERM);
}

/// How long a stopped helper has to end on SIGTERM before it is killed:
/// past the helper's own cancel grace (half a second).
const STOP_GRACE: Duration = Duration::from_millis(800);

fn signal_pid(pidfd: &std::os::fd::OwnedFd, sig: c_int) {
    use std::os::fd::AsRawFd;
    // SAFETY: a valid pidfd, a signal number, no info pointer.
    let _ = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
}

/// Whether the child its pidfd names has ended: reaped now, or not ours
/// to wait for (a caller that ignores SIGCHLD has the kernel reap it, and
/// one that reaps its own children may have); false while it runs.
/// `waitid(P_PIDFD, ..)` waits on that process alone (Linux 5.4).
fn ended_through(pidfd: &std::os::fd::OwnedFd, flags: c_int) -> bool {
    use std::os::fd::AsRawFd;
    loop {
        // SAFETY: an all-zero siginfo_t is a valid out-parameter.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: a pidfd, a valid out-pointer, and the wait's flags.
        let r = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pidfd.as_raw_fd() as libc::id_t,
                &mut info,
                libc::WEXITED | flags,
            )
        };
        if r < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return true;
        }
        // SAFETY: si_pid is set by a waitid that returned 0; zero means
        // nothing had ended under WNOHANG.
        return unsafe { info.si_pid() } != 0;
    }
}

/// Reap the child through its pidfd: within `STOP_GRACE`, or killed
/// through it (SIGKILL) and then waited for.
fn reap(pidfd: &std::os::fd::OwnedFd) {
    let by = Instant::now() + STOP_GRACE;
    loop {
        if ended_through(pidfd, libc::WNOHANG) {
            return;
        }
        if Instant::now() > by {
            signal_pid(pidfd, libc::SIGKILL);
            let _ = ended_through(pidfd, 0);
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A helper the module runs as root: a regular file, no symlink, and it
/// and every directory above it root's and closed to group and other
/// writers, as the daemon holds its private stacks.
fn root_only_path(p: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let root_only = |md: &std::fs::Metadata| md.uid() == 0 && md.mode() & 0o022 == 0;
    std::fs::symlink_metadata(p).is_ok_and(|md| md.file_type().is_file() && root_only(&md))
        && p.parent()
            .and_then(|d| std::fs::canonicalize(d).ok())
            .is_some_and(|d| {
                d.ancestors()
                    .all(|a| std::fs::metadata(a).is_ok_and(|md| root_only(&md)))
            })
}

/// The user's uid and primary gid, from the system's user database.
fn user_ids(user: &str) -> Option<(u32, u32)> {
    let name = std::ffi::CString::new(user).ok()?;
    // SAFETY: an all-zero passwd is a valid out-parameter for getpwnam_r.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as c_char; 16 * 1024];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call, and buf's length is
    // passed with it.
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        )
    };
    (rc == 0 && !out.is_null()).then_some((pw.pw_uid, pw.pw_gid))
}

/// Between fork and exec: a session, and so a process group, of the
/// child's own. Async-signal-safe.
fn new_session() -> std::io::Result<()> {
    // SAFETY: setsid takes nothing and touches only the calling process.
    if unsafe { libc::setsid() } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Between fork and exec: the key check's child becomes plain root, real
/// and effective, with no supplementary groups, as the daemon's unit runs
/// it; it may not dump core (round 6, Opus N4: the PIN is in its memory,
/// and polkit's helper runs with no core limit); it takes SIGCHLD's default
/// back, and dies with the module's process.
fn become_root(parent: libc::pid_t) -> std::io::Result<()> {
    let last = std::io::Error::last_os_error;
    let no_core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain syscalls on values; `no_core` outlives the call.
    unsafe {
        if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0
            || libc::setgroups(0, std::ptr::null()) != 0
            || libc::setresgid(0, 0, 0) != 0
            || libc::setresuid(0, 0, 0) != 0
            // SIGTERM (round 19): the helper cancels the key's wait and
            // exits, so a PAM caller that dies leaves no key blinking.
            || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0
        {
            return Err(last());
        }
        libc::signal(libc::SIGCHLD, libc::SIG_DFL);
        // A session of its own (fix round 12, Opus N2): the terminal's
        // Ctrl-Z and signals to sudo's process group never reach it.
        new_session()?;
        if libc::getppid() != parent {
            return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
        }
    }
    Ok(())
}

/// One stock key check by the package's helper (`faceauth-keycheck
/// --converse`, fix round 11, Codex 4): pam_u2f on the private stack that
/// carries `lane`'s own line words, as root, a clean environment, no core
/// dump, every message of its conversation handed to `relay` and every
/// answer passed back (`run_converse`), killed after the touch window (not
/// counting the time a prompt waits on the user) or the moment `still`
/// says no.
fn key_check_direct(
    lane: &str,
    user: &str,
    still: &dyn Fn() -> bool,
    back: &(dyn Fn() -> bool + Sync),
    timing: Timing,
    relay: &mut dyn FnMut(c_int, &[u8]) -> Option<Wiped>,
) -> Ended {
    use std::os::unix::process::CommandExt;
    let parent = std::process::id() as libc::pid_t;
    let mut c = std::process::Command::new(KEYCHECK_HELPER);
    c.arg("--converse")
        .arg(lane)
        .arg(user)
        .env_clear()
        .env("PATH", "/usr/bin")
        .current_dir("/");
    // SAFETY: become_root makes only async-signal-safe calls.
    unsafe { c.pre_exec(move || become_root(parent)) };
    run_converse_full(
        c,
        timing.fallback_deadline,
        timing.still_tick,
        still,
        back,
        HELPER_WITHIN,
        relay,
    )
}

/// The key's lease file (`lockgate::KEY_LEASE`), made when it is missing:
/// root's, 0600, never truncated, no link followed. The package's tmpfiles
/// entry makes it at boot; where this cannot (polkit's helper with a
/// read-only /run), the check finds no lease and goes to the password.
fn ensure_key_lease() {
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(lockgate::KEY_LEASE);
}

/// The PAM service's name.
fn pam_service(pamh: *const pam_handle_t) -> Option<String> {
    let mut item: *const c_void = std::ptr::null();
    // SAFETY: pamh is PAM's handle; item is a valid out-pointer.
    if unsafe { pam_get_item(pamh, PAM_SERVICE, &mut item) } != PAM_SUCCESS || item.is_null() {
        return None;
    }
    // SAFETY: PAM_SERVICE is a NUL-terminated string PAM owns for the life
    // of the handle, and the pointer was checked not null.
    Some(
        unsafe { CStr::from_ptr(item as *const c_char) }
            .to_string_lossy()
            .into_owned(),
    )
}

/// What the direct key needs, found the first time the daemon is down.
struct Direct {
    lane: &'static str,
}

/// The key-fallback line's world in a PAM transaction.
struct PamEnv<'a> {
    pamh: *const pam_handle_t,
    socket: &'a Path,
    user: &'a str,
    cue: bool,
    t0: Instant,
    direct: std::cell::OnceCell<Option<Direct>>,
    agent: Option<Agent>,
}

impl<'a> PamEnv<'a> {
    fn new(
        pamh: *const pam_handle_t,
        socket: &'a Path,
        user: &'a str,
        cue: bool,
        agent: Option<Agent>,
    ) -> Self {
        PamEnv {
            pamh,
            socket,
            user,
            cue,
            t0: Instant::now(),
            direct: std::cell::OnceCell::new(),
            agent,
        }
    }

    /// The direct key's facts, or why it cannot run (logged once).
    fn direct(&self) -> Option<&Direct> {
        self.direct
            .get_or_init(|| {
                let no = |why: &str| {
                    log(self.pamh, &format!("faceauthd is down and {}: no key", why));
                    None
                };
                // SAFETY: geteuid has no preconditions.
                if unsafe { libc::geteuid() } != 0 {
                    return no("this process is not root");
                }
                let Some(lane) = pam_service(self.pamh).as_deref().and_then(lane_of_service)
                else {
                    return no("this is not sudo's or polkit's stack");
                };
                if user_ids(self.user).is_none_or(|(uid, _)| uid == 0) {
                    return no("the user is root or unknown");
                }
                if !root_only_path(Path::new(KEYCHECK_HELPER)) {
                    return no("its key check is missing or not root's alone");
                }
                log(
                    self.pamh,
                    &format!(
                        "user {}: faceauthd is down; the key line asks the key itself, as stock pam_u2f does",
                        sanitise(self.user)
                    ),
                );
                Some(Direct { lane })
            })
            .as_ref()
    }
}

impl KeyEnv for PamEnv<'_> {
    fn connect(&self) -> Result<UnixStream, Said> {
        connect_daemon(self.pamh, self.socket)
    }
    fn agent(&self) -> Option<Agent> {
        self.agent
    }

    fn ask_pin(&self) -> Option<Wiped> {
        ask_pin(self.pamh)
    }

    fn tell_wait(&self) {
        let _ = converse(self.pamh, PAM_TEXT_INFO, WAIT_TEXT);
    }

    fn cue(&self) {
        if self.cue {
            let _ = converse(self.pamh, PAM_TEXT_INFO, "Touch your security key.");
        }
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }

    fn now(&self) -> Duration {
        self.t0.elapsed()
    }

    fn direct_ok(&self) -> bool {
        self.direct().is_some()
    }

    fn check(&self, still: &dyn Fn() -> bool) -> Ended {
        let Some(d) = self.direct() else {
            return Ended::Failed;
        };
        ensure_key_lease();
        // pam_u2f's own prompts (its PIN, once per credential that asks)
        // and messages go to the caller as stock pam_u2f's would; its cue
        // only when the line says `cue`, as the line's own pam_u2f would.
        let mut relay = |style: c_int, text: &[u8]| {
            let text = String::from_utf8_lossy(text);
            match style {
                PAM_PROMPT_ECHO_OFF | PAM_PROMPT_ECHO_ON => converse(self.pamh, style, &text),
                PAM_TEXT_INFO if !self.cue => Some(Wiped(Vec::new())),
                PAM_TEXT_INFO | PAM_ERROR_MSG => {
                    let _ = converse(self.pamh, style, &text);
                    Some(Wiped(Vec::new()))
                }
                _ => None,
            }
        };
        // Watched while a prompt waits: faceauthd back, by its socket alone
        // (the PAM handle is not this thread's to use).
        let socket = self.socket.to_path_buf();
        let back = move || !matches!(connect_to(&socket), Err(Said::Down));
        key_check_direct(d.lane, self.user, still, &back, Timing::REAL, &mut relay)
    }
}

/// The daemon serializes the tag first and always follows it with more
/// fields: the reply must BEGIN with the match object, so no later field
/// (which may echo request bytes) can ever make a non-match read as one. A
/// refusal is read the same way, and only on a consent line: a plain scan
/// and a key line have no answer no.
fn classify(line: &str, ask: Ask) -> Said {
    let t = line.trim_start();
    let consent = ask == Ask::Consent;
    if t.starts_with("{\"result\":\"match\",") {
        Said::Match
    } else if consent && t.starts_with("{\"result\":\"refused\",") {
        Said::Refused
    } else if consent && t.starts_with("{\"result\":\"refused_parked\",") {
        Said::RefusedParked
    } else if ask.key() && t.starts_with("{\"result\":\"key_wait\",") {
        let state = t["{\"result\":\"key_wait\",".len()..].strip_prefix("\"state\":\"");
        match state.and_then(|r| r.split('"').next()) {
            Some("card") => Said::CardWait,
            Some("locked") => Said::Wait(Verdict::Locked),
            Some("held") => Said::Wait(Verdict::Held),
            _ => Said::Wait(Verdict::Unknown),
        }
    } else if consent && t.trim_end() == "{\"result\":\"need_cookie\"}" {
        Said::NeedCookie
    } else if ask == Ask::KeyReady && t.trim_end() == "{\"result\":\"key_ready\"}" {
        Said::Ready
    } else if t.starts_with("{\"result\":\"error\",") {
        Said::Error
    } else if t.starts_with("{\"result\":") {
        Said::Other
    } else {
        Said::Unreachable
    }
}

/// The PAM code for what the daemon said on a line of this kind. A key
/// line succeeds on a match and fails on everything else. A consent line
/// answers PAM_AUTHINFO_UNAVAIL for a parked refusal, the daemon's error
/// and every failure to reach it; under Omarchy's controls that goes on,
/// as an ignore does, to the stack's key-fallback line, which goes
/// through the daemon too.
fn pam_code(said: Said, ask: Ask) -> c_int {
    match (ask, said) {
        (_, Said::Match) => PAM_SUCCESS,
        (_, Said::Abandoned) => PAM_AUTH_ERR,
        (Ask::KeyFallback | Ask::KeyUnlock | Ask::KeyReady, _) => PAM_AUTH_ERR,
        // faceauthd down: the stack's stock pam_fprintd line runs next.
        (Ask::FprintUnlock, Said::Down) => PAM_IGNORE,
        (Ask::FprintUnlock, _) => PAM_AUTH_ERR,
        (Ask::Consent, Said::Refused) => PAM_AUTH_ERR,
        (
            Ask::Consent,
            Said::RefusedParked | Said::Error | Said::Unreachable | Said::Down | Said::NeedCookie,
        ) => PAM_AUTHINFO_UNAVAIL,
        _ => PAM_IGNORE,
    }
}

/// What a line of this kind answers when the module cannot get to the
/// daemon's answer at all (no user, a remote host, a panic).
fn no_answer(ask: Option<Ask>) -> c_int {
    match ask {
        None => PAM_AUTH_ERR,
        Some(ask) => pam_code(Said::Unreachable, ask),
    }
}

fn authenticate(pamh: *mut pam_handle_t, argc: c_int, argv: *const *const c_char) -> c_int {
    let args = parse_args(pamh, argc, argv);
    let Some(ask) = ask_of(&args) else {
        log(
            pamh,
            "more than one of consent, key-fallback, key-unlock and fprint-unlock on one line: nothing is asked, auth error",
        );
        return PAM_AUTH_ERR;
    };
    let no = no_answer(Some(ask));
    let mut user_ptr: *const c_char = std::ptr::null();
    // SAFETY: pamh is the handle PAM gave us; user_ptr is a valid out-pointer.
    let rc = unsafe { pam_get_user(pamh, &mut user_ptr, std::ptr::null()) };
    if rc != PAM_SUCCESS || user_ptr.is_null() {
        return no;
    }
    // A name that is not UTF-8 is refused, not rewritten: a rewritten name
    // would ask the daemon about a different user than PAM_USER.
    // SAFETY: pam_get_user succeeded and user_ptr is not null, so it points
    // to PAM's NUL-terminated user name, which lives as long as the handle.
    let Ok(user) = unsafe { CStr::from_ptr(user_ptr) }
        .to_str()
        .map(str::to_owned)
    else {
        log(pamh, "user name is not UTF-8, ignoring");
        return no;
    };
    if user.is_empty() || user.len() > 256 {
        return no;
    }
    // A remote host on the transaction means a network login (sshd sets it):
    // the camera cannot vouch for that caller, so no scan. The daemon checks
    // the caller's ancestry and logind session itself; this is the cheap
    // first gate, not the trusted one.
    let mut rhost: *const c_void = std::ptr::null();
    // SAFETY: pamh is PAM's handle; rhost is a valid out-pointer.
    if unsafe { pam_get_item(pamh, PAM_RHOST, &mut rhost) } == PAM_SUCCESS && !rhost.is_null() {
        // SAFETY: PAM_RHOST is a NUL-terminated string PAM owns for the
        // life of the handle, and the pointer was checked not null.
        let host = unsafe { CStr::from_ptr(rhost as *const c_char) }.to_string_lossy();
        if !host.is_empty() {
            log(
                pamh,
                &format!(
                    "user {}: remote host {} on the transaction, no scan",
                    sanitise(&user),
                    sanitise(&host)
                ),
            );
            return no;
        }
    }
    let t0 = std::time::Instant::now();
    let said = daemon_says(
        pamh,
        Path::new(&args.socket),
        &user,
        args.timeout,
        ask,
        args.cue,
        ask == Ask::KeyFallback && wants_pin(line_pin(&args), u2f_conf_text().as_deref()),
    );
    let code = pam_code(said, ask);
    log(
        pamh,
        &format!(
            "user {}: {} after {} ms",
            sanitise(&user),
            match (said, code) {
                (Said::Match, _) => "match, success",
                (Said::Abandoned, _) => "polkit's agent hung up, auth error",
                (_, PAM_AUTH_ERR) if ask.key() => "no key touch, auth error",
                (Said::Down, PAM_IGNORE) if ask == Ask::FprintUnlock => {
                    "faceauthd is down, ignore: the stock fingerprint line runs"
                }
                (_, PAM_AUTH_ERR) if ask == Ask::FprintUnlock => "no fingerprint match, auth error",
                (Said::Refused, _) => "refused by the user, auth error",
                (Said::RefusedParked, _) => "unapproved while locked, authinfo unavailable",
                (Said::Error, PAM_AUTHINFO_UNAVAIL) => "daemon error, authinfo unavailable",
                (Said::Unreachable, PAM_AUTHINFO_UNAVAIL) => "no daemon, authinfo unavailable",
                _ => "no match or no daemon, ignore",
            },
            t0.elapsed().as_millis()
        ),
    );
    code
}

/// The line's kind, read on its own, so a panic in the request still
/// answers as its kind does: a key line fails, a consent line is
/// PAM_AUTHINFO_UNAVAIL. None for two kind words on one line.
fn kind_of(argc: c_int, argv: *const *const c_char) -> Option<Ask> {
    let mut kinds = (false, false, false, false);
    if !argv.is_null() {
        for i in 0..argc.max(0) as usize {
            // SAFETY: PAM passes argc valid C strings.
            let p = unsafe { *argv.add(i) };
            if p.is_null() {
                continue;
            }
            // SAFETY: a non-null argument is one of PAM's C strings.
            match unsafe { CStr::from_ptr(p) }.to_bytes() {
                b"consent" => kinds.0 = true,
                b"key-fallback" => kinds.1 = true,
                b"key-unlock" => kinds.2 = true,
                b"fprint-unlock" => kinds.3 = true,
                _ => {}
            }
        }
    }
    kind_from(kinds.0, kinds.1, kinds.2, kinds.3)
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let failed = catch_unwind(|| no_answer(kind_of(argc, argv))).unwrap_or(PAM_AUTH_ERR);
    catch_unwind(AssertUnwindSafe(|| authenticate(pamh, argc, argv))).unwrap_or(failed)
}

/// Credentials: nothing to establish, and success rather than ignore. On
/// the lock stack a face success freezes the chain and `pam_setcred` then
/// runs on into `pam_deny`'s setcred; an ignore here made that transaction
/// answer PAM_CRED_ERR, where pam_fprintd and pam_u2f answer success.
#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut pam_handle_t,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_IGNORE
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(user: &str, ask: Ask, pin: Option<&str>) -> Option<String> {
        request_line(user, ask, pin).map(|w| String::from_utf8(w.0.clone()).unwrap())
    }

    #[test]
    fn replies_are_read_by_their_leading_tag_only() {
        let all = [Ask::Look, Ask::Consent, Ask::KeyFallback, Ask::KeyUnlock];
        for ask in all {
            assert_eq!(
                classify("{\"result\":\"match\",\"frames\":2}", ask),
                Said::Match
            );
            assert_eq!(
                classify(
                    "{\"result\":\"no_match\",\"message\":\"{\\\"result\\\":\\\"match\\\",\"}",
                    ask
                ),
                Said::Other
            );
            assert_eq!(
                classify("{\"result\":\"error\",\"message\":\"busy\"}", ask),
                Said::Error
            );
            assert_eq!(classify("", ask), Said::Unreachable);
            assert_eq!(classify("garbage", ask), Said::Unreachable);
        }
        assert_eq!(
            classify(
                "{\"result\":\"refused\",\"reason\":\"shaken\",\"elapsed_ms\":5}",
                Ask::Consent
            ),
            Said::Refused
        );
        assert_eq!(
            classify(
                "{\"result\":\"refused_parked\",\"reason\":\"dismissed\",\"elapsed_ms\":5}",
                Ask::Consent
            ),
            Said::RefusedParked
        );
        for ask in [Ask::Look, Ask::KeyFallback, Ask::KeyUnlock] {
            assert_eq!(
                classify("{\"result\":\"refused\",\"reason\":\"shaken\"}", ask),
                Said::Other,
                "only a consent line has an answer no"
            );
            assert_eq!(
                classify("{\"result\":\"refused_parked\",\"reason\":\"x\"}", ask),
                Said::Other
            );
        }
        assert_eq!(
            classify(
                "{\"result\":\"consent_denied\",\"reason\":\"no answer\"}",
                Ask::Consent
            ),
            Said::Other
        );
    }

    /// Round 4: each answer's PAM code, by line kind. A consent line's
    /// parked refusal, the daemon's error and every way of not reaching it
    /// (the connection cap's busy, no daemon, a panic) are
    /// PAM_AUTHINFO_UNAVAIL on sudo and polkit alike, which goes on to the
    /// key-fallback line through the daemon; the user's no at a card is
    /// PAM_AUTH_ERR (polkit's `auth_err=die`), and a denial sudo gets after
    /// a no is an ignore, so sudo's key line runs next. A key line fails
    /// on everything but a match.
    #[test]
    fn each_answer_has_its_pam_code() {
        assert_eq!(PAM_AUTH_ERR, 7);
        assert_eq!(PAM_AUTHINFO_UNAVAIL, 9);
        assert_eq!(PAM_CONV, 5);
        assert_ne!(PAM_AUTHINFO_UNAVAIL, PAM_IGNORE);
        assert_eq!(pam_code(Said::Match, Ask::Consent), PAM_SUCCESS);
        assert_eq!(pam_code(Said::Refused, Ask::Consent), PAM_AUTH_ERR);
        assert_eq!(pam_code(Said::Other, Ask::Consent), PAM_IGNORE);
        for said in [Said::RefusedParked, Said::Error, Said::Unreachable] {
            assert_eq!(
                pam_code(said, Ask::Consent),
                PAM_AUTHINFO_UNAVAIL,
                "{:?}",
                said
            );
        }
        assert_eq!(pam_code(Said::Match, Ask::Look), PAM_SUCCESS);
        for said in [Said::Other, Said::Error, Said::Unreachable] {
            assert_eq!(pam_code(said, Ask::Look), PAM_IGNORE);
        }
        for ask in [Ask::KeyFallback, Ask::KeyUnlock] {
            assert_eq!(pam_code(Said::Match, ask), PAM_SUCCESS);
            for said in [
                Said::Refused,
                Said::RefusedParked,
                Said::Error,
                Said::Unreachable,
                Said::Other,
            ] {
                assert_eq!(pam_code(said, ask), PAM_AUTH_ERR, "{:?} {:?}", ask, said);
            }
        }
        assert_eq!(no_answer(Some(Ask::Consent)), PAM_AUTHINFO_UNAVAIL);
        assert_eq!(no_answer(Some(Ask::KeyFallback)), PAM_AUTH_ERR);
        assert_eq!(no_answer(Some(Ask::KeyUnlock)), PAM_AUTH_ERR);
        assert_eq!(no_answer(Some(Ask::Look)), PAM_IGNORE);
        assert_eq!(no_answer(None), PAM_AUTH_ERR);
    }

    fn argv(words: &[&str]) -> (Vec<std::ffi::CString>, Vec<*const c_char>) {
        let owned: Vec<std::ffi::CString> = words
            .iter()
            .map(|w| std::ffi::CString::new(*w).unwrap())
            .collect();
        let ptrs = owned.iter().map(|c| c.as_ptr()).collect();
        (owned, ptrs)
    }

    /// Round 4: the line's kind is read on its own for a panic's answer,
    /// and two kind words ask nothing and fail.
    #[test]
    fn the_kind_is_read_on_its_own_and_two_kinds_fail() {
        for (words, want) in [
            (vec!["socket=/x"], Some(Ask::Look)),
            (vec!["consent"], Some(Ask::Consent)),
            (vec!["key-fallback", "cue"], Some(Ask::KeyFallback)),
            (vec!["key-unlock"], Some(Ask::KeyUnlock)),
            (vec!["consent", "key-fallback"], None),
            (vec!["key-unlock", "key-fallback"], None),
        ] {
            let (_o, p) = argv(&words);
            assert_eq!(kind_of(p.len() as c_int, p.as_ptr()), want, "{:?}", words);
            assert_eq!(ask_of(&parse(&words)), want, "{:?}", words);
        }
        assert_eq!(kind_of(0, std::ptr::null()), Some(Ask::Look));
    }

    /// The fingerprint line's kind is a word of its own, alone on its line,
    /// and its request is the one the daemon reads as `fprint_unlock`.
    #[test]
    fn the_fingerprint_line_is_a_kind_of_its_own() {
        for (words, want) in [
            (vec!["socket=/x", "fprint-unlock"], Some(Ask::FprintUnlock)),
            (vec!["fprint-unlock", "key-unlock"], None),
            (vec!["consent", "fprint-unlock"], None),
            (vec!["fprint-unlock", "key-fallback"], None),
        ] {
            let (_o, p) = argv(&words);
            assert_eq!(kind_of(p.len() as c_int, p.as_ptr()), want, "{:?}", words);
            assert_eq!(ask_of(&parse(&words)), want, "{:?}", words);
        }
        let l = line("alice", Ask::FprintUnlock, Some("1234")).unwrap();
        assert_eq!(
            l, "{\"user\":\"alice\",\"fprint_unlock\":true}\n",
            "no PIN rides on it"
        );
        assert_eq!(
            faceauth_daemon::server::request_op(&l),
            Some("fprint_unlock")
        );
        assert!(line("ali\"ce", Ask::FprintUnlock, None).is_none());
    }

    /// The fingerprint line succeeds on a match alone, ignores only with
    /// faceauthd down, so the stack's stock pam_fprintd line runs as on
    /// stock Omarchy, and fails on everything else: a daemon restarting, an
    /// error, no answer, a panic.
    #[test]
    fn the_fingerprint_line_ignores_only_with_faceauthd_down() {
        assert_eq!(pam_code(Said::Match, Ask::FprintUnlock), PAM_SUCCESS);
        assert_eq!(pam_code(Said::Down, Ask::FprintUnlock), PAM_IGNORE);
        for said in [
            Said::Unreachable,
            Said::Error,
            Said::Other,
            Said::Refused,
            Said::Abandoned,
            Said::Wait(Verdict::Locked),
        ] {
            assert_eq!(
                pam_code(said, Ask::FprintUnlock),
                PAM_AUTH_ERR,
                "{:?}",
                said
            );
        }
        assert_eq!(no_answer(Some(Ask::FprintUnlock)), PAM_AUTH_ERR);
        assert!(!Ask::FprintUnlock.key(), "no key_wait is read on it");
    }

    /// The fingerprint line passes each status the daemon's check reports
    /// to the conversation as pam_fprintd's own message would come, skips
    /// the keepalives, and takes the answer after them; a daemon down is
    /// `Down`, and one gone silent past the line's patience is no answer.
    #[test]
    fn the_fingerprint_line_passes_the_checks_status_to_the_lock_screen() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!("pam-faceauth-fprint-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut req = String::new();
            BufReader::new(&s).read_line(&mut req).unwrap();
            for l in [
                "{\"result\":\"fprint_status\",\"status\":\"place\"}\n",
                "{\"result\":\"pending\"}\n",
                "{\"result\":\"fprint_status\",\"status\":\"retry\"}\n",
                "{\"result\":\"fprint_status\",\"status\":\"Place your finger\"}\n",
                "{\"result\":\"match\",\"score\":null,\"frames\":0,\"elapsed_ms\":5}\n",
            ] {
                s.write_all(l.as_bytes()).unwrap();
            }
            req
        });
        let said = std::cell::RefCell::new(Vec::new());
        let connect = || UnixStream::connect(&path).map_err(|_| Said::Unreachable);
        let got = fprint_unlock_line(&connect, "alice", FAST, &|style, text| {
            said.borrow_mut().push((style, text.to_string()))
        });
        let req = server.join().unwrap();
        assert_eq!(req, "{\"user\":\"alice\",\"fprint_unlock\":true}\n");
        assert_eq!(
            got,
            Said::Other,
            "a status line the module does not know is no status, and ends the line"
        );
        assert_eq!(
            *said.borrow(),
            vec![
                (PAM_TEXT_INFO, FPRINT_PLACE.to_string()),
                (PAM_ERROR_MSG, FPRINT_RETRY.to_string())
            ]
        );
        std::fs::remove_file(&path).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut req = String::new();
            BufReader::new(&s).read_line(&mut req).unwrap();
            s.write_all(b"{\"result\":\"fprint_status\",\"status\":\"place\"}\n{\"result\":\"match\",\"score\":null,\"frames\":0,\"elapsed_ms\":5}\n")
                .unwrap();
        });
        let got = fprint_unlock_line(&connect, "alice", FAST, &|_, _| {});
        server.join().unwrap();
        assert_eq!(got, Said::Match);
        assert_eq!(
            fprint_unlock_line(&|| Err(Said::Down), "alice", FAST, &|_, _| {}),
            Said::Down
        );
        std::fs::remove_file(&path).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            std::thread::sleep(FAST.liveness * 3);
            drop(s);
        });
        let t = Instant::now();
        assert_eq!(
            fprint_unlock_line(&connect, "alice", FAST, &|_, _| {}),
            Said::Unreachable
        );
        assert!(
            t.elapsed() < FAST.liveness * 3,
            "a silent daemon is given up on"
        );
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_listener_that_is_not_root_is_not_the_daemon() {
        // A socket pair: both ends are this test's uid, so the peer is root
        // only when the test itself runs as root.
        let (a, _b) = UnixStream::pair().unwrap();
        // SAFETY: getuid has no preconditions.
        let me_root = unsafe { libc::getuid() } == 0;
        assert_eq!(peer_is_root(&a), me_root);
    }

    /// Round 4: no daemon is no match, and on a key line a failure, never
    /// an ignore that would let another line read the key. Round 5 (A): on
    /// the key-fallback line a socket that is missing is the daemon down,
    /// and the line runs the gated direct key only as root.
    #[test]
    fn no_daemon_is_not_a_match_and_fails_a_key_line() {
        for ask in [Ask::Look, Ask::Consent, Ask::KeyFallback, Ask::KeyUnlock] {
            let said = daemon_says(
                std::ptr::null(),
                Path::new("/nonexistent/faceauth.sock"),
                "alice",
                Duration::from_secs(1),
                ask,
                true,
                false,
            );
            // Round 6: the key-fallback line takes the down path itself; a
            // test is not root, so the direct key is not for it either.
            assert_eq!(said, Said::Unreachable, "{:?}", ask);
            assert_ne!(pam_code(said, ask), PAM_SUCCESS);
        }
        assert_eq!(pam_code(Said::Unreachable, Ask::KeyFallback), PAM_AUTH_ERR);
        assert_eq!(
            pam_code(Said::Unreachable, Ask::Consent),
            PAM_AUTHINFO_UNAVAIL
        );
    }

    /// 1: a daemon that takes a request and breaks off without a reply is
    /// no answer at all: AUTHINFO_UNAVAIL on a consent line, a failure on a
    /// key line.
    #[test]
    fn a_daemon_that_breaks_off_is_no_answer() {
        let dir = std::env::temp_dir().join(format!("pam_faceauth-hangup-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            for _ in 0..2 {
                let (mut c, _) = listener.accept().unwrap();
                let mut line = String::new();
                let _ = BufReader::new(&mut c).read_line(&mut line);
                drop(c);
            }
        });
        let consent = daemon_says(
            std::ptr::null(),
            &path,
            "alice",
            Duration::from_secs(2),
            Ask::Consent,
            false,
            false,
        );
        let key = daemon_says(
            std::ptr::null(),
            &path,
            "alice",
            Duration::from_secs(2),
            Ask::KeyFallback,
            false,
            false,
        );
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        // A listener that is not root is not the daemon at all, which is no
        // answer as well.
        assert_eq!(consent, Said::Unreachable);
        assert_eq!(key, Said::Unreachable);
        assert_eq!(pam_code(consent, Ask::Consent), PAM_AUTHINFO_UNAVAIL);
        assert_eq!(pam_code(key, Ask::KeyFallback), PAM_AUTH_ERR);
    }

    /// Round 4: a key-fallback line that needs the PIN and has no
    /// conversation to ask it on asks the daemon nothing.
    #[test]
    fn a_pin_line_without_a_conversation_asks_nothing() {
        assert!(converse(std::ptr::null(), PAM_PROMPT_ECHO_OFF, "x").is_none());
        assert!(ask_pin(std::ptr::null()).is_none());
    }

    /// Round 5 (Opus F4): a key line waits at least as long as the daemon
    /// can take to answer a touch, so it never gives up on one the daemon
    /// took.
    #[test]
    fn a_key_line_waits_as_long_as_the_daemon_can_take() {
        assert!(
            KEY_WAIT >= faceauth_daemon::consent::KEY_REPLY_WITHIN,
            "{:?} < {:?}",
            KEY_WAIT,
            faceauth_daemon::consent::KEY_REPLY_WITHIN
        );
        assert!(
            faceauth_daemon::consent::KEY_REPLY_WITHIN
                > faceauth_daemon::consent::KEY_FINISH + faceauth_daemon::consent::KEY_DEADLINE
        );
    }

    /// The module's waits at a twentieth of their real length, so the tests
    /// drive the same control flow quickly.
    const FAST: Timing = Timing {
        liveness: Duration::from_millis(300),
        tick: Duration::from_millis(50),
        unknown_limit: Duration::from_millis(500),
        still_tick: Duration::from_millis(12),
        fallback_deadline: Duration::from_millis(300),
    };

    /// `PASSWORD_WITHIN` and the daemon's own bounds at FAST's scale.
    const FAST_BUDGET: Duration = Duration::from_millis(750);
    const FAST_BEAT: Duration = Duration::from_millis(100);
    const FAST_CAMERA_WAIT: Duration = Duration::from_millis(200);
    const FAST_HOLD: Duration = Duration::from_millis(25);

    /// One connection's script for a fake daemon: what to do once the
    /// request line is in.
    #[derive(Clone)]
    enum Turn {
        /// Answer this line.
        Say(&'static str),
        /// Send keepalives every `FAST_BEAT` for this long, then this line.
        BeatThen(Duration, &'static str),
        /// Never answer; hold the connection until the client goes.
        Hang,
        /// Hang up without a word.
        Close,
    }

    /// A fake daemon on a socket of its own: each connection that sends a
    /// request line takes the next turn of the script (the last repeats);
    /// a connection that sends nothing (the module's probe) takes none.
    struct FakeDaemon {
        path: std::path::PathBuf,
        got: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl FakeDaemon {
        fn start(name: &str, script: Vec<Turn>) -> FakeDaemon {
            FakeDaemon::start_with(name, script, false)
        }

        /// The script over and over, from its first turn after its last.
        fn cycling(name: &str, script: Vec<Turn>) -> FakeDaemon {
            FakeDaemon::start_with(name, script, true)
        }

        fn start_with(name: &str, script: Vec<Turn>, cycle: bool) -> FakeDaemon {
            use std::os::unix::net::UnixListener;
            use std::sync::atomic::{AtomicBool, Ordering};
            use std::sync::{Arc, Mutex};
            let dir =
                std::env::temp_dir().join(format!("pam_faceauth-{}-{}", name, std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("sock");
            let listener = UnixListener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            let got = Arc::new(Mutex::new(Vec::new()));
            let stop = Arc::new(AtomicBool::new(false));
            let next = Arc::new(Mutex::new(0usize));
            let script = Arc::new(script);
            let (g, st) = (Arc::clone(&got), Arc::clone(&stop));
            std::thread::spawn(move || {
                while !st.load(Ordering::SeqCst) {
                    let Ok((c, _)) = listener.accept() else {
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    };
                    let (g, st, next, script) = (
                        Arc::clone(&g),
                        Arc::clone(&st),
                        Arc::clone(&next),
                        Arc::clone(&script),
                    );
                    std::thread::spawn(move || {
                        c.set_nonblocking(false).unwrap();
                        c.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                        let mut line = String::new();
                        let _ = BufReader::new(&c).read_line(&mut line);
                        if line.trim().is_empty() {
                            return;
                        }
                        g.lock().unwrap().push(line);
                        let turn = {
                            let mut n = next.lock().unwrap();
                            let i = if cycle {
                                *n % script.len()
                            } else {
                                (*n).min(script.len() - 1)
                            };
                            let t = script[i].clone();
                            *n += 1;
                            t
                        };
                        let mut c = c;
                        match turn {
                            Turn::Say(r) => {
                                let _ = c.write_all(r.as_bytes());
                            }
                            Turn::BeatThen(d, r) => {
                                let t0 = Instant::now();
                                while t0.elapsed() < d {
                                    if c.write_all(b"{\"result\":\"pending\"}\n").is_err() {
                                        return;
                                    }
                                    std::thread::sleep(FAST_BEAT);
                                }
                                let _ = c.write_all(r.as_bytes());
                            }
                            Turn::Hang => {
                                while !st.load(Ordering::SeqCst) {
                                    std::thread::sleep(Duration::from_millis(5));
                                }
                            }
                            Turn::Close => {}
                        }
                    });
                }
            });
            FakeDaemon { path, got, stop }
        }

        fn got(&self) -> Vec<String> {
            self.got.lock().unwrap().clone()
        }
    }

    impl Drop for FakeDaemon {
        fn drop(&mut self) {
            self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(dir) = self.path.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    const WAIT_CARD: &str =
        "{\"result\":\"key_wait\",\"state\":\"card\",\"reason\":\"the card on screen has the key\"}\n";
    const WAIT_LOCKED: &str =
        "{\"result\":\"key_wait\",\"state\":\"locked\",\"reason\":\"the screen is locked\"}\n";
    const WAIT_HELD: &str =
        "{\"result\":\"key_wait\",\"state\":\"held\",\"reason\":\"the hold\"}\n";
    const WAIT_UNKNOWN: &str =
        "{\"result\":\"key_wait\",\"state\":\"unknown\",\"reason\":\"no answer\"}\n";
    const READY: &str = "{\"result\":\"key_ready\"}\n";
    const MATCH: &str = "{\"result\":\"match\",\"frames\":0,\"elapsed_ms\":3}\n";
    const NO_TOUCH: &str =
        "{\"result\":\"error\",\"message\":\"the key check ran past its deadline\"}\n";
    const BUSY: &str = "{\"result\":\"error\",\"message\":\"busy\"}\n";
    const DENIED: &str =
        "{\"result\":\"consent_denied\",\"reason\":\"no window\",\"elapsed_ms\":1}\n";
    const UNKNOWN_TOO_LONG: &str =
        "{\"result\":\"error\",\"message\":\"the lock state has read as unknown\"}\n";

    type CheckFn = Box<dyn Fn(&dyn Fn() -> bool) -> Ended>;

    /// The key line's world, faked: the daemon is at `daemon` (or down).
    /// Time is real; `sleep` sleeps.
    struct FakeEnv {
        daemon: std::rc::Rc<std::cell::RefCell<Option<std::path::PathBuf>>>,
        /// Connections answer `Unreachable` (a listener that is not root).
        unreachable: std::cell::Cell<bool>,
        pin: Option<&'static [u8]>,
        pins: std::cell::Cell<usize>,
        told: std::cell::Cell<usize>,
        cued: std::cell::Cell<usize>,
        t0: Instant,
        direct: bool,
        check: CheckFn,
        checks: std::cell::RefCell<Vec<Option<Vec<u8>>>>,
        events: std::cell::RefCell<Vec<&'static str>>,
        /// Runs when the line says it waits.
        on_tell: Box<dyn Fn()>,
        agent: Option<Agent>,
    }

    impl FakeEnv {
        fn new() -> FakeEnv {
            FakeEnv {
                daemon: std::rc::Rc::new(std::cell::RefCell::new(None)),
                unreachable: std::cell::Cell::new(false),
                pin: None,
                pins: std::cell::Cell::new(0),
                told: std::cell::Cell::new(0),
                cued: std::cell::Cell::new(0),
                t0: Instant::now(),
                direct: true,
                check: Box::new(|_| Ended::Code(1)),
                checks: std::cell::RefCell::new(Vec::new()),
                events: std::cell::RefCell::new(Vec::new()),
                on_tell: Box::new(|| {}),
                agent: None,
            }
        }

        fn with_daemon(self, d: &FakeDaemon) -> FakeEnv {
            *self.daemon.borrow_mut() = Some(d.path.clone());
            self
        }
    }

    impl KeyEnv for FakeEnv {
        fn connect(&self) -> Result<UnixStream, Said> {
            if self.unreachable.get() {
                return Err(Said::Unreachable);
            }
            match &*self.daemon.borrow() {
                Some(p) => UnixStream::connect(p)
                    .map_err(|e| connect_kind(e.kind(), runtime_dir_present(p))),
                None => Err(Said::Down),
            }
        }
        fn ask_pin(&self) -> Option<Wiped> {
            self.pins.set(self.pins.get() + 1);
            self.events.borrow_mut().push("pin");
            self.pin.map(|p| Wiped(p.to_vec()))
        }
        fn tell_wait(&self) {
            self.told.set(self.told.get() + 1);
            (self.on_tell)();
        }
        fn cue(&self) {
            self.cued.set(self.cued.get() + 1);
            self.events.borrow_mut().push("cue");
        }
        fn sleep(&self, d: Duration) {
            std::thread::sleep(d);
        }
        fn now(&self) -> Duration {
            self.t0.elapsed()
        }
        fn direct_ok(&self) -> bool {
            self.direct
        }
        fn agent(&self) -> Option<Agent> {
            self.agent
        }
        fn check(&self, still: &dyn Fn() -> bool) -> Ended {
            self.events.borrow_mut().push("check");
            self.checks.borrow_mut().push(None);
            (self.check)(still)
        }
    }

    /// A direct check that waits for a touch at `at` from its start, is
    /// stopped as `still` says, and gives up at FAST's deadline, like the
    /// real one.
    fn touch_at(at: Duration) -> CheckFn {
        Box::new(move |still| {
            let t0 = Instant::now();
            loop {
                if t0.elapsed() >= at {
                    return Ended::Code(KEY_TOUCHED);
                }
                if t0.elapsed() >= FAST.fallback_deadline {
                    return Ended::Failed;
                }
                if !still() {
                    return Ended::Stopped;
                }
                std::thread::sleep(FAST.still_tick);
            }
        })
    }

    /// Round 5 (Codex 3), round 6 (B): the PIN is typed with no connection
    /// open: the ask whether the line may run is answered and closed before
    /// the prompt, and the check goes on a fresh connection once the PIN is
    /// in. The line waits on short connections while the daemon says so,
    /// says it once, asks for the PIN once and keeps it when a lock stops
    /// the check, and waits on the daemon's keepalives meanwhile.
    #[test]
    fn a_key_line_waits_for_the_unlock_on_short_connections() {
        let d = FakeDaemon::start(
            "wait",
            vec![
                Turn::Say(WAIT_LOCKED),
                Turn::Say(WAIT_LOCKED),
                Turn::Say(READY),
                Turn::BeatThen(Duration::from_millis(150), WAIT_LOCKED),
                Turn::Say(READY),
                Turn::BeatThen(Duration::from_millis(450), MATCH),
            ],
        );
        let env = FakeEnv {
            pin: Some(b"2468"),
            ..FakeEnv::new()
        }
        .with_daemon(&d);
        let said = key_line(&env, "alice", true, FAST);
        assert_eq!(said, Said::Match);
        assert_eq!(env.pins.get(), 1, "the PIN is asked once");
        assert_eq!(env.told.get(), 1, "the wait is said once");
        assert_eq!(env.cued.get(), 1, "the touch is cued once");
        let got = d.got();
        assert_eq!(got.len(), 6, "one short connection per ask: {:?}", got);
        for (i, line) in got.iter().enumerate() {
            let check = i == 3 || i == 5;
            assert_eq!(
                line.contains("\"key_ready\":true"),
                !check,
                "{}: {}",
                i,
                line
            );
            assert_eq!(
                line.contains("\"consent_password\":\"2468\""),
                check,
                "{}: {}",
                i,
                line
            );
        }
        assert!(
            env.checks.borrow().is_empty(),
            "no direct check with the daemon up"
        );
    }

    /// Round 7 (B): while the daemon says only the hold after an unlock is
    /// left, the line asks again four times as often, so approvals open
    /// about one hold after a real unlock at the key line too.
    #[test]
    fn a_held_wait_is_asked_again_soon() {
        let d = FakeDaemon::start(
            "held",
            vec![Turn::Say(WAIT_HELD), Turn::Say(READY), Turn::Say(MATCH)],
        );
        let env = FakeEnv::new().with_daemon(&d);
        let t0 = Instant::now();
        assert_eq!(key_line(&env, "alice", false, FAST), Said::Match);
        assert!(t0.elapsed() < FAST.tick, "{:?}", t0.elapsed());
    }

    /// Round 5 (A): only a daemon truly down (its socket missing or
    /// refusing) sends a key line to the direct key; a busy or malformed
    /// answer, a peer that is not root and a broken-off reply go to the
    /// password.
    #[test]
    fn only_a_daemon_down_takes_the_direct_key() {
        let env = FakeEnv::new();
        env.unreachable.set(true);
        assert_eq!(key_line(&env, "alice", false, FAST), Said::Unreachable);
        assert!(env.checks.borrow().is_empty());
        let env = FakeEnv::new();
        assert_eq!(
            key_line(&env, "alice", false, FAST),
            Said::Other,
            "down: the key, no touch"
        );
        assert_eq!(env.checks.borrow().len(), 1);
        let d = FakeDaemon::start("busy", vec![Turn::Say(BUSY)]);
        let env = FakeEnv::new().with_daemon(&d);
        assert_eq!(key_line(&env, "alice", false, FAST), Said::Error);
        assert!(env.checks.borrow().is_empty());
        let d = FakeDaemon::start("close", vec![Turn::Close]);
        let env = FakeEnv::new().with_daemon(&d);
        assert_eq!(key_line(&env, "alice", false, FAST), Said::Unreachable);
        assert_eq!(
            connect_kind(std::io::ErrorKind::NotFound, false),
            Said::Down
        );
        assert_eq!(
            connect_kind(std::io::ErrorKind::ConnectionRefused, false),
            Said::Down
        );
        assert_eq!(
            connect_kind(std::io::ErrorKind::ConnectionRefused, true),
            Said::Unreachable,
            "restarting (fix round 11)"
        );
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::TimedOut,
            std::io::ErrorKind::WouldBlock,
            std::io::ErrorKind::Other,
        ] {
            for dir in [false, true] {
                assert_eq!(connect_kind(kind, dir), Said::Unreachable, "{:?}", kind);
            }
        }
        assert_eq!(pam_code(Said::Down, Ask::Consent), PAM_AUTHINFO_UNAVAIL);
        assert_eq!(pam_code(Said::Down, Ask::KeyUnlock), PAM_AUTH_ERR);
        assert_eq!(pam_code(Said::Down, Ask::Look), PAM_IGNORE);
        let env = FakeEnv {
            direct: false,
            ..FakeEnv::new()
        };
        assert_eq!(
            key_line(&env, "alice", false, FAST),
            Said::Unreachable,
            "not root, or no helpers: the password"
        );
        assert!(env.checks.borrow().is_empty());
    }

    /// Fix round 10, item 6 (Mike's ruling): with faceauthd truly down the
    /// key line is stock Omarchy's pam_u2f line. It runs its private
    /// stack's check at once and takes the touch, whatever the session's
    /// lock state, logind's records or where the request comes from, none
    /// of which it asks about (`KeyEnv` has no way to); it says no wait, and
    /// since fix round 11 (Codex 4) asks no PIN and gives no cue of its own:
    /// pam_u2f's own prompts go to the caller through the conversation
    /// (`run_converse`). With no touch in the check's window it goes on to
    /// the password.
    #[test]
    fn with_faceauthd_down_the_key_line_is_stock() {
        let env = FakeEnv {
            pin: Some(b"2468"),
            check: touch_at(Duration::ZERO),
            ..FakeEnv::new()
        };
        let t0 = Instant::now();
        assert_eq!(key_line(&env, "alice", true, FAST), Said::Match);
        assert!(t0.elapsed() < FAST.tick, "at once: {:?}", t0.elapsed());
        assert_eq!(env.told.get(), 0, "no wait is said");
        assert_eq!(
            *env.events.borrow(),
            ["check"],
            "no prompt or cue of the module's"
        );
        assert_eq!(env.pins.get(), 0);
        let env = FakeEnv {
            check: touch_at(Duration::from_secs(60)),
            ..FakeEnv::new()
        };
        let t0 = Instant::now();
        assert_eq!(key_line(&env, "alice", false, FAST), Said::Other);
        let took = t0.elapsed();
        assert!(
            took >= FAST.fallback_deadline && took < FAST.fallback_deadline + FAST.tick,
            "the check's own window: {:?}",
            took
        );
        assert_eq!(env.checks.borrow().len(), 1);
        assert_ne!(
            pam_code(Said::Other, Ask::KeyFallback),
            PAM_SUCCESS,
            "a sufficient line that fails: on to the password"
        );
    }

    /// A line that waited on the daemon's doubt before the daemon went
    /// down keeps only what is left of its wait budget for the stock check,
    /// and once that is spent goes to the password; it never starts the
    /// capped check over and over.
    #[test]
    fn a_line_that_waited_before_the_outage_keeps_its_budget() {
        let d = FakeDaemon::cycling("doubt-then-down", vec![Turn::Say(WAIT_UNKNOWN)]);
        // The daemon is stopped once the line has waited on its doubt for
        // most of the budget: its runtime directory goes with it.
        let (stop, path) = (std::sync::Arc::clone(&d.stop), d.path.clone());
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(dir) = path.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        });
        let env = FakeEnv {
            check: touch_at(Duration::from_secs(60)),
            ..FakeEnv::new()
        }
        .with_daemon(&d);
        let t0 = Instant::now();
        assert_eq!(
            key_line_until(&env, Duration::from_secs(3)),
            Said::Unreachable
        );
        assert!(t0.elapsed() < FAST_BUDGET, "{:?}", t0.elapsed());
        assert_eq!(env.checks.borrow().len(), 1, "one capped check");
    }

    /// A touch that lands as faceauthd comes back counts for nothing: the
    /// daemon may have a check of its own on the key by then. The line
    /// goes back to the daemon with the PIN.
    #[test]
    fn a_touch_as_faceauthd_comes_back_counts_for_nothing() {
        let d = FakeDaemon::start("back-at-touch", vec![Turn::Say(READY), Turn::Say(MATCH)]);
        let path = d.path.clone();
        let env = FakeEnv {
            pin: Some(b"1357"),
            ..FakeEnv::new()
        };
        let daemon = std::rc::Rc::clone(&env.daemon);
        let env = FakeEnv {
            check: Box::new(move |_| {
                *daemon.borrow_mut() = Some(path.clone());
                Ended::Code(KEY_TOUCHED)
            }),
            ..env
        };
        assert_eq!(key_line(&env, "alice", true, FAST), Said::Match);
        let got = d.got();
        assert_eq!(got.len(), 2, "the daemon's own check decided: {:?}", got);
        assert!(got[1].contains("\"consent_password\":\"1357\""));
        assert_eq!(env.pins.get(), 1);
    }

    /// Round 6 (Codex 2, Opus N3): "down" is not decided once. A direct
    /// check under way is stopped the moment the daemon answers again,
    /// before the line goes back to it, so two checks never share the key;
    /// the daemon's word (its start latch) then decides, and the line asks
    /// for the PIN for the daemon's check (the stock check asked nothing of
    /// its own: pam_u2f's prompts went through the conversation).
    #[test]
    fn the_line_goes_back_to_the_daemon_the_moment_it_answers() {
        let d = FakeDaemon::start(
            "back",
            vec![Turn::Say(WAIT_HELD), Turn::Say(READY), Turn::Say(MATCH)],
        );
        let path = d.path.clone();
        let stopped_at = std::rc::Rc::new(std::cell::Cell::new(None::<Instant>));
        let sa = std::rc::Rc::clone(&stopped_at);
        let env = FakeEnv {
            pin: Some(b"9753"),
            ..FakeEnv::new()
        };
        let daemon = std::rc::Rc::clone(&env.daemon);
        let env = FakeEnv {
            check: Box::new(move |still| {
                let t0 = Instant::now();
                loop {
                    if t0.elapsed() > Duration::from_millis(60) {
                        // faceauthd is back.
                        *daemon.borrow_mut() = Some(path.clone());
                    }
                    if !still() {
                        sa.set(Some(Instant::now()));
                        return Ended::Stopped;
                    }
                    std::thread::sleep(FAST.still_tick);
                }
            }),
            ..env
        };
        assert_eq!(key_line(&env, "alice", true, FAST), Said::Match);
        assert!(stopped_at.get().is_some(), "the direct check was stopped");
        assert_eq!(env.checks.borrow().len(), 1, "one direct check");
        let got = d.got();
        assert_eq!(got.len(), 3, "{:?}", got);
        assert!(
            got[2].contains("\"consent_password\":\"9753\""),
            "the PIN carried over"
        );
        assert_eq!(env.pins.get(), 1);
    }

    /// Opus N1, round 6 item 6: the daemon's unknown lock state is waited
    /// on for at most the limit, then the line goes to the password, never
    /// to the key (a positive lock is waited on without one:
    /// `a_positive_lock_on_the_desktop_waits_past_the_budget`).
    #[test]
    fn an_unknown_lock_state_falls_to_the_password() {
        let d = FakeDaemon::start("unknown", vec![Turn::Say(WAIT_UNKNOWN)]);
        let env = FakeEnv::new().with_daemon(&d);
        let t0 = Instant::now();
        assert_eq!(key_line(&env, "alice", false, FAST), Said::Unreachable);
        assert!(t0.elapsed() < FAST.unknown_limit + 3 * FAST.tick);
        assert!(env.checks.borrow().is_empty());
    }

    /// The key line, with the socket turning unreachable at `after`.
    fn key_line_until(env: &FakeEnv, after: Duration) -> Said {
        struct Until<'a> {
            env: &'a FakeEnv,
            at: Instant,
        }
        impl KeyEnv for Until<'_> {
            fn connect(&self) -> Result<UnixStream, Said> {
                if Instant::now() >= self.at {
                    return Err(Said::Unreachable);
                }
                self.env.connect()
            }
            fn ask_pin(&self) -> Option<Wiped> {
                self.env.ask_pin()
            }
            fn tell_wait(&self) {
                self.env.tell_wait()
            }
            fn cue(&self) {
                self.env.cue()
            }
            fn sleep(&self, d: Duration) {
                self.env.sleep(d)
            }
            fn now(&self) -> Duration {
                self.env.now()
            }
            fn direct_ok(&self) -> bool {
                self.env.direct_ok()
            }
            fn check(&self, still: &dyn Fn() -> bool) -> Ended {
                self.env.check(still)
            }
        }
        key_line(
            &Until {
                env,
                at: Instant::now() + after,
            },
            "alice",
            false,
            FAST,
        )
    }

    /// Round 5 (A): the key check's byte means what the daemon's helper
    /// says it means, and the lanes are the daemon's.
    #[test]
    fn the_key_checks_answers_are_the_daemons() {
        assert_eq!(KEY_TOUCHED, faceauth_daemon::consent::KEY_TOUCHED);
        assert_eq!(lane_of_service("sudo"), Some("sudo"));
        assert_eq!(lane_of_service("sudo-i"), Some("sudo"));
        assert_eq!(lane_of_service("polkit-1"), Some("polkit"));
        assert_eq!(lane_of_service("login"), None);
    }

    fn sh(script: &str) -> std::process::Command {
        let mut c = std::process::Command::new("/bin/sh");
        c.args(["-c", script]);
        c
    }

    /// Round 6 (Codex 6): a helper's answer is its own line on stdout
    /// (fix round 11: `R <code>`), read from a pipe; a run is killed the
    /// moment `still` says no, or at its deadline; anything else, or none,
    /// is no answer.
    #[test]
    fn a_helper_run_answers_on_its_own_line_and_is_stopped_in_time() {
        let never = || true;
        let tick = Duration::from_millis(20);
        let limit = Duration::from_secs(5);
        let mut none = |_: c_int, _: &[u8]| None;
        assert_eq!(
            run_converse(sh("printf 'R 42\\n'"), limit, tick, &never, &mut none),
            Ended::Code(42)
        );
        assert_eq!(
            run_converse(
                sh("printf 'R 1\\n'; exit 9"),
                limit,
                tick,
                &never,
                &mut none
            ),
            Ended::Code(1)
        );
        assert_eq!(
            run_converse(sh("printf 'ab'"), limit, tick, &never, &mut none),
            Ended::Failed
        );
        assert_eq!(
            run_converse(
                sh("printf 'X 1\\n'; sleep 1"),
                limit,
                tick,
                &never,
                &mut none
            ),
            Ended::Failed,
            "a line that is none of the protocol's"
        );
        assert_eq!(
            run_converse(sh("exit 42"), limit, tick, &never, &mut none),
            Ended::Failed,
            "an exit status alone is no answer"
        );
        let asks = std::cell::Cell::new(0);
        let t0 = Instant::now();
        let ended = run_converse(
            sh("exec sleep 30"),
            limit,
            tick,
            &|| {
                asks.set(asks.get() + 1);
                asks.get() < 3
            },
            &mut none,
        );
        assert_eq!(ended, Ended::Stopped);
        assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
        let t0 = Instant::now();
        assert_eq!(
            run_converse(
                sh("exec sleep 30"),
                Duration::from_millis(150),
                tick,
                &never,
                &mut none
            ),
            Ended::Failed
        );
        assert!(t0.elapsed() < Duration::from_secs(1));
    }

    /// Fix round 11 (Codex 4): the stock check's conversation goes to the
    /// PAM caller: each message the helper sends is relayed and answered,
    /// the time the user spends on a prompt is not counted against the
    /// touch window, a run is stopped when `still` says no, and one that
    /// never answers is given up at the window.
    #[test]
    fn the_stock_check_relays_its_conversation() {
        let tick = Duration::from_millis(20);
        let script = format!(
            "printf 'Q 1 {}\\n'; read a; [ \"$a\" = 'A 39383736' ] || exit 1; printf 'Q 4 {}\\n'; read b; printf 'R 42\\n'",
            lockgate::hex_encode(b"Please enter the PIN: "),
            lockgate::hex_encode(b"Please touch the device."),
        );
        let seen = std::cell::RefCell::new(Vec::new());
        let mut relay = |style: c_int, text: &[u8]| {
            seen.borrow_mut()
                .push((style, String::from_utf8_lossy(text).into_owned()));
            if style == PAM_PROMPT_ECHO_OFF {
                std::thread::sleep(Duration::from_millis(300));
                Some(Wiped(b"9876".to_vec()))
            } else {
                Some(Wiped(Vec::new()))
            }
        };
        let t0 = Instant::now();
        assert_eq!(
            run_converse(
                sh(&script),
                Duration::from_millis(200),
                tick,
                &|| true,
                &mut relay
            ),
            Ended::Code(KEY_TOUCHED),
            "the prompt's 300 ms are the user's, not the 200 ms window's"
        );
        assert!(t0.elapsed() >= Duration::from_millis(300));
        assert_eq!(
            *seen.borrow(),
            [
                (PAM_PROMPT_ECHO_OFF, "Please enter the PIN: ".to_string()),
                (PAM_TEXT_INFO, "Please touch the device.".to_string())
            ]
        );
        let mut none = |_: c_int, _: &[u8]| None;
        assert_eq!(
            run_converse(
                sh("exec sleep 30"),
                Duration::from_millis(200),
                tick,
                &|| true,
                &mut none
            ),
            Ended::Failed,
            "no answer within the window"
        );
        let t0 = Instant::now();
        assert_eq!(
            run_converse(
                sh("exec sleep 30"),
                Duration::from_secs(5),
                tick,
                &|| t0.elapsed() < Duration::from_millis(100),
                &mut none
            ),
            Ended::Stopped
        );
        assert_eq!(
            run_converse(
                sh("printf 'Q 1 41\\n'; read a; [ \"$a\" = N ] && printf 'R 1\\n'"),
                Duration::from_secs(5),
                tick,
                &|| true,
                &mut none
            ),
            Ended::Code(1),
            "a prompt with no answer is answered N"
        );
    }

    /// Fix round 12 (Codex 2, Opus N2): a prompt the PAM caller holds open
    /// does not hold the key. While it waits, the stock check is watched on
    /// a thread of its own: it is killed the moment faceauthd is back
    /// (`back`), or at its overall bound, prompt time included, and once
    /// the prompt returns the line goes to the password.
    #[test]
    fn the_stock_check_is_killed_mid_prompt_when_the_daemon_is_back() {
        let dir =
            std::env::temp_dir().join(format!("pam_faceauth-midprompt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pidfile = dir.join("pid");
        let script = format!(
            "echo $$ > '{}'; printf 'Q 1 41\\n'; exec sleep 30",
            pidfile.display()
        );
        let state_of = |pidfile: &Path| -> Option<char> {
            let pid = std::fs::read_to_string(pidfile).ok()?;
            let stat = std::fs::read_to_string(format!("/proc/{}/stat", pid.trim())).ok()?;
            stat.rsplit(')').next()?.trim().chars().next()
        };
        let tick = Duration::from_millis(20);
        let t0 = Instant::now();
        let seen = std::cell::Cell::new(None);
        let mut relay = |_: c_int, _: &[u8]| {
            // The user takes a second over the PIN; meanwhile the daemon
            // comes back at 200 ms.
            std::thread::sleep(Duration::from_millis(600));
            seen.set(state_of(&pidfile));
            std::thread::sleep(Duration::from_millis(400));
            Some(Wiped(b"1234".to_vec()))
        };
        let back = || t0.elapsed() > Duration::from_millis(200);
        assert_eq!(
            run_converse_full(
                sh(&script),
                Duration::from_secs(5),
                tick,
                &|| true,
                &back,
                Duration::from_secs(60),
                &mut relay
            ),
            Ended::Failed,
            "the line goes to the password"
        );
        assert_eq!(
            seen.get(),
            Some('Z'),
            "killed while the prompt was still open"
        );
        // The overall bound, prompt time included.
        let t0 = Instant::now();
        let mut slow = |_: c_int, _: &[u8]| {
            std::thread::sleep(Duration::from_millis(600));
            seen.set(state_of(&pidfile));
            Some(Wiped(Vec::new()))
        };
        assert_eq!(
            run_converse_full(
                sh(&script),
                Duration::from_secs(5),
                tick,
                &|| true,
                &|| false,
                Duration::from_millis(300),
                &mut slow
            ),
            Ended::Failed
        );
        assert_eq!(seen.get(), Some('Z'));
        assert!(t0.elapsed() < Duration::from_secs(2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Round 19 (live test 2): a stock check that is stopped is asked first,
    /// with SIGTERM, which the helper answers by cancelling the key's wait,
    /// so the key stops blinking with it; one that does not end on that is
    /// killed a moment later, within the line's bounds.
    #[test]
    fn a_stopped_stock_check_is_asked_to_stop_before_it_is_killed() {
        let dir = std::env::temp_dir().join(format!("pam_faceauth-term-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mark = dir.join("asked");
        let ready = dir.join("ready");
        let tick = Duration::from_millis(20);
        let mut none = |_: c_int, _: &[u8]| None;
        // The helper says when its handler is in place, and the line is
        // stopped only then: a stop that lands first meets the shell's
        // default action, which proves nothing either way.
        let script = format!(
            "trap 'touch \"{}\"; kill $! 2>/dev/null; exit 1' TERM; touch \"{}\"; sleep 30 & wait",
            mark.display(),
            ready.display()
        );
        let ended = run_converse(
            sh(&script),
            Duration::from_secs(5),
            tick,
            &|| !ready.exists(),
            &mut none,
        );
        assert_eq!(ended, Ended::Stopped);
        assert!(mark.exists(), "the helper heard SIGTERM before any kill");
        // A helper that ignores SIGTERM is still gone, killed in time.
        let t0 = Instant::now();
        let ended = run_converse(
            sh("trap '' TERM; exec sleep 30"),
            Duration::from_secs(5),
            tick,
            &|| t0.elapsed() < Duration::from_millis(100),
            &mut none,
        );
        assert_eq!(ended, Ended::Stopped);
        assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fix round 12 (Opus N2): the stock check runs in a session of its
    /// own, so the terminal's Ctrl-Z, and signals to sudo's process group,
    /// never reach it.
    #[test]
    fn the_stock_check_runs_in_a_session_of_its_own() {
        use std::os::unix::process::CommandExt;
        let mut c = sh("cut -d' ' -f6 /proc/$$/stat");
        // SAFETY: new_session makes one async-signal-safe call.
        unsafe { c.pre_exec(new_session) };
        let child = c.stdout(std::process::Stdio::piped()).spawn().unwrap();
        let pid = child.id();
        let out = child.wait_with_output().unwrap();
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), pid.to_string());
    }

    /// Round 6 (Codex 6), item 12: a PAM caller that ignores SIGCHLD has
    /// its children reaped by the kernel, exit status and all. The helpers'
    /// answers come over a pipe, so the gate and the check still get them
    /// and never hang. Run in a child of this test binary with SIGCHLD
    /// ignored (the disposition carries through exec), as Codex ran it.
    #[test]
    fn a_caller_that_ignores_sigchld_still_gets_its_answers() {
        use std::os::unix::process::CommandExt;
        let me = std::env::current_exe().unwrap();
        let mut c = std::process::Command::new(me);
        c.args([
            "--exact",
            "tests::sigchld_inner",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("PAM_FACEAUTH_SIGCHLD_INNER", "1");
        // SAFETY: setting a signal's disposition is async-signal-safe.
        unsafe {
            c.pre_exec(|| {
                libc::signal(libc::SIGCHLD, libc::SIG_IGN);
                Ok(())
            })
        };
        let t0 = Instant::now();
        let out = c.output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success(),
            "{}{}",
            text,
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(text.contains("sigchld inner ran"), "{}", text);
        assert!(t0.elapsed() < Duration::from_secs(20));
    }

    /// Fix round 13 (Codex 1): the stock check's pidfd is the child's own,
    /// taken between fork and exec and passed up before it runs anything,
    /// never opened afterwards by a pid that may name another process by
    /// then. With SIGCHLD ignored the kernel reaps a child the moment it
    /// exits, and its pid is free for reuse; the descriptor still names
    /// that child, now gone, so a kill through it reaches nothing, and a
    /// wait through it is an error at once, not a wait on another process.
    /// Run in the SIGCHLD-ignored child below.
    fn the_pidfd_is_the_childs_own_from_before_exec() {
        use std::os::fd::AsRawFd;
        let (child, pidfd) = spawn_with_pidfd(&mut sh("exit 0")).expect("a pidfd from the child");
        drop(child);
        std::thread::sleep(Duration::from_millis(300));
        // SAFETY: a pidfd, signal 0 (no signal, only the check), no info.
        let sent = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                0,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        assert_eq!(sent, -1, "the child is gone");
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH),
            "and the descriptor names only it"
        );
        let t0 = Instant::now();
        reap(&pidfd);
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "{:?}",
            t0.elapsed()
        );
    }

    /// Fix round 13 (Codex 1): nothing in the module signals or waits by
    /// pid: every signal goes through the child's own pidfd, and every
    /// wait is `waitid(P_PIDFD, ..)`, which waits on that process alone.
    #[test]
    fn the_module_signals_and_waits_only_through_pidfds() {
        let source = include_str!("lib.rs");
        let module = source
            .split(concat!("#[cfg(test)]\n", "mod tests {"))
            .next()
            .unwrap();
        for by_pid in [
            concat!(".kill", "()"),
            concat!("libc::", "kill("),
            concat!("kill", "pg"),
            concat!(".try_", "wait()"),
            concat!(".wait", "()"),
            concat!("wait", "pid"),
            concat!("pidfd_open(", "child"),
            concat!("P_", "PID,"),
        ] {
            assert!(
                !module.contains(by_pid),
                "the module calls {} outside its tests",
                by_pid
            );
        }
    }

    /// The inner half of the test above; passes trivially when run alone.
    #[test]
    fn sigchld_inner() {
        if std::env::var_os("PAM_FACEAUTH_SIGCHLD_INNER").is_none() {
            return;
        }
        // SAFETY: reading a disposition with a null new action.
        let ignored = unsafe {
            let mut old: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut old);
            old.sa_sigaction == libc::SIG_IGN
        };
        assert!(ignored, "the inner run has SIGCHLD ignored");
        the_pidfd_is_the_childs_own_from_before_exec();
        // The failure Codex found is real here: an exit status is lost.
        let lost = sh("exit 3").status();
        assert!(
            lost.as_ref().map_or(true, |st| st.code() != Some(3)),
            "with SIGCHLD ignored an exit status is lost: {:?}",
            lost
        );
        let tick = Duration::from_millis(20);
        let mut answer = |_: c_int, _: &[u8]| Some(Wiped(b"1".to_vec()));
        assert_eq!(
            run_converse(
                sh("sleep 0.05; printf 'R 0\\n'"),
                Duration::from_secs(5),
                tick,
                &|| true,
                &mut answer
            ),
            Ended::Code(0),
            "a helper's answer arrives"
        );
        assert_eq!(
            run_converse(
                sh("printf 'Q 1 41\\n'; read a; sleep 0.05; printf 'R 42\\n'"),
                Duration::from_secs(5),
                tick,
                &|| true,
                &mut answer
            ),
            Ended::Code(42),
            "the key check's answer arrives, after its prompt"
        );
        // The whole line: the check, a real process, reaches an answer
        // and then the password.
        let env = FakeEnv {
            check: Box::new(|still| {
                run_converse(
                    sh("printf 'R 1\\n'"),
                    FAST.fallback_deadline,
                    FAST.still_tick,
                    still,
                    &mut |_, _| None,
                )
            }),
            ..FakeEnv::new()
        };
        let t0 = Instant::now();
        assert_eq!(key_line(&env, "alice", false, FAST), Said::Other);
        assert!(t0.elapsed() < FAST_BUDGET, "{:?}", t0.elapsed());
        println!("sigchld inner ran");
    }

    /// Where a sudo or polkit stack ends, as Omarchy's controls run it.
    #[derive(Debug, PartialEq)]
    enum Reached {
        Approved,
        Password,
        /// Polkit's face line answered PAM_AUTH_ERR: `auth_err=die`.
        Denied,
    }

    /// Omarchy's sudo or polkit stack: the face line, the key-fallback line
    /// (`sufficient`), then the password.
    fn stack(face: Said, key: &dyn Fn() -> Said, polkit: bool) -> Reached {
        match pam_code(face, Ask::Consent) {
            PAM_SUCCESS => return Reached::Approved,
            PAM_AUTH_ERR if polkit => return Reached::Denied,
            _ => {}
        }
        match pam_code(key(), Ask::KeyFallback) {
            PAM_SUCCESS => Reached::Approved,
            _ => Reached::Password,
        }
    }

    /// The face line against a fake daemon at `d` (or none), with the
    /// module's real reading of it.
    fn face_line(d: Option<&FakeDaemon>) -> Said {
        let path = d.map(|d| d.path.clone());
        ask_daemon(
            &|| path.as_ref().and_then(|p| UnixStream::connect(p).ok()),
            "alice",
            Duration::from_secs(1),
            Ask::Consent,
            FAST,
            None,
            None,
        )
    }

    /// Round 6, item 12: the password stays reachable. Each failure below
    /// drives the module's real control flow, the face line and then the
    /// key-fallback line, against fakes, at FAST's scale, and the password
    /// line is reached within the budget, on sudo and polkit alike.
    fn reaches_password(name: &str, face: &dyn Fn() -> Said, key: &dyn Fn() -> Said) {
        for polkit in [false, true] {
            let t0 = Instant::now();
            let reached = stack(face(), key, polkit);
            let took = t0.elapsed();
            assert_eq!(reached, Reached::Password, "{} (polkit {})", name, polkit);
            assert!(
                took < FAST_BUDGET,
                "{} (polkit {}): {:?}",
                name,
                polkit,
                took
            );
        }
    }

    #[test]
    fn the_password_is_reached_with_the_daemon_hung() {
        let d = FakeDaemon::start("hung", vec![Turn::Hang]);
        let env = FakeEnv::new().with_daemon(&d);
        reaches_password("daemon hung", &|| face_line(Some(&d)), &|| {
            key_line(&env, "alice", false, FAST)
        });
    }

    #[test]
    fn the_password_is_reached_with_the_daemon_dead() {
        // Unlocked, the key is asked and nobody touches it.
        let env = FakeEnv {
            check: touch_at(Duration::from_secs(60)),
            ..FakeEnv::new()
        };
        reaches_password("daemon dead", &|| face_line(None), &|| {
            key_line(&env, "alice", false, FAST)
        });
    }

    #[test]
    fn the_password_is_reached_with_a_key_check_hung() {
        // Faceauth down: the real supervision of a check that never ends.
        let env = FakeEnv {
            check: Box::new(|still| {
                run_converse(
                    sh("exec sleep 30"),
                    FAST.fallback_deadline,
                    FAST.still_tick,
                    still,
                    &mut |_, _| None,
                )
            }),
            ..FakeEnv::new()
        };
        reaches_password("keycheck hung (direct)", &|| face_line(None), &|| {
            key_line(&env, "alice", false, FAST)
        });
        // Faceauth up: the daemon's check runs to its deadline, saying it
        // is at work meanwhile, and says no touch.
        let d = FakeDaemon::start(
            "keyhung",
            vec![
                Turn::Say(DENIED),
                Turn::Say(READY),
                Turn::BeatThen(FAST.fallback_deadline, NO_TOUCH),
            ],
        );
        let env = FakeEnv::new().with_daemon(&d);
        let t0 = Instant::now();
        assert_eq!(
            stack(
                face_line(Some(&d)),
                &|| key_line(&env, "alice", false, FAST),
                false
            ),
            Reached::Password
        );
        assert!(
            t0.elapsed() < FAST_BUDGET,
            "keycheck hung (daemon): {:?}",
            t0.elapsed()
        );
    }

    #[test]
    fn the_password_is_reached_with_hyprland_missing_renamed_or_doubled() {
        use faceauth_daemon::consent::{hyprland_instance, lock_state_from_monitors, LockState};
        // Hyprland renames the field the lock is read from: the helper's
        // reading, and its byte as the module reads it.
        let renamed = lock_state_from_monitors(br#"[{"name":"eDP-1","solitaryBlocked":["LOCK"]}]"#);
        // A second instance directory: no one instance to ask.
        let run = std::env::temp_dir().join(format!("pam_faceauth-hypr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        for sig in ["a1", "b2"] {
            std::fs::create_dir_all(run.join("hypr").join(sig)).unwrap();
            std::fs::write(run.join("hypr").join(sig).join(".socket.sock"), "").unwrap();
        }
        let doubled = match hyprland_instance(&run) {
            Some(_) => LockState::Unlocked,
            None => LockState::Unknown,
        };
        let _ = std::fs::remove_dir_all(&run);
        let missing = match hyprland_instance(Path::new("/nonexistent/run")) {
            Some(_) => LockState::Unlocked,
            None => LockState::Unknown,
        };
        for (name, answer) in [
            ("renamed", renamed),
            ("second instance", doubled),
            ("missing", missing),
        ] {
            assert_eq!(answer, LockState::Unknown, "{}", name);
        }
        // Faceauth up: the face line parks on the doubt until the daemon's
        // limit, and the key line then hears the same doubt.
        let d = FakeDaemon::start(
            "hyprup",
            vec![
                Turn::BeatThen(FAST.unknown_limit, UNKNOWN_TOO_LONG),
                Turn::Say(UNKNOWN_TOO_LONG),
            ],
        );
        let env = FakeEnv::new().with_daemon(&d);
        let t0 = Instant::now();
        assert_eq!(
            stack(
                face_line(Some(&d)),
                &|| key_line(&env, "alice", false, FAST),
                true
            ),
            Reached::Password,
            "polkit, too, reaches its password"
        );
        assert!(t0.elapsed() < FAST_BUDGET, "{:?}", t0.elapsed());
    }

    #[test]
    fn the_password_is_reached_with_the_camera_busy() {
        // The face line waits for the camera, saying it is at work, then
        // says busy; the key line is offered, and nobody touches it.
        let d = FakeDaemon::start(
            "camera",
            vec![
                Turn::BeatThen(FAST_CAMERA_WAIT, BUSY),
                Turn::Say(WAIT_HELD),
                Turn::Say(READY),
                Turn::BeatThen(FAST.fallback_deadline, NO_TOUCH),
            ],
        );
        let env = FakeEnv::new().with_daemon(&d);
        let t0 = Instant::now();
        assert_eq!(
            stack(
                face_line(Some(&d)),
                &|| key_line(&env, "alice", false, FAST),
                true
            ),
            Reached::Password
        );
        assert!(t0.elapsed() < FAST_BUDGET, "{:?}", t0.elapsed());
    }

    /// The exemption: a request from the locked desktop, with the screen
    /// positively locked, waits for the unlock past the budget and runs no
    /// key meanwhile.
    #[test]
    fn a_positive_lock_on_the_desktop_waits_past_the_budget() {
        let d = FakeDaemon::start("locked", vec![Turn::Say(WAIT_LOCKED)]);
        let env = FakeEnv::new().with_daemon(&d);
        let t0 = Instant::now();
        assert_eq!(
            key_line_until(&env, FAST_BUDGET + FAST.tick),
            Said::Unreachable
        );
        assert!(t0.elapsed() >= FAST_BUDGET);
        assert!(
            d.got().iter().all(|l| l.contains("\"key_ready\":true")),
            "only asks, no check"
        );
    }

    /// Round 6, item 12, at the real scale: the bounds the module and the
    /// daemon run on keep the password within `PASSWORD_WITHIN` for every
    /// failure above, alone and in the worst pairs.
    #[test]
    fn the_real_timing_keeps_the_password_within_reach() {
        use faceauth_daemon::auth::CONFIRM_LIMIT;
        use faceauth_daemon::consent::{
            ANCHOR_READ, DEFAULT_HOLD_MS, KEY_FINISH, QUEUE_UNSEEN, USER_CALL_LIMIT,
            USER_CALL_WITHIN,
        };
        let r = Timing::REAL;
        let budget = lockgate::PASSWORD_WITHIN;
        let hold = Duration::from_millis(DEFAULT_HOLD_MS);
        // The daemon's longest silence on a waiting line stays below the
        // module's patience.
        assert!(USER_CALL_LIMIT < r.liveness);
        assert!(KEY_FINISH < r.liveness);
        assert!(lockgate::CAMERA_WAIT < r.liveness);
        assert!(lockgate::BEAT * 2 < r.liveness);
        // Hung: the face line and the key line's ask each wait out the
        // patience once.
        assert!(r.liveness * 2 <= budget);
        // The camera busy, then the hold, then a touch window nobody uses.
        assert!(lockgate::CAMERA_WAIT + hold + r.fallback_deadline <= budget);
        // An unknown lock state: the daemon's anchored look is the last
        // answer the budget waits for (fix round 10: the module asks none
        // of its own with faceauthd down).
        assert!(r.unknown_limit + r.tick + ANCHOR_READ <= budget);
        // A hung check: the touch window and the stop.
        assert!(r.fallback_deadline + KEY_FINISH <= budget);
        assert_eq!(r.fallback_deadline, lockgate::FALLBACK_DEADLINE);
        // Fix round 10 (Opus N3): a nod's commit runs end_key, the
        // "Confirming" summon, the confirm and the fresh anchored look, a
        // beat before each, so each alone stays below the patience.
        assert!(USER_CALL_WITHIN < r.liveness);
        assert!(CONFIRM_LIMIT < r.liveness);
        assert!(ANCHOR_READ < r.liveness);
        // Fix round 10 (Opus N4): a request queued behind cards never
        // shown waits QUEUE_UNSEEN, beating, then its key line goes on to
        // the password at once (its budget counts as spent).
        assert!(QUEUE_UNSEEN + r.liveness <= budget);
        // FAST is REAL at a twentieth.
        assert_eq!(FAST.liveness * 20, r.liveness);
        assert_eq!(FAST.unknown_limit * 20, r.unknown_limit);
        assert_eq!(FAST.fallback_deadline * 20, r.fallback_deadline);
        assert_eq!(FAST_BUDGET * 20, budget);
        assert_eq!(FAST_CAMERA_WAIT * 20, lockgate::CAMERA_WAIT);
        assert_eq!(FAST_HOLD * 20, hold);
    }

    /// Round 5 (A): the module runs a helper as root only when root alone
    /// could have written it and the directories above it.
    #[test]
    fn a_helper_runs_only_when_it_is_roots() {
        let env = Path::new("/usr/bin/env");
        if std::fs::symlink_metadata(env).is_ok_and(|m| m.file_type().is_file()) {
            assert!(root_only_path(env), "a system binary");
        }
        let dir = std::env::temp_dir().join(format!("pam_faceauth-helper-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mine = dir.join("helper");
        std::fs::write(&mine, "#!/bin/sh\n").unwrap();
        // SAFETY: getuid has no preconditions.
        if unsafe { libc::getuid() } != 0 {
            assert!(!root_only_path(&mine), "a user's file");
        }
        let link = dir.join("link");
        std::os::unix::fs::symlink("/bin/sh", &link).unwrap();
        assert!(!root_only_path(&link), "a symlink");
        assert!(!root_only_path(&dir.join("missing")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F7: a name the escaper would have altered is refused, not rewritten.
    #[test]
    fn a_name_that_needs_escaping_is_refused() {
        assert_eq!(
            line("alice", Ask::Look, None).as_deref(),
            Some("{\"user\":\"alice\"}\n")
        );
        assert_eq!(
            line("alice", Ask::Consent, None).as_deref(),
            Some("{\"user\":\"alice\",\"consent\":true}\n")
        );
        assert_eq!(
            line("alice", Ask::KeyUnlock, None).as_deref(),
            Some("{\"user\":\"alice\",\"key_unlock\":true}\n")
        );
        assert_eq!(
            line("alice", Ask::KeyFallback, None).as_deref(),
            Some("{\"user\":\"alice\",\"key_fallback\":true}\n")
        );
        assert_eq!(
            line("alice", Ask::KeyReady, Some("1234")).as_deref(),
            Some("{\"user\":\"alice\",\"key_fallback\":true,\"key_ready\":true}\n"),
            "the ask carries no PIN"
        );
        for bad in [
            "ali\u{7}ce",
            "ali\"ce",
            "ali\\ce",
            "alice\n",
            "",
            "alice\u{7f}",
        ] {
            for ask in [
                Ask::Look,
                Ask::Consent,
                Ask::KeyFallback,
                Ask::KeyUnlock,
                Ask::KeyReady,
            ] {
                assert!(line(bad, ask, None).is_none(), "{:?} was sent", bad);
            }
        }
        assert!(line(&"a".repeat(257), Ask::Look, None).is_none());
    }

    /// Round 4: the key's PIN rides in the password field, escaped so the
    /// daemon's hand parse reads back exactly what was typed, and only on a
    /// key-fallback line.
    #[test]
    fn the_pin_rides_escaped_in_the_password_field() {
        for pin in ["123456", "a\"b\\c", "tab\there", "ünï", "\u{1}x"] {
            let l = line("alice", Ask::KeyFallback, Some(pin)).unwrap();
            let v: serde_json::Value = serde_json::from_str(&l).unwrap();
            assert_eq!(v["consent_password"], pin, "{:?}", l);
            assert_eq!(v["key_fallback"], true);
            assert_eq!(
                faceauth_daemon::server::request_op(&l),
                Some("key_fallback"),
                "{:?}",
                l
            );
        }
        for ask in [Ask::Look, Ask::Consent, Ask::KeyUnlock] {
            assert!(!line("alice", ask, Some("1234"))
                .unwrap()
                .contains("consent_password"));
        }
    }

    /// F7: with such a name the daemon is never even connected to.
    #[test]
    fn a_control_character_in_the_name_never_reaches_the_socket() {
        let dir = std::env::temp_dir().join(format!("pam_faceauth-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        assert_eq!(
            daemon_says(
                std::ptr::null(),
                &path,
                "ali\u{7}ce",
                Duration::from_secs(1),
                Ask::Consent,
                false,
                false
            ),
            Said::Unreachable
        );
        assert_eq!(
            listener.accept().map(|_| ()).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "a connection was made for a refused name"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F10: the daemon trusts a root peer with enrollment and deletion, and
    /// this module runs as root under sudo and polkit. Each line the
    /// builder makes, for any name it sends, carries exactly `user`, and
    /// `consent: true` on a consent line, `key_fallback: true` (with the
    /// PIN in `consent_password`) on a key fallback and `key_unlock: true`
    /// on a key unlock, with the name as given; and the daemon's own parse
    /// reads it as that operation.
    #[test]
    fn the_module_can_only_emit_its_five_requests() {
        for user in ["alice", "a.b-c_d", "ålice", "x", &"a".repeat(256)] {
            for (ask, pin, op, flags) in [
                (Ask::Look, None, "look", vec![]),
                (Ask::Consent, None, "consent", vec!["consent"]),
                (Ask::KeyUnlock, None, "key_unlock", vec!["key_unlock"]),
                (Ask::KeyFallback, None, "key_fallback", vec!["key_fallback"]),
                (
                    Ask::KeyFallback,
                    Some("4321"),
                    "key_fallback",
                    vec!["key_fallback"],
                ),
                (
                    Ask::KeyReady,
                    None,
                    "key_ready",
                    vec!["key_fallback", "key_ready"],
                ),
            ] {
                let l = line(user, ask, pin).expect("a plain name is sent");
                let v: serde_json::Value = serde_json::from_str(&l).expect("one JSON object");
                let fields = v.as_object().expect("an object");
                let keys: Vec<&str> = fields.keys().map(String::as_str).collect();
                let mut want: Vec<&str> = flags.iter().copied().chain(["user"]).collect();
                if pin.is_some() {
                    want.push("consent_password");
                }
                want.sort();
                assert_eq!(keys, want, "{:?}", l);
                assert_eq!(fields["user"], user, "{:?}", l);
                for f in &flags {
                    assert_eq!(fields[*f], true, "{:?}", l);
                }
                assert_eq!(faceauth_daemon::server::request_op(&l), Some(op), "{:?}", l);
            }
        }
    }

    #[test]
    fn args_parse_with_defaults() {
        let a = parse_args(std::ptr::null(), 0, std::ptr::null());
        assert_eq!(a.socket, DEFAULT_SOCKET);
        assert_eq!(a.timeout, Duration::from_secs(DEFAULT_TIMEOUT));
        assert!(!a.consent && !a.key_unlock && !a.key_fallback && !a.cue && !a.pin);
    }

    fn parse(words: &[&str]) -> Args {
        let args: Vec<std::ffi::CString> = words
            .iter()
            .map(|s| std::ffi::CString::new(*s).unwrap())
            .collect();
        let ptrs: Vec<*const c_char> = args.iter().map(|c| c.as_ptr()).collect();
        parse_args(std::ptr::null(), words.len() as c_int, ptrs.as_ptr())
    }

    /// The module's whole argument surface: `socket=`, `timeout=`,
    /// `consent`, `key-fallback` with the pam_u2f words it mirrors, and
    /// `key-unlock`. Any other word changes nothing (it is logged), so a
    /// misspelt `consent` leaves a plain look the daemon refuses from a
    /// root caller.
    #[test]
    fn the_only_arguments_are_the_kinds_and_their_words() {
        let a = parse(&["socket=/run/x/sock", "timeout=3", "consent"]);
        assert_eq!(a.socket, "/run/x/sock");
        assert_eq!(a.timeout, Duration::from_secs(3));
        assert!(a.consent);
        let k = parse(&[
            "socket=/run/x/sock",
            "key-fallback",
            "cue",
            "pinverification=1",
            "userverification=1",
        ]);
        assert!(k.key_fallback && k.cue && k.pin && !k.consent);
        assert!(!parse(&["key-fallback", "pinverification=0"]).pin);
        let u = parse(&["key-unlock"]);
        assert!(u.key_unlock && !u.key_fallback);
        let defaults = parse(&[]);
        for stray in [
            "prompt",
            "prompt=Face:_Enter_to_scan",
            "consnet",
            "try_first_pass",
            "timeout=abc",
            "key_unlock",
            "key-unlock=1",
            "key_fallback",
            "pinverification=2",
            "",
        ] {
            let b = parse(&[stray]);
            assert_eq!(b.socket, defaults.socket, "{:?}", stray);
            assert_eq!(b.timeout, defaults.timeout, "{:?}", stray);
            assert!(
                !b.consent && !b.key_unlock && !b.key_fallback && !b.pin,
                "{:?}",
                stray
            );
        }
        assert_eq!(
            parse(&["timeout=0"]).timeout,
            Duration::from_secs(1),
            "clamped"
        );
        assert_eq!(
            parse(&["timeout=9999"]).timeout,
            Duration::from_secs(600),
            "clamped"
        );
    }

    /// Round 8 (Codex 6): the fallback prompts for the PIN from the
    /// effective policy, the line's word else pam_u2f.conf's default, read
    /// as the daemon reads it, so a global `pinverification=1` still
    /// prompts; a file the daemon refuses prompts for nothing (the key is
    /// withheld there anyway).
    #[test]
    fn the_pin_prompt_follows_the_effective_policy() {
        assert!(!wants_pin(None, None));
        assert!(wants_pin(Some(true), None));
        assert!(
            wants_pin(None, Some("pinverification=1\n")),
            "pam_u2f.conf's default"
        );
        assert!(wants_pin(
            None,
            Some("# defaults\nuserpresence=1\npinverification=1\n")
        ));
        assert!(
            !wants_pin(Some(false), Some("pinverification=1\n")),
            "the line wins"
        );
        assert!(wants_pin(Some(true), Some("pinverification=0\n")));
        assert!(
            !wants_pin(None, Some("pinverification=1\ncue\n")),
            "a file the daemon refuses"
        );
        assert_eq!(
            line_pin(&parse(&["key-fallback", "pinverification=0"])),
            Some(false)
        );
        assert_eq!(
            line_pin(&parse(&["key-fallback", "pinverification=1"])),
            Some(true)
        );
        assert_eq!(line_pin(&parse(&["key-fallback"])), None);
    }

    /// Round 8 (Codex 2): the daemon's socket is connected without
    /// blocking: a listener that never accepts, its backlog full, is no
    /// answer at once rather than a hang.
    #[test]
    fn a_daemon_that_never_accepts_is_no_answer_at_once() {
        use std::os::fd::FromRawFd;
        let dir = std::env::temp_dir().join(format!("pam_faceauth-full-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sock");
        // SAFETY: a plain socket call; the fd is owned below.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        // SAFETY: fd is a new descriptor nothing else owns.
        let _listener = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        let (addr, len) = lockgate::sockaddr(&path).unwrap();
        // SAFETY: a valid socket and address for the call.
        unsafe {
            assert_eq!(
                libc::bind(fd, (&addr as *const libc::sockaddr_un).cast(), len),
                0
            );
            assert_eq!(libc::listen(fd, 0), 0);
        }
        let _filled: Vec<_> = (0..4)
            .filter_map(|_| lockgate::connect_nonblocking(&path).ok())
            .collect();
        let t0 = Instant::now();
        assert!(matches!(connect_to(&path), Err(Said::Unreachable)));
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "{:?}",
            t0.elapsed()
        );
        assert!(
            matches!(connect_to(&dir.join("gone/none")), Err(Said::Down)),
            "no runtime directory: down"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fix round 11 (Codex 1): a restart is not "down". The unit keeps its
    /// runtime directory across an automatic restart
    /// (`RuntimeDirectoryPreserve=restart`: systemd removes it only once
    /// the unit is inactive or failed with no restart and no job pending,
    /// src/core/unit.c, `unit_release_resources`, and
    /// src/core/service.c, `service_will_restart`), so a socket missing or
    /// refusing inside a directory that is still there is a daemon
    /// restarting, which goes to the password; only a missing directory (the
    /// service stopped, or failed for good) is down, the stock key.
    #[test]
    fn a_restart_is_not_down() {
        use std::os::unix::net::UnixListener;
        let base =
            std::env::temp_dir().join(format!("pam_faceauth-restart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let run = base.join("faceauth");
        std::fs::create_dir_all(&run).unwrap();
        let sock = run.join("sock");
        assert!(
            matches!(connect_to(&sock), Err(Said::Unreachable)),
            "the directory, no socket yet: restarting"
        );
        drop(UnixListener::bind(&sock).unwrap());
        assert!(sock.exists());
        assert!(
            matches!(connect_to(&sock), Err(Said::Unreachable)),
            "a socket nothing listens on, in the kept directory: restarting"
        );
        std::fs::remove_dir_all(&run).unwrap();
        assert!(
            matches!(connect_to(&sock), Err(Said::Down)),
            "no runtime directory: down"
        );
        // Fix round 12 (Opus): only "not found" is gone; any other answer
        // about the directory is "can't tell", which goes to the password,
        // never to the stock key.
        use std::io::ErrorKind as K;
        assert!(!dir_seen(Err(std::io::Error::from(K::NotFound))), "gone");
        for kind in [
            K::PermissionDenied,
            K::Other,
            K::NotADirectory,
            K::Interrupted,
        ] {
            assert!(
                dir_seen(Err(std::io::Error::from(kind))),
                "{:?}: can't tell",
                kind
            );
        }
        assert!(dir_seen(Ok(())));
        // The same through a connection: a directory under one closed to
        // this process.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            use std::os::unix::fs::PermissionsExt;
            let closed = base.join("closed");
            std::fs::create_dir_all(closed.join("faceauth")).unwrap();
            std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
            let hidden = closed.join("faceauth/sock");
            let seen = connect_to(&hidden);
            std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
            assert!(matches!(seen, Err(Said::Unreachable)), "{:?}", seen.err());
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    /// The daemon's no once a consent request of the user's spent its
    /// wait budget.
    const SPENT: &str = "{\"result\":\"error\",\"message\":\"the consent request just spent its wait budget; use the password\"}\n";

    /// Round 8 (Codex 1, Opus F1): item 12's guarantee again, under the
    /// lock channel's failures. A dropped channel and a stale second one
    /// left open (the daemon saying unknown on every ask), and churn (a
    /// channel opened and closed over and over: unknown, the hold, a
    /// moment unlocked in which a check starts and is cut off, or unknown
    /// and the hold alone) each reach the password within the budget, on
    /// sudo and polkit alike: the key line's wait budget is cumulative and
    /// never reset, and the face line's spent budget sends the key line on
    /// at once.
    #[test]
    fn the_password_is_reached_under_dropped_churning_and_stale_channels() {
        let cases: [(&str, Vec<Turn>); 4] = [
            ("dropped", vec![Turn::Say(BUSY), Turn::Say(WAIT_UNKNOWN)]),
            (
                "stale second",
                vec![Turn::Say(BUSY), Turn::Say(WAIT_UNKNOWN)],
            ),
            (
                "churn, unknown and held",
                vec![Turn::Say(WAIT_UNKNOWN), Turn::Say(WAIT_HELD)],
            ),
            (
                "churn, with checks cut off",
                vec![
                    Turn::Say(WAIT_UNKNOWN),
                    Turn::Say(WAIT_HELD),
                    Turn::Say(READY),
                    Turn::BeatThen(FAST.fallback_deadline - FAST.tick, WAIT_HELD),
                ],
            ),
        ];
        for (name, script) in cases {
            for polkit in [false, true] {
                let d = if name.starts_with("churn") {
                    FakeDaemon::cycling(name, script.clone())
                } else {
                    FakeDaemon::start(name, script.clone())
                };
                let env = FakeEnv::new().with_daemon(&d);
                let face = if name.starts_with("churn") {
                    Said::Unreachable
                } else {
                    face_line(Some(&d))
                };
                let t0 = Instant::now();
                let reached = stack(face, &|| key_line_until(&env, 3 * FAST_BUDGET), polkit);
                assert_eq!(reached, Reached::Password, "{} (polkit {})", name, polkit);
                assert!(
                    t0.elapsed() < FAST_BUDGET,
                    "{} (polkit {}): {:?}",
                    name,
                    polkit,
                    t0.elapsed()
                );
                assert!(env.checks.borrow().is_empty(), "the daemon was up");
            }
        }
        // The face line parks until its budget is spent; the key line
        // then hears it and goes on at once.
        let d = FakeDaemon::start(
            "spent",
            vec![
                Turn::BeatThen(FAST.unknown_limit, UNKNOWN_TOO_LONG),
                Turn::Say(SPENT),
            ],
        );
        let env = FakeEnv::new().with_daemon(&d);
        let t0 = Instant::now();
        assert_eq!(
            stack(
                face_line(Some(&d)),
                &|| key_line(&env, "alice", false, FAST),
                true
            ),
            Reached::Password
        );
        assert!(t0.elapsed() < FAST_BUDGET, "{:?}", t0.elapsed());
    }

    /// Round 8 (Opus L6): a card on screen holding the key is the user's
    /// own work, waited on for free, but not for ever: cards cycled one
    /// after another are charged after `unknown_limit` of them, and the
    /// line then reaches the password.
    #[test]
    fn cycled_cards_reach_the_password() {
        assert_eq!(classify(WAIT_CARD, Ask::KeyReady), Said::CardWait);
        assert_eq!(
            classify(WAIT_LOCKED, Ask::KeyReady),
            Said::Wait(Verdict::Locked)
        );
        let d = FakeDaemon::cycling("cards", vec![Turn::Say(WAIT_CARD)]);
        let env = FakeEnv::new().with_daemon(&d);
        let t0 = Instant::now();
        assert_eq!(
            key_line_until(&env, Duration::from_secs(5)),
            Said::Unreachable
        );
        let took = t0.elapsed();
        assert!(
            took >= 2 * FAST.unknown_limit && took < 2 * FAST.unknown_limit + 4 * FAST.tick,
            "{:?}",
            took
        );
    }

    /// Fix round 9 (Codex 1): a key line held off by another account's
    /// unlock (the daemon says the hold) still reaches the password within
    /// the budget.
    #[test]
    fn a_line_held_off_by_another_accounts_unlock_reaches_the_password() {
        let d = FakeDaemon::cycling("held-off", vec![Turn::Say(WAIT_HELD)]);
        let env = FakeEnv::new().with_daemon(&d);
        let t0 = Instant::now();
        assert_eq!(
            key_line_until(&env, Duration::from_secs(5)),
            Said::Unreachable
        );
        assert!(t0.elapsed() < FAST_BUDGET, "{:?}", t0.elapsed());
    }

    /// Round 16 (Opus N3): the agent's hang-up is seen on a socket, as
    /// polkit's socket-activated helper has, and on a pipe, as a helper an
    /// agent spawns has; nothing is read.
    #[test]
    fn an_agent_hang_up_is_seen_on_a_socket_and_a_pipe() {
        use std::os::fd::AsRawFd;
        let (ours, theirs) = UnixStream::pair().unwrap();
        let agent = Agent(ours.as_raw_fd());
        assert!(!agent.hung_up(), "an agent still there");
        drop(theirs);
        assert!(agent.hung_up(), "an agent gone");
        let mut fds = [0 as c_int; 2];
        // SAFETY: pipe fills the two-element array.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let pipe = Agent(fds[0]);
        assert!(!pipe.hung_up());
        // SAFETY: the write end, closed once.
        unsafe { libc::close(fds[1]) };
        assert!(pipe.hung_up(), "the write end closed");
        // SAFETY: the read end, closed once.
        unsafe { libc::close(fds[0]) };
    }

    /// Live test 1 (2026-10-13): a consent line parked behind the lock ends
    /// when polkit's agent hangs up, though the daemon keeps saying it is
    /// at work: an auth error, which ends polkit's stack, and the line's
    /// connection closes, which the daemon takes for its requester gone.
    #[test]
    fn a_consent_line_ends_when_polkits_agent_hangs_up() {
        use std::os::fd::AsRawFd;
        let d = FakeDaemon::start(
            "agent-consent",
            vec![Turn::BeatThen(Duration::from_secs(4), MATCH)],
        );
        let (ours, theirs) = UnixStream::pair().unwrap();
        let gone = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(theirs);
        });
        let t0 = Instant::now();
        let path = d.path.clone();
        let said = ask_daemon(
            &|| UnixStream::connect(&path).ok(),
            "alice",
            Duration::from_secs(1),
            Ask::Consent,
            FAST,
            Some(Agent(ours.as_raw_fd())),
            None,
        );
        gone.join().unwrap();
        assert_eq!(said, Said::Abandoned);
        assert!(t0.elapsed() < Duration::from_secs(2), "{:?}", t0.elapsed());
        assert_eq!(
            pam_code(said, Ask::Consent),
            PAM_AUTH_ERR,
            "polkit's auth_err=die"
        );
    }

    /// Round 16b (Codex 3): a direct check that the agent's hang-up raced
    /// is no approval: the touch came after nobody was left to hear it.
    #[test]
    fn a_direct_touch_after_polkits_agent_hung_up_is_no_approval() {
        use std::os::fd::AsRawFd;
        let (ours, theirs) = UnixStream::pair().unwrap();
        let theirs = std::cell::RefCell::new(Some(theirs));
        let mut env = FakeEnv::new();
        env.agent = Some(Agent(ours.as_raw_fd()));
        env.check = Box::new(move |_| {
            theirs.borrow_mut().take();
            Ended::Code(KEY_TOUCHED)
        });
        assert_eq!(key_line(&env, "alice", false, FAST), Said::Abandoned);
    }

    /// Round 16c, 17 and 18: a polkit consent line the daemon answers
    /// `need_cookie` asks the agent through the conversation, once, with a
    /// fresh challenge (`lockgate::polkit_cookie_question`), and asks the
    /// daemon again with the cookie from an answer that carries the tag and
    /// that challenge (`lockgate::polkit_cookie_answer`); any other answer,
    /// such as something typed into a prompt shown by mistake, a password
    /// that starts with the tag included, goes nowhere and the line has no
    /// answer; an agent that hung up during the prompt ends it as abandoned,
    /// with no second request; a line with no conversation for it (sudo's)
    /// never asks; and a second `need_cookie` is no answer.
    #[test]
    fn a_polkit_line_brings_the_requests_cookie_when_asked() {
        use std::os::fd::AsRawFd;
        const NEED: &str = "{\"result\":\"need_cookie\"}\n";
        // Every question the fake agents were asked, in order.
        let questions = std::cell::RefCell::new(Vec::<String>::new());
        // The fake agent reads the challenge off the question and puts it
        // where its answer says `{c}`.
        let ask =
            |d: &FakeDaemon, answer: Option<&'static [u8]>, polkit: bool, agent: Option<Agent>| {
                let path = d.path.clone();
                let asked = std::cell::Cell::new(0);
                let cookie_of = |question: &str| {
                    asked.set(asked.get() + 1);
                    questions.borrow_mut().push(question.to_string());
                    let challenge = question
                        .strip_prefix(lockgate::POLKIT_COOKIE_PROMPT)
                        .expect("the cookie question");
                    answer.map(|a| {
                        Wiped(
                            String::from_utf8(a.to_vec())
                                .unwrap()
                                .replace("{c}", challenge)
                                .into_bytes(),
                        )
                    })
                };
                let said = ask_daemon(
                    &|| UnixStream::connect(&path).ok(),
                    "alice",
                    Duration::from_secs(1),
                    Ask::Consent,
                    FAST,
                    agent,
                    if polkit { Some(&cookie_of) } else { None },
                );
                (said, asked.get())
            };
        let d = FakeDaemon::start("cookie-good", vec![Turn::Say(NEED), Turn::Say(MATCH)]);
        assert_eq!(
            ask(&d, Some(b"faceauth-cookie {c} 1-0123abcd-77-1"), true, None),
            (Said::Match, 1)
        );
        let got = d.got();
        assert_eq!(got.len(), 2, "{:?}", got);
        assert!(!got[0].contains("polkit_cookie"), "{}", got[0]);
        assert!(
            got[1].contains("\"polkit_cookie\":\"1-0123abcd-77-1\""),
            "{}",
            got[1]
        );
        let d = FakeDaemon::start("cookie-none", vec![Turn::Say(NEED), Turn::Say(MATCH)]);
        assert_eq!(
            ask(&d, Some(b"faceauth-cookie {c} "), true, None),
            (Said::Match, 1)
        );
        assert!(
            d.got()[1].contains("\"polkit_cookie\":\"\""),
            "an agent with no cookie"
        );
        // Each question is the prompt's text and a challenge of its own.
        {
            let q = questions.borrow();
            assert_eq!(q.len(), 2, "{:?}", q);
            for question in q.iter() {
                let challenge = question
                    .strip_prefix(lockgate::POLKIT_COOKIE_PROMPT)
                    .unwrap();
                assert_eq!(challenge.len(), 32, "{}", question);
                assert!(
                    challenge
                        .bytes()
                        .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                    "{}",
                    question
                );
            }
            assert_ne!(q[0], q[1], "a fresh challenge for each question");
        }
        // Round 18: round 17's answer, the tag and a cookie with no
        // challenge, is what a password that starts with the tag makes; it
        // and an answer with another challenge go nowhere, like any
        // untagged one.
        for typed in [
            &b"hunter2"[..],
            b"1-0123abcd-77-1",
            b"hunter2 \"x",
            b"faceauth-cookie 1-0123abcd-77-1",
            b"faceauth-cookie ",
            b"faceauth-cookie 0123456789abcdef0123456789abcdef 1-0123abcd-77-1",
            b"faceauth-cookie {c}1-0123abcd-77-1",
            b"faceauth-cookie {c}",
            b"faceauth-cookie {c} hunter 2",
        ] {
            let d = FakeDaemon::start("cookie-typed", vec![Turn::Say(NEED), Turn::Say(MATCH)]);
            let typed: &'static [u8] = Box::leak(typed.to_vec().into_boxed_slice());
            assert_eq!(
                ask(&d, Some(typed), true, None),
                (Said::Unreachable, 1),
                "{}",
                String::from_utf8_lossy(typed)
            );
            assert_eq!(
                d.got().len(),
                1,
                "an answer without the question's challenge is never sent: {:?}",
                d.got()
            );
        }
        // The agent hangs up while the prompt is out: no answer comes, and
        // the line ends as abandoned without asking the daemon again.
        let d = FakeDaemon::start("cookie-gone", vec![Turn::Say(NEED), Turn::Say(MATCH)]);
        let (ours, theirs) = UnixStream::pair().unwrap();
        let theirs = std::cell::RefCell::new(Some(theirs));
        let asked = std::cell::Cell::new(0);
        let hang_up = |_: &str| {
            asked.set(asked.get() + 1);
            theirs.borrow_mut().take();
            None
        };
        let path = d.path.clone();
        let said = ask_daemon(
            &|| UnixStream::connect(&path).ok(),
            "alice",
            Duration::from_secs(1),
            Ask::Consent,
            FAST,
            Some(Agent(ours.as_raw_fd())),
            Some(&hang_up),
        );
        assert_eq!((said, asked.get()), (Said::Abandoned, 1));
        assert_eq!(
            d.got().len(),
            1,
            "no second request after the agent hung up"
        );
        let d = FakeDaemon::start("cookie-silent", vec![Turn::Say(NEED), Turn::Say(MATCH)]);
        assert_eq!(ask(&d, None, true, None), (Said::Unreachable, 1));
        assert_eq!(d.got().len(), 1);
        let d = FakeDaemon::start("cookie-sudo", vec![Turn::Say(NEED), Turn::Say(MATCH)]);
        assert_eq!(
            ask(
                &d,
                Some(b"faceauth-cookie {c} 1-0123abcd-77-1"),
                false,
                None
            ),
            (Said::Unreachable, 0)
        );
        assert_eq!(d.got().len(), 1, "sudo asks once");
        let d = FakeDaemon::start("cookie-twice", vec![Turn::Say(NEED), Turn::Say(NEED)]);
        assert_eq!(
            ask(&d, Some(b"faceauth-cookie {c} 1-0123abcd-77-1"), true, None),
            (Said::Unreachable, 1)
        );
        assert_eq!(
            pam_code(Said::NeedCookie, Ask::Consent),
            PAM_AUTHINFO_UNAVAIL
        );
    }

    /// Round 18: each cookie question's challenge is 32 lowercase hex
    /// characters from the kernel's random source, never one seen before.
    #[test]
    fn each_cookie_question_has_a_fresh_challenge() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..256 {
            let c = fresh_challenge().expect("a challenge");
            assert_eq!(c.len(), 32, "{}", c);
            assert!(
                c.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                "{}",
                c
            );
            assert!(seen.insert(c.clone()), "{} twice", c);
        }
    }

    /// The same for polkit's key line waiting behind a positive lock, which
    /// it does without a deadline.
    #[test]
    fn a_key_line_waiting_on_the_lock_ends_when_polkits_agent_hangs_up() {
        use std::os::fd::AsRawFd;
        // Two seconds of a positive lock (40 ticks at FAST's scale), then an
        // error, so a line that never sees the hang-up still ends.
        let mut script: Vec<Turn> = (0..40).map(|_| Turn::Say(WAIT_LOCKED)).collect();
        script.push(Turn::Say(BUSY));
        let d = FakeDaemon::start("agent-key", script);
        let (ours, theirs) = UnixStream::pair().unwrap();
        let mut env = FakeEnv::new().with_daemon(&d);
        env.agent = Some(Agent(ours.as_raw_fd()));
        let gone = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(theirs);
        });
        let t0 = Instant::now();
        let said = key_line(&env, "alice", false, FAST);
        gone.join().unwrap();
        assert_eq!(said, Said::Abandoned);
        assert!(t0.elapsed() < Duration::from_secs(1), "{:?}", t0.elapsed());
        assert_eq!(pam_code(said, Ask::KeyFallback), PAM_AUTH_ERR);
    }
}
