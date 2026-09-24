//! `pam_faceauth.so`: the smallest possible PAM module.
//!
//! It asks `faceauthd` over its Unix socket whether the user in front of the
//! camera is the user being authenticated, and maps the answer:
//!
//! - match                        -> PAM_SUCCESS
//! - refused                      -> PAM_AUTH_ERR (consent lines only: a head
//!   shake, a dismissed window, or a confirm after the nods that failed;
//!   the daemon sends it on the polkit lane, where the agent cancels the
//!   request on it, and answers sudo with "not by face" instead)
//! - anything else, any failure   -> PAM_IGNORE
//!
//! No camera, no models, no templates, no image data in this process, and no
//! conversation with the application: the module never prompts and never
//! sees a password. Every failure path is PAM_IGNORE so that under
//! `sufficient` or `[success=done default=ignore]` the stack falls through to
//! the password; lockout is structurally impossible from here. Panics are
//! caught and become PAM_IGNORE too. The one deliberate answer, a refusal, is
//! PAM_AUTH_ERR so that a consent line written as
//! `[success=done auth_err=die default=ignore]` ends the stack on it: the
//! window had the password box, so closing it without a password or a nod is
//! the answer no, and no other prompt follows.
//!
//! Module arguments (in the PAM line), and no others:
//!
//! - `socket=/run/faceauth/sock`: where the daemon listens.
//! - `consent`: the elevation argument, for sudo and polkit. The daemon opens
//!   a window naming the command and the requester, and the request is
//!   approved by two nods or by the password typed into that window; sitting
//!   in front of the machine never elevates anything by itself. The window
//!   waits until it is answered, so `timeout=` is ignored on a consent line
//!   (the module logs that it was).
//! - `timeout=8`: seconds to wait for the daemon's reply on a plain look (the
//!   lock screen, where looking at the machine is the act).
//!
//! Any other word is ignored and logged: a misspelt `consent` must not pass
//! in silence, and the daemon refuses the plain look it would leave from a
//! root caller.
//!
//! The daemon trusts an effective-uid-0 peer with its root-only requests
//! (enrolment, deletion, calibration), and under sudo and polkit this module
//! runs as root. It therefore builds exactly two request shapes, the plain
//! look and the consent request, in one place (`request_line`), and a test
//! pins that no other field can ever leave this module.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::Duration;

const PAM_SUCCESS: c_int = 0;
/// PAM_RHOST: set by network services (sshd) to the remote host name.
const PAM_RHOST: c_int = 4;
const PAM_IGNORE: c_int = 25;
const PAM_AUTH_ERR: c_int = 7;

const DEFAULT_SOCKET: &str = "/run/faceauth/sock";
const DEFAULT_TIMEOUT: u64 = 8;
const MAX_REPLY: usize = 4096;

#[repr(C)]
pub struct pam_handle_t {
    _private: [u8; 0],
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

struct Args {
    socket: String,
    timeout: Duration,
    /// Elevation: the daemon opens the window and requires the nod. No
    /// conversation with the caller at all, since the caller cannot be trusted
    /// to relay a yes.
    consent: bool,
}

const LOG_AUTHPRIV_INFO: c_int = (10 << 3) | 6;

/// One line to the auth log per decision, for measuring the stack around
/// us. Through `pam_syslog`, which prefixes the module and the service
/// (`pam_faceauth(sudo:auth)`), so the log says which stack decided. Never
/// includes a password: the module never holds one.
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
    Other,
}

/// The only place a request to the daemon is built. Two shapes exist: the
/// plain look and the consent request. The name goes in verbatim, so a name
/// that would need escaping (a quote, a backslash, a control character) is
/// refused here rather than rewritten into a different name: the daemon must
/// be asked about PAM_USER or about nobody.
fn request_line(user: &str, consent: bool) -> Option<String> {
    if user.is_empty()
        || user.len() > 256
        || user
            .chars()
            .any(|c| c == '"' || c == '\\' || c.is_control())
    {
        return None;
    }
    Some(if consent {
        format!("{{\"user\":\"{}\",\"consent\":true}}\n", user)
    } else {
        format!("{{\"user\":\"{}\"}}\n", user)
    })
}

/// The whole conversation with the daemon. Anything but a match or a
/// refusal, and any error, is `Said::Other`.
fn daemon_says(
    pamh: *const pam_handle_t,
    socket: &Path,
    user: &str,
    timeout: Duration,
    consent: bool,
) -> Said {
    let Some(req) = request_line(user, consent) else {
        log(pamh, "user name would need escaping; not asking the daemon");
        return Said::Other;
    };
    let Ok(mut stream) = UnixStream::connect(socket) else {
        return Said::Other;
    };
    // The socket lives under a root-owned runtime directory, so nobody else
    // can put a listener there; this check is the belt to that suspender. A
    // peer that is not root is not the daemon, and its answers are nobody's.
    if !peer_is_root(&stream) {
        log(
            pamh,
            "the socket's peer is not root; not the daemon, ignoring it",
        );
        return Said::Other;
    }
    // A consent request has no deadline: the daemon answers when the user does.
    let read_timeout = if consent { None } else { Some(timeout) };
    if stream.set_read_timeout(read_timeout).is_err()
        || stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .is_err()
    {
        return Said::Other;
    }
    if stream.write_all(req.as_bytes()).is_err() {
        return Said::Other;
    }
    let mut line = String::new();
    let mut reader = BufReader::new(stream).take(MAX_REPLY as u64);
    if reader.read_line(&mut line).is_err() {
        return Said::Other;
    }
    classify(&line, consent)
}

/// The daemon serialises the tag first and always follows it with more
/// fields: the reply must BEGIN with the match object, so no later field
/// (which may echo request bytes) can ever make a non-match read as one. A
/// refusal is read the same way, and only on a consent line: a plain scan
/// has no answer no.
fn classify(line: &str, consent: bool) -> Said {
    let t = line.trim_start();
    if t.starts_with("{\"result\":\"match\",") {
        Said::Match
    } else if consent && t.starts_with("{\"result\":\"refused\",") {
        Said::Refused
    } else {
        Said::Other
    }
}

fn authenticate(pamh: *mut pam_handle_t, argc: c_int, argv: *const *const c_char) -> c_int {
    let args = parse_args(pamh, argc, argv);
    let mut user_ptr: *const c_char = std::ptr::null();
    // SAFETY: pamh is the handle PAM gave us; user_ptr is a valid out-pointer.
    let rc = unsafe { pam_get_user(pamh, &mut user_ptr, std::ptr::null()) };
    if rc != PAM_SUCCESS || user_ptr.is_null() {
        return PAM_IGNORE;
    }
    // A name that is not UTF-8 is refused, not rewritten: a rewritten name
    // would ask the daemon about a different user than PAM_USER.
    let Ok(user) = unsafe { CStr::from_ptr(user_ptr) }
        .to_str()
        .map(str::to_owned)
    else {
        log(pamh, "user name is not UTF-8, ignoring");
        return PAM_IGNORE;
    };
    if user.is_empty() || user.len() > 256 {
        return PAM_IGNORE;
    }
    // A remote host on the transaction means a network login (sshd sets it):
    // the camera cannot vouch for that caller, so no scan. The daemon checks
    // the caller's ancestry and logind session itself; this is the cheap
    // first gate, not the trusted one.
    let mut rhost: *const c_void = std::ptr::null();
    // SAFETY: pamh is PAM's handle; rhost is a valid out-pointer.
    if unsafe { pam_get_item(pamh, PAM_RHOST, &mut rhost) } == PAM_SUCCESS && !rhost.is_null() {
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
            return PAM_IGNORE;
        }
    }
    let t0 = std::time::Instant::now();
    let said = daemon_says(
        pamh,
        Path::new(&args.socket),
        &user,
        args.timeout,
        args.consent,
    );
    log(
        pamh,
        &format!(
            "user {}: {} after {} ms",
            sanitise(&user),
            match said {
                Said::Match => "match, success",
                Said::Refused => "refused by the user, auth error",
                Said::Other => "no match or no daemon, ignore",
            },
            t0.elapsed().as_millis()
        ),
    );
    match said {
        Said::Match => PAM_SUCCESS,
        Said::Refused => PAM_AUTH_ERR,
        Said::Other => PAM_IGNORE,
    }
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(
    pamh: *mut pam_handle_t,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    catch_unwind(AssertUnwindSafe(|| authenticate(pamh, argc, argv))).unwrap_or(PAM_IGNORE)
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

    #[test]
    fn replies_are_read_by_their_leading_tag_only() {
        assert_eq!(
            classify("{\"result\":\"match\",\"frames\":2}", true),
            Said::Match
        );
        assert_eq!(
            classify(
                "{\"result\":\"refused\",\"reason\":\"shaken\",\"elapsed_ms\":5}",
                true
            ),
            Said::Refused
        );
        assert_eq!(
            classify("{\"result\":\"refused\",\"reason\":\"shaken\"}", false),
            Said::Other,
            "a plain scan has no refusal"
        );
        assert_eq!(
            classify(
                "{\"result\":\"consent_denied\",\"reason\":\"no answer\"}",
                true
            ),
            Said::Other
        );
        assert_eq!(
            classify(
                "{\"result\":\"no_match\",\"message\":\"{\\\"result\\\":\\\"match\\\",\"}",
                true
            ),
            Said::Other
        );
        assert_eq!(classify("", true), Said::Other);
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

    #[test]
    fn no_daemon_is_not_a_match() {
        assert_eq!(
            daemon_says(
                std::ptr::null(),
                Path::new("/nonexistent/faceauth.sock"),
                "alice",
                Duration::from_secs(1),
                false
            ),
            Said::Other
        );
    }

    /// F7: a name the escaper would have altered is refused, not rewritten.
    #[test]
    fn a_name_that_needs_escaping_is_refused() {
        assert_eq!(
            request_line("alice", false).as_deref(),
            Some("{\"user\":\"alice\"}\n")
        );
        assert_eq!(
            request_line("alice", true).as_deref(),
            Some("{\"user\":\"alice\",\"consent\":true}\n")
        );
        for bad in [
            "ali\u{7}ce",
            "ali\"ce",
            "ali\\ce",
            "alice\n",
            "",
            "alice\u{7f}",
        ] {
            assert!(request_line(bad, false).is_none(), "{:?} was sent", bad);
            assert!(request_line(bad, true).is_none(), "{:?} was sent", bad);
        }
        assert!(request_line(&"a".repeat(257), false).is_none());
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
                true
            ),
            Said::Other
        );
        assert_eq!(
            listener.accept().map(|_| ()).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "a connection was made for a refused name"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F10: the daemon trusts a root peer with enrolment, deletion and
    /// calibration, and this module runs as root under sudo and polkit. The
    /// request builder is the one place a request is made, and the only keys
    /// it can write are `user` and `consent`.
    #[test]
    fn the_module_can_only_emit_a_look_or_a_consent_request() {
        let src = include_str!("lib.rs");
        let start = src
            .find("fn request_line(")
            .expect("the request builder exists");
        let body = &src[start..];
        let body = &body[..body.find("\n}\n").expect("the builder ends")];
        // Every JSON key the builder writes is a `\"name\":` fragment in a format string.
        let mut keys = std::collections::BTreeSet::new();
        for (i, _) in body.match_indices("\\\"") {
            let after = &body[i + 2..];
            let ident: String = after
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if !ident.is_empty() && after[ident.len()..].starts_with("\\\":") {
                keys.insert(ident);
            }
        }
        assert_eq!(
            keys.into_iter().collect::<Vec<_>>(),
            ["consent", "user"],
            "the builder emits exactly these request keys"
        );
        // The rest of the module builds no request at all: no other format string opens a JSON object.
        let non_test = &src[..src.find("#[cfg(test)]").unwrap()];
        let object_openers = non_test.matches("format!(\"{{").count();
        assert_eq!(
            object_openers, 2,
            "the two shapes in request_line are the only JSON objects the module formats"
        );
        for root_only in [
            ["en", "rol"].concat(),
            ["del", "ete"].concat(),
            ["cali", "brate"].concat(),
        ] {
            assert!(
                !body.contains(&root_only),
                "the builder names {}",
                root_only
            );
        }
    }

    #[test]
    fn args_parse_with_defaults() {
        let a = parse_args(std::ptr::null(), 0, std::ptr::null());
        assert_eq!(a.socket, DEFAULT_SOCKET);
        assert_eq!(a.timeout, Duration::from_secs(DEFAULT_TIMEOUT));
        assert!(!a.consent);
    }

    fn parse(words: &[&str]) -> Args {
        let args: Vec<std::ffi::CString> = words
            .iter()
            .map(|s| std::ffi::CString::new(*s).unwrap())
            .collect();
        let ptrs: Vec<*const c_char> = args.iter().map(|c| c.as_ptr()).collect();
        parse_args(std::ptr::null(), words.len() as c_int, ptrs.as_ptr())
    }

    /// The module's whole argument surface: `socket=`, `timeout=` and
    /// `consent`. The old `prompt` mode is gone, and any other word changes
    /// nothing (it is logged), so a misspelt `consent` leaves a plain look
    /// the daemon refuses from a root caller.
    #[test]
    fn the_only_arguments_are_socket_timeout_and_consent() {
        let a = parse(&["socket=/run/x/sock", "timeout=3", "consent"]);
        assert_eq!(a.socket, "/run/x/sock");
        assert_eq!(a.timeout, Duration::from_secs(3));
        assert!(a.consent);
        let defaults = parse(&[]);
        for stray in [
            "prompt",
            "prompt=Face:_Enter_to_scan",
            "consnet",
            "try_first_pass",
            "timeout=abc",
            "",
        ] {
            let b = parse(&[stray]);
            assert_eq!(b.socket, defaults.socket, "{:?}", stray);
            assert_eq!(b.timeout, defaults.timeout, "{:?}", stray);
            assert!(!b.consent, "{:?}", stray);
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
        // The source names no other argument either.
        let src = include_str!("lib.rs");
        let non_test = &src[..src.find("#[cfg(test)]").unwrap()];
        assert!(!non_test.contains("PAM_AUTHTOK") && !non_test.contains("PAM_CONV"));
        assert!(!non_test.contains("pam_set_item"));
    }
}
