//! `pam_faceauth.so`: the smallest possible PAM module.
//!
//! It asks `faceauthd` over its Unix socket whether the user in front of the
//! camera is the user being authenticated, and maps the answer:
//!
//! - match                        -> PAM_SUCCESS
//! - refused                      -> PAM_AUTH_ERR (consent lines only: a head
//!   shake, a dismissed window, or a confirm after the nods that failed)
//! - anything else, any failure   -> PAM_IGNORE
//!
//! No camera, no models, no templates, no image data in this process. Every
//! failure path is PAM_IGNORE so that under `sufficient` or
//! `[success=done default=ignore]` the stack falls through to the password;
//! lockout is structurally impossible from here. Panics are caught and become
//! PAM_IGNORE too. The one deliberate answer, a refusal, is PAM_AUTH_ERR so
//! that a consent line written as `[success=done auth_err=die default=ignore]`
//! ends the stack on it: the window had the password box, so closing it
//! without a password or a nod is the answer no, and no other prompt follows.
//!
//! Module arguments (in the PAM line):
//!
//! - `socket=/run/faceauth/sock`: where the daemon listens.
//! - `consent`: the elevation argument, for sudo and polkit. The daemon opens
//!   a window naming the command and the requester, and the request is
//!   approved by two nods or by the password typed into that window; sitting
//!   in front of the machine never elevates anything by itself. The window
//!   waits until it is answered, so `timeout=` is ignored on a consent line
//!   (the module logs that it was) and `prompt` is not consulted.
//! - `timeout=8`: seconds to wait for the daemon's reply on a plain look (the
//!   lock screen, where looking at the machine is the act).
//! - `prompt`: the older deliberate act for a caller that has a conversation:
//!   Enter on an empty line runs the face scan, anything typed is handed on
//!   as the password (PAM_AUTHTOK, for the `try_first_pass` module behind us,
//!   byte for byte) and no scan runs. `consent` is preferred for elevation
//!   because the caller relaying the conversation is the process asking to be
//!   elevated.
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
const PAM_AUTHTOK: c_int = 6;
const PAM_CONV: c_int = 5;
const PAM_PROMPT_ECHO_OFF: c_int = 1;

#[repr(C)]
struct pam_message {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct pam_response {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct pam_conv {
    conv: Option<unsafe extern "C" fn(c_int, *mut *const pam_message, *mut *mut pam_response, *mut c_void) -> c_int>,
    appdata_ptr: *mut c_void,
}

const DEFAULT_SOCKET: &str = "/run/faceauth/sock";
const DEFAULT_TIMEOUT: u64 = 8;
const MAX_REPLY: usize = 4096;

#[repr(C)]
pub struct pam_handle_t {
    _private: [u8; 0],
}

extern "C" {
    fn syslog(priority: c_int, fmt: *const c_char, ...);
    fn pam_get_user(pamh: *mut pam_handle_t, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_get_item(pamh: *const pam_handle_t, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_set_item(pamh: *mut pam_handle_t, item_type: c_int, item: *const c_void) -> c_int;
    fn free(p: *mut c_void);
}

struct Args {
    socket: String,
    timeout: Duration,
    prompt: Option<String>,
    /// Elevation: the daemon opens the window and requires the nod. No
    /// conversation with the caller at all, since the caller cannot be trusted
    /// to relay a yes.
    consent: bool,
}

const LOG_AUTHPRIV_INFO: c_int = (10 << 3) | 6;

/// One line to the auth log per decision, for `doctor` and for measuring the
/// stack around us. Never includes the password.
fn log(msg: &str) {
    if let Ok(c) = std::ffi::CString::new(msg) {
        let fmt = b"pam_faceauth: %s\0";
        // SAFETY: format string with one %s and a matching C string argument.
        unsafe { syslog(LOG_AUTHPRIV_INFO, fmt.as_ptr() as *const c_char, c.as_ptr()) };
    }
}

/// Overwrite a buffer that may hold a password before it is freed.
fn wipe_bytes(mut bytes: Vec<u8>) {
    for b in bytes.iter_mut() {
        // Volatile so the compiler keeps the stores to a buffer it is about to free.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    drop(bytes);
}

/// Overwrite a CString's bytes before it is freed.
fn wipe(c: std::ffi::CString) {
    wipe_bytes(c.into_bytes());
}

/// Names go into the auth log; strip anything that could forge a line.
fn sanitise(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(64).collect()
}

const DEFAULT_PROMPT: &str = "Press Enter to authenticate by face, or type your password: ";

/// Ask through the application's conversation. `Ok(Some(bytes))` is what the
/// user typed (empty for a bare Enter), kept as the bytes the application
/// handed over because a password is not text: rewriting it into UTF-8 would
/// hand the module behind us a password that can never match. `Ok(None)`
/// means no conversation is available, `Err` that the application refused.
fn converse(pamh: *mut pam_handle_t, text: &str) -> Result<Option<Vec<u8>>, ()> {
    let mut item: *const c_void = std::ptr::null();
    // SAFETY: pamh is PAM's handle; item is a valid out-pointer.
    let rc = unsafe { pam_get_item(pamh, PAM_CONV, &mut item) };
    if rc != PAM_SUCCESS || item.is_null() {
        return Ok(None);
    }
    let conv = unsafe { &*(item as *const pam_conv) };
    let Some(f) = conv.conv else { return Ok(None) };
    let ctext = std::ffi::CString::new(text).map_err(|_| ())?;
    let msg = pam_message { msg_style: PAM_PROMPT_ECHO_OFF, msg: ctext.as_ptr() };
    let mut msg_ptr: *const pam_message = &msg;
    let mut resp: *mut pam_response = std::ptr::null_mut();
    // SAFETY: one message, one response slot; the application allocates the
    // response array with malloc and we free it (the PAM contract).
    let rc = unsafe { f(1, &mut msg_ptr, &mut resp, conv.appdata_ptr) };
    if rc != PAM_SUCCESS || resp.is_null() {
        return Err(());
    }
    let out = unsafe {
        let r = &*resp;
        let bytes = if r.resp.is_null() { Vec::new() } else { CStr::from_ptr(r.resp).to_bytes().to_vec() };
        if !r.resp.is_null() {
            // Wipe before freeing: it may be a password.
            let len = bytes.len();
            std::ptr::write_bytes(r.resp, 0, len);
            free(r.resp as *mut c_void);
        }
        free(resp as *mut c_void);
        bytes
    };
    Ok(Some(out))
}

fn parse_args(argc: c_int, argv: *const *const c_char) -> Args {
    let mut a = Args { socket: DEFAULT_SOCKET.to_string(), timeout: Duration::from_secs(DEFAULT_TIMEOUT), prompt: None, consent: false };
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
        } else if s == "prompt" {
            a.prompt = Some(DEFAULT_PROMPT.to_string());
        } else if let Some(v) = s.strip_prefix("prompt=") {
            a.prompt = Some(v.replace('_', " "));
        }
    }
    if a.consent && timeout_given {
        // A consent line waits for the user, without limit: the window sits
        // there until it is answered. `timeout=` bounds a plain look only.
        log("timeout= is ignored on a consent line; the window waits until it is answered");
    }
    a
}

/// The whole conversation with the daemon. Any error is `false`.
/// Is the process on the other end of `stream` running as root?
fn peer_is_root(stream: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: u32::MAX, gid: u32::MAX };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a valid socket fd, a correctly sized out-buffer and its length.
    let rc = unsafe { libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut libc::ucred as *mut c_void, &mut len) };
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
    if user.is_empty() || user.len() > 256 || user.chars().any(|c| c == '"' || c == '\\' || c.is_control()) {
        return None;
    }
    Some(if consent { format!("{{\"user\":\"{}\",\"consent\":true}}\n", user) } else { format!("{{\"user\":\"{}\"}}\n", user) })
}

fn daemon_says(socket: &Path, user: &str, timeout: Duration, consent: bool) -> Said {
    let Some(req) = request_line(user, consent) else {
        log("user name would need escaping; not asking the daemon");
        return Said::Other;
    };
    let Ok(mut stream) = UnixStream::connect(socket) else { return Said::Other };
    // The socket lives under a root-owned runtime directory, so nobody else
    // can put a listener there; this check is the belt to that suspender. A
    // peer that is not root is not the daemon, and its answers are nobody's.
    if !peer_is_root(&stream) {
        log("the socket's peer is not root; not the daemon, ignoring it");
        return Said::Other;
    }
    // A consent request has no deadline: the daemon answers when the user does.
    let read_timeout = if consent { None } else { Some(timeout) };
    if stream.set_read_timeout(read_timeout).is_err() || stream.set_write_timeout(Some(Duration::from_secs(2))).is_err() {
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

/// The daemon serialises the tag first: the reply must BEGIN with the match
/// object, so no later field (which may echo request bytes) can ever make a
/// non-match read as one. A refusal is read the same way, and only on a
/// consent line: a plain scan has no answer no.
fn classify(line: &str, consent: bool) -> Said {
    let t = line.trim_start();
    if t.starts_with("{\"result\":\"match\",") || t == "{\"result\":\"match\"}" {
        Said::Match
    } else if consent && t.starts_with("{\"result\":\"refused\",") {
        Said::Refused
    } else {
        Said::Other
    }
}

fn authenticate(pamh: *mut pam_handle_t, argc: c_int, argv: *const *const c_char) -> c_int {
    let args = parse_args(argc, argv);
    let mut user_ptr: *const c_char = std::ptr::null();
    // SAFETY: pamh is the handle PAM gave us; user_ptr is a valid out-pointer.
    let rc = unsafe { pam_get_user(pamh, &mut user_ptr, std::ptr::null()) };
    if rc != PAM_SUCCESS || user_ptr.is_null() {
        return PAM_IGNORE;
    }
    // A name that is not UTF-8 is refused, not rewritten: a rewritten name
    // would ask the daemon about a different user than PAM_USER.
    let Ok(user) = unsafe { CStr::from_ptr(user_ptr) }.to_str().map(str::to_owned) else {
        log("user name is not UTF-8, ignoring");
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
            log(&format!("user {}: remote host {} on the transaction, no scan", sanitise(&user), sanitise(&host)));
            return PAM_IGNORE;
        }
    }
    let t0 = std::time::Instant::now();
    if let (Some(text), false) = (&args.prompt, args.consent) {
        match converse(pamh, text) {
            // Typed something: that is the password for the module behind us,
            // handed on as the bytes typed; no scan.
            Ok(Some(typed)) if !typed.is_empty() => {
                // The bytes came from a C string, so they hold no NUL and this cannot fail.
                if let Ok(tok) = std::ffi::CString::new(typed) {
                    // SAFETY: PAM copies the item.
                    unsafe { pam_set_item(pamh, PAM_AUTHTOK, tok.as_ptr() as *const c_void) };
                    // The password must not linger in freed heap.
                    wipe(tok);
                }
                log(&format!("user {}: password typed at the prompt, no scan", sanitise(&user)));
                return PAM_IGNORE;
            }
            // Bare Enter: the deliberate act. Scan.
            Ok(Some(_)) => {}
            // No conversation (a non-interactive caller): do not scan on our own initiative.
            Ok(None) => return PAM_IGNORE,
            Err(()) => return PAM_IGNORE,
        }
    }
    let said = daemon_says(Path::new(&args.socket), &user, args.timeout, args.consent);
    log(&format!("user {}: {} after {} ms", sanitise(&user), match said { Said::Match => "match, success", Said::Refused => "refused by the user, auth error", Said::Other => "no match or no daemon, ignore" }, t0.elapsed().as_millis()));
    match said {
        Said::Match => PAM_SUCCESS,
        Said::Refused => PAM_AUTH_ERR,
        Said::Other => PAM_IGNORE,
    }
}

#[no_mangle]
pub extern "C" fn pam_sm_authenticate(pamh: *mut pam_handle_t, _flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    catch_unwind(AssertUnwindSafe(|| authenticate(pamh, argc, argv))).unwrap_or(PAM_IGNORE)
}

#[no_mangle]
pub extern "C" fn pam_sm_setcred(_pamh: *mut pam_handle_t, _flags: c_int, _argc: c_int, _argv: *const *const c_char) -> c_int {
    PAM_IGNORE
}

#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(_pamh: *mut pam_handle_t, _flags: c_int, _argc: c_int, _argv: *const *const c_char) -> c_int {
    PAM_IGNORE
}

#[allow(dead_code)]
fn _keep(_: *mut c_void) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replies_are_read_by_their_leading_tag_only() {
        assert_eq!(classify("{\"result\":\"match\",\"frames\":2}", true), Said::Match);
        assert_eq!(classify("{\"result\":\"refused\",\"reason\":\"shaken\",\"elapsed_ms\":5}", true), Said::Refused);
        assert_eq!(classify("{\"result\":\"refused\",\"reason\":\"shaken\"}", false), Said::Other, "a plain scan has no refusal");
        assert_eq!(classify("{\"result\":\"consent_denied\",\"reason\":\"no answer\"}", true), Said::Other);
        assert_eq!(classify("{\"result\":\"no_match\",\"message\":\"{\\\"result\\\":\\\"match\\\",\"}", true), Said::Other);
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
        assert_eq!(daemon_says(Path::new("/nonexistent/faceauth.sock"), "alice", Duration::from_secs(1), false), Said::Other);
    }

    /// F7: a typed password reaches PAM_AUTHTOK as the bytes typed. The
    /// conversion the module applies is CStr bytes to CString, with no text
    /// decoding in between, so a Latin-1 byte survives.
    #[test]
    fn a_typed_password_keeps_its_bytes() {
        let typed: &[u8] = b"caf\xe9-pass\0";
        let c = CStr::from_bytes_with_nul(typed).unwrap();
        let as_module_keeps_it = c.to_bytes().to_vec();
        let handed_on = std::ffi::CString::new(as_module_keeps_it).unwrap();
        assert_eq!(handed_on.as_bytes(), &typed[..typed.len() - 1], "the bytes handed to PAM_AUTHTOK are the bytes typed");
        assert_ne!(handed_on.as_bytes(), "caf\u{FFFD}-pass".as_bytes(), "no replacement character was introduced");
    }

    /// F7: a name the escaper would have altered is refused, not rewritten.
    #[test]
    fn a_name_that_needs_escaping_is_refused() {
        assert_eq!(request_line("alice", false).as_deref(), Some("{\"user\":\"alice\"}\n"));
        assert_eq!(request_line("alice", true).as_deref(), Some("{\"user\":\"alice\",\"consent\":true}\n"));
        for bad in ["ali\u{7}ce", "ali\"ce", "ali\\ce", "alice\n", "", "alice\u{7f}"] {
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
        assert_eq!(daemon_says(&path, "ali\u{7}ce", Duration::from_secs(1), true), Said::Other);
        assert_eq!(listener.accept().map(|_| ()).unwrap_err().kind(), std::io::ErrorKind::WouldBlock, "a connection was made for a refused name");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// F10: the daemon trusts a root peer with enrolment, deletion and
    /// calibration, and this module runs as root under sudo and polkit. The
    /// request builder is the one place a request is made, and the only keys
    /// it can write are `user` and `consent`.
    #[test]
    fn the_module_can_only_emit_a_look_or_a_consent_request() {
        let src = include_str!("lib.rs");
        let start = src.find("fn request_line(").expect("the request builder exists");
        let body = &src[start..];
        let body = &body[..body.find("\n}\n").expect("the builder ends")];
        // Every JSON key the builder writes is a `\"name\":` fragment in a format string.
        let mut keys = std::collections::BTreeSet::new();
        for (i, _) in body.match_indices("\\\"") {
            let after = &body[i + 2..];
            let ident: String = after.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
            if !ident.is_empty() && after[ident.len()..].starts_with("\\\":") {
                keys.insert(ident);
            }
        }
        assert_eq!(keys.into_iter().collect::<Vec<_>>(), ["consent", "user"], "the builder emits exactly these request keys");
        // The rest of the module builds no request at all: no other format string opens a JSON object.
        let non_test = &src[..src.find("#[cfg(test)]").unwrap()];
        let object_openers = non_test.matches("format!(\"{{").count();
        assert_eq!(object_openers, 2, "the two shapes in request_line are the only JSON objects the module formats");
        for root_only in [["en", "rol"].concat(), ["del", "ete"].concat(), ["cali", "brate"].concat()] {
            assert!(!body.contains(&root_only), "the builder names {}", root_only);
        }
    }

    #[test]
    fn args_parse_with_defaults() {
        let a = parse_args(0, std::ptr::null());
        assert_eq!(a.socket, DEFAULT_SOCKET);
        assert_eq!(a.timeout, Duration::from_secs(DEFAULT_TIMEOUT));
        assert!(a.prompt.is_none());
    }

    #[test]
    fn prompt_arguments() {
        let args: Vec<std::ffi::CString> = ["prompt", "timeout=3"].iter().map(|s| std::ffi::CString::new(*s).unwrap()).collect();
        let ptrs: Vec<*const c_char> = args.iter().map(|c| c.as_ptr()).collect();
        let a = parse_args(2, ptrs.as_ptr());
        assert_eq!(a.prompt.as_deref(), Some(DEFAULT_PROMPT));
        assert_eq!(a.timeout, Duration::from_secs(3));
        let args: Vec<std::ffi::CString> = ["consent"].iter().map(|s| std::ffi::CString::new(*s).unwrap()).collect();
        let ptrs: Vec<*const c_char> = args.iter().map(|c| c.as_ptr()).collect();
        let c = parse_args(1, ptrs.as_ptr());
        assert!(c.consent);
        let args: Vec<std::ffi::CString> = ["prompt=Face:_Enter_to_scan"].iter().map(|s| std::ffi::CString::new(*s).unwrap()).collect();
        let ptrs: Vec<*const c_char> = args.iter().map(|c| c.as_ptr()).collect();
        assert_eq!(parse_args(1, ptrs.as_ptr()).prompt.as_deref(), Some("Face: Enter to scan"));
    }
}
