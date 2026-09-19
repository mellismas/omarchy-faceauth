//! `pam_faceauth.so`: the smallest possible PAM module.
//!
//! It asks `faceauthd` over its Unix socket whether the user in front of the
//! camera is the user being authenticated, and maps the answer:
//!
//! - match                        -> PAM_SUCCESS
//! - anything else, any failure   -> PAM_IGNORE
//!
//! No camera, no models, no templates, no image data in this process. Every
//! failure path is PAM_IGNORE so that under `sufficient` or
//! `[success=done default=ignore]` the stack falls through to the password;
//! lockout is structurally impossible from here. Panics are caught and become
//! PAM_IGNORE too.
//!
//! Module arguments (in the PAM line): `socket=/run/faceauth/sock`,
//! `timeout=8` (seconds to wait for the daemon's reply), and `prompt`, which
//! makes the scan a deliberate act: the module asks through the PAM
//! conversation, Enter on an empty line runs the face scan, anything typed is
//! handed on as the password (PAM_AUTHTOK, for the `try_first_pass` module
//! behind us) and no scan runs. Elevation (sudo, polkit) should use `prompt`;
//! the lock screen, where looking at the machine is the act, should not.

use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::Duration;

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;
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

/// Overwrite a CString's bytes before it is freed.
fn wipe(c: std::ffi::CString) {
    let mut bytes = c.into_bytes();
    for b in bytes.iter_mut() {
        // SAFETY-adjacent: volatile so the compiler keeps the stores.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    drop(bytes);
}

/// Names go into the auth log; strip anything that could forge a line.
fn sanitise(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(64).collect()
}

const DEFAULT_PROMPT: &str = "Press Enter to authenticate by face, or type your password: ";

/// Ask through the application's conversation. `Ok(Some(text))` is what the
/// user typed (empty for a bare Enter); `Ok(None)` means no conversation is
/// available, `Err` that the application refused.
fn converse(pamh: *mut pam_handle_t, text: &str) -> Result<Option<String>, ()> {
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
        let text = if r.resp.is_null() { String::new() } else { CStr::from_ptr(r.resp).to_string_lossy().into_owned() };
        if !r.resp.is_null() {
            // Wipe before freeing: it may be a password.
            let len = CStr::from_ptr(r.resp).to_bytes().len();
            std::ptr::write_bytes(r.resp, 0, len);
            free(r.resp as *mut c_void);
        }
        free(resp as *mut c_void);
        text
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
                a.timeout = Duration::from_secs(t.clamp(1, 60));
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
    if a.consent && !timeout_given {
        // Scan plus the nod window plus the window itself.
        a.timeout = Duration::from_secs(20);
    }
    a
}

/// The whole conversation with the daemon. Any error is `false`.
fn daemon_says_match(socket: &Path, user: &str, timeout: Duration, consent: bool) -> bool {
    let Ok(mut stream) = UnixStream::connect(socket) else { return false };
    if stream.set_read_timeout(Some(timeout)).is_err() || stream.set_write_timeout(Some(Duration::from_secs(2))).is_err() {
        return false;
    }
    // A tiny hand-built JSON object: the user name is escaped for quotes and backslashes.
    let escaped: String = user.chars().flat_map(|c| match c {
        '"' => vec!['\\', '"'],
        '\\' => vec!['\\', '\\'],
        c if c.is_control() => vec![],
        c => vec![c],
    }).collect();
    let req = if consent { format!("{{\"user\":\"{}\",\"consent\":true}}\n", escaped) } else { format!("{{\"user\":\"{}\"}}\n", escaped) };
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut line = String::new();
    let mut reader = BufReader::new(stream).take(MAX_REPLY as u64);
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    // The daemon serialises the tag first: the reply must BEGIN with the
    // match object, so no later field (which may echo request bytes) can
    // ever make a non-match read as one.
    let t = line.trim_start();
    t.starts_with("{\"result\":\"match\",") || t == "{\"result\":\"match\"}"
}

fn authenticate(pamh: *mut pam_handle_t, argc: c_int, argv: *const *const c_char) -> c_int {
    let args = parse_args(argc, argv);
    let mut user_ptr: *const c_char = std::ptr::null();
    // SAFETY: pamh is the handle PAM gave us; user_ptr is a valid out-pointer.
    let rc = unsafe { pam_get_user(pamh, &mut user_ptr, std::ptr::null()) };
    if rc != PAM_SUCCESS || user_ptr.is_null() {
        return PAM_IGNORE;
    }
    let user = unsafe { CStr::from_ptr(user_ptr) }.to_string_lossy().into_owned();
    if user.is_empty() || user.len() > 256 {
        return PAM_IGNORE;
    }
    let t0 = std::time::Instant::now();
    if let (Some(text), false) = (&args.prompt, args.consent) {
        match converse(pamh, text) {
            // Typed something: that is the password for the module behind us; no scan.
            Ok(Some(mut typed)) if !typed.is_empty() => {
                if let Ok(tok) = std::ffi::CString::new(typed.clone()) {
                    // SAFETY: PAM copies the item.
                    unsafe { pam_set_item(pamh, PAM_AUTHTOK, tok.as_ptr() as *const c_void) };
                    wipe(tok);
                }
                // The password must not linger in freed heap.
                unsafe { std::ptr::write_bytes(typed.as_mut_vec().as_mut_ptr(), 0, typed.len()) };
                drop(typed);
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
    let ok = daemon_says_match(Path::new(&args.socket), &user, args.timeout, args.consent);
    log(&format!("user {}: {} after {} ms", sanitise(&user), if ok { "match, success" } else { "no match or no daemon, ignore" }, t0.elapsed().as_millis()));
    if ok {
        PAM_SUCCESS
    } else {
        PAM_IGNORE
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
    fn no_daemon_is_not_a_match() {
        assert!(!daemon_says_match(Path::new("/nonexistent/faceauth.sock"), "alice", Duration::from_secs(1), false));
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
        assert_eq!(c.timeout, Duration::from_secs(20));
        let args: Vec<std::ffi::CString> = ["prompt=Face:_Enter_to_scan"].iter().map(|s| std::ffi::CString::new(*s).unwrap()).collect();
        let ptrs: Vec<*const c_char> = args.iter().map(|c| c.as_ptr()).collect();
        assert_eq!(parse_args(1, ptrs.as_ptr()).prompt.as_deref(), Some("Face: Enter to scan"));
    }
}
