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
//! `timeout=8` (seconds to wait for the daemon's reply).

use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::Duration;

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;

const DEFAULT_SOCKET: &str = "/run/faceauth/sock";
const DEFAULT_TIMEOUT: u64 = 8;
const MAX_REPLY: usize = 4096;

#[repr(C)]
pub struct pam_handle_t {
    _private: [u8; 0],
}

extern "C" {
    fn pam_get_user(pamh: *mut pam_handle_t, user: *mut *const c_char, prompt: *const c_char) -> c_int;
}

struct Args {
    socket: String,
    timeout: Duration,
}

fn parse_args(argc: c_int, argv: *const *const c_char) -> Args {
    let mut a = Args { socket: DEFAULT_SOCKET.to_string(), timeout: Duration::from_secs(DEFAULT_TIMEOUT) };
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
            }
        }
    }
    a
}

/// The whole conversation with the daemon. Any error is `false`.
fn daemon_says_match(socket: &Path, user: &str, timeout: Duration) -> bool {
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
    let req = format!("{{\"user\":\"{}\"}}\n", escaped);
    if stream.write_all(req.as_bytes()).is_err() {
        return false;
    }
    let mut line = String::new();
    let mut reader = BufReader::new(stream).take(MAX_REPLY as u64);
    if reader.read_line(&mut line).is_err() {
        return false;
    }
    // The reply is `{"result":"match",...}`; only that exact tag counts.
    line.contains("\"result\":\"match\"")
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
    if daemon_says_match(Path::new(&args.socket), &user, args.timeout) {
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
        assert!(!daemon_says_match(Path::new("/nonexistent/faceauth.sock"), "alice", Duration::from_secs(1)));
    }

    #[test]
    fn args_parse_with_defaults() {
        let a = parse_args(0, std::ptr::null());
        assert_eq!(a.socket, DEFAULT_SOCKET);
        assert_eq!(a.timeout, Duration::from_secs(DEFAULT_TIMEOUT));
    }
}
