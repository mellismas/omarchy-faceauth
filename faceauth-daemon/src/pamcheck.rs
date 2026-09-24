//! Verify a password against the system's PAM stack from inside the daemon,
//! so the consent window can take a typed password as the answer instead of
//! the nod. Uses the `system-auth` service (pam_unix and faillock on Arch), as
//! root, with a conversation that supplies the password to any prompt.

use std::ffi::{c_char, c_int, c_void, CStr, CString};

const PAM_SUCCESS: c_int = 0;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}
#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}
#[repr(C)]
struct PamConv {
    conv: Option<unsafe extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int>,
    appdata_ptr: *mut c_void,
}
#[repr(C)]
struct PamHandle {
    _private: [u8; 0],
}

#[link(name = "pam")]
extern "C" {
    fn pam_start(service: *const c_char, user: *const c_char, conv: *const PamConv, pamh: *mut *mut PamHandle) -> c_int;
    fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut PamHandle, status: c_int) -> c_int;
    fn strdup(s: *const c_char) -> *mut c_char;
    fn calloc(n: usize, size: usize) -> *mut c_void;
}

unsafe extern "C" fn conv(n: c_int, msgs: *mut *const PamMessage, out: *mut *mut PamResponse, data: *mut c_void) -> c_int {
    if n <= 0 || msgs.is_null() || out.is_null() || data.is_null() {
        return 19; // PAM_CONV_ERR
    }
    let password = &*(data as *const CString);
    let resp = calloc(n as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
    if resp.is_null() {
        return 5; // PAM_BUF_ERR
    }
    for i in 0..n as usize {
        // Linux-PAM passes an array of pointers to messages.
        let m = &**msgs.add(i);
        let r = &mut *resp.add(i);
        r.resp_retcode = 0;
        r.resp = if m.msg_style == PAM_PROMPT_ECHO_OFF || m.msg_style == PAM_PROMPT_ECHO_ON { strdup(password.as_ptr()) } else { std::ptr::null_mut() };
    }
    *out = resp;
    PAM_SUCCESS
}

/// True when `password` authenticates `user` through `service`.
pub fn check(service: &str, user: &str, password: &str) -> bool {
    let (Ok(svc), Ok(usr), Ok(pw)) = (CString::new(service), CString::new(user), CString::new(password)) else { return false };
    let conv_s = PamConv { conv: Some(conv), appdata_ptr: &pw as *const CString as *mut c_void };
    let mut h: *mut PamHandle = std::ptr::null_mut();
    // SAFETY: valid C strings and a conversation struct that outlives the transaction.
    unsafe {
        if pam_start(svc.as_ptr(), usr.as_ptr(), &conv_s, &mut h) != PAM_SUCCESS || h.is_null() {
            return false;
        }
        let rc = pam_authenticate(h, 0);
        pam_end(h, rc);
        // Wipe this function's own copy (the CString). PAM's strdup copies
        // from the conversation are freed by PAM; the daemon's other copies
        // are wiped by `consent::Secret` and the server as they go (F12).
        let bytes = pw.into_bytes();
        let mut bytes = bytes;
        for b in bytes.iter_mut() {
            std::ptr::write_volatile(b, 0);
        }
        rc == PAM_SUCCESS
    }
}

#[allow(dead_code)]
fn _cstr(p: *const c_char) -> String {
    unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
}
