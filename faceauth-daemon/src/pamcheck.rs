//! Verify a password against the system's PAM stack from inside the daemon,
//! so the consent window can take a typed password as the answer instead of
//! the nod. Uses the `system-auth` service (pam_unix and faillock on Arch), as
//! root, with a conversation that supplies the password to any prompt.

use std::ffi::{c_char, c_int, c_void, CString};

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
#[repr(C)]
struct PamHandle {
    _private: [u8; 0],
}

#[link(name = "pam")]
extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        pamh: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_start_confdir(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        confdir: *const c_char,
        pamh: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut PamHandle, status: c_int) -> c_int;
    fn strdup(s: *const c_char) -> *mut c_char;
    fn calloc(n: usize, size: usize) -> *mut c_void;
}

/// The conversation: every prompt gets a copy of the password, every other
/// message no response.
///
/// # Safety
///
/// Called by libpam with `n` messages behind `msgs` (an array of pointers
/// on Linux-PAM), an out-pointer for the response array, and the
/// `appdata_ptr` from `check`, which is a `CString` that outlives the
/// transaction. The responses are `calloc`ed and `strdup`ed because libpam
/// frees them with `free`.
unsafe extern "C" fn conv(
    n: c_int,
    msgs: *mut *const PamMessage,
    out: *mut *mut PamResponse,
    data: *mut c_void,
) -> c_int {
    if n <= 0 || msgs.is_null() || out.is_null() || data.is_null() {
        return 19; // PAM_CONV_ERR
    }
    // SAFETY: the contract above: `data` is the `CString` `check` passed
    // and still owns, `msgs` holds `n` valid message pointers, `out` is a
    // valid out-pointer, and the array handed back is libpam's to free.
    unsafe {
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
            r.resp = if m.msg_style == PAM_PROMPT_ECHO_OFF || m.msg_style == PAM_PROMPT_ECHO_ON {
                strdup(password.as_ptr())
            } else {
                std::ptr::null_mut()
            };
        }
        *out = resp;
    }
    PAM_SUCCESS
}

/// True when `password` authenticates `user` through `service`, read from
/// the system's PAM configuration.
pub fn check(service: &str, user: &str, password: &str) -> bool {
    check_in(service, user, password, None)
}

/// As `check`, with the service file read from `confdir` when one is given
/// (`pam_start_confdir`), which is how the test below runs a throwaway
/// stack without touching `/etc/pam.d`.
fn check_in(service: &str, user: &str, password: &str, confdir: Option<&str>) -> bool {
    let (Ok(svc), Ok(usr), Ok(pw)) = (
        CString::new(service),
        CString::new(user),
        CString::new(password),
    ) else {
        return false;
    };
    let dir = match confdir.map(CString::new) {
        None => None,
        Some(Ok(d)) => Some(d),
        Some(Err(_)) => return false,
    };
    let conv_s = PamConv {
        conv: Some(conv),
        appdata_ptr: &pw as *const CString as *mut c_void,
    };
    let mut h: *mut PamHandle = std::ptr::null_mut();
    // SAFETY: valid C strings and a conversation struct that outlives the transaction.
    unsafe {
        let started = match &dir {
            None => pam_start(svc.as_ptr(), usr.as_ptr(), &conv_s, &mut h),
            Some(d) => pam_start_confdir(svc.as_ptr(), usr.as_ptr(), &conv_s, d.as_ptr(), &mut h),
        };
        if started != PAM_SUCCESS || h.is_null() {
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The password check against a throwaway stack in a private confdir:
    /// a permitting stack answers true and a denying one false, a service
    /// with no file is false, and a NUL in any argument never reaches PAM.
    /// This exercises the transaction and the conversation the window's
    /// password answer rides on, without the system's own stacks.
    #[test]
    fn a_throwaway_stack_answers_through_the_conversation() {
        let dir = std::env::temp_dir().join(format!("faceauth-pam-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("faceauth-test-permit"),
            "auth required pam_permit.so\naccount required pam_permit.so\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("faceauth-test-deny"),
            "auth required pam_deny.so\n",
        )
        .unwrap();
        let confdir = dir.to_str().unwrap();
        let user = nix::unistd::User::from_uid(nix::unistd::getuid())
            .ok()
            .flatten()
            .map(|u| u.name)
            .unwrap_or_else(|| "nobody".into());
        assert!(check_in(
            "faceauth-test-permit",
            &user,
            "any",
            Some(confdir)
        ));
        assert!(!check_in("faceauth-test-deny", &user, "any", Some(confdir)));
        assert!(!check_in(
            "faceauth-test-missing",
            &user,
            "any",
            Some(confdir)
        ));
        assert!(!check_in(
            "faceauth-test-permit",
            "us\0er",
            "any",
            Some(confdir)
        ));
        assert!(!check_in(
            "faceauth-test-permit",
            &user,
            "pa\0ss",
            Some(confdir)
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
