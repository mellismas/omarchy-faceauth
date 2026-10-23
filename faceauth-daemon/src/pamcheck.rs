//! Verify a password against the system's PAM stack from inside the daemon,
//! so the consent window can take a typed password as the answer instead of
//! the nod. Uses the `system-auth` service (pam_unix and faillock on Arch), as
//! root, with a conversation that supplies the password to any prompt. The
//! security key is checked through the same transaction, from the daemon's
//! private stack, with a conversation that answers no prompt at all.

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

/// The key check's conversation: a prompt fails it, so nothing is ever
/// typed for the user, and every other message (pam_u2f's cue) gets an
/// empty response.
///
/// # Safety
///
/// As `conv`, except that the appdata is never read.
unsafe extern "C" fn conv_silent(
    n: c_int,
    msgs: *mut *const PamMessage,
    out: *mut *mut PamResponse,
    _data: *mut c_void,
) -> c_int {
    if n <= 0 || msgs.is_null() || out.is_null() {
        return 19; // PAM_CONV_ERR
    }
    // SAFETY: the contract above: `msgs` holds `n` valid message pointers,
    // `out` is a valid out-pointer, and the array handed back is libpam's
    // to free.
    unsafe {
        for i in 0..n as usize {
            let style = (**msgs.add(i)).msg_style;
            if style == PAM_PROMPT_ECHO_OFF || style == PAM_PROMPT_ECHO_ON {
                return 19; // PAM_CONV_ERR
            }
        }
        let resp = calloc(n as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        if resp.is_null() {
            return 5; // PAM_BUF_ERR
        }
        *out = resp;
    }
    PAM_SUCCESS
}

/// The fingerprint check's conversation appdata: where each message's
/// style goes.
struct Styles<'a> {
    said: &'a mut dyn FnMut(c_int),
}

/// The fingerprint check's conversation: a prompt fails it, as the key's
/// does (pam_fprintd asks none, so a prompt means the stack is not the one
/// shipped), and every other message (pam_fprintd's "place your finger",
/// its "failed to match", its timeout) has its style handed on and gets an
/// empty response. The text is never read: fprintd translates it, and the
/// style says all the card needs.
///
/// # Safety
///
/// As `conv`, with `data` a `Styles` that outlives the transaction.
unsafe extern "C" fn conv_fprint(
    n: c_int,
    msgs: *mut *const PamMessage,
    out: *mut *mut PamResponse,
    data: *mut c_void,
) -> c_int {
    if n <= 0 || msgs.is_null() || out.is_null() || data.is_null() {
        return 19; // PAM_CONV_ERR
    }
    // SAFETY: the contract above: `data` is the `Styles` `check_fprint`
    // passed and still owns, `msgs` holds `n` valid message pointers, `out`
    // is a valid out-pointer, and the array handed back is libpam's to
    // free.
    unsafe {
        let styles = &mut *(data as *mut Styles<'_>);
        for i in 0..n as usize {
            let style = (**msgs.add(i)).msg_style;
            if style == PAM_PROMPT_ECHO_OFF || style == PAM_PROMPT_ECHO_ON {
                return 19; // PAM_CONV_ERR
            }
        }
        let resp = calloc(n as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        if resp.is_null() {
            return 5; // PAM_BUF_ERR
        }
        for i in 0..n as usize {
            (styles.said)((**msgs.add(i)).msg_style);
        }
        *out = resp;
    }
    PAM_SUCCESS
}

/// The key PIN's conversation appdata: the PIN, and whether a prompt has
/// already had it.
struct OnePin {
    pin: CString,
    used: std::cell::Cell<bool>,
}

/// The key check's conversation with a PIN: the first prompt of the whole
/// transaction gets the PIN, and any later prompt, or a second prompt in
/// the same call, fails the conversation. pam_u2f asks once per credential
/// on the key, so a mistyped PIN is tried against the key once, not once
/// per credential, and spends one of its retries. Every other message gets
/// an empty response.
///
/// # Safety
///
/// As `conv`, with `data` an `OnePin` that outlives the transaction.
unsafe extern "C" fn conv_pin(
    n: c_int,
    msgs: *mut *const PamMessage,
    out: *mut *mut PamResponse,
    data: *mut c_void,
) -> c_int {
    if n <= 0 || msgs.is_null() || out.is_null() || data.is_null() {
        return 19; // PAM_CONV_ERR
    }
    // SAFETY: the contract above: `data` is the `OnePin` `check_key`
    // passed and still owns, `msgs` holds `n` valid message pointers, `out`
    // is a valid out-pointer, and the array handed back is libpam's to
    // free.
    unsafe {
        let one = &*(data as *const OnePin);
        let is_prompt = |i: usize| {
            let style = (**msgs.add(i)).msg_style;
            style == PAM_PROMPT_ECHO_OFF || style == PAM_PROMPT_ECHO_ON
        };
        let prompts = (0..n as usize).filter(|&i| is_prompt(i)).count();
        if prompts > 1 || (prompts == 1 && one.used.get()) {
            return 19; // PAM_CONV_ERR
        }
        let resp = calloc(n as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        if resp.is_null() {
            return 5; // PAM_BUF_ERR
        }
        for i in 0..n as usize {
            if is_prompt(i) {
                (*resp.add(i)).resp = strdup(one.pin.as_ptr());
                one.used.set(true);
            }
        }
        *out = resp;
    }
    PAM_SUCCESS
}

/// The stock check's conversation appdata (fix round 11, Codex 4): where
/// each message goes, and what comes back for a prompt.
struct Relay<'a> {
    relay: &'a mut dyn FnMut(i32, &str) -> Option<String>,
}

/// The stock check's conversation: every message, in order, goes to the
/// relay (the PAM module's own conversation, through the helper's pipes),
/// and a prompt gets the relay's answer; a prompt it has no answer for
/// fails the conversation, as with a PAM caller that gives none. pam_u2f
/// asks once per credential that needs it, so a key with two credentials
/// is asked twice, as on stock Omarchy.
///
/// # Safety
///
/// As `conv`, with `data` a `Relay` that outlives the transaction.
unsafe extern "C" fn conv_relay(
    n: c_int,
    msgs: *mut *const PamMessage,
    out: *mut *mut PamResponse,
    data: *mut c_void,
) -> c_int {
    if n <= 0 || msgs.is_null() || out.is_null() || data.is_null() {
        return 19; // PAM_CONV_ERR
    }
    // SAFETY: the contract above: `data` is the `Relay` `check_key_relay`
    // passed and still owns, `msgs` holds `n` valid message pointers, `out`
    // is a valid out-pointer, and the array handed back is libpam's to
    // free (a failed call frees what it made).
    unsafe {
        let relay = &mut *(data as *mut Relay<'_>);
        let resp = calloc(n as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        if resp.is_null() {
            return 5; // PAM_BUF_ERR
        }
        for i in 0..n as usize {
            let m = &**msgs.add(i);
            let text = if m.msg.is_null() {
                String::new()
            } else {
                std::ffi::CStr::from_ptr(m.msg)
                    .to_string_lossy()
                    .into_owned()
            };
            let answer = (relay.relay)(m.msg_style, &text);
            if m.msg_style == PAM_PROMPT_ECHO_OFF || m.msg_style == PAM_PROMPT_ECHO_ON {
                let Some(mut a) = answer else {
                    free_responses(resp, i);
                    return 19; // PAM_CONV_ERR
                };
                let c = CString::new(a.as_str()).ok();
                crate::consent::wipe_string(&mut a);
                let Some(c) = c else {
                    free_responses(resp, i);
                    return 19;
                };
                (*resp.add(i)).resp = strdup(c.as_ptr());
                crate::consent::wipe_bytes(&mut c.into_bytes());
            }
        }
        *out = resp;
    }
    PAM_SUCCESS
}

/// Free the first `made` responses of `resp`, wiped, and the array, for a
/// conversation that fails part way.
///
/// # Safety
///
/// `resp` is a `calloc`ed array of at least `made` responses, each null or
/// `strdup`ed.
unsafe fn free_responses(resp: *mut PamResponse, made: usize) {
    // SAFETY: the contract above.
    unsafe {
        for i in 0..made {
            let r = (*resp.add(i)).resp;
            if !r.is_null() {
                let len = libc::strlen(r);
                std::ptr::write_bytes(r, 0, len);
                libc::free(r as *mut c_void);
            }
        }
        libc::free(resp as *mut c_void);
    }
}

/// The stdout this process was started with, kept aside for the answer,
/// with /dev/null put in its place for everything that runs here after:
/// the key's and the fingerprint's helpers each answer on it, and nothing
/// a PAM module or its libraries print can stand in for that answer.
pub fn set_report_aside() -> Option<std::fs::File> {
    use std::os::fd::FromRawFd;
    // SAFETY: dup of fd 1 returns a new descriptor nothing else owns (or
    // -1, checked); the File takes sole ownership of it.
    let kept = unsafe { libc::dup(1) };
    let null = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .ok()?;
    // SAFETY: both are open descriptors; dup2 replaces fd 1 only.
    let moved = unsafe { libc::dup2(std::os::fd::AsRawFd::as_raw_fd(&null), 1) };
    if kept < 0 {
        return None;
    }
    // SAFETY: `kept` is the descriptor dup returned above, owned by no one
    // else.
    let report = unsafe { std::fs::File::from_raw_fd(kept) };
    (moved == 1).then_some(report)
}

/// A conversation function as libpam calls it.
type ConvFn = unsafe extern "C" fn(
    c_int,
    *mut *const PamMessage,
    *mut *mut PamResponse,
    *mut c_void,
) -> c_int;

/// One `pam_authenticate` of `usr` through `svc`, read from `dir` when one
/// is given (`pam_start_confdir`), with `conv` as the conversation and
/// `data` as its appdata. The return code, or None when the transaction
/// did not start.
///
/// # Safety
///
/// `data` must be what `conv` reads it as, and must outlive the call.
unsafe fn authenticate(
    svc: &CString,
    usr: &CString,
    dir: Option<&CString>,
    conv: ConvFn,
    data: *mut c_void,
) -> Option<c_int> {
    let conv_s = PamConv {
        conv: Some(conv),
        appdata_ptr: data,
    };
    let mut h: *mut PamHandle = std::ptr::null_mut();
    // SAFETY: valid C strings and a conversation struct that outlives the
    // transaction; the appdata is the caller's contract.
    unsafe {
        let started = match dir {
            None => pam_start(svc.as_ptr(), usr.as_ptr(), &conv_s, &mut h),
            Some(d) => pam_start_confdir(svc.as_ptr(), usr.as_ptr(), &conv_s, d.as_ptr(), &mut h),
        };
        if started != PAM_SUCCESS || h.is_null() {
            None
        } else {
            let rc = pam_authenticate(h, 0);
            pam_end(h, rc);
            Some(rc)
        }
    }
}

/// The stock check (fix round 11, Codex 4): true when pam_u2f, through
/// `service` read from `confdir`, approves `user`, every message of its
/// conversation handed to `relay` and every prompt answered from it.
pub fn check_key_relay(
    service: &str,
    user: &str,
    confdir: &str,
    relay: &mut dyn FnMut(i32, &str) -> Option<String>,
) -> bool {
    let (Ok(svc), Ok(usr), Ok(dir)) = (
        CString::new(service),
        CString::new(user),
        CString::new(confdir),
    ) else {
        return false;
    };
    let mut data = Relay { relay };
    // SAFETY: `conv_relay` reads its appdata as this `Relay`, which
    // outlives the transaction.
    let rc = unsafe {
        authenticate(
            &svc,
            &usr,
            Some(&dir),
            conv_relay,
            &mut data as *mut Relay<'_> as *mut c_void,
        )
    };
    rc == Some(PAM_SUCCESS)
}

/// pam_fprintd's answer for `user`, through `service` read from `confdir`
/// (the fingerprint's private stack), with each message's style handed to
/// `said` as it comes; None when the transaction did not start. It blocks
/// until pam_fprintd returns (a match, the tries spent, a try timed out,
/// the reader not there), so it runs in the fingerprint check's own
/// process, which the daemon stops.
pub fn check_fprint(
    service: &str,
    user: &str,
    confdir: &str,
    said: &mut dyn FnMut(c_int),
) -> Option<c_int> {
    let (Ok(svc), Ok(usr), Ok(dir)) = (
        CString::new(service),
        CString::new(user),
        CString::new(confdir),
    ) else {
        return None;
    };
    let mut data = Styles { said };
    // SAFETY: `conv_fprint` reads its appdata as this `Styles`, which
    // outlives the transaction.
    unsafe {
        authenticate(
            &svc,
            &usr,
            Some(&dir),
            conv_fprint,
            &mut data as *mut Styles<'_> as *mut c_void,
        )
    }
}

/// True when `user` touches a key registered for them, through `service`
/// read from `confdir`: a private pam_u2f stack. With `pin` the PIN
/// prompt gets it, through the password's conversation and with the
/// password's wiping; without one nothing is typed on the user's behalf,
/// so a stack that asks for a PIN fails. It blocks until pam_u2f returns
/// (at a touch, at the key's own timeout, or at once with no key plugged
/// in), so it runs in the key check's own process, which the daemon stops.
pub fn check_key(service: &str, user: &str, confdir: &str, pin: Option<&str>) -> bool {
    if let Some(pin) = pin {
        return check_key_pin(service, user, confdir, pin);
    }
    let (Ok(svc), Ok(usr), Ok(dir)) = (
        CString::new(service),
        CString::new(user),
        CString::new(confdir),
    ) else {
        return false;
    };
    // SAFETY: `conv_silent` never reads its appdata.
    let rc = unsafe { authenticate(&svc, &usr, Some(&dir), conv_silent, std::ptr::null_mut()) };
    rc == Some(PAM_SUCCESS)
}

/// `check_key` with a PIN, through `conv_pin`: the PIN's own copy is
/// wiped on every way out, as the password's is.
fn check_key_pin(service: &str, user: &str, confdir: &str, pin: &str) -> bool {
    let pin = match CString::new(pin) {
        Ok(pin) => pin,
        Err(e) => {
            crate::consent::wipe_bytes(&mut e.into_vec());
            return false;
        }
    };
    let one = OnePin {
        pin,
        used: std::cell::Cell::new(false),
    };
    let rc = match (
        CString::new(service),
        CString::new(user),
        CString::new(confdir),
    ) {
        // SAFETY: `conv_pin` reads its appdata as this `OnePin`, which
        // outlives the transaction.
        (Ok(svc), Ok(usr), Ok(dir)) => unsafe {
            authenticate(
                &svc,
                &usr,
                Some(&dir),
                conv_pin,
                &one as *const OnePin as *mut c_void,
            )
        },
        _ => None,
    };
    crate::consent::wipe_bytes(&mut one.pin.into_bytes());
    rc == Some(PAM_SUCCESS)
}

/// True when `password` authenticates `user` through `service`, read from
/// the system's PAM configuration.
pub fn check(service: &str, user: &str, password: &str) -> bool {
    check_in(service, user, password, None)
}

/// As `check`, with the service file read from `confdir` when one is given
/// (`pam_start_confdir`): the key check's private stacks, and the test
/// below's throwaway stack.
fn check_in(service: &str, user: &str, password: &str, confdir: Option<&str>) -> bool {
    // This function's copy of the password (the CString, or the error's
    // copy of a password with a NUL in it) is wiped on every way out.
    let pw = match CString::new(password) {
        Ok(pw) => pw,
        Err(e) => {
            crate::consent::wipe_bytes(&mut e.into_vec());
            return false;
        }
    };
    let (Ok(svc), Ok(usr)) = (CString::new(service), CString::new(user)) else {
        crate::consent::wipe_bytes(&mut pw.into_bytes());
        return false;
    };
    let dir = match confdir.map(CString::new) {
        None => None,
        Some(Ok(d)) => Some(d),
        Some(Err(_)) => {
            crate::consent::wipe_bytes(&mut pw.into_bytes());
            return false;
        }
    };
    // SAFETY: `conv` reads its appdata as this CString, which outlives
    // the transaction.
    let rc = unsafe {
        authenticate(
            &svc,
            &usr,
            dir.as_ref(),
            conv,
            &pw as *const CString as *mut c_void,
        )
    };
    // Wipe this function's own copy (the CString), whether PAM started or
    // not. PAM's strdup copies from the conversation are freed by PAM; the
    // daemon's other copies are wiped by `consent::Secret` and the server
    // as they go (F12).
    crate::consent::wipe_bytes(&mut pw.into_bytes());
    rc == Some(PAM_SUCCESS)
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

    /// The key check's conversation types nothing: an info message (the
    /// cue pam_u2f shows) gets an empty response, and a prompt (a PIN)
    /// fails the conversation with no response handed back. No PAM
    /// transaction runs here.
    #[test]
    fn the_key_conversation_answers_no_prompt() {
        const PAM_TEXT_INFO: c_int = 4;
        let text = CString::new("Please touch the device.").unwrap();
        let ask = |style: c_int| -> (c_int, *mut PamResponse) {
            let m = PamMessage {
                msg_style: style,
                msg: text.as_ptr(),
            };
            let mut list = [&m as *const PamMessage];
            let mut out: *mut PamResponse = std::ptr::null_mut();
            // SAFETY: one valid message and an out-pointer, as libpam
            // passes them; the appdata is never read.
            let rc = unsafe { conv_silent(1, list.as_mut_ptr(), &mut out, std::ptr::null_mut()) };
            (rc, out)
        };
        let (rc, out) = ask(PAM_TEXT_INFO);
        assert_eq!(rc, PAM_SUCCESS);
        assert!(!out.is_null());
        // SAFETY: the conversation calloc'ed one response; it is read and
        // freed here as libpam would.
        unsafe {
            assert!((*out).resp.is_null(), "an info message gets no text back");
            libc::free(out as *mut c_void);
        }
        for style in [PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_ON] {
            let (rc, out) = ask(style);
            assert_ne!(rc, PAM_SUCCESS, "a prompt fails the conversation");
            assert!(out.is_null(), "and nothing is handed back for it");
        }
    }

    /// The fingerprint check's conversation answers no prompt, as the
    /// key's does, and hands each other message's style on without reading
    /// its text; a throwaway stack's answers come back as PAM gives them.
    #[test]
    fn the_fingerprint_conversation_reports_styles_and_answers_no_prompt() {
        const PAM_ERROR_MSG: c_int = 3;
        const PAM_TEXT_INFO: c_int = 4;
        let text = CString::new("Place your finger on the fingerprint reader").unwrap();
        let mut seen = Vec::new();
        {
            let mut said = |style: c_int| seen.push(style);
            let mut data = Styles { said: &mut said };
            let mut ask = |styles: &[c_int]| -> c_int {
                let ms: Vec<PamMessage> = styles
                    .iter()
                    .map(|&msg_style| PamMessage {
                        msg_style,
                        msg: text.as_ptr(),
                    })
                    .collect();
                let mut list: Vec<*const PamMessage> = ms.iter().map(|m| m as *const _).collect();
                let mut out: *mut PamResponse = std::ptr::null_mut();
                // SAFETY: valid messages and an out-pointer, as libpam
                // passes them, and the `Styles` the conversation reads.
                let rc = unsafe {
                    conv_fprint(
                        list.len() as c_int,
                        list.as_mut_ptr(),
                        &mut out,
                        &mut data as *mut Styles<'_> as *mut c_void,
                    )
                };
                if !out.is_null() {
                    // SAFETY: the conversation calloc'ed the responses and
                    // put no text in them; freed here as libpam would.
                    unsafe { libc::free(out as *mut c_void) };
                }
                rc
            };
            assert_eq!(ask(&[PAM_TEXT_INFO]), PAM_SUCCESS);
            assert_eq!(ask(&[PAM_ERROR_MSG]), PAM_SUCCESS);
            assert_ne!(
                ask(&[PAM_PROMPT_ECHO_OFF]),
                PAM_SUCCESS,
                "a prompt fails it"
            );
            assert_ne!(ask(&[PAM_TEXT_INFO, PAM_PROMPT_ECHO_ON]), PAM_SUCCESS);
        }
        assert_eq!(
            seen,
            vec![PAM_TEXT_INFO, PAM_ERROR_MSG],
            "a call with a prompt reports nothing"
        );
        let dir = std::env::temp_dir().join(format!("faceauth-pam-fprint-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("faceauth-test-permit"),
            "auth required pam_permit.so\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("faceauth-test-deny"),
            "auth required pam_deny.so\n",
        )
        .unwrap();
        let confdir = dir.to_str().unwrap();
        let mut ignore = |_: c_int| {};
        assert_eq!(
            check_fprint("faceauth-test-permit", "nobody", confdir, &mut ignore),
            Some(PAM_SUCCESS)
        );
        assert_ne!(
            check_fprint("faceauth-test-deny", "nobody", confdir, &mut ignore),
            Some(PAM_SUCCESS)
        );
        assert_eq!(
            check_fprint("faceauth-test-permit", "no\0body", confdir, &mut ignore),
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 9: the PIN goes to the first prompt of the transaction alone. A
    /// later prompt, or two prompts in one call, fails the conversation,
    /// so one mistyped PIN is never tried twice against the key; an info
    /// message before it takes nothing.
    #[test]
    fn the_key_pin_answers_one_prompt_and_no_more() {
        const PAM_TEXT_INFO: c_int = 4;
        let text = CString::new("Please enter the PIN:").unwrap();
        let one = OnePin {
            pin: CString::new("123456").unwrap(),
            used: std::cell::Cell::new(false),
        };
        let data = &one as *const OnePin as *mut c_void;
        let ask = |styles: &[c_int]| -> (c_int, *mut PamResponse) {
            let ms: Vec<PamMessage> = styles
                .iter()
                .map(|&msg_style| PamMessage {
                    msg_style,
                    msg: text.as_ptr(),
                })
                .collect();
            let mut list: Vec<*const PamMessage> = ms.iter().map(|m| m as *const _).collect();
            let mut out: *mut PamResponse = std::ptr::null_mut();
            // SAFETY: valid messages and an out-pointer, as libpam passes
            // them, and the `OnePin` the conversation reads.
            let rc = unsafe { conv_pin(list.len() as c_int, list.as_mut_ptr(), &mut out, data) };
            (rc, out)
        };
        let free = |out: *mut PamResponse, n: usize| {
            // SAFETY: the conversation calloc'ed `n` responses and strdup'ed
            // their texts; they are read and freed here as libpam would.
            unsafe {
                for i in 0..n {
                    libc::free((*out.add(i)).resp as *mut c_void);
                }
                libc::free(out as *mut c_void);
            }
        };
        let (rc, out) = ask(&[PAM_TEXT_INFO]);
        assert_eq!(rc, PAM_SUCCESS);
        free(out, 1);
        assert!(!one.used.get(), "an info message takes nothing");
        let (rc, out) = ask(&[PAM_PROMPT_ECHO_OFF, PAM_PROMPT_ECHO_OFF]);
        assert_ne!(rc, PAM_SUCCESS, "two prompts in one call fail");
        assert!(out.is_null());
        let (rc, out) = ask(&[PAM_TEXT_INFO, PAM_PROMPT_ECHO_OFF]);
        assert_eq!(rc, PAM_SUCCESS);
        // SAFETY: the second response is the prompt's, a strdup'ed C string.
        let answered = unsafe { std::ffi::CStr::from_ptr((*out.add(1)).resp) };
        assert_eq!(
            answered.to_str(),
            Ok("123456"),
            "the first prompt gets the PIN"
        );
        free(out, 2);
        let (rc, out) = ask(&[PAM_PROMPT_ECHO_OFF]);
        assert_ne!(rc, PAM_SUCCESS, "a later prompt gets nothing");
        assert!(out.is_null());
    }
}
