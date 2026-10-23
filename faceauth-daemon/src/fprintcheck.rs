//! `faceauth-fprintcheck LANE USER`: one fingerprint check, for the
//! consent card (LANE `sudo` or `polkit`) or for the lock screen
//! (`unlock`). faceauthd runs it in a transient unit of its own per check
//! (consent/fprint.rs), as root, so fprintd lets it ask for any user's
//! finger. It runs pam_fprintd through the package's private stack,
//! `/usr/lib/faceauth/pam.d/faceauth-fprint`, with `pam_start_confdir`,
//! never through `/etc/pam.d`, and answers with its exit status:
//! `FPRINT_MATCHED` (42) for a finger enrolled for USER, `FPRINT_UNAVAILABLE`
//! (3) when the reader did not answer, 1 for anything else (the tries
//! spent, an error), 2 for a call it does not take. While pam_fprintd
//! talks it writes one word a line to the stdout it was started with,
//! `place` or `retry`, which the daemon turns into the card's status;
//! pam_fprintd and libsystemd get /dev/null for their stdout, so nothing
//! of theirs reads as a word.
//!
//! A binary of its own, not a mode of `faceauth-keycheck`: that helper
//! exports libfido2's call and arms a SIGTERM handler that cancels the
//! key's wait, holds the key's lease, and runs in a sandbox with no
//! AF_UNIX and the bus hidden, none of which a fingerprint check needs or
//! may have. pam_fprintd needs the system bus and no device, and a stop
//! needs no handler at all: SIGTERM ends the process, and fprintd frees
//! the reader once the check's bus name is gone.

use faceauth_daemon::consent::{fprint_check, key_user_ok, FprintStatus};
use std::io::Write;
use std::process::ExitCode;

fn main() -> ExitCode {
    let mut report = faceauth_daemon::pamcheck::set_report_aside();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run_with(
        &args,
        &mut |user, said| fprint_check(user, said),
        &mut |st| {
            if let Some(out) = report.as_mut() {
                let _ = out
                    .write_all(format!("{}\n", st.word()).as_bytes())
                    .and_then(|_| out.flush());
            }
        },
    );
    ExitCode::from(code)
}

/// The check: the user, and where its status words go; its exit status.
type Check<'a> = dyn FnMut(&str, &mut dyn FnMut(FprintStatus)) -> u8 + 'a;

/// The check of `args` (lane and user) through `check`, its words to
/// `said`: 2 for a call the helper does not take, else the check's own
/// exit status.
fn run_with(args: &[String], check: &mut Check, said: &mut dyn FnMut(FprintStatus)) -> u8 {
    let [lane, user] = args else {
        return 2;
    };
    if !matches!(lane.as_str(), "sudo" | "polkit" | "unlock") || !key_user_ok(user) {
        return 2;
    }
    check(user, said)
}

#[cfg(test)]
mod tests {
    use super::*;
    use faceauth_daemon::consent::FPRINT_MATCHED;

    /// The helper takes a lane and a user it can name, nothing else, and
    /// passes the check's words and exit status through as they come.
    #[test]
    fn the_helper_takes_its_lane_and_user_and_passes_the_check_through() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let asked = std::cell::RefCell::new(Vec::new());
        let mut check = |user: &str, said: &mut dyn FnMut(FprintStatus)| {
            asked.borrow_mut().push(user.to_string());
            said(FprintStatus::Place);
            said(FprintStatus::Retry);
            FPRINT_MATCHED
        };
        let mut words = Vec::new();
        for lane in ["sudo", "polkit", "unlock"] {
            let mut said = |st: FprintStatus| words.push(st.word());
            assert_eq!(
                run_with(&args(&[lane, "alice"]), &mut check, &mut said),
                FPRINT_MATCHED
            );
        }
        assert_eq!(*asked.borrow(), ["alice", "alice", "alice"]);
        assert_eq!(
            words,
            ["place", "retry", "place", "retry", "place", "retry"]
        );
        let mut said = |_: FprintStatus| {};
        for bad in [
            args(&["su", "alice"]),
            args(&["sudo", "Alice"]),
            args(&["sudo", "-alice"]),
            args(&["sudo"]),
            args(&["sudo", "alice", "extra"]),
        ] {
            assert_eq!(run_with(&bad, &mut check, &mut said), 2, "{:?}", bad);
        }
        assert_eq!(
            asked.borrow().len(),
            3,
            "a call it does not take asks nothing"
        );
    }
}
