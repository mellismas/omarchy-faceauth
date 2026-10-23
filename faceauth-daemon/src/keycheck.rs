//! `faceauth-keycheck LANE USER`: one security key check for the consent
//! card (LANE `sudo` or `polkit`) or for the lock screen (`unlock`, on
//! sudo's FIDO2 line's policy, never a PIN). faceauthd runs it in a
//! transient unit of its own per check (consent/key.rs). The only other
//! caller is pam_faceauth's key-fallback line while faceauthd is down
//! (round 5's A; since fix round 10, item 6, exactly as stock pam_u2f's
//! line, with no lock gate), as root, outside the sandbox as stock pam_u2f
//! runs, and only on the sudo and polkit lanes. It reads the key's PIN, when the
//! lane's FIDO2 line asks for one, from stdin, which is a pipe from the
//! daemon, runs pam_u2f through the private stack that mirrors that line,
//! and answers with its exit status: `KEY_TOUCHED` for a touch of a key
//! registered for USER, 1 for anything else, 2 for a call it does not
//! take. The same code goes as one byte to the stdout it was started with,
//! which the PAM module reads (it gets that whatever its caller did with
//! SIGCHLD); pam_u2f and libfido2 get /dev/null for their stdout, so
//! nothing of theirs can stand in for the answer.
//!
//! `faceauth-keycheck --converse LANE USER` (fix round 11, Codex 4) is the
//! stock check the PAM module runs with faceauthd down: pam_u2f through the
//! private stack that carries the lane's own line words, with none of the
//! card's credential rules, and its whole conversation passed through to
//! the module, and so to sudo's terminal or polkit's agent. Each message
//! goes out on the report descriptor as `Q <style> <hex>`, each is
//! answered on stdin as `A <hex>` (or `N`, no answer), and the answer goes
//! last as `R <code>`.
//!
//! Before it asks the key it takes the key's lease (`lockgate::KEY_LEASE`,
//! fix round 11), and holds it until it exits; with the lease held
//! elsewhere for `LEASE_WAIT` it answers `KEY_BUSY` and asks nothing, so
//! the daemon's check and the module's never share the key.

#[path = "keycheck_cancel.rs"]
mod keycheck_cancel;

use faceauth_daemon::consent::{
    key_check, key_check_stock, key_user_ok, wipe_bytes, Secret, KEY_TOUCHED,
};
use faceauth_daemon::lockgate::{hex_decode, hex_encode, take_key_lease, KEY_LEASE};
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;

/// The answer when another check holds the key's lease.
const KEY_BUSY: u8 = 3;

/// How long a check waits for the lease: the time a stopped check's unit
/// takes to go, a margin under the card's two-second rearm.
const LEASE_WAIT: Duration = Duration::from_secs(1);

/// The stock check's own hard deadline, prompt time included (fix round
/// 12, Codex 2, Opus N2): a prompt left open (an unanswered PIN prompt, a
/// polkit dialog, a terminal stopped with Ctrl-Z) gives the key's lease
/// back by then. The PAM module kills it sooner when faceauthd comes back.
const HELPER_DEADLINE: Duration = Duration::from_secs(60);

/// The longest PIN a FIDO2 key takes is 63 bytes; anything past this is
/// not a PIN.
const PIN_MAX: usize = 128;

/// The answer for a helper whose stop could not be armed (Codex 19c): no
/// touch, at once. Nothing could then cancel the key's wait, nor end the
/// helper in time, so no check runs at all; the PAM line goes on to the
/// password. None when the stop is armed.
fn unarmed_answer(armed: bool) -> Option<u8> {
    (!armed).then_some(1)
}

fn main() -> ExitCode {
    // Round 19: a stop (SIGTERM) cancels the key's wait and ends the
    // helper, and a check reports a touch only when it claims it before
    // any stop (keycheck_cancel.rs).
    if let Some(code) = unarmed_answer(keycheck_cancel::arm(keycheck_cancel::exit_stopped)) {
        return ExitCode::from(code);
    }
    let mut report = faceauth_daemon::pamcheck::set_report_aside();
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--converse") {
        let Some(out) = report.as_mut() else {
            return ExitCode::from(2);
        };
        // A backstop past the deadline: whatever the check is blocked on,
        // the process, and with it the lease, is gone.
        let _ = std::thread::Builder::new().spawn(|| {
            std::thread::sleep(HELPER_DEADLINE + Duration::from_secs(5));
            // SAFETY: _exit ends the process at once, with no handler run.
            unsafe { libc::_exit(1) };
        });
        let code = converse_on_stdin(
            &args,
            Path::new(KEY_LEASE),
            &|lane: &str, user: &str, relay: &mut dyn FnMut(i32, &str) -> Option<String>| {
                key_check_stock(lane, user, relay) && keycheck_cancel::claim_touch()
            },
            out,
            HELPER_DEADLINE,
        );
        return ExitCode::from(code);
    }
    let code = run();
    if let Some(mut out) = report {
        let _ = out.write_all(&[code]);
    }
    ExitCode::from(code)
}

/// The stock check: lane, user and the relay its conversation goes to
/// (each message's style and text in, a prompt's answer out).
type StockCheck = dyn Fn(&str, &str, &mut dyn FnMut(i32, &str) -> Option<String>) -> bool;

/// The stock check's conversation answer on `input`, one line: `A <hex>`
/// for a response, `N` for none, at most `ANSWER_MAX` bytes, and wiped;
/// None as well when it has not come by `by`. The descriptor is polled and
/// read directly, a byte at a time, never through a buffer (fix round 13,
/// Opus N1): a buffered reader takes the whole line on its first read, and
/// the next poll then waits for bytes it already holds. Nothing past the
/// line is taken.
fn read_answer(input: BorrowedFd<'_>, by: std::time::Instant) -> Option<String> {
    use std::os::fd::AsRawFd;
    const ANSWER_MAX: usize = 2 + 2 * PIN_MAX + 2;
    let mut line = Vec::with_capacity(ANSWER_MAX);
    let mut b = [0u8; 1];
    loop {
        let left = by.saturating_duration_since(std::time::Instant::now());
        let mut fds = [libc::pollfd {
            fd: input.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        // SAFETY: one valid pollfd, its count, a timeout.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 1, left.as_millis().min(60_000) as i32) };
        if ready <= 0 {
            if ready < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            if !left.is_zero() && ready == 0 {
                continue;
            }
            wipe_bytes(&mut line);
            return None;
        }
        // SAFETY: a read of one byte into a one-byte buffer this function
        // owns, from a descriptor the caller keeps open for the call.
        let n = unsafe { libc::read(input.as_raw_fd(), b.as_mut_ptr().cast(), 1) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        match (n, b[0]) {
            (1, b'\n') => break,
            (1, c) if line.len() < ANSWER_MAX => line.push(c),
            _ => {
                wipe_bytes(&mut line);
                return None;
            }
        }
    }
    let answer = match line.as_slice() {
        [b'A', b' ', hex @ ..] => {
            std::str::from_utf8(hex)
                .ok()
                .and_then(hex_decode)
                .and_then(|mut v| match String::from_utf8(std::mem::take(&mut v)) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        wipe_bytes(&mut e.into_bytes());
                        None
                    }
                })
        }
        _ => None,
    };
    wipe_bytes(&mut line);
    answer
}

/// The `--converse` mode on this process's own stdin, as `main` runs it.
fn converse_on_stdin(
    args: &[String],
    lease: &Path,
    check: &StockCheck,
    output: &mut dyn Write,
    deadline: Duration,
) -> u8 {
    // fd 0 itself, read unbuffered (fix round 13, Opus N1): `Stdin`'s own
    // reads go through an 8 KiB buffer, which nothing here uses.
    let stdin = std::io::stdin();
    run_converse_with(args, lease, check, stdin.as_fd(), output, deadline)
}

/// The `--converse` mode with the lease at `lease`, `check` for the stock
/// check, answers from `input` and lines to `output`, and nothing waited
/// for past `deadline` from now; the code it answers with, also sent last
/// as `R <code>`.
fn run_converse_with(
    args: &[String],
    lease: &Path,
    check: &StockCheck,
    input: BorrowedFd<'_>,
    output: &mut dyn Write,
    deadline: Duration,
) -> u8 {
    let by = std::time::Instant::now() + deadline;
    let code = (|| {
        let [_, lane, user] = args else {
            return 2;
        };
        if !matches!(lane.as_str(), "sudo" | "polkit") || !key_user_ok(user) {
            return 2;
        }
        let Some(held) = take_key_lease(lease, LEASE_WAIT) else {
            return KEY_BUSY;
        };
        let mut relay = |style: i32, text: &str| {
            let line = format!("Q {} {}\n", style, hex_encode(text.as_bytes()));
            if output
                .write_all(line.as_bytes())
                .and_then(|_| output.flush())
                .is_err()
            {
                return None;
            }
            read_answer(input, by)
        };
        let touched = check(lane, user, &mut relay);
        if cfg!(test) {
            drop(held);
        } else {
            // Released by the kernel when this process exits, not before.
            std::mem::forget(held);
        }
        if touched {
            KEY_TOUCHED
        } else {
            1
        }
    })();
    let _ = output
        .write_all(format!("R {}\n", code).as_bytes())
        .and_then(|_| output.flush());
    code
}

fn run() -> u8 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    run_with(
        &args,
        Path::new(KEY_LEASE),
        &|lane: &str, user: &str, pin: Option<&str>| {
            key_check(lane, user, pin) && keycheck_cancel::claim_touch()
        },
        &mut std::io::stdin(),
    )
}

/// `run` with the lease at `lease`, `check` for the key and the PIN from
/// `input`. The lease, once taken, is kept to the process's exit.
fn run_with(
    args: &[String],
    lease: &Path,
    check: &dyn Fn(&str, &str, Option<&str>) -> bool,
    input: &mut dyn Read,
) -> u8 {
    let [lane, user] = args else {
        return 2;
    };
    if !matches!(lane.as_str(), "sudo" | "polkit" | "unlock") || !key_user_ok(user) {
        return 2;
    }
    let Some(held) = take_key_lease(lease, LEASE_WAIT) else {
        return KEY_BUSY;
    };
    let pin = read_pin(input);
    let touched = check(lane, user, pin.as_deref());
    if cfg!(test) {
        drop(held);
    } else {
        // Released by the kernel when this process exits, not before.
        std::mem::forget(held);
    }
    if touched {
        KEY_TOUCHED
    } else {
        1
    }
}

/// The PIN from `input`: up to `PIN_MAX` bytes of UTF-8 without a NUL, a
/// trailing newline dropped, as a `Secret`; None when there is nothing,
/// or something that is not a PIN. The bytes are read into a fixed buffer
/// that is wiped, so no copy is left in freed memory.
fn read_pin(input: &mut dyn Read) -> Option<Secret> {
    let mut buf = [0u8; PIN_MAX + 1];
    let mut n = 0;
    while n < buf.len() {
        match input.read(&mut buf[n..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => n += k,
        }
    }
    let mut bytes = buf[..n].to_vec();
    for b in buf.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusively borrowed byte.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    if bytes.last() == Some(&b'\n') {
        let _ = bytes.pop();
    }
    if bytes.is_empty() || bytes.len() > PIN_MAX || bytes.contains(&0) {
        wipe_bytes(&mut bytes);
        return None;
    }
    match String::from_utf8(bytes) {
        Ok(pin) => Some(Secret::new(pin)),
        Err(e) => {
            wipe_bytes(&mut e.into_bytes());
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Codex 19c: a check whose stop could not be armed does not run: it
    /// answers no touch at once, since nothing could then cancel the key's
    /// wait or end it in time.
    #[test]
    fn a_check_that_cannot_arm_its_stop_does_not_run() {
        assert_eq!(unarmed_answer(false), Some(1));
        assert_eq!(unarmed_answer(true), None);
    }

    /// E: the PIN is what the pipe carried, without the newline, and
    /// nothing that is not a PIN gets through: an empty pipe, a NUL, or
    /// more than a key takes.
    #[test]
    fn the_pin_is_read_from_the_pipe_and_nothing_else_passes() {
        let read = |b: &[u8]| read_pin(&mut &b[..]).map(|p| p.to_string());
        assert_eq!(read(b"123456\n").as_deref(), Some("123456"));
        assert_eq!(read(b"12 34").as_deref(), Some("12 34"));
        assert_eq!(read(b""), None);
        assert_eq!(read(b"\n"), None);
        assert_eq!(read(b"12\x0034"), None);
        assert_eq!(read(&[b'1'; PIN_MAX + 1]), None);
        assert_eq!(read(&[0xff, 0xfe]), None);
    }

    /// Fix round 11 (Codex 2, Opus N4): no check runs without the key's
    /// lease; while another holds it the helper answers busy at once,
    /// having asked the key nothing.
    #[test]
    fn no_check_runs_without_the_lease() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("faceauth-keycheck-lease-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lease = dir.join("key.lease");
        std::fs::write(&lease, "").unwrap();
        std::fs::set_permissions(&lease, std::fs::Permissions::from_mode(0o600)).unwrap();
        let asked = std::cell::Cell::new(0);
        let check = |_: &str, _: &str, _: Option<&str>| {
            asked.set(asked.get() + 1);
            true
        };
        let args = ["sudo".to_string(), "alice".to_string()];
        assert_eq!(run_with(&args, &lease, &check, &mut &b""[..]), KEY_TOUCHED);
        let held = faceauth_daemon::lockgate::take_key_lease(&lease, FREED_WITHIN).unwrap();
        assert_eq!(run_with(&args, &lease, &check, &mut &b""[..]), KEY_BUSY);
        assert_eq!(
            asked.get(),
            1,
            "the key was not asked while the lease was held"
        );
        drop(held);
        assert_eq!(
            run_with(&args, &dir.join("missing"), &check, &mut &b""[..]),
            KEY_BUSY,
            "no lease file: no check"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fix round 11 (Codex 4): with faceauthd down the check is stock
    /// pam_u2f's, so its conversation goes to the PAM caller through the
    /// module: every message out as a line (`Q style hex`), each answered
    /// (`A hex`, or `N` for none), and the answer last (`R code`).
    #[test]
    fn the_stock_check_passes_its_conversation_through() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("faceauth-keycheck-conv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lease = dir.join("key.lease");
        std::fs::write(&lease, "").unwrap();
        std::fs::set_permissions(&lease, std::fs::Permissions::from_mode(0o600)).unwrap();
        let check = |_: &str, _: &str, relay: &mut dyn FnMut(i32, &str) -> Option<String>| {
            let pin = relay(1, "Please enter the PIN: ");
            let _ = relay(4, "Please touch the device.");
            let second = relay(1, "Please enter the PIN: ");
            pin.as_deref() == Some("1234") && second.is_none()
        };
        let args = [
            "--converse".to_string(),
            "sudo".to_string(),
            "alice".to_string(),
        ];
        let answers = answered(b"A 31323334\nA \nN\n");
        let mut out = Vec::new();
        let code = run_converse_with(&args, &lease, &check, answers.as_fd(), &mut out, WITHIN);
        assert_eq!(code, KEY_TOUCHED);
        let text = String::from_utf8(out).unwrap();
        let want = format!(
            "Q 1 {}\nQ 4 {}\nQ 1 {}\nR 42\n",
            faceauth_daemon::lockgate::hex_encode(b"Please enter the PIN: "),
            faceauth_daemon::lockgate::hex_encode(b"Please touch the device."),
            faceauth_daemon::lockgate::hex_encode(b"Please enter the PIN: "),
        );
        assert_eq!(text, want);
        // Only the sudo and polkit lanes; the lease first.
        let unlock = [
            "--converse".to_string(),
            "unlock".to_string(),
            "alice".to_string(),
        ];
        assert_eq!(
            run_converse_with(
                &unlock,
                &lease,
                &check,
                answered(b"").as_fd(),
                &mut Vec::new(),
                WITHIN
            ),
            2
        );
        let held = faceauth_daemon::lockgate::take_key_lease(&lease, FREED_WITHIN).unwrap();
        let mut out = Vec::new();
        assert_eq!(
            run_converse_with(
                &args,
                &lease,
                &check,
                answered(b"").as_fd(),
                &mut out,
                WITHIN
            ),
            KEY_BUSY
        );
        assert_eq!(out, b"R 3\n");
        drop(held);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fix round 13 (Opus N1; Opus's probe
    /// `opus13_probe_stdin_answer_with_the_pipe_kept_open`, turned around):
    /// the stock check reads each answer the moment it comes, on its own
    /// stdin, with the module's end kept open as the module keeps it. A
    /// buffered reader takes the whole line on its first byte, and the next
    /// poll of the descriptor then waits, to the deadline, for bytes already
    /// read; with Omarchy's stock `cue` line every check went to the
    /// password so. Run in a child of this test binary, whose fd 0 is the
    /// socket the answers come down, through the function `main` calls.
    #[test]
    fn each_answer_is_read_as_it_comes_with_the_module_end_kept_open() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "FACEAUTH_KEYCHECK_STDIN_CHILD";
        const NAME: &str = "tests::each_answer_is_read_as_it_comes_with_the_module_end_kept_open";
        if let Some(lease) = std::env::var_os(CHILD) {
            let check = |_: &str, _: &str, relay: &mut dyn FnMut(i32, &str) -> Option<String>| {
                let pin = relay(1, "Please enter the PIN: ");
                let cue = relay(4, "Please touch the device.");
                pin.as_deref() == Some("1234") && cue.is_none()
            };
            let args = [
                "--converse".to_string(),
                "sudo".to_string(),
                "alice".to_string(),
            ];
            // The lines go to stderr: the harness writes its own to stdout.
            let code = converse_on_stdin(
                &args,
                Path::new(&lease),
                &check,
                &mut std::io::stderr(),
                std::time::Duration::from_secs(5),
            );
            std::process::exit(i32::from(code));
        }
        let dir =
            std::env::temp_dir().join(format!("faceauth-keycheck-stdin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lease = dir.join("key.lease");
        std::fs::write(&lease, "").unwrap();
        std::fs::set_permissions(&lease, std::fs::Permissions::from_mode(0o600)).unwrap();
        // As the PAM module does: the answers come down a socket whose
        // other end stays open for the whole check.
        let (mut answers, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", NAME, "--test-threads=1", "--quiet"])
            .env(CHILD, &lease)
            .stdin(std::process::Stdio::from(std::os::fd::OwnedFd::from(
                theirs,
            )))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut said = Vec::new();
        let mut last = None;
        let t0 = std::time::Instant::now();
        for l in BufReader::new(child.stderr.take().unwrap()).lines() {
            let l = l.unwrap();
            if l.starts_with("Q 1 ") {
                answers.write_all(b"A 31323334\n").unwrap();
            } else if l.starts_with("Q 4 ") {
                answers.write_all(b"N\n").unwrap();
            } else if let Some(code) = l.strip_prefix("R ") {
                last = Some((code.to_string(), t0.elapsed()));
                break;
            }
            said.push(l);
        }
        let _ = child.wait();
        drop(answers);
        let _ = std::fs::remove_dir_all(&dir);
        let (code, took) = last.unwrap_or_else(|| panic!("no answer line: {:?}", said));
        assert_eq!(
            code,
            KEY_TOUCHED.to_string(),
            "both answers reached the check"
        );
        assert!(
            took < std::time::Duration::from_secs(2),
            "each answer read as it came, not at the deadline: {:?}",
            took
        );
    }

    /// The stock check's answers in these tests: a socket with `bytes`
    /// waiting on it, then its end.
    fn answered(bytes: &[u8]) -> std::os::unix::net::UnixStream {
        use std::io::Write;
        let (ours, mut theirs) = std::os::unix::net::UnixStream::pair().unwrap();
        theirs.write_all(bytes).unwrap();
        ours
    }

    /// How long these tests wait for a lease they expect free: a check's
    /// own wait. A child another test forks at that moment (the stdin test
    /// below) holds a copy of the lease's descriptor until its exec closes
    /// it, close-on-exec as it is; no check in a real helper forks.
    const FREED_WITHIN: std::time::Duration = LEASE_WAIT;

    /// The stock check's deadline in these tests.
    const WITHIN: std::time::Duration = std::time::Duration::from_secs(10);

    /// Fix round 12 (Codex 2, Opus N2; Opus's probe
    /// `opus12_probe_a_prompt_left_open_holds_the_lease`, turned around):
    /// the stock check has a hard deadline of its own, prompt time
    /// included, so a prompt left open (an unanswered sudo PIN prompt, a
    /// polkit dialog, a Ctrl-Z) gives the key's lease back at that
    /// deadline: the answer it waits for never comes, the conversation
    /// fails, and the helper ends.
    #[test]
    fn a_prompt_left_open_gives_the_lease_back_at_the_deadline() {
        use std::os::unix::fs::PermissionsExt;
        let dir =
            std::env::temp_dir().join(format!("faceauth-keycheck-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lease = dir.join("key.lease");
        std::fs::write(&lease, "").unwrap();
        std::fs::set_permissions(&lease, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (theirs, ours) = std::os::unix::net::UnixStream::pair().unwrap();
        let l2 = lease.clone();
        let t0 = std::time::Instant::now();
        let t = std::thread::spawn(move || {
            let check = |_: &str, _: &str, relay: &mut dyn FnMut(i32, &str) -> Option<String>| {
                relay(1, "Please enter the PIN: ").is_some()
            };
            let args = [
                "--converse".to_string(),
                "sudo".to_string(),
                "alice".to_string(),
            ];
            let mut out = Vec::new();
            run_converse_with(
                &args,
                &l2,
                &check,
                theirs.as_fd(),
                &mut out,
                std::time::Duration::from_millis(300),
            )
        });
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            faceauth_daemon::lockgate::take_key_lease(&lease, std::time::Duration::ZERO).is_none(),
            "held while the prompt is open"
        );
        assert_eq!(t.join().unwrap(), 1, "no answer by the deadline: no touch");
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            t0.elapsed()
        );
        assert!(
            faceauth_daemon::lockgate::take_key_lease(&lease, FREED_WITHIN).is_some(),
            "and the lease is free again, the socket still open"
        );
        drop(ours);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
