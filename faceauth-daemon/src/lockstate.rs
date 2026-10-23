//! `faceauth-lockstate`: is the user's Hyprland session locked? It reads
//! the compositor's `monitors` answer with the daemon's own strict reading
//! (`consent::lock_state_from_monitors`) and answers with one byte on its
//! stdout and the same exit status: 0 unlocked, 1 locked, 2 no answer (a
//! malformed one, a timeout, being run as root, or no mode it knows). The
//! caller reads the byte, which it gets whatever it did with SIGCHLD
//! (Codex 6, round 6). After a no-answer byte come two more naming why
//! (`lockgate::Why::bytes`; live test 1, 2026-10-13), which the daemon logs;
//! anything but exactly one answer byte is still no answer to it. Its only mode is the anchored one below; the
//! user-side check it once ran as the requesting user, asking hyprctl, is
//! gone (fix round 9, Codex 2): same-user code could forge it. So is
//! `--stdin PID`, which the PAM module's own lock gate used with faceauthd
//! down (fix round 10, item 6: faceauthd down is stock Omarchy for the key,
//! and the module asks no lock question then).
//!
//! `faceauth-lockstate --anchor UID BIND` (round 8, item 3): the daemon's
//! lock question, run in a transient system unit as a dynamic user holding
//! CAP_DAC_OVERRIDE alone (`consent::anchor`): logind's `CONTROLLER=` for
//! the bound session (`desktop`, the
//! user's only one, or `session:<id>`), its pid on the system bus, and the
//! one socket under `/run/user/UID` whose listener is that pid, all within
//! one deadline. It clears its ambient capabilities before it runs
//! `busctl`, so the child gets none, and drops the capability for good the
//! moment the connection is open, before it reads a byte the compositor
//! sends; it answers nothing if the drop fails.

use faceauth_daemon::consent::{
    lock_state_from_monitors, lockstate_exit, LockState, LOCKSTATE_UNKNOWN,
};
use faceauth_daemon::lockgate::{
    anchored_why, bind_from_arg, parse_bus_pid, recv_from, set_passcred, Bind, Why,
};
use std::path::Path;
use std::process::{ExitCode, Stdio};
use std::time::{Duration, Instant};

fn main() -> ExitCode {
    // A caller that ignored SIGCHLD handed that on through exec; this
    // process waits for busctl, so it takes the default back first.
    // SAFETY: setting a signal's disposition to the default has no
    // preconditions.
    unsafe { libc::signal(libc::SIGCHLD, libc::SIG_DFL) };
    let args: Vec<String> = std::env::args().skip(1).collect();
    // SAFETY: geteuid has no preconditions.
    let answer = dispatch(&args, unsafe { libc::geteuid() } == 0);
    report(&mut std::io::stdout(), answer)
}

/// The answer for `args`: the anchored mode only (fix round 9, Codex 2).
/// The user-side check that asked hyprctl as the requesting user is gone,
/// since same-user code could forge it, and so is the module's `--stdin`
/// (fix round 10); no mode, another, or being run as root is no answer.
fn dispatch(args: &[String], root: bool) -> Result<LockState, Why> {
    if root {
        return Err(Why::Root);
    }
    match args.first().map(String::as_str) {
        Some("--anchor") => {
            let (uid, bind) = anchor_args(args).ok_or(Why::Usage)?;
            anchor(uid, &bind)
        }
        _ => Err(Why::Usage),
    }
}

/// The answer: one byte on `out`, and the same as the exit status; after a
/// no-answer byte, the two of why.
fn report(out: &mut dyn std::io::Write, answer: Result<LockState, Why>) -> ExitCode {
    let mut bytes = Vec::with_capacity(3);
    match answer {
        Ok(state) => bytes.push(lockstate_exit(state)),
        Err(why) => {
            bytes.push(LOCKSTATE_UNKNOWN);
            bytes.extend_from_slice(&why.bytes());
        }
    }
    let _ = out.write_all(&bytes).and_then(|_| out.flush());
    ExitCode::from(bytes[0])
}

/// Ask `monitors` on the anchor's connection to the compositor's socket,
/// as hyprctl does (`j/monitors`), and read the answer strictly, taking it
/// only from the pinned compositor `pid`, the whole exchange inside
/// `limit`, however slowly the answer comes. SO_PASSCRED is set before the request goes out, so every
/// buffer of the reply carries its writer, and the reply counts only when
/// each one names `pid` (`lockgate::recv_from`; round 8, Codex 1): this
/// process makes the check, on the kernel's word, before a byte is parsed.
fn ask_on_within(
    socket: std::os::unix::net::UnixStream,
    pid: u32,
    limit: Duration,
) -> Result<LockState, Why> {
    use std::io::Write;
    let by = Instant::now() + limit;
    let left = || by.saturating_duration_since(Instant::now());
    if left().is_zero() {
        return Err(Why::Deadline);
    }
    if !set_passcred(&socket) {
        return Err(Why::Passcred);
    }
    if socket.set_write_timeout(Some(left())).is_err()
        || (&socket).write_all(b"j/monitors").is_err()
    {
        return Err(Why::Send);
    }
    let out = recv_from(&socket, pid, left(), 1 << 20).ok_or(Why::Reply)?;
    match lock_state_from_monitors(&out) {
        LockState::Unknown => Err(Why::Unreadable),
        state => Ok(state),
    }
}

/// `--anchor UID BIND`: the uid and the binding, or None.
fn anchor_args(args: &[String]) -> Option<(u32, Bind)> {
    let [flag, uid, bind] = args else {
        return None;
    };
    if flag != "--anchor" {
        return None;
    }
    Some((uid.parse().ok()?, bind_from_arg(bind)?))
}

/// The anchor's whole look, within `faceauth_daemon::consent::ANCHOR_WITHIN`.
fn anchor(uid: u32, bind: &Bind) -> Result<LockState, Why> {
    // No child of this process inherits the capability: busctl runs with
    // none. Checked, not assumed: a set that did not clear answers nothing.
    // The guard threads `anchored` starts inherit the cleared set.
    if !clear_ambient() {
        return Err(Why::Ambient);
    }
    anchor_at(
        Path::new("/run/systemd"),
        Path::new("/run/user"),
        uid,
        bind,
        Instant::now() + faceauth_daemon::consent::ANCHOR_WITHIN,
        &bus_pid,
        &drop_capabilities,
    )
}

/// The anchor against `logind` and `runtime_root`, with `resolve` naming a
/// bus name's pid and `drop_caps` run (and required to succeed) the moment
/// the compositor's connection is open, before its answer is read.
fn anchor_at(
    logind: &Path,
    runtime_root: &Path,
    uid: u32,
    bind: &Bind,
    deadline: Instant,
    resolve: &dyn Fn(&str, Duration) -> Option<u32>,
    drop_caps: &dyn Fn() -> bool,
) -> Result<LockState, Why> {
    let ask = |stream: std::os::unix::net::UnixStream, pid: u32, left: Duration| {
        if drop_caps() {
            ask_on_within(stream, pid, left)
        } else {
            Err(Why::Caps)
        }
    };
    anchored_why(logind, runtime_root, uid, bind, deadline, resolve, &ask)
}

/// Clear this thread's ambient capabilities and check that none is left
/// (round 8): `PR_CAP_AMBIENT_CLEAR_ALL`, then `PR_CAP_AMBIENT_IS_SET`
/// for every capability the kernel knows (EINVAL past the last one).
fn clear_ambient() -> bool {
    // SAFETY: plain prctl calls on values.
    unsafe {
        if libc::prctl(
            libc::PR_CAP_AMBIENT,
            libc::PR_CAP_AMBIENT_CLEAR_ALL as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        ) != 0
        {
            return false;
        }
        for cap in 0..64 as libc::c_ulong {
            match libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_IS_SET as libc::c_ulong,
                cap,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) {
                0 => {}
                -1 if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) => break,
                _ => return false,
            }
        }
    }
    true
}

/// Drop every capability for good: permitted, effective and inheritable
/// emptied with `capset`, and read back empty. False when either fails.
fn drop_capabilities() -> bool {
    #[repr(C)]
    struct Header {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct Data {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    const VERSION_3: u32 = 0x2008_0522;
    let mut header = Header {
        version: VERSION_3,
        pid: 0,
    };
    let none = [Data::default(); 2];
    // SAFETY: a valid version-3 header and two data words, as capset takes.
    let set = unsafe { libc::syscall(libc::SYS_capset, &mut header as *mut Header, none.as_ptr()) };
    if set != 0 {
        return false;
    }
    let mut header = Header {
        version: VERSION_3,
        pid: 0,
    };
    let mut now = [Data::default(); 2];
    // SAFETY: the same, with room for capget's two words.
    let got = unsafe {
        libc::syscall(
            libc::SYS_capget,
            &mut header as *mut Header,
            now.as_mut_ptr(),
        )
    };
    got == 0
        && now
            .iter()
            .all(|d| d.effective == 0 && d.permitted == 0 && d.inheritable == 0)
}

/// The pid behind a unique bus name on the system bus (`busctl`'s
/// `GetConnectionUnixProcessID`), within `limit`.
fn bus_pid(name: &str, limit: Duration) -> Option<u32> {
    use std::io::Read;
    let mut busctl = std::process::Command::new("/usr/bin/busctl");
    busctl
        .args([
            "--system",
            "--timeout=1",
            "call",
            "org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus",
            "GetConnectionUnixProcessID",
            "s",
            name,
        ])
        .env_clear()
        .env("PATH", "/usr/bin")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Its own pidfd, the only way it is signalled (fix round 13, Codex 1).
    let (mut child, pidfd) = faceauth_daemon::child::spawn_with_pidfd(&mut busctl).ok()?;
    let by = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => break,
            Ok(Some(_)) | Err(_) => return None,
            Ok(None) if Instant::now() > by => {
                faceauth_daemon::child::kill(&pidfd);
                let _ = child.wait();
                return None;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(10)),
        }
    }
    let mut out = Vec::new();
    child.stdout.take()?.take(64).read_to_end(&mut out).ok()?;
    parse_bus_pid(&out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use faceauth_daemon::consent::LOCKSTATE_LOCKED;

    /// The exchange's bound in these tests.
    const WITHIN: Duration = Duration::from_secs(5);

    /// Round 7 (A): on the connection the anchor opened (to the socket
    /// whose listener is the compositor logind names), it asks `monitors`
    /// in hyprctl's own words and reads the answer with the strict reading.
    #[test]
    fn it_asks_the_compositor_on_the_anchors_connection() {
        use std::io::{Read, Write};
        use std::os::unix::net::UnixStream;
        let cases: [(&[u8], Result<LockState, Why>); 3] = [
            (
                br#"[{"name":"eDP-1","solitaryBlockedBy":["LOCK"]}]"#,
                Ok(LockState::Locked),
            ),
            (
                br#"[{"name":"eDP-1","solitaryBlockedBy":null}]"#,
                Ok(LockState::Unlocked),
            ),
            (
                br#"[{"name":"eDP-1","solitaryBlocked":["LOCK"]}]"#,
                Err(Why::Unreadable),
            ),
        ];
        for (reply, want) in cases {
            let (ours, theirs) = UnixStream::pair().unwrap();
            let fake = std::thread::spawn(move || {
                let mut req = [0u8; 64];
                let n = (&theirs).read(&mut req).unwrap();
                let _ = (&theirs).write_all(reply);
                String::from_utf8_lossy(&req[..n]).into_owned()
            });
            assert_eq!(ask_on_within(ours, std::process::id(), WITHIN), want);
            assert_eq!(fake.join().unwrap(), "j/monitors");
        }
    }

    /// Round 6 (Codex 6): the answer is one byte on stdout as well as the
    /// exit status, so a caller that cannot reap still reads it.
    #[test]
    fn the_answer_is_one_byte_and_the_exit_status() {
        let mut out = Vec::new();
        let _ = report(&mut out, Ok(LockState::Locked));
        assert_eq!(out, [LOCKSTATE_LOCKED]);
    }

    /// Round 8 (item 3): the anchor mode, the daemon's lock question, finds
    /// the compositor logind names for the bound session and asks it on
    /// the one socket whose listener is that process, within one deadline,
    /// with every capability dropped before a byte of the answer is read.
    /// Here against a fake logind, a resolver naming this process and a
    /// listener of this process's answering as Hyprland would.
    #[test]
    fn the_anchor_mode_asks_the_named_compositor_without_privilege() {
        use std::io::{Read, Write};
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        let base = std::env::temp_dir().join(format!("lockstate-anchor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let hypr = base.join("run").join(uid.to_string()).join("hypr/sig_1");
        std::fs::create_dir_all(&hypr).unwrap();
        std::fs::create_dir_all(base.join("logind/sessions")).unwrap();
        std::fs::write(
            base.join("logind/sessions/1"),
            format!("UID={}\nTYPE=wayland\nCONTROLLER=:1.35\n", uid),
        )
        .unwrap();
        let listener = std::os::unix::net::UnixListener::bind(hypr.join(".socket.sock")).unwrap();
        let fake = std::thread::spawn(move || {
            let (c, _) = listener.accept().unwrap();
            let mut req = [0u8; 64];
            let n = (&c).read(&mut req).unwrap();
            let _ = (&c).write_all(br#"[{"name":"eDP-1","solitaryBlockedBy":["LOCK"]}]"#);
            String::from_utf8_lossy(&req[..n]).into_owned()
        });
        let dropped = std::cell::Cell::new(false);
        let me = |name: &str, _: Duration| (name == ":1.35").then_some(std::process::id());
        let got = anchor_at(
            &base.join("logind"),
            &base.join("run"),
            uid,
            &faceauth_daemon::lockgate::Bind::OnlyDesktop,
            Instant::now() + Duration::from_secs(2),
            &me,
            &|| {
                dropped.set(true);
                true
            },
        );
        assert_eq!(got, Ok(LockState::Locked));
        assert!(dropped.get(), "the capability was dropped first");
        assert_eq!(fake.join().unwrap(), "j/monitors");
        let refused = anchor_at(
            &base.join("logind"),
            &base.join("run"),
            uid,
            &faceauth_daemon::lockgate::Bind::Ambiguous,
            Instant::now() + Duration::from_secs(2),
            &me,
            &|| true,
        );
        assert_eq!(refused, Err(Why::NoDesktop), "an ambiguous binding");
        let _ = std::fs::remove_dir_all(&base);
        assert!(
            drop_capabilities(),
            "an unprivileged process drops nothing and says so"
        );
        assert_eq!(
            anchor_args(&["--anchor".into(), "1000".into(), "session:3".into()]),
            Some((1000, faceauth_daemon::lockgate::Bind::Session("3".into())))
        );
        assert_eq!(
            anchor_args(&["--anchor".into(), "x".into(), "desktop".into()]),
            None
        );
        assert_eq!(anchor_args(&["--anchor".into(), "1000".into()]), None);
    }

    /// Round 8 (Codex 1): the helper takes the compositor's reply only
    /// when the kernel says the pinned pid wrote it. A reply another
    /// process writes on the same connection is no answer.
    #[test]
    fn the_helper_takes_the_reply_only_from_the_pinned_writer() {
        use std::io::Read;
        use std::os::fd::OwnedFd;
        use std::os::unix::net::UnixStream;
        let locked = br#"[{"name":"eDP-1","solitaryBlockedBy":["LOCK"]}]"#;
        let (ours, theirs) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            let mut req = [0u8; 64];
            let _ = (&theirs).read(&mut req).unwrap();
            let st = std::process::Command::new("/bin/sh")
                .args(["-c", r#"printf '%s' "$1""#, "sh"])
                .arg(String::from_utf8_lossy(locked).into_owned())
                .stdout(std::process::Stdio::from(OwnedFd::from(theirs)))
                .status()
                .unwrap();
            assert!(st.success());
        });
        assert_eq!(
            ask_on_within(ours, std::process::id(), WITHIN),
            Err(Why::Reply)
        );
        fake.join().unwrap();
    }

    /// Live test 1 (2026-10-13): a look that gives no answer says why,
    /// after its no-answer byte, so the daemon's log names the step: here
    /// a runtime directory with no `hypr/`, whose listing fails with
    /// ENOENT. The exit status is still the no-answer byte.
    #[test]
    fn no_answer_names_its_step() {
        // SAFETY: getuid has no preconditions.
        let uid = unsafe { libc::getuid() };
        let base = std::env::temp_dir().join(format!("lockstate-why-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("run").join(uid.to_string())).unwrap();
        std::fs::create_dir_all(base.join("logind/sessions")).unwrap();
        std::fs::write(
            base.join("logind/sessions/1"),
            format!("UID={}\nTYPE=wayland\nCONTROLLER=:1.35\n", uid),
        )
        .unwrap();
        let me = |name: &str, _: Duration| (name == ":1.35").then_some(std::process::id());
        let got = anchor_at(
            &base.join("logind"),
            &base.join("run"),
            uid,
            &faceauth_daemon::lockgate::Bind::OnlyDesktop,
            Instant::now() + Duration::from_secs(2),
            &me,
            &|| true,
        );
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(got, Err(Why::Sockets(libc::ENOENT)));
        let mut out = Vec::new();
        let _ = report(&mut out, got);
        assert_eq!(out, [LOCKSTATE_UNKNOWN, 9, libc::ENOENT as u8]);
        assert_eq!(
            Why::from_bytes([out[1], out[2]]),
            Some(Why::Sockets(libc::ENOENT)),
            "read back as written"
        );
    }

    /// Round 8 (Codex, Opus L2): clearing the ambient set is checked, not
    /// assumed; here, unprivileged, there is nothing to clear and the check
    /// says so.
    #[test]
    fn clearing_the_ambient_set_is_checked() {
        assert!(clear_ambient());
    }

    /// Fix round 9 (Codex 2): the helper's only mode is the anchored one.
    /// Run with no mode (the user-side check, which asked hyprctl as the
    /// requesting user, so same-user code could forge it), with an unknown
    /// one, with the module's `--stdin` (fix round 10), or as root, it
    /// answers nothing.
    #[test]
    fn only_the_anchored_mode_answers() {
        assert_eq!(dispatch(&[], false), Err(Why::Usage), "no mode");
        assert_eq!(dispatch(&["--user".into()], false), Err(Why::Usage));
        assert_eq!(
            dispatch(&["--stdin".into(), "4242".into()], false),
            Err(Why::Usage),
            "the module's mode, gone with its gate"
        );
        assert_eq!(
            dispatch(&["--anchor".into(), "1000".into(), "desktop".into()], true),
            Err(Why::Root),
            "as root"
        );
    }
}
