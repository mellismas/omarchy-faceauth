//! The daemon's lock question (round 8, item 3): the anchor
//! (`lockgate::anchored`: logind's
//! `CONTROLLER=` for the session the request is bound to, that bus name's
//! pid on the system bus, the one socket under the user's runtime
//! directory whose listener is that pid, and the answer read without
//! privilege), run by `faceauth-lockstate --anchor` in a transient system
//! unit, the way the key check runs. faceauthd itself keeps no capability.
//!
//! The unit holds one capability, CAP_DAC_OVERRIDE, as a dynamic user.
//! The user's runtime directory is 0700 and Hyprland's socket is 0755:
//! reaching the socket needs search permission on the directory, and
//! connecting to a Unix socket needs write permission on its inode.
//! CAP_DAC_READ_SEARCH grants only read and search, so it cannot connect;
//! CAP_DAC_OVERRIDE is the narrowest capability that can. A dynamic user
//! rather than root keeps the unit away from every root-owned file it
//! could otherwise write with that capability (the file system is
//! read-only to it besides), and needs no CAP_SETUID to drop to nobody
//! for the parse: the helper clears its ambient set before it runs
//! `busctl`, so the child gets nothing, and drops the capability for good
//! (`capset` to empty) the moment the connection is open, before it reads
//! a byte the compositor sends.
//!
//! Forging an unlock then needs code inside the genuine compositor (the
//! process logind names as the session's controller), which is the stated
//! boundary (SECURITY.md).

use crate::lockgate::{bind_arg, Bind, LockState, Why};
use std::time::{Duration, Instant};

/// The helper the unit runs.
pub const ANCHOR_HELPER: &str = "/usr/lib/faceauth/faceauth-lockstate";

/// The helper's own deadline over the whole look (`lockgate::anchored`).
pub const ANCHOR_WITHIN: Duration = Duration::from_millis(1500);

/// The longest the daemon waits for the unit, `systemd-run` included:
/// below `lockgate::LIVENESS`, so a lock question never outlasts a
/// waiting PAM line's patience (round 6, item 12).
pub const ANCHOR_LIMIT: Duration = Duration::from_secs(3);

/// How long the daemon reads one anchored question before it gives it up:
/// the launcher's `timeout` and a moment more. A fresh look (a commit's)
/// takes at most this, below `lockgate::LIVENESS` (fix round 10, Opus N3).
pub const ANCHOR_READ: Duration = Duration::from_millis(ANCHOR_LIMIT.as_millis() as u64 + 500);

/// The sandbox of the anchor's unit. A dynamic user with
/// CAP_DAC_OVERRIDE alone (ambient and bounding), no new privileges, a
/// read-only file system, /run an allow-list of logind's session records,
/// the system bus socket and this user's runtime directory (lstat and
/// connect need no write to the mount), AF_UNIX only, no network, no
/// devices, the daemon's state, config, the key file, sudoers, the
/// password and group shadows, SSH's keys, /boot, /efi, /var/lib and
/// /var/log out of sight (the capability would read them otherwise), a
/// hard runtime cap. It shares the host's pid namespace on
/// purpose: the bus answers with host pids, and the socket's listener and
/// the reply's writer must read as the same pid.
pub const ANCHOR_UNIT_PROPERTIES: &[&str] = &[
    "DynamicUser=yes",
    "AmbientCapabilities=CAP_DAC_OVERRIDE",
    "CapabilityBoundingSet=CAP_DAC_OVERRIDE",
    "NoNewPrivileges=yes",
    "RuntimeMaxSec=3s",
    "ProtectSystem=strict",
    // An allow-list (fix round 8, Codex and Opus L2): an empty, read-only
    // /run and an empty /home, /root and /run/user, with only logind's
    // session records and the system bus bound back in, read-only, and
    // this user's runtime directory (`anchor_command`). So no other control
    // socket (/run/systemd/private, /run/udev/control, the daemon's own)
    // is reachable, whatever a path names. systemd.exec(5) gives this very
    // pairing as TemporaryFileSystem='s example ("TemporaryFileSystem=/var:ro"
    // with "BindReadOnlyPaths=/var/lib/systemd").
    "ProtectHome=tmpfs",
    "TemporaryFileSystem=/run:ro",
    "BindReadOnlyPaths=/run/systemd/sessions /run/dbus/system_bus_socket",
    "PrivateTmp=yes",
    "PrivateNetwork=yes",
    "PrivateIPC=yes",
    "PrivateDevices=yes",
    "RestrictAddressFamilies=AF_UNIX",
    "IPAddressDeny=any",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "RestrictNamespaces=yes",
    "RestrictSUIDSGID=yes",
    "RestrictRealtime=yes",
    "LockPersonality=yes",
    "MemoryDenyWriteExecute=yes",
    "SystemCallArchitectures=native",
    "SystemCallFilter=@system-service",
    "SystemCallErrorNumber=EPERM",
    "DevicePolicy=closed",
    // CAP_DAC_OVERRIDE bypasses read checks as well as write ones
    // (capabilities(7)), and ProtectSystem=strict stops only writes, so
    // everything the unit must not read is out of sight (fix round 9, Opus
    // L3): the daemon's files, the key file, sudoers, the password and
    // group shadows, SSH's keys, /boot, /efi, /var/lib and /var/log.
    "InaccessiblePaths=-/etc/faceauth -/etc/fido2 -/etc/sudoers -/etc/sudoers.d -/etc/shadow -/etc/gshadow -/etc/ssh -/boot -/efi -/var/lib -/var/log",
    "KillSignal=SIGKILL",
    "UMask=0077",
    "LimitCORE=0",
    "MemoryMax=64M",
    "TasksMax=8",
];

/// The `systemd-run` that runs the anchor for `uid`, bound as `bind` (the
/// argument form, `lockgate::bind_arg`), under `timeout`. `--pipe` brings
/// the helper's one byte back; `--wait` holds until it has exited.
pub fn anchor_command(uid: u32, bind: &str) -> std::process::Command {
    anchor_command_with(std::path::Path::new("/usr/bin/systemd-run"), uid, bind)
}

/// `anchor_command` with `systemd_run` as the launcher (a test's stand-in).
pub fn anchor_command_with(
    systemd_run: &std::path::Path,
    uid: u32,
    bind: &str,
) -> std::process::Command {
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    let mut c = std::process::Command::new("/usr/bin/timeout");
    c.args(["-k", "1"])
        .arg(ANCHOR_LIMIT.as_secs().to_string())
        .arg(systemd_run)
        .args([
            "--quiet",
            "--collect",
            "--wait",
            "--pipe",
            "--service-type=exec",
            "--description=Omarchy FaceAuth lock question",
        ])
        .args(
            ANCHOR_UNIT_PROPERTIES
                .iter()
                .map(|p| format!("--property={}", p)),
        )
        // This user's runtime directory, read-only, into the empty /run
        // ("-": a missing one is no answer, not a failed unit).
        .arg(format!("--property=BindReadOnlyPaths=-/run/user/{}", uid))
        .args([ANCHOR_HELPER, "--anchor"])
        .arg(uid.to_string())
        .arg(bind)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // Its own process group, so a run past its deadline is killed
        // whole: `timeout`, the launcher and anything they started.
        .process_group(0);
    c
}

/// The answer in a finished run: its exit code (None when a signal ended
/// it) and what it wrote. The helper writes one byte and exits with the
/// same status, and `systemd-run --wait` hands the service's status back
/// (systemd v262 src/run/run.c, the end of `start_transient_service`:
/// result "success" returns 0, "exit-code" the status, "signal" 255, any
/// other result, a `RuntimeMaxSec=` timeout among them, 1). So only an
/// exact pair is an answer, (0, 0) unlocked and (1, 1) locked; (2, 2), the
/// helper's own "no answer" (with the two bytes of why after it, which
/// `why_of` reads), and everything else (a mismatch, no byte or two, a
/// signal, `timeout`'s 124 or 137, a unit that never started) are Unknown.
pub fn answer_of(code: Option<i32>, out: &[u8]) -> LockState {
    match (code, out) {
        (Some(0), [0]) => LockState::Unlocked,
        (Some(1), [1]) => LockState::Locked,
        _ => LockState::Unknown,
    }
}

/// Why a finished run gave no answer, in words for the log (live test 1,
/// 2026-10-13, when every look went unanswered and the log said only that
/// the lock state read unknown): the step the helper names after its
/// no-answer byte (`lockgate::Why`), or how the run ended. None for an
/// answer.
pub fn why_of(code: Option<i32>, out: &[u8]) -> Option<String> {
    if answer_of(code, out) != LockState::Unknown {
        return None;
    }
    Some(match (code, out) {
        (Some(2), [2, step, errno]) => match Why::from_bytes([*step, *errno]) {
            Some(why) => why.to_string(),
            None => format!(
                "the helper gave no answer, for a reason this daemon does not know (step {})",
                step
            ),
        },
        (Some(2), [2]) => "the helper gave no answer".to_string(),
        (Some(c), _) => format!(
            "the lock question's unit ended with status {} after {} byte(s)",
            c,
            out.len()
        ),
        (None, _) => "the lock question's unit was ended by a signal".to_string(),
    })
}

/// How long an unchanged reason waits before it is logged again while the
/// lock question keeps going unanswered: the daemon asks about once a
/// second.
pub const WHY_AGAIN: Duration = Duration::from_secs(60);

/// How many sessions' reasons `WhyLog` keeps at once: more than any machine
/// has desktops. Past it, reasons older than `WHY_AGAIN` go first, then all.
pub const WHY_KEYS: usize = 64;

/// What the daemon last logged about each session's lock question, keyed
/// by uid and binding (round 16, Codex: one reason for all of them mixed
/// users, so alternating users logged an unchanged failure every time, and
/// one user's answer announced another's recovery).
#[derive(Default)]
pub struct WhyLog {
    last: std::collections::HashMap<(u32, String), (String, Instant)>,
}

/// A line `WhyLog::note` says to log.
#[derive(Debug, PartialEq)]
pub enum WhyLine {
    /// The session's question went unanswered, for this reason.
    Failing(String),
    /// It answers again after a failure that was logged.
    Answers,
}

impl WhyLog {
    /// The line to log, if any, for `uid`'s question about `bind` at `now`:
    /// a new reason at once, the same one again only `WHY_AGAIN` later, and
    /// an answer after a logged failure once, for that session alone.
    pub fn note(
        &mut self,
        uid: u32,
        bind: &str,
        why: Option<&str>,
        now: Instant,
    ) -> Option<WhyLine> {
        let key = (uid, bind.to_string());
        let Some(why) = why else {
            return self.last.remove(&key).map(|_| WhyLine::Answers);
        };
        if let Some((said, at)) = self.last.get(&key) {
            if said == why && now.saturating_duration_since(*at) < WHY_AGAIN {
                return None;
            }
        }
        if !self.last.contains_key(&key) && self.last.len() >= WHY_KEYS {
            self.last
                .retain(|_, (_, at)| now.saturating_duration_since(*at) < WHY_AGAIN);
            if self.last.len() >= WHY_KEYS {
                self.last.clear();
            }
        }
        self.last.insert(key, (why.to_string(), now));
        Some(WhyLine::Failing(why.to_string()))
    }
}

/// The daemon's `WhyLog`.
static WHY_LOG: std::sync::LazyLock<std::sync::Mutex<WhyLog>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(WhyLog::default()));

/// Log why `uid`'s lock question about `bind` went unanswered (`why`), or,
/// once it answers again after that, that it does.
fn note_why(uid: u32, bind: &str, why: Option<String>) {
    let line = WHY_LOG.lock().unwrap_or_else(|e| e.into_inner()).note(
        uid,
        bind,
        why.as_deref(),
        Instant::now(),
    );
    match line {
        Some(WhyLine::Failing(why)) => log::warn!(
            "lock question for uid {} ({}): {}; it reads as unknown until it answers",
            uid,
            bind,
            why
        ),
        Some(WhyLine::Answers) => {
            log::info!("lock question for uid {} ({}) answers again", uid, bind)
        }
        None => {}
    }
}

/// Run an anchor command within `within` (round 8, Opus L3): how it
/// ended, its exit code and what it wrote. The bytes are read as they
/// come, never waiting for EOF, since the pipe `--pipe` hands the unit is
/// held by PID 1 until the unit is collected; the run is over once the
/// wrapper has exited. Past the deadline the run's process group is
/// killed, and it gave nothing. More than a few bytes is no answer
/// (`consent::bounded`, shared with every call into the user's session
/// since fix round 10).
pub fn run_anchor(c: std::process::Command, within: Duration) -> Option<(Option<i32>, Vec<u8>)> {
    let ran = super::bounded::run_bounded(c, None, within, 8).ok()?;
    Some((
        ran.code,
        if ran.overflowed {
            vec![0xff; 9]
        } else {
            ran.out
        },
    ))
}

/// The lock state of the session of `user`'s that `bind` names, from the
/// anchor's unit. Unknown for an ambiguous binding (nothing is run), a
/// user the system does not know, and any failure.
pub fn anchored_lock_state(user: &str, bind: &Bind) -> LockState {
    let Some(uid) = nix::unistd::User::from_name(user)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
    else {
        return LockState::Unknown;
    };
    anchored_lock_state_as(uid, bind, &|c| run_anchor(c, ANCHOR_READ))
}

/// `anchored_lock_state` for `uid`, with `run` running the command and
/// handing back how it ended: its exit code and what it wrote.
pub fn anchored_lock_state_as(
    uid: u32,
    bind: &Bind,
    run: &dyn Fn(std::process::Command) -> Option<(Option<i32>, Vec<u8>)>,
) -> LockState {
    let Some(arg) = bind_arg(bind) else {
        return LockState::Unknown;
    };
    let (state, why) = match run(anchor_command(uid, &arg)) {
        Some((code, out)) => (answer_of(code, &out), why_of(code, &out)),
        None => (
            LockState::Unknown,
            Some(
                "the lock question's unit could not be run, or did not finish in time".to_string(),
            ),
        ),
    };
    note_why(uid, &arg, why);
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(c: &std::process::Command) -> Vec<String> {
        c.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    /// Round 8 (item 3): the daemon's lock question runs the anchor in a
    /// transient system unit, as the key check runs: a dynamic user with
    /// CAP_DAC_OVERRIDE alone, no new privileges, AF_UNIX only, nothing
    /// writable and a hard cap, in the host's pid namespace; the binding
    /// goes as an argument, and an ambiguous one runs nothing. Only its one
    /// byte is read, and anything else is no answer.
    #[test]
    fn the_anchor_unit_holds_one_capability_and_nothing_else() {
        let c = anchor_command(1000, "session:3");
        let a = args(&c);
        assert_eq!(c.get_program(), "/usr/bin/timeout");
        for want in [
            "--property=DynamicUser=yes",
            "--property=AmbientCapabilities=CAP_DAC_OVERRIDE",
            "--property=CapabilityBoundingSet=CAP_DAC_OVERRIDE",
            "--property=NoNewPrivileges=yes",
            "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=ProtectHome=tmpfs",
            "--property=TemporaryFileSystem=/run:ro",
            "--property=BindReadOnlyPaths=/run/systemd/sessions /run/dbus/system_bus_socket",
            "--property=BindReadOnlyPaths=-/run/user/1000",
            "--property=ProtectSystem=strict",
            "--property=PrivateNetwork=yes",
            "--property=PrivateDevices=yes",
            "--pipe",
            "--wait",
        ] {
            assert!(a.iter().any(|x| x == want), "{}: {:?}", want, a);
        }
        assert_eq!(
            a.iter().filter(|x| x.contains("Capabilit")).count(),
            2,
            "no other capability is named"
        );
        assert!(
            !a.iter().any(|x| x.contains("PrivatePIDs")),
            "the listener's pid must read as the bus's"
        );
        assert!(!a.iter().any(|x| x == "--user"), "a system unit");
        // Fix round 9 (Opus L3): CAP_DAC_OVERRIDE bypasses read checks too
        // (capabilities(7)), and ProtectSystem=strict only stops writes, so
        // what the unit must not read is out of sight.
        let hidden: Vec<&str> = a
            .iter()
            .filter_map(|x| x.strip_prefix("--property=InaccessiblePaths="))
            .flat_map(|v| v.split_whitespace())
            .collect();
        for p in [
            "-/etc/shadow",
            "-/etc/gshadow",
            "-/etc/ssh",
            "-/boot",
            "-/efi",
            "-/var/lib",
            "-/var/log",
            "-/etc/faceauth",
            "-/etc/fido2",
            "-/etc/sudoers",
            "-/etc/sudoers.d",
        ] {
            assert!(hidden.contains(&p), "{} is out of reach: {:?}", p, hidden);
        }
        // Round 8 (Codex, Opus L2): /run is an allow-list. Nothing under it
        // is reachable but logind's session records, the system bus and
        // this user's runtime directory: not /run/systemd/private, not any
        // other control socket.
        assert!(
            !a.iter().any(|x| x.contains("ProtectHome=read-only")),
            "{:?}",
            a
        );
        assert!(
            !a.iter()
                .any(|x| x.contains("/run/user/") && !x.ends_with("/run/user/1000")),
            "only this user's runtime directory"
        );
        assert_eq!(
            &a[a.len() - 4..],
            [ANCHOR_HELPER, "--anchor", "1000", "session:3"]
        );
        assert!(ANCHOR_LIMIT < crate::lockgate::LIVENESS);
        assert!(ANCHOR_WITHIN < ANCHOR_LIMIT);
        let ran = std::cell::Cell::new(0);
        let answer = |out: Option<(Option<i32>, Vec<u8>)>| {
            let out = std::cell::RefCell::new(out);
            anchored_lock_state_as(1000, &Bind::OnlyDesktop, &|c| {
                ran.set(ran.get() + 1);
                assert!(args(&c).iter().any(|x| x == "desktop"));
                out.borrow_mut().take()
            })
        };
        assert_eq!(answer(Some((Some(1), vec![1]))), LockState::Locked);
        assert_eq!(answer(Some((Some(0), vec![0]))), LockState::Unlocked);
        assert_eq!(
            answer(Some((Some(0), vec![0, 0]))),
            LockState::Unknown,
            "one byte only"
        );
        assert_eq!(answer(None), LockState::Unknown);
        assert_eq!(ran.get(), 4);
        assert_eq!(
            anchored_lock_state_as(1000, &Bind::Ambiguous, &|_| panic!("ran")),
            LockState::Unknown
        );
    }

    /// Live test 1 (2026-10-13): a run with no answer is logged with why,
    /// in words: the helper's own step, read from the bytes after its
    /// no-answer byte, or how the run ended; an answer has no reason. An
    /// unchanged reason is logged again only after `WHY_AGAIN`.
    #[test]
    fn no_answer_is_logged_with_why() {
        assert_eq!(why_of(Some(0), &[0]), None);
        assert_eq!(why_of(Some(1), &[1]), None);
        let blocked = why_of(Some(2), &[2, 9, 38]).unwrap();
        assert!(
            blocked.contains("could not be listed") && blocked.contains("os error 38"),
            "{}",
            blocked
        );
        assert_eq!(
            why_of(Some(2), &[2, 6, 0]).unwrap(),
            Why::NoDesktop.to_string()
        );
        assert!(why_of(Some(2), &[2, 200, 0]).unwrap().contains("step 200"));
        assert_eq!(why_of(Some(2), &[2]).unwrap(), "the helper gave no answer");
        assert!(why_of(Some(124), &[]).unwrap().contains("status 124"));
        assert!(why_of(None, &[1]).unwrap().contains("signal"));
        for why in [
            Why::Root,
            Why::Usage,
            Why::Ambient,
            Why::Hidden,
            Why::Stalled,
            Why::NoDesktop,
            Why::Bus,
            Why::Deadline,
            Why::Sockets(38),
            Why::NoSocket,
            Why::Passcred,
            Why::Caps,
            Why::Send,
            Why::Reply,
            Why::Unreadable,
        ] {
            assert_eq!(Why::from_bytes(why.bytes()), Some(why), "{:?}", why);
        }
        let t0 = Instant::now();
        let at = |s: u64| t0 + Duration::from_secs(s);
        let failing = |w: &str| Some(WhyLine::Failing(w.into()));
        let mut log = WhyLog::default();
        assert_eq!(
            log.note(1000, "desktop", Some("a"), at(0)),
            failing("a"),
            "the first reason"
        );
        assert_eq!(
            log.note(1000, "desktop", Some("a"), at(1)),
            None,
            "the same, soon after"
        );
        assert_eq!(
            log.note(1000, "desktop", Some("b"), at(2)),
            failing("b"),
            "a new reason at once"
        );
        assert_eq!(log.note(1000, "desktop", Some("b"), at(61)), None);
        assert_eq!(
            log.note(1000, "desktop", Some("b"), at(62)),
            failing("b"),
            "again after WHY_AGAIN"
        );
        // Users and sessions never mix: another's failures do not repeat
        // this one's, and another's answer announces no recovery here.
        assert_eq!(log.note(1001, "desktop", Some("b"), at(63)), failing("b"));
        assert_eq!(
            log.note(1000, "desktop", Some("b"), at(64)),
            None,
            "uid 1000 still quiet"
        );
        assert_eq!(log.note(1000, "session:3", Some("b"), at(64)), failing("b"));
        assert_eq!(
            log.note(1001, "desktop", None, at(65)),
            Some(WhyLine::Answers)
        );
        assert_eq!(
            log.note(1001, "desktop", None, at(66)),
            None,
            "announced once"
        );
        assert_eq!(
            log.note(1000, "desktop", Some("b"), at(70)),
            None,
            "1000 is still failing, already said"
        );
        assert_eq!(
            log.note(1000, "desktop", None, at(71)),
            Some(WhyLine::Answers)
        );
        assert_eq!(
            log.note(1002, "desktop", None, at(71)),
            None,
            "no failure to recover from"
        );
        // Bounded: past WHY_KEYS sessions the stale ones go first.
        let mut log = WhyLog::default();
        for uid in 0..WHY_KEYS as u32 {
            assert!(log.note(uid, "desktop", Some("x"), at(0)).is_some());
        }
        assert!(log.note(9999, "desktop", Some("x"), at(120)).is_some());
        assert!(log.last.len() <= WHY_KEYS, "{}", log.last.len());
    }

    /// Round 8 (Codex 3): the helper answers with one byte and the same
    /// exit status (0 unlocked, 1 locked, 2 no answer), and `systemd-run
    /// --wait` hands the service's status back (systemd v262 src/run/run.c,
    /// at the end of `start_transient_service`: "success" is 0, "exit-code"
    /// is the status, "signal" is 255, anything else, a timeout included,
    /// is 1). Only an exact pair is an answer: a genuine lock (1, 1) reads
    /// locked, where round 8 took any status but 0 for no answer and so
    /// refused every key unlock. Every other termination is no answer.
    #[test]
    fn the_wrapper_answers_only_on_a_matching_status_and_byte() {
        assert_eq!(answer_of(Some(0), &[0]), LockState::Unlocked);
        assert_eq!(answer_of(Some(1), &[1]), LockState::Locked);
        assert_eq!(answer_of(Some(2), &[2]), LockState::Unknown);
        for (code, out) in [
            (Some(1), &[0u8][..]),
            (Some(0), &[1u8][..]),
            (Some(255), &[1u8][..]),
            (Some(1), &[][..]),
            (Some(0), &[][..]),
            (Some(1), &[1u8, 1][..]),
            (Some(124), &[0u8][..]),
            (Some(137), &[1u8][..]),
            (None, &[1u8][..]),
            (Some(3), &[3u8][..]),
        ] {
            assert_eq!(
                answer_of(code, out),
                LockState::Unknown,
                "{:?} {:?}",
                code,
                out
            );
        }
    }

    /// The fake `systemd-run` the next test hands the real `timeout`
    /// wrapper: a script in `dir` that behaves as `body` says.
    fn fake_systemd_run(dir: &std::path::Path, name: &str, body: &str) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(&p, format!("#!/bin/sh\n{}\n", body)).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// Round 8 (Codex 3, Opus L3): the real wrapper, `timeout` around a
    /// stand-in `systemd-run` that propagates the helper's status as run.c
    /// does, read the way the daemon reads it. Each status and byte comes
    /// through; a run whose pipe something else keeps open (PID 1 holds the
    /// one `--pipe` hands the unit until it is collected) is answered as
    /// soon as the wrapper exits, never at EOF; and a run that never ends is
    /// no answer at the deadline, its process group killed.
    #[test]
    fn the_real_wrapper_passes_the_status_through_and_never_waits_for_eof() {
        let dir = std::env::temp_dir().join(format!("faceauth-anchor-wrap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let within = Duration::from_millis(1500);
        let cases = [
            ("locked", "printf '\\001'; exit 1", LockState::Locked),
            ("unlocked", "printf '\\000'; exit 0", LockState::Unlocked),
            ("unknown", "printf '\\002'; exit 2", LockState::Unknown),
            ("signal", "printf '\\001'; exit 255", LockState::Unknown),
            (
                "timeout result",
                "printf '\\000'; exit 1",
                LockState::Unknown,
            ),
            ("not started", "exit 1", LockState::Unknown),
            (
                "two bytes",
                "printf '\\001\\001'; exit 1",
                LockState::Unknown,
            ),
            (
                "pipe held open",
                "printf '\\001'; sleep 3 & exit 1",
                LockState::Locked,
            ),
        ];
        for (name, body, want) in cases {
            let fake = fake_systemd_run(&dir, &name.replace(' ', "-"), body);
            let t0 = std::time::Instant::now();
            let ran = run_anchor(anchor_command_with(&fake, 1000, "desktop"), within);
            let got = ran.map_or(LockState::Unknown, |(code, out)| answer_of(code, &out));
            assert_eq!(got, want, "{}", name);
            assert!(
                t0.elapsed() < Duration::from_millis(1000),
                "{}: {:?}",
                name,
                t0.elapsed()
            );
        }
        let fake = fake_systemd_run(&dir, "hangs", "printf '\\000'; exec sleep 30");
        let t0 = std::time::Instant::now();
        let got = run_anchor(
            anchor_command_with(&fake, 1000, "desktop"),
            Duration::from_millis(300),
        );
        assert_eq!(got, None, "no answer at the deadline");
        assert!(
            t0.elapsed() < Duration::from_millis(900),
            "{:?}",
            t0.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
