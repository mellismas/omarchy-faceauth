//! The fingerprint on the consent card and the lock screen (Mike's 10/12
//! ruling: the fingerprint is pulled into faceauth like the key, "so they
//! all ride together"). While the nods are armed (the scan and the nod
//! window), the daemon also asks the user's fingerprint, and a matching
//! finger approves the request as a key's touch does, under the key's own
//! guards (`ConsentState::fprint_matched`). It is the factor sudo's stock
//! line takes: pam_fprintd, through fprintd, against the prints
//! `sudo fprintd-enroll` stored.
//!
//! pam_fprintd runs outside the daemon, in a transient unit of its own per
//! check (`FPRINT_UNIT_PROPERTIES`), from a private stack the package ships
//! (`packaging/pam.d/faceauth-fprint`), the way the key's helper runs
//! pam_u2f. Unlike the key's, the check holds no device: fprintd owns the
//! reader and talks to it over USB, and the check is a client of fprintd
//! on the system bus. So the unit reaches the bus and nothing else. Its
//! exit status is the answer, and the words it writes as pam_fprintd talks
//! (`place`, `retry`) are the card's status line, nothing more.
//!
//! A stop is SIGTERM, which ends the check at once (pam_fprintd catches
//! only SIGINT, pam/pam_fprintd.c `do_verify`), and fprintd then cancels
//! the verify and closes the reader on its own, because its client's bus
//! name vanished (src/device.c, `_fprint_device_client_vanished`). So
//! unlike the key there is no cancel wrapper: stopping the unit frees the
//! reader.
//!
//! One long check per armed window, not one every two seconds: every
//! check claims the reader, and a claim opens the device, which can take
//! seconds. fprintd allows one claim per reader, so the daemon hands it
//! over through the key's own arbiter (`KeyLane::claim_reader`): the lock
//! screen comes before the card, and the card before any fallback line.
//! The lock screen's lane (`FprintLane::unlock`, pam_faceauth's
//! `fprint-unlock` line in `omarchy-lock-fingerprint`) latches the user as
//! the key's does (`ConsentState::begin_fprint_unlock`), so a finger while
//! locked can only unlock. With every lid shut nothing arms the reader:
//! a laptop's reader is under the lid, as Omarchy's own clamshell gate on
//! its fingerprint lines says.
//!
//! Not built here, with the seam for each: the polkit rule that keeps
//! fprintd to root while faceauth runs (decision 1: the unit would add it
//! under /run at start and remove it at stop; nothing here depends on it,
//! and `fprint.rule` in doctor waits for it); the fallback line that arms
//! the reader after a decline on sudo (decision 2: `FprintLane` would gain
//! a `fallback` as `KeyLane` has, and `ConsentState::arm_fprint` would
//! cancel it); and Omarchy's setup and removal for the fingerprint.

use super::key::{
    key_user_ok, root_only_file, trusted_stack, unit_escape, KeyLane, Unlocked, KEY, KEY_FINISH,
    KEY_PAM_DIR, KEY_POLL, KEY_SUPERVISE, UNLOCK_RECHECK,
};
use super::state::{ConsentState, FprintStatus};
use crate::lockgate::{Bind, LockState, Verdict};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The private stack the check runs, in the package's own directory beside
/// the key's (`KEY_PAM_DIR`), read with `pam_start_confdir` and never from
/// `/etc/pam.d`.
pub const FPRINT_SERVICE: &str = "faceauth-fprint";

/// The helper each check's unit runs.
const FPRINT_HELPER: &str = "/usr/lib/faceauth/faceauth-fprintcheck";

/// pam_fprintd, which the private stack names; fprintd's package ships it.
const PAM_FPRINTD: &str = "/usr/lib/security/pam_fprintd.so";

/// Where fprintd keeps its prints (`StateDirectory=fprint`): one directory
/// per user, root's alone, then the driver, the device and one file per
/// finger.
const FPRINT_STATE: &str = "/var/lib/fprint";

/// The stacks a pam_fprintd line in would read the reader outside the
/// daemon, as a pam_u2f line there reads the key (`KeyLane`'s rule).
const ELEVATION_STACKS: [&str; 2] = ["sudo", "polkit-1"];

/// The helper's exit status for a matching finger. Not 0, as the key's is
/// not: `systemd-run --wait` answers 0 for a unit that was stopped.
pub const FPRINT_MATCHED: u8 = 42;

/// The helper's exit status when the reader did not answer the check:
/// pam_fprintd's `PAM_AUTHINFO_UNAVAIL`, which it gives for a claim another
/// client holds, no reader, no prints, the reader gone mid-check and a try
/// that timed out. The key helper's busy answer has the same number.
pub const FPRINT_UNAVAILABLE: u8 = 3;

/// The stack's `max-tries=`: pam_fprintd's own default, the tries stock
/// Omarchy's sudo line gives a finger. Three wrong fingers end the check
/// with `PAM_MAXTRIES`, and the card's fingerprint with it for the window.
pub const FPRINT_TRIES: u32 = 3;

/// The stack's `timeout=`, per try: the card's whole armed window as
/// shipped, the scan (`consent_scan_seconds`, 20) and the nod window after
/// it (`consent_seconds`, 90), so one claim serves the window and the
/// reader is opened once per request, where pam_fprintd's own 30 s would
/// open it four times. A window made longer in the config gets a fresh
/// check when this one times out.
pub const FPRINT_TRY_SECONDS: u64 = 110;

/// The sandbox of each check's unit, as tight as the key's but for what
/// a client of fprintd needs: AF_UNIX alone, for the system bus at
/// /run/dbus/system_bus_socket (`sd_bus_open_system`), which stays in
/// reach; no device at all (`PrivateDevices=`, `DevicePolicy=closed`),
/// since fprintd owns the reader; and systemd's own sockets and udev's
/// control hidden, as for the key. Root with no capabilities can still ask
/// systemd for anything over the bus, which this sandbox cannot take away
/// without taking fprintd with it; what it keeps out of reach is the
/// daemon's store, config and sudoers. The bus is also how a result can
/// reach the check that fprintd never sent: pam_fprintd takes its verify
/// result from a `VerifyStatus` signal it matches by fprintd's well-known
/// name, sd-bus does not hold a signal addressed straight to the check to
/// the name's owner (systemd src/libsystemd/sd-bus/bus-match.c, the
/// sender match), and the system bus's default policy lets any connection
/// send any other a signal (/usr/share/dbus-1/system.conf). So on a stock
/// bus any program can hand a waiting pam_fprintd a match it never had,
/// this check and stock Omarchy's own pam_fprintd lines alike. The
/// package's bus policy (`packaging/system.d/faceauth-fprint.conf`, in
/// the mandatory context) lets fprintd's device signals reach a receiver
/// only from the connection that owns fprintd's name, which only root may
/// own, and the fingerprint is offered only while that file stands as
/// shipped (`bus_policy_state`). Root itself can still send the signal;
/// root needs no forgery. The runtime cap covers every try at its full
/// timeout.
pub(super) const FPRINT_UNIT_PROPERTIES: &[&str] = &[
    "RuntimeMaxSec=340s",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "PrivateNetwork=yes",
    "PrivateIPC=yes",
    "RestrictAddressFamilies=AF_UNIX",
    "IPAddressDeny=any",
    "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelLogs=yes",
    "ProtectControlGroups=yes",
    "ProtectClock=yes",
    "ProtectHostname=yes",
    "ProtectProc=invisible",
    "RestrictNamespaces=yes",
    "RestrictSUIDSGID=yes",
    "RestrictRealtime=yes",
    "LockPersonality=yes",
    "MemoryDenyWriteExecute=yes",
    "SystemCallArchitectures=native",
    "SystemCallFilter=@system-service",
    "SystemCallErrorNumber=EPERM",
    "PrivateDevices=yes",
    "DevicePolicy=closed",
    "InaccessiblePaths=-/var/lib/faceauth -/run/faceauth -/etc/faceauth -/etc/sudoers -/etc/sudoers.d -/run/systemd -/run/udev/control -/etc/fido2",
    // Root with no capability still owns these, as for the key: nothing
    // the check needs is there (fprintd reads the prints, not the check).
    "InaccessiblePaths=-/etc/shadow -/etc/gshadow -/etc/ssh -/boot -/efi -/var/lib -/var/log",
    "PrivatePIDs=yes",
    // SIGTERM ends pam_fprintd at once, and fprintd frees the reader when
    // the check's bus name goes; SIGKILL a second later for one that has
    // not ended.
    "KillSignal=SIGTERM",
    "TimeoutStopSec=1s",
    "SendSIGKILL=yes",
    "UMask=0077",
    "LimitCORE=0",
    "MemoryMax=64M",
    "TasksMax=8",
    // As the key's: stopped with the daemon's service, never rerun by it.
    "StopPropagatedFrom=faceauth.service",
];

/// The daemon's own bound on one check: the unit's `RuntimeMaxSec=` and a
/// margin, for a unit whose stop never came.
pub const FPRINT_DEADLINE: Duration = Duration::from_secs(345);

/// How soon a watch asks again after a check that never reached the
/// reader (another client holds it, or it is not there): long enough that
/// a reader held elsewhere is not asked twenty times a minute.
const FPRINT_BUSY_AGAIN: Duration = Duration::from_secs(5);

/// How soon a watch asks the lock question again when it found the
/// session other than unlocked, as the key's rearm does.
const FPRINT_RECHECK: Duration = Duration::from_secs(2);

/// The stop of every fingerprint check unit left from before the daemon
/// started, as `stale_checks_stop` does for the key's: a crash or an
/// upgrade can leave one holding the reader for minutes.
pub fn stale_fprint_checks_stop() -> std::process::Command {
    let mut c = std::process::Command::new("/usr/bin/timeout");
    c.args([
        "-k",
        "1",
        "5",
        "/usr/bin/systemctl",
        "stop",
        "--quiet",
        "faceauth-fprint-*.service",
    ])
    .env_clear()
    .env("PATH", "/usr/bin:/bin");
    c
}

/// Why the card or the lock screen does not offer the fingerprint.
#[derive(Clone, Debug, PartialEq)]
pub enum FprintOff {
    /// Nothing to offer: fprintd is not installed, or no finger enrolled.
    NotSetUp(String),
    /// A fingerprint is set up, but the daemon holds it back: a
    /// pam_fprintd line reads the reader outside it, or the check is not
    /// installed right.
    Withheld(String),
    /// The user's prints could not be counted: they are root's, so a
    /// caller that is not root (doctor run as the user) cannot read them.
    /// Not offered, as withheld is, and said as needing root.
    Unreadable(String),
}

impl std::fmt::Display for FprintOff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FprintOff::NotSetUp(why) | FprintOff::Withheld(why) | FprintOff::Unreadable(why) => {
                f.write_str(why)
            }
        }
    }
}

/// How one check ended.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FprintEnd {
    /// pam_fprintd matched a finger enrolled for the user.
    Matched,
    /// The tries ran out on fingers that did not match, or anything the
    /// helper did not answer as a match or the reader unavailable.
    NoMatch,
    /// The reader did not answer. `reached` when the check had got as far
    /// as asking for a finger (a try that timed out, the reader gone
    /// mid-check), so the next check may start at once; else the claim
    /// itself failed (held elsewhere, no reader) and the next waits
    /// `FPRINT_BUSY_AGAIN`.
    Unavailable { reached: bool },
}

/// The helper's exit status for pam_fprintd's answer (`rc`, None for a
/// transaction that never started): a match only for `PAM_SUCCESS`, the
/// reader unavailable for `PAM_AUTHINFO_UNAVAIL`, and no match for every
/// other answer, `PAM_MAXTRIES` and `PAM_AUTH_ERR` among them. The helper's
/// exit mirrors the key helper's: 42 for the factor, 3 for the device not
/// there, 1 for anything else.
pub fn fprint_exit_code(rc: Option<i32>) -> u8 {
    const PAM_SUCCESS: i32 = 0;
    const PAM_AUTHINFO_UNAVAIL: i32 = 9;
    match rc {
        Some(PAM_SUCCESS) => FPRINT_MATCHED,
        Some(PAM_AUTHINFO_UNAVAIL) => FPRINT_UNAVAILABLE,
        _ => 1,
    }
}

/// How the daemon reads the helper's exit status. Only `FPRINT_MATCHED`
/// is a match: a stop, a crash, a signal, `systemd-run` failing to start
/// the unit and every status it does not know end the window as no match,
/// so nothing fails over into a loop of fresh claims.
fn end_of_exit(code: Option<i32>, reached: bool) -> FprintEnd {
    match code {
        Some(c) if c == i32::from(FPRINT_MATCHED) => FprintEnd::Matched,
        Some(c) if c == i32::from(FPRINT_UNAVAILABLE) => FprintEnd::Unavailable { reached },
        _ => FprintEnd::NoMatch,
    }
}

/// The status a pam_fprintd message stands for, by its style alone, never
/// its text (which fprintd translates): an error message is a finger that
/// did not match or a scan to do again; an informational one is the
/// reader asking for a finger, which pam_fprintd sends only once its claim
/// landed and the verify started (`verify_finger_selected`), or the try's
/// timeout, after which the check ends at once.
pub fn status_of_message(style: i32) -> Option<FprintStatus> {
    const PAM_ERROR_MSG: i32 = 3;
    const PAM_TEXT_INFO: i32 = 4;
    match style {
        PAM_ERROR_MSG => Some(FprintStatus::Retry),
        PAM_TEXT_INFO => Some(FprintStatus::Place),
        _ => None,
    }
}

/// The status words the helper writes, one per line, read back as they
/// come. Only the exact words count; anything else, and a line past
/// `LINE_MAX` bytes, is dropped. The words only change the card's line.
#[derive(Default)]
struct StatusLines {
    buf: Vec<u8>,
    /// Bytes of an overlong line still being dropped.
    dropping: bool,
}

impl StatusLines {
    const LINE_MAX: usize = 16;

    fn feed(&mut self, bytes: &[u8]) -> Vec<FprintStatus> {
        let mut out = Vec::new();
        for &b in bytes {
            if b == b'\n' {
                if !self.dropping {
                    match self.buf.as_slice() {
                        b"place" => out.push(FprintStatus::Place),
                        b"retry" => out.push(FprintStatus::Retry),
                        _ => {}
                    }
                }
                self.buf.clear();
                self.dropping = false;
            } else if self.buf.len() >= Self::LINE_MAX {
                self.buf.clear();
                self.dropping = true;
            } else if !self.dropping {
                self.buf.push(b);
            }
        }
        out
    }
}

/// What the lane needs from the host: the daemon's is `SystemdFprint`, the
/// tests' a fake reader.
pub(super) trait FprintHost: Sync {
    /// Whether the fingerprint may be offered to `user`, or why not.
    fn offer(&self, user: &str) -> Result<(), FprintOff>;
    /// Start one check for `user`, on `lane` (`sudo`, `polkit`, `unlock`).
    fn start(&self, user: &str, lane: &str) -> std::io::Result<Box<dyn FprintRun>>;
    /// Whether every lid the firmware reports is shut.
    fn lid_closed(&self) -> bool;
}

/// One check under way.
pub(super) trait FprintRun: Send {
    /// What the check said since the last poll, and how it ended once it
    /// has.
    fn poll(&mut self) -> (Option<FprintStatus>, Option<FprintEnd>);
    /// End the check now; the reader is fprintd's to free when this
    /// returns.
    fn stop(&mut self);
}

/// The fingerprint through a transient unit per check.
struct SystemdFprint;

/// The unit name for `user`'s check on `lane`, for a name the key's check
/// takes too: the card's (`faceauth-fprint-card-<user>.service`) and the
/// lock screen's (`faceauth-fprint-unlock-<user>.service`) apart, so a stop
/// that failed on one, which leaves its name taken and the next start of
/// that name failing, never costs the other its check.
fn fprint_unit(user: &str, lane: &str) -> Option<String> {
    let which = if lane == "unlock" { "unlock" } else { "card" };
    key_user_ok(user).then(|| format!("faceauth-fprint-{}-{}.service", which, unit_escape(user)))
}

/// The `systemd-run` that runs one check of `user` on `lane` in `unit`.
/// `--pipe` hands the caller's pipe to the helper as its stdout, on which
/// it writes its status words, and `--wait` returns its exit status. A
/// unit of that name still there makes the start fail, as for the key.
fn fprint_command(unit: &str, lane: &str, user: &str) -> std::process::Command {
    use std::process::Stdio;
    let mut c = std::process::Command::new("/usr/bin/systemd-run");
    c.args([
        "--quiet",
        "--collect",
        "--wait",
        "--pipe",
        "--service-type=exec",
    ])
    .arg(format!("--unit={}", unit))
    .arg("--description=Omarchy FaceAuth fingerprint check")
    .args(
        FPRINT_UNIT_PROPERTIES
            .iter()
            .map(|p| format!("--property={}", p)),
    )
    .args([FPRINT_HELPER, lane, user])
    .env_clear()
    .env("PATH", "/usr/bin:/bin")
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::null());
    c
}

impl FprintHost for SystemdFprint {
    fn offer(&self, user: &str) -> Result<(), FprintOff> {
        fprint_offer(user)
    }

    fn start(&self, user: &str, lane: &str) -> std::io::Result<Box<dyn FprintRun>> {
        use std::os::fd::AsRawFd;
        let unit = fprint_unit(user, lane).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a user name")
        })?;
        let (mut child, pidfd) =
            crate::child::spawn_with_pidfd(&mut fprint_command(&unit, lane, user))?;
        let out = child.stdout.take();
        if let Some(out) = &out {
            // SAFETY: fcntl on the pipe's own open descriptor, setting a
            // flag; nothing else reads it.
            unsafe {
                let fl = libc::fcntl(out.as_raw_fd(), libc::F_GETFL);
                libc::fcntl(out.as_raw_fd(), libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
        }
        Ok(Box::new(UnitRun {
            unit,
            child,
            pidfd,
            out,
            lines: StatusLines::default(),
            reached: false,
        }))
    }

    fn lid_closed(&self) -> bool {
        crate::server::lid_closed()
    }
}

/// A check as `systemd-run --wait`, with the helper's status words on a
/// pipe read without blocking.
struct UnitRun {
    unit: String,
    child: std::process::Child,
    /// The child's own pidfd, the only way it is signalled
    /// (`crate::child`).
    pidfd: std::os::fd::OwnedFd,
    out: Option<std::process::ChildStdout>,
    lines: StatusLines,
    /// The helper has said anything at all: pam_fprintd got as far as
    /// asking for a finger.
    reached: bool,
}

impl FprintRun for UnitRun {
    fn poll(&mut self) -> (Option<FprintStatus>, Option<FprintEnd>) {
        use std::io::Read;
        let mut said = None;
        if let Some(out) = self.out.as_mut() {
            // At most a few short reads a poll: the words are a handful of
            // bytes, and a helper that writes more is not believed anyway.
            let mut buf = [0u8; 64];
            for _ in 0..4 {
                match out.read(&mut buf) {
                    Ok(0) => {
                        self.out = None;
                        break;
                    }
                    Ok(n) => {
                        if let Some(st) = self.lines.feed(&buf[..n]).pop() {
                            self.reached = true;
                            said = Some(st);
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        let end = match self.child.try_wait() {
            Ok(Some(status)) => Some(end_of_exit(status.code(), self.reached)),
            Ok(None) => None,
            Err(_) => Some(FprintEnd::NoMatch),
        };
        (said, end)
    }

    fn stop(&mut self) {
        let stopped = std::process::Command::new("/usr/bin/timeout")
            .args(["-k", "1", "3", "/usr/bin/systemctl", "stop", "--quiet"])
            .arg(&self.unit)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .status();
        if !stopped.is_ok_and(|s| s.success()) {
            log::warn!("consent: {} did not stop", self.unit);
        }
        crate::child::kill(&self.pidfd);
        let _ = self.child.wait();
    }
}

/// Whether `user` may be offered the fingerprint, from the files as they
/// stand; the reason when not. `faceauth doctor` reports the same answer.
pub fn fprint_offer(user: &str) -> Result<(), FprintOff> {
    offer_from(&OfferFacts {
        user,
        pam_fprintd: Path::new(PAM_FPRINTD).exists(),
        prints: prints_of(Path::new(FPRINT_STATE), user),
        reached: fprintd_reached(Path::new(PAM_DIR), &ELEVATION_STACKS),
        installed: trusted_stack(Path::new(KEY_PAM_DIR), FPRINT_SERVICE).is_some()
            && root_only_file(Path::new(FPRINT_HELPER)),
        bus_policy: bus_policy_state(Path::new(BUS_POLICY_DIR)),
    })
}

/// The PAM directory the elevation stacks and what they include are read
/// from.
const PAM_DIR: &str = "/etc/pam.d";

/// Where the package's bus policy goes.
const BUS_POLICY_DIR: &str = "/usr/share/dbus-1/system.d";

/// The package's bus policy's name there.
pub const BUS_POLICY_NAME: &str = "faceauth-fprint.conf";

/// The bus policy as the package ships it.
pub const BUS_POLICY_TEXT: &str = include_str!("../../../packaging/system.d/faceauth-fprint.conf");

/// Whether the package's bus policy (`BUS_POLICY_TEXT`) stands in `dir` as
/// shipped, or why not: there, a regular file in a tree only root could
/// have written (`trusted_stack`, as for the private PAM stacks), with the
/// shipped text. Without it pam_fprintd takes a forged verify result from
/// any connection on the bus (see `FPRINT_UNIT_PROPERTIES`), so the
/// fingerprint is offered nowhere. A file in place is not proof the bus
/// has read it: pacman's dbus-reload hook reloads the bus when a package
/// installs one there, and a bus started since reads it at start.
pub fn bus_policy_state(dir: &Path) -> Result<(), String> {
    let path = dir.join(BUS_POLICY_NAME);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(format!(
            "the bus policy that keeps fprintd's device signals to fprintd is not installed ({})",
            path.display()
        ))
        }
        Err(e) => return Err(format!("{} cannot be read: {}", path.display(), e)),
        Ok(_) => {}
    }
    let Some(dir) = trusted_stack(dir, BUS_POLICY_NAME) else {
        return Err(format!(
            "the bus policy {} is not root's alone, so it does not count",
            path.display()
        ));
    };
    match std::fs::read_to_string(dir.join(BUS_POLICY_NAME)) {
        Ok(text) if text == BUS_POLICY_TEXT => Ok(()),
        Ok(_) => Err(format!(
            "the bus policy {} is not the one this faceauth ships",
            path.display()
        )),
        Err(e) => Err(format!("{} cannot be read: {}", path.display(), e)),
    }
}

/// How deep `fprintd_reached` follows includes, and how many files it
/// reads in all: Arch's stacks nest two deep (sudo, system-auth).
const INCLUDE_DEPTH: usize = 8;
const INCLUDE_FILES: usize = 32;

/// The most of one PAM file `fprintd_reached` reads.
const PAM_FILE_MAX: u64 = 64 * 1024;

/// The files with an active pam_fprintd line that the `stacks` in `dir`
/// reach, through their `include` and `substack` lines (with a `-type`
/// too) and `@include` lines, or why they could not be followed: an
/// included name that is not a plain file name in `dir` (a `/`, a leading
/// dot, none at all), one that is not there, nesting past `INCLUDE_DEPTH`,
/// or more than `INCLUDE_FILES` files. Anything that cannot be followed
/// counts against the offer, since what it would include is unknown. A
/// top stack that is not there has no lines (polkit's vendor stack in
/// /usr/lib/pam.d includes system-auth, which sudo's walk reads anyway).
pub fn fprintd_reached(dir: &Path, stacks: &[&str]) -> Result<Vec<String>, String> {
    let mut found = Vec::new();
    let mut seen = Vec::new();
    for name in stacks {
        if let Some(text) = read_pam_file(&dir.join(name))? {
            walk_stack(dir, name, &text, 0, &mut seen, &mut found)?;
        }
    }
    Ok(found)
}

/// One stack of `fprintd_reached`'s walk, `depth` includes down.
fn walk_stack(
    dir: &Path,
    name: &str,
    text: &str,
    depth: usize,
    seen: &mut Vec<String>,
    found: &mut Vec<String>,
) -> Result<(), String> {
    if seen.iter().any(|n| n == name) {
        return Ok(());
    }
    seen.push(name.to_string());
    if seen.len() > INCLUDE_FILES {
        return Err(format!(
            "the stacks sudo and polkit-1 include are more than {} files, so they were not all read",
            INCLUDE_FILES
        ));
    }
    let path = dir.join(name);
    if fprintd_lines(text).next().is_some() {
        found.push(path.display().to_string());
    }
    for target in included_names(text) {
        let target = target.map_err(|why| format!("{} {}", path.display(), why))?;
        if depth + 1 > INCLUDE_DEPTH {
            return Err(format!(
                "{} includes stacks nested deeper than {}, which were not all read",
                path.display(),
                INCLUDE_DEPTH
            ));
        }
        let Some(inner) = read_pam_file(&dir.join(target))? else {
            return Err(format!(
                "{} includes {}, which is not in {}, so what it reads is unknown",
                path.display(),
                target,
                dir.display()
            ));
        };
        walk_stack(dir, target, &inner, depth + 1, seen, found)?;
    }
    Ok(())
}

/// The names a PAM file's active lines include, each checked to be a
/// plain file name in the directory, or what is wrong with it.
fn included_names(text: &str) -> Vec<Result<&str, &'static str>> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .filter_map(|l| {
            let w: Vec<&str> = l.split_whitespace().collect();
            let target = match w.as_slice() {
                ["@include", rest @ ..] => rest.first().copied(),
                [_, "include" | "substack", rest @ ..] => rest.first().copied(),
                _ => return None,
            };
            Some(match target {
                None | Some("") => Err("has an include with no name"),
                Some(t) if t.contains('/') || t.starts_with('.') => {
                    Err("includes a name outside its own directory")
                }
                Some(t) => Ok(t),
            })
        })
        .collect()
}

/// A PAM file's text, up to `PAM_FILE_MAX`; None when it is not there.
fn read_pam_file(path: &Path) -> Result<Option<String>, String> {
    use std::io::Read;
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{} cannot be read: {}", path.display(), e)),
    };
    let mut text = String::new();
    f.take(PAM_FILE_MAX)
        .read_to_string(&mut text)
        .map_err(|e| format!("{} cannot be read: {}", path.display(), e))?;
    Ok(Some(text))
}

/// What the offer is decided from.
struct OfferFacts<'a> {
    user: &'a str,
    /// pam_fprintd is installed (fprintd's package).
    pam_fprintd: bool,
    /// The user's enrolled prints, or why they could not be counted.
    prints: Result<usize, String>,
    /// The files with a pam_fprintd line that sudo's and polkit's stacks
    /// reach, or why the stacks could not be followed.
    reached: Result<Vec<String>, String>,
    /// The private stack and the helper are root's and closed to others.
    installed: bool,
    /// The package's bus policy stands as shipped, or why not.
    bus_policy: Result<(), String>,
}

/// The offer from the facts: a name the check takes, fprintd installed, no
/// pam_fprintd line that sudo's or polkit's stack reaches (through what it
/// includes too), the check installed right, the bus policy as shipped,
/// and a finger enrolled for the user. A pam_fprintd line those stacks
/// reach takes the reader outside the daemon, and a finger meant for the
/// lock screen could then approve a request hidden behind it, so with one
/// there no lane offers the fingerprint at all, as a pam_u2f line keeps the
/// key off (`KeyLane`'s `lane_policy`).
fn offer_from(f: &OfferFacts<'_>) -> Result<(), FprintOff> {
    if !key_user_ok(f.user) {
        return Err(FprintOff::Withheld(format!(
            "{} is not a name the fingerprint check takes",
            f.user
        )));
    }
    if !f.pam_fprintd {
        return Err(FprintOff::NotSetUp(format!(
            "fprintd is not installed ({} is missing)",
            PAM_FPRINTD
        )));
    }
    match &f.reached {
        Ok(files) => {
            if let Some(path) = files.first() {
                return Err(FprintOff::Withheld(format!(
                    "a pam_fprintd line in {}, which sudo's or polkit's stack reaches, reads the reader outside faceauthd",
                    path
                )));
            }
        }
        Err(why) => return Err(FprintOff::Withheld(why.clone())),
    }
    if !f.installed {
        return Err(FprintOff::Withheld(format!(
            "the fingerprint check is not installed root-owned: {}/{} and {}",
            KEY_PAM_DIR, FPRINT_SERVICE, FPRINT_HELPER
        )));
    }
    if let Err(why) = &f.bus_policy {
        return Err(FprintOff::Withheld(why.clone()));
    }
    // The prints last: a caller that is not root cannot read them, and
    // everything above is still worth saying to it.
    match &f.prints {
        Ok(0) => Err(FprintOff::NotSetUp(format!(
            "no fingerprint enrolled for {} in {}",
            f.user, FPRINT_STATE
        ))),
        Ok(_) => Ok(()),
        Err(why) => Err(FprintOff::Unreadable(why.clone())),
    }
}

/// The active pam_fprintd lines of a PAM file, with any comment cut.
pub fn fprintd_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| l.contains("pam_fprintd.so"))
}

/// How many prints fprintd keeps for `user` under `state`: the files three
/// levels down (driver, device, finger), at most `CAP` entries a level so
/// a strange tree costs little. A user with no directory has none; a
/// directory that cannot be read is a reason, not a count.
pub fn prints_of(state: &Path, user: &str) -> Result<usize, String> {
    const CAP: usize = 64;
    let dir = state.join(user);
    let entries = |d: &Path| -> Result<Vec<PathBuf>, std::io::Error> {
        Ok(std::fs::read_dir(d)?
            .flatten()
            .take(CAP)
            .map(|e| e.path())
            .collect())
    };
    let drivers = match entries(&dir) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(format!("{} cannot be read: {}", dir.display(), e)),
    };
    let mut prints = 0;
    for driver in drivers.iter().filter(|p| p.is_dir()) {
        for device in entries(driver).unwrap_or_default() {
            prints += entries(&device)
                .unwrap_or_default()
                .iter()
                .filter(|p| p.is_file())
                .count();
        }
    }
    Ok(prints)
}

/// One check, as the helper runs it: pam_fprintd for `user` through the
/// private stack, from the canonical path the trust check vouched for,
/// each of its messages handed to `said` as a status, and pam_fprintd's
/// answer as the helper's exit status (`fprint_exit_code`).
pub fn fprint_check(user: &str, said: &mut dyn FnMut(FprintStatus)) -> u8 {
    let Some(dir) = trusted_stack(Path::new(KEY_PAM_DIR), FPRINT_SERVICE)
        .and_then(|d| d.to_str().map(str::to_string))
    else {
        return 1;
    };
    let rc = crate::pamcheck::check_fprint(FPRINT_SERVICE, user, &dir, &mut |style| {
        if let Some(st) = status_of_message(style) {
            said(st);
        }
    });
    fprint_exit_code(rc)
}

/// The daemon's fingerprint checks: the host, the key's lane (its arbiter
/// for the reader, its shared lock answers and its verdict), the daemon's
/// own deadline on a check and the wait after a reader that did not
/// answer.
pub struct FprintLane {
    keys: &'static KeyLane,
    host: &'static dyn FprintHost,
    deadline: Duration,
    busy_again: Duration,
}

pub static FPRINT: FprintLane = FprintLane {
    keys: &KEY,
    host: &SystemdFprint,
    deadline: FPRINT_DEADLINE,
    busy_again: FPRINT_BUSY_AGAIN,
};

/// Ends a fingerprint unlock's ask in the record however the unlock ends.
struct Asking<'a> {
    state: &'a ConsentState,
    user: &'a str,
}

impl Drop for Asking<'_> {
    fn drop(&mut self) {
        self.state.end_fprint_unlock(self.user);
    }
}

/// The fingerprint watch of one scan and nod window of one request, as
/// `KeyWatch` is the key's: dropping it marks the record and sets the
/// flag the thread reads, and `finish` also waits for the check to stop.
pub struct FprintWatch {
    state: &'static ConsentState,
    user: String,
    token: String,
    generation: u64,
    stop: Arc<AtomicBool>,
    done: Option<std::sync::mpsc::Receiver<()>>,
}

impl FprintWatch {
    /// End the watch and wait, up to `KEY_FINISH`, until its thread has
    /// stopped any check under way, so the reader is free before the
    /// request's answer goes back to PAM.
    pub fn finish(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.state
            .disarm_fprint(&self.user, &self.token, self.generation);
        if let Some(done) = self.done.take() {
            if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = done.recv_timeout(KEY_FINISH) {
                log::warn!(
                    "consent: the fingerprint check for {} did not end in time",
                    self.user
                );
            }
        }
    }
}

impl Drop for FprintWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.state
            .disarm_fprint(&self.user, &self.token, self.generation);
    }
}

/// What one watch's thread works on.
struct Watched<'a> {
    state: &'a ConsentState,
    user: &'a str,
    token: &'a str,
    lane: &'a str,
    generation: u64,
    stop: &'a AtomicBool,
    bind: &'a Bind,
}

impl FprintLane {
    /// A lane on `keys` and `host`: a test's.
    #[cfg(test)]
    const fn new(
        keys: &'static KeyLane,
        host: &'static dyn FprintHost,
        deadline: Duration,
        busy_again: Duration,
    ) -> Self {
        FprintLane {
            keys,
            host,
            deadline,
            busy_again,
        }
    }

    /// Whether the lock screen's fingerprint lane is there for `user`, and
    /// why not (the `fprint_lane` reply). The lid does not take the lane
    /// away: it only keeps the reader from being asked.
    pub fn unlock_offer(&self, user: &str) -> Result<(), FprintOff> {
        self.host.offer(user)
    }

    /// Arm the fingerprint for `user`'s live request named by `token`, on
    /// `lane`: a new generation in the record, which the card's next
    /// payload carries, and a thread that runs the checks. None, with
    /// nothing armed, when every lid is shut, the fingerprint is not
    /// offered, the request is not live, or no thread could start.
    pub fn arm(
        &'static self,
        state: &'static ConsentState,
        user: &str,
        token: &str,
        lane: &str,
        bind: &Bind,
    ) -> Option<FprintWatch> {
        // Only the lanes the helper takes, as the key arms only lanes it
        // has a stack for (`lane_stack`): a card for another requester
        // would show the fingerprint, then lose it to a helper that
        // refuses the lane.
        if !matches!(lane, "sudo" | "polkit") {
            log::debug!(
                "consent: fingerprint not armed for {}: no fingerprint on the {} lane",
                user,
                lane
            );
            return None;
        }
        if self.host.lid_closed() {
            log::debug!(
                "consent: fingerprint not armed for {}: the lid is shut",
                user
            );
            return None;
        }
        if let Err(why) = self.host.offer(user) {
            log::debug!("consent: fingerprint not offered to {}: {}", user, why);
            return None;
        }
        let generation = state.arm_fprint(user, token)?;
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let mut watch = FprintWatch {
            state,
            user: user.to_string(),
            token: token.to_string(),
            generation,
            stop: Arc::new(AtomicBool::new(false)),
            done: Some(rx),
        };
        let (u, t, l, stop, b) = (
            watch.user.clone(),
            watch.token.clone(),
            lane.to_string(),
            Arc::clone(&watch.stop),
            bind.clone(),
        );
        let spawned = std::thread::Builder::new()
            .name("faceauth-fprint".into())
            .spawn(move || {
                let _done = tx;
                self.watch(&Watched {
                    state,
                    user: &u,
                    token: &t,
                    lane: &l,
                    generation,
                    stop: &stop,
                    bind: &b,
                })
            });
        match spawned {
            Ok(_) => {
                log::debug!("consent: fingerprint armed for {} ({})", user, generation);
                Some(watch)
            }
            Err(e) => {
                log::warn!("consent: no thread for the fingerprint check: {}", e);
                watch.done = None;
                None
            }
        }
    }

    /// The watch's thread. A check starts whenever the record allows one
    /// for this generation, the one verdict says unlocked, the request's
    /// session is in front and the reader is free, and it runs as long as
    /// the window does. After a match that counted the watch ends; after
    /// the tries ran out it ends too and the card's fingerprint goes off
    /// for the window; after a try that timed out the next check starts at
    /// once; after a claim that never reached the reader the card says the
    /// reader is busy and the next waits `busy_again`.
    fn watch(&self, w: &Watched<'_>) {
        let mut not_before: Option<Instant> = None;
        while !w.stop.load(Ordering::SeqCst) {
            let now = Instant::now();
            if not_before.is_some_and(|t| now < t) {
                std::thread::sleep(KEY_POLL);
                continue;
            }
            // The record first, which a dwell or a latch holds; the lock
            // question, which reads the compositor and logind, only when a
            // check could start, and at most every `FPRINT_RECHECK` while
            // it reads anything but unlocked, as the key's rearm does.
            if !w.state.fprint_may_check(w.user, w.token, w.generation, now) {
                std::thread::sleep(KEY_POLL);
                continue;
            }
            self.keys.refresh_priority(w.state);
            if self.keys.verdict(w.state, w.user, w.bind) != Verdict::Unlocked
                || !self.keys.request_in_front(w.state, w.user, w.bind)
            {
                not_before = Some(now + FPRINT_RECHECK);
                continue;
            }
            let Some(running) = self.keys.claim_reader(w.user, false) else {
                // The lock screen's check, or one still stopping, holds the
                // reader: asked again shortly.
                std::thread::sleep(KEY_POLL);
                continue;
            };
            let end = self.run_one(w, now);
            drop(running);
            match end {
                Some(FprintEnd::Matched) => {
                    if self.matched(w, now) {
                        return;
                    }
                    not_before = Some(Instant::now() + FPRINT_RECHECK);
                }
                Some(FprintEnd::NoMatch) => {
                    log::info!(
                        "consent: no fingerprint match for {} in {} tries; the card's fingerprint is off for this window",
                        w.user,
                        FPRINT_TRIES
                    );
                    w.state.fprint_spent(w.user, w.token, w.generation);
                    return;
                }
                Some(FprintEnd::Unavailable { reached: true }) => {
                    w.state
                        .fprint_status(w.user, w.token, w.generation, FprintStatus::Place);
                }
                Some(FprintEnd::Unavailable { reached: false }) => {
                    w.state
                        .fprint_status(w.user, w.token, w.generation, FprintStatus::Busy);
                    not_before = Some(Instant::now() + self.busy_again);
                }
                None => {}
            }
        }
    }

    /// One check that started at `started`, supervised: its status words
    /// go to the record, and it is stopped the moment the watch ends, the
    /// record no longer allows it (the round waits or parks, the lock
    /// screen took the reader, the card was re-shown), the request's
    /// session leaves the foreground, or the daemon's deadline passes; None
    /// then. A "no match" stays on the card for the rest of the check,
    /// though pam_fprintd asks for the next try at once.
    fn run_one(&self, w: &Watched<'_>, started: Instant) -> Option<FprintEnd> {
        let mut run = match self.host.start(w.user, w.lane) {
            Ok(run) => run,
            Err(e) => {
                log::warn!(
                    "consent: the fingerprint check for {} did not start: {}",
                    w.user,
                    e
                );
                return Some(FprintEnd::Unavailable { reached: false });
            }
        };
        let mut missed = false;
        loop {
            let (said, end) = run.poll();
            if let Some(st) = said {
                missed |= st == FprintStatus::Retry;
                let shown = if missed { FprintStatus::Retry } else { st };
                w.state.fprint_status(w.user, w.token, w.generation, shown);
            }
            if let Some(end) = end {
                return Some(end);
            }
            let late = started.elapsed() > self.deadline;
            if late
                || w.stop.load(Ordering::SeqCst)
                || !w
                    .state
                    .fprint_may_check(w.user, w.token, w.generation, started)
                || !self.keys.request_in_front(w.state, w.user, w.bind)
            {
                if late {
                    log::warn!(
                        "consent: the fingerprint check for {} ran past its deadline",
                        w.user
                    );
                }
                run.stop();
                return None;
            }
            std::thread::sleep(KEY_SUPERVISE);
        }
    }

    /// A match the helper reported, written to the record if it still
    /// counts there, under the key's commit.
    fn matched(&self, w: &Watched<'_>, started: Instant) -> bool {
        if w.stop.load(Ordering::SeqCst) {
            log::info!(
                "consent: a fingerprint match for {} came as its watch ended; it answers nothing",
                w.user
            );
            return false;
        }
        if !self.keys.request_in_front(w.state, w.user, w.bind) {
            log::info!(
                "consent: a fingerprint match for {} came with its session in the background; it answers nothing",
                w.user
            );
            return false;
        }
        let counted = w.state.fprint_matched(
            w.user,
            w.token,
            w.generation,
            started,
            &|| self.keys.look(w.user, w.bind),
            &|| self.keys.request_in_front(w.state, w.user, w.bind),
        );
        if counted {
            log::info!("consent: fingerprint matched for {}", w.user);
        } else {
            log::info!(
                "consent: a fingerprint match for {} came after its card; it answers nothing",
                w.user
            );
        }
        counted
    }

    /// The lock screen's fingerprint: one check of `user`'s finger while
    /// the session is locked, the lock screen asking, exactly as the key's
    /// unlock (`KeyLane::unlock`): the session in front, the ask latching
    /// the user and taking the card off the key and the reader in one step,
    /// a fresh anchored look that finds the session locked, the shared
    /// priority started from it, and the reader handed over from a card's
    /// check still stopping. `said` gets each status the check reports, for
    /// the lock screen's conversation. The check is stopped at once when
    /// the lock screen stops asking (`gone`), when the session leaves the
    /// foreground, within `UNLOCK_RECHECK` of the session unlocking, and at
    /// the daemon's deadline. A match unlocks only; it never answers a card.
    pub fn unlock(
        &self,
        state: &ConsentState,
        user: &str,
        bind: &Bind,
        gone: &dyn Fn() -> bool,
        said: &dyn Fn(FprintStatus),
    ) -> Unlocked {
        let no = |why: &str, hung_up: bool| Unlocked::No {
            why: why.to_string(),
            hung_up,
        };
        if self.host.lid_closed() {
            return no("the lid is shut", false);
        }
        let Some(uid) = self.keys.uid_of(user) else {
            return no("the user is unknown", false);
        };
        if !state.unlock_session_in_front(uid, bind) {
            return no("the session is not in the foreground", false);
        }
        if !state.begin_fprint_unlock(user) {
            return no(
                "a fingerprint unlock of this user's is already asked",
                false,
            );
        }
        let asking = Asking { state, user };
        if let Err(why) = self.host.offer(user) {
            return no(&why.to_string(), false);
        }
        if self.keys.compositor_fresh(user, bind) != LockState::Locked {
            return no("the session is not locked", false);
        }
        if !state.start_priority(user, uid, bind) {
            return no("the session is not in the foreground", false);
        }
        let Some(running) = self.keys.claim_reader_within(user, true, &|| !gone()) else {
            return no("a check for the card did not stop in time", gone());
        };
        let started = Instant::now();
        let mut run = match self.host.start(user, "unlock") {
            Ok(run) => run,
            Err(e) => {
                return no(
                    &format!("the fingerprint check did not start: {}", e),
                    false,
                )
            }
        };
        let (why, hung_up, seen, end) = std::thread::scope(|scope| {
            let mut look: Option<std::thread::ScopedJoinHandle<'_, LockState>> = None;
            let mut looked = started;
            let ended = loop {
                let (st, end) = run.poll();
                if let Some(st) = st {
                    said(st);
                }
                if let Some(end) = end {
                    break ("", false, None, Some(end));
                }
                if gone() {
                    break ("the lock screen stopped asking", true, None, None);
                }
                if !state.holds_priority(user) {
                    break (
                        "the session is no longer in the foreground",
                        false,
                        None,
                        None,
                    );
                }
                if started.elapsed() > self.deadline {
                    break (
                        "the fingerprint check ran past its deadline",
                        false,
                        None,
                        None,
                    );
                }
                match look.take() {
                    Some(h) if h.is_finished() => {
                        let st = h.join().unwrap_or(LockState::Unknown);
                        if st != LockState::Locked {
                            break ("the session unlocked", false, Some(st), None);
                        }
                    }
                    Some(h) => look = Some(h),
                    None if looked.elapsed() >= UNLOCK_RECHECK => {
                        looked = Instant::now();
                        look = Some(scope.spawn(|| self.keys.compositor_polled(user, bind)));
                    }
                    None => {}
                }
                std::thread::sleep(KEY_SUPERVISE);
            };
            if ended.3.is_none() {
                run.stop();
            }
            ended
        });
        drop(running);
        if let Some(end) = end {
            return match end {
                // A match counts only while the session is still the one in
                // front, as a touch does.
                FprintEnd::Matched if state.holds_priority(user) => Unlocked::Touched,
                FprintEnd::Matched => no("the session is no longer in the foreground", false),
                FprintEnd::NoMatch => no("no fingerprint matched", false),
                FprintEnd::Unavailable { reached: true } => {
                    no("the fingerprint check timed out", false)
                }
                FprintEnd::Unavailable { reached: false } => {
                    no("the fingerprint reader did not answer", false)
                }
            };
        }
        drop(asking);
        if let Some(st) = seen {
            let _ = state.judge(user, st, self.keys.desktop());
        }
        no(why, hung_up)
    }
}

/// Write the check's status to the lock screen's waiting line, as
/// `{"result":"fprint_status","status":WORD}`, without blocking and without
/// a signal, as the beat is written; the module turns it into a message on
/// the lock screen's conversation. A full socket buffer skips it.
pub(crate) fn send_fprint_status(fd: &impl std::os::fd::AsRawFd, status: FprintStatus) {
    let line = format!(
        "{{\"result\":\"fprint_status\",\"status\":\"{}\"}}\n",
        status.word()
    );
    // SAFETY: `fd` is an open socket for the call; the buffer and its
    // length are a valid slice; MSG_DONTWAIT and MSG_NOSIGNAL make the
    // call neither block nor raise SIGPIPE.
    let _ = unsafe {
        libc::send(
            fd.as_raw_fd(),
            line.as_ptr().cast(),
            line.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::consent::key::{KeyHost, KeyOff, KeyPolicy, KeyRun};
    use crate::consent::state::{test_state, Answer, Secret};
    use crate::consent::window::{Dialog, ACK_DWELL};
    use crate::lockgate::Desktop;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Mutex;

    /// The lock answers and uids the key's lane gives the fingerprint's:
    /// the compositor locked or not, as the test says. No key is offered.
    struct Looks {
        locked: AtomicBool,
    }

    impl KeyHost for Looks {
        fn offer(&self, _user: &str, _lane: &str) -> Result<KeyPolicy, KeyOff> {
            Err(KeyOff::NotSetUp("no key in this test".into()))
        }
        fn start(
            &self,
            _user: &str,
            _lane: &str,
            _pin: Option<Secret>,
        ) -> std::io::Result<Box<dyn KeyRun>> {
            Err(std::io::Error::other("no key in this test"))
        }
        fn lock_state(&self, _user: &str, _bind: &Bind) -> LockState {
            if self.locked.load(Ordering::SeqCst) {
                LockState::Locked
            } else {
                LockState::Unlocked
            }
        }
        fn desktop(&self) -> Desktop {
            Desktop::Some
        }
        fn uid_of(&self, user: &str) -> Option<u32> {
            Some(300_000 + user.bytes().map(u32::from).sum::<u32>())
        }
    }

    /// One check the fake reader started: what the test makes it say and
    /// how it ends, and whether it was stopped.
    #[derive(Default)]
    struct Script {
        said: Option<FprintStatus>,
        end: Option<FprintEnd>,
        stopped: bool,
        lane: String,
    }

    struct FakeRun {
        reader: &'static Reader,
        script: Arc<Mutex<Script>>,
    }

    impl FprintRun for FakeRun {
        fn poll(&mut self) -> (Option<FprintStatus>, Option<FprintEnd>) {
            let mut s = self.script.lock().unwrap();
            (s.said.take(), s.end.take())
        }
        fn stop(&mut self) {
            self.script.lock().unwrap().stopped = true;
        }
    }

    impl Drop for FakeRun {
        fn drop(&mut self) {
            self.reader.running.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// A reader whose checks the test answers, with a lid.
    struct Reader {
        offer: Result<(), FprintOff>,
        lid: AtomicBool,
        runs: Mutex<Vec<Arc<Mutex<Script>>>>,
        running: AtomicUsize,
        most_running: AtomicUsize,
    }

    impl FprintHost for Reader {
        fn offer(&self, _user: &str) -> Result<(), FprintOff> {
            self.offer.clone()
        }
        fn start(&self, _user: &str, lane: &str) -> std::io::Result<Box<dyn FprintRun>> {
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.most_running.fetch_max(now, Ordering::SeqCst);
            let script = Arc::new(Mutex::new(Script {
                lane: lane.to_string(),
                ..Script::default()
            }));
            self.runs.lock().unwrap().push(Arc::clone(&script));
            // SAFETY: every reader is leaked by `Reader::new`, so it lives
            // as long as the test binary.
            let reader: &'static Reader = unsafe { &*(self as *const Reader) };
            Ok(Box::new(FakeRun { reader, script }))
        }
        fn lid_closed(&self) -> bool {
            self.lid.load(Ordering::SeqCst)
        }
    }

    impl Reader {
        fn new(offer: Result<(), FprintOff>) -> &'static Reader {
            Box::leak(Box::new(Reader {
                offer,
                lid: AtomicBool::new(false),
                runs: Mutex::new(Vec::new()),
                running: AtomicUsize::new(0),
                most_running: AtomicUsize::new(0),
            }))
        }
        fn checks(&self) -> usize {
            self.runs.lock().unwrap().len()
        }
        fn running(&self) -> usize {
            self.running.load(Ordering::SeqCst)
        }
        fn run(&self, n: usize) -> Arc<Mutex<Script>> {
            Arc::clone(&self.runs.lock().unwrap()[n])
        }
        /// Check `n` (from 0) says `st`.
        fn say(&self, n: usize, st: FprintStatus) {
            self.run(n).lock().unwrap().said = Some(st);
        }
        /// Check `n` ends with `end`.
        fn end(&self, n: usize, end: FprintEnd) {
            self.run(n).lock().unwrap().end = Some(end);
        }
        fn stopped(&self, n: usize) -> bool {
            self.run(n).lock().unwrap().stopped
        }
    }

    const SHORT: Duration = Duration::from_millis(50);
    const LONG: Duration = Duration::from_secs(60);

    /// A lane on a fresh key lane and `reader`, with the session locked
    /// when `looks` says so.
    fn lane(
        reader: &'static Reader,
        busy_again: Duration,
    ) -> (&'static FprintLane, &'static Looks) {
        let looks: &'static Looks = Box::leak(Box::new(Looks {
            locked: AtomicBool::new(false),
        }));
        let keys: &'static KeyLane = Box::leak(Box::new(KeyLane::new(looks, SHORT, LONG)));
        let lane = Box::leak(Box::new(FprintLane::new(keys, reader, LONG, busy_again)));
        (lane, looks)
    }

    fn eventually(cond: impl Fn() -> bool) -> bool {
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        cond()
    }

    /// A card up for `user`'s live request, acknowledged a dwell ago.
    fn card(st: &'static ConsentState, user: &str) -> (Dialog, String) {
        let d = Dialog::new(&Config::default(), user, st).unwrap();
        let token = d.token().to_string();
        assert!(st.ack(user, Some(&token)));
        st.backdate_ack(user, ACK_DWELL);
        (d, token)
    }

    fn unlocked_look() -> (LockState, Desktop) {
        (LockState::Unlocked, Desktop::Some)
    }

    /// The fingerprint wins: a matching finger at the card's request
    /// approves it as its own answer, not the key's, the card is told the
    /// fingerprint works while the watch runs, and once the finger counted
    /// the reader is asked no more.
    #[test]
    fn a_finger_approves_the_request_it_was_armed_on() {
        let user = "faceauth-fprint-win-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let reader = Reader::new(Ok(()));
        let (lane, _) = lane(reader, SHORT);
        let watch = lane
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .expect("an offered fingerprint arms");
        let card = st.fprint_for_payload(user, &tok);
        assert!(card.armed, "the card is told the fingerprint works");
        assert_eq!(card.status, FprintStatus::Place);
        assert!(
            eventually(|| reader.checks() == 1),
            "the watch asks the reader"
        );
        assert_eq!(reader.run(0).lock().unwrap().lane, "sudo");
        assert!(!st.answered(user));
        reader.end(0, FprintEnd::Matched);
        assert!(eventually(|| st.answered(user)));
        assert!(matches!(st.poll(user), Some(Answer::Fingerprint)));
        std::thread::sleep(SHORT * 4);
        assert_eq!(reader.checks(), 1, "a match that counted ends the checks");
        drop(watch);
        assert!(!st.fprint_for_payload(user, &tok).armed);
    }

    /// One long check per armed window: while a check waits for a finger
    /// no second one starts, however long it waits (the key re-arms every
    /// two seconds; every fingerprint check claims and opens the reader).
    #[test]
    fn one_check_serves_the_whole_window() {
        let user = "faceauth-fprint-long-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let reader = Reader::new(Ok(()));
        let (lane, _) = lane(reader, SHORT);
        let _watch = lane
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(eventually(|| reader.running() == 1));
        std::thread::sleep(SHORT * 10);
        assert_eq!(reader.checks(), 1, "no rearm while the check waits");
        assert!(!reader.stopped(0));
    }

    /// No check starts until the dwell has passed since the card's
    /// acknowledgment, and a check older than the latest acknowledgment's
    /// dwell counts for nothing, as for the key.
    #[test]
    fn the_fingerprint_waits_out_the_dwell_after_the_acknowledgment() {
        let user = "faceauth-fprint-dwell-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let d = Dialog::new(&Config::default(), user, st).unwrap();
        let tok = d.token().to_string();
        assert!(st.ack(user, Some(&tok)));
        let reader = Reader::new(Ok(()));
        let (lane, _) = lane(reader, SHORT);
        let _watch = lane
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        std::thread::sleep(SHORT * 4);
        assert_eq!(reader.checks(), 0, "no check inside the dwell");
        st.backdate_ack(user, ACK_DWELL);
        assert!(eventually(|| reader.checks() == 1));
        let g = st.fprint_armed_now(user).unwrap();
        let before = Instant::now() - ACK_DWELL * 2;
        assert!(
            !st.fprint_matched(user, &tok, g, before, &unlocked_look, &|| true),
            "a check that started before the dwell counts for nothing"
        );
    }

    /// The tries ran out: the card's fingerprint goes off for the window,
    /// the card is sent again to say so, and no new claim follows.
    #[test]
    fn three_wrong_fingers_end_the_fingerprint_for_the_window() {
        let user = "faceauth-fprint-nomatch-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let reader = Reader::new(Ok(()));
        let (lane, _) = lane(reader, SHORT);
        let _watch = lane
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(eventually(|| reader.checks() == 1));
        let _ = st.take_key_card_stale(user);
        reader.end(0, FprintEnd::NoMatch);
        assert!(eventually(|| !st.fprint_for_payload(user, &tok).armed));
        assert!(st.take_key_card_stale(user), "the card is sent again");
        std::thread::sleep(SHORT * 6);
        assert_eq!(reader.checks(), 1, "no new claim in the window");
        assert!(!st.answered(user));
    }

    /// The card's status follows the check: a finger that did not match
    /// says so, and keeps saying so while pam_fprintd waits for the next
    /// try, which it asks for at once.
    #[test]
    fn a_wrong_finger_says_try_again_until_the_check_ends() {
        let user = "faceauth-fprint-retry-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let reader = Reader::new(Ok(()));
        let (lane, _) = lane(reader, SHORT);
        let _watch = lane
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(eventually(|| reader.checks() == 1));
        reader.say(0, FprintStatus::Place);
        std::thread::sleep(SHORT * 2);
        assert_eq!(
            st.fprint_for_payload(user, &tok).status,
            FprintStatus::Place
        );
        reader.say(0, FprintStatus::Retry);
        assert!(eventually(
            || st.fprint_for_payload(user, &tok).status == FprintStatus::Retry
        ));
        reader.say(0, FprintStatus::Place);
        std::thread::sleep(SHORT * 3);
        assert_eq!(
            st.fprint_for_payload(user, &tok).status,
            FprintStatus::Retry,
            "the next try's prompt does not hide the miss"
        );
    }

    /// A reader another client holds (or one not there) is said to be busy
    /// and asked again only after `busy_again`; a try that timed out, which
    /// had reached the reader, is followed by a fresh check at once.
    #[test]
    fn a_busy_reader_is_asked_again_later_and_a_timeout_at_once() {
        let user = "faceauth-fprint-busy-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let reader = Reader::new(Ok(()));
        let (lane, _) = lane(reader, Duration::from_millis(400));
        let _watch = lane
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(eventually(|| reader.checks() == 1));
        let t = Instant::now();
        reader.end(0, FprintEnd::Unavailable { reached: false });
        assert!(eventually(
            || st.fprint_for_payload(user, &tok).status == FprintStatus::Busy
        ));
        assert!(eventually(|| reader.checks() == 2));
        assert!(
            t.elapsed() >= Duration::from_millis(350),
            "a busy reader waits before the next claim"
        );
        let t = Instant::now();
        reader.end(1, FprintEnd::Unavailable { reached: true });
        assert!(eventually(|| reader.checks() == 3));
        assert!(
            t.elapsed() < Duration::from_millis(350),
            "a timed-out try is followed at once"
        );
        assert_eq!(
            st.fprint_for_payload(user, &tok).status,
            FprintStatus::Place
        );
    }

    /// The nods win while the check still waits: `finish` returns only
    /// once the check has been stopped, so the reader is free before the
    /// round goes on, and no other check starts.
    #[test]
    fn a_nod_that_wins_first_stops_the_check() {
        let user = "faceauth-fprint-nod-wins-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let reader = Reader::new(Ok(()));
        let (lane, _) = lane(reader, SHORT);
        let watch = lane
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(eventually(|| reader.running() == 1));
        watch.finish();
        assert!(
            reader.stopped(0),
            "the check is stopped when finish returns"
        );
        assert_eq!(reader.running(), 0);
        assert!(
            lane.keys.claim_reader(user, false).is_some(),
            "the reader is free"
        );
        std::thread::sleep(SHORT * 4);
        assert_eq!(reader.checks(), 1);
        assert!(!st.answered(user));
    }

    /// The lock screen comes before the card: its ask latches the user,
    /// which stops the card's check, and its own check starts only once
    /// that one has gone, so the reader never has two claims. Its match
    /// unlocks and never answers the card.
    #[test]
    fn the_lock_screen_takes_the_reader_from_the_card() {
        let user = "faceauth-fprint-lock-first-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let reader = Reader::new(Ok(()));
        let (lane, looks) = lane(reader, SHORT);
        let _watch = lane
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(eventually(|| reader.running() == 1));
        looks.locked.store(true, Ordering::SeqCst);
        let said = Mutex::new(Vec::new());
        let ended = std::thread::scope(|s| {
            let h = s.spawn(|| {
                lane.unlock(st, user, &Bind::OnlyDesktop, &|| false, &|w| {
                    said.lock().unwrap().push(w)
                })
            });
            assert!(
                eventually(|| reader.checks() == 2),
                "the lock screen's check starts"
            );
            assert!(reader.stopped(0), "after the card's was stopped");
            assert_eq!(reader.run(1).lock().unwrap().lane, "unlock");
            reader.say(1, FprintStatus::Place);
            std::thread::sleep(SHORT * 2);
            reader.end(1, FprintEnd::Matched);
            h.join().unwrap()
        });
        assert_eq!(ended, Unlocked::Touched);
        assert_eq!(*said.lock().unwrap(), vec![FprintStatus::Place]);
        assert_eq!(
            reader.most_running.load(Ordering::SeqCst),
            1,
            "never two claims on the reader"
        );
        std::thread::sleep(SHORT * 4);
        assert!(
            !st.answered(user),
            "the finger at the lock screen answers no card"
        );
        assert!(!st.fprint_for_payload(user, &tok).armed);
    }

    /// The latch: while the lock screen holds the user, a finger reported
    /// on the card's check counts for nothing, so a finger while locked can
    /// only unlock; and while the key unlock is asked the fingerprint lane
    /// still asks (the two lanes run side by side and keep separate asks).
    #[test]
    fn a_finger_while_locked_never_approves_a_card() {
        let user = "faceauth-fprint-latch-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let g = st.arm_fprint(user, &tok).unwrap();
        let started = Instant::now();
        st.latch_lock_screen(user);
        assert!(!st.fprint_may_check(user, &tok, g, started));
        assert!(
            !st.fprint_matched(user, &tok, g, started, &unlocked_look, &|| true),
            "a latched user's finger approves nothing"
        );
        assert!(st.begin_key_unlock(user));
        assert!(
            st.begin_fprint_unlock(user),
            "a key unlock under way does not refuse the fingerprint's ask"
        );
        assert!(!st.begin_fprint_unlock(user), "but a second one is refused");
        st.end_fprint_unlock(user);
        st.end_key_unlock(user);
        assert!(!st.answered(user));
    }

    /// A finger the record already took (in the slot) is dropped by the
    /// lock screen's latch, as a touch is, and the socket cannot write one.
    #[test]
    fn a_finger_in_the_slot_is_dropped_by_the_latch_and_the_socket_cannot_answer() {
        let user = "faceauth-fprint-slot-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let g = st.arm_fprint(user, &tok).unwrap();
        let started = Instant::now();
        assert!(st.fprint_matched(user, &tok, g, started, &unlocked_look, &|| true));
        st.latch_lock_screen(user);
        assert!(st.poll(user).is_none(), "the latch dropped it");
        assert!(st.answer(user, Some(&tok), Answer::Fingerprint).is_err());
    }

    /// With every lid shut the reader is not armed on the card and the
    /// lock screen's check does not start; the lane is still offered.
    #[test]
    fn a_shut_lid_arms_nothing() {
        let user = "faceauth-fprint-lid-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let reader = Reader::new(Ok(()));
        reader.lid.store(true, Ordering::SeqCst);
        let (lane, looks) = lane(reader, SHORT);
        assert!(lane
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .is_none());
        assert!(!st.fprint_for_payload(user, &tok).armed);
        looks.locked.store(true, Ordering::SeqCst);
        assert!(matches!(
            lane.unlock(st, user, &Bind::OnlyDesktop, &|| false, &|_| {}),
            Unlocked::No { ref why, .. } if why.contains("lid")
        ));
        assert_eq!(reader.checks(), 0);
        assert_eq!(lane.unlock_offer(user), Ok(()));
    }

    /// A fingerprint not offered arms nothing, and its lane says why.
    #[test]
    fn a_fingerprint_not_offered_arms_nothing() {
        let user = "faceauth-fprint-off-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let off = FprintOff::NotSetUp("no fingerprint enrolled".into());
        let reader = Reader::new(Err(off.clone()));
        let (lane, _) = lane(reader, SHORT);
        assert!(lane
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .is_none());
        assert_eq!(lane.unlock_offer(user), Err(off));
        assert_eq!(reader.checks(), 0);
    }

    /// The reader is one claim at a time, whoever's, while the key keeps
    /// its own rule beside it: the two devices never block each other.
    #[test]
    fn the_reader_takes_one_claim_at_a_time_beside_the_key() {
        let reader = Reader::new(Ok(()));
        let (lane, _) = lane(reader, SHORT);
        let keys = lane.keys;
        let a = keys
            .claim_reader("fp-claim-a", false)
            .expect("the reader is free");
        assert!(keys.claim_reader("fp-claim-b", false).is_none());
        assert!(keys.claim_reader("fp-claim-a", true).is_none());
        assert!(
            keys.claim_reader_within("fp-claim-b", true, &|| false)
                .is_none(),
            "a held reader is not taken"
        );
        drop(a);
        let u = keys.claim_reader("fp-claim-b", true).expect("free again");
        assert!(keys.claim_reader("fp-claim-a", false).is_none());
        drop(u);
    }

    /// A scratch PAM directory holding `files` (name, text).
    fn pam_dir(tag: &str, files: &[(&str, &str)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "faceauth-fprint-pamd-{}-{}",
            std::process::id(),
            tag
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for (name, text) in files {
            std::fs::write(dir.join(name), text).unwrap();
        }
        dir
    }

    /// The offer: a name the check takes, fprintd installed, no pam_fprintd
    /// line that sudo's or polkit's stack reaches, the check installed
    /// right, the bus policy as shipped, and a finger enrolled, each with
    /// its reason; prints a caller cannot read are unreadable, not
    /// withheld (doctor as the user says to run it as root).
    #[test]
    fn the_offer_needs_prints_no_stray_line_and_the_check_installed() {
        let facts = |user, pam_fprintd, prints: Result<usize, String>, reached, installed| {
            offer_from(&OfferFacts {
                user,
                pam_fprintd,
                prints,
                reached,
                installed,
                bus_policy: Ok(()),
            })
        };
        let clean = || Ok(Vec::new());
        assert_eq!(facts("alice", true, Ok(2), clean(), true), Ok(()));
        assert!(matches!(
            facts("Alice", true, Ok(2), clean(), true),
            Err(FprintOff::Withheld(_))
        ));
        assert!(matches!(
            facts("alice", false, Ok(2), clean(), true),
            Err(FprintOff::NotSetUp(w)) if w.contains("fprintd")
        ));
        assert!(matches!(
            facts("alice", true, Ok(0), clean(), true),
            Err(FprintOff::NotSetUp(w)) if w.contains("no fingerprint enrolled")
        ));
        assert!(matches!(
            facts("alice", true, Err("unreadable".into()), clean(), true),
            Err(FprintOff::Unreadable(w)) if w == "unreadable"
        ));
        let dir = pam_dir(
            "offer",
            &[
                ("sudo", "auth sufficient pam_fprintd.so\nauth sufficient pam_faceauth.so consent\n"),
                ("polkit-1", "#auth sufficient pam_fprintd.so\nauth include system-auth # pam_fprintd.so was here\n"),
                ("system-auth", "auth required pam_unix.so\n"),
            ],
        );
        assert!(matches!(
            facts("alice", true, Ok(2), fprintd_reached(&dir, &ELEVATION_STACKS), true),
            Err(FprintOff::Withheld(w)) if w.contains("sudo")
        ));
        assert_eq!(
            facts(
                "alice",
                true,
                Ok(1),
                fprintd_reached(&dir, &["polkit-1"]),
                true
            ),
            Ok(()),
            "a commented line reads nothing"
        );
        assert!(matches!(
            facts("alice", true, Ok(2), clean(), false),
            Err(FprintOff::Withheld(w)) if w.contains("root-owned")
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// H1: the fingerprint is offered only while the package's bus policy
    /// stands as shipped, so no pam_fprintd of the daemon's takes a result
    /// from a connection that is not fprintd's; doctor gives the reason.
    #[test]
    fn the_offer_needs_the_bus_policy_as_shipped() {
        let with = |bus_policy| {
            offer_from(&OfferFacts {
                user: "alice",
                pam_fprintd: true,
                prints: Ok(1),
                reached: Ok(Vec::new()),
                installed: true,
                bus_policy,
            })
        };
        assert_eq!(with(Ok(())), Ok(()));
        assert!(matches!(
            with(Err("the bus policy is not installed".into())),
            Err(FprintOff::Withheld(w)) if w.contains("bus policy")
        ));
    }

    /// H1: the bus policy counts only where root alone could have put it and
    /// only with the shipped text, whose rules are the mandatory pair: deny
    /// fprintd's device signals to every receiver, then allow them from the
    /// owner of fprintd's name.
    #[test]
    fn the_bus_policy_stands_only_as_shipped_and_root_owned() {
        let rules: Vec<&str> = BUS_POLICY_TEXT
            .lines()
            .map(str::trim)
            .filter(|l| {
                l.starts_with("<deny") || l.starts_with("<allow") || l.starts_with("<policy")
            })
            .collect();
        assert_eq!(
            rules,
            vec![
                r#"<policy context="mandatory">"#,
                r#"<deny receive_type="signal" receive_interface="net.reactivated.Fprint.Device"/>"#,
                r#"<allow receive_type="signal" receive_interface="net.reactivated.Fprint.Device" receive_sender="net.reactivated.Fprint"/>"#,
            ]
        );
        let missing = std::env::temp_dir().join("faceauth-fprint-no-such-dir");
        assert!(matches!(bus_policy_state(&missing), Err(w) if w.contains("not installed")));
        let mine = pam_dir("buspolicy", &[(BUS_POLICY_NAME, BUS_POLICY_TEXT)]);
        assert!(
            matches!(bus_policy_state(&mine), Err(w) if w.contains("root")),
            "a copy the test's own user owns does not count"
        );
        let _ = std::fs::remove_dir_all(&mine);
    }

    /// M1: what sudo's and polkit's stacks reach is followed through
    /// `include`, `substack` and their `-type` and `@include` forms, so a
    /// pam_fprintd line in a stack they include withholds the fingerprint
    /// as one in their own text does; a name that is missing, leaves the
    /// directory or nests too deep cannot be followed and withholds too;
    /// a loop ends; a stack that is not there has no lines.
    #[test]
    fn a_pam_fprintd_line_an_elevation_stack_includes_withholds() {
        let fp = "auth sufficient pam_fprintd.so\n";
        let dir = pam_dir(
            "include",
            &[
                (
                    "sudo",
                    "#%PAM-1.0\nauth include system-auth\naccount include system-auth\n",
                ),
                ("system-auth", fp),
            ],
        );
        let r = fprintd_reached(&dir, &ELEVATION_STACKS).unwrap();
        assert_eq!(r, vec![dir.join("system-auth").display().to_string()]);
        assert!(matches!(
            offer_from(&OfferFacts {
                user: "alice",
                pam_fprintd: true,
                prints: Ok(1),
                reached: fprintd_reached(&dir, &ELEVATION_STACKS),
                installed: true,
                bus_policy: Ok(()),
            }),
            Err(FprintOff::Withheld(w)) if w.contains("system-auth")
        ));
        let _ = std::fs::remove_dir_all(&dir);
        for (tag, line) in [
            ("substack", "auth substack inner\n"),
            ("dash", "-auth include inner\n"),
            ("at", "@include inner\n"),
        ] {
            let dir = pam_dir(tag, &[("sudo", line), ("inner", fp)]);
            assert_eq!(
                fprintd_reached(&dir, &["sudo"]).unwrap().len(),
                1,
                "{}",
                tag
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
        for (tag, line) in [
            ("missing", "auth include nowhere\n"),
            ("slash", "auth include /etc/pam.d/system-auth\n"),
            ("dotdot", "auth include ../system-auth\n"),
            ("empty", "auth include\n"),
        ] {
            let dir = pam_dir(
                tag,
                &[
                    ("sudo", line),
                    ("system-auth", "auth required pam_unix.so\n"),
                ],
            );
            assert!(
                fprintd_reached(&dir, &["sudo"]).is_err(),
                "{} withholds",
                tag
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
        let dir = pam_dir(
            "loop",
            &[
                ("sudo", "auth include a\n# auth include nowhere\n"),
                ("a", "auth include b\n"),
                ("b", "auth include a\nauth [success=1 default=ignore] pam_exec.so quiet /usr/bin/omarchy-hw-laptop-closed\n"),
            ],
        );
        assert_eq!(
            fprintd_reached(&dir, &["sudo", "polkit-1"]),
            Ok(Vec::new()),
            "a loop ends, and a missing top stack has no lines"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let mut chain: Vec<(String, String)> = (0..12)
            .map(|i| (format!("s{}", i), format!("auth include s{}\n", i + 1)))
            .collect();
        chain.push(("s12".into(), "auth required pam_unix.so\n".into()));
        chain.push(("sudo".into(), "auth include s0\n".into()));
        let files: Vec<(&str, &str)> = chain
            .iter()
            .map(|(a, b)| (a.as_str(), b.as_str()))
            .collect();
        let dir = pam_dir("deep", &files);
        assert!(
            matches!(fprintd_reached(&dir, &["sudo"]), Err(w) if w.contains("deep")),
            "nesting past the bound withholds"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// L2: the card arms the fingerprint only on the lanes the helper
    /// takes, sudo and polkit, as the key keeps to the lanes it has a stack
    /// for; another requester's card shows no fingerprint line at all.
    #[test]
    fn the_card_arms_the_fingerprint_only_on_the_helpers_lanes() {
        let user = "faceauth-fprint-lane-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let reader = Reader::new(Ok(()));
        let (lane, _) = lane(reader, SHORT);
        assert!(lane.arm(st, user, &tok, "su", &Bind::OnlyDesktop).is_none());
        assert!(lane
            .arm(st, user, &tok, "unlock", &Bind::OnlyDesktop)
            .is_none());
        assert!(!st.fprint_for_payload(user, &tok).armed);
        assert!(lane
            .arm(st, user, &tok, "polkit", &Bind::OnlyDesktop)
            .is_some());
    }

    /// L3: the card's check and the lock screen's run in units of their
    /// own, so a stop that failed on one leaves the other's name free; both
    /// fall under the stale-unit stop at start.
    #[test]
    fn the_card_and_the_lock_screen_run_in_units_of_their_own() {
        let card_sudo = fprint_unit("alice", "sudo").unwrap();
        let card_polkit = fprint_unit("alice", "polkit").unwrap();
        let unlock = fprint_unit("alice", "unlock").unwrap();
        assert_eq!(card_sudo, card_polkit, "one card at a time per user");
        assert_ne!(card_sudo, unlock);
        for u in [&card_sudo, &unlock] {
            assert!(
                u.starts_with("faceauth-fprint-") && u.ends_with(".service"),
                "{}",
                u
            );
        }
    }

    /// The prints are counted three levels down, a missing user has none,
    /// and nothing but files counts.
    #[test]
    fn prints_are_counted_per_finger_file() {
        let dir =
            std::env::temp_dir().join(format!("faceauth-fprint-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dev = dir.join("alice/virtual_device/0");
        std::fs::create_dir_all(&dev).unwrap();
        std::fs::write(dev.join("7"), b"print").unwrap();
        std::fs::write(dev.join("2"), b"print").unwrap();
        std::fs::create_dir_all(dev.join("not-a-print")).unwrap();
        std::fs::write(dir.join("alice/stray"), b"x").unwrap();
        assert_eq!(prints_of(&dir, "alice"), Ok(2));
        assert_eq!(prints_of(&dir, "bob"), Ok(0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The helper's exit mirrors the key helper's: 42 only for pam_fprintd's
    /// success, 3 for the reader unavailable, 1 for every other answer, the
    /// tries running out and a transaction that never started included;
    /// and the daemon reads 42 alone as a match, so a stopped, killed or
    /// unstarted check never does.
    #[test]
    fn the_exit_maps_match_no_match_and_reader_unavailable() {
        assert_eq!(fprint_exit_code(Some(0)), FPRINT_MATCHED);
        assert_eq!(fprint_exit_code(Some(9)), FPRINT_UNAVAILABLE);
        for rc in [Some(7), Some(11), Some(6), Some(19), None] {
            assert_eq!(fprint_exit_code(rc), 1, "{:?}", rc);
        }
        assert_eq!(end_of_exit(Some(42), false), FprintEnd::Matched);
        assert_eq!(
            end_of_exit(Some(3), true),
            FprintEnd::Unavailable { reached: true }
        );
        assert_eq!(
            end_of_exit(Some(3), false),
            FprintEnd::Unavailable { reached: false }
        );
        for code in [Some(0), Some(1), Some(2), Some(143), None] {
            assert_eq!(end_of_exit(code, true), FprintEnd::NoMatch, "{:?}", code);
        }
        assert_eq!(status_of_message(3), Some(FprintStatus::Retry));
        assert_eq!(status_of_message(4), Some(FprintStatus::Place));
        assert_eq!(status_of_message(1), None, "a prompt is no status");
    }

    /// Only the exact status words count, as they come, and an overlong
    /// line is dropped whole, however it is split.
    #[test]
    fn the_status_words_are_read_exactly_and_bounded() {
        let mut l = StatusLines::default();
        assert_eq!(l.feed(b"pla"), vec![]);
        assert_eq!(
            l.feed(b"ce\nretry\n"),
            vec![FprintStatus::Place, FprintStatus::Retry]
        );
        assert_eq!(l.feed(b"busy\nPLACE\n match\n"), vec![]);
        assert_eq!(l.feed(b"retryretryretryretry"), vec![]);
        assert_eq!(
            l.feed(b"retry\nplace\n"),
            vec![FprintStatus::Place],
            "the overlong line went whole"
        );
    }

    /// The status line the daemon writes to the lock screen's waiting line
    /// is the exact line the module reads (pam_faceauth's
    /// `fprint_status_of`, whose test holds the same text).
    #[test]
    fn the_status_line_is_the_one_the_module_reads() {
        use std::io::Read;
        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        send_fprint_status(&a, FprintStatus::Place);
        send_fprint_status(&a, FprintStatus::Retry);
        drop(a);
        let mut got = String::new();
        b.read_to_string(&mut got).unwrap();
        assert_eq!(
            got,
            "{\"result\":\"fprint_status\",\"status\":\"place\"}\n{\"result\":\"fprint_status\",\"status\":\"retry\"}\n"
        );
    }

    /// The stack the package ships says the tries and the timeout these
    /// constants document, through pam_fprintd and nothing else.
    #[test]
    fn the_shipped_stack_carries_its_tries_and_timeout() {
        let text = include_str!("../../../packaging/pam.d/faceauth-fprint");
        let lines: Vec<Vec<&str>> = text
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
            .map(|l| l.split_whitespace().collect())
            .collect();
        let tries = format!("max-tries={}", FPRINT_TRIES);
        let timeout = format!("timeout={}", FPRINT_TRY_SECONDS);
        assert_eq!(
            lines,
            vec![vec!["auth", "required", "pam_fprintd.so", &tries, &timeout]]
        );
        let cap: u64 = FPRINT_UNIT_PROPERTIES
            .iter()
            .find_map(|p| p.strip_prefix("RuntimeMaxSec="))
            .and_then(|v| v.strip_suffix('s'))
            .and_then(|v| v.parse().ok())
            .unwrap();
        assert!(
            cap >= u64::from(FPRINT_TRIES) * FPRINT_TRY_SECONDS,
            "the runtime cap covers every try"
        );
        assert!(
            FPRINT_DEADLINE.as_secs() > cap,
            "the daemon's bound is past the unit's"
        );
    }

    /// The check's unit is shaped for a client of fprintd: AF_UNIX alone,
    /// the system bus left in reach, no device at all, systemd's and udev's
    /// sockets and the daemon's own files hidden, a SIGTERM stop with a
    /// SIGKILL after it, and stopped with the daemon, never rerun by it.
    #[test]
    fn the_check_unit_reaches_the_bus_and_no_device() {
        let props = FPRINT_UNIT_PROPERTIES;
        let has = |p: &str| props.contains(&p);
        assert!(has("RestrictAddressFamilies=AF_UNIX"));
        assert!(has("PrivateDevices=yes") && has("DevicePolicy=closed"));
        assert!(!props.iter().any(|p| p.starts_with("DeviceAllow=")));
        let hidden: Vec<&str> = props
            .iter()
            .filter_map(|p| p.strip_prefix("InaccessiblePaths="))
            .flat_map(|v| v.split_whitespace())
            .map(|p| p.trim_start_matches('-'))
            .collect();
        for p in [
            "/run/systemd",
            "/run/udev/control",
            "/var/lib/faceauth",
            "/run/faceauth",
            "/etc/sudoers.d",
        ] {
            assert!(hidden.contains(&p), "{} hidden", p);
        }
        assert!(
            !hidden
                .iter()
                .any(|p| p.starts_with("/run/dbus") || *p == "/var/run/dbus"),
            "the system bus stays in reach"
        );
        for p in [
            "KillSignal=SIGTERM",
            "SendSIGKILL=yes",
            "CapabilityBoundingSet=",
            "NoNewPrivileges=yes",
            "PrivateNetwork=yes",
            "StopPropagatedFrom=faceauth.service",
        ] {
            assert!(has(p), "{}", p);
        }
        let c = fprint_command("faceauth-fprint-alice.service", "sudo", "alice");
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(c.get_program(), "/usr/bin/systemd-run");
        assert!(args.iter().any(|a| a == "--pipe") && args.iter().any(|a| a == "--wait"));
        assert_eq!(
            &args[args.len() - 3..],
            &[FPRINT_HELPER.to_string(), "sudo".into(), "alice".into()]
        );
        assert_eq!(
            fprint_unit("alice", "sudo").as_deref(),
            Some("faceauth-fprint-card-alice.service")
        );
        assert_eq!(
            fprint_unit("alice", "unlock").as_deref(),
            Some("faceauth-fprint-unlock-alice.service")
        );
        assert_eq!(fprint_unit("Alice", "sudo"), None);
        let stop: Vec<String> = stale_fprint_checks_stop()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            stop.last().map(String::as_str),
            Some("faceauth-fprint-*.service")
        );
    }
}
