//! The security key on the consent card. While the nods are armed (the
//! scan and the nod window), the daemon also asks the user's FIDO2 key,
//! and a touch approves the request as a nod does, the passwordless rider
//! included, under the nod's own guards: only a card the user has had a
//! dwell to read. It is the factor sudo's own stack accepts: pam_u2f
//! against the same key file, with what the lane's own key line (the
//! key-fallback line under the face line) asks of the key (a PIN, user
//! verification) mirrored into the stack the check runs. A line the card
//! cannot mirror keeps the key off the card, so the card never asks for
//! less than the stack.
//!
//! pam_u2f runs outside the daemon, in a transient unit of its own per
//! check (`KEY_UNIT_PROPERTIES`): the hidraw nodes and none of the
//! daemon's reach, so whatever a USB device does to libfido2 happens away
//! from the templates, the camera, the TPM and sudoers.d. The PIN, when
//! the line asks for one, goes to it down a pipe, and its exit status is
//! the only answer. A watch (`KeyWatch`) runs the checks on a thread of
//! its own, one per user at a time, and stops the unit the moment the
//! watch ends, which frees the key. A touch counts only for the watch's
//! own generation of the request that armed it, for a check that started
//! a dwell after the card's latest acknowledgment
//! (`ConsentState::key_touched`).
//!
//! Every use of the key goes through here while face is set up. The
//! lock screen's key (`KeyLane::unlock`): its PAM stack,
//! `omarchy-lock-fido2`, is pam_faceauth's `key-unlock` line and pam_deny,
//! and the daemon runs the same sandboxed check, on the policy of sudo's
//! key line, while the compositor says the session is locked. The stacks'
//! own key line (`KeyLane::fallback`): sudo's and polkit's pam_u2f line
//! becomes pam_faceauth's `key-fallback` line under the face line, and the
//! daemon runs the check for it too, held back (the module waits and asks
//! again) while the session reads as locked or the lock screen holds the
//! key, and stopped the moment either changes. With faceauthd down the
//! module runs the same helper itself, as stock pam_u2f would (fix round
//! 10, item 6). The three are exclusive per user (`KeyLane::claim`): the card
//! on screen takes the key from a fallback, and the lock screen takes it
//! from both. The lock screen's first ask, its word that it is up, and the
//! daemon's own lock latch the user (`ConsentState::latch_lock_screen`):
//! from then until the daemon has seen the session unlocked and
//! `key_unlock_hold_ms` has passed, the card takes no touch and no
//! fallback runs, so a touch while locked can only unlock.

use super::state::{ConsentState, Secret, CONSENT};
use crate::lockgate::{
    Bind, Desktop, LockState, Origin, Verdict, FALLBACK_DEADLINE, UNKNOWN_LIMIT,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// The daemon's private PAM stacks, which the package ships in a
/// root-owned directory. They are read with `pam_start_confdir`, never
/// from `/etc/pam.d`, so no edit there reaches them.
pub(super) const KEY_PAM_DIR: &str = "/usr/lib/faceauth/pam.d";

/// The key file the stacks name, written by `pamu2fcfg` through Omarchy's
/// FIDO2 setup. Read here only to decide whether to offer the key;
/// pam_u2f reads it again for every check and decides.
const KEY_AUTHFILE: &str = "/etc/fido2/fido2";

/// The helper each check's unit runs.
const KEY_HELPER: &str = "/usr/lib/faceauth/faceauth-keycheck";

/// pam_u2f's own defaults for every module argument a line leaves out,
/// which it reads for the stack's key line and the private stacks alike.
use crate::lockgate::U2F_CONF;

/// The helper's exit status for a touch. Not 0: `systemd-run --wait`
/// answers 0 for a unit that was stopped, and a stopped check must never
/// read as a touch.
pub const KEY_TOUCHED: u8 = 42;

/// The sandbox of each check's unit. Root, for root's hidraw nodes and
/// the key file, with no capabilities, no network, a read-only system and
/// /dev, the hidraw nodes as its only devices, the daemon's state, config
/// and sudoers out of sight, and what root owns but the check never reads
/// (the password and group shadows, SSH's keys, /boot, /efi, /var/lib and
/// /var/log) hidden too, and a hard runtime cap. It reaches no control
/// socket: no AF_UNIX at all (netlink stays for libfido2's NFC scan, in a
/// network namespace of its own), and systemd's, D-Bus's and udev's
/// sockets hidden besides, since root needs no capability to ask systemd
/// for a new unit. It sees no other process and is killed outright.
const KEY_UNIT_PROPERTIES: &[&str] = &[
    "RuntimeMaxSec=30s",
    "CapabilityBoundingSet=",
    "AmbientCapabilities=",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "PrivateNetwork=yes",
    "PrivateIPC=yes",
    "RestrictAddressFamilies=AF_NETLINK",
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
    "DevicePolicy=closed",
    "DeviceAllow=char-hidraw rw",
    "InaccessiblePaths=-/var/lib/faceauth -/run/faceauth -/etc/faceauth -/etc/sudoers -/etc/sudoers.d -/run/systemd -/run/dbus -/var/run/dbus -/run/udev/control",
    // Root with no capability still owns these, and could read them (fix
    // round 9, Opus L3): nothing the check needs is there.
    "InaccessiblePaths=-/etc/shadow -/etc/gshadow -/etc/ssh -/boot -/efi -/var/lib -/var/log",
    "ReadOnlyPaths=/dev",
    "PrivatePIDs=yes",
    // Round 19: a stop is SIGTERM, which the helper answers by cancelling
    // the key's wait (keycheck_cancel.rs), so the key goes dark with the
    // check; SIGKILL a second later for one that has not ended.
    "KillSignal=SIGTERM",
    "TimeoutStopSec=1s",
    "SendSIGKILL=yes",
    "UMask=0077",
    "LimitCORE=0",
    "MemoryMax=64M",
    "TasksMax=8",
    // The daemon's service stopping, restarting or dying stops the check
    // with it, and never reruns it (fix rounds 11 and 12, Opus N4:
    // `PartOf=` would try-restart a live check with a crash's automatic
    // restart, src/core/transaction.c); unlike `BindsTo=`, nothing here
    // would start the service for a daemon run outside it. systemd-run
    // may set it on a transient unit (src/core/dbus-unit.c,
    // `UNIT_STOP_PROPAGATED_FROM`).
    "StopPropagatedFrom=faceauth.service",
];

/// The stop of every check unit left from before the daemon started (fix
/// round 11, Opus N4): a crash or an upgrade can leave one holding the key
/// for up to its 30 s. `systemctl stop` expands the pattern to the units in
/// memory (man systemctl), which is every running one.
pub fn stale_checks_stop() -> std::process::Command {
    let mut c = std::process::Command::new("/usr/bin/timeout");
    c.args([
        "-k",
        "1",
        "5",
        "/usr/bin/systemctl",
        "stop",
        "--quiet",
        "faceauth-key-*.service",
    ])
    .env_clear()
    .env("PATH", "/usr/bin:/bin");
    c
}

/// The longest a poll waits for another's look of the same session: the
/// anchor's own bound and a margin.
const LOOK_WAIT: Duration = Duration::from_secs(5);

/// How often a check is started while the nods are armed. With no key
/// plugged in pam_u2f answers at once, so this is how soon a key plugged
/// in mid-request is asked.
const KEY_REARM: Duration = Duration::from_secs(2);

/// The daemon's own bound on one check: the unit's `RuntimeMaxSec=`
/// (30 s) and a margin, for a unit whose stop never came.
pub const KEY_DEADLINE: Duration = Duration::from_secs(35);

/// The longest `KeyWatch::finish` waits for its thread to stop a check:
/// the stop's own timeout (`timeout -k 1 3`) and a margin, below
/// `lockgate::LIVENESS`, so a stop that hangs never outlasts a waiting
/// PAM line's patience (round 6, item 12).
pub const KEY_FINISH: Duration = Duration::from_secs(5);

/// The longest the daemon takes to answer a touch on a key line: two lock
/// questions before the check, the wait for a card's check to stop, the
/// check's own deadline, and one lock question that runs past it. The PAM
/// module waits at least this long (`pam_faceauth`'s `KEY_WAIT`, which a
/// test holds to it), so it never gives up on a touch the daemon took.
pub const KEY_REPLY_WITHIN: Duration = Duration::from_secs(
    3 * super::shell::USER_CALL_LIMIT.as_secs() + KEY_FINISH.as_secs() + KEY_DEADLINE.as_secs(),
);

/// The longest the watch sleeps between looks at its stop flag and the
/// record, idle and while a check runs.
pub(super) const KEY_POLL: Duration = Duration::from_millis(100);
pub(super) const KEY_SUPERVISE: Duration = Duration::from_millis(50);

/// How often a key unlock or a key fallback asks the compositor about the
/// lock while its check runs, to stop the check when it changes.
pub(super) const UNLOCK_RECHECK: Duration = Duration::from_secs(1);

/// How long, after a key unlock that ended in a touch or with the lock
/// screen hanging up, the daemon looks for the unlock, so the latch's
/// hold starts from it rather than from the next look anyone takes.
const UNLOCK_WATCH: Duration = Duration::from_secs(3);

/// What a lane's key line asks of the key beyond a touch, mirrored into
/// the stack the check runs. Each word is kept as the line has it: absent
/// (pam_u2f's own default, which follows the credential's attributes),
/// `=0` or `=1`, since pam_u2f treats the three differently.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct KeyPolicy {
    /// `pinverification=`: `Some(true)` asks for the key's PIN, which the
    /// card, the key line's terminal prompt or nothing (the lock screen)
    /// supplies.
    pub pin: Option<bool>,
    /// `userverification=`: verification on the key itself, the
    /// fingerprint on a YubiKey Bio.
    pub uv: Option<bool>,
}

impl KeyPolicy {
    /// Whether a check of this policy asks for the key's PIN.
    pub fn asks_pin(self) -> bool {
        self.pin == Some(true)
    }

    /// The private stack (`packaging/pam.d/`) that carries this policy:
    /// one per combination of absent, `=0` and `=1`.
    fn service(self) -> &'static str {
        match (self.pin, self.uv) {
            (None, None) => "faceauth-key",
            (Some(true), None) => "faceauth-key-pin",
            (Some(false), None) => "faceauth-key-nopin",
            (None, Some(true)) => "faceauth-key-uv",
            (None, Some(false)) => "faceauth-key-nouv",
            (Some(true), Some(true)) => "faceauth-key-pin-uv",
            (Some(true), Some(false)) => "faceauth-key-pin-nouv",
            (Some(false), Some(true)) => "faceauth-key-nopin-uv",
            (Some(false), Some(false)) => "faceauth-key-nopin-nouv",
        }
    }

    /// The words of the policy, as the private stack carries them.
    #[cfg(test)]
    fn words(self) -> Vec<&'static str> {
        let mut w = Vec::new();
        match self.pin {
            Some(true) => w.push("pinverification=1"),
            Some(false) => w.push("pinverification=0"),
            None => {}
        }
        match self.uv {
            Some(true) => w.push("userverification=1"),
            Some(false) => w.push("userverification=0"),
            None => {}
        }
        w
    }
}

/// Why the card does not offer the key.
#[derive(Clone, Debug, PartialEq)]
pub enum KeyOff {
    /// Nothing to offer: no key registered, or no key line on this lane.
    NotSetUp(String),
    /// A key is set up, but the card holds it back: the lane's line asks
    /// for something the card cannot mirror, or the check is not installed
    /// right.
    Withheld(String),
}

impl std::fmt::Display for KeyOff {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyOff::NotSetUp(why) | KeyOff::Withheld(why) => f.write_str(why),
        }
    }
}

/// What the watch needs from the host: the daemon's is `SystemdKey`, the
/// tests' a fake launcher. The fingerprint lane asks the same host for the
/// lock answers and uids (`consent/fprint.rs`).
pub(super) trait KeyHost: Sync {
    /// Whether the card may offer `user`'s key on `lane`, and with what.
    fn offer(&self, user: &str, lane: &str) -> Result<KeyPolicy, KeyOff>;
    /// Start one check for `user` on `lane`, with the PIN when the lane
    /// asks for one.
    fn start(
        &self,
        user: &str,
        lane: &str,
        pin: Option<Secret>,
    ) -> std::io::Result<Box<dyn KeyRun>>;
    /// What the compositor says of the session of `user`'s that `bind`
    /// names, now. A key unlock needs Locked; everything else asks the one
    /// verdict (`KeyLane::verdict`), which weighs this answer.
    fn lock_state(&self, user: &str, bind: &Bind) -> LockState;
    /// Whether logind's records show anyone a graphical session now.
    fn desktop(&self) -> Desktop;
    /// `user`'s uid, for the shared key's priority (fix round 9).
    fn uid_of(&self, user: &str) -> Option<u32>;
}

/// One check under way.
pub(super) trait KeyRun: Send {
    /// The answer once the check has ended: true for a touch.
    fn poll(&mut self) -> Option<bool>;
    /// End the check now; the key is free when this returns.
    fn stop(&mut self);
}

/// The key through a transient unit per check.
struct SystemdKey;

/// The `systemd-run` that runs one check of `user` on `lane` in `unit`.
/// `--pipe` hands the caller's pipe to the helper as its stdin, so the
/// PIN is on no command line and in no environment, and `--wait` returns
/// the helper's exit status. A unit of that name still there (a stop that
/// failed) makes the start fail, so no check is adopted from an earlier
/// one.
fn key_command(unit: &str, lane: &str, user: &str) -> std::process::Command {
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
    .arg("--description=Omarchy FaceAuth security key check")
    .args(
        KEY_UNIT_PROPERTIES
            .iter()
            .map(|p| format!("--property={}", p)),
    )
    .args([KEY_HELPER, lane, user])
    .env_clear()
    .env("PATH", "/usr/bin:/bin")
    .stdin(Stdio::piped())
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    c
}

impl KeyHost for SystemdKey {
    fn offer(&self, user: &str, lane: &str) -> Result<KeyPolicy, KeyOff> {
        key_offer(user, lane)
    }

    fn start(
        &self,
        user: &str,
        lane: &str,
        pin: Option<Secret>,
    ) -> std::io::Result<Box<dyn KeyRun>> {
        use std::io::Write;
        let unit = key_unit(user).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a user name")
        })?;
        let (mut child, pidfd) =
            crate::child::spawn_with_pidfd(&mut key_command(&unit, lane, user))?;
        // The pipe is closed when this block ends, so the helper reads to
        // its end; the `Secret` is wiped as it drops.
        if let Some(mut stdin) = child.stdin.take() {
            if let Some(pin) = &pin {
                let _ = stdin.write_all(pin.as_bytes());
            }
        }
        Ok(Box::new(UnitRun { unit, child, pidfd }))
    }

    fn lock_state(&self, user: &str, bind: &Bind) -> LockState {
        super::anchor::anchored_lock_state(user, bind)
    }

    fn desktop(&self) -> Desktop {
        crate::lockgate::graphical_sessions(Path::new("/run/systemd"))
    }

    fn uid_of(&self, user: &str) -> Option<u32> {
        nix::unistd::User::from_name(user)
            .ok()
            .flatten()
            .map(|u| u.uid.as_raw())
    }
}

/// The one verdict on the session of `user`'s that `bind` names (R1;
/// round 8, Codex 3), as every path in the daemon asks it: the card's key
/// and its commit, the key-fallback line, its `key_ready` and `key_wait`
/// answers, the consent round and the park.
pub fn lock_verdict(user: &str, bind: &Bind) -> Verdict {
    KEY.verdict(&CONSENT, user, bind)
}

/// A check as `systemd-run --wait`, which returns once the helper has
/// exited, with its exit status: `KEY_TOUCHED` only for a touch.
struct UnitRun {
    unit: String,
    child: std::process::Child,
    /// The child's own pidfd, the only way it is signalled (fix round 13,
    /// Codex 1; `crate::child`).
    pidfd: std::os::fd::OwnedFd,
}

impl KeyRun for UnitRun {
    fn poll(&mut self) -> Option<bool> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(status.code() == Some(i32::from(KEY_TOUCHED))),
            Ok(None) => None,
            Err(_) => Some(false),
        }
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

/// The PAM file behind a lane. The lock screen's key ("unlock") asks for
/// what sudo's key line asks.
fn lane_stack(lane: &str) -> Option<&'static str> {
    match lane {
        "sudo" | "unlock" => Some("/etc/pam.d/sudo"),
        "polkit" => Some("/etc/pam.d/polkit-1"),
        _ => None,
    }
}

/// The other elevation stack: a pam_u2f line there takes the key outside
/// the daemon as surely as one in the lane's own stack.
fn other_stack(lane: &str) -> &'static str {
    match lane {
        "polkit" => "/etc/pam.d/sudo",
        _ => "/etc/pam.d/polkit-1",
    }
}

/// Whether the card may offer `user`'s key on `lane` ("sudo" or
/// "polkit"), whether the lock screen may ("unlock"), and whether the
/// stack's own key line may run (the same lanes), and what each asks of
/// the key, read from the files as they stand; the reason when not.
/// `faceauth doctor` reports the same answer.
pub fn key_offer(user: &str, lane: &str) -> Result<KeyPolicy, KeyOff> {
    let read = |p: &str| std::fs::read_to_string(p).ok();
    let policy = offer_from(
        lane,
        lane_stack(lane).and_then(read).as_deref(),
        read(other_stack(lane)).as_deref(),
        read(KEY_AUTHFILE).as_deref(),
        u2f_conf()?.as_deref(),
        user,
    )?;
    if !key_user_ok(user) {
        return Err(KeyOff::Withheld(format!(
            "{} is not a name the key check takes",
            user
        )));
    }
    if trusted_stack(Path::new(KEY_PAM_DIR), policy.service()).is_none()
        || !root_only_file(Path::new(KEY_HELPER))
    {
        return Err(KeyOff::Withheld(format!(
            "the key check is not installed root-owned: {}/{} and {}",
            KEY_PAM_DIR,
            policy.service(),
            KEY_HELPER
        )));
    }
    Ok(policy)
}

/// pam_u2f's defaults file as it stands: None when there is none (pam_u2f
/// allows that), its text otherwise; withheld when it cannot be read.
fn u2f_conf() -> Result<Option<String>, KeyOff> {
    match std::fs::read(U2F_CONF) {
        Ok(bytes) => String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| KeyOff::Withheld(format!("{} is not text pam_u2f reads", U2F_CONF))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(KeyOff::Withheld(format!(
            "{} cannot be read: {}",
            U2F_CONF, e
        ))),
    }
}

/// The defaults pam_u2f takes from its file's text for the two words the
/// daemon mirrors, `pinverification=` and `userverification=`, and
/// `userpresence=`, read as the PAM module reads them
/// (`lockgate::u2f_conf_words`); any other setting, a value other than 0
/// or 1, a setting twice, or a file past the size pam_u2f reads is a
/// policy the private stacks would not carry the way the line does, so the
/// key is withheld (Codex 5).
fn u2f_defaults(text: &str) -> Result<(KeyPolicy, Option<bool>), String> {
    let w = crate::lockgate::u2f_conf_words(text)?;
    Ok((
        KeyPolicy {
            pin: w.pin,
            uv: w.uv,
        },
        w.presence,
    ))
}

/// The policy a check runs on: the line's word, else pam_u2f's default
/// from its file, for each of the two words. pam_u2f applies its file to
/// the stack's line and to the private stack alike, so the private stack
/// that says the effective word outright behaves as the line does.
fn effective(line: KeyPolicy, conf: Option<&str>) -> Result<(KeyPolicy, bool), KeyOff> {
    let (d, presence) = match conf {
        Some(text) => u2f_defaults(text).map_err(KeyOff::Withheld)?,
        None => (KeyPolicy::default(), None),
    };
    Ok((
        KeyPolicy {
            pin: line.pin.or(d.pin),
            uv: line.uv.or(d.uv),
        },
        presence == Some(true),
    ))
}

/// The offer from the files' texts: the key file must name `user`, the
/// lane's key line must be one the daemon mirrors, pam_u2f's defaults file
/// (`conf`) must set nothing else, and a credential that asks for its PIN
/// (`+pin`) needs the effective policy to ask for it too: pam_u2f asks such
/// a credential for its PIN whatever `pinverification=0` says (upstream's
/// util.c), and no lane answers a prompt it did not ask for.
fn offer_from(
    lane: &str,
    own: Option<&str>,
    other: Option<&str>,
    authfile: Option<&str>,
    conf: Option<&str>,
    user: &str,
) -> Result<KeyPolicy, KeyOff> {
    if !authfile.is_some_and(|t| authfile_names(t, user)) {
        return Err(KeyOff::NotSetUp(format!(
            "no key registered for {} in {}",
            user, KEY_AUTHFILE
        )));
    }
    let line = lane_policy(lane, own, other)?;
    let (policy, presence_forced) = effective(line, conf)?;
    // Round 7 (D): a key that approves without a touch is on no lane.
    if !presence_forced && authfile.is_some_and(|t| authfile_touchless(t, user)) {
        return Err(KeyOff::Withheld(format!(
            "a credential for {} in {} is registered without +presence, so pam_u2f would approve it without a touch; register it again without pamu2fcfg's -P, or set userpresence=1 in {}",
            user, KEY_AUTHFILE, U2F_CONF
        )));
    }
    if lane == "unlock" && policy.asks_pin() {
        return Err(KeyOff::Withheld(format!(
            "pam_u2f's defaults in {} ask for the key's PIN, and the lock screen has no field for one",
            U2F_CONF
        )));
    }
    if !policy.asks_pin() && authfile.is_some_and(|t| authfile_wants_pin(t, user)) {
        let says = match line.pin {
            Some(false) => "says pinverification=0, which pam_u2f overrides for such a credential",
            _ => "does not say pinverification=",
        };
        return Err(KeyOff::Withheld(format!(
            "a credential for {} in {} asks for its PIN (+pin), and the key line {}; set pinverification=1 on the line",
            user, KEY_AUTHFILE, says
        )));
    }
    Ok(policy)
}

/// The policy of `lane`'s key line, from the text of its PAM file (`own`)
/// and of the other elevation stack (`other`). While face is set up the
/// stack's key line is pam_faceauth's `key-fallback` line, which the
/// daemon runs: the lane needs exactly one, `auth sufficient`, whose
/// `cue`, `pinverification=` and `userverification=` (0 or 1) are
/// mirrored; any other word or control, or a second one, is a policy the
/// private stacks do not carry, so the key stays off. A pam_u2f line in
/// either stack takes the key outside the daemon, so with one there no
/// lane offers the key at all: not the card, not the lock screen, not the
/// fallback.
fn lane_policy(lane: &str, own: Option<&str>, other: Option<&str>) -> Result<KeyPolicy, KeyOff> {
    let Some(file) = lane_stack(lane) else {
        return Err(KeyOff::NotSetUp(format!(
            "no stack stands behind the {} lane",
            lane
        )));
    };
    for (path, text) in [(file, own), (other_stack(lane), other)] {
        if u2f_lines(text.unwrap_or("")).next().is_some() {
            return Err(KeyOff::Withheld(format!(
                "a pam_u2f line in {} reads the key outside faceauthd",
                path
            )));
        }
    }
    let lines: Vec<Vec<&str>> = key_lines(own.unwrap_or("")).collect();
    let [line] = lines.as_slice() else {
        return Err(if lines.is_empty() {
            KeyOff::NotSetUp(format!("{} has no key-fallback line", file))
        } else {
            KeyOff::Withheld(format!("{} has more than one key-fallback line", file))
        });
    };
    let policy = line_policy(line).map_err(|why| {
        KeyOff::Withheld(format!(
            "the key-fallback line in {} ({}) has {}, which the daemon cannot ask for",
            file,
            line.join(" "),
            why
        ))
    })?;
    // The lock screen has no PIN field, and a lane that opened on a bare
    // touch would ask for less than the line: no lane at all.
    if lane == "unlock" && policy.asks_pin() {
        return Err(KeyOff::Withheld(format!(
            "the key-fallback line in {} asks for the key's PIN, and the lock screen has no field for one",
            file
        )));
    }
    Ok(policy)
}

/// The policy of one key-fallback line, as words, or what in it the
/// daemon cannot carry: a word it does not know, or one said twice.
fn line_policy(words: &[&str]) -> Result<KeyPolicy, String> {
    let ["auth", "sufficient", "pam_faceauth.so", args @ ..] = words else {
        return Err("another control or module path".into());
    };
    let mut policy = KeyPolicy::default();
    let mut seen: Vec<&str> = Vec::new();
    for arg in args {
        let key = arg.split('=').next().unwrap_or(arg);
        if seen.contains(&key) {
            return Err(format!("`{}` twice", key));
        }
        seen.push(key);
        match *arg {
            "userpresence=0" => {
                return Err("`userpresence=0`, which lets a key approve without a touch".into())
            }
            "key-fallback" | "cue" | "socket=/run/faceauth/sock" => {}
            "pinverification=1" => policy.pin = Some(true),
            "pinverification=0" => policy.pin = Some(false),
            "userverification=1" => policy.uv = Some(true),
            "userverification=0" => policy.uv = Some(false),
            other => return Err(format!("`{}`", other)),
        }
    }
    Ok(policy)
}

/// What in a sudo or polkit stack's `text` keeps the key from going
/// through the daemon while face is set up there, or None: a pam_u2f line
/// (it reads the key outside the daemon), a key-fallback line with a word
/// or control the daemon does not mirror or a word said twice, or a second
/// key-fallback line. Face setup refuses the same stacks before it changes
/// them; `faceauth doctor` names the line. Nothing to say about a stack
/// with no face line.
pub fn key_lines_problem(text: &str) -> Option<String> {
    let face = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .any(|l| l.contains("pam_faceauth.so") && l.split_whitespace().any(|w| w == "consent"));
    if !face {
        return None;
    }
    if let Some(line) = u2f_lines(text).next() {
        return Some(format!(
            "a pam_u2f line reads the key outside faceauthd: {}",
            line.join(" ")
        ));
    }
    let lines: Vec<Vec<&str>> = key_lines(text).collect();
    if lines.len() > 1 {
        return Some(format!(
            "more than one key-fallback line: {}",
            lines[1].join(" ")
        ));
    }
    lines.first().and_then(|line| {
        line_policy(line)
            .err()
            .map(|why| format!("the key-fallback line has {}: {}", why, line.join(" ")))
    })
}

/// The active key-fallback lines of a PAM file, as words, with any comment
/// cut.
fn key_lines(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .filter(|l| l.contains("pam_faceauth.so"))
        .map(|l| l.split_whitespace().collect::<Vec<_>>())
        .filter(|w| w.contains(&"key-fallback"))
}

/// The active pam_u2f lines of a PAM file, as words, with any comment cut.
fn u2f_lines(text: &str) -> impl Iterator<Item = Vec<&str>> {
    text.lines()
        .map(|l| l.split('#').next().unwrap_or(""))
        .filter(|l| l.contains("pam_u2f.so"))
        .map(|l| l.split_whitespace().collect())
}

/// Whether pam_u2f's key file `text` holds a credential for `user`: a
/// line whose first field, up to the first colon, is the name, with
/// something after it, the way pam_u2f reads the file.
fn authfile_names(text: &str, user: &str) -> bool {
    !user.is_empty()
        && text.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(name, keys)| name == user && !keys.trim().is_empty())
        })
}

/// The attributes of each of `user`'s credentials in the key file, as
/// pam_u2f reads them: the fourth field of a native credential (empty when
/// it has none), and `+presence` for one in the old two-field format,
/// which pam_u2f assumes.
fn credential_attrs<'a>(text: &'a str, user: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    text.lines()
        .filter_map(move |line| {
            line.split_once(':')
                .filter(|(name, _)| !user.is_empty() && *name == user)
                .map(|(_, creds)| creds)
        })
        .flat_map(|creds| creds.split(':'))
        .map(|cred| {
            let fields: Vec<&str> = cred.split(',').collect();
            match fields.len() {
                0..=2 => "+presence",
                _ => fields.get(3).copied().unwrap_or(""),
            }
        })
}

/// Whether a credential of `user`'s asks for its PIN (`+pin`), matched as
/// pam_u2f matches it, by substring.
fn authfile_wants_pin(text: &str, user: &str) -> bool {
    credential_attrs(text, user).any(|attrs| attrs.contains("+pin"))
}

/// Whether a credential of `user`'s asks for no touch: one without
/// `+presence`, which pam_u2f asks for a touch only when its defaults say
/// `userpresence=1` (round 7, D).
fn authfile_touchless(text: &str, user: &str) -> bool {
    credential_attrs(text, user).any(|attrs| !attrs.contains("+presence"))
}

/// A user name the key check takes: what useradd accepts by default,
/// lowercase letters, digits, `_` and `-`, not starting with a digit or
/// `-`, at most 32 characters. The helper checks it again.
pub fn key_user_ok(user: &str) -> bool {
    let mut b = user.bytes();
    let first_ok = b
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c == b'_');
    first_ok
        && user.len() <= 32
        && b.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
}

/// The unit name for `user`'s check, `faceauth-key-<user>.service`, for
/// a name `key_user_ok` takes, escaped the way `systemd-escape` does.
fn key_unit(user: &str) -> Option<String> {
    key_user_ok(user).then(|| format!("faceauth-key-{}.service", unit_escape(user)))
}

/// A string escaped for a unit name the way `systemd-escape` does:
/// letters, digits, `:`, `_` and a `.` that does not lead are kept, `/`
/// becomes `-`, and every other byte is `\xNN`.
pub(super) fn unit_escape(s: &str) -> String {
    let mut out = String::new();
    for (i, b) in s.bytes().enumerate() {
        match b {
            b'/' => out.push('-'),
            b'.' if i > 0 => out.push('.'),
            b if b.is_ascii_alphanumeric() || b == b':' || b == b'_' => out.push(b as char),
            b => out.push_str(&format!("\\x{:02x}", b)),
        }
    }
    out
}

/// One check, as the helper runs it: pam_u2f for `user` through the
/// private stack that mirrors `lane`'s key line as it stands now, with
/// `pin` when that line asks for one, from the canonical path the trust
/// check vouched for, never the path as written, so no symlink on the way
/// can be switched between the check and the open.
pub fn key_check(lane: &str, user: &str, pin: Option<&str>) -> bool {
    let read = |p: &str| std::fs::read_to_string(p).ok();
    let own = lane_stack(lane).and_then(read);
    let other = read(other_stack(lane));
    let Ok(conf) = u2f_conf() else {
        return false;
    };
    let Ok(policy) = offer_from(
        lane,
        own.as_deref(),
        other.as_deref(),
        read(KEY_AUTHFILE).as_deref(),
        conf.as_deref(),
        user,
    ) else {
        return false;
    };
    if policy.asks_pin() && pin.is_none() {
        return false;
    }
    let pin = if policy.asks_pin() { pin } else { None };
    trusted_stack(Path::new(KEY_PAM_DIR), policy.service())
        .and_then(|dir| dir.to_str().map(str::to_string))
        .is_some_and(|dir| crate::pamcheck::check_key(policy.service(), user, &dir, pin))
}

/// The private stack a stock check of `lane` runs (fix round 11, Codex
/// 4): the one carrying the words of the lane's own key line, from the
/// texts of its PAM file (`own`) and the other elevation stack's (`other`).
/// The line must still be the daemon's mirrored key-fallback line with no
/// pam_u2f line beside it (`lane_policy`); none of the card's rules about
/// credentials or pam_u2f's defaults apply, since pam_u2f reads both
/// itself, as it does on stock Omarchy. Only the sudo and polkit lanes.
fn stock_service(lane: &str, own: Option<&str>, other: Option<&str>) -> Option<&'static str> {
    if !matches!(lane, "sudo" | "polkit") {
        return None;
    }
    lane_policy(lane, own, other).ok().map(KeyPolicy::service)
}

/// One stock check, as the helper runs it with faceauthd down (fix round
/// 11, Codex 4): pam_u2f for `user` through the stack `stock_service`
/// names, from the canonical path the trust check vouched for, with every
/// message of its conversation handed to `relay` (style and text) and its
/// answer, for a prompt, typed back; None fails the conversation, as a
/// PAM caller that gives no answer does.
pub fn key_check_stock(
    lane: &str,
    user: &str,
    relay: &mut dyn FnMut(i32, &str) -> Option<String>,
) -> bool {
    let read = |p: &str| std::fs::read_to_string(p).ok();
    let own = lane_stack(lane).and_then(read);
    let other = read(other_stack(lane));
    let Some(service) = stock_service(lane, own.as_deref(), other.as_deref()) else {
        return false;
    };
    trusted_stack(Path::new(KEY_PAM_DIR), service)
        .and_then(|dir| dir.to_str().map(str::to_string))
        .is_some_and(|dir| crate::pamcheck::check_key_relay(service, user, &dir, relay))
}

/// The canonical path of `dir`, when only root could have written the
/// stack: it, every directory above it and the service file in it root's
/// and closed to group and other writers, and the file no symlink. A
/// stack anyone else could edit could put pam_permit where the key is.
pub(super) fn trusted_stack(dir: &Path, service: &str) -> Option<PathBuf> {
    let dir = std::fs::canonicalize(dir).ok()?;
    let ancestors_ok = dir
        .ancestors()
        .all(|p| std::fs::metadata(p).is_ok_and(root_only));
    (ancestors_ok && root_only_file(&dir.join(service))).then_some(dir)
}

/// A regular file, no symlink, root's and closed to other writers.
pub(super) fn root_only_file(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|md| md.file_type().is_file() && root_only(md))
}

fn root_only(md: std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    md.uid() == 0 && md.mode() & 0o022 == 0
}

/// What a check holds while it runs: the security key, or the fingerprint
/// reader. The two are separate devices, and each has its own rule in
/// `KeyLane::claim_on`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Device {
    Key,
    Reader,
}

/// One check's place in `KeyLane::running`: the device it holds, whose
/// check it is, and whether it is the lock screen's.
struct Claim {
    device: Device,
    user: String,
    unlock: bool,
}

/// The daemon's key checks: the host, the users with a check running,
/// the re-arm interval and the daemon's own deadline on a check. The
/// daemon has one (`KEY`); a test makes its own around a fake launcher.
/// It is also the one arbiter of the fingerprint reader's checks
/// (`claim_reader`), so the lock screen's lanes, the card's and later the
/// stacks' fallback lines hand both devices over under the same rules.
pub struct KeyLane {
    host: &'static dyn KeyHost,
    /// The checks running, by device. A check's stop can outlast the
    /// watch that started it, so this is kept per user, not per watch.
    /// Each entry says whether it is an unlock's (round 8: a key unlock
    /// runs only with no key check of anyone's running, and while one
    /// runs no other key check starts).
    running: Mutex<Vec<Claim>>,
    rearm: Duration,
    deadline: Duration,
    /// How long a polled lock answer is shared (`POLL_CACHE` for the
    /// daemon's lane; nothing for a plain lane, a test's).
    pub(crate) cache_ttl: Duration,
    /// The lock answers by session, and the looks under way.
    cache: Mutex<Vec<Looked>>,
    cache_cv: std::sync::Condvar,
    /// Ids for polled looks.
    looks: std::sync::atomic::AtomicU64,
}

/// How long a lock answer asked on a polling path is shared with other
/// polls of the same session (fix round 8, Codex and Opus L1): every poll
/// of the daemon (a key line's `key_ready`, a card's watch, a park, the
/// walk-away watch) used to start a transient unit of its own. The
/// commits (the card's, the key line's, and the unlock lane's lock check)
/// never use it: they always ask afresh.
pub const POLL_CACHE: Duration = Duration::from_secs(1);

/// One session's last lock answer, stamped with when its look began, and
/// the polled look under way, if any (fix round 9, Opus M1: an older look
/// that finishes late never overwrites a newer answer, and only the look
/// that took the place in line gives it back).
struct Looked {
    user: String,
    bind: Bind,
    answer: Option<(Instant, LockState)>,
    /// Answers stored, so a poll that waited for one takes it.
    seq: u64,
    /// The id of the polled look under way.
    asking: Option<u64>,
}

pub static KEY: KeyLane = KeyLane::with_cache(&SystemdKey, KEY_REARM, KEY_DEADLINE, POLL_CACHE);

/// A user's place in `KeyLane::running`, given back when the check ends.
pub(super) struct Running<'a> {
    lane: &'a KeyLane,
    device: Device,
    user: String,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        let (device, user) = (self.device, &self.user);
        self.lane
            .lock()
            .retain(|c| !(c.device == device && c.user == *user));
    }
}

/// Ends a key unlock's ask in the record however the unlock ends.
struct Asking<'a> {
    state: &'a ConsentState,
    user: &'a str,
}

impl Drop for Asking<'_> {
    fn drop(&mut self) {
        self.state.end_key_unlock(self.user);
    }
}

/// Ends a key fallback in the record however it ends.
struct Falling<'a> {
    state: &'a ConsentState,
    user: &'a str,
    n: u64,
}

impl Drop for Falling<'_> {
    fn drop(&mut self) {
        self.state.end_fallback(self.user, self.n);
    }
}

/// Who asks for a key fallback: where the request comes from (round 6,
/// item 7) and the session its lock question is about (round 8, Codex 3),
/// both read from the PAM process.
#[derive(Clone, Debug, PartialEq)]
pub struct Asker {
    pub origin: Origin,
    pub bind: Bind,
}

impl Asker {
    pub fn new(origin: Origin, bind: Bind) -> Asker {
        Asker { origin, bind }
    }
}

/// How a key fallback ended, or why it cannot run now.
#[derive(Debug, PartialEq)]
pub enum Fallback {
    /// The key was touched: the request is approved.
    Touched,
    /// Not now, with what kind of wait it is (`locked`, `held`, `unknown`,
    /// or `card` for another request's card on screen holding the key) and
    /// why. The module waits and asks again (`key_wait`), so the key is
    /// offered once the unlock is seen and the hold has passed.
    Wait(&'static str, String),
    /// No: the stack goes on to the password.
    No(String),
}

/// How a key unlock ended.
#[derive(Debug, PartialEq)]
pub enum Unlocked {
    /// The key was touched: the lock screen unlocks.
    Touched,
    /// Not touched, with the reason; `hung_up` when the lock screen
    /// stopped asking, which may be its unlock by another lane.
    No { why: String, hung_up: bool },
}

/// The key watch of one scan and nod window of one request. Its thread
/// asks the key while the watch's generation is armed. Dropping the watch
/// marks the record and sets the flag the thread reads, and the thread
/// stops a check under way within `KEY_SUPERVISE`; `finish` also waits
/// for that.
pub struct KeyWatch {
    state: &'static ConsentState,
    user: String,
    token: String,
    generation: u64,
    stop: Arc<AtomicBool>,
    /// Disconnects when the thread ends.
    done: Option<std::sync::mpsc::Receiver<()>>,
}

impl KeyWatch {
    /// End the watch and wait, up to `KEY_FINISH`, until its thread has
    /// stopped any check under way, so the key is free before the
    /// request's answer goes back to PAM: after a refusal on sudo, the
    /// stack's key-fallback line is next, and its check would wait out
    /// a check still holding the key.
    pub fn finish(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Disarmed before the wait, so a result the thread reads meanwhile
        // finds its generation gone and counts for nothing.
        self.state
            .disarm_key(&self.user, &self.token, self.generation);
        if let Some(done) = self.done.take() {
            if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = done.recv_timeout(KEY_FINISH) {
                log::warn!(
                    "consent: the key check for {} did not end in time",
                    self.user
                );
            }
        }
    }
}

impl Drop for KeyWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.state
            .disarm_key(&self.user, &self.token, self.generation);
    }
}

/// What one watch's thread works on.
struct Watched<'a> {
    state: &'a ConsentState,
    user: &'a str,
    token: &'a str,
    lane: &'a str,
    policy: KeyPolicy,
    generation: u64,
    stop: &'a AtomicBool,
    /// The session the request's lock question is about.
    bind: &'a Bind,
}

impl KeyLane {
    /// A lane that shares no polled answer: a test's.
    #[cfg(test)]
    pub(super) const fn new(
        host: &'static dyn KeyHost,
        rearm: Duration,
        deadline: Duration,
    ) -> Self {
        Self::with_cache(host, rearm, deadline, Duration::ZERO)
    }

    /// A lane sharing polled lock answers for `cache_ttl`.
    const fn with_cache(
        host: &'static dyn KeyHost,
        rearm: Duration,
        deadline: Duration,
        cache_ttl: Duration,
    ) -> Self {
        KeyLane {
            host,
            running: Mutex::new(Vec::new()),
            rearm,
            deadline,
            cache_ttl,
            cache: Mutex::new(Vec::new()),
            cache_cv: std::sync::Condvar::new(),
            looks: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn cache(&self) -> MutexGuard<'_, Vec<Looked>> {
        self.cache.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The lock answer for a polling path: one whose look began less than
    /// the cache's ttl ago if there is one, else the answer of a polled
    /// look already under way for the same session (waited for, never
    /// doubled), else a look of its own.
    pub(super) fn compositor_polled(&self, user: &str, bind: &Bind) -> LockState {
        let mut c = self.cache();
        loop {
            let i = match c.iter().position(|l| l.user == user && l.bind == *bind) {
                Some(i) => i,
                None => {
                    c.push(Looked {
                        user: user.to_string(),
                        bind: bind.clone(),
                        answer: None,
                        seq: 0,
                        asking: None,
                    });
                    c.len() - 1
                }
            };
            if let Some((at, st)) = c[i].answer {
                if at.elapsed() < self.cache_ttl {
                    return st;
                }
            }
            if c[i].asking.is_none() {
                let id = self.looks.fetch_add(1, Ordering::SeqCst) + 1;
                c[i].asking = Some(id);
                drop(c);
                let began = Instant::now();
                let st = self.host.lock_state(user, bind);
                return self.store(user, bind, st, began, Some(id));
            }
            let seen = c[i].seq;
            let (guard, timeout) = self
                .cache_cv
                .wait_timeout_while(c, LOOK_WAIT, |c| {
                    c.iter()
                        .find(|l| l.user == user && l.bind == *bind)
                        .is_some_and(|l| l.asking.is_some() && l.seq == seen)
                })
                .unwrap_or_else(|p| p.into_inner());
            c = guard;
            if let Some(l) = c.iter().find(|l| l.user == user && l.bind == *bind) {
                if l.seq != seen {
                    if let Some((_, st)) = l.answer {
                        return st;
                    }
                }
            }
            if timeout.timed_out() {
                // The look under way did not come back in time: no answer.
                return LockState::Unknown;
            }
        }
    }

    /// A fresh lock answer, for a commit: always asked, and shared with
    /// later polls.
    pub(super) fn compositor_fresh(&self, user: &str, bind: &Bind) -> LockState {
        let began = Instant::now();
        let st = self.host.lock_state(user, bind);
        self.store(user, bind, st, began, None);
        st
    }

    /// Keep the answer of a look that began at `began`, unless a newer
    /// one is kept already; the polled look `mine` gives back its place
    /// in line. The answer to hand the caller: this look's own for a
    /// commit, the newest kept for a poll.
    fn store(
        &self,
        user: &str,
        bind: &Bind,
        st: LockState,
        began: Instant,
        mine: Option<u64>,
    ) -> LockState {
        let mut c = self.cache();
        // A bounded record: a session no longer asked about is forgotten.
        c.retain(|l| {
            l.asking.is_some()
                || l.answer
                    .is_some_and(|(at, _)| at.elapsed() < Duration::from_secs(60))
        });
        let i = match c.iter().position(|l| l.user == user && l.bind == *bind) {
            Some(i) => i,
            None => {
                c.push(Looked {
                    user: user.to_string(),
                    bind: bind.clone(),
                    answer: None,
                    seq: 0,
                    asking: None,
                });
                c.len() - 1
            }
        };
        let l = &mut c[i];
        if mine.is_some() && l.asking == mine {
            l.asking = None;
        }
        if l.answer.is_none_or(|(at, _)| at <= began) {
            l.answer = Some((began, st));
            l.seq += 1;
        }
        let newest = l.answer.map_or(st, |(_, s)| s);
        drop(c);
        self.cache_cv.notify_all();
        newest
    }

    /// The kept answer for a session, as a test reads it.
    #[cfg(test)]
    fn cached(&self, user: &str, bind: &Bind) -> Option<LockState> {
        self.cache()
            .iter()
            .find(|l| l.user == user && l.bind == *bind)
            .and_then(|l| l.answer.map(|(_, s)| s))
    }

    /// Whether a polled look of the session is under way, as a test reads it.
    #[cfg(test)]
    fn look_in_flight(&self, user: &str, bind: &Bind) -> bool {
        self.cache()
            .iter()
            .any(|l| l.user == user && l.bind == *bind && l.asking.is_some())
    }

    /// Whether a nod approval of `user`'s may commit now (fix round 9,
    /// Codex 3, Opus M1): a fresh anchored look, asked before the consent
    /// record's lock and judged under it with the epoch, as a key touch's
    /// commit is, so a lock that landed during the nods or the confirm, or
    /// while it looked, refuses it.
    pub fn nod_may_commit(&self, state: &ConsentState, user: &str, bind: &Bind) -> bool {
        state.commit_nod(user, &|| self.look(user, bind))
    }

    fn lock(&self) -> MutexGuard<'_, Vec<Claim>> {
        self.running.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// `user`'s place for a key check, unless a key check of theirs, or
    /// any key unlock's, is running; for a key unlock (`unlock`), only
    /// while no key check of anyone's runs (round 8: one key may serve
    /// several accounts).
    fn claim(&self, user: &str, unlock: bool) -> Option<Running<'_>> {
        self.claim_on(Device::Key, user, unlock)
    }

    /// `user`'s place for a fingerprint check, only while no fingerprint
    /// check of anyone's runs: fprintd lets one client claim a reader at a
    /// time and answers any other `AlreadyInUse` (src/device.c), so the
    /// daemon hands the reader over rather than let two checks race for
    /// it. The order the reader goes in is the key's: the lock screen's
    /// ask takes it from the card (its latch moves the card's generation
    /// on, which stops the card's check, and `claim_reader_within` waits
    /// for that), and the card's arm will take it from a fallback line
    /// once there is one.
    pub(super) fn claim_reader(&self, user: &str, unlock: bool) -> Option<Running<'_>> {
        self.claim_on(Device::Reader, user, unlock)
    }

    /// `user`'s place for a check on `device`, by that device's rule.
    fn claim_on(&self, device: Device, user: &str, unlock: bool) -> Option<Running<'_>> {
        let mut running = self.lock();
        let mut held = running.iter().filter(|c| c.device == device);
        let free = match (device, unlock) {
            (Device::Key, true) | (Device::Reader, _) => held.next().is_none(),
            (Device::Key, false) => !held.any(|c| c.user == user || c.unlock),
        };
        if !free {
            return None;
        }
        running.push(Claim {
            device,
            user: user.to_string(),
            unlock,
        });
        Some(Running {
            lane: self,
            device,
            user: user.to_string(),
        })
    }

    /// The one verdict on the session of `user`'s that `bind` names (R1):
    /// the compositor's word and logind's records asked now, weighed with
    /// the latch, the lock screen's asks, the daemon's start and its
    /// connection places.
    pub fn verdict(&self, state: &ConsentState, user: &str, bind: &Bind) -> Verdict {
        state.judge(
            user,
            self.compositor_polled(user, bind),
            self.host.desktop(),
        )
    }

    /// Look at every account holding the shared key's priority, through
    /// the polled answers, so its anchored unlock is seen and the priority
    /// ends with the hold after it (fix round 9): whoever is held off asks
    /// this, the key line at each ask and a card's watch at each turn.
    pub(super) fn refresh_priority(&self, state: &ConsentState) {
        for (user, bind) in state.priority_holders() {
            let st = self.compositor_polled(&user, &bind);
            let _ = state.judge(&user, st, self.host.desktop());
        }
    }

    /// Whether `user`'s request bound to `bind` has its own session in the
    /// foreground (`ConsentState::request_session_in_front`, fix round 11,
    /// Opus N2).
    pub(super) fn request_in_front(&self, state: &ConsentState, user: &str, bind: &Bind) -> bool {
        self.host
            .uid_of(user)
            .is_some_and(|uid| state.request_session_in_front(uid, bind))
    }

    /// A fresh look for a commit, asked under the record's lock.
    pub(super) fn look(&self, user: &str, bind: &Bind) -> (LockState, Desktop) {
        (self.compositor_fresh(user, bind), self.host.desktop())
    }

    /// `user`'s uid, as the host reads it (the unlock lanes' priority).
    pub(super) fn uid_of(&self, user: &str) -> Option<u32> {
        self.host.uid_of(user)
    }

    /// Whether logind's records show anyone a graphical session now.
    pub(super) fn desktop(&self) -> Desktop {
        self.host.desktop()
    }

    /// Whether the lock screen's key lane is there for `user`, and why
    /// not: their key registered, sudo's key-fallback line one the lane
    /// can mirror and asking for no PIN, no pam_u2f line in either stack,
    /// and the check installed right. The lock screen shows the lane only
    /// on this (the `key_lane` reply).
    pub fn unlock_offer(&self, user: &str) -> Result<KeyPolicy, KeyOff> {
        self.host.offer(user, "unlock")
    }

    /// Wait, up to `KEY_FINISH`, for `user`'s place for a check (a key
    /// unlock's with `unlock`): a check still stopping holds the key. None
    /// when `go_on` turns false first.
    fn claim_within(
        &self,
        user: &str,
        unlock: bool,
        go_on: &dyn Fn() -> bool,
    ) -> Option<Running<'_>> {
        self.claim_on_within(Device::Key, user, unlock, go_on)
    }

    /// `claim_within` for the fingerprint reader: a card's check still
    /// stopping holds it.
    pub(super) fn claim_reader_within(
        &self,
        user: &str,
        unlock: bool,
        go_on: &dyn Fn() -> bool,
    ) -> Option<Running<'_>> {
        self.claim_on_within(Device::Reader, user, unlock, go_on)
    }

    fn claim_on_within(
        &self,
        device: Device,
        user: &str,
        unlock: bool,
        go_on: &dyn Fn() -> bool,
    ) -> Option<Running<'_>> {
        let by = Instant::now() + KEY_FINISH;
        loop {
            if let Some(r) = self.claim_on(device, user, unlock) {
                return Some(r);
            }
            if !go_on() || Instant::now() > by {
                return None;
            }
            std::thread::sleep(KEY_SUPERVISE);
        }
    }

    /// The lock screen's key: one check of `user`'s key while the session
    /// is locked, the lock screen asking. `Unlocked::Touched` on a touch,
    /// which unlocks; the reason otherwise. The ask latches the user and
    /// takes their card off the key in one step under the record's lock
    /// (`ConsentState::begin_key_unlock`): the card's key is disarmed, a
    /// touch it left in the slot dropped, a fallback cancelled, a card's
    /// check under way stopped before this one starts, and none starts
    /// until the daemon has seen the unlock and the hold has passed. The
    /// check is stopped at once when the lock screen stops asking (`gone`),
    /// within `UNLOCK_RECHECK` of the session unlocking, and at the
    /// daemon's deadline. A touch does not end the latch: only an unlock
    /// the daemon sees does.
    pub fn unlock(
        &self,
        state: &ConsentState,
        user: &str,
        bind: &Bind,
        gone: &dyn Fn() -> bool,
    ) -> Unlocked {
        let no = |why: &str, hung_up: bool| Unlocked::No {
            why: why.to_string(),
            hung_up,
        };
        // Its session in front first (fix round 11, Opus N3): a locked
        // account in the background asks no anchor and starts nothing; its
        // lock screen's retries each cost a look at logind's record.
        let Some(uid) = self.host.uid_of(user) else {
            return no("the user is unknown", false);
        };
        if !state.unlock_session_in_front(uid, bind) {
            return no("the session is not in the foreground", false);
        }
        if !state.begin_key_unlock(user) {
            return no("a key unlock of this user's is already asked", false);
        }
        let asking = Asking { state, user };
        let policy = match self.host.offer(user, "unlock") {
            Ok(p) => p,
            Err(why) => return no(&why.to_string(), false),
        };
        if policy.asks_pin() {
            return no("the lock screen's key lane asks for no PIN", false);
        }
        if self.compositor_fresh(user, bind) != LockState::Locked {
            return no("the session is not locked", false);
        }
        // Found locked, afresh: only now does the shared key's priority
        // start, taking every account's card and key line off the key (fix
        // round 9, Codex 1 and Opus L2). An account that is not locked
        // never gets this far.
        if !state.start_priority(user, uid, bind) {
            return no("the session is not in the foreground", false);
        }
        let Some(running) = self.claim_within(user, true, &|| !gone()) else {
            return no("a check for the card did not stop in time", gone());
        };
        let started = Instant::now();
        let mut run = match self.host.start(user, "unlock", None) {
            Ok(run) => run,
            Err(e) => return no(&format!("the key check did not start: {}", e), false),
        };
        // The lock question goes out on a thread of its own (fix round 11,
        // Codex 5): an anchor may take 3.5 s, and the supervision below,
        // the session in front above all, keeps running meanwhile, so a VT
        // switch stops the check at once. The check is stopped before the
        // scope waits for a question still out.
        let (why, hung_up, seen, touched) = std::thread::scope(|scope| {
            let mut look: Option<std::thread::ScopedJoinHandle<'_, LockState>> = None;
            let mut looked = started;
            let ended = loop {
                if let Some(touched) = run.poll() {
                    break ("", false, None, Some(touched));
                }
                if gone() {
                    break ("the lock screen stopped asking", true, None, None);
                }
                // Its session switched away from, closing or gone: the
                // check stops at once (fix round 10, Opus N1).
                if !state.holds_priority(user) {
                    break (
                        "the session is no longer in the foreground",
                        false,
                        None,
                        None,
                    );
                }
                if started.elapsed() > self.deadline {
                    break ("the key check ran past its deadline", false, None, None);
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
                        look = Some(scope.spawn(|| self.compositor_polled(user, bind)));
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
        if let Some(touched) = touched {
            // A touch counts only while the session is still the one in
            // front (fix round 10, Opus N1).
            if touched && state.holds_priority(user) {
                return Unlocked::Touched;
            }
            if touched {
                return no("the session is no longer in the foreground", false);
            }
            return no("the key check ended without a touch", false);
        }
        drop(asking);
        if let Some(st) = seen {
            let _ = state.judge(user, st, self.host.desktop());
        }
        no(why, hung_up)
    }

    /// After a key unlock that ended in a touch or with the lock screen
    /// hanging up, look for the unlock for up to `UNLOCK_WATCH`, so the
    /// latch's hold runs from the unlock itself; any later look by anyone
    /// would see it too, only later.
    pub fn watch_for_unlock(&self, state: &ConsentState, user: &str, bind: &Bind) {
        let by = Instant::now() + UNLOCK_WATCH;
        while Instant::now() < by {
            let st = self.compositor_fresh(user, bind);
            let _ = state.judge(user, st, self.host.desktop());
            if st == LockState::Unlocked {
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// Whether the stack's key line may run for `user` on `lane` now: the
    /// policy it runs on, or why not. Only the one verdict's unlocked lets
    /// it run (R1). A request from the locked desktop waits (`Wait`, with
    /// the verdict's kind) while the lock is up, while a latch runs out its
    /// hold, and, for up to `UNKNOWN_LIMIT`, while the verdict is unknown;
    /// past that, and at once for a request that is not from the desktop
    /// (a text console, a remote login: round 6, item 7), it is `No`, and
    /// the stack goes on to the password. It waits too while the user's
    /// card has the key armed.
    pub fn fallback_gate(
        &self,
        state: &ConsentState,
        user: &str,
        lane: &str,
        asker: &Asker,
    ) -> Result<KeyPolicy, Fallback> {
        let (origin, bind) = (asker.origin, &asker.bind);
        let policy = self
            .host
            .offer(user, lane)
            .map_err(|why| Fallback::No(why.to_string()))?;
        if state.budget_spent(user) {
            return Err(Fallback::No(
                "the consent request just spent its wait budget; use the password".into(),
            ));
        }
        self.refresh_priority(state);
        let verdict = self.verdict(state, user, bind);
        if verdict != Verdict::Unlocked {
            if origin == Origin::Elsewhere {
                return Err(Fallback::No(format!(
                    "the request is not from the desktop, and the desktop reads as {}; use the password",
                    verdict.name()
                )));
            }
            if verdict == Verdict::Unknown && state.doubt_for(user) >= UNKNOWN_LIMIT {
                return Err(Fallback::No(format!(
                    "the lock state has read as unknown for {} s; use the password",
                    UNKNOWN_LIMIT.as_secs()
                )));
            }
            let why = match verdict {
                Verdict::Locked => "the screen is locked",
                Verdict::Held => "the lock screen holds the key until the hold after the unlock",
                _ => "the lock state is unknown, which counts as locked",
            };
            return Err(Fallback::Wait(verdict.name(), why.into()));
        }
        // Only while the request's own session is in front (fix round 11,
        // Opus N2); a wait the module counts as unknown, so it goes on to
        // the password.
        if !self.request_in_front(state, user, bind) {
            return Err(Fallback::Wait(
                "unknown",
                "the request's session is not in the foreground".into(),
            ));
        }
        if state.card_has_key(user) {
            return Err(Fallback::Wait(
                "card",
                "the card on screen has the key".into(),
            ));
        }
        Ok(policy)
    }

    /// The stack's own key line (pam_faceauth's `key-fallback`, under the
    /// face line on sudo and polkit): one check of `user`'s key on `lane`,
    /// with `pin` when the line asks for one, used once. `Touched` on a
    /// touch; `Wait` when it cannot run now (`fallback_gate`) or was stopped
    /// because the verdict stopped reading unlocked, the lock screen asked
    /// or a card armed, so the module asks again after the unlock; `No`
    /// otherwise. The check waits for a touch at most `FALLBACK_DEADLINE`.
    /// A touch counts only if the fallback is still on and the one
    /// verdict, asked again at the commit under the record's lock, says
    /// unlocked (R1).
    pub fn fallback(
        &self,
        state: &ConsentState,
        user: &str,
        lane: &str,
        pin: Option<Secret>,
        gone: &dyn Fn() -> bool,
        asker: &Asker,
    ) -> Fallback {
        let bind = &asker.bind;
        let policy = match self.fallback_gate(state, user, lane, asker) {
            Ok(p) => p,
            Err(f) => return f,
        };
        if policy.asks_pin() && pin.is_none() {
            return Fallback::No("the key's PIN is needed and none was given".into());
        }
        let pin = if policy.asks_pin() { pin } else { None };
        let Some(n) = state.begin_fallback(user) else {
            return Fallback::Wait("held", "the card or the lock screen has the key".into());
        };
        let _falling = Falling { state, user, n };
        let live = || state.fallback_live(user, n);
        let Some(running) = self.claim_within(user, false, &|| live() && !gone()) else {
            return if gone() {
                Fallback::No("the requester went away".into())
            } else if !live() {
                Fallback::Wait("held", "the card or the lock screen took the key".into())
            } else {
                Fallback::No("a check for the card did not stop in time".into())
            };
        };
        let deadline = self.deadline.min(FALLBACK_DEADLINE);
        let started = Instant::now();
        let mut run = match self.host.start(user, lane, pin) {
            Ok(run) => run,
            Err(e) => return Fallback::No(format!("the key check did not start: {}", e)),
        };
        // As the unlock's: the lock question on a thread of its own, and
        // the supervision, the request's session in front above all, every
        // tick meanwhile (fix round 11, Codex 5, Opus N2).
        let ended = std::thread::scope(|scope| {
            let mut look: Option<std::thread::ScopedJoinHandle<'_, LockState>> = None;
            let mut looked = started;
            let ended = loop {
                if let Some(touched) = run.poll() {
                    break Err(touched);
                }
                if !live() {
                    break Ok(Fallback::Wait(
                        "held",
                        "the card or the lock screen took the key".into(),
                    ));
                }
                if gone() {
                    break Ok(Fallback::No("the requester went away".into()));
                }
                if !self.request_in_front(state, user, bind) {
                    break Ok(Fallback::Wait(
                        "unknown",
                        "the request's session went to the background".into(),
                    ));
                }
                if started.elapsed() > deadline {
                    break Ok(Fallback::No("the key check ran past its deadline".into()));
                }
                match look.take() {
                    Some(h) if h.is_finished() => {
                        let st = h.join().unwrap_or(LockState::Unknown);
                        let v = state.judge(user, st, self.host.desktop());
                        if v != Verdict::Unlocked {
                            break Ok(Fallback::Wait(v.name(), "the screen locked".into()));
                        }
                    }
                    Some(h) => look = Some(h),
                    None if looked.elapsed() >= UNLOCK_RECHECK => {
                        looked = Instant::now();
                        look = Some(scope.spawn(|| self.compositor_polled(user, bind)));
                    }
                    None => {}
                }
                std::thread::sleep(KEY_SUPERVISE);
            };
            if ended.is_ok() {
                run.stop();
            }
            ended
        });
        drop(running);
        match ended {
            Ok(f) => f,
            Err(false) => Fallback::No("the key check ended without a touch".into()),
            // A touch counts only with the request's session still in
            // front, and the fallback still on and the one verdict, asked
            // again at the commit under the record's lock, unlocked (R1).
            Err(true) if !self.request_in_front(state, user, bind) => Fallback::Wait(
                "unknown",
                "the touch came with the request's session in the background".into(),
            ),
            Err(true) => {
                // The request's own session asked again after the look, at
                // the commit (fix round 12, Codex 1).
                if state.fallback_touched(user, n, &|| self.look(user, bind), &|| {
                    self.request_in_front(state, user, bind)
                }) {
                    Fallback::Touched
                } else {
                    Fallback::Wait(
                        "held",
                        "the touch came as the screen locked or the key was taken".into(),
                    )
                }
            }
        }
    }

    /// Arm the key for `user`'s live request named by `token`, on `lane`:
    /// a new generation in the record, which the card's next payload
    /// carries, and a thread that asks the key. None, with nothing armed,
    /// when the key is not offered there, the request is not live, or no
    /// thread could start.
    pub fn arm(
        &'static self,
        state: &'static ConsentState,
        user: &str,
        token: &str,
        lane: &str,
        bind: &Bind,
    ) -> Option<KeyWatch> {
        let policy = match self.host.offer(user, lane) {
            Ok(policy) => policy,
            Err(why) => {
                log::debug!("consent: security key not offered to {}: {}", user, why);
                return None;
            }
        };
        let generation = state.arm_key(user, token, policy.asks_pin())?;
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let mut watch = KeyWatch {
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
            .name("faceauth-key".into())
            .spawn(move || {
                let _done = tx;
                self.watch(&Watched {
                    state,
                    user: &u,
                    token: &t,
                    lane: &l,
                    policy,
                    generation,
                    stop: &stop,
                    bind: &b,
                })
            });
        match spawned {
            Ok(_) => {
                log::debug!("consent: security key armed for {} ({})", user, generation);
                Some(watch)
            }
            Err(e) => {
                log::warn!("consent: no thread for the key check: {}", e);
                watch.done = None;
                None
            }
        }
    }

    /// The watch's thread. A check starts whenever the record allows one
    /// for this generation now, no check of the user's is running, `rearm`
    /// has passed since this thread last started one and, on a lane that
    /// asks for a PIN, the card has sent one. It ends when stopped, or
    /// once a touch has counted.
    fn watch(&self, w: &Watched<'_>) {
        let mut last: Option<Instant> = None;
        while !w.stop.load(Ordering::SeqCst) {
            let now = Instant::now();
            let due = last.is_none_or(|t| now - t >= self.rearm);
            if due {
                self.refresh_priority(w.state);
            }
            // Each check starts only on the one verdict's unlocked (R1),
            // asked first, so the unlock it sees starts the latch's hold,
            // and asked again a `rearm` later when it is anything else.
            if due
                && (self.verdict(w.state, w.user, w.bind) != Verdict::Unlocked
                    || !self.request_in_front(w.state, w.user, w.bind))
            {
                // Not unlocked, or the request's session not in front (fix
                // round 11, Opus N2): asked again a `rearm` later.
                last = Some(now);
            } else if due && w.state.key_may_check(w.user, w.token, w.generation, now) {
                if let Some(running) = self.claim(w.user, false) {
                    let pin = if w.policy.asks_pin() {
                        w.state.take_key_pin(w.user, w.token, w.generation)
                    } else {
                        None
                    };
                    if !w.policy.asks_pin() || pin.is_some() {
                        last = Some(now);
                        let touched = self.run_one(w, pin, now);
                        drop(running);
                        if w.policy.asks_pin() {
                            w.state.key_pin_spent(w.user, w.token);
                        }
                        if touched && self.touched(w, now) {
                            return;
                        }
                        continue;
                    }
                }
            }
            std::thread::sleep(self.rearm.min(KEY_POLL));
        }
    }

    /// One check that started at `started`, supervised. True when it
    /// ended in a touch. It is stopped the moment the watch ends, the
    /// record no longer allows it (the round waits or parks, another watch
    /// took over, the card was re-shown or re-acknowledged), or the
    /// daemon's deadline passes.
    fn run_one(&self, w: &Watched<'_>, pin: Option<Secret>, started: Instant) -> bool {
        let mut run = match self.host.start(w.user, w.lane, pin) {
            Ok(run) => run,
            Err(e) => {
                log::warn!("consent: the key check for {} did not start: {}", w.user, e);
                return false;
            }
        };
        loop {
            if let Some(touched) = run.poll() {
                return touched;
            }
            let late = started.elapsed() > self.deadline;
            if late
                || w.stop.load(Ordering::SeqCst)
                || !w
                    .state
                    .key_may_check(w.user, w.token, w.generation, started)
                || !self.request_in_front(w.state, w.user, w.bind)
            {
                if late {
                    log::warn!(
                        "consent: the key check for {} ran past its deadline",
                        w.user
                    );
                }
                run.stop();
                return false;
            }
            std::thread::sleep(KEY_SUPERVISE);
        }
    }

    /// A touch the helper reported, written to the record if it still
    /// counts there.
    fn touched(&self, w: &Watched<'_>, started: Instant) -> bool {
        // A watch told to stop takes no touch, even one that answered in
        // the same instant.
        if w.stop.load(Ordering::SeqCst) {
            log::info!(
                "consent: a security key touch for {} came as its watch ended; it answers nothing",
                w.user
            );
            return false;
        }
        // The request's session in front at the touch (fix round 11, Opus
        // N2), and the one verdict asked again by the commit itself, under
        // the record's lock (R1).
        if !self.request_in_front(w.state, w.user, w.bind) {
            log::info!(
                "consent: a security key touch for {} came with its session in the background; it answers nothing",
                w.user
            );
            return false;
        }
        let counted = w.state.key_touched(
            w.user,
            w.token,
            w.generation,
            started,
            &|| self.look(w.user, w.bind),
            &|| self.request_in_front(w.state, w.user, w.bind),
        );
        if counted {
            log::info!("consent: security key touched for {}", w.user);
        } else {
            log::info!(
                "consent: a security key touch for {} came after its card; it answers nothing",
                w.user
            );
        }
        counted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::consent::state::{test_state, Answer};
    use crate::consent::window::{Dialog, ACK_DWELL};
    use std::sync::atomic::AtomicUsize;

    /// A look for a commit: the compositor's unlocked on a desktop.
    fn unlocked_look() -> (LockState, Desktop) {
        (LockState::Unlocked, Desktop::Some)
    }

    /// A look for a commit: the compositor's lock on a desktop.
    fn locked_look() -> (LockState, Desktop) {
        (LockState::Locked, Desktop::Some)
    }

    /// One check the fake launcher started. It waits for the test's
    /// answer, as pam_u2f waits for a touch, unless the key is unplugged,
    /// when it answers false at once. Its stop takes the launcher's
    /// `stop_delay`, as a unit's stop takes time.
    struct FakeRun {
        host: &'static FakeHost,
        answer: Arc<Mutex<Option<bool>>>,
        stopped: Arc<AtomicBool>,
    }

    impl KeyRun for FakeRun {
        fn poll(&mut self) -> Option<bool> {
            if self.host.unplugged {
                return Some(false);
            }
            self.answer.lock().unwrap().take()
        }

        fn stop(&mut self) {
            std::thread::sleep(self.host.stop_delay);
            self.stopped.store(true, Ordering::SeqCst);
        }
    }

    impl Drop for FakeRun {
        fn drop(&mut self) {
            self.host.running.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// A check the fake launcher started: when, its answer, whether it was
    /// stopped, and the PIN it was handed.
    type Started = (
        Instant,
        Arc<Mutex<Option<bool>>>,
        Arc<AtomicBool>,
        Option<String>,
    );

    /// A launcher whose checks the test answers and whose session it locks.
    struct FakeHost {
        offer: Result<KeyPolicy, KeyOff>,
        unplugged: bool,
        stop_delay: Duration,
        locked: AtomicBool,
        /// The compositor gives no answer.
        unknown: AtomicBool,
        /// logind's records: 0 a desktop, 1 none (a text console), 2
        /// unreadable.
        desktop: std::sync::atomic::AtomicU8,
        runs: Mutex<Vec<Started>>,
        running: AtomicUsize,
        most_running: AtomicUsize,
        /// Only this user's session is locked.
        locked_user: Mutex<Option<&'static str>>,
        /// Lock questions asked, and how long each takes.
        asks: AtomicUsize,
        ask_delay: Mutex<Duration>,
    }

    impl KeyHost for FakeHost {
        fn offer(&self, _user: &str, _lane: &str) -> Result<KeyPolicy, KeyOff> {
            self.offer.clone()
        }

        fn start(
            &self,
            _user: &str,
            _lane: &str,
            pin: Option<Secret>,
        ) -> std::io::Result<Box<dyn KeyRun>> {
            let now = self.running.fetch_add(1, Ordering::SeqCst) + 1;
            self.most_running.fetch_max(now, Ordering::SeqCst);
            let answer = Arc::new(Mutex::new(None));
            let stopped = Arc::new(AtomicBool::new(false));
            self.runs.lock().unwrap().push((
                Instant::now(),
                Arc::clone(&answer),
                Arc::clone(&stopped),
                pin.as_deref().map(str::to_string),
            ));
            Ok(Box::new(FakeRun {
                host: FakeHost::leaked(self),
                answer,
                stopped,
            }))
        }

        fn desktop(&self) -> Desktop {
            match self.desktop.load(Ordering::SeqCst) {
                0 => Desktop::Some,
                1 => Desktop::None,
                _ => Desktop::Unreadable,
            }
        }

        fn uid_of(&self, user: &str) -> Option<u32> {
            Some(200_000 + user.bytes().map(u32::from).sum::<u32>())
        }

        fn lock_state(&self, user: &str, _bind: &Bind) -> LockState {
            self.asks.fetch_add(1, Ordering::SeqCst);
            let delay = *self.ask_delay.lock().unwrap();
            // The answer is the compositor as of the ask; the look then
            // takes its time, as a unit does.
            let answer = if let Some(u) = *self.locked_user.lock().unwrap() {
                if u == user {
                    LockState::Locked
                } else {
                    LockState::Unlocked
                }
            } else if self.unknown.load(Ordering::SeqCst) {
                LockState::Unknown
            } else if self.locked.load(Ordering::SeqCst) {
                LockState::Locked
            } else {
                LockState::Unlocked
            };
            std::thread::sleep(delay);
            answer
        }
    }

    impl FakeHost {
        fn with(offer: Result<KeyPolicy, KeyOff>, unplugged: bool) -> &'static FakeHost {
            Box::leak(Box::new(FakeHost {
                offer,
                unplugged,
                stop_delay: Duration::ZERO,
                locked: AtomicBool::new(false),
                unknown: AtomicBool::new(false),
                desktop: std::sync::atomic::AtomicU8::new(0),
                runs: Mutex::new(Vec::new()),
                running: AtomicUsize::new(0),
                most_running: AtomicUsize::new(0),
                locked_user: Mutex::new(None),
                asks: AtomicUsize::new(0),
                ask_delay: Mutex::new(Duration::ZERO),
            }))
        }

        fn new(unplugged: bool) -> &'static FakeHost {
            FakeHost::with(Ok(KeyPolicy::default()), unplugged)
        }

        /// A launcher whose stops take `delay`, as a unit's stop takes time.
        fn slow_to_stop(delay: Duration) -> &'static FakeHost {
            Box::leak(Box::new(FakeHost {
                offer: Ok(KeyPolicy::default()),
                unplugged: false,
                stop_delay: delay,
                locked: AtomicBool::new(false),
                unknown: AtomicBool::new(false),
                desktop: std::sync::atomic::AtomicU8::new(0),
                runs: Mutex::new(Vec::new()),
                running: AtomicUsize::new(0),
                most_running: AtomicUsize::new(0),
                locked_user: Mutex::new(None),
                asks: AtomicUsize::new(0),
                ask_delay: Mutex::new(Duration::ZERO),
            }))
        }

        /// Every fake host is leaked by its constructor, so a reference to
        /// one lives as long as the test binary.
        fn leaked(&self) -> &'static FakeHost {
            // SAFETY: both constructors leak the box they build.
            unsafe { &*(self as *const FakeHost) }
        }

        /// The latest check ends with `ok`.
        fn touch(&self, ok: bool) {
            if let Some(run) = self.runs.lock().unwrap().last() {
                *run.1.lock().unwrap() = Some(ok);
            }
        }

        fn checks(&self) -> usize {
            self.runs.lock().unwrap().len()
        }

        fn running(&self) -> usize {
            self.running.load(Ordering::SeqCst)
        }

        /// Whether check `n` (from 0) was stopped.
        fn stopped(&self, n: usize) -> bool {
            self.runs
                .lock()
                .unwrap()
                .get(n)
                .is_some_and(|r| r.2.load(Ordering::SeqCst))
        }

        /// The PIN check `n` was handed.
        fn pin(&self, n: usize) -> Option<String> {
            self.runs.lock().unwrap().get(n).and_then(|r| r.3.clone())
        }
    }

    fn lane(host: &'static FakeHost, rearm: Duration, deadline: Duration) -> &'static KeyLane {
        Box::leak(Box::new(KeyLane::new(host, rearm, deadline)))
    }

    /// Up to two seconds for `cond` to hold.
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

    /// A card up for `user`'s live request: its Dialog, acknowledged a
    /// dwell ago, so the key may be asked at once.
    fn card(st: &'static ConsentState, user: &str) -> (Dialog, String) {
        let d = Dialog::new(&Config::default(), user, st).unwrap();
        let token = d.token().to_string();
        assert!(st.ack(user, Some(&token)));
        st.backdate_ack(user, ACK_DWELL);
        (d, token)
    }

    const SHORT: Duration = Duration::from_millis(50);
    const LONG: Duration = Duration::from_secs(60);

    /// The key wins: a touch at the card's request approves it, the card
    /// is told the key works while the watch runs, and once the touch has
    /// counted the key is asked no more.
    #[test]
    fn a_touch_approves_the_request_it_was_armed_on() {
        let user = "faceauth-key-win-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let host = FakeHost::new(false);
        let watch = lane(host, SHORT, LONG)
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .expect("an offered key arms");
        assert_eq!(
            st.key_for_payload(user, &tok).pair(),
            (true, false),
            "the card is told the key works"
        );
        assert!(eventually(|| host.checks() == 1), "the watch asks the key");
        assert!(!st.answered(user), "nothing is answered before the touch");
        host.touch(true);
        assert!(eventually(|| st.answered(user)));
        assert!(matches!(st.poll(user), Some(Answer::Key)));
        std::thread::sleep(SHORT * 4);
        assert_eq!(host.checks(), 1, "a touch that counted ends the checks");
        drop(watch);
        assert_eq!(
            st.key_for_payload(user, &tok).pair(),
            (false, false),
            "the next payload says the key is off"
        );
    }

    /// A: no check starts until the dwell has passed since the card's
    /// acknowledgment, and a check that started before the latest
    /// acknowledgment's dwell counts for nothing.
    #[test]
    fn the_key_waits_out_the_dwell_after_the_acknowledgment() {
        let user = "faceauth-key-dwell-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let d = Dialog::new(&Config::default(), user, st).unwrap();
        let tok = d.token().to_string();
        assert!(st.ack(user, Some(&tok)));
        let host = FakeHost::new(false);
        let _watch = lane(host, SHORT, LONG)
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        std::thread::sleep(SHORT * 4);
        assert_eq!(host.checks(), 0, "no check inside the dwell");
        st.backdate_ack(user, ACK_DWELL);
        assert!(
            eventually(|| host.checks() == 1),
            "the key is asked once the dwell has passed"
        );
        let g = st.key_armed_now(user).unwrap();
        let before = Instant::now() - ACK_DWELL * 2;
        assert!(
            !st.key_touched(user, &tok, g, before, &unlocked_look, &|| true),
            "a check that started before the dwell counts for nothing"
        );
    }

    /// A: a rider armed while a check waits for a touch changes what the
    /// approval grants. The check is stopped and its touch counts for
    /// nothing; the card is shown the rider and acknowledges it again, and
    /// only a check that starts a dwell after that counts, carrying the
    /// rider as a nod would.
    #[test]
    fn a_rider_armed_mid_check_stops_it_and_its_touch_does_not_count() {
        let user = "faceauth-key-rider-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (mut d, tok) = card(st, user);
        st.rider_for_payload(user, &tok, true, true);
        st.set_face_present(user, true);
        let host = FakeHost::new(false);
        let _watch = lane(host, SHORT, LONG)
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(
            eventually(|| host.running() == 1),
            "the check waits for a touch"
        );
        let g = st.key_armed_now(user).unwrap();
        let first_started = host.runs.lock().unwrap()[0].0;
        assert_eq!(st.arm_passwordless(user, &tok, 15), Ok(()));
        assert!(eventually(|| host.stopped(0)), "the rider stops the check");
        assert!(
            !st.key_touched(user, &tok, g, first_started, &unlocked_look, &|| true),
            "a touch on that check counts for nothing"
        );
        assert!(!st.answered(user));
        // The flow re-shows the card naming the rider; it acknowledges it.
        d.reset_ack();
        st.rider_for_payload(user, &tok, true, true);
        assert!(st.ack(user, Some(&tok)));
        std::thread::sleep(SHORT * 3);
        assert_eq!(host.checks(), 1, "nothing is asked inside the new dwell");
        assert!(
            !st.key_touched(user, &tok, g, first_started, &unlocked_look, &|| true),
            "the old check is older than the new acknowledgment"
        );
        st.backdate_ack(user, ACK_DWELL);
        assert!(
            eventually(|| host.checks() == 2),
            "a new check starts after the dwell"
        );
        host.touch(true);
        assert!(eventually(|| st.answered(user)));
        assert!(matches!(st.poll(user), Some(Answer::Key)));
        assert_eq!(
            st.take_passwordless(user, &tok),
            Some(15),
            "a touch at a card that showed the rider carries it, as a nod does"
        );
    }

    /// The nods win while the check still waits for a touch: the round
    /// finishes its watch, and the helper is stopped before `finish`
    /// returns, which frees the key. Its answer is never read, and no
    /// other check starts.
    #[test]
    fn a_nod_that_wins_first_stops_the_helper() {
        let user = "faceauth-key-nod-wins-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let host = FakeHost::new(false);
        let lane = lane(host, SHORT, LONG);
        let watch = lane
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(
            eventually(|| host.running() == 1),
            "the check waits for a touch"
        );
        watch.finish();
        assert!(host.stopped(0), "the helper is stopped when finish returns");
        assert_eq!(host.running(), 0);
        assert!(
            lane.claim(user, false).is_some(),
            "the check gave its place back"
        );
        std::thread::sleep(SHORT * 4);
        assert!(!st.answered(user));
        assert_eq!(host.checks(), 1, "and the finished watch started no other");
    }

    /// H: on a refusal the round finishes its watch before the answer goes
    /// back to PAM, and `finish` returns only once the helper's stop has
    /// completed, however long the stop takes, so sudo's key-fallback line
    /// finds the key free.
    #[test]
    fn a_refusal_stops_the_helper_before_the_answer_goes_back() {
        let user = "faceauth-key-refusal-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let host = FakeHost::slow_to_stop(Duration::from_millis(300));
        let watch = lane(host, SHORT, LONG)
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(eventually(|| host.running() == 1));
        st.push_answer(user, Answer::Dismiss);
        let t = Instant::now();
        watch.finish();
        assert!(host.stopped(0), "the stop has completed");
        assert!(
            t.elapsed() >= Duration::from_millis(300),
            "finish waited for it"
        );
        assert_eq!(host.running(), 0, "nothing holds the key");
        assert!(
            matches!(st.poll(user), Some(Answer::Dismiss)),
            "the refusal stands"
        );
    }

    /// A second watch armed on the same request takes over: the first
    /// one's generation is no longer armed, so its check is stopped, and
    /// the new watch asks the key only once that check has ended. Never
    /// two checks at once, and only the new watch's touch counts.
    #[test]
    fn a_newer_watch_takes_over_and_one_check_runs_per_user() {
        let user = "faceauth-key-takeover-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let host = FakeHost::new(false);
        let lane = lane(host, SHORT, LONG);
        let _first = lane
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(eventually(|| host.running() == 1));
        let _second = lane
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(eventually(|| host.stopped(0)), "the older check is stopped");
        assert!(
            eventually(|| host.checks() == 2),
            "the newer watch asks the key"
        );
        assert_eq!(
            host.most_running.load(Ordering::SeqCst),
            1,
            "never two checks at once"
        );
        host.touch(true);
        assert!(eventually(|| st.answered(user)));
        assert!(matches!(st.poll(user), Some(Answer::Key)));
    }

    /// D: a touch carries its watch's generation. One from a generation the
    /// record has moved past (a park, a wait, a newer watch) counts for
    /// nothing, even on the same request with the card up; the current
    /// generation's counts.
    #[test]
    fn a_stale_generation_is_refused() {
        let user = "faceauth-key-generation-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let now = Instant::now();
        let unlocked = unlocked_look;
        let old = st.arm_key(user, &tok, false).unwrap();
        st.key_off(user, true);
        let new = st.arm_key(user, &tok, false).unwrap();
        assert_ne!(old, new);
        assert!(!st.key_may_check(user, &tok, old, now));
        assert!(
            !st.key_touched(user, &tok, old, now, &unlocked, &|| true),
            "a stale touch counts for nothing"
        );
        assert!(!st.answered(user));
        st.disarm_key(user, &tok, old);
        assert!(
            st.key_may_check(user, &tok, new, now),
            "ending an old watch leaves the new one armed"
        );
        assert!(st.key_touched(user, &tok, new, now, &unlocked, &|| true));
        assert!(matches!(st.poll(user), Some(Answer::Key)));
    }

    /// C: a touch on a locked session counts for nothing, whatever the
    /// record says; a touch already queued, and a PIN not yet used, are
    /// dropped when the request parks, and a wait that does not park keeps
    /// the touch for the scan to take.
    #[test]
    fn a_touch_on_a_locked_session_or_queued_at_a_park_approves_nothing() {
        let user = "faceauth-key-lock-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let now = Instant::now();
        let g = st.arm_key(user, &tok, false).unwrap();
        assert!(
            !st.key_touched(user, &tok, g, now, &locked_look, &|| true),
            "locked: refused"
        );
        assert!(!st.answered(user));
        // R2: the lock it saw latched the user and took the card off the
        // key; after the unlock, a commit waits out the hold.
        st.observe_lock(user, LockState::Unlocked);
        let g = st.arm_key(user, &tok, false).unwrap();
        assert!(
            !st.key_touched(user, &tok, g, now, &unlocked_look, &|| true),
            "inside the hold after the unlock"
        );
        st.set_key_unlock_hold(Duration::ZERO);
        assert!(st.key_touched(user, &tok, g, now, &unlocked_look, &|| true));
        st.key_off(user, false);
        assert!(st.answered(user), "a wait keeps a touch already queued");
        let g = st.arm_key(user, &tok, true).unwrap();
        st.poll(user);
        assert_eq!(
            st.set_key_pin(user, Some(&tok), Secret::new("123456".into())),
            Ok(())
        );
        assert!(st.key_touched(user, &tok, g, now, &unlocked_look, &|| true));
        st.key_off(user, true);
        assert!(!st.answered(user), "a park drops the queued touch");
        let g = st.arm_key(user, &tok, true).unwrap();
        assert!(st.take_key_pin(user, &tok, g).is_none(), "and the PIN");
        let host = FakeHost::new(false);
        host.locked.store(true, Ordering::SeqCst);
        let watch = lane(host, SHORT, LONG)
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        std::thread::sleep(SHORT * 5);
        assert_eq!(
            host.checks(),
            0,
            "R1: no check starts while the one verdict says locked"
        );
        assert_eq!(
            st.key_armed_now(user),
            None,
            "R2: the lock seen took the card off the key until the round re-arms it"
        );
        drop(watch);
        host.locked.store(false, Ordering::SeqCst);
        let _watch = lane(host, SHORT, LONG)
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(eventually(|| host.running() == 1), "unlocked: asked");
        host.locked.store(true, Ordering::SeqCst);
        host.touch(true);
        std::thread::sleep(SHORT * 3);
        assert!(
            !st.answered(user),
            "the watch's touch on a session locked at the commit is refused"
        );
    }

    /// A touch belongs to the user whose request armed it: when alice's
    /// request ends her watch's check is stopped, and nothing of hers
    /// reaches bob's request; the record takes no touch or watch across
    /// users or tokens.
    #[test]
    fn a_touch_for_another_user_answers_nothing() {
        let (alice, bob) = ("faceauth-key-alice", "faceauth-key-bob");
        let st = test_state();
        let host = FakeHost::new(false);
        let lane = lane(host, SHORT, LONG);
        let turn = st.test_live(1000, alice);
        let (d, tok_a) = card(st, alice);
        let watch = lane
            .arm(st, alice, &tok_a, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(eventually(|| host.running() == 1));
        let g_a = st.key_armed_now(alice).unwrap();
        drop(d);
        drop(turn);
        let _turn = st.test_live(1001, bob);
        let (_d, tok_b) = card(st, bob);
        assert!(
            eventually(|| host.stopped(0)),
            "alice's check is stopped with her request"
        );
        assert!(
            lane.arm(st, alice, &tok_b, "sudo", &Bind::OnlyDesktop)
                .is_none(),
            "alice's watch cannot arm on bob's request"
        );
        let now = Instant::now();
        let g_b = st.arm_key(bob, &tok_b, false).unwrap();
        assert!(
            !st.key_touched(alice, &tok_b, g_b, now, &unlocked_look, &|| true),
            "no touch for another user"
        );
        assert!(
            !st.key_touched(bob, &tok_a, g_a, now, &unlocked_look, &|| true),
            "or under another request's token"
        );
        assert!(!st.answered(bob));
        drop(watch);
    }

    /// A key the card does not offer (none registered, or a line it cannot
    /// mirror) gets no watch: the card is not told the key works, and the
    /// key is never asked.
    #[test]
    fn a_key_not_offered_arms_nothing() {
        let user = "faceauth-key-none-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        for off in [
            KeyOff::NotSetUp("no key".into()),
            KeyOff::Withheld("`max_devices=2`".into()),
        ] {
            let host = FakeHost::with(Err(off), false);
            assert!(lane(host, SHORT, LONG)
                .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
                .is_none());
            assert_eq!(st.key_for_payload(user, &tok).pair(), (false, false));
            std::thread::sleep(SHORT * 3);
            assert_eq!(host.checks(), 0);
        }
    }

    /// E: on a lane that asks for a PIN, the card is told to show its PIN
    /// field, no check runs until the card has sent a PIN, and each PIN
    /// goes to one check alone, handed to the launcher and nowhere else,
    /// so a wrong one is never tried twice against the key's retry count.
    #[test]
    fn a_pin_goes_to_one_check_and_only_where_the_line_asks_for_one() {
        let user = "faceauth-key-pin-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        assert_eq!(
            st.set_key_pin(user, Some(&tok), Secret::new("123456".into())),
            Err("the key asks for no PIN now"),
            "no PIN before the key is armed"
        );
        let host = FakeHost::with(
            Ok(KeyPolicy {
                pin: Some(true),
                uv: None,
            }),
            true,
        );
        let _watch = lane(host, SHORT, LONG)
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert_eq!(
            st.key_for_payload(user, &tok).pair(),
            (true, true),
            "the card shows its PIN field"
        );
        std::thread::sleep(SHORT * 3);
        assert_eq!(host.checks(), 0, "no check without a PIN");
        assert_eq!(
            st.set_key_pin(user, Some("not-the-token"), Secret::new("123456".into())),
            Err("no pending request")
        );
        assert_eq!(
            st.set_key_pin(user, Some(&tok), Secret::new("123456".into())),
            Ok(())
        );
        assert!(eventually(|| host.checks() == 1));
        assert_eq!(
            host.pin(0).as_deref(),
            Some("123456"),
            "the PIN goes to the check"
        );
        std::thread::sleep(SHORT * 4);
        assert_eq!(
            host.checks(),
            1,
            "a PIN serves one check, which failed here"
        );
        assert_eq!(
            st.set_key_pin(user, Some(&tok), Secret::new("654321".into())),
            Ok(())
        );
        assert!(eventually(|| host.checks() == 2));
        assert_eq!(host.pin(1).as_deref(), Some("654321"));
        let plain = FakeHost::new(true);
        let user2 = "faceauth-key-nopin-user";
        let _turn2 = {
            drop(_watch);
            drop(_d);
            drop(_turn);
            st.test_live(1000, user2)
        };
        let (_d2, tok2) = card(st, user2);
        let _w2 = lane(plain, SHORT, LONG)
            .arm(st, user2, &tok2, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert_eq!(st.key_for_payload(user2, &tok2).pair(), (true, false));
        assert_eq!(
            st.set_key_pin(user2, Some(&tok2), Secret::new("123456".into())),
            Err("the key asks for no PIN now"),
            "a lane without a PIN takes none"
        );
        assert!(eventually(|| plain.checks() >= 1));
        assert_eq!(plain.pin(0), None, "and its checks are handed none");
    }

    /// With no key plugged in pam_u2f answers at once; the watch asks
    /// again every `rearm`, so a key plugged in mid-request is found, and
    /// stops asking when the watch ends.
    #[test]
    fn with_no_key_plugged_in_the_check_is_rearmed_every_interval() {
        let user = "faceauth-key-unplugged-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let host = FakeHost::new(true);
        let rearm = Duration::from_millis(80);
        let watch = lane(host, rearm, LONG)
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        std::thread::sleep(Duration::from_millis(500));
        let starts: Vec<Instant> = host.runs.lock().unwrap().iter().map(|r| r.0).collect();
        assert!(
            (3..=8).contains(&starts.len()),
            "{} checks in 500 ms at an 80 ms re-arm",
            starts.len()
        );
        for w in starts.windows(2) {
            assert!(
                w[1] - w[0] >= rearm * 9 / 10,
                "checks {:?} apart",
                w[1] - w[0]
            );
        }
        assert!(!st.answered(user), "a check with no key answers nothing");
        drop(watch);
        std::thread::sleep(SHORT * 3);
        let n = host.checks();
        std::thread::sleep(rearm * 3);
        assert_eq!(host.checks(), n, "no check after the watch ends");
    }

    /// F: a check that never ends is stopped at the daemon's own deadline,
    /// however its unit behaves, and the next one starts after it.
    #[test]
    fn a_check_past_the_deadline_is_stopped() {
        let user = "faceauth-key-deadline-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let host = FakeHost::new(false);
        let _watch = lane(host, SHORT, Duration::from_millis(150))
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(eventually(|| host.stopped(0)), "stopped at the deadline");
        assert!(
            eventually(|| host.checks() >= 2),
            "and the key is asked again"
        );
        assert!(!st.answered(user));
    }

    /// The record's rules for a touch: no check starts and no touch counts
    /// before the card has acknowledged the request or after its watch
    /// ended; the card's own answer is never displaced, so a dismissal
    /// stays a refusal; "Ready to nod" gives way; and the socket cannot
    /// answer with the key.
    #[test]
    fn a_touch_counts_only_at_an_acknowledged_card_and_never_over_its_answer() {
        let user = "faceauth-key-record-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let d = Dialog::new(&Config::default(), user, st).unwrap();
        let tok = d.token().to_string();
        let unlocked = unlocked_look;
        let g = st.arm_key(user, &tok, false).unwrap();
        let later = Instant::now() + ACK_DWELL * 2;
        assert!(
            !st.key_may_check(user, &tok, g, later),
            "no check before the acknowledgment"
        );
        assert!(
            !st.key_touched(user, &tok, g, later, &unlocked, &|| true),
            "and no touch counts"
        );
        assert!(st.ack(user, Some(&tok)));
        assert!(st.key_may_check(user, &tok, g, later));
        assert!(
            st.answer(user, Some(&tok), Answer::Key).is_err(),
            "the socket cannot answer with the key"
        );
        assert!(!st.answered(user));
        st.answer(user, Some(&tok), Answer::Dismiss).unwrap();
        assert!(
            !st.key_touched(user, &tok, g, later, &unlocked, &|| true),
            "a touch never displaces a dismissal"
        );
        assert!(matches!(st.poll(user), Some(Answer::Dismiss)));
        st.answer(user, Some(&tok), Answer::Rearm).unwrap();
        assert!(
            st.key_touched(user, &tok, g, later, &unlocked, &|| true),
            "Ready to nod gives way"
        );
        assert!(matches!(st.poll(user), Some(Answer::Key)));
        st.disarm_key(user, &tok, g);
        assert!(!st.key_may_check(user, &tok, g, later));
        assert!(
            !st.key_touched(user, &tok, g, later, &unlocked, &|| true),
            "no touch once the watch ended"
        );
        drop(d);
        assert!(
            st.arm_key(user, &tok, false).is_none(),
            "the token dies with its request"
        );
    }

    /// E, round 4: while face is set up the lane's key-fallback line
    /// decides. `cue`, a PIN and user verification are mirrored into the
    /// matching private stack; any other option or control, or a second
    /// line, keeps the key off, with the reason; a commented line is not a
    /// policy. A pam_u2f line in either stack, hand-added or left over,
    /// keeps the key off every lane, since it reads the key outside the
    /// daemon.
    #[test]
    fn the_lanes_key_line_is_mirrored_or_keeps_the_key_off() {
        let stack = |line: &str| {
            format!("#%PAM-1.0\nauth sufficient pam_faceauth.so socket=/run/faceauth/sock consent\n{}\nauth include system-auth\n", line)
        };
        let ours =
            "auth      sufficient pam_faceauth.so socket=/run/faceauth/sock key-fallback cue";
        // Round 5 (Codex 4): a word absent, `=0` and `=1` stay three things,
        // each with its own private stack.
        let base = "auth sufficient pam_faceauth.so socket=/run/faceauth/sock key-fallback cue";
        let mut services = Vec::new();
        for (words, pin, uv, service) in [
            ("", None, None, "faceauth-key"),
            (" pinverification=1", Some(true), None, "faceauth-key-pin"),
            (
                " pinverification=0",
                Some(false),
                None,
                "faceauth-key-nopin",
            ),
            (" userverification=1", None, Some(true), "faceauth-key-uv"),
            (
                " userverification=0",
                None,
                Some(false),
                "faceauth-key-nouv",
            ),
            (
                " pinverification=1 userverification=1",
                Some(true),
                Some(true),
                "faceauth-key-pin-uv",
            ),
            (
                " pinverification=1 userverification=0",
                Some(true),
                Some(false),
                "faceauth-key-pin-nouv",
            ),
            (
                " pinverification=0 userverification=1",
                Some(false),
                Some(true),
                "faceauth-key-nopin-uv",
            ),
            (
                " pinverification=0 userverification=0",
                Some(false),
                Some(false),
                "faceauth-key-nopin-nouv",
            ),
        ] {
            let line = format!("{}{}", base, words);
            services.push(service);
            for lane in ["sudo", "polkit"] {
                let p = lane_policy(lane, Some(&stack(&line)), None)
                    .unwrap_or_else(|e| panic!("{}: {}", line, e));
                assert_eq!((p.pin, p.uv, p.service()), (pin, uv, service), "{}", line);
            }
        }
        services.sort();
        services.dedup();
        assert_eq!(services.len(), 9, "one stack per combination");
        for (line, pin, uv, service) in [
            (ours, None, None, "faceauth-key"),
            (
                "auth sufficient pam_faceauth.so key-fallback",
                None,
                None,
                "faceauth-key",
            ),
        ] {
            for lane in ["sudo", "polkit"] {
                let p = lane_policy(lane, Some(&stack(line)), None)
                    .unwrap_or_else(|e| panic!("{}: {}", line, e));
                assert_eq!((p.pin, p.uv, p.service()), (pin, uv, service), "{}", line);
            }
        }
        let commented = format!(
            "# auth sufficient pam_faceauth.so key-fallback max_devices=2\n# auth sufficient pam_u2f.so cue\n{}",
            stack(ours)
        );
        assert_eq!(
            lane_policy("sudo", Some(&commented), None),
            Ok(KeyPolicy::default())
        );
        for custom in [
            "auth sufficient pam_faceauth.so socket=/run/faceauth/sock key-fallback pinverification=1 pinverification=0",
            "auth sufficient pam_faceauth.so socket=/run/faceauth/sock key-fallback userverification=1 userverification=1",
            "auth sufficient pam_faceauth.so socket=/run/faceauth/sock key-fallback cue cue",
            "auth sufficient pam_faceauth.so socket=/run/faceauth/sock key-fallback timeout=45",
            "auth sufficient pam_faceauth.so socket=/run/faceauth/sock key-fallback max_devices=2",
            "auth sufficient pam_faceauth.so socket=/run/faceauth/sock key-fallback pinverification=2",
            "auth required pam_faceauth.so socket=/run/faceauth/sock key-fallback",
            "auth sufficient pam_faceauth.so socket=/tmp/sock key-fallback",
            "auth sufficient /usr/lib/security/pam_faceauth.so key-fallback",
        ] {
            match lane_policy("sudo", Some(&stack(custom)), None) {
                Err(KeyOff::Withheld(why)) => assert!(why.contains("/etc/pam.d/sudo"), "{}", why),
                other => panic!("{}: {:?}", custom, other),
            }
        }
        let two = format!("{}\n{}", ours, ours);
        assert!(matches!(
            lane_policy("sudo", Some(&stack(&two)), None),
            Err(KeyOff::Withheld(_))
        ));
        // A pam_u2f line anywhere in sudo or polkit-1: no card key, no lock
        // lane, no fallback, whichever stack it is in.
        let u2f = "auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2";
        let with_u2f = format!("{}\n{}", ours, u2f);
        for lane in ["sudo", "polkit", "unlock"] {
            match lane_policy(lane, Some(&stack(&with_u2f)), None) {
                Err(KeyOff::Withheld(why)) => {
                    assert!(why.contains("pam_u2f line in /etc/pam.d/"), "{}", why)
                }
                other => panic!("{}: {:?}", lane, other),
            }
            match lane_policy(lane, Some(&stack(ours)), Some(&stack(u2f))) {
                Err(KeyOff::Withheld(why)) => assert!(why.contains("outside faceauthd"), "{}", why),
                other => panic!("{} with pam_u2f in the other stack: {:?}", lane, other),
            }
        }
        assert!(matches!(
            lane_policy("sudo", Some("auth include system-auth\n"), None),
            Err(KeyOff::NotSetUp(_))
        ));
        assert!(matches!(
            lane_policy("polkit", None, None),
            Err(KeyOff::NotSetUp(_))
        ));
        assert!(matches!(
            lane_policy("su", Some(&stack(ours)), None),
            Err(KeyOff::NotSetUp(_))
        ));
    }

    /// pam_u2f's key file names a user by the whole first field, with a
    /// credential after it.
    #[test]
    fn the_key_file_names_a_user_by_the_whole_first_field() {
        let file = "alice:handle,key,es256,+presence\nmallory:h2,k2,es256,+presence:h3,k3,es256,+presence\nbob:\n";
        assert!(authfile_names(file, "alice"));
        assert!(authfile_names(file, "mallory"));
        assert!(!authfile_names(file, "al"), "a prefix is not the name");
        assert!(!authfile_names(file, "alice:handle"));
        assert!(
            !authfile_names(file, "bob"),
            "a name with no credential has no key"
        );
        assert!(!authfile_names(file, ""));
        assert!(!authfile_names("", "alice"));
    }

    /// F: the unit is named for a user only after the name is checked,
    /// escaped as `systemd-escape` would.
    #[test]
    fn the_unit_name_is_a_checked_and_escaped_user() {
        assert_eq!(
            key_unit("mellis").as_deref(),
            Some("faceauth-key-mellis.service")
        );
        assert_eq!(
            key_unit("al-ice").as_deref(),
            Some("faceauth-key-al\\x2dice.service")
        );
        assert_eq!(key_unit("_x9").as_deref(), Some("faceauth-key-_x9.service"));
        for bad in [
            "",
            "-a",
            "9a",
            "Alice",
            "a b",
            "../x",
            "a/b",
            "a.b",
            "a$",
            "a\\x2f",
            &"a".repeat(33),
        ] {
            assert_eq!(key_unit(bad), None, "{:?}", bad);
        }
        assert_eq!(unit_escape("a/b.c-d"), "a-b.c\\x2dd");
        assert_eq!(unit_escape(".x"), "\\x2ex");
    }

    /// F: the command that runs a check carries the unit's sandbox, the
    /// helper, the lane and the user, and nothing else: no PIN on the
    /// command line or in the environment, which holds PATH alone, and
    /// stdin is the pipe the PIN goes down.
    #[test]
    fn the_check_runs_in_its_own_unit_with_the_pin_on_a_pipe() {
        let c = key_command("faceauth-key-mellis.service", "sudo", "mellis");
        assert_eq!(c.get_program(), "/usr/bin/systemd-run");
        let args: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        for want in [
            "--wait",
            "--pipe",
            "--collect",
            "--service-type=exec",
            "--unit=faceauth-key-mellis.service",
        ] {
            assert!(args.iter().any(|a| a == want), "{}", want);
        }
        for p in KEY_UNIT_PROPERTIES {
            assert!(args.contains(&format!("--property={}", p)), "{}", p);
        }
        assert_eq!(&args[args.len() - 3..], [KEY_HELPER, "sudo", "mellis"]);
        let envs: Vec<_> = c
            .get_envs()
            .filter_map(|(k, v)| v.map(|_| k.to_string_lossy().into_owned()))
            .collect();
        assert_eq!(envs, ["PATH"]);
    }

    /// F: the unit's sandbox holds the hidraw nodes and nothing else of the
    /// daemon's reach: no capabilities, no network, a read-only system,
    /// the daemon's state, config and sudoers out of sight, nothing
    /// writable, and a hard runtime cap. The daemon's own unit no longer
    /// holds hidraw at all. Round 19: a stop is SIGTERM, which the helper
    /// answers by cancelling the key's wait, and SIGKILL a second later.
    #[test]
    fn the_helper_unit_is_sandboxed_and_the_daemon_loses_hidraw() {
        let get = |k: &str| -> Vec<&str> {
            KEY_UNIT_PROPERTIES
                .iter()
                .filter_map(|p| p.split_once('='))
                .filter(|(key, _)| *key == k)
                .map(|(_, v)| v)
                .collect()
        };
        for (k, v) in [
            ("RuntimeMaxSec", "30s"),
            ("CapabilityBoundingSet", ""),
            ("AmbientCapabilities", ""),
            ("NoNewPrivileges", "yes"),
            ("ProtectSystem", "strict"),
            ("ProtectHome", "yes"),
            ("PrivateTmp", "yes"),
            ("PrivateNetwork", "yes"),
            ("RestrictAddressFamilies", "AF_NETLINK"),
            ("ReadOnlyPaths", "/dev"),
            ("PrivatePIDs", "yes"),
            ("KillSignal", "SIGTERM"),
            ("TimeoutStopSec", "1s"),
            ("SendSIGKILL", "yes"),
            ("IPAddressDeny", "any"),
            ("DevicePolicy", "closed"),
            ("MemoryDenyWriteExecute", "yes"),
            ("RestrictSUIDSGID", "yes"),
            ("SystemCallFilter", "@system-service"),
        ] {
            assert_eq!(get(k), [v], "{}", k);
        }
        assert_eq!(
            get("DeviceAllow"),
            ["char-hidraw rw"],
            "hidraw and no other device"
        );
        assert!(
            get("ReadWritePaths").is_empty() && get("BindPaths").is_empty(),
            "nothing writable"
        );
        let hidden: Vec<&str> = get("InaccessiblePaths")
            .iter()
            .flat_map(|v| v.split_whitespace())
            .collect();
        for p in [
            "-/var/lib/faceauth",
            "-/run/faceauth",
            "-/etc/sudoers.d",
            "-/etc/sudoers",
            "-/etc/faceauth",
            "-/run/systemd",
            "-/run/dbus",
            "-/var/run/dbus",
            "-/run/udev/control",
            // Fix round 9 (Opus L3): root with no capability still owns
            // these and could read them.
            "-/etc/shadow",
            "-/etc/gshadow",
            "-/etc/ssh",
            "-/boot",
            "-/efi",
            "-/var/lib",
            "-/var/log",
        ] {
            assert!(hidden.contains(&p), "{} is out of reach", p);
        }
        let daemon = include_str!("../../../packaging/faceauth.service");
        assert!(
            !daemon
                .lines()
                .any(|l| l.starts_with("DeviceAllow=") && l.contains("hidraw")),
            "the daemon's unit holds no hidraw node"
        );
    }

    /// Records for the round 11 tests: `id` of `uid`'s, controlled, in
    /// front or not.
    fn fg_records(name: &str) -> (std::path::PathBuf, impl Fn(&str, u32, bool)) {
        let logind = std::env::temp_dir().join(format!("faceauth-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&logind);
        std::fs::create_dir_all(logind.join("sessions")).unwrap();
        let root = logind.clone();
        let rec = move |id: &str, uid: u32, active: bool| {
            let text = format!(
                "UID={}\nTYPE=wayland\nSEAT=seat0\nACTIVE={}\nCONTROLLER=:1.{}\n",
                uid,
                u8::from(active),
                id
            );
            std::fs::write(root.join("sessions").join(id), text).unwrap();
        };
        (logind, rec)
    }

    /// Fix round 11 (Opus N2; Opus's probe
    /// `opus11_probe_background_key_line_takes_the_returning_touch`, turned
    /// around): an approval check starts, runs and commits only while the
    /// request's own session is in the foreground. After a switch away and
    /// back, a background account's key line does not run, so a touch made
    /// at the returning account's lock screen approves nothing of its; it
    /// waits (counted as unknown) and then goes to the password.
    #[test]
    fn a_background_key_line_never_takes_the_returning_touch() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        st.set_key_unlock_hold(Duration::from_millis(80));
        let (alice, bob) = ("faceauth-r11-alice", "faceauth-r11-bob");
        let (a_uid, b_uid) = (host.uid_of(alice).unwrap(), host.uid_of(bob).unwrap());
        let (logind, rec) = fg_records("r11-bg");
        rec("3", a_uid, true);
        rec("7", b_uid, false);
        st.set_logind_root(&logind);
        let gone = || Arc::new(AtomicBool::new(false));
        *host.locked_user.lock().unwrap() = Some(alice);
        st.channel_open(alice);
        let unlock = unlock_on_thread(l, st, alice, gone());
        assert!(eventually(|| host.running() == 1));
        rec("3", a_uid, false);
        rec("7", b_uid, true);
        let _ = unlock.recv_timeout(ANSWER).unwrap();
        assert!(eventually(|| host.running() == 0));
        // Back to alice's VT, still locked, her lock screen not asking yet.
        rec("3", a_uid, true);
        rec("7", b_uid, false);
        let rx = fallback_on_thread(l, st, bob, None, gone());
        let got = rx.recv_timeout(ANSWER).unwrap();
        assert!(
            matches!(&got, Fallback::Wait("unknown", why) if why.contains("foreground")),
            "{:?}",
            got
        );
        assert_eq!(host.running(), 0, "bob's background key line ran no check");
        // In front again, his line runs; sent to the background mid-check,
        // the check stops at once and the touch counts for nothing.
        rec("3", a_uid, false);
        rec("7", b_uid, true);
        *host.locked_user.lock().unwrap() = None;
        std::thread::sleep(Duration::from_millis(100));
        let rx = fallback_on_thread(l, st, bob, None, gone());
        assert!(
            eventually(|| host.running() == 1),
            "in front: his line runs"
        );
        rec("7", b_uid, false);
        let got = rx.recv_timeout(ANSWER).unwrap();
        assert!(matches!(got, Fallback::Wait("unknown", _)), "{:?}", got);
        assert!(eventually(|| host.running() == 0));
        let _ = std::fs::remove_dir_all(&logind);
    }

    /// Fix round 12 (Opus N1; Opus's probe
    /// `opus12_probe_seatless_request_is_always_in_front`, turned around):
    /// logind writes ACTIVE=1 for every session without a seat
    /// (logind-session.c, `session_is_active`), so a seatless session (an
    /// SSH login) is never in front by itself: its request counts as in
    /// front only while the desktop its lock question goes to says
    /// ACTIVE=1 on its seat. Bob's SSH sudo, his desktop in the background
    /// and Alice at the seat, never takes her touch; with his desktop in
    /// front it runs.
    #[test]
    fn a_seatless_request_is_in_front_only_with_its_desktop() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let (alice, bob) = ("faceauth-r12-alice", "faceauth-r12-bob");
        let (a_uid, b_uid) = (host.uid_of(alice).unwrap(), host.uid_of(bob).unwrap());
        let logind = std::env::temp_dir().join(format!("faceauth-r12-seat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&logind);
        std::fs::create_dir_all(logind.join("sessions")).unwrap();
        let w = |id: &str, text: String| {
            std::fs::write(logind.join("sessions").join(id), text).unwrap()
        };
        w(
            "3",
            format!(
                "UID={}\nACTIVE=1\nSTATE=active\nTYPE=wayland\nSEAT=seat0\nCONTROLLER=:1.3\n",
                a_uid
            ),
        );
        w(
            "7",
            format!(
                "UID={}\nACTIVE=0\nSTATE=online\nTYPE=wayland\nSEAT=seat0\nCONTROLLER=:1.7\n",
                b_uid
            ),
        );
        w(
            "9",
            format!(
                "UID={}\nACTIVE=1\nSTATE=active\nREMOTE=1\nTYPE=tty\nCLASS=user\n",
                b_uid
            ),
        );
        st.set_logind_root(&logind);
        let ssh = Bind::Session("9".into());
        assert!(
            !st.request_session_in_front(b_uid, &ssh),
            "seatless, his desktop behind"
        );
        assert!(!st.request_session_in_front(b_uid, &Bind::OnlyDesktop));
        let ask = |bind: Bind| {
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let never = || false;
                let _ = tx.send(l.fallback(
                    st,
                    bob,
                    "sudo",
                    None,
                    &never,
                    &Asker::new(Origin::Elsewhere, bind),
                ));
            });
            rx
        };
        let got = ask(ssh.clone()).recv_timeout(ANSWER).unwrap();
        assert!(matches!(&got, Fallback::Wait("unknown", _)), "{:?}", got);
        assert_eq!(
            host.running(),
            0,
            "no check ran while Alice was at the seat"
        );
        // Bob at the seat: his own desktop in front, his SSH line runs.
        w(
            "3",
            format!(
                "UID={}\nACTIVE=0\nSTATE=online\nTYPE=wayland\nSEAT=seat0\nCONTROLLER=:1.3\n",
                a_uid
            ),
        );
        w(
            "7",
            format!(
                "UID={}\nACTIVE=1\nSTATE=active\nTYPE=wayland\nSEAT=seat0\nCONTROLLER=:1.7\n",
                b_uid
            ),
        );
        assert!(st.request_session_in_front(b_uid, &ssh));
        let rx = ask(ssh);
        assert!(eventually(|| host.running() == 1));
        host.touch(true);
        assert_eq!(rx.recv_timeout(ANSWER).unwrap(), Fallback::Touched);
        let _ = std::fs::remove_dir_all(&logind);
    }

    /// Fix round 11 (Codex 5): the unlock check's supervision keeps running
    /// while its lock question is out (an anchor may take 3.5 s), so a
    /// switch to another account's VT stops the check at once, not after
    /// the question comes back.
    #[test]
    fn a_vt_switch_stops_the_unlock_check_during_a_slow_look() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let alice = "faceauth-r11-slow";
        let a_uid = host.uid_of(alice).unwrap();
        let (logind, rec) = fg_records("r11-slow");
        rec("3", a_uid, true);
        st.set_logind_root(&logind);
        *host.locked_user.lock().unwrap() = Some(alice);
        let unlock = unlock_on_thread(l, st, alice, Arc::new(AtomicBool::new(false)));
        assert!(eventually(|| host.running() == 1));
        // Every look from now on takes 2 s; let one go out.
        *host.ask_delay.lock().unwrap() = Duration::from_secs(2);
        std::thread::sleep(UNLOCK_RECHECK + Duration::from_millis(200));
        let switched = Instant::now();
        rec("3", a_uid, false);
        let last = host.checks() - 1;
        assert!(
            eventually(|| host.stopped(last)),
            "the check stopped while the look was out"
        );
        assert!(
            switched.elapsed() < Duration::from_millis(700),
            "{:?}",
            switched.elapsed()
        );
        assert_eq!(
            unlock.recv_timeout(ANSWER).unwrap(),
            no("the session is no longer in the foreground")
        );
        *host.ask_delay.lock().unwrap() = Duration::ZERO;
        let _ = std::fs::remove_dir_all(&logind);
    }

    /// Fix round 11 (Opus N3): a locked account whose session is in the
    /// background asks no anchor: its lock screen's retries, every 2 s,
    /// cost a look at logind's record and nothing more, until it is in
    /// front again.
    #[test]
    fn a_background_locked_account_starts_no_anchor() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let alice = "faceauth-r11-quiet";
        let a_uid = host.uid_of(alice).unwrap();
        let (logind, rec) = fg_records("r11-quiet");
        rec("3", a_uid, false);
        st.set_logind_root(&logind);
        *host.locked_user.lock().unwrap() = Some(alice);
        let asked = host.asks.load(Ordering::SeqCst);
        for _ in 0..5 {
            assert_eq!(
                l.unlock(st, alice, &Bind::OnlyDesktop, &|| false),
                no("the session is not in the foreground")
            );
        }
        assert_eq!(
            host.asks.load(Ordering::SeqCst),
            asked,
            "no lock question asked"
        );
        rec("3", a_uid, true);
        let unlock = unlock_on_thread(l, st, alice, Arc::new(AtomicBool::new(false)));
        assert!(
            eventually(|| host.running() == 1),
            "in front: asked and run"
        );
        assert!(host.asks.load(Ordering::SeqCst) > asked);
        host.touch(false);
        let _ = unlock.recv_timeout(ANSWER).unwrap();
        let _ = std::fs::remove_dir_all(&logind);
    }

    /// Fix round 11 (Codex 4): with faceauthd down the check is stock
    /// pam_u2f's. It runs the private stack that carries the line's own
    /// words, and none of the card's rules about credentials apply: a
    /// credential that asks for its PIN (`+pin`) is asked for it, through
    /// the conversation, and pam_u2f's defaults file is pam_u2f's to read.
    /// The line must still be the one the daemon mirrors.
    #[test]
    fn the_stock_check_runs_the_lines_own_stack() {
        let sudo = "auth sufficient pam_faceauth.so consent\nauth sufficient pam_faceauth.so key-fallback cue\n";
        let pin_cred = "alice:cred,pub,es256,+presence+pin\n";
        // The card withholds this credential under a line with no PIN word.
        assert!(offer_from("sudo", Some(sudo), Some(""), Some(pin_cred), None, "alice").is_err());
        assert_eq!(
            stock_service("sudo", Some(sudo), Some("")),
            Some("faceauth-key")
        );
        let sudo_pin = "auth sufficient pam_faceauth.so key-fallback cue pinverification=1\n";
        assert_eq!(
            stock_service("sudo", Some(sudo_pin), Some("")),
            Some("faceauth-key-pin")
        );
        let stray = "auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\n";
        assert_eq!(
            stock_service("sudo", Some(sudo), Some(stray)),
            None,
            "a pam_u2f line takes the key itself"
        );
        assert_eq!(stock_service("unlock", Some(sudo), Some("")), None);
    }

    /// Fix round 11 (Opus N4): a check's unit goes with the daemon's, and
    /// since fix round 12 (Opus N4) only goes: `StopPropagatedFrom=` stops
    /// it on the service's stop, its restart and a crash's automatic
    /// restart, and never restarts it, where `PartOf=` would rerun a live
    /// check for nobody (systemd v262 src/core/transaction.c: a stop,
    /// restart or start-as-restart takes `UNIT_ATOM_PROPAGATE_STOP` units
    /// along as try-restart but `UNIT_ATOM_PROPAGATE_STOP_GRACEFUL` ones,
    /// `PropagatesStopTo=`, as stop, `job_type_propagate_stop_graceful`;
    /// src/core/unit.c stops them too when the service dies unasked,
    /// `retroactively_stop_dependencies`). Nothing here starts the
    /// service. And the daemon,
    /// starting, stops any check unit left from before (a crash, an
    /// upgrade), by its name's pattern, which `systemctl stop` expands to
    /// the units in memory (man systemctl, "unit glob patterns").
    #[test]
    fn a_check_unit_does_not_outlive_the_daemon() {
        let props: Vec<&str> = KEY_UNIT_PROPERTIES.to_vec();
        assert!(
            props.contains(&"StopPropagatedFrom=faceauth.service"),
            "{:?}",
            props
        );
        assert!(
            !props.iter().any(|p| p.starts_with("BindsTo=")
                || p.starts_with("Requires=")
                || p.starts_with("PartOf=")),
            "nothing that would start the service, or rerun a check with its restart"
        );
        let c = stale_checks_stop();
        let a: Vec<String> = c
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(c.get_program(), "/usr/bin/timeout");
        assert_eq!(
            a,
            [
                "-k",
                "1",
                "5",
                "/usr/bin/systemctl",
                "stop",
                "--quiet",
                "faceauth-key-*.service"
            ]
        );
        assert_eq!(
            key_unit("alice").as_deref(),
            Some("faceauth-key-alice.service")
        );
    }

    /// G: the stack runs only from a tree root alone can write, and the
    /// check gets the canonical path it vouched for, never the path as
    /// written: a link in the way resolves before it is checked and is not
    /// what PAM opens.
    #[test]
    fn the_stack_is_vouched_for_and_opened_by_its_canonical_path() {
        let dir = std::env::temp_dir().join(format!("faceauth-key-stack-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("faceauth-key"), "auth required pam_permit.so\n").unwrap();
        assert_eq!(trusted_stack(&dir, "faceauth-key"), None);
        assert_eq!(
            trusted_stack(Path::new("/nonexistent/faceauth/pam.d"), "faceauth-key"),
            None
        );
        if root_only_file(Path::new("/usr/lib/os-release")) {
            let canonical = std::fs::canonicalize("/usr/lib").unwrap();
            assert_eq!(
                trusted_stack(Path::new("/usr/lib"), "os-release"),
                Some(canonical.clone())
            );
            let link = dir.join("link");
            std::os::unix::fs::symlink("/usr/lib", &link).unwrap();
            assert_eq!(
                trusted_stack(&link, "os-release"),
                Some(canonical),
                "the path handed on is the canonical one, not the link"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The words a private stack's name stands for.
    fn extra_words(service: &str) -> Vec<&'static str> {
        let mut w = Vec::new();
        let rest = service.trim_start_matches("faceauth-key");
        for part in rest.split('-').filter(|p| !p.is_empty()) {
            w.push(match part {
                "pin" => "pinverification=1",
                "nopin" => "pinverification=0",
                "uv" => "userverification=1",
                "nouv" => "userverification=0",
                other => panic!("{}", other),
            });
        }
        w
    }

    /// Round 19 (live test 2): libpam reads `other` beside any service it
    /// opens from the private directory, and logged its absence as an
    /// error on every key check. The package ships one that denies every
    /// type, and the check only ever authenticates, which each stack
    /// defines, so it never decides a check.
    #[test]
    fn the_private_directory_has_a_deny_all_other() {
        let text = include_str!("../../../packaging/pam.d/other");
        let lines: Vec<Vec<&str>> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.split_whitespace().collect())
            .collect();
        let types: Vec<&str> = lines.iter().map(|w| w[0]).collect();
        assert_eq!(types, ["auth", "account", "password", "session"]);
        for w in &lines {
            assert_eq!(&w[1..], ["required", "pam_deny.so"], "{:?}", w);
        }
    }

    /// E: the package ships one stack per policy, each pam_u2f alone with
    /// Omarchy's key file, `cue`, and what that policy mirrors from the
    /// key-fallback line that picks it.
    #[test]
    fn the_shipped_stacks_carry_the_policies_they_are_named_for() {
        for (service, text, extra) in [
            (
                "faceauth-key",
                include_str!("../../../packaging/pam.d/faceauth-key"),
                vec![],
            ),
            (
                "faceauth-key-pin",
                include_str!("../../../packaging/pam.d/faceauth-key-pin"),
                vec!["pinverification=1"],
            ),
            (
                "faceauth-key-uv",
                include_str!("../../../packaging/pam.d/faceauth-key-uv"),
                vec!["userverification=1"],
            ),
            (
                "faceauth-key-pin-uv",
                include_str!("../../../packaging/pam.d/faceauth-key-pin-uv"),
                vec!["pinverification=1", "userverification=1"],
            ),
            (
                "faceauth-key-nopin",
                include_str!("../../../packaging/pam.d/faceauth-key-nopin"),
                vec!["pinverification=0"],
            ),
            (
                "faceauth-key-nouv",
                include_str!("../../../packaging/pam.d/faceauth-key-nouv"),
                vec!["userverification=0"],
            ),
            (
                "faceauth-key-pin-nouv",
                include_str!("../../../packaging/pam.d/faceauth-key-pin-nouv"),
                vec!["pinverification=1", "userverification=0"],
            ),
            (
                "faceauth-key-nopin-uv",
                include_str!("../../../packaging/pam.d/faceauth-key-nopin-uv"),
                vec!["pinverification=0", "userverification=1"],
            ),
            (
                "faceauth-key-nopin-nouv",
                include_str!("../../../packaging/pam.d/faceauth-key-nopin-nouv"),
                vec!["pinverification=0", "userverification=0"],
            ),
        ] {
            let lines: Vec<Vec<&str>> = text
                .lines()
                .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
                .map(|l| l.split_whitespace().collect())
                .collect();
            let mut want = vec![
                "auth",
                "required",
                "pam_u2f.so",
                "cue",
                "authfile=/etc/fido2/fido2",
            ];
            want.extend(extra.iter().copied());
            assert_eq!(lines, [want], "{}", service);
            // The key-fallback line with the same words picks this stack.
            let mut words = vec![
                "auth",
                "sufficient",
                "pam_faceauth.so",
                "socket=/run/faceauth/sock",
                "key-fallback",
                "cue",
            ];
            words.extend(extra);
            assert_eq!(
                line_policy(&words).map(KeyPolicy::service),
                Ok(service),
                "{}",
                service
            );
            assert_eq!(
                line_policy(&words).map(KeyPolicy::words),
                Ok(extra_words(service)),
                "{}",
                service
            );
        }
    }

    /// 8: `finish` disarms the watch before it waits for the check to
    /// stop, so a result that arrives meanwhile finds its generation gone;
    /// and a watch told to stop takes no touch at all, even one that
    /// answered in the same instant.
    #[test]
    fn finish_disarms_before_it_waits_and_a_stopped_watch_takes_no_touch() {
        let user = "faceauth-key-finish-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let host = FakeHost::slow_to_stop(Duration::from_millis(400));
        let watch = lane(host, SHORT, LONG)
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(eventually(|| host.running() == 1));
        let g = st.key_armed_now(user).unwrap();
        let finishing = std::thread::spawn(move || watch.finish());
        assert!(
            eventually(|| st.key_armed_now(user).is_none()),
            "disarmed while the stop is still under way"
        );
        assert!(!host.stopped(0), "the stop has not finished yet");
        assert!(
            !st.key_touched(user, &tok, g, Instant::now(), &unlocked_look, &|| true),
            "a result now counts for nothing"
        );
        finishing.join().unwrap();
        assert!(host.stopped(0));
        let l = lane(FakeHost::new(false), SHORT, LONG);
        let g = st.arm_key(user, &tok, false).unwrap();
        let stopped = AtomicBool::new(true);
        let w = Watched {
            state: st,
            user,
            token: &tok,
            lane: "sudo",
            policy: KeyPolicy::default(),
            generation: g,
            stop: &stopped,
            bind: &Bind::OnlyDesktop,
        };
        assert!(
            !l.touched(&w, Instant::now()),
            "a stopped watch takes no touch"
        );
        assert!(!st.answered(user));
    }

    /// 9: the card asks for the PIN whenever none is waiting or in use: not
    /// while a PIN waits for its check or the check runs, and again once
    /// that check has ended with the PIN spent, when the card is to be sent
    /// again so it says so.
    #[test]
    fn the_card_asks_for_the_pin_again_once_it_is_spent() {
        let user = "faceauth-key-pin-again-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let host = FakeHost::with(
            Ok(KeyPolicy {
                pin: Some(true),
                uv: None,
            }),
            false,
        );
        let _watch = lane(host, SHORT, LONG)
            .arm(st, user, &tok, "sudo", &Bind::OnlyDesktop)
            .unwrap();
        assert!(
            st.key_for_payload(user, &tok).pin_wanted,
            "the card asks for the PIN"
        );
        assert!(!st.take_key_card_stale(user));
        assert_eq!(
            st.set_key_pin(user, Some(&tok), Secret::new("123456".into())),
            Ok(())
        );
        assert!(eventually(|| host.running() == 1));
        assert!(
            !st.key_for_payload(user, &tok).pin_wanted,
            "not while its check runs"
        );
        host.touch(false);
        assert!(
            eventually(|| st.take_key_card_stale(user)),
            "a spent PIN sends the card again"
        );
        assert!(
            st.key_for_payload(user, &tok).pin_wanted,
            "and the card asks for the PIN once more"
        );
    }

    /// 6, round 3's 3: a card shown again after the lock drops its old
    /// acknowledgment rather than restamping it: no check counts until the
    /// card acknowledges afresh, however long that takes, and then only a
    /// whole dwell after that acknowledgment, as at a card the user has
    /// just been shown; the nods wait the same.
    #[test]
    fn an_unlock_drops_the_old_acknowledgment() {
        let user = "faceauth-key-unlock-dwell-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (mut d, tok) = card(st, user);
        let g = st.arm_key(user, &tok, false).unwrap();
        assert!(
            st.key_may_check(user, &tok, g, Instant::now()),
            "the dwell from before the lock has passed"
        );
        d.reset_ack();
        for later in [Duration::ZERO, ACK_DWELL, ACK_DWELL * 20] {
            assert!(
                !st.key_may_check(user, &tok, g, Instant::now() + later),
                "no check without a fresh acknowledgment, {:?} on",
                later
            );
        }
        assert!(st.ack(user, Some(&tok)), "the card acknowledges again");
        assert!(
            !st.key_may_check(user, &tok, g, Instant::now()),
            "the key waits out a dwell from the fresh acknowledgment"
        );
        assert!(st.key_may_check(user, &tok, g, Instant::now() + ACK_DWELL));
    }

    /// 5: the rider is marked shown and the acknowledgment reset in one
    /// look at the record, so a rider armed while a show is being built
    /// is never shown under an acknowledgment from before it. Raced here
    /// against an arm on another thread, many times over.
    #[test]
    fn a_rider_is_never_shown_under_an_acknowledgment_from_before_it() {
        let user = "faceauth-key-rider-race-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        st.rider_snapshot(user, &tok, true, true);
        st.set_face_present(user, true);
        for _ in 0..500 {
            let _ = st.take_passwordless(user, &tok);
            assert!(st.ack(user, Some(&tok)));
            let t = tok.clone();
            let arm = std::thread::spawn(move || st.arm_passwordless(user, &t, 15));
            let (shown, _, reset) = st.rider_snapshot(user, &tok, true, true);
            arm.join().unwrap().unwrap();
            if shown.is_some() {
                assert!(
                    reset,
                    "a rider shown for the first time resets the acknowledgment"
                );
                assert!(
                    !st.acknowledged(user, &tok),
                    "and none from before it stands"
                );
            }
        }
    }

    /// Runs `lane.unlock` for `user` on a thread of its own; its answer
    /// comes back on the receiver. `gone` stands for the lock screen's
    /// hang-up.
    fn unlock_on_thread(
        lane: &'static KeyLane,
        st: &'static ConsentState,
        user: &'static str,
        gone: Arc<AtomicBool>,
    ) -> std::sync::mpsc::Receiver<Unlocked> {
        unlock_on_thread_from(lane, st, user, Bind::OnlyDesktop, gone)
    }

    /// `unlock_on_thread`, the lock screen asking from `bind`.
    fn unlock_on_thread_from(
        lane: &'static KeyLane,
        st: &'static ConsentState,
        user: &'static str,
        bind: Bind,
        gone: Arc<AtomicBool>,
    ) -> std::sync::mpsc::Receiver<Unlocked> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let asked_off = move || gone.load(Ordering::SeqCst);
            let _ = tx.send(lane.unlock(st, user, &bind, &asked_off));
        });
        rx
    }

    /// Runs `lane.fallback` for `user` on `stack` on a thread of its own.
    fn fallback_on_thread(
        lane: &'static KeyLane,
        st: &'static ConsentState,
        user: &'static str,
        pin: Option<&'static str>,
        gone: Arc<AtomicBool>,
    ) -> std::sync::mpsc::Receiver<Fallback> {
        fallback_from(lane, st, user, pin, gone, Origin::Desktop)
    }

    /// The same, for a request from `origin`.
    fn fallback_from(
        lane: &'static KeyLane,
        st: &'static ConsentState,
        user: &'static str,
        pin: Option<&'static str>,
        gone: Arc<AtomicBool>,
        origin: Origin,
    ) -> std::sync::mpsc::Receiver<Fallback> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let asked_off = move || gone.load(Ordering::SeqCst);
            let pin = pin.map(|p| Secret::new(p.to_string()));
            let _ = tx.send(lane.fallback(
                st,
                user,
                "sudo",
                pin,
                &asked_off,
                &Asker::new(origin, Bind::OnlyDesktop),
            ));
        });
        rx
    }

    fn no(why: &str) -> Unlocked {
        Unlocked::No {
            why: why.into(),
            hung_up: false,
        }
    }

    const ANSWER: Duration = Duration::from_secs(3);

    /// F2: the lock screen's lane mirrors sudo's key line: user
    /// verification carries over, and a line that asks for the PIN gives
    /// no lane at all, while the card's own sudo lane keeps its PIN.
    #[test]
    fn the_unlock_lane_mirrors_sudos_key_line_and_takes_no_pin() {
        let line = |extra: &str| {
            format!(
                "auth sufficient pam_faceauth.so socket=/run/faceauth/sock key-fallback cue{}\n",
                extra
            )
        };
        assert_eq!(lane_stack("unlock"), lane_stack("sudo"));
        assert_eq!(
            lane_policy("unlock", Some(&line("")), None),
            Ok(KeyPolicy::default())
        );
        assert_eq!(
            lane_policy("unlock", Some(&line(" userverification=1")), None),
            Ok(KeyPolicy {
                pin: None,
                uv: Some(true)
            })
        );
        for pin in [
            " pinverification=1",
            " pinverification=1 userverification=1",
        ] {
            assert!(
                matches!(
                    lane_policy("unlock", Some(&line(pin)), None),
                    Err(KeyOff::Withheld(_))
                ),
                "{}",
                pin
            );
        }
        assert!(matches!(
            lane_policy("unlock", Some("auth include system-auth\n"), None),
            Err(KeyOff::NotSetUp(_))
        ));
        assert_eq!(
            lane_policy("sudo", Some(&line(" pinverification=1")), None),
            Ok(KeyPolicy {
                pin: Some(true),
                uv: None
            }),
            "the card and the fallback ask for the PIN themselves"
        );
    }

    /// F2, round 4: a key unlock runs only while the compositor says the
    /// session is locked, never on a lane whose line asks for the PIN or
    /// with no key set up, and one per user at a time. Every ask latches
    /// the user, refused or not, and a touch that unlocked does not let go
    /// of the latch: only an unlock the daemon sees, and the hold after it.
    #[test]
    fn a_key_unlock_is_refused_unlocked_under_a_pin_and_twice_at_once() {
        let user = "faceauth-unlock-refused-user";
        let st = test_state();
        let never = || false;
        let host = FakeHost::new(false);
        let open = lane(host, SHORT, LONG);
        assert!(open.unlock_offer(user).is_ok());
        assert_eq!(
            open.unlock(st, user, &Bind::OnlyDesktop, &never),
            no("the session is not locked")
        );
        assert_eq!(host.checks(), 0, "no check while unlocked");
        assert!(
            st.unlock_holds(user),
            "the ask latches the user's card off the key all the same"
        );
        host.unknown.store(true, Ordering::SeqCst);
        assert_eq!(
            open.unlock(st, user, &Bind::OnlyDesktop, &never),
            no("the session is not locked"),
            "an unanswered question is not a lock to unlock"
        );
        let pin = FakeHost::with(
            Ok(KeyPolicy {
                pin: Some(true),
                uv: None,
            }),
            false,
        );
        pin.locked.store(true, Ordering::SeqCst);
        assert!(matches!(
            lane(pin, SHORT, LONG).unlock(st, user, &Bind::OnlyDesktop, &never),
            Unlocked::No { .. }
        ));
        assert_eq!(pin.checks(), 0, "no lane under a PIN policy");
        let off = FakeHost::with(Err(KeyOff::NotSetUp("no key registered".into())), false);
        off.locked.store(true, Ordering::SeqCst);
        let off_lane = lane(off, SHORT, LONG);
        assert!(off_lane.unlock_offer(user).is_err());
        assert_eq!(
            off_lane.unlock(st, user, &Bind::OnlyDesktop, &never),
            no("no key registered")
        );
        assert_eq!(off.checks(), 0);
        let host = FakeHost::new(false);
        host.locked.store(true, Ordering::SeqCst);
        let l = lane(host, SHORT, LONG);
        let user = "faceauth-unlock-twice-user";
        let rx = unlock_on_thread(l, st, user, Arc::new(AtomicBool::new(false)));
        assert!(
            eventually(|| host.running() == 1),
            "the unlock asks the key"
        );
        assert_eq!(
            l.unlock(st, user, &Bind::OnlyDesktop, &never),
            no("a key unlock of this user's is already asked")
        );
        assert_eq!(host.checks(), 1, "never a second check for one user");
        host.touch(true);
        assert_eq!(rx.recv_timeout(ANSWER).unwrap(), Unlocked::Touched);
        assert!(
            st.unlock_holds(user),
            "a touch is no evidence of the unlock: the latch stays"
        );
        st.set_key_unlock_hold(Duration::from_millis(40));
        host.locked.store(false, Ordering::SeqCst);
        l.watch_for_unlock(st, user, &Bind::OnlyDesktop);
        assert!(st.unlock_holds(user), "the hold runs from the unlock seen");
        std::thread::sleep(Duration::from_millis(60));
        assert!(!st.unlock_holds(user), "and lets go once it has passed");
    }

    /// Round 4 (Codex 4, the setting): the latch, from the lock screen's
    /// first ask or its word that it is up, lasts until the daemon sees the
    /// session unlocked with no ask under way, and then for
    /// `key_unlock_hold_ms`. An unlock seen during an ask counts for
    /// nothing, a lock seen stops the hold's clock, and a fresh ask or word
    /// latches again.
    #[test]
    fn the_latch_lasts_until_the_unlock_is_seen_and_the_hold_has_passed() {
        use super::super::shell::LockState;
        let user = "faceauth-latch-hold-user";
        let st = test_state();
        let hold = Duration::from_millis(80);
        st.set_key_unlock_hold(hold);
        assert!(!st.unlock_holds(user));
        st.observe_lock(user, LockState::Unlocked);
        assert!(!st.unlock_holds(user), "nothing to release without a latch");
        st.latch_lock_screen(user);
        assert!(st.unlock_holds(user));
        std::thread::sleep(hold * 2);
        assert!(
            st.unlock_holds(user),
            "no time runs out before the unlock is seen"
        );
        st.observe_lock(user, LockState::Unknown);
        assert!(st.unlock_holds(user));
        st.observe_lock(user, LockState::Unlocked);
        assert!(st.unlock_holds(user), "the hold runs from the unlock");
        st.observe_lock(user, LockState::Locked);
        std::thread::sleep(hold * 2);
        assert!(st.unlock_holds(user), "a lock seen stops the hold's clock");
        assert!(st.begin_key_unlock(user));
        st.observe_lock(user, LockState::Unlocked);
        std::thread::sleep(hold * 2);
        assert!(
            st.unlock_holds(user),
            "an unlock seen during an ask counts for nothing"
        );
        st.end_key_unlock(user);
        st.observe_lock(user, LockState::Unlocked);
        assert!(st.unlock_holds(user));
        std::thread::sleep(hold + Duration::from_millis(30));
        assert!(!st.unlock_holds(user), "the hold passed after the unlock");
        st.set_key_unlock_hold(Duration::ZERO);
        st.latch_lock_screen(user);
        st.observe_lock(user, LockState::Unlocked);
        assert!(!st.unlock_holds(user), "a zero hold lets go at the unlock");
    }

    /// Round 4 (Codex 3): one lock serializes the latch with the key's
    /// commit and its consumption. A latch published before the commit's
    /// look refuses the touch; one published after it drops the touch from
    /// the slot; and a touch is never handed out while a latch holds the
    /// user. Raced here against a slow compositor question, many times.
    #[test]
    fn the_latch_and_the_touch_are_serialized_under_one_lock() {
        let user = "faceauth-latch-race-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let g = st.arm_key(user, &tok, false).unwrap();
        assert!(st.key_touched(user, &tok, g, Instant::now(), &unlocked_look, &|| true));
        st.latch_lock_screen(user);
        assert!(
            !matches!(st.poll(user), Some(Answer::Key)),
            "dropped from the slot"
        );
        assert!(st.unlock_holds(user));
        let g = st.arm_key(user, &tok, false).unwrap();
        assert!(
            !st.key_touched(user, &tok, g, Instant::now(), &unlocked_look, &|| true),
            "refused under the latch"
        );
        for i in 0..200 {
            let user: &'static str =
                Box::leak(format!("faceauth-latch-race-{}", i).into_boxed_str());
            let st = test_state();
            let _turn = st.test_live(1000, user);
            let (_d, tok) = card(st, user);
            let g = st.arm_key(user, &tok, false).unwrap();
            let t = tok.clone();
            let toucher = std::thread::spawn(move || {
                let slow = || {
                    std::thread::sleep(Duration::from_micros(200));
                    unlocked_look()
                };
                st.key_touched(user, &t, g, Instant::now(), &slow, &|| true)
            });
            std::thread::sleep(Duration::from_micros((i % 7) * 60));
            assert!(st.begin_key_unlock(user));
            toucher.join().unwrap();
            assert!(
                !matches!(st.poll(user), Some(Answer::Key)),
                "round {}: a touch survived a latch",
                i
            );
        }
    }

    /// F2: a key unlock is exclusive per user. The card's check under way
    /// is stopped before the unlock's starts, the card's key is disarmed,
    /// the two never run at once, and the touch unlocks and approves
    /// nothing.
    #[test]
    fn a_key_unlock_takes_the_key_from_the_users_card() {
        let user = "faceauth-unlock-exclusive-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let _watch = l.arm(st, user, &tok, "sudo", &Bind::OnlyDesktop).unwrap();
        assert!(eventually(|| host.running() == 1), "the card's check runs");
        host.locked.store(true, Ordering::SeqCst);
        let rx = unlock_on_thread(l, st, user, Arc::new(AtomicBool::new(false)));
        assert!(
            eventually(|| host.stopped(0)),
            "the card's check is stopped"
        );
        assert!(
            eventually(|| host.checks() == 2 && host.running() == 1),
            "the unlock's own check runs"
        );
        assert_eq!(
            host.most_running.load(Ordering::SeqCst),
            1,
            "never two at once"
        );
        assert_eq!(
            st.key_for_payload(user, &tok).pair(),
            (false, false),
            "the card's key is disarmed"
        );
        host.touch(true);
        assert_eq!(rx.recv_timeout(ANSWER).unwrap(), Unlocked::Touched);
        std::thread::sleep(SHORT * 4);
        assert!(
            !st.answered(user),
            "the touch unlocked and approved nothing"
        );
        assert_eq!(host.checks(), 2, "and the card asks the key no more");
    }

    /// F2, round 4 (Codex 2): while the lock screen's latch holds its user
    /// a card starts no check and a touch reported for one counts for
    /// nothing, even with the compositor answering "unlocked" to the card.
    /// The lock screen's word that it is up latches as an ask does.
    #[test]
    fn a_card_takes_no_touch_while_the_lock_screen_holds_its_user() {
        let user = "faceauth-unlock-hold-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        st.latch_lock_screen(user);
        let _watch = l.arm(st, user, &tok, "sudo", &Bind::OnlyDesktop).unwrap();
        std::thread::sleep(SHORT * 6);
        assert_eq!(host.checks(), 0, "the card starts no check while latched");
        let g = st.arm_key(user, &tok, false).unwrap();
        let stop = AtomicBool::new(false);
        let w = Watched {
            state: st,
            user,
            token: &tok,
            lane: "sudo",
            policy: KeyPolicy::default(),
            generation: g,
            stop: &stop,
            bind: &Bind::OnlyDesktop,
        };
        assert!(!l.touched(&w, Instant::now()), "and takes no touch");
        assert!(!st.answered(user));
        let other = test_state();
        let _t2 = other.test_live(1000, user);
        let (_d2, tok2) = card(other, user);
        let g2 = other.arm_key(user, &tok2, false).unwrap();
        let w2 = Watched {
            state: other,
            user,
            token: &tok2,
            lane: "sudo",
            policy: KeyPolicy::default(),
            generation: g2,
            stop: &stop,
            bind: &Bind::OnlyDesktop,
        };
        assert!(
            lane(FakeHost::new(false), SHORT, LONG).touched(&w2, Instant::now()),
            "the same touch counts where nothing latches the user"
        );
    }

    /// F2: the unlock's check is stopped at once when the lock screen
    /// stops asking (its PAM transaction hangs up), within a recheck when
    /// the session unlocks by other means, and at its deadline.
    #[test]
    fn a_key_unlock_stops_its_check_at_the_unlock_or_when_the_lock_screen_stops_asking() {
        let user = "faceauth-unlock-stop-user";
        let st = test_state();
        let host = FakeHost::new(false);
        host.locked.store(true, Ordering::SeqCst);
        let l = lane(host, SHORT, LONG);
        let gone = Arc::new(AtomicBool::new(false));
        let rx = unlock_on_thread(l, st, user, Arc::clone(&gone));
        assert!(eventually(|| host.running() == 1));
        gone.store(true, Ordering::SeqCst);
        assert_eq!(
            rx.recv_timeout(ANSWER).unwrap(),
            Unlocked::No {
                why: "the lock screen stopped asking".into(),
                hung_up: true
            }
        );
        assert!(host.stopped(0) && host.running() == 0, "the key is free");
        let rx = unlock_on_thread(l, st, user, Arc::new(AtomicBool::new(false)));
        assert!(eventually(|| host.running() == 1));
        host.locked.store(false, Ordering::SeqCst);
        assert_eq!(
            rx.recv_timeout(UNLOCK_RECHECK * 3).unwrap(),
            no("the session unlocked")
        );
        assert!(host.stopped(1) && host.running() == 0, "the key is free");
        host.locked.store(true, Ordering::SeqCst);
        let rx = unlock_on_thread(
            lane(host, SHORT, Duration::from_millis(200)),
            st,
            "faceauth-unlock-late-user",
            Arc::new(AtomicBool::new(false)),
        );
        assert_eq!(
            rx.recv_timeout(ANSWER).unwrap(),
            no("the key check ran past its deadline")
        );
    }

    fn wait(kind: &'static str, why: &str) -> Fallback {
        Fallback::Wait(kind, why.into())
    }

    /// Round 4: the stack's key line runs through the daemon: the same
    /// check, a touch approves, and with a PIN policy the PIN the module
    /// asked for goes to that one check and no other; without one, a PIN
    /// line is refused, and a PIN the policy does not ask for is dropped.
    #[test]
    fn a_fallback_runs_the_check_and_takes_its_pin_once() {
        let st = test_state();
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let user = "faceauth-fallback-user";
        let rx = fallback_on_thread(l, st, user, Some("9999"), Arc::new(AtomicBool::new(false)));
        assert!(eventually(|| host.running() == 1));
        assert_eq!(host.pin(0), None, "no PIN where the line asks for none");
        host.touch(true);
        assert_eq!(rx.recv_timeout(ANSWER).unwrap(), Fallback::Touched);
        let pin = FakeHost::with(
            Ok(KeyPolicy {
                pin: Some(true),
                uv: None,
            }),
            false,
        );
        let lp = lane(pin, SHORT, LONG);
        let never = || false;
        assert!(matches!(
            lp.fallback(
                st,
                user,
                "sudo",
                None,
                &never,
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            ),
            Fallback::No(_)
        ));
        assert_eq!(pin.checks(), 0, "a PIN line with no PIN asks nothing");
        let rx = fallback_on_thread(lp, st, user, Some("1234"), Arc::new(AtomicBool::new(false)));
        assert!(eventually(|| pin.running() == 1));
        assert_eq!(pin.pin(0).as_deref(), Some("1234"));
        pin.touch(false);
        assert!(matches!(rx.recv_timeout(ANSWER).unwrap(), Fallback::No(_)));
        assert_eq!(pin.checks(), 1, "the PIN served one check");
    }

    /// Round 5 (B, Mike: the key works on the request after the unlock):
    /// the key line waits rather than refuse while the session reads as
    /// locked (the compositor's lock or no answer), while the lock screen
    /// holds the user, and while their card has the key armed; a policy
    /// that withholds the key is still a no. No check starts meanwhile.
    #[test]
    fn a_fallback_waits_while_locked_latched_or_carded() {
        let never = || false;
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let user = "faceauth-fallback-wait-user";
        // Round 7 (B): the lock screen's channel open and the compositor's
        // lock: a positive lock.
        st.channel_open(user);
        host.locked.store(true, Ordering::SeqCst);
        assert_eq!(
            l.fallback(
                st,
                user,
                "sudo",
                None,
                &never,
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            ),
            wait("locked", "the screen is locked")
        );
        host.locked.store(false, Ordering::SeqCst);
        host.unknown.store(true, Ordering::SeqCst);
        assert!(matches!(
            l.fallback(
                st,
                user,
                "sudo",
                None,
                &never,
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            ),
            Fallback::Wait(..)
        ));
        host.unknown.store(false, Ordering::SeqCst);
        assert!(
            matches!(
                l.fallback(
                    st,
                    user,
                    "sudo",
                    None,
                    &never,
                    &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
                ),
                Fallback::Wait(..)
            ),
            "the lock it saw latched the user: it waits out the hold after the unlock"
        );
        assert_eq!(host.checks(), 0);
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        st.arm_key(user, &tok, false).unwrap();
        assert_eq!(
            l.fallback(
                st,
                user,
                "sudo",
                None,
                &never,
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            ),
            wait("card", "the card on screen has the key")
        );
        assert_eq!(host.checks(), 0);
        let off = lane(
            FakeHost::with(
                Err(KeyOff::Withheld(
                    "a pam_u2f line in /etc/pam.d/sudo reads the key outside faceauthd".into(),
                )),
                false,
            ),
            SHORT,
            LONG,
        );
        match off.fallback(
            test_state(),
            user,
            "sudo",
            None,
            &never,
            &Asker::new(Origin::Desktop, Bind::OnlyDesktop),
        ) {
            Fallback::No(why) => assert!(why.contains("outside faceauthd"), "{}", why),
            other => panic!("{:?}", other),
        }
    }

    /// Round 5 (B): the readiness question waits for the unlock and then
    /// for the hold. A lock it sees latches the user; the unlock it sees
    /// starts the hold's clock; only after the hold does it answer that the
    /// key may run. Nothing is checked meanwhile, so a touch while locked
    /// still only ever unlocks.
    #[test]
    fn the_key_line_is_offered_only_after_the_unlock_and_the_hold() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        st.set_key_unlock_hold(Duration::from_millis(150));
        let user = "faceauth-fallback-hold-user";
        assert!(
            l.fallback_gate(
                st,
                user,
                "sudo",
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            )
            .is_ok(),
            "unlocked, unlatched: at once"
        );
        host.locked.store(true, Ordering::SeqCst);
        assert!(matches!(
            l.fallback_gate(
                st,
                user,
                "sudo",
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            ),
            Err(Fallback::Wait(..))
        ));
        assert!(st.unlock_holds(user), "the lock it saw latched the user");
        host.locked.store(false, Ordering::SeqCst);
        assert!(
            matches!(
                l.fallback_gate(
                    st,
                    user,
                    "sudo",
                    &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
                ),
                Err(Fallback::Wait(..))
            ),
            "unlocked, but the hold has not passed"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            l.fallback_gate(
                st,
                user,
                "sudo",
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            )
            .is_ok(),
            "after the hold"
        );
        assert_eq!(host.checks(), 0, "the question starts no check");
        // Round 6 (Codex 4, Opus N2): logind showing no desktop never
        // drops a latch: with one held, the line waits, as unknown.
        st.latch_lock_screen(user);
        host.unknown.store(true, Ordering::SeqCst);
        host.desktop.store(1, Ordering::SeqCst);
        assert!(matches!(
            l.fallback_gate(
                st,
                user,
                "sudo",
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            ),
            Err(Fallback::Wait("unknown", _))
        ));
        host.desktop.store(0, Ordering::SeqCst);
        host.unknown.store(false, Ordering::SeqCst);
    }

    /// Round 4 (Codex 1), round 5 (B): a key line under way is stopped the
    /// moment the screen locks (within a recheck), when the lock screen
    /// says it is up or asks for the key, and when a card arms the key, and
    /// then waits rather than fail, so the key is offered again after the
    /// unlock; a touch that lands as the screen locks counts for nothing.
    #[test]
    fn a_fallback_stops_and_waits_when_a_lock_or_a_card_arrives() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let user = "faceauth-fallback-cancel-user";
        let rx = fallback_on_thread(l, st, user, None, Arc::new(AtomicBool::new(false)));
        assert!(eventually(|| host.running() == 1));
        host.locked.store(true, Ordering::SeqCst);
        // The compositor's lock with no lock screen channel behind it is
        // unknown (round 7, B); either way the check stops.
        assert_eq!(
            rx.recv_timeout(UNLOCK_RECHECK * 3).unwrap(),
            wait("unknown", "the screen locked")
        );
        assert!(host.stopped(0) && host.running() == 0, "the key is free");
        host.locked.store(false, Ordering::SeqCst);
        let st = test_state();
        let rx = fallback_on_thread(l, st, user, None, Arc::new(AtomicBool::new(false)));
        assert!(eventually(|| host.running() == 1));
        st.latch_lock_screen(user);
        assert_eq!(
            rx.recv_timeout(ANSWER).unwrap(),
            wait("held", "the card or the lock screen took the key")
        );
        assert!(host.stopped(1));
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let (_d, tok) = card(st, user);
        let rx = fallback_on_thread(l, st, user, None, Arc::new(AtomicBool::new(false)));
        assert!(eventually(|| host.running() == 1));
        let _watch = l.arm(st, user, &tok, "sudo", &Bind::OnlyDesktop).unwrap();
        assert_eq!(
            rx.recv_timeout(ANSWER).unwrap(),
            wait("held", "the card or the lock screen took the key")
        );
        assert!(
            eventually(|| host.checks() == 4 && host.running() == 1),
            "the card's check takes the key next"
        );
        assert_eq!(
            host.most_running.load(Ordering::SeqCst),
            1,
            "never two at once"
        );
        let late = test_state();
        let n = late.begin_fallback("faceauth-fallback-late-user").unwrap();
        assert!(
            !late.fallback_touched("faceauth-fallback-late-user", n, &locked_look, &|| true),
            "a touch as the screen locks counts for nothing"
        );
        let gone = Arc::new(AtomicBool::new(false));
        let rx = fallback_on_thread(
            lane(host, SHORT, LONG),
            test_state(),
            "faceauth-fallback-gone-user",
            None,
            Arc::clone(&gone),
        );
        assert!(eventually(|| host.running() == 2));
        gone.store(true, Ordering::SeqCst);
        assert_eq!(
            rx.recv_timeout(ANSWER).unwrap(),
            Fallback::No("the requester went away".into())
        );
    }

    /// Round 5 (Codex 1, Opus F2): doctor names every stack face setup
    /// would refuse: a pam_u2f line beside face, a second key line, or a
    /// key-fallback line with a word it does not mirror; a stack without a
    /// face line is not its business.
    #[test]
    fn the_key_lines_problem_is_named() {
        let face = "auth sufficient pam_faceauth.so socket=/run/faceauth/sock consent\n";
        let fb = "auth sufficient pam_faceauth.so socket=/run/faceauth/sock key-fallback cue\n";
        assert_eq!(key_lines_problem(&format!("{}{}", face, fb)), None);
        assert_eq!(key_lines_problem(face), None, "face without a key");
        assert_eq!(
            key_lines_problem(
                "auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2 nodetect\n"
            ),
            None,
            "no face: stock Omarchy's business"
        );
        for (bad, says) in [
            (format!("auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2 nodetect\n{}{}", face, fb), "pam_u2f line"),
            (format!("{}auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\n", face), "pam_u2f line"),
            (format!("{}{}{}", face, fb, fb), "more than one"),
            (format!("{}auth sufficient pam_faceauth.so key-fallback timeout=45\n", face), "timeout=45"),
            (format!("{}auth sufficient pam_faceauth.so key-fallback pinverification=1 pinverification=0\n", face), "twice"),
        ] {
            match key_lines_problem(&bad) {
                Some(why) => assert!(why.contains(says), "{}: {}", says, why),
                None => panic!("not named: {}", bad),
            }
        }
    }

    /// Round 5 (Codex 5): a credential registered with its PIN required
    /// (`+pin`, synthetic here) makes pam_u2f ask for the PIN when the key
    /// line does not say; no lane can answer that unasked prompt, so the key
    /// is withheld, with the reason, until the line says
    /// `pinverification=`. A line that says it is taken at its word.
    #[test]
    fn a_credential_that_asks_for_its_pin_needs_the_line_to_say_so() {
        let auth = "alice:h1,k1,es256,+presence+pin\nbob:h2,k2,es256,+presence\ncarol:h3,k3,es256,+presence:h4,k4,es256,+presence+pin\ndave:h5,k5\neve:h6,k6,es256,+presence+pinned\n";
        let stack = |words: &str| {
            format!(
                "auth sufficient pam_faceauth.so socket=/run/faceauth/sock consent\nauth sufficient pam_faceauth.so socket=/run/faceauth/sock key-fallback cue{}\n",
                words
            )
        };
        for user in ["alice", "carol"] {
            assert!(authfile_wants_pin(auth, user), "{}", user);
            match offer_from("sudo", Some(&stack("")), None, Some(auth), None, user) {
                Err(KeyOff::Withheld(why)) => {
                    assert!(
                        why.contains("+pin") && why.contains("pinverification=1"),
                        "{}",
                        why
                    );
                    assert!(
                        !why.contains("h1") && !why.contains("k1"),
                        "nothing of the key file is said: {}",
                        why
                    );
                }
                other => panic!("{}: {:?}", user, other),
            }
            let asked = offer_from(
                "sudo",
                Some(&stack(" pinverification=1")),
                None,
                Some(auth),
                None,
                user,
            )
            .unwrap();
            assert!(asked.asks_pin());
            // Round 6 (Codex 5): pam_u2f asks a `+pin` credential for its
            // PIN whatever `pinverification=0` says, so that line is no
            // better than one that omits the word: withheld.
            match offer_from(
                "sudo",
                Some(&stack(" pinverification=0")),
                None,
                Some(auth),
                None,
                user,
            ) {
                Err(KeyOff::Withheld(why)) => assert!(why.contains("pinverification=0"), "{}", why),
                other => panic!("{}: {:?}", user, other),
            }
            assert!(matches!(
                offer_from(
                    "unlock",
                    Some(&stack(" pinverification=1")),
                    None,
                    Some(auth),
                    None,
                    user
                ),
                Err(KeyOff::Withheld(_))
            ));
        }
        // Round 7: pam_u2f finds `+pin` by substring (strstr), so eve's
        // `+pinned` asks for the PIN too; the daemon reads it the same way.
        assert!(authfile_wants_pin(auth, "eve"));
        for user in ["bob", "dave"] {
            assert!(!authfile_wants_pin(auth, user), "{}", user);
            assert_eq!(
                offer_from("sudo", Some(&stack("")), None, Some(auth), None, user),
                Ok(KeyPolicy::default()),
                "{}",
                user
            );
        }
        assert!(matches!(
            offer_from("sudo", Some(&stack("")), None, Some(auth), None, "mallory"),
            Err(KeyOff::NotSetUp(_))
        ));
        assert!(matches!(
            offer_from("sudo", Some(&stack("")), None, None, None, "alice"),
            Err(KeyOff::NotSetUp(_))
        ));
    }

    /// Round 6 (Codex 5): pam_u2f's own defaults, `/etc/security/pam_u2f.conf`
    /// (synthetic here), apply to the stack's key line and to the private
    /// stacks alike for every word the line leaves out, so the policy the
    /// daemon mirrors is the line's word, else the file's. A file that sets
    /// anything else, or that pam_u2f would not read, withholds the key.
    #[test]
    fn pam_u2fs_own_defaults_are_accounted_for_or_the_key_is_withheld() {
        let auth = "alice:h1,k1,es256,+presence+pin\nbob:h2,k2,es256,+presence\n";
        let stack = |words: &str| {
            format!(
                "auth sufficient pam_faceauth.so socket=/run/faceauth/sock consent\nauth sufficient pam_faceauth.so socket=/run/faceauth/sock key-fallback cue{}\n",
                words
            )
        };
        let offer = |words: &str, conf: &str, user: &str| {
            offer_from(
                "sudo",
                Some(&stack(words)),
                None,
                Some(auth),
                Some(conf),
                user,
            )
        };
        let pin_on = "# defaults\n  pinverification = 1 \n\n";
        assert_eq!(
            offer("", pin_on, "bob").map(|p| p.asks_pin()),
            Ok(true),
            "the file's PIN default applies where the line says nothing"
        );
        assert_eq!(
            offer("", pin_on, "bob").unwrap().service(),
            "faceauth-key-pin"
        );
        assert_eq!(
            offer(" pinverification=0", pin_on, "bob").map(|p| p.asks_pin()),
            Ok(false),
            "the line's word wins over the file's"
        );
        assert!(
            offer("", pin_on, "alice").unwrap().asks_pin(),
            "a +pin credential is answered"
        );
        assert_eq!(
            offer("", "userverification=0\n", "bob").unwrap().service(),
            "faceauth-key-nouv"
        );
        assert_eq!(
            offer("", "", "bob"),
            Ok(KeyPolicy::default()),
            "an empty file"
        );
        for bad in [
            "userpresence=0\n",
            "cue\n",
            "authfile=/tmp/x\n",
            "pinverification=2\n",
            "pinverification=1\npinverification=0\n",
            "conf=/etc/other\n",
        ] {
            match offer("", bad, "bob") {
                Err(KeyOff::Withheld(why)) => assert!(why.contains("pam_u2f.conf"), "{}", why),
                other => panic!("{:?}: {:?}", bad, other),
            }
        }
        let big = format!("# {}\n", "x".repeat(4096));
        assert!(
            matches!(offer("", &big, "bob"), Err(KeyOff::Withheld(_))),
            "over pam_u2f's 4 KiB"
        );
    }

    /// Round 7 (D): a key that approves without a touch is on no lane. A
    /// credential registered without `+presence` (synthetic here) is asked
    /// for no touch unless pam_u2f's defaults force one (`userpresence=1`),
    /// and pam_u2f.conf or a key line that turns presence off
    /// (`userpresence=0`) withholds the key outright. An old-format
    /// credential, which pam_u2f takes as `+presence`, passes.
    #[test]
    fn a_key_that_approves_without_a_touch_is_on_no_lane() {
        let auth = "alice:h1,k1,es256,+presence\nbob:h2,k2,es256,\ncarol:h3,k3,es256,+presence:h4,k4,es256,+pin\ndave:h5,k5\n";
        let stack = |words: &str| {
            format!(
                "auth sufficient pam_faceauth.so socket=/run/faceauth/sock consent\nauth sufficient pam_faceauth.so socket=/run/faceauth/sock key-fallback cue{}\n",
                words
            )
        };
        for lane in ["sudo", "polkit", "unlock"] {
            for user in ["bob", "carol"] {
                let own = if lane == "polkit" {
                    None
                } else {
                    Some(stack(""))
                };
                let polkit = if lane == "polkit" {
                    Some(stack(""))
                } else {
                    None
                };
                let (own, other) = match lane {
                    "polkit" => (polkit.as_deref(), None),
                    _ => (own.as_deref(), None),
                };
                match offer_from(lane, own, other, Some(auth), None, user) {
                    Err(KeyOff::Withheld(why)) => {
                        assert!(
                            why.contains("+presence") && why.contains("touch"),
                            "{}",
                            why
                        );
                        assert!(
                            !why.contains("h2") && !why.contains("k2"),
                            "nothing of the key file: {}",
                            why
                        );
                    }
                    other => panic!("{} {}: {:?}", lane, user, other),
                }
            }
        }
        assert!(offer_from("sudo", Some(&stack("")), None, Some(auth), None, "alice").is_ok());
        assert!(
            offer_from("sudo", Some(&stack("")), None, Some(auth), None, "dave").is_ok(),
            "old format: +presence"
        );
        assert!(
            offer_from(
                "sudo",
                Some(&stack("")),
                None,
                Some(auth),
                Some("userpresence=1\n"),
                "bob"
            )
            .is_ok(),
            "pam_u2f's defaults force the touch"
        );
        for conf in ["userpresence=0\n", "userpresence = 0\n"] {
            match offer_from(
                "sudo",
                Some(&stack("")),
                None,
                Some(auth),
                Some(conf),
                "alice",
            ) {
                Err(KeyOff::Withheld(why)) => assert!(
                    why.contains("userpresence=0") && why.contains("touch"),
                    "{}",
                    why
                ),
                other => panic!("{:?}", other),
            }
        }
        match offer_from(
            "sudo",
            Some(&stack(" userpresence=0")),
            None,
            Some(auth),
            None,
            "alice",
        ) {
            Err(KeyOff::Withheld(why)) => assert!(
                why.contains("userpresence=0") && why.contains("touch"),
                "{}",
                why
            ),
            other => panic!("{:?}", other),
        }
    }

    /// Round 5 (the text console ruling), round 6 (items 4, 5 and 7): with
    /// no graphical session of anyone's in logind's records, nothing latched
    /// and nobody asking, sudo's key line takes the key though no compositor
    /// answers. With a desktop anywhere it waits for the compositor's
    /// unlocked if it comes from the desktop, and goes straight to the
    /// password if it comes from a text console or a remote login; a
    /// desktop that appears during the check brings that rule with it.
    #[test]
    fn a_text_console_with_no_desktop_takes_the_key_and_a_desktop_keeps_the_rule() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let user = "faceauth-console-user";
        let never = || false;
        host.unknown.store(true, Ordering::SeqCst);
        assert!(
            matches!(
                l.fallback(
                    st,
                    user,
                    "sudo",
                    None,
                    &never,
                    &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
                ),
                Fallback::Wait("unknown", _)
            ),
            "a desktop whose compositor cannot answer"
        );
        let st = test_state();
        host.unknown.store(false, Ordering::SeqCst);
        host.locked.store(true, Ordering::SeqCst);
        st.channel_open(user);
        assert_eq!(
            l.fallback(
                st,
                user,
                "sudo",
                None,
                &never,
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            ),
            wait("locked", "the screen is locked"),
            "a locked desktop, the request from it"
        );
        assert!(
            matches!(
                l.fallback(st, user, "sudo", None, &never, &Asker::new(Origin::Elsewhere, Bind::OnlyDesktop)),
                Fallback::No(why) if why.contains("not from the desktop")
            ),
            "a locked desktop, the request from a text console: the password"
        );
        assert_eq!(host.checks(), 0);
        let st = test_state();
        host.locked.store(false, Ordering::SeqCst);
        host.unknown.store(true, Ordering::SeqCst);
        host.desktop.store(1, Ordering::SeqCst);
        let rx = fallback_from(
            l,
            st,
            user,
            None,
            Arc::new(AtomicBool::new(false)),
            Origin::Elsewhere,
        );
        assert!(
            eventually(|| host.running() == 1),
            "no desktop at all: the key is asked, from a text console too"
        );
        host.touch(true);
        assert_eq!(rx.recv_timeout(ANSWER).unwrap(), Fallback::Touched);
        let rx = fallback_on_thread(l, st, user, None, Arc::new(AtomicBool::new(false)));
        assert!(eventually(|| host.running() == 1));
        host.desktop.store(0, Ordering::SeqCst);
        assert_eq!(
            rx.recv_timeout(UNLOCK_RECHECK * 3).unwrap(),
            wait("unknown", "the screen locked"),
            "a desktop that appears brings the compositor's rule"
        );
        assert!(host.stopped(1) && host.running() == 0);
        host.desktop.store(0, Ordering::SeqCst);
        host.unknown.store(false, Ordering::SeqCst);
    }

    /// Round 6 (item 10, Opus N3): while the connection places refused or
    /// dropped a caller within one hold, and for one hold after the daemon
    /// starts, no approval lane opens for anyone: the verdict never reads
    /// unlocked, the key line waits, a fallback cannot begin and a commit
    /// is refused. Filling the places only denies service.
    #[test]
    fn filling_the_places_or_a_restart_never_opens_an_approval() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        st.set_key_unlock_hold(Duration::from_millis(120));
        let user = "faceauth-saturated-user";
        assert_eq!(l.verdict(st, user, &Bind::OnlyDesktop), Verdict::Unlocked);
        st.note_refusal();
        assert_eq!(
            l.verdict(st, user, &Bind::OnlyDesktop),
            Verdict::Unknown,
            "saturated: never unlocked"
        );
        assert!(matches!(
            l.fallback_gate(
                st,
                user,
                "sudo",
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            ),
            Err(Fallback::Wait("unknown", _))
        ));
        assert!(st.begin_fallback(user).is_none(), "no fallback begins");
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(
            l.verdict(st, user, &Bind::OnlyDesktop),
            Verdict::Unlocked,
            "one hold after the last refusal"
        );
        let n = st.begin_fallback(user).unwrap();
        st.note_refusal();
        assert!(
            !st.fallback_touched(user, n, &unlocked_look, &|| true),
            "a commit while saturated"
        );
        let st = test_state();
        st.set_key_unlock_hold(Duration::from_millis(120));
        st.mark_started();
        assert_eq!(
            l.verdict(st, user, &Bind::OnlyDesktop),
            Verdict::Held,
            "a daemon just started latches everyone"
        );
        assert!(l
            .fallback_gate(
                st,
                user,
                "sudo",
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            )
            .is_err());
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(l.verdict(st, user, &Bind::OnlyDesktop), Verdict::Unlocked);
        assert_eq!(host.checks(), 0);
    }

    /// Round 7 (B): the lock screen's reserved channel is the latch while
    /// locked. Open, the user is latched; a positive lock, waited on with
    /// no deadline, needs the channel open and the compositor saying
    /// locked, and either without the other is unknown (no approvals, and
    /// the password after the limit): malware holding a channel open
    /// cannot hold a request forever. A drop without the graceful
    /// "unlocked" keeps the user latched; only a graceful close, then the
    /// compositor's unlocked, then the hold, releases.
    #[test]
    fn the_lock_screens_channel_latches_until_a_graceful_unlock_and_the_hold() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        st.set_key_unlock_hold(Duration::from_millis(100));
        let user = "faceauth-channel-user";
        st.channel_open(user);
        host.locked.store(true, Ordering::SeqCst);
        assert_eq!(
            l.verdict(st, user, &Bind::OnlyDesktop),
            Verdict::Locked,
            "the channel and the lock"
        );
        assert!(matches!(
            l.fallback_gate(
                st,
                user,
                "sudo",
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            ),
            Err(Fallback::Wait("locked", _))
        ));
        host.locked.store(false, Ordering::SeqCst);
        assert_eq!(
            l.verdict(st, user, &Bind::OnlyDesktop),
            Verdict::Unknown,
            "the channel open, the compositor unlocked"
        );
        assert!(st.begin_fallback(user).is_none());
        st.backdate_doubt(user, UNKNOWN_LIMIT);
        assert!(
            matches!(
                l.fallback_gate(
                    st,
                    user,
                    "sudo",
                    &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
                ),
                Err(Fallback::No(_))
            ),
            "a channel held open never holds a request past the limit"
        );
        // Dropped without the graceful word: still latched.
        st.channel_closed(user, false);
        std::thread::sleep(Duration::from_millis(150));
        assert_ne!(
            l.verdict(st, user, &Bind::OnlyDesktop),
            Verdict::Unlocked,
            "a drop does not release"
        );
        assert_ne!(l.verdict(st, user, &Bind::OnlyDesktop), Verdict::Unlocked);
        // The compositor's lock with no channel open: unknown, not locked.
        host.locked.store(true, Ordering::SeqCst);
        assert_eq!(
            l.verdict(st, user, &Bind::OnlyDesktop),
            Verdict::Unknown,
            "the compositor locked, no channel"
        );
        // A later lock, and a graceful unlock: released after the hold.
        st.channel_open(user);
        assert_eq!(l.verdict(st, user, &Bind::OnlyDesktop), Verdict::Locked);
        st.channel_closed(user, true);
        assert_eq!(
            l.verdict(st, user, &Bind::OnlyDesktop),
            Verdict::Unknown,
            "closed, but the compositor still says locked"
        );
        host.locked.store(false, Ordering::SeqCst);
        assert_eq!(
            l.verdict(st, user, &Bind::OnlyDesktop),
            Verdict::Held,
            "the unlock seen, the hold running"
        );
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(l.verdict(st, user, &Bind::OnlyDesktop), Verdict::Unlocked);
        assert_eq!(host.checks(), 0);
    }

    /// Round 7 (B): after a real unlock (the channel closed gracefully and
    /// the compositor saying unlocked) approvals open about one hold later,
    /// with the shipped hold.
    #[test]
    fn approvals_open_about_one_hold_after_a_real_unlock() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let hold = Duration::from_millis(crate::consent::DEFAULT_HOLD_MS);
        let user = "faceauth-hold-measure-user";
        st.channel_open(user);
        host.locked.store(true, Ordering::SeqCst);
        assert_eq!(l.verdict(st, user, &Bind::OnlyDesktop), Verdict::Locked);
        // The unlock: the lock screen's graceful word, the compositor's.
        st.channel_closed(user, true);
        host.locked.store(false, Ordering::SeqCst);
        let t0 = Instant::now();
        while l
            .fallback_gate(
                st,
                user,
                "sudo",
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop),
            )
            .is_err()
        {
            assert!(t0.elapsed() < hold * 4, "approvals never opened");
            std::thread::sleep(Duration::from_millis(5));
        }
        let took = t0.elapsed();
        eprintln!(
            "approvals opened {:?} after the unlock, hold {:?}",
            took, hold
        );
        assert!(took >= hold, "{:?}", took);
        assert!(took < hold + Duration::from_millis(100), "{:?}", took);
    }

    /// Round 7 (C): a refusal at one account's share latches that account
    /// alone, for a hold; a refusal at the daemon's own limit latches
    /// everyone (item 10).
    #[test]
    fn a_refusal_at_one_share_latches_only_that_account() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        st.set_key_unlock_hold(Duration::from_millis(120));
        st.note_refusal_for("faceauth-share-alice");
        assert_eq!(
            l.verdict(st, "faceauth-share-alice", &Bind::OnlyDesktop),
            Verdict::Unknown
        );
        assert!(st.begin_fallback("faceauth-share-alice").is_none());
        assert_eq!(
            l.verdict(st, "faceauth-share-bob", &Bind::OnlyDesktop),
            Verdict::Unlocked,
            "bob is not latched"
        );
        assert!(st.begin_fallback("faceauth-share-bob").is_some());
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(
            l.verdict(st, "faceauth-share-alice", &Bind::OnlyDesktop),
            Verdict::Unlocked,
            "one hold later"
        );
    }

    /// Opus N1: an unknown lock state is waited on for at most
    /// `UNKNOWN_LIMIT`; past it the key line is a no, and the stack goes
    /// on to the password, never to the key. A positive lock is waited on
    /// without a deadline.
    #[test]
    fn an_unknown_lock_state_falls_to_the_password_in_time() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let user = "faceauth-unknown-user";
        host.unknown.store(true, Ordering::SeqCst);
        assert!(matches!(
            l.fallback_gate(
                st,
                user,
                "sudo",
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            ),
            Err(Fallback::Wait("unknown", _))
        ));
        assert!(st.doubt_for(user) < UNKNOWN_LIMIT);
        st.backdate_doubt(user, UNKNOWN_LIMIT);
        match l.fallback_gate(
            st,
            user,
            "sudo",
            &Asker::new(Origin::Desktop, Bind::OnlyDesktop),
        ) {
            Err(Fallback::No(why)) => assert!(why.contains("unknown"), "{}", why),
            other => panic!("{:?}", other),
        }
        host.unknown.store(false, Ordering::SeqCst);
        host.locked.store(true, Ordering::SeqCst);
        st.channel_open(user);
        assert!(matches!(
            l.fallback_gate(
                st,
                user,
                "sudo",
                &Asker::new(Origin::Desktop, Bind::OnlyDesktop)
            ),
            Err(Fallback::Wait("locked", _))
        ));
        assert_eq!(
            st.doubt_for(user),
            Duration::ZERO,
            "a positive lock ends the doubt"
        );
        host.locked.store(false, Ordering::SeqCst);
        assert_eq!(host.checks(), 0);
    }

    /// R2: the moment the lock screen's key lane asks for the key, a key
    /// line's check under way is stopped at once, not left to finish, and
    /// the unlock gets the key.
    #[test]
    fn the_unlock_lane_stops_an_approval_check_at_once() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let user = "faceauth-unlock-first-user";
        let rx = fallback_on_thread(l, st, user, None, Arc::new(AtomicBool::new(false)));
        assert!(eventually(|| host.running() == 1));
        host.locked.store(true, Ordering::SeqCst);
        let t0 = Instant::now();
        let unlock = unlock_on_thread(l, st, user, Arc::new(AtomicBool::new(false)));
        assert!(
            eventually(|| host.stopped(0)),
            "the approval check is stopped"
        );
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "at once: {:?}",
            t0.elapsed()
        );
        assert!(matches!(
            rx.recv_timeout(ANSWER).unwrap(),
            Fallback::Wait(..)
        ));
        assert!(
            eventually(|| host.checks() == 2 && host.running() == 1),
            "the unlock has the key"
        );
        host.touch(true);
        assert_eq!(unlock.recv_timeout(ANSWER).unwrap(), Unlocked::Touched);
        host.locked.store(false, Ordering::SeqCst);
    }

    fn leaked(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    /// Round 5 (Opus F3): a key line's touch and the lock screen's latch
    /// are serialized under the record's lock. Raced many times against a
    /// slow compositor question: no touch that began after the latch was
    /// published ever counts, and the fallback is gone once it is.
    #[test]
    fn a_fallback_touch_and_a_latch_are_serialized() {
        for i in 0..200u64 {
            let user = leaked(format!("faceauth-fb-race-{}", i));
            let st = test_state();
            let n = st.begin_fallback(user).unwrap();
            let latched = Arc::new(AtomicBool::new(false));
            let seen = Arc::clone(&latched);
            let toucher = std::thread::spawn(move || {
                let mut tries = Vec::new();
                loop {
                    let after = seen.load(Ordering::SeqCst);
                    let slow = || {
                        std::thread::sleep(Duration::from_micros(100));
                        unlocked_look()
                    };
                    let counted = st.fallback_touched(user, n, &slow, &|| true);
                    tries.push((after, counted));
                    if counted || after {
                        return tries;
                    }
                }
            });
            std::thread::sleep(Duration::from_micros((i % 7) * 60));
            st.latch_lock_screen(user);
            latched.store(true, Ordering::SeqCst);
            let tries = toucher.join().unwrap();
            assert!(
                !tries.iter().any(|(after, counted)| *after && *counted),
                "round {}: a touch counted after the latch",
                i
            );
            assert!(!st.fallback_live(user, n), "round {}", i);
        }
    }

    /// Round 5 (Opus F3, Codex): the lock screen's key-lane question
    /// latches as an ask does, against the card's commit and its
    /// consumption at once. A touch committed before the latch is dropped
    /// from the slot; none committed after it; and no poll that began
    /// after the latch was published hands one out.
    #[test]
    fn the_key_lane_latch_beats_the_commit_and_the_consumption() {
        for i in 0..200u64 {
            let user = leaked(format!("faceauth-lane-race-{}", i));
            let st = test_state();
            let _turn = st.test_live(1000, user);
            let (_d, tok) = card(st, user);
            let g = st.arm_key(user, &tok, false).unwrap();
            let latched = Arc::new(AtomicBool::new(false));
            let t = tok.clone();
            let toucher = std::thread::spawn(move || {
                let slow = || {
                    std::thread::sleep(Duration::from_micros(150));
                    unlocked_look()
                };
                st.key_touched(user, &t, g, Instant::now(), &slow, &|| true)
            });
            let seen = Arc::clone(&latched);
            let poller = std::thread::spawn(move || {
                let mut got = Vec::new();
                for _ in 0..40 {
                    let after = seen.load(Ordering::SeqCst);
                    got.push((after, matches!(st.poll(user), Some(Answer::Key))));
                    std::thread::sleep(Duration::from_micros(20));
                }
                got
            });
            std::thread::sleep(Duration::from_micros((i % 9) * 40));
            st.latch_lock_screen(user);
            latched.store(true, Ordering::SeqCst);
            toucher.join().unwrap();
            let got = poller.join().unwrap();
            assert!(
                !got.iter().any(|(after, key)| *after && *key),
                "round {}: a touch was handed out after the latch",
                i
            );
            assert!(
                !matches!(st.poll(user), Some(Answer::Key)),
                "round {}: a touch survived the latch",
                i
            );
        }
    }

    /// Round 5 (Codex's hold note): the hold runs from the unlock the
    /// daemon sees, and every refresh of the latch (the lock screen's
    /// question or ask) stops its clock. Refreshes that come faster than
    /// the hold leave no gap, even with the forged unlock read between
    /// every pair; a refresh that comes late leaves a gap as long as its
    /// lateness past the hold, which is what `key_unlock_hold_ms` is tuned
    /// against.
    #[test]
    fn a_refresh_inside_the_hold_leaves_no_gap_and_a_late_one_does() {
        use super::super::shell::LockState;
        let user = "faceauth-refresh-user";
        let st = test_state();
        st.set_key_unlock_hold(Duration::from_millis(100));
        st.latch_lock_screen(user);
        let stop = Arc::new(AtomicBool::new(false));
        let (s1, s2) = (Arc::clone(&stop), Arc::clone(&stop));
        let refresher = std::thread::spawn(move || {
            while !s1.load(Ordering::SeqCst) {
                st.latch_lock_screen(user);
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        let forger = std::thread::spawn(move || {
            while !s2.load(Ordering::SeqCst) {
                st.observe_lock(user, LockState::Unlocked);
                std::thread::sleep(Duration::from_millis(3));
            }
        });
        let until = Instant::now() + Duration::from_millis(600);
        let mut gaps = 0;
        while Instant::now() < until {
            if !st.unlock_holds(user) {
                gaps += 1;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        stop.store(true, Ordering::SeqCst);
        refresher.join().unwrap();
        forger.join().unwrap();
        assert_eq!(
            gaps, 0,
            "refreshes every 20 ms under a 100 ms hold leave no gap"
        );
        // A late refresh: the forged unlock read, then nothing for longer
        // than the hold.
        st.observe_lock(user, LockState::Unlocked);
        std::thread::sleep(Duration::from_millis(150));
        assert!(!st.unlock_holds(user), "past the hold, the gap is open");
        st.latch_lock_screen(user);
        assert!(st.unlock_holds(user), "and the late refresh closes it");
    }

    /// Round 5 (B, faceauth up): a card parked behind the lock already
    /// waits and comes back after the unlock. Its resume reads the session
    /// the way `consent::session_locked` does, the latch included, so it
    /// comes back only once the daemon has seen the unlock and the hold has
    /// passed, as the key lines do.
    #[test]
    fn a_parked_card_comes_back_after_the_unlock_and_the_hold() {
        use super::super::shell::LockState;
        let st = test_state();
        let user = "faceauth-parked-card-user";
        st.set_key_unlock_hold(Duration::from_millis(150));
        let lock = crate::presence::SessionLock::new();
        let t0 = Instant::now();
        lock.adopt(t0);
        st.latch_lock_screen(user);
        let compositor = std::cell::Cell::new(LockState::Locked);
        let session_locked = || {
            st.observe_lock(user, compositor.get());
            st.unlock_holds(user) || compositor.get() != LockState::Unlocked
        };
        assert_eq!(
            lock.resumed(Instant::now(), false, Duration::ZERO, &session_locked),
            None
        );
        compositor.set(LockState::Unlocked);
        assert_eq!(
            lock.resumed(Instant::now(), false, Duration::ZERO, &session_locked),
            None,
            "unlocked, but the hold has not passed"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(
            lock.resumed(Instant::now(), false, Duration::ZERO, &session_locked),
            Some("without a face")
        );
    }

    /// Round 8 (Codex 1, Opus F1): a latch held only by a dropped channel
    /// reads as unknown, never held, so the password deadline bounds it;
    /// the drop lets go once the compositor has said unlocked, look after
    /// look, for `DROP_CLEARS`, and the hold then runs as after any unlock.
    /// A lock seen meanwhile starts that over.
    #[test]
    fn a_dropped_channel_is_unknown_and_lets_go_after_a_steady_unlock() {
        use crate::lockgate::DROP_CLEARS;
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        st.set_key_unlock_hold(Duration::from_millis(40));
        let user = "faceauth-drop-user";
        let any = Bind::OnlyDesktop;
        st.channel_open(user);
        host.locked.store(true, Ordering::SeqCst);
        assert_eq!(l.verdict(st, user, &any), Verdict::Locked);
        st.channel_closed(user, false);
        host.locked.store(false, Ordering::SeqCst);
        assert_eq!(
            l.verdict(st, user, &any),
            Verdict::Unknown,
            "a drop-only latch is unknown, not held"
        );
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(
            l.verdict(st, user, &any),
            Verdict::Unknown,
            "no hold starts"
        );
        assert!(st.doubt_for(user) >= Duration::from_millis(60));
        st.backdate_doubt(user, UNKNOWN_LIMIT);
        assert!(
            matches!(
                l.fallback_gate(st, user, "sudo", &Asker::new(Origin::Desktop, any.clone())),
                Err(Fallback::No(_))
            ),
            "the password in time"
        );
        // A lock seen in the middle starts the steady stretch over.
        st.backdate_unlocked(user, DROP_CLEARS / 2);
        host.locked.store(true, Ordering::SeqCst);
        assert_eq!(l.verdict(st, user, &any), Verdict::Unknown);
        host.locked.store(false, Ordering::SeqCst);
        assert_eq!(l.verdict(st, user, &any), Verdict::Unknown);
        st.backdate_unlocked(user, DROP_CLEARS / 2);
        assert_eq!(
            l.verdict(st, user, &any),
            Verdict::Unknown,
            "half a stretch twice is not one"
        );
        st.backdate_unlocked(user, DROP_CLEARS);
        assert_eq!(
            l.verdict(st, user, &any),
            Verdict::Held,
            "the drop let go; the hold runs"
        );
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(l.verdict(st, user, &any), Verdict::Unlocked);
        assert_eq!(host.checks(), 0);
    }

    /// Round 8 (Opus F1): a stale second channel, left open after the
    /// lock screen's own closed gracefully, never reads as held: the
    /// channel open with the compositor saying unlocked is unknown, which
    /// the password deadline bounds, and no key approval runs meanwhile.
    #[test]
    fn a_stale_second_channel_is_unknown_and_bounded() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        st.set_key_unlock_hold(Duration::from_millis(40));
        let user = "faceauth-stale-user";
        let any = Bind::OnlyDesktop;
        st.channel_open(user);
        st.channel_open(user);
        host.locked.store(true, Ordering::SeqCst);
        assert_eq!(l.verdict(st, user, &any), Verdict::Locked);
        st.channel_closed(user, true);
        host.locked.store(false, Ordering::SeqCst);
        for _ in 0..3 {
            assert_eq!(l.verdict(st, user, &any), Verdict::Unknown, "never held");
            std::thread::sleep(Duration::from_millis(30));
        }
        assert!(
            st.begin_fallback(user).is_none(),
            "no key approval meanwhile"
        );
        st.backdate_doubt(user, UNKNOWN_LIMIT);
        assert!(
            matches!(
                l.fallback_gate(st, user, "sudo", &Asker::new(Origin::Desktop, any.clone())),
                Err(Fallback::No(_))
            ),
            "the password in time"
        );
        st.channel_closed(user, true);
        assert_eq!(
            l.verdict(st, user, &any),
            Verdict::Held,
            "the last one closed: the hold runs"
        );
    }

    /// Round 8 (Codex 1): a consent request that spent its wait budget
    /// sends the stack's key line straight to the password for a while,
    /// whatever the verdict reads by then, so the face line and the key
    /// line together stay inside the password deadline.
    #[test]
    fn a_spent_budget_sends_the_key_line_to_the_password() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let user = "faceauth-spent-user";
        let any = Bind::OnlyDesktop;
        assert!(l
            .fallback_gate(st, user, "sudo", &Asker::new(Origin::Desktop, any.clone()))
            .is_ok());
        st.note_budget_spent(user);
        match l.fallback_gate(st, user, "sudo", &Asker::new(Origin::Desktop, any.clone())) {
            Err(Fallback::No(why)) => assert!(why.contains("password"), "{}", why),
            other => panic!("{:?}", other),
        }
        assert!(
            l.fallback_gate(
                st,
                "faceauth-spent-other",
                "sudo",
                &Asker::new(Origin::Desktop, any.clone())
            )
            .is_ok(),
            "only that account"
        );
        st.backdate_budget_spent(user, UNKNOWN_LIMIT);
        assert!(
            l.fallback_gate(st, user, "sudo", &Asker::new(Origin::Desktop, any.clone()))
                .is_ok(),
            "for a while"
        );
    }

    /// Round 8 (Codex 4; owner ruling "unlock queue always is priority"):
    /// any account's unlock lane preempts approval checks on every
    /// account, so one key registered to two accounts never lets one
    /// account's unlock touch approve the other's request. Bob's check is
    /// stopped before Alice's unlock check starts, none of Bob's starts
    /// while Alice's is asked or inside the hold after it, and the touch
    /// that unlocks Alice answers only her check.
    #[test]
    fn one_accounts_unlock_touch_never_approves_another_accounts_request() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let hold = Duration::from_millis(300);
        st.set_key_unlock_hold(hold);
        let (alice, bob) = ("faceauth-shared-alice", "faceauth-shared-bob");
        let any = Bind::OnlyDesktop;
        // Bob's card, armed: may it ask the key now?
        let card_may_check = || {
            let _turn = st.test_live(1001, bob);
            let (_d, tok) = card(st, bob);
            let g = st.arm_key(bob, &tok, false).unwrap();
            st.key_may_check(bob, &tok, g, Instant::now())
        };
        *host.locked_user.lock().unwrap() = Some(alice);
        assert_eq!(l.verdict(st, bob, &any), Verdict::Unlocked);
        assert!(card_may_check(), "bob's card may ask the key");
        let fb = fallback_on_thread(l, st, bob, None, Arc::new(AtomicBool::new(false)));
        assert!(
            eventually(|| host.running() == 1),
            "bob's key line asks the key"
        );
        let unlock = unlock_on_thread(l, st, alice, Arc::new(AtomicBool::new(false)));
        assert!(eventually(|| host.stopped(0)), "bob's check is stopped");
        assert!(matches!(
            fb.recv_timeout(ANSWER).unwrap(),
            Fallback::Wait(..)
        ));
        assert!(
            eventually(|| host.checks() == 2 && host.running() == 1),
            "alice's unlock has the key"
        );
        assert!(
            matches!(
                l.fallback(
                    st,
                    bob,
                    "sudo",
                    None,
                    &|| false,
                    &Asker::new(Origin::Desktop, any.clone())
                ),
                Fallback::Wait(..)
            ),
            "bob's key line waits while alice's unlock is asked"
        );
        assert!(!card_may_check(), "and so does his card");
        host.touch(true);
        assert_eq!(unlock.recv_timeout(ANSWER).unwrap(), Unlocked::Touched);
        assert!(
            matches!(
                l.fallback(
                    st,
                    bob,
                    "sudo",
                    None,
                    &|| false,
                    &Asker::new(Origin::Desktop, any.clone())
                ),
                Fallback::Wait(..)
            ),
            "nor inside the hold after it"
        );
        assert!(!card_may_check());
        assert_eq!(
            host.checks(),
            2,
            "the one touch answered alice's check alone"
        );
        *host.locked_user.lock().unwrap() = None;
        l.watch_for_unlock(st, alice, &any);
        std::thread::sleep(hold + Duration::from_millis(100));
        assert!(card_may_check(), "once the hold has passed");
        let fb = fallback_on_thread(l, st, bob, None, Arc::new(AtomicBool::new(false)));
        assert!(
            eventually(|| host.checks() == 3),
            "bob's key line runs again"
        );
        host.touch(false);
        assert!(matches!(fb.recv_timeout(ANSWER).unwrap(), Fallback::No(_)));
    }

    /// Fix round 9 (Codex 1, Opus L2): the shared key's priority is a
    /// verified state, not a timer. It starts only after a fresh anchored
    /// Locked check for the asking account, so an account that is not
    /// locked cannot keep other accounts' keys off with key-unlock asks.
    /// Once started it holds, however slow or suspended that lock screen's
    /// retries are, until that account's anchored unlock and the hold
    /// after it, or until logind's records show its session has ended.
    /// Meanwhile another account's key line is told to wait (it goes to
    /// the password on its own budget).
    #[test]
    fn the_shared_keys_priority_holds_until_a_verified_end() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let hold = Duration::from_millis(80);
        st.set_key_unlock_hold(hold);
        let (alice, bob, carol, dave) = (
            "faceauth-prio-alice",
            "faceauth-prio-bob",
            "faceauth-prio-carol",
            "faceauth-prio-dave",
        );
        let logind = std::env::temp_dir().join(format!("faceauth-prio-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&logind);
        std::fs::create_dir_all(logind.join("sessions")).unwrap();
        // Each account's one desktop, controlled by its compositor and in
        // the foreground of a seat of its own (fix round 10: the priority
        // is bound to that session, which has to say ACTIVE=1).
        for (i, u) in [alice, bob, carol, dave].iter().enumerate() {
            std::fs::write(
                logind.join("sessions").join((i + 1).to_string()),
                format!(
                    "UID={}\nTYPE=wayland\nSEAT=seat0\nCONTROLLER=:1.{}\nACTIVE=1\n",
                    host.uid_of(u).unwrap(),
                    i + 1
                ),
            )
            .unwrap();
        }
        st.set_logind_root(&logind);
        let any = Bind::OnlyDesktop;
        let bob_may = || match st.begin_fallback(bob) {
            Some(n) => {
                st.end_fallback(bob, n);
                true
            }
            None => false,
        };
        // An account that is not locked asks: no priority, no hold.
        let carol_asks = l.unlock(st, carol, &any, &|| false);
        assert_eq!(carol_asks, no("the session is not locked"));
        assert!(
            bob_may(),
            "an unlocked account's asks keep nobody's key off"
        );
        // Alice is locked: her ask starts the priority, and an untouched
        // check does not end it, however long her lock screen takes to ask
        // again.
        *host.locked_user.lock().unwrap() = Some(alice);
        let unlock = unlock_on_thread(l, st, alice, Arc::new(AtomicBool::new(false)));
        assert!(eventually(|| host.running() == 1));
        host.touch(false);
        assert!(matches!(
            unlock.recv_timeout(ANSWER).unwrap(),
            Unlocked::No { .. }
        ));
        std::thread::sleep(hold * 4);
        assert!(!bob_may(), "no timer ends it");
        assert!(
            l.fallback_gate(st, bob, "sudo", &Asker::new(Origin::Desktop, any.clone()))
                .is_ok()
                && !bob_may(),
            "bob's line may ask, but no check of his starts"
        );
        // Alice's anchored unlock, seen when bob asks again: the hold, then
        // bob's key.
        *host.locked_user.lock().unwrap() = None;
        let _ = l.fallback_gate(st, bob, "sudo", &Asker::new(Origin::Desktop, any.clone()));
        assert!(!bob_may(), "inside the hold after alice's unlock");
        std::thread::sleep(hold * 2);
        assert!(bob_may(), "after it, bob's key line may run");
        // Dave is locked and asks; his session ends: logind's records end
        // the priority.
        *host.locked_user.lock().unwrap() = Some(dave);
        let unlock = unlock_on_thread(l, st, dave, Arc::new(AtomicBool::new(false)));
        assert!(eventually(|| host.running() == 1));
        host.touch(false);
        assert!(matches!(
            unlock.recv_timeout(ANSWER).unwrap(),
            Unlocked::No { .. }
        ));
        assert!(!bob_may());
        std::fs::remove_file(logind.join("sessions/4")).unwrap();
        assert!(bob_may(), "dave's session has ended");
        let _ = std::fs::remove_dir_all(&logind);
    }

    /// Fix round 10 (Opus N1, Codex 4): the priority is bound to the
    /// session the holder's lock screen asked from, pinned as it starts
    /// (the one desktop resolved then), and ends when logind's record for
    /// that session stops saying ACTIVE=1 or is gone, whatever other
    /// sessions the account has (the anchored unlock still ends it with
    /// the hold after it). The unlock check under way stops at once with
    /// it: after a switch to another account's VT, that account's touch at
    /// its own lock screen cannot reach the check of the session left
    /// behind, and no other check starts before hers has stopped
    /// (`claim`). A session in the background cannot start one.
    #[test]
    fn the_priority_is_bound_to_the_holders_foreground_session() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let hold = Duration::from_millis(80);
        st.set_key_unlock_hold(hold);
        let (alice, bob) = ("faceauth-fg-alice", "faceauth-fg-bob");
        let (a_uid, b_uid) = (host.uid_of(alice).unwrap(), host.uid_of(bob).unwrap());
        let logind = std::env::temp_dir().join(format!("faceauth-fg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&logind);
        std::fs::create_dir_all(logind.join("sessions")).unwrap();
        // Each desktop on a seat, as logind records one: session 9, the
        // second desktop below, on a second seat.
        let rec = |id: &str, uid: u32, controlled: bool, active: bool| {
            let seat = if id == "9" { "seat1" } else { "seat0" };
            let mut text = format!(
                "UID={}\nTYPE=wayland\nACTIVE={}\nSEAT={}\n",
                uid,
                u8::from(active),
                seat
            );
            if controlled {
                text.push_str(&format!("CONTROLLER=:1.{}\n", id));
            }
            std::fs::write(logind.join("sessions").join(id), text).unwrap();
        };
        rec("3", a_uid, true, true);
        rec("7", b_uid, true, false);
        st.set_logind_root(&logind);
        let bob_may = || match st.begin_fallback(bob) {
            Some(n) => {
                st.end_fallback(bob, n);
                true
            }
            None => false,
        };
        let gone = || Arc::new(AtomicBool::new(false));
        // Alice locked, asking from her one desktop: the priority is
        // pinned to session 3.
        *host.locked_user.lock().unwrap() = Some(alice);
        let unlock = unlock_on_thread(l, st, alice, gone());
        assert!(eventually(|| host.running() == 1));
        assert_eq!(
            st.priority_holders(),
            vec![(alice.to_string(), Bind::Session("3".into()))]
        );
        assert!(!bob_may());
        // A switch to bob's VT: her check stops at once, and then bob's
        // key may run.
        rec("3", a_uid, true, false);
        rec("7", b_uid, true, true);
        let t0 = Instant::now();
        assert_eq!(
            unlock.recv_timeout(ANSWER).unwrap(),
            no("the session is no longer in the foreground")
        );
        assert!(
            t0.elapsed() < Duration::from_millis(500),
            "{:?}",
            t0.elapsed()
        );
        assert!(eventually(|| host.running() == 0), "her check is stopped");
        assert!(st.priority_holders().is_empty());
        assert!(bob_may(), "bob's key line may run");
        // Her session in the background cannot start the priority.
        assert_eq!(
            l.unlock(st, alice, &Bind::Session("3".into()), &|| false),
            no("the session is not in the foreground")
        );
        assert!(bob_may(), "and keeps nobody's key off");
        // Back in front, with a second desktop of hers on another seat:
        // the priority bound to session 3 ends when 3 does, though she
        // still has a desktop.
        rec("3", a_uid, true, true);
        rec("7", b_uid, true, false);
        rec("9", a_uid, false, true);
        let unlock = unlock_on_thread_from(l, st, alice, Bind::Session("3".into()), gone());
        assert!(eventually(|| host.running() == 1));
        assert!(!bob_may());
        std::fs::remove_file(logind.join("sessions/3")).unwrap();
        assert_eq!(
            unlock.recv_timeout(ANSWER).unwrap(),
            no("the session is no longer in the foreground")
        );
        assert!(bob_may(), "an obsolete binding blocks nobody");
        let _ = std::fs::remove_dir_all(&logind);
    }

    /// Fix round 13 (Opus N3; Opus's probe
    /// `opus13_probe_seatless_unlock_session_is_in_front`, turned around):
    /// the unlock lane's foreground test, where the key's priority starts
    /// and where it ends, is the one approvals use (fix round 12, Opus N1):
    /// `ACTIVE=1` on a seat. logind writes a seatless session (an SSH
    /// login) as always active, and its user may take control of it and
    /// retype it wayland (lockgate.rs, `controller_of`), so by ACTIVE=1
    /// alone a second account's SSH login could answer "locked" for itself
    /// and pin the priority to a session that never goes to the background.
    #[test]
    fn a_seatless_session_never_holds_the_keys_priority() {
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        let (alice, bob) = ("faceauth-o13-alice", "faceauth-o13-bob");
        let (a_uid, b_uid) = (host.uid_of(alice).unwrap(), host.uid_of(bob).unwrap());
        let logind =
            std::env::temp_dir().join(format!("faceauth-seatless-prio-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&logind);
        std::fs::create_dir_all(logind.join("sessions")).unwrap();
        let w = |id: &str, text: String| {
            std::fs::write(logind.join("sessions").join(id), text).unwrap()
        };
        let alice_desktop = |seat: bool| {
            format!(
                "UID={}\nACTIVE=1\nSTATE=active\nTYPE=wayland\n{}CONTROLLER=:1.3\n",
                a_uid,
                if seat { "SEAT=seat0\n" } else { "" }
            )
        };
        w("3", alice_desktop(true));
        // Bob's SSH session, taken control of and retyped: no seat.
        w(
            "9",
            format!(
                "UID={}\nACTIVE=1\nSTATE=active\nREMOTE=1\nTYPE=wayland\nORIGINAL_TYPE=tty\nCLASS=user\nCONTROLLER=:1.9\n",
                b_uid
            ),
        );
        st.set_logind_root(&logind);
        let ssh = Bind::Session("9".into());
        assert!(!st.request_session_in_front(b_uid, &ssh), "approvals");
        assert!(
            !st.unlock_session_in_front(b_uid, &ssh),
            "nor the lock screen's unlock"
        );
        *host.locked_user.lock().unwrap() = Some(bob);
        assert_eq!(
            l.unlock(st, bob, &ssh, &|| false),
            no("the session is not in the foreground")
        );
        assert_eq!(host.running(), 0, "no check started");
        assert!(st.priority_holders().is_empty(), "and no priority");
        // Where it ends: a priority whose session shows no seat ends at
        // the next look, as one in the background does.
        st.latch_lock_screen(alice);
        assert!(st.start_priority(alice, a_uid, &Bind::Session("3".into())));
        assert!(st.holds_priority(alice));
        w("3", alice_desktop(false));
        assert!(
            !st.holds_priority(alice),
            "a seatless session holds nothing"
        );
        let _ = std::fs::remove_dir_all(&logind);
    }

    /// Fix round 8 (both reviewers): an open channel the compositor has
    /// contradicted expires. After `CHANNEL_EXPIRES` of anchored "unlocked"
    /// from looks no more than `LOOK_GAP` apart, the channel is no longer
    /// counted, its thread is told to close it, and the hold runs; a gap
    /// between looks starts the steady stretch over.
    #[test]
    fn a_stale_open_channel_expires_after_a_steady_unlock() {
        use crate::consent::{CHANNEL_EXPIRES, LOOK_GAP};
        let host = FakeHost::new(false);
        let l = lane(host, SHORT, LONG);
        let st = test_state();
        st.set_key_unlock_hold(Duration::from_millis(40));
        let user = "faceauth-expire-user";
        let any = Bind::OnlyDesktop;
        let id = st.channel_open(user);
        assert_eq!(
            l.verdict(st, user, &any),
            Verdict::Unknown,
            "open, unlocked"
        );
        st.backdate_unlocked(user, CHANNEL_EXPIRES);
        st.backdate_last_look(user, LOOK_GAP + Duration::from_millis(500));
        assert_eq!(
            l.verdict(st, user, &any),
            Verdict::Unknown,
            "a gap starts over"
        );
        assert!(!st.channel_expired(id));
        st.backdate_unlocked(user, CHANNEL_EXPIRES);
        assert_eq!(
            l.verdict(st, user, &any),
            Verdict::Held,
            "expired: the hold runs"
        );
        assert!(st.channel_expired(id), "its thread is told to close it");
        assert_eq!(st.channels_open(user), 0);
        st.channel_end(user, id, false);
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(
            l.verdict(st, user, &any),
            Verdict::Unlocked,
            "its end afterwards is no drop"
        );
    }

    /// Fix round 8 (Opus L3): a commit asks the lock question before it
    /// takes the consent record's lock, so a slow look never holds every
    /// other request up, and revalidates under the lock: a latch that
    /// began while it looked makes the touch count for nothing.
    #[test]
    fn a_commit_looks_before_it_takes_the_record() {
        let user = "faceauth-look-first-user";
        let st = test_state();
        let n = st.begin_fallback(user).unwrap();
        let looking = Arc::new(AtomicBool::new(false));
        let l2 = Arc::clone(&looking);
        let toucher = std::thread::spawn(move || {
            let slow = || {
                l2.store(true, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(300));
                unlocked_look()
            };
            st.fallback_touched(user, n, &slow, &|| true)
        });
        assert!(eventually(|| looking.load(Ordering::SeqCst)));
        let t0 = Instant::now();
        let _ = st.unlock_holds("faceauth-look-first-other");
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "the record is free while the commit looks: {:?}",
            t0.elapsed()
        );
        st.latch_lock_screen(user);
        assert!(
            !toucher.join().unwrap(),
            "a latch begun during the look wins"
        );
        // Without one, the same slow look commits.
        let other = "faceauth-look-first-clean";
        let n = st.begin_fallback(other).unwrap();
        let slow = || {
            std::thread::sleep(Duration::from_millis(50));
            unlocked_look()
        };
        assert!(st.fallback_touched(other, n, &slow, &|| true));
    }

    /// Fix round 8 (Codex, Opus L1): polling paths share one answer for up
    /// to `POLL_CACHE`, and concurrent polls of the same session wait for
    /// the one look under way rather than each starting a unit; the
    /// commits (the card's, the key line's, and the unlock lane's lock
    /// check) always ask afresh.
    #[test]
    fn polls_share_a_recent_answer_and_commits_ask_afresh() {
        let host = FakeHost::new(false);
        let l: &'static KeyLane =
            Box::leak(Box::new(KeyLane::with_cache(host, SHORT, LONG, POLL_CACHE)));
        let st = test_state();
        let user = "faceauth-cache-user";
        let any = Bind::OnlyDesktop;
        assert_eq!(l.verdict(st, user, &any), Verdict::Unlocked);
        assert_eq!(l.verdict(st, user, &any), Verdict::Unlocked);
        assert_eq!(
            host.asks.load(Ordering::SeqCst),
            1,
            "one look for two polls"
        );
        let _ = l.look(user, &any);
        let _ = l.look(user, &any);
        assert_eq!(host.asks.load(Ordering::SeqCst), 3, "a commit always asks");
        // Concurrent polls coalesce onto one look.
        *host.ask_delay.lock().unwrap() = Duration::from_millis(200);
        let other = "faceauth-cache-other";
        let polls: Vec<_> = (0..8)
            .map(|_| std::thread::spawn(move || l.verdict(st, other, &Bind::OnlyDesktop)))
            .collect();
        for p in polls {
            assert_eq!(p.join().unwrap(), Verdict::Unlocked);
        }
        assert_eq!(host.asks.load(Ordering::SeqCst), 4, "eight polls, one look");
        *host.ask_delay.lock().unwrap() = Duration::ZERO;
        std::thread::sleep(POLL_CACHE + Duration::from_millis(50));
        let _ = l.verdict(st, user, &any);
        assert_eq!(
            host.asks.load(Ordering::SeqCst),
            5,
            "a stale answer is asked again"
        );
        // The lane the daemon uses caches; a test lane, built plain, does not.
        assert_eq!(KEY.cache_ttl, POLL_CACHE);
        assert_eq!(lane(host, SHORT, LONG).cache_ttl, Duration::ZERO);
    }

    /// Fix round 9 (Codex 3, Opus M1): a nod approval commits on a fresh
    /// anchored look, as a key touch does, asked before the consent record's
    /// lock and judged under it with the epoch: a polled answer from before
    /// a lock never lets it through, and a lock that lands during
    /// recognition, confirmation or the look itself refuses it.
    #[test]
    fn a_nod_commits_only_on_a_fresh_unlocked_look() {
        let host = FakeHost::new(false);
        let l: &'static KeyLane =
            Box::leak(Box::new(KeyLane::with_cache(host, SHORT, LONG, POLL_CACHE)));
        let st = test_state();
        let user = "faceauth-nod-commit-user";
        let any = Bind::OnlyDesktop;
        assert_eq!(
            l.verdict(st, user, &any),
            Verdict::Unlocked,
            "polled while nodding"
        );
        host.locked.store(true, Ordering::SeqCst);
        assert_eq!(
            l.verdict(st, user, &any),
            Verdict::Unlocked,
            "the cache still says so"
        );
        assert!(
            !l.nod_may_commit(st, user, &any),
            "the lock landed during the nods"
        );
        host.locked.store(false, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(10));
        let fresh = test_state();
        assert!(
            l.nod_may_commit(fresh, user, &any),
            "unlocked and nothing latched"
        );
        // A lock that lands while the commit looks.
        *host.ask_delay.lock().unwrap() = Duration::from_millis(200);
        let racing = test_state();
        let t = std::thread::spawn(move || {
            l.nod_may_commit(racing, "faceauth-nod-race", &Bind::OnlyDesktop)
        });
        std::thread::sleep(Duration::from_millis(50));
        racing.latch_lock_screen("faceauth-nod-race");
        assert!(!t.join().unwrap(), "a latch begun during the look wins");
        *host.ask_delay.lock().unwrap() = Duration::ZERO;
    }

    /// Fix round 9 (Opus M1): the cache stamps each look with when it
    /// began, so an older look that finishes late never overwrites a newer
    /// answer, and no look clears another's place in line.
    #[test]
    fn an_older_look_never_overwrites_a_newer_answer() {
        let host = FakeHost::new(false);
        let l: &'static KeyLane =
            Box::leak(Box::new(KeyLane::with_cache(host, SHORT, LONG, POLL_CACHE)));
        let st = test_state();
        let user = "faceauth-cache-order-user";
        *host.ask_delay.lock().unwrap() = Duration::from_millis(300);
        let slow = std::thread::spawn(move || l.verdict(st, user, &Bind::OnlyDesktop));
        std::thread::sleep(Duration::from_millis(50));
        *host.ask_delay.lock().unwrap() = Duration::ZERO;
        host.locked.store(true, Ordering::SeqCst);
        let _ = l.look(user, &Bind::OnlyDesktop);
        let _ = slow.join().unwrap();
        assert_eq!(
            l.cached(user, &Bind::OnlyDesktop),
            Some(LockState::Locked),
            "the newer answer stands"
        );
        assert!(!l.look_in_flight(user, &Bind::OnlyDesktop));
    }
}
