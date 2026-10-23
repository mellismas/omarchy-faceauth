//! The machine checks behind `faceauth doctor`: the IR sensor and its
//! node, the udev tags, and the PAM stacks. They read sysfs, the udev
//! database and the PAM files directly, without asking the daemon.

#[cfg(test)]
use anyhow::anyhow;
use std::path::Path;

/// The IR sensor as sysfs names it, without opening its node: the subdev's
/// directory name (`v4l-subdev8`) and its `name` attribute (`ov7251 3-0060`).
/// Matched by name, never by number, like the udev rule.
pub(super) fn ir_sensor_from_sysfs(class_dir: &Path) -> Option<(String, String)> {
    let mut nodes: Vec<_> = std::fs::read_dir(class_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    nodes.sort();
    for p in nodes {
        let node = p.file_name()?.to_str()?.to_string();
        if !node.starts_with("v4l-subdev") {
            continue;
        }
        let name = std::fs::read_to_string(p.join("name"))
            .ok()?
            .trim()
            .to_string();
        if name.starts_with("ov7251 ") {
            return Some((node, name));
        }
    }
    None
}

/// The udev database's current tags for a character device (`Q:` lines in
/// `/run/udev/data/c<major>:<minor>`). `G:` lines are every tag the device
/// ever carried and stay after a rule takes one away, so they are not read.
pub(super) fn udev_current_tags(db_dir: &Path, rdev: u64) -> Vec<String> {
    let (major, minor) = (nix::sys::stat::major(rdev), nix::sys::stat::minor(rdev));
    std::fs::read_to_string(db_dir.join(format!("c{}:{}", major, minor)))
        .map(|t| {
            t.lines()
                .filter_map(|l| l.strip_prefix("Q:"))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// Whether this process could open the node for writing: the ACL as the
/// kernel applies it, which is the grant that matters.
pub(super) fn user_can_write(dev: &Path) -> bool {
    std::fs::OpenOptions::new().write(true).open(dev).is_ok()
}

/// The verdict on the IR sensor's control node. Right is root:root 0600 with
/// no uaccess tag and no write access for the caller; anything looser lets a
/// process running as the user change the sensor under the daemon.
pub(super) fn ir_node_verdict(
    mode: u32,
    uid: u32,
    gid: u32,
    current_tags: &[String],
    user_can_write: bool,
) -> (&'static str, String) {
    ir_node_verdict_for(
        "72-faceauth-ir.rules",
        mode,
        uid,
        gid,
        current_tags,
        user_can_write,
    )
}

/// `ir_node_verdict` for a node the udev rule `rule` locks (the IR
/// capture node's is face setup's 72-faceauth-ir-node.rules).
pub(super) fn ir_node_verdict_for(
    rule: &str,
    mode: u32,
    uid: u32,
    gid: u32,
    current_tags: &[String],
    user_can_write: bool,
) -> (&'static str, String) {
    let root_only = uid == 0 && gid == 0 && mode & 0o077 == 0;
    let uaccess = current_tags.iter().any(|t| t == "uaccess");
    let running_as_root = nix::unistd::geteuid().is_root();
    let mut notes = Vec::new();
    if !root_only {
        notes.push(format!("mode {:04o} uid {} gid {} (want root:root 0600: the udev rule {} is missing or not applied)", mode, uid, gid, rule));
    }
    if uaccess {
        notes.push("tagged uaccess, so the seat user is granted access on every login".to_string());
    }
    if user_can_write && !running_as_root {
        notes.push("this user can write the sensor's controls (an ACL granted before the rule survives until reboot or `setfacl -b` on the node)".to_string());
    }
    if notes.is_empty() {
        (
            "pass",
            if running_as_root {
                "root-only, no uaccess tag (the ACL was not checked: run doctor as the user for that)".to_string()
            } else {
                "root-only, no uaccess tag, no write access for this user".to_string()
            },
        )
    } else {
        ("warn", notes.join("; "))
    }
}

/// The walk-away lock's helper as the verdict reads it: whether it exists,
/// whether it is a regular file, its mode and its owner, following a
/// symlink as the daemon's exec does. `Err` when its metadata cannot be
/// read for any reason but its absence.
pub(super) fn lock_helper_state(path: &Path) -> std::io::Result<(bool, bool, u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(path) {
        Ok(m) => Ok((true, m.is_file(), m.mode(), m.uid())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((false, false, 0, 0)),
        Err(e) => Err(e),
    }
}

/// The verdict on the walk-away lock's helper, which the daemon runs as
/// root by its fixed path: it must exist, be a regular file owned by root,
/// be executable, and be writable by nobody else, or a lock never happens
/// or runs what another account wrote.
pub(super) fn lock_helper_verdict(
    mode: u32,
    uid: u32,
    is_file: bool,
    exists: bool,
) -> (&'static str, String) {
    if !exists {
        return (
            "fail",
            "missing: the walk-away lock cannot lock the session".into(),
        );
    }
    if !is_file {
        return ("fail", "not a regular file".into());
    }
    let mut wrong = Vec::new();
    if uid != 0 {
        wrong.push(format!("owned by uid {}, not root", uid));
    }
    if mode & 0o111 == 0 {
        wrong.push("not executable".to_string());
    }
    if mode & 0o022 != 0 {
        wrong.push(format!(
            "mode {:04o} lets group or other write it",
            mode & 0o7777
        ));
    }
    if wrong.is_empty() {
        ("pass", format!("root-owned, mode {:04o}", mode & 0o7777))
    } else {
        ("fail", wrong.join("; "))
    }
}

/// One helper's state as the faceauthd-down key path reads it: the state
/// `lock_helper_state` gives and whether the path itself is a symlink,
/// which the PAM module refuses to run.
pub(super) type HelperState<'a> = (&'a str, std::io::Result<(bool, bool, u32, u32)>, bool);

/// The faceauthd-down key path (round 5's A; fix round 10, item 6: stock
/// pam_u2f's behavior): with faceauthd down, the stacks' key line runs
/// `faceauth-keycheck` as root, by its fixed path, only when it is a
/// root-owned regular file, no symlink, that nobody else can write. A
/// helper the module would refuse fails the row; one missing warns, since
/// the key line then falls to the password; a state it cannot read is
/// unknown.
pub(super) fn key_down_verdict(helpers: &[HelperState<'_>]) -> (&'static str, String) {
    let mut missing = Vec::new();
    let mut refused = Vec::new();
    let mut unknown = Vec::new();
    for (path, state, link) in helpers {
        match state {
            Err(e) => unknown.push(format!("{}: {}", path, e)),
            Ok((false, ..)) => missing.push(path.to_string()),
            Ok(_) if *link => {
                refused.push(format!("{}: a symlink, which the module never runs", path))
            }
            Ok((exists, is_file, mode, uid)) => {
                let (st, d) = lock_helper_verdict(*mode, *uid, *is_file, *exists);
                if st != "pass" {
                    refused.push(format!("{}: {}", path, d));
                }
            }
        }
    }
    if !refused.is_empty() {
        return (
            "fail",
            format!(
                "{}; with faceauthd down, the key line falls to the password",
                refused.join("; ")
            ),
        );
    }
    if !unknown.is_empty() {
        return ("unknown", unknown.join("; "));
    }
    if !missing.is_empty() {
        return (
            "warn",
            format!(
                "{} missing: with faceauthd down, the key line falls to the password",
                missing.join(" and ")
            ),
        );
    }
    (
        "pass",
        "when faceauthd is down, sudo's and polkit's key line asks the key itself, as stock pam_u2f does"
            .into(),
    )
}

/// The `lock.state` row (round 6, Opus N1): what the compositor says of
/// the session lock, as the key lines read it. Unknown sends every key
/// line and parked request to the password after the unknown limit: a
/// warning with the reason (`why`). No graphical session at all is a text
/// console.
pub(super) fn lock_state_verdict(
    state: faceauth_daemon::lockgate::LockState,
    desktop: faceauth_daemon::lockgate::Desktop,
    why: &str,
) -> (&'static str, String) {
    use faceauth_daemon::lockgate::{Desktop, LockState, UNKNOWN_LIMIT};
    match (state, desktop) {
        (LockState::Locked, _) => ("pass", "the compositor says the session is locked".into()),
        (LockState::Unlocked, _) => ("pass", "the compositor says the session is unlocked".into()),
        (LockState::Unknown, Desktop::None) => (
            "info",
            "no graphical session: a text console, where the key line needs no lock check".into(),
        ),
        (LockState::Unknown, _) => (
            "warn",
            format!(
                "the session's lock state cannot be read{}: key lines and parked requests fall to the password after {} s",
                if why.is_empty() { String::new() } else { format!(" ({})", why) },
                UNKNOWN_LIMIT.as_secs()
            ),
        ),
    }
}

/// The `lock.anchor` row (round 7, A): the chain the daemon's anchored
/// question asks the lock through. `controller` is the bus name logind gives for the
/// user's one graphical session, `pid` what the system bus says is behind
/// it, `matched` whether exactly one Hyprland socket's listener is that
/// pid.
pub(super) fn anchor_verdict(
    controller: Option<&str>,
    pid: Option<u32>,
    matched: Option<bool>,
) -> (&'static str, String) {
    match (controller, pid, matched) {
        (None, _, _) => (
            "info",
            "logind gives no CONTROLLER for one graphical session of yours (none, or two): the daemon reads the lock as unknown, so key lines and parked requests go to the password after 10 s".into(),
        ),
        (Some(name), None, _) => (
            "warn",
            format!("the system bus names no process behind the compositor's bus name {}", name),
        ),
        (Some(_), Some(pid), Some(true)) => (
            "pass",
            format!("logind names the compositor (pid {}), and exactly one Hyprland socket is its own", pid),
        ),
        (Some(_), Some(pid), _) => (
            "warn",
            format!("no Hyprland socket under your runtime directory, or more than one, has the compositor (pid {}) as its listener: the daemon reads the lock as unknown", pid),
        ),
    }
}

/// The `camera.ir_capture` row (fix round 11, Mike's ruling): whether
/// the capture node the IR frames arrive on (`node`) is locked to root.
/// `rule` is the rule setup would write for it, or why it is left open;
/// `file` the text of `irlock::RULE_FILE`, if there is one; `live` the
/// node's live state as `ir_node_verdict` reads it.
pub(super) fn ir_capture_verdict(
    rule: Result<&str, &str>,
    file: Option<&str>,
    node: &str,
    live: (&'static str, String),
) -> (&'static str, String) {
    use faceauth_camera::irlock::RULE_FILE;
    let rule = match rule {
        Ok(r) => r,
        Err(why) => return ("info", format!("left open: {}", why)),
    };
    // Every line of the rule (a USB camera's has two) must be in the file.
    let held = |t: &str| {
        rule.lines()
            .all(|r| t.lines().any(|l| l.trim() == r.trim()))
    };
    if !file.is_some_and(held) {
        return (
            "warn",
            format!(
                "/dev/{} is not locked: {} does not hold its rule; run face setup again to write it",
                node, RULE_FILE
            ),
        );
    }
    match live {
        ("pass", _) => (
            "pass",
            format!("/dev/{} is root's alone ({})", node, RULE_FILE),
        ),
        (_, d) => (
            "warn",
            format!("/dev/{}: the rule is written but not in force: {}", node, d),
        ),
    }
}

/// The `camera.ir_capture` row once face removal has deleted the rule
/// (fix round 13, Codex 6, Opus nit): `rule_file` whether the rule file is
/// there, `left` whether the node is still what the lock left
/// (`irlock::lock_left`), None when it could not be read. A fail with the
/// way out when the lock outlived its rule; None when this has nothing to
/// say and the rule's own verdict stands.
pub(super) fn ir_lock_left_verdict(
    node: &str,
    rule_file: bool,
    left: Option<bool>,
) -> Option<(&'static str, String)> {
    (!rule_file && left == Some(true)).then(|| {
        (
            "fail",
            format!(
                "/dev/{} is still locked though no rule holds it (root's group, or an ACL whose mask shuts out the seat user): `sudo faceauth cam ir-reset`, then `sudo udevadm trigger --action=add --subsystem-match=video4linux`, or replug the camera",
                node
            ),
        )
    })
}

/// The `key.cancel` row (round 19): what the key helper's and pam_u2f's
/// dynamic symbol tables say of `fido_dev_get_assert`, the call the
/// helper's wrapper takes from pam_u2f so that a stopped check cancels
/// the key's wait (None for a file not there or not an ELF file).
pub(super) fn key_cancel_verdict(
    helper: Option<faceauth_daemon::elfsym::Sym>,
    pam_u2f: Option<faceauth_daemon::elfsym::Sym>,
) -> (&'static str, String) {
    use faceauth_daemon::elfsym::Sym;
    const COST: &str = "a stopped key check cannot cancel the key's wait, so the key keeps blinking for up to 30 s after a card is answered another way, and answers the next check busy meanwhile";
    match (helper, pam_u2f) {
        (Some(Sym::Exported), None) => (
            "info",
            "pam_u2f is not installed, so no key check runs".into(),
        ),
        (Some(Sym::Exported), Some(Sym::Imported)) => (
            "pass",
            "a stopped key check cancels the key's wait, so the key stops blinking with it".into(),
        ),
        (Some(Sym::Exported), Some(_)) => (
            "warn",
            format!(
                "pam_u2f no longer asks the key through libfido2's fido_dev_get_assert, so {}",
                COST
            ),
        ),
        _ => (
            "warn",
            format!(
                "/usr/lib/faceauth/faceauth-keycheck does not export fido_dev_get_assert, so {}; reinstall the package",
                COST
            ),
        ),
    }
}

/// The `key.lease` row (fix round 11): the key's lease file, as
/// `(is_file, uid, mode)`, or None when it is not there. Every key check
/// holds it while it runs; without it no check runs at all, and one that
/// others could open, they could hold.
pub(super) fn key_lease_verdict(state: Option<(bool, u32, u32)>) -> (&'static str, String) {
    use faceauth_daemon::lockgate::KEY_LEASE;
    match state {
        None => (
            "warn",
            format!(
                "{} is missing, so no security key check runs; `sudo systemd-tmpfiles --create` makes it from the package's tmpfiles entry",
                KEY_LEASE
            ),
        ),
        Some((true, 0, mode)) if mode & 0o077 == 0 => (
            "pass",
            format!("{} is root's alone; one key check runs at a time", KEY_LEASE),
        ),
        Some((is_file, uid, mode)) => (
            "fail",
            format!(
                "{} is {} uid {} mode {:04o}, not a root-only file, so no key check takes it",
                KEY_LEASE,
                if is_file { "a file of" } else { "not a regular file;" },
                uid,
                mode & 0o7777
            ),
        ),
    }
}

/// The `key.down_polkit` row (round 6, item 11): polkit's socket-activated
/// helper, from `systemctl show polkit-agent-helper@….service -p
/// DeviceAllow -p ProtectHome` (`props`; None when the unit is not there).
/// Its sandbox allows /dev/null; with faceauthd down its key line needs
/// pam-u2f's drop-in to reach the key's hidraw node, as stock pam_u2f does
/// (fix round 10, item 6: it asks no lock question, so /run/user does not
/// matter).
pub(super) fn polkit_helper_verdict(props: Option<&str>) -> (&'static str, String) {
    let Some(text) = props else {
        return (
            "info",
            "no socket-activated polkit helper: polkit's key line runs in the agent's helper as stock".into(),
        );
    };
    let hidraw = text.lines().any(|l| {
        l.strip_prefix("DeviceAllow=")
            .is_some_and(|v| v.split_whitespace().next() == Some("char-hidraw"))
    });
    if hidraw {
        (
            "pass",
            "polkit's helper may reach the key (char-hidraw)".into(),
        )
    } else {
        (
            "warn",
            "polkit's helper has no hidraw access: with faceauthd down, polkit's key line falls to the password; install pam-u2f, whose drop-in allows char-hidraw".into(),
        )
    }
}

/// Whether this process is refused the node read-write, the way the
/// camera probe opens it: the IR sensor's root-only node, for a user.
pub(super) fn node_denied(dev: &Path) -> bool {
    matches!(
        std::fs::OpenOptions::new().read(true).write(true).open(dev),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied
    )
}

/// Whether an error from the camera probe is the node refusing to open.
pub(super) fn is_permission_denied(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .map(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
            .unwrap_or(false)
    })
}

/// A PAM line that counts: not blank, not a comment.
fn pam_active_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// The verdict on one PAM service file. `pam.lock` must be closed by a live
/// `auth required|requisite pam_deny.so` AFTER the face line: a commented-out
/// pam_deny closes nothing, and one above the face line runs before it. On
/// the elevation services `timeout=` on a consent line is flagged, because
/// the module ignores it and an administrator reading the file would take it
/// for a bound.
pub(super) fn pam_stack_verdict(id: &str, text: &str) -> (&'static str, String) {
    let want_deny = id == "pam.lock";
    let elevation = id == "pam.sudo" || id == "pam.polkit";
    let face_lines: Vec<&str> = pam_active_lines(text)
        .filter(|l| l.contains("pam_faceauth.so"))
        .collect();
    let has = !face_lines.is_empty();
    let deny_after_face = {
        let mut seen_face = false;
        let mut closed = false;
        for l in pam_active_lines(text) {
            if l.contains("pam_faceauth.so") {
                seen_face = true;
            } else if seen_face && l.contains("pam_deny.so") {
                let mut words = l.split_whitespace();
                let control = (words.next(), words.next());
                if matches!(
                    control,
                    (Some("auth"), Some("required")) | (Some("auth"), Some("requisite"))
                ) {
                    closed = true;
                }
            }
        }
        closed
    };
    let prompt = face_lines.iter().any(|l| {
        l.split_whitespace()
            .any(|w| w == "prompt" || w.starts_with("prompt="))
    });
    let consent = face_lines
        .iter()
        .any(|l| l.split_whitespace().any(|w| w == "consent"));
    let consent_timeout = face_lines.iter().any(|l| {
        l.split_whitespace().any(|w| w == "consent")
            && l.split_whitespace().any(|w| w.starts_with("timeout="))
    });
    let mut st = if !has {
        if id == "pam.greeter" {
            "info"
        } else {
            "warn"
        }
    } else if want_deny && !deny_after_face {
        "fail"
    } else if elevation && !consent {
        // A face line on sudo or polkit without `consent` (a pasted lock
        // line, a misspelt word, the older `prompt`) asks for a plain look,
        // which the daemon refuses from a root caller: the line is dead,
        // not passive (A3).
        "fail"
    } else {
        "pass"
    };
    let mut d = if has {
        "wired".to_string()
    } else {
        "not wired".to_string()
    };
    if has && elevation {
        d += if consent {
            ", consent (window + nod)"
        } else if prompt {
            ", prompt: the daemon refuses a plain look from sudo or polkit; use consent"
        } else {
            ", NO consent or prompt: the daemon refuses a plain look from sudo or polkit; add consent"
        };
    }
    if has && want_deny {
        d += if deny_after_face {
            ", closed by pam_deny"
        } else {
            ", NOT closed by a live 'auth required pam_deny.so' after the face line: when the module ignores, the stack's answer is left to Linux-PAM's own default for a stack with no verdict (1.7.2 refuses it, but that is library behavior, not a promise); add the pam_deny line"
        };
    }
    if consent_timeout {
        d += ", timeout= on a consent line is ignored (the window waits until answered): remove it";
        if st == "pass" {
            st = "warn";
        }
    }
    (st, d)
}

/// The verdict on the lock screen's key lane, `omarchy-lock-fido2`: the
/// daemon's `key-unlock` line, closed by a live pam_deny after it, and no
/// pam_u2f line anywhere in it, which would ask the key itself, beside
/// the daemon and outside its rules for the touch.
pub(super) fn key_lane_verdict(text: Option<&str>) -> (&'static str, String) {
    let Some(text) = text else {
        return ("info", "no lock screen key lane".into());
    };
    let lines: Vec<&str> = pam_active_lines(text).collect();
    if lines.iter().any(|l| l.contains("pam_u2f.so")) {
        return (
            "fail",
            "a pam_u2f line asks the key outside the daemon; the lane must be pam_faceauth's key-unlock line alone".into(),
        );
    }
    let at = lines.iter().position(|l| {
        l.contains("pam_faceauth.so") && l.split_whitespace().any(|w| w == "key-unlock")
    });
    let Some(at) = at else {
        return ("warn", "no key-unlock line (not wired)".into());
    };
    let closed = lines[at + 1..].iter().any(|l| {
        let mut w = l.split_whitespace();
        matches!(
            (w.next(), w.next()),
            (Some("auth"), Some("required")) | (Some("auth"), Some("requisite"))
        ) && l.contains("pam_deny.so")
    });
    if closed {
        (
            "pass",
            "wired: the daemon's key-unlock line, closed by pam_deny".into(),
        )
    } else {
        ("fail", "no live pam_deny after the key-unlock line".into())
    }
}

/// The doctor's row for the security key on one lane of the consent card,
/// or on the lock screen (`what` says which). A key nobody set up is
/// information; a key held back (a pam_u2f option the lane cannot mirror,
/// a PIN the lock screen has no field for, a check not installed right) is
/// a warning, with the reason.
pub(super) fn key_row(
    what: &str,
    offer: Result<faceauth_daemon::consent::KeyPolicy, faceauth_daemon::consent::KeyOff>,
) -> (&'static str, String) {
    use faceauth_daemon::consent::KeyOff;
    match offer {
        Ok(p) => (
            "pass",
            format!(
                "{} offers the key{}",
                what,
                match (p.pin == Some(true), p.uv == Some(true)) {
                    (false, false) => "",
                    (true, false) => ", with its PIN",
                    (false, true) => ", with verification on the key",
                    (true, true) => ", with its PIN and verification on the key",
                }
            ),
        ),
        Err(KeyOff::NotSetUp(why)) => ("info", format!("not offered: {}", why)),
        Err(KeyOff::Withheld(why)) => ("warn", format!("not offered: {}", why)),
    }
}

/// What `fprint.service` reads: whether fprintd's daemon, libfprint and
/// pam_fprintd are installed, how many readers fprintd says it sees (None
/// when it could not be asked), and the user's enrolled prints as fprintd
/// keeps them (an error as a non-root caller, who cannot read them).
pub(super) struct FprintFacts<'a> {
    pub fprintd: bool,
    pub libfprint: bool,
    pub pam_fprintd: bool,
    pub readers: Option<usize>,
    pub prints: Result<usize, String>,
    pub user: &'a str,
}

/// The readers fprintd says it sees, from `fprintd-list`'s output in the C
/// locale: its "found N devices" line, or none for "No devices available";
/// None for anything else (fprintd not answering, a changed format).
pub(super) fn readers_of_list(text: &str) -> Option<usize> {
    text.lines().find_map(|l| {
        let l = l.trim();
        if l.starts_with("No devices available") {
            return Some(0);
        }
        l.strip_prefix("found ")
            .and_then(|r| r.strip_suffix(" devices"))
            .and_then(|n| n.parse().ok())
    })
}

/// The verdict on fprintd itself: information when no part of it is
/// installed (no fingerprint here), a warning for a part missing, no
/// reader seen, or no finger enrolled, and a pass with the counts. Prints
/// the caller cannot read are said to need root, not counted as none.
pub(super) fn fprint_service_verdict(f: &FprintFacts<'_>) -> (&'static str, String) {
    if !f.fprintd && !f.libfprint && !f.pam_fprintd {
        return ("info", "fprintd is not installed (no fingerprint)".into());
    }
    let missing: Vec<&str> = [
        (f.fprintd, "/usr/lib/fprintd"),
        (f.libfprint, "/usr/lib/libfprint-2.so.2"),
        (f.pam_fprintd, "/usr/lib/security/pam_fprintd.so"),
    ]
    .into_iter()
    .filter_map(|(here, p)| (!here).then_some(p))
    .collect();
    if !missing.is_empty() {
        return (
            "warn",
            format!(
                "fprintd is not whole: {} missing; Setup > Security > Fingerprint installs it",
                missing.join(", ")
            ),
        );
    }
    let readers = match f.readers {
        Some(0) => return ("warn", "fprintd sees no fingerprint reader".into()),
        Some(n) => format!("{} reader{}", n, if n == 1 { "" } else { "s" }),
        None => "readers unknown (fprintd-list did not answer)".into(),
    };
    match &f.prints {
        Ok(0) => (
            "warn",
            format!(
                "fprintd and libfprint installed, {}; no finger enrolled for {}",
                readers, f.user
            ),
        ),
        Ok(n) => (
            if f.readers.is_some() { "pass" } else { "warn" },
            format!(
                "fprintd and libfprint installed, {}, {} print{} enrolled for {}",
                readers,
                n,
                if *n == 1 { "" } else { "s" },
                f.user
            ),
        ),
        Err(_) => (
            "info",
            format!(
                "fprintd and libfprint installed, {}; the prints are root's: run doctor as root to count them",
                readers
            ),
        ),
    }
}

/// The doctor's row for the fingerprint on the card and the lock screen:
/// offered, or why not, as the key's rows say it.
pub(super) fn fprint_row(
    offer: Result<(), faceauth_daemon::consent::FprintOff>,
) -> (&'static str, String) {
    use faceauth_daemon::consent::FprintOff;
    match offer {
        Ok(()) => (
            "pass",
            "the consent card and the lock screen offer the fingerprint".into(),
        ),
        Err(FprintOff::NotSetUp(why)) => ("info", format!("not offered: {}", why)),
        Err(FprintOff::Withheld(why)) => ("warn", format!("not offered: {}", why)),
        // Doctor run as the user: the prints are root's, as
        // `fprint.service` says.
        Err(FprintOff::Unreadable(_)) => (
            "info",
            "the prints are root's: run doctor as root to see whether the fingerprint is offered"
                .into(),
        ),
    }
}

/// The verdict on the package's bus policy
/// (`/usr/share/dbus-1/system.d/faceauth-fprint.conf`), which lets
/// fprintd's device signals reach a receiver only from fprintd: a pass in
/// place as shipped; with fprintd installed and the file missing or
/// changed, a failure, since the fingerprint is then offered nowhere and
/// every pam_fprintd on the machine, stock lines included, can be handed a
/// forged result; information with no fprintd at all.
pub(super) fn fprint_bus_policy_verdict(
    fprintd: bool,
    state: Result<(), String>,
) -> (&'static str, String) {
    match state {
        Ok(()) => (
            "pass",
            "installed as shipped: fprintd's device signals reach a receiver only from fprintd (the bus reads it at start, and pacman's dbus-reload hook reloads it on install)"
                .into(),
        ),
        Err(why) if fprintd => (
            "fail",
            format!(
                "{}: the fingerprint is offered nowhere, and any pam_fprintd on this machine can be handed a verify result that did not come from fprintd; reinstall omarchy-faceauth",
                why
            ),
        ),
        Err(why) => ("info", format!("fprintd is not installed; {}", why)),
    }
}

/// The control the lock screen's `fprint-unlock` line must carry: a match
/// ends the stack with success, an ignore (faceauthd down) goes on to the
/// stock pam_fprintd line, and so does a module that will not load (the
/// package removed: Linux-PAM 1.7.3 answers `PAM_MODULE_UNKNOWN` for it,
/// measured with a throwaway stack, and `default=die` would fail the lane
/// outright), and every other answer ends the stack, so no refusal of the
/// daemon's falls through to a pam_fprintd that would take the finger
/// outside it.
pub(super) const FPRINT_UNLOCK_CONTROL: &str =
    "[success=done ignore=ignore module_unknown=ignore default=die]";

/// The verdict on the lines faceauth owns for the fingerprint, today the
/// lock screen's stack, `omarchy-lock-fingerprint`: its first auth line the
/// daemon's `fprint-unlock` line with `FPRINT_UNLOCK_CONTROL`, and any
/// pam_fprintd line (stock Omarchy's, for faceauthd down) after it. A stack
/// without the line is stock Omarchy's lane, which is information: the
/// lock screen's finger then waits on the fingerprint's setup to go
/// through faceauthd.
pub(super) fn fprint_lines_verdict(text: Option<&str>) -> (&'static str, String) {
    let Some(text) = text else {
        return ("info", "no lock screen fingerprint lane".into());
    };
    let auth: Vec<&str> = pam_active_lines(text)
        .filter(|l| l.split_whitespace().next() == Some("auth"))
        .collect();
    let is_ours = |l: &str| {
        l.contains("pam_faceauth.so") && l.split_whitespace().any(|w| w == "fprint-unlock")
    };
    let Some(at) = auth.iter().position(|l| is_ours(l)) else {
        return (
            "info",
            "the lock screen's fingerprint lane is stock Omarchy's pam_fprintd, outside faceauthd"
                .into(),
        );
    };
    if at != 0 {
        return (
            "fail",
            "a line runs before the fprint-unlock line in omarchy-lock-fingerprint; it must be the first auth line".into(),
        );
    }
    let control = {
        let l = auth[0];
        let rest = l.trim_start_matches("auth").trim_start();
        if rest.starts_with('[') {
            rest.split(']').next().map(|c| format!("{}]", c))
        } else {
            rest.split_whitespace().next().map(str::to_string)
        }
    };
    if control
        .as_deref()
        .map(|c| c.split_whitespace().collect::<Vec<_>>())
        != Some(FPRINT_UNLOCK_CONTROL.split_whitespace().collect())
    {
        return (
            "fail",
            format!(
                "the fprint-unlock line's control is {}, not {}: a refusal of faceauthd's could fall through to pam_fprintd",
                control.unwrap_or_default(),
                FPRINT_UNLOCK_CONTROL
            ),
        );
    }
    (
        "pass",
        "wired: the daemon's fprint-unlock line first, stock pam_fprintd after it for faceauthd down".into(),
    )
}

/// The verdict on pam_fprintd lines in files faceauth does not own:
/// `strays` names each file with one, and whether it is sudo's or
/// polkit's stack, where a line takes the reader outside the daemon and
/// keeps the fingerprint off the card and the lock screen. `face` says
/// whether face is set up on those stacks; without it their lines are
/// stock Omarchy's.
pub(super) fn fprint_stray_verdict(
    strays: &[(String, bool)],
    face: bool,
    unknown: Option<&str>,
) -> (&'static str, String) {
    // What sudo and polkit include could not be followed (the offer's
    // reason, `consent::fprintd_reached`): the card and the lock screen do
    // not offer the fingerprint, whatever else is found.
    if let (true, Some(why)) = (face, unknown) {
        return (
            "warn",
            format!(
                "{}: the card and the lock screen do not offer the fingerprint until it can be read",
                why
            ),
        );
    }
    if strays.is_empty() {
        return (
            "pass",
            "no pam_fprintd line outside the lines faceauth owns".into(),
        );
    }
    let names: Vec<&str> = strays.iter().map(|(p, _)| p.as_str()).collect();
    if !face {
        return (
            "info",
            format!(
                "pam_fprintd in {}; face is not set up on sudo or polkit, so these are stock Omarchy's",
                names.join(", ")
            ),
        );
    }
    if strays.iter().any(|(_, elevation)| *elevation) {
        return (
            "warn",
            format!(
                "pam_fprintd in {}: sudo and polkit wait on the reader before the card shows, and the card and the lock screen do not offer the fingerprint while a line reads it outside faceauthd",
                names.join(", ")
            ),
        );
    }
    (
        "warn",
        format!(
            "pam_fprintd in {}: these read the reader outside faceauthd",
            names.join(", ")
        ),
    )
}

#[cfg(test)]
mod doctor_tests {
    use super::*;

    /// `fprint.service`: nothing installed is information, a part missing
    /// or no reader a warning, and a pass carries the counts; prints a
    /// non-root caller cannot read need root rather than read as none.
    #[test]
    fn the_fprint_service_row_reads_install_readers_and_prints() {
        let base = FprintFacts {
            fprintd: true,
            libfprint: true,
            pam_fprintd: true,
            readers: Some(1),
            prints: Ok(2),
            user: "alice",
        };
        let (st, d) = fprint_service_verdict(&base);
        assert_eq!(st, "pass", "{}", d);
        assert!(
            d.contains("1 reader,") && d.contains("2 prints enrolled for alice"),
            "{}",
            d
        );
        let none = FprintFacts {
            fprintd: false,
            libfprint: false,
            pam_fprintd: false,
            ..base
        };
        assert_eq!(fprint_service_verdict(&none).0, "info");
        let part = FprintFacts {
            libfprint: false,
            ..FprintFacts {
                prints: Ok(2),
                ..none
            }
        };
        let (st, d) = fprint_service_verdict(&FprintFacts {
            fprintd: true,
            pam_fprintd: true,
            ..part
        });
        assert_eq!(st, "warn");
        assert!(d.contains("libfprint-2.so.2"), "{}", d);
        let no_reader = FprintFacts {
            fprintd: true,
            libfprint: true,
            pam_fprintd: true,
            readers: Some(0),
            prints: Ok(2),
            user: "alice",
        };
        assert_eq!(fprint_service_verdict(&no_reader).0, "warn");
        let no_prints = FprintFacts {
            readers: Some(2),
            prints: Ok(0),
            ..no_reader
        };
        let (st, d) = fprint_service_verdict(&no_prints);
        assert_eq!(st, "warn");
        assert!(
            d.contains("2 readers") && d.contains("no finger enrolled"),
            "{}",
            d
        );
        let not_root = FprintFacts {
            readers: Some(1),
            prints: Err("permission denied".into()),
            ..no_prints
        };
        let (st, d) = fprint_service_verdict(&not_root);
        assert_eq!(st, "info");
        assert!(d.contains("run doctor as root"), "{}", d);
        assert_eq!(readers_of_list("found 2 devices\nDevice at /x\n"), Some(2));
        assert_eq!(readers_of_list("No devices available\n"), Some(0));
        assert_eq!(readers_of_list("Impossible to get devices\n"), None);
    }

    /// `fprint.unlock`: the offer, or why not, as the key's rows say it.
    #[test]
    fn the_fprint_unlock_row_reports_the_offer_and_the_reason() {
        use faceauth_daemon::consent::FprintOff;
        assert_eq!(fprint_row(Ok(())).0, "pass");
        let (st, d) = fprint_row(Err(FprintOff::NotSetUp(
            "no fingerprint enrolled for alice".into(),
        )));
        assert_eq!(st, "info");
        assert!(d.contains("no fingerprint enrolled"), "{}", d);
        let (st, d) = fprint_row(Err(FprintOff::Withheld(
            "a pam_fprintd line in /etc/pam.d/sudo reads the reader outside faceauthd".into(),
        )));
        assert_eq!(st, "warn");
        assert!(d.contains("/etc/pam.d/sudo"), "{}", d);
    }

    /// L1: prints a caller cannot read (doctor run as the user: they are
    /// root's) are information that says to run doctor as root, as
    /// `fprint.service` says it, not a warning.
    #[test]
    fn prints_doctor_cannot_read_are_information_not_a_warning() {
        use faceauth_daemon::consent::FprintOff;
        let (st, d) = fprint_row(Err(FprintOff::Unreadable(
            "/var/lib/fprint/alice cannot be read: Permission denied (os error 13)".into(),
        )));
        assert_eq!(st, "info", "{}", d);
        assert!(d.contains("run doctor as root"), "{}", d);
    }

    /// H1: `fprint.bus_policy` passes with the shipped file in place, fails
    /// without it while fprintd is installed (the fingerprint is offered
    /// nowhere, and every pam_fprintd takes a forged result), and is
    /// information with no fprintd at all.
    #[test]
    fn the_bus_policy_row_says_whether_the_shipped_file_stands() {
        let (st, d) = fprint_bus_policy_verdict(true, Ok(()));
        assert_eq!(st, "pass", "{}", d);
        assert!(d.contains("only from fprintd"), "{}", d);
        let why = "the bus policy that keeps fprintd's device signals to fprintd is not installed (/usr/share/dbus-1/system.d/faceauth-fprint.conf)";
        let (st, d) = fprint_bus_policy_verdict(true, Err(why.into()));
        assert_eq!(st, "fail", "{}", d);
        assert!(d.contains(why) && d.contains("offered nowhere"), "{}", d);
        assert_eq!(fprint_bus_policy_verdict(false, Err(why.into())).0, "info");
    }

    /// M1: a stack sudo or polkit cannot be followed through (an include
    /// missing, a name outside /etc/pam.d) keeps the fingerprint off, and
    /// `fprint.stray` says so with the offer's reason rather than pass.
    #[test]
    fn an_include_that_cannot_be_followed_is_named_as_the_offer_names_it() {
        let why = "/etc/pam.d/sudo includes nowhere, which is not in /etc/pam.d, so what it reads is unknown";
        let (st, d) = fprint_stray_verdict(&[], true, Some(why));
        assert_eq!(st, "warn", "{}", d);
        assert!(
            d.contains(why) && d.contains("do not offer the fingerprint"),
            "{}",
            d
        );
        assert_eq!(
            fprint_stray_verdict(&[], false, Some(why)).0,
            "pass",
            "without face it is stock Omarchy's"
        );
    }

    /// `pam.fprint_lines`: the lock screen's stack in faceauth's form
    /// passes; stock Omarchy's is information; a line before ours, or a
    /// control that lets a refusal fall through to pam_fprintd, fails.
    #[test]
    fn the_fprint_lines_are_the_daemons_line_first_with_its_control() {
        let ours = "#%PAM-1.0\nauth       [success=done ignore=ignore module_unknown=ignore default=die]  pam_faceauth.so socket=/run/faceauth/sock fprint-unlock\nauth       required                    pam_fprintd.so\naccount    include                     system-local-login\n";
        assert_eq!(
            fprint_lines_verdict(Some(ours)).0,
            "pass",
            "{}",
            fprint_lines_verdict(Some(ours)).1
        );
        assert_eq!(fprint_lines_verdict(None).0, "info");
        let stock = "#%PAM-1.0\nauth       required                    pam_fprintd.so\naccount    include                     system-local-login\n";
        assert_eq!(fprint_lines_verdict(Some(stock)).0, "info");
        let below = "auth required pam_fprintd.so\nauth [success=done ignore=ignore module_unknown=ignore default=die] pam_faceauth.so fprint-unlock\n";
        assert_eq!(fprint_lines_verdict(Some(below)).0, "fail");
        for control in [
            "sufficient",
            "[success=done default=ignore]",
            "optional",
            "[success=done ignore=ignore default=die]",
        ] {
            let open = ours.replace(
                "[success=done ignore=ignore module_unknown=ignore default=die]",
                control,
            );
            let (st, d) = fprint_lines_verdict(Some(&open));
            assert_eq!(st, "fail", "{}: {}", control, d);
            assert!(d.contains("fall through"), "{}", d);
        }
        let commented = ours.replace("auth       [success", "#auth       [success");
        assert_eq!(
            fprint_lines_verdict(Some(&commented)).0,
            "info",
            "a commented line is not ours"
        );
    }

    /// `fprint.stray`: none passes; with face set up, one in sudo's or
    /// polkit's stack warns that it keeps the fingerprint off the card, any
    /// other warns plainly; without face they are stock Omarchy's.
    #[test]
    fn a_stray_pam_fprintd_line_is_named() {
        assert_eq!(fprint_stray_verdict(&[], true, None).0, "pass");
        let sudo = vec![("/etc/pam.d/sudo".to_string(), true)];
        let (st, d) = fprint_stray_verdict(&sudo, true, None);
        assert_eq!(st, "warn");
        assert!(
            d.contains("/etc/pam.d/sudo") && d.contains("do not offer the fingerprint"),
            "{}",
            d
        );
        assert_eq!(fprint_stray_verdict(&sudo, false, None).0, "info");
        let login = vec![("/etc/pam.d/sddm".to_string(), false)];
        let (st, d) = fprint_stray_verdict(&login, true, None);
        assert_eq!(st, "warn");
        assert!(!d.contains("card"), "{}", d);
    }

    /// E: the key's row says what the card offers, and why not when it
    /// does not: a key nobody set up is information, a key held back a
    /// warning with its reason.
    #[test]
    fn the_key_row_reports_the_offer_and_the_reason() {
        use faceauth_daemon::consent::{KeyOff, KeyPolicy};
        assert_eq!(
            key_row("the consent card", Ok(KeyPolicy::default())),
            ("pass", "the consent card offers the key".to_string())
        );
        assert_eq!(
            key_row(
                "the lock screen",
                Ok(KeyPolicy {
                    pin: None,
                    uv: Some(true)
                })
            )
            .1,
            "the lock screen offers the key, with verification on the key"
        );
        assert_eq!(
            key_row(
                "the consent card",
                Ok(KeyPolicy {
                    pin: Some(true),
                    uv: None
                })
            )
            .1,
            "the consent card offers the key, with its PIN"
        );
        let (st, d) = key_row(
            "the consent card",
            Err(KeyOff::NotSetUp("no key registered".into())),
        );
        assert_eq!((st, d.as_str()), ("info", "not offered: no key registered"));
        let (st, d) = key_row(
            "the consent card",
            Err(KeyOff::Withheld("`max_devices=2`".into())),
        );
        assert_eq!(st, "warn");
        assert!(d.contains("max_devices=2"), "{}", d);
    }

    /// F2: the lock screen's key lane is the daemon's key-unlock line
    /// closed by pam_deny, and a pam_u2f line in it fails the row.
    #[test]
    fn the_key_lane_is_the_daemons_line_and_never_pam_u2f() {
        let ours = "#%PAM-1.0\nauth       sufficient                  pam_faceauth.so socket=/run/faceauth/sock key-unlock\nauth       required                    pam_deny.so\naccount    include                     system-local-login\n";
        assert_eq!(key_lane_verdict(Some(ours)).0, "pass");
        assert_eq!(key_lane_verdict(None).0, "info");
        let u2f = "#%PAM-1.0\nauth       required                    pam_u2f.so cue authfile=/etc/fido2/fido2\naccount    include                     system-local-login\n";
        assert_eq!(key_lane_verdict(Some(u2f)).0, "fail");
        let both = format!(
            "{}auth sufficient pam_u2f.so cue authfile=/etc/fido2/fido2\n",
            ours
        );
        assert_eq!(key_lane_verdict(Some(&both)).0, "fail");
        let open = ours.replace(
            "auth       required                    pam_deny.so",
            "#auth required pam_deny.so",
        );
        assert_eq!(key_lane_verdict(Some(&open)).0, "fail");
        let plain = ours.replace(" key-unlock", " timeout=8");
        assert_eq!(key_lane_verdict(Some(&plain)).0, "warn");
    }

    /// E6: only a live `auth required|requisite pam_deny.so` after the face
    /// line closes the lock stack.
    #[test]
    fn a_commented_out_pam_deny_does_not_close_the_lock_stack() {
        let open = "#%PAM-1.0\nauth sufficient pam_faceauth.so socket=/run/faceauth/sock timeout=8\n#auth required pam_deny.so\naccount include system-local-login\n";
        let (st, d) = pam_stack_verdict("pam.lock", open);
        assert_eq!(st, "fail", "{}", d);
        assert!(d.contains("NOT closed"), "{}", d);
        // I4: the reason given is the one measured (pam-example.txt), not
        // round 3's "read as success".
        assert!(
            d.contains("1.7.2 refuses it") && d.contains("add the pam_deny line"),
            "{}",
            d
        );
        assert!(!d.contains("success"), "{}", d);
        let closed = open.replace("#auth required pam_deny.so", "auth required pam_deny.so");
        assert_eq!(
            pam_stack_verdict("pam.lock", &closed),
            ("pass", "wired, closed by pam_deny".to_string())
        );
        let requisite = open.replace(
            "#auth required pam_deny.so",
            "auth   requisite   pam_deny.so",
        );
        assert_eq!(pam_stack_verdict("pam.lock", &requisite).0, "pass");
        // A pam_deny above the face line runs first and never lets the face line answer.
        let above = "auth required pam_deny.so\nauth sufficient pam_faceauth.so\n";
        assert_eq!(pam_stack_verdict("pam.lock", above).0, "fail");
        // The wrong control word or a different module type does not close the stack.
        let optional = open.replace("#auth required pam_deny.so", "auth optional pam_deny.so");
        assert_eq!(pam_stack_verdict("pam.lock", &optional).0, "fail");
        let account = open.replace("#auth required pam_deny.so", "account required pam_deny.so");
        assert_eq!(pam_stack_verdict("pam.lock", &account).0, "fail");
    }

    /// I4: each stack packaging/pam-example.txt gives is one doctor passes,
    /// and doctor's reason for the lock stack's pam_deny is the library
    /// behavior the example records as measured.
    #[test]
    fn the_pam_example_stacks_pass_and_share_the_doctors_reason() {
        let example = include_str!("../../packaging/pam-example.txt");
        let mut seen = Vec::new();
        for section in example.split("# /etc/pam.d/").skip(1) {
            let service = section.split([' ', ':']).next().unwrap();
            let id = match service {
                "omarchy-lock-face" => "pam.lock",
                "sudo" => "pam.sudo",
                "polkit-1" => "pam.polkit",
                "omarchy-lock-fido2" => "pam.lock_fido2",
                other => panic!("pam-example.txt has a stack for {}", other),
            };
            let (st, d) = if id == "pam.lock_fido2" {
                key_lane_verdict(Some(section))
            } else {
                pam_stack_verdict(id, section)
            };
            assert_eq!(st, "pass", "{}: {}", id, d);
            seen.push(id);
        }
        assert_eq!(
            seen,
            ["pam.lock", "pam.sudo", "pam.polkit", "pam.lock_fido2"]
        );
        let open = "auth sufficient pam_faceauth.so timeout=8\n";
        let (_, d) = pam_stack_verdict("pam.lock", open);
        assert!(
            example.contains("Linux-PAM 1.7.2") && example.contains("PAM_PERM_DENIED"),
            "the example no longer records the measurement doctor cites"
        );
        assert!(d.contains("Linux-PAM") && d.contains("1.7.2"), "{}", d);
    }

    /// F11: `timeout=` on a consent line is ignored by the module and doctor says so.
    #[test]
    fn timeout_on_a_consent_line_is_flagged() {
        let stale = "auth sufficient pam_faceauth.so socket=/run/faceauth/sock timeout=60 consent\nauth include system-auth\n";
        let (st, d) = pam_stack_verdict("pam.sudo", stale);
        assert_eq!(st, "warn", "{}", d);
        assert!(
            d.contains("consent (window + nod)")
                && d.contains("timeout= on a consent line is ignored"),
            "{}",
            d
        );
        let clean = "auth sufficient pam_faceauth.so socket=/run/faceauth/sock consent\nauth include system-auth\n";
        assert_eq!(
            pam_stack_verdict("pam.sudo", clean),
            ("pass", "wired, consent (window + nod)".to_string())
        );
        // A plain look keeps its timeout without comment.
        let lock = "auth sufficient pam_faceauth.so timeout=8\nauth required pam_deny.so\n";
        assert!(!pam_stack_verdict("pam.lock", lock).1.contains("timeout="));
        // A commented-out face line is not wired.
        assert_eq!(
            pam_stack_verdict("pam.sudo", "#auth sufficient pam_faceauth.so consent\n").0,
            "warn"
        );
    }

    /// A3: an elevation line without `consent` (a pasted lock line, a
    /// misspelt word) is a failure, not a pass with a note.
    #[test]
    fn an_elevation_line_without_consent_fails() {
        for line in [
            "auth      sufficient pam_faceauth.so socket=/run/faceauth/sock timeout=8\n",
            "auth      sufficient pam_faceauth.so socket=/run/faceauth/sock consnet\n",
        ] {
            let sudo = format!("{}#%PAM-1.0\nauth\t\tinclude\t\tsystem-auth\n", line);
            let (st, d) = pam_stack_verdict("pam.sudo", &sudo);
            assert_eq!(st, "fail", "{}", d);
            assert!(d.contains("NO consent"), "{}", d);
            let polkit = format!(
                "#%PAM-1.0\n{}auth include system-auth\n",
                line.replace("sufficient", "[success=done auth_err=die default=ignore]")
            );
            assert_eq!(pam_stack_verdict("pam.polkit", &polkit).0, "fail");
        }
        // The lock stack is the plain-look caller and needs no consent.
        let lock = "auth sufficient pam_faceauth.so timeout=8\nauth required pam_deny.so\n";
        assert_eq!(pam_stack_verdict("pam.lock", lock).0, "pass");
    }

    /// D3: the IR sensor is found by name in sysfs without opening its node,
    /// so doctor keeps going once the node is root-only.
    #[test]
    fn the_ir_sensor_is_found_by_name_in_sysfs() {
        let dir =
            std::env::temp_dir().join(format!("faceauth-doctor-sysfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (node, name) in [
            ("v4l-subdev2", "ipu3-csi2 0"),
            ("v4l-subdev6", "ov8865 3-0010"),
            ("v4l-subdev8", "ov7251 3-0060"),
            ("v4l-subdev9", "dw9719 3-000c"),
            ("video0", "ipu3-cio2 0"),
        ] {
            std::fs::create_dir_all(dir.join(node)).unwrap();
            std::fs::write(dir.join(node).join("name"), format!("{}\n", name)).unwrap();
        }
        assert_eq!(
            ir_sensor_from_sysfs(&dir),
            Some(("v4l-subdev8".to_string(), "ov7251 3-0060".to_string()))
        );
        std::fs::remove_dir_all(dir.join("v4l-subdev8")).unwrap();
        assert_eq!(ir_sensor_from_sysfs(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The lock helper passes only as a root-owned regular file that is
    /// executable and that group and other cannot write; anything else is a
    /// failure that says why.
    #[test]
    fn the_lock_helper_passes_only_root_owned_executable_and_unwritable() {
        assert_eq!(lock_helper_verdict(0o100755, 0, true, true).0, "pass");
        assert_eq!(lock_helper_verdict(0o100700, 0, true, true).0, "pass");
        for (mode, uid, is_file, exists, why) in [
            (0, 0, false, false, "missing"),
            (0o40755, 0, false, true, "not a regular file"),
            (0o100755, 1000, true, true, "not root"),
            (0o100644, 0, true, true, "not executable"),
            (0o100775, 0, true, true, "group or other write"),
            (0o100757, 0, true, true, "group or other write"),
        ] {
            let (st, d) = lock_helper_verdict(mode, uid, is_file, exists);
            assert_eq!(st, "fail", "{:o} {}", mode, uid);
            assert!(d.contains(why), "{:o} {}: {}", mode, uid, d);
        }
    }

    /// Round 5 (A), fix round 10 (item 6): with faceauthd down, the
    /// stacks' key line runs the key check itself, as root, as stock
    /// pam_u2f would, only when it is a root-owned regular file, no
    /// symlink, that nobody else can write; it needs no lock helper. The
    /// check missing is a warning (the key line falls to the password); one
    /// the module would refuse is a failure that says why.
    #[test]
    fn the_down_key_path_needs_its_check_roots() {
        let good = (true, true, 0o100755, 0);
        let row = |a: (bool, bool, u32, u32), link: bool| {
            key_down_verdict(&[("/usr/lib/faceauth/faceauth-keycheck", Ok(a), link)])
        };
        let (st, d) = row(good, false);
        assert_eq!(st, "pass", "{}", d);
        assert!(
            d.contains("faceauthd is down") && d.contains("stock") && !d.contains("unlocked"),
            "{}",
            d
        );
        let (st, d) = row((false, false, 0, 0), false);
        assert_eq!(st, "warn");
        assert!(
            d.contains("faceauth-keycheck") && d.contains("missing") && d.contains("password"),
            "{}",
            d
        );
        let (st, d) = row(good, true);
        assert_eq!(st, "fail");
        assert!(
            d.contains("faceauth-keycheck") && d.contains("symlink"),
            "{}",
            d
        );
        let (st, d) = row((true, true, 0o100775, 0), false);
        assert_eq!(st, "fail");
        assert!(d.contains("group or other write"), "{}", d);
        let (st, _) = key_down_verdict(&[(
            "/usr/lib/faceauth/faceauth-keycheck",
            Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
            false,
        )]);
        assert_eq!(st, "unknown");
    }

    /// Round 6 (Opus N1): doctor flags a lock state the compositor cannot
    /// give, which sends every key line and parked request to the password
    /// after the unknown limit. With faceauthd down nothing reads it (fix
    /// round 10, item 6). No desktop at all is a text console, not a fault.
    #[test]
    fn doctor_flags_an_unknown_lock_state() {
        use faceauth_daemon::lockgate::{Desktop, LockState};
        for st in [LockState::Locked, LockState::Unlocked] {
            assert_eq!(
                lock_state_verdict(st, Desktop::Some, "").0,
                "pass",
                "{:?}",
                st
            );
        }
        let (st, d) =
            lock_state_verdict(LockState::Unknown, Desktop::Some, "two Hyprland instances");
        assert_eq!(st, "warn");
        assert!(
            d.contains("two Hyprland instances")
                && d.contains("password")
                && !d.contains("faceauthd down"),
            "{}",
            d
        );
        assert_eq!(
            lock_state_verdict(LockState::Unknown, Desktop::None, "").0,
            "info"
        );
        assert_eq!(
            lock_state_verdict(LockState::Unknown, Desktop::Unreadable, "").0,
            "warn"
        );
    }

    /// Round 7 (A): doctor checks the chain the daemon's anchored question
    /// uses (fix round 10: the module's own gate is gone): logind names the
    /// compositor of the user's desktop, the system bus gives its pid, and
    /// exactly one Hyprland socket's listener is that pid. Each broken link
    /// is a warning that says which.
    #[test]
    fn doctor_checks_the_compositor_anchor() {
        assert_eq!(
            anchor_verdict(Some(":1.35"), Some(1257), Some(true)).0,
            "pass"
        );
        let (st, d) = anchor_verdict(None, None, None);
        assert_eq!(st, "info");
        assert!(
            d.contains("CONTROLLER") && d.contains("key lines") && !d.contains("faceauthd down"),
            "{}",
            d
        );
        let (st, d) = anchor_verdict(Some(":1.35"), None, None);
        assert_eq!(st, "warn");
        assert!(d.contains("bus"), "{}", d);
        let (st, d) = anchor_verdict(Some(":1.35"), Some(1257), Some(false));
        assert_eq!(st, "warn");
        assert!(d.contains("socket") && d.contains("1257"), "{}", d);
    }

    /// Round 6, item 11: polkit's socket-activated helper runs in a sandbox
    /// with no device but /dev/null; with faceauthd down its key line
    /// reaches the key only with pam-u2f's drop-in (`DeviceAllow=char-hidraw
    /// rw`), as stock pam_u2f does. It asks no lock question then (fix
    /// round 10, item 6), so `/run/user` no longer matters.
    #[test]
    fn doctor_says_whether_polkits_helper_can_reach_the_key() {
        let with = "DeviceAllow=/dev/null rw\nDeviceAllow=/dev/urandom r\nDeviceAllow=char-hidraw rw\nDevicePolicy=strict\nProtectHome=read-only\n";
        assert_eq!(polkit_helper_verdict(Some(with)).0, "pass");
        let without = "DeviceAllow=/dev/null rw\nDevicePolicy=strict\nProtectHome=yes\n";
        let (st, d) = polkit_helper_verdict(Some(without));
        assert_eq!(st, "warn");
        assert!(d.contains("pam-u2f") && d.contains("hidraw"), "{}", d);
        let (st, d) = polkit_helper_verdict(Some("DeviceAllow=char-hidraw rw\nProtectHome=yes\n"));
        assert_eq!(st, "pass", "{}", d);
        assert_eq!(
            polkit_helper_verdict(None).0,
            "info",
            "no socket-activated helper"
        );
    }

    /// D3: the verdict reads the node's live state. Right is root:root 0600,
    /// no uaccess in the current tags and no write access for the caller.
    #[test]
    fn the_ir_node_verdict_reads_the_live_state() {
        let none: Vec<String> = vec![];
        let seat = vec!["seat".to_string()];
        let uaccess = vec!["seat".to_string(), "uaccess".to_string()];
        assert_eq!(ir_node_verdict(0o600, 0, 0, &seat, false).0, "pass");
        assert_eq!(ir_node_verdict(0o600, 0, 0, &none, false).0, "pass");
        // Before the rule: video group, rw, uaccess tag, and the user holds an ACL.
        let (st, d) = ir_node_verdict(0o660, 0, 983, &uaccess, true);
        assert_eq!(st, "warn");
        assert!(
            d.contains("want root:root 0600") && d.contains("tagged uaccess"),
            "{}",
            d
        );
        // The rule applied to the udev database but the earlier ACL still stands.
        let (st, d) = ir_node_verdict(0o600, 0, 0, &seat, true);
        assert_eq!(st, "warn");
        assert!(d.contains("setfacl -b"), "{}", d);
        // Right mode, stale tag: the next login grants access again.
        assert_eq!(ir_node_verdict(0o600, 0, 0, &uaccess, false).0, "warn");
    }

    /// D3: the probe's error for a root-only node is recognized through the
    /// context anyhow wraps around it, and anything else is still a fault.
    #[test]
    fn a_root_only_node_is_permission_denied_not_a_fault() {
        let denied =
            anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                .context("open /dev/v4l-subdev8")
                .context("IPU3 probe");
        assert!(is_permission_denied(&denied));
        let missing = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context("open /dev/media0");
        assert!(!is_permission_denied(&missing));
        assert!(!is_permission_denied(&anyhow!("no subdev node")));
    }

    /// D3: the udev database's Q: lines are the current tags; G: lines are history.
    #[test]
    fn udev_current_tags_come_from_q_lines() {
        let dir = std::env::temp_dir().join(format!("faceauth-doctor-udev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 81:22 as the kernel encodes it: major in bits 8..20, minor low byte plus bits 20..32.
        let rdev: u64 = (81 << 8) | 22;
        assert_eq!(
            (nix::sys::stat::major(rdev), nix::sys::stat::minor(rdev)),
            (81, 22)
        );
        std::fs::write(
            dir.join("c81:22"),
            "I:1\nE:ID_PATH=x\nG:seat\nG:uaccess\nQ:seat\nV:1\n",
        )
        .unwrap();
        assert_eq!(udev_current_tags(&dir, rdev), vec!["seat".to_string()]);
        assert!(udev_current_tags(&dir, (81 << 8) | 23).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fix round 11 (Mike's ruling, the IR lock-down in its narrow form):
    /// doctor says whether the IR capture node is locked, and when it is
    /// left open, why.
    #[test]
    fn doctor_says_whether_the_ir_capture_node_is_locked() {
        let rule = r#"ACTION!="remove", SUBSYSTEM=="video4linux", KERNEL=="video*", ATTR{name}=="ipu3-cio2 1", SUBSYSTEMS=="pci", KERNELS=="0000:00:14.3", TAG-="uaccess", GROUP="root", MODE="0600""#;
        let file = format!("# written by setup\n{}\n", rule);
        let locked = ("pass", "root only".to_string());
        let (st, d) = ir_capture_verdict(Ok(rule), Some(&file), "video1", locked.clone());
        assert_eq!(st, "pass", "{}", d);
        let (st, d) = ir_capture_verdict(Ok(rule), None, "video1", locked.clone());
        assert_eq!(st, "warn");
        assert!(
            d.contains("not locked") && d.contains("72-faceauth-ir-node.rules"),
            "{}",
            d
        );
        let (st, d) = ir_capture_verdict(
            Ok(rule),
            Some(&file),
            "video1",
            ("warn", "tagged uaccess".into()),
        );
        assert_eq!(st, "warn", "the rule is there but not applied: {}", d);
        // A USB camera's rule is two lines (fix round 12): both must be
        // there.
        let two = "ACTION!=\"remove\", MARK\nACTION!=\"remove\", LOCK";
        let half = "# written by setup\nACTION!=\"remove\", MARK\n";
        assert_eq!(
            ir_capture_verdict(Ok(two), Some(half), "video2", locked.clone()).0,
            "warn"
        );
        let whole = format!("# written by setup\n{}\n", two);
        assert_eq!(
            ir_capture_verdict(Ok(two), Some(&whole), "video2", locked.clone()).0,
            "pass"
        );
        let (st, d) = ir_capture_verdict(
            Err("/dev/video1 offers colour formats too (YUYV), so it may be a webcam's"),
            None,
            "video1",
            locked,
        );
        assert_eq!(st, "info");
        assert!(d.contains("left open") && d.contains("colour"), "{}", d);
    }

    /// Fix round 13 (Codex 6, Opus nit): once face removal deleted the
    /// rule, doctor reads the node itself. Still what the lock left (root's
    /// group on a node udev gives the video group, or the seat user's ACL
    /// entry under a shut mask) is a fail, with the way out; given back,
    /// this row has nothing to add.
    #[test]
    fn doctor_says_when_the_lock_outlives_its_rule() {
        let (st, d) = ir_lock_left_verdict("video1", false, Some(true)).unwrap();
        assert_eq!(st, "fail");
        assert!(
            d.contains("still locked")
                && d.contains("faceauth cam ir-reset")
                && d.contains("--action=add"),
            "{}",
            d
        );
        assert_eq!(ir_lock_left_verdict("video1", false, Some(false)), None);
        assert_eq!(
            ir_lock_left_verdict("video1", true, Some(true)),
            None,
            "the rule is there: the rule's own verdict"
        );
        assert_eq!(
            ir_lock_left_verdict("video1", false, None),
            None,
            "not read"
        );
    }

    /// Round 19: doctor holds the key check's cancel to both its ends: the
    /// helper exports the wrapper and pam_u2f imports the call, or the row
    /// says which end broke and what it costs.
    #[test]
    fn doctor_checks_the_key_cancel() {
        use faceauth_daemon::elfsym::Sym;
        let (st, d) = key_cancel_verdict(Some(Sym::Exported), Some(Sym::Imported));
        assert_eq!(st, "pass");
        assert!(d.contains("cancels"), "{}", d);
        let (st, d) = key_cancel_verdict(Some(Sym::Exported), Some(Sym::Absent));
        assert_eq!(st, "warn");
        assert!(d.contains("pam_u2f") && d.contains("blinking"), "{}", d);
        for helper in [None, Some(Sym::Absent), Some(Sym::Imported)] {
            let (st, d) = key_cancel_verdict(helper, Some(Sym::Imported));
            assert_eq!(st, "warn", "{:?}", helper);
            assert!(d.contains("faceauth-keycheck"), "{}", d);
        }
        assert_eq!(key_cancel_verdict(Some(Sym::Exported), None).0, "info");
    }

    /// Fix round 11 (Codex 2, Opus N4): no key check runs without the
    /// key's lease, so doctor says when it is missing or not root's alone.
    #[test]
    fn doctor_checks_the_key_lease() {
        assert_eq!(key_lease_verdict(Some((true, 0, 0o600))).0, "pass");
        let (st, d) = key_lease_verdict(None);
        assert_eq!(st, "warn");
        assert!(d.contains("systemd-tmpfiles"), "{}", d);
        assert_eq!(key_lease_verdict(Some((true, 1000, 0o600))).0, "fail");
        assert_eq!(key_lease_verdict(Some((true, 0, 0o644))).0, "fail");
        assert_eq!(key_lease_verdict(Some((false, 0, 0o600))).0, "fail");
    }
}
