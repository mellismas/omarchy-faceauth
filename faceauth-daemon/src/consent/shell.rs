//! Calls into the user's session: the window's shell, the lock and
//! desktop notices. Each runs inside the user's own systemd manager, so
//! the daemon never switches uid to reach the desktop, and by a route that
//! can never start a manager (`user_command`).

use anyhow::{anyhow, Result};

/// The longest a call into the user's session (the card's summon, a
/// notice) runs before `timeout` ends it.
/// Below `lockgate::LIVENESS`, so a call never outlasts a waiting PAM
/// line's patience (round 6, item 12).
pub const USER_CALL_LIMIT: std::time::Duration = std::time::Duration::from_secs(4);

/// How long the daemon reads a call into the user's session before it
/// gives the call up, kills what it started and closes the pipes (fix
/// round 10, Codex 2, Opus N4). `timeout` ends only the outer
/// `systemd-run`; PID 1, the carrier unit and the user's unit hold the
/// pipes on, so the end of a pipe is never what the daemon waits for
/// (`bounded::run_bounded`). Each unit also ends itself at
/// `USER_CALL_LIMIT` (`RuntimeMaxSec=`), so nothing of a stalled call is
/// left running in either manager.
pub const USER_CALL_WITHIN: std::time::Duration =
    std::time::Duration::from_millis(USER_CALL_LIMIT.as_millis() as u64 + 500);
const _: () = assert!(USER_CALL_WITHIN.as_millis() < crate::lockgate::LIVENESS.as_millis());

/// The most of a call's output the daemon keeps: the shell's answer is a
/// word or two.
const USER_CALL_CAP: usize = 4096;

/// The sandbox of the system unit that carries a call into the user's
/// manager: it runs as the user, holds nothing, and reaches only the
/// user's bus socket.
const CARRIER_PROPERTIES: &[&str] = &[
    "NoNewPrivileges=yes",
    "CapabilityBoundingSet=",
    "ProtectSystem=strict",
    "ProtectHome=read-only",
    "PrivateTmp=yes",
    "PrivateNetwork=yes",
    "RestrictAddressFamilies=AF_UNIX",
    "LockPersonality=yes",
    "RestrictSUIDSGID=yes",
];

/// The check each unit of a call into the user's session makes the moment
/// it starts (fix round 10, Codex 6): run as `/bin/sh -c PIN_CHECK
/// faceauth-pin UID ID... -- COMMAND...`, it runs COMMAND only while every
/// pinned session is still a live desktop of UID in logind's records (the
/// rule of `lockgate::user_desktops`: the uid's, graphical by its type now
/// or the type it was created with, not closing, not a greeter), and
/// otherwise exits 75 with nothing run. logind writes the records 0644
/// under a 0755 /run/systemd/sessions (systemd v262
/// src/login/logind-session.c, `session_save`), so the user's own units
/// can read them, and only root can write them. One line, so it reaches
/// the unit's command line as written; the lock helper carries the same
/// text (`packaging/faceauth-lock-session`).
pub const PIN_CHECK: &str = r#"uid=$1; shift; [ "$1" != -- ] || exit 75; while [ "$#" -gt 0 ] && [ "$1" != -- ]; do case $1 in ""|*[!A-Za-z0-9]*) exit 75;; esac; r=/run/systemd/sessions/$1; [ -f "$r" ] && /usr/bin/grep -qx "UID=$uid" "$r" && /usr/bin/grep -qxE "(ORIGINAL_)?TYPE=(wayland|x11|mir)" "$r" && ! /usr/bin/grep -qxE "STATE=closing|CLASS=greeter" "$r" || exit 75; shift; done; [ "$#" -gt 1 ] || exit 75; shift; exec "$@""#;

/// One command inside `user`'s (`uid`'s) own systemd manager, the route
/// every call into the user's session takes (the window, a notice, the
/// lock), so the daemon never switches uid itself (H18), and one that can
/// never start a manager (fix round 9, Codex 5, Opus L1).
///
/// The route used to be `systemd-run --user --machine=USER@.host`, which
/// sd-bus turns into `systemd-run -M.host -pUser=USER -pPAMName=login
/// systemd-stdio-bridge --user` (systemd v262
/// src/libsystemd/sd-bus/sd-bus.c, `bus_set_address_machine`): a PAM
/// session, for which logind starts the user's manager when it is not
/// running (src/login/logind-user.c, `user_start`). Root cannot reach the
/// manager directly with systemd's own tools: its private socket accepts
/// root (src/core/dbus.c, `bus_on_connection` and `bus_check_peercred`),
/// but systemd's client refuses a manager of another uid
/// (src/shared/bus-util.c, `bus_connect_user_systemd`), `--wait` and
/// `--pipe` go over the D-Bus user bus instead (src/run/run.c,
/// `connect_bus`), and that bus admits only its own user. So the call is
/// carried by a system unit that runs as the user with no `PAMName=` (no
/// session, so logind starts nothing), its runtime directory and bus
/// address set outright, and that unit runs `systemd-run --user`, which
/// talks to the manager over the user's own bus socket. A manager that is
/// not running has no bus socket: the call fails and nothing starts.
///
/// `systemd-run` gets a clean environment with only PATH, like every
/// other command the daemon runs; the command itself runs in the user's
/// manager with that manager's environment. `description` names the unit
/// in the journal, where the default would be the command line, payload
/// and token included; with `omarchy` the tree the shell was launched
/// from goes in as OMARCHY_PATH; `wait` waits for the command to end and
/// `pipe` brings its stdout back, through both units.
///
/// Both units start with `PIN_CHECK` on `pin`'s sessions (fix round 10),
/// both end themselves at `USER_CALL_LIMIT` (`RuntimeMaxSec=`), and
/// neither manager expands `$` in the arguments (`--expand-environment=no`:
/// by default the manager substitutes its environment into a transient
/// unit's command line at exec, systemd v262 src/run/run.c,
/// `transient_service_set_properties`, ExecStart without
/// EXEC_COMMAND_NO_ENV_EXPAND), so the check and a notice's text arrive
/// as written.
fn user_command(
    pin: &Pin,
    description: Option<&str>,
    omarchy: bool,
    wait: bool,
    pipe: bool,
) -> std::process::Command {
    let (user, uid) = (pin.user.as_str(), pin.uid);
    let runtime_max = format!("--property=RuntimeMaxSec={}s", USER_CALL_LIMIT.as_secs());
    // A unit past its limit is stopped with `KillSignal=`; SIGKILL, so no
    // payload that ignores SIGTERM acts late (fix round 11, Codex 6).
    let stop_now = "--property=KillSignal=SIGKILL";
    let check = |c: &mut std::process::Command| {
        c.args(["/bin/sh", "-c", PIN_CHECK, "faceauth-pin"])
            .arg(uid.to_string())
            .args(&pin.sessions)
            .arg("--");
    };
    let mut c = std::process::Command::new("/usr/bin/timeout");
    c.args(["-k", "1"])
        .arg(USER_CALL_LIMIT.as_secs().to_string())
        .args([
            "/usr/bin/systemd-run",
            "--quiet",
            "--collect",
            "--expand-environment=no",
        ]);
    if wait {
        c.arg("--wait");
    }
    if pipe {
        c.arg("--pipe");
    }
    c.arg("--service-type=exec")
        .arg("--description=Omarchy FaceAuth call into the user's manager")
        .arg(format!("--property=User={}", user))
        .arg(format!(
            "--property=Environment=XDG_RUNTIME_DIR=/run/user/{}",
            uid
        ))
        .arg(format!(
            "--property=Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{}/bus",
            uid
        ))
        .args(
            CARRIER_PROPERTIES
                .iter()
                .map(|p| format!("--property={}", p)),
        )
        .arg(&runtime_max)
        .arg(stop_now);
    check(&mut c);
    c.args([
        "/usr/bin/systemd-run",
        "--user",
        "--quiet",
        "--collect",
        "--expand-environment=no",
    ])
    .arg(&runtime_max)
    .arg(stop_now);
    if wait {
        c.arg("--wait");
    }
    if pipe {
        c.arg("--pipe");
    }
    if let Some(d) = description {
        c.arg(format!("--description={}", d));
    }
    if omarchy {
        c.arg(format!("-EOMARCHY_PATH={}", omarchy_path()));
    }
    check(&mut c);
    c.env_clear().env("PATH", "/usr/local/bin:/usr/bin:/bin");
    c
}

/// The user's live desktops when work into their manager began (fix
/// round 9, Codex 5): every dispatch checks, immediately before it is
/// made, that these are still exactly the user's live desktops in
/// logind's records, so a logout, or a logout and a fresh login, between
/// the start and a dispatch stops it, and nothing acts on a replacement
/// session.
#[derive(Clone, Debug)]
pub struct Pin {
    user: String,
    uid: u32,
    sessions: Vec<String>,
}

impl Pin {
    /// The pin for `user` (`uid`) against logind's records under
    /// `logind`; an error when they have no desktop.
    pub fn take_at(logind: &std::path::Path, user: &str, uid: u32) -> Result<Pin> {
        let sessions = crate::lockgate::user_desktops(logind, uid);
        if sessions.is_empty() {
            return Err(anyhow!(
                "uid {} has no graphical session; nothing is run in their manager",
                uid
            ));
        }
        Ok(Pin {
            user: user.to_string(),
            uid,
            sessions,
        })
    }

    /// The pin for `user`, against logind's records. Never under test,
    /// where nothing is dispatched and the machine's records are not read.
    pub fn take(user: &str) -> Result<Pin> {
        if cfg!(test) {
            return Err(anyhow!("no pin under test"));
        }
        let uid = nix::unistd::User::from_name(user)
            .ok()
            .flatten()
            .map(|u| u.uid.as_raw())
            .ok_or_else(|| anyhow!("no user {}", user))?;
        Pin::take_at(std::path::Path::new("/run/systemd"), user, uid)
    }

    /// Whether the pinned sessions are still exactly the user's live
    /// desktops under `logind`.
    pub fn still_at(&self, logind: &std::path::Path) -> bool {
        crate::lockgate::user_desktops(logind, self.uid) == self.sessions
    }

    /// The command for one dispatch into the pinned user's manager, only
    /// while the pin still holds, checked now.
    fn command(
        &self,
        description: Option<&str>,
        omarchy: bool,
        wait: bool,
        pipe: bool,
    ) -> Result<std::process::Command> {
        if !self.still_at(std::path::Path::new("/run/systemd")) {
            return Err(anyhow!(
                "{}'s pinned session is gone or replaced; nothing is dispatched",
                self.user
            ));
        }
        Ok(user_command(self, description, omarchy, wait, pipe))
    }
}

/// Whether the daemon may run anything in `uid`'s manager now: only while
/// logind's records under `logind` show them a desktop (fix round 8,
/// item 14; `lockgate::user_has_desktop`).
#[cfg(test)]
pub fn desktop_gate_at(logind: &std::path::Path, uid: u32) -> Result<()> {
    Pin::take_at(logind, "", uid).map(|_| ())
}

/// One `omarchy-shell` invocation inside the user's own systemd manager,
/// the same route the session lock uses, under a pin taken when the work
/// it belongs to began (fix round 10, Codex 6).
pub fn shell_call_pinned(pin: &Pin, args: &[&str]) -> Result<()> {
    // The shell's answer comes back on stdout (`--pipe`), so a summon the
    // shell could not honor is read here rather than by a change to the
    // shared command (F2).
    let mut c = pin.command(Some("omarchy-faceauth window"), true, true, true)?;
    c.arg("/usr/bin/omarchy-shell").args(args);
    let ran = super::bounded::run_bounded(c, None, USER_CALL_WITHIN, USER_CALL_CAP)
        .map_err(|e| anyhow!("omarchy-shell {:?} {}", args, e))?;
    shell_answer(args, ran.code == Some(0), &ran.out)
}

/// What `omarchy-shell` said, read for the daemon's purposes. A failed
/// exit is an error. A summon answered "unknown" is one too: the shell
/// has no such window (a disabled or absent plugin), nothing was shown,
/// and a caller that summoned something must not read the answer as
/// shown. Every other answer is the shell's business.
pub fn shell_answer(args: &[&str], success: bool, stdout: &[u8]) -> Result<()> {
    if !success {
        return Err(anyhow!("omarchy-shell {:?} failed", args));
    }
    let summon = args.len() >= 2 && args[0] == "shell" && args[1] == "summon";
    if summon && String::from_utf8_lossy(stdout).trim() == "unknown" {
        return Err(anyhow!(
            "omarchy-shell has no such window: {}",
            args.get(2).copied().unwrap_or("")
        ));
    }
    Ok(())
}

/// A summon of the window `target` with `payload`, which carries the
/// request's answer token: `omarchy-shell -s` from the Omarchy tree the
/// shell was launched from (`omarchy_path`, as the lock helper is handed
/// it), inside the user's manager, with the payload on its stdin
/// (`systemd-run --pipe` hands it the pipe). The token is then on no
/// command line that `ps` or `/proc/PID/cmdline` shows, and goes to the
/// shell over its own socket. A package install resolves to
/// /usr/share/omarchy, whose /usr/bin links match; a checkout resolves to
/// itself, whose omarchy-shell carries `-s` where /usr/bin's may not.
/// Under the pin the card took when its request began, checked again now
/// and inside both units.
pub fn shell_summon_pinned(pin: &Pin, target: &str, payload: &str) -> Result<()> {
    let tree = omarchy_path();
    if !pin.still_at(std::path::Path::new("/run/systemd")) {
        return Err(anyhow!(
            "the pinned session is gone or replaced; the card is not shown"
        ));
    }
    run_summon(summon_command(&tree, pin, target), &tree, target, payload)
}

fn summon_command(tree: &str, pin: &Pin, target: &str) -> std::process::Command {
    let mut c = user_command(pin, Some("omarchy-faceauth window"), true, true, true);
    c.arg(format!("{}/bin/omarchy-shell", tree))
        .args(["-s", "shell", "summon", target]);
    c
}

/// Run one summon, once, with the payload on stdin. An omarchy-shell that
/// cannot take a stdin argument (a tree from before `-s`) never reads it
/// and fails the call; the card then stays down and the request falls to
/// the password. Nothing retries the summon another way, so the token
/// never reaches a command line.
fn run_summon(c: std::process::Command, tree: &str, target: &str, payload: &str) -> Result<()> {
    run_summon_within(c, tree, target, payload, USER_CALL_WITHIN)
}

/// `run_summon`, read for at most `within` (fix round 10): a summon that
/// has not finished by then is given up, what it started killed and its
/// pipes closed, and the card is not shown.
fn run_summon_within(
    c: std::process::Command,
    tree: &str,
    target: &str,
    payload: &str,
    within: std::time::Duration,
) -> Result<()> {
    let ran = super::bounded::run_bounded(c, Some(payload.as_bytes()), within, USER_CALL_CAP)
        .map_err(|e| anyhow!("the summon of {} {}, and the card is not shown", target, e))?;
    if ran.code != Some(0) {
        return Err(anyhow!(
            "{}/bin/omarchy-shell -s did not take the window's payload ({}); an Omarchy tree whose omarchy-shell has no -s cannot show the card, and the token is never put on a command line instead",
            tree,
            String::from_utf8_lossy(&ran.err).trim()
        ));
    }
    shell_answer(&["shell", "summon", target], true, &ran.out)
}

/// What the compositor says about the session lock: the one type the
/// daemon and the PAM module share (`lockgate`).
pub use crate::lockgate::LockState;

/// Is the session of `user`'s that `bind` names locked? The one verdict
/// (`consent::lock_verdict`, R1) reads as anything but unlocked: a lock,
/// an answer the compositor cannot give, a timeout or an error, a latch
/// or a recent ask of the lock screen, the daemon's start or its
/// connection places refusing. So a check that fails can never let a key
/// touch approve a card behind the lock or resume a parked request. The
/// compositor's word comes from the anchor (`consent::anchor`, round 8):
/// the compositor logind names, asked by a transient unit.
pub fn session_locked(user: &str, bind: &crate::lockgate::Bind) -> bool {
    super::key::lock_verdict(user, bind) != crate::lockgate::Verdict::Unlocked
}

/// The lock as `hyprctl -j monitors` reports it. Hyprland reports no lock
/// state directly, but an active ext-session-lock is one of the reasons a
/// monitor cannot go solitary: LOCK in `solitaryBlockedBy`, which stays set
/// once the lock's client dies. Hyprland stops at the first reason on a
/// monitor with no workspace yet, so a monitor blocked by WORKSPACE says
/// nothing either way. The same reading as `omarchy-hyprland-session-locked`.
/// Every monitor must be an object whose `solitaryBlockedBy` is an array
/// of strings, or null, which Hyprland reports for a monitor with no
/// reason; a reply in any other shape (a field gone or renamed, a monitor
/// that is not an object, an empty list) is one this cannot read, so it
/// is Unknown, never Unlocked.
pub fn lock_state_from_monitors(json: &[u8]) -> LockState {
    let Ok(serde_json::Value::Array(monitors)) = serde_json::from_slice(json) else {
        return LockState::Unknown;
    };
    // Each monitor's reasons, or None for a monitor this cannot read.
    let reasons: Option<Vec<Vec<&str>>> = monitors
        .iter()
        .map(|m| match m.as_object()?.get("solitaryBlockedBy")? {
            serde_json::Value::Null => Some(Vec::new()),
            serde_json::Value::Array(rs) => rs.iter().map(|r| r.as_str()).collect(),
            _ => None,
        })
        .collect();
    let Some(reasons) = reasons.filter(|r| !r.is_empty()) else {
        return LockState::Unknown;
    };
    if reasons.iter().any(|r| r.contains(&"LOCK")) {
        LockState::Locked
    } else if reasons.iter().any(|r| !r.contains(&"WORKSPACE")) {
        LockState::Unlocked
    } else {
        LockState::Unknown
    }
}

/// `faceauth-lockstate`'s answer for each state: one byte on its stdout
/// and its exit status, which the PAM module reads (the same `lockgate`
/// file, compiled into both).
pub use crate::lockgate::{
    lockstate_code as lockstate_exit, LOCKSTATE_LOCKED, LOCKSTATE_UNKNOWN, LOCKSTATE_UNLOCKED,
};

/// The one Hyprland instance under the user's runtime directory
/// (`<runtime>/hypr/<signature>/.socket.sock`), named by its signature;
/// None for none, more than one, or a name that is not a signature. What
/// `faceauth-lockstate` hands hyprctl, so nothing from the caller's
/// environment picks the instance.
pub fn hyprland_instance(runtime: &std::path::Path) -> Option<String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(runtime.join("hypr")).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let ok_name = !name.is_empty()
            && name.len() <= 128
            && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        let is_dir = entry.file_type().is_ok_and(|t| t.is_dir());
        if ok_name && is_dir && entry.path().join(".socket.sock").exists() {
            found.push(name);
        }
    }
    match found.as_slice() {
        [one] => Some(one.clone()),
        _ => None,
    }
}

/// The Omarchy tree the running shell was launched from:
/// `/etc/omarchy.conf` (written by `omarchy-dev-link` as `export
/// OMARCHY_PATH="..."`, and by hand as a bare assignment), else the
/// package. One resolver for the window, the notices and the lock helper,
/// so a dev-linked desktop is reached the same way by all three.
pub fn omarchy_path() -> String {
    std::fs::read_to_string("/etc/omarchy.conf")
        .ok()
        .and_then(|t| omarchy_path_from_conf(&t))
        .unwrap_or_else(|| "/usr/share/omarchy".into())
}

/// The `OMARCHY_PATH` value in an omarchy.conf text, with or without an
/// `export` prefix and with or without quotes; `None` when the file names
/// nothing usable, so the caller falls through to the package.
pub fn omarchy_path_from_conf(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let l = l.trim();
        let l = l.strip_prefix("export ").map(str::trim_start).unwrap_or(l);
        let v = l
            .strip_prefix("OMARCHY_PATH=")?
            .trim()
            .trim_matches('"')
            .trim_matches('\'');
        (!v.is_empty() && v.starts_with('/')).then(|| v.to_string())
    })
}

/// A desktop notification in the user's session: every elevation by face
/// announces itself, so a loop is visible the first time it fires. Under
/// the pin its request took when it began (fix round 10, Codex 6), so a
/// notice about one session's request never lands on a session that
/// replaced it.
pub fn notify(pin: &Pin, title: &str, body: &str) {
    if let Ok(mut c) = pin.command(Some("omarchy-faceauth notice"), true, false, false) {
        c.args(["/usr/bin/omarchy-notification-send", title, body]);
        let _ = super::bounded::run_bounded(c, None, USER_CALL_WITHIN, USER_CALL_CAP);
    }
}

#[cfg(test)]
mod lock_and_summon_tests {
    use super::*;

    fn args(c: &std::process::Command) -> Vec<String> {
        c.get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    fn test_pin() -> Pin {
        Pin {
            user: "mellis".into(),
            uid: 1000,
            sessions: vec!["4".into(), "c2".into()],
        }
    }

    /// Fix round 11 (Codex 6): both units end at once when their time is
    /// up. `RuntimeMaxSec=` stops the unit (systemd v262
    /// src/core/service.c, `service_dispatch_timer`: "Service reached
    /// runtime time limit. Stopping."), and a stop sends `KillSignal=`
    /// (`state_to_kill_operation`: `KILL_TERMINATE`), SIGTERM by default,
    /// which a payload may ignore until `TimeoutStopSec=`; with SIGKILL
    /// nothing of a call outlives its limit to act late.
    #[test]
    fn both_units_end_at_once() {
        let a = args(&user_command(&test_pin(), None, true, true, true));
        for want in [
            "--property=RuntimeMaxSec=4s",
            "--property=KillSignal=SIGKILL",
        ] {
            assert_eq!(
                a.iter().filter(|x| *x == want).count(),
                2,
                "{}: {:?}",
                want,
                a
            );
        }
    }

    /// Fix round 10 (Codex 6, Opus's transport note): the pinned sessions
    /// are checked again inside both units, the moment each starts: the
    /// carrier before it reaches the user's manager, and the user's unit
    /// before the command, so a call the manager starts late, after the
    /// session it was pinned to has gone, runs nothing. Neither manager
    /// expands `$` in the arguments, so the check, a notice's text and a
    /// command line reach their command as they were written.
    #[test]
    fn the_pin_is_checked_again_inside_both_units() {
        let a = args(&user_command(&test_pin(), None, true, true, true));
        let checks: Vec<usize> = a
            .iter()
            .enumerate()
            .filter(|(_, x)| x.as_str() == PIN_CHECK)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(checks.len(), 2, "{:?}", a);
        for &at in &checks {
            assert_eq!(&a[at - 2..at], ["/bin/sh", "-c"]);
            assert_eq!(
                &a[at + 1..at + 6],
                ["faceauth-pin", "1000", "4", "c2", "--"]
            );
        }
        assert_eq!(a[checks[0] + 6], "/usr/bin/systemd-run");
        assert_eq!(a[checks[0] + 7], "--user");
        assert_eq!(checks[1] + 6, a.len(), "the command goes right after it");
        assert_eq!(
            a.iter().filter(|x| *x == "--expand-environment=no").count(),
            2,
            "{:?}",
            a
        );
    }

    /// The check itself, run against records of a test's own: the command
    /// runs only while every pinned session is still a live desktop of the
    /// pinned uid (the rule `lockgate::user_desktops` applies), and
    /// otherwise the unit exits 75 with nothing run.
    #[test]
    fn the_in_unit_pin_check_runs_the_command_only_for_a_live_pinned_desktop() {
        let dir = std::env::temp_dir().join(format!("faceauth-pincheck-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sessions")).unwrap();
        let script = PIN_CHECK.replace(
            "/run/systemd/sessions/",
            &format!("{}/sessions/", dir.display()),
        );
        assert_ne!(script, PIN_CHECK, "the records' path is in the check");
        let run = |ids: &[&str]| {
            let o = std::process::Command::new("/bin/sh")
                .args(["-c", &script, "faceauth-pin", "1000"])
                .args(ids)
                .args(["--", "/bin/echo", "ran $HOME"])
                .output()
                .unwrap();
            (
                o.status.code(),
                String::from_utf8_lossy(&o.stdout).into_owned(),
            )
        };
        let record =
            |id: &str, text: &str| std::fs::write(dir.join("sessions").join(id), text).unwrap();
        record("4", "UID=1000\nTYPE=wayland\n");
        record("5", "UID=1000\nTYPE=tty\nORIGINAL_TYPE=x11\n");
        assert_eq!(run(&["4", "5"]), (Some(0), "ran $HOME\n".into()));
        let refused = (Some(75), String::new());
        assert_eq!(run(&["4", "6"]), refused, "a pinned session gone");
        assert_eq!(run(&[]), refused, "nothing pinned");
        assert_eq!(run(&["../sessions/4"]), refused, "not a session id");
        record("6", "UID=1001\nTYPE=wayland\n");
        assert_eq!(run(&["6"]), refused, "another user's");
        record("6", "UID=1000\nTYPE=wayland\nSTATE=closing\n");
        assert_eq!(run(&["6"]), refused, "closing");
        record("6", "UID=1000\nTYPE=wayland\nCLASS=greeter\n");
        assert_eq!(run(&["6"]), refused, "a greeter");
        record("6", "UID=1000\nTYPE=tty\n");
        assert_eq!(run(&["6"]), refused, "not graphical");
        record("6", "UID=10000\nTYPE=wayland\n");
        assert_eq!(run(&["6"]), refused, "a uid that only starts the same");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The lock helper's calls carry the same check, word for word.
    #[test]
    fn the_lock_helper_checks_the_pin_the_same_way() {
        let helper = include_str!("../../../packaging/faceauth-lock-session");
        assert!(
            helper.contains(&format!("pin_check='{}'", PIN_CHECK)),
            "the helper's pin_check is not the daemon's PIN_CHECK"
        );
    }

    /// Round 5 (A): the helper finds the one Hyprland instance with a
    /// socket under the runtime directory, and nothing when there are
    /// none, two, or a name that is not a signature; each answer has its
    /// exit status.
    #[test]
    fn the_lock_helper_finds_the_one_instance_and_answers_in_one_bit() {
        let base = std::env::temp_dir().join(format!("faceauth-hypr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let hypr = base.join("hypr");
        std::fs::create_dir_all(&hypr).unwrap();
        assert_eq!(hyprland_instance(&base), None, "none");
        let a = hypr.join("abc123_1791804929_273063492");
        std::fs::create_dir_all(&a).unwrap();
        assert_eq!(hyprland_instance(&base), None, "no socket yet");
        std::fs::write(a.join(".socket.sock"), b"").unwrap();
        assert_eq!(
            hyprland_instance(&base).as_deref(),
            Some("abc123_1791804929_273063492")
        );
        let b = hypr.join("def456_1_2");
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(b.join(".socket.sock"), b"").unwrap();
        assert_eq!(hyprland_instance(&base), None, "two: no telling which");
        std::fs::remove_dir_all(&b).unwrap();
        let odd = hypr.join("../x");
        let _ = odd;
        let weird = hypr.join("a-b");
        std::fs::create_dir_all(&weird).unwrap();
        std::fs::write(weird.join(".socket.sock"), b"").unwrap();
        assert_eq!(
            hyprland_instance(&base).as_deref(),
            Some("abc123_1791804929_273063492"),
            "a name that is not a signature is no instance"
        );
        assert_eq!(hyprland_instance(&base.join("nowhere")), None);
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(lockstate_exit(LockState::Unlocked), 0);
        assert_eq!(lockstate_exit(LockState::Locked), 1);
        assert_eq!(lockstate_exit(LockState::Unknown), 2);
    }

    /// 3, round 3's 4: only an affirmative "unlocked" counts as unlocked;
    /// a lock, a monitor that cannot tell, no monitors, a reply in another
    /// shape (the field gone, renamed or of another type, a monitor that is
    /// not an object), or an answer that is not the monitors list all read
    /// as locked. Hyprland's null for a monitor with no reason is read.
    #[test]
    fn only_an_affirmative_unlocked_counts_as_unlocked() {
        let state = |j: &str| lock_state_from_monitors(j.as_bytes());
        assert_eq!(
            state(r#"[{"name":"eDP-1","solitaryBlockedBy":["LOCK","WORKSPACE"]}]"#),
            LockState::Locked
        );
        assert_eq!(
            state(
                r#"[{"name":"eDP-1","solitaryBlockedBy":["WINDOWS"]},{"name":"DP-1","solitaryBlockedBy":["LOCK"]}]"#
            ),
            LockState::Locked
        );
        assert_eq!(
            state(r#"[{"name":"eDP-1","solitaryBlockedBy":["WINDOWS"]}]"#),
            LockState::Unlocked
        );
        assert_eq!(
            state(r#"[{"name":"eDP-1","solitaryBlockedBy":null}]"#),
            LockState::Unlocked,
            "null: no reason at all"
        );
        assert_eq!(
            state(
                r#"[{"name":"eDP-1","solitaryBlockedBy":null},{"name":"DP-1","solitaryBlockedBy":["LOCK"]}]"#
            ),
            LockState::Locked
        );
        for unknown in [
            r#"[{"name":"eDP-1","solitaryBlockedBy":["WORKSPACE"]}]"#,
            r#"[{"name":"eDP-1"}]"#,
            r#"[{"name":"eDP-1","solitaryBlocked":["WINDOWS"]}]"#,
            r#"[{"name":"eDP-1","solitaryBlockedBy":"WINDOWS"}]"#,
            r#"[{"name":"eDP-1","solitaryBlockedBy":{}}]"#,
            r#"[{"name":"eDP-1","solitaryBlockedBy":[1]}]"#,
            r#"[{"name":"eDP-1","solitaryBlockedBy":["WINDOWS"]},{"name":"DP-1"}]"#,
            r#"[null]"#,
            r#"[["LOCK"]]"#,
            r#"[{"name":"eDP-1","solitaryBlockedBy":["WINDOWS"]},null]"#,
            "[]",
            "",
            "not json",
            r#"{"monitors":[]}"#,
        ] {
            assert_eq!(state(unknown), LockState::Unknown, "{:?}", unknown);
        }
        let locked = |s: LockState| s != LockState::Unlocked;
        assert!(locked(LockState::Locked) && locked(LockState::Unknown));
        assert!(!locked(LockState::Unlocked));
    }

    /// Fix round 9 (Codex 5, Opus L1): the way into the user's manager
    /// can never start one. No `--machine=USER@.host` (sd-bus turns that
    /// into `systemd-run … -pPAMName=login`, a PAM session for which
    /// logind starts a manager) and no PAM session at all: a system unit
    /// runs as the user, with no `PAMName=`, and talks to the manager over
    /// the user's own bus socket (`systemd-run --user`). A manager that is
    /// not running has no socket, so the call fails and nothing starts.
    #[test]
    fn the_way_into_the_users_manager_opens_no_pam_session() {
        let c = user_command(
            &test_pin(),
            Some("omarchy-faceauth window"),
            true,
            true,
            true,
        );
        let a = args(&c);
        assert!(!a.iter().any(|x| x.contains("--machine")), "{:?}", a);
        assert!(!a.iter().any(|x| x.contains("PAMName")), "{:?}", a);
        for want in [
            "--property=User=mellis",
            "--property=Environment=XDG_RUNTIME_DIR=/run/user/1000",
            "--property=Environment=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
            "--property=NoNewPrivileges=yes",
            "--property=CapabilityBoundingSet=",
        ] {
            assert!(a.iter().any(|x| x == want), "{}: {:?}", want, a);
        }
        let inner = a
            .iter()
            .rposition(|x| x == "/usr/bin/systemd-run")
            .expect("the inner systemd-run");
        let outer = a.iter().position(|x| x == "/usr/bin/systemd-run").unwrap();
        assert!(inner > outer, "a system unit that runs systemd-run --user");
        assert_eq!(a[inner + 1], "--user");
        assert!(a[inner..]
            .iter()
            .any(|x| x.starts_with("--setenv=OMARCHY_PATH=") || x.starts_with("-EOMARCHY_PATH=")));
        assert!(
            a[inner..].iter().any(|x| x == "--pipe")
                && a[outer..inner].iter().any(|x| x == "--pipe")
        );
    }

    /// Fix round 9 (Codex 5): a dispatch into the user's manager is made
    /// only while the sessions pinned when the work began are still the
    /// user's live desktops: one gone, or a new one in its place (a logout
    /// and a fresh login), and nothing is dispatched.
    #[test]
    fn a_dispatch_revalidates_its_pinned_session() {
        let dir = std::env::temp_dir().join(format!("faceauth-pin-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sessions")).unwrap();
        assert!(
            Pin::take_at(&dir, "alice", 1000).is_err(),
            "no desktop, no pin"
        );
        std::fs::write(dir.join("sessions/3"), "UID=1000\nTYPE=wayland\n").unwrap();
        let pin = Pin::take_at(&dir, "alice", 1000).unwrap();
        assert!(pin.still_at(&dir));
        std::fs::write(
            dir.join("sessions/3"),
            "UID=1000\nTYPE=wayland\nSTATE=closing\n",
        )
        .unwrap();
        assert!(!pin.still_at(&dir), "closing");
        std::fs::remove_file(dir.join("sessions/3")).unwrap();
        std::fs::write(dir.join("sessions/9"), "UID=1000\nTYPE=wayland\n").unwrap();
        assert!(
            !pin.still_at(&dir),
            "a replacement session is not the pinned one"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 2: the summon runs `omarchy-shell -s` from the Omarchy tree the
    /// shell was launched from, a checkout or the package's tree alike, by
    /// its absolute path, and carries no payload on its command line: the
    /// payload, answer token and all, goes on stdin.
    #[test]
    fn the_summon_runs_the_resolved_trees_shell_with_no_payload_on_its_command_line() {
        for tree in [
            "/usr/share/omarchy",
            "/home/mellis/Work/Omarchy-FaceAuth-Prod/omarchy",
        ] {
            let a = args(&summon_command(tree, &test_pin(), "omarchy.faceauth"));
            let shell = format!("{}/bin/omarchy-shell", tree);
            let at = a
                .iter()
                .position(|x| *x == shell)
                .expect("the tree's omarchy-shell");
            assert_eq!(&a[at + 1..], ["-s", "shell", "summon", "omarchy.faceauth"]);
            assert!(
                !a.iter().any(|x| x == "/usr/bin/omarchy-shell"),
                "never /usr/bin's, which may lag the tree"
            );
            assert!(!a.iter().any(|x| x.contains("token") || x.starts_with('{')));
            assert!(a.iter().any(|x| x == "--pipe"), "stdin reaches the command");
        }
    }

    /// Fix round 10 (Codex 2, Opus N4): a summon whose units never end,
    /// and hold its pipes, is given up at its deadline; one that answers
    /// and ends is read at once, whoever still holds its pipes.
    #[test]
    fn a_stalled_summon_is_given_up_with_its_pipes_closed() {
        let t0 = std::time::Instant::now();
        let mut stalled = std::process::Command::new("/bin/sh");
        stalled.args(["-c", "cat >/dev/null; sleep 30 & exec sleep 30"]);
        let e = run_summon_within(
            stalled,
            "/usr/share/omarchy",
            "omarchy.faceauth",
            "{}",
            std::time::Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(e.to_string().contains("did not finish"), "{}", e);
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(900),
            "{:?}",
            t0.elapsed()
        );
        let t0 = std::time::Instant::now();
        let mut answered = std::process::Command::new("/bin/sh");
        answered.args(["-c", "cat >/dev/null; echo ok; sleep 30 & exit 0"]);
        assert!(run_summon_within(
            answered,
            "/usr/share/omarchy",
            "omarchy.faceauth",
            "{}",
            std::time::Duration::from_secs(5),
        )
        .is_ok());
        assert!(
            t0.elapsed() < std::time::Duration::from_millis(900),
            "{:?}",
            t0.elapsed()
        );
        // Both units are capped too.
        let a = args(&user_command(&test_pin(), None, false, true, true));
        assert_eq!(
            a.iter()
                .filter(|x| x.starts_with("--property=RuntimeMaxSec="))
                .count(),
            2,
            "the carrier and the user unit: {:?}",
            a
        );
    }

    /// 2: the payload goes down the command's stdin; and a shell that
    /// cannot take it (a tree whose omarchy-shell has no -s) fails the
    /// summon once, with a log line that says so, and nothing runs again.
    #[test]
    fn a_summon_sends_the_payload_on_stdin_and_a_shell_without_s_fails_closed() {
        let dir = std::env::temp_dir().join(format!("faceauth-summon-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let got = dir.join("stdin");
        let mut c = std::process::Command::new("/bin/sh");
        c.args(["-c", "cat >\"$0\"", got.to_str().unwrap()]);
        assert!(run_summon(
            c,
            "/usr/share/omarchy",
            "omarchy.faceauth",
            "{\"token\":\"t\"}"
        )
        .is_ok());
        assert_eq!(std::fs::read_to_string(&got).unwrap(), "{\"token\":\"t\"}");
        let runs = dir.join("runs");
        let mut old = std::process::Command::new("/bin/sh");
        old.args([
            "-c",
            "echo run >>\"$0\"; echo 'Target not found.' >&2; exit 1",
            runs.to_str().unwrap(),
        ]);
        let e = run_summon(
            old,
            "/home/x/omarchy",
            "omarchy.faceauth",
            "{\"token\":\"t\"}",
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("/home/x/omarchy/bin/omarchy-shell -s") && e.contains("has no -s"),
            "{}",
            e
        );
        assert!(e.contains("Target not found."), "{}", e);
        assert!(!e.contains("\"t\""), "the log line carries no token");
        assert_eq!(
            std::fs::read_to_string(&runs).unwrap(),
            "run\n",
            "one run, no other way"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod shell_answer_tests {
    use super::*;

    /// F2: the "unknown" a summon gets for a window the shell does not
    /// have is read by the daemon, not by a change to the shared command.
    #[test]
    fn a_summon_answered_unknown_is_an_error_and_nothing_else_is() {
        let summon = ["shell", "summon", "omarchy.faceauth", "{}"];
        assert!(shell_answer(&summon, true, b"unknown\n").is_err());
        assert!(shell_answer(&summon, true, b"  unknown  ").is_err());
        assert!(shell_answer(&summon, true, b"ok\n").is_ok());
        assert!(shell_answer(&summon, true, b"").is_ok());
        assert!(
            shell_answer(&summon, false, b"ok\n").is_err(),
            "a failed exit is an error whatever was said"
        );
        let hide = ["shell", "hide", "omarchy.faceauth"];
        assert!(
            shell_answer(&hide, true, b"unknown\n").is_ok(),
            "only a summon has to have shown something"
        );
        assert!(shell_answer(&["shell", "ping"], true, b"unknown").is_ok());
    }
}

#[cfg(test)]
mod window_text_tests {

    #[test]
    fn the_omarchy_path_is_read_in_every_form_the_conf_takes() {
        use super::omarchy_path_from_conf as f;
        assert_eq!(
            f("export OMARCHY_PATH=\"/home/x/omarchy\"\n").as_deref(),
            Some("/home/x/omarchy")
        );
        assert_eq!(
            f("OMARCHY_PATH=/usr/share/omarchy\n").as_deref(),
            Some("/usr/share/omarchy")
        );
        assert_eq!(
            f("# comment\n  export  OMARCHY_PATH='/opt/o'\n").as_deref(),
            Some("/opt/o")
        );
        assert_eq!(f("OMARCHY_PATH=\n"), None);
        assert_eq!(f("OMARCHY_PATH=relative\n"), None);
        assert_eq!(f(""), None);
    }

    /// Fix round 8 (item 14): every call into the user's manager (the
    /// card's summon, a notice) is made only while the user has a
    /// desktop in logind's records.
    #[test]
    fn nothing_is_run_in_the_users_manager_without_a_desktop() {
        let dir = std::env::temp_dir().join(format!("faceauth-shellgate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sessions")).unwrap();
        assert!(super::desktop_gate_at(&dir, 1000).is_err());
        std::fs::write(dir.join("sessions/2"), "UID=1000\nTYPE=wayland\n").unwrap();
        assert!(super::desktop_gate_at(&dir, 1000).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
