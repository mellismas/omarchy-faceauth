//! The one answer to "is the session locked?" (Mike's R1, round 6). Every
//! path that lets the security key approve anything asks it: the daemon's
//! card and key-fallback lanes, its `key_ready` and `key_wait` answers,
//! and the text-console rule. With faceauthd down the PAM module's key line
//! is stock pam_u2f's and asks nothing of it (fix round 10, item 6). The
//! daemon compiles this file as `faceauth_daemon::lockgate`; the PAM module
//! includes the same file (it links nothing but libc) for the wait budget,
//! so the two can never drift. Std only.
//!
//! `is_locked` fails closed: it answers `Unlocked` only when it can show
//! the session unlocked, and anything it cannot show counts as locked. It
//! tells three kinds of "locked" apart, because what a caller does next
//! differs:
//!
//! - `Locked`: positive. In the daemon, the lock screen's reserved channel
//!   is open and the compositor says the lock is up, both (round 7, B); in
//!   the PAM module, which has no channel to weigh, the compositor it
//!   verified itself says so. A request from the locked desktop may wait
//!   for this without a deadline.
//! - `Held`: the compositor says unlocked, but a latch is still running out
//!   its hold after a locked-to-unlocked switch (R2). Bounded by the hold.
//! - `Unknown`: no answer, a malformed one, a latch with no unlock seen,
//!   or the daemon's connection places refusing callers. Never waited on
//!   for more than `UNKNOWN_LIMIT` (Opus N1): the line falls to the
//!   password, never to the key.

use std::path::Path;
use std::time::Duration;

/// What the compositor said of the session lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockState {
    Unlocked,
    Locked,
    /// No answer, a malformed one, or one the reader does not know.
    Unknown,
}

/// Whether logind's records show a graphical session for anyone at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Desktop {
    /// No graphical session of any user, on any seat: a text console.
    None,
    Some,
    /// The records could not be read: counts as a desktop.
    Unreadable,
}

/// Where a request comes from: the user's graphical desktop (or a process
/// of theirs with no session of its own, which is where desktop apps run),
/// or a session that is not the desktop (a text console, a remote login).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Desktop,
    Elsewhere,
}

/// The one verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Unlocked,
    Held,
    Locked,
    Unknown,
}

impl Verdict {
    /// The name the daemon's `key_wait` answer carries.
    pub fn name(self) -> &'static str {
        match self {
            Verdict::Unlocked => "unlocked",
            Verdict::Held => "held",
            Verdict::Locked => "locked",
            Verdict::Unknown => "unknown",
        }
    }
}

/// What `is_locked` weighs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    /// The compositor's word, asked now.
    pub compositor: LockState,
    /// logind's records, read now.
    pub desktop: Desktop,
    /// The lock screen's reserved channel (round 7, B): `Some(true)` while
    /// one is open for the user, `Some(false)` when none is, `None` where
    /// there is no channel to weigh (the verdict before the latch).
    pub channel: Option<bool>,
    /// A latch holds the user: a channel open or dropped, a key unlock
    /// asked, a lock or a doubt seen, and the hold not yet run out after an
    /// unlock seen since; or the daemon started within one hold.
    pub latched: bool,
    /// The latch's hold clock runs: the compositor was seen to say unlocked
    /// since the latch began (or the daemon's start latch, which ends by
    /// itself), so the wait is bounded by the hold. A latch without one (a
    /// dropped channel, a key unlock asked, a lock or a doubt not yet
    /// followed by an unlock) is unknown, never held (round 8, Codex 1).
    pub holding: bool,
    /// The daemon's connection places refused or dropped a caller within
    /// one hold: every user counts as latched (round 6, item 10).
    pub saturated: bool,
}

/// The one function. In order: with the lock screen's channel open, only
/// the compositor's lock is a positive lock, and anything else unknown;
/// the compositor's lock is positive where no channel is weighed, and
/// unknown where one should be and is not; a latch or a saturated daemon
/// never reads as unlocked, whatever logind says (a session turning
/// nongraphical never drops a latch: Codex 4, Opus N2); the compositor's
/// unlocked is unlocked; with no graphical session of anyone's in logind's
/// records and nothing latched, there is no lock screen to wait for (the
/// text-console rule); anything else is unknown.
pub fn is_locked(f: &Facts) -> Verdict {
    match (f.channel, f.compositor) {
        (Some(true), LockState::Locked) => return Verdict::Locked,
        (Some(true), _) => return Verdict::Unknown,
        (Some(false), LockState::Locked) => return Verdict::Unknown,
        (None, LockState::Locked) => return Verdict::Locked,
        _ => {}
    }
    if f.saturated {
        return Verdict::Unknown;
    }
    if f.latched {
        return if f.compositor == LockState::Unlocked && f.holding {
            Verdict::Held
        } else {
            Verdict::Unknown
        };
    }
    match (f.compositor, f.desktop) {
        (LockState::Unlocked, _) => Verdict::Unlocked,
        (_, Desktop::None) => Verdict::Unlocked,
        _ => Verdict::Unknown,
    }
}

/// The longest a key line or a parked consent request waits on an
/// `Unknown` verdict before it falls to the password (Opus N1).
pub const UNKNOWN_LIMIT: Duration = Duration::from_secs(10);

/// How long the compositor (the anchored one, logind's) must have said
/// unlocked, look after look, before a latch held only by a dropped
/// channel lets go (round 8, Opus F1). Until then the latch reads as
/// unknown, which `UNKNOWN_LIMIT` bounds; 3 s (fix round 8, Opus L4), well
/// inside one request's budget, so the first request after a drop still
/// gets its answer.
pub const DROP_CLEARS: Duration = Duration::from_secs(3);

/// How often the daemon tells a waiting PAM line it is still at work
/// (`{"result":"pending"}`), and how long the line waits between lines
/// before it takes the daemon for hung (round 6, item 12). Every blocking
/// step in the daemon between two keepalives is bounded below `LIVENESS`.
pub const BEAT: Duration = Duration::from_secs(2);
pub const LIVENESS: Duration = Duration::from_secs(6);

/// How long a key-fallback line's check waits for a touch, the daemon's
/// and the module's own alike, so a check that never ends (a hung helper,
/// a key that never answers) still reaches the password in time.
pub const FALLBACK_DEADLINE: Duration = Duration::from_secs(6);

/// The longest a consent request waits for a camera held elsewhere before
/// it answers "busy", below `LIVENESS`.
pub const CAMERA_WAIT: Duration = Duration::from_secs(4);

/// The password line is reached within this of a request, whatever fails
/// in faceauth, alone or together, unless the screen is positively locked
/// and the request comes from the locked desktop, or the user is at work
/// on a card or a PIN prompt (round 6, item 12). The module's tests hold
/// the bounds above to it.
pub const PASSWORD_WITHIN: Duration = Duration::from_secs(15);

/// `faceauth-lockstate`'s answer, one byte on its stdout and the same as
/// its exit status: unlocked, locked, no answer.
pub const LOCKSTATE_UNLOCKED: u8 = 0;
pub const LOCKSTATE_LOCKED: u8 = 1;
pub const LOCKSTATE_UNKNOWN: u8 = 2;

/// How the question pam_faceauth puts to polkit's agent starts. The question
/// goes through polkit's own helper conversation (a `PAM_PROMPT_ECHO_OFF`),
/// for the cookie of the request the helper serves (round 16c): polkit gives
/// the daemon no other tie between the agent's context and the helper's PAM
/// request. This text is followed by a fresh challenge
/// (`polkit_cookie_question`, round 18). Omarchy's agent answers it with the
/// challenge and the request's cookie and shows nothing; only an agent that
/// said it answers it, by sending this exact text (`context_cookie_prompt`),
/// is asked, so no other agent ever shows it as a field to type into.
pub const POLKIT_COOKIE_PROMPT: &str = "faceauth: polkit cookie challenge ";

/// Whether `s` has the form of a cookie question's challenge: 32 lowercase
/// hex characters, 16 bytes from the kernel's random source.
pub fn polkit_challenge_ok(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The question for one ask: the prompt's text and its challenge.
pub fn polkit_cookie_question(challenge: &str) -> String {
    format!("{POLKIT_COOKIE_PROMPT}{challenge}")
}

/// Whether `s` has the form of a polkit cookie as faceauth takes one: 1 to
/// 256 bytes of letters, digits, `-`, `_`, `.` and `:` (polkitd's own are
/// letters, digits and `-`). Anything else, an empty answer included, is
/// no cookie.
pub fn polkit_cookie_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
}

/// What Omarchy's agent puts before the challenge and the cookie in its
/// answer to the cookie question (round 17, Codex 1): an answer without it,
/// such as something typed into a prompt an agent showed by mistake, is no
/// answer, and is never passed on.
pub const POLKIT_COOKIE_TAG: &str = "faceauth-cookie ";

/// The cookie in an agent's answer to the question that carried `challenge`:
/// after the tag, that challenge and a space, a cookie of the right form, or
/// "" for an agent that has none. None for any other answer, and for any
/// answer to a challenge not of its form. The challenge is what text typed
/// into a prompt shown by mistake cannot carry, a password that starts with
/// the tag included: it did not exist before the question (round 18, Codex
/// 17b's Low).
pub fn polkit_cookie_answer<'a>(answer: &'a str, challenge: &str) -> Option<&'a str> {
    if !polkit_challenge_ok(challenge) {
        return None;
    }
    let cookie = answer
        .strip_prefix(POLKIT_COOKIE_TAG)?
        .strip_prefix(challenge)?
        .strip_prefix(' ')?;
    (cookie.is_empty() || polkit_cookie_ok(cookie)).then_some(cookie)
}

/// The byte for a lock state.
pub fn lockstate_code(s: LockState) -> u8 {
    match s {
        LockState::Unlocked => LOCKSTATE_UNLOCKED,
        LockState::Locked => LOCKSTATE_LOCKED,
        LockState::Unknown => LOCKSTATE_UNKNOWN,
    }
}

/// Is a logind session record (`/run/systemd/sessions/<id>`) a graphical
/// one? Its type now or the type it was created with: the session's
/// controller (the compositor) can change the first (`SetType`), not the
/// second.
fn record_is_graphical(text: &str) -> bool {
    text.lines().any(|l| {
        matches!(
            l,
            "TYPE=wayland"
                | "TYPE=x11"
                | "TYPE=mir"
                | "ORIGINAL_TYPE=wayland"
                | "ORIGINAL_TYPE=x11"
                | "ORIGINAL_TYPE=mir"
        )
    })
}

/// Is a logind session record a greeter's (`CLASS=greeter`)? A login
/// screen is not a desktop anyone can lock (round 8, Opus Low).
fn record_is_greeter(text: &str) -> bool {
    text.lines().any(|l| l == "CLASS=greeter")
}

/// A logind session id as it names a record file: letters and digits.
fn session_id_ok(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// Whether logind's records under `root` (`/run/systemd`, root's to
/// write) show a graphical session for any user (Opus N5: the seat, not
/// PAM_USER). No sessions directory is no session at all; a directory or
/// a record that cannot be read is `Unreadable`, which counts as a
/// desktop.
pub fn graphical_sessions(root: &Path) -> Desktop {
    let dir = match std::fs::read_dir(root.join("sessions")) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Desktop::None,
        Err(_) => return Desktop::Unreadable,
    };
    let mut unreadable = false;
    for entry in dir {
        let Ok(entry) = entry else {
            unreadable = true;
            continue;
        };
        let name = entry.file_name();
        // logind writes each record through a temporary file beside it.
        if !name.to_str().is_some_and(session_id_ok) {
            continue;
        }
        match std::fs::read_to_string(entry.path()) {
            Ok(text) if record_is_graphical(&text) && !record_is_greeter(&text) => {
                return Desktop::Some
            }
            Ok(_) => {}
            // Gone between the listing and the read: a session that ended.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => unreadable = true,
        }
    }
    if unreadable {
        Desktop::Unreadable
    } else {
        Desktop::None
    }
}

/// Whether `uid` has a desktop now, from logind's root-readable records
/// under `root` alone (fix round 8, item 14): a graphical session of
/// theirs, by its type now or the type it was created with, that is
/// neither a greeter nor closing. Such a session pins the user, so logind
/// has started their service manager; with none, nothing the daemon runs
/// in that manager may run, since reaching it opens a PAM session that
/// would start one (systemd v262 src/libsystemd/sd-bus/sd-bus.c,
/// `bus_set_address_machine`: `systemd-run -M.host -pUser=… -pPAMName=login
/// systemd-stdio-bridge --user`; logind's `user_start` starts the manager
/// for a new session's user, src/login/logind-user.c). Unreadable records
/// are no desktop.
pub fn user_has_desktop(root: &Path, uid: u32) -> bool {
    !user_desktops(root, uid).is_empty()
}

/// The ids of `uid`'s live desktops in logind's records under `root`
/// (`user_has_desktop`'s sessions), sorted: what a dispatch into the
/// user's manager pins, and checks again before it acts (fix round 9).
pub fn user_desktops(root: &Path, uid: u32) -> Vec<String> {
    let want = format!("UID={}", uid);
    let Ok(dir) = std::fs::read_dir(root.join("sessions")) else {
        return Vec::new();
    };
    let mut ids: Vec<String> = dir
        .flatten()
        .filter_map(|entry| {
            let name = entry.file_name().to_str()?.to_string();
            let text = std::fs::read_to_string(entry.path()).ok()?;
            (session_id_ok(&name)
                && text.lines().any(|l| l == want)
                && record_is_graphical(&text)
                && !record_is_greeter(&text)
                && !text.lines().any(|l| l == "STATE=closing"))
            .then_some(name)
        })
        .collect();
    ids.sort();
    ids
}

/// Where a process comes from, from its cgroup listing (`/proc/<pid>/cgroup`)
/// and logind's records under `root`: a process in a session scope whose
/// record says remote, or whose type is not graphical (a text console),
/// is `Elsewhere`; a graphical session, a process with no session scope
/// (the user manager, where desktop apps and the polkit agent run, or a
/// system service), and anything that cannot be read are `Desktop`. Either
/// answer is safe for the key: `Elsewhere` only sends a request to the
/// password sooner.
pub fn origin_of(cgroup: &str, root: &Path) -> Origin {
    let scope = cgroup
        .lines()
        .flat_map(|l| l.rsplit(':').next().unwrap_or("").split('/'))
        .find_map(|c| c.strip_prefix("session-")?.strip_suffix(".scope"));
    let Some(id) = scope.filter(|id| session_id_ok(id)) else {
        return Origin::Desktop;
    };
    let Ok(text) = std::fs::read_to_string(root.join("sessions").join(id)) else {
        return Origin::Desktop;
    };
    if text.lines().any(|l| l == "REMOTE=1") || !record_is_graphical(&text) {
        Origin::Elsewhere
    } else {
        Origin::Desktop
    }
}

/// Which of a user's graphical sessions a lock question is about (round
/// 8, Codex 3): the session the request came from, or, from the user
/// manager (desktop apps, the polkit agent), the user's only desktop; or
/// none that can be named.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Bind {
    /// This logind session.
    Session(String),
    /// The user's only graphical session; two or more name none.
    OnlyDesktop,
    /// Nothing unambiguous: no answer. The default, so a request whose
    /// binding was never read gets none.
    #[default]
    Ambiguous,
}

/// Where the system manager puts polkit's socket-activated helper
/// instances (fix round 13, Codex 5): polkit 127's
/// `polkit-agent-helper@.service` sets no `Slice=`, so an instance goes to
/// its template's slice, `system-` and the escaped prefix (systemd v262
/// src/core/unit.c, `unit_set_default_slice`; `unit_name_escape` turns
/// each `-` into `\x2d`), under system.slice (src/basic/cgroup-util.c,
/// `cg_slice_to_path`), at the root of the hierarchy, where the system
/// manager's cgroup root is (src/core/cgroup.c, `unit_default_cgroup_path`).
/// The daemon reads every listing from the root: `ProtectControlGroups=yes`
/// makes no cgroup namespace (systemd.exec(5); only `private` and `strict`
/// do). Only root makes units there; a user manager's units, whatever
/// their names, are all under /user.slice/user-UID.slice/user@UID.service/.
pub const POLKIT_HELPER_SLICE: &str = "/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/";

/// polkit's helper's comm: `polkit-agent-helper-1`, cut to the kernel's
/// 15 bytes (`TASK_COMM_LEN`).
pub const POLKIT_HELPER_COMM: &str = "polkit-agent-he";

/// What faceauthd reads of a process that may be polkit's helper, besides
/// its cgroup (fix round 14, Opus N1, Codex 2): its real uid, from
/// /proc/PID/status, and its comm, neither of which takes a ptrace check
/// (fs/proc/base.c, `tgid_base_stuff`). Never its executable: faceauthd is
/// uid 0 with no capability, polkit 127's helper runs as root with its
/// unit's full permitted set, and the exe link takes ptrace access
/// (`call_proc_get_link`, `PTRACE_MODE_READ_FSCREDS`), which
/// `cap_ptrace_access_check` refuses unless the target's permitted set is
/// within the caller's effective one (security/commoncap.c), so it never
/// reads. The cgroup is the proof: only PID 1 makes cgroups under
/// /system.slice/ and writes the instance name; these are a second sign.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HelperSigns<'a> {
    /// The real uid.
    pub ruid: Option<u32>,
    /// The comm, trimmed.
    pub comm: Option<&'a str>,
}

impl HelperSigns<'_> {
    /// Real uid 0 and polkit's helper's comm.
    fn helper(&self) -> bool {
        self.ruid == Some(0) && self.comm == Some(POLKIT_HELPER_COMM)
    }
}

/// The instance of polkit's socket-activated helper unit a process is in,
/// believed only when its cgroup is that unit's in the system manager's own
/// hierarchy (`POLKIT_HELPER_SLICE`, from the root: never anything in a
/// user's delegated tree, where any unit name goes; fix round 13, Codex 5),
/// and the process is root with polkit's helper's comm (`HelperSigns`, fix
/// round 14). None otherwise.
pub fn polkit_helper_instance<'a>(cgroup: &'a str, signs: HelperSigns<'_>) -> Option<&'a str> {
    if !signs.helper() {
        return None;
    }
    let path = cgroup
        .lines()
        .find_map(|l| l.strip_prefix("0::"))?
        .trim_end();
    let instance = path
        .strip_prefix(POLKIT_HELPER_SLICE)?
        .strip_prefix("polkit-agent-helper@")?
        .strip_suffix(".service")?;
    (!instance.is_empty() && !instance.contains('/')).then_some(instance)
}

/// The agent systemd wrote into polkit's socket-activated helper instance
/// (`polkit-agent-helper@<n>-<cookie>-<pid>_<pidfd id>-<uid>.service`, or
/// `<n>-<cookie>-<pid>-<uid>` without pidfd ids; systemd's
/// `instance_from_socket`), for a process `polkit_helper_instance` believes:
/// the pid and the uid of the process that connected it, polkit's agent.
/// None for anything else, `<n>-<cookie>-unknown` (a peer in another
/// namespace) included.
pub fn polkit_instance(cgroup: &str, signs: HelperSigns<'_>) -> Option<(u32, u32)> {
    let instance = polkit_helper_instance(cgroup, signs)?;
    let parts: Vec<&str> = instance.split('-').collect();
    let [n, cookie, pid, uid] = parts.as_slice() else {
        return None;
    };
    n.parse::<u64>().ok()?;
    cookie.parse::<u64>().ok()?;
    let pid = pid.split_once('_').map_or(*pid, |(p, _)| p);
    Some((pid.parse::<u32>().ok()?, uid.parse::<u32>().ok()?))
}

/// The pidfs inode systemd wrote beside the agent's pid in polkit's helper
/// instance name, when it wrote one: what proves the pid is still that
/// agent and not a process that reused it.
pub fn polkit_instance_id(cgroup: &str, signs: HelperSigns<'_>) -> Option<u64> {
    let instance = polkit_helper_instance(cgroup, signs)?;
    let pid = instance.split('-').nth(2)?;
    pid.split_once('_')?.1.parse().ok()
}

/// The uid of polkit's agent, from its helper instance (`polkit_instance`).
pub fn polkit_instance_uid(cgroup: &str, signs: HelperSigns<'_>) -> Option<u32> {
    polkit_instance(cgroup, signs).map(|(_, uid)| uid)
}

/// The binding of a request from a process with this cgroup listing and
/// these signs (`HelperSigns`), for the account `uid`: its own logind session scope;
/// polkit's helper, whose agent must be that account's (another account's
/// agent is ambiguous, and so is anything named as a helper that
/// `polkit_helper_instance` does not believe); anything else, the user's
/// only desktop.
pub fn bind_of(cgroup: &str, signs: HelperSigns<'_>, uid: u32) -> Bind {
    if cgroup.trim().is_empty() {
        return Bind::Ambiguous;
    }
    if cgroup.contains("polkit-agent-helper@") {
        return match polkit_instance_uid(cgroup, signs) {
            Some(agent) if agent == uid => Bind::OnlyDesktop,
            _ => Bind::Ambiguous,
        };
    }
    let scope = cgroup
        .lines()
        .flat_map(|l| l.rsplit(':').next().unwrap_or("").split('/'))
        .find_map(|c| c.strip_prefix("session-")?.strip_suffix(".scope"));
    match scope {
        Some(id) if session_id_ok(id) => Bind::Session(id.to_string()),
        Some(_) => Bind::Ambiguous,
        None => Bind::OnlyDesktop,
    }
}

/// The binding of a request whose PAM process (sudo, or polkit's helper)
/// has this cgroup listing, for the account `uid` (round 8, Codex 3): for
/// polkit's helper, the session of the agent that connected it, read
/// through `cgroup_of` (the agent's pid is systemd's, from the helper's
/// instance name), and ambiguous for another account's agent or one that
/// cannot be read; for anything else, `bind_of`.
pub fn bind_for(
    cgroup: &str,
    signs: HelperSigns<'_>,
    uid: u32,
    cgroup_of: &dyn Fn(u32) -> Option<String>,
) -> Bind {
    match polkit_instance(cgroup, signs) {
        Some((agent, agent_uid)) if agent_uid == uid => match cgroup_of(agent) {
            Some(cg) if !cg.contains("polkit-agent-helper@") => {
                bind_of(&cg, HelperSigns::default(), uid)
            }
            _ => Bind::Ambiguous,
        },
        Some(_) => Bind::Ambiguous,
        None => bind_of(cgroup, signs, uid),
    }
}

/// A binding as the anchor unit's argument (`faceauth-lockstate --anchor
/// UID BIND`): `desktop` or `session:<id>`; None for an ambiguous one,
/// which is asked nothing.
pub fn bind_arg(bind: &Bind) -> Option<String> {
    match bind {
        Bind::OnlyDesktop => Some("desktop".into()),
        Bind::Session(id) if session_id_ok(id) => Some(format!("session:{}", id)),
        _ => None,
    }
}

/// The binding an argument names (`bind_arg`'s), or None.
pub fn bind_from_arg(arg: &str) -> Option<Bind> {
    if arg == "desktop" {
        return Some(Bind::OnlyDesktop);
    }
    let id = arg.strip_prefix("session:")?;
    session_id_ok(id).then(|| Bind::Session(id.to_string()))
}

/// The bus name of the compositor holding the graphical session `bind`
/// names for `uid`: its logind record's `CONTROLLER=` (round 7, A). logind
/// writes it when a process takes control of the session; same-user code
/// cannot take control from a live compositor (`TakeControl` without force
/// is refused while one holds it, and force is root's), but it can take
/// control of a session nobody controls and retype it graphical (systemd
/// v262 src/login/logind-session-dbus.c, `method_take_control` and
/// `method_set_type`), which is also how Hyprland started from a text
/// console makes its own session graphical. So the answer is given only
/// when the uid has exactly one controlled graphical session, greeters and
/// closing sessions aside, and the binding names it (round 8, Opus M3):
/// a request from a session with no compositor (a text console) and one
/// from the user manager name the one desktop; a second controlled
/// graphical session, made by a user or not, leaves nothing to answer
/// about. None, too, for another user's session, one with no record, or a
/// name that is not a unique bus name (`:` and digits and dots).
pub fn controller_of(root: &Path, uid: u32, bind: &Bind) -> Option<String> {
    controlled_desktop(root, uid, bind).map(|(_, controller)| controller)
}

/// The id of the session `controller_of` answers about for `uid` and
/// `bind`: the one controlled desktop the anchor asks, resolved now (fix
/// round 10, Opus N1 and Codex 4: the key's priority is pinned to it).
pub fn controlled_session_of(root: &Path, uid: u32, bind: &Bind) -> Option<String> {
    controlled_desktop(root, uid, bind).map(|(id, _)| id)
}

/// Whether logind's record under `root` for session `id` is `uid`'s and
/// in the foreground of its seat: `ACTIVE=1`, which logind writes from
/// `session_is_active` (systemd v262 src/login/logind-session.c,
/// `session_save`: a session is active when it is its seat's active
/// session, or has no seat), and not closing. A record that is gone, or
/// cannot be read, is not.
pub fn session_in_front(root: &Path, uid: u32, id: &str) -> bool {
    if !session_id_ok(id) {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(root.join("sessions").join(id)) else {
        return false;
    };
    let want = format!("UID={}", uid);
    text.lines().any(|l| l == want)
        && text.lines().any(|l| l == "ACTIVE=1")
        && !text.lines().any(|l| l == "STATE=closing")
}

/// Where session `id` of `uid`'s stands in logind's record under `root`
/// (fix round 12, Opus N1): `Some(true)` in the foreground of its seat
/// (`ACTIVE=1` and a `SEAT=`, not closing), `Some(false)` for a session
/// with no seat, which logind writes as ACTIVE=1 whatever happens on any
/// seat (src/login/logind-session.c, `session_is_active`), so it is never
/// in front by itself; None when it is the uid's but not active, or gone.
pub fn session_on_seat_in_front(root: &Path, uid: u32, id: &str) -> Option<bool> {
    if !session_in_front(root, uid, id) {
        return None;
    }
    let text = std::fs::read_to_string(root.join("sessions").join(id)).ok()?;
    Some(
        text.lines()
            .any(|l| l.strip_prefix("SEAT=").is_some_and(|s| !s.is_empty())),
    )
}

/// `controller_of`'s answer with the session it belongs to.
fn controlled_desktop(root: &Path, uid: u32, bind: &Bind) -> Option<(String, String)> {
    let want = format!("UID={}", uid);
    let named = match bind {
        Bind::Ambiguous => return None,
        Bind::Session(id) => {
            if !session_id_ok(id) {
                return None;
            }
            let text = std::fs::read_to_string(root.join("sessions").join(id)).ok()?;
            if !text.lines().any(|l| l == want) {
                return None;
            }
            // A text console, or a greeter, has no compositor of its own:
            // its request asks about the user's one desktop.
            (record_is_graphical(&text) && !record_is_greeter(&text)).then(|| id.clone())
        }
        Bind::OnlyDesktop => None,
    };
    let mut found = Vec::new();
    for entry in std::fs::read_dir(root.join("sessions")).ok()?.flatten() {
        let name = entry.file_name();
        let Some(id) = name.to_str().filter(|n| session_id_ok(n)) else {
            continue;
        };
        let Ok(text) = std::fs::read_to_string(entry.path()) else {
            continue;
        };
        let counts = text.lines().any(|l| l == want)
            && record_is_graphical(&text)
            && !record_is_greeter(&text)
            && !text.lines().any(|l| l == "STATE=closing");
        if !counts {
            continue;
        }
        if let Some(c) = text.lines().find_map(|l| l.strip_prefix("CONTROLLER=")) {
            found.push((id.to_string(), c.to_string()));
        }
    }
    let [(id, name)] = found.as_slice() else {
        return None;
    };
    if named.as_ref().is_some_and(|n| n != id) {
        return None;
    }
    let unique = name.len() > 1
        && name.len() <= 64
        && name.starts_with(':')
        && name[1..].bytes().all(|b| b.is_ascii_digit() || b == b'.');
    unique.then(|| (id.clone(), name.clone()))
}

/// The pid in `busctl call … GetConnectionUnixProcessID`'s answer
/// (`u <pid>` and a newline, exactly); None for anything else. The answer
/// is the system bus's, root's.
pub fn parse_bus_pid(out: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(out).ok()?;
    let digits = text.strip_prefix("u ")?.strip_suffix('\n')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u32>().ok().filter(|p| *p > 0)
}

/// The most directory entries a look inspects under `hypr/` (round 8,
/// Codex 4): a directory full of junk costs a bounded walk.
pub const MAX_ENTRIES: usize = 64;

/// The most connections a look makes (round 8, Opus L5). Only connects
/// that succeed count: a socket left by a crashed session refuses at once
/// and costs nothing, so stale directories never hide the live one.
pub const MAX_CONNECTS: usize = 8;

/// One candidate socket: an `O_PATH` descriptor of the very inode checked
/// to be a socket the user owns, connected through /proc/self/fd so no
/// path is looked up again.
#[derive(Debug)]
pub struct Candidate {
    fd: std::os::fd::OwnedFd,
}

impl Candidate {
    /// The path that reaches this descriptor's inode and nothing else.
    fn proc_path(&self) -> std::path::PathBuf {
        use std::os::fd::AsRawFd;
        std::path::PathBuf::from(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))
    }
}

/// One entry `name` of the directory `dir` (a single path component),
/// opened with `openat(2)` and `flags`, never following a symlink there
/// (`O_NOFOLLOW`): a symlink opened with `O_PATH` is the link itself, which
/// `O_DIRECTORY` refuses and a caller's file type check rejects.
///
/// Not `openat2(2)` with `RESOLVE_*` (live test 1, 2026-10-13): systemd
/// blocks `openat2` with ENOSYS in every unit with `RestrictSUIDSGID=`,
/// which `DynamicUser=` implies, so in the anchor's unit it never opens
/// anything (v262 src/core/unit.c, `unit_patch_contexts`;
/// src/shared/seccomp-util.c, `seccomp_restrict_suid_sgid`, which says to
/// use `openat` instead). One component at a time with `O_NOFOLLOW`, and
/// the mount checked at each step (`entry_on_mount`), keeps what the
/// resolve flags kept.
fn open_entry(
    dir: std::os::fd::RawFd,
    name: &str,
    flags: libc::c_int,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    let c = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: a valid C string and a directory descriptor for the call.
    let fd = unsafe { libc::openat(dir, c.as_ptr(), flags | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a new descriptor nothing else owns.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// The id of the mount the descriptor `fd` is on (`statx`, `STATX_MNT_ID`),
/// or an error when the kernel does not say. `AT_STATX_DONT_SYNC`: the
/// mount id is the VFS's own, and a FUSE server mounted where the walk
/// looks is never asked for attributes, so it cannot hold the look or
/// `faceauth doctor` (round 16, Opus N1).
fn mount_id(fd: std::os::fd::RawFd) -> std::io::Result<u64> {
    // SAFETY: an all-zero statx is a valid out-parameter.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    // SAFETY: a valid descriptor, an empty path with AT_EMPTY_PATH, and an
    // out-parameter of the right type.
    let rc = unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_DONT_SYNC,
            libc::STATX_MNT_ID,
            &mut stx,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if stx.stx_mask & libc::STATX_MNT_ID == 0 {
        return Err(std::io::Error::from_raw_os_error(libc::ENOSYS));
    }
    Ok(stx.stx_mnt_id)
}

/// `open_entry`, and only when the entry is on the mount `mount`: no mount
/// crossed below the runtime directory, bind mounts included, as
/// `RESOLVE_NO_XDEV` kept (round 8, Opus L2). EXDEV for an entry on
/// another.
fn entry_on_mount(
    dir: std::os::fd::RawFd,
    name: &str,
    flags: libc::c_int,
    mount: u64,
) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::AsRawFd;
    let fd = open_entry(dir, name, flags)?;
    if mount_id(fd.as_raw_fd())? != mount {
        return Err(std::io::Error::from_raw_os_error(libc::EXDEV));
    }
    Ok(fd)
}

/// Whether `name` in the directory `dir` is still the directory `opened`:
/// the same inode, on the same device. A walk one component at a time
/// holds each directory by its descriptor, and one moved away after it was
/// opened is still reachable through it; asked once the entry below it is
/// open, this gives what a resolution beneath `dir` gave, an entry that was
/// there at that moment (round 16, Codex). A move cannot leave the mount
/// (rename is refused across mounts), and the runtime directory is a mount
/// of its own (logind mounts a tmpfs at /run/user/UID).
fn still_entry(dir: std::os::fd::RawFd, name: &str, opened: std::os::fd::RawFd) -> bool {
    use std::os::fd::AsRawFd;
    let Ok(now) = open_entry(dir, name, libc::O_PATH | libc::O_DIRECTORY) else {
        return false;
    };
    let id = |fd: std::os::fd::RawFd| {
        // SAFETY: an all-zero stat is a valid out-parameter.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid descriptor and out-parameter.
        (unsafe { libc::fstat(fd, &mut st) } == 0).then_some((st.st_dev, st.st_ino))
    };
    let (a, b) = (id(now.as_raw_fd()), id(opened));
    a.is_some() && a == b
}

/// The directory at the absolute `path`, opened one component at a time
/// from `/`, with no symlink followed anywhere along it (as
/// `RESOLVE_NO_SYMLINKS` kept); mounts on the way are crossed, since the
/// runtime directory is a mount of its own.
fn open_dir_nofollow(path: &Path) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::path::Component;
    let mut parts = path.components();
    if parts.next() != Some(Component::RootDir) {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    // SAFETY: a constant C string; the result is checked and owned below.
    let fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a new descriptor nothing else owns.
    let mut dir = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    for part in parts {
        let Component::Normal(name) = part else {
            return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
        };
        let name = name
            .to_str()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        dir = open_entry(dir.as_raw_fd(), name, libc::O_PATH | libc::O_DIRECTORY)?;
    }
    Ok(dir)
}

/// Hyprland's request sockets under a runtime directory
/// (`<runtime>/hypr/<signature>/.socket.sock`, the signature letters,
/// digits and `_`), each opened race-free (round 8): from the runtime
/// directory one component at a time, no symlink followed and no mount
/// crossed anywhere below it (`entry_on_mount`), an `O_PATH` descriptor
/// checked with fstat to be a socket the account `uid` owns. At most
/// `MAX_ENTRIES` entries are inspected, and the walk stops at `deadline`.
/// An error when the directory itself cannot be opened, so a caller can
/// tell a sandbox that hides it from no compositor.
pub fn compositor_sockets(
    runtime: &Path,
    uid: u32,
    deadline: std::time::Instant,
) -> std::io::Result<Vec<Candidate>> {
    use std::os::fd::AsRawFd;
    let root = open_dir_nofollow(runtime)?;
    let mount = mount_id(root.as_raw_fd())?;
    let hypr = entry_on_mount(
        root.as_raw_fd(),
        "hypr",
        libc::O_PATH | libc::O_DIRECTORY,
        mount,
    )?;
    let listing = std::fs::read_dir(format!("/proc/self/fd/{}", hypr.as_raw_fd()))?;
    let mut out = Vec::new();
    for entry in listing.take(MAX_ENTRIES) {
        if std::time::Instant::now() >= deadline {
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|n| {
            !n.is_empty()
                && n.len() <= 128
                && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        }) else {
            continue;
        };
        let Ok(instance) = entry_on_mount(
            hypr.as_raw_fd(),
            name,
            libc::O_PATH | libc::O_DIRECTORY,
            mount,
        ) else {
            continue;
        };
        let Ok(fd) = entry_on_mount(instance.as_raw_fd(), ".socket.sock", libc::O_PATH, mount)
        else {
            continue;
        };
        // Both directories still where the walk found them: `hypr` under
        // the runtime directory too (round 16b, Codex 4).
        if !still_entry(hypr.as_raw_fd(), name, instance.as_raw_fd())
            || !still_entry(root.as_raw_fd(), "hypr", hypr.as_raw_fd())
        {
            continue;
        }
        // SAFETY: an all-zero stat is a valid out-parameter.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: a valid descriptor and out-parameter.
        let ok = unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } == 0
            && st.st_mode & libc::S_IFMT == libc::S_IFSOCK
            && st.st_uid == uid;
        if ok {
            out.push(Candidate { fd });
        }
    }
    Ok(out)
}

/// The `sockaddr_un` for a path, and its length; None for a path too long.
pub fn sockaddr(path: &Path) -> Option<(libc::sockaddr_un, libc::socklen_t)> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: an all-zero sockaddr_un is a valid value.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return None;
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (d, s) in addr.sun_path.iter_mut().zip(bytes) {
        *d = *s as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
    Some((addr, len as libc::socklen_t))
}

/// Connect to a Unix socket without blocking: a listener whose backlog is
/// full answers EAGAIN at once rather than holding the caller. The stream
/// comes back blocking, for the reader it is handed to.
pub fn connect_nonblocking(path: &Path) -> std::io::Result<std::os::unix::net::UnixStream> {
    use std::os::fd::{FromRawFd, OwnedFd};
    let Some((addr, len)) = sockaddr(path) else {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    };
    // SAFETY: a plain socket call; the result is checked and owned below.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: fd is a new descriptor nothing else owns.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    // SAFETY: a valid socket and a sockaddr_un of the length given.
    let rc = unsafe { libc::connect(fd, (&addr as *const libc::sockaddr_un).cast(), len) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stream = std::os::unix::net::UnixStream::from(owned);
    stream.set_nonblocking(false)?;
    Ok(stream)
}

/// The pid of the process that listens on the far end of `stream`
/// (SO_PEERCRED: the listener's credentials as they were at its
/// `listen`).
pub fn peer_pid(stream: &std::os::unix::net::UnixStream) -> Option<u32> {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: a valid socket, and an out-parameter of the size given.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (rc == 0 && cred.pid > 0).then_some(cred.pid as u32)
}

/// A connection to the one socket among `sockets` whose listener is the
/// process `pid` (the compositor logind names), or None. Each is connected
/// through its descriptor without blocking, none past `deadline`, and at
/// most `MAX_CONNECTS` connections are made; the others are closed without
/// a word.
pub fn compositor_stream(
    sockets: &[Candidate],
    pid: u32,
    deadline: std::time::Instant,
) -> Option<std::os::unix::net::UnixStream> {
    let mut hits = Vec::new();
    let mut made = 0;
    for c in sockets {
        if std::time::Instant::now() >= deadline || made >= MAX_CONNECTS {
            break;
        }
        if let Ok(s) = connect_nonblocking(&c.proc_path()) {
            made += 1;
            if peer_pid(&s) == Some(pid) {
                hits.push(s);
            }
        }
    }
    if std::time::Instant::now() >= deadline {
        return None;
    }
    match hits.len() {
        1 => hits.pop(),
        _ => None,
    }
}

/// Run `f` on a thread of its own and wait for it until `deadline` (round
/// 8, Codex 4): a file system call that never returns (a FUSE mount in the
/// user's runtime directory) costs the deadline, not the caller. None past
/// it, or when no thread could start; the thread is left to finish.
pub fn guarded<T: Send + 'static>(
    deadline: std::time::Instant,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("faceauth-look".into())
        .spawn(move || {
            let _ = tx.send(f());
        })
        .ok()?;
    rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
        .ok()
}

/// Ask the kernel for the writer's credentials with every read on
/// `stream` (SO_PASSCRED). Set before the request goes out, so every
/// buffer of the reply carries its writer (round 8, Codex 1).
pub fn set_passcred(stream: &std::os::unix::net::UnixStream) -> bool {
    use std::os::fd::AsRawFd;
    let on: libc::c_int = 1;
    // SAFETY: a valid socket and an int option of the size given.
    unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&on as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) == 0
    }
}

/// Everything on `stream` up to its end, within `limit` and at most `max`
/// bytes, taken only when every read's SCM_CREDENTIALS name `pid` as the
/// writer (round 8, Codex 1). Linux attaches the writing task's
/// thread-group pid to each buffer when the receiver has SO_PASSCRED set
/// (v7.2 net/unix/af_unix.c, `unix_maybe_add_creds`); a sender can claim
/// another pid only with CAP_SYS_ADMIN over its pid namespace
/// (net/core/scm.c, `scm_check_creds`), and a stream read never joins
/// buffers from different writers (`unix_stream_read_generic`: "Never
/// glue messages from different writers"). So a process holding a stolen
/// copy of the compositor's socket writes as itself, and is refused. None
/// for a read with no credentials, another writer, a truncated control
/// message, too much, or the deadline.
pub fn recv_from(
    stream: &std::os::unix::net::UnixStream,
    pid: u32,
    limit: Duration,
    max: usize,
) -> Option<Vec<u8>> {
    use std::os::fd::AsRawFd;
    let by = std::time::Instant::now() + limit;
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::ucred>() as u32) } as usize;
    let mut control = vec![0u8; space];
    loop {
        let rest = by.saturating_duration_since(std::time::Instant::now());
        if rest.is_zero() || stream.set_read_timeout(Some(rest)).is_err() {
            return None;
        }
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        // SAFETY: an all-zero msghdr is valid; its pointers are set below.
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() as _;
        // SAFETY: a valid socket and a msghdr whose buffers outlive the
        // call.
        let n = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if n < 0 {
            return None;
        }
        if n == 0 {
            return Some(out);
        }
        if msg.msg_flags & libc::MSG_CTRUNC != 0 {
            return None;
        }
        let mut writer = None;
        // SAFETY: walking the control buffer the kernel filled, with the
        // libc macros, within msg_controllen.
        unsafe {
            let mut cm = libc::CMSG_FIRSTHDR(&msg);
            while !cm.is_null() {
                if (*cm).cmsg_level == libc::SOL_SOCKET && (*cm).cmsg_type == libc::SCM_CREDENTIALS
                {
                    let cred: libc::ucred = std::ptr::read_unaligned(libc::CMSG_DATA(cm).cast());
                    writer = Some(cred.pid);
                }
                cm = libc::CMSG_NXTHDR(&msg, cm);
            }
        }
        if writer != Some(pid as libc::pid_t) || out.len() + n as usize > max {
            return None;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
}

/// What the anchored look found.
#[derive(Debug, PartialEq)]
pub enum Anchored {
    /// The compositor logind names said this, or no answer.
    Answer(LockState),
    /// The user's runtime directory cannot be seen from here (a sandbox
    /// that hides it).
    Hidden,
}

/// Why the anchored look gave no answer (live test 1, 2026-10-13: every
/// look in the anchor's unit went unanswered, and the daemon's log said
/// only that the lock state read unknown). The helper writes it after its
/// no-answer byte (`Why::bytes`), and the daemon logs it
/// (`consent::anchor::why_of`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// Run as root, which the helper refuses.
    Root,
    /// Arguments the helper does not take.
    Usage,
    /// Its ambient capabilities did not clear.
    Ambient,
    /// The user's runtime directory cannot be seen from here.
    Hidden,
    /// A look into the runtime directory outlasted the deadline.
    Stalled,
    /// logind names no one controlled desktop for the binding.
    NoDesktop,
    /// The system bus named no process for the controller.
    Bus,
    /// The deadline passed.
    Deadline,
    /// Hyprland's sockets could not be listed: the errno.
    Sockets(i32),
    /// No socket, or more than one, has the controller as its listener.
    NoSocket,
    /// SO_PASSCRED could not be set on the connection.
    Passcred,
    /// The capability did not drop.
    Caps,
    /// The request could not be sent.
    Send,
    /// No reply came, wholly from the compositor, in time.
    Reply,
    /// The reply did not read as locked or unlocked.
    Unreadable,
}

impl Why {
    /// The step and its errno (0 for a step that has none), as the helper
    /// writes them after its no-answer byte.
    pub fn bytes(self) -> [u8; 2] {
        let step = match self {
            Why::Root => 1,
            Why::Usage => 2,
            Why::Ambient => 3,
            Why::Hidden => 4,
            Why::Stalled => 5,
            Why::NoDesktop => 6,
            Why::Bus => 7,
            Why::Deadline => 8,
            Why::Sockets(_) => 9,
            Why::NoSocket => 10,
            Why::Passcred => 11,
            Why::Caps => 12,
            Why::Send => 13,
            Why::Reply => 14,
            Why::Unreadable => 15,
        };
        let errno = match self {
            Why::Sockets(e) => u8::try_from(e).unwrap_or(0),
            _ => 0,
        };
        [step, errno]
    }

    /// `bytes` read back; None for a step this build does not know.
    pub fn from_bytes(b: [u8; 2]) -> Option<Why> {
        Some(match b[0] {
            1 => Why::Root,
            2 => Why::Usage,
            3 => Why::Ambient,
            4 => Why::Hidden,
            5 => Why::Stalled,
            6 => Why::NoDesktop,
            7 => Why::Bus,
            8 => Why::Deadline,
            9 => Why::Sockets(i32::from(b[1])),
            10 => Why::NoSocket,
            11 => Why::Passcred,
            12 => Why::Caps,
            13 => Why::Send,
            14 => Why::Reply,
            15 => Why::Unreadable,
            _ => return None,
        })
    }
}

impl std::fmt::Display for Why {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Why::Root => write!(f, "the helper was run as root, which it refuses"),
            Why::Usage => write!(f, "the helper was given arguments it does not take"),
            Why::Ambient => write!(f, "the helper's ambient capabilities did not clear"),
            Why::Hidden => write!(
                f,
                "the user's runtime directory cannot be seen from the unit"
            ),
            Why::Stalled => write!(
                f,
                "a look into the user's runtime directory did not finish in time"
            ),
            Why::NoDesktop => write!(f, "logind names no one controlled desktop for this request"),
            Why::Bus => write!(
                f,
                "the system bus named no process for the session's controller"
            ),
            Why::Deadline => write!(f, "the look ran out of time"),
            Why::Sockets(e) => write!(
                f,
                "Hyprland's sockets could not be listed ({})",
                std::io::Error::from_raw_os_error(*e)
            ),
            Why::NoSocket => write!(
                f,
                "no socket, or more than one, has the compositor as its listener"
            ),
            Why::Passcred => write!(f, "the writer check (SO_PASSCRED) could not be set"),
            Why::Caps => write!(f, "the helper's capability did not drop"),
            Why::Send => write!(f, "the request could not be sent to the compositor"),
            Why::Reply => write!(f, "no reply came, wholly from the compositor, in time"),
            Why::Unreadable => write!(
                f,
                "the compositor's reply did not read as locked or unlocked"
            ),
        }
    }
}

/// The lock state from the compositor logind names (rounds 7 and 8): the
/// controller of the session `bind` names, resolved to a pid (`resolve`,
/// the system bus, with what is left of the deadline), and only the socket
/// under the user's runtime directory whose listener is that pid, with
/// SO_PASSCRED set, handed to `ask` with that pid, so it takes the reply
/// only from the compositor itself (round 8, Codex 1; `recv_from`), and
/// parses it without privilege. One deadline over all of it, and every
/// look into the user's runtime directory runs guarded (`guarded`). Run
/// by the daemon's anchor unit (`faceauth-lockstate --anchor`).
pub fn anchored(
    logind: &Path,
    runtime_root: &Path,
    uid: u32,
    bind: &Bind,
    deadline: std::time::Instant,
    resolve: &dyn Fn(&str, Duration) -> Option<u32>,
    ask: &dyn Fn(std::os::unix::net::UnixStream, u32, Duration) -> LockState,
) -> Anchored {
    let ask = |stream, pid, left| Ok(ask(stream, pid, left));
    match anchored_why(logind, runtime_root, uid, bind, deadline, resolve, &ask) {
        Ok(state) => Anchored::Answer(state),
        Err(Why::Hidden) => Anchored::Hidden,
        Err(_) => Anchored::Answer(LockState::Unknown),
    }
}

/// `anchored`, with why there is no answer when there is none: the step
/// that failed, or the one `ask` names.
pub fn anchored_why(
    logind: &Path,
    runtime_root: &Path,
    uid: u32,
    bind: &Bind,
    deadline: std::time::Instant,
    resolve: &dyn Fn(&str, Duration) -> Option<u32>,
    ask: &dyn Fn(std::os::unix::net::UnixStream, u32, Duration) -> Result<LockState, Why>,
) -> Result<LockState, Why> {
    let runtime = runtime_root.join(uid.to_string());
    let probe = runtime.clone();
    match guarded(deadline, move || probe.exists()) {
        Some(true) => {}
        Some(false) => return Err(Why::Hidden),
        None => return Err(Why::Stalled),
    }
    let left = || deadline.saturating_duration_since(std::time::Instant::now());
    let name = controller_of(logind, uid, bind).ok_or(Why::NoDesktop)?;
    let pid = resolve(&name, left()).ok_or(Why::Bus)?;
    if left().is_zero() {
        return Err(Why::Deadline);
    }
    let stream = guarded(deadline, move || {
        let sockets = compositor_sockets(&runtime, uid, deadline)
            .map_err(|e| Why::Sockets(e.raw_os_error().unwrap_or(0)))?;
        compositor_stream(&sockets, pid, deadline).ok_or_else(|| {
            if std::time::Instant::now() >= deadline {
                Why::Deadline
            } else {
                Why::NoSocket
            }
        })
    })
    .ok_or(Why::Stalled)??;
    if left().is_zero() {
        return Err(Why::Deadline);
    }
    if !set_passcred(&stream) {
        return Err(Why::Passcred);
    }
    ask(stream, pid, left())
}

/// The key's lease (fix round 11, Codex 2, Opus N4): one root-owned file,
/// outside the daemon's runtime directory so a restart leaves it alone,
/// on which every key check holds an exclusive `flock` from before it asks
/// the key until it exits, whoever runs it (the daemon's transient unit,
/// or the PAM module while faceauthd is down). One key may serve several
/// accounts and several processes, and nothing tells their checks apart
/// by device, so two must never run at once. The package's tmpfiles entry
/// makes it at boot (`f /run/faceauth-key.lease 0600 root root`), and the
/// module makes it when it is missing; a `flock` needs no write access, so
/// the check's read-only unit takes it too.
pub const KEY_LEASE: &str = "/run/faceauth-key.lease";

/// The key's lease at `path`, waiting up to `wait` for another holder to
/// let go: the open file, whose descriptor holds the lock until it is
/// closed, at the latest when the process exits. None when it is held
/// elsewhere all that time, missing, not a regular file, not owned by this
/// process's user, or open to anyone else (a file others could open, they
/// could hold, and keep every check off the key).
pub fn take_key_lease(path: &Path, wait: Duration) -> Option<std::fs::File> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let md = file.metadata().ok()?;
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    if !md.file_type().is_file() || md.uid() != me || md.mode() & 0o077 != 0 {
        return None;
    }
    let by = std::time::Instant::now() + wait;
    loop {
        // SAFETY: flock on a descriptor this function owns.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Some(file);
        }
        if std::time::Instant::now() >= by {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Bytes as lowercase hex: the stock check's conversation lines carry the
/// messages and answers this way, so nothing in them can break a line.
pub fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// `hex_encode`'s bytes back, or None for anything that is not its output.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.as_bytes();
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    s.chunks(2)
        .map(|p| Some(digit(p[0])? << 4 | digit(p[1])?))
        .collect()
}

/// pam_u2f's defaults file, which it reads for every pam_u2f line.
pub const U2F_CONF: &str = "/etc/security/pam_u2f.conf";

/// The largest `U2F_CONF` pam_u2f reads.
pub const U2F_CONF_MAX: usize = 4096;

/// The words of `U2F_CONF` the daemon mirrors, each as the file sets it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct U2fWords {
    /// `pinverification=`.
    pub pin: Option<bool>,
    /// `userverification=`.
    pub uv: Option<bool>,
    /// `userpresence=`.
    pub presence: Option<bool>,
}

/// pam_u2f's defaults from its file's text, read the one way the daemon and
/// the PAM module both read them (round 8, Codex 6): `pinverification=`,
/// `userverification=` and `userpresence=`, each 0 or 1, once. Any other
/// setting (a touch it does not ask for, another key file, a prompt the
/// checks cannot answer), another value, a setting twice, a file past the
/// size pam_u2f reads, or `userpresence=0` is an error, with why.
pub fn u2f_conf_words(text: &str) -> Result<U2fWords, String> {
    if text.len() > U2F_CONF_MAX {
        return Err(format!(
            "{} is over the {} bytes pam_u2f reads",
            U2F_CONF, U2F_CONF_MAX
        ));
    }
    let mut w = U2fWords::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = match line.split_once('=') {
            Some((n, v)) => (n.trim(), v.trim()),
            None => (line, ""),
        };
        let slot = match name {
            "pinverification" => &mut w.pin,
            "userverification" => &mut w.uv,
            "userpresence" => &mut w.presence,
            other => {
                return Err(format!(
                    "{} sets `{}`, which the daemon cannot mirror",
                    U2F_CONF, other
                ))
            }
        };
        if slot.is_some() {
            return Err(format!("{} sets `{}` twice", U2F_CONF, name));
        }
        *slot = Some(match value {
            "1" => true,
            "0" => false,
            _ => return Err(format!("{} sets `{}={}`", U2F_CONF, name, value)),
        });
    }
    if w.presence == Some(false) {
        return Err(format!(
            "{} sets `userpresence=0`, which lets a key approve without a touch",
            U2F_CONF
        ));
    }
    Ok(w)
}

/// A request's wait budget (round 8, Codex 1, Opus F1): the time it has
/// spent waiting on a verdict that is neither unlocked nor a positive lock,
/// summed over the whole request and never reset, so churn between
/// unknown, held and unlocked cannot start it over. The time from one look
/// to the next counts when the earlier look was such a wait. A key check
/// that ended without an answer because the verdict stopped reading
/// unlocked is owed to it (`owe`), and counts at the next look unless that
/// look is a positive lock, so a check churn keeps cutting off cannot
/// stretch the request either. Waits on a card on screen (`observe_card`)
/// are free for a while and then count (fix round 8, Opus L6). Measured
/// on any monotonic clock.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WaitBudget {
    spent: Duration,
    owed: Duration,
    /// Card waits so far, and how much of them is free.
    card: Duration,
    card_free: Duration,
    /// The last look: when, and what the time since is.
    last: Option<(Duration, Since)>,
}

/// What the time since a look is, for the budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Since {
    /// A wait on no positive lock: it counts.
    Counted,
    /// A positive lock, an unlock: free.
    Free,
    /// A card on screen: free until `card_free` in all.
    Card,
}

impl WaitBudget {
    /// Charge the time since the last look, as that look said.
    fn settle(&mut self, now: Duration) {
        let Some((at, since)) = self.last else {
            return;
        };
        let d = now.saturating_sub(at);
        match since {
            Since::Counted => self.spent += d,
            Since::Free => {}
            Since::Card => {
                let over = |c: Duration| c.saturating_sub(self.card_free);
                let before = over(self.card);
                self.card += d;
                self.spent += over(self.card) - before;
            }
        }
    }

    /// One verdict at `now`: the budget spent so far.
    pub fn observe(&mut self, v: Verdict, now: Duration) -> Duration {
        self.settle(now);
        if v == Verdict::Locked {
            self.owed = Duration::ZERO;
        } else {
            self.spent += std::mem::take(&mut self.owed);
        }
        let since = if matches!(v, Verdict::Unknown | Verdict::Held) {
            Since::Counted
        } else {
            Since::Free
        };
        self.last = Some((now, since));
        self.spent
    }

    /// A wait on a card on screen at `now`, the first `free` of such waits
    /// in all free: the budget spent so far.
    pub fn observe_card(&mut self, now: Duration, free: Duration) -> Duration {
        self.settle(now);
        self.card_free = free;
        self.owed = Duration::ZERO;
        self.last = Some((now, Since::Card));
        self.spent
    }

    /// A check of this long ended without an answer: owed to the budget.
    pub fn owe(&mut self, d: Duration) {
        self.owed += d;
    }

    /// The budget spent so far.
    pub fn spent(&self) -> Duration {
        self.spent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(compositor: LockState, desktop: Desktop) -> Facts {
        Facts {
            compositor,
            desktop,
            channel: None,
            latched: false,
            holding: false,
            saturated: false,
        }
    }

    /// R1: the verdict fails closed. Only the compositor's unlocked, or no
    /// desktop at all with nothing latched, is unlocked; a latch is held
    /// while the compositor says unlocked and unknown otherwise; a
    /// saturated daemon is never unlocked. (The module, with no channel to
    /// weigh, takes the compositor's lock, which it verified itself.)
    #[test]
    fn the_verdict_is_unlocked_only_when_it_can_show_it() {
        use Desktop as D;
        use LockState as L;
        use Verdict as V;
        for d in [D::None, D::Some, D::Unreadable] {
            assert_eq!(is_locked(&facts(L::Locked, d)), V::Locked, "{:?}", d);
            assert_eq!(is_locked(&facts(L::Unlocked, d)), V::Unlocked, "{:?}", d);
        }
        assert_eq!(
            is_locked(&facts(L::Unknown, D::None)),
            V::Unlocked,
            "a text console"
        );
        assert_eq!(is_locked(&facts(L::Unknown, D::Some)), V::Unknown);
        assert_eq!(
            is_locked(&facts(L::Unknown, D::Unreadable)),
            V::Unknown,
            "unreadable records count as a desktop"
        );
        for c in [L::Unlocked, L::Locked, L::Unknown] {
            for d in [D::None, D::Some, D::Unreadable] {
                let latched = Facts {
                    latched: true,
                    holding: true,
                    ..facts(c, d)
                };
                let want = match c {
                    L::Locked => V::Locked,
                    L::Unlocked => V::Held,
                    L::Unknown => V::Unknown,
                };
                assert_eq!(
                    is_locked(&latched),
                    want,
                    "a latch, nongraphical or not: {:?} {:?}",
                    c,
                    d
                );
                let saturated = Facts {
                    saturated: true,
                    ..facts(c, d)
                };
                assert_ne!(
                    is_locked(&saturated),
                    V::Unlocked,
                    "saturated: {:?} {:?}",
                    c,
                    d
                );
                assert_ne!(
                    is_locked(&saturated),
                    V::Held,
                    "saturation is not a bounded hold"
                );
            }
        }
    }

    /// Round 7 (B): with the lock screen's channel in the daemon's facts, a
    /// lock is positive only with the channel open and the compositor
    /// saying locked; either without the other is unknown (latched, and
    /// the password after the limit), so a channel held open by malware,
    /// or a compositor lock no lock screen of ours stands behind, never
    /// holds a request without a deadline.
    #[test]
    fn a_positive_lock_needs_the_channel_and_the_compositor() {
        use Desktop as D;
        use LockState as L;
        use Verdict as V;
        let with = |channel: bool, c: LockState, d: Desktop| {
            is_locked(&Facts {
                channel: Some(channel),
                ..facts(c, d)
            })
        };
        for d in [D::None, D::Some, D::Unreadable] {
            assert_eq!(with(true, L::Locked, d), V::Locked, "both: {:?}", d);
            assert_eq!(
                with(true, L::Unlocked, d),
                V::Unknown,
                "the channel open, the compositor unlocked: {:?}",
                d
            );
            assert_eq!(with(true, L::Unknown, d), V::Unknown);
            assert_eq!(
                with(false, L::Locked, d),
                V::Unknown,
                "the compositor locked, no channel: {:?}",
                d
            );
            let latched = is_locked(&Facts {
                channel: Some(true),
                latched: true,
                saturated: true,
                ..facts(L::Unlocked, d)
            });
            assert_eq!(
                latched,
                V::Unknown,
                "never held, never unlocked with the channel open"
            );
        }
        assert_eq!(with(false, L::Unlocked, D::Some), V::Unlocked);
        assert_eq!(
            with(false, L::Unknown, D::None),
            V::Unlocked,
            "a text console"
        );
        assert_eq!(
            is_locked(&facts(L::Locked, D::Some)),
            V::Locked,
            "the module, no channel to weigh"
        );
    }

    /// A deadline far enough off not to matter.
    fn far() -> std::time::Instant {
        std::time::Instant::now() + Duration::from_secs(5)
    }

    fn sessions(name: &str, records: &[(&str, &str)]) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("lockgate-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("sessions")).unwrap();
        for (id, text) in records {
            std::fs::write(root.join("sessions").join(id), text).unwrap();
        }
        root
    }

    /// Opus N5, Codex 4: the text-console test counts every user's
    /// graphical sessions, and a session counts as graphical by the type
    /// it was created with as well as the type its controller set since.
    #[test]
    fn every_users_graphical_session_counts_and_settype_does_not_hide_one() {
        let none = std::env::temp_dir().join(format!("lockgate-none-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&none);
        assert_eq!(
            graphical_sessions(&none),
            Desktop::None,
            "no records at all"
        );
        let root = sessions(
            "tty",
            &[
                ("3", "UID=1000\nTYPE=tty\nORIGINAL_TYPE=tty\n"),
                ("4", "UID=1000\nTYPE=unspecified\nCLASS=manager\n"),
            ],
        );
        assert_eq!(
            graphical_sessions(&root),
            Desktop::None,
            "text consoles and the manager"
        );
        std::fs::write(root.join("sessions/9"), "UID=1001\nTYPE=wayland\n").unwrap();
        assert_eq!(
            graphical_sessions(&root),
            Desktop::Some,
            "another user's desktop counts"
        );
        std::fs::write(
            root.join("sessions/9"),
            "UID=1000\nTYPE=tty\nORIGINAL_TYPE=wayland\n",
        )
        .unwrap();
        assert_eq!(
            graphical_sessions(&root),
            Desktop::Some,
            "a desktop set to tty by its controller"
        );
        std::fs::remove_file(root.join("sessions/9")).unwrap();
        std::fs::write(root.join("sessions/.#9abc"), "TYPE=wayland\n").unwrap();
        assert_eq!(
            graphical_sessions(&root),
            Desktop::None,
            "logind's temporary files are not records"
        );
        // SAFETY: getuid has no preconditions.
        if unsafe { libc::getuid() } != 0 {
            use std::os::unix::fs::PermissionsExt;
            let p = root.join("sessions/5");
            std::fs::write(&p, "TYPE=wayland\n").unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o000)).unwrap();
            std::fs::write(root.join("sessions/3"), "TYPE=tty\n").unwrap();
            assert_eq!(
                graphical_sessions(&root),
                Desktop::Unreadable,
                "a record it cannot read counts as a desktop"
            );
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Round 6, item 7: a request from a text console or a remote login is
    /// not from the desktop; one from the desktop's session, the user
    /// manager (where Omarchy's terminals run) or a system service is.
    #[test]
    fn a_text_console_or_a_remote_login_is_not_the_desktop() {
        let root = sessions(
            "origin",
            &[
                (
                    "1",
                    "UID=1000\nREMOTE=0\nTYPE=wayland\nORIGINAL_TYPE=wayland\n",
                ),
                ("3", "UID=1000\nREMOTE=0\nTYPE=tty\nORIGINAL_TYPE=tty\n"),
                ("7", "UID=1000\nREMOTE=1\nTYPE=tty\n"),
            ],
        );
        let at = |cg: &str| origin_of(cg, &root);
        assert_eq!(
            at("0::/user.slice/user-1000.slice/session-1.scope\n"),
            Origin::Desktop
        );
        assert_eq!(
            at("0::/user.slice/user-1000.slice/session-3.scope\n"),
            Origin::Elsewhere,
            "a VT"
        );
        assert_eq!(
            at("0::/user.slice/user-1000.slice/session-7.scope\n"),
            Origin::Elsewhere,
            "ssh"
        );
        assert_eq!(
            at("0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-Hyprland-xdg\\x2dterminal\\x2dexec-1.scope\n"),
            Origin::Desktop,
            "a desktop terminal"
        );
        assert_eq!(at("0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@1.service\n"), Origin::Desktop);
        assert_eq!(
            at("0::/user.slice/user-1000.slice/session-99.scope\n"),
            Origin::Desktop,
            "unreadable: may wait, never the key"
        );
        assert_eq!(
            at("0::/user.slice/user-1000.slice/session-../../x.scope\n"),
            Origin::Desktop
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Round 7 (A): logind names the genuine compositor. The user's one
    /// graphical session's `CONTROLLER=` is the bus name of the process
    /// that holds it, which same-user code cannot take from a live
    /// compositor; no such session, two of them, or a name that is not a
    /// unique bus name is no anchor.
    #[test]
    fn logind_names_the_compositor_of_the_users_one_desktop() {
        let root = sessions(
            "controller",
            &[
                (
                    "1",
                    "UID=1000\nTYPE=wayland\nORIGINAL_TYPE=wayland\nCONTROLLER=:1.35\n",
                ),
                ("2", "UID=1000\nTYPE=unspecified\nCLASS=manager\n"),
                ("4", "UID=1001\nTYPE=wayland\nCONTROLLER=:1.99\n"),
            ],
        );
        assert_eq!(
            controller_of(&root, 1000, &Bind::OnlyDesktop).as_deref(),
            Some(":1.35")
        );
        assert_eq!(
            controller_of(&root, 1001, &Bind::OnlyDesktop).as_deref(),
            Some(":1.99")
        );
        assert_eq!(
            controller_of(&root, 1002, &Bind::OnlyDesktop),
            None,
            "no desktop"
        );
        std::fs::write(
            root.join("sessions/5"),
            "UID=1000\nTYPE=x11\nCONTROLLER=:1.40\n",
        )
        .unwrap();
        assert_eq!(
            controller_of(&root, 1000, &Bind::OnlyDesktop),
            None,
            "two desktops: no one compositor"
        );
        std::fs::remove_file(root.join("sessions/5")).unwrap();
        std::fs::write(root.join("sessions/1"), "UID=1000\nTYPE=wayland\n").unwrap();
        assert_eq!(
            controller_of(&root, 1000, &Bind::OnlyDesktop),
            None,
            "no controller"
        );
        for bad in ["org.example.Name", ":1.35;x", ":", ""] {
            std::fs::write(
                root.join("sessions/1"),
                format!("UID=1000\nTYPE=wayland\nCONTROLLER={}\n", bad),
            )
            .unwrap();
            assert_eq!(
                controller_of(&root, 1000, &Bind::OnlyDesktop),
                None,
                "{:?}",
                bad
            );
        }
        let _ = std::fs::remove_dir_all(&root);
        assert_eq!(parse_bus_pid(b"u 1257\n"), Some(1257));
        for bad in [
            &b"u 1257"[..],
            b"s 1257\n",
            b"u -1\n",
            b"u 1257 7\n",
            b"u 0\n",
            b"",
            b"u \n",
        ] {
            assert_eq!(
                parse_bus_pid(bad),
                None,
                "{:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    /// Round 7 (A): the compositor's sockets under the runtime directory
    /// are found by Hyprland's layout, and only the one whose listener is
    /// the named compositor (by its SO_PEERCRED pid) is used: a fake
    /// listener or a second instance has another pid.
    #[test]
    fn only_the_named_compositors_socket_is_used() {
        use std::os::unix::net::UnixListener;
        let run = std::env::temp_dir().join(format!("lockgate-hypr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        for sig in ["aaa_1", "bbb_2"] {
            std::fs::create_dir_all(run.join("hypr").join(sig)).unwrap();
        }
        std::fs::create_dir_all(run.join("hypr").join("bad name")).unwrap();
        let mine = UnixListener::bind(run.join("hypr/aaa_1/.socket.sock")).unwrap();
        // A second listener in another process: a different pid.
        let other = std::process::Command::new("python3")
            .args([
                "-c",
                "import socket,sys,time;s=socket.socket(socket.AF_UNIX);s.bind(sys.argv[1]);s.listen(4);print('up',flush=True);time.sleep(30)",
                &run.join("hypr/bbb_2/.socket.sock").to_string_lossy(),
            ])
            .stdout(std::process::Stdio::piped())
            .spawn();
        let Ok(mut other) = other else {
            eprintln!("no python3: the second listener is skipped");
            return;
        };
        let mut up = String::new();
        let _ = std::io::BufRead::read_line(
            &mut std::io::BufReader::new(other.stdout.as_mut().unwrap()),
            &mut up,
        );
        let me = std::process::id();
        // SAFETY: getuid has no preconditions.
        let sockets = compositor_sockets(&run, unsafe { libc::getuid() }, far()).unwrap();
        assert_eq!(sockets.len(), 2, "{:?}", sockets);
        let soon = || std::time::Instant::now() + Duration::from_secs(2);
        let pick = |pid: u32| compositor_stream(&sockets, pid, soon()).map(|_| ());
        assert!(pick(me).is_some(), "this process's listener");
        assert!(pick(other.id()).is_some(), "the other process's");
        assert!(pick(1).is_none(), "nobody else's");
        let s = compositor_stream(&sockets, other.id(), soon()).unwrap();
        assert_eq!(peer_pid(&s), Some(other.id()));
        let _ = other.kill();
        let _ = other.wait();
        drop(mine);
        assert!(
            compositor_sockets(&run.join("gone"), 0, far()).is_err(),
            "no runtime directory"
        );
        let _ = std::fs::remove_dir_all(&run);
    }

    /// Round 8 (Codex 1, Opus F1): a latch reads as held, the bounded wait
    /// after an unlock, only while its hold clock runs; a latch with no
    /// clock running (a dropped channel, a key unlock asked, a lock or a
    /// doubt not yet followed by an unlock) is unknown, which the password
    /// deadline bounds, whatever the compositor says.
    #[test]
    fn a_latch_without_a_running_clock_is_unknown() {
        use Desktop as D;
        use LockState as L;
        use Verdict as V;
        let latch = |holding: bool, c: LockState| {
            is_locked(&Facts {
                latched: true,
                holding,
                ..facts(c, D::Some)
            })
        };
        assert_eq!(latch(true, L::Unlocked), V::Held);
        assert_eq!(latch(false, L::Unlocked), V::Unknown, "a drop-only latch");
        assert_eq!(latch(true, L::Unknown), V::Unknown);
        assert_eq!(
            latch(false, L::Locked),
            V::Locked,
            "the module's lock, no channel to weigh"
        );
    }

    /// Round 8 (Opus Low): a greeter is not a desktop: with only SDDM's
    /// greeter up, the text-console rule still offers the key.
    #[test]
    fn a_greeter_is_not_a_desktop() {
        let root = sessions(
            "greeter",
            &[("c1", "UID=964\nTYPE=wayland\nCLASS=greeter\n")],
        );
        assert_eq!(graphical_sessions(&root), Desktop::None);
        std::fs::write(
            root.join("sessions/2"),
            "UID=1000\nTYPE=wayland\nCLASS=user\n",
        )
        .unwrap();
        assert_eq!(graphical_sessions(&root), Desktop::Some);
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Round 8 (Codex 3, Opus Low): the lock question is bound to the
    /// session the request came from: a graphical session's own scope, or,
    /// from the user manager (desktop apps, the polkit agent), the user's
    /// only desktop. Records without a controller (one left closing after a
    /// relogin) and greeters are skipped; two desktops with nothing to pick
    /// between them, or polkit's helper connected by another account's
    /// agent, are ambiguous and get no answer.
    #[test]
    fn the_lock_question_is_bound_to_the_requesting_session() {
        let root = sessions(
            "bind",
            &[
                ("1", "UID=1000\nTYPE=wayland\nCONTROLLER=:1.35\n"),
                ("7", "UID=1000\nTYPE=wayland\nSTATE=closing\n"),
                (
                    "c1",
                    "UID=964\nTYPE=wayland\nCLASS=greeter\nCONTROLLER=:1.2\n",
                ),
            ],
        );
        assert_eq!(
            controller_of(&root, 1000, &Bind::OnlyDesktop).as_deref(),
            Some(":1.35"),
            "the closing record has no controller"
        );
        assert_eq!(
            controller_of(&root, 964, &Bind::OnlyDesktop),
            None,
            "a greeter"
        );
        std::fs::write(
            root.join("sessions/3"),
            "UID=1000\nTYPE=wayland\nCONTROLLER=:1.77\n",
        )
        .unwrap();
        assert_eq!(
            controller_of(&root, 1000, &Bind::OnlyDesktop),
            None,
            "two desktops"
        );
        // Round 8 (fix round 8, item 6): two controlled desktops answer
        // nothing, whichever one the request comes from.
        assert_eq!(
            controller_of(&root, 1000, &Bind::Session("3".into())),
            None,
            "the requester's own, beside another"
        );
        assert_eq!(controller_of(&root, 1000, &Bind::Session("1".into())), None);
        assert_eq!(
            controller_of(&root, 1001, &Bind::Session("3".into())),
            None,
            "another user's session"
        );
        assert_eq!(controller_of(&root, 1000, &Bind::Ambiguous), None);
        // A text console's own session has no compositor: its request asks
        // about the user's only desktop, as before.
        std::fs::write(root.join("sessions/9"), "UID=1000\nTYPE=tty\n").unwrap();
        assert_eq!(
            controller_of(&root, 1000, &Bind::Session("9".into())),
            None,
            "two desktops still"
        );
        std::fs::remove_file(root.join("sessions/3")).unwrap();
        assert_eq!(
            controller_of(&root, 1000, &Bind::Session("9".into())).as_deref(),
            Some(":1.35"),
            "the one desktop"
        );
        assert_eq!(
            controller_of(&root, 1000, &Bind::Session("1".into())).as_deref(),
            Some(":1.35"),
            "the requester's own, alone"
        );
        assert_eq!(
            controller_of(&root, 1000, &Bind::Session("4".into())),
            None,
            "a session with no record"
        );
        let _ = std::fs::remove_dir_all(&root);
        let helper = |uid: u32| {
            format!("0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@1-4114-1410496_1411230-{}.service\n", uid)
        };
        let helper_signs = HelperSigns {
            ruid: Some(0),
            comm: Some(POLKIT_HELPER_COMM),
        };
        assert_eq!(
            bind_of(&helper(1000), helper_signs, 1000),
            Bind::OnlyDesktop,
            "polkit's agent is the user's"
        );
        assert_eq!(
            bind_of(&helper(1001), helper_signs, 1000),
            Bind::Ambiguous,
            "another account's agent"
        );
        assert_eq!(
            bind_of(
                "0::/user.slice/user-1000.slice/session-3.scope\n",
                HelperSigns::default(),
                1000
            ),
            Bind::Session("3".into())
        );
        assert_eq!(
            bind_of(
                "0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-x.scope\n",
                HelperSigns::default(),
                1000
            ),
            Bind::OnlyDesktop
        );
        // The request's binding as the daemon and the module read it: for
        // polkit's helper, the agent's own cgroup.
        let agent = |p: u32| {
            (p == 1410496).then(|| "0::/user.slice/user-1000.slice/session-2.scope\n".to_string())
        };
        let gone = |_: u32| None;
        assert_eq!(
            bind_for(&helper(1000), helper_signs, 1000, &agent),
            Bind::Session("2".into()),
            "the agent's session"
        );
        assert_eq!(
            bind_for(&helper(1000), helper_signs, 1000, &gone),
            Bind::Ambiguous,
            "the agent gone"
        );
        assert_eq!(
            bind_for(&helper(1001), helper_signs, 1000, &agent),
            Bind::Ambiguous,
            "another account's agent"
        );
        assert_eq!(
            bind_for(
                "0::/user.slice/user-1000.slice/session-3.scope\n",
                HelperSigns::default(),
                1000,
                &gone
            ),
            Bind::Session("3".into())
        );
        assert_eq!(
            bind_for("", HelperSigns::default(), 1000, &gone),
            Bind::Ambiguous,
            "no cgroup to read"
        );
        // The binding as the anchor unit's argument, and back.
        assert_eq!(bind_arg(&Bind::OnlyDesktop).as_deref(), Some("desktop"));
        assert_eq!(
            bind_arg(&Bind::Session("3".into())).as_deref(),
            Some("session:3")
        );
        assert_eq!(bind_arg(&Bind::Ambiguous), None, "nothing to ask about");
        assert_eq!(bind_from_arg("session:3"), Some(Bind::Session("3".into())));
        assert_eq!(bind_from_arg("desktop"), Some(Bind::OnlyDesktop));
        assert_eq!(bind_from_arg("session:../x"), None);
        assert_eq!(bind_from_arg("session:"), None);
        assert_eq!(polkit_instance_uid(&helper(1000), helper_signs), Some(1000));
        assert_eq!(
            polkit_instance(&helper(1000), helper_signs),
            Some((1410496, 1000)),
            "the agent's pid and uid"
        );
        assert_eq!(
            polkit_instance_id(&helper(1000), helper_signs),
            Some(1411230),
            "its pidfs inode"
        );
        assert_eq!(
            polkit_instance("0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@2-77-3120-1000.service\n", helper_signs),
            Some((3120, 1000)),
            "without pidfd ids"
        );
        assert_eq!(
            polkit_instance_uid(
                "0::/system.slice/polkit-agent-helper@7-4114-unknown.service\n",
                helper_signs
            ),
            None
        );
        // Fix round 13 (Codex 5): only in the system manager's own helper
        // slice; and (fix round 14) only for root with polkit's helper's
        // comm, never by its executable, which faceauthd cannot read.
        let forged = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/polkit-agent-helper@1-4114-1410496_1411230-1000.service\n";
        assert_eq!(
            polkit_instance(forged, helper_signs),
            None,
            "a user's own unit"
        );
        assert_eq!(
            bind_for(forged, helper_signs, 1000, &agent),
            Bind::Ambiguous,
            "named as a helper, not believed: no binding"
        );
        let nested = "0::/user.slice/user-1000.slice/user@1000.service/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@1-4114-1410496_1411230-1000.service\n";
        assert_eq!(
            polkit_instance(nested, helper_signs),
            None,
            "the slice's name inside a user's tree"
        );
        assert_eq!(
            polkit_instance(
                &helper(1000),
                HelperSigns {
                    ruid: Some(0),
                    comm: Some("sudo")
                }
            ),
            None,
            "not polkit's helper by its comm"
        );
        assert_eq!(
            polkit_instance(
                &helper(1000),
                HelperSigns {
                    ruid: Some(1000),
                    comm: Some(POLKIT_HELPER_COMM)
                }
            ),
            None,
            "not root"
        );
        assert_eq!(
            polkit_instance(&helper(1000), HelperSigns::default()),
            None,
            "nothing read"
        );
        assert_eq!(
            polkit_instance(&format!("{}/x", helper(1000).trim_end()), helper_signs),
            None,
            "a cgroup below the unit's"
        );
    }

    /// Round 8 (Codex 2, Opus F2): the anchor never blocks. Only a socket
    /// the user owns, not a symlink, is a candidate, a bounded number of
    /// them; each is connected without blocking, so a listener whose
    /// backlog is full is passed over at once; and the whole look has one
    /// deadline.
    #[test]
    fn the_anchor_never_blocks() {
        use std::os::fd::FromRawFd;
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        let base = std::env::temp_dir().join(format!("lockgate-nb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let run = base.join(me.to_string());
        std::fs::create_dir_all(run.join("hypr/full_1")).unwrap();
        std::fs::create_dir_all(run.join("hypr/link_2")).unwrap();
        // A listener with no room in its backlog, never accepting.
        let path = run.join("hypr/full_1/.socket.sock");
        // SAFETY: a plain socket call; the fd is owned below.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
        assert!(fd >= 0);
        // SAFETY: fd is a new descriptor nothing else owns.
        let listener = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        let addr = sockaddr(&path).unwrap();
        // SAFETY: a valid socket and address for the call.
        unsafe {
            assert_eq!(
                libc::bind(fd, (&addr.0 as *const libc::sockaddr_un).cast(), addr.1),
                0
            );
            assert_eq!(libc::listen(fd, 0), 0);
        }
        let _filled: Vec<_> = (0..4)
            .filter_map(|_| connect_nonblocking(&path).ok())
            .collect();
        std::os::unix::fs::symlink(&path, run.join("hypr/link_2/.socket.sock")).unwrap();
        let sockets = compositor_sockets(&run, me, far()).unwrap();
        assert_eq!(
            sockets.len(),
            1,
            "the symlink is no candidate: {:?}",
            sockets
        );
        assert!(
            compositor_sockets(&run, me + 1, far()).unwrap().is_empty(),
            "a socket the user does not own"
        );
        let t0 = std::time::Instant::now();
        let got = compositor_stream(&sockets, std::process::id(), t0 + Duration::from_secs(1));
        assert!(got.is_none(), "a full backlog is passed over");
        assert!(
            t0.elapsed() < Duration::from_millis(200),
            "at once: {:?}",
            t0.elapsed()
        );
        // One deadline over the whole look, a slow resolver included, and a
        // resolver naming the full listener's process.
        let record = format!("UID={}\nTYPE=wayland\nCONTROLLER=:1.35\n", me);
        let logind = sessions("nb-logind", &[("1", record.as_str())]);
        let never = |_: std::os::unix::net::UnixStream, _: u32, _: Duration| LockState::Unlocked;
        let slow = |_: &str, budget: Duration| {
            std::thread::sleep(budget);
            Some(std::process::id())
        };
        let t0 = std::time::Instant::now();
        let looked = anchored(
            &logind,
            &base,
            me,
            &Bind::OnlyDesktop,
            t0 + Duration::from_millis(150),
            &slow,
            &never,
        );
        assert_eq!(looked, Anchored::Answer(LockState::Unknown));
        assert!(
            t0.elapsed() < Duration::from_millis(400),
            "{:?}",
            t0.elapsed()
        );
        let fast = |_: &str, _: Duration| Some(std::process::id());
        let t0 = std::time::Instant::now();
        let looked = anchored(
            &logind,
            &base,
            me,
            &Bind::OnlyDesktop,
            t0 + Duration::from_secs(5),
            &fast,
            &never,
        );
        assert_eq!(
            looked,
            Anchored::Answer(LockState::Unknown),
            "the full listener is passed over"
        );
        assert!(
            t0.elapsed() < Duration::from_millis(200),
            "{:?}",
            t0.elapsed()
        );
        assert_eq!(
            anchored(
                &logind,
                &base,
                me + 1,
                &Bind::OnlyDesktop,
                t0 + Duration::from_secs(1),
                &fast,
                &never
            ),
            Anchored::Hidden,
            "no runtime directory to see"
        );
        drop(listener);
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&logind);
    }

    /// Round 8 (Codex 1, Opus F1): a request's wait budget sums every wait
    /// on a verdict that is neither unlocked nor a positive lock, and is
    /// never reset, so churn between unknown, held and unlocked cannot
    /// start it over. A key check that a churned verdict cut off is owed
    /// to it, unless the next look is a positive lock.
    #[test]
    fn the_wait_budget_is_cumulative_and_never_reset() {
        let ms = Duration::from_millis;
        let mut b = WaitBudget::default();
        assert_eq!(b.observe(Verdict::Unknown, ms(0)), ms(0));
        assert_eq!(b.observe(Verdict::Held, ms(400)), ms(400));
        assert_eq!(
            b.observe(Verdict::Unlocked, ms(600)),
            ms(600),
            "held counts"
        );
        assert_eq!(
            b.observe(Verdict::Unknown, ms(5600)),
            ms(600),
            "the unlocked stretch does not"
        );
        assert_eq!(b.observe(Verdict::Locked, ms(6000)), ms(1000));
        assert_eq!(
            b.observe(Verdict::Unknown, ms(60_000)),
            ms(1000),
            "a positive lock waits freely"
        );
        assert_eq!(
            b.observe(Verdict::Unknown, ms(61_000)),
            ms(2000),
            "and nothing reset it"
        );
        b.owe(ms(3000));
        assert_eq!(
            b.observe(Verdict::Held, ms(61_000)),
            ms(5000),
            "a check cut off by churn counts"
        );
        b.owe(ms(3000));
        assert_eq!(
            b.observe(Verdict::Locked, ms(61_500)),
            ms(5500),
            "one a lock stopped does not"
        );
        assert_eq!(b.spent(), ms(5500));
    }

    /// Round 8 (Opus M3): logind lets a session's owner take control of a
    /// session no one controls and retype it (systemd v262
    /// src/login/logind-session-dbus.c: `method_take_control` refuses only
    /// another uid, or `force` without root, and `session_set_controller`
    /// refuses only while a controller holds it; `method_set_type` needs
    /// only the controller). Hyprland started from a text console does
    /// exactly that, so a retyped session is a real desktop; but a second
    /// one, made from a text console or an SSH login while the desktop is
    /// up, would name its maker as a compositor. So the lock question is
    /// answered only when the uid has exactly one controlled graphical
    /// session (closing ones aside) and the binding names it.
    #[test]
    fn a_session_the_user_made_graphical_makes_the_topology_ambiguous() {
        let desktop = "UID=1000\nTYPE=wayland\nORIGINAL_TYPE=wayland\nCONTROLLER=:1.35\n";
        let retyped = "UID=1000\nTYPE=wayland\nORIGINAL_TYPE=tty\nCONTROLLER=:1.90\n";
        let root = sessions("retyped", &[("1", desktop), ("5", retyped)]);
        for bind in [
            Bind::Session("5".into()),
            Bind::Session("1".into()),
            Bind::OnlyDesktop,
        ] {
            assert_eq!(controller_of(&root, 1000, &bind), None, "{:?}", bind);
        }
        std::fs::write(root.join("sessions/9"), "UID=1000\nTYPE=tty\n").unwrap();
        assert_eq!(
            controller_of(&root, 1000, &Bind::Session("9".into())),
            None,
            "a text console's request: still two"
        );
        std::fs::remove_file(root.join("sessions/5")).unwrap();
        assert_eq!(
            controller_of(&root, 1000, &Bind::Session("1".into())).as_deref(),
            Some(":1.35")
        );
        std::fs::write(
            root.join("sessions/3"),
            "UID=1000\nTYPE=wayland\nSTATE=closing\nCONTROLLER=:1.4\n",
        )
        .unwrap();
        assert_eq!(
            controller_of(&root, 1000, &Bind::OnlyDesktop).as_deref(),
            Some(":1.35"),
            "a closing session does not count"
        );
        let _ = std::fs::remove_dir_all(&root);
        // Hyprland started from a text console: one retyped session.
        let tty = sessions(
            "from-tty",
            &[(
                "2",
                "UID=1000\nTYPE=wayland\nORIGINAL_TYPE=tty\nCONTROLLER=:1.7\n",
            )],
        );
        assert_eq!(
            controller_of(&tty, 1000, &Bind::Session("2".into())).as_deref(),
            Some(":1.7")
        );
        assert_eq!(
            controller_of(&tty, 1000, &Bind::OnlyDesktop).as_deref(),
            Some(":1.7")
        );
        let _ = std::fs::remove_dir_all(&tty);
    }

    /// A listening socket at `path`, and one left behind by a listener
    /// that is gone (connects are refused).
    fn listener_at(path: &std::path::Path) -> std::os::unix::net::UnixListener {
        std::os::unix::net::UnixListener::bind(path).unwrap()
    }

    /// A socket file left with no listener, as a crashed session leaves
    /// one: bound, never listening, closed. A connect is refused at once.
    /// Not a dropped listener: a child another test forks in the moment
    /// that one is open keeps a copy listening until its exec, and the
    /// look then sees two listeners of this process and rightly answers
    /// nothing (measured 2026-10-13: 1 run in 10 of the module's suite,
    /// "2 hits of 13 sockets"; none single-threaded).
    fn stale_socket_at(path: &std::path::Path) {
        use std::os::fd::FromRawFd;
        // SAFETY: a plain socket call; the fd is owned below.
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);
        // SAFETY: fd is a new descriptor nothing else owns.
        let _owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        let (addr, len) = sockaddr(path).unwrap();
        // SAFETY: a valid socket and address for the call.
        let rc = unsafe { libc::bind(fd, (&addr as *const libc::sockaddr_un).cast(), len) };
        assert_eq!(rc, 0);
    }

    /// Round 8 (Codex 4, Opus L5): enumeration is bounded: at most
    /// `MAX_ENTRIES` directory entries are inspected, with the deadline
    /// checked inside the loop, and the cap is on connections made
    /// (`MAX_CONNECTS`), not on entries, so instance directories left by
    /// crashed sessions, whose sockets refuse, never hide the live one.
    #[test]
    fn enumeration_is_bounded_and_stale_directories_cannot_hide_the_live_socket() {
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        let run = std::env::temp_dir().join(format!("lockgate-enum-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        for i in 0..12 {
            let d = run.join(format!("hypr/stale_{}", i));
            std::fs::create_dir_all(&d).unwrap();
            stale_socket_at(&d.join(".socket.sock"));
        }
        std::fs::create_dir_all(run.join("hypr/live_1")).unwrap();
        let _live = listener_at(&run.join("hypr/live_1/.socket.sock"));
        let found = compositor_sockets(&run, me, far()).unwrap();
        assert_eq!(found.len(), 13, "every socket is a candidate");
        let s = compositor_stream(&found, std::process::id(), far());
        assert!(s.is_some(), "twelve stale sockets do not hide the live one");
        // Junk past the entry cap is never inspected, and a passed deadline
        // stops the walk at once.
        for i in 0..200 {
            std::fs::create_dir_all(run.join(format!("hypr/junk_{}", i))).unwrap();
        }
        let found = compositor_sockets(&run, me, far()).unwrap();
        assert!(found.len() <= MAX_ENTRIES, "{}", found.len());
        let t0 = std::time::Instant::now();
        let none = compositor_sockets(&run, me, t0).unwrap();
        assert!(none.is_empty() && t0.elapsed() < Duration::from_millis(50));
        const { assert!(MAX_CONNECTS < MAX_ENTRIES) };
        let _ = std::fs::remove_dir_all(&run);
    }

    /// systemd's block on `openat2` as the anchor's unit sees it: ENOSYS,
    /// for every unit with `RestrictSUIDSGID=`, which `DynamicUser=`
    /// implies (v262 src/core/unit.c, `unit_patch_contexts`;
    /// src/shared/seccomp-util.c, `seccomp_restrict_suid_sgid`: "we return
    /// ENOSYS to force programs to call open() or openat() instead").
    /// Installed on the calling thread alone.
    fn block_openat2_as_systemd_does() {
        #[cfg(target_arch = "x86_64")]
        const ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
        #[cfg(target_arch = "aarch64")]
        const ARCH: u32 = 0xC000_00B7; // AUDIT_ARCH_AARCH64
        let stmt = |code: u32, k: u32| libc::sock_filter {
            code: code as u16,
            jt: 0,
            jf: 0,
            k,
        };
        let jeq = |k: u32, jt: u8, jf: u8| libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt,
            jf,
            k,
        };
        let mut prog = [
            // seccomp_data.arch, then seccomp_data.nr.
            stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 4),
            jeq(ARCH, 1, 0),
            stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
            stmt(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, 0),
            jeq(libc::SYS_openat2 as u32, 0, 1),
            stmt(
                libc::BPF_RET | libc::BPF_K,
                libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32,
            ),
            stmt(libc::BPF_RET | libc::BPF_K, libc::SECCOMP_RET_ALLOW),
        ];
        let fprog = libc::sock_fprog {
            len: prog.len() as u16,
            filter: prog.as_mut_ptr(),
        };
        // SAFETY: prctl on values, and a filter program that outlives the
        // call (the kernel copies it).
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                    &fprog as *const libc::sock_fprog,
                ),
                0
            );
        }
    }

    /// Live test 1 (2026-10-13): in the anchor's unit every lock question
    /// went unanswered, since the look opened the runtime directory with
    /// `openat2`, which systemd blocks there with ENOSYS. The look finds
    /// the compositor's socket with that block in place.
    #[test]
    fn the_socket_is_found_where_systemd_blocks_openat2() {
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        let run = std::env::temp_dir().join(format!("lockgate-noopenat2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        std::fs::create_dir_all(run.join("hypr/live_1")).unwrap();
        let _live = listener_at(&run.join("hypr/live_1/.socket.sock"));
        let looked = {
            let run = run.clone();
            std::thread::spawn(move || {
                block_openat2_as_systemd_does();
                // SAFETY: an openat2 call with no open_how, which the
                // filter answers before the kernel reads it.
                let rc = unsafe {
                    libc::syscall(libc::SYS_openat2, libc::AT_FDCWD, c"/".as_ptr(), 0, 0)
                };
                let blocked = rc == -1
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOSYS);
                let found = compositor_sockets(&run, me, far()).map(|s| s.len());
                (blocked, found.map_err(|e| e.to_string()))
            })
            .join()
            .unwrap()
        };
        let _ = std::fs::remove_dir_all(&run);
        assert!(looked.0, "the block is in place, as in the unit");
        assert_eq!(looked.1, Ok(1), "the live socket is found");
    }

    /// The walk keeps what `openat2`'s resolve flags kept: no mount crossed
    /// below the runtime directory (/proc is always a mount of its own
    /// under /), no symlink anywhere along the runtime directory's own
    /// path, and no entry name that leaves the directory it is opened in.
    #[test]
    fn the_walk_crosses_no_mount_follows_no_symlink_and_stays_beneath() {
        use std::os::fd::AsRawFd;
        let root = open_dir_nofollow(Path::new("/")).unwrap();
        let mount = mount_id(root.as_raw_fd()).unwrap();
        let crossed = entry_on_mount(
            root.as_raw_fd(),
            "proc",
            libc::O_PATH | libc::O_DIRECTORY,
            mount,
        );
        assert_eq!(
            crossed.map(|_| ()).map_err(|e| e.raw_os_error()),
            Err(Some(libc::EXDEV)),
            "an entry on another mount"
        );
        for name in ["", ".", "..", "a/b", "/etc"] {
            assert!(
                open_entry(root.as_raw_fd(), name, libc::O_PATH).is_err(),
                "{:?} is not one entry of the directory",
                name
            );
        }
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        let base = std::env::temp_dir().join(format!("lockgate-pathlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("real").join(me.to_string()).join("hypr/live_1"))
            .unwrap();
        let _live = listener_at(
            &base
                .join("real")
                .join(me.to_string())
                .join("hypr/live_1/.socket.sock"),
        );
        std::os::unix::fs::symlink(base.join("real"), base.join("link")).unwrap();
        let direct =
            compositor_sockets(&base.join("real").join(me.to_string()), me, far()).map(|s| s.len());
        let linked = compositor_sockets(&base.join("link").join(me.to_string()), me, far());
        let relative = compositor_sockets(Path::new("real"), me, far());
        let _ = std::fs::remove_dir_all(&base);
        assert_eq!(direct.map_err(|e| e.to_string()), Ok(1));
        assert!(linked.is_err(), "a symlink on the runtime directory's path");
        assert!(relative.is_err(), "a relative runtime directory");
    }

    /// Round 16 (Codex): an instance directory moved out of `hypr/` after
    /// the walk opened it is no longer the entry, so its socket is no
    /// candidate; moved back, it is again.
    #[test]
    fn an_instance_directory_moved_away_is_no_longer_the_entry() {
        use std::os::fd::AsRawFd;
        let base = std::env::temp_dir().join(format!("lockgate-moved-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("hypr/inst_1")).unwrap();
        let root = open_dir_nofollow(&base).unwrap();
        let mount = mount_id(root.as_raw_fd()).unwrap();
        let hypr = entry_on_mount(
            root.as_raw_fd(),
            "hypr",
            libc::O_PATH | libc::O_DIRECTORY,
            mount,
        )
        .unwrap();
        let inst = entry_on_mount(
            hypr.as_raw_fd(),
            "inst_1",
            libc::O_PATH | libc::O_DIRECTORY,
            mount,
        )
        .unwrap();
        assert!(still_entry(hypr.as_raw_fd(), "inst_1", inst.as_raw_fd()));
        std::fs::rename(base.join("hypr/inst_1"), base.join("moved")).unwrap();
        let away = still_entry(hypr.as_raw_fd(), "inst_1", inst.as_raw_fd());
        std::fs::create_dir_all(base.join("hypr/inst_1")).unwrap();
        let replaced = still_entry(hypr.as_raw_fd(), "inst_1", inst.as_raw_fd());
        std::fs::remove_dir(base.join("hypr/inst_1")).unwrap();
        std::fs::rename(base.join("moved"), base.join("hypr/inst_1")).unwrap();
        let back = still_entry(hypr.as_raw_fd(), "inst_1", inst.as_raw_fd());
        // `hypr` itself, moved away from under the runtime directory.
        let hypr_here = still_entry(root.as_raw_fd(), "hypr", hypr.as_raw_fd());
        std::fs::rename(base.join("hypr"), base.join("hypr_moved")).unwrap();
        let hypr_away = still_entry(root.as_raw_fd(), "hypr", hypr.as_raw_fd());
        let _ = std::fs::remove_dir_all(&base);
        assert!(!away, "moved away");
        assert!(!replaced, "another directory in its place");
        assert!(back, "moved back");
        assert!(hypr_here && !hypr_away, "hypr moved away");
    }

    /// Round 8 (Opus L2): the socket is opened race-free: no symlink
    /// anywhere below the runtime directory (one component at a time with
    /// `O_NOFOLLOW`, `entry_on_mount`), checked to be a socket the
    /// user owns on the descriptor itself, and connected through
    /// /proc/self/fd, so a swapped path never steers the connect.
    #[test]
    fn the_socket_is_opened_without_following_a_symlink_anywhere() {
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        let run = std::env::temp_dir().join(format!("lockgate-nofollow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
        let elsewhere = run.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(run.join("hypr")).unwrap();
        let _l = listener_at(&elsewhere.join(".socket.sock"));
        std::os::unix::fs::symlink(&elsewhere, run.join("hypr/linked_1")).unwrap();
        assert!(
            compositor_sockets(&run, me, far()).unwrap().is_empty(),
            "a symlinked instance directory is no candidate"
        );
        std::fs::remove_file(run.join("hypr/linked_1")).unwrap();
        std::fs::create_dir_all(run.join("hypr/real_1")).unwrap();
        let _r = listener_at(&run.join("hypr/real_1/.socket.sock"));
        let found = compositor_sockets(&run, me, far()).unwrap();
        assert_eq!(found.len(), 1);
        // The candidate is the inode that was checked: renaming another
        // socket into its place afterwards does not change what is
        // connected.
        std::fs::rename(
            run.join("hypr/real_1/.socket.sock"),
            run.join("hypr/real_1/old.sock"),
        )
        .unwrap();
        std::fs::rename(
            elsewhere.join(".socket.sock"),
            run.join("hypr/real_1/.socket.sock"),
        )
        .unwrap();
        let s = compositor_stream(&found, std::process::id(), far()).unwrap();
        assert_eq!(peer_pid(&s), Some(std::process::id()));
        let _ = std::fs::remove_dir_all(&run);
    }

    /// Round 8 (Codex 1): a reply counts only when the kernel says the
    /// pinned compositor wrote it. With SO_PASSCRED on the receiving
    /// socket, Linux attaches the writing task's thread-group pid to every
    /// buffer (v7.2 net/unix/af_unix.c, `unix_maybe_add_creds`; a sender
    /// may claim another pid only with CAP_SYS_ADMIN over its pid
    /// namespace, net/core/scm.c `scm_check_creds`), and a stream read
    /// never glues buffers from different writers
    /// (`unix_stream_read_generic`), so each read carries its writer. A
    /// process that holds a stolen copy of the compositor's socket writes
    /// as itself.
    #[test]
    fn a_reply_is_taken_only_from_the_pinned_compositor() {
        use std::io::Write;
        use std::os::fd::OwnedFd;
        let dir = std::env::temp_dir().join(format!("lockgate-creds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sock");
        let listener = listener_at(&path);
        let me = std::process::id();
        let ask = |writer: &dyn Fn(std::os::unix::net::UnixStream)| {
            let client = std::os::unix::net::UnixStream::connect(&path).unwrap();
            assert!(set_passcred(&client));
            let (server, _) = listener.accept().unwrap();
            writer(server);
            recv_from(&client, me, Duration::from_secs(2), 4096)
        };
        // This process writes: its own pid.
        let got = ask(&|mut s| {
            s.write_all(b"[1]").unwrap();
        });
        assert_eq!(got.as_deref(), Some(&b"[1]"[..]));
        // Another process writes on the same connection: refused.
        let got = ask(&|s| {
            let st = std::process::Command::new("/bin/sh")
                .args(["-c", "printf '[0]'"])
                .stdout(std::process::Stdio::from(OwnedFd::from(s)))
                .status()
                .unwrap();
            assert!(st.success());
        });
        assert_eq!(got, None, "a writer that is not the compositor");
        // Half from the compositor, half from another process: refused.
        let got = ask(&|mut s| {
            s.write_all(b"[").unwrap();
            let st = std::process::Command::new("/bin/sh")
                .args(["-c", "sleep 0.05; printf '0]'"])
                .stdout(std::process::Stdio::from(OwnedFd::from(s)))
                .status()
                .unwrap();
            assert!(st.success());
        });
        assert_eq!(got, None, "never glued across writers");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Round 8 (Codex 4): a look that could stall (a file system that
    /// never answers) is run on a thread of its own and given up at the
    /// deadline.
    #[test]
    fn a_stalled_look_is_given_up_at_the_deadline() {
        let t0 = std::time::Instant::now();
        let got = guarded(t0 + Duration::from_millis(100), || {
            std::thread::sleep(Duration::from_secs(5));
            1
        });
        assert_eq!(got, None);
        assert!(t0.elapsed() < Duration::from_millis(300));
        assert_eq!(guarded(far(), || 7), Some(7));
    }

    /// Round 8 (Opus L6): waits on a card on screen are the user's own
    /// work and free, but only for a while: past `free` in all, as cycled
    /// cards would make them, they are charged like an unknown wait.
    #[test]
    fn card_waits_are_free_only_for_a_while() {
        let ms = Duration::from_millis;
        let free = ms(1000);
        let mut b = WaitBudget::default();
        assert_eq!(b.observe_card(ms(0), free), ms(0));
        assert_eq!(b.observe_card(ms(600), free), ms(0));
        assert_eq!(
            b.observe(Verdict::Unknown, ms(900)),
            ms(0),
            "900 ms of cards, free"
        );
        assert_eq!(
            b.observe_card(ms(1000), free),
            ms(100),
            "the unknown stretch counts"
        );
        assert_eq!(
            b.observe_card(ms(1500), free),
            ms(500),
            "card time past the free 1000 ms counts"
        );
        assert_eq!(b.observe(Verdict::Locked, ms(2000)), ms(1000));
        assert_eq!(
            b.observe(Verdict::Unlocked, ms(9000)),
            ms(1000),
            "a positive lock is free"
        );
    }

    /// Fix round 8 (Opus L4): a drop lets go after 3 s of steady unlocked
    /// looks, well inside one request's 10 s budget, so the first request
    /// after a drop is not always sent to the password.
    #[test]
    fn a_drop_clears_inside_one_requests_budget() {
        assert_eq!(DROP_CLEARS, Duration::from_secs(3));
        assert!(DROP_CLEARS * 3 <= UNKNOWN_LIMIT);
    }

    /// Fix round 8 (item 14): whether a user has a desktop, from logind's
    /// root-readable records alone: a graphical session of theirs that is
    /// neither a greeter nor closing. With none, nothing the daemon runs
    /// in the user's manager may run, since the way it reaches the manager
    /// opens a PAM session that would start one.
    #[test]
    fn a_desktop_is_a_live_graphical_session_of_the_users() {
        let none = sessions("desk-none", &[]);
        assert!(!user_has_desktop(&none, 1000));
        let _ = std::fs::remove_dir_all(&none);
        for (name, record, want) in [
            ("tty", "UID=1000\nTYPE=tty\n", false),
            ("greeter", "UID=1000\nTYPE=wayland\nCLASS=greeter\n", false),
            ("closing", "UID=1000\nTYPE=wayland\nSTATE=closing\n", false),
            ("other", "UID=1001\nTYPE=wayland\n", false),
            ("desktop", "UID=1000\nTYPE=wayland\nSTATE=active\n", true),
            (
                "retyped",
                "UID=1000\nTYPE=wayland\nORIGINAL_TYPE=tty\n",
                true,
            ),
        ] {
            let root = sessions(&format!("desk-{}", name), &[("1", record)]);
            assert_eq!(user_has_desktop(&root, 1000), want, "{}", name);
            let _ = std::fs::remove_dir_all(&root);
        }
        assert!(!user_has_desktop(
            std::path::Path::new("/nonexistent/logind"),
            1000
        ));
        let two = sessions(
            "desk-two",
            &[
                ("4", "UID=1000\nTYPE=wayland\n"),
                ("2", "UID=1000\nTYPE=x11\n"),
                ("3", "UID=1000\nTYPE=tty\n"),
            ],
        );
        assert_eq!(
            user_desktops(&two, 1000),
            ["2", "4"],
            "sorted ids of the live desktops"
        );
        let _ = std::fs::remove_dir_all(&two);
    }

    /// Fix round 11 (Codex 2, Opus N4): one lease on the key across
    /// processes. Whoever runs a check (the daemon's unit, or the PAM
    /// module's check while faceauthd is down) takes an exclusive flock on
    /// one root-owned file outside the daemon's runtime directory and holds
    /// it until it exits, so the two can never run at once, across a
    /// restart too. A file another account could open, or one that is not
    /// there, gives no lease.
    #[test]
    fn the_key_lease_is_held_by_one_process_at_a_time() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("faceauth-lease-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let lease = dir.join("key.lease");
        assert!(
            take_key_lease(&lease, Duration::ZERO).is_none(),
            "no file, no lease"
        );
        std::fs::write(&lease, "").unwrap();
        std::fs::set_permissions(&lease, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(
            take_key_lease(&lease, Duration::ZERO).is_none(),
            "a file others can open is no lease"
        );
        std::fs::set_permissions(&lease, std::fs::Permissions::from_mode(0o600)).unwrap();
        let first = take_key_lease(&lease, Duration::ZERO).expect("the lease");
        let t0 = std::time::Instant::now();
        assert!(
            take_key_lease(&lease, Duration::from_millis(150)).is_none(),
            "held: a second taker waits, then has none"
        );
        assert!(t0.elapsed() >= Duration::from_millis(150));
        drop(first);
        // With a moment's wait: a child another test forks in the moment the
        // lease is held keeps a copy of its open file, and so the lock, until
        // its exec closes it (round 16b, Opus F5: 3 of 49 runs).
        assert!(
            take_key_lease(&lease, Duration::from_secs(1)).is_some(),
            "free again"
        );
        // Another process holding it: none until it exits.
        let mut holder = std::process::Command::new("/usr/bin/flock")
            .args(["-x"])
            .arg(&lease)
            .args(["/bin/sh", "-c", "sleep 0.4"])
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(150));
        assert!(
            take_key_lease(&lease, Duration::ZERO).is_none(),
            "held by another process"
        );
        let _ = holder.wait();
        assert!(
            take_key_lease(&lease, Duration::from_millis(100)).is_some(),
            "free once it has exited"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The package makes the lease at boot, root's alone, never truncated.
    #[test]
    fn the_package_makes_the_key_lease() {
        let tmpfiles = include_str!("../../packaging/faceauth.tmpfiles");
        let want = format!("f {} 0600 root root -", KEY_LEASE);
        assert_eq!(
            tmpfiles
                .lines()
                .filter(|l| !l.starts_with('#'))
                .collect::<Vec<_>>(),
            [want.as_str()]
        );
    }
}
