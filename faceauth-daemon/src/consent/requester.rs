//! Who is asking for consent, read from /proc and from the context the
//! polkit agent relays. The window shows what is gathered here, so the
//! command text is clipped and cleaned before it gets that far.

use crate::procfs;
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Who is asking, as far as /proc can say. The fields the window never
/// reads are kept out of its payload: the raw command line would put a
/// long sudo command past the kernel's argument limit and cost the card
/// the ruling says it keeps (D5).
#[derive(Clone, Debug, Default, Serialize)]
pub struct CallerInfo {
    /// The process that holds the PAM transaction (sudo, polkit-agent-helper-1).
    #[serde(skip)]
    pub pid: i32,
    #[serde(skip)]
    pub exe: String,
    #[serde(skip)]
    pub cmdline: String,
    /// What is being asked. When `verified` it is the daemon's own reading
    /// of the requesting process's command line (sudo's, pkexec's). When
    /// not, it is what the requesting side said about itself: for a plain
    /// polkit action, the message and action id the agent relayed. Any
    /// process of the user's can send that, so the window labels it.
    pub command: String,
    pub verified: bool,
    /// `command` was cut at `COMMAND_CLIP`: the card says so rather
    /// than pass the tail off as the whole (A6). The nod path stays open.
    #[serde(default)]
    pub clipped: bool,
    /// Who asked: the requesting process and pid, then its parents
    /// ("sudo (pid 3011002)  from  bash (2990241) <- foot (13950)"), or the
    /// polkit helper's pid with a note that the asking process was not found.
    pub who: String,
    /// The chain above the requester: "alacritty (3910) <- bash (3921)".
    #[serde(skip)]
    pub parents: String,
    /// The process to kill if the user says no: the requester, not the helper.
    pub kill_pid: i32,
    /// The pidfs id of `kill_pid` (round 19): the card's kill names its
    /// process by both, so a pid another process holds by then is never
    /// signalled (`kill_pinned`). Text on the wire, since a pidfs id can
    /// pass a double's whole-number range. 0, with `kill_pid` 0, when no
    /// process could be pinned (`pin_kill`).
    #[serde(serialize_with = "ino_text")]
    pub kill_ino: u64,
    pub via: String,
    /// On the polkit lane, the requesting process as polkitd named it, when
    /// it did: the server runs the locality check on it as well.
    #[serde(skip)]
    pub requester: Option<i32>,
    /// A pidfd of `requester`, opened before anything about it was read and
    /// checked alive after the last read (round 16b, Codex 1 and Opus F3),
    /// so what the card says, the server's locality check and the request's
    /// watch are all about one process, never whatever holds the pid later.
    #[serde(skip)]
    pub requester_fd: Option<std::sync::Arc<std::os::fd::OwnedFd>>,
    /// The session the request's lock question is about (round 8, Codex
    /// 3): set by the server from the PAM process; ambiguous until then.
    #[serde(skip)]
    pub bind: crate::lockgate::Bind,
}

fn ino_text<S: serde::Serializer>(ino: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&ino.to_string())
}

impl CallerInfo {
    /// Pin the process the card may kill (round 19): sudo's own process by
    /// the connection's peer pidfd (`peer`), polkit's requester by the
    /// pidfd it was named with. Anything else is no kill target at all.
    pub fn pin_kill(&mut self, peer: Option<AgentPeer>) {
        let ino = match (&self.requester_fd, peer) {
            (Some(fd), _) if self.requester == Some(self.kill_pid) => {
                nix::sys::stat::fstat(fd.as_ref()).ok().map(|st| st.st_ino)
            }
            (_, Some(p)) if p.pid == self.kill_pid => Some(p.id),
            _ => None,
        };
        match ino {
            Some(i) if self.kill_pid > 1 && i != 0 => self.kill_ino = i,
            _ => {
                self.kill_pid = 0;
                self.kill_ino = 0;
            }
        }
    }
}

/// Signal the process `pid` with `sig`, only while it is the process whose
/// pidfs id is `ino` (round 19): a pidfd opened now names one process for
/// its life, and its id says whether that is still the process the daemon
/// pinned for the card. Any other is refused, never signalled.
pub fn kill_pinned(pid: i32, ino: u64, sig: i32) -> Result<(), &'static str> {
    use std::os::fd::AsRawFd;
    if pid <= 1 || ino == 0 {
        return Err("no requester to kill");
    }
    let fd = pidfd_of(pid).ok_or("the requester has ended")?;
    let now = nix::sys::stat::fstat(&fd)
        .map_err(|_| "the requester cannot be read")?
        .st_ino;
    if now != ino {
        return Err("the requester has ended, and its pid is another process's now");
    }
    // SAFETY: a valid pidfd, a signal number, no info pointer.
    let sent = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if sent == 0 {
        Ok(())
    } else {
        Err("the requester could not be signalled")
    }
}

/// The card's Deny and kill (round 19): SIGTERM to the process the daemon
/// pinned for the card, by pid and pidfs id (`kill_pinned`).
pub fn kill_requester(pid: i32, ino: u64) -> Result<(), &'static str> {
    kill_pinned(pid, ino, libc::SIGTERM)
}

/// A pidfd of `pid`, or None for a process gone.
fn pidfd_of(pid: i32) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    // SAFETY: pidfd_open takes a pid and flags and no pointers.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    // SAFETY: a new descriptor nothing else owns.
    (fd >= 0).then(|| unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as libc::c_int) })
}

fn cgroup_path_of(pid: i32) -> String {
    procfs::read(pid, "cgroup")
        .and_then(|c| procfs::cgroup_path(&c).map(str::to_string))
        .unwrap_or_default()
}

/// Which process a polkit request is for, from polkitd's caller and
/// subject pids. The caller is the process that asked polkitd, identified
/// by its D-Bus credentials: `pkexec` itself, or a system service asking
/// on behalf of the process it serves (systemd-timedated for timedatectl).
/// In the second case the service vouches for the subject, so the subject
/// is the requester; otherwise the caller is, and the subject is the
/// caller's own claim about itself.
pub fn polkit_requester(
    caller: Option<i32>,
    subject: Option<i32>,
    is_root_service: &dyn Fn(i32) -> bool,
) -> Option<i32> {
    let caller = caller.filter(|p| *p > 1)?;
    match (is_root_service(caller), subject.filter(|p| *p > 1)) {
        (true, Some(s)) => Some(s),
        _ => Some(caller),
    }
}

/// Longest command text shown, in characters. Wider than any real command
/// line (a kernel's argument limit is far larger, but a shown command past
/// this is not read by a person); what is cut is flagged, never hidden (A6).
pub const COMMAND_CLIP: usize = 16_384;

/// Text for the window: nothing that formats or steers the text (a newline
/// or a bidi override in a command line would let the requester write its
/// own description). Characters are kept or dropped by Unicode general
/// category: Cc (controls), Cf (format: zero-width, bidi, joiners), Zl and
/// Zp (line and paragraph separators) go; a tab becomes a space; every
/// other category stays. Cut at `COMMAND_CLIP`; `clip_command` says
/// whether it was. Applied to everything read from /proc or sent by the
/// polkit agent before it reaches the window or the log.
pub fn clip(s: &str) -> String {
    clip_command(s).0
}

/// `clip`, and whether the text was cut.
pub fn clip_command(s: &str) -> (String, bool) {
    let kept: String = s
        .chars()
        .filter_map(|c| {
            if c == '\t' {
                Some(' ')
            } else if is_dropped_category(c) {
                None
            } else {
                Some(c)
            }
        })
        .take(COMMAND_CLIP + 1)
        .collect();
    if kept.chars().count() > COMMAND_CLIP {
        log::info!(
            "consent: a command line of over {} characters is shown cut",
            COMMAND_CLIP
        );
        (kept.chars().take(COMMAND_CLIP).collect(), true)
    } else {
        (kept, false)
    }
}

/// Unicode general categories Cc, Cf, Zl and Zp (Unicode 15). The Cf
/// table is the standard's, listed in full so nothing new that formats or
/// reorders text slips through as "not on the hand list".
fn is_dropped_category(c: char) -> bool {
    if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
        return true;
    }
    const CF: [(u32, u32); 21] = [
        (0x00AD, 0x00AD),
        (0x0600, 0x0605),
        (0x061C, 0x061C),
        (0x06DD, 0x06DD),
        (0x070F, 0x070F),
        (0x0890, 0x0891),
        (0x08E2, 0x08E2),
        (0x180E, 0x180E),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0x110BD, 0x110BD),
        (0x110CD, 0x110CD),
        (0x13430, 0x1343F),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0001, 0xE0001),
        (0xE0020, 0xE007F),
    ];
    let u = c as u32;
    CF.iter().any(|&(lo, hi)| lo <= u && u <= hi)
}

/// A process's name as the window shows it: `comm`, clipped.
pub(crate) fn comm_of(pid: i32) -> String {
    clip(&procfs::read(pid, "comm").unwrap_or_default())
}

/// What a polkit request is, as the agent heard it from polkitd: the action
/// id and the message (which for pkexec names the command). polkit's PAM
/// helper carries none of this (and on polkit 127 it is socket-activated by
/// systemd, so not even the agent's child), so the agent hands it to the
/// daemon as the request starts. Contexts queue per user, and a helper's
/// request takes only a context sent by the agent that connected it: the
/// one with the request's cookie, which the module asks that agent for
/// (`take_context_by_cookie`, round 16c), or, from an agent that does not
/// answer that prompt, one picked by arrival and never shown as verified
/// (`take_polkit_context`). One context serves one request.
#[derive(Clone, Debug)]
pub struct PolkitContext {
    pub action: String,
    pub message: String,
    /// The peer that sent it, as the kernel reported it.
    pub agent: Option<AgentPeer>,
    /// polkitd's own details, when the agent's Quickshell exposes them:
    /// the process that asked polkitd (from its D-Bus credentials) and the
    /// process the authorization is for.
    pub caller_pid: Option<i32>,
    pub subject_pid: Option<i32>,
    pub at: Instant,
    /// When it arrived, as time since boot (`boottime_now`), to set beside
    /// its helper's start (`take_polkit_context`).
    pub at_boot: Duration,
    /// polkitd's cookie for the request, when the agent sent one of the
    /// right form (`lockgate::polkit_cookie_ok`): the one tie to the
    /// helper's PAM request, by way of `POLKIT_COOKIE_PROMPT` (round 16c).
    pub cookie: Option<String>,
    /// Its agent said, with it, that it answers the cookie prompt: such a
    /// context is served by its cookie alone, never by arrival (round 17b,
    /// Codex 1, Opus F1).
    pub cookie_prompt: bool,
}

/// Agents that said they answer pam_faceauth's cookie prompt, by sending a
/// context with `context_cookie_prompt` (round 16c): their requests are
/// matched to their contexts by cookie alone. A few at a time, the newest
/// kept.
/// Kept per uid of the sender (round 17, Opus F1), so another account's
/// peers can never push this one's agent out.
pub static COOKIE_AGENTS: std::sync::LazyLock<
    Mutex<std::collections::HashMap<u32, std::collections::VecDeque<AgentPeer>>>,
> = std::sync::LazyLock::new(Default::default);

/// The most agents `COOKIE_AGENTS` keeps for one uid.
pub const COOKIE_AGENTS_MAX: usize = 16;

/// Whether the process `agent` names still runs: its pid opens a pidfd of
/// the same pidfs id.
fn peer_alive(agent: AgentPeer) -> bool {
    pidfd_of(agent.pid)
        .and_then(|fd| nix::sys::stat::fstat(&fd).ok())
        .is_some_and(|st| st.st_ino == agent.id)
}

/// `agent`, sending as `uid`, says it answers the cookie prompt. Peers
/// whose process is gone go first, then the oldest.
pub fn note_cookie_agent(uid: u32, agent: AgentPeer) {
    if let Ok(mut m) = COOKIE_AGENTS.lock() {
        let q = m.entry(uid).or_default();
        if q.contains(&agent) {
            return;
        }
        if q.len() >= COOKIE_AGENTS_MAX {
            q.retain(|a| peer_alive(*a));
        }
        q.push_back(agent);
        while q.len() > COOKIE_AGENTS_MAX {
            q.pop_front();
        }
    }
}

/// `agent` sent a context without saying it answers the cookie prompt (an
/// older shell's code in its process, round 17, Codex 1): it is asked no
/// more.
pub fn forget_cookie_agent(agent: AgentPeer) {
    if let Ok(mut m) = COOKIE_AGENTS.lock() {
        for q in m.values_mut() {
            q.retain(|a| *a != agent);
        }
    }
}

/// Whether `agent` answers the cookie prompt, waiting up to `wait` for its
/// first context to say so: the helper's PAM request and the agent's
/// context race.
pub fn speaks_cookies(agent: AgentPeer, wait: Duration) -> bool {
    let by = Instant::now() + wait;
    loop {
        if COOKIE_AGENTS
            .lock()
            .is_ok_and(|m| m.values().any(|q| q.contains(&agent)))
        {
            return true;
        }
        if Instant::now() >= by {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// What the request's PAM module brought of polkit's cookie (round 16c).
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Asked<'a> {
    /// The agent's answer to the cookie prompt: a cookie, or "" for none.
    Cookie(&'a str),
    /// Its agent was never asked: it does not answer the prompt.
    Unasked,
    /// Not for a card: no context is taken (a key line's log).
    Skip,
}

/// The context `agent` sent with `cookie`, waiting up to `wait` for it: the
/// one context that is this request's (round 16c). Another agent's, or one
/// with another cookie, never is; the others stay for their own requests
/// until they expire.
pub(crate) fn take_context_by_cookie(
    agent: AgentPeer,
    cookie: &str,
    wait: Duration,
) -> Option<PolkitContext> {
    let by = Instant::now() + wait;
    loop {
        if let Ok(mut m) = CONTEXTS.lock() {
            for q in m.values_mut() {
                if let Some(c) = pick_by_cookie(q, agent, cookie) {
                    return Some(c);
                }
            }
        }
        if Instant::now() >= by {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The context in `q` from `agent` with `cookie`, taken out.
fn pick_by_cookie(
    q: &mut std::collections::VecDeque<PolkitContext>,
    agent: AgentPeer,
    cookie: &str,
) -> Option<PolkitContext> {
    q.retain(|c| c.at.elapsed() < Duration::from_secs(120));
    // Left in place: every helper of the request carries its cookie, a
    // password retry's too (round 17, Codex 2, Opus F5).
    q.iter()
        .rev()
        .find(|c| c.agent == Some(agent) && c.cookie.as_deref() == Some(cookie))
        .cloned()
}

/// Round 17 tests: a peer of this test process, by its pidfs id.
#[cfg(test)]
fn self_peer() -> AgentPeer {
    let me = std::process::id() as i32;
    let fd = pidfd_of(me).unwrap();
    AgentPeer {
        pid: me,
        id: nix::sys::stat::fstat(&fd).unwrap().st_ino,
    }
}

/// Time since boot, suspend included (CLOCK_BOOTTIME): the clock a
/// process's start time in `/proc/<pid>/stat` is kept in.
pub fn boottime_now() -> Duration {
    // SAFETY: an all-zero timespec is a valid out-parameter.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: a clock id and an out-parameter.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) } != 0 {
        return Duration::ZERO;
    }
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

/// How long before its helper started a request's context may have been
/// sent: the agent sends it as it starts that helper, a few dozen ms apart.
pub const CONTEXT_LEAD: Duration = Duration::from_secs(2);

/// A process as a kernel fact: its pid and its pidfs inode, which outlives
/// no process and is never reused. It is what systemd writes into the name
/// of a socket-activated instance (polkit's helper) for the peer that
/// connected it, and what the daemon reads from a peer's pidfd.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AgentPeer {
    pub pid: i32,
    pub id: u64,
}

pub static CONTEXTS: std::sync::LazyLock<
    Mutex<std::collections::HashMap<u32, std::collections::VecDeque<PolkitContext>>>,
> = std::sync::LazyLock::new(Default::default);

/// The oldest fresh context sent by this agent (the one that connected the
/// request's helper), waiting briefly for one: the helper's PAM request and
/// the agent's context race, and the context usually loses by a few dozen
/// ms. A context from any other peer, however old, is never this request's.
/// `helper_started` is when the request's helper started
/// (`procfs::started_since_boot`); unknown, no context is served.
pub(crate) fn take_polkit_context(
    agent: AgentPeer,
    helper_started: Option<Duration>,
) -> Option<PolkitContext> {
    let deadline = Instant::now() + Duration::from_millis(1500);
    loop {
        if let Ok(mut m) = CONTEXTS.lock() {
            for q in m.values_mut() {
                if let Some(c) = pick_context(q, agent, helper_started) {
                    return Some(c);
                }
            }
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The context in `q` for a request whose helper `agent` connected and
/// which started at `helper_started`, taken out of the queue.
fn pick_context(
    q: &mut std::collections::VecDeque<PolkitContext>,
    agent: AgentPeer,
    helper_started: Option<Duration>,
) -> Option<PolkitContext> {
    q.retain(|c| c.at.elapsed() < Duration::from_secs(120));
    // Unknown, nothing: an earlier request's context is worse than none,
    // which the card labels (round 16b, Opus F2).
    let started = helper_started?;
    // This agent's contexts from before its helper started, less the lead,
    // were earlier requests'; they go now.
    q.retain(|c| c.agent != Some(agent) || c.at_boot + CONTEXT_LEAD >= started);
    // A context sent for the cookie prompt is its cookie's alone: kept for
    // its own request's retries, it must never label another by arrival
    // (round 17b, Codex 1, Opus F1).
    let i = q
        .iter()
        .position(|c| c.agent == Some(agent) && !c.cookie_prompt)?;
    q.remove(i)
}

/// The lane a consent request from `pid` is on: "polkit" for polkit's
/// helper, else the requester's base name ("sudo"). Read the same way as
/// `CallerInfo::from_pid` reads it, for the answers given before that
/// runs (`auth::lane_answer`).
pub fn caller_lane(pid: i32) -> String {
    if is_polkit_helper(pid) {
        return "polkit".into();
    }
    base_of(&procfs::exe(pid).unwrap_or_default(), &comm_of(pid))
}

/// Whether `pid` is polkit's helper, by the one predicate the locality
/// check and the connection limits use (fix round 15, Opus N1):
/// `lockgate::polkit_helper_instance` on its cgroup, its real uid and its
/// comm. comm alone is only the name the file was exec'd under
/// (fs/exec.c), so a link named `polkit-agent-helper-1` to sudo gave a
/// real sudo the polkit lane: a card with no command, and polkit-1's key
/// policy. The cgroup is PID 1's to make.
fn is_polkit_helper(pid: i32) -> bool {
    let cgroup = procfs::read(pid, "cgroup").unwrap_or_default();
    let comm = procfs::read(pid, "comm");
    crate::lockgate::polkit_helper_instance(
        &cgroup,
        crate::lockgate::HelperSigns {
            ruid: procfs::real_uid(pid),
            comm: comm.as_deref(),
        },
    )
    .is_some()
}

/// The requester's base name, from its exe or else its comm. Neither
/// requester's exe link reads here (fix round 14, Opus N1): faceauthd is
/// uid 0 with no capability, and the link takes ptrace access
/// (fs/proc/base.c, `call_proc_get_link`), which `cap_ptrace_access_check`
/// refuses for a target whose permitted set is not within the daemon's
/// empty effective one (security/commoncap.c). polkit 127's helper is not
/// setuid; it runs as root with its unit's full permitted set, and sudo,
/// setuid root, has a full one too. So it comes down to comm, readable
/// with no ptrace check but cut to 15 bytes. The base name is the
/// requester's own (a process may name its executable anything): clipped
/// like the command it labels. It names the lane only for a process that is
/// not polkit's helper (`is_polkit_helper`), so a program run under the
/// helper's name keeps that name, which no key line takes
/// (`admit_key_fallback`).
fn base_of(exe: &str, comm: &str) -> String {
    Path::new(exe)
        .file_name()
        .map(|s| clip(&s.to_string_lossy()))
        .unwrap_or_else(|| comm.to_string())
}

impl CallerInfo {
    /// `from_pid_asked` for a request whose agent was never asked for a
    /// cookie.
    pub fn from_pid(pid: i32, user_uid: u32, agent: Option<AgentPeer>) -> CallerInfo {
        CallerInfo::from_pid_asked(pid, user_uid, agent, Asked::Unasked)
    }

    /// Who is asking, and for a polkit request what, by `asked`: the
    /// context with the request's cookie, shown as verified when polkitd's
    /// pids name the requester; none for an agent that gave no cookie; and
    /// for an agent that does not answer the prompt, the context picked by
    /// arrival, never shown as verified, since nothing ties it to this
    /// request (round 16c).
    pub fn from_pid_asked(
        pid: i32,
        user_uid: u32,
        agent: Option<AgentPeer>,
        asked: Asked<'_>,
    ) -> CallerInfo {
        let exe = procfs::exe(pid).unwrap_or_default();
        // Capped before it is read (fix round 11, Codex 1), and the card
        // says when it was cut.
        let shown = procfs::read_shown(pid, "cmdline");
        let cut = shown.as_ref().is_some_and(|s| s.truncated);
        let cmdline = shown.map(|s| s.text).unwrap_or_default();
        let base = base_of(&exe, &comm_of(pid));
        if is_polkit_helper(pid) {
            let agent_comm = agent.map(|a| comm_of(a.pid)).unwrap_or_default();
            // A key line's log names the polkit request and takes no
            // context (round 17, Opus F4).
            if asked == Asked::Skip {
                let mut info = CallerInfo::polkit_logged(pid);
                info.exe = exe;
                info.cmdline = cmdline;
                return info;
            }
            let (context, exact) = match (agent, asked) {
                (Some(a), Asked::Cookie(c)) if crate::lockgate::polkit_cookie_ok(c) => (
                    take_context_by_cookie(a, c, Duration::from_millis(1500)),
                    true,
                ),
                (Some(a), Asked::Unasked) => {
                    let started = procfs::started_since_boot(pid);
                    (take_polkit_context(a, started), false)
                }
                _ => (None, false),
            };
            let mut info =
                CallerInfo::polkit_with(pid, user_uid, agent, &agent_comm, context, exact);
            info.exe = exe;
            info.cmdline = cmdline;
            return info;
        }
        let (command, clipped) = clip_command(&cmdline);
        let clipped = clipped || cut;
        CallerInfo {
            pid,
            exe: exe.clone(),
            cmdline: cmdline.clone(),
            kill_pid: pid,
            kill_ino: 0,
            via: base.clone(),
            command,
            clipped,
            verified: true,
            parents: parent_chain(pid),
            who: format!("{} (pid {})  from  {}", base, pid, parent_chain(pid)),
            requester: None,
            requester_fd: None,
            bind: Default::default(),
        }
    }

    /// A request through polkit's helper. The helper carries nothing that
    /// names its requester. A scan of the user's processes for one named
    /// `pkexec` is a guess any same-uid process can plant, so nothing found
    /// that way is ever presented as verified. What can be trusted: which
    /// agent connected the helper (read from the helper's unit name and
    /// pinned by the locality check), and, when that agent's Quickshell
    /// exposes them, the pids polkitd attached to the request. polkitd
    /// takes the caller's pid from its D-Bus credentials, so the requester
    /// resolved from it is read from /proc by this daemon, shown as
    /// verified, and offered to kill; the server runs the locality check
    /// on it too. Without those pids the request is described by the
    /// agent's context, labeled by the window as the requesting side's
    /// word, and there is nothing to kill.
    pub fn polkit(
        pid: i32,
        user_uid: u32,
        agent: Option<AgentPeer>,
        agent_comm: &str,
        context: Option<PolkitContext>,
    ) -> CallerInfo {
        CallerInfo::polkit_with(pid, user_uid, agent, agent_comm, context, true)
    }

    /// A polkit request as a key line's log names it: the lane and the
    /// helper, no context taken and nothing verified (round 17, Opus F4).
    pub fn polkit_logged(pid: i32) -> CallerInfo {
        CallerInfo {
            pid,
            via: "polkit".into(),
            command: "a polkit action".into(),
            who: format!("polkit's helper (pid {})", pid),
            ..Default::default()
        }
    }

    /// `polkit`, where `exact` says the context is this request's by its
    /// cookie. A context that is not is the agent's word alone: its
    /// polkitd pids are not followed, so it is never shown as verified,
    /// never offered to kill and never watched (round 16c).
    pub fn polkit_with(
        pid: i32,
        user_uid: u32,
        agent: Option<AgentPeer>,
        agent_comm: &str,
        context: Option<PolkitContext>,
        exact: bool,
    ) -> CallerInfo {
        let mut info = CallerInfo {
            pid,
            via: "polkit".into(),
            kill_pid: 0,
            verified: false,
            ..Default::default()
        };
        let agent_text = match agent {
            Some(a) => format!("agent {} (pid {})", clip(agent_comm), a.pid),
            None => "agent not known".to_string(),
        };
        let Some(c) = context else {
            log::warn!(
                "consent: no context from the agent that connected polkit helper pid {}",
                pid
            );
            info.command = "a polkit action (no description was given)".into();
            info.who = format!(
                "polkit's helper (pid {}), {}; polkit does not say which process asked",
                pid, agent_text
            );
            return info;
        };
        let relayed = clip(&format!("{} [{}]", c.message.trim(), c.action));
        let is_root_service = |p: i32| {
            procfs::real_uid(p) == Some(0) && cgroup_path_of(p).starts_with("/system.slice/")
        };
        let requester = if exact {
            polkit_requester(c.caller_pid, c.subject_pid, &is_root_service)
        } else {
            None
        };
        // The requester must be the user's own process (polkitd allows a
        // caller to ask for its own uid or, as root, for anyone), still
        // there, with a command line to read.
        // Pinned first, read after, and alive at the end: every read below
        // is of the process the pidfd holds.
        let named = requester.and_then(|rp| {
            let pidfd = pidfd_of(rp)?;
            let uid = procfs::real_uid(rp)?;
            if uid != user_uid {
                log::warn!("consent: polkit named requester pid {} with uid {}, not uid {}; not shown as verified", rp, uid, user_uid);
                return None;
            }
            let shown = procfs::read_shown(rp, "cmdline")?;
            let (cl, clipped) = clip_command(&shown.text);
            let clipped = clipped || shown.truncated;
            if cl.is_empty() {
                return None;
            }
            let name = comm_of(rp);
            let parents = parent_chain(rp);
            if super::process_exited(&pidfd) {
                log::warn!("consent: polkit named requester pid {}, which exited while it was read; not shown as verified", rp);
                return None;
            }
            Some((rp, cl, clipped, name, parents, pidfd))
        });
        match named {
            Some((rp, cl, clipped, name, parents, pidfd)) => {
                let asked = match (c.caller_pid, c.subject_pid) {
                    (Some(cp), Some(sp)) if cp != sp && rp == sp => {
                        format!("; asked by {} (pid {})", comm_of(cp), cp)
                    }
                    _ => String::new(),
                };
                log::info!("consent: polkit helper pid {}: requester {} (pid {}) named by polkitd; the agent relayed: {}", pid, name, rp, relayed);
                info.command = cl;
                info.clipped = clipped;
                info.verified = true;
                info.kill_pid = rp;
                info.requester = Some(rp);
                info.requester_fd = Some(std::sync::Arc::new(pidfd));
                info.parents = parents.clone();
                info.who = format!(
                    "{} (pid {})  from  {}{}; via polkit, {}",
                    name, rp, parents, asked, agent_text
                );
            }
            None => {
                log::info!("consent: polkit helper pid {}: no requester polkitd could name; the agent relayed (unverified): {}", pid, relayed);
                info.command = relayed;
                info.who = format!(
                    "polkit's helper (pid {}), {}; polkit does not say which process asked",
                    pid, agent_text
                );
            }
        }
        info
    }
}

fn parent_chain(pid: i32) -> String {
    let mut out = Vec::new();
    let mut p = pid;
    for _ in 0..4 {
        let Some(pp) = procfs::ppid(p) else { break };
        if pp <= 1 {
            break;
        }
        out.push(format!("{} ({})", comm_of(pp), pp));
        p = pp;
    }
    out.join(" <- ")
}

#[cfg(test)]
mod polkit_context_tests {
    use super::*;

    /// Fix round 15 (Opus N1; Opus's probe
    /// `opus15_probe_lane_by_symlink_name`, turned around): comm is only
    /// the name a file was exec'd under (fs/exec.c), so a link named
    /// `polkit-agent-helper-1` to sudo gave a real sudo the polkit lane:
    /// a card saying "a polkit action" with no command, and polkit-1's key
    /// policy, which may ask no PIN. The lane is polkit's only where the
    /// locality check and the limits believe polkit's helper
    /// (`lockgate::polkit_helper_instance`); a renamed program keeps its
    /// own name as its lane, which no key line takes (`admit_key_fallback`),
    /// and the card shows its own command.
    #[test]
    fn a_program_run_under_the_helpers_name_is_not_on_the_polkit_lane() {
        let dir = std::env::temp_dir().join(format!("faceauth-lane-name-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("polkit-agent-helper-1");
        std::os::unix::fs::symlink("/usr/bin/sleep", &link).unwrap();
        let mut child = std::process::Command::new(&link).arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let t0 = std::time::Instant::now();
        while comm_of(pid) != "polkit-agent-he" && t0.elapsed() < Duration::from_secs(5) {
            std::thread::sleep(Duration::from_millis(10));
        }
        let comm = comm_of(pid);
        let lane = caller_lane(pid);
        let info = CallerInfo::from_pid(pid, 1000, None);
        let _ = child.kill();
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(comm, "polkit-agent-he", "the name it was run under");
        // Its own name is its lane: here its exe's (the test can read its
        // own child's exe link), for a sudo its comm, which is what the
        // daemon can read of it.
        assert!(
            matches!(lane.as_str(), "sleep" | "polkit-agent-he"),
            "its own name is its lane, not polkit's: {}",
            lane
        );
        assert_eq!(info.via, lane);
        assert!(
            info.command.contains("polkit-agent-helper-1 30")
                && !info.command.contains("polkit action"),
            "the card shows its own command: {}",
            info.command
        );
    }

    fn ctx(_uid: u32, agent: Option<AgentPeer>, action: &str) -> PolkitContext {
        PolkitContext {
            action: action.into(),
            message: "m".into(),
            agent,
            caller_pid: None,
            subject_pid: None,
            at: Instant::now(),
            at_boot: boottime_now(),
            cookie: None,
            cookie_prompt: false,
        }
    }

    /// Round 17b (Codex 1, Opus F1): a context its agent sent saying it
    /// answers the cookie prompt is served by its cookie alone. With the
    /// agent's mark gone (pushed out of its bucket by the user's own
    /// processes, or revoked by its own later context), its next request is
    /// matched by arrival, and such a context, kept in place for its own
    /// request's retries, must not label that one: the card then names no
    /// action at all rather than the wrong one. A context sent without the
    /// word (an agent that never answers the prompt) is still picked.
    #[test]
    fn a_context_for_the_cookie_prompt_is_never_picked_by_arrival() {
        let shell = AgentPeer { pid: 504, id: 5004 };
        let started = Duration::from_secs(20_000);
        let mut flagged = ctx(1, Some(shell), "org.example.cookie-served");
        flagged.cookie = Some("1-dddd-1-1".into());
        flagged.cookie_prompt = true;
        flagged.at_boot = started;
        let mut q = std::collections::VecDeque::from(vec![flagged.clone()]);
        assert!(
            pick_context(&mut q, shell, Some(started)).is_none(),
            "not by arrival"
        );
        assert_eq!(q.len(), 1, "left for its own request");
        let mut plain = ctx(1, Some(shell), "org.example.plain");
        plain.at_boot = started;
        let mut q = std::collections::VecDeque::from(vec![flagged, plain]);
        assert_eq!(
            pick_context(&mut q, shell, Some(started))
                .map(|c| c.action)
                .as_deref(),
            Some("org.example.plain")
        );
    }

    /// Round 16c (Codex 1, Opus F1): a request's context is the one with
    /// its cookie, whatever came before it or after: a context its own
    /// request never took (a fingerprint approved it first, the lid was
    /// shut, the queue was full) labels nothing else, and another agent's
    /// with the same cookie is not this one's.
    #[test]
    fn a_request_takes_only_the_context_with_its_cookie() {
        let shell = AgentPeer { pid: 501, id: 5001 };
        let other = AgentPeer { pid: 601, id: 6001 };
        let with = |agent, action: &str, cookie: &str| PolkitContext {
            cookie: Some(cookie.into()),
            ..ctx(1, Some(agent), action)
        };
        let mut q = std::collections::VecDeque::from(vec![
            with(shell, "org.example.earlier", "1-aaaa-1-1"),
            with(other, "org.example.elsewhere", "1-bbbb-1-1"),
            with(shell, "org.example.this", "1-bbbb-1-1"),
        ]);
        assert_eq!(
            pick_by_cookie(&mut q, shell, "1-bbbb-1-1")
                .map(|c| c.action)
                .as_deref(),
            Some("org.example.this")
        );
        assert!(
            pick_by_cookie(&mut q, shell, "1-cccc-1-1").is_none(),
            "no context has it"
        );
        // Round 17 (Codex 2, Opus F5): every helper of one request, a
        // password retry's included, carries its cookie, so the context
        // stays until it expires and serves each of them.
        assert_eq!(
            pick_by_cookie(&mut q, shell, "1-bbbb-1-1")
                .map(|c| c.action)
                .as_deref(),
            Some("org.example.this"),
            "a retry of the same request"
        );
        assert_eq!(q.len(), 3, "nothing is taken out");
    }

    /// Round 17 (Opus F1, Codex 1): an agent is asked for cookies only while
    /// it says it answers the prompt: a later context of its without the
    /// word takes the mark away; marks are kept per uid, so another account's
    /// flood of peers cannot push this one out; and a peer whose process is
    /// gone goes first.
    #[test]
    fn the_cookie_mark_is_per_uid_live_and_revocable() {
        let shell = self_peer();
        note_cookie_agent(4243, shell);
        assert!(speaks_cookies(shell, Duration::ZERO));
        for i in 0..(COOKIE_AGENTS_MAX as u64 * 2) {
            note_cookie_agent(
                4244,
                AgentPeer {
                    pid: 999_000 + i as i32,
                    id: 42_000 + i,
                },
            );
        }
        assert!(
            speaks_cookies(shell, Duration::ZERO),
            "another uid's flood leaves it"
        );
        forget_cookie_agent(shell);
        assert!(
            !speaks_cookies(shell, Duration::ZERO),
            "a context without the word revokes it"
        );
        // Round 17b (Opus F2): a live agent first in a full bucket of gone
        // ones outlasts them; first in, first out would drop it.
        note_cookie_agent(4246, shell);
        for i in 0..(COOKIE_AGENTS_MAX as u64) {
            note_cookie_agent(
                4246,
                AgentPeer {
                    pid: 996_000 + i as i32,
                    id: 45_000 + i,
                },
            );
        }
        assert!(
            speaks_cookies(shell, Duration::ZERO),
            "the live one at the front is kept"
        );
        // Dead peers go first: a bucket full of gone processes takes a live
        // one without dropping it.
        for i in 0..(COOKIE_AGENTS_MAX as u64) {
            note_cookie_agent(
                4245,
                AgentPeer {
                    pid: 998_000 + i as i32,
                    id: 43_000 + i,
                },
            );
        }
        note_cookie_agent(4245, shell);
        note_cookie_agent(
            4245,
            AgentPeer {
                pid: 997_000,
                id: 44_000,
            },
        );
        assert!(
            speaks_cookies(shell, Duration::ZERO),
            "the live one is kept"
        );
        forget_cookie_agent(shell);
    }

    /// Round 17 (Opus F4): a key line's log takes no context and names the
    /// polkit request without the warning a card's missing context logs.
    #[test]
    fn a_key_lines_log_names_polkit_without_a_context() {
        let info = CallerInfo::polkit_logged(4242);
        assert!(!info.verified && info.kill_pid == 0 && info.via == "polkit");
        assert!(info.requester.is_none() && info.requester_fd.is_none());
        assert!(!info.command.contains("no description"), "{}", info.command);
    }

    /// Round 16c: a context that is not this request's by its cookie is the
    /// agent's word alone, even with polkitd's pids naming a live requester
    /// of the user's: not verified, nothing to kill, nothing to watch.
    #[test]
    fn a_context_without_its_cookie_is_never_verified() {
        let me = std::process::id() as i32;
        let my_uid = nix::unistd::getuid().as_raw();
        let agent = AgentPeer { pid: 502, id: 5002 };
        let mut c = ctx(my_uid, Some(agent), "org.freedesktop.policykit.exec");
        c.caller_pid = Some(me);
        c.subject_pid = Some(me);
        let info = CallerInfo::polkit_with(
            600,
            my_uid,
            Some(agent),
            "quickshell",
            Some(c.clone()),
            false,
        );
        assert!(!info.verified, "{}", info.who);
        assert_eq!(info.kill_pid, 0);
        assert!(info.requester.is_none() && info.requester_fd.is_none());
        let exact = CallerInfo::polkit_with(600, my_uid, Some(agent), "quickshell", Some(c), true);
        assert!(exact.verified, "{}", exact.who);
    }

    /// Round 16c: an agent counts as answering the cookie prompt once one
    /// of its contexts says so, and not before; a peer reused with another
    /// pidfs id is another agent.
    #[test]
    fn an_agent_answers_the_cookie_prompt_once_it_says_so() {
        let shell = AgentPeer { pid: 503, id: 5003 };
        assert!(!speaks_cookies(shell, Duration::from_millis(100)));
        note_cookie_agent(1000, shell);
        assert!(speaks_cookies(shell, Duration::ZERO));
        assert!(!speaks_cookies(
            AgentPeer { pid: 503, id: 9003 },
            Duration::ZERO
        ));
        forget_cookie_agent(shell);
    }

    /// Round 16b (Opus F2): a context its agent sent well before the
    /// request's helper started is an earlier request's, one that ended
    /// before it took its context (the lid closed, no desktop, a full
    /// queue): polkit serves one request per agent at a time, and the agent
    /// sends a request's context as it starts that request's helper. It is
    /// dropped, never served, so a card never names an earlier request. A
    /// context that arrives after its helper started (the usual race) is
    /// this one's; another peer's are left alone; and with the helper's
    /// start unknown, nothing is served.
    #[test]
    fn a_context_older_than_its_helper_is_an_earlier_requests() {
        let shell = AgentPeer { pid: 500, id: 5000 };
        let other = AgentPeer { pid: 600, id: 6000 };
        let started = Duration::from_secs(10_000);
        let at = |c: PolkitContext, boot: Duration| PolkitContext { at_boot: boot, ..c };
        let queue = || {
            std::collections::VecDeque::from(vec![
                at(
                    ctx(1, Some(shell), "org.example.earlier"),
                    started - Duration::from_secs(30),
                ),
                at(
                    ctx(1, Some(other), "org.example.elsewhere"),
                    started - Duration::from_secs(30),
                ),
                at(
                    ctx(1, Some(shell), "org.example.this"),
                    started + Duration::from_millis(40),
                ),
            ])
        };
        let mut q = queue();
        assert_eq!(
            pick_context(&mut q, shell, Some(started))
                .map(|c| c.action)
                .as_deref(),
            Some("org.example.this")
        );
        let left: Vec<String> = q.iter().map(|c| c.action.clone()).collect();
        assert_eq!(
            left,
            vec!["org.example.elsewhere".to_string()],
            "the earlier one is dropped"
        );
        let mut q = queue();
        q.remove(2);
        assert!(
            pick_context(&mut q, shell, Some(started)).is_none(),
            "only an earlier one"
        );
        let mut q = queue();
        assert!(
            pick_context(&mut q, shell, None).is_none(),
            "the helper's start unknown"
        );
        // A context sent just before its helper started is still its own.
        let mut q = std::collections::VecDeque::from(vec![at(
            ctx(1, Some(shell), "org.example.just-before"),
            started - Duration::from_millis(300),
        )]);
        assert!(pick_context(&mut q, shell, Some(started)).is_some());
    }

    /// The daemon's own reading of a process's start: this test's, a
    /// moment before now on the same clock.
    #[test]
    fn a_process_start_reads_on_the_boot_clock() {
        let started = crate::procfs::started_since_boot(std::process::id() as i32).unwrap();
        let now = boottime_now();
        assert!(
            started <= now && now - started < Duration::from_secs(3600),
            "{:?} {:?}",
            started,
            now
        );
    }

    /// A context serves only a request whose helper was connected by the
    /// peer that sent it: not the oldest for the uid, and never one from a
    /// process that merely runs as the user (A8, A5).
    #[test]
    fn a_context_is_matched_to_the_agent_that_sent_it_not_by_arrival_order() {
        let planted = AgentPeer { pid: 900, id: 9000 };
        let shell = AgentPeer { pid: 500, id: 5000 };
        {
            let mut m = CONTEXTS.lock().unwrap();
            let q = m.entry(4242).or_default();
            q.clear();
            q.push_back(ctx(4242, Some(planted), "org.example.benign"));
            q.push_back(ctx(4242, None, "org.example.anonymous"));
            q.push_back(ctx(4242, Some(shell), "org.example.real"));
        }
        assert_eq!(
            take_polkit_context(shell, Some(boottime_now()))
                .map(|c| c.action)
                .as_deref(),
            Some("org.example.real")
        );
        // A second request from the same agent finds nothing of its own,
        // and does not fall back to what another peer left behind.
        let t = Instant::now();
        assert!(take_polkit_context(shell, Some(boottime_now())).is_none());
        assert!(t.elapsed() >= Duration::from_millis(1400));
        let left: Vec<String> = CONTEXTS
            .lock()
            .unwrap()
            .get(&4242)
            .unwrap()
            .iter()
            .map(|c| c.action.clone())
            .collect();
        assert_eq!(
            left,
            vec![
                "org.example.benign".to_string(),
                "org.example.anonymous".to_string()
            ]
        );
        CONTEXTS.lock().unwrap().remove(&4242);
    }

    /// Without polkitd's pids nothing on the polkit lane is verified,
    /// whatever processes of the user's are named `pkexec`, and there is
    /// nothing to kill.
    #[test]
    fn a_polkit_request_without_polkitds_pids_is_never_presented_as_verified() {
        let agent = AgentPeer { pid: 500, id: 5000 };
        let info = CallerInfo::polkit(
            600,
            1000,
            Some(agent),
            "quickshell",
            Some(ctx(1000, Some(agent), "org.freedesktop.policykit.exec")),
        );
        assert!(!info.verified);
        assert_eq!(info.kill_pid, 0);
        assert_eq!(info.requester, None);
        assert_eq!(info.via, "polkit");
        assert!(
            info.who.contains("agent quickshell (pid 500)"),
            "{}",
            info.who
        );
        assert!(
            info.command.ends_with("[org.freedesktop.policykit.exec]"),
            "{}",
            info.command
        );
        let info = CallerInfo::polkit(600, 1000, None, "", None);
        assert!(!info.verified && info.kill_pid == 0);
        assert!(info.command.contains("no description"), "{}", info.command);
    }

    /// With polkitd's caller pid the requester is read from /proc by the
    /// daemon: this test process stands in for pkexec.
    #[test]
    fn polkitds_caller_pid_names_a_verified_requester() {
        let me = std::process::id() as i32;
        let my_uid = nix::unistd::getuid().as_raw();
        let agent = AgentPeer { pid: 500, id: 5000 };
        let mut c = ctx(my_uid, Some(agent), "org.freedesktop.policykit.exec");
        c.caller_pid = Some(me);
        c.subject_pid = Some(me);
        let info = CallerInfo::polkit(600, my_uid, Some(agent), "quickshell", Some(c.clone()));
        assert!(info.verified, "{}", info.who);
        assert_eq!(info.kill_pid, me);
        assert_eq!(info.requester, Some(me));
        // Round 16b: pinned, and to this very process, by its pidfs inode.
        let fd = info.requester_fd.as_ref().expect("the requester's pidfd");
        let own = pidfd_of(me).unwrap();
        assert_eq!(
            nix::sys::stat::fstat(fd.as_ref()).unwrap().st_ino,
            nix::sys::stat::fstat(&own).unwrap().st_ino
        );
        assert!(!super::super::process_exited(fd));
        assert!(info.command.contains("faceauth"), "{}", info.command);
        assert!(
            info.who.contains(&format!("(pid {})", me))
                && info.who.contains("via polkit, agent quickshell (pid 500)"),
            "{}",
            info.who
        );
        // A requester of another uid is not the user's and is not shown as verified.
        let info = CallerInfo::polkit(
            600,
            my_uid.wrapping_add(1),
            Some(agent),
            "quickshell",
            Some(c.clone()),
        );
        assert!(!info.verified && info.requester.is_none(), "{}", info.who);
        // A requester that is gone: unverified.
        c.caller_pid = Some(i32::MAX - 1);
        let info = CallerInfo::polkit(600, my_uid, Some(agent), "quickshell", Some(c));
        assert!(!info.verified && info.kill_pid == 0, "{}", info.who);
    }

    #[test]
    fn the_requester_is_the_caller_unless_a_root_service_asked_for_a_subject() {
        let root_service = |p: i32| p == 77;
        assert_eq!(
            polkit_requester(Some(42), Some(42), &root_service),
            Some(42)
        );
        assert_eq!(
            polkit_requester(Some(42), Some(43), &root_service),
            Some(42),
            "a plain caller's subject claim is not followed"
        );
        assert_eq!(
            polkit_requester(Some(77), Some(43), &root_service),
            Some(43),
            "a root service vouches for its subject"
        );
        assert_eq!(polkit_requester(Some(77), None, &root_service), Some(77));
        assert_eq!(
            polkit_requester(None, Some(43), &root_service),
            None,
            "no caller, nothing to trust"
        );
        assert_eq!(polkit_requester(Some(0), Some(43), &root_service), None);
    }
}

#[cfg(test)]
mod window_text_tests {
    use super::clip;

    #[test]
    fn clip_drops_line_breaks_and_direction_overrides() {
        use super::{clip_command, COMMAND_CLIP};
        assert_eq!(
            clip("sudo /bin/sh -c true\nRoutine update\nNo action needed"),
            "sudo /bin/sh -c trueRoutine updateNo action needed"
        );
        assert_eq!(clip("ls \u{202E}txt.sh"), "ls txt.sh");
        assert_eq!(
            clip("a\u{200B}b\u{2066}c\tD"),
            "abc D",
            "a tab is a space; format characters go"
        );
        // Line and paragraph separators, next line, and the Arabic letter
        // mark: every category that breaks or steers a line, not a hand list.
        assert_eq!(
            clip("a\u{2028}b\u{2029}c\u{0085}d\u{061C}e\u{FEFF}f\u{00AD}g\u{E0041}h"),
            "abcdefgh"
        );
        assert_eq!(clip("plain command --flag"), "plain command --flag");
        assert_eq!(
            clip("caf\u{E9} \u{00A0}x \u{4E2D}\u{6587} \u{1F600}"),
            "caf\u{E9} \u{00A0}x \u{4E2D}\u{6587} \u{1F600}",
            "letters, symbols and other spaces stay"
        );
        // A 2,500-character command is shown whole and unflagged (the old
        // 2,000 cut is gone); a command past the limit is cut and flagged,
        // and neither changes what the request may do (A6, ruling D5).
        let (c, clipped) = clip_command(&"x".repeat(2500));
        assert_eq!((c.chars().count(), clipped), (2500, false));
        let (c, clipped) = clip_command(&"y".repeat(COMMAND_CLIP + 500));
        assert_eq!((c.chars().count(), clipped), (COMMAND_CLIP, true));
        let (c, clipped) = clip_command(&"z".repeat(COMMAND_CLIP));
        assert_eq!((c.chars().count(), clipped), (COMMAND_CLIP, false));
        let (c, clipped) = clip_command(&"w".repeat(20_000));
        assert_eq!(
            (c.chars().count(), clipped),
            (COMMAND_CLIP, true),
            "a 20,000-character command is cut and flagged"
        );
    }

    /// The window payload carries the flag with the caller, so the card can
    /// say the command is cut; the caller is otherwise the same request.
    #[test]
    fn a_clipped_command_is_flagged_in_the_payload() {
        use super::{clip_command, CallerInfo, COMMAND_CLIP};
        let (command, clipped) = clip_command(&"x".repeat(20_000));
        let info = CallerInfo {
            command,
            clipped,
            verified: true,
            ..Default::default()
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["clipped"], serde_json::Value::Bool(true));
        // The flag is a label for the card only: the nod path reads
        // nothing from it, so consent proceeds on a cut command as on any.
        assert!(info.verified && info.kill_pid == 0);
        assert_eq!(
            json["command"].as_str().unwrap().chars().count(),
            COMMAND_CLIP
        );
        let plain = CallerInfo {
            command: "sudo ls".into(),
            verified: true,
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(&plain).unwrap()["clipped"],
            serde_json::Value::Bool(false)
        );
    }
}

#[cfg(test)]
mod kill_tests {
    use super::{kill_pinned, AgentPeer, CallerInfo};
    use std::os::fd::AsRawFd;

    fn ino_of(pid: i32) -> u64 {
        let fd = super::pidfd_of(pid).expect("a pidfd");
        nix::sys::stat::fstat(&fd).unwrap().st_ino
    }

    /// Round 19 (live test 2, Mike: "deny and kill is supposed to deny and
    /// kill the pid"): the card's kill names its process by pid and pidfs
    /// id, and only that process is signalled: a pid another process holds
    /// now, a wrong id, or nothing to name is refused, and the process
    /// lives on.
    #[test]
    fn a_kill_reaches_only_the_process_the_daemon_pinned() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let pid = child.id() as i32;
        let ino = ino_of(pid);
        assert!(
            kill_pinned(pid, ino + 1, libc::SIGTERM).is_err(),
            "another id"
        );
        assert!(kill_pinned(pid, 0, libc::SIGTERM).is_err(), "no id");
        assert!(kill_pinned(1, ino, libc::SIGTERM).is_err(), "pid 1");
        assert!(
            child.try_wait().unwrap().is_none(),
            "the process is untouched"
        );
        kill_pinned(pid, ino, libc::SIGTERM).expect("the pinned process");
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(child.wait().unwrap().signal(), Some(libc::SIGTERM));
        // Gone, and its pid perhaps another's: refused.
        assert!(kill_pinned(pid, ino, libc::SIGTERM).is_err());
    }

    /// Round 19: the card offers a kill only for a process the daemon has
    /// pinned by its pidfs id: sudo's own process by the connection's peer
    /// pidfd, polkit's requester by the pidfd it was named with; any other
    /// target is no kill at all.
    #[test]
    fn the_kill_target_is_pinned_or_not_offered() {
        let me = std::process::id() as i32;
        let own = super::pidfd_of(me).unwrap();
        let own_ino = nix::sys::stat::fstat(&own).unwrap().st_ino;
        let peer = Some(AgentPeer {
            pid: me,
            id: own_ino,
        });
        let mut sudo = CallerInfo {
            kill_pid: me,
            verified: true,
            via: "sudo".into(),
            ..Default::default()
        };
        sudo.pin_kill(peer);
        assert_eq!((sudo.kill_pid, sudo.kill_ino), (me, own_ino));
        let mut polkit = CallerInfo {
            kill_pid: me,
            verified: true,
            via: "polkit".into(),
            requester: Some(me),
            requester_fd: Some(std::sync::Arc::new(super::pidfd_of(me).unwrap())),
            ..Default::default()
        };
        polkit.pin_kill(Some(AgentPeer { pid: me + 1, id: 7 }));
        assert_eq!((polkit.kill_pid, polkit.kill_ino), (me, own_ino));
        for (who, peer) in [
            ("no peer", None),
            ("another peer", Some(AgentPeer { pid: me + 1, id: 7 })),
        ] {
            let mut other = CallerInfo {
                kill_pid: me,
                verified: true,
                via: "sudo".into(),
                ..Default::default()
            };
            other.pin_kill(peer);
            assert_eq!((other.kill_pid, other.kill_ino), (0, 0), "{}", who);
        }
        // The card reads the id as text: a pidfs id can pass a double's
        // whole-number range.
        let v = serde_json::to_value(&sudo).unwrap();
        assert_eq!(
            v["kill_ino"],
            serde_json::Value::String(own_ino.to_string())
        );
        let _ = own.as_raw_fd();
    }
}
