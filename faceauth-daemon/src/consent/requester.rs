//! Who is asking for consent, read from /proc and from the context the
//! polkit agent relays. The window shows what is gathered here, so the
//! command text is clipped and cleaned before it gets that far.

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
    pub via: String,
    /// On the polkit lane, the requesting process as polkitd named it, when
    /// it did: the server runs the locality check on it as well.
    #[serde(skip)]
    pub requester: Option<i32>,
}

pub(crate) fn real_uid_of(pid: i32) -> Option<u32> {
    read_proc(pid, "status")?
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|s| s.parse().ok())
}

fn cgroup_path_of(pid: i32) -> String {
    read_proc(pid, "cgroup")
        .and_then(|c| {
            c.lines()
                .find_map(|l| l.splitn(3, ':').nth(2).map(str::to_string))
        })
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

pub(crate) fn read_proc(pid: i32, what: &str) -> Option<String> {
    std::fs::read(format!("/proc/{}/{}", pid, what))
        .ok()
        .map(|b| {
            String::from_utf8_lossy(&b)
                .replace('\0', " ")
                .trim()
                .to_string()
        })
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

fn exe_of(pid: i32) -> String {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

pub(crate) fn ppid_of(pid: i32) -> Option<i32> {
    let stat = read_proc(pid, "stat")?;
    // "pid (comm) state ppid ..."; comm may contain spaces, so split after the last ')'.
    let rest = stat.rsplit(')').next()?;
    rest.split_whitespace().nth(1)?.parse().ok()
}

pub(crate) fn comm_of(pid: i32) -> String {
    clip(&read_proc(pid, "comm").unwrap_or_default())
}

/// What a polkit request is, as the agent heard it from polkitd: the action
/// id and the message (which for pkexec names the command). polkit's PAM
/// helper carries none of this (and on polkit 127 it is socket-activated by
/// systemd, so not even the agent's child), so the agent hands it to the
/// daemon as the request starts. Contexts queue per user in arrival order;
/// polkit serves one request per agent at a time, in that order, so the
/// helper's request takes the oldest fresh context for its user. One context
/// serves one request.
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
}

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
pub(crate) fn take_polkit_context(agent: AgentPeer) -> Option<PolkitContext> {
    let deadline = Instant::now() + Duration::from_millis(1500);
    loop {
        if let Ok(mut m) = CONTEXTS.lock() {
            for q in m.values_mut() {
                q.retain(|c| c.at.elapsed() < Duration::from_secs(120));
                if let Some(i) = q.iter().position(|c| c.agent == Some(agent)) {
                    return q.remove(i);
                }
            }
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl CallerInfo {
    pub fn from_pid(pid: i32, user_uid: u32, agent: Option<AgentPeer>) -> CallerInfo {
        let exe = exe_of(pid);
        let cmdline = read_proc(pid, "cmdline").unwrap_or_default();
        // The helper is setuid, so its exe link is unreadable without ptrace
        // rights (this daemon has none); comm is readable but truncated to 15 bytes.
        let comm = comm_of(pid);
        // The base name is the requester's own (a process may name its
        // executable anything): clipped like the command it labels.
        let base = Path::new(&exe)
            .file_name()
            .map(|s| clip(&s.to_string_lossy()))
            .unwrap_or_else(|| comm.clone());
        if base == "polkit-agent-helper-1" || comm.starts_with("polkit-agent-he") {
            let agent_comm = agent.map(|a| comm_of(a.pid)).unwrap_or_default();
            let context = agent.and_then(take_polkit_context);
            let mut info = CallerInfo::polkit(pid, user_uid, agent, &agent_comm, context);
            info.exe = exe;
            info.cmdline = cmdline;
            return info;
        }
        let (command, clipped) = clip_command(&cmdline);
        CallerInfo {
            pid,
            exe: exe.clone(),
            cmdline: cmdline.clone(),
            kill_pid: pid,
            via: base.clone(),
            command,
            clipped,
            verified: true,
            parents: parent_chain(pid),
            who: format!("{} (pid {})  from  {}", base, pid, parent_chain(pid)),
            requester: None,
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
    /// agent's context, labelled by the window as the requesting side's
    /// word, and there is nothing to kill.
    pub fn polkit(
        pid: i32,
        user_uid: u32,
        agent: Option<AgentPeer>,
        agent_comm: &str,
        context: Option<PolkitContext>,
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
        let is_root_service =
            |p: i32| real_uid_of(p) == Some(0) && cgroup_path_of(p).starts_with("/system.slice/");
        let requester = polkit_requester(c.caller_pid, c.subject_pid, &is_root_service);
        // The requester must be the user's own process (polkitd allows a
        // caller to ask for its own uid or, as root, for anyone), still
        // there, with a command line to read.
        let named = requester.and_then(|rp| {
            let uid = real_uid_of(rp)?;
            if uid != user_uid {
                log::warn!("consent: polkit named requester pid {} with uid {}, not uid {}; not shown as verified", rp, uid, user_uid);
                return None;
            }
            let (cl, clipped) = clip_command(&read_proc(rp, "cmdline").unwrap_or_default());
            if cl.is_empty() {
                return None;
            }
            Some((rp, cl, clipped))
        });
        match named {
            Some((rp, cl, clipped)) => {
                let name = comm_of(rp);
                let parents = parent_chain(rp);
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
        let Some(pp) = ppid_of(p) else { break };
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

    fn ctx(_uid: u32, agent: Option<AgentPeer>, action: &str) -> PolkitContext {
        PolkitContext {
            action: action.into(),
            message: "m".into(),
            agent,
            caller_pid: None,
            subject_pid: None,
            at: Instant::now(),
        }
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
            take_polkit_context(shell).map(|c| c.action).as_deref(),
            Some("org.example.real")
        );
        // A second request from the same agent finds nothing of its own,
        // and does not fall back to what another peer left behind.
        let t = Instant::now();
        assert!(take_polkit_context(shell).is_none());
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
