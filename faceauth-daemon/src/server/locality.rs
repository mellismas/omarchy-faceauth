//! Where a request comes from. The check is positive and fails closed: a
//! caller is local only when the daemon can show it from /proc and logind,
//! and remote on any read error or unfamiliar shape.

use super::user_uid;
use anyhow::{bail, Context, Result};
use std::os::fd::AsFd;

/// Where a request comes from, as far as the daemon can prove it.
pub enum Locality {
    /// Local; for polkit's helper, with the agent that connected it.
    Local(Option<crate::consent::AgentPeer>),
    Remote(String),
}

/// A positive, fail-closed check: a caller is local when the daemon can show
/// it is, and remote otherwise (any read error, timeout or unfamiliar shape).
///
/// 1. Any `sshd` or `sshd-session` in the parent chain: remote.
/// 2. Root in `/system.slice/`: only polkit's authentication helper is
///    followed, and no other root service is local. On polkit 127 the helper
///    is socket-activated per connection, and systemd names the instance
///    after the peer that connected it (`<n>-<cookie>-<pid>_<pidfd id>-<uid>`,
///    from SO_PEERCRED and the peer's pidfs inode): the agent that is serving
///    the request. The check moves to that agent, pinned by its pidfd id, and
///    the answer is the agent's. Omarchy's shell is in the user's session;
///    `pkexec` from an SSH shell, which registers its own text agent, is
///    under `sshd-session` and refused. The helper itself is never local.
/// 3. In a logind session scope (`session-N.scope`): local only if logind
///    says that session is the target user's, not remote, and on a seat.
/// 4. Inside the target user's own manager (`user-<uid>.slice/user@<uid>.service`,
///    where every desktop app and the lock screen's PAM helper lives, with no
///    session scope of its own): local only if that user has a live session on
///    a seat that logind does not mark remote.
/// 5. Anything else: remote.
///
/// The concession in step 4, written here rather than discovered later: a
/// same-uid process inside the user manager counts as local whenever the
/// user has a local session, and provenance cannot tell a same-uid remote
/// shell that asked the manager to fork for it (`systemd-run --user`) from a
/// local one. What stands between that and root is the consent window, which
/// names the requester, and the nod, which a remote shell cannot produce.
///
/// `pidfd`, when the kernel gives one (SO_PEERPIDFD), is checked after the
/// reads: a caller that exits before its /proc is read is not local.
pub(super) fn locality(
    pid: i32,
    pidfd: Option<&std::os::fd::OwnedFd>,
    target_user: &str,
) -> Locality {
    match locality_inner(&LiveProcs, pid, target_user) {
        Ok(Locality::Local(agent)) => match pidfd {
            // The /proc reads above were of a live process only if it is
            // still the same process now; without a pidfd to prove that,
            // a reused pid could have been laundered into local.
            None => Locality::Remote("no peer pidfd to pin the caller".into()),
            Some(fd) if process_exited(fd) => {
                Locality::Remote("caller exited before it could be verified".into())
            }
            Some(_) => Locality::Local(agent),
        },
        Ok(l) => l,
        Err(e) => Locality::Remote(format!("cannot verify the caller: {}", e)),
    }
}

/// What the locality check reads: /proc and logind for the daemon, a table
/// for the tests.
pub(crate) trait ProcView {
    fn ppid(&self, pid: i32) -> Option<i32>;
    fn comm(&self, pid: i32) -> String;
    fn real_uid(&self, pid: i32) -> Option<u32>;
    /// The cgroup listing as `/proc/<pid>/cgroup` prints it.
    fn cgroup(&self, pid: i32) -> Option<String>;
    /// The pidfs inode of a live process (what systemd writes into a
    /// socket-activated instance name); None when the process is gone.
    fn pidfd_id(&self, pid: i32) -> Option<u64>;
    fn user_uid(&self, name: &str) -> Option<u32>;
    /// logind's session ids for a uid, whitespace separated.
    fn user_sessions(&self, uid: u32) -> Result<String>;
    /// logind's view of a session: (uid, remote, seat, class).
    fn session(&self, id: &str) -> Result<(Option<u32>, bool, String, String)>;
    /// logind's Type and Active for a session ("wayland", true).
    fn session_kind(&self, id: &str) -> Result<(String, bool)>;
}

/// Does the user have a graphical session that is in the foreground on its
/// seat right now? That is where the window goes; anywhere else it cannot
/// be seen or nodded at.
pub(super) fn active_graphical_session(v: &dyn ProcView, uid: u32) -> bool {
    let Ok(sessions) = v.user_sessions(uid) else {
        return false;
    };
    for id in sessions.split_whitespace() {
        if let Ok((kind, active)) = v.session_kind(id) {
            if active && (kind == "wayland" || kind == "x11") {
                return true;
            }
        }
    }
    false
}

pub(super) struct LiveProcs;

/// A pidfd for a live process, or None when it is gone.
pub(super) fn pidfd_open(pid: i32) -> Option<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if raw < 0 {
        return None;
    }
    Some(unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as i32) })
}

impl ProcView for LiveProcs {
    fn ppid(&self, pid: i32) -> Option<i32> {
        crate::consent::ppid_of(pid)
    }
    fn comm(&self, pid: i32) -> String {
        crate::consent::comm_of(pid)
    }
    fn real_uid(&self, pid: i32) -> Option<u32> {
        crate::consent::real_uid_of(pid)
    }
    fn cgroup(&self, pid: i32) -> Option<String> {
        crate::consent::read_proc(pid, "cgroup")
    }
    fn pidfd_id(&self, pid: i32) -> Option<u64> {
        nix::sys::stat::fstat(&pidfd_open(pid)?)
            .ok()
            .map(|st| st.st_ino)
    }
    fn user_uid(&self, name: &str) -> Option<u32> {
        user_uid(name)
    }
    fn user_sessions(&self, uid: u32) -> Result<String> {
        loginctl(&["show-user", &uid.to_string(), "-p", "Sessions", "--value"])
    }
    fn session(&self, id: &str) -> Result<(Option<u32>, bool, String, String)> {
        let out = loginctl(&[
            "show-session",
            id,
            "-p",
            "User",
            "-p",
            "Remote",
            "-p",
            "Seat",
            "-p",
            "Class",
        ])?;
        let get = |k: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
                .unwrap_or("")
                .trim()
                .to_string()
        };
        Ok((
            get("User").parse().ok(),
            get("Remote") != "no",
            get("Seat"),
            get("Class"),
        ))
    }
    fn session_kind(&self, id: &str) -> Result<(String, bool)> {
        let out = loginctl(&["show-session", id, "-p", "Type", "-p", "Active"])?;
        let get = |k: &str| {
            out.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
                .unwrap_or("")
                .trim()
                .to_string()
        };
        Ok((get("Type"), get("Active") == "yes"))
    }
}

fn locality_inner(v: &dyn ProcView, pid: i32, target_user: &str) -> Result<Locality> {
    locality_of(v, pid, target_user, false)
}

fn locality_of(
    v: &dyn ProcView,
    pid: i32,
    target_user: &str,
    via_helper: bool,
) -> Result<Locality> {
    // 1. Ancestry. The chain must reach init; a break means the caller (or a
    // parent) vanished mid-read, which is not a demonstration of anything.
    let mut p = pid;
    let mut reached_init = false;
    for _ in 0..128 {
        let pp = v
            .ppid(p)
            .ok_or_else(|| anyhow::anyhow!("process {} unreadable", p))?;
        if pp <= 1 {
            reached_init = true;
            break;
        }
        let comm = v.comm(pp);
        if is_ssh_comm(&comm) {
            return Ok(Locality::Remote(format!(
                "started under {} (pid {})",
                comm, pp
            )));
        }
        p = pp;
    }
    if !reached_init {
        // A chain deeper than any real desktop's is not something this
        // check has looked all the way through; it does not vouch for it.
        return Ok(Locality::Remote(
            "ancestry deeper than 128 without reaching init".into(),
        ));
    }
    let real_uid = v
        .real_uid(pid)
        .ok_or_else(|| anyhow::anyhow!("no uid for process {}", pid))?;
    let cgroup = v
        .cgroup(pid)
        .ok_or_else(|| anyhow::anyhow!("no cgroup for process {}", pid))?;
    let path = cgroup
        .lines()
        .find_map(|l| l.splitn(3, ':').nth(2))
        .ok_or_else(|| anyhow::anyhow!("no cgroup path"))?
        .to_string();
    let target_uid = v
        .user_uid(target_user)
        .ok_or_else(|| anyhow::anyhow!("unknown user {}", target_user))?;
    // 2. Root's services: only polkit's helper, and only through to the
    // agent that connected it.
    if real_uid == 0 && path.starts_with("/system.slice/") {
        let unit = path.trim().rsplit('/').next().unwrap_or("").to_string();
        let Some(instance) = polkit_helper_instance(&unit) else {
            return Ok(Locality::Remote(format!(
                "root service {} is not a session",
                unit
            )));
        };
        if via_helper {
            return Ok(Locality::Remote(
                "a polkit helper connected by another polkit helper".into(),
            ));
        }
        let Some((agent, id)) = helper_peer(instance) else {
            return Ok(Locality::Remote(format!(
                "polkit helper instance {} does not name its agent",
                instance
            )));
        };
        let Some(id) = id else {
            return Ok(Locality::Remote(format!(
                "polkit helper instance {} carries no pidfd id to pin its agent",
                instance
            )));
        };
        if v.pidfd_id(agent) != Some(id) {
            return Ok(Locality::Remote(format!(
                "the agent (pid {}) that connected polkit helper {} is gone",
                agent, instance
            )));
        }
        log::debug!(
            "locality: polkit helper {} was connected by agent pid {}; checking the agent",
            instance,
            agent
        );
        return match locality_of(v, agent, target_user, true)? {
            Locality::Local(_) => Ok(Locality::Local(Some(crate::consent::AgentPeer {
                pid: agent,
                id,
            }))),
            Locality::Remote(why) => Ok(Locality::Remote(format!(
                "polkit agent pid {}: {}",
                agent, why
            ))),
        };
    }
    // 3. A logind session of its own, which must be the target user's.
    if let Some(id) = session_id_from_cgroup(&cgroup) {
        let (uid, remote, seat, class) = v.session(&id)?;
        if uid != Some(target_uid) {
            return Ok(Locality::Remote(format!(
                "logind session {} is not {}'s",
                id, target_user
            )));
        }
        return Ok(match !remote && !seat.is_empty() && class == "user" {
            true => Locality::Local(None),
            false => Locality::Remote(format!("logind session {} is remote or seatless", id)),
        });
    }
    // 4. The target user's manager.
    if path.starts_with(&format!(
        "/user.slice/user-{}.slice/user@{}.service/",
        target_uid, target_uid
    )) {
        let sessions = v.user_sessions(target_uid)?;
        for id in sessions.split_whitespace() {
            match v.session(id) {
                Ok((_, remote, seat, class)) if !remote && !seat.is_empty() && class == "user" => {
                    return Ok(Locality::Local(None))
                }
                Ok(_) => {}
                // A session in the list that logind no longer knows: the
                // daemon's own `systemd-run --machine` calls (a notice, the
                // window) each open a session for an instant, and a request
                // arriving in that instant (sudo's retry) lists it. It says
                // nothing about the caller; the other sessions do.
                Err(e) if e.to_string().contains("known") => {
                    log::debug!("locality: session {} vanished while checking: {}", id, e)
                }
                Err(e) => return Err(e),
            }
        }
        return Ok(Locality::Remote(format!(
            "{} has no local session on a seat",
            target_user
        )));
    }
    Ok(Locality::Remote(format!(
        "caller in {} is not a session of {}",
        path.trim(),
        target_user
    )))
}

/// The instance of a `polkit-agent-helper@<instance>.service` unit name.
fn polkit_helper_instance(unit: &str) -> Option<&str> {
    unit.strip_prefix("polkit-agent-helper@")?
        .strip_suffix(".service")
        .filter(|i| !i.is_empty())
}

/// The peer systemd wrote into a socket-activated instance name,
/// `<n>-<cookie>-<pid>_<pidfd id>-<uid>` (or `<n>-<cookie>-<pid>-<uid>` from
/// a systemd without pidfd ids): the pid and the id. Anything else is None.
fn helper_peer(instance: &str) -> Option<(i32, Option<u64>)> {
    let parts: Vec<&str> = instance.split('-').collect();
    if parts.len() != 4 || !parts.iter().all(|p| !p.is_empty()) {
        return None;
    }
    parts[0].parse::<u64>().ok()?;
    parts[1].parse::<u64>().ok()?;
    parts[3].parse::<u32>().ok()?;
    match parts[2].split_once('_') {
        Some((pid, id)) => Some((pid.parse().ok()?, Some(id.parse().ok()?))),
        None => Some((parts[2].parse().ok()?, None)),
    }
}

fn loginctl(args: &[&str]) -> Result<String> {
    let out = std::process::Command::new("/usr/bin/timeout")
        .args(["-k", "2", "5", "/usr/bin/loginctl"])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .context("run loginctl")?;
    if !out.status.success() {
        bail!(
            "loginctl {}: {} {}",
            args.join(" "),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// A pidfd polls readable once its process has exited.
fn process_exited(fd: &std::os::fd::OwnedFd) -> bool {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
    match poll(&mut fds, PollTimeout::ZERO) {
        Ok(n) if n > 0 => true,
        Ok(_) => false,
        Err(_) => true,
    }
}

/// OpenSSH's per-connection processes: `sshd` up to 9.7, `sshd-session`
/// from 9.8 (and `sshd-auth` during authentication, never an ancestor of a
/// shell, listed for completeness).
fn is_ssh_comm(comm: &str) -> bool {
    matches!(comm.trim(), "sshd" | "sshd-session" | "sshd-auth")
}

/// The logind session id from a cgroup listing (`session-3.scope`,
/// `session-c1.scope`), if the process is directly in one. Only the
/// canonical position counts: `/user.slice/user-<uid>.slice/session-<id>.scope`
/// and nothing below it. The user's own manager (`user@<uid>.service`) is
/// delegated, so a component of that name anywhere under it is the user's
/// to create; it names nothing (F8).
fn session_id_from_cgroup(cgroup: &str) -> Option<String> {
    let path = cgroup.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
    let parts: Vec<&str> = path.split('/').collect();
    let ["", "user.slice", slice, scope] = parts.as_slice() else {
        return None;
    };
    let uid = slice.strip_prefix("user-")?.strip_suffix(".slice")?;
    if uid.is_empty() || !uid.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let id = scope.strip_prefix("session-")?.strip_suffix(".scope")?;
    if id.is_empty() || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(id.to_string())
}

#[cfg(test)]
mod locality_tests {
    use super::*;

    #[test]
    fn ssh_process_names() {
        assert!(is_ssh_comm("sshd"));
        assert!(is_ssh_comm("sshd-session"));
        assert!(!is_ssh_comm("bash"));
        assert!(!is_ssh_comm("sshd-agent"));
    }

    #[test]
    fn session_ids_from_cgroups() {
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/user-1000.slice/session-3.scope\n"),
            Some("3".into())
        );
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/user-1000.slice/session-c1.scope"),
            Some("c1".into())
        );
        // The desktop's app scope and systemd-run --user: no logind session of their own.
        assert_eq!(session_id_from_cgroup("0::/user.slice/user-1000.slice/user@1000.service/app.slice/app-graphical.slice/app-Hyprland-xdg\\x2dterminal\\x2dexec-af100da6.scope"), None);
        assert_eq!(session_id_from_cgroup("0::/user.slice/user-1000.slice/user@1000.service/app.slice/run-p193148-i205978.service"), None);
        assert_eq!(
            session_id_from_cgroup("0::/system.slice/faceauth.service"),
            None
        );
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/session-.scope"),
            None
        );
    }

    /// A session-shaped component the user made inside their delegated
    /// manager names no session; only the canonical position does (F8,
    /// poc_authz_2 inverted).
    #[test]
    fn a_forged_session_component_under_the_user_manager_names_nothing() {
        assert_eq!(
            session_id_from_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/session-c1.scope/evil\n"
            ),
            None
        );
        assert_eq!(
            session_id_from_cgroup(
                "0::/user.slice/user-1000.slice/user@1000.service/session-c1.scope\n"
            ),
            None
        );
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/user-1000.slice/session-3.scope/sub\n"),
            None,
            "nothing below the scope either"
        );
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/session-3.scope\n"),
            None
        );
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/user-x.slice/session-3.scope\n"),
            None
        );
        assert_eq!(
            session_id_from_cgroup("1:name=systemd:/user.slice/user-1000.slice/session-3.scope\n"),
            None,
            "only the unified hierarchy line"
        );
        assert_eq!(
            session_id_from_cgroup("0::/user.slice/user-1000.slice/session-3.scope\n"),
            Some("3".into())
        );
    }

    /// A process table the check reads instead of /proc and logind.
    struct Table {
        procs: std::collections::HashMap<i32, (i32, &'static str, u32, &'static str, Option<u64>)>,
        sessions: std::collections::HashMap<
            &'static str,
            (Option<u32>, bool, &'static str, &'static str),
        >,
        kinds: std::collections::HashMap<&'static str, (&'static str, bool)>,
        user_sessions: &'static str,
    }

    impl Table {
        fn new() -> Table {
            let mut t = Table {
                procs: Default::default(),
                sessions: Default::default(),
                kinds: Default::default(),
                user_sessions: "3",
            };
            t.kinds.insert("3", ("wayland", true));
            t.kinds.insert("7", ("tty", false));
            t.kinds.insert("9", ("tty", true));
            t.sessions.insert("3", (Some(1000), false, "seat0", "user"));
            t.sessions.insert("7", (Some(1000), true, "", "user"));
            t.sessions.insert("9", (Some(1001), false, "seat0", "user"));
            t.procs
                .insert(1, (0, "systemd", 0, "0::/init.scope\n", Some(1)));
            t
        }
        fn add(
            &mut self,
            pid: i32,
            ppid: i32,
            comm: &'static str,
            uid: u32,
            cgroup: &'static str,
        ) -> &mut Table {
            self.procs
                .insert(pid, (ppid, comm, uid, cgroup, Some(pid as u64 * 10)));
            self
        }
    }

    impl ProcView for Table {
        fn ppid(&self, pid: i32) -> Option<i32> {
            self.procs.get(&pid).map(|p| p.0)
        }
        fn comm(&self, pid: i32) -> String {
            self.procs
                .get(&pid)
                .map(|p| p.1.to_string())
                .unwrap_or_default()
        }
        fn real_uid(&self, pid: i32) -> Option<u32> {
            self.procs.get(&pid).map(|p| p.2)
        }
        fn cgroup(&self, pid: i32) -> Option<String> {
            self.procs.get(&pid).map(|p| p.3.to_string())
        }
        fn pidfd_id(&self, pid: i32) -> Option<u64> {
            self.procs.get(&pid).and_then(|p| p.4)
        }
        fn user_uid(&self, name: &str) -> Option<u32> {
            match name {
                "mike" => Some(1000),
                "other" => Some(1001),
                _ => None,
            }
        }
        fn user_sessions(&self, _uid: u32) -> Result<String> {
            Ok(self.user_sessions.to_string())
        }
        fn session(&self, id: &str) -> Result<(Option<u32>, bool, String, String)> {
            self.sessions
                .get(id)
                .map(|s| (s.0, s.1, s.2.to_string(), s.3.to_string()))
                .ok_or_else(|| anyhow::anyhow!("No session '{}' known", id))
        }
        fn session_kind(&self, id: &str) -> Result<(String, bool)> {
            self.kinds
                .get(id)
                .map(|k| (k.0.to_string(), k.1))
                .ok_or_else(|| anyhow::anyhow!("No session '{}' known", id))
        }
    }

    /// The window can only be answered in a graphical session that is in
    /// the foreground on its seat (B2).
    #[test]
    fn a_window_needs_an_active_graphical_session() {
        let mut t = Table::new();
        assert!(active_graphical_session(&t, 1000));
        // The desktop is on another VT while a text console is in front.
        t.kinds.insert("3", ("wayland", false));
        t.user_sessions = "3 9";
        assert!(!active_graphical_session(&t, 1000));
        // Only a tty session at all.
        t.user_sessions = "9";
        assert!(!active_graphical_session(&t, 1000));
        t.user_sessions = "";
        assert!(!active_graphical_session(&t, 1000));
    }

    const HELPER: &str = "0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@306-8263-500_5000-1000.service\n";

    const SHELL: &str = "0::/user.slice/user-1000.slice/user@1000.service/session.slice/wayland-wm@hyprland.desktop.service\n";

    const SSH: &str = "0::/user.slice/user-1000.slice/session-7.scope\n";

    fn remote(r: Result<Locality>) -> String {
        match r.unwrap() {
            Locality::Remote(why) => why,
            Locality::Local(_) => panic!("expected remote"),
        }
    }

    /// The desktop case: the helper's agent is the shell in the user's session.
    #[test]
    fn a_polkit_helper_is_as_local_as_the_agent_that_connected_it() {
        let mut t = Table::new();
        t.add(500, 1, "quickshell", 1000, SHELL)
            .add(600, 1, "polkit-agent-he", 0, HELPER);
        match locality_inner(&t, 600, "mike").unwrap() {
            Locality::Local(agent) => assert_eq!(
                agent,
                Some(crate::consent::AgentPeer { pid: 500, id: 5000 })
            ),
            Locality::Remote(why) => panic!("{}", why),
        }
    }

    /// pkexec over SSH registers its own text agent inside the SSH session;
    /// the helper it connects must not be local (A1).
    #[test]
    fn a_polkit_helper_connected_from_an_ssh_session_is_remote() {
        let mut t = Table::new();
        t.add(400, 1, "sshd-session", 1000, SSH)
            .add(500, 400, "pkexec", 0, SSH)
            .add(600, 1, "polkit-agent-he", 0, HELPER);
        let why = remote(locality_inner(&t, 600, "mike"));
        assert!(
            why.contains("agent pid 500") && why.contains("sshd-session"),
            "{}",
            why
        );
    }

    /// The agent named by the instance is pinned by its pidfd id: a reused
    /// pid, a gone agent, or an instance without the id is not followed.
    #[test]
    fn a_polkit_helper_whose_agent_cannot_be_pinned_is_remote() {
        let mut t = Table::new();
        t.add(600, 1, "polkit-agent-he", 0, HELPER);
        assert!(remote(locality_inner(&t, 600, "mike")).contains("is gone"));
        t.add(500, 1, "quickshell", 1000, SHELL);
        t.procs.get_mut(&500).unwrap().4 = Some(5001);
        assert!(remote(locality_inner(&t, 600, "mike")).contains("is gone"));
        t.add(601, 1, "polkit-agent-he", 0, "0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@306-8263-500-1000.service\n");
        assert!(remote(locality_inner(&t, 601, "mike")).contains("no pidfd id"));
        t.add(602, 1, "polkit-agent-he", 0, "0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@garbage.service\n");
        assert!(remote(locality_inner(&t, 602, "mike")).contains("does not name its agent"));
    }

    /// Root in system.slice is no longer local on its own.
    #[test]
    fn a_root_service_that_is_not_the_polkit_helper_is_remote() {
        let mut t = Table::new();
        t.add(700, 1, "cron", 0, "0::/system.slice/cronie.service\n");
        assert!(remote(locality_inner(&t, 700, "mike")).contains("not a session"));
    }

    /// A session scope is local only when it is the target user's session.
    #[test]
    fn another_users_seated_session_is_not_local_for_the_target_user() {
        let mut t = Table::new();
        t.add(
            800,
            1,
            "sudo",
            1001,
            "0::/user.slice/user-1001.slice/session-9.scope\n",
        );
        assert!(matches!(
            locality_inner(&t, 800, "other").unwrap(),
            Locality::Local(None)
        ));
        assert!(remote(locality_inner(&t, 800, "mike")).contains("not mike's"));
    }

    #[test]
    fn helper_instance_names_are_parsed_strictly() {
        assert_eq!(
            helper_peer("306-8263-3747358_3757126-1000"),
            Some((3747358, Some(3757126)))
        );
        assert_eq!(helper_peer("23-1-42-0"), Some((42, None)));
        assert_eq!(helper_peer("23"), None);
        assert_eq!(helper_peer("a-b-c-d"), None);
        assert_eq!(helper_peer("306-8263-3747358_x-1000"), None);
        assert_eq!(
            polkit_helper_instance("polkit-agent-helper@23.service"),
            Some("23")
        );
        assert_eq!(polkit_helper_instance("polkit.service"), None);
    }

    #[test]
    fn a_caller_without_a_pidfd_is_not_local() {
        let me = std::env::var("USER").unwrap_or_else(|_| "root".into());
        match locality(std::process::id() as i32, None, &me) {
            Locality::Remote(why) => assert!(why.contains("pidfd"), "{}", why),
            Locality::Local(_) => panic!("no pidfd must not be local"),
        }
    }

    #[test]
    fn a_vanished_caller_is_not_local() {
        // A pid that cannot exist: every read fails, and failure is remote.
        match locality(i32::MAX - 1, None, "root") {
            Locality::Remote(why) => assert!(why.contains("cannot verify"), "{}", why),
            Locality::Local(_) => panic!("an unreadable caller must not be local"),
        }
    }

    #[test]
    fn a_process_that_exited_is_not_local() {
        use std::os::fd::FromRawFd;
        let child = std::process::Command::new("/bin/true").spawn().unwrap();
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) };
        assert!(raw >= 0, "pidfd_open");
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as i32) };
        let mut child = child;
        child.wait().unwrap();
        assert!(process_exited(&fd));
    }

    /// This test process is local when the developer is at the machine and
    /// remote over SSH; either way the answer must be the true one.
    #[test]
    fn this_test_process_is_classified() {
        let me = std::env::var("USER").unwrap_or_else(|_| "root".into());
        // With a pidfd of this very process, as the daemon would hold for a peer.
        use std::os::fd::FromRawFd;
        let raw =
            unsafe { libc::syscall(libc::SYS_pidfd_open, std::process::id() as libc::pid_t, 0) };
        assert!(raw >= 0, "pidfd_open");
        let fd = unsafe { std::os::fd::OwnedFd::from_raw_fd(raw as i32) };
        let r = locality(std::process::id() as i32, Some(&fd), &me);
        if std::env::var_os("SSH_CONNECTION").is_some() {
            assert!(
                matches!(r, Locality::Remote(_)),
                "running over SSH should be remote"
            );
        } else if std::path::Path::new("/run/systemd/seats/seat0").exists() {
            match r {
                Locality::Local(_) => {}
                Locality::Remote(why) => panic!("a shell on the console should be local: {}", why),
            }
        }
    }
}
