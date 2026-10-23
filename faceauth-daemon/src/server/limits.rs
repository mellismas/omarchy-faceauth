//! The connection places, counted the way systemd counts a socket's
//! (`MaxConnections=`, `MaxConnectionsPerSource=`; round 7, C): one limit
//! for the daemon, and one per source, so one account filling its share
//! leaves the rest theirs. A source is the account behind the peer: a
//! user peer's uid; for root, the account it acts for (sudo's, where its
//! login uid, its real uid and its cgroup's user slice agree, read
//! through a pidfd; polkit's socket-activated helper's connecting uid,
//! from its systemd instance name); and a small share of its own for root
//! that cannot be attributed. The lock screen's reserved channel
//! (`server/channel.rs`) sits outside both.

use std::sync::Mutex;

/// Where a connection's place is charged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum Source {
    /// An account: a user peer, or root acting for that user.
    User(u32),
    /// Root that cannot be attributed to an account.
    Root,
}

impl Source {
    /// The account's uid; None for unattributed root.
    pub(crate) fn into_uid(self) -> Option<u32> {
        match self {
            Source::User(uid) => Some(uid),
            Source::Root => None,
        }
    }
}

impl std::fmt::Display for Source {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Source::User(uid) => write!(f, "uid {}", uid),
            Source::Root => f.write_str("unattributed root"),
        }
    }
}

/// The least any one account gets, whatever the daemon's limit and the
/// number of enrolled users: the most places one normal session holds at
/// once, counted (design note, "Connection limits"): the lock screen's
/// look, key unlock, key-lane check-in and face probe (4), a consent card's
/// window answers (1), sudo's and polkit's consent admissions and their
/// key lines' asks and checks (4), the bar's presence probe (1), doctor (1),
/// an enrollment window (1): 12, rounded up to 16 for bursts. Provisional:
/// Mike measures it at the live test.
pub(crate) const PER_SOURCE_FLOOR: usize = 16;

/// Unattributed root's own share.
pub(crate) const ROOT_SHARE: usize = 4;

/// The per-source limit: the configured one, or the daemon's limit split
/// over the enrolled users, never under `PER_SOURCE_FLOOR`, never over
/// the daemon's limit.
pub(crate) fn per_source_limit(max: usize, configured: Option<usize>, enrolled: usize) -> usize {
    configured
        .unwrap_or_else(|| (max / enrolled.max(1)).max(PER_SOURCE_FLOOR))
        .min(max)
        .max(1)
}

/// The account a connection is charged to. `uid` is the peer's from
/// SO_PEERCRED; for root, `cgroup`, `comm`, `loginuid` and `ruid` (its real
/// uid) are what /proc says of the peer, and `alive` whether its pidfd
/// still names that process after they were read, so a recycled pid
/// cannot lend its account.
///
/// polkit's helper is charged to the uid systemd wrote into its instance
/// name, where `lockgate::polkit_helper_instance` believes it: in the
/// system manager's own helper slice (fix round 13, Codex 5; a unit of a
/// user's own may carry any name, and a real sudo run in it would charge
/// the uid the name claims), with real uid 0 and the helper's comm (fix
/// round 14: never its executable, which faceauthd cannot read).
/// Anything else is charged to its login uid only where its real
/// uid and its cgroup's `user-UID.slice` (root's to create; a process
/// cannot move itself into another account's slice) say the same account
/// (round 8, Codex 7): a process whose login uid is unset may set it to
/// any uid with no privilege at all (kernel/audit.c,
/// `audit_set_loginuid_perm`, "if we are unset, we don't need privs", on
/// a write to its own /proc/self/loginuid, fs/proc/base.c,
/// `proc_loginuid_write`), and sudo inherits it. Anything less is charged
/// the stricter way, to unattributed root's small share, so no process
/// picks the share it is charged to.
pub(crate) fn attribute(
    uid: u32,
    cgroup: Option<&str>,
    comm: Option<&str>,
    loginuid: Option<&str>,
    ruid: Option<u32>,
    alive: bool,
) -> Source {
    if uid != 0 {
        return Source::User(uid);
    }
    if !alive {
        return Source::Root;
    }
    let signs = crate::lockgate::HelperSigns { ruid, comm };
    if let Some(u) = cgroup.and_then(|c| crate::lockgate::polkit_instance_uid(c, signs)) {
        return Source::User(u);
    }
    // 4294967295 is "no login uid": root that never logged in.
    let login = loginuid
        .map(str::trim)
        .and_then(|l| l.parse::<u32>().ok())
        .filter(|&u| u != u32::MAX && u != 0);
    let slice = cgroup.and_then(slice_uid);
    match (login, ruid, slice) {
        (Some(l), Some(r), Some(s)) if l == r && r == s => Source::User(l),
        _ => Source::Root,
    }
}

/// The account of the `user-UID.slice` a cgroup listing sits under.
pub(crate) fn slice_uid(cgroup: &str) -> Option<u32> {
    cgroup
        .lines()
        .flat_map(|l| l.rsplit(':').next().unwrap_or("").split('/'))
        .find_map(|c| {
            c.strip_prefix("user-")?
                .strip_suffix(".slice")?
                .parse()
                .ok()
        })
}

/// The real uid in a /proc/PID/status text (its `Uid:` line's first field).
pub(crate) fn real_uid(status: &str) -> Option<u32> {
    status
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Which limit refused a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Full {
    /// The daemon's own limit: every user is latched for a hold.
    Total,
    /// The source's share: only that account is latched.
    Source,
}

/// The places taken now, in all and by source.
pub(crate) struct Places {
    taken: Mutex<(usize, Vec<(Source, usize)>)>,
}

impl Places {
    pub(crate) const fn new() -> Self {
        Places {
            taken: Mutex::new((0, Vec::new())),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, (usize, Vec<(Source, usize)>)> {
        self.taken.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Take a place for `source` under `total` and `share`, or say which
    /// limit is full.
    pub(crate) fn take(&self, source: Source, total: usize, share: usize) -> Result<(), Full> {
        let mut t = self.lock();
        if t.0 >= total {
            return Err(Full::Total);
        }
        let mine =
            t.1.iter()
                .find(|(s, _)| *s == source)
                .map_or(0, |(_, n)| *n);
        if mine >= share {
            return Err(Full::Source);
        }
        t.0 += 1;
        match t.1.iter_mut().find(|(s, _)| *s == source) {
            Some((_, n)) => *n += 1,
            None => t.1.push((source, 1)),
        }
        Ok(())
    }

    /// Give a place back.
    pub(crate) fn give(&self, source: Source) {
        let mut t = self.lock();
        t.0 = t.0.saturating_sub(1);
        if let Some((_, n)) = t.1.iter_mut().find(|(s, _)| *s == source) {
            *n = n.saturating_sub(1);
        }
        t.1.retain(|(_, n)| *n > 0);
    }

    /// Places taken: in all, and by `source`.
    #[cfg(test)]
    pub(crate) fn taken(&self, source: Source) -> (usize, usize) {
        let t = self.lock();
        (
            t.0,
            t.1.iter()
                .find(|(s, _)| *s == source)
                .map_or(0, |(_, n)| *n),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// polkit's helper's comm, and sudo's.
    fn helper() -> Option<&'static str> {
        Some(crate::lockgate::POLKIT_HELPER_COMM)
    }
    fn sudo() -> Option<&'static str> {
        Some("sudo")
    }

    /// Round 7 (C): the per-source share is the daemon's limit over the
    /// enrolled users, recomputed as they change, never under the floor
    /// nor over the limit; a configured share wins.
    #[test]
    fn the_share_is_the_limit_over_the_enrolled_users_with_a_floor() {
        assert_eq!(per_source_limit(64, None, 0), 64);
        assert_eq!(per_source_limit(64, None, 1), 64);
        assert_eq!(per_source_limit(64, None, 2), 32);
        assert_eq!(per_source_limit(64, None, 4), PER_SOURCE_FLOOR);
        assert_eq!(
            per_source_limit(64, None, 10),
            PER_SOURCE_FLOOR,
            "the floor"
        );
        assert_eq!(per_source_limit(8, None, 1), 8, "never over the limit");
        assert_eq!(
            per_source_limit(64, Some(10), 1),
            10,
            "a configured share wins"
        );
        assert_eq!(per_source_limit(64, Some(100), 1), 64);
        assert_eq!(per_source_limit(64, Some(0), 1), 1);
    }

    /// Round 7 (C): a connection is charged to the account behind it: a
    /// user peer's uid; root acting for a user, by sudo's login uid or by
    /// polkit's helper instance (its format checked against systemd's
    /// `instance_from_socket`); root that cannot be attributed, or whose
    /// process changed under the reads, to a share of its own.
    #[test]
    fn a_connection_is_charged_to_the_account_behind_it() {
        assert_eq!(
            attribute(1000, None, None, None, None, true),
            Source::User(1000)
        );
        assert_eq!(
            attribute(
                0,
                Some("0::/user.slice/user-1000.slice/session-3.scope\n"),
                sudo(),
                Some("1000"),
                Some(1000),
                true
            ),
            Source::User(1000),
            "sudo"
        );
        let helper = "0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@1-4114-1410496_1411230-1000.service\n";
        assert_eq!(
            attribute(
                0,
                Some(helper),
                self::helper(),
                Some("4294967295"),
                Some(0),
                true
            ),
            Source::User(1000),
            "polkit's helper"
        );
        let old = "0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@7-4114-1410496-1001.service\n";
        assert_eq!(
            attribute(0, Some(old), self::helper(), None, Some(0), true),
            Source::User(1001),
            "without pidfd ids"
        );
        let unknown = "0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@7-4114-unknown.service\n";
        assert_eq!(
            attribute(
                0,
                Some(unknown),
                self::helper(),
                Some("4294967295"),
                Some(0),
                true
            ),
            Source::Root
        );
        assert_eq!(
            attribute(
                0,
                Some("0::/system.slice/cron.service\n"),
                None,
                Some("4294967295"),
                None,
                true
            ),
            Source::Root,
            "no login uid"
        );
        assert_eq!(
            attribute(0, None, None, Some("0"), None, true),
            Source::Root,
            "root's own login"
        );
        assert_eq!(
            attribute(
                0,
                Some(helper),
                self::helper(),
                Some("1000"),
                Some(0),
                false
            ),
            Source::Root,
            "the process changed under the reads"
        );
        assert_eq!(
            attribute(0, None, None, Some("garbage"), None, true),
            Source::Root
        );
        assert_eq!(
            crate::lockgate::polkit_instance_uid(
                "0::/system.slice/polkit-agent-helper@1-2-3_4-5-6.service\n",
                crate::lockgate::HelperSigns {
                    ruid: Some(0),
                    comm: self::helper()
                }
            ),
            None
        );
    }

    /// Round 8 (Codex 7): the login uid is corroborated. A process whose
    /// login uid is unset may set it to any uid with no privilege at all
    /// (kernel/audit.c, `audit_set_loginuid_perm`: "if we are unset, we
    /// don't need privs"; written through its own /proc/self/loginuid,
    /// fs/proc/base.c, `proc_loginuid_write`), and sudo inherits it. So it
    /// is believed only where the peer's real uid and its root-owned
    /// cgroup slice name the same account; anything less is charged the
    /// stricter way, to unattributed root's small share: never to the
    /// account the login uid names, and not to the process's own larger
    /// share either.
    #[test]
    fn a_forged_login_uid_never_picks_the_account_charged() {
        let s1001 = Some("0::/user.slice/user-1001.slice/session-4.scope\n");
        assert_eq!(
            attribute(0, s1001, sudo(), Some("1001"), Some(1001), true),
            Source::User(1001)
        );
        assert_eq!(
            attribute(0, s1001, sudo(), Some("1000"), Some(1001), true),
            Source::Root,
            "a forged login uid: not the victim's share"
        );
        assert_eq!(
            attribute(0, s1001, sudo(), Some("4294967295"), Some(1001), true),
            Source::Root,
            "no login uid to corroborate"
        );
        assert_eq!(
            attribute(
                0,
                Some("0::/system.slice/foo.service\n"),
                sudo(),
                Some("1000"),
                Some(1000),
                true
            ),
            Source::Root,
            "no slice to corroborate it"
        );
        assert_eq!(
            attribute(0, s1001, sudo(), Some("1001"), Some(1000), true),
            Source::Root,
            "the real uid disagrees"
        );
        assert_eq!(
            attribute(0, s1001, sudo(), Some("1001"), None, true),
            Source::Root,
            "no real uid"
        );
        assert_eq!(
            slice_uid("0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope\n"),
            Some(1000)
        );
        assert_eq!(slice_uid("0::/system.slice/cron.service\n"), None);
        assert_eq!(real_uid("Name:\tsudo\nUid:\t1000\t0\t0\t0\n"), Some(1000));
        assert_eq!(real_uid("Name:\tsudo\n"), None);
    }

    /// Fix round 13 (Codex 5): polkit's helper is believed only in the
    /// hierarchy the system manager gives it. A unit of the user's own,
    /// named as a helper instance (any name goes in a user manager), with
    /// a real sudo running in it, is charged by sudo's rules to the user,
    /// never to the uid its name claims; so is one under a slice the user
    /// named as the helpers' own.
    #[test]
    fn a_unit_named_as_polkits_helper_is_not_believed() {
        let forged = "0::/user.slice/user-1000.slice/user@1000.service/app.slice/polkit-agent-helper@1-2-3_4-1001.service\n";
        assert_eq!(
            attribute(0, Some(forged), sudo(), Some("1000"), Some(1000), true),
            Source::User(1000),
            "sudo in a unit of the user's: the user's own"
        );
        assert_eq!(
            attribute(0, Some(forged), helper(), Some("1000"), Some(0), true),
            Source::Root,
            "root there with the helper's comm (sudo, then renamed): the cgroup is not the helper's"
        );
        let nested = "0::/user.slice/user-1000.slice/user@1000.service/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@1-2-3_4-1001.service\n";
        assert_eq!(
            attribute(0, Some(nested), sudo(), Some("1000"), Some(1000), true),
            Source::User(1000),
            "the helpers' slice inside the user's own tree"
        );
        assert_eq!(
            attribute(0, Some(nested), helper(), Some("1000"), Some(0), true),
            Source::Root,
            "root with the helper's comm in that slice: still not the helper's"
        );
        let real = "0::/system.slice/system-polkit\\x2dagent\\x2dhelper.slice/polkit-agent-helper@1-2-3_4-1001.service\n";
        assert_eq!(
            attribute(0, Some(real), helper(), None, Some(0), true),
            Source::User(1001),
            "polkit's helper in its own slice"
        );
        assert_eq!(
            attribute(0, Some(real), sudo(), None, Some(0), true),
            Source::Root,
            "in the helpers' slice, but not polkit's helper by its comm"
        );
        assert_eq!(
            attribute(0, Some(real), helper(), None, Some(1000), true),
            Source::Root,
            "not root"
        );
        assert_eq!(
            attribute(0, Some(real), None, None, None, true),
            Source::Root,
            "nothing read"
        );
    }

    /// Round 7 (C): the daemon's limit and each source's share are both
    /// held, and a refusal says which; places come back.
    #[test]
    fn the_limit_and_each_share_are_held() {
        let p = Places::new();
        let (a, b) = (Source::User(1000), Source::User(1001));
        for _ in 0..3 {
            assert_eq!(p.take(a, 5, 3), Ok(()));
        }
        assert_eq!(p.take(a, 5, 3), Err(Full::Source), "alice's share is full");
        assert_eq!(p.take(b, 5, 3), Ok(()), "bob still gets in");
        assert_eq!(p.take(Source::Root, 5, 1), Ok(()));
        assert_eq!(p.take(b, 5, 3), Err(Full::Total), "the daemon's limit");
        p.give(a);
        assert_eq!(p.taken(a), (4, 2));
        assert_eq!(p.take(b, 5, 3), Ok(()));
        for s in [a, a, b, b, Source::Root] {
            p.give(s);
        }
        assert_eq!(p.taken(a), (0, 0));
    }
}
