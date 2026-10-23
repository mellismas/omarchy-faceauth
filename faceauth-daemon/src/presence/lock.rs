//! Locking the session and noticing the unlock. The consent flow and the
//! watch read the same record, so a park and a resume agree on when the
//! user came back.

#[cfg(test)]
use super::config::PresenceMode;
#[cfg(test)]
use super::observe::Observation;
#[cfg(test)]
use super::test_support::{cfg, first_lock, obs};
#[cfg(test)]
use super::watch::{State, Watch};
use anyhow::Result;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// While the session is locked, every this many ticks the watch asks the
/// compositor whether it still is: a password or fingerprint unlock, which
/// leaves no face match behind, resumes the watch this way (C2).
pub const LOCK_CHECK_TICKS: u32 = 3;

/// The one session lock the daemon makes: the walk-away lock, whether
/// the presence watch or a consent request whose user left asked for it.
/// It holds the one record of when the session was locked, runs the lock
/// helper once, and answers the one question both askers have: has the
/// session unlocked since, by a face match newer than the lock or by
/// anything else the compositor reports (a password, a fingerprint)?
pub struct SessionLock {
    inner: Mutex<LockState>,
}

#[derive(Default)]
struct LockState {
    locked_at: Option<Instant>,
    /// When the compositor was last asked, so the askers share one cadence.
    last_check: Option<Instant>,
}

pub static SESSION_LOCK: SessionLock = SessionLock::new();

impl Default for SessionLock {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionLock {
    pub const fn new() -> Self {
        SessionLock {
            inner: Mutex::new(LockState {
                locked_at: None,
                last_check: None,
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, LockState> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// When the session was locked, if it is.
    pub fn locked_at(&self) -> Option<Instant> {
        self.state().locked_at
    }

    /// Lock `user`'s session with the lock helper, unless it is locked
    /// already: when it was locked. `omarchy_path` is the tree the running
    /// shell was launched from, resolved by the daemon (the helper parses
    /// nothing). The helper runs outside the lock's own mutex, so a reader
    /// is never held behind it.
    pub fn lock(&self, user: &str, omarchy_path: &str) -> Result<Instant> {
        if let Some(t) = self.locked_at() {
            return Ok(t);
        }
        // The user's card is off the key from before the lock is up, until
        // the daemon sees the unlock (`ConsentState::latch_lock_screen`).
        crate::consent::CONSENT.latch_lock_screen(user);
        let uid = nix::unistd::User::from_name(user)
            .ok()
            .flatten()
            .map(|u| u.uid.as_raw())
            .ok_or_else(|| anyhow::anyhow!("no user {}", user))?;
        // Whether the lock happened is the anchored question's to say,
        // asked of the session the lock was pinned to (fix round 9).
        let logind = std::path::Path::new("/run/systemd");
        let desktops = crate::lockgate::user_desktops(logind, uid);
        let bind = match desktops.as_slice() {
            [one] => crate::lockgate::Bind::Session(one.clone()),
            _ => crate::lockgate::Bind::OnlyDesktop,
        };
        let verify = || match crate::consent::anchored_lock_state(user, &bind) {
            crate::lockgate::LockState::Locked => LockedAnswer::Locked,
            _ => LockedAnswer::NotYet,
        };
        lock_session_at(
            logind,
            std::path::Path::new(LOCK_HELPER),
            user,
            uid,
            omarchy_path,
            &verify,
            LOCK_VERIFY,
        )?;
        Ok(self.adopt(Instant::now()))
    }

    /// The session was locked by other means (the idle lock, a key, the
    /// lid): record it, unless a lock is recorded already. When it counts
    /// from.
    pub fn adopt(&self, at: Instant) -> Instant {
        let mut st = self.state();
        *st.locked_at.get_or_insert(at)
    }

    /// Has the session unlocked since the lock? `matched` is a face match
    /// newer than the lock, which resumes at once; otherwise the
    /// compositor is asked, at most once per `check_every` across every
    /// asker. `None` while it stays locked; how it unlocked once it has,
    /// with the lock forgotten. A lock another asker already saw end
    /// reads as unlocked too.
    pub fn resumed(
        &self,
        now: Instant,
        matched: bool,
        check_every: Duration,
        session_locked: &dyn Fn() -> bool,
    ) -> Option<&'static str> {
        let mut st = self.state();
        if st.locked_at.is_none() {
            return Some("elsewhere");
        }
        if matched {
            st.locked_at = None;
            return Some("by face");
        }
        let due = st
            .last_check
            .map(|c| now.duration_since(c) >= check_every)
            .unwrap_or(true);
        if !due {
            return None;
        }
        st.last_check = Some(now);
        drop(st);
        if session_locked() {
            return None;
        }
        self.state().locked_at = None;
        Some("without a face")
    }
}

/// The lock helper the package ships, run as root with the user whose
/// session to lock, the Omarchy tree the shell was launched from, the
/// user's uid and the sessions the lock is pinned to. It runs the lock
/// inside the user's own manager, by a route that can never start one,
/// checking the pinned sessions before each call, and answers whether the
/// lock commands ran; whether the session is locked is the daemon's
/// anchored question to answer (fix round 9). An internal helper, so under
/// /usr/lib, off every PATH.
pub const LOCK_HELPER: &str = "/usr/lib/faceauth/faceauth-lock-session";

/// How long the daemon waits, after the lock commands, for the anchored
/// question to say the session is locked.
const LOCK_VERIFY: Duration = Duration::from_secs(3);

/// How long the daemon reads the lock helper before it gives it up and
/// kills what it started (fix round 10, Codex 2, Opus N4): the helper's two
/// calls into the user's manager, each under `timeout -k 1 4` with both
/// units capped at 4 s, and a moment for its own checks. The helper's
/// pipes are never read to their end, since a unit of the user's may hold
/// them.
const LOCK_HELPER_WITHIN: Duration = Duration::from_secs(11);

/// What the anchored question said of a lock just made.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LockedAnswer {
    Locked,
    NotYet,
}

/// Lock `user`'s (`uid`'s) session with `helper` (fix rounds 8 and 9).
/// Only while logind's records under `logind` show them a desktop: the
/// sessions found are pinned, handed to the helper (which checks them
/// before each call into the manager), and checked again here at every
/// look. The lock counts only once `verify`, the anchored question, says
/// locked within `within`, never on the helper's or the manager's word;
/// a pinned session gone or replaced meanwhile is no lock.
fn lock_session_at(
    logind: &std::path::Path,
    helper: &std::path::Path,
    user: &str,
    uid: u32,
    omarchy_path: &str,
    verify: &dyn Fn() -> LockedAnswer,
    within: Duration,
) -> Result<()> {
    lock_session_within(
        logind,
        helper,
        user,
        uid,
        omarchy_path,
        verify,
        within,
        LOCK_HELPER_WITHIN,
    )
}

/// `lock_session_at`, reading the helper for at most `helper_within`.
#[allow(clippy::too_many_arguments)]
fn lock_session_within(
    logind: &std::path::Path,
    helper: &std::path::Path,
    user: &str,
    uid: u32,
    omarchy_path: &str,
    verify: &dyn Fn() -> LockedAnswer,
    within: Duration,
    helper_within: Duration,
) -> Result<()> {
    let pinned = crate::lockgate::user_desktops(logind, uid);
    if pinned.is_empty() {
        anyhow::bail!(
            "{} has no graphical session; nothing is run in their manager",
            user
        );
    }
    let mut c = std::process::Command::new(helper);
    c.args([user, omarchy_path, &uid.to_string()])
        .args(&pinned)
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin");
    let o = match crate::consent::run_bounded(c, None, helper_within, 4096) {
        Ok(o) => o,
        Err(e) => anyhow::bail!("the lock helper {}", e),
    };
    if o.code != Some(0) {
        anyhow::bail!(
            "exited {:?}: {} {}",
            o.code,
            String::from_utf8_lossy(&o.out).trim(),
            String::from_utf8_lossy(&o.err).trim()
        );
    }
    let by = Instant::now() + within;
    loop {
        let answer = verify();
        if crate::lockgate::user_desktops(logind, uid) != pinned {
            anyhow::bail!("the pinned session is gone or replaced; no lock");
        }
        if answer == LockedAnswer::Locked {
            return Ok(());
        }
        if Instant::now() >= by {
            anyhow::bail!("faceauth-lock-session: the session is not locked");
        }
        std::thread::sleep(within / 6);
    }
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    /// While locked, the watch resumes on a face match, or on the session
    /// reading as unlocked by other means, checked every few ticks, with a
    /// fresh absence clock: an empty chair after a password unlock locks
    /// again at away_seconds, and in the secure mode a stranger locks it
    /// again on the first check (C2). The lock is `SessionLock`'s, driven
    /// here at the watch's own cadence.
    #[test]
    fn the_watch_resumes_after_an_unlock_without_a_face() {
        let lock = SessionLock::new();
        let mut w = Watch::new(cfg());
        let t0 = Instant::now();
        let _ = w.step(&obs(true, Some(true)), t0, PresenceMode::Default);
        lock.adopt(t0 + Duration::from_secs(30));
        w.locked();
        assert!(lock.locked_at().is_some() && w.locked_by_presence);
        let still_locked = || true;
        let unlocked = || false;
        let check_every = Duration::from_secs(5 * LOCK_CHECK_TICKS as u64 - 2);
        let mut tick = 0u64;
        let mut now = || {
            tick += 1;
            t0 + Duration::from_secs(30 + 5 * tick)
        };
        for _ in 0..(LOCK_CHECK_TICKS * 2) {
            assert_eq!(
                lock.resumed(now(), false, check_every, &still_locked),
                None,
                "locked and no match: keep waiting"
            );
        }
        // Unlocked by a password: noticed at the next check tick.
        let mut resumed = None;
        for _ in 0..LOCK_CHECK_TICKS {
            let at = now();
            if let Some(how) = lock.resumed(at, false, check_every, &unlocked) {
                w.resumed(at, false);
                resumed = Some(how);
                break;
            }
        }
        assert_eq!(resumed, Some("without a face"));
        assert!(lock.locked_at().is_none() && !w.locked_by_presence);
        assert_eq!(
            w.state,
            State::Unknown,
            "nobody seen yet after a password unlock"
        );
        // An empty chair from here on: the fresh clock runs from the resume
        // and runs out at 20 s, tick 4.
        let resume_at = t0 + Duration::from_secs(30 + 5 * tick);
        let looks: Vec<Observation> = (0..8).map(|_| obs(false, None)).collect();
        assert_eq!(
            first_lock(&mut w, resume_at, &looks, PresenceMode::Default),
            Some(4),
            "the fresh clock runs out after the resume"
        );
        // A face match resumes at once, and reads as present.
        lock.adopt(resume_at + Duration::from_secs(60));
        w.locked();
        let at = resume_at + Duration::from_secs(65);
        assert_eq!(
            lock.resumed(at, true, check_every, &still_locked),
            Some("by face")
        );
        w.resumed(at, true);
        assert_eq!(w.state, State::Present);
        // In the secure mode a stranger after the resume is out on the
        // first check, one tick in.
        lock.adopt(resume_at + Duration::from_secs(120));
        w.locked();
        let at = resume_at + Duration::from_secs(125);
        assert_eq!(
            lock.resumed(at, true, check_every, &still_locked),
            Some("by face")
        );
        w.resumed(at, true);
        let looks: Vec<Observation> = (0..4).map(|_| obs(true, Some(false))).collect();
        assert_eq!(
            first_lock(
                &mut w,
                resume_at + Duration::from_secs(125),
                &looks,
                PresenceMode::Secure
            ),
            Some(1)
        );
    }

    /// One lock, two askers: a consent request that parked behind the lock
    /// and the watch that took it over see the same unlock, whichever asks
    /// first, and the compositor is asked on one shared cadence (H13).
    #[test]
    fn a_consent_park_and_the_watch_see_the_same_unlock() {
        let lock = SessionLock::new();
        let t0 = Instant::now();
        assert_eq!(lock.adopt(t0), t0);
        assert_eq!(
            lock.adopt(t0 + Duration::from_secs(9)),
            t0,
            "a lock already recorded is not moved"
        );
        let asked = std::cell::Cell::new(0u32);
        let locked = || {
            asked.set(asked.get() + 1);
            true
        };
        let unlocked = || {
            asked.set(asked.get() + 1);
            false
        };
        let park = Duration::from_secs(2);
        // The park asks every two seconds, the watch every few ticks; a
        // check by one is a check for both.
        assert_eq!(
            lock.resumed(t0 + Duration::from_secs(1), false, park, &locked),
            None
        );
        assert_eq!(asked.get(), 1);
        assert_eq!(
            lock.resumed(t0 + Duration::from_secs(2), false, park, &locked),
            None
        );
        assert_eq!(asked.get(), 1, "inside the cadence, not asked again");
        assert_eq!(
            lock.resumed(
                t0 + Duration::from_secs(3),
                false,
                Duration::from_secs(15),
                &locked
            ),
            None
        );
        assert_eq!(asked.get(), 1, "the watch shares the park's last check");
        // The park sees the password unlock first.
        assert_eq!(
            lock.resumed(t0 + Duration::from_secs(4), false, park, &unlocked),
            Some("without a face")
        );
        assert!(lock.locked_at().is_none());
        // The watch, asking next, finds the lock gone and resumes too.
        assert_eq!(
            lock.resumed(t0 + Duration::from_secs(5), false, park, &locked),
            Some("elsewhere")
        );
        // A face match newer than the lock resumes without asking.
        lock.adopt(t0 + Duration::from_secs(10));
        let before = asked.get();
        assert_eq!(
            lock.resumed(t0 + Duration::from_secs(11), true, park, &locked),
            Some("by face")
        );
        assert_eq!(asked.get(), before);
    }

    /// Fix round 8 (item 14): the lock helper runs only while the user has
    /// a desktop in logind's records; with none it is not run at all, so
    /// nothing the daemon starts brings up a user manager that was not
    /// running.
    #[test]
    fn the_lock_helper_runs_only_with_a_desktop() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("faceauth-lockgate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("logind/sessions")).unwrap();
        let marker = dir.join("ran");
        let helper = dir.join("helper");
        std::fs::write(
            &helper,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let logind = dir.join("logind");
        let locked = || LockedAnswer::Locked;
        let e = lock_session_at(
            &logind,
            &helper,
            "alice",
            1000,
            "/usr/share/omarchy",
            &locked,
            SHORT_VERIFY,
        )
        .unwrap_err();
        assert!(e.to_string().contains("no graphical session"), "{}", e);
        assert!(!marker.exists(), "the helper was not run");
        std::fs::write(logind.join("sessions/2"), "UID=1000\nTYPE=wayland\n").unwrap();
        lock_session_at(
            &logind,
            &helper,
            "alice",
            1000,
            "/usr/share/omarchy",
            &locked,
            SHORT_VERIFY,
        )
        .unwrap();
        assert!(marker.exists(), "with a desktop it runs");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The verification's bound in these tests.
    const SHORT_VERIFY: Duration = Duration::from_millis(300);

    /// Fix round 9 (Codex 5, Opus L1): the helper only runs the lock; the
    /// daemon asks the anchored question whether it happened, never the
    /// user's manager. The helper is handed the uid and the pinned session
    /// ids, which it checks before each of its calls, and the daemon
    /// checks them too: a pinned session gone, or replaced by a new one,
    /// is no lock.
    #[test]
    fn the_daemon_asks_the_anchor_whether_the_lock_happened() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("faceauth-lockverify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("logind/sessions")).unwrap();
        let logind = dir.join("logind");
        std::fs::write(logind.join("sessions/7"), "UID=1000\nTYPE=wayland\n").unwrap();
        let args = dir.join("args");
        let helper = dir.join("helper");
        std::fs::write(
            &helper,
            format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n", args.display()),
        )
        .unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let asked = std::cell::Cell::new(0);
        let second = || {
            asked.set(asked.get() + 1);
            if asked.get() >= 2 {
                LockedAnswer::Locked
            } else {
                LockedAnswer::NotYet
            }
        };
        lock_session_at(
            &logind,
            &helper,
            "alice",
            1000,
            "/usr/share/omarchy",
            &second,
            SHORT_VERIFY,
        )
        .unwrap();
        let got = std::fs::read_to_string(&args).unwrap();
        assert_eq!(
            got, "alice\n/usr/share/omarchy\n1000\n7\n",
            "the uid and the pinned session"
        );
        let never = || LockedAnswer::NotYet;
        let t0 = Instant::now();
        let e = lock_session_at(
            &logind,
            &helper,
            "alice",
            1000,
            "/usr/share/omarchy",
            &never,
            SHORT_VERIFY,
        )
        .unwrap_err();
        assert!(e.to_string().contains("not locked"), "{}", e);
        assert!(t0.elapsed() < SHORT_VERIFY + Duration::from_millis(400));
        // The pinned session replaced while the lock runs: no lock.
        let relogin = || {
            let _ = std::fs::remove_file(logind.join("sessions/7"));
            let _ = std::fs::write(logind.join("sessions/8"), "UID=1000\nTYPE=wayland\n");
            LockedAnswer::Locked
        };
        let e = lock_session_at(
            &logind,
            &helper,
            "alice",
            1000,
            "/usr/share/omarchy",
            &relogin,
            SHORT_VERIFY,
        )
        .unwrap_err();
        assert!(e.to_string().contains("pinned session"), "{}", e);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fix round 10 (Codex 2, Opus N4): a helper that never ends, and
    /// holds its pipes, is given up at its bound with what it started
    /// killed; nothing waits for the pipes' end, and no lock is counted.
    #[test]
    fn a_lock_helper_that_holds_its_pipes_is_given_up() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("faceauth-lockstall-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("logind/sessions")).unwrap();
        let logind = dir.join("logind");
        std::fs::write(logind.join("sessions/7"), "UID=1000\nTYPE=wayland\n").unwrap();
        let helper = dir.join("helper");
        std::fs::write(&helper, "#!/bin/sh\nsleep 30 & exec sleep 30\n").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o755)).unwrap();
        let locked = || LockedAnswer::Locked;
        let t0 = Instant::now();
        let e = lock_session_within(
            &logind,
            &helper,
            "alice",
            1000,
            "/usr/share/omarchy",
            &locked,
            SHORT_VERIFY,
            Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(e.to_string().contains("did not finish"), "{}", e);
        assert!(
            t0.elapsed() < Duration::from_millis(900),
            "{:?}",
            t0.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
        // The real bound covers the helper's two bounded calls.
        assert!(LOCK_HELPER_WITHIN >= Duration::from_secs(2 * 5));
    }
}
