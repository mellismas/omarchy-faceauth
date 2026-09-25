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
        lock_session(user, omarchy_path)?;
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
/// session to lock and the Omarchy tree the shell was launched from. It
/// runs the lock inside the user's own manager and answers with what the
/// compositor says (0 locked, 1 not), so a lock that never happened is
/// not believed.
pub const LOCK_HELPER: &str = "/usr/bin/faceauth-lock-session";

fn lock_session(user: &str, omarchy_path: &str) -> Result<()> {
    let o = std::process::Command::new(LOCK_HELPER)
        .args([user, omarchy_path])
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .output()?;
    if !o.status.success() {
        anyhow::bail!(
            "exited {}: {} {}",
            o.status,
            String::from_utf8_lossy(&o.stdout).trim(),
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(())
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
}
