//! The watch's thread: the tick loop that borrows the camera for a moment
//! each tick, and the snapshot it publishes for the socket's presence
//! query.

use super::config::{
    mode_for_camera, presence_mode, set_presence_mode, AwayTime, LockWord, PresenceConfig,
    PresenceMode, SECURE_NEEDS_STROBE,
};
use super::lock::{LOCK_CHECK_TICKS, SESSION_LOCK};
use super::observe::observe_in;
use super::watch::{identify_this_tick, tick_for, State, Watch, IDENTIFY_EVERY};
use crate::auth::Authenticator;
use faceauth_engine::Grey;
use serde::Serialize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What the watch last decided, for the socket's presence query: the
/// state, how long the user has been unseen, and whether the lock in
/// force is the watch's. Root-only in effect: the query answers it to
/// root and the watched user, since whether the owner is at the desk is
/// a timing signal an attacker on the machine would like.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Snapshot {
    pub state: State,
    pub attentive: bool,
    pub away_for: Option<f32>,
    pub locked_by_presence: bool,
}

static LAST: Mutex<Option<Snapshot>> = Mutex::new(None);

/// The watch as its last tick left it, for a consent card to run a copy
/// of on its own looks while it holds the camera and the watch cannot
/// tick: who has held the clock, the shape a hidden face is held by.
static LIVE: Mutex<Option<Watch>> = Mutex::new(None);

/// The latest sighting of a user the consent lane made (a scan match):
/// who, when, and the frame and box, for the watch to take at its next
/// tick (`Watch::sighted`). A card holds the camera, so the watch misses
/// the sightings under it; without this its first tick after a long card
/// would judge the user by a shape reference from before the card.
static SIGHTING: Mutex<Option<Sighting>> = Mutex::new(None);

/// Whose sighting, when, the frame and the face's box.
type Sighting = (String, Instant, Grey, [f32; 4]);

/// Note that `user` was identified at `at`, at `frame` and `bbox`, where
/// the watch did not look.
pub(crate) fn note_sighting(user: &str, at: Instant, frame: &Grey, bbox: [f32; 4]) {
    *SIGHTING.lock().unwrap_or_else(|p| p.into_inner()) =
        Some((user.to_string(), at, frame.clone(), bbox));
}

/// The sighting noted for `user`, taken; one for another user is left.
fn take_sighting(user: &str) -> Option<(Instant, Grey, [f32; 4])> {
    let mut s = SIGHTING.lock().unwrap_or_else(|p| p.into_inner());
    if s.as_ref().is_some_and(|(u, ..)| u == user) {
        s.take().map(|(_, at, f, b)| (at, f, b))
    } else {
        None
    }
}

/// The watch's last decision, or None before its first tick.
pub fn snapshot() -> Option<Snapshot> {
    *LAST.lock().unwrap_or_else(|p| p.into_inner())
}

/// A copy of the watch as its last tick left it; None while no watch runs
/// or before its first tick.
pub(crate) fn watch_copy() -> Option<Watch> {
    LIVE.lock().unwrap_or_else(|p| p.into_inner()).clone()
}

/// The longest a failed walk-away lock waits before the next try.
pub(crate) const LOCK_BACKOFF_CAP: Duration = Duration::from_secs(600);

/// What the watch does about the desktop and its own lock attempts (fix
/// round 8, item 14). With no graphical session of the user's in logind's
/// records it pauses: no look, no lock, nothing run in the user's manager;
/// it resumes, afresh, when one appears. A lock that fails waits before
/// the next try, doubling from the tick up to `LOCK_BACKOFF_CAP`, rather
/// than trying every tick; a lock that works, or a resume, starts that
/// over.
#[derive(Debug, Default)]
pub(crate) struct Governor {
    paused: bool,
    failures: u32,
    next_try: Option<Instant>,
}

/// How the desktop's presence changed the watch.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Change {
    Same,
    Paused,
    Resumed,
}

impl Governor {
    /// Whether the user has a desktop now.
    pub(crate) fn desktop(&mut self, present: bool) -> Change {
        match (self.paused, present) {
            (false, false) => {
                self.paused = true;
                Change::Paused
            }
            (true, true) => {
                *self = Governor::default();
                Change::Resumed
            }
            _ => Change::Same,
        }
    }

    pub(crate) fn paused(&self) -> bool {
        self.paused
    }

    /// Whether a lock may be tried at `now`.
    pub(crate) fn may_lock(&self, now: Instant) -> bool {
        !self.paused && self.next_try.is_none_or(|t| now >= t)
    }

    /// A lock failed at `now`: how long until the next try.
    pub(crate) fn lock_failed(&mut self, now: Instant, tick: Duration) -> Duration {
        let wait = tick
            .saturating_mul(1u32 << self.failures.min(16))
            .min(LOCK_BACKOFF_CAP);
        self.failures = self.failures.saturating_add(1);
        self.next_try = Some(now + wait);
        wait
    }

    pub(crate) fn lock_worked(&mut self) {
        self.failures = 0;
        self.next_try = None;
    }
}

pub fn run(auth: Arc<Mutex<Authenticator>>, cfg: PresenceConfig) {
    set_presence_mode(cfg.mode);
    let mut w = Watch::new(cfg.clone());
    let mut tick: u32 = 0;
    log::info!(
        "presence watch on for {} (mode {}, tick {}s, away {} (secure {}s), obscured face lock {})",
        cfg.user,
        cfg.mode.name(),
        tick_for(&cfg, cfg.mode, false),
        match cfg.away_seconds {
            AwayTime::Seconds(s) => format!("after {}s", s),
            AwayTime::Word(LockWord::Never) => "never".into(),
        },
        cfg.secure_away_seconds,
        match cfg.obscured_lock_for(cfg.mode) {
            Some(d) => format!("after {} min", d.as_secs() / 60),
            None => "never".into(),
        }
    );
    for w in cfg.obscured_lock_warnings() {
        log::warn!("presence: {}", w);
    }
    let mut on_battery = false;
    let mut mode = presence_mode();
    let uid = nix::unistd::User::from_name(&cfg.user)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw());
    let mut governor = Governor::default();
    loop {
        let tick_s = tick_for(&cfg, mode, on_battery);
        std::thread::sleep(Duration::from_secs_f32(tick_s));
        tick = tick.wrapping_add(1);
        // No desktop, no watch (fix round 8, item 14): nothing is looked
        // at, locked or run in the user's manager until logind shows a
        // graphical session of theirs again.
        let present = uid.is_some_and(|uid| {
            crate::lockgate::user_has_desktop(std::path::Path::new("/run/systemd"), uid)
        });
        match governor.desktop(present) {
            Change::Paused => log::info!(
                "presence: {} has no graphical session; the watch pauses",
                cfg.user
            ),
            Change::Resumed => {
                log::info!(
                    "presence: a graphical session of {}'s is back; the watch resumes",
                    cfg.user
                );
                w = Watch::new(cfg.clone());
            }
            Change::Same => {}
        }
        if governor.paused() {
            continue;
        }
        let battery = on_battery_now();
        if battery != on_battery {
            on_battery = battery;
            log::info!(
                "presence: {} (tick {}s)",
                if battery { "on battery" } else { "on mains" },
                if battery && cfg.battery_tick_seconds > 0.0 {
                    cfg.battery_tick_seconds
                } else {
                    cfg.tick_seconds
                }
            );
        }
        // The config can ask for the secure mode on a camera that cannot
        // strobe, which only the first look finds out: the watch then runs
        // in the default mode and says why, once (the socket refuses the
        // switch back).
        let mut now_mode = presence_mode();
        let fit = mode_for_camera(now_mode, crate::tier::seen());
        if fit != now_mode {
            log::warn!("presence: {}", SECURE_NEEDS_STROBE);
            set_presence_mode(fit);
            now_mode = fit;
        }
        if now_mode != mode {
            mode = now_mode;
            log::info!("presence: mode is now {}", mode.name());
        }
        let identify = identify_this_tick(mode, tick, IDENTIFY_EVERY, w.state);
        // A consent request that locked the session while the user was
        // away hands the lock to this watch, which then waits for the
        // unlock like one of its own.
        if !w.locked_by_presence && SESSION_LOCK.locked_at().is_some() {
            w.locked();
        }
        // After locking, leave the camera to the lock screen (its own probe
        // wakes the panel); resume once an attempt has matched, or once the
        // session reads as unlocked by other means (a password, a
        // fingerprint), asked every `LOCK_CHECK_TICKS` ticks.
        if w.locked_by_presence {
            let now = Instant::now();
            let matched = SESSION_LOCK.locked_at().is_some_and(|t| {
                auth.lock()
                    .map(|a| a.last_match.get(&cfg.user).is_some_and(|m| *m > t))
                    .unwrap_or(false)
            });
            let check_every =
                Duration::from_secs_f32(tick_s * LOCK_CHECK_TICKS as f32 - tick_s / 2.0);
            let Some(how) = SESSION_LOCK.resumed(now, matched, check_every, &|| {
                crate::consent::session_locked(&cfg.user, &crate::lockgate::Bind::OnlyDesktop)
            }) else {
                continue;
            };
            w.resumed(now, matched);
            log::info!("presence: session unlocked {}, watch resumes", how);
        }
        let obs = {
            let mut a = auth.lock().unwrap_or_else(|p| p.into_inner());
            // A consent window that ran while this thread waited for the lock
            // is the user at the desk, not seconds unseen: the walk-away clock
            // restarts from the end of that flow, and from any face match.
            let recent = [a.last_consent.get(&cfg.user), a.last_match.get(&cfg.user)]
                .into_iter()
                .flatten()
                .max()
                .copied();
            if let Some(r) = recent {
                w.note_recent(r);
            }
            // A consent card's match is a sighting with a frame: the shape
            // hold runs from it (C1's reference, from a passing check).
            if let Some((at, frame, bbox)) = take_sighting(&cfg.user) {
                w.sighted(at, &frame, bbox);
            }
            let persist = matches!(w.state, State::Present | State::Stranger);
            match observe_in(
                &mut a,
                &cfg,
                identify,
                mode == PresenceMode::Secure,
                persist,
            ) {
                Ok(o) => o,
                Err(e) => {
                    log::warn!("presence tick: {}", e);
                    continue;
                }
            }
        };
        let now = Instant::now();
        let step = w.step(&obs, now, mode);
        // A lock that failed waits before the next try, doubling up to a
        // cap (fix round 8, item 14), rather than retrying every tick.
        if step.lock && governor.may_lock(now) {
            log::info!("presence: locking the session");
            match SESSION_LOCK.lock(&cfg.user, &crate::consent::omarchy_path()) {
                Ok(_) => {
                    w.locked();
                    governor.lock_worked();
                }
                Err(e) => {
                    let wait = governor.lock_failed(now, Duration::from_secs_f32(tick_s));
                    log::warn!("lock command: {}; the next try in {} s", e, wait.as_secs());
                }
            }
        }
        *LAST.lock().unwrap_or_else(|p| p.into_inner()) = Some(Snapshot {
            state: step.state,
            attentive: obs.attentive,
            away_for: step.away_for,
            locked_by_presence: w.locked_by_presence,
        });
        *LIVE.lock().unwrap_or_else(|p| p.into_inner()) = Some(w.clone());
    }
}

/// Is the machine running on its battery? True when a battery is present
/// and no mains supply reports itself online; a desktop, with no battery,
/// is never on battery.
pub(crate) fn on_battery_now() -> bool {
    let Ok(dir) = std::fs::read_dir("/sys/class/power_supply") else {
        return false;
    };
    let (mut battery, mut mains_online) = (false, false);
    for e in dir.flatten() {
        let p = e.path();
        let read = |n: &str| {
            std::fs::read_to_string(p.join(n))
                .map(|v| v.trim().to_string())
                .unwrap_or_default()
        };
        match read("type").as_str() {
            "Battery" => battery = true,
            "Mains" | "USB" | "USB_PD" | "USB_C" if read("online") == "1" => {
                mains_online = true;
            }
            _ => {}
        }
    }
    battery && !mains_online
}

#[cfg(test)]
mod sighting_tests {
    use super::*;

    /// A card's match is handed to the watch of that user once, and to no
    /// other user's watch.
    #[test]
    fn a_card_sighting_goes_to_its_users_watch_once() {
        let at = Instant::now();
        note_sighting("sighting-alice", at, &Grey::new(4, 4), [1.0, 2.0, 3.0, 4.0]);
        assert!(take_sighting("sighting-bob").is_none());
        let (t, _, b) = take_sighting("sighting-alice").expect("alice's sighting");
        assert_eq!((t, b), (at, [1.0, 2.0, 3.0, 4.0]));
        assert!(take_sighting("sighting-alice").is_none(), "taken once");
    }

    /// Fix round 8 (item 14): with no desktop the watch pauses and starts
    /// nothing, and resumes, afresh, when one appears; a lock that fails
    /// backs off, doubling from the tick to a cap, rather than retrying
    /// every tick, and a lock that works or a pause starts it over.
    #[test]
    fn the_watch_pauses_without_a_desktop_and_failed_locks_back_off() {
        let t0 = Instant::now();
        let tick = Duration::from_secs(15);
        let mut g = Governor::default();
        assert_eq!(g.desktop(true), Change::Same);
        assert_eq!(g.desktop(false), Change::Paused);
        assert!(g.paused());
        assert_eq!(g.desktop(false), Change::Same);
        assert_eq!(g.desktop(true), Change::Resumed);
        assert!(!g.paused());
        assert!(g.may_lock(t0));
        assert_eq!(g.lock_failed(t0, tick), tick);
        assert!(!g.may_lock(t0 + tick - Duration::from_secs(1)));
        assert!(g.may_lock(t0 + tick));
        assert_eq!(g.lock_failed(t0 + tick, tick), tick * 2);
        assert_eq!(g.lock_failed(t0 + tick * 3, tick), tick * 4);
        for _ in 0..10 {
            let _ = g.lock_failed(t0, tick);
        }
        assert_eq!(g.lock_failed(t0, tick), LOCK_BACKOFF_CAP, "capped");
        g.lock_worked();
        assert!(g.may_lock(t0));
        let _ = g.lock_failed(t0, tick);
        assert_eq!(g.desktop(false), Change::Paused);
        assert_eq!(g.desktop(true), Change::Resumed);
        assert!(g.may_lock(t0), "a resume starts the backoff over");
    }
}
