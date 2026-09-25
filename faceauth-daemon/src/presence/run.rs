//! The watch's thread: the tick loop that borrows the camera for a moment
//! each tick, and the snapshot it publishes for the socket's presence
//! query.

use super::config::{presence_mode, set_presence_mode, PresenceConfig, PresenceMode};
use super::lock::{LOCK_CHECK_TICKS, SESSION_LOCK};
use super::observe::observe_in;
use super::watch::{identify_this_tick, tick_for, State, Watch, IDENTIFY_EVERY};
use crate::auth::Authenticator;
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

/// The watch's last decision, or None before its first tick.
pub fn snapshot() -> Option<Snapshot> {
    *LAST.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn run(auth: Arc<Mutex<Authenticator>>, cfg: PresenceConfig) {
    set_presence_mode(cfg.mode);
    let mut w = Watch::new(cfg.clone());
    let mut tick: u32 = 0;
    log::info!(
        "presence watch on for {} (mode {}, tick {}s, away after {}s, obscured face lock {})",
        cfg.user,
        cfg.mode.name(),
        tick_for(&cfg, cfg.mode, false),
        cfg.away_seconds,
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
    loop {
        let tick_s = tick_for(&cfg, mode, on_battery);
        std::thread::sleep(Duration::from_secs_f32(tick_s));
        tick = tick.wrapping_add(1);
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
        let now_mode = presence_mode();
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
                crate::consent::session_locked(&cfg.user)
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
        if step.lock {
            log::info!("presence: locking the session");
            match SESSION_LOCK.lock(&cfg.user, &crate::consent::omarchy_path()) {
                Ok(_) => w.locked(),
                Err(e) => log::warn!("lock command: {}", e),
            }
        }
        *LAST.lock().unwrap_or_else(|p| p.into_inner()) = Some(Snapshot {
            state: step.state,
            attentive: obs.attentive,
            away_for: step.away_for,
            locked_by_presence: w.locked_by_presence,
        });
    }
}

/// Is the machine running on its battery? True when a battery is present
/// and no mains supply reports itself online; a desktop, with no battery,
/// is never on battery.
fn on_battery_now() -> bool {
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
