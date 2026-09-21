//! Presence watch: is the enrolled user in front of the machine?
//!
//! Low duty by construction: every `tick_seconds` the watch takes the camera
//! for a fraction of a second, grabs a few frames with the illuminator on,
//! detects on the last one and, every `identify_every` ticks, embeds it and
//! checks it against the templates. The camera is closed between ticks, so an
//! authentication attempt never waits for more than one tick.
//!
//! State: `Present` (enrolled user seen recently), `Away` (no face for
//! `away_seconds`, session locked once on the transition), `Stranger` (a face
//! that is not the enrolled user; treated as away for locking). The state is
//! published to `<runtime>/presence.json` for the shell.

use crate::auth::Authenticator;
use anyhow::Result;
use faceauth_engine::pose;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PresenceConfig {
    pub enabled: bool,
    /// Whose presence: the user whose templates are matched.
    pub user: String,
    pub tick_seconds: f32,
    /// Ticks between identity checks (detection alone runs every tick).
    pub identify_every: u32,
    /// On battery (no mains supply online) the tick stretches to this and
    /// identity checks come every `battery_identify_every` ticks. Zero keeps
    /// the mains cadence.
    pub battery_tick_seconds: f32,
    pub battery_identify_every: u32,
    /// Seconds without the user before the session is locked.
    pub away_seconds: f32,
    /// Also require the face to be turned toward the camera.
    pub require_attention: bool,
    pub max_yaw: f32,
    pub max_roll_degrees: f32,
    /// Command run (as root) to lock the session on the away transition.
    pub lock_command: Vec<String>,
    /// Where the state file goes.
    pub state_file: String,
}

impl Default for PresenceConfig {
    fn default() -> Self {
        PresenceConfig {
            enabled: false,
            user: String::new(),
            tick_seconds: 2.0,
            identify_every: 3,
            battery_tick_seconds: 5.0,
            battery_identify_every: 6,
            away_seconds: 20.0,
            require_attention: false,
            max_yaw: 0.25,
            max_roll_degrees: 25.0,
            lock_command: vec!["/usr/bin/faceauth-lock-session".into()],
            state_file: "/run/faceauth/presence.json".into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Present,
    Away,
    Stranger,
    Unknown,
}

#[derive(Clone, Debug, Serialize)]
pub struct Published {
    pub state: State,
    pub attentive: bool,
    pub last_seen_secs_ago: Option<f32>,
    pub locked_by_presence: bool,
    pub updated: u64,
}

pub fn run(auth: Arc<Mutex<Authenticator>>, cfg: PresenceConfig) {
    let mut last_seen: Option<Instant> = None;
    let mut state = State::Unknown;
    let mut locked_by_presence = false;
    let mut tick: u32 = 0;
    let mut identity_ok = true; // until two consecutive identity checks say otherwise
    let mut identity_fails: u32 = 0;
    let mut locked_at: Option<Instant> = None;
    let mut adopted: Option<Instant> = None;
    log::info!("presence watch on for {} (tick {}s, away after {}s, attention {})", cfg.user, cfg.tick_seconds, cfg.away_seconds, cfg.require_attention);
    let mut on_battery = false;
    loop {
        let (tick_s, every) = if on_battery && cfg.battery_tick_seconds > 0.0 { (cfg.battery_tick_seconds, cfg.battery_identify_every) } else { (cfg.tick_seconds, cfg.identify_every) };
        std::thread::sleep(Duration::from_secs_f32(tick_s));
        tick = tick.wrapping_add(1);
        let battery = on_battery_now();
        if battery != on_battery {
            on_battery = battery;
            log::info!("presence: {} (tick {}s)", if battery { "on battery" } else { "on mains" }, if battery && cfg.battery_tick_seconds > 0.0 { cfg.battery_tick_seconds } else { cfg.tick_seconds });
        }
        // Identity is the dear part of a tick (the embedder costs several
        // times the detector): on its cadence while present, every other tick
        // while a face is there that has not been confirmed.
        let identify = tick % every.max(1) == 0 || (state != State::Present && tick % 2 == 0);
        // After locking, leave the camera to the lock screen (its own probe wakes
        // the panel); resume only once an attempt has matched.
        if let Some(t) = locked_at {
            let resumed = auth.lock().map(|a| a.last_match.get(&cfg.user).map(|m| *m > t).unwrap_or(false)).unwrap_or(false);
            if !resumed {
                continue;
            }
            log::info!("presence: session unlocked by face, watch resumes");
            locked_at = None;
            locked_by_presence = false;
            last_seen = Some(Instant::now());
            state = State::Present;
            identity_ok = true;
            identity_fails = 0;
        }
        {
            // A consent request that locked the session while the user was
            // away hands the lock to this watch, which then waits for the
            // face match that unlocks it like one of its own.
            let taken = auth.lock().ok().and_then(|a| a.session_locked_at);
            if let Some(t) = taken {
                if adopted.map(|a| t > a).unwrap_or(true) {
                    adopted = Some(t);
                    locked_at = Some(t);
                    locked_by_presence = true;
                    state = State::Away;
                    continue;
                }
            }
        }
        let obs = {
            let mut a = auth.lock().unwrap_or_else(|p| p.into_inner());
            // A consent window that ran while this thread waited for the lock
            // is the user at the desk, not seconds unseen: the walk-away clock
            // restarts from the end of that flow, and from any face match.
            let recent = [a.last_consent.get(&cfg.user), a.last_match.get(&cfg.user)].into_iter().flatten().max().copied();
            if let Some(r) = recent {
                if last_seen.map(|l| r > l).unwrap_or(true) {
                    last_seen = Some(r);
                    if state != State::Present {
                        log::info!("presence: consent or match since the last tick; clock restarts");
                    }
                }
            }
            match observe(&mut a, &cfg, identify) {
                Ok(o) => o,
                Err(e) => {
                    log::warn!("presence tick: {}", e);
                    continue;
                }
            }
        };
        let now = Instant::now();
        if let Some(id) = obs.identity {
            if id {
                identity_fails = 0;
                identity_ok = true;
            } else {
                identity_fails += 1;
                if identity_fails >= 2 {
                    identity_ok = false;
                }
            }
        }
        let seen = obs.face && identity_ok && (!cfg.require_attention || obs.attentive);
        if seen {
            last_seen = Some(now);
        }
        let away_for = last_seen.map(|t| now.duration_since(t).as_secs_f32());
        let next = if seen {
            State::Present
        } else if obs.face && !identity_ok {
            State::Stranger
        } else if away_for.map(|s| s >= cfg.away_seconds).unwrap_or(false) {
            State::Away
        } else if state == State::Unknown {
            State::Unknown
        } else {
            state // in the away window: keep the previous state
        };
        if next != state {
            log::info!("presence: {:?} -> {:?}{}", state, next, away_for.map(|s| format!(" (unseen {:.0}s)", s)).unwrap_or_default());
        }
        // Lock on the away transition, and keep trying every tick while away
        // until it succeeds: a failed lock must not leave the machine open.
        if next == State::Away && !locked_by_presence {
            log::info!("presence: locking the session");
            let args: Vec<String> = cfg.lock_command.iter().skip(1).map(|a| if a.is_empty() { cfg.user.clone() } else { a.clone() }).collect();
            match std::process::Command::new(&cfg.lock_command[0]).args(&args).env("PATH", "/usr/local/bin:/usr/bin:/bin").output() {
                Ok(o) if o.status.success() => {
                    locked_by_presence = true;
                    locked_at = Some(Instant::now());
                }
                Ok(o) => log::warn!("lock command exited {}: {} {}", o.status, String::from_utf8_lossy(&o.stdout).trim(), String::from_utf8_lossy(&o.stderr).trim()),
                Err(e) => log::warn!("lock command: {}", e),
            }
        }
        if next == State::Present {
            locked_by_presence = false;
        }
        state = next;
        let pub_ = Published {
            state,
            attentive: obs.attentive,
            last_seen_secs_ago: away_for,
            locked_by_presence,
            updated: crate::store::now_secs(),
        };
        if let Ok(json) = serde_json::to_string(&pub_) {
            // Root-only: whether the owner is at the desk is a timing signal an
            // attacker on the machine would like. The lock screen reads it as
            // root through the daemon, not from this file.
            use std::os::unix::fs::OpenOptionsExt;
            let tmp = format!("{}.tmp", cfg.state_file);
            let written = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp).and_then(|mut f| {
                use std::io::Write;
                f.write_all(json.as_bytes())
            });
            if written.and_then(|_| std::fs::rename(&tmp, &cfg.state_file)).is_err() {
                log::debug!("presence: cannot write {}", cfg.state_file);
            }
        }
    }
}

struct Observation {
    face: bool,
    attentive: bool,
    /// Some(true/false) when an identity check ran.
    identity: Option<bool>,
}

/// Is the machine running on its battery? True when a battery is present
/// and no mains supply reports itself online; a desktop, with no battery,
/// is never on battery.
fn on_battery_now() -> bool {
    let Ok(dir) = std::fs::read_dir("/sys/class/power_supply") else { return false };
    let (mut battery, mut mains_online) = (false, false);
    for e in dir.flatten() {
        let p = e.path();
        let read = |n: &str| std::fs::read_to_string(p.join(n)).map(|v| v.trim().to_string()).unwrap_or_default();
        match read("type").as_str() {
            "Battery" => battery = true,
            "Mains" | "USB" | "USB_PD" | "USB_C" => {
                if read("online") == "1" {
                    mains_online = true;
                }
            }
            _ => {}
        }
    }
    battery && !mains_online
}

/// One short look: open the camera, LEDs on, a few frames, detect, maybe identify, close.
fn observe(a: &mut Authenticator, cfg: &PresenceConfig, identify: bool) -> Result<Observation> {
    use crate::capture::IrCapture;
    let mut cap = IrCapture::open_at(&a.cfg, a.last_exposure)?;
    if let Some(i) = &cap.illuminator {
        i.set(true)?;
    }
    // Let exposure react for a handful of frames; the last one is what we look at.
    let mut img = None;
    let deadline = Instant::now() + Duration::from_millis(450);
    while Instant::now() < deadline {
        if let Some(g) = cap.next(Duration::from_millis(500))? {
            img = Some(g);
        }
    }
    let Some(img) = img else {
        cap.stop()?;
        return Ok(Observation { face: false, attentive: false, identity: None });
    };
    let faces = a.pipeline.detector.detect(&img, a.cfg.min_detection)?;
    let Some(face) = faces.into_iter().max_by(|x, y| x.score.total_cmp(&y.score)) else {
        cap.stop()?;
        return Ok(Observation { face: false, attentive: false, identity: None });
    };
    // A face was in view at this exposure: the next look starts from it.
    a.last_exposure = Some(cap.exposure);
    let p = pose::pose(&face.landmarks);
    let attentive = pose::is_attentive(&p, cfg.max_yaw, cfg.max_roll_degrees);
    let identity = if identify {
        let crop = faceauth_engine::align::align_112(&img, &face.landmarks);
        let e = a.pipeline.embedder.embed(&crop)?;
        let score = match a.store.load(&cfg.user)? {
            Some(t) => t.best_match(&e).map(|(s, _)| s).unwrap_or(-1.0),
            None => -1.0,
        };
        if score < a.cfg.accept_threshold {
            log::info!("presence: identity check failed, score {:.2} (exp {} gain {}, face {:.2})", score, cap.exposure.exposure, cap.exposure.gain, face.score);
        }
        Some(score >= a.cfg.accept_threshold)
    } else {
        None
    };
    cap.stop()?;
    log::debug!("presence tick: face {:.2} yaw {:.2} pitch {:.2} roll {:.0} attentive {} identity {:?}", face.score, p.yaw, p.pitch, p.roll.to_degrees(), attentive, identity);
    Ok(Observation { face: true, attentive, identity })
}
