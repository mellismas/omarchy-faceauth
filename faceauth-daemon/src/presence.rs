//! Presence watch: is the enrolled user in front of the machine?
//!
//! Low duty by construction: every `tick_seconds` the watch takes the camera
//! for a fraction of a second, grabs a few frames with the illuminator on,
//! detects on the last one and, every `identify_every` ticks, strobes one
//! lit/unlit pair through the flash gate and embeds the face to check it
//! against the templates. A print that fails the gate is not the user, so
//! it cannot keep the session marked present. The camera is closed between
//! ticks, so an authentication attempt never waits for more than one tick.
//!
//! State: `Present` (enrolled user seen recently), `Away` (the user not
//! seen for `away_seconds`, session locked once on the transition),
//! `Stranger` (a face that is not the enrolled user; it does not count as
//! the user, and it does not hold the lock off either: the away clock runs
//! under it). Two modes (`[presence] mode`): `default` tolerates a hidden
//! face and a flaky identity check; `secure` locks whenever the enrolled
//! user is not positively in frame for `away_seconds`. In the default mode a
//! face the detector only half sees (a hand over the chin while reading) is
//! not absence: while no face is found, the away clock is held for up to
//! `PARTIAL_GRACE_S` after the last full sighting when the shape under the
//! last face box is unchanged. The state is published to
//! `<runtime>/presence.json` for the shell.

use crate::auth::Authenticator;
use anyhow::Result;
use faceauth_engine::{pose, Grey};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PresenceConfig {
    pub enabled: bool,
    /// Whose presence: the user whose templates are matched.
    pub user: String,
    /// How strict the watch is; see `PresenceMode`. The starting mode; the
    /// watched user may switch it at run time over the socket.
    pub mode: PresenceMode,
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
            mode: PresenceMode::Default,
            tick_seconds: 5.0,
            identify_every: 3,
            battery_tick_seconds: 10.0,
            battery_identify_every: 3,
            away_seconds: 20.0,
            require_attention: false,
            max_yaw: 0.25,
            max_roll_degrees: 25.0,
            // The empty argument is filled with the watched user when the
            // command runs, so the default helper locks the right session.
            lock_command: vec!["/usr/bin/faceauth-lock-session".into(), String::new()],
            state_file: "/run/faceauth/presence.json".into(),
        }
    }
}

/// How strict the walk-away watch is.
///
/// `Default`: the away clock runs whenever the enrolled user is not seen,
/// a stranger in view included, so nobody else in the chair holds the lock
/// off past `away_seconds`. A hidden face (no face found, the same shape in
/// the chair) holds the clock for a while, and an identity check has to
/// fail twice running before a face stops counting as the user, so a
/// flaky check or a hand over the chin does not lock the desk.
///
/// `Secure`: the session locks whenever the enrolled user is not
/// positively in frame for `away_seconds`. One failed identity check is
/// enough, and nothing holds the clock but the user's own face.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceMode {
    Default,
    Secure,
}

impl PresenceMode {
    pub fn parse(s: &str) -> Option<PresenceMode> {
        match s {
            "default" => Some(PresenceMode::Default),
            "secure" => Some(PresenceMode::Secure),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            PresenceMode::Default => "default",
            PresenceMode::Secure => "secure",
        }
    }
}

/// The mode in force, set from the config when the watch starts and
/// changed at run time by the watched user over the socket (it does not
/// persist; the config sets the starting mode at every start).
static MODE: AtomicU8 = AtomicU8::new(0);

pub fn presence_mode() -> PresenceMode {
    if MODE.load(Ordering::SeqCst) == 1 { PresenceMode::Secure } else { PresenceMode::Default }
}

pub fn set_presence_mode(mode: PresenceMode) {
    MODE.store(if mode == PresenceMode::Secure { 1 } else { 0 }, Ordering::SeqCst);
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
    pub mode: PresenceMode,
    pub updated: u64,
}

/// While the session is locked, every this many ticks the watch asks the
/// compositor whether it still is: a password or fingerprint unlock, which
/// leaves no face match behind, resumes the watch this way (C2).
pub const LOCK_CHECK_TICKS: u32 = 3;

/// The watch's state between ticks, and the rules that move it: what
/// `run` drives from the camera, kept apart from it so the rules can be
/// exercised on made-up observations.
pub(crate) struct Watch {
    cfg: PresenceConfig,
    pub(crate) state: State,
    last_seen: Option<Instant>,
    last_full: Option<Instant>,
    partial_logged: bool,
    /// The frame and face box of the last sighting whose identity passed.
    reference: Option<(Grey, [f32; 4])>,
    pub(crate) locked_by_presence: bool,
    identity_ok: bool,
    identity_fails: u32,
    /// When this watch (or a consent request it adopted) locked the session.
    pub(crate) locked_at: Option<Instant>,
    lock_checks: u32,
}

/// What one tick decided.
pub(crate) struct Step {
    pub(crate) state: State,
    /// Lock the session now (the away transition, or an earlier lock that
    /// failed and is retried).
    pub(crate) lock: bool,
    pub(crate) away_for: Option<f32>,
}

impl Watch {
    pub(crate) fn new(cfg: PresenceConfig) -> Watch {
        Watch { cfg, state: State::Unknown, last_seen: None, last_full: None, partial_logged: false, reference: None, locked_by_presence: false, identity_ok: true, identity_fails: 0, locked_at: None, lock_checks: 0 }
    }

    /// A consent window that ran, or a face match, since the last tick: the
    /// user was at the desk then, and the away clock restarts from it.
    pub(crate) fn note_recent(&mut self, at: Instant) {
        if self.last_seen.map(|l| at > l).unwrap_or(true) {
            self.last_seen = Some(at);
            if self.state != State::Present {
                log::info!("presence: consent or match since the last tick; clock restarts");
            }
        }
    }

    /// The session was locked at `at`, by this watch or by a consent
    /// request handing its lock over.
    pub(crate) fn locked(&mut self, at: Instant) {
        self.locked_at = Some(at);
        self.locked_by_presence = true;
        self.state = State::Away;
        self.lock_checks = 0;
    }

    /// One tick while the session is locked. The camera is left to the
    /// lock screen; the watch resumes on a face match newer than the lock
    /// (`matched_since_lock`), or, every `LOCK_CHECK_TICKS`, when the
    /// session reads as unlocked by any other means. Returns how it
    /// resumed, or None to keep waiting.
    pub(crate) fn locked_step(&mut self, now: Instant, matched_since_lock: bool, session_locked: &dyn Fn() -> bool) -> Option<&'static str> {
        self.lock_checks = self.lock_checks.wrapping_add(1);
        let how = if matched_since_lock {
            "by face"
        } else if self.lock_checks.is_multiple_of(LOCK_CHECK_TICKS) && !session_locked() {
            "without a face"
        } else {
            return None;
        };
        self.locked_at = None;
        self.locked_by_presence = false;
        // A fresh absence clock either way. After a face the user is
        // present; after a password nobody has been seen yet, and the next
        // identity check decides.
        self.last_seen = Some(now);
        self.identity_ok = true;
        self.identity_fails = 0;
        self.state = if matched_since_lock { State::Present } else { State::Unknown };
        Some(how)
    }

    /// One look's worth of the rules.
    pub(crate) fn step(&mut self, obs: &Observation, now: Instant, mode: PresenceMode) -> Step {
        let cfg = &self.cfg;
        if let Some(id) = obs.identity {
            if id {
                self.identity_fails = 0;
                self.identity_ok = true;
            } else {
                self.identity_fails += 1;
                // Default: two checks running, so one flaky read does not
                // turn the user into a stranger. Secure: one is enough.
                let strikes = if mode == PresenceMode::Secure { 1 } else { 2 };
                if self.identity_fails >= strikes {
                    self.identity_ok = false;
                }
            }
        }
        let seen = obs.face && self.identity_ok && (!cfg.require_attention || obs.attentive);
        if seen {
            self.last_seen = Some(now);
            self.last_full = Some(now);
            self.partial_logged = false;
            // The shape reference comes only from a look whose identity
            // passed: a stranger's torso must not become the shape that
            // holds the clock for a hidden face (C1).
            if obs.identity == Some(true) {
                if let (Some(f), Some(b)) = (obs.frame.as_ref(), obs.bbox) {
                    self.reference = Some((f.clone(), b));
                }
            }
        } else if self.state == State::Present || self.state == State::Stranger {
            log::info!("presence: the user's face is not seen this look (face {}, frame {}, last full sighting {})", obs.face, obs.frame.is_some(), self.last_full.map(|t| format!("{:.0}s ago", now.duration_since(t).as_secs_f32())).unwrap_or_else(|| "never".into()));
        }
        // A hidden face (no face found at all) may still be the user in the
        // chair: a hand or a sheet over the face leaves the shape under the
        // last face box, standing up replaces it with the wall. A face that
        // is found and fails identity is somebody, not a hidden user, and
        // holds nothing; in the secure mode nothing but the user's own face
        // holds the clock.
        if !seen && !obs.face && mode == PresenceMode::Default && partial_holds(now, self.last_full) {
            let sim = match (self.reference.as_ref(), obs.frame.as_ref()) {
                (Some(r), Some(f)) => same_shape(r, f),
                _ => 0.0,
            };
            if sim >= SAME_SHAPE {
                self.last_seen = Some(now);
                if !self.partial_logged {
                    log::info!("presence: the user's face is not seen but the same shape is in the chair ({:.2}); the clock is held", sim);
                    self.partial_logged = true;
                }
            } else if !self.partial_logged {
                // Logged once per episode so the threshold can be set from
                // what real hands and sheets score. A scene similarity, not
                // a match score.
                log::info!("presence: the user's face is not seen and the shape under the last box differs ({:.2} < {}); the clock runs", sim, SAME_SHAPE);
                self.partial_logged = true;
            }
        }
        let away_for = self.last_seen.map(|t| now.duration_since(t).as_secs_f32());
        // The away clock decides before the stranger does: a face that is
        // not the user's is reported while the clock runs, and the session
        // locks when it runs out, whoever is in view (C1).
        let next = if seen {
            State::Present
        } else if away_for.map(|s| s >= cfg.away_seconds).unwrap_or(false) {
            State::Away
        } else if obs.face && !self.identity_ok {
            State::Stranger
        } else if self.state == State::Unknown {
            State::Unknown
        } else {
            self.state // in the away window: keep the previous state
        };
        if next != self.state {
            log::info!("presence: {:?} -> {:?}{}", self.state, next, away_for.map(|s| format!(" (unseen {:.0}s)", s)).unwrap_or_default());
        }
        // Lock on the away transition, and keep trying every tick while away
        // until it succeeds: a failed lock must not leave the machine open.
        let lock = next == State::Away && !self.locked_by_presence;
        if next == State::Present {
            self.locked_by_presence = false;
        }
        self.state = next;
        Step { state: next, lock, away_for }
    }
}

pub fn run(auth: Arc<Mutex<Authenticator>>, cfg: PresenceConfig) {
    set_presence_mode(cfg.mode);
    let mut w = Watch::new(cfg.clone());
    let mut tick: u32 = 0;
    let mut adopted: Option<Instant> = None;
    log::info!("presence watch on for {} (mode {}, tick {}s, away after {}s, attention {})", cfg.user, cfg.mode.name(), cfg.tick_seconds, cfg.away_seconds, cfg.require_attention);
    let mut on_battery = false;
    let mut mode = presence_mode();
    loop {
        let (tick_s, every) = if on_battery && cfg.battery_tick_seconds > 0.0 { (cfg.battery_tick_seconds, cfg.battery_identify_every) } else { (cfg.tick_seconds, cfg.identify_every) };
        std::thread::sleep(Duration::from_secs_f32(tick_s));
        tick = tick.wrapping_add(1);
        let battery = on_battery_now();
        if battery != on_battery {
            on_battery = battery;
            log::info!("presence: {} (tick {}s)", if battery { "on battery" } else { "on mains" }, if battery && cfg.battery_tick_seconds > 0.0 { cfg.battery_tick_seconds } else { cfg.tick_seconds });
        }
        let now_mode = presence_mode();
        if now_mode != mode {
            mode = now_mode;
            log::info!("presence: mode is now {}", mode.name());
        }
        // Identity is the dear part of a tick (the embedder costs several
        // times the detector): on its cadence while present, every other tick
        // while a face is there that has not been confirmed.
        let identify = tick.is_multiple_of(every.max(1)) || (w.state != State::Present && tick.is_multiple_of(2));
        // After locking, leave the camera to the lock screen (its own probe wakes
        // the panel); resume once an attempt has matched, or once the session
        // reads as unlocked by other means (a password, a fingerprint).
        if let Some(t) = w.locked_at {
            let matched = auth.lock().map(|a| a.last_match.get(&cfg.user).map(|m| *m > t).unwrap_or(false)).unwrap_or(false);
            let Some(how) = w.locked_step(Instant::now(), matched, &|| crate::consent::session_locked(&cfg.user)) else { continue };
            log::info!("presence: session unlocked {}, watch resumes", how);
        }
        {
            // A consent request that locked the session while the user was
            // away hands the lock to this watch, which then waits for the
            // face match that unlocks it like one of its own.
            let taken = auth.lock().ok().and_then(|a| a.session_locked_at);
            if let Some(t) = taken.filter(|t| adopted.map(|a| *t > a).unwrap_or(true)) {
                adopted = Some(t);
                w.locked(t);
                continue;
            }
        }
        let obs = {
            let mut a = auth.lock().unwrap_or_else(|p| p.into_inner());
            // A consent window that ran while this thread waited for the lock
            // is the user at the desk, not seconds unseen: the walk-away clock
            // restarts from the end of that flow, and from any face match.
            let recent = [a.last_consent.get(&cfg.user), a.last_match.get(&cfg.user)].into_iter().flatten().max().copied();
            if let Some(r) = recent {
                w.note_recent(r);
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
        let step = w.step(&obs, now, mode);
        if step.lock {
            log::info!("presence: locking the session");
            match run_lock_command(&cfg) {
                Ok(()) => w.locked(Instant::now()),
                Err(e) => log::warn!("lock command: {}", e),
            }
        }
        let pub_ = Published {
            state: step.state,
            attentive: obs.attentive,
            last_seen_secs_ago: step.away_for,
            locked_by_presence: w.locked_by_presence,
            mode,
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

/// Run the configured lock command. An empty command is refused at config
/// load; this guards the same case so the watch can never panic on it.
fn run_lock_command(cfg: &PresenceConfig) -> Result<()> {
    let Some(bin) = cfg.lock_command.first().filter(|b| !b.is_empty()) else { anyhow::bail!("no lock command configured") };
    let args: Vec<String> = cfg.lock_command.iter().skip(1).map(|a| if a.is_empty() { cfg.user.clone() } else { a.clone() }).collect();
    let o = std::process::Command::new(bin).args(&args).env("PATH", "/usr/local/bin:/usr/bin:/bin").output()?;
    if !o.status.success() {
        anyhow::bail!("exited {}: {} {}", o.status, String::from_utf8_lossy(&o.stdout).trim(), String::from_utf8_lossy(&o.stderr).trim());
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct Observation {
    pub(crate) face: bool,
    pub(crate) attentive: bool,
    /// The frame this look decided on, and the face box when one was found,
    /// so the watch can keep a reference and compare the next look to it.
    pub(crate) frame: Option<Grey>,
    pub(crate) bbox: Option<[f32; 4]>,
    /// Some(true/false) when an identity check ran.
    pub(crate) identity: Option<bool>,
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
pub(crate) fn observe(a: &mut Authenticator, cfg: &PresenceConfig, identify: bool) -> Result<Observation> {
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
        return Ok(Observation { face: false, attentive: false, identity: None, frame: None, bbox: None });
    };
    let faces = a.pipeline.detector.detect(&img, a.cfg.min_detection)?;
    let Some(face) = faces.into_iter().max_by(|x, y| x.score.total_cmp(&y.score)) else {
        cap.stop()?;
        return Ok(Observation { face: false, attentive: false, identity: None, frame: Some(img), bbox: None });
    };
    // A face was in view at this exposure: the next look starts from it.
    a.last_exposure = Some(cap.exposure);
    let p = pose::pose(&face.landmarks);
    // Attention from the mesh when the model is installed: its angles hold
    // where the five points' do not (a chin-up seen from below).
    let attentive = match a.pipeline.mesh.as_mut().and_then(|m| m.for_face(&img, &face).ok().flatten()) {
        Some(m) => faceauth_engine::mesh::is_attentive(&faceauth_engine::mesh::head_pose(&m), cfg.max_yaw * crate::consent::NodDetector::YAW_DEG_PER_UNIT, cfg.max_roll_degrees),
        None => pose::is_attentive(&p, cfg.max_yaw, cfg.max_roll_degrees),
    };
    let identity = if identify {
        // Liveness first: one lit/unlit pair under the alternating pattern.
        // A refusal is "not the user"; no signal (a bright room, a face far
        // back) decides nothing and the embedding decides alone, as before.
        if let Some(live) = strobe_pair(&mut cap, &a.cfg, &face)? {
            if !live {
                cap.stop()?;
                return Ok(Observation { face: true, attentive, identity: Some(false), frame: Some(img), bbox: Some(face.bbox) });
            }
        }
        let crop = faceauth_engine::align::align_112(&img, &face.landmarks);
        let e = a.pipeline.embedder.embed(&crop)?;
        // Templates only count on the camera they were enrolled on, and a
        // store that cannot be read is nobody, not everybody: the check fails
        // closed rather than skipping the tick with identity still assumed.
        let score = match a.store.load(&cfg.user) {
            Ok(Some(t)) => t.best_match_on(&e, &cap.identity).map(|(s, _)| s).unwrap_or(-1.0),
            Ok(None) => -1.0,
            Err(e) => {
                log::warn!("presence: templates unreadable, identity check fails: {}", e);
                -1.0
            }
        };
        if score < a.cfg.accept_threshold {
            // The score itself stays at debug: the journal is readable by
            // wheel on Omarchy, and a scored stream is a tuning oracle.
            log::info!("presence: identity check failed");
            log::debug!("presence: identity score {:.2} (exp {} gain {}, face {:.2})", score, cap.exposure.exposure, cap.exposure.gain, face.score);
        }
        Some(score >= a.cfg.accept_threshold)
    } else {
        None
    };
    cap.stop()?;
    log::debug!("presence tick: face {:.2} yaw {:.2} pitch {:.2} roll {:.0} attentive {} identity {:?}", face.score, p.yaw, p.pitch, p.roll.to_degrees(), attentive, identity);
    let bbox = face.bbox;
    Ok(Observation { face: true, attentive, identity, frame: Some(img), bbox: Some(bbox) })
}

/// How long a partly hidden face holds off the away clock, measured from
/// the last full sighting of the user. Long enough to read with a hand on
/// the chin; short enough that a coat on the chair does not keep the
/// machine open all evening.
pub const PARTIAL_GRACE_S: f32 = 120.0;

/// One strobed lit/unlit pair on the open camera, gated at `face`'s box:
/// `Some(true)` passed, `Some(false)` refused, `None` no usable pair within
/// the window (no signal, or the pattern never took). The gate's numbers
/// are logged at debug either way, so real faces and prints build up a
/// distribution for the thresholds.
fn strobe_pair(cap: &mut crate::capture::IrCapture, cfg: &crate::config::Config, face: &faceauth_engine::Face) -> Result<Option<bool>> {
    use faceauth_engine::liveness::{FlashResponse, StrobePhase, Verdict};
    if cap.illuminator.is_none() || !cfg.liveness {
        return Ok(None);
    }
    // A fresh random mask per look, and a pair counts only once the frames
    // have followed it (D5): a stream that brightens on its own schedule is
    // no signal here as everywhere else.
    let mut phase = StrobePhase::random();
    cap.illuminator.as_ref().unwrap().set_pattern(phase.pattern())?;
    let t0 = Instant::now();
    let mut prev: Option<Grey> = None;
    let mut verdict = None;
    while t0.elapsed() < Duration::from_millis(600) {
        let Some(img) = cap.next(Duration::from_millis(200))? else { continue };
        let mean = img.data.iter().map(|&v| v as f64).sum::<f64>() / img.data.len() as f64;
        let pair = phase.push(mean);
        let Some(p_img) = prev.replace(img.clone()) else { continue };
        if !pair {
            continue;
        }
        let fr = FlashResponse::measure(&img, &p_img, face, cap.exposure.exposure, cap.exposure.gain.max(16));
        match fr.verdict() {
            Verdict::Pass => {
                log::debug!("presence liveness: pass {:?}", fr);
                verdict = Some(true);
            }
            Verdict::NoSignal => {
                log::debug!("presence liveness: no signal {:?}", fr);
                continue;
            }
            v => {
                log::info!("presence liveness: refused ({:?})", v);
                log::debug!("presence liveness: refused {:?}", fr);
                verdict = Some(false);
            }
        }
        break;
    }
    cap.illuminator.as_ref().unwrap().set(true)?;
    Ok(verdict)
}

/// How alike the region under the last face box must look, against the
/// frame of the last full sighting, for "still there, face hidden".
/// Measured 2026-09-22: a hand over part of the face 1.00, a sheet over it
/// 0.95, the face fully covered 0.79, the chair empty -0.34.
pub const SAME_SHAPE: f32 = 0.60;

/// Is the person still in the chair? No face cleared the threshold, but the
/// shoulders and torso under where the face was look as they did at the
/// last full sighting. A hand over the face leaves them alone; standing up
/// replaces them with the wall.
pub fn same_shape(reference: &(Grey, [f32; 4]), frame: &Grey) -> f32 {
    let r = faceauth_engine::motion::below(reference.1, frame.width, frame.height);
    faceauth_engine::motion::similarity(&reference.0, frame, r)
}

/// Does a hidden-face sighting at `now` hold off the away clock?
pub fn partial_holds(now: Instant, last_full: Option<Instant>) -> bool {
    last_full.map(|t| now.duration_since(t).as_secs_f32() < PARTIAL_GRACE_S).unwrap_or(false)
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    fn obs(face: bool, identity: Option<bool>) -> Observation {
        Observation { face, attentive: true, frame: None, bbox: if face { Some([10.0, 10.0, 80.0, 80.0]) } else { None }, identity }
    }

    fn cfg() -> PresenceConfig {
        PresenceConfig { user: "alice".into(), away_seconds: 20.0, ..Default::default() }
    }

    /// Drive the watch through `looks`, five seconds apart, and return the
    /// tick (from 1) at which it first asked for the lock.
    fn first_lock(w: &mut Watch, t0: Instant, looks: &[Observation], mode: PresenceMode) -> Option<usize> {
        for (i, o) in looks.iter().enumerate() {
            let now = t0 + Duration::from_secs(5 * (i as u64 + 1));
            let step = w.step(o, now, mode);
            if step.lock {
                return Some(i + 1);
            }
        }
        None
    }

    /// A stranger in the chair does not hold the lock off: the away clock
    /// runs from the last sighting of the user and locks at away_seconds,
    /// in both modes (C1, ruling D2).
    #[test]
    fn a_stranger_in_view_locks_at_away_seconds_in_both_modes() {
        for mode in [PresenceMode::Default, PresenceMode::Secure] {
            let mut w = Watch::new(cfg());
            let t0 = Instant::now();
            let mut looks = vec![obs(true, Some(true))];
            looks.extend((0..12).map(|_| obs(true, Some(false))));
            let at = first_lock(&mut w, t0, &looks, mode).unwrap_or_else(|| panic!("{:?}: a stranger held the lock off", mode));
            // Secure: the user was last seen at tick 1 (5 s) and the clock
            // runs out at 25 s, tick 5. Default: the first failed check at
            // tick 2 is tolerated, so the clock runs from 10 s and locks at
            // tick 6. Either way the stranger never holds it past that.
            assert_eq!(at, if mode == PresenceMode::Secure { 5 } else { 6 }, "{:?}", mode);
            assert_eq!(w.state, State::Away);
        }
    }

    /// Between checks the stranger is reported as one, and the default mode
    /// waits for the second failed check before a face stops counting; the
    /// secure mode stops counting it on the first.
    #[test]
    fn one_failed_check_is_enough_only_in_the_secure_mode() {
        let looks: Vec<Observation> = vec![obs(true, Some(true)), obs(true, Some(false)), obs(true, None), obs(true, None), obs(true, None), obs(true, None), obs(true, None), obs(true, None)];
        let mut w = Watch::new(cfg());
        let t0 = Instant::now();
        assert_eq!(first_lock(&mut w, t0, &looks, PresenceMode::Default), None, "default: one failed check, then unconfirmed faces, still counts as the user");
        assert_eq!(w.state, State::Present);
        let mut w = Watch::new(cfg());
        assert_eq!(first_lock(&mut w, t0, &looks, PresenceMode::Secure), Some(5), "secure: the clock ran from the last good sighting at tick 1");
        // Default: the second failed check turns the face into a stranger and
        // the clock runs from the last good sighting.
        let mut w = Watch::new(cfg());
        let looks2 = vec![obs(true, Some(true)), obs(true, Some(false)), obs(true, Some(false)), obs(true, None)];
        assert_eq!(first_lock(&mut w, t0, &looks2, PresenceMode::Default), None);
        assert_eq!(w.state, State::Stranger);
    }

    /// A hidden face (no face found) holds the clock in the default mode
    /// only, and only with a matching shape; nothing holds it in the secure
    /// mode. Without a reference frame there is no shape, so the hold does
    /// not apply and the clock runs.
    #[test]
    fn a_hidden_face_holds_the_clock_only_in_the_default_mode_and_only_with_a_shape() {
        let mut frame = Grey::new(120, 120);
        frame.data.iter_mut().enumerate().for_each(|(i, v)| *v = (i % 251) as u8);
        let seen = Observation { face: true, attentive: true, frame: Some(frame.clone()), bbox: Some([20.0, 10.0, 40.0, 40.0]), identity: Some(true) };
        let hidden = Observation { face: false, attentive: false, frame: Some(frame.clone()), bbox: None, identity: None };
        let mut looks = vec![seen.clone()];
        looks.extend((0..8).map(|_| hidden.clone()));
        let t0 = Instant::now();
        let mut w = Watch::new(cfg());
        assert_eq!(first_lock(&mut w, t0, &looks, PresenceMode::Default), None, "default: the same shape under the box holds the clock");
        let mut w = Watch::new(cfg());
        assert_eq!(first_lock(&mut w, t0, &looks, PresenceMode::Secure), Some(5), "secure: nothing but the user's face holds it");
        // The reference is taken only from a look whose identity passed: a
        // sighting between checks leaves no shape to hold the clock (C1).
        let unchecked = Observation { identity: None, ..seen.clone() };
        let mut looks = vec![unchecked];
        looks.extend((0..8).map(|_| hidden.clone()));
        let mut w = Watch::new(cfg());
        assert_eq!(first_lock(&mut w, t0, &looks, PresenceMode::Default), Some(5));
    }

    /// While locked, the watch resumes on a face match, or on the session
    /// reading as unlocked by other means, checked every few ticks, with a
    /// fresh absence clock: a stranger after a password unlock locks again
    /// at away_seconds (C2).
    #[test]
    fn the_watch_resumes_after_an_unlock_without_a_face() {
        let mut w = Watch::new(cfg());
        let t0 = Instant::now();
        let _ = w.step(&obs(true, Some(true)), t0, PresenceMode::Default);
        w.locked(t0 + Duration::from_secs(30));
        assert!(w.locked_at.is_some() && w.locked_by_presence);
        let still_locked = || true;
        let unlocked = || false;
        let mut tick = 0u64;
        let mut now = || { tick += 1; t0 + Duration::from_secs(30 + 5 * tick) };
        for _ in 0..(LOCK_CHECK_TICKS * 2) {
            assert_eq!(w.locked_step(now(), false, &still_locked), None, "locked and no match: keep waiting");
        }
        // Unlocked by a password: noticed at the next check tick.
        let mut resumed = None;
        for _ in 0..LOCK_CHECK_TICKS {
            if let Some(how) = w.locked_step(now(), false, &unlocked) {
                resumed = Some(how);
                break;
            }
        }
        assert_eq!(resumed, Some("without a face"));
        assert!(w.locked_at.is_none() && !w.locked_by_presence);
        assert_eq!(w.state, State::Unknown, "nobody seen yet after a password unlock");
        // A stranger from here on: the fresh clock runs out and it locks again.
        let resume_at = t0 + Duration::from_secs(30 + 5 * tick);
        let looks: Vec<Observation> = (0..8).map(|_| obs(true, Some(false))).collect();
        // The first failed check is tolerated (tick 1 counts as seen), the
        // second is not: the clock runs from 5 s after the resume and locks
        // at 25 s, tick 5.
        assert_eq!(first_lock(&mut w, resume_at, &looks, PresenceMode::Default), Some(5), "the fresh clock runs out after the resume");
        // A face match resumes at once, and reads as present.
        w.locked(resume_at + Duration::from_secs(60));
        assert_eq!(w.locked_step(resume_at + Duration::from_secs(65), true, &still_locked), Some("by face"));
        assert_eq!(w.state, State::Present);
    }

    #[test]
    fn the_mode_switch_is_read_by_name() {
        assert_eq!(PresenceMode::parse("secure"), Some(PresenceMode::Secure));
        assert_eq!(PresenceMode::parse("default"), Some(PresenceMode::Default));
        assert_eq!(PresenceMode::parse("Secure"), None);
        set_presence_mode(PresenceMode::Secure);
        assert_eq!(presence_mode(), PresenceMode::Secure);
        set_presence_mode(PresenceMode::Default);
        assert_eq!(presence_mode(), PresenceMode::Default);
    }
}

#[cfg(test)]
mod partial_tests {
    use super::*;

    #[test]
    fn a_partial_face_holds_the_clock_only_after_a_full_sighting_and_only_for_the_grace() {
        let now = Instant::now();
        assert!(!partial_holds(now, None), "never seen in full: a weak blob is not the user");
        assert!(partial_holds(now, Some(now - Duration::from_secs(30))));
        assert!(!partial_holds(now, Some(now - Duration::from_secs_f32(PARTIAL_GRACE_S + 1.0))));
    }
}
