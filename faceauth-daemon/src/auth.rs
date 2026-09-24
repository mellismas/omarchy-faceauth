//! One authentication attempt: burst, recognise, flash-response gate, decide.
//!
//! The decision needs `required_matches` frames whose best template similarity
//! is at or above the threshold. When the illuminator is available the strobe
//! alternates and every scored frame is a lit frame whose pair passed the
//! liveness gate; a gate denial ends the attempt as `Denied` immediately.

use crate::capture::IrCapture;
use crate::consent::{notify, take_answer, wait_for_nods, Answer, Answers, Dialog, Gesture};
use crate::config::Config;
use crate::store::{Store, UserTemplates};
use anyhow::Result;
use faceauth_engine::liveness::{FlashResponse, Verdict};
use faceauth_engine::{Grey, Pipeline};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Outcome {
    /// Enough frames matched; `score` is the best. The score is only sent
    /// to root: to any other caller it is a tuning oracle for a spoof.
    Match {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        score: Option<f32>,
        frames: usize,
        elapsed_ms: u64,
    },
    /// A face was seen but did not match.
    NoMatch {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        score: Option<f32>,
        frames: usize,
        elapsed_ms: u64,
    },
    /// No usable face within the timeout.
    NoFace { elapsed_ms: u64 },
    /// The liveness gate refused: a presentation attack or a flat object.
    Denied { reason: String, elapsed_ms: u64 },
    /// Nothing enrolled for this user.
    NotEnrolled,
    /// Camera or model failure; the caller falls through to the next factor.
    Error { message: String },
    /// Answer to a presence probe: one short look, detector only.
    Probe { face: bool, attentive: bool, face_px: f32, elapsed_ms: u64 },
    /// Root only: every frame of a pose sweep scored against the user's
    /// templates, with the head pose it was taken at.
    Sweep { frames: Vec<SweepFrame>, templates: usize, elapsed_ms: u64 },
    /// Answer to a ping: the daemon is up and its models are loaded.
    Pong {
        version: String,
        model: String,
        templates: usize,
        /// Whether this user's templates rest sealed to the TPM.
        #[serde(default)]
        sealed: bool,
        /// Templates from before camera binding, which match on any camera.
        #[serde(default)]
        unbound: usize,
        /// This user's gesture floors (nod, shake) if calibrated.
        #[serde(default)]
        floors: Option<(f32, f32)>,
    },
    /// Enrolment result.
    Enrolled { added: usize, total: usize, consistency_min: f32, consistency_mean: f32, path: String },
    /// Templates deleted.
    Deleted,
    /// A polkit context was noted for the request the agent is serving.
    Noted,
    /// A calibration round's measurement.
    Calibrated {
        gesture: String,
        /// The movement on the axis this round is about (vertical for a nod
        /// and for the everyday rounds, horizontal for a shake).
        amplitude: f32,
        /// The movement on the other axis.
        #[serde(default)]
        sideways: f32,
        stored: bool,
        nod_floor: f32,
        shake_floor: f32,
        /// Typical gesture over largest everyday movement, per axis, once both exist.
        #[serde(default)]
        nod_margin: Option<f32>,
        #[serde(default)]
        shake_margin: Option<f32>,
    },
    /// Too many failed attempts for this user recently; try again later.
    Cooldown { seconds: u64 },
    /// Every round of a calibration session replayed through the detectors
    /// at the floors it produced.
    Verified { rounds: Vec<RoundCheck>, all_ok: bool, nod_floor: f32, shake_floor: f32 },
    /// The consent request ended without an answer that could count: no
    /// window to ask in, the requester gone, no answer inside a caller's
    /// budget. Not a decision; the module ignores it and the caller's stack
    /// falls to its password.
    ConsentDenied { reason: String, elapsed_ms: u64 },
    /// The user said no to a polkit request: a head shake, the window
    /// dismissed, or the confirm after the nods refused. The module fails
    /// the stack on it and the agent cancels the request, so no other prompt
    /// follows. A sudo request gets `ConsentDenied` for the same answer
    /// instead: sudo's terminal prompt is where a password goes next, and a
    /// failure there would only make sudo ask again, ten times.
    Refused { reason: String, elapsed_ms: u64 },
}

impl Outcome {
    /// The outcome as an unprivileged caller may see it: without scores.
    pub fn redacted(self) -> Outcome {
        match self {
            Outcome::Match { frames, elapsed_ms, .. } => Outcome::Match { score: None, frames, elapsed_ms },
            Outcome::NoMatch { frames, elapsed_ms, .. } => Outcome::NoMatch { score: None, frames, elapsed_ms },
            Outcome::Sweep { templates, elapsed_ms, .. } => Outcome::Sweep { frames: Vec::new(), templates, elapsed_ms },
            o => o,
        }
    }
}

/// One frame of a pose sweep: when, the best cosine against the templates
/// and which one, and the head pose it was taken at (see `pose::Pose`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SweepFrame {
    pub t: f32,
    pub score: f32,
    pub template: usize,
    pub yaw: f32,
    pub pitch: f32,
    pub nose_pitch: f32,
    /// Sideways tilt, degrees.
    pub roll: f32,
    pub face_px: f32,
}

/// The longest a caller with a limit of its own (the CLI) may ask a consent
/// request to stay open.
pub const MAX_BUDGET: f32 = 3600.0;
/// A request from the PAM module has no deadline: like the lock screen it
/// waits, looking for attention, until it is answered or the requester goes
/// away. About four months, so every duration derived from it stays
/// representable.
pub const NO_DEADLINE: f32 = 1.0e7;

/// One round of a calibration session, as the daemon keeps it.
#[derive(Clone)]
pub struct CalRound {
    pub kind: String,
    pub frames: Vec<crate::consent::CalFrame>,
    /// The gesture amplitude this round added to the store, if it did.
    pub sample: Option<f32>,
}

/// One calibration round replayed at the derived floors.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RoundCheck {
    pub kind: String,
    pub nods: usize,
    pub shakes: usize,
    /// A nod round read as nods and nothing else, a shake round as shakes and
    /// nothing else, an everyday round as nothing.
    pub ok: bool,
}

pub struct ConsentSession {
    pub user: String,
    pub caller: crate::consent::CallerInfo,
    pub dialog: Dialog,
    pub started: Instant,
    /// Seconds the whole request may take.
    pub total: f32,
    templates: UserTemplates,
    pending: Arc<Mutex<std::collections::HashSet<String>>>,
    /// When this request locked the session because the user left.
    pub locked_at: Option<Instant>,
}

impl Drop for ConsentSession {
    fn drop(&mut self) {
        if let Ok(mut p) = self.pending.lock() {
            p.remove(&self.user);
        }
    }
}

pub enum Round {
    Done(Outcome),
    /// No face for the away time: lock, park, come back.
    FaceLost,
}

pub struct Authenticator {
    pub cfg: Config,
    pub pipeline: Pipeline,
    pub store: Store,
    /// When the last attempt matched, per user; the presence watch resumes on it.
    pub last_match: std::collections::HashMap<String, Instant>,
    /// Recent failed attempts per user, for the cooldown.
    failures: std::collections::HashMap<String, Strikes>,
    /// Answers from the consent window, shared with the server threads.
    pub answers: Answers,
    /// Users with a consent request in flight (the window is up).
    pub pending: Arc<Mutex<std::collections::HashSet<String>>>,
    /// When the last consent flow ended, per user. The presence watch cannot
    /// tick while one runs (the camera lock is held for the whole window), so
    /// it treats the flow as the user being there rather than as time unseen.
    pub last_consent: std::collections::HashMap<String, Instant>,
    /// The rounds of the calibration session in progress, per user: kind,
    /// frames, and the gesture sample the round stored (if any), kept until
    /// a new session starts so failed rounds can be redone and their
    /// samples withdrawn.
    pub cal_rounds: std::collections::HashMap<String, Vec<CalRound>>,
    /// When a consent request locked the session (the user left mid-request);
    /// the presence watch adopts it instead of locking again.
    pub session_locked_at: Option<Instant>,
    /// The exposure the last attempt settled on with a face in view; the
    /// presence watch starts its short looks from it.
    pub last_exposure: Option<faceauth_camera::calib::Exposure>,
}

/// After this many failed attempts within the window, the user waits.
const COOLDOWN_FAILURES: usize = 5;
const COOLDOWN_WINDOW: Duration = Duration::from_secs(60);
const COOLDOWN_HOLD: Duration = Duration::from_secs(30);
/// Each hold served without a match in between doubles the next, up to this
/// many doublings (30 s, 60 s, 120 s, 240 s, 480 s).
const COOLDOWN_MAX_DOUBLINGS: u32 = 4;
/// This long without a failure, and the escalation is forgotten.
const COOLDOWN_QUIET: Duration = Duration::from_secs(600);

/// A user's recent failures and the holds they have earned. A match clears
/// it. Shared by the lock-screen lane and the consent lane: a print held up
/// to either gets the same five tries and the same escalating holds.
#[derive(Default)]
pub struct Strikes {
    times: Vec<Instant>,
    last: Option<Instant>,
    /// The hold in force, if one is.
    until: Option<Instant>,
    /// Holds served since the last match (or the last quiet spell).
    holds: u32,
}

impl Strikes {
    fn charge(&mut self, now: Instant) {
        if self.holds > 0 && self.last.map(|l| now.duration_since(l) >= COOLDOWN_QUIET).unwrap_or(true) {
            // A long quiet spell forgets the escalation, not the failure.
            self.holds = 0;
        }
        self.times.push(now);
        self.last = Some(now);
    }

    /// The hold in force, if any. The first hold takes `COOLDOWN_FAILURES`
    /// failures inside the window; once one has been served, every further
    /// failure starts the next hold at once, twice as long as the last, until
    /// a match or `COOLDOWN_QUIET` without a failure.
    fn hold(&mut self, now: Instant) -> Option<Duration> {
        if let Some(u) = self.until {
            if now < u {
                return Some(u - now);
            }
            // Served. The failures are spent; the next one starts a longer hold.
            self.until = None;
            self.holds = self.holds.saturating_add(1);
            self.times.clear();
        }
        self.times.retain(|t| now.duration_since(*t) < COOLDOWN_WINDOW);
        let needed = if self.holds > 0 { 1 } else { COOLDOWN_FAILURES };
        if self.times.len() < needed {
            return None;
        }
        let last = self.times.last().copied().unwrap_or(now);
        let length = COOLDOWN_HOLD * 2u32.pow(self.holds.min(COOLDOWN_MAX_DOUBLINGS));
        let until = last + length;
        self.until = Some(until);
        self.times.clear();
        Some(until.saturating_duration_since(now))
    }
}

impl Authenticator {
    pub fn new(cfg: Config) -> Result<Self> {
        let pipeline = Pipeline::load(&cfg.models_dir)?;
        let store = Store::open(&cfg.store_dir)?;
        log::info!("templates rest {}", store.sealing().describe());
        if let crate::store::Sealing::Plain(_) = store.sealing() {
            log::warn!("templates would be written in plaintext (see above); a store that already holds sealed templates refuses to downgrade");
        }
        Ok(Authenticator { cfg, pipeline, store, last_match: Default::default(), failures: Default::default(), answers: Default::default(), pending: Default::default(), last_consent: Default::default(), cal_rounds: Default::default(), session_locked_at: None, last_exposure: None })
    }

    /// One cheap look for the lock screen while its panel is blank: is anyone
    /// there? About half a second of camera, detection only, no identity.
    /// A pose sweep: score every frame for `seconds` against the user's
    /// templates and record the head pose with it, so the curve of how the
    /// match falls off with yaw and pitch can be measured, and measured
    /// again after enrolment changes. Root only (the server enforces it):
    /// it returns scores.
    #[cfg(feature = "dev-tools")]
    pub fn sweep(&mut self, user: &str, seconds: f32) -> Outcome {
        let t0 = Instant::now();
        let templates = match self.store.load(user) {
            Ok(Some(t)) => t,
            Ok(None) => return Outcome::NotEnrolled,
            Err(e) => return Outcome::Error { message: e.to_string() },
        };
        let r = (|| -> Result<Outcome> {
            let mut cap = IrCapture::open(&self.cfg)?;
            if let Some(i) = &cap.illuminator {
                i.set(true)?;
            }
            let device = cap.identity.clone();
            let deadline = Duration::from_secs_f32(seconds.clamp(3.0, 60.0));
            let mut frames = Vec::new();
            while t0.elapsed() < deadline {
                let Some(img) = cap.next(Duration::from_secs(2))? else { continue };
                if cap.frames % 2 != 0 {
                    continue;
                }
                let faces = self.pipeline.analyse(&img, self.cfg.min_detection, 1)?;
                let Some(face) = faces.first() else { continue };
                cap.meter_on(face);
                let Some(e) = &face.embedding else { continue };
                let p = faceauth_engine::pose::pose(&face.landmarks);
                let (score, template) = templates.best_match_on(e, &device).unwrap_or((-1.0, usize::MAX));
                frames.push(SweepFrame { t: t0.elapsed().as_secs_f32(), score, template, yaw: p.yaw, pitch: p.pitch, nose_pitch: p.nose_pitch, roll: p.roll.to_degrees(), face_px: face.bbox[2] });
            }
            cap.stop()?;
            Ok(Outcome::Sweep { frames, templates: templates.usable_on(&device), elapsed_ms: t0.elapsed().as_millis() as u64 })
        })();
        match r {
            Ok(o) => o,
            Err(e) => Outcome::Error { message: e.to_string() },
        }
    }

    pub fn probe(&mut self) -> Outcome {
        let t0 = Instant::now();
        let r = (|| -> Result<Outcome> {
            let mut cap = IrCapture::open(&self.cfg)?;
            if let Some(i) = &cap.illuminator {
                i.set(true)?;
            }
            let mut img = None;
            let deadline = Instant::now() + Duration::from_millis(450);
            while Instant::now() < deadline {
                if let Some(g) = cap.next(Duration::from_millis(500))? {
                    img = Some(g);
                }
            }
            let out = match img {
                None => Outcome::Probe { face: false, attentive: false, face_px: 0.0, elapsed_ms: 0 },
                Some(img) => {
                    let faces = self.pipeline.detector.detect(&img, self.cfg.min_detection)?;
                    match faces.into_iter().max_by(|a, b| a.score.total_cmp(&b.score)) {
                        Some(f) => {
                            let p = faceauth_engine::pose::pose(&f.landmarks);
                            Outcome::Probe { face: true, attentive: faceauth_engine::pose::is_attentive(&p, 0.25, 25.0), face_px: f.bbox[2], elapsed_ms: 0 }
                        }
                        None => Outcome::Probe { face: false, attentive: false, face_px: 0.0, elapsed_ms: 0 },
                    }
                }
            };
            cap.stop()?;
            Ok(out)
        })();
        match r {
            Ok(Outcome::Probe { face, attentive, face_px, .. }) => Outcome::Probe { face, attentive, face_px, elapsed_ms: t0.elapsed().as_millis() as u64 },
            Ok(o) => o,
            Err(e) => Outcome::Error { message: e.to_string() },
        }
    }

    pub fn ping(&self, user: &str) -> Outcome {
        let loaded = self.store.load(user).ok().flatten();
        let templates = loaded.as_ref().map(|t| t.templates.len()).unwrap_or(0);
        let unbound = loaded.as_ref().map(|t| t.templates.iter().filter(|x| x.device.is_none()).count()).unwrap_or(0);
        let floors = loaded.as_ref().filter(|t| t.gesture.is_calibrated()).map(|t| t.gesture.floors(crate::consent::NodDetector::MIN_DOWN, crate::consent::ShakeDetector::MIN_TURN));
        Outcome::Pong { version: env!("CARGO_PKG_VERSION").to_string(), model: faceauth_engine::embed::AURAFACE_FILE.to_string(), templates, sealed: self.store.is_sealed(user), unbound, floors }
    }

    /// Enrol: capture `count` embeddings over `seconds`, spaced across the
    /// window so they cover different poses, LEDs on, exposure metered on the
    /// face. Stored under `label` beside any existing templates.
    pub fn enroll(&mut self, user: &str, label: &str, seconds: f32, count: usize, pose: Option<&str>) -> Outcome {
        match self.run_enroll(user, label, seconds, count, pose) {
            Ok(o) => o,
            Err(e) => Outcome::Error { message: e.to_string() },
        }
    }

    fn run_enroll(&mut self, user: &str, label: &str, seconds: f32, count: usize, pose: Option<&str>) -> Result<Outcome> {
        use crate::store::{now_secs, Template, UserTemplates};
        if let Some(p) = pose {
            if !POSES.contains(&p) {
                return Ok(Outcome::Error { message: format!("unknown pose {:?}; one of {}", p, POSES.join(", ")) });
            }
        }
        // Enrolment is the recovery path for a blob this machine can no longer
        // open (a cleared TPM, a firmware reset): set it aside and start fresh.
        let existing = match self.store.load(user) {
            Ok(t) => t,
            Err(e) => match self.store.set_aside_unreadable(user)? {
                Some(aside) => {
                    log::warn!("enrolment for {}: existing templates unreadable ({}); set aside as {} and starting fresh", user, e, aside.display());
                    None
                }
                None => return Err(e),
            },
        };
        let mut u = existing.unwrap_or_else(|| UserTemplates::new(user, faceauth_engine::embed::AURAFACE_FILE));
        if u.model != faceauth_engine::embed::AURAFACE_FILE {
            return Ok(Outcome::Error { message: format!("existing templates are for model {}; delete them first", u.model) });
        }
        let t0 = Instant::now();
        let deadline = Duration::from_secs_f32(seconds.clamp(4.0, 60.0));
        let count = count.clamp(3, 40);
        let spacing = Duration::from_millis((((seconds - 2.0).max(1.0) * 1000.0) / count as f32).clamp(150.0, 2000.0) as u64);
        let mut cap = IrCapture::open(&self.cfg)?;
        if let Some(i) = &cap.illuminator {
            i.set(true)?;
        }
        let mut samples: Vec<(Vec<f32>, f32, f32, faceauth_engine::pose::Pose)> = Vec::new();
        let mut last = Instant::now() - spacing;
        let mut seen = 0usize;
        let mut off_pose = 0usize;
        // This person's level, from the centre look already enrolled, so
        // up and down are measured against it rather than a fixed number.
        let level = level_of(&u);
        let (mut lo_seen, mut hi_seen) = (f32::MAX, f32::MIN);
        let (mut yaw_lo, mut yaw_hi) = (f32::MAX, f32::MIN);
        while t0.elapsed() < deadline && samples.len() < count {
            let Some(img) = cap.next(Duration::from_secs(2))? else { continue };
            if cap.frames % 3 != 0 {
                continue;
            }
            let faces = self.pipeline.analyse(&img, self.cfg.min_detection, 1)?;
            let Some(face) = faces.first() else { continue };
            seen += 1;
            cap.meter_on(face);
            // Let the metering act before the first sample, then space them out.
            if seen <= 3 || last.elapsed() < spacing {
                continue;
            }
            let p = faceauth_engine::pose::pose(&face.landmarks);
            // A guided round keeps only frames in the pose it asked for.
            if let Some(want) = pose {
                lo_seen = lo_seen.min(p.nose_pitch);
                hi_seen = hi_seen.max(p.nose_pitch);
                yaw_lo = yaw_lo.min(p.yaw);
                yaw_hi = yaw_hi.max(p.yaw);
                if !pose_bin_accepts_at(want, &p, level) {
                    off_pose += 1;
                    continue;
                }
            }
            last = Instant::now();
            if let Some(e) = &face.embedding {
                samples.push((e.clone(), face.score, face.bbox[2], p));
            }
        }
        let device = cap.identity.clone();
        cap.stop()?;
        if samples.len() < 3 {
            let hint = match pose {
                Some(p) if off_pose > 0 => {
                    let want = match p {
                        "up" => format!("up needs a pitch reading of {:.2} or less", level - UP_BELOW_LEVEL),
                        "down" => format!("down needs {:.2} or more", level + DOWN_ABOVE_LEVEL),
                        "left" => "left needs a turn reading of -0.18 or less".to_string(),
                        "right" => "right needs a turn reading of 0.18 or more".to_string(),
                        _ => format!("centre needs a turn within 0.12 and a pitch within 0.06 of {:.2}", level),
                    };
                    format!("only {} frames in the {} pose; the {} frames read pitch {:.2} to {:.2} and turn {:+.2} to {:+.2}, and {}. {}", samples.len(), p, off_pose, lo_seen, hi_seen, yaw_lo, yaw_hi, want, POSE_HINTS[POSES.iter().position(|q| *q == p).unwrap_or(0)])
                }
                _ => format!("only {} usable frames; face the camera at normal distance and try again", samples.len()),
            };
            return Ok(Outcome::Error { message: hint });
        }
        let now = now_secs();
        let added = samples.len();
        // Templates from before camera binding match on any camera. They were
        // enrolled on this machine's IR camera, which the enrolment running
        // now has just used, so bind them to it rather than leave one unbound
        // template holding the door open for every camera.
        let legacy = u.templates.iter().filter(|t| t.device.is_none()).count();
        if legacy > 0 {
            for t in u.templates.iter_mut().filter(|t| t.device.is_none()) {
                t.device = Some(device.clone());
            }
            log::info!("enrolment for {}: {} earlier template(s) bound to {}", user, legacy, device);
        }
        for (e, q, w, p) in samples {
            u.templates.push(Template { embedding: e, quality: q, face_width: w, created: now, label: label.to_string(), device: Some(device.clone()), yaw: Some(p.yaw), nose_pitch: Some(p.nose_pitch) });
        }
        // Over the cap, the surplus copies of looks already held go, not
        // the new look: coverage is what an identity is for.
        let pruned = u.prune_to(crate::store::MAX_TEMPLATES);
        if pruned > 0 {
            log::info!("enrolment for {}: {} near-duplicate template(s) dropped to stay within {}", user, pruned, crate::store::MAX_TEMPLATES);
        }
        let (lo, mean, _) = u.self_consistency().unwrap_or((1.0, 1.0, 1.0));
        let path = self.store.save(&u)?;
        Ok(Outcome::Enrolled { added, total: u.templates.len(), consistency_min: lo, consistency_mean: mean, path: path.display().to_string() })
    }

    /// An elevation request: the window goes up first, so nothing happens
    /// silently; then the face must match, then the nod must come.
    /// Start a consent request: open the window, load the templates, mark the
    /// user pending. Errors are final outcomes.
    /// With `open_window` false (the session is locked) the window is not
    /// summoned; the caller shows it when the request resumes.
    pub fn consent_begin(&mut self, user: &str, caller: crate::consent::CallerInfo, budget: Option<f32>, open_window: bool) -> std::result::Result<ConsentSession, Outcome> {
        // A caller with a limit of its own (the CLI) sets the budget, minus a
        // margin so it always sees the verdict. The PAM module sets none and
        // the request has no deadline: gestures are read for
        // `consent_seconds` after each match, and when that passes unanswered
        // the camera drops to the presence rhythm and an attentive face
        // re-arms it, as the lock screen does.
        let total = match budget {
            Some(b) if b.is_finite() => (b - 3.0).clamp(5.0, MAX_BUDGET),
            _ => NO_DEADLINE,
        };
        let mut dialog = match Dialog::new(&self.cfg, user) {
            Ok(d) => d,
            Err(e) => return Err(Outcome::Error { message: e.to_string() }),
        };
        if open_window {
            if let Err(e) = dialog.show("scanning", "Look at the camera.", &caller, 0.0) {
                log::warn!("consent: no window for {}: {}", user, e);
                return Err(Outcome::ConsentDenied { reason: "the consent window did not open".into(), elapsed_ms: 0 });
            }
        }
        let templates = match self.store.load(user) {
            Ok(Some(t)) => t,
            Ok(None) => return Err(Outcome::NotEnrolled),
            Err(e) => return Err(Outcome::Error { message: e.to_string() }),
        };
        let _ = take_answer(&self.answers, user); // stale answers from an earlier request
        if let Ok(mut p) = self.pending.lock() {
            p.insert(user.to_string());
        }
        self.last_consent.insert(user.to_string(), Instant::now());
        Ok(ConsentSession { user: user.to_string(), caller, dialog, started: Instant::now(), total, templates, pending: Arc::clone(&self.pending), locked_at: None })
    }

    /// One round with the camera: scan until the face matches, then watch for
    /// the nod. Ends with a verdict, or with the user gone (no face for the
    /// presence watch's away time) so the caller can lock the session, park
    /// without the camera and come back for another round.
    pub fn consent_round(&mut self, s: &mut ConsentSession) -> Round {
        let cfg = self.cfg.clone();
        let answers = Arc::clone(&self.answers);
        let user = s.user.clone();
        let total = s.total;
        let started = s.started;
        let lost_after = if cfg.presence.enabled && cfg.presence.user == s.user { Some(Duration::from_secs_f32(cfg.presence.away_seconds)) } else { None };
        let msg = format!("Recognised. Nod {} times to allow this, shake your head to refuse, or type your password.", cfg.consent_nods);
        let floors = s.templates.gesture.floors(crate::consent::NodDetector::MIN_DOWN, crate::consent::ShakeDetector::MIN_TURN);
        let dialog_cell = std::cell::RefCell::new(&mut s.dialog);
        let caller_ref = &s.caller;
        let gesture_cell: std::cell::RefCell<Option<Gesture>> = std::cell::RefCell::new(None);
        let scan_answers = (Arc::clone(&answers), user.clone());
        let gesture: Option<Gesture>;
        let outcome;
        loop {
            let left = total - started.elapsed().as_secs_f32();
            if left < 2.0 {
                outcome = Outcome::ConsentDenied { reason: "no answer".into(), elapsed_ms: started.elapsed().as_millis() as u64 };
                gesture = Some(Gesture::Timeout);
                break;
            }
            // A hold (the cooldown counts the lock screen's failures and this
            // lane's together) pauses the face checks, not the request: the
            // window stays up with its password box, and when the hold is
            // over the scan resumes on its own.
            if let Some(hold) = self.hold_for(&user) {
                // An answer already waiting (typed during the hold) goes to
                // the scan start, which takes it before touching the camera.
                let answered = answers.lock().map(|m| m.contains_key(&user)).unwrap_or(false);
                if !answered {
                    log::warn!("consent for {}: {} recent failures; face checks paused for {}s", user, COOLDOWN_FAILURES, hold.as_secs());
                    let _ = dialog_cell.borrow_mut().show("password", &format!("Too many failed face checks. They pause for {} seconds; type your password, or wait.", hold.as_secs().max(1)), caller_ref, 0.0);
                    self.wait_for_hold(&user, hold, &answers);
                    continue;
                }
            }
            let templates_ref = &s.templates;
            let mut hook = |cap: &mut IrCapture, pipeline: &mut Pipeline, matched: &faceauth_engine::Face| -> Result<bool> {
                // No window the daemon can vouch for, no nods: the request
                // ends and the caller's stack falls to its password.
                if let Err(e) = dialog_cell.borrow_mut().show("nod", &msg, caller_ref, 0.0) {
                    log::warn!("consent for {}: the window is not there to nod at: {}", user, e);
                    *gesture_cell.borrow_mut() = Some(Gesture::NoWindow);
                    return Ok(false);
                }
                let left = total - started.elapsed().as_secs_f32();
                let window = cfg.consent_seconds.clamp(10.0, MAX_BUDGET).min(left).max(1.0);
                let dwell = dialog_cell.borrow().dwell_left(Instant::now());
                let (g, followed) = wait_for_nods(cap, pipeline, &cfg, Duration::from_secs_f32(window), cfg.consent_nods, Some((&answers, &user)), lost_after, floors, Some(matched.bbox), dwell)?;
                let g = if g == Gesture::Nodded {
                    // The nods came from the followed box; before they count,
                    // that box must be live and enrolled, right now.
                    let _ = dialog_cell.borrow_mut().show("confirming", "Confirming.", caller_ref, 0.0);
                    match confirm(cap, pipeline, &cfg, templates_ref, followed.unwrap_or(matched.bbox))? {
                        Confirm::Live => Gesture::Nodded,
                        Confirm::NoSignal => Gesture::ConfirmUnclear,
                        Confirm::Refused(why) => Gesture::ConfirmFailed(why),
                    }
                } else {
                    g
                };
                let ok = matches!(g, Gesture::Nodded | Gesture::Password(_));
                *gesture_cell.borrow_mut() = Some(g);
                Ok(ok)
            };
            let scan = cfg.consent_scan_seconds.min(left);
            let o = match self.run_with_answers(&s.templates, Some(&mut hook), scan, Some(&scan_answers)) {
                Ok(o) => o,
                Err(e) => Outcome::Error { message: e.to_string() },
            };
            let g = gesture_cell.borrow_mut().take();
            match (&g, &o) {
                // Nobody is waiting for the verdict: no verdict, and the
                // window comes down when the session drops.
                (Some(Gesture::Gone), _) => return Round::Done(Outcome::ConsentDenied { reason: "requester gone".into(), elapsed_ms: started.elapsed().as_millis() as u64 }),
                (Some(Gesture::NoWindow), _) => return Round::Done(Outcome::ConsentDenied { reason: "the consent window did not open".into(), elapsed_ms: started.elapsed().as_millis() as u64 }),
                (None, Outcome::ConsentDenied { reason, .. }) if reason == "requester gone" => return Round::Done(o.clone()),
                (Some(Gesture::FaceLost), _) => return Round::FaceLost,
                (None, Outcome::NoFace { .. }) if lost_after.is_some() => return Round::FaceLost,
                // The confirm could not read the strobe (a bright room, the
                // user leaned away): not a refusal. Ask for the face and go
                // round again.
                (Some(Gesture::ConfirmUnclear), _) => {
                    log::info!("consent: the confirm saw no strobe signal; asking for the face again");
                    let _ = dialog_cell.borrow_mut().show("scanning", "Could not confirm. Face the camera and nod again, or type your password.", caller_ref, 0.0);
                    if let Some(r) = self.wait_for_attention(&user, &answers, lost_after) {
                        return r;
                    }
                    continue;
                }
                // The confirm refused: the thing that nodded is not a live
                // enrolled face. A failure, charged like a refused scan.
                (Some(Gesture::ConfirmFailed(why)), _) => {
                    log::warn!("consent: the confirm after the nods refused ({})", why);
                    let _ = self.charge(&user);
                    outcome = refusal(&s.caller, format!("confirm: {}", why), started.elapsed().as_millis() as u64);
                    gesture = g;
                    break;
                }
                // The nod window passed with nobody answering: no verdict.
                // The camera drops to the presence rhythm and an attentive
                // face re-arms the request, the lock screen's cycle.
                (Some(Gesture::Timeout), _) if total >= NO_DEADLINE => {
                    log::info!("consent: no answer in the nod window; waiting for attention");
                    let _ = dialog_cell.borrow_mut().show("scanning", "Look at the camera to nod, or type your password.", caller_ref, 0.0);
                    if let Some(r) = self.wait_for_attention(&user, &answers, lost_after) {
                        return r;
                    }
                    continue;
                }
                (None, Outcome::NoMatch { .. }) | (None, Outcome::NoFace { .. }) => {
                    if matches!(o, Outcome::NoMatch { .. }) && self.charge(&user).is_some() {
                        continue; // the loop top shows the hold
                    }
                    let _ = dialog_cell.borrow_mut().show("scanning", "Face not recognised. Look at the camera, or type your password.", caller_ref, 0.0);
                    if let Some(r) = self.wait_for_attention(&user, &answers, lost_after) {
                        return r;
                    }
                    continue;
                }
                // A liveness refusal is a verdict for a plain attempt, but the
                // window is waiting for the user: it keeps waiting (nothing is
                // approved by it), and the log keeps the refusal.
                (None, Outcome::Denied { reason, .. }) if reason != "password" => {
                    log::info!("consent: scan refused ({}); the window keeps waiting", reason);
                    if self.charge(&user).is_some() {
                        continue; // the loop top shows the hold
                    }
                    let _ = dialog_cell.borrow_mut().show("scanning", "Not accepted. Look straight at the camera, or type your password.", caller_ref, 0.0);
                    if let Some(r) = self.wait_for_attention(&user, &answers, lost_after) {
                        return r;
                    }
                    continue;
                }
                _ => {
                    gesture = g;
                    outcome = o;
                    break;
                }
            }
        }
        Round::Done(self.consent_finish(s, gesture, outcome))
    }

    /// A calibration round for one gesture: the window asks for it, the face
    /// must match, then the motion is measured for `seconds` and stored with
    /// the templates. Root only (the server enforces it). Nothing is decided.
    /// Replay every round of the user's calibration session at the floors
    /// they produced, as the consent loop would read them.
    pub fn calibrate_verify(&mut self, user: &str) -> Outcome {
        let mut u = match self.store.load(user) {
            Ok(Some(t)) => t,
            Ok(None) => return Outcome::NotEnrolled,
            Err(e) => return Outcome::Error { message: e.to_string() },
        };
        let needed = self.cfg.consent_nods;
        let rounds = self.cal_rounds.get(user).cloned().unwrap_or_default();
        // The floors this person's everyday rounds demand: start from the
        // gesture-derived ones and raise a floor, a step at a time and no
        // further than the cap, while any everyday round still reads as
        // that gesture. Sizes do not decide this; the detectors do.
        let (dn, ds) = (crate::consent::NodDetector::MIN_DOWN, crate::consent::ShakeDetector::MIN_TURN);
        let (mut nf, mut sf) = u.gesture.base_floors(dn, ds);
        let everyday: Vec<&CalRound> = rounds.iter().filter(|r| !matches!(r.kind.as_str(), "nod" | "shake")).collect();
        for _ in 0..40 {
            let (mut nods, mut shakes) = (0usize, 0usize);
            for r in &everyday {
                let (n, s) = crate::consent::replay_round(&r.frames, (nf, sf));
                nods += n;
                shakes += s;
            }
            let mut moved = false;
            if nods > 0 && nf < crate::store::GestureCal::NOD_FLOOR_MAX {
                nf = (nf + 0.01).min(crate::store::GestureCal::NOD_FLOOR_MAX);
                moved = true;
            }
            if shakes > 0 && sf < crate::store::GestureCal::SHAKE_FLOOR_MAX {
                sf = (sf + 0.01).min(crate::store::GestureCal::SHAKE_FLOOR_MAX);
                moved = true;
            }
            if !moved {
                break;
            }
        }
        if !everyday.is_empty() {
            let (bn, bs) = u.gesture.base_floors(dn, ds);
            u.gesture.nod_floor_min = if nf > bn { Some(nf) } else { None };
            u.gesture.shake_floor_min = if sf > bs { Some(sf) } else { None };
            if let Err(e) = self.store.save(&u) {
                return Outcome::Error { message: e.to_string() };
            }
        }
        let floors = u.gesture.floors(dn, ds);
        let checks: Vec<RoundCheck> = rounds
            .iter()
            .map(|r| {
                let (nods, shakes) = crate::consent::replay_round(&r.frames, floors);
                let ok = match r.kind.as_str() {
                    "nod" => nods >= needed && shakes == 0,
                    "shake" => shakes >= needed && nods == 0,
                    _ => nods == 0 && shakes == 0,
                };
                RoundCheck { kind: r.kind.clone(), nods, shakes, ok }
            })
            .collect();
        let all_ok = !checks.is_empty() && checks.iter().all(|c| c.ok);
        log::info!("calibration verified for {}: {} round(s), all ok {}; floors nod {:.3} shake {:.3}: {}", user, checks.len(), all_ok, floors.0, floors.1, checks.iter().map(|c| format!("{} {}n/{}s{}", c.kind, c.nods, c.shakes, if c.ok { "" } else { "!" })).collect::<Vec<_>>().join(" "));
        Outcome::Verified { rounds: checks, all_ok, nod_floor: floors.0, shake_floor: floors.1 }
    }

    pub fn calibrate(&mut self, user: &str, gesture: &str, seconds: f32, start: bool, replace: bool) -> Outcome {
        if start {
            self.cal_rounds.remove(user);
        }
        let mut u = match self.store.load(user) {
            Ok(Some(t)) => t,
            Ok(None) => return Outcome::NotEnrolled,
            Err(e) => return Outcome::Error { message: e.to_string() },
        };
        if replace {
            // Redoing a kind: this session's earlier rounds of it go, and so
            // does what they stored, so the floors come from the good ones.
            let mut changed = false;
            if let Some(rounds) = self.cal_rounds.get_mut(user) {
                let mut kept = Vec::new();
                for r in rounds.drain(..) {
                    if r.kind != gesture {
                        kept.push(r);
                        continue;
                    }
                    match (r.kind.as_str(), r.sample) {
                        ("nod", Some(v)) => { if let Some(i) = u.gesture.nod.iter().rposition(|x| *x == v) { u.gesture.nod.remove(i); changed = true; } }
                        ("shake", Some(v)) => { if let Some(i) = u.gesture.shake.iter().rposition(|x| *x == v) { u.gesture.shake.remove(i); changed = true; } }
                        (k, _) => { if let Some(i) = u.gesture.everyday.iter().rposition(|e| e.kind == k) { u.gesture.everyday.remove(i); changed = true; } }
                    }
                }
                *rounds = kept;
            }
            if changed {
                if let Err(e) = self.store.save(&u) {
                    return Outcome::Error { message: e.to_string() };
                }
            }
        }
        let view = u.clone();
        let cfg = self.cfg.clone();
        let (ask, prompt) = calibration_text(gesture);
        let caller = crate::consent::CallerInfo { command: format!("Calibration: {}", ask), verified: true, who: "faceauth calibrate, recording motion only".into(), via: "calibration".into(), ..Default::default() };
        let mut dialog = match crate::consent::Dialog::new(&cfg, user) {
            Ok(d) => d,
            Err(e) => return Outcome::Error { message: e.to_string() },
        };
        if let Err(e) = dialog.show("scanning", "Look at the camera.", &caller, seconds) {
            return Outcome::Error { message: format!("no window to calibrate in: {}", e) };
        }
        let dialog_cell = std::cell::RefCell::new(&mut dialog);
        let measured: std::cell::RefCell<Option<crate::consent::Measured>> = std::cell::RefCell::new(None);
        let msg = prompt;
        let mut hook = |cap: &mut IrCapture, pipeline: &mut Pipeline, _matched: &faceauth_engine::Face| -> Result<bool> {
            let _ = dialog_cell.borrow_mut().show("nod", msg, &caller, seconds);
            let m = crate::consent::measure_motion(cap, pipeline, &cfg, user, gesture, seconds)?;
            *measured.borrow_mut() = Some(m);
            Ok(false)
        };
        let scan = self.run_with_answers(&view, Some(&mut hook), cfg.consent_scan_seconds, None);
        dialog.hide();
        let Some(m) = measured.borrow_mut().take() else {
            return match scan {
                Ok(o @ Outcome::NoFace { .. }) | Ok(o @ Outcome::NoMatch { .. }) | Ok(o @ Outcome::Denied { .. }) => o,
                Ok(o) => Outcome::Error { message: format!("calibration did not run: {:?}", o) },
                Err(e) => Outcome::Error { message: e.to_string() },
            };
        };
        let (dy, dx) = (m.dy, m.dx);
        let frames = m.frames;
        let (amplitude, sideways, stored) = match gesture {
            "shake" => {
                // Below the default floor nothing would ever count: the
                // sample is reported but not stored, so a missed attempt
                // cannot lower a floor.
                let stored = dx >= crate::consent::ShakeDetector::MIN_TURN;
                if stored { u.gesture.shake.push(dx) }
                (dx, dy, stored)
            }
            "nod" => {
                let stored = dy >= crate::consent::NodDetector::MIN_DOWN;
                if stored { u.gesture.nod.push(dy) }
                (dy, dx, stored)
            }
            // An everyday movement: both axes are kept, however small, since
            // what matters is how far under the floors it stays. The
            // numbers-only fields of the earlier format go with the save.
            _ => {
                u.gesture.everyday.push(crate::store::EverydayRound { kind: gesture.to_string(), dy, dx });
                u.gesture.still_nod.clear();
                u.gesture.still_shake.clear();
                (dy, dx, true)
            }
        };
        if stored {
            if let Err(e) = self.store.save(&u) {
                return Outcome::Error { message: e.to_string() };
            }
        }
        let sample = if stored && matches!(gesture, "nod" | "shake") { Some(amplitude) } else { None };
        self.cal_rounds.entry(user.to_string()).or_default().push(CalRound { kind: gesture.to_string(), frames, sample });
        let (nf, sf) = u.gesture.floors(crate::consent::NodDetector::MIN_DOWN, crate::consent::ShakeDetector::MIN_TURN);
        let (nm, sm) = u.gesture.margins();
        log::info!("calibration for {}: {} moved {:.3} (sideways {:.3}, stored: {}); floors now nod {:.3} shake {:.3}", user, gesture, amplitude, sideways, stored, nf, sf);
        Outcome::Calibrated { gesture: gesture.to_string(), amplitude, sideways, stored, nod_floor: nf, shake_floor: sf, nod_margin: nm, shake_margin: sm }
    }

    /// Turn a gesture and a face outcome into the verdict, show it, notify.
    /// Waiting is not scanning. After a round that found nobody to accept,
    /// the camera stays off but for a short look every two seconds, like the
    /// presence watch's, until a face is turned to the camera (then the next
    /// round scans it), the window answers (the next round takes the answer),
    /// or nobody has been there for the presence away time (the user left).
    /// Sit out a hold without the camera: until it is over, or the window
    /// answers (a password or a dismissal, which the next scan start takes).
    fn wait_for_hold(&mut self, user: &str, hold: Duration, answers: &Answers) {
        let until = Instant::now() + hold;
        while Instant::now() < until {
            std::thread::sleep(Duration::from_millis(200));
            if answers.lock().map(|m| m.contains_key(user)).unwrap_or(false) {
                return;
            }
        }
    }

    fn wait_for_attention(&mut self, user: &str, answers: &Answers, lost_after: Option<Duration>) -> Option<Round> {
        let look = crate::presence::PresenceConfig { user: user.to_string(), ..Default::default() };
        let mut unseen_since = Instant::now();
        let mut looks = 0u32;
        loop {
            for _ in 0..10 {
                std::thread::sleep(Duration::from_millis(200));
                if answers.lock().map(|m| m.contains_key(user)).unwrap_or(false) {
                    return None;
                }
            }
            looks += 1;
            match crate::presence::observe(self, &look, false) {
                Ok(o) if o.face && o.attentive => {
                    log::info!("consent: a face turned to the camera after {} looks; scanning", looks);
                    return None;
                }
                Ok(o) => {
                    if o.face {
                        unseen_since = Instant::now();
                    } else if let Some(l) = lost_after {
                        {
                            if unseen_since.elapsed() > l {
                                log::info!("consent: nobody for {:.0}s while waiting; the user left", l.as_secs_f32());
                                return Some(Round::FaceLost);
                            }
                        }
                    }
                }
                Err(e) => log::warn!("consent: look while waiting: {}", e),
            }
        }
    }

    pub fn consent_finish(&mut self, s: &mut ConsentSession, gesture: Option<Gesture>, outcome: Outcome) -> Outcome {
        let user = s.user.as_str();
        let caller = &s.caller;
        // A password typed at any point is checked against the system stack;
        // a good one approves exactly like a nod.
        let password_ok = match (&gesture, &outcome) {
            (Some(Gesture::Password(pw)), _) => crate::pamcheck::check("system-auth", user, pw),
            (None, Outcome::Denied { reason, .. }) if reason == "password" => {
                // The scan phase returned early with a password answer; it is carried in `answers`.
                match take_answer(&self.answers, user) {
                    Some(Answer::Password(pw)) => crate::pamcheck::check("system-auth", user, &pw),
                    _ => false,
                }
            }
            _ => false,
        };
        let outcome = match (&gesture, outcome) {
            // Anything that is not an approval ends as a consent refusal, so
            // the module ignores it and the terminal password is the floor.
            (Some(Gesture::Timeout), o @ Outcome::Match { .. }) => Outcome::ConsentDenied { reason: "no answer".into(), elapsed_ms: elapsed_of(&o) },
            // A shake or a dismissal is the answer no: the window had the
            // password box, so closing it without either is a refusal that
            // ends the request, not a hand-off to another prompt.
            (Some(Gesture::Dismissed), o) => refusal(caller, "dismissed".into(), elapsed_of(&o)),
            (Some(Gesture::Shaken), o) => refusal(caller, "shaken".into(), elapsed_of(&o)),
            (Some(Gesture::Password(_)), o) if !password_ok => {
                // A face was seen and the password behind it was wrong: it
                // counts against the same budget as a failed scan.
                let _ = self.charge(user);
                Outcome::ConsentDenied { reason: "wrong password".into(), elapsed_ms: elapsed_of(&o) }
            }
            (_, o) => o,
        };
        let outcome = if password_ok { Outcome::Match { score: Some(1.0), frames: 0, elapsed_ms: s.started.elapsed().as_millis() as u64 } } else { outcome };
        self.last_consent.insert(user.to_string(), Instant::now());
        if !matches!(outcome, Outcome::Match { .. }) {
            // Whatever the card asked for rides on an approval only.
            let _ = crate::consent::take_passwordless(user);
        }
        match &outcome {
            Outcome::Match { frames, .. } => {
                self.last_match.insert(user.to_string(), Instant::now());
                self.failures.remove(user);
                let how = if *frames == 0 { "password" } else { "face and nod" };
                if *frames > 0 {
                    faillock_reset(user);
                }
                s.dialog.show_final("approved", "Allowed.", caller);
                notify(&self.cfg, user, &format!("Root access granted by {}", how), &format!("{}\n{}", caller.command, caller.parents));
                log::info!("consent granted ({}) for {}: {} [{}]", how, user, caller.command, caller.parents);
                // The card's passwordless button: the same approval turns
                // passwordless sudo on for the minutes asked, the way
                // Omarchy's own command would, with no further request.
                if let Some(minutes) = crate::consent::take_passwordless(user) {
                    if crate::consent::is_passwordless_command(caller) {
                        log::info!("passwordless sudo for {} not armed from the passwordless command's own request", user);
                        notify(&self.cfg, user, "Passwordless sudo: use the command's own answer", "The button does not apply to omarchy-sudo-passwordless itself.");
                    } else {
                    match crate::consent::enable_passwordless(std::path::Path::new("/etc/sudoers.d"), user, minutes, &|args| crate::consent::run_passwordless_timer(user, args)) {
                        Ok(_) => {
                            log::warn!("passwordless sudo on for {} for {} min, by the card's button and this approval", user, minutes);
                            notify(&self.cfg, user, &format!("Passwordless sudo on for {} minutes", minutes), "Any process running as you can use sudo without asking until then. Setup > Security > Passwordless Sudo turns it off early.");
                        }
                        Err(e) => {
                            log::warn!("passwordless sudo for {} not enabled: {:#}", user, e);
                            notify(&self.cfg, user, "Passwordless sudo not enabled", &format!("{:#}", e));
                        }
                    }
                    }
                }
            }
            Outcome::Refused { reason, .. } | Outcome::ConsentDenied { reason, .. } if reason == "shaken" || reason == "dismissed" => {
                // The user closed the window, or shook their head at it: the
                // answer is no, and the window goes away without a verdict on it.
                let _ = crate::consent::take_passwordless(user);
                s.dialog.hide();
                let how = if reason == "shaken" { "Refused by head shake" } else { "Refused: dismissed" };
                notify(&self.cfg, user, how, &format!("{}\n{}", caller.command, caller.parents));
                log::warn!("consent refused for {}: {} [{}] ({})", user, caller.command, caller.parents, reason);
            }
            Outcome::Refused { reason, .. } | Outcome::ConsentDenied { reason, .. } if reason.starts_with("confirm: ") => {
                s.dialog.show_final("denied", "The nod did not come from a live, enrolled face. Refused.", caller);
                notify(&self.cfg, user, "Refused: the nod was not a live, enrolled face", &format!("{}\n{}", caller.command, caller.parents));
                log::warn!("consent refused for {}: {} [{}] ({})", user, caller.command, caller.parents, reason);
            }
            Outcome::Cooldown { seconds } => {
                s.dialog.show_final("denied", &format!("Too many failed attempts. Try again in {} seconds, or use your password.", seconds), caller);
                notify(&self.cfg, user, "Refused: too many failed attempts", &format!("{}\n{}", caller.command, caller.parents));
                log::warn!("consent refused for {}: {} [{}] (cooldown {}s)", user, caller.command, caller.parents, seconds);
            }
            Outcome::ConsentDenied { .. } => {
                let why = match gesture { Some(Gesture::Password(_)) => "Wrong password. Refused.", _ => "No answer. Refused." };
                s.dialog.show_final("denied", &format!("{} Kill or block the requester, or dismiss.", why), caller);
                let how = match gesture { Some(Gesture::Password(_)) => "Refused: wrong password", _ => "Refused: no answer" };
                notify(&self.cfg, user, how, &format!("{}\n{}", caller.command, caller.parents));
                log::warn!("consent refused for {}: {} [{}] ({})", user, caller.command, caller.parents, why);
            }
            _ => {
                s.dialog.show_final("denied", "Refused. Kill or block the requester, or dismiss.", caller);
                notify(&self.cfg, user, "Refused", &format!("{}\n{}", caller.command, caller.parents));
            }
        }
        outcome
    }

    pub fn authenticate(&mut self, user: &str) -> Outcome {
        let templates = match self.store.load(user) {
            Ok(Some(t)) => t,
            Ok(None) => return Outcome::NotEnrolled,
            Err(e) => return Outcome::Error { message: e.to_string() },
        };
        // Cooldown: a print held up at the lock screen does not get unlimited tries.
        if let Some(hold) = self.hold_for(user) {
            return Outcome::Cooldown { seconds: hold.as_secs().max(1) };
        }
        match self.run(&templates) {
            Ok(o) => {
                match &o {
                    Outcome::Match { .. } => {
                        self.last_match.insert(user.to_string(), Instant::now());
                        self.failures.remove(user);
                        faillock_reset(user);
                    }
                    Outcome::NoMatch { .. } | Outcome::Denied { .. } => {
                        let _ = self.charge(user);
                    }
                    _ => {}
                }
                o
            }
            Err(e) => Outcome::Error { message: e.to_string() },
        }
    }

    /// The hold this user is under, if any.
    fn hold_for(&mut self, user: &str) -> Option<Duration> {
        self.failures.entry(user.to_string()).or_default().hold(Instant::now())
    }

    /// Record a failure where a face was seen; the hold it starts, if any.
    fn charge(&mut self, user: &str) -> Option<Duration> {
        let now = Instant::now();
        let s = self.failures.entry(user.to_string()).or_default();
        s.charge(now);
        s.hold(now)
    }

    fn run(&mut self, templates: &UserTemplates) -> Result<Outcome> {
        let t = self.cfg.attempt_timeout;
        self.run_with(templates, None, t)
    }

    /// `after_match` runs on the still-open camera once two frames matched, before
    /// the outcome is returned; `Ok(false)` from it turns the match into
    /// `ConsentDenied`. Keeping the camera open avoids the two-to-three second
    /// restart that would otherwise eat the start of a consent gesture.
    fn run_with(&mut self, templates: &UserTemplates, after_match: Option<&mut dyn FnMut(&mut IrCapture, &mut Pipeline, &faceauth_engine::Face) -> Result<bool>>, timeout_seconds: f32) -> Result<Outcome> {
        self.run_with_answers(templates, after_match, timeout_seconds, None)
    }

    fn run_with_answers(&mut self, templates: &UserTemplates, after_match: Option<&mut dyn FnMut(&mut IrCapture, &mut Pipeline, &faceauth_engine::Face) -> Result<bool>>, timeout_seconds: f32, answers: Option<&(Answers, String)>) -> Result<Outcome> {
        let t0 = Instant::now();
        let deadline = Duration::from_secs_f32(timeout_seconds);
        let ms = |t: Instant| t.elapsed().as_millis() as u64;
        let mut cap = IrCapture::open(&self.cfg)?;
        let strobe = cap.illuminator.is_some() && self.cfg.liveness;
        // Without the strobe the flash-response gate cannot run, and a print in
        // front of an IR camera is the documented attack. Refuse unless the
        // administrator has explicitly accepted ungated authentication.
        if !strobe && self.cfg.liveness_required {
            cap.stop()?;
            return Ok(Outcome::Error { message: "liveness gate unavailable (no strobe control) and liveness_required is set".into() });
        }
        // Templates only match on the camera they were enrolled on: a camera
        // swapped in for it has nothing to match against.
        let device = cap.identity.clone();
        if templates.usable_on(&device) == 0 {
            cap.stop()?;
            log::warn!("attempt for {}: templates are bound to {:?}, this camera is {:?}; re-enrol", templates.user, templates.bound_devices(), device);
            return Ok(Outcome::Error { message: format!("templates are bound to another camera ({}); this one is {}; re-enrol", templates.bound_devices().join(", "), device) });
        }
        if let Some(i) = &cap.illuminator {
            i.set(true)?;
        }
        // Phase 1: find the face and let the exposure settle on it (steady light).
        let mut settled = false;
        let mut prev: Option<(Grey, f64)> = None;
        let (mut best, mut matches, mut scored) = (-1f32, 0usize, 0usize);
        let mut face_seen = false;
        let mut alternating_since: Option<Instant> = None;
        let (mut n_frames, mut n_lit, mut n_faces, mut n_nosignal) = (0usize, 0usize, 0usize, 0usize);
        let mut settle_info = String::new();
        let mut score_trail: Vec<String> = Vec::new();
        loop {
            if t0.elapsed() > deadline {
                break;
            }
            if let Some((a, u)) = answers {
                // The window answered while we were still looking for the face.
                if let Ok(mut m) = a.lock() {
                    if let Some(ans) = m.get(u).cloned() {
                        match ans {
                            Answer::Dismiss => {
                                m.remove(u);
                                cap.stop()?;
                                return Ok(Outcome::ConsentDenied { reason: "dismissed".into(), elapsed_ms: ms(t0) });
                            }
                            Answer::Password(_) => {
                                // Leave it in the map for the caller to verify.
                                cap.stop()?;
                                return Ok(Outcome::Denied { reason: "password".into(), elapsed_ms: ms(t0) });
                            }
                            Answer::Gone => {
                                m.remove(u);
                                cap.stop()?;
                                return Ok(Outcome::ConsentDenied { reason: "requester gone".into(), elapsed_ms: ms(t0) });
                            }
                        }
                    }
                }
            }
            let Some(img) = cap.next(Duration::from_secs(2))? else { continue };
            n_frames += 1;
            let mean = img.data.iter().map(|&v| v as f64).sum::<f64>() / img.data.len() as f64;

            if !settled {
                if cap.frames % 3 != 0 {
                    continue;
                }
                let faces = self.pipeline.detector.detect(&img, self.cfg.min_detection)?;
                if let Some(f) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) {
                    face_seen = true;
                    cap.meter_on(f);
                }
                // Settled: a face has been metered on for a few steps, or a second has passed with one.
                if face_seen && t0.elapsed() > Duration::from_millis(1200) {
                    settled = true;
                    self.last_exposure = Some(cap.exposure);
                    settle_info = format!("settled at {:.2}s exp {} gain {} meter {:.2} frame mean {:.0}", t0.elapsed().as_secs_f32(), cap.exposure.exposure, cap.exposure.gain, cap.metering.mean, mean);
                    cap.freeze_exposure(true);
                    if strobe {
                        cap.illuminator.as_ref().unwrap().set_pattern(0xaa)?;
                        alternating_since = Some(Instant::now());
                    }
                }
                continue;
            }

            // Phase 2: score frames. With the strobe alternating, only lit frames
            // (brighter than their predecessor by a margin) are scored, each with
            // its unlit predecessor through the gate.
            let pair = if strobe {
                let Some((p_img, p_mean)) = prev.replace((img.clone(), mean)) else { continue };
                // Give the pattern a few frames to take effect after switching.
                if alternating_since.map(|t| t.elapsed() < Duration::from_millis(150)).unwrap_or(false) {
                    continue;
                }
                if mean < p_mean * 1.15 {
                    continue;
                }
                n_lit += 1;
                Some(p_img)
            } else {
                if cap.frames % 3 != 0 {
                    continue;
                }
                None
            };
            let faces = self.pipeline.analyse(&img, self.cfg.min_detection, 1)?;
            let Some(face) = faces.first() else { continue };
            n_faces += 1;
            if let Some(unlit) = &pair {
                let fr = FlashResponse::measure(&img, unlit, face, cap.exposure.exposure, cap.exposure.gain.max(16));
                match fr.verdict() {
                    Verdict::Pass => {}
                    Verdict::NoSignal => {
                        n_nosignal += 1;
                        continue;
                    }
                    v => {
                        log::warn!("liveness denied: {:?} {:?}", v, fr);
                        cap.stop()?;
                        return Ok(Outcome::Denied { reason: format!("{:?}", v), elapsed_ms: ms(t0) });
                    }
                }
            }
            let Some(e) = &face.embedding else { continue };
            let Some((score, _)) = templates.best_match_on(e, &device) else { continue };
            scored += 1;
            if score_trail.len() < 40 {
                score_trail.push(format!("{:.1}s:{:.2}{}", t0.elapsed().as_secs_f32(), score, if score >= self.cfg.accept_threshold { "*" } else { "" }));
            }
            #[cfg(debug_assertions)]
            if let Ok(dir) = std::env::var("FACEAUTH_DUMP") {
                if scored <= 3 {
                    let _ = std::fs::create_dir_all(&dir);
                    let _ = img.write_pgm(format!("{}/scored-{}-lit.pgm", dir, scored));
                    if let Some(u) = &pair {
                        let _ = u.write_pgm(format!("{}/scored-{}-unlit.pgm", dir, scored));
                    }
                    let _ = faceauth_engine::align::align_112(&img, &face.landmarks).write_pgm(format!("{}/scored-{}-crop.pgm", dir, scored));
                    log::info!("dump {}: score {:.3} det {:.2} face {:.0}px at ({:.0},{:.0}) exp {} gain {}", scored, score, face.score, face.bbox[2], face.bbox[0], face.bbox[1], cap.exposure.exposure, cap.exposure.gain);
                }
            }
            best = best.max(score);
            if score >= self.cfg.accept_threshold {
                matches += 1;
            }
            log::debug!("frame {} score {:.3} matches {}/{}", scored, score, matches, self.cfg.required_matches);
            if matches >= self.cfg.required_matches {
                // Scores (and the exposure they came at) are debug-only: the
                // journal is readable by wheel on Omarchy, so at info it would
                // be the tuning oracle the wire no longer is.
                log::info!("attempt detail: frames {} lit {} faces {} nosignal {} scored {} matches {}", n_frames, n_lit, n_faces, n_nosignal, scored, matches);
                log::debug!("attempt scores: {} | {}", settle_info, score_trail.join(" "));
                if let Some(hook) = after_match {
                    // Steady light and free-running exposure for the gesture.
                    if let Some(i) = &cap.illuminator {
                        i.set(true)?;
                    }
                    cap.freeze_exposure(false);
                    let ok = hook(&mut cap, &mut self.pipeline, face)?;
                    cap.stop()?;
                    if !ok {
                        return Ok(Outcome::ConsentDenied { reason: "no nod".into(), elapsed_ms: ms(t0) });
                    }
                    return Ok(Outcome::Match { score: Some(best), frames: scored, elapsed_ms: ms(t0) });
                }
                cap.stop()?;
                return Ok(Outcome::Match { score: Some(best), frames: scored, elapsed_ms: ms(t0) });
            }
        }
        log::info!("attempt detail: frames {} lit {} faces {} nosignal {} scored {} matches {}{}", n_frames, n_lit, n_faces, n_nosignal, scored, matches, if settle_info.is_empty() { " (never settled)" } else { "" });
        log::debug!("attempt scores: {} | {}", settle_info, score_trail.join(" "));
        cap.stop()?;
        if scored == 0 {
            Ok(Outcome::NoFace { elapsed_ms: ms(t0) })
        } else {
            Ok(Outcome::NoMatch { score: Some(best), frames: scored, elapsed_ms: ms(t0) })
        }
    }
}

/// A face match is proof a password guesser does not have: it clears the
/// account's bad-password lockout (pam_faillock), the way a correct
/// password would, since our line answers before faillock's own reset
/// module ever runs. Mike's call, 2026-09-22.
fn faillock_reset(user: &str) {
    match std::process::Command::new("/usr/bin/faillock").env_clear().env("PATH", "/usr/bin:/bin").args(["--user", user, "--reset"]).output() {
        Ok(o) if o.status.success() => log::info!("faillock counter reset for {} after a face match", user),
        Ok(o) => log::warn!("faillock --reset for {} exited {}: {}", user, o.status, String::from_utf8_lossy(&o.stderr).trim()),
        Err(e) => log::warn!("faillock --reset for {}: {}", user, e),
    }
}

/// The user's no, as the caller's lane can take it: polkit gets a refusal
/// that ends the request; sudo gets a fall-through to its own prompt.
fn refusal(caller: &crate::consent::CallerInfo, reason: String, elapsed_ms: u64) -> Outcome {
    if caller.via == "polkit" {
        Outcome::Refused { reason, elapsed_ms }
    } else {
        Outcome::ConsentDenied { reason, elapsed_ms }
    }
}

/// The confirm's verdict.
pub enum Confirm {
    /// Two strobed pairs passed the flash gate and matched the templates.
    Live,
    /// Every pair read no strobe signal: nothing to decide on.
    NoSignal,
    /// The gate refused, or the face did not match.
    Refused(String),
}

/// How long the confirm may take before it gives up.
const CONFIRM_SECONDS: f32 = 2.5;

/// After the nods: is the followed box a live, enrolled face right now?
/// The illuminator goes back to the alternating pattern and the exposure is
/// frozen; lit frames are gated against their unlit predecessor and embedded,
/// and two pairs at or above the accept threshold say yes. One gate refusal
/// or one non-match says no. Pairs with no signal are skipped; if that is
/// all there was, nothing is decided.
pub fn confirm(cap: &mut IrCapture, pipeline: &mut Pipeline, cfg: &Config, templates: &UserTemplates, followed: [f32; 4]) -> Result<Confirm> {
    if cap.illuminator.is_none() {
        // No strobe control: the scan already ran ungated under the
        // administrator's explicit setting, and so does this.
        return Ok(if cfg.liveness_required { Confirm::Refused("no strobe control".into()) } else { Confirm::Live });
    }
    cap.freeze_exposure(true);
    cap.illuminator.as_ref().unwrap().set_pattern(0xaa)?;
    let t0 = Instant::now();
    let device = cap.identity.clone();
    let mut prev: Option<(Grey, f64)> = None;
    let mut tracked = followed;
    let (mut passed, mut failed, mut nosignal, mut pairs) = (0usize, 0usize, 0usize, 0usize);
    let verdict = loop {
        if t0.elapsed().as_secs_f32() > CONFIRM_SECONDS {
            break if pairs == 0 || nosignal == pairs { Confirm::NoSignal } else { Confirm::Refused("no match within the confirm window".into()) };
        }
        let Some(img) = cap.next(Duration::from_secs(1))? else { continue };
        let mean = img.data.iter().map(|&v| v as f64).sum::<f64>() / img.data.len() as f64;
        let Some((p_img, p_mean)) = prev.replace((img.clone(), mean)) else { continue };
        if t0.elapsed() < Duration::from_millis(150) || mean < p_mean * 1.15 {
            continue;
        }
        let faces = pipeline.analyse(&img, cfg.min_detection, 1)?;
        let Some(face) = faces.first() else { continue };
        // The embedded face must be the followed one, not whichever scored best.
        match crate::consent::track(std::slice::from_ref(face), tracked) {
            crate::consent::Track::Found(_) => {}
            _ => {
                log::debug!("confirm: the scored face is not the followed box");
                continue;
            }
        }
        tracked = face.bbox;
        pairs += 1;
        let fr = FlashResponse::measure(&img, &p_img, face, cap.exposure.exposure, cap.exposure.gain.max(16));
        match fr.verdict() {
            Verdict::Pass => {}
            Verdict::NoSignal => {
                nosignal += 1;
                continue;
            }
            v => {
                log::warn!("confirm: liveness denied: {:?} {:?}", v, fr);
                break Confirm::Refused(format!("{:?}", v));
            }
        }
        let Some(e) = &face.embedding else { continue };
        match templates.best_match_on(e, &device) {
            Some((score, _)) if score >= cfg.accept_threshold => {
                passed += 1;
                log::debug!("confirm: pair {} matched", passed);
                if passed >= 2 {
                    break Confirm::Live;
                }
            }
            // One pair under the threshold is a frame caught mid-movement
            // as often as a stranger; the refusal, like the pass, takes two.
            Some((score, _)) => {
                failed += 1;
                log::debug!("confirm: pair {} under the threshold ({:.3})", pairs, score);
                if failed >= 2 {
                    break Confirm::Refused("the face that nodded does not match".into());
                }
            }
            None => break Confirm::Refused("no template for this camera".into()),
        }
    };
    cap.illuminator.as_ref().unwrap().set(true)?;
    log::info!("confirm: {} in {:.2}s ({} pairs, {} no signal, {} matched, {} under)", match &verdict { Confirm::Live => "live".to_string(), Confirm::NoSignal => "no signal".to_string(), Confirm::Refused(w) => format!("refused: {}", w) }, t0.elapsed().as_secs_f32(), pairs, nosignal, passed, failed);
    Ok(verdict)
}

/// What the window asks for in a calibration round, and the prompt once
/// the face has matched. The everyday rounds record what a person does when
/// they are not gesturing, so their floors stand clear of it.
pub fn calibration_text(gesture: &str) -> (&'static str, &'static str) {
    match gesture {
        "shake" => ("shake your head twice, naturally", "Recognised. Shake your head twice, the way you would to say no."),
        "read" => ("read the screen for a few seconds", "Recognised. Just read this window for a few seconds, the way you normally read."),
        "glance" => ("look down at the keyboard and back, twice", "Recognised. Look down at your keyboard and back up at the screen, twice."),
        "talk" => ("say a sentence or two, facing the screen", "Recognised. Keep facing the screen and say a sentence or two out loud, as if on a call."),
        "lean" => ("lean in toward the screen and back, twice", "Recognised. Lean in toward the screen and sit back, twice."),
        "aside" => ("look over at something beside the screen and back, twice", "Recognised. Look over at something beside the screen and back, twice."),
        _ => ("nod twice, naturally", "Recognised. Nod twice, the way you would to say yes."),
    }
}

/// The rounds `faceauth calibrate` runs: the two gestures, then the
/// everyday movements they must stand clear of.
pub const CALIBRATION_ROUNDS: [(&str, usize, f32); 7] = [("nod", 2, 8.0), ("shake", 2, 8.0), ("read", 1, 10.0), ("glance", 1, 8.0), ("talk", 1, 8.0), ("lean", 1, 8.0), ("aside", 1, 8.0)];

fn elapsed_of(o: &Outcome) -> u64 {
    match o {
        Outcome::Match { elapsed_ms, .. } | Outcome::NoMatch { elapsed_ms, .. } | Outcome::NoFace { elapsed_ms, .. } | Outcome::Denied { elapsed_ms, .. } | Outcome::ConsentDenied { elapsed_ms, .. } | Outcome::Refused { elapsed_ms, .. } => *elapsed_ms,
        _ => 0,
    }
}

#[cfg(test)]
mod strikes_tests {
    use super::*;

    fn t(secs: u64) -> Instant {
        // A fixed origin far enough in the past that every test time is after it.
        static ORIGIN: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(|| Instant::now() - Duration::from_secs(100_000));
        *ORIGIN + Duration::from_secs(secs)
    }

    #[test]
    fn five_failures_in_a_minute_start_a_hold() {
        let mut s = Strikes::default();
        for i in 0..4 {
            s.charge(t(i));
            assert_eq!(s.hold(t(i)), None, "four failures are free");
        }
        s.charge(t(4));
        let hold = s.hold(t(4)).expect("the fifth starts a hold");
        assert_eq!(hold, COOLDOWN_HOLD);
        assert_eq!(s.hold(t(4 + 10)), Some(COOLDOWN_HOLD - Duration::from_secs(10)));
    }

    #[test]
    fn each_served_hold_doubles_the_next() {
        let mut s = Strikes::default();
        for i in 0..5 {
            s.charge(t(i));
        }
        assert_eq!(s.hold(t(4)), Some(COOLDOWN_HOLD));
        // Served in full: free again, but the next failure is not a fresh budget.
        assert_eq!(s.hold(t(4 + 30)), None);
        s.charge(t(35));
        assert_eq!(s.hold(t(35)), Some(COOLDOWN_HOLD * 2), "one failure after a served hold starts the next, twice as long");
        assert_eq!(s.hold(t(35 + 60)), None);
        s.charge(t(96));
        assert_eq!(s.hold(t(96)), Some(COOLDOWN_HOLD * 4));
        // Ten quiet minutes and the escalation is forgotten: five tries again.
        assert_eq!(s.hold(t(96 + 120)), None);
        s.charge(t(96 + 120 + 600));
        assert_eq!(s.hold(t(96 + 120 + 600)), None);
    }

    #[test]
    fn the_doubling_is_capped() {
        let mut s = Strikes { last: Some(t(0)), holds: 40, ..Default::default() };
        for i in 0..5 {
            s.charge(t(i));
        }
        assert_eq!(s.hold(t(4)), Some(COOLDOWN_HOLD * 16));
    }

    #[test]
    fn failures_older_than_the_window_do_not_count() {
        let mut s = Strikes::default();
        for i in 0..4 {
            s.charge(t(i));
        }
        s.charge(t(70));
        assert_eq!(s.hold(t(70)), None, "four of the five are over a minute old");
    }
}

/// The looks a guided enrolment asks for, in order, and what to tell the
/// person for each. Yaw is the nose offset in inter-eye distances (about
/// 0.35 for a 30 degree turn); nose_pitch is the nose's drop below the eye
/// line in the same units (about 0.5 level, more looking down).
pub const POSES: [&str; 5] = ["centre", "left", "right", "up", "down"];
pub const POSE_HINTS: [&str; 5] = [
    "look straight at the camera",
    "turn your head to the left, about a quarter turn, and hold it",
    "turn your head to the right, about a quarter turn, and hold it",
    "tilt your chin up a little, not much, and hold it",
    "tilt your head down a little, as if reading the keyboard, and hold it",
];

/// The nose_pitch a person reads at level: the mean over their centre
/// templates, else over any template that recorded one, else the sweep's
/// typical 0.53 (2026-09-23; a lid camera looks up at the face, so the
/// chin-up moves this measure only a little).
pub const LEVEL_DEFAULT: f32 = 0.53;
/// How far below the level reading counts as chin-up, and above as chin-down.
pub const UP_BELOW_LEVEL: f32 = 0.02;
pub const DOWN_ABOVE_LEVEL: f32 = 0.08;

pub fn level_of(u: &UserTemplates) -> f32 {
    let centre: Vec<f32> = u.templates.iter().filter(|t| t.label.ends_with("-centre")).filter_map(|t| t.nose_pitch).collect();
    let any: Vec<f32> = u.templates.iter().filter_map(|t| t.nose_pitch).collect();
    let pick = if !centre.is_empty() { centre } else { any };
    if pick.is_empty() { LEVEL_DEFAULT } else { pick.iter().sum::<f32>() / pick.len() as f32 }
}

/// Is this frame in the pose a guided round asked for, with up and down
/// measured against this person's own level? Turn bands are from the
/// pose sweep of 2026-09-23: a quarter turn reads 0.25 to 0.40 on yaw.
pub fn pose_bin_accepts_at(name: &str, p: &faceauth_engine::pose::Pose, level: f32) -> bool {
    match name {
        "centre" => p.yaw.abs() <= 0.12 && (p.nose_pitch - level).abs() <= 0.06,
        "left" => p.yaw <= -0.18 && p.yaw >= -0.60,
        "right" => p.yaw >= 0.18 && p.yaw <= 0.60,
        "up" => p.nose_pitch <= level - UP_BELOW_LEVEL && p.yaw.abs() <= 0.20,
        "down" => p.nose_pitch >= level + DOWN_ABOVE_LEVEL && p.yaw.abs() <= 0.20,
        _ => false,
    }
}

/// The bands at the default level.
pub fn pose_bin_accepts(name: &str, p: &faceauth_engine::pose::Pose) -> bool {
    pose_bin_accepts_at(name, p, LEVEL_DEFAULT)
}

#[cfg(test)]
mod pose_bin_tests {
    use super::*;
    use faceauth_engine::pose::Pose;

    fn at(yaw: f32, nose_pitch: f32) -> Pose {
        Pose { yaw, pitch: 0.5, roll: 0.0, nose_pitch, mouth_drop: 1.0, inter_eye: 40.0 }
    }

    #[test]
    fn each_pose_takes_its_own_frames_and_no_others() {
        let frontal = at(0.0, LEVEL_DEFAULT);
        assert!(pose_bin_accepts("centre", &frontal));
        for p in ["left", "right", "up", "down"] {
            assert!(!pose_bin_accepts(p, &frontal), "{} must not take a frontal frame", p);
        }
        assert!(pose_bin_accepts("left", &at(-0.3, 0.5)) && !pose_bin_accepts("right", &at(-0.3, 0.5)));
        assert!(pose_bin_accepts("right", &at(0.3, 0.5)) && !pose_bin_accepts("centre", &at(0.3, 0.5)));
        assert!(pose_bin_accepts("up", &at(0.05, 0.50)) && !pose_bin_accepts("centre", &at(0.05, 0.44)), "a comfortable chin-up reads a couple of hundredths under level");
        assert!(pose_bin_accepts("down", &at(0.05, 0.7)) && !pose_bin_accepts("centre", &at(0.05, 0.7)));
        assert!(pose_bin_accepts("centre", &at(0.05, 0.55)) && !pose_bin_accepts("up", &at(0.05, 0.55)) && !pose_bin_accepts("down", &at(0.05, 0.55)), "level is level");
        // Relative to a person who reads higher at level, the same bands move with them.
        assert!(pose_bin_accepts_at("up", &at(0.0, 0.57), 0.60) && !pose_bin_accepts_at("up", &at(0.0, 0.59), 0.60));
        assert!(pose_bin_accepts_at("down", &at(0.0, 0.69), 0.60) && !pose_bin_accepts_at("down", &at(0.0, 0.66), 0.60));
        assert!(!pose_bin_accepts("left", &at(-0.9, 0.5)), "a profile is past what the aligner can use");
        assert!(!pose_bin_accepts("sideways", &frontal));
        assert_eq!(POSES.len(), POSE_HINTS.len());
    }
}
