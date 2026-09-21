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
    /// Enough frames matched; `score` is the best.
    Match { score: f32, frames: usize, elapsed_ms: u64 },
    /// A face was seen but did not match.
    NoMatch { score: f32, frames: usize, elapsed_ms: u64 },
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
    /// Answer to a ping: the daemon is up and its models are loaded.
    Pong { version: String, model: String, templates: usize },
    /// Enrolment result.
    Enrolled { added: usize, total: usize, consistency_min: f32, consistency_mean: f32, path: String },
    /// Templates deleted.
    Deleted,
    /// Too many failed attempts for this user recently; try again later.
    Cooldown { seconds: u64 },
    /// The face matched but the consent gesture did not come (or the window
    /// could not be shown): elevation refused.
    ConsentDenied { reason: String, elapsed_ms: u64 },
}

/// A consent request that outlives one turn with the camera.
/// "Wait for the user" as a finite number of seconds: about four months, so
/// every duration derived from it stays representable.
pub const NO_BUDGET: f32 = 1.0e7;

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
    failures: std::collections::HashMap<String, Vec<Instant>>,
    /// Answers from the consent window, shared with the server threads.
    pub answers: Answers,
    /// Users with a consent request in flight (the window is up).
    pub pending: Arc<Mutex<std::collections::HashSet<String>>>,
    /// When the last consent flow ended, per user. The presence watch cannot
    /// tick while one runs (the camera lock is held for the whole window), so
    /// it treats the flow as the user being there rather than as time unseen.
    pub last_consent: std::collections::HashMap<String, Instant>,
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

impl Authenticator {
    pub fn new(cfg: Config) -> Result<Self> {
        let pipeline = Pipeline::load(&cfg.models_dir)?;
        let store = Store::open(&cfg.store_dir)?;
        Ok(Authenticator { cfg, pipeline, store, last_match: Default::default(), failures: Default::default(), answers: Default::default(), pending: Default::default(), last_consent: Default::default(), session_locked_at: None, last_exposure: None })
    }

    /// One cheap look for the lock screen while its panel is blank: is anyone
    /// there? About half a second of camera, detection only, no identity.
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
        let templates = self.store.load(user).ok().flatten().map(|t| t.templates.len()).unwrap_or(0);
        Outcome::Pong { version: env!("CARGO_PKG_VERSION").to_string(), model: faceauth_engine::embed::AURAFACE_FILE.to_string(), templates }
    }

    /// Enrol: capture `count` embeddings over `seconds`, spaced across the
    /// window so they cover different poses, LEDs on, exposure metered on the
    /// face. Stored under `label` beside any existing templates.
    pub fn enroll(&mut self, user: &str, label: &str, seconds: f32, count: usize) -> Outcome {
        match self.run_enroll(user, label, seconds, count) {
            Ok(o) => o,
            Err(e) => Outcome::Error { message: e.to_string() },
        }
    }

    fn run_enroll(&mut self, user: &str, label: &str, seconds: f32, count: usize) -> Result<Outcome> {
        use crate::store::{now_secs, Template, UserTemplates};
        let mut u = self.store.load(user)?.unwrap_or_else(|| UserTemplates::new(user, faceauth_engine::embed::AURAFACE_FILE));
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
        let mut samples: Vec<(Vec<f32>, f32, f32)> = Vec::new();
        let mut last = Instant::now() - spacing;
        let mut seen = 0usize;
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
            last = Instant::now();
            if let Some(e) = &face.embedding {
                samples.push((e.clone(), face.score, face.bbox[2]));
            }
        }
        cap.stop()?;
        if samples.len() < 3 {
            return Ok(Outcome::Error { message: format!("only {} usable frames; face the camera at normal distance and try again", samples.len()) });
        }
        let now = now_secs();
        let added = samples.len();
        for (e, q, w) in samples {
            u.templates.push(Template { embedding: e, quality: q, face_width: w, created: now, label: label.to_string() });
        }
        let (lo, mean, _) = u.self_consistency().unwrap_or((1.0, 1.0, 1.0));
        let path = self.store.save(&u)?;
        Ok(Outcome::Enrolled { added, total: u.templates.len(), consistency_min: lo, consistency_mean: mean, path: path.display().to_string() })
    }

    /// An elevation request: the window goes up first, so nothing happens
    /// silently; then the face must match, then the nod must come.
    /// Start a consent request: open the window, load the templates, mark the
    /// user pending. Errors are final outcomes.
    pub fn consent_begin(&mut self, user: &str, caller: crate::consent::CallerInfo, budget: Option<f32>) -> std::result::Result<ConsentSession, Outcome> {
        let mut dialog = Dialog::new(&self.cfg, user);
        if let Err(e) = dialog.show("scanning", "Look at the camera.", &caller, 0.0) {
            log::warn!("consent: no window for {}: {}", user, e);
            return Err(Outcome::ConsentDenied { reason: "no graphical session to ask in".into(), elapsed_ms: 0 });
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
        // A caller with a limit of its own (the CLI) sets the budget, minus a
        // margin so it always sees the verdict. The PAM module sets none: the
        // window waits until it is answered, and the only way it ends without
        // an answer is the user dismissing it or the requester going away.
        let total = match budget {
            Some(b) => (b - 3.0).max(5.0),
            None => NO_BUDGET,
        };
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
        let msg = format!("Recognised. Nod {} times to allow this, or type your password.", cfg.consent_nods);
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
            let mut hook = |cap: &mut IrCapture, pipeline: &mut Pipeline| -> Result<bool> {
                let _ = dialog_cell.borrow_mut().show("nod", &msg, caller_ref, total);
                let left = total - started.elapsed().as_secs_f32();
                let g = wait_for_nods(cap, pipeline, cfg.min_detection, Duration::from_secs_f32(left.max(1.0)), cfg.consent_nods, Some((&answers, &user)), lost_after)?;
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
                (None, Outcome::ConsentDenied { reason, .. }) if reason == "requester gone" => return Round::Done(o.clone()),
                (Some(Gesture::FaceLost), _) => return Round::FaceLost,
                (None, Outcome::NoFace { .. }) if lost_after.is_some() => return Round::FaceLost,
                (None, Outcome::NoMatch { .. }) | (None, Outcome::NoFace { .. }) => {
                    let _ = dialog_cell.borrow_mut().show("scanning", "Face not recognised. Look at the camera, or type your password.", caller_ref, total);
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
                    let _ = dialog_cell.borrow_mut().show("scanning", "Not accepted. Look straight at the camera, or type your password.", caller_ref, total);
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
        drop(dialog_cell);
        Round::Done(self.consent_finish(s, gesture, outcome))
    }

    /// Turn a gesture and a face outcome into the verdict, show it, notify.
    /// Waiting is not scanning. After a round that found nobody to accept,
    /// the camera stays off but for a short look every two seconds, like the
    /// presence watch's, until a face is turned to the camera (then the next
    /// round scans it), the window answers (the next round takes the answer),
    /// or nobody has been there for the presence away time (the user left).
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
            (Some(Gesture::Dismissed), o) => Outcome::ConsentDenied { reason: "dismissed".into(), elapsed_ms: elapsed_of(&o) },
            (Some(Gesture::Password(_)), o) if !password_ok => Outcome::ConsentDenied { reason: "wrong password".into(), elapsed_ms: elapsed_of(&o) },
            (_, o) => o,
        };
        let outcome = if password_ok { Outcome::Match { score: 1.0, frames: 0, elapsed_ms: s.started.elapsed().as_millis() as u64 } } else { outcome };
        self.last_consent.insert(user.to_string(), Instant::now());
        match &outcome {
            Outcome::Match { frames, .. } => {
                self.last_match.insert(user.to_string(), Instant::now());
                self.failures.remove(user);
                let how = if *frames == 0 { "password" } else { "face and nod" };
                s.dialog.show_final("approved", "Allowed.", caller);
                notify(&self.cfg, user, &format!("Root access granted by {}", how), &format!("{}\n{}", caller.command, caller.parents));
                log::info!("consent granted ({}) for {}: {} [{}]", how, user, caller.command, caller.parents);
            }
            Outcome::ConsentDenied { reason, .. } if matches!(gesture, Some(Gesture::Dismissed)) || reason == "dismissed" => {
                // The user closed the window; do not put it back up with a
                // verdict on it.
                s.dialog.hide();
                log::warn!("consent refused for {}: {} [{}] (dismissed)", user, caller.command, caller.parents);
            }
            Outcome::ConsentDenied { .. } => {
                let why = match gesture { Some(Gesture::Password(_)) => "Wrong password. Refused.", _ => "No answer. Refused." };
                s.dialog.show_final("denied", &format!("{} Kill or block the requester, or dismiss.", why), caller);
                log::warn!("consent refused for {}: {} [{}] ({})", user, caller.command, caller.parents, why);
            }
            _ => {
                s.dialog.show_final("denied", "Refused. Kill or block the requester, or dismiss.", caller);
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
        let now = Instant::now();
        let fails = self.failures.entry(user.to_string()).or_default();
        fails.retain(|t| now.duration_since(*t) < COOLDOWN_WINDOW);
        if fails.len() >= COOLDOWN_FAILURES {
            let last = fails.last().copied().unwrap_or(now);
            let hold = COOLDOWN_HOLD.saturating_sub(now.duration_since(last));
            if !hold.is_zero() {
                return Outcome::Cooldown { seconds: hold.as_secs().max(1) };
            }
            fails.clear();
        }
        match self.run(&templates) {
            Ok(o) => {
                match &o {
                    Outcome::Match { .. } => {
                        self.last_match.insert(user.to_string(), Instant::now());
                        self.failures.remove(user);
                    }
                    Outcome::NoMatch { .. } | Outcome::Denied { .. } => {
                        self.failures.entry(user.to_string()).or_default().push(Instant::now());
                    }
                    _ => {}
                }
                o
            }
            Err(e) => Outcome::Error { message: e.to_string() },
        }
    }

    fn run(&mut self, templates: &UserTemplates) -> Result<Outcome> {
        let t = self.cfg.attempt_timeout;
        self.run_with(templates, None, t)
    }

    /// `after_match` runs on the still-open camera once two frames matched, before
    /// the outcome is returned; `Ok(false)` from it turns the match into
    /// `ConsentDenied`. Keeping the camera open avoids the two-to-three second
    /// restart that would otherwise eat the start of a consent gesture.
    fn run_with(&mut self, templates: &UserTemplates, after_match: Option<&mut dyn FnMut(&mut IrCapture, &mut Pipeline) -> Result<bool>>, timeout_seconds: f32) -> Result<Outcome> {
        self.run_with_answers(templates, after_match, timeout_seconds, None)
    }

    fn run_with_answers(&mut self, templates: &UserTemplates, after_match: Option<&mut dyn FnMut(&mut IrCapture, &mut Pipeline) -> Result<bool>>, timeout_seconds: f32, answers: Option<&(Answers, String)>) -> Result<Outcome> {
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
            let Some((score, _)) = templates.best_match(e) else { continue };
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
                log::info!("attempt detail: {} | frames {} lit {} faces {} nosignal {} scored {} matches {} | scores {}", settle_info, n_frames, n_lit, n_faces, n_nosignal, scored, matches, score_trail.join(" "));
                if let Some(hook) = after_match {
                    // Steady light and free-running exposure for the gesture.
                    if let Some(i) = &cap.illuminator {
                        i.set(true)?;
                    }
                    cap.freeze_exposure(false);
                    let ok = hook(&mut cap, &mut self.pipeline)?;
                    cap.stop()?;
                    if !ok {
                        return Ok(Outcome::ConsentDenied { reason: "no nod".into(), elapsed_ms: ms(t0) });
                    }
                    return Ok(Outcome::Match { score: best, frames: scored, elapsed_ms: ms(t0) });
                }
                cap.stop()?;
                return Ok(Outcome::Match { score: best, frames: scored, elapsed_ms: ms(t0) });
            }
        }
        log::info!("attempt detail: {} | frames {} lit {} faces {} nosignal {} scored {} matches {} | scores {}", if settle_info.is_empty() { "never settled".to_string() } else { settle_info.clone() }, n_frames, n_lit, n_faces, n_nosignal, scored, matches, score_trail.join(" "));
        cap.stop()?;
        if scored == 0 {
            Ok(Outcome::NoFace { elapsed_ms: ms(t0) })
        } else {
            Ok(Outcome::NoMatch { score: best, frames: scored, elapsed_ms: ms(t0) })
        }
    }
}

fn elapsed_of(o: &Outcome) -> u64 {
    match o {
        Outcome::Match { elapsed_ms, .. } | Outcome::NoMatch { elapsed_ms, .. } | Outcome::NoFace { elapsed_ms, .. } | Outcome::Denied { elapsed_ms, .. } | Outcome::ConsentDenied { elapsed_ms, .. } => *elapsed_ms,
        _ => 0,
    }
}
