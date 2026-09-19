//! One authentication attempt: burst, recognise, flash-response gate, decide.
//!
//! The decision needs `required_matches` frames whose best template similarity
//! is at or above the threshold. When the illuminator is available the strobe
//! alternates and every scored frame is a lit frame whose pair passed the
//! liveness gate; a gate denial ends the attempt as `Denied` immediately.

use crate::capture::IrCapture;
use crate::consent::{notify, wait_for_nods, Dialog};
use crate::config::Config;
use crate::store::{Store, UserTemplates};
use anyhow::Result;
use faceauth_engine::liveness::{FlashResponse, Verdict};
use faceauth_engine::{Grey, Pipeline};
use serde::{Deserialize, Serialize};
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

pub struct Authenticator {
    pub cfg: Config,
    pub pipeline: Pipeline,
    pub store: Store,
    /// When the last attempt matched, per user; the presence watch resumes on it.
    pub last_match: std::collections::HashMap<String, Instant>,
    /// Recent failed attempts per user, for the cooldown.
    failures: std::collections::HashMap<String, Vec<Instant>>,
}

/// After this many failed attempts within the window, the user waits.
const COOLDOWN_FAILURES: usize = 5;
const COOLDOWN_WINDOW: Duration = Duration::from_secs(60);
const COOLDOWN_HOLD: Duration = Duration::from_secs(30);

impl Authenticator {
    pub fn new(cfg: Config) -> Result<Self> {
        let pipeline = Pipeline::load(&cfg.models_dir)?;
        let store = Store::open(&cfg.store_dir)?;
        Ok(Authenticator { cfg, pipeline, store, last_match: Default::default(), failures: Default::default() })
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
    pub fn authenticate_with_consent(&mut self, user: &str, caller: crate::consent::CallerInfo) -> Outcome {
        let mut dialog = Dialog::new(&self.cfg, user);
        if let Err(e) = dialog.show("scanning", "Look at the camera.", &caller, self.cfg.consent_seconds) {
            log::warn!("consent: no window for {}: {}", user, e);
            return Outcome::ConsentDenied { reason: "no graphical session to ask in".into(), elapsed_ms: 0 };
        }
        let templates = match self.store.load(user) {
            Ok(Some(t)) => t,
            Ok(None) => return Outcome::NotEnrolled,
            Err(e) => return Outcome::Error { message: e.to_string() },
        };
        let cfg = self.cfg.clone();
        let msg = format!("Recognised. Nod {} times to allow this.", cfg.consent_nods);
        let dialog_cell = std::cell::RefCell::new(&mut dialog);
        let caller_ref = &caller;
        let mut hook = |cap: &mut IrCapture, pipeline: &mut Pipeline| -> Result<bool> {
            let _ = dialog_cell.borrow_mut().show("nod", &msg, caller_ref, cfg.consent_seconds);
            wait_for_nods(cap, pipeline, cfg.min_detection, Duration::from_secs_f32(cfg.consent_seconds), cfg.consent_nods)
        };
        let outcome = match self.run_with(&templates, Some(&mut hook)) {
            Ok(o) => o,
            Err(e) => Outcome::Error { message: e.to_string() },
        };
        match &outcome {
            Outcome::Match { .. } => {
                self.last_match.insert(user.to_string(), Instant::now());
                self.failures.remove(user);
                let _ = dialog.show("approved", "Allowed.", &caller, 0.0);
                notify(&self.cfg, user, "Root access granted by face", &format!("{}\n{}", caller.command, caller.parents));
                log::info!("consent granted for {}: {} [{}]", user, caller.command, caller.parents);
                std::thread::sleep(Duration::from_millis(600));
            }
            Outcome::ConsentDenied { .. } => {
                let _ = dialog.show("denied", "No nod seen. Refused.", &caller, 0.0);
                log::warn!("consent refused for {} (no nod): {} [{}]", user, caller.command, caller.parents);
                std::thread::sleep(Duration::from_millis(900));
            }
            _ => {
                let _ = dialog.show("denied", "Face not recognised. Use your password.", &caller, 0.0);
                std::thread::sleep(Duration::from_millis(900));
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
        self.run_with(templates, None)
    }

    /// `after_match` runs on the still-open camera once two frames matched, before
    /// the outcome is returned; `Ok(false)` from it turns the match into
    /// `ConsentDenied`. Keeping the camera open avoids the two-to-three second
    /// restart that would otherwise eat the start of a consent gesture.
    fn run_with(&mut self, templates: &UserTemplates, after_match: Option<&mut dyn FnMut(&mut IrCapture, &mut Pipeline) -> Result<bool>>) -> Result<Outcome> {
        let t0 = Instant::now();
        let deadline = Duration::from_secs_f32(self.cfg.attempt_timeout);
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
