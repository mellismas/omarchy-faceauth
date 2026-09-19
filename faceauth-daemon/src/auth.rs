//! One authentication attempt: burst, recognise, flash-response gate, decide.
//!
//! The decision needs `required_matches` frames whose best template similarity
//! is at or above the threshold. When the illuminator is available the strobe
//! alternates and every scored frame is a lit frame whose pair passed the
//! liveness gate; a gate denial ends the attempt as `Denied` immediately.

use crate::capture::IrCapture;
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
}

pub struct Authenticator {
    pub cfg: Config,
    pub pipeline: Pipeline,
    pub store: Store,
}

impl Authenticator {
    pub fn new(cfg: Config) -> Result<Self> {
        let pipeline = Pipeline::load(&cfg.models_dir)?;
        let store = Store::open(&cfg.store_dir)?;
        Ok(Authenticator { cfg, pipeline, store })
    }

    pub fn authenticate(&mut self, user: &str) -> Outcome {
        let templates = match self.store.load(user) {
            Ok(Some(t)) => t,
            Ok(None) => return Outcome::NotEnrolled,
            Err(e) => return Outcome::Error { message: e.to_string() },
        };
        match self.run(&templates) {
            Ok(o) => o,
            Err(e) => Outcome::Error { message: e.to_string() },
        }
    }

    fn run(&mut self, templates: &UserTemplates) -> Result<Outcome> {
        let t0 = Instant::now();
        let deadline = Duration::from_secs_f32(self.cfg.attempt_timeout);
        let ms = |t: Instant| t.elapsed().as_millis() as u64;
        let mut cap = IrCapture::open(&self.cfg)?;
        let strobe = cap.illuminator.is_some() && self.cfg.liveness;
        if let Some(i) = &cap.illuminator {
            i.set(true)?;
        }
        // Phase 1: find the face and let the exposure settle on it (steady light).
        let mut settled = false;
        let mut prev: Option<(Grey, f64)> = None;
        let (mut best, mut matches, mut scored) = (-1f32, 0usize, 0usize);
        let mut face_seen = false;
        let mut alternating_since: Option<Instant> = None;
        loop {
            if t0.elapsed() > deadline {
                break;
            }
            let Some(img) = cap.next(Duration::from_secs(2))? else { continue };
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
                Some(p_img)
            } else {
                if cap.frames % 3 != 0 {
                    continue;
                }
                None
            };
            let faces = self.pipeline.analyse(&img, self.cfg.min_detection, 1)?;
            let Some(face) = faces.first() else { continue };
            if let Some(unlit) = &pair {
                let fr = FlashResponse::measure(&img, unlit, face, cap.exposure.exposure, cap.exposure.gain.max(16));
                match fr.verdict() {
                    Verdict::Pass => {}
                    Verdict::NoSignal => continue,
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
                cap.stop()?;
                return Ok(Outcome::Match { score: best, frames: scored, elapsed_ms: ms(t0) });
            }
        }
        cap.stop()?;
        if scored == 0 {
            Ok(Outcome::NoFace { elapsed_ms: ms(t0) })
        } else {
            Ok(Outcome::NoMatch { score: best, frames: scored, elapsed_ms: ms(t0) })
        }
    }
}
