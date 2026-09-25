//! The authenticator and one attempt at the camera: the scan that scores
//! gated frames against the templates until enough of them match. The
//! consent flow runs the same scan, so a match means the same thing on the
//! lock screen and at the consent window.

use super::cooldown::Strikes;
#[cfg(feature = "dev-tools")]
use super::outcome::SweepFrame;
use super::outcome::{consent_denied, Outcome, Refusal};
use super::scan::{gated_face, scannable, Gated, Scan};
use crate::capture::IrCapture;
use crate::config::Config;
use crate::consent::{Answer, ConsentState};
use crate::store::{Store, UserTemplates};
use anyhow::{anyhow, Result};
use faceauth_engine::Pipeline;
use std::time::{Duration, Instant};

/// The optional hook `run_with` calls on the still-open camera once two
/// frames matched; `Ok(false)` from it turns the match into `ConsentDenied`.
type AfterMatch<'a> = Option<
    &'a mut (dyn FnMut(&mut IrCapture, &mut Pipeline, &faceauth_engine::Face) -> Result<bool> + 'a),
>;

pub struct Authenticator {
    pub cfg: Config,
    pub pipeline: Pipeline,
    pub store: Store,
    /// When the last attempt matched, per user; the presence watch resumes on it.
    pub last_match: std::collections::HashMap<String, Instant>,
    /// Recent failed attempts per user, for the cooldown.
    pub(super) failures: std::collections::HashMap<String, Strikes>,
    /// When the last consent flow ended, per user. The presence watch cannot
    /// tick while one runs (the camera lock is held for the whole window), so
    /// it treats the flow as the user being there rather than as time unseen.
    pub last_consent: std::collections::HashMap<String, Instant>,
    /// The exposure the last attempt settled on with a face in view; the
    /// presence watch starts its short looks from it.
    pub last_exposure: Option<faceauth_camera::calib::Exposure>,
}

impl Authenticator {
    pub fn new(cfg: Config) -> Result<Self> {
        let pipeline = Pipeline::load(&cfg.models_dir)?;
        if pipeline.mesh.is_none() {
            return Err(mesh_missing(&cfg.models_dir));
        }
        let store = Store::open(std::path::Path::new(crate::config::STORE_DIR))?;
        log::info!("templates rest {}", store.sealing().describe());
        if let crate::store::Sealing::Plain(_) = store.sealing() {
            log::warn!("templates would be written in plaintext (see above); a store that already holds sealed templates refuses to downgrade");
        }
        Ok(Authenticator {
            cfg,
            pipeline,
            store,
            last_match: Default::default(),
            failures: Default::default(),
            last_consent: Default::default(),
            last_exposure: None,
        })
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
            Err(e) => {
                return Outcome::Error {
                    message: e.to_string(),
                }
            }
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
                let Some(img) = cap.next(Duration::from_secs(2))? else {
                    continue;
                };
                if cap.frames % 2 != 0 {
                    continue;
                }
                let faces = self.pipeline.analyse(&img, self.cfg.min_detection, 1)?;
                let Some(face) = faces.first() else { continue };
                cap.meter_on(face);
                let Some(e) = &face.embedding else { continue };
                let p = faceauth_engine::pose::pose(&face.landmarks);
                let (score, template) = templates
                    .best_match_on(e, &device)
                    .unwrap_or((-1.0, usize::MAX));
                frames.push(SweepFrame {
                    t: t0.elapsed().as_secs_f32(),
                    score,
                    template,
                    yaw: p.yaw,
                    pitch: p.pitch,
                    nose_pitch: p.nose_pitch,
                    roll: p.roll.to_degrees(),
                    face_px: face.bbox[2],
                });
            }
            cap.stop()?;
            Ok(Outcome::Sweep {
                frames,
                templates: templates.usable_on(&device),
                elapsed_ms: t0.elapsed().as_millis() as u64,
            })
        })();
        match r {
            Ok(o) => o,
            Err(e) => Outcome::Error {
                message: e.to_string(),
            },
        }
    }

    /// One cheap look for the lock screen while its panel is blank: is
    /// anyone there? The presence watch's look without its identity check,
    /// so the probe stays detector-only, with no identity and no scores,
    /// and the two looks cannot drift apart again (H12).
    pub fn probe(&mut self) -> Outcome {
        let t0 = Instant::now();
        let look = crate::presence::PresenceConfig::default();
        match crate::presence::observe_in(self, &look, false, false, false) {
            Ok(o) => Outcome::Probe {
                face: o.face,
                attentive: o.attentive,
                face_px: o.bbox.map(|b| b[2]).unwrap_or(0.0),
                scannable: match (o.bbox, o.frame.as_ref()) {
                    (Some(b), Some(f)) => scannable(b[2], f.width, f.height),
                    _ => false,
                },
                elapsed_ms: t0.elapsed().as_millis() as u64,
            },
            Err(e) => Outcome::Error {
                message: e.to_string(),
            },
        }
    }

    pub fn ping(&self, user: &str) -> Outcome {
        let (loaded, load_error) = match self.store.load(user) {
            Ok(t) => (t, None),
            Err(e) => (None, Some(e.to_string())),
        };
        let templates = loaded.as_ref().map(|t| t.templates.len()).unwrap_or(0);
        let bound = loaded
            .as_ref()
            .map(|t| t.bound_devices())
            .unwrap_or_default();
        let floors = loaded
            .as_ref()
            .filter(|t| t.gesture.is_calibrated())
            .map(|t| consent_floors(&t.gesture));
        Outcome::Pong {
            version: env!("CARGO_PKG_VERSION").to_string(),
            model: faceauth_engine::embed::AURAFACE_FILE.to_string(),
            templates,
            sealed: self.store.is_sealed(user),
            bound,
            floors,
            load_error,
        }
    }

    pub fn authenticate(&mut self, user: &str) -> Outcome {
        let templates = match self.store.load(user) {
            Ok(Some(t)) => t,
            Ok(None) => return Outcome::NotEnrolled,
            Err(e) => {
                return Outcome::Error {
                    message: e.to_string(),
                }
            }
        };
        // Cooldown: a print held up at the lock screen does not get unlimited tries.
        if let Some(hold) = self.hold_for(user) {
            return Outcome::Cooldown {
                seconds: hold.as_secs().max(1),
            };
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
            Err(e) => Outcome::Error {
                message: e.to_string(),
            },
        }
    }

    /// The hold this user is under, if any.
    pub(super) fn hold_for(&mut self, user: &str) -> Option<Duration> {
        self.failures
            .entry(user.to_string())
            .or_default()
            .hold(Instant::now())
    }

    /// Record a failure where a face was seen; the hold it starts, if any.
    pub(super) fn charge(&mut self, user: &str) -> Option<Duration> {
        // A development build measuring distance limits runs many failing
        // attempts on purpose; FACEAUTH_DEV_NO_COOLDOWN keeps them from
        // starting holds. Release builds have no such switch.
        #[cfg(feature = "dev-tools")]
        if std::env::var_os("FACEAUTH_DEV_NO_COOLDOWN").is_some() {
            return None;
        }
        let now = Instant::now();
        let s = self.failures.entry(user.to_string()).or_default();
        s.charge(now);
        s.hold(now)
    }

    fn run(&mut self, templates: &UserTemplates) -> Result<Outcome> {
        let t = self.cfg.attempt_timeout;
        match self.run_with(templates, None, t)? {
            Scan::Done(o) => Ok(o),
            // Without a consent state there is nothing to answer.
            Scan::Answered(_) => Ok(Outcome::NoFace { elapsed_ms: 0 }),
        }
    }

    /// `after_match` runs on the still-open camera once two frames matched, before
    /// the outcome is returned; `Ok(false)` from it turns the match into
    /// `ConsentDenied`. Keeping the camera open avoids the two-to-three second
    /// restart that would otherwise eat the start of a consent gesture.
    fn run_with(
        &mut self,
        templates: &UserTemplates,
        after_match: AfterMatch<'_>,
        timeout_seconds: f32,
    ) -> Result<Scan> {
        self.run_with_answers(templates, after_match, timeout_seconds, None)
    }

    /// The scan, with the consent window's answers read between frames
    /// when `state` names the live request: an answer ends the scan at
    /// once as `Scan::Answered`, before the camera has said anything.
    pub(super) fn run_with_answers(
        &mut self,
        templates: &UserTemplates,
        after_match: AfterMatch<'_>,
        timeout_seconds: f32,
        state: Option<(&ConsentState, &str)>,
    ) -> Result<Scan> {
        let t0 = Instant::now();
        let deadline = Duration::from_secs_f32(timeout_seconds);
        let ms = |t: Instant| t.elapsed().as_millis() as u64;
        let mut cap = IrCapture::open(&self.cfg)?;
        let strobe = cap.illuminator.is_some();
        // Without the strobe the flash-response gate cannot run, and a print in
        // front of an IR camera is the documented attack. Refuse unless the
        // administrator has explicitly accepted ungated authentication.
        if !strobe && self.cfg.liveness_required {
            cap.stop()?;
            return Ok(Scan::Done(Outcome::Error {
                message:
                    "liveness gate unavailable (no strobe control) and liveness_required is set"
                        .into(),
            }));
        }
        // Templates only match on the camera they were enrolled on: a camera
        // swapped in for it has nothing to match against.
        let device = cap.identity.clone();
        if templates.usable_on(&device) == 0 {
            cap.stop()?;
            log::warn!(
                "attempt for {}: templates are bound to {:?}, this camera is {:?}; re-enrol",
                templates.user,
                templates.bound_devices(),
                device
            );
            return Ok(Scan::Done(Outcome::Error {
                message: format!(
                    "templates are bound to another camera ({}); this one is {}; re-enrol",
                    templates.bound_devices().join(", "),
                    device
                ),
            }));
        }
        if let Some(i) = &cap.illuminator {
            i.set(true)?;
        }
        // Phase 1: find the face and let the exposure settle on it (steady light).
        let mut face_seen = false;
        let mut last_face: Option<[f32; 4]> = None;
        let mut settle_info = String::new();
        let mut n_frames = 0usize;
        let cap_after = scoring_cap(self.cfg.attempt_timeout);
        loop {
            if t0.elapsed() > deadline {
                break;
            }
            if let Some((st, u)) = state {
                match st.poll(u) {
                    Some(Answer::Rearm) | None => {}
                    Some(a) => {
                        cap.stop()?;
                        return Ok(Scan::Answered(a));
                    }
                }
            }
            let Some(img) = cap.next(Duration::from_secs(2))? else {
                continue;
            };
            n_frames += 1;
            if cap.frames % 3 != 0 {
                continue;
            }
            let faces = self
                .pipeline
                .detector
                .detect(&img, self.cfg.min_detection)?;
            if let Some(f) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) {
                face_seen = true;
                last_face = Some(f.bbox);
                cap.meter_on(f);
            }
            // Settled: a face has been metered on for a few steps, or a second has
            // passed with one, and the flash on it reads rather than clips (C10).
            // The clip test is bounded, because auto-exposure holds where a
            // metered face clips between 5 and 15 percent and would never settle.
            if face_seen
                && t0.elapsed() > SETTLE
                && (cap.metering.clip < 0.05 || t0.elapsed() > SETTLE + Duration::from_millis(800))
            {
                self.last_exposure = Some(cap.exposure);
                settle_info = format!(
                    "settled at {:.2}s exp {} gain {} meter {:.2} frame mean {:.0}",
                    t0.elapsed().as_secs_f32(),
                    cap.exposure.exposure,
                    cap.exposure.gain,
                    cap.metering.mean,
                    img.mean()
                );
                break;
            }
        }
        if settle_info.is_empty() {
            log::info!("attempt detail: frames {} (never settled)", n_frames);
            cap.stop()?;
            return Ok(Scan::Done(Outcome::NoFace { elapsed_ms: ms(t0) }));
        }
        // Phase 2: score frames. With the strobe on its mask, only lit
        // frames after an unlit one are scored, each with that unlit
        // predecessor through the gate, and only once the frames have
        // followed the mask: a stream that brightens on its own schedule
        // is never a pair (D5). The gate owns the mask, the exposure freeze
        // and the pairing (H7); the face is detected and measured first and
        // embedded only on a pass, so a denied pair never pays a
        // recognition (J8).
        let (mut best, mut matches, mut scored) = (-1f32, 0usize, 0usize);
        let (mut n_lit, mut n_faces, mut n_nosignal) = (0usize, 0usize, 0usize);
        let mut score_trail: Vec<String> = Vec::new();
        let mut scoring_since: Option<Instant> = None;
        let mut gate = crate::strobe::StrobeGate::start(&mut cap, strobe)?;
        if let Some(b) = last_face {
            gate.focus_on(b);
        }
        let matched: Option<faceauth_engine::Face> = loop {
            if t0.elapsed() > deadline {
                break None;
            }
            if let Some((st, u)) = state {
                match st.poll(u) {
                    Some(Answer::Rearm) | None => {}
                    Some(a) => {
                        drop(gate);
                        cap.stop()?;
                        return Ok(Scan::Answered(a));
                    }
                }
            }
            // Scoring is bounded like a lock-screen attempt: a face that has
            // been scored for `scoring_cap` without matching ends the scan
            // as a non-match, charged, so the shared five-a-minute rule
            // reaches a stranger's face on this lane too (A4). The scan's
            // own length stays the wait for a face to appear.
            if scoring_over(scoring_since, Instant::now(), cap_after) {
                break None;
            }
            let Some(pair) = gate.next_frame(Duration::from_secs(2))? else {
                continue;
            };
            if pair.unlit.is_some() {
                n_lit += 1;
            }
            let face = match gated_face(
                &gate,
                &mut self.pipeline,
                &pair,
                self.cfg.min_detection,
                None,
            )? {
                Gated::NoFace => continue,
                Gated::NoSignal => {
                    n_faces += 1;
                    n_nosignal += 1;
                    continue;
                }
                Gated::Denied(why) => {
                    // The verdict only: the measurements behind it are
                    // the cues a print would be tuned against, and the
                    // journal is readable by wheel (D6).
                    log::warn!("liveness denied: {}", why);
                    drop(gate);
                    cap.stop()?;
                    return Ok(Scan::Done(Outcome::Denied {
                        reason: why,
                        elapsed_ms: ms(t0),
                    }));
                }
                Gated::Pass(face) => {
                    n_faces += 1;
                    gate.focus_on(face.bbox);
                    face
                }
            };
            let Some(e) = &face.embedding else { continue };
            let Some((score, _)) = templates.best_match_on(e, &device) else {
                continue;
            };
            scored += 1;
            scoring_since.get_or_insert_with(Instant::now);
            if score_trail.len() < 40 {
                score_trail.push(format!(
                    "{:.1}s:{:.2}{}",
                    t0.elapsed().as_secs_f32(),
                    score,
                    if score >= self.cfg.accept_threshold {
                        "*"
                    } else {
                        ""
                    }
                ));
            }
            #[cfg(debug_assertions)]
            if let Ok(dir) = std::env::var("FACEAUTH_DUMP") {
                if scored <= 3 {
                    let _ = std::fs::create_dir_all(&dir);
                    let _ = pair
                        .lit
                        .write_pgm(format!("{}/scored-{}-lit.pgm", dir, scored));
                    if let Some(u) = &pair.unlit {
                        let _ = u.write_pgm(format!("{}/scored-{}-unlit.pgm", dir, scored));
                    }
                    let _ = faceauth_engine::align::align_112(&pair.lit, &face.landmarks)
                        .write_pgm(format!("{}/scored-{}-crop.pgm", dir, scored));
                    let e = gate.exposure();
                    log::info!("dump {}: score {:.3} det {:.2} face {:.0}px at ({:.0},{:.0}) exp {} gain {}", scored, score, face.score, face.bbox[2], face.bbox[0], face.bbox[1], e.exposure, e.gain);
                }
            }
            best = best.max(score);
            if score >= self.cfg.accept_threshold {
                matches += 1;
            }
            log::debug!(
                "frame {} score {:.3} matches {}/{}",
                scored,
                score,
                matches,
                self.cfg.required_matches
            );
            if matches >= self.cfg.required_matches {
                break Some(face);
            }
            // The next match must come under a fresh mask (C11). Only a
            // match earns the redraw: redrawing after every scored pair
            // spent eight frames on each miss and halved the pairs an
            // attempt could score, and the matches are what a replay has
            // to land under two masks.
            if score >= self.cfg.accept_threshold {
                gate.redraw()?;
            }
        };
        let n_frames = n_frames + gate.frames();
        // The gate ends here: steady light and free-running exposure for
        // whatever follows, the gesture included.
        drop(gate);
        let Some(face) = matched else {
            // How many frames matched is logged only on success: on a failure
            // it says how close the presentation came (D6).
            log::info!(
                "attempt detail: frames {} lit {} faces {} nosignal {} scored {}",
                n_frames,
                n_lit,
                n_faces,
                n_nosignal,
                scored
            );
            log::debug!(
                "attempt scores: matches {} | {} | {}",
                matches,
                settle_info,
                score_trail.join(" ")
            );
            cap.stop()?;
            return Ok(Scan::Done(if scored == 0 {
                Outcome::NoFace { elapsed_ms: ms(t0) }
            } else {
                Outcome::NoMatch {
                    score: Some(best),
                    frames: scored,
                    elapsed_ms: ms(t0),
                }
            }));
        };
        // Scores (and the exposure they came at) are debug-only: the
        // journal is readable by wheel on Omarchy, so at info it would
        // be the tuning oracle the wire no longer is.
        log::info!(
            "attempt detail: frames {} lit {} faces {} nosignal {} scored {} matches {}",
            n_frames,
            n_lit,
            n_faces,
            n_nosignal,
            scored,
            matches
        );
        log::debug!(
            "attempt scores: {} | {}",
            settle_info,
            score_trail.join(" ")
        );
        if let Some(hook) = after_match {
            let ok = hook(&mut cap, &mut self.pipeline, &face)?;
            cap.stop()?;
            if !ok {
                return Ok(Scan::Done(consent_denied(Refusal::NoNod, ms(t0))));
            }
        } else {
            cap.stop()?;
        }
        Ok(Scan::Done(Outcome::Match {
            score: Some(best),
            frames: scored,
            elapsed_ms: ms(t0),
        }))
    }
}

/// How long the exposure takes to settle on a face before frames are
/// scored.
const SETTLE: Duration = Duration::from_millis(1200);

/// How long one scan may score a face without a match before it ends as a
/// non-match: a lock-screen attempt's `attempt_timeout` less its settle,
/// and never under a second, so a consent scan charges a stranger's face
/// at the lock screen's rate (A4).
pub fn scoring_cap(attempt_timeout: f32) -> Duration {
    Duration::from_secs_f32(attempt_timeout.max(0.0))
        .saturating_sub(SETTLE)
        .max(Duration::from_secs(1))
}

/// Has scoring run past the cap? `since` is when the first frame scored.
pub fn scoring_over(since: Option<Instant>, now: Instant, cap: Duration) -> bool {
    since.is_some_and(|s| now.saturating_duration_since(s) > cap)
}

/// A face match is proof a password guesser does not have: it clears the
/// account's bad-password lockout (pam_faillock), the way a correct
/// password would, since our line answers before faillock's own reset
/// module ever runs. Mike's call, 2026-09-22.
pub(super) fn faillock_reset(user: &str) {
    match std::process::Command::new("/usr/bin/faillock")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .args(["--user", user, "--reset"])
        .output()
    {
        Ok(o) if o.status.success() => {
            log::info!("faillock counter reset for {} after a face match", user)
        }
        Ok(o) => log::warn!(
            "faillock --reset for {} exited {}: {}",
            user,
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => log::warn!("faillock --reset for {}: {}", user, e),
    }
}

/// What the window asks for in a calibration round, and the prompt once
/// the face has matched. The everyday rounds record what a person does when
/// they are not gesturing, so their floors stand clear of it.
/// The floors the consent window's detectors run at for this person, in
/// degrees: the walk-through's derived ones, never under the detectors'
/// own minimums. `ping` reports the same pair, so the floors doctor shows
/// are the floors the nod window uses.
pub fn consent_floors(g: &crate::store::GestureCal) -> (f32, f32) {
    g.floors_deg(
        crate::consent::NodDetector::MESH_MIN_DEG,
        crate::consent::ShakeDetector::MESH_MIN_DEG,
    )
}

/// The face mesh is not optional: the gestures are read from its angles
/// and nothing else, and the enrolment walk-through refuses without it. A
/// daemon that started without it would open a nod window that can never
/// count, so it does not start at all; every PAM stack it sits in falls to
/// the password, and the log names the file and the package that ships it.
pub fn mesh_missing(models_dir: &std::path::Path) -> anyhow::Error {
    anyhow!(
        "the face mesh model {} is not in {}: the omarchy-faceauth-models package installs it (a development checkout runs `faceauth models fetch`); refusing to start",
        faceauth_engine::mesh::FACE_MESH_FILE,
        models_dir.display()
    )
}

#[cfg(test)]
mod scoring_cap_tests {
    use super::*;

    /// A4: a consent scan scores a face for no longer than a lock-screen
    /// attempt does, so a stranger's face is charged at the same rate.
    #[test]
    fn scoring_is_capped_at_an_attempt_less_its_settle() {
        assert_eq!(scoring_cap(6.0), Duration::from_millis(4800));
        assert_eq!(scoring_cap(3.5), Duration::from_millis(2300));
        assert_eq!(
            scoring_cap(1.0),
            Duration::from_secs(1),
            "never under a second"
        );
        let cap = scoring_cap(6.0);
        let t = Instant::now();
        assert!(
            !scoring_over(None, t + Duration::from_secs(60), cap),
            "no face scored yet: the scan waits its whole length"
        );
        assert!(!scoring_over(Some(t), t + Duration::from_millis(4700), cap));
        assert!(scoring_over(Some(t), t + Duration::from_millis(4900), cap));
    }
}

#[cfg(test)]
mod mesh_required_tests {
    use super::*;

    /// A daemon without the mesh model does not start, and the error says
    /// which file is missing and which package ships it (round-4 C3).
    #[test]
    fn the_daemon_refuses_to_start_without_the_mesh_model() {
        let e = mesh_missing(std::path::Path::new("/usr/share/faceauth/models")).to_string();
        assert!(e.contains(faceauth_engine::mesh::FACE_MESH_FILE), "{}", e);
        assert!(e.contains("/usr/share/faceauth/models"), "{}", e);
        assert!(e.contains("omarchy-faceauth-models"), "{}", e);
        assert!(e.contains("refusing to start"), "{}", e);
    }

    /// The floors `ping` reports (doctor's `gestures.calibrated` row) are
    /// the floors `consent_round` hands the nod window: one derivation,
    /// in degrees, never under the detectors' minimums.
    #[test]
    fn the_reported_floors_are_the_floors_the_nod_window_runs_at() {
        let none = crate::store::GestureCal::default();
        assert!(!none.is_calibrated());
        assert_eq!(
            consent_floors(&none),
            (
                crate::consent::NodDetector::MESH_MIN_DEG,
                crate::consent::ShakeDetector::MESH_MIN_DEG
            )
        );
        let g = crate::store::GestureCal {
            nod_reads_to_deg: vec![14.0, 14.0],
            shake_reads_to_deg: vec![26.0, 20.0],
            ..Default::default()
        };
        assert!(g.is_calibrated());
        let floors = consent_floors(&g);
        assert_eq!(
            floors,
            g.floors_deg(
                crate::consent::NodDetector::MESH_MIN_DEG,
                crate::consent::ShakeDetector::MESH_MIN_DEG
            )
        );
        let det = crate::consent::NodDetector::mesh(floors.0);
        assert!((det.inner.min_thr - floors.0).abs() < 1e-6);
        let shake = crate::consent::ShakeDetector::mesh(floors.1);
        assert!((shake.inner.min_thr - floors.1).abs() < 1e-6);
    }
}
