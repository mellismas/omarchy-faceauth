//! One authentication attempt: burst, recognise, flash-response gate, decide.
//!
//! The decision needs `required_matches` frames whose best template similarity
//! is at or above the threshold. When the illuminator is available the strobe
//! follows a mask drawn for the attempt and every scored frame is a lit frame
//! whose pair passed the liveness gate; a gate denial ends the attempt as
//! `Denied` immediately.

use crate::capture::IrCapture;
use crate::config::Config;
use crate::consent::{notify, wait_for_nods, Answer, ConsentState, Dialog, Gesture, CONSENT};
use crate::store::{Store, UserTemplates};
use anyhow::{anyhow, Result};
use faceauth_engine::{Grey, Pipeline};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

/// The optional hook `run_with` calls on the still-open camera once two
/// frames matched; `Ok(false)` from it turns the match into `ConsentDenied`.
type AfterMatch<'a> = Option<
    &'a mut (dyn FnMut(&mut IrCapture, &mut Pipeline, &faceauth_engine::Face) -> Result<bool> + 'a),
>;

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
    Probe {
        face: bool,
        attentive: bool,
        face_px: f32,
        /// Near enough for an attempt to judge (`scannable`); the lock
        /// screen wakes the panel only for such a face.
        scannable: bool,
        elapsed_ms: u64,
    },
    /// Root only, development builds only: every frame of a pose sweep
    /// scored against the user's templates, with the head pose it was
    /// taken at.
    #[cfg(feature = "dev-tools")]
    Sweep {
        frames: Vec<SweepFrame>,
        templates: usize,
        elapsed_ms: u64,
    },
    /// Answer to a ping: the daemon is up and its models are loaded.
    Pong {
        version: String,
        model: String,
        templates: usize,
        /// Whether this user's templates rest sealed to the TPM.
        #[serde(default)]
        sealed: bool,
        /// The camera identities this user's templates are bound to
        /// (`IrCapture::identity`), sorted and deduplicated; `doctor`
        /// compares them with the live camera's identity.
        #[serde(default)]
        bound: Vec<String>,
        /// This user's gesture floors (nod, shake) in degrees, the ones the
        /// consent window runs at, once the walk-through has recorded them.
        #[serde(default)]
        floors: Option<(f32, f32)>,
        /// Why the templates could not be read, when they could not: a
        /// sealed blob this machine cannot open is not "not enrolled"
        /// (STORE-14).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        load_error: Option<String>,
    },
    /// Enrolment result.
    Enrolled {
        added: usize,
        total: usize,
        consistency_min: f32,
        consistency_mean: f32,
        path: String,
    },
    /// Templates deleted.
    Deleted,
    /// A polkit context was noted for the request the agent is serving.
    Noted,
    /// The presence watch's mode, whether the daemon watches this user,
    /// and, when it does, what the watch last decided (H16).
    PresenceMode {
        mode: String,
        watching: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state: Option<crate::presence::State>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        away_for: Option<f32>,
    },
    /// Too many failed attempts for this user recently; try again later.
    Cooldown { seconds: u64 },
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
            Outcome::Match {
                frames, elapsed_ms, ..
            } => Outcome::Match {
                score: None,
                frames,
                elapsed_ms,
            },
            Outcome::NoMatch {
                frames, elapsed_ms, ..
            } => Outcome::NoMatch {
                score: None,
                frames,
                elapsed_ms,
            },
            #[cfg(feature = "dev-tools")]
            Outcome::Sweep {
                templates,
                elapsed_ms,
                ..
            } => Outcome::Sweep {
                frames: Vec::new(),
                templates,
                elapsed_ms,
            },
            o => o,
        }
    }
}

/// One frame of a pose sweep: when, the best cosine against the templates
/// and which one, and the head pose it was taken at (see `pose::Pose`).
#[cfg(feature = "dev-tools")]
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

/// The nods that approve a request: one gesture, which the detector
/// counts as two nods (down-up, down-up). Fixed, so the card's "Nod 2
/// times" and the count the window needs cannot disagree (H15).
pub const NODS_NEEDED: usize = 2;

/// A consent request has no deadline: like the lock screen it waits,
/// looking for attention, until it is answered or the requester goes
/// away.
pub struct ConsentSession {
    pub user: String,
    pub caller: crate::consent::CallerInfo,
    pub dialog: Dialog,
    pub started: Instant,
    templates: UserTemplates,
    /// When the enrolled user was last known to be at the card: set as the
    /// request starts and refreshed only by a scan match, a passing identity
    /// look, and the nod window's frames of the matched box. The request's
    /// own away clock runs from it, wherever the round is (a scan, the wait
    /// for attention, a hold), so a stranger who takes the chair while a
    /// card is up is locked out at the presence away time like anyone
    /// else (E2). The server resets it when a parked request resumes at an
    /// unlock.
    pub user_seen_at: std::cell::Cell<Instant>,
}

pub enum Round {
    Done(Outcome),
    /// No face for the away time: lock, park, come back.
    FaceLost,
    /// The session locked under the card by other means (the idle lock, a
    /// key, the lid): park without locking again, come back at the unlock.
    SessionLocked,
}

pub struct Authenticator {
    pub cfg: Config,
    pub pipeline: Pipeline,
    pub store: Store,
    /// When the last attempt matched, per user; the presence watch resumes on it.
    pub last_match: std::collections::HashMap<String, Instant>,
    /// Recent failed attempts per user, for the cooldown.
    failures: std::collections::HashMap<String, Strikes>,
    /// When the last consent flow ended, per user. The presence watch cannot
    /// tick while one runs (the camera lock is held for the whole window), so
    /// it treats the flow as the user being there rather than as time unseen.
    pub last_consent: std::collections::HashMap<String, Instant>,
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
        if self.holds > 0
            && self
                .last
                .map(|l| now.duration_since(l) >= COOLDOWN_QUIET)
                .unwrap_or(true)
        {
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
        self.times
            .retain(|t| now.duration_since(*t) < COOLDOWN_WINDOW);
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
        match crate::presence::observe_in(self, &look, false, false) {
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

    /// Enrol: capture `count` embeddings over `seconds`, spaced across the
    /// window so they cover different poses, LEDs on, exposure metered on the
    /// face. Stored under `label` beside any existing templates.
    pub fn enroll(
        &mut self,
        user: &str,
        label: &str,
        seconds: f32,
        count: usize,
        pose: Option<&str>,
    ) -> Outcome {
        match self.run_enroll(user, label, seconds, count, pose) {
            Ok(o) => o,
            Err(e) => Outcome::Error {
                message: e.to_string(),
            },
        }
    }

    fn run_enroll(
        &mut self,
        user: &str,
        label: &str,
        seconds: f32,
        count: usize,
        pose: Option<&str>,
    ) -> Result<Outcome> {
        use crate::store::{now_secs, Template, UserTemplates};
        if let Some(p) = pose {
            if !POSES.contains(&p) {
                return Ok(Outcome::Error {
                    message: format!("unknown pose {:?}; one of {}", p, POSES.join(", ")),
                });
            }
        }
        // The store's one enrolment opener, shared with the walk-through:
        // no plaintext over a sealed set, and a blob this machine can no
        // longer open goes aside only on the credential tool's own verdict
        // (F2). Its error becomes the outcome's message.
        let existing = self.store.open_for_enrolment(user)?;
        let uid = crate::store::current_uid(user)
            .ok_or_else(|| anyhow::anyhow!("unknown user {}", user))?;
        let mut u = existing.unwrap_or_else(|| {
            UserTemplates::new(user, uid, faceauth_engine::embed::AURAFACE_FILE)
        });
        if u.model != faceauth_engine::embed::AURAFACE_FILE {
            return Ok(Outcome::Error {
                message: format!(
                    "existing templates are for model {}; delete them first",
                    u.model
                ),
            });
        }
        let t0 = Instant::now();
        let deadline = Duration::from_secs_f32(seconds.clamp(4.0, 60.0));
        let count = count.clamp(3, 40);
        let spacing = Duration::from_millis(
            (((seconds - 2.0).max(1.0) * 1000.0) / count as f32).clamp(150.0, 2000.0) as u64,
        );
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
            let Some(img) = cap.next(Duration::from_secs(2))? else {
                continue;
            };
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
                        "up" => format!(
                            "up needs a pitch reading of {:.2} or less",
                            level - UP_BELOW_LEVEL
                        ),
                        "down" => format!("down needs {:.2} or more", level + DOWN_ABOVE_LEVEL),
                        "left" => "left needs a turn reading of -0.18 or less".to_string(),
                        "right" => "right needs a turn reading of 0.18 or more".to_string(),
                        _ => format!(
                            "centre needs a turn within 0.12 and a pitch within 0.06 of {:.2}",
                            level
                        ),
                    };
                    format!("only {} frames in the {} pose; the {} frames read pitch {:.2} to {:.2} and turn {:+.2} to {:+.2}, and {}. {}", samples.len(), p, off_pose, lo_seen, hi_seen, yaw_lo, yaw_hi, want, POSE_HINTS[POSES.iter().position(|q| *q == p).unwrap_or(0)])
                }
                _ => format!(
                    "only {} usable frames; face the camera at normal distance and try again",
                    samples.len()
                ),
            };
            return Ok(Outcome::Error { message: hint });
        }
        let now = now_secs();
        let added = samples.len();
        for (e, q, w, p) in samples {
            u.templates.push(Template {
                embedding: e,
                quality: q,
                face_width: w,
                created: now,
                label: label.to_string(),
                device: device.clone(),
                yaw: Some(p.yaw),
                nose_pitch: Some(p.nose_pitch),
            });
        }
        // Over the cap, the surplus copies of looks already held go, not
        // the new look: coverage is what an identity is for.
        let pruned = u.prune_to(crate::store::MAX_TEMPLATES);
        if pruned > 0 {
            log::info!(
                "enrolment for {}: {} near-duplicate template(s) dropped to stay within {}",
                user,
                pruned,
                crate::store::MAX_TEMPLATES
            );
        }
        let (lo, mean, _) = u.self_consistency().unwrap_or((1.0, 1.0, 1.0));
        let path = self.store.save(&u)?;
        Ok(Outcome::Enrolled {
            added,
            total: u.templates.len(),
            consistency_min: lo,
            consistency_mean: mean,
            path: path.display().to_string(),
        })
    }

    /// An elevation request: the window goes up first, so nothing happens
    /// silently; then the face must match, then the nod must come.
    /// Start a consent request: open the window, load the templates, mark the
    /// user pending. Errors are final outcomes.
    /// With `open_window` false (the session is locked) the window is not
    /// summoned; the caller shows it when the request resumes.
    pub fn consent_begin(
        &mut self,
        user: &str,
        caller: crate::consent::CallerInfo,
        open_window: bool,
    ) -> std::result::Result<ConsentSession, Outcome> {
        // The request has no deadline: gestures are read for
        // `consent_seconds` after each match, and when that passes unanswered
        // the camera drops to the presence rhythm and an attentive face
        // re-arms it, as the lock screen does.
        let mut dialog = match Dialog::new(&self.cfg, user, &CONSENT) {
            Ok(d) => d,
            Err(e) => {
                return Err(Outcome::Error {
                    message: e.to_string(),
                })
            }
        };
        if open_window {
            if let Err(e) = dialog.show("scanning", "Look at the camera.", &caller) {
                log::warn!("consent: no window for {}: {}", user, e);
                return Err(consent_denied(Refusal::NoWindow, 0));
            }
        }
        let templates = match self.store.load(user) {
            Ok(Some(t)) => t,
            // The window is already up with this request's token: bring it
            // down, or it keeps that token as pending and ignores the next
            // request's summon (seen live when a store failed to load).
            Ok(None) => {
                dialog.hide();
                return Err(Outcome::NotEnrolled);
            }
            Err(e) => {
                dialog.hide();
                return Err(Outcome::Error {
                    message: e.to_string(),
                });
            }
        };
        self.last_consent.insert(user.to_string(), Instant::now());
        Ok(ConsentSession {
            user: user.to_string(),
            caller,
            dialog,
            started: Instant::now(),
            templates,
            user_seen_at: std::cell::Cell::new(Instant::now()),
        })
    }

    /// One round with the camera: scan until the face matches, then watch for
    /// the nod. Ends with a verdict, or with the user gone (no face for the
    /// presence watch's away time) so the caller can lock the session, park
    /// without the camera and come back for another round.
    pub fn consent_round(&mut self, s: &mut ConsentSession) -> Round {
        let cfg = self.cfg.clone();
        let state = &CONSENT;
        let user = s.user.clone();
        let started = s.started;
        let lost_after = if cfg.presence.enabled && cfg.presence.user == s.user {
            Some(Duration::from_secs_f32(cfg.presence.away_seconds))
        } else {
            None
        };
        let msg = format!("Recognised. Nod {} times to allow this, shake your head to refuse, or type your password.", NODS_NEEDED);
        let floors_deg = consent_floors(&s.templates.gesture);
        let seen = &s.user_seen_at;
        let dialog_cell = std::cell::RefCell::new(&mut s.dialog);
        let caller_ref = &s.caller;
        let gesture_cell: std::cell::RefCell<Option<Gesture>> = std::cell::RefCell::new(None);
        let gesture: Option<Gesture>;
        let outcome;
        loop {
            // An answer already waiting (typed during a hold or a wait)
            // goes to the scan start, which takes it before touching the
            // camera; it is the user's, whether or not the camera saw them.
            let answered = state.answered(&user);
            // The request's own away clock (E2): a scan that ended without
            // the user, however it ended, does not start the clock over.
            if let Some(l) = lost_after {
                if !answered && seen.get().elapsed() > l {
                    log::info!(
                        "consent: the user has not been seen for {:.0}s; the user left",
                        l.as_secs_f32()
                    );
                    return Round::FaceLost;
                }
            }
            // A hold (the cooldown counts the lock screen's failures and this
            // lane's together) pauses the face checks, not the request: the
            // window stays up with its password box, and when the hold is
            // over the scan resumes on its own.
            if let Some(hold) = self.hold_for(&user) {
                if !answered {
                    log::warn!(
                        "consent for {}: {} recent failures; face checks paused for {}s",
                        user,
                        COOLDOWN_FAILURES,
                        hold.as_secs()
                    );
                    let _ = dialog_cell.borrow_mut().show("password", &format!("Too many failed face checks. They pause for {} seconds; type your password, or wait.", hold.as_secs().max(1)), caller_ref);
                    if let Some(r) = self.wait_for_hold(&user, hold, state, seen, lost_after) {
                        return r;
                    }
                    continue;
                }
            }
            // A card the lock screen covers is a card nobody nods at, and
            // the lock screen needs the camera: park until the unlock (D2).
            if crate::consent::session_locked(&user) {
                log::info!("consent: the session is locked; the request parks until the unlock");
                return Round::SessionLocked;
            }
            let templates_ref = &s.templates;
            let mut hook = |cap: &mut IrCapture,
                            pipeline: &mut Pipeline,
                            matched: &faceauth_engine::Face|
             -> Result<bool> {
                // The scan just matched the enrolled face: from here until
                // the nod window ends the card may arm passwordless sudo,
                // and the payload says so. The match is the user at the
                // card, so the away clock starts over.
                state.set_face_present(&user, true);
                seen.set(Instant::now());
                // No window the daemon can vouch for, no nods: the request
                // ends and the caller's stack falls to its password.
                if let Err(e) = dialog_cell.borrow_mut().show("nod", &msg, caller_ref) {
                    log::warn!(
                        "consent for {}: the window is not there to nod at: {}",
                        user,
                        e
                    );
                    *gesture_cell.borrow_mut() = Some(Gesture::NoWindow);
                    return Ok(false);
                }
                let window = cfg.consent_seconds.max(10.0);
                let mut nod_frames = Vec::new();
                let mut start = Some(matched.bbox);
                // The card follows the face: when the nod window loses or
                // regains the matched face the card is told, so its
                // passwordless button greys and ungreys with the daemon's
                // own view. The show carries no ack wait.
                let presence = |_present: bool| {
                    let _ = dialog_cell.borrow_mut().show_again("nod", &msg, caller_ref);
                };
                let locked = || crate::consent::session_locked(&user);
                let (g, followed) = loop {
                    let dwell = dialog_cell.borrow().dwell_left(Instant::now());
                    let (g, followed) = wait_for_nods(
                        cap,
                        pipeline,
                        &cfg,
                        Duration::from_secs_f32(window),
                        NODS_NEEDED,
                        Some((state, user.as_str())),
                        lost_after,
                        floors_deg,
                        start,
                        dwell,
                        &mut nod_frames,
                        Some(&presence),
                        Some(&locked),
                        seen,
                    )?;
                    if g != Gesture::RiderArmed {
                        break (g, followed);
                    }
                    // The card armed passwordless sudo: what the nod grants
                    // changed, so the card is shown again naming it. The
                    // show resets the acknowledgement and waits for a fresh
                    // one; the dwell then runs whole and the nods start
                    // over at a card that says what they approve.
                    nod_frames.clear();
                    start = followed;
                    state.set_face_present(&user, true);
                    let mut d = dialog_cell.borrow_mut();
                    if let Err(e) = d.show("nod", &msg, caller_ref) {
                        log::warn!(
                            "consent for {}: the window did not re-acknowledge the passwordless rider: {}",
                            user,
                            e
                        );
                        *gesture_cell.borrow_mut() = Some(Gesture::NoWindow);
                        return Ok(false);
                    }
                };
                let g = if g == Gesture::Nodded {
                    // The nods came from the followed box; before they count,
                    // that box must be live and enrolled, right now, and the
                    // frames kept from the nods themselves must be the
                    // enrolled face too (D4): a face swapped in for the
                    // gesture and out again before the confirm is refused.
                    let _ = dialog_cell
                        .borrow_mut()
                        .show("confirming", "Confirming.", caller_ref);
                    match confirm(
                        cap,
                        pipeline,
                        &cfg,
                        templates_ref,
                        followed.unwrap_or(matched.bbox),
                    )? {
                        Confirm::Live => match nod_frames_match(
                            pipeline,
                            templates_ref,
                            &nod_frames,
                            &cap.identity,
                            cfg.accept_threshold,
                        )? {
                            Ok(()) => Gesture::Nodded,
                            Err(why) => Gesture::ConfirmFailed(why),
                        },
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
            let scan = cfg.consent_scan_seconds;
            let (g, o) = match self.run_with_answers(
                &s.templates,
                Some(&mut hook),
                scan,
                Some((state, user.as_str())),
            ) {
                Ok(Scan::Done(o)) => (gesture_cell.borrow_mut().take(), o),
                // The window answered before the face matched: the answer
                // is the user's whether or not the camera saw them (J18).
                Ok(Scan::Answered(a)) => (
                    Some(match a {
                        Answer::Password(pw) => Gesture::Password(pw),
                        Answer::Dismiss => Gesture::Dismissed,
                        Answer::Gone | Answer::Rearm => Gesture::Gone,
                    }),
                    Outcome::NoFace {
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    },
                ),
                Err(e) => (
                    None,
                    Outcome::Error {
                        message: e.to_string(),
                    },
                ),
            };
            match (&g, &o) {
                // Nobody is waiting for the verdict: no verdict, and the
                // window comes down when the session drops.
                (Some(Gesture::Gone), _) => {
                    return Round::Done(consent_denied(
                        Refusal::Gone,
                        started.elapsed().as_millis() as u64,
                    ))
                }
                (Some(Gesture::NoWindow), _) => {
                    return Round::Done(consent_denied(
                        Refusal::NoWindow,
                        started.elapsed().as_millis() as u64,
                    ))
                }
                (Some(Gesture::FaceLost), _) => return Round::FaceLost,
                (Some(Gesture::SessionLocked), _) => return Round::SessionLocked,
                // The followed face left its place and a single face is back
                // in view: whether it is the user is the scan's to say, not
                // the tracker's, so the round scans again before any nod
                // counts (E2).
                (Some(Gesture::Moved), _) => {
                    log::info!(
                        "consent: the matched face moved; scanning again before the nods resume"
                    );
                    let _ = dialog_cell.borrow_mut().show(
                        "scanning",
                        "Look at the camera again, or type your password.",
                        caller_ref,
                    );
                    continue;
                }
                (None, Outcome::NoFace { .. }) if lost_after.is_some() => return Round::FaceLost,
                // The confirm could not read the strobe (a bright room, the
                // user leaned away): not a refusal. Ask for the face and go
                // round again.
                (Some(Gesture::ConfirmUnclear), _) => {
                    log::info!(
                        "consent: the confirm saw no strobe signal; asking for the face again"
                    );
                    let _ = dialog_cell.borrow_mut().show(
                        "scanning",
                        "Could not confirm. Face the camera and nod again, or type your password.",
                        caller_ref,
                    );
                    let beat = || dialog_cell.borrow_mut().heartbeat(caller_ref);
                    if let Some(r) =
                        self.wait_for_attention(&user, state, lost_after, false, seen, &beat)
                    {
                        return r;
                    }
                    continue;
                }
                // The confirm refused: the thing that nodded is not a live
                // enrolled face. A failure, charged like a refused scan.
                (Some(Gesture::ConfirmFailed(why)), _) => {
                    log::warn!("consent: the confirm after the nods refused ({})", why);
                    let _ = self.charge(&user);
                    outcome = refused(
                        &s.caller,
                        Refusal::Confirm(why.clone()),
                        started.elapsed().as_millis() as u64,
                    );
                    gesture = g;
                    break;
                }
                // The nod window passed with nobody answering: no verdict,
                // and the nods stay unarmed. The camera drops to the
                // presence rhythm, and the request is re-armed when the
                // enrolled face has been away from the card and is back
                // and attentive, or by the card's own "Ready to nod" (Q8):
                // a face that merely stays in view does not re-arm it.
                (Some(Gesture::Timeout), _) => {
                    log::info!("consent: no answer in the nod window; the nods are disarmed until the user is back at the card");
                    let _ = dialog_cell.borrow_mut().show_waiting(
                        "No nod seen. Press Ready to nod and look at the camera, or type your password.",
                        caller_ref,
                    );
                    let beat = || dialog_cell.borrow_mut().heartbeat(caller_ref);
                    if let Some(r) =
                        self.wait_for_attention(&user, state, lost_after, true, seen, &beat)
                    {
                        return r;
                    }
                    continue;
                }
                (None, Outcome::NoMatch { .. }) | (None, Outcome::NoFace { .. }) => {
                    if matches!(o, Outcome::NoMatch { .. }) && self.charge(&user).is_some() {
                        continue; // the loop top shows the hold
                    }
                    let _ = dialog_cell.borrow_mut().show(
                        "scanning",
                        "Face not recognised. Look at the camera, or type your password.",
                        caller_ref,
                    );
                    let beat = || dialog_cell.borrow_mut().heartbeat(caller_ref);
                    if let Some(r) =
                        self.wait_for_attention(&user, state, lost_after, false, seen, &beat)
                    {
                        return r;
                    }
                    continue;
                }
                // A liveness refusal is a verdict for a plain attempt, but the
                // window is waiting for the user: it keeps waiting (nothing is
                // approved by it), and the log keeps the refusal.
                (None, Outcome::Denied { reason, .. }) => {
                    log::info!(
                        "consent: scan refused ({}); the window keeps waiting",
                        reason
                    );
                    if self.charge(&user).is_some() {
                        continue; // the loop top shows the hold
                    }
                    let _ = dialog_cell.borrow_mut().show(
                        "scanning",
                        "Not accepted. Look straight at the camera, or type your password.",
                        caller_ref,
                    );
                    let beat = || dialog_cell.borrow_mut().heartbeat(caller_ref);
                    if let Some(r) =
                        self.wait_for_attention(&user, state, lost_after, false, seen, &beat)
                    {
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

    /// Turn a gesture and a face outcome into the verdict, show it, notify.
    /// Waiting is not scanning. After a round that found nobody to accept,
    /// the camera stays off but for a short look every two seconds, like the
    /// presence watch's, until a face is turned to the camera (then the next
    /// round scans it), the window answers (the next round takes the answer),
    /// or nobody has been there for the presence away time (the user left).
    /// Sit out a hold without scanning: until it is over, or the window
    /// answers (a password or a dismissal, which the next scan start takes).
    /// The chair is still watched at the presence rhythm, so a user who
    /// left during the hold, or a stranger who took the chair, ends the
    /// round with the user gone at the away time (E2).
    fn wait_for_hold(
        &mut self,
        user: &str,
        hold: Duration,
        state: &ConsentState,
        seen: &std::cell::Cell<Instant>,
        lost_after: Option<Duration>,
    ) -> Option<Round> {
        let look_cfg = crate::presence::PresenceConfig {
            user: user.to_string(),
            ..Default::default()
        };
        let strict = crate::presence::presence_mode() == crate::presence::PresenceMode::Secure;
        let mut look =
            |identify: bool| crate::presence::observe_in(self, &look_cfg, identify, strict);
        hold_wait(
            &mut look,
            state,
            user,
            Instant::now() + hold,
            seen,
            lost_after,
            Duration::from_millis(200),
        )
    }

    /// Wait, at the presence rhythm, for the request to be re-armed: by
    /// an answer from the card, or by the enrolled face attentive at the
    /// camera. With `need_away` the face must first have been away from
    /// the card (absent, turned away, or not the user) for a look. Ends
    /// with a round when the user left for the away time or the session
    /// locked. `beat` re-sends the card now and then (D1). The identity
    /// look is the presence watch's for the mode in force: in the secure
    /// mode a face the gate read no signal from re-arms nothing.
    fn wait_for_attention(
        &mut self,
        user: &str,
        state: &ConsentState,
        lost_after: Option<Duration>,
        need_away: bool,
        seen: &std::cell::Cell<Instant>,
        beat: &dyn Fn(),
    ) -> Option<Round> {
        let look_cfg = crate::presence::PresenceConfig {
            user: user.to_string(),
            ..Default::default()
        };
        let mode = crate::presence::presence_mode();
        let strict = mode == crate::presence::PresenceMode::Secure;
        let mut look =
            |identify: bool| crate::presence::observe_in(self, &look_cfg, identify, strict);
        let locked = || crate::consent::session_locked(user);
        attention_wait(
            &mut look,
            state,
            user,
            &locked,
            beat,
            RearmGate::new(need_away, mode),
            lost_after,
            seen,
            Duration::from_millis(200),
        )
    }

    pub fn consent_finish(
        &mut self,
        s: &mut ConsentSession,
        gesture: Option<Gesture>,
        outcome: Outcome,
    ) -> Outcome {
        let user = s.user.as_str();
        let caller = &s.caller;
        // A password typed at any point is checked against the system stack;
        // a good one approves exactly like a nod.
        let password_ok = match &gesture {
            Some(Gesture::Password(pw)) => crate::pamcheck::check("system-auth", user, pw),
            _ => false,
        };
        let outcome = match (&gesture, outcome) {
            // Anything that is not an approval ends as a consent refusal, so
            // the module ignores it and the terminal password is the floor.
            (Some(Gesture::Timeout), o @ Outcome::Match { .. }) => {
                consent_denied(Refusal::NoAnswer, elapsed_of(&o))
            }
            // A shake or a dismissal is the answer no: the window had the
            // password box, so closing it without either is a refusal that
            // ends the request, not a hand-off to another prompt.
            (Some(Gesture::Dismissed), o) => refused(caller, Refusal::Dismissed, elapsed_of(&o)),
            (Some(Gesture::Shaken), o) => refused(caller, Refusal::Shaken, elapsed_of(&o)),
            (Some(Gesture::Password(_)), o) if !password_ok => {
                // A face was seen and the password behind it was wrong: it
                // counts against the same budget as a failed scan.
                let _ = self.charge(user);
                consent_denied(Refusal::WrongPassword, elapsed_of(&o))
            }
            (_, o) => o,
        };
        let outcome = if password_ok {
            Outcome::Match {
                score: Some(1.0),
                frames: 0,
                elapsed_ms: s.started.elapsed().as_millis() as u64,
            }
        } else {
            outcome
        };
        self.last_consent.insert(user.to_string(), Instant::now());
        if !matches!(outcome, Outcome::Match { .. }) {
            // Whatever the card asked for rides on an approval only.
            let _ = CONSENT.take_passwordless(user, s.dialog.token());
        }
        match &outcome {
            Outcome::Match { frames, .. } => {
                self.last_match.insert(user.to_string(), Instant::now());
                self.failures.remove(user);
                let how = if *frames == 0 {
                    "password"
                } else {
                    "face and nod"
                };
                if *frames > 0 {
                    faillock_reset(user);
                }
                s.dialog.show_final("approved", "Allowed.", caller);
                notify(
                    user,
                    &format!("Root access granted by {}", how),
                    &format!("{}\n{}", caller.command, caller.parents),
                );
                log::info!(
                    "consent granted ({}) for {}: {} [{}]",
                    how,
                    user,
                    caller.command,
                    caller.parents
                );
                // The card's passwordless button: the same approval turns
                // passwordless sudo on for the minutes asked, the way
                // Omarchy's own command would, with no further request.
                // Only the rider armed at this request's own card, and
                // shown on it, counts; the arm itself was refused unless
                // the lane was sudo and the face was in the nod window.
                if let Some(minutes) = CONSENT.take_passwordless(user, s.dialog.token()) {
                    if crate::consent::is_passwordless_command(caller) {
                        log::info!("passwordless sudo for {} not armed from the passwordless command's own request", user);
                        notify(
                            user,
                            "Passwordless sudo: use the command's own answer",
                            "The button does not apply to omarchy-sudo-passwordless itself.",
                        );
                    } else {
                        match crate::consent::enable_passwordless(
                            std::path::Path::new("/etc/sudoers.d"),
                            user,
                            minutes,
                            &|args| crate::consent::run_passwordless_timer(user, args),
                        ) {
                            Ok(_) => {
                                log::warn!("passwordless sudo on for {} for {} min, by the card's button and this approval", user, minutes);
                                notify(user, &format!("Passwordless sudo on for {} minutes", minutes), "Any process running as you can use sudo without asking until then. Setup > Security > Passwordless Sudo turns it off early.");
                            }
                            Err(e) => {
                                log::warn!("passwordless sudo for {} not enabled: {:#}", user, e);
                                notify(user, "Passwordless sudo not enabled", &format!("{:#}", e));
                            }
                        }
                    }
                }
            }
            Outcome::Refused { reason, .. } | Outcome::ConsentDenied { reason, .. }
                if matches!(
                    Refusal::parse(reason),
                    Some(Refusal::Shaken | Refusal::Dismissed)
                ) =>
            {
                // The user closed the window, or shook their head at it: the
                // answer is no, and the window goes away without a verdict on it.
                let _ = CONSENT.take_passwordless(user, s.dialog.token());
                s.dialog.hide();
                let how = if Refusal::parse(reason) == Some(Refusal::Shaken) {
                    "Refused by head shake"
                } else {
                    "Refused: dismissed"
                };
                notify(
                    user,
                    how,
                    &format!("{}\n{}", caller.command, caller.parents),
                );
                log::warn!(
                    "consent refused for {}: {} [{}] ({})",
                    user,
                    caller.command,
                    caller.parents,
                    reason
                );
            }
            Outcome::Refused { reason, .. } | Outcome::ConsentDenied { reason, .. }
                if matches!(Refusal::parse(reason), Some(Refusal::Confirm(_))) =>
            {
                s.dialog.show_final(
                    "denied",
                    "The nod did not come from a live, enrolled face. Refused.",
                    caller,
                );
                notify(
                    user,
                    "Refused: the nod was not a live, enrolled face",
                    &format!("{}\n{}", caller.command, caller.parents),
                );
                log::warn!(
                    "consent refused for {}: {} [{}] ({})",
                    user,
                    caller.command,
                    caller.parents,
                    reason
                );
            }
            Outcome::Cooldown { seconds } => {
                s.dialog.show_final(
                    "denied",
                    &format!(
                        "Too many failed attempts. Try again in {} seconds, or use your password.",
                        seconds
                    ),
                    caller,
                );
                notify(
                    user,
                    "Refused: too many failed attempts",
                    &format!("{}\n{}", caller.command, caller.parents),
                );
                log::warn!(
                    "consent refused for {}: {} [{}] (cooldown {}s)",
                    user,
                    caller.command,
                    caller.parents,
                    seconds
                );
            }
            Outcome::ConsentDenied { .. } => {
                let why = match gesture {
                    Some(Gesture::Password(_)) => "Wrong password. Refused.",
                    _ => "No answer. Refused.",
                };
                s.dialog
                    .show_final("denied", &denied_text(why, caller), caller);
                let how = match gesture {
                    Some(Gesture::Password(_)) => "Refused: wrong password",
                    _ => "Refused: no answer",
                };
                notify(
                    user,
                    how,
                    &format!("{}\n{}", caller.command, caller.parents),
                );
                log::warn!(
                    "consent refused for {}: {} [{}] ({})",
                    user,
                    caller.command,
                    caller.parents,
                    why
                );
            }
            _ => {
                s.dialog
                    .show_final("denied", &denied_text("Refused.", caller), caller);
                notify(
                    user,
                    "Refused",
                    &format!("{}\n{}", caller.command, caller.parents),
                );
            }
        }
        outcome
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
    fn hold_for(&mut self, user: &str) -> Option<Duration> {
        self.failures
            .entry(user.to_string())
            .or_default()
            .hold(Instant::now())
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
    fn run_with_answers(
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

/// What a gated pair gave at the face: detected first, measured through
/// the gate, and embedded only on a pass (J8).
pub(crate) enum Gated {
    NoFace,
    NoSignal,
    Denied(String),
    /// The face, with its embedding.
    Pass(faceauth_engine::Face),
}

/// The narrowest face, as a fraction of the frame's shorter side, that an
/// attempt scores (60 px on a 480 px side). Enrolment's right distance
/// starts at 0.14 (`enrol::SIZE_RIGHT`); sitting back from the reference
/// machine measured 45 px, where the strobe cannot be read and the crop
/// does not match. A face under this is treated as no face: never scored,
/// so never a match and never charged against the five-a-minute rule, and
/// the lock screen's probe does not wake the panel for it.
pub const SCAN_MIN_FACE_FRAC: f32 = 0.125;

/// Is a face `face_w` pixels wide, in a `w` by `h` frame, near enough to
/// judge?
pub fn scannable(face_w: f32, w: usize, h: usize) -> bool {
    face_w >= SCAN_MIN_FACE_FRAC * w.min(h) as f32
}

/// Detect the face in a pair's lit frame (the best one, or, with `follow`,
/// only a detection that continues that box), put the pair through the
/// gate at it, and embed it only when the gate passed.
pub(crate) fn gated_face(
    gate: &crate::strobe::StrobeGate<'_>,
    pipeline: &mut Pipeline,
    pair: &crate::strobe::Pair,
    min_detection: f32,
    follow: Option<[f32; 4]>,
) -> Result<Gated> {
    use crate::strobe::Gate;
    let mut faces = pipeline.detector.detect(&pair.lit, min_detection)?;
    faces.sort_by(|a, b| b.score.total_cmp(&a.score));
    let Some(mut face) = faces.into_iter().next() else {
        return Ok(Gated::NoFace);
    };
    if let Some(tracked) = follow {
        // The embedded face must be the followed one, not whichever scored best.
        if crate::consent::track(std::slice::from_ref(&face), tracked)
            != crate::consent::Track::Found(0)
        {
            log::debug!("confirm: the scored face is not the followed box");
            return Ok(Gated::NoFace);
        }
    }
    if !scannable(face.bbox[2], pair.lit.width, pair.lit.height) {
        log::debug!("gate: face {:.0} px wide, too far to judge", face.bbox[2]);
        return Ok(Gated::NoFace);
    }
    match gate.judge(pair, &face)? {
        Gate::Pass(fr) => {
            if let Some(fr) = fr {
                log::debug!("gate: pass {:?}", fr);
            }
        }
        Gate::NoSignal(fr) => {
            log::debug!("gate: no signal {:?}", fr);
            return Ok(Gated::NoSignal);
        }
        Gate::Denied(why, fr) => {
            log::debug!("gate: denied {} {:?}", why, fr);
            return Ok(Gated::Denied(why));
        }
    }
    let crop = faceauth_engine::align::align_112(&pair.lit, &face.landmarks);
    face.embedding = Some(pipeline.embedder.embed(&crop)?);
    Ok(Gated::Pass(face))
}

/// How a scan ended: with the camera's verdict, or with an answer from
/// the consent window that arrived before the face matched.
pub enum Scan {
    Done(Outcome),
    Answered(Answer),
}

/// Whether the nods may be armed again while a request waits, decided
/// look by look (Q8). The nods arm on the enrolled face attentive at the
/// camera, the lock screen's rule; after a nod window passed unanswered
/// they arm only once that face has been away from the card for a look
/// and is back, so a face that merely stays in view is not a re-arm and
/// there is no standing nod loop. An attentive face is asked its identity
/// before it arms: a stranger at the desk never re-arms a scan.
pub struct RearmGate {
    need_away: bool,
    away_seen: bool,
    /// How many failed identity checks in a row count a face as not the
    /// user for the away clock: one in secure mode, two in default.
    strikes: u32,
    identity_fails: u32,
}

/// What one look decided.
#[derive(Debug, PartialEq)]
pub enum Looked {
    /// Nothing to arm; the away clock ran if the user was not seen.
    Wait { user_seen: bool },
    /// An attentive face whose identity this look did not check: look
    /// again with the identity check before arming on it.
    Identify,
    /// The enrolled face is attentive at the camera and was away: arm.
    Arm,
}

impl RearmGate {
    pub fn new(need_away: bool, mode: crate::presence::PresenceMode) -> Self {
        RearmGate {
            need_away,
            away_seen: false,
            strikes: if mode == crate::presence::PresenceMode::Secure {
                1
            } else {
                2
            },
            identity_fails: 0,
        }
    }

    /// Feed one look: a face seen, attentive, and the identity check's
    /// verdict when one ran.
    pub fn look(&mut self, face: bool, attentive: bool, identity: Option<bool>) -> Looked {
        match identity {
            Some(true) => self.identity_fails = 0,
            Some(false) => self.identity_fails += 1,
            None => {}
        }
        let user_seen = face && self.identity_fails < self.strikes;
        let attentive_user = face && attentive && identity != Some(false);
        if !attentive_user {
            self.away_seen = true;
            return Looked::Wait { user_seen };
        }
        if self.need_away && !self.away_seen {
            return Looked::Wait { user_seen };
        }
        if identity == Some(true) {
            Looked::Arm
        } else {
            Looked::Identify
        }
    }
}

/// Whether a look should check identity: every third look for the away
/// clock, and every look once the clock is past half of `lost_after`, so
/// a user who is there is confirmed before the clock runs out and a
/// stranger is found out within one look of it.
fn identity_due(looks: u32, seen: &std::cell::Cell<Instant>, lost_after: Option<Duration>) -> bool {
    looks.is_multiple_of(3)
        || lost_after
            .map(|l| seen.get().elapsed() > l / 2)
            .unwrap_or(false)
}

/// The away clock, read after a look: a passing identity look is the user
/// seen and restarts it; past `lost_after` without one, the user left.
fn away_clock(
    o: &crate::presence::Observation,
    seen: &std::cell::Cell<Instant>,
    lost_after: Option<Duration>,
    where_: &str,
) -> Option<Round> {
    if o.identity == Some(true) {
        seen.set(Instant::now());
        return None;
    }
    let l = lost_after?;
    if seen.get().elapsed() <= l {
        return None;
    }
    log::info!(
        "consent: {} for {:.0}s while {}; the user left",
        if o.face { "not the user" } else { "nobody" },
        l.as_secs_f32(),
        where_
    );
    Some(Round::FaceLost)
}

/// A hold as a loop over injectable parts: no scan until `until`, one look
/// at the presence rhythm meanwhile for the away clock. Ends with `None`
/// when the hold is over or the window answered, with `FaceLost` when the
/// user has not been seen for `lost_after`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn hold_wait(
    look: &mut dyn FnMut(bool) -> Result<crate::presence::Observation>,
    state: &ConsentState,
    user: &str,
    until: Instant,
    seen: &std::cell::Cell<Instant>,
    lost_after: Option<Duration>,
    tick: Duration,
) -> Option<Round> {
    let mut looks = 0u32;
    while Instant::now() < until {
        for _ in 0..10 {
            std::thread::sleep(tick);
            if state.answered(user) {
                return None;
            }
            if Instant::now() >= until {
                return None;
            }
        }
        if lost_after.is_none() {
            continue;
        }
        looks += 1;
        let o = match look(identity_due(looks, seen, lost_after)) {
            Ok(o) => o,
            Err(e) => {
                log::warn!("consent: look during a hold: {}", e);
                continue;
            }
        };
        if let Some(r) = away_clock(&o, seen, lost_after, "the face checks were paused") {
            return Some(r);
        }
    }
    None
}

/// The attention wait as a loop over injectable parts, so a test can drive
/// it without a camera. Ends with `None` when the request is re-armed (an
/// answer in the slot, or the gate's `Arm`), with a round when the user
/// left for `lost_after` (the request's own clock in `seen`) or the
/// session locked.
#[allow(clippy::too_many_arguments)]
pub(crate) fn attention_wait(
    look: &mut dyn FnMut(bool) -> Result<crate::presence::Observation>,
    state: &ConsentState,
    user: &str,
    locked: &dyn Fn() -> bool,
    beat: &dyn Fn(),
    mut gate: RearmGate,
    lost_after: Option<Duration>,
    seen: &std::cell::Cell<Instant>,
    tick: Duration,
) -> Option<Round> {
    let mut last_beat = Instant::now();
    let mut looks = 0u32;
    loop {
        for _ in 0..10 {
            std::thread::sleep(tick);
            // The card's "Ready to nod": taken here, it re-arms the nods;
            // the scan ahead is not to read it as an answer.
            if state.take_rearm(user) {
                log::info!("consent: the card says ready to nod; scanning");
                return None;
            }
            // A password, a dismissal or a hang-up: the scan start takes
            // it before touching the camera.
            if state.answered(user) {
                return None;
            }
        }
        if locked() {
            log::info!("consent: the session locked while waiting; the request parks");
            return Some(Round::SessionLocked);
        }
        if last_beat.elapsed() >= crate::consent::HEARTBEAT {
            last_beat = Instant::now();
            beat();
        }
        looks += 1;
        // The identity check costs the strobe and the embedder, so it runs
        // every third look for the away clock (every look once the clock
        // is half spent), and on demand before an arm: the face that
        // re-arms the nods is checked to be the user.
        let mut o = match look(identity_due(looks, seen, lost_after)) {
            Ok(o) => o,
            Err(e) => {
                log::warn!("consent: look while waiting: {}", e);
                continue;
            }
        };
        let mut decision = gate.look(o.face, o.attentive, o.identity);
        if decision == Looked::Identify {
            o = match look(true) {
                Ok(o) => o,
                Err(e) => {
                    log::warn!("consent: identity look while waiting: {}", e);
                    continue;
                }
            };
            decision = gate.look(o.face, o.attentive, o.identity);
            // Asked and still unchecked (the secure mode's gate read no
            // signal): not an arm, and a look the clock counts.
            if decision == Looked::Identify {
                decision = Looked::Wait { user_seen: false };
            }
        }
        match decision {
            Looked::Arm => {
                log::info!(
                    "consent: the user turned to the camera after {} looks; scanning",
                    looks
                );
                return None;
            }
            Looked::Identify => continue,
            // The gate's `user_seen` decides the arm; the away clock runs
            // on the request's own record of the user, which only a
            // passing identity look refreshes (E2).
            Looked::Wait { .. } => {
                if let Some(r) = away_clock(&o, seen, lost_after, "waiting") {
                    return Some(r);
                }
            }
        }
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
fn faillock_reset(user: &str) {
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

/// Why a consent request ended without an approval. One type inside the
/// daemon, turned into the wire `reason` string once, so a verdict path
/// is never picked by matching a string literal (H14). The strings are
/// what the window and the PAM module read and do not change.
#[derive(Clone, Debug, PartialEq)]
pub enum Refusal {
    /// Two head shakes.
    Shaken,
    /// The window's dismiss or kill button.
    Dismissed,
    /// The confirm after the nods refused, with its reason.
    Confirm(String),
    WrongPassword,
    NoAnswer,
    /// The requester hung up.
    Gone,
    /// The window could not be shown, or never acknowledged the request.
    NoWindow,
    /// The nod window ended without an approval.
    NoNod,
    /// No active graphical session to ask in.
    NoSession,
    /// Another user's request holds the window.
    OtherUser,
    /// This user already has the bound of requests waiting.
    TooMany,
    /// A refusal a moment ago still stands (A5).
    RefusedRecently,
}

impl Refusal {
    /// The `reason` the outcome carries on the wire.
    pub fn wire(&self) -> String {
        match self {
            Refusal::Shaken => "shaken".into(),
            Refusal::Dismissed => "dismissed".into(),
            Refusal::Confirm(why) => format!("confirm: {}", why),
            Refusal::WrongPassword => "wrong password".into(),
            Refusal::NoAnswer => "no answer".into(),
            Refusal::Gone => "requester gone".into(),
            Refusal::NoWindow => "the consent window did not open".into(),
            Refusal::NoNod => "no nod".into(),
            Refusal::NoSession => "no active graphical session to ask in".into(),
            Refusal::OtherUser => "another user's request is on screen".into(),
            Refusal::TooMany => "too many requests waiting".into(),
            Refusal::RefusedRecently => "refused a moment ago".into(),
        }
    }

    /// The refusal a wire `reason` names, if it is one of ours: the one
    /// place a string is read back.
    pub fn parse(reason: &str) -> Option<Refusal> {
        if let Some(why) = reason.strip_prefix("confirm: ") {
            return Some(Refusal::Confirm(why.to_string()));
        }
        Some(match reason {
            "shaken" => Refusal::Shaken,
            "dismissed" => Refusal::Dismissed,
            "wrong password" => Refusal::WrongPassword,
            "no answer" => Refusal::NoAnswer,
            "requester gone" => Refusal::Gone,
            "the consent window did not open" => Refusal::NoWindow,
            "no nod" => Refusal::NoNod,
            "no active graphical session to ask in" => Refusal::NoSession,
            "another user's request is on screen" => Refusal::OtherUser,
            "too many requests waiting" => Refusal::TooMany,
            "refused a moment ago" => Refusal::RefusedRecently,
            _ => return None,
        })
    }

    /// The user's own no (a shake, a dismissal, a confirm that refused):
    /// what starts the standing refusal (A5). Not a timeout, a wrong
    /// password or a request that fell through.
    pub fn is_explicit_no(&self) -> bool {
        matches!(
            self,
            Refusal::Shaken | Refusal::Dismissed | Refusal::Confirm(_)
        )
    }
}

/// A request that ended without a decision: the module ignores it and
/// the caller's stack falls to its password, on either lane.
pub fn consent_denied(why: Refusal, elapsed_ms: u64) -> Outcome {
    Outcome::ConsentDenied {
        reason: why.wire(),
        elapsed_ms,
    }
}

/// What the denied card says the user can do next: kill only when the
/// daemon named a requester it can kill (the window hides Kill otherwise),
/// and never "block", which is no control of the card's (I12).
pub fn denied_text(why: &str, caller: &crate::consent::CallerInfo) -> String {
    if caller.kill_pid > 0 {
        format!("{} Kill the requester, or dismiss.", why)
    } else {
        format!("{} Dismiss.", why)
    }
}

/// The user's no, as the caller's lane can take it: polkit gets a refusal
/// that ends the request; sudo gets a fall-through to its own prompt.
pub fn refused(caller: &crate::consent::CallerInfo, why: Refusal, elapsed_ms: u64) -> Outcome {
    if caller.via == "polkit" {
        Outcome::Refused {
            reason: why.wire(),
            elapsed_ms,
        }
    } else {
        consent_denied(why, elapsed_ms)
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

/// The confirm's answer when its window ran out: refused only on two
/// pairs under the threshold (the same two strikes a pass takes);
/// otherwise nothing was decided, whether one good pair came, one weak
/// one, or none at all (J17). A gate denial ends the confirm before this
/// is asked.
pub fn confirm_at_timeout(failed: usize) -> Confirm {
    if failed >= 2 {
        Confirm::Refused("the face that nodded does not match".into())
    } else {
        Confirm::NoSignal
    }
}

/// After the nods: is the followed box a live, enrolled face right now?
/// The gate switches the illuminator to a fresh mask for the confirm and
/// freezes the exposure; lit frames are gated against their unlit
/// predecessor and embedded, and two pairs at or above the accept
/// threshold say yes. One gate refusal or two non-matches say no. Pairs
/// with no signal are skipped; if that is all there was, nothing is
/// decided.
pub fn confirm(
    cap: &mut IrCapture,
    pipeline: &mut Pipeline,
    cfg: &Config,
    templates: &UserTemplates,
    followed: [f32; 4],
) -> Result<Confirm> {
    if cap.illuminator.is_none() {
        // No strobe control: the scan already ran ungated under the
        // administrator's explicit setting, and so does this.
        return Ok(if cfg.liveness_required {
            Confirm::Refused("no strobe control".into())
        } else {
            Confirm::Live
        });
    }
    let t0 = Instant::now();
    let device = cap.identity.clone();
    // A fresh mask for the confirm, and pairs only once the frames follow it (D5).
    let mut gate = crate::strobe::StrobeGate::start(cap, true)?;
    let mut tracked = followed;
    let (mut passed, mut failed, mut nosignal, mut pairs) = (0usize, 0usize, 0usize, 0usize);
    let verdict = loop {
        if t0.elapsed().as_secs_f32() > CONFIRM_SECONDS {
            break confirm_at_timeout(failed);
        }
        let Some(pair) = gate.next_frame(Duration::from_secs(1))? else {
            continue;
        };
        let face = match gated_face(&gate, pipeline, &pair, cfg.min_detection, Some(tracked))? {
            Gated::NoFace => continue,
            Gated::NoSignal => {
                pairs += 1;
                nosignal += 1;
                continue;
            }
            Gated::Denied(why) => {
                pairs += 1;
                log::warn!("confirm: liveness denied: {}", why);
                break Confirm::Refused(why);
            }
            Gated::Pass(face) => {
                pairs += 1;
                face
            }
        };
        tracked = face.bbox;
        let Some(e) = &face.embedding else { continue };
        match templates.best_match_on(e, &device) {
            Some((score, _)) if score >= cfg.accept_threshold => {
                passed += 1;
                log::debug!("confirm: pair {} matched", passed);
                if passed >= 2 {
                    break Confirm::Live;
                }
                // The second match comes under a fresh mask (C11).
                gate.redraw()?;
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
    // The gate's drop restores steady light, on every exit.
    drop(gate);
    // The pair counts go to the journal on a pass only; on a refusal they
    // would say how close it came (D6).
    match &verdict {
        Confirm::Live => log::info!(
            "confirm: live in {:.2}s ({} pairs, {} no signal, {} matched)",
            t0.elapsed().as_secs_f32(),
            pairs,
            nosignal,
            passed
        ),
        Confirm::NoSignal => log::info!("confirm: no signal in {:.2}s", t0.elapsed().as_secs_f32()),
        Confirm::Refused(w) => log::info!(
            "confirm: refused: {} ({:.2}s)",
            w,
            t0.elapsed().as_secs_f32()
        ),
    }
    log::debug!(
        "confirm detail: {} pairs, {} no signal, {} matched, {} under",
        pairs,
        nosignal,
        passed,
        failed
    );
    Ok(verdict)
}

/// After a live confirm: embed the frames kept from the nod legs and require
/// each to be the enrolled face at the accept threshold (D4). The check runs
/// after the nods, on frames already captured, so the live nod detectors
/// and their floors are untouched. The inner result is the refusal reason.
pub fn nod_frames_match(
    pipeline: &mut Pipeline,
    templates: &UserTemplates,
    frames: &[(Grey, faceauth_engine::Face)],
    device: &str,
    threshold: f32,
) -> Result<std::result::Result<(), String>> {
    let mut embeddings = Vec::with_capacity(frames.len());
    for (img, face) in frames {
        let crop = faceauth_engine::align::align_112(img, &face.landmarks);
        embeddings.push(pipeline.embedder.embed(&crop)?);
    }
    let r = check_nod_embeddings(&embeddings, templates, device, threshold);
    match &r {
        Ok(()) => log::info!(
            "confirm: the {} nod frames are the enrolled face",
            embeddings.len()
        ),
        Err(why) => log::warn!("confirm: {}", why),
    }
    Ok(r)
}

/// How far under the accept threshold a nod frame may score and still count
/// as the user's own face pitched mid-nod. The frames are kept at the ends
/// of the nod legs, chin down or chin up, which is where the embedder is
/// weakest on an enrolled face; another person's face scores far below
/// this against the user's templates, since different identities sit
/// around 0.1 to 0.3 on this model, and the live confirm just before the
/// nods matched at the full threshold. Set by reasoning, not measured on
/// a corpus; the refusal log carries the scores so it can be.
pub const NOD_FRAME_SLACK: f32 = 0.20;

/// The rule behind `nod_frames_match`, on embeddings: there must be at
/// least one kept frame, every frame must score within `NOD_FRAME_SLACK`
/// of `threshold` against a template usable on `device`, and at least half
/// of them must reach `threshold` itself. One pitched frame under the line
/// is the user mid-nod; a frame far under it, or most of them under it,
/// is someone else nodding.
pub fn check_nod_embeddings(
    embeddings: &[Vec<f32>],
    templates: &UserTemplates,
    device: &str,
    threshold: f32,
) -> std::result::Result<(), String> {
    if embeddings.is_empty() {
        return Err("no frames were kept from the nods".into());
    }
    let floor = threshold - NOD_FRAME_SLACK;
    let mut scores = Vec::with_capacity(embeddings.len());
    for (i, e) in embeddings.iter().enumerate() {
        match templates.best_match_on(e, device) {
            Some((score, _)) if score >= floor => scores.push(score),
            Some((score, _)) => {
                log::debug!("confirm: nod frame {} scored {:.3}", i + 1, score);
                return Err(format!(
                    "nod frame {} of {} is not the enrolled face",
                    i + 1,
                    embeddings.len()
                ));
            }
            None => return Err("no template for this camera".into()),
        }
    }
    let passed = scores.iter().filter(|s| **s >= threshold).count();
    if passed * 2 < scores.len() {
        log::debug!("confirm: nod frame scores {:?}", scores);
        return Err(format!(
            "only {} of {} nod frames are the enrolled face",
            passed,
            scores.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    /// H14: each refusal maps to the wire string the window and the module
    /// expect, and back; only the user's own no starts a standing refusal.
    #[test]
    fn each_refusal_maps_to_its_wire_string_and_back() {
        let table = [
            (Refusal::Shaken, "shaken", true),
            (Refusal::Dismissed, "dismissed", true),
            (
                Refusal::Confirm("not live".into()),
                "confirm: not live",
                true,
            ),
            (Refusal::WrongPassword, "wrong password", false),
            (Refusal::NoAnswer, "no answer", false),
            (Refusal::Gone, "requester gone", false),
            (Refusal::NoWindow, "the consent window did not open", false),
            (Refusal::NoNod, "no nod", false),
            (
                Refusal::NoSession,
                "no active graphical session to ask in",
                false,
            ),
            (
                Refusal::OtherUser,
                "another user's request is on screen",
                false,
            ),
            (Refusal::TooMany, "too many requests waiting", false),
            (Refusal::RefusedRecently, "refused a moment ago", false),
        ];
        for (r, wire, no) in table {
            assert_eq!(r.wire(), wire);
            assert_eq!(Refusal::parse(wire), Some(r.clone()), "{}", wire);
            assert_eq!(r.is_explicit_no(), no, "{}", wire);
        }
        assert_eq!(Refusal::parse("something else"), None);
        let caller = crate::consent::CallerInfo {
            via: "polkit".into(),
            ..Default::default()
        };
        assert!(matches!(
            refused(&caller, Refusal::Shaken, 1),
            Outcome::Refused { .. }
        ));
        let sudo = crate::consent::CallerInfo {
            via: "sudo".into(),
            ..Default::default()
        };
        assert!(matches!(
            refused(&sudo, Refusal::Shaken, 1),
            Outcome::ConsentDenied { .. }
        ));
    }
}

#[cfg(test)]
mod denied_text_tests {
    use super::*;

    /// I12: the card offers Kill only for a named requester.
    #[test]
    fn the_denied_card_mentions_kill_only_for_a_named_requester() {
        let named = crate::consent::CallerInfo {
            kill_pid: 4242,
            verified: true,
            ..Default::default()
        };
        assert_eq!(
            denied_text("No answer. Refused.", &named),
            "No answer. Refused. Kill the requester, or dismiss."
        );
        let unnamed = crate::consent::CallerInfo::default();
        assert_eq!(denied_text("Refused.", &unnamed), "Refused. Dismiss.");
        assert!(!denied_text("Refused.", &unnamed).contains("block"));
    }
}

#[cfg(test)]
mod confirm_tests {
    use super::*;

    /// J17: a confirm that ran out of time refuses only after two pairs
    /// under the threshold; one good pair, one weak pair or no pair at
    /// all decides nothing, so it is asked again rather than charged.
    #[test]
    fn a_timed_out_confirm_refuses_only_on_two_strikes() {
        assert!(matches!(confirm_at_timeout(0), Confirm::NoSignal));
        assert!(matches!(confirm_at_timeout(1), Confirm::NoSignal));
        assert!(matches!(confirm_at_timeout(2), Confirm::Refused(_)));
        assert!(matches!(confirm_at_timeout(5), Confirm::Refused(_)));
    }
}

#[cfg(test)]
mod scannable_tests {
    use super::*;

    /// On the reference camera's 640x480 frames: ordinary sitting (78 to
    /// 96 px) is judged, sitting back (45 px, measured) is not; the rule
    /// follows the frame's shorter side.
    #[test]
    fn a_face_too_far_to_judge_is_not_scanned() {
        assert!(scannable(78.0, 640, 480));
        assert!(scannable(60.0, 640, 480));
        assert!(!scannable(45.0, 640, 480));
        assert!(!scannable(59.0, 640, 480));
        assert!(scannable(120.0, 1280, 960));
        assert!(!scannable(100.0, 1280, 960));
    }
}

#[cfg(test)]
mod nod_frame_tests {
    use super::*;
    use crate::store::Template;

    fn templates() -> UserTemplates {
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates.push(Template {
            embedding: vec![1.0, 0.0],
            quality: 0.9,
            face_width: 80.0,
            created: 1,
            label: "enrol".into(),
            device: "ipu3:x".into(),
            yaw: None,
            nose_pitch: None,
        });
        u
    }

    /// A confirm whose nod frames embed to another identity refuses, even
    /// though the face present at the confirm matched (D4).
    #[test]
    fn nod_frames_of_another_face_refuse() {
        let u = templates();
        let me = vec![0.95, 0.31];
        let other = vec![0.0, 1.0];
        assert_eq!(
            check_nod_embeddings(&[me.clone(), me.clone()], &u, "ipu3:x", 0.70),
            Ok(())
        );
        let e = check_nod_embeddings(&[me.clone(), other.clone(), me.clone()], &u, "ipu3:x", 0.70)
            .unwrap_err();
        assert!(e.contains("nod frame 2 of 3"), "{}", e);
        assert!(check_nod_embeddings(&[other], &u, "ipu3:x", 0.70).is_err());
        assert!(
            check_nod_embeddings(&[], &u, "ipu3:x", 0.70).is_err(),
            "no frames is not a pass"
        );
        // The user's own face pitched mid-nod: one frame under the
        // threshold but within the slack passes beside frames that reach
        // it; most frames under it do not, and one far under it never does.
        let pitched = vec![0.6, 0.8];
        assert_eq!(
            check_nod_embeddings(
                &[me.clone(), pitched.clone(), me.clone()],
                &u,
                "ipu3:x",
                0.70
            ),
            Ok(())
        );
        assert_eq!(
            check_nod_embeddings(&[me.clone(), pitched.clone()], &u, "ipu3:x", 0.70),
            Ok(()),
            "half at the threshold is enough"
        );
        let e = check_nod_embeddings(
            &[me.clone(), pitched.clone(), pitched.clone()],
            &u,
            "ipu3:x",
            0.70,
        )
        .unwrap_err();
        assert!(e.contains("only 1 of 3"), "{}", e);
        let far = vec![0.4, 0.917];
        let e =
            check_nod_embeddings(&[me.clone(), far, me.clone()], &u, "ipu3:x", 0.70).unwrap_err();
        assert!(e.contains("nod frame 2 of 3"), "{}", e);
        assert!(check_nod_embeddings(&[me], &u, "uvc:other", 0.70)
            .unwrap_err()
            .contains("no template"));
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

fn elapsed_of(o: &Outcome) -> u64 {
    match o {
        Outcome::Match { elapsed_ms, .. }
        | Outcome::NoMatch { elapsed_ms, .. }
        | Outcome::NoFace { elapsed_ms, .. }
        | Outcome::Denied { elapsed_ms, .. }
        | Outcome::ConsentDenied { elapsed_ms, .. }
        | Outcome::Refused { elapsed_ms, .. } => *elapsed_ms,
        _ => 0,
    }
}

#[cfg(test)]
mod rearm_tests {
    use super::*;
    use crate::presence::{Observation, PresenceMode};

    fn obs(face: bool, attentive: bool, identity: Option<bool>) -> Observation {
        Observation {
            face,
            attentive,
            identity,
            near_miss: false,
            frame: None,
            bbox: None,
        }
    }

    /// Q8: after a nod window passed unanswered a face that stays in view
    /// does not re-arm the nods; the same face away for a look and back,
    /// checked to be the user, does.
    #[test]
    fn a_face_that_stays_in_view_does_not_re_arm_after_a_timeout() {
        let mut g = RearmGate::new(true, PresenceMode::Default);
        for _ in 0..50 {
            assert_eq!(g.look(true, true, None), Looked::Wait { user_seen: true });
            assert_eq!(
                g.look(true, true, Some(true)),
                Looked::Wait { user_seen: true }
            );
        }
        assert_eq!(
            g.look(true, false, None),
            Looked::Wait { user_seen: true },
            "turned away: the away clock does not run on the user"
        );
        assert_eq!(
            g.look(true, true, None),
            Looked::Identify,
            "back and attentive: who is it?"
        );
        assert_eq!(g.look(true, true, Some(true)), Looked::Arm);
    }

    /// Before any nod window (a scan that failed, a confirm that could not
    /// read the strobe) an attentive enrolled face re-arms at once.
    #[test]
    fn without_the_away_rule_an_attentive_user_re_arms_at_once() {
        let mut g = RearmGate::new(false, PresenceMode::Default);
        assert_eq!(g.look(true, true, None), Looked::Identify);
        assert_eq!(g.look(true, true, Some(true)), Looked::Arm);
        let mut g = RearmGate::new(false, PresenceMode::Default);
        assert_eq!(
            g.look(false, false, None),
            Looked::Wait { user_seen: false }
        );
        assert_eq!(g.look(true, false, None), Looked::Wait { user_seen: true });
    }

    /// A stranger never re-arms a scan: an attentive face that fails the
    /// identity check waits, and after the mode's strikes it is nobody for
    /// the away clock (one strike in secure mode, two in default).
    #[test]
    fn a_stranger_never_re_arms_and_counts_as_nobody_after_the_strikes() {
        let mut g = RearmGate::new(false, PresenceMode::Default);
        assert_eq!(g.look(true, true, None), Looked::Identify);
        assert_eq!(
            g.look(true, true, Some(false)),
            Looked::Wait { user_seen: true }
        );
        assert_eq!(
            g.look(true, true, Some(false)),
            Looked::Wait { user_seen: false }
        );
        assert_eq!(
            g.look(true, true, None),
            Looked::Identify,
            "still asked, never armed"
        );
        assert_eq!(
            g.look(true, true, Some(false)),
            Looked::Wait { user_seen: false }
        );
        let mut g = RearmGate::new(false, PresenceMode::Secure);
        assert_eq!(
            g.look(true, true, Some(false)),
            Looked::Wait { user_seen: false }
        );
        assert_eq!(
            g.look(true, true, Some(true)),
            Looked::Arm,
            "a passing check clears the strikes"
        );
    }

    /// A consent state of the test's own, with `user`'s request live.
    fn live(user: &str) -> ConsentState {
        let st = ConsentState::new();
        std::mem::forget(st.test_live(1000, user));
        st
    }

    /// A2: a round driven past its first timeout with an attentive face
    /// opens no second nod window until a re-arm answer arrives.
    #[test]
    fn the_wait_ends_only_on_a_re_arm_answer_while_the_face_stays() {
        let user = "rearm-wait-test";
        let st = live(user);
        let mut n = 0u32;
        let st_ref = &st;
        let mut look = move |identify: bool| {
            n += 1;
            if n == 6 {
                st_ref.push_answer(user, Answer::Rearm);
            }
            assert!(n < 12, "the wait never ended");
            Ok(obs(true, true, identify.then_some(true)))
        };
        let beats = std::cell::Cell::new(0u32);
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| beats.set(beats.get() + 1),
            RearmGate::new(true, PresenceMode::Default),
            Some(Duration::from_secs(20)),
            &fresh(),
            Duration::ZERO,
        );
        assert!(r.is_none(), "the answer re-arms the request");
        assert!(
            !st.answered(user),
            "the re-arm answer is consumed, not left for the scan"
        );
    }

    /// A2: the face away for a look and back, checked to be the user,
    /// re-arms without a click.
    #[test]
    fn the_wait_ends_when_the_user_is_back_at_the_card() {
        let user = "rearm-back-test";
        let st = live(user);
        let mut n = 0u32;
        let mut identity_looks = 0u32;
        let mut look = |identify: bool| {
            n += 1;
            if identify {
                identity_looks += 1;
            }
            // Ten looks with the user watching another monitor, then back.
            Ok(if n <= 10 {
                obs(true, false, identify.then_some(true))
            } else {
                obs(true, true, identify.then_some(true))
            })
        };
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| {},
            RearmGate::new(true, PresenceMode::Default),
            Some(Duration::from_secs(20)),
            &fresh(),
            Duration::ZERO,
        );
        assert!(r.is_none());
        assert!(
            (11..=13).contains(&n),
            "re-armed as soon as the face was back: {} looks",
            n
        );
    }

    /// D2: the wait parks the request when the session locks.
    #[test]
    fn the_wait_parks_when_the_session_locks() {
        let user = "rearm-lock-test";
        let st = live(user);
        let mut look = |identify: bool| Ok(obs(true, true, identify.then_some(true)));
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| true,
            &|| {},
            RearmGate::new(true, PresenceMode::Default),
            None,
            &fresh(),
            Duration::ZERO,
        );
        assert!(matches!(r, Some(Round::SessionLocked)));
    }

    /// C1 on this lane: nobody, or a stranger past the strikes, for the
    /// away time ends the wait with the user gone.
    #[test]
    fn the_wait_ends_with_the_user_gone_after_the_away_time() {
        let user = "rearm-gone-test";
        let st = live(user);
        let mut look = |identify: bool| Ok(obs(true, true, identify.then_some(false)));
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| {},
            RearmGate::new(false, PresenceMode::Secure),
            Some(Duration::ZERO),
            &fresh(),
            Duration::ZERO,
        );
        assert!(matches!(r, Some(Round::FaceLost)));
    }

    /// E2: a stranger who sits down while a card is up does not hold the
    /// lock off. The request's clock last saw the user before the away
    /// time; the stranger's first look is asked its identity, fails, and
    /// the wait ends with the user gone: away time plus one look.
    #[test]
    fn a_stranger_at_the_card_is_locked_out_at_the_away_time() {
        let user = "e2-stranger-test";
        let st = live(user);
        let mut n = 0u32;
        let mut asked = 0u32;
        let mut look = |identify: bool| {
            n += 1;
            if identify {
                asked += 1;
            }
            Ok(obs(true, true, identify.then_some(false)))
        };
        let seen = ago(21);
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| {},
            RearmGate::new(false, PresenceMode::Default),
            Some(Duration::from_secs(20)),
            &seen,
            Duration::ZERO,
        );
        assert!(matches!(r, Some(Round::FaceLost)), "the stranger is nobody");
        assert_eq!(n, 1, "one look past the away time");
        assert_eq!(asked, 1, "and that look checked identity");
        assert!(
            seen.get().elapsed() >= Duration::from_secs(21),
            "a failed check never refreshes the clock"
        );
    }

    /// E2: the same stale clock with the user in the chair is refreshed by
    /// the passing identity look, and the wait goes on.
    #[test]
    fn a_passing_identity_look_refreshes_the_request_clock() {
        let user = "e2-user-test";
        let st = live(user);
        let mut n = 0u32;
        let st_ref = &st;
        let mut look = move |identify: bool| {
            n += 1;
            if n == 4 {
                st_ref.push_answer(user, Answer::Dismiss);
            }
            assert!(n < 8, "the wait never ended");
            // Reading at the card, not attentive: no arm, only the clock.
            Ok(obs(true, false, identify.then_some(true)))
        };
        let seen = ago(21);
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| {},
            RearmGate::new(true, PresenceMode::Default),
            Some(Duration::from_secs(20)),
            &seen,
            Duration::ZERO,
        );
        assert!(r.is_none(), "the answer ends the wait, not the clock");
        assert!(seen.get().elapsed() < Duration::from_secs(1));
    }

    /// E2, secure mode: a face the gate cannot read is asked again and
    /// again but counts for the clock, so it cannot hold a request open.
    #[test]
    fn an_unchecked_face_in_secure_mode_does_not_hold_the_request() {
        let user = "e2-unchecked-test";
        let st = live(user);
        let mut n = 0u32;
        let mut look = |_identify: bool| {
            n += 1;
            assert!(n < 10, "the wait never ended");
            Ok(obs(true, true, None))
        };
        let r = attention_wait(
            &mut look,
            &st,
            user,
            &|| false,
            &|| {},
            RearmGate::new(false, PresenceMode::Secure),
            Some(Duration::from_secs(20)),
            &ago(21),
            Duration::ZERO,
        );
        assert!(matches!(r, Some(Round::FaceLost)));
    }

    /// E2: a hold watches the chair. A stranger there (or nobody) past the
    /// away time ends the round with the user gone; the user's own face
    /// keeps the clock and the hold runs to its end.
    #[test]
    fn a_hold_ends_with_the_user_gone_when_a_stranger_sits_through_it() {
        let user = "e2-hold-test";
        let st = live(user);
        let mut n = 0u32;
        let mut look = |identify: bool| {
            n += 1;
            Ok(obs(true, true, identify.then_some(false)))
        };
        let r = hold_wait(
            &mut look,
            &st,
            user,
            Instant::now() + Duration::from_secs(30),
            &ago(21),
            Some(Duration::from_secs(20)),
            Duration::ZERO,
        );
        assert!(matches!(r, Some(Round::FaceLost)));
        assert_eq!(n, 1, "one look past the away time");
    }

    #[test]
    fn a_hold_with_the_user_in_view_runs_to_its_end() {
        let user = "e2-hold-user-test";
        let st = live(user);
        let mut n = 0u32;
        let mut look = |identify: bool| {
            n += 1;
            Ok(obs(true, false, identify.then_some(true)))
        };
        let seen = ago(21);
        let r = hold_wait(
            &mut look,
            &st,
            user,
            Instant::now() + Duration::from_millis(30),
            &seen,
            Some(Duration::from_secs(20)),
            Duration::ZERO,
        );
        assert!(r.is_none(), "the hold ended by itself");
        assert!(n >= 1, "the chair was looked at");
        assert!(seen.get().elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_hold_ends_early_on_an_answer_and_looks_only_with_a_watch() {
        let user = "e2-hold-answer-test";
        let st = live(user);
        let n = std::cell::Cell::new(0u32);
        let mut look = |identify: bool| {
            n.set(n.get() + 1);
            Ok(obs(false, false, identify.then_some(false)))
        };
        // No presence watch, no looks: the hold is the old plain wait.
        let r = hold_wait(
            &mut look,
            &st,
            user,
            Instant::now() + Duration::from_millis(20),
            &ago(21),
            None,
            Duration::ZERO,
        );
        assert!(r.is_none());
        assert_eq!(n.get(), 0);
        st.push_answer(user, Answer::Dismiss);
        let r = hold_wait(
            &mut look,
            &st,
            user,
            Instant::now() + Duration::from_secs(30),
            &ago(21),
            Some(Duration::from_secs(20)),
            Duration::ZERO,
        );
        assert!(r.is_none(), "the answer ends the hold before any look");
        assert_eq!(n.get(), 0);
    }

    fn fresh() -> std::cell::Cell<Instant> {
        std::cell::Cell::new(Instant::now())
    }

    /// A request clock that last saw the user this many seconds ago.
    fn ago(secs: u64) -> std::cell::Cell<Instant> {
        std::cell::Cell::new(
            Instant::now()
                .checked_sub(Duration::from_secs(secs))
                .expect("the machine has been up longer than that"),
        )
    }
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
mod strikes_tests {
    use super::*;

    fn t(secs: u64) -> Instant {
        // A fixed origin far enough in the past that every test time is after it.
        static ORIGIN: std::sync::LazyLock<Instant> =
            std::sync::LazyLock::new(|| Instant::now() - Duration::from_secs(100_000));
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
        assert_eq!(
            s.hold(t(4 + 10)),
            Some(COOLDOWN_HOLD - Duration::from_secs(10))
        );
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
        assert_eq!(
            s.hold(t(35)),
            Some(COOLDOWN_HOLD * 2),
            "one failure after a served hold starts the next, twice as long"
        );
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
        let mut s = Strikes {
            last: Some(t(0)),
            holds: 40,
            ..Default::default()
        };
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
        assert_eq!(
            s.hold(t(70)),
            None,
            "four of the five are over a minute old"
        );
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
    let centre: Vec<f32> = u
        .templates
        .iter()
        .filter(|t| t.label.ends_with("-centre"))
        .filter_map(|t| t.nose_pitch)
        .collect();
    let any: Vec<f32> = u.templates.iter().filter_map(|t| t.nose_pitch).collect();
    let pick = if !centre.is_empty() { centre } else { any };
    if pick.is_empty() {
        LEVEL_DEFAULT
    } else {
        pick.iter().sum::<f32>() / pick.len() as f32
    }
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
        Pose {
            yaw,
            pitch: 0.5,
            roll: 0.0,
            nose_pitch,
            mouth_drop: 1.0,
            inter_eye: 40.0,
        }
    }

    #[test]
    fn each_pose_takes_its_own_frames_and_no_others() {
        let frontal = at(0.0, LEVEL_DEFAULT);
        assert!(pose_bin_accepts("centre", &frontal));
        for p in ["left", "right", "up", "down"] {
            assert!(
                !pose_bin_accepts(p, &frontal),
                "{} must not take a frontal frame",
                p
            );
        }
        assert!(
            pose_bin_accepts("left", &at(-0.3, 0.5)) && !pose_bin_accepts("right", &at(-0.3, 0.5))
        );
        assert!(
            pose_bin_accepts("right", &at(0.3, 0.5)) && !pose_bin_accepts("centre", &at(0.3, 0.5))
        );
        assert!(
            pose_bin_accepts("up", &at(0.05, 0.50)) && !pose_bin_accepts("centre", &at(0.05, 0.44)),
            "a comfortable chin-up reads a couple of hundredths under level"
        );
        assert!(
            pose_bin_accepts("down", &at(0.05, 0.7)) && !pose_bin_accepts("centre", &at(0.05, 0.7))
        );
        assert!(
            pose_bin_accepts("centre", &at(0.05, 0.55))
                && !pose_bin_accepts("up", &at(0.05, 0.55))
                && !pose_bin_accepts("down", &at(0.05, 0.55)),
            "level is level"
        );
        // Relative to a person who reads higher at level, the same bands move with them.
        assert!(
            pose_bin_accepts_at("up", &at(0.0, 0.57), 0.60)
                && !pose_bin_accepts_at("up", &at(0.0, 0.59), 0.60)
        );
        assert!(
            pose_bin_accepts_at("down", &at(0.0, 0.69), 0.60)
                && !pose_bin_accepts_at("down", &at(0.0, 0.66), 0.60)
        );
        assert!(
            !pose_bin_accepts("left", &at(-0.9, 0.5)),
            "a profile is past what the aligner can use"
        );
        assert!(!pose_bin_accepts("sideways", &frontal));
        assert_eq!(POSES.len(), POSE_HINTS.len());
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
