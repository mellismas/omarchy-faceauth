//! One look with the camera: detect, measure the pose, and on an identity
//! tick strobe a lit and unlit pair through the flash gate before the
//! face is embedded. A print that fails the gate is never taken for the
//! user.

use super::config::PresenceConfig;
use crate::auth::Authenticator;
use crate::capture::IrCapture;
use crate::store::UserTemplates;
use anyhow::Result;
use faceauth_camera::calib::Exposure;
use faceauth_engine::mesh::HeadPose;
use faceauth_engine::{Face, Grey};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

/// How long a look keeps trying to find the face when someone was there at
/// the last look: a hand passing over the face (a scratch, a sip) or a turn
/// away for a moment is not an empty chair, so the look waits it out instead
/// of recording a miss. A look at an empty chair stops after the exposure
/// settles, so the camera and the illuminator are not held for nobody.
pub const LOOK_SEE_BUDGET: Duration = Duration::from_secs(2);

/// The longest a look spends settling the exposure on the face before its
/// flash reading: a few frames usually, bounded because auto-exposure can
/// hold where a metered face clips a few percent.
pub const FACE_SETTLE_MAX: Duration = Duration::from_millis(500);
/// Whether the watched user's store failed to load on the last check, so
/// the warning is logged once per episode rather than every tick.
static STORE_UNREADABLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Whether the last look found the face beyond the line, so the note is
/// logged once per episode.
static BEYOND_LINE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Whether the last check read a side view past the enrolled looks, so the
/// note is logged once per episode.
static SIDE_VIEW: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// A face turned to the screen: yaw within `ATTENTIVE_MAX_YAW_DEG` on the
/// face mesh and roll within `ATTENTIVE_MAX_ROLL_DEG`
/// (`faceauth_engine::mesh::is_attentive`, the one attention rule). What
/// "attentive" means everywhere a look asks it: the watch, the lock
/// screen's probe and the re-arm gate. The yaw bound was set as 0.25 of
/// the five-point measure, where a 30 degree turn reads about 0.35: 21.4
/// degrees. A face the mesh reads no pose from is not attentive, so the
/// watch treats it as hidden (the user's own hand over the mouth or
/// chin), with one exception, `facing_the_session`: when this look's
/// identity check scored it and failed it by more than `NEAR_MISS_SLACK`
/// (a scored wide miss, never a strobe-gate refusal), it is someone
/// else's face at the session, mesh or no mesh, and it is reported
/// attentive so the watch's stranger rule sees it (the secure mode locks
/// on that tick; the default mode labels it Stranger). A near miss or no
/// check keeps it hidden. The shape under the box tells a person from the
/// wall, not one person from another, so it must not hold for a face the
/// check has already said is not the user.
pub const ATTENTIVE_MAX_YAW_DEG: f32 = 21.428_572;
pub const ATTENTIVE_MAX_ROLL_DEG: f32 = 25.0;

/// How far past the widest enrolled look on its side a face may turn, in
/// the five-point yaw's inter-eye units (about 0.35 is a 30 degree turn),
/// before a failed check on it reads as nothing rather than as someone
/// else. A judgment, not a measurement: about 9 degrees past the last look
/// the templates hold.
const SIDE_VIEW_MARGIN: f32 = 0.10;

/// The least reach on each side, whatever the templates recorded: about the
/// attention rule's 21 degrees, so a face turned to the screen is always
/// checked as itself. A set enrolled before pose was recorded, or one whose
/// looks all sit to one side, reaches this far.
const MIN_REACH: f32 = 0.25;

/// Whether a face at five-point `yaw` (`pose::Pose`, the measure the
/// templates record) is turned past every look enrolled on `device`, on its
/// own side, by more than `SIDE_VIEW_MARGIN`; never within `MIN_REACH`. The
/// embedding of a face turned that far scores low whoever it is, so a miss
/// there says nothing about who it is.
pub(crate) fn past_enrolled_looks(yaw: f32, t: &UserTemplates, device: &str) -> bool {
    let yaws = t
        .templates
        .iter()
        .filter(|x| x.device == device)
        .filter_map(|x| x.yaw);
    let left = yaws.clone().fold(-MIN_REACH, f32::min);
    let right = yaws.fold(MIN_REACH, f32::max);
    yaw > right + SIDE_VIEW_MARGIN || yaw < left - SIDE_VIEW_MARGIN
}

/// A check that read the face: pass or fail, and whether a fail was near
/// enough the line to be the user's own face half covered. The score
/// itself stays at debug: the journal is readable by wheel on Omarchy, and
/// a scored stream is a tuning oracle.
fn checked(
    score: f32,
    accept_threshold: f32,
    face: &Face,
    eyes: &dyn Eyes,
) -> (Option<bool>, bool) {
    if score < accept_threshold {
        log::info!("presence: identity check failed");
        let e = eyes.exposure();
        log::debug!(
            "presence: identity score {:.2} (exp {} gain {}, face {:.2})",
            score,
            e.map(|e| e.exposure).unwrap_or(0),
            e.map(|e| e.gain).unwrap_or(0),
            face.score
        );
    }
    let passed = score >= accept_threshold;
    (
        Some(passed),
        !passed && score >= accept_threshold - NEAR_MISS_SLACK,
    )
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
    /// A failed check that scored within `NEAR_MISS_SLACK` of the accept
    /// threshold: the user's own face half covered by a hand or pitched
    /// over a phone scores there; another person scores far below it.
    pub(crate) near_miss: bool,
    /// The default mode's check missed a face turned past every enrolled
    /// look (`past_enrolled_looks`), and so read nothing (`identity` is
    /// None): the user reading a second screen, or anyone turned that way.
    /// The watch lets it hold the clock only for a while after a check
    /// confirmed the user (`watch::SIDE_VIEW_HOLD`).
    pub(crate) side_view: bool,
}

/// What the flash gate's verdict lets the identity check do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AfterGate {
    /// The gate refused: not the user, no embedding needed.
    Refused,
    /// The gate passed, or could not run at all (the sensor has no strobe
    /// control) in the default mode: the embedding decides.
    Embed,
    /// The gate ran and read no signal (a bright room, a face far back), or
    /// could not run at all. In the secure mode that confirms nothing: the
    /// embedding alone must not hold the clock there (E4), so the look ends
    /// unchecked.
    Unconfirmed,
}

/// `gate_ran` is whether the gate could run at all; `verdict` is its
/// answer (`None` for no signal); `strict` is the secure mode.
pub(crate) fn after_gate(gate_ran: bool, verdict: Option<bool>, strict: bool) -> AfterGate {
    match (gate_ran, verdict) {
        // No strobe control. The secure mode is not offered on such a
        // camera (`secure_mode_for`), and should a secure look run there
        // anyway (the first look after a start, before the camera has been
        // opened) it confirms nobody: a print of the user must not hold the
        // clock. The default mode's embedding decides, as with no signal
        // below.
        (false, _) if strict => AfterGate::Unconfirmed,
        (false, _) => AfterGate::Embed,
        (true, Some(false)) => AfterGate::Refused,
        (true, Some(true)) => AfterGate::Embed,
        (true, None) if strict => AfterGate::Unconfirmed,
        // The default mode's look is the convenience lane: with no signal,
        // a failed exposure read-back (J19) included, the embedding still
        // decides. Refusing here would lock the user out in a bright room,
        // where every pair reads no signal. Nothing is unlocked by it: the
        // scan, the confirm and the enrollment check never pass a pair they
        // could not verify.
        (true, None) => AfterGate::Embed,
    }
}

/// One short look: open the camera, LEDs on, a few frames, detect, maybe
/// identify, close. With `strict` (the secure mode) a face the gate read
/// no signal from, or could not run on, comes back unchecked
/// (`identity: None`) rather than judged by the embedding alone; without
/// it the embedding decides.
pub(crate) fn observe_in(
    a: &mut Authenticator,
    cfg: &PresenceConfig,
    identify: bool,
    strict: bool,
    persist: bool,
) -> Result<Observation> {
    let accept = a.cfg.accept_threshold;
    let mut eyes = LiveEyes::open(a)?;
    look(&mut eyes, cfg, accept, identify, strict, persist, None).map(|(o, _)| o)
}

/// The lock screen probe's look: the same look without the identity check,
/// and with `user`'s best template score for the face on the look's own
/// frame, taken without the flash or the gate once the camera is closed. A
/// filter for the probe's `likely`, never a decision.
pub(crate) fn probe_look(
    a: &mut Authenticator,
    cfg: &PresenceConfig,
    user: &str,
) -> Result<(Observation, ProbeReading)> {
    let accept = a.cfg.accept_threshold;
    let mut eyes = LiveEyes::open(a)?;
    probe_look_with(&mut eyes, cfg, accept, user)
}

/// `probe_look` through any eyes: the watch's own look, asked for no
/// identity and for the probe's score.
pub(crate) fn probe_look_with(
    eyes: &mut dyn Eyes,
    cfg: &PresenceConfig,
    accept_threshold: f32,
    user: &str,
) -> Result<(Observation, ProbeReading)> {
    look(eyes, cfg, accept_threshold, false, false, false, Some(user))
}

/// What a probe's look read of the asking user's face.
pub(crate) struct ProbeReading {
    /// The best template score, or why the look has none: no frame, no
    /// face, a face beyond the line an attempt would judge, nothing
    /// enrolled, no templates for this camera, or a face that could not be
    /// scored.
    pub(crate) score: std::result::Result<f32, &'static str>,
    /// The look's frames were lit by the IR illuminator: every frame, with
    /// the exposure metered on the whole frame, where a full scan scores the
    /// lit frames of strobed pairs with the exposure settled on the face.
    pub(crate) lit: bool,
}

/// What a look needs from the camera, the models and the store, so one
/// look serves the watch, the consent waits and the lock screen's probe,
/// and a test can run it with none of them (H12). `LiveEyes` is the
/// daemon's.
pub(crate) trait Eyes {
    /// Whether the illuminator lights the look, and can strobe its pair.
    fn lit(&self) -> bool;
    /// The next frame, written into `img`; false when none came within
    /// `timeout`, and `img` is then left as it was.
    fn frame(&mut self, img: &mut Grey, timeout: Duration) -> Result<bool>;
    /// The faces on `img` the detector is sure enough of.
    fn detect(&mut self, img: &Grey) -> Result<Vec<Face>>;
    /// The face mesh's head pose for `face`, when the mesh reads it.
    fn head_pose(&mut self, img: &Grey, face: &Face) -> Option<HeadPose>;
    /// The exposure in force now, for the log; None once closed.
    fn exposure(&self) -> Option<Exposure>;
    /// The next look starts from the exposure in force now.
    fn keep_exposure(&mut self);
    /// Settle the exposure on `face` before the flash, as an unlock
    /// attempt does (C10).
    fn settle_on(&mut self, face: &Face) -> Result<()>;
    /// One strobed pair gated at `face` (`strobe_pair`).
    fn strobe_pair(&mut self, face: &Face) -> Result<Option<bool>>;
    /// The camera's identity, which templates are bound to.
    fn device(&self) -> String;
    /// Close the camera.
    fn close(&mut self) -> Result<()>;
    fn embed(&mut self, crop: &Grey) -> Result<Vec<f32>>;
    fn templates(&mut self, user: &str) -> Result<Option<UserTemplates>>;
}

/// The daemon's eyes: the IR camera for one look, the authenticator's
/// models and its template store.
struct LiveEyes<'a> {
    a: &'a mut Authenticator,
    /// None once closed.
    cap: Option<IrCapture>,
}

impl<'a> LiveEyes<'a> {
    /// Open the camera at the exposure the last look ended on, LEDs on.
    fn open(a: &'a mut Authenticator) -> Result<Self> {
        let cap = IrCapture::open_at(&a.cfg, a.last_exposure)?;
        if let Some(i) = &cap.illuminator {
            i.set(true)?;
        }
        Ok(LiveEyes { a, cap: Some(cap) })
    }

    fn cap(&mut self) -> Result<&mut IrCapture> {
        self.cap
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("the look's camera is closed"))
    }
}

impl Eyes for LiveEyes<'_> {
    fn lit(&self) -> bool {
        self.cap.as_ref().is_some_and(|c| c.tier().gated())
    }

    fn frame(&mut self, img: &mut Grey, timeout: Duration) -> Result<bool> {
        self.cap()?.next_into(img, timeout)
    }

    fn detect(&mut self, img: &Grey) -> Result<Vec<Face>> {
        self.a
            .pipeline
            .detector
            .detect(img, self.a.cfg.min_detection)
    }

    fn head_pose(&mut self, img: &Grey, face: &Face) -> Option<HeadPose> {
        self.a
            .pipeline
            .mesh
            .as_mut()
            .and_then(|m| m.for_face(img, face).ok().flatten())
            .map(|m| faceauth_engine::mesh::head_pose(&m))
    }

    fn exposure(&self) -> Option<Exposure> {
        self.cap.as_ref().map(|c| c.exposure)
    }

    fn keep_exposure(&mut self) {
        if let Some(e) = self.exposure() {
            self.a.last_exposure = Some(e);
        }
    }

    fn settle_on(&mut self, face: &Face) -> Result<()> {
        // The look's exposure came from the whole frame, and a face near
        // the screen then clips under the strobe: 20 to 23 percent of the
        // face blown out, read as no signal, measured live on 2026-09-24
        // at an ordinary seated distance. Bounded, since auto-exposure can
        // hold where a face clips a few percent.
        let cap = self.cap()?;
        cap.meter_on(face);
        let until = Instant::now() + FACE_SETTLE_MAX;
        let mut steps = 0;
        let mut scratch = Grey::default();
        while Instant::now() < until {
            if cap.next_into(&mut scratch, Duration::from_millis(200))? {
                steps += 1;
                if steps >= 3 && cap.metering.clip < 0.05 {
                    break;
                }
            }
        }
        self.keep_exposure();
        Ok(())
    }

    fn strobe_pair(&mut self, face: &Face) -> Result<Option<bool>> {
        let min_detection = self.a.cfg.min_detection;
        let cap = self
            .cap
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("the look's camera is closed"))?;
        strobe_pair(cap, &mut self.a.pipeline.detector, min_detection, face)
    }

    fn device(&self) -> String {
        self.cap
            .as_ref()
            .map(|c| c.identity.clone())
            .unwrap_or_default()
    }

    fn close(&mut self) -> Result<()> {
        match self.cap.take() {
            Some(c) => c.stop(),
            None => Ok(()),
        }
    }

    fn embed(&mut self, crop: &Grey) -> Result<Vec<f32>> {
        self.a.pipeline.embedder.embed(crop)
    }

    fn templates(&mut self, user: &str) -> Result<Option<UserTemplates>> {
        self.a.store.load(user)
    }
}

/// The look itself, through `eyes`: the watch's, the consent waits' and
/// the probe's alike.
fn look(
    eyes: &mut dyn Eyes,
    cfg: &PresenceConfig,
    accept_threshold: f32,
    identify: bool,
    strict: bool,
    persist: bool,
    score_for: Option<&str>,
) -> Result<(Observation, ProbeReading)> {
    let lit = eyes.lit();
    let unscored = |why: &'static str| ProbeReading {
        score: Err(why),
        lit,
    };
    // Let exposure react for a handful of frames; the last one is what we
    // look at. One frame, read into again and again (C7).
    let mut img = Grey::default();
    let mut got = false;
    let deadline = Instant::now() + Duration::from_millis(450);
    while Instant::now() < deadline {
        got |= eyes.frame(&mut img, Duration::from_millis(500))?;
    }
    if !got {
        eyes.close()?;
        return Ok((
            Observation {
                face: false,
                attentive: false,
                identity: None,
                near_miss: false,
                side_view: false,
                frame: None,
                bbox: None,
            },
            unscored("no frame"),
        ));
    }
    let mut faces = eyes.detect(&img)?;
    // With someone there at the last look, keep looking for up to
    // `LOOK_SEE_BUDGET` before calling it no face (a hand over the face for
    // a moment is not an empty chair).
    if persist && faces.is_empty() {
        let until = Instant::now() + LOOK_SEE_BUDGET;
        while faces.is_empty() && Instant::now() < until {
            if eyes.frame(&mut img, Duration::from_millis(200))? {
                faces = eyes.detect(&img)?;
            }
        }
    }
    // The next look starts from where this one's exposure ended, face or
    // no face: a seed that saturates after the light changes is escaped one
    // step per look this way, where saving it only behind a found face left
    // the watch blind until an authentication refreshed it (E4).
    eyes.keep_exposure();
    let Some(face) = faces.into_iter().max_by(|x, y| x.score.total_cmp(&y.score)) else {
        eyes.close()?;
        return Ok((
            Observation {
                face: false,
                attentive: false,
                identity: None,
                near_miss: false,
                side_view: false,
                frame: Some(img),
                bbox: None,
            },
            unscored("no face"),
        ));
    };
    // Attention from the mesh's angles, the one rule: they hold where the
    // five detector points' do not (a chin-up seen from below). No pose
    // from the mesh on a detected face is not attentive.
    let hp = eyes.head_pose(&img, &face);
    let posed = hp.as_ref().is_some_and(|hp| {
        faceauth_engine::mesh::is_attentive(hp, ATTENTIVE_MAX_YAW_DEG, ATTENTIVE_MAX_ROLL_DEG)
    });
    let attentive = facing_the_session(hp.is_some(), posed, None, false);
    // Beyond the line an unlock attempt would not judge, the look does not
    // flash or check identity either: it cannot read the face there, and
    // flashing at someone out of range every tick is what the user saw as
    // being read over and over. The look still reports the face; the
    // default mode holds on it, the secure mode treats it as hidden.
    let near_enough = crate::auth::scannable(face.bbox[2], img.width, img.height);
    if identify && !near_enough {
        if !BEYOND_LINE.swap(true, Ordering::Relaxed) {
            log::info!(
                "presence: face {:.0} px wide, beyond the line; no flash and no identity check until it is nearer",
                face.bbox[2]
            );
        }
    } else if near_enough {
        BEYOND_LINE.store(false, Ordering::Relaxed);
    }
    let identify = identify && near_enough;
    if identify && eyes.lit() {
        eyes.settle_on(&face)?;
    }
    let (identity, near_miss, side_view) = if identify {
        // Liveness first: one lit/unlit pair under the look's own mask,
        // with exposure frozen for it as the confirm does, since an
        // auto-exposure step inside the pair breaks the phase lock or skews
        // the lit and unlit frames against each other (E4). A refusal is
        // "not the user"; no signal, or no gate at all, decides nothing in
        // the default mode and ends the look unchecked in the secure mode.
        let gate_ran = eyes.lit();
        let verdict = eyes.strobe_pair(&face)?;
        match after_gate(gate_ran, verdict, strict) {
            AfterGate::Embed => {}
            AfterGate::Refused => {
                eyes.close()?;
                return Ok((
                    Observation {
                        face: true,
                        // The gate refuses for reasons that are not identity
                        // (an exposure read-back mismatch, a lit surround, a
                        // reflectance the user's own forearm at the chin could
                        // give), so a refusal is not a wide miss: no check, as
                        // far as attention goes.
                        attentive: facing_the_session(hp.is_some(), posed, None, false),
                        identity: Some(false),
                        near_miss: false,
                        side_view: false,
                        frame: Some(img),
                        bbox: Some(face.bbox),
                    },
                    unscored("not asked"),
                ));
            }
            AfterGate::Unconfirmed => {
                if gate_ran {
                    log::info!("presence: the gate read no signal; the look confirms nobody");
                } else {
                    log::info!("presence: no strobe control, so the secure look confirms nobody");
                }
                eyes.close()?;
                return Ok((
                    Observation {
                        face: true,
                        attentive,
                        identity: None,
                        near_miss: false,
                        side_view: false,
                        frame: Some(img),
                        bbox: Some(face.bbox),
                    },
                    unscored("not asked"),
                ));
            }
        }
        let crop = faceauth_engine::align::align_112(&img, &face.landmarks);
        let e = eyes.embed(&crop)?;
        // Templates only count on the camera they were enrolled on, and a
        // store that cannot be read is nobody, not everybody: the check fails
        // closed rather than skipping the tick with identity still assumed.
        // The default mode also asks whether the face is turned past every
        // enrolled look, as when the user reads a second screen: a miss
        // there says nothing about who it is (below).
        let (score, turned) = match eyes.templates(&cfg.user) {
            Ok(Some(t)) => {
                STORE_UNREADABLE.store(false, Ordering::Relaxed);
                let device = eyes.device();
                let score = t.best_match_on(&e, &device).map(|(s, _)| s).unwrap_or(-1.0);
                let yaw = faceauth_engine::pose::pose(&face.landmarks).yaw;
                (score, !strict && past_enrolled_looks(yaw, &t, &device))
            }
            Ok(None) => (-1.0, false),
            Err(e) => {
                // Not a failed check: there is nothing to check against.
                // The look decides nothing, so the watch does not run a
                // check on every tick (the stranger cadence) and hold the
                // camera against the re-enrollment that fixes it. Warned
                // once per episode.
                if !STORE_UNREADABLE.swap(true, Ordering::Relaxed) {
                    log::warn!(
                        "presence: templates unreadable, identity is not checked until they are: {}",
                        e
                    );
                }
                eyes.close()?;
                return Ok((
                    Observation {
                        face: true,
                        attentive,
                        identity: None,
                        near_miss: false,
                        side_view: false,
                        frame: Some(img),
                        bbox: Some(face.bbox),
                    },
                    unscored("not asked"),
                ));
            }
        };
        if score < accept_threshold && turned {
            // The embedding of a face turned that far scores low whoever it
            // is, so the miss is no reading, and two side views do not make
            // a stranger of the user. How long it may hold the clock is the
            // watch's call (`watch::SIDE_VIEW_HOLD`). The secure mode never
            // takes this path. Logged once per episode.
            if !SIDE_VIEW.swap(true, Ordering::Relaxed) {
                log::info!("presence: the face is turned past the enrolled looks; the check reads nothing until it turns back");
            }
            (None, false, true)
        } else {
            SIDE_VIEW.store(false, Ordering::Relaxed);
            let (identity, near_miss) = checked(score, accept_threshold, &face, &*eyes);
            (identity, near_miss, false)
        }
    } else {
        (None, false, false)
    };
    let attentive = facing_the_session(hp.is_some(), posed, identity, near_miss);
    let device = eyes.device();
    eyes.close()?;
    // After the camera is closed, so the embed does not hold it.
    let reading = match score_for {
        None => unscored("not asked"),
        Some(_) if !near_enough => unscored("face beyond the line"),
        Some(user) => ProbeReading {
            score: probe_score(eyes, user, &img, &face.landmarks, &device),
            lit,
        },
    };
    log::debug!(
        "presence tick: face {:.2} mesh {} attentive {} identity {:?}",
        face.score,
        hp.map_or("none".to_string(), |hp| format!(
            "yaw {:.0} pitch {:.0} roll {:.0}",
            hp.yaw, hp.pitch, hp.roll
        )),
        attentive,
        identity
    );
    let bbox = face.bbox;
    Ok((
        Observation {
            face: true,
            attentive,
            identity,
            near_miss,
            side_view,
            frame: Some(img),
            bbox: Some(bbox),
        },
        reading,
    ))
}

/// Whether the last probe could not score its face (templates unreadable,
/// or the embedder failing), so the warning is logged once per episode.
static PROBE_UNSCORED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `user`'s best template score for the face at `landmarks` on `img`,
/// against the templates enrolled on `device` only, or why there is none.
/// The store is read first, so a user with nothing enrolled costs no embed.
/// The score never leaves the daemon; `probe` logs it at debug only, as an
/// attempt logs its frame scores.
fn probe_score(
    eyes: &mut dyn Eyes,
    user: &str,
    img: &Grey,
    landmarks: &[[f32; 2]; 5],
    device: &str,
) -> std::result::Result<f32, &'static str> {
    let scored = (|| -> Result<std::result::Result<f32, &'static str>> {
        let Some(t) = eyes.templates(user)? else {
            return Ok(Err("not enrolled"));
        };
        let crop = faceauth_engine::align::align_112(img, landmarks);
        let e = eyes.embed(&crop)?;
        Ok(t.best_match_on(&e, device)
            .map(|(s, _)| s)
            .ok_or("no templates for this camera"))
    })();
    match scored {
        Ok(s) => {
            PROBE_UNSCORED.store(false, Ordering::Relaxed);
            s
        }
        Err(e) => {
            if !PROBE_UNSCORED.swap(true, Ordering::Relaxed) {
                log::warn!(
                    "probe: the face could not be scored, so no probe reads as likely until it can: {:#}",
                    e
                );
            }
            Err("could not be scored")
        }
    }
}

/// How long a presence look may strobe for its one reading. The phase lock
/// alone takes about half a second (the settle, then eight frames that
/// follow the mask), so the 0.6 s the look used to allow left room for one
/// pair at best, and many looks at a user sitting in front of the screen
/// read nothing. Two seconds, so a hand or a turn in the middle of a look
/// does not end it unread: the look keeps trying until it has a verdict
/// or two seconds have passed. It returns at the first verdict, so an
/// ordinary look still strobes for about half a second.
pub const PRESENCE_STROBE_WINDOW: Duration = Duration::from_millis(2000);

/// One strobed lit/unlit pair on the open camera, gated at the face:
/// `Some(true)` passed, `Some(false)` refused, `None` no usable pair within
/// the window. The flash is judged where the face is in each lit frame, as
/// an unlock attempt does; the box from before the strobe misses a head
/// that moved. A look that ends without a verdict says why at info (frames,
/// pairs, pairs too faint, whether the frames ever followed the mask); the
/// gate's numbers stay at debug.
fn strobe_pair(
    cap: &mut crate::capture::IrCapture,
    detector: &mut faceauth_engine::detect::YuNet,
    min_detection: f32,
    face: &faceauth_engine::Face,
) -> Result<Option<bool>> {
    use crate::strobe::{Gate, StrobeGate};
    if cap.illuminator.is_none() {
        return Ok(None);
    }
    // The one gate: a fresh random mask per look, a pair only once the
    // frames have followed it (D5), the settle after the mask is written
    // (E4) and steady light back when the look ends, whichever way.
    let mut gate = StrobeGate::start(cap, true)?;
    gate.focus_on(face.bbox);
    let t0 = Instant::now();
    let mut tracked = face.clone();
    let (mut pairs, mut faint) = (0usize, 0usize);
    while t0.elapsed() < PRESENCE_STROBE_WINDOW {
        let Some(pair) = gate.next_frame(Duration::from_millis(200))? else {
            continue;
        };
        let faces = detector.detect(&pair.lit, min_detection)?;
        if let crate::consent::Track::Found(i) = crate::consent::track(&faces, tracked.bbox) {
            tracked = faces[i].clone();
            gate.focus_on(tracked.bbox);
        }
        pairs += 1;
        match gate.judge(&pair, &tracked)? {
            Gate::Pass(fr) => {
                log::debug!(
                    "presence liveness: pass after {} ms, pair {} {:?}",
                    t0.elapsed().as_millis(),
                    pairs,
                    fr
                );
                return Ok(Some(true));
            }
            Gate::NoSignal(fr) => {
                faint += 1;
                log::debug!("presence liveness: no signal {:?}", fr);
            }
            Gate::Denied(why, fr) => {
                log::info!("presence liveness: refused ({})", why);
                log::debug!("presence liveness: refused {:?}", fr);
                return Ok(Some(false));
            }
        }
    }
    log::info!(
        "presence liveness: no reading in {} ms: {} frames, {} pairs, {} too faint, the frames {} the mask",
        t0.elapsed().as_millis(),
        gate.frames(),
        pairs,
        faint,
        if gate.locked() { "followed" } else { "never followed" }
    );
    Ok(None)
}

/// How far under the accept threshold a failed presence check may score and
/// still count as the user's own face partly hidden rather than someone
/// else's (0.45 at the default 0.70). Different people score around 0.1 to
/// 0.3 against a set on this model; a hand on the chin or a face pitched
/// over a phone lands between. Reasoned, not measured on a corpus: the
/// scores are logged at debug so it can be. A near miss holds the clock
/// only through the shape in the chair, never on its own. The covered
/// face's mesh and identity scores are to be measured in the a6 recording
/// (condition a6-cover), and this slack revisited then.
pub const NEAR_MISS_SLACK: f32 = 0.25;

/// Whether a detected face counts as turned to the session. `posed` is
/// the mesh rule's answer when the mesh read a pose (`pose_read`). A face
/// the mesh read no pose from is not attentive unless this look's identity
/// check scored it and failed it by a wide margin: that is another person
/// at the session whatever hides the mouth or chin, so it is reported
/// attentive for the watch's stranger rule. A near miss, no check, or a
/// strobe-gate refusal (which is not an identity reading, and which a live
/// stranger passes anyway) leaves it hidden, the user's own covered face.
fn facing_the_session(
    pose_read: bool,
    posed: bool,
    identity: Option<bool>,
    near_miss: bool,
) -> bool {
    if pose_read {
        posed
    } else {
        identity == Some(false) && !near_miss
    }
}

/// Eyes with no camera, models or store behind them, for the tests: one
/// face on every frame, a fixed head pose, a fixed embedding, and a count
/// of what the look asked for.
#[cfg(test)]
pub(crate) mod stub_eyes {
    use super::*;

    pub(crate) struct StubEyes {
        pub face: Option<Face>,
        pub pose: HeadPose,
        /// The mesh reads no pose from the face (a hand over the mouth or
        /// chin): `head_pose` answers None.
        pub no_pose: bool,
        pub embedding: Vec<f32>,
        pub templates: Option<UserTemplates>,
        pub device: String,
        /// The illuminator lights the look and can strobe its pair; without
        /// it the pair reads None, as the live camera's does.
        pub lit: bool,
        /// The strobed pair's verdict.
        pub gate: Option<bool>,
        pub strobes: usize,
        pub embeds: usize,
        /// Embeds made while the camera was still open.
        pub embeds_open: usize,
        pub closed: bool,
    }

    impl StubEyes {
        /// A face `width` px wide, straight at the camera, in a 480x640
        /// frame, whose embedding is `embedding`, for a user whose one
        /// template on this camera is `template`.
        pub(crate) fn new(width: f32, embedding: Vec<f32>, template: Vec<f32>) -> StubEyes {
            let (cx, cy) = (240.0, 320.0);
            let u = width / 4.0;
            StubEyes {
                face: Some(Face {
                    bbox: [cx - width / 2.0, cy - width * 0.6, width, width * 1.2],
                    score: 0.9,
                    landmarks: [
                        [cx - u, cy - u],
                        [cx + u, cy - u],
                        [cx, cy],
                        [cx - u * 0.8, cy + u],
                        [cx + u * 0.8, cy + u],
                    ],
                    embedding: None,
                }),
                pose: HeadPose {
                    yaw: 0.0,
                    pitch: 10.0,
                    roll: 0.0,
                },
                no_pose: false,
                embedding,
                templates: Some(UserTemplates {
                    version: 1,
                    user: "alice".into(),
                    uid: 1000,
                    model: String::new(),
                    templates: vec![crate::store::Template {
                        embedding: template,
                        quality: 0.9,
                        face_width: 90.0,
                        created: 0,
                        label: "enrol".into(),
                        device: "stub-camera".into(),
                        yaw: None,
                        nose_pitch: None,
                    }],
                    gesture: Default::default(),
                }),
                device: "stub-camera".into(),
                lit: true,
                gate: Some(true),
                strobes: 0,
                embeds: 0,
                embeds_open: 0,
                closed: false,
            }
        }
    }

    impl Eyes for StubEyes {
        fn lit(&self) -> bool {
            self.lit
        }
        fn frame(&mut self, img: &mut Grey, _timeout: Duration) -> Result<bool> {
            std::thread::sleep(Duration::from_millis(30));
            if img.data.is_empty() {
                // Textured, so the shape under the box can be compared
                // between looks (a flat frame has no shape to match).
                *img = Grey::new(480, 640);
                img.data
                    .iter_mut()
                    .enumerate()
                    .for_each(|(i, v)| *v = (i % 251) as u8);
            }
            Ok(true)
        }
        fn detect(&mut self, _img: &Grey) -> Result<Vec<Face>> {
            Ok(self.face.iter().cloned().collect())
        }
        fn head_pose(&mut self, _img: &Grey, _face: &Face) -> Option<HeadPose> {
            (!self.no_pose).then_some(self.pose)
        }
        fn exposure(&self) -> Option<Exposure> {
            None
        }
        fn keep_exposure(&mut self) {}
        fn settle_on(&mut self, _face: &Face) -> Result<()> {
            Ok(())
        }
        fn strobe_pair(&mut self, _face: &Face) -> Result<Option<bool>> {
            if !self.lit {
                return Ok(None);
            }
            self.strobes += 1;
            Ok(self.gate)
        }
        fn device(&self) -> String {
            self.device.clone()
        }
        fn close(&mut self) -> Result<()> {
            self.closed = true;
            Ok(())
        }
        fn embed(&mut self, _crop: &Grey) -> Result<Vec<f32>> {
            self.embeds += 1;
            if !self.closed {
                self.embeds_open += 1;
            }
            Ok(self.embedding.clone())
        }
        fn templates(&mut self, _user: &str) -> Result<Option<UserTemplates>> {
            Ok(self.templates.clone())
        }
    }
}

#[cfg(test)]
mod look_tests {
    use super::stub_eyes::StubEyes;
    use super::*;

    /// H12: the watch's identity look and the probe's look are one look.
    /// Asked for identity it strobes a pair and embeds with the camera
    /// open; asked for the probe it never strobes, and scores the face
    /// only once the camera is closed.
    #[test]
    fn the_watch_look_strobes_and_the_probe_look_does_not() {
        let cfg = PresenceConfig {
            user: "alice".into(),
            ..Default::default()
        };
        let mut watch = StubEyes::new(90.0, vec![1.0, 0.0], vec![1.0, 0.0]);
        let (o, reading) = look(&mut watch, &cfg, 0.7, true, false, false, None).unwrap();
        assert_eq!((o.face, o.attentive, o.identity), (true, true, Some(true)));
        assert_eq!((watch.strobes, watch.embeds_open), (1, 1));
        assert!(watch.closed && reading.score.is_err());

        let mut probe = StubEyes::new(90.0, vec![1.0, 0.0], vec![1.0, 0.0]);
        let (o, reading) = probe_look_with(&mut probe, &cfg, 0.7, "alice").unwrap();
        assert_eq!((o.face, o.attentive, o.identity), (true, true, None));
        assert_eq!(probe.strobes, 0, "the probe never strobes");
        assert_eq!((probe.embeds, probe.embeds_open), (1, 0));
        assert_eq!(reading.score, Ok(1.0));
    }

    /// A face the mesh reads no pose from, through the look and into the
    /// watch. A wide identity miss on it is a stranger: the secure mode
    /// locks on that tick and the default mode labels it Stranger. A near
    /// miss, or a look that ran no check, is the user's own covered face:
    /// not attentive, and the shape under the box holds as before.
    #[test]
    fn a_face_without_a_mesh_pose_is_a_stranger_only_on_a_wide_miss() {
        use super::super::watch::{State, Watch};
        use crate::presence::PresenceMode;
        let cfg = PresenceConfig {
            user: "alice".into(),
            ..Default::default()
        };
        let no_pose = |embedding: Vec<f32>| {
            let mut eyes = StubEyes::new(90.0, embedding, vec![1.0, 0.0]);
            eyes.no_pose = true;
            eyes
        };
        // (a) Secure mode, wide miss: attentive for the stranger rule, and
        // the watch locks on that very tick.
        let mut eyes = no_pose(vec![0.0, 1.0]);
        let (far, _) = look(&mut eyes, &cfg, 0.7, true, true, false, None).unwrap();
        assert_eq!(
            (far.face, far.attentive, far.identity, far.near_miss),
            (true, true, Some(false), false)
        );
        let t0 = Instant::now();
        let mut w = Watch::new(cfg.clone());
        let mut eyes = StubEyes::new(90.0, vec![1.0, 0.0], vec![1.0, 0.0]);
        let (seen, _) = look(&mut eyes, &cfg, 0.7, true, true, false, None).unwrap();
        w.step(&seen, t0, PresenceMode::Secure);
        let step = w.step(&far, t0 + Duration::from_secs(5), PresenceMode::Secure);
        assert!(
            step.lock,
            "secure: a wide miss on an unread face locks on the tick"
        );
        assert_eq!(w.state, State::Away);
        // (b) Secure mode, near miss or no check: hidden, not attentive, and
        // the same shape holds the clock as before.
        let mut eyes = no_pose(vec![0.6, 0.8]);
        let (near, _) = look(&mut eyes, &cfg, 0.7, true, true, false, None).unwrap();
        assert_eq!(
            (near.attentive, near.identity, near.near_miss),
            (false, Some(false), true)
        );
        let mut eyes = no_pose(vec![0.0, 1.0]);
        let (unchecked, _) = look(&mut eyes, &cfg, 0.7, false, true, false, None).unwrap();
        assert_eq!((unchecked.attentive, unchecked.identity), (false, None));
        // A strobe-gate refusal is not an identity reading: a forearm at
        // the chin can light the surround, and a live stranger passes the
        // gate to be scored anyway. Not attentive, held by shape.
        let mut eyes = no_pose(vec![0.0, 1.0]);
        eyes.gate = Some(false);
        let (refused, _) = look(&mut eyes, &cfg, 0.7, true, true, false, None).unwrap();
        assert_eq!(
            (refused.attentive, refused.identity, refused.near_miss),
            (false, Some(false), false)
        );
        for (what, o) in [
            ("near miss", &near),
            ("no check", &unchecked),
            ("gate refusal", &refused),
        ] {
            let mut w = Watch::new(cfg.clone());
            w.step(&seen, t0, PresenceMode::Secure);
            let mut locked = false;
            for i in 1..=6 {
                locked |= w
                    .step(o, t0 + Duration::from_secs(5 * i), PresenceMode::Secure)
                    .lock;
            }
            assert!(
                !locked,
                "secure: a {} on an unread face holds by shape",
                what
            );
        }
        // (c) Default mode, wide miss: after the two strikes the face holds
        // the clock as a stranger looking at the session (Q9) and the shell
        // reads Stranger.
        let mut w = Watch::new(cfg.clone());
        w.step(&seen, t0, PresenceMode::Default);
        let mut locked = false;
        for i in 1..=6 {
            locked |= w
                .step(
                    &far,
                    t0 + Duration::from_secs(10 * i),
                    PresenceMode::Default,
                )
                .lock;
        }
        assert!(
            !locked,
            "default: never locks on a stranger looking at the screen"
        );
        assert_eq!(w.state, State::Stranger);
    }

    /// E4 on a camera without the strobe control. The gate cannot run
    /// there, so the secure mode is not offered on it, and a secure look
    /// that runs there anyway (before the watch has learned what the camera
    /// can do) must not take identity from the embedding alone: a print of
    /// the user would hold the away clock. The default mode's look still
    /// lets the embedding decide, as it does when the gate reads no signal.
    #[test]
    fn a_secure_look_without_the_strobe_confirms_nobody() {
        let cfg = PresenceConfig {
            user: "alice".into(),
            ..Default::default()
        };
        let unlit = || {
            let mut eyes = StubEyes::new(90.0, vec![1.0, 0.0], vec![1.0, 0.0]);
            eyes.lit = false;
            eyes
        };
        let mut eyes = unlit();
        let (secure, _) = look(&mut eyes, &cfg, 0.7, true, true, false, None).unwrap();
        assert_eq!(secure.identity, None, "secure: no gate, no identity");
        assert_eq!(eyes.embeds, 0, "secure: nothing is scored");
        let mut eyes = unlit();
        let (default, _) = look(&mut eyes, &cfg, 0.7, true, false, false, None).unwrap();
        assert_eq!(
            default.identity,
            Some(true),
            "default: the embedding decides"
        );
    }

    /// The user turned to a second screen, the face still in frame: the
    /// embedding of a face turned past every enrolled look scores low
    /// whoever it is. In the default mode a miss there reads as nothing,
    /// so the user's last confirmed check stands and two side views do not
    /// make a stranger of them. The secure mode still counts the miss, and
    /// a frontal miss counts in both.
    #[test]
    fn a_side_view_past_the_enrolled_looks_reads_nothing_in_the_default_mode() {
        let cfg = PresenceConfig {
            user: "alice".into(),
            ..Default::default()
        };
        // Someone else's embedding, so the check misses; the nose moved by
        // 0.6 inter-eye distances is a head turned well to the side.
        let turned = || {
            let mut eyes = StubEyes::new(90.0, vec![0.0, 1.0], vec![1.0, 0.0]);
            let face = eyes.face.as_mut().unwrap();
            let inter_eye = face.landmarks[1][0] - face.landmarks[0][0];
            face.landmarks[2][0] += 0.6 * inter_eye;
            eyes.pose.yaw = 45.0;
            eyes
        };
        let mut eyes = turned();
        let (default, _) = look(&mut eyes, &cfg, 0.7, true, false, false, None).unwrap();
        assert_eq!(default.identity, None, "default: a side view reads nothing");
        assert!(!default.near_miss);
        assert!(!default.attentive, "turned away from this screen");
        // The watch: the user confirmed, then a minute and a half of side
        // views. With no frame the shape cannot hold the clock, so only the
        // standing check does, and it stands.
        {
            use super::super::watch::{State, Watch};
            use crate::presence::{AwayTime, PresenceMode};
            let cfg = PresenceConfig {
                away_seconds: AwayTime::Seconds(20.0),
                ..cfg.clone()
            };
            let mut w = Watch::new(cfg.clone());
            let mut eyes = StubEyes::new(90.0, vec![1.0, 0.0], vec![1.0, 0.0]);
            let (seen, _) = look(&mut eyes, &cfg, 0.7, true, false, false, None).unwrap();
            let t0 = Instant::now();
            w.step(&seen, t0, PresenceMode::Default);
            let side = Observation {
                frame: None,
                ..default.clone()
            };
            for i in 1..=9 {
                let step = w.step(
                    &side,
                    t0 + Duration::from_secs(10 * i),
                    PresenceMode::Default,
                );
                assert!(!step.lock, "default: side views never lock the user out");
            }
            assert_eq!(w.state, State::Present);
        }
        let mut eyes = turned();
        let (secure, _) = look(&mut eyes, &cfg, 0.7, true, true, false, None).unwrap();
        assert_eq!(secure.identity, Some(false), "secure: the miss counts");
        let mut eyes = StubEyes::new(90.0, vec![0.0, 1.0], vec![1.0, 0.0]);
        let (frontal, _) = look(&mut eyes, &cfg, 0.7, true, false, false, None).unwrap();
        assert_eq!(
            frontal.identity,
            Some(false),
            "default: a frontal miss counts"
        );
    }

    /// The enrolled reach on each side is the widest enrolled look on that
    /// side of this camera, and never less than `MIN_REACH`, so a face
    /// turned to the screen is always checked as itself: a set whose looks
    /// all sit to one side (an off-axis camera) still checks a face just
    /// to the other side.
    #[test]
    fn the_enrolled_reach_is_per_side_and_per_camera() {
        let mut t = StubEyes::new(90.0, vec![1.0, 0.0], vec![1.0, 0.0])
            .templates
            .unwrap();
        let base = t.templates[0].clone();
        let at = |yaw: f32, device: &str| crate::store::Template {
            yaw: Some(yaw),
            device: device.into(),
            ..base.clone()
        };
        t.templates = vec![at(-0.45, "cam"), at(0.10, "cam"), at(0.90, "other")];
        assert!(
            !past_enrolled_looks(-0.50, &t, "cam"),
            "within the widest look plus the margin"
        );
        assert!(
            past_enrolled_looks(-0.60, &t, "cam"),
            "past the widest look on this camera"
        );
        assert!(
            !past_enrolled_looks(0.30, &t, "cam"),
            "a narrow side still reaches the floor"
        );
        assert!(
            past_enrolled_looks(0.40, &t, "cam"),
            "the other camera's wide look does not count"
        );
        // Looks all to one side, as an off-axis camera records them.
        t.templates = vec![at(0.02, "cam"), at(0.12, "cam")];
        for yaw in [-0.11, -0.30, 0.20, 0.30] {
            assert!(
                !past_enrolled_looks(yaw, &t, "cam"),
                "{} is within reach",
                yaw
            );
        }
        assert!(past_enrolled_looks(-0.40, &t, "cam"));
        // No recorded angles: the floor on both sides.
        t.templates = vec![base.clone()];
        assert!(!past_enrolled_looks(0.30, &t, "stub-camera"));
        assert!(past_enrolled_looks(0.40, &t, "stub-camera"));
        assert!(past_enrolled_looks(-0.40, &t, "stub-camera"));
    }
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    /// The secure mode does not accept identity from the embedding alone:
    /// a gate that ran and read no signal ends the look unchecked there,
    /// while the default mode lets the embedding decide as before. A gate
    /// that cannot run (no strobe control) ends the secure look unchecked
    /// too: the secure mode is not offered on such a camera, and a secure
    /// look that runs there anyway confirms nobody (E4).
    #[test]
    fn secure_mode_does_not_take_identity_from_the_embedding_alone() {
        assert_eq!(after_gate(true, None, true), AfterGate::Unconfirmed);
        assert_eq!(after_gate(true, None, false), AfterGate::Embed);
        assert_eq!(after_gate(true, Some(true), true), AfterGate::Embed);
        assert_eq!(after_gate(true, Some(false), true), AfterGate::Refused);
        assert_eq!(after_gate(true, Some(false), false), AfterGate::Refused);
        assert_eq!(after_gate(false, None, true), AfterGate::Unconfirmed);
        assert_eq!(after_gate(false, None, false), AfterGate::Embed);
    }
}
