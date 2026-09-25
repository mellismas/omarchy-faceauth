//! One look with the camera: detect, measure the pose, and on an identity
//! tick strobe a lit and unlit pair through the flash gate before the
//! face is embedded. A print that fails the gate is never taken for the
//! user.

use super::config::PresenceConfig;
use crate::auth::Authenticator;
use anyhow::Result;
use faceauth_engine::{pose, Grey};
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
/// A face turned to the screen: yaw within this on the five-point
/// measure (the mesh's degrees convert through `YAW_DEG_PER_UNIT`) and
/// roll within this many degrees. What "attentive" means everywhere a
/// look asks it: the watch, the lock screen's probe and the re-arm gate.
pub const ATTENTIVE_MAX_YAW: f32 = 0.25;
pub const ATTENTIVE_MAX_ROLL_DEG: f32 = 25.0;

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
}

/// What the flash gate's verdict lets the identity check do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AfterGate {
    /// The gate refused: not the user, no embedding needed.
    Refused,
    /// The gate passed, or could not run at all (no strobe control, or the
    /// gate switched off in the config): the embedding decides.
    Embed,
    /// The gate ran and read no signal (a bright room, a face far back).
    /// In the secure mode that confirms nothing: the embedding alone must
    /// not hold the clock there (E4), so the look ends unchecked.
    Unconfirmed,
}

/// `gate_ran` is whether the gate could run at all; `verdict` is its
/// answer (`None` for no signal); `strict` is the secure mode.
pub(crate) fn after_gate(gate_ran: bool, verdict: Option<bool>, strict: bool) -> AfterGate {
    match (gate_ran, verdict) {
        (false, _) => AfterGate::Embed,
        (true, Some(false)) => AfterGate::Refused,
        (true, Some(true)) => AfterGate::Embed,
        (true, None) if strict => AfterGate::Unconfirmed,
        (true, None) => AfterGate::Embed,
    }
}

/// One short look: open the camera, LEDs on, a few frames, detect, maybe
/// identify, close. With `strict` (the secure mode) a face the gate read
/// no signal from comes back unchecked (`identity: None`) rather than
/// judged by the embedding alone; without it the embedding decides.
pub(crate) fn observe_in(
    a: &mut Authenticator,
    cfg: &PresenceConfig,
    identify: bool,
    strict: bool,
    persist: bool,
) -> Result<Observation> {
    look(a, cfg, identify, strict, persist, None).map(|(o, _)| o)
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
    look(a, cfg, false, false, false, Some(user))
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

fn look(
    a: &mut Authenticator,
    cfg: &PresenceConfig,
    identify: bool,
    strict: bool,
    persist: bool,
    score_for: Option<&str>,
) -> Result<(Observation, ProbeReading)> {
    use crate::capture::IrCapture;
    let mut cap = IrCapture::open_at(&a.cfg, a.last_exposure)?;
    if let Some(i) = &cap.illuminator {
        i.set(true)?;
    }
    let lit = cap.illuminator.is_some();
    let unscored = |why: &'static str| ProbeReading {
        score: Err(why),
        lit,
    };
    // Let exposure react for a handful of frames; the last one is what we look at.
    let mut img = None;
    let deadline = Instant::now() + Duration::from_millis(450);
    while Instant::now() < deadline {
        if let Some(g) = cap.next(Duration::from_millis(500))? {
            img = Some(g);
        }
    }
    let Some(mut img) = img else {
        cap.stop()?;
        return Ok((
            Observation {
                face: false,
                attentive: false,
                identity: None,
                near_miss: false,
                frame: None,
                bbox: None,
            },
            unscored("no frame"),
        ));
    };
    let mut faces = a.pipeline.detector.detect(&img, a.cfg.min_detection)?;
    // With someone there at the last look, keep looking for up to
    // `LOOK_SEE_BUDGET` before calling it no face (a hand over the face for
    // a moment is not an empty chair).
    if persist && faces.is_empty() {
        let until = Instant::now() + LOOK_SEE_BUDGET;
        while faces.is_empty() && Instant::now() < until {
            if let Some(g) = cap.next(Duration::from_millis(200))? {
                faces = a.pipeline.detector.detect(&g, a.cfg.min_detection)?;
                img = g;
            }
        }
    }
    // The next look starts from where this one's exposure ended, face or
    // no face: a seed that saturates after the light changes is escaped one
    // step per look this way, where saving it only behind a found face left
    // the watch blind until an authentication refreshed it (E4).
    a.last_exposure = Some(cap.exposure);
    let Some(face) = faces.into_iter().max_by(|x, y| x.score.total_cmp(&y.score)) else {
        cap.stop()?;
        return Ok((
            Observation {
                face: false,
                attentive: false,
                identity: None,
                near_miss: false,
                frame: Some(img),
                bbox: None,
            },
            unscored("no face"),
        ));
    };
    let p = pose::pose(&face.landmarks);
    // Attention from the mesh when the model is installed: its angles hold
    // where the five points' do not (a chin-up seen from below).
    let attentive = match a
        .pipeline
        .mesh
        .as_mut()
        .and_then(|m| m.for_face(&img, &face).ok().flatten())
    {
        Some(m) => faceauth_engine::mesh::is_attentive(
            &faceauth_engine::mesh::head_pose(&m),
            ATTENTIVE_MAX_YAW * crate::consent::NodDetector::YAW_DEG_PER_UNIT,
            ATTENTIVE_MAX_ROLL_DEG,
        ),
        None => pose::is_attentive(&p, ATTENTIVE_MAX_YAW, ATTENTIVE_MAX_ROLL_DEG),
    };
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
    if identify && cap.illuminator.is_some() {
        // Settle the exposure on the face before the flash, as an unlock
        // attempt does (C10). The look's exposure came from the whole frame,
        // and a face near the screen then clips under the strobe: 20 to 23
        // percent of the face blown out, read as no signal, measured live
        // on 2026-09-24 at an ordinary seated distance. Bounded, since
        // auto-exposure can hold where a face clips a few percent.
        cap.meter_on(&face);
        let until = Instant::now() + FACE_SETTLE_MAX;
        let mut steps = 0;
        while Instant::now() < until {
            if cap.next(Duration::from_millis(200))?.is_some() {
                steps += 1;
                if steps >= 3 && cap.metering.clip < 0.05 {
                    break;
                }
            }
        }
        a.last_exposure = Some(cap.exposure);
    }
    let (identity, near_miss) = if identify {
        // Liveness first: one lit/unlit pair under the look's own mask,
        // with exposure frozen for it as the confirm does, since an
        // auto-exposure step inside the pair breaks the phase lock or skews
        // the lit and unlit frames against each other (E4). A refusal is
        // "not the user"; no signal decides nothing in the default mode and
        // ends the look unchecked in the secure mode.
        let gate_ran = cap.illuminator.is_some();
        let verdict = strobe_pair(
            &mut cap,
            &mut a.pipeline.detector,
            a.cfg.min_detection,
            &face,
        )?;
        match after_gate(gate_ran, verdict, strict) {
            AfterGate::Embed => {}
            AfterGate::Refused => {
                cap.stop()?;
                return Ok((
                    Observation {
                        face: true,
                        attentive,
                        identity: Some(false),
                        near_miss: false,
                        frame: Some(img),
                        bbox: Some(face.bbox),
                    },
                    unscored("not asked"),
                ));
            }
            AfterGate::Unconfirmed => {
                log::info!("presence: the gate read no signal; the look confirms nobody");
                cap.stop()?;
                return Ok((
                    Observation {
                        face: true,
                        attentive,
                        identity: None,
                        near_miss: false,
                        frame: Some(img),
                        bbox: Some(face.bbox),
                    },
                    unscored("not asked"),
                ));
            }
        }
        let crop = faceauth_engine::align::align_112(&img, &face.landmarks);
        let e = a.pipeline.embedder.embed(&crop)?;
        // Templates only count on the camera they were enrolled on, and a
        // store that cannot be read is nobody, not everybody: the check fails
        // closed rather than skipping the tick with identity still assumed.
        let score = match a.store.load(&cfg.user) {
            Ok(Some(t)) => {
                STORE_UNREADABLE.store(false, Ordering::Relaxed);
                t.best_match_on(&e, &cap.identity)
                    .map(|(s, _)| s)
                    .unwrap_or(-1.0)
            }
            Ok(None) => -1.0,
            Err(e) => {
                // Not a failed check: there is nothing to check against.
                // The look decides nothing, so the watch does not run a
                // check on every tick (the stranger cadence) and hold the
                // camera against the re-enrolment that fixes it. Warned
                // once per episode.
                if !STORE_UNREADABLE.swap(true, Ordering::Relaxed) {
                    log::warn!(
                        "presence: templates unreadable, identity is not checked until they are: {}",
                        e
                    );
                }
                cap.stop()?;
                return Ok((
                    Observation {
                        face: true,
                        attentive,
                        identity: None,
                        near_miss: false,
                        frame: Some(img),
                        bbox: Some(face.bbox),
                    },
                    unscored("not asked"),
                ));
            }
        };
        if score < a.cfg.accept_threshold {
            // The score itself stays at debug: the journal is readable by
            // wheel on Omarchy, and a scored stream is a tuning oracle.
            log::info!("presence: identity check failed");
            log::debug!(
                "presence: identity score {:.2} (exp {} gain {}, face {:.2})",
                score,
                cap.exposure.exposure,
                cap.exposure.gain,
                face.score
            );
        }
        let passed = score >= a.cfg.accept_threshold;
        (
            Some(passed),
            !passed && score >= a.cfg.accept_threshold - NEAR_MISS_SLACK,
        )
    } else {
        (None, false)
    };
    let device = cap.identity.clone();
    cap.stop()?;
    // After the camera is closed, so the embed does not hold it.
    let reading = match score_for {
        None => unscored("not asked"),
        Some(_) if !near_enough => unscored("face beyond the line"),
        Some(user) => ProbeReading {
            score: probe_score(a, user, &img, &face.landmarks, &device),
            lit,
        },
    };
    log::debug!(
        "presence tick: face {:.2} yaw {:.2} pitch {:.2} roll {:.0} attentive {} identity {:?}",
        face.score,
        p.yaw,
        p.pitch,
        p.roll.to_degrees(),
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
    a: &mut Authenticator,
    user: &str,
    img: &Grey,
    landmarks: &[[f32; 2]; 5],
    device: &str,
) -> std::result::Result<f32, &'static str> {
    let scored = (|| -> Result<std::result::Result<f32, &'static str>> {
        let Some(t) = a.store.load(user)? else {
            return Ok(Err("not enrolled"));
        };
        let crop = faceauth_engine::align::align_112(img, landmarks);
        let e = a.pipeline.embedder.embed(&crop)?;
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
/// does not end it unread (Mike, 2026-09-24: "keeps looking until it sees or
/// for 2 sec"). The look returns at the first verdict, so an ordinary look
/// still strobes for about half a second.
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
/// only through the shape in the chair, never on its own.
pub const NEAR_MISS_SLACK: f32 = 0.25;

#[cfg(test)]
mod watch_tests {
    use super::*;

    /// The secure mode does not accept identity from the embedding alone:
    /// a gate that ran and read no signal ends the look unchecked there,
    /// while the default mode lets the embedding decide as before. A gate
    /// that cannot run (no strobe control, or switched off) is not a
    /// no-signal read, and the embedding decides in both modes (E4).
    #[test]
    fn secure_mode_does_not_take_identity_from_the_embedding_alone() {
        assert_eq!(after_gate(true, None, true), AfterGate::Unconfirmed);
        assert_eq!(after_gate(true, None, false), AfterGate::Embed);
        assert_eq!(after_gate(true, Some(true), true), AfterGate::Embed);
        assert_eq!(after_gate(true, Some(false), true), AfterGate::Refused);
        assert_eq!(after_gate(true, Some(false), false), AfterGate::Refused);
        assert_eq!(after_gate(false, None, true), AfterGate::Embed);
        assert_eq!(after_gate(false, None, false), AfterGate::Embed);
    }
}
