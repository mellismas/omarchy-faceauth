//! The nod wait: the loop that follows one face from frame to frame and
//! feeds its head angles to the detectors while the window is up. It keeps
//! the frames the identity check needs after the confirm, and it gives up
//! once the user has left.

use super::detector::{NodDetector, ShakeDetector};
#[cfg(feature = "dev-tools")]
use super::round::{round_line, ROUND_HEADER};
use super::state::{Answer, ConsentState, Secret};
use crate::capture::IrCapture;
use crate::config::Config;
use anyhow::Result;
use faceauth_engine::{Grey, Pipeline};
#[cfg(feature = "dev-tools")]
use std::path::Path;
use std::time::{Duration, Instant};

/// Result of the gesture phase.
#[derive(Clone, Debug, PartialEq)]
pub enum Gesture {
    Nodded,
    /// Two head shakes: a refusal.
    Shaken,
    /// The window supplied a password (verified by the caller).
    Password(Secret),
    Dismissed,
    /// The requester went away; the window comes down with it.
    Gone,
    Timeout,
    /// No face for the presence watch's away time: the user left.
    FaceLost,
    /// The nods came, but the confirm after them could not read the strobe.
    ConfirmUnclear,
    /// The nods came, but the confirm refused: not a live enrolled face.
    ConfirmFailed(String),
    /// The window could not be shown, or never acknowledged the request.
    NoWindow,
    /// The card armed a passwordless rider the card has not been shown
    /// yet: the caller re-shows it and starts the nods over.
    RiderArmed,
    /// The session locked under the card (the idle lock, a key, the lid):
    /// nobody can see the card, so nothing is read until the unlock (D2).
    SessionLocked,
    /// The followed face left its place and one face has been back in
    /// view for a second: the scan says whether it is the user before any
    /// nod counts again (E2).
    Moved,
}

/// Writes a round's per-frame recording when the round ends, if
/// `gesture_trace` is on: `<store_dir>/gestures/<user>/<unix seconds>-<how
/// it ended>.txt`, mode 0600 in a 0700 directory, newest sixty kept. The
/// recording is `ROUND_HEADER` and one line per frame looked at: the head's
/// angles and the box; never an image, and never the journal.
#[cfg_attr(not(feature = "dev-tools"), allow(dead_code))]
struct TraceSaver<'a> {
    cfg: &'a Config,
    user: String,
    trace: std::cell::RefCell<Vec<String>>,
    label: std::cell::Cell<&'static str>,
}

impl Drop for TraceSaver<'_> {
    fn drop(&mut self) {
        // The recordings exist only in a dev-tools build: the package has
        // no key to switch them on.
        #[cfg(feature = "dev-tools")]
        self.save();
    }
}

#[cfg(feature = "dev-tools")]
impl TraceSaver<'_> {
    fn save(&self) {
        if !self.cfg.gesture_trace {
            return;
        }
        let trace = self.trace.borrow();
        if trace.is_empty() {
            return;
        }
        // One directory per user, so a delete of that user takes exactly
        // these and never a neighbour's (the user name may hold hyphens).
        let dir = Path::new(crate::config::STORE_DIR)
            .join("gestures")
            .join(&self.user);
        let res = (|| -> std::io::Result<()> {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            std::fs::create_dir_all(&dir)?;
            std::fs::set_permissions(
                dir.parent().unwrap_or(&dir),
                std::fs::Permissions::from_mode(0o700),
            )?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            let name = format!("{}-{}.txt", crate::store::now_secs(), self.label.get());
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dir.join(&name))?;
            f.write_all(ROUND_HEADER.as_bytes())?;
            f.write_all(b"\n")?;
            f.write_all(trace.join("\n").as_bytes())?;
            f.write_all(b"\n")?;
            let mut files: Vec<_> = std::fs::read_dir(&dir)?
                .flatten()
                .map(|e| e.path())
                .collect();
            files.sort();
            while files.len() > 60 {
                let _ = std::fs::remove_file(files.remove(0));
            }
            log::info!("consent: gesture recording saved as {}", name);
            Ok(())
        })();
        if let Err(e) = res {
            log::warn!("consent: gesture recording not saved: {}", e);
        }
    }
}

/// Which detection in a frame is the face being followed.
#[derive(Debug, PartialEq)]
pub enum Track {
    /// The followed face, by index into the detections.
    Found(usize),
    /// No detection continues the followed box.
    Lost,
    /// Two detections could each be it: the gesture pauses.
    Ambiguous,
}

/// Follow `tracked` through `faces`: the detection whose centre moved less
/// than half a face width and whose width is within 30 percent continues
/// it. A second detection that also fits, or overlaps it, is ambiguous.
/// Other faces in the frame are ignored (the one that matched is the one
/// that answers).
pub fn track(faces: &[faceauth_engine::Face], tracked: [f32; 4]) -> Track {
    let (tw, tcx, tcy) = (
        tracked[2].max(1.0),
        tracked[0] + tracked[2] / 2.0,
        tracked[1] + tracked[3] / 2.0,
    );
    let fits = |b: &[f32; 4]| -> bool {
        let (cx, cy) = (b[0] + b[2] / 2.0, b[1] + b[3] / 2.0);
        let dist = ((cx - tcx).powi(2) + (cy - tcy).powi(2)).sqrt();
        let ratio = b[2] / tw;
        dist < 0.5 * tw && (0.7..=1.43).contains(&ratio)
    };
    let mut candidates: Vec<(usize, f32)> = faces
        .iter()
        .enumerate()
        .filter(|(_, f)| fits(&f.bbox))
        .map(|(i, f)| {
            let (cx, cy) = (f.bbox[0] + f.bbox[2] / 2.0, f.bbox[1] + f.bbox[3] / 2.0);
            (i, ((cx - tcx).powi(2) + (cy - tcy).powi(2)).sqrt())
        })
        .collect();
    candidates.sort_by(|a, b| a.1.total_cmp(&b.1));
    match candidates.len() {
        0 => Track::Lost,
        1 => Track::Found(candidates[0].0),
        _ => Track::Ambiguous,
    }
}

/// The most recent frames kept from a nod's legs for the identity check
/// after the confirm (D4): two per gesture and a few to spare.
pub const NOD_FRAMES_KEPT: usize = 8;

/// `nod_frames` receives the frame and face at the end of each counted
/// nod leg, and at each counted nod, newest last, capped at
/// `NOD_FRAMES_KEPT`. The caller embeds them after the confirm and
/// requires each to match the templates: the nods must have come from
/// the enrolled face, not merely from the box the confirm later finds
/// live (D4). Nothing about identity is read here; the detectors and
/// their floors are untouched. `seen` is the request's own away clock:
/// every frame that finds the followed box refreshes it, and past
/// `lost_after` without one the user has left (E2).
#[allow(clippy::too_many_arguments)]
pub fn wait_for_nods(
    cap: &mut IrCapture,
    pipeline: &mut Pipeline,
    cfg: &Config,
    window: Duration,
    nods_needed: usize,
    state: Option<(&ConsentState, &str)>,
    lost_after: Option<Duration>,
    floors_deg: (f32, f32),
    start: Option<[f32; 4]>,
    dwell: Duration,
    nod_frames: &mut Vec<(Grey, faceauth_engine::Face)>,
    presence: Option<&dyn Fn(bool)>,
    session_locked: Option<&dyn Fn() -> bool>,
    seen: &std::cell::Cell<Instant>,
) -> Result<(Gesture, Option<[f32; 4]>)> {
    let min_detection = cfg.min_detection;
    #[cfg(feature = "dev-tools")]
    let record_only = cfg.gesture_record_only;
    #[cfg(not(feature = "dev-tools"))]
    let record_only = false;
    let user_name = state
        .map(|(_, u)| u.to_string())
        .unwrap_or_else(|| "unknown".into());
    // The rider record follows the followed face: while this window runs
    // and the matched face is in view the card may arm passwordless sudo,
    // and at no other time. Whichever way the window ends, it ends that.
    struct FaceMark<'a>(Option<(&'a ConsentState, &'a str)>);
    impl FaceMark<'_> {
        fn set(&self, present: bool) -> bool {
            self.0
                .is_some_and(|(state, user)| state.set_face_present(user, present))
        }
    }
    impl Drop for FaceMark<'_> {
        fn drop(&mut self) {
            self.set(false);
        }
    }
    let face_mark = FaceMark(state);
    let t0 = Instant::now();
    // The gestures are read from the head's angles on the face mesh, which
    // the daemon does not start without; the box still has to carry each
    // leg (`co_motion`), so a landmark fit cannot nod on its own.
    let mut det = NodDetector::mesh(floors_deg.0);
    let mut shake = ShakeDetector::mesh(floors_deg.1);
    // No still second is credited from the scan: a first leg must follow
    // a head seen still inside this window, after the dwell, so a nod
    // already under way when the nod card appears is not a nod at it (D4).
    // Per-frame recording: the raw material for tuning both detectors.
    // Saved to the root-only gestures directory when the round ends, if
    // enabled; never to the journal (it is per-frame head pose).
    let saver = TraceSaver {
        cfg,
        user: user_name.clone(),
        trace: Default::default(),
        label: std::cell::Cell::new("ended"),
    };
    let label = &saver.label;
    let trace = &saver.trace;
    let mut frame_no = 0usize;
    // The face being followed: the one the scan matched. A detection that
    // does not continue it is not the answerer, however well it scores.
    let mut tracked: Option<[f32; 4]> = start;
    let mut lost_since: Option<Instant> = None;
    let mut paused_logged = false;
    // Until the dwell has passed frames are drained and nothing is read;
    // the still second before a first leg is then observed inside the
    // window, so a nod already under way at a card that just appeared is
    // not one.
    let mut dwelt = dwell.is_zero();
    if !dwelt {
        log::debug!(
            "consent: nods count only after a {:.1}s dwell",
            dwell.as_secs_f32()
        );
    }
    // The compositor is asked whether the session locked under the card
    // every couple of seconds (the probe spawns a process, so not per
    // frame): a card the lock screen covers is a card nobody nods at.
    let mut last_lock_check = Instant::now();
    let summary = |det: &NodDetector, shake: &ShakeDetector, t: f32| {
        format!(
            "{} nods, {} shakes in {:.1}s, thresholds {:.3}/{:.3}",
            det.nods, shake.shakes, t, det.inner.thr, shake.inner.thr
        )
    };
    while t0.elapsed() < window {
        if let Some((state, user)) = state {
            match state.poll(user) {
                Some(Answer::Password(pw)) => {
                    log::info!(
                        "consent: password answer after {}",
                        summary(&det, &shake, t0.elapsed().as_secs_f32())
                    );
                    label.set("password");
                    return Ok((Gesture::Password(pw), tracked));
                }
                Some(Answer::Dismiss) => {
                    log::info!(
                        "consent: dismissed after {}",
                        summary(&det, &shake, t0.elapsed().as_secs_f32())
                    );
                    label.set("dismissed");
                    return Ok((Gesture::Dismissed, tracked));
                }
                Some(Answer::Gone) => {
                    log::info!(
                        "consent: requester gone after {}",
                        summary(&det, &shake, t0.elapsed().as_secs_f32())
                    );
                    label.set("gone");
                    return Ok((Gesture::Gone, tracked));
                }
                // The nods are armed already: the button changes nothing.
                Some(Answer::Rearm) | None => {}
            }
            // A rider armed since the card's last payload changes what a
            // nod grants: the window ends here, before any frame is read,
            // so the caller can re-show the card and start the nods over.
            if state.rider_unshown(user) {
                log::info!(
                    "consent: passwordless sudo armed after {}; the card is re-shown and the nods start over",
                    summary(&det, &shake, t0.elapsed().as_secs_f32())
                );
                label.set("rider-armed");
                return Ok((Gesture::RiderArmed, tracked));
            }
        }
        if let Some(l) = lost_after {
            if seen.get().elapsed() > l {
                log::info!(
                    "consent: no face for {:.0}s after {} nods; the user left",
                    l.as_secs_f32(),
                    det.nods
                );
                label.set("face-lost");
                return Ok((Gesture::FaceLost, tracked));
            }
        }
        if let Some(locked) = session_locked {
            if last_lock_check.elapsed() > Duration::from_secs(2) {
                last_lock_check = Instant::now();
                if locked() {
                    log::info!(
                        "consent: the session locked under the card after {}; parked",
                        summary(&det, &shake, t0.elapsed().as_secs_f32())
                    );
                    label.set("session-locked");
                    return Ok((Gesture::SessionLocked, tracked));
                }
            }
        }
        let Some(img) = cap.next(Duration::from_secs(1))? else {
            continue;
        };
        if !dwelt {
            if t0.elapsed() < dwell {
                continue;
            }
            dwelt = true;
        }
        // Slow polling while the head is still: every other frame is looked
        // at (a leg leaves the rest for six or more frames, so its start
        // cannot slip between two), the rest are only drained. Once a
        // movement begins every frame is looked at.
        frame_no += 1;
        let t = t0.elapsed().as_secs_f32();
        // Plain modulo kept on purpose; `is_multiple_of` reads worse here.
        #[allow(clippy::manual_is_multiple_of)]
        if det.idle(t) && shake.inner.idle(t) && frame_no % 2 != 0 {
            continue;
        }
        let faces = pipeline.detector.detect(&img, min_detection)?;
        if faces.is_empty() {
            continue;
        }
        let face = match tracked {
            None => faces
                .into_iter()
                .max_by(|a, b| a.score.total_cmp(&b.score))
                .unwrap(),
            Some(tb) => match track(&faces, tb) {
                Track::Found(i) => {
                    lost_since = None;
                    if paused_logged && face_mark.set(true) {
                        if let Some(p) = presence {
                            p(true);
                        }
                    }
                    paused_logged = false;
                    faces.into_iter().nth(i).unwrap()
                }
                other => {
                    // The followed face is not there, or cannot be told from
                    // another: nothing counts meanwhile, and a nod begun
                    // before is forgotten. A face that is not the followed
                    // one does not hold the request open: the away clock
                    // runs from the last sight of the followed face, so a
                    // stranger at the desk cannot keep a request pending
                    // past the presence away time (C1, consent lane). A
                    // single face back for a second is not adopted here,
                    // since the tracker cannot say whose it is: the window
                    // ends and the scan decides before the nods resume (E2).
                    if !paused_logged {
                        log::info!(
                            "consent: gesture paused, the matched face is {}",
                            if other == Track::Lost {
                                "not in view"
                            } else {
                                "one of two"
                            }
                        );
                        paused_logged = true;
                        // The card's passwordless button follows the face:
                        // greyed while the matched face is out of view.
                        if face_mark.set(false) {
                            if let Some(p) = presence {
                                p(false);
                            }
                        }
                    }
                    det = NodDetector::mesh(floors_deg.0);
                    shake = ShakeDetector::mesh(floors_deg.1);
                    let since = *lost_since.get_or_insert(Instant::now());
                    if other == Track::Lost
                        && faces.len() == 1
                        && since.elapsed() > Duration::from_secs(1)
                    {
                        log::info!(
                            "consent: one face in view again after {}; the scan decides whether it is the user",
                            summary(&det, &shake, t0.elapsed().as_secs_f32())
                        );
                        label.set("moved");
                        return Ok((Gesture::Moved, tracked));
                    }
                    continue;
                }
            },
        };
        tracked = Some(face.bbox);
        seen.set(Instant::now());
        let geom = (
            face.bbox[2],
            face.bbox[0] + face.bbox[2] / 2.0,
            face.bbox[1] + face.bbox[3] / 2.0,
        );
        // A frame the mesh cannot read is skipped: nothing else feeds the
        // detectors.
        let Some(m) = pipeline
            .mesh
            .as_mut()
            .and_then(|mesh| mesh.for_face(&img, &face).ok().flatten())
        else {
            continue;
        };
        let hp = faceauth_engine::mesh::head_pose(&m);
        // The per-frame line is built only where a recording can be
        // written: a development build with the trace switched on.
        #[cfg(feature = "dev-tools")]
        if cfg.gesture_trace && trace.borrow().len() < 1200 {
            let size = face.bbox[2] / img.width.min(img.height).max(1) as f32;
            trace
                .borrow_mut()
                .push(round_line(t, &hp, geom, size, m.score));
        }
        if shake.push_with(hp.yaw, t, Some(geom)) {
            if record_only {
                log::info!(
                    "consent: head shake recorded (record-only), {}",
                    summary(&det, &shake, t)
                );
            } else {
                log::info!(
                    "consent: head shake, refused after {}",
                    summary(&det, &shake, t)
                );
                label.set("shaken");
                return Ok((Gesture::Shaken, tracked));
            }
        }
        let legs_before = det.inner.legs.len();
        let counted = det.push_full(hp.pitch, Some(hp.yaw), t, Some(geom));
        if counted || det.inner.legs.len() > legs_before {
            nod_frames.push((img.clone(), face.clone()));
            if nod_frames.len() > NOD_FRAMES_KEPT {
                nod_frames.remove(0);
            }
        }
        if counted {
            log::debug!("consent: nod {} at {:.2}s", det.nods, t);
            if det.nods >= nods_needed {
                if record_only {
                    log::info!(
                        "consent: nods recorded (record-only), {}",
                        summary(&det, &shake, t)
                    );
                } else {
                    log::info!("consent: {}", summary(&det, &shake, t));
                    label.set("nodded");
                    return Ok((Gesture::Nodded, tracked));
                }
            }
        }
    }
    log::info!(
        "consent: timed out, {} ({} face frames)",
        summary(&det, &shake, window.as_secs_f32()),
        trace.borrow().len()
    );
    label.set("timeout");
    Ok((Gesture::Timeout, tracked))
}

#[cfg(test)]
mod track_tests {
    use super::{track, Track};
    use faceauth_engine::Face;

    fn face(x: f32, y: f32, w: f32, score: f32) -> Face {
        Face {
            bbox: [x, y, w, w * 1.2],
            score,
            landmarks: [[0.0; 2]; 5],
            embedding: None,
        }
    }

    #[test]
    fn the_matched_box_is_followed_through_a_nod_sized_move() {
        let t = [200.0, 300.0, 90.0, 108.0];
        assert_eq!(
            track(&[face(205.0, 318.0, 92.0, 0.7)], t),
            Track::Found(0),
            "moved 18 px down on a 90 px face: the same head"
        );
        assert_eq!(
            track(&[face(200.0, 300.0, 100.0, 0.7)], t),
            Track::Found(0),
            "came a little closer"
        );
    }

    #[test]
    fn a_face_elsewhere_or_of_another_size_is_not_it() {
        let t = [200.0, 300.0, 90.0, 108.0];
        assert_eq!(
            track(&[face(300.0, 300.0, 90.0, 0.9)], t),
            Track::Lost,
            "a face width away is someone else, however well it scores"
        );
        assert_eq!(
            track(&[face(200.0, 300.0, 50.0, 0.9)], t),
            Track::Lost,
            "half the size is not the same head"
        );
        assert_eq!(track(&[], t), Track::Lost);
    }

    #[test]
    fn the_followed_face_is_chosen_over_a_better_scoring_stranger() {
        let t = [200.0, 300.0, 90.0, 108.0];
        assert_eq!(
            track(
                &[
                    face(400.0, 300.0, 120.0, 0.95),
                    face(203.0, 305.0, 90.0, 0.6)
                ],
                t
            ),
            Track::Found(1)
        );
    }

    #[test]
    fn two_faces_that_both_fit_are_ambiguous() {
        let t = [200.0, 300.0, 90.0, 108.0];
        assert_eq!(
            track(
                &[face(205.0, 300.0, 90.0, 0.7), face(230.0, 310.0, 85.0, 0.7)],
                t
            ),
            Track::Ambiguous
        );
    }
}
