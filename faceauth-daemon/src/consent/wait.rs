//! The nod wait: the loop that follows one face from frame to frame and
//! feeds its head angles to the detectors while the window is up. It keeps
//! the frames the identity check needs after the confirm, and it gives up
//! once the user has left.
//!
//! While the head is still the loop spends less (D3): the mesh is not
//! read for a box that has not moved since the mesh last read it. A
//! skipped frame feeds the detectors nothing; see `FrameBudget::mesh_due`
//! for what the gap does to them, and why it is harmless.

use super::detector::{NodDetector, Oscillation, ShakeDetector};
#[cfg(feature = "dev-tools")]
use super::round::{round_line, ROUND_HEADER};
use super::state::{Answer, ConsentState, Secret};
use super::window::ACK_DWELL;
use crate::capture::IrCapture;
use crate::config::Config;
use anyhow::Result;
use faceauth_engine::{Grey, Pipeline};
#[cfg(feature = "dev-tools")]
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Result of the gesture phase.
#[derive(Clone, Debug, PartialEq)]
pub enum Gesture {
    Nodded,
    /// Two head shakes: a refusal.
    Shaken,
    /// The window supplied a password (verified by the caller).
    Password(Secret),
    /// A touch of the user's security key, already checked by pam_u2f on
    /// the key watch's thread: an approval.
    Key,
    /// A finger pam_fprintd matched on the fingerprint watch's thread: an
    /// approval, a gesture of its own so two-factor can tell it from the
    /// key.
    Fingerprint,
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
        // these and never a neighbor's (the user name may hold hyphens).
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

/// Follow `tracked` through `faces`: the detection whose center moved less
/// than half a face width and whose width is within 30 percent continues
/// it. A second detection that also fits is ambiguous.
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

/// A box within this much of another, in face widths (center and width),
/// is the same head where it was: the mesh has nothing new to read from it.
/// A detector fit that flips moves the box 0.011 face widths and a nod
/// leg carries it 0.04 or more (`Oscillation::CO_MOTION`), so a leg
/// crosses this inside its first frame or two while a flip stays under it.
pub const STILL_FRAC: f32 = 0.015;

/// Whether `b` is where `a` was: the center moved less than `STILL_FRAC`
/// face widths and the width changed less than that fraction.
pub fn box_still(a: [f32; 4], b: [f32; 4]) -> bool {
    let w = a[2].max(b[2]).max(1.0);
    let (acx, acy) = (a[0] + a[2] / 2.0, a[1] + a[3] / 2.0);
    let (bcx, bcy) = (b[0] + b[2] / 2.0, b[1] + b[3] / 2.0);
    let shift = ((acx - bcx).powi(2) + (acy - bcy).powi(2)).sqrt();
    shift / w < STILL_FRAC && (a[2] - b[2]).abs() / w < STILL_FRAC
}

/// Which of a frame's readings the wait takes, decided from the frames
/// before it, with no camera in it so a test can drive it (D3): the mesh
/// is not read for a box that has not moved since the mesh last read it
/// while the detectors are idle. Nothing here grants or decides anything.
///
/// A half-size detection pass belongs here too, once the dynamic-shape
/// YuNet is packaged (the fixed 640x640 model letterboxes a half frame
/// back onto its canvas and saves nothing); seed its "seen" state from
/// `start.is_some()`, since the scan has just matched the face.
pub struct FrameBudget {
    /// The box the mesh last read, and the frame it was read on.
    mesh_read: Option<([f32; 4], usize)>,
}

impl FrameBudget {
    pub fn new() -> Self {
        FrameBudget { mesh_read: None }
    }

    /// Whether the mesh reads `bbox` on frame `tick`. It does unless the
    /// detectors are idle and the box is where the mesh last read it; a
    /// read is recorded, a skip is not.
    ///
    /// A skip feeds the detectors no sample, so the sample that comes
    /// after a run of skips lands beside the last one read, with a time
    /// gap between them. The detectors are written for gaps: the median
    /// picks up from the pitch last read, the pivot and departure point
    /// re-anchor to it once the gap passes 0.5 s (`Oscillation::push_with`),
    /// and the baseline's time step is clamped. The last angle read is
    /// therefore the reference the next leg is measured from, which is
    /// what a still head gives anyway, and no angle is counted as a frame
    /// of its own. A replay of the recorded v2 rounds through the
    /// detectors with this skip changed no nod or shake count
    /// (fa-build/wave4/d3sim, 2026-09-28; not a test in this tree).
    pub fn mesh_due(&mut self, bbox: [f32; 4], idle: bool, tick: usize) -> bool {
        let due = !idle || !self.mesh_read.is_some_and(|(b, _)| box_still(bbox, b));
        if due {
            self.mesh_read = Some((bbox, tick));
        }
        due
    }

    /// The frame the mesh last read, if any.
    #[cfg(test)]
    pub fn mesh_read_on(&self) -> Option<usize> {
        self.mesh_read.map(|(_, t)| t)
    }
}

impl Default for FrameBudget {
    fn default() -> Self {
        Self::new()
    }
}

/// How often the nod window asks whether the session locked under the card.
pub const LOCK_EVERY: Duration = Duration::from_secs(2);

/// The nod window's question to the compositor: has the session locked
/// under the card? Owned, so the watch's own thread can ask it.
pub type LockQuestion = Arc<dyn Fn() -> bool + Send + Sync>;

/// Asks the `LockQuestion` every `LOCK_EVERY` on a thread of its own, so the
/// frame loop never waits on it. One look starts processes and took 0.7 to
/// 1.7 s at rest, longer under load, and while the loop waited the camera's
/// frames went unread and the nods in them were missed (2026-10-19 and
/// 10-20). A locked answer stays until the window ends. A lock that lands
/// while a look is under way is still caught before anything is granted:
/// the nod's commit takes a fresh look of its own (`KEY.nod_may_commit`).
struct LockWatch {
    shared: Arc<LockShared>,
}

/// At most this many lock watches have a thread at once: the window's own,
/// and one whose window ended while it was still finishing a look. Past it
/// the loop asks the question itself, as it did before the watch. The
/// unit's TasksMax counts exactly these (packaging/faceauth.service).
pub const LOCK_WATCHES_MAX: usize = 2;

/// Lock watch threads alive now.
static LOCK_WATCHES: AtomicUsize = AtomicUsize::new(0);

/// Held by a watch's thread for its whole life. It gives back the thread's
/// place in the count, and if the thread dies of a panic it marks the
/// session locked: a watch that cannot look parks the card, never vouches
/// for it.
struct WatchAlive<'a> {
    shared: &'a LockShared,
    live: &'static AtomicUsize,
}

impl Drop for WatchAlive<'_> {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.shared.flags().1 = true;
        }
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Default)]
struct LockShared {
    /// Whether the window ended, and whether a look found the lock.
    flags: Mutex<(bool, bool)>,
    wake: Condvar,
}

impl LockWatch {
    /// Start the watch, or hand the question back when no thread can be
    /// started, so the loop asks it itself as before.
    fn start(question: LockQuestion, every: Duration) -> Result<LockWatch, LockQuestion> {
        Self::start_counted(question, every, &LOCK_WATCHES)
    }

    /// `start`, counting the watch's thread in `live` (a test counts its
    /// own) and starting none past `LOCK_WATCHES_MAX`.
    fn start_counted(
        question: LockQuestion,
        every: Duration,
        live: &'static AtomicUsize,
    ) -> Result<LockWatch, LockQuestion> {
        if live
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < LOCK_WATCHES_MAX).then_some(n + 1)
            })
            .is_err()
        {
            log::info!(
                "consent: {} lock watches are still finishing; the nod loop asks itself",
                LOCK_WATCHES_MAX
            );
            return Err(question);
        }
        let shared = Arc::new(LockShared::default());
        let theirs = Arc::clone(&shared);
        let asked = Arc::clone(&question);
        match std::thread::Builder::new()
            .name("consent-lock".into())
            .spawn(move || {
                let _alive = WatchAlive {
                    shared: &theirs,
                    live,
                };
                theirs.run(asked.as_ref(), every)
            }) {
            Ok(_) => Ok(LockWatch { shared }),
            Err(e) => {
                live.fetch_sub(1, Ordering::SeqCst);
                log::warn!(
                    "consent: the lock watch did not start ({}); the nod loop asks itself",
                    e
                );
                Err(question)
            }
        }
    }

    /// Whether a look has found the session locked.
    fn locked(&self) -> bool {
        self.shared.flags().1
    }
}

impl Drop for LockWatch {
    /// The window ended: the thread finishes a look already under way,
    /// sees the stop and returns. Nothing waits for it.
    fn drop(&mut self) {
        self.shared.flags().0 = true;
        self.shared.wake.notify_all();
    }
}

impl LockShared {
    fn flags(&self) -> MutexGuard<'_, (bool, bool)> {
        self.flags.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// One interval, then a look, until the window ends or a look finds
    /// the lock. Looks start `every` apart, from the start of the one
    /// before, as the loop's own did; one that took longer is followed at
    /// once. The flags are never held across a look.
    fn run(&self, question: &(dyn Fn() -> bool + Send + Sync), every: Duration) {
        let mut next = Instant::now() + every;
        let mut flags = self.flags();
        loop {
            let wait = next.saturating_duration_since(Instant::now());
            flags = self
                .wake
                .wait_timeout_while(flags, wait, |f| !f.0)
                .unwrap_or_else(|p| p.into_inner())
                .0;
            if flags.0 {
                return;
            }
            drop(flags);
            next = Instant::now() + every;
            let locked = question();
            flags = self.flags();
            if flags.0 {
                return;
            }
            if locked {
                flags.1 = true;
                return;
            }
        }
    }
}

/// The nod detector for a window. A card naming a passwordless rider
/// (`rider`) keeps the still second before a first leg that other cards do
/// without (Mike, 2026-10-19): the rider can reach the card with no scan
/// before the nods, so a nod the user was already making at the card as it
/// was before must not approve it (SECURITY.md).
pub(crate) fn nod_detector(floor_deg: f32, rider: bool) -> NodDetector {
    let mut det = NodDetector::mesh(floor_deg);
    if rider {
        det.inner.still_s = Oscillation::STILL_S;
    }
    det
}

/// `nod_frames` receives the frame and face at the end of each counted
/// nod leg, and at each counted nod, newest last, capped at
/// `NOD_FRAMES_KEPT`. The caller embeds them after the confirm and
/// requires each to match the templates: the nods must have come from
/// the enrolled face, not merely from the box the confirm later finds
/// live (D4). Nothing about identity is read here; the detectors and
/// their floors are untouched. `seen` is the request's own away clock:
/// every frame that finds the followed box refreshes it, and past
/// `lost_after` without one the user has left (E2). A card that names a
/// passwordless rider as the window starts (`ConsentState::rider_on_card`)
/// has no frame read for `ACK_DWELL`, and a first nod leg must follow a
/// still second (`nod_detector`).
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
    nod_frames: &mut Vec<(Grey, faceauth_engine::Face)>,
    presence: Option<&dyn Fn(bool)>,
    session_locked: Option<LockQuestion>,
    seen: &std::cell::Cell<Instant>,
    refresh: Option<&dyn Fn()>,
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
    // A card naming a passwordless rider keeps the dwell and the still
    // second, however the rider reached it: re-shown after the nods began,
    // or on the first nod show when it was armed just after the match.
    let rider = state.is_some_and(|(s, u)| s.rider_on_card(u));
    let mut det = nod_detector(floors_deg.0, rider);
    let mut shake = ShakeDetector::mesh(floors_deg.1);
    // A nod counts from the first frame read: there is no dwell, and the
    // nod detector asks for no still second (Mike, 2026-10-19), except on
    // a card naming a rider, which keeps both. A shake still follows
    // a still second seen inside this window: none is credited from the
    // scan (D4).
    let dwell_until = rider.then(|| t0 + ACK_DWELL);
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
    // The compositor is asked whether the session locked under the card
    // every couple of seconds (the probe spawns a process, so not per
    // frame), on the watch's own thread so no frame waits for it: a card
    // the lock screen covers is a card nobody nods at. With no thread to
    // be had, the loop asks it itself, as it did before the watch.
    let mut ask_here: Option<LockQuestion> = None;
    let watch = match session_locked.map(|q| LockWatch::start(q, LOCK_EVERY)) {
        Some(Ok(w)) => Some(w),
        Some(Err(q)) => {
            ask_here = Some(q);
            None
        }
        None => None,
    };
    let mut last_lock_check = Instant::now();
    let summary = |det: &NodDetector, shake: &ShakeDetector, t: f32| {
        format!(
            "{} nods, {} shakes in {:.1}s, thresholds {:.3}/{:.3}",
            det.nods, shake.shakes, t, det.inner.thr, shake.inner.thr
        )
    };
    // One frame, read into again and again (C7).
    let mut img = Grey::default();
    // Which readings each frame gets (D3).
    let mut budget = FrameBudget::new();
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
                Some(Answer::Key) => {
                    log::info!(
                        "consent: security key answer after {}",
                        summary(&det, &shake, t0.elapsed().as_secs_f32())
                    );
                    label.set("key");
                    return Ok((Gesture::Key, tracked));
                }
                Some(Answer::Fingerprint) => {
                    log::info!(
                        "consent: fingerprint answer after {}",
                        summary(&det, &shake, t0.elapsed().as_secs_f32())
                    );
                    label.set("fingerprint");
                    return Ok((Gesture::Fingerprint, tracked));
                }
                // The nods are armed already: the button changes nothing.
                Some(Answer::Rearm) | None => {}
            }
            // The key's PIN was spent on a check that ended, so the card
            // asks for it once more, or the fingerprint's status changed:
            // the card is sent again.
            if state.take_key_card_stale(user) {
                if let Some(r) = refresh {
                    r();
                }
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
        let locked = match (&watch, &ask_here) {
            (Some(w), _) => w.locked(),
            (None, Some(q)) if last_lock_check.elapsed() > LOCK_EVERY => {
                last_lock_check = Instant::now();
                q()
            }
            _ => false,
        };
        if locked {
            log::info!(
                "consent: the session locked under the card after {}; parked",
                summary(&det, &shake, t0.elapsed().as_secs_f32())
            );
            label.set("session-locked");
            return Ok((Gesture::SessionLocked, tracked));
        }
        if !cap.next_into(&mut img, Duration::from_secs(1))? {
            continue;
        }
        // A rider card's frames are drained, not read, until its dwell
        // has passed.
        if dwell_until.is_some_and(|until| Instant::now() < until) {
            continue;
        }
        // Slow polling while the head is still: every other frame is looked
        // at (a leg leaves the rest for six or more frames, so its start
        // cannot slip between two), the rest are only drained. Once a
        // movement begins every frame is looked at.
        frame_no += 1;
        let t = t0.elapsed().as_secs_f32();
        let idle = det.idle(t) && shake.inner.idle(t);
        // Plain modulo kept on purpose; `is_multiple_of` reads worse here.
        #[allow(clippy::manual_is_multiple_of)]
        if idle && frame_no % 2 != 0 {
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
                        // grayed while the matched face is out of view.
                        if face_mark.set(false) {
                            if let Some(p) = presence {
                                p(false);
                            }
                        }
                    }
                    det = nod_detector(floors_deg.0, rider);
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
        // A box the mesh has already read, while the detectors are idle,
        // is not read again: a still head has no new angle to give, and
        // the frame feeds the detectors nothing. The every-other-frame
        // rule above already relies on a leg's start not slipping past a
        // skipped frame; what the gap does inside the detectors is at
        // `FrameBudget::mesh_due` (D3).
        if !budget.mesh_due(face.bbox, idle, frame_no) {
            continue;
        }
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
                    // Arming closes with the nods, in the same look that
                    // catches a rider armed since this frame's check: that
                    // one goes back to the card, guarded, before any confirm.
                    if state.is_some_and(|(s, u)| s.close_rider_arming(u)) {
                        log::info!(
                            "consent: passwordless sudo armed as the nods finished, {}; the card is re-shown and the nods start over",
                            summary(&det, &shake, t)
                        );
                        label.set("rider-armed");
                        return Ok((Gesture::RiderArmed, tracked));
                    }
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

#[cfg(test)]
mod budget_tests {
    use super::{box_still, FrameBudget, STILL_FRAC};

    const BOX: [f32; 4] = [200.0, 300.0, 90.0, 108.0];

    /// (a) The mesh is skipped for a box within the movement threshold
    /// and run again once the box moves, and always while a gesture may
    /// be under way.
    #[test]
    fn the_mesh_is_skipped_for_a_still_box_and_run_when_it_moves() {
        let mut b = FrameBudget::new();
        assert!(b.mesh_due(BOX, true, 1), "the first sight is read");
        let flicker = [200.6, 300.4, 90.5, 108.6];
        assert!(box_still(BOX, flicker));
        assert!(
            !b.mesh_due(flicker, true, 2),
            "a fit flicker under {} face widths is not a new angle",
            STILL_FRAC
        );
        // A nod leg carries the box 9 to 16 px on a 90 px face.
        let leg = [200.0, 303.0, 90.0, 108.0];
        assert!(!box_still(BOX, leg));
        assert!(b.mesh_due(leg, true, 3), "three px down is read");
        assert!(
            b.mesh_due(leg, false, 4),
            "while the detectors are not idle every frame is read, moved or not"
        );
    }

    /// (c) A frame whose mesh was skipped records nothing: the last read
    /// stays on its own tick, so the loop feeds the detectors no sample
    /// for the skipped frame (the detectors' own reference stays the last
    /// angle read, as `mesh_due` documents).
    #[test]
    fn a_skipped_mesh_leaves_no_reading_to_reuse_past_its_tick() {
        let mut b = FrameBudget::new();
        assert_eq!(b.mesh_read_on(), None);
        assert!(b.mesh_due(BOX, true, 7));
        assert_eq!(b.mesh_read_on(), Some(7));
        assert!(!b.mesh_due(BOX, true, 8));
        assert_eq!(
            b.mesh_read_on(),
            Some(7),
            "tick 8 read nothing and recorded nothing"
        );
        assert!(!b.mesh_due(BOX, true, 9));
        assert_eq!(b.mesh_read_on(), Some(7));
        assert!(b.mesh_due([210.0, 300.0, 90.0, 108.0], true, 10));
        assert_eq!(b.mesh_read_on(), Some(10));
    }
}

#[cfg(test)]
mod lock_watch_tests {
    use super::{LockQuestion, LockWatch, LOCK_WATCHES_MAX};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    /// Wait up to two seconds for `cond`.
    fn soon(cond: impl Fn() -> bool) -> bool {
        let until = Instant::now() + Duration::from_secs(2);
        while !cond() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
        cond()
    }

    /// The bug of 2026-10-19 and 10-20: the frame loop waited on each look,
    /// 0.7 to 1.7 s at rest and longer under load, and missed the nods in
    /// the frames it did not read. With the watch, asking costs nothing
    /// while a slow look runs.
    #[test]
    fn a_slow_look_never_holds_up_the_frame_loop() {
        static LIVE: AtomicUsize = AtomicUsize::new(0);
        let looks = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&looks);
        let question: LockQuestion = Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(300));
            false
        });
        let watch = LockWatch::start_counted(question, Duration::from_millis(10), &LIVE)
            .ok()
            .unwrap();
        let until = Instant::now() + Duration::from_millis(700);
        let mut slowest = Duration::ZERO;
        while Instant::now() < until {
            let asked = Instant::now();
            assert!(!watch.locked(), "an unlocked session reads unlocked");
            slowest = slowest.max(asked.elapsed());
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(looks.load(Ordering::SeqCst) >= 1, "the watch looked");
        assert!(
            slowest < Duration::from_millis(150),
            "asking waited {:?} on a 300 ms look",
            slowest
        );
    }

    #[test]
    fn a_locked_look_is_seen_and_stays() {
        static LIVE: AtomicUsize = AtomicUsize::new(0);
        let question: LockQuestion = Arc::new(|| true);
        let watch = LockWatch::start_counted(question, Duration::from_millis(10), &LIVE)
            .ok()
            .unwrap();
        assert!(soon(|| watch.locked()), "the locked look reached the loop");
        std::thread::sleep(Duration::from_millis(50));
        assert!(watch.locked(), "and stays until the window ends");
    }

    /// The first look waits out one interval, as the loop's own ask did,
    /// and the watch stops looking once the window ends.
    #[test]
    fn the_watch_waits_one_interval_and_stops_with_the_window() {
        static LIVE: AtomicUsize = AtomicUsize::new(0);
        let looks = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&looks);
        let question: LockQuestion = Arc::new(move || {
            counted.fetch_add(1, Ordering::SeqCst);
            false
        });
        let watch = LockWatch::start_counted(question, Duration::from_millis(200), &LIVE)
            .ok()
            .unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(
            looks.load(Ordering::SeqCst),
            0,
            "no look before the interval"
        );
        std::thread::sleep(Duration::from_millis(500));
        assert!(looks.load(Ordering::SeqCst) >= 1, "a look after it");
        drop(watch);
        let at_end = looks.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(500));
        assert!(
            looks.load(Ordering::SeqCst) <= at_end + 1,
            "no look after the window ends but one already under way"
        );
        assert!(
            soon(|| LIVE.load(Ordering::SeqCst) == 0),
            "its thread ended"
        );
    }

    /// Looks start an interval apart from the start of the one before,
    /// not an interval after it ends: with 400 ms looks every 200 ms the
    /// next starts as the last ends, not 200 ms later.
    #[test]
    fn looks_start_an_interval_apart() {
        static LIVE: AtomicUsize = AtomicUsize::new(0);
        let starts = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&starts);
        let question: LockQuestion = Arc::new(move || {
            seen.lock().unwrap().push(Instant::now());
            std::thread::sleep(Duration::from_millis(400));
            false
        });
        let watch = LockWatch::start_counted(question, Duration::from_millis(200), &LIVE)
            .ok()
            .unwrap();
        assert!(soon(|| starts.lock().unwrap().len() >= 2), "two looks");
        drop(watch);
        let s = starts.lock().unwrap();
        let gap = s[1] - s[0];
        assert!(
            gap < Duration::from_millis(520),
            "the second look started {:?} after the first",
            gap
        );
    }

    /// No more than `LOCK_WATCHES_MAX` watches hold a thread, the count the
    /// unit's TasksMax is sized for; past it the loop asks for itself, and
    /// a place comes back when a thread ends.
    #[test]
    fn no_more_watches_have_a_thread_than_the_unit_counts() {
        static LIVE: AtomicUsize = AtomicUsize::new(0);
        let question: LockQuestion = Arc::new(|| {
            std::thread::sleep(Duration::from_millis(300));
            false
        });
        let every = Duration::from_millis(10);
        let held: Vec<LockWatch> = (0..LOCK_WATCHES_MAX)
            .map(|_| LockWatch::start_counted(Arc::clone(&question), every, &LIVE))
            .map(|w| w.ok().unwrap())
            .collect();
        assert!(
            LockWatch::start_counted(Arc::clone(&question), every, &LIVE).is_err(),
            "one past the most is handed back to the loop"
        );
        drop(held);
        assert!(
            soon(|| LIVE.load(Ordering::SeqCst) == 0),
            "their threads ended"
        );
        assert!(LockWatch::start_counted(question, every, &LIVE).is_ok());
    }

    /// A look that panics kills the watch's thread; the window then reads
    /// the session as locked and parks, rather than nodding on unwatched.
    #[test]
    fn a_watch_that_dies_parks_the_card() {
        static LIVE: AtomicUsize = AtomicUsize::new(0);
        let question: LockQuestion = Arc::new(|| panic!("a look that panics"));
        let watch = LockWatch::start_counted(question, Duration::from_millis(10), &LIVE)
            .ok()
            .unwrap();
        assert!(soon(|| watch.locked()), "a dead watch reads locked");
        assert!(
            soon(|| LIVE.load(Ordering::SeqCst) == 0),
            "and gives its place back"
        );
    }
}

#[cfg(test)]
mod reshown_tests {
    use super::nod_detector;

    /// A nod already under way: 0.3 s near rest, then two motions of 15
    /// degrees a leg, 0.27 s each at 30 fps, the box riding each leg. With
    /// `still_first` a full still second comes first instead.
    fn counts(reshown: bool, still_first: bool) -> bool {
        let mut det = nod_detector(8.0, reshown);
        let mut frames: Vec<f32> = vec![0.0; if still_first { 45 } else { 9 }];
        for _ in 0..2 {
            frames.extend((1..=8).map(|k| k as f32 / 8.0));
            frames.extend((1..=8).map(|k| 1.0 - k as f32 / 8.0));
        }
        frames.extend([0.0; 30]);
        let mut t = 0.0f32;
        for f in frames {
            if det.push_full(15.0 * f, Some(0.0), t, Some((90.0, 250.0, 340.0 + 7.0 * f))) {
                return true;
            }
            t += 1.0 / 30.0;
        }
        false
    }

    /// The first card counts a nod from the match (Mike, 2026-10-19). A card
    /// re-shown naming a passwordless rider keeps the still second: a nod
    /// the user was already making at the card as it was before must not
    /// approve the rider (SECURITY.md, the rider).
    #[test]
    fn a_card_reshown_for_a_rider_keeps_the_still_second() {
        assert!(counts(false, false), "the first card takes a nod at once");
        assert!(
            !counts(true, false),
            "a re-shown card does not take a nod already under way"
        );
        assert!(counts(true, true), "it takes one after a still second");
    }
}
