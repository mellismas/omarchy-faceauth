//! The session proper: the camera loop that judges each frame, moves the
//! dot, stores the templates and records the rounds. Every precondition is
//! checked before the claim is taken.

use super::dot::{
    distance_of, dot_of, hold_target, on_target, path_point, zone_of_point, Centre, Filter, Reach,
    Where, HOLD_ZONES,
};
use super::everyday::clear_everyday;
use super::flash::{self, Flash, FLASH_TRIES};
use super::follow::{
    losses_said, new_set_is_the_face, straight_on, verify_hit, Follow, New, Pause, Read,
};
use super::session::{broadcast, is_active, take_control, Session, WINDOW_WAIT};
use super::steps::{
    begin_kind, last_step, look_name, message_for, round_at, round_count, swing, Progress,
    RoundTrace, Step, Taken, READ_SLOTS, READ_SLOT_SECONDS, ROUND_COUNTDOWN,
};
#[cfg(feature = "dev-tools")]
use super::stream::TickRecord;
use super::stream::{Start, Tick};
use crate::auth::{Authenticator, Outcome};
use crate::capture::IrCapture;
use crate::store::{now_secs, Template, UserTemplates, MAX_TEMPLATES};
use anyhow::{anyhow, Result};
use faceauth_engine::{Face, Grey, Pipeline};
use std::time::{Duration, Instant};

const HOLD_WANTED: usize = 3;
/// How long the path takes when the person keeps up, and how many
/// templates it may take along the way.
const PATH_SECONDS: f32 = 45.0;
const PATH_MAX: usize = 16;
const SAMPLE_SPACING: Duration = Duration::from_millis(500);
const SESSION_LIMIT: Duration = Duration::from_secs(15 * 60);
/// How often the window hears from a screen that waits for a click with
/// the camera off (Welcome, the Bridge): often enough that Continue and
/// Cancel answer at once.
const WAITING_TICK: Duration = Duration::from_millis(200);
/// The session's reference face: an embedding of the still face every
/// `SAMPLE_SPACING` while the center step learns the center, the latest
/// `CENTRE_REFS` of them, and at least `CENTRE_REFS_MIN` before the center
/// counts (A6).
const CENTRE_REFS: usize = 5;
const CENTRE_REFS_MIN: usize = 3;

/// How long a recording runs (dev-tools builds).
#[cfg(feature = "dev-tools")]
const RECORD_SECONDS: f32 = 45.0;
/// A recording keeps the frames it saw under the store's
/// `record/<user>/<label>/` (root only, for tuning the walk-through and
/// for measuring the model on recorded looks; nothing reads them but a
/// developer, and a delete of the user takes them). One frame in five,
/// named by the readings, as 8-bit PGM.
#[cfg(feature = "dev-tools")]
fn save_pgm(dir: &std::path::Path, name: &str, img: &faceauth_engine::Grey) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let _ = std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    img.write_pgm(dir.join(name))?;
    Ok(())
}

/// How long the range step gives the person to go all the way round.
const RANGE_SECONDS: f32 = 14.0;

/// A recording's label names its directory under the user's record
/// directory, so it must be a plain name: letters, digits, dash,
/// underscore and dot, not starting with a dot.
#[cfg(feature = "dev-tools")]
fn record_label_ok(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && !label.starts_with('.')
        && label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// The embedding of `face` in `img`.
fn embed_face(p: &mut Pipeline, img: &Grey, face: &Face) -> Result<Vec<f32>> {
    p.embedder
        .embed(&faceauth_engine::align::align_112(img, &face.landmarks))
}

/// The verified looks join the user's set, pruned to its cap in J1's
/// order, just before the one save. Nothing joins before verify has
/// passed, so a pre-session template is never dropped in favor of a look
/// nobody has checked. Returns how many joined.
fn join_verified(u: &mut UserTemplates, taken: Taken, user: &str) -> usize {
    let added = taken.count();
    u.templates.extend(taken.into_templates());
    let pruned = u.prune_to(MAX_TEMPLATES);
    if pruned > 0 {
        log::info!(
            "enrollment for {}: {} template(s) pruned to stay within {}",
            user,
            pruned,
            MAX_TEMPLATES
        );
    }
    added
}

/// What the person is told when the everyday rounds raised a floor past
/// where their own recorded `gestures` stop reading (C3): that gesture is
/// switched off for them, what takes its place, and how to get it back.
/// None when no raise went that far.
fn switched_off(gestures: &[&str]) -> Option<String> {
    let nod = gestures.contains(&"nod");
    let shake = gestures.contains(&"shake");
    let off = match (nod, shake) {
        (true, true) => "your everyday movement reads as a nod and as a shake, so nodding and shaking your head are switched off: approvals will ask for your password, and a request is refused from the card",
        (true, false) => "your everyday movement reads as a nod, so nodding is switched off and approvals will ask for your password",
        (false, true) => "your everyday movement reads as a shake, so shaking your head is switched off and a request is refused from the card",
        (false, false) => return None,
    };
    Some(format!(
        "{}{}. Run Tune Gestures again with calmer everyday movement.",
        off[..1].to_uppercase(),
        &off[1..]
    ))
}

/// The lowest degree a gesture's recorded rounds read to, for the journal.
fn own_reach(reads_to: &[f32]) -> String {
    reads_to
        .iter()
        .copied()
        .reduce(f32::min)
        .map_or("none recorded".into(), |d| format!("{:.0} deg", d))
}

/// The per-frame recording of a round, kept in dev-tools builds under the
/// root-only gestures directory, one directory per user: the round header
/// (`consent::ROUND_HEADER`), then one line per frame with the mesh's
/// angles and the box, for designing the detectors. The consent window's
/// recordings share the format, so either replays through the same test.
#[cfg(feature = "dev-tools")]
fn save_round_trace(
    store: &crate::store::Store,
    user: &str,
    kind: &str,
    n: usize,
    lines: &[String],
) {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let res = (|| -> anyhow::Result<()> {
        let dir = store.gestures_dir_for(user)?;
        std::fs::create_dir_all(&dir)?;
        if let Some(parent) = dir.parent() {
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let name = format!("{}-v3-{}-{}.txt", now_secs(), kind, n);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(&name))?;
        writeln!(f, "{}", crate::consent::ROUND_HEADER)?;
        for l in lines {
            writeln!(f, "{}", l)?;
        }
        Ok(())
    })();
    if let Err(e) = res {
        log::warn!("round recording for {}: {}", user, e);
    }
}

/// Run a session on the authenticator's camera and store. Returns the
/// enrollment outcome; the window is summoned at the start and hidden at
/// the end, whichever way the session ends.
pub fn run(a: &mut Authenticator, user: &str, start: &Start) -> Outcome {
    let mut session = None;
    let outcome = match run_inner(a, user, start, &mut session) {
        Ok(o) => o,
        Err(e) => Outcome::Error {
            message: e.to_string(),
        },
    };
    // A session still claimed here ended without telling the window (an
    // error after the summon): the window is told now, with the reason,
    // so it closes and the next enrollment is not "already running" (C9).
    if let Some(mut s) = session {
        let message = match &outcome {
            Outcome::Error { message } => message.clone(),
            _ => "The enrollment ended.".to_string(),
        };
        s.end("failed", &message);
    }
    outcome
}

/// The session proper. Every precondition is checked before the claim;
/// once `session` holds the claim, the window is up and every return
/// goes through `Session::end`, or `run` ends it with the outcome's
/// message.
fn run_inner(
    a: &mut Authenticator,
    user: &str,
    start: &Start,
    session: &mut Option<Session>,
) -> Result<Outcome> {
    let uid = crate::store::current_uid(user).ok_or_else(|| anyhow!("unknown user {}", user))?;
    if is_active() {
        return Ok(Outcome::Error {
            message: "an enrollment session is already running".into(),
        });
    }
    // Only the setup script's start points, and in a development build its
    // own (H2).
    let Some(mut step) = Step::from_start(start.start_at.as_deref()) else {
        return Ok(Outcome::Error {
            message: format!(
                "unknown start point {:?}",
                start.start_at.as_deref().unwrap_or_default()
            ),
        });
    };
    #[cfg(feature = "dev-tools")]
    if step.records() && !record_label_ok(&start.label) {
        return Ok(Outcome::Error {
            message: format!(
                "a recording's label names its directory: letters, digits, '-', '_' and '.' only, not {:?}",
                start.label
            ),
        });
    }
    // The store's one enrollment opener: a set the TPM could not open in
    // time stays where it is and the session fails instead (F2).
    let existing = a.store.open_for_enrolment(user)?;
    let mut u = existing
        .unwrap_or_else(|| UserTemplates::new(user, uid, faceauth_engine::embed::AURAFACE_FILE));
    if u.model != faceauth_engine::embed::AURAFACE_FILE {
        return Ok(Outcome::Error {
            message: format!(
                "existing templates are for model {}; delete them first",
                u.model
            ),
        });
    }
    // The daemon does not start without the mesh (C3), so this cannot
    // fail today; it stays as a precondition, checked before the window
    // is summoned rather than after (C9).
    if a.pipeline.mesh.is_none() {
        return Ok(Outcome::Error {
            message: format!(
                "the face mesh model ({}) is not installed; install the omarchy-faceauth-models package",
                faceauth_engine::mesh::FACE_MESH_FILE
            ),
        });
    }
    // Every call the enrollment makes into the user's session goes to the
    // desktops they have now, as it begins (fix round 10, Codex 6).
    let pin = match crate::consent::Pin::take(user) {
        Ok(p) => p,
        Err(e) => {
            return Ok(Outcome::Error {
                message: format!("no enrollment window: {}", e),
            })
        }
    };
    let claim = Session::claim(user, uid, Some(pin.clone()));
    let payload = serde_json::json!({ "user": user, "start": start.start_at.as_deref().unwrap_or("welcome") }).to_string();
    if let Err(e) = crate::consent::shell_call_pinned(
        &pin,
        &["shell", "summon", "omarchy.faceauth.enrol", &payload],
    ) {
        claim.abandon();
        return Ok(Outcome::Error {
            message: format!("no enrollment window: {}", e),
        });
    }
    let session = session.insert(claim);
    // Nothing runs until the window watches the stream, whatever the
    // session starts at: with no window on screen nobody sees what the
    // camera is doing, or can click Continue or Cancel, and a session that
    // waited for a click would hold the camera's lock to its time limit.
    // A window that never connects ends the session within the wait (C9).
    session.await_window(WINDOW_WAIT)?;
    // The camera streams, lit, only while a step reads the face: it opens
    // on leaving Welcome, stops at the Bridge and opens again on its
    // Continue from the exposure it had (J6). `device` is its identity,
    // which the templates bind to.
    let mut cap: Option<IrCapture> = None;
    let mut seed: Option<faceauth_camera::calib::Exposure> = None;
    let mut device = String::new();
    let t0 = Instant::now();
    // Whose face the steps read: one face in view, the one the center
    // step learns, followed frame to frame and identified again by its
    // embedding whenever the track is lost (A6).
    let mut follow = Follow::default();
    // The person's center pose in degrees: learned in the center step from
    // a still, level look at the screen, and zero until then.
    let mut centre = Centre {
        yaw: 0.0,
        level: 0.0,
        x: 0.5,
        y: 0.5,
    };
    // What the step at hand has learned or passed so far: the center's
    // still frames and reference, a hold's time on target and flash pass.
    let mut progress = Progress::default();
    let mut centre_ref_at = Instant::now() - SAMPLE_SPACING;
    // The person's reach, learned in the range step; the defaults until then.
    let mut reach = Reach::default();
    let mut extents = [0.0f32; 8]; // pose left, right, up, down; place left, right, up, down
    let mut covar = (0.0f32, 0.0f32); // sum of dyaw*dx, sum of dpitch*dy: the axis directions
    let mut range_since: Option<Instant> = None;
    // The path parameter, advanced only while the dot is on the target.
    let mut path_s = 0.0f32;
    let mut last_frame = Instant::now();
    let mut last_taken_pose: Option<(f32, f32)> = None;
    // The templates the path and the holds take, by step; they stay apart
    // from the set through verify, join it once verify has passed and are
    // stored only when the session ends well (J3, A6).
    let mut taken = Taken::default();
    let mut verified = false;
    // What the person is told about looks verify dropped templates from.
    let mut dropped_said: Option<String> = None;
    let mut last_sample = Instant::now() - SAMPLE_SPACING;
    // How many flash checks in a row have read nothing at the step at
    // hand (A6).
    let mut flash_misses = 0usize;
    let mut verify_hits = 0usize;
    let mut verify_since: Option<Instant> = None;
    let last = last_step(start.start_at.as_deref());
    // A round: when it started counting down, the angle series for the
    // swing measure, the recording, and the round as the detectors see it,
    // replayed when it ends to find where it stops reading (the floors
    // come from that).
    let mut round_started: Option<Instant> = None;
    // The kinds this session has recorded so far (J4).
    let mut kinds_this_session: Vec<&'static str> = Vec::new();
    let mut round_angles: Vec<(f32, f32, f32)> = Vec::new(); // t, yaw, pitch in degrees
    let mut round_trace = RoundTrace::default();
    let mut round_frames: Vec<crate::consent::RoundFrame> = Vec::new();
    // The everyday rounds as the detectors saw them, replayed at the
    // floors once the rounds are done (C3).
    let mut everyday: Vec<(&'static str, Vec<crate::consent::RoundFrame>)> = Vec::new();
    let mut added = 0usize;
    let mut filter = Filter::new();
    let take_template = |a: &mut Authenticator,
                         img: &Grey,
                         face: &Face,
                         p: &faceauth_engine::pose::Pose,
                         zone: &str,
                         device: &str|
     -> Result<Template> {
        let e = embed_face(&mut a.pipeline, img, face)?;
        Ok(Template {
            embedding: e,
            quality: face.score,
            face_width: face.bbox[2],
            created: now_secs(),
            label: format!("{}-{}", start.label, zone),
            device: device.to_string(),
            yaw: Some(p.yaw),
            nose_pitch: Some(p.nose_pitch),
        })
    };
    loop {
        if t0.elapsed() > SESSION_LIMIT {
            return Err(anyhow!("the enrollment session ran out of time"));
        }
        // A window that stopped watching has gone, at a camera step as at
        // a click: nobody sees what the camera is doing or can cancel it,
        // so the session ends at once, the camera off and the lock free,
        // with nothing stored (C9).
        if session.window_gone() {
            if let Some(c) = cap.take() {
                c.stop()?;
            }
            return Err(anyhow!(
                "the enrollment window closed, so nothing was stored"
            ));
        }
        match take_control().as_deref() {
            Some("cancel") => return Err(anyhow!("canceled from the window")),
            Some("continue") => {
                if step == Step::Welcome {
                    step = Step::Centre;
                } else if step == Step::Bridge {
                    step = Step::Round(0);
                    round_started = None;
                }
            }
            // Redo drops everything the step at hand added: its templates,
            // so the count is back where the step began (J3), what it
            // measured, and what it learned or passed on the way (A6).
            Some("redo") => {
                taken.redo(step);
                progress.redo(step);
                match step {
                    Step::Range => {
                        range_since = None;
                        extents = [0.0; 8];
                        covar = (0.0, 0.0);
                    }
                    Step::Path => {
                        path_s = 0.0;
                        last_taken_pose = None;
                    }
                    Step::Round(_) => round_started = None,
                    _ => {}
                }
            }
            _ => {}
        }
        if !step.reads_face() {
            if let Some(c) = cap.take() {
                seed = Some(c.exposure);
                c.stop()?;
                // Whoever is in the chair when the camera opens again is
                // identified before anything counts (A6).
                follow.lose();
            }
            let mut tick = Tick::blank(step.name(), &message_for(step, "far"));
            tick.on_target = step == Step::Bridge;
            broadcast(&tick);
            std::thread::sleep(WAITING_TICK);
            continue;
        }
        let cam = match &mut cap {
            Some(c) => c,
            None => {
                let c = IrCapture::open_at(&a.cfg, seed)?;
                // The looks ahead go through the flash gate (A6). Without
                // the strobe it cannot run, and templates enrolled here
                // could never be used, unless the administrator has
                // accepted ungated authentication. The rounds take no
                // template and a recording stores nothing.
                let looks_ahead = !matches!(step, Step::Round(_)) && !step.records();
                let refused = crate::tier::gate(c.tier(), a.cfg.liveness_required)
                    == crate::tier::Gate::Refuse;
                if refused && looks_ahead {
                    c.stop()?;
                    return Err(anyhow!(crate::tier::NO_GATE));
                }
                if let Some(i) = &c.illuminator {
                    i.set(true)?;
                }
                device = c.identity.clone();
                // A session with no center step (Tune Gestures) knows its
                // person by the templates they hold on this camera.
                if !follow.has_reference() && !step.learns_face() {
                    let held: Vec<Vec<f32>> = u
                        .templates
                        .iter()
                        .filter(|t| t.device == device)
                        .map(|t| t.embedding.clone())
                        .collect();
                    if held.is_empty() {
                        c.stop()?;
                        return Err(anyhow!(
                            "no templates on this camera to recognize you by; enroll first"
                        ));
                    }
                    follow.set_reference(held);
                }
                // The readings from before the camera stopped are not this
                // stream's.
                filter = Filter::new();
                cap.insert(c)
            }
        };
        let Some(img) = cam.next(Duration::from_secs(2))? else {
            continue;
        };
        let dt = last_frame.elapsed().as_secs_f32().min(0.25);
        last_frame = Instant::now();
        let short = (img.width.min(img.height)).max(1) as f32;
        let faces = a.pipeline.detector.detect(&img, a.cfg.min_detection)?;
        let mut tick = Tick::blank(step.name(), "");
        tick.zone = step.zone();
        #[cfg(feature = "dev-tools")]
        {
            tick.record.centre_yaw = centre.yaw;
            tick.record.level = centre.level;
        }
        if let [one] = faces.as_slice() {
            cam.meter_on(one);
        }
        // Only the followed face is read: a frame with two faces in view,
        // or with a face that is not the one the session began with, takes
        // no template, moves no path and times no hold (A6).
        let threshold = a.cfg.accept_threshold;
        let read = follow.read(faces, Instant::now(), step.learns_face(), threshold, |f| {
            embed_face(&mut a.pipeline, &img, f)
        })?;
        let face = match read {
            Ok(Read::Followed(face)) => face,
            Ok(Read::Adopted(face)) => {
                // A face taken on at the center step: what the step learned
                // from any face before goes with it.
                progress.restart_centre();
                face
            }
            Err(pause) => {
                tick.message = pause.message().into();
                match step {
                    Step::Path => {
                        let (tx, ty) = path_point(path_s);
                        tick.target_x = tx;
                        tick.target_y = ty;
                    }
                    Step::Hold(i) => {
                        let (tx, ty) = hold_target(HOLD_ZONES[i]);
                        tick.target_x = tx;
                        tick.target_y = ty;
                    }
                    _ => {}
                }
                // Another face in view, or not the followed one: the center
                // starts its three still seconds over, so its reference is one
                // face's, and a hold its wait. A round records only the
                // followed face's frames, so it goes on past the gap.
                if pause != Pause::NoFace {
                    progress.restart_centre();
                    progress.on_since = None;
                }
                broadcast(&tick);
                continue;
            }
        };
        let raw = faceauth_engine::pose::pose(&face.landmarks);
        let size_raw = face.bbox[2] / short;
        let x_raw = (face.bbox[0] + face.bbox[2] / 2.0) / img.width.max(1) as f32;
        let y_raw = (face.bbox[1] + face.bbox[3] / 2.0) / img.height.max(1) as f32;
        // The head pose, in degrees, from the dense mesh: measured
        // 2026-09-23, a chin-up straight at the camera reads -31 and a
        // chin-down +36 where the five-point figures barely moved. Without
        // a mesh on this frame the frame is not read.
        let Some(m) = a
            .pipeline
            .mesh
            .as_mut()
            .and_then(|mesh| mesh.for_face(&img, &face).ok().flatten())
        else {
            tick.face = true;
            tick.message = "Hold on, reading the face.".into();
            broadcast(&tick);
            continue;
        };
        let hp = faceauth_engine::mesh::head_pose(&m);
        let sm = filter.push([hp.yaw, hp.pitch, size_raw, x_raw, y_raw]);
        let p = raw;
        let here = Where {
            yaw: sm[0],
            pitch: sm[1],
            x: sm[3],
            y: sm[4],
        };
        tick.face = true;
        tick.size = sm[2];
        tick.distance = distance_of(tick.size);
        #[cfg(feature = "dev-tools")]
        {
            tick.record = TickRecord {
                yaw: sm[0],
                pitch: sm[1],
                roll: hp.roll,
                raw_yaw: hp.yaw,
                raw_pitch: hp.pitch,
                nose_pitch: raw.nose_pitch,
                mesh_yaw: Some(hp.yaw),
                mesh_pitch: Some(hp.pitch),
                mesh_roll: Some(hp.roll),
                mesh_score: Some(m.score),
                x: sm[3],
                y: sm[4],
                centre_yaw: centre.yaw,
                level: centre.level,
            };
        }
        let (dx, dy) = dot_of(&here, &centre, &reach);
        tick.dot_x = dx;
        tick.dot_y = dy;
        match step {
            Step::Range => {
                tick.message = message_for(step, tick.distance);
                tick.on_target = true;
                let since = *range_since.get_or_insert(Instant::now());
                let dyaw = here.yaw - centre.yaw;
                let dp = here.pitch - centre.level;
                let (ex, ey) = (here.x - centre.x, here.y - centre.y);
                extents[0] = extents[0].max(-dyaw);
                extents[1] = extents[1].max(dyaw);
                extents[2] = extents[2].max(-dp);
                extents[3] = extents[3].max(dp);
                covar.0 += dyaw * ex;
                covar.1 += dp * ey;
                // The place extents are sorted out once the axis directions
                // are known, so they are kept both ways round meanwhile.
                extents[4] = extents[4].max(-ex);
                extents[5] = extents[5].max(ex);
                extents[6] = extents[6].max(-ey);
                extents[7] = extents[7].max(ey);
                if since.elapsed().as_secs_f32() > RANGE_SECONDS {
                    let (sx, sy) = (
                        if covar.0 < 0.0 { -1.0 } else { 1.0 },
                        if covar.1 < 0.0 { -1.0 } else { 1.0 },
                    );
                    // With the sign applied, "left" is the side a left turn moved the face to.
                    let (pl, pr) = if sx > 0.0 {
                        (extents[4], extents[5])
                    } else {
                        (extents[5], extents[4])
                    };
                    let (pu, pd) = if sy > 0.0 {
                        (extents[6], extents[7])
                    } else {
                        (extents[7], extents[6])
                    };
                    reach = Reach::from_extents(extents[0], extents[1], extents[2], extents[3])
                        .with_place(pl, pr, pu, pd, covar.0, covar.1);
                    log::info!("enrollment for {}: reach learned, turn left {:.0} right {:.0} chin up {:.0} down {:.0} deg, place left {:.3} right {:.3} up {:.3} down {:.3} (axes {:+.0} {:+.0}, covar {:+.1} {:+.1}, place counts x {} y {}); ring at turn {:.0}/{:.0} chin {:.0}/{:.0} deg", user, extents[0], extents[1], extents[2], extents[3], pl, pr, pu, pd, sx, sy, covar.0, covar.1, reach.place_x, reach.place_y, reach.left, reach.right, reach.up, reach.down);
                    step = Step::Path;
                    path_s = 0.0;
                    last_taken_pose = None;
                }
            }
            #[cfg(feature = "dev-tools")]
            Step::Record => {
                tick.message = message_for(step, tick.distance);
                tick.on_target = true;
                if cam.frames % 5 == 0 {
                    let name = format!(
                        "{:06.2}_yaw{:+.3}_pitch{:.3}_dot{:+.2}_{:+.2}_size{:.3}.pgm",
                        t0.elapsed().as_secs_f32(),
                        raw.yaw,
                        raw.nose_pitch,
                        dx,
                        dy,
                        tick.size
                    );
                    if let Err(e) = a
                        .store
                        .record_dir_for(user)
                        .and_then(|dir| save_pgm(&dir.join(&start.label), &name, &img))
                    {
                        log::warn!("recording: cannot save a frame: {}", e);
                    }
                }
                if t0.elapsed().as_secs_f32() > RECORD_SECONDS {
                    if let Some(c) = cap.take() {
                        c.stop()?;
                    }
                    session.end("done", "Recorded. Nothing was stored.");
                    return Ok(Outcome::Enrolled {
                        added: 0,
                        total: u.templates.len(),
                        consistency_min: 1.0,
                        consistency_mean: 1.0,
                        path: String::new(),
                        warning: None,
                    });
                }
            }
            // Answered above, with the camera off.
            Step::Welcome | Step::Bridge => {}
            Step::Centre => {
                tick.message = message_for(step, tick.distance);
                // Learn the center from three still seconds at the right
                // distance: a spread of readings small enough to be one pose.
                if tick.distance == "right" {
                    let pr = &mut progress;
                    pr.centre_samples
                        .push([here.yaw, here.pitch, here.x, here.y]);
                    if pr.centre_samples.len() > 60 {
                        pr.centre_samples.remove(0);
                    }
                    let since = *pr.still_since.get_or_insert(Instant::now());
                    // The session's reference face, from the same still
                    // frames (A6).
                    if centre_ref_at.elapsed() >= SAMPLE_SPACING {
                        pr.centre_refs
                            .push(embed_face(&mut a.pipeline, &img, &face)?);
                        if pr.centre_refs.len() > CENTRE_REFS {
                            pr.centre_refs.remove(0);
                        }
                        centre_ref_at = Instant::now();
                    }
                    let n = pr.centre_samples.len() as f32;
                    let mean = |i: usize| pr.centre_samples.iter().map(|s| s[i]).sum::<f32>() / n;
                    let running = Centre {
                        yaw: mean(0),
                        level: mean(1),
                        x: mean(2),
                        y: mean(3),
                    };
                    let spread = pr
                        .centre_samples
                        .iter()
                        .map(|s| (s[0] - running.yaw).abs().max((s[1] - running.level).abs()))
                        .fold(0.0, f32::max)
                        / 60.0;
                    // The dot is drawn against the running center so it settles
                    // into the circle as the person does.
                    let (cx, cy) = dot_of(&here, &running, &reach);
                    tick.dot_x = cx;
                    tick.dot_y = cy;
                    #[cfg(feature = "dev-tools")]
                    {
                        tick.record.centre_yaw = running.yaw;
                        tick.record.level = running.level;
                    }
                    tick.on_target = true;
                    if since.elapsed() > Duration::from_millis(3000)
                        && pr.centre_samples.len() >= 40
                        && spread < 0.06
                        && pr.centre_refs.len() >= CENTRE_REFS_MIN
                    {
                        // One strobed pair through the flash gate before
                        // the center counts (A6). The gate reads the frames
                        // after this one, so the window hears this first.
                        broadcast(&tick);
                        match flash::check(
                            cam,
                            &mut a.pipeline.detector,
                            a.cfg.min_detection,
                            face.bbox,
                        )? {
                            Flash::Live((b, at)) => {
                                follow.seen_at(b, at);
                                follow.set_reference(std::mem::take(&mut pr.centre_refs));
                                flash_misses = 0;
                                centre = running;
                                log::info!("enrollment for {}: center learned, yaw {:+.1} pitch {:+.1} deg, place ({:.3}, {:.3}); the flash reads a live face", user, centre.yaw, centre.level, centre.x, centre.y);
                                step = Step::Range;
                                range_since = None;
                                extents = [0.0; 8];
                                covar = (0.0, 0.0);
                            }
                            Flash::Refused => return Err(anyhow!(flash::REFUSED)),
                            Flash::Unread(seen) => {
                                flash_misses += 1;
                                if flash_misses >= FLASH_TRIES {
                                    return Err(anyhow!(flash::UNREAD));
                                }
                                match seen {
                                    Some((b, at)) => follow.seen_at(b, at),
                                    None => follow.lose(),
                                }
                            }
                            // Another face came into view: the center's three
                            // still seconds start over, as a crowd frame read
                            // here does, and so does the check.
                            Flash::Crowd(seen) => {
                                match seen {
                                    Some((b, at)) => follow.seen_at(b, at),
                                    None => follow.lose(),
                                }
                                pr.restart_centre();
                            }
                        }
                        continue;
                    }
                } else {
                    progress.restart_centre();
                }
            }
            Step::Path => {
                let (tx, ty) = path_point(path_s);
                tick.target_x = tx;
                tick.target_y = ty;
                tick.on_target = on_target((dx, dy), (tx, ty)) && tick.distance == "right";
                tick.taken = taken.by(step);
                tick.wanted = PATH_MAX;
                tick.message = message_for(step, tick.distance);
                if tick.on_target {
                    // The target moves only while the dot is with it.
                    path_s += dt / PATH_SECONDS;
                    let moved = last_taken_pose
                        .map(|(ly, lp)| {
                            (here.yaw - ly).abs() >= 5.0 || (here.pitch - lp).abs() >= 4.0
                        })
                        .unwrap_or(true);
                    if tick.taken < PATH_MAX && moved && last_sample.elapsed() >= SAMPLE_SPACING {
                        let zone = zone_of_point(tx, ty);
                        let t = take_template(a, &img, &face, &p, zone, &device)?;
                        // Straight on by the look it is for and the mesh's
                        // pitch, never the five points' alone (A6).
                        taken.push(step, t, straight_on(zone, p.yaw, here.pitch, centre.level));
                        last_sample = Instant::now();
                        last_taken_pose = Some((here.yaw, here.pitch));
                        tick.taken = taken.by(step);
                    }
                }
                if path_s >= 1.0 {
                    step = Step::Hold(0);
                    progress.on_since = None;
                    progress.hold_live = false;
                    flash_misses = 0;
                }
            }
            Step::Hold(i) => {
                let zone = HOLD_ZONES[i];
                let (tx, ty) = hold_target(zone);
                tick.target_x = tx;
                tick.target_y = ty;
                tick.on_target = on_target((dx, dy), (tx, ty)) && tick.distance == "right";
                tick.wanted = HOLD_WANTED;
                tick.message = message_for(step, tick.distance);
                if tick.on_target {
                    let since = *progress.on_since.get_or_insert(Instant::now());
                    if since.elapsed() > Duration::from_millis(400) && !progress.hold_live {
                        // One strobed pair through the flash gate at each
                        // hold before it takes anything (A6).
                        tick.taken = taken.by(step);
                        broadcast(&tick);
                        match flash::check(
                            cam,
                            &mut a.pipeline.detector,
                            a.cfg.min_detection,
                            face.bbox,
                        )? {
                            Flash::Live((b, at)) => {
                                follow.seen_at(b, at);
                                progress.hold_live = true;
                                flash_misses = 0;
                            }
                            Flash::Refused => return Err(anyhow!(flash::REFUSED)),
                            Flash::Unread(seen) => {
                                flash_misses += 1;
                                if flash_misses >= FLASH_TRIES {
                                    return Err(anyhow!(flash::UNREAD));
                                }
                                match seen {
                                    Some((b, at)) => follow.seen_at(b, at),
                                    None => follow.lose(),
                                }
                            }
                            // Another face came into view: the hold waits
                            // again, as a crowd frame read here makes it,
                            // and the check starts over at the followed face.
                            Flash::Crowd(seen) => {
                                match seen {
                                    Some((b, at)) => follow.seen_at(b, at),
                                    None => follow.lose(),
                                }
                                progress.on_since = None;
                            }
                        }
                        continue;
                    }
                    if since.elapsed() > Duration::from_millis(400)
                        && last_sample.elapsed() >= SAMPLE_SPACING
                    {
                        let t = take_template(a, &img, &face, &p, zone, &device)?;
                        taken.push(step, t, straight_on(zone, p.yaw, here.pitch, centre.level));
                        last_sample = Instant::now();
                    }
                } else {
                    progress.on_since = None;
                }
                tick.taken = taken.by(step);
                if tick.taken >= HOLD_WANTED {
                    step = step.next().unwrap_or(Step::Verify);
                    progress.on_since = None;
                    progress.hold_live = false;
                    flash_misses = 0;
                    if step == Step::Verify {
                        // The looks stay apart from the set: verify reads
                        // them on their own (A6), and nothing is stored
                        // until the session ends well (J3). Each must be
                        // the face the session began with at its own pose;
                        // one that is not is dropped and its look named,
                        // and past the tripwires (`new_set_is_the_face`)
                        // the session fails with nothing stored.
                        let names: Vec<String> =
                            taken.entries().map(|(s, _, _)| look_name(s)).collect();
                        let new: Vec<New> = taken
                            .entries()
                            .zip(&names)
                            .map(|((_, t, straight), look)| New { t, straight, look })
                            .collect();
                        let dropped = new_set_is_the_face(&new, follow.reference(), threshold)
                            .map_err(|why| {
                                log::warn!("enrollment for {}: verify refused: {}", user, why);
                                anyhow!("The new looks are not all the face that began the enrollment, so nothing was stored.")
                            })?;
                        dropped_said = losses_said(&new, &dropped);
                        if let Some(said) = &dropped_said {
                            log::info!(
                                "enrollment for {}: {} of {} new templates dropped, under the reference at their pose. {}",
                                user,
                                dropped.len(),
                                new.len(),
                                said
                            );
                            taken.drop_at(&dropped);
                        }
                        verify_since = Some(Instant::now());
                    }
                }
            }
            Step::Verify => {
                tick.message = message_for(step, tick.distance);
                tick.on_target = true;
                if last_sample.elapsed() >= SAMPLE_SPACING {
                    let e = embed_face(&mut a.pipeline, &img, &face)?;
                    last_sample = Instant::now();
                    // The new looks must recognize the face, and the face
                    // must be the one the session began with (A6).
                    if verify_hit(&e, &taken.templates(), follow.reference(), threshold) {
                        verify_hits += 1;
                    }
                }
                if verify_hits >= 2 {
                    verified = true;
                    if last == Step::Verify {
                        if let Some(c) = cap.take() {
                            c.stop()?;
                        }
                        added = join_verified(&mut u, std::mem::take(&mut taken), user);
                        let (lo, mean, _) = u.self_consistency().unwrap_or((1.0, 1.0, 1.0));
                        // The session ended well: the set is stored now, once
                        // (J3), and `path` is the file it rests in, the sealed
                        // blob when the store seals, else the plaintext.
                        let path = a.store.save(&u)?.display().to_string();
                        let done = match &dropped_said {
                            Some(said) => format!("Recognized. Enrollment complete. {}", said),
                            None => "Recognized. Enrollment complete.".to_string(),
                        };
                        session.end("done", &done);
                        return Ok(Outcome::Enrolled {
                            added,
                            total: u.templates.len(),
                            consistency_min: lo,
                            consistency_mean: mean,
                            path,
                            warning: dropped_said,
                        });
                    }
                    step = Step::Bridge;
                }
                if verify_since
                    .map(|s| s.elapsed() > Duration::from_secs(20))
                    .unwrap_or(false)
                {
                    return Err(anyhow!(
                        "the new templates did not recognize you within 20 s ({} taken)",
                        taken.count()
                    ));
                }
            }
            Step::Round(i) => {
                let Some((r, n)) = round_at(i) else {
                    return Err(anyhow!("no round {}", i));
                };
                tick.round = Some(r.kind);
                tick.round_no = i + 1;
                tick.round_of = round_count();
                tick.on_target = true;
                let started = *round_started.get_or_insert_with(|| {
                    round_angles.clear();
                    round_trace.clear();
                    round_frames.clear();
                    Instant::now()
                });
                let since = started.elapsed().as_secs_f32();
                if since < ROUND_COUNTDOWN {
                    tick.countdown = true;
                    tick.seconds_left = ROUND_COUNTDOWN - since;
                    tick.message = format!("Get ready: {}", r.prompt);
                } else {
                    let t = since - ROUND_COUNTDOWN;
                    tick.seconds_left = (r.seconds - t).max(0.0);
                    tick.message = r.prompt.to_string();
                    if r.kind == "read" {
                        tick.read_slot = Some(((t / READ_SLOT_SECONDS) as usize) % READ_SLOTS);
                    }
                    let geom = (
                        face.bbox[2],
                        face.bbox[0] + face.bbox[2] / 2.0,
                        face.bbox[1] + face.bbox[3] / 2.0,
                    );
                    round_angles.push((t, hp.yaw, hp.pitch));
                    round_frames.push(crate::consent::RoundFrame {
                        t,
                        yaw: hp.yaw,
                        pitch: hp.pitch,
                        roll: hp.roll,
                        geom,
                    });
                    round_trace
                        .push(|| crate::consent::round_line(t, &hp, geom, tick.size, m.score));
                    if t >= r.seconds {
                        // The round is over: its swings go with the templates
                        // for the record, and its replay through the mesh
                        // detectors says where it stops reading, which is
                        // what the floors derive from (a floor at a fraction
                        // of the swing lost the reference user's own shake).
                        let dpitch = swing(&round_angles, |s| s.2);
                        let dyaw = swing(&round_angles, |s| s.1);
                        let reads_to = match r.stored_as {
                            "nod" => crate::consent::reads_to_deg(&round_frames, true),
                            "shake" => crate::consent::reads_to_deg(&round_frames, false),
                            _ => None,
                        };
                        begin_kind(&mut u.gesture, &mut kinds_this_session, r.stored_as);
                        let stored = match r.stored_as {
                            "nod" => {
                                if dpitch >= crate::consent::NodDetector::MESH_MIN_DEG {
                                    u.gesture.nod_deg.push(dpitch)
                                }
                                if let Some(f) = reads_to {
                                    u.gesture.nod_reads_to_deg.push(f)
                                }
                                reads_to.is_some()
                            }
                            "shake" => {
                                if dyaw >= crate::consent::ShakeDetector::MESH_MIN_DEG {
                                    u.gesture.shake_deg.push(dyaw)
                                }
                                if let Some(f) = reads_to {
                                    u.gesture.shake_reads_to_deg.push(f)
                                }
                                reads_to.is_some()
                            }
                            kind => {
                                u.gesture.everyday_deg.push(crate::store::EverydayDeg {
                                    kind: kind.to_string(),
                                    dyaw,
                                    dpitch,
                                });
                                everyday.push((r.kind, std::mem::take(&mut round_frames)));
                                true
                            }
                        };
                        log::info!("round {} of {} for {}: {} {} swung {:.0} deg pitch, {:.0} deg yaw{}", i + 1, round_count(), user, r.kind, n, dpitch, dyaw, match (stored, reads_to) { (true, Some(f)) => format!("; reads on the mesh up to a {:.0} degree floor", f), (false, _) => "; does not read on the mesh even at the minimum floor (sets no floor)".to_string(), _ => String::new() });
                        #[cfg(feature = "dev-tools")]
                        save_round_trace(&a.store, user, r.kind, n, round_trace.lines());
                        round_started = None;
                        match step.next() {
                            Some(s) if step != last => step = s,
                            _ => {
                                if let Some(c) = cap.take() {
                                    c.stop()?;
                                }
                                // The everyday rounds replayed at the floors
                                // the gesture rounds derived: what the Bridge
                                // told the person is made sure of here (C3).
                                let clear = clear_everyday(&u.gesture, &everyday).map_err(|why| {
                                    log::warn!("rounds done for {}: {}", user, why);
                                    anyhow!("Your everyday movement reads like a nod or a shake at every floor, so it cannot be told from one and nothing was stored. Run it again, keeping your head still while you read and talk.")
                                })?;
                                u.gesture.nod_floor_min_deg = clear.nod;
                                u.gesture.shake_floor_min_deg = clear.shake;
                                let (nd, sd) = crate::auth::consent_floors(&u.gesture);
                                log::info!(
                                    "rounds done for {}: floors nod {:.0} deg, shake {:.0} deg{}",
                                    user,
                                    nd,
                                    sd,
                                    if clear.nod.is_some() || clear.shake.is_some() {
                                        " (raised so no everyday round reads as a gesture)"
                                    } else {
                                        ""
                                    }
                                );
                                // A raise past where the person's own recorded
                                // gestures stop reading switches that gesture
                                // off for them: said plainly, on the window,
                                // in the journal and at the root terminal.
                                let warning = switched_off(&clear.past_own);
                                if let Some(w) = &warning {
                                    log::warn!(
                                        "rounds done for {}: everyday movement reads past the recorded {} (floors nod {:.0} deg against a reach of {}, shake {:.0} deg against {}): {}",
                                        user,
                                        clear.past_own.join(" and "),
                                        nd,
                                        own_reach(&u.gesture.nod_reads_to_deg),
                                        sd,
                                        own_reach(&u.gesture.shake_reads_to_deg),
                                        w
                                    );
                                }
                                let done = match &warning {
                                    None => "All done. Your nods, shakes and everyday movements are recorded.".to_string(),
                                    Some(w) => format!("All done, with one warning. {}", w),
                                };
                                // The looks verify dropped templates from, if
                                // this session took looks, are said too.
                                let (done, warning) =
                                    match (&dropped_said, verified) {
                                        (Some(said), true) => (
                                            format!("{} {}", done, said),
                                            Some(warning.map_or(said.clone(), |w| {
                                                format!("{} {}", w, said)
                                            })),
                                        ),
                                        _ => (done, warning),
                                    };
                                if verified {
                                    added = join_verified(&mut u, std::mem::take(&mut taken), user);
                                }
                                let (lo, mean, _) = u.self_consistency().unwrap_or((1.0, 1.0, 1.0));
                                // The session ended well: the looks and the
                                // rounds are stored now, once (J3).
                                let path = a.store.save(&u)?.display().to_string();
                                session.end("done", &done);
                                return Ok(Outcome::Enrolled {
                                    added,
                                    total: u.templates.len(),
                                    consistency_min: lo,
                                    consistency_mean: mean,
                                    path,
                                    warning,
                                });
                            }
                        }
                    }
                }
            }
        }
        broadcast(&tick);
    }
}

#[cfg(test)]
mod warning_tests {
    use super::switched_off;

    /// C3: a floor raised past the person's own recorded nods or shakes is
    /// said plainly: the gesture is switched off, what takes its place, and
    /// how to get it back. No raise that far, no warning.
    #[test]
    fn a_raise_past_the_recorded_gestures_says_the_gesture_is_off() {
        assert_eq!(switched_off(&[]), None);
        let nod = switched_off(&["nod"]).unwrap();
        assert_eq!(
            nod,
            "Your everyday movement reads as a nod, so nodding is switched off and approvals will ask for your password. Run Tune Gestures again with calmer everyday movement."
        );
        let shake = switched_off(&["shake"]).unwrap();
        assert!(
            shake.contains("shaking your head is switched off") && !shake.contains("password"),
            "{}",
            shake
        );
        let both = switched_off(&["nod", "shake"]).unwrap();
        assert!(
            both.contains("nodding and shaking your head are switched off")
                && both.contains("password"),
            "{}",
            both
        );
    }
}

#[cfg(all(test, feature = "dev-tools"))]
mod record_tests {
    use super::record_label_ok;

    /// A recording's label is a directory name under the user's record
    /// directory: a plain name, never a path out of it.
    #[test]
    fn a_recording_label_is_a_plain_name() {
        for ok in ["a6-plain", "hat_2", "mask.cloth", "enrol"] {
            assert!(record_label_ok(ok), "{}", ok);
        }
        for bad in [
            "",
            ".",
            "..",
            "../x",
            "a/b",
            ".hidden",
            "sp ace",
            &"x".repeat(65),
        ] {
            assert!(!record_label_ok(bad), "{:?}", bad);
        }
    }
}
