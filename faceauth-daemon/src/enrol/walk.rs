//! The session proper: the camera loop that judges each frame, moves the
//! dot, stores the templates and records the rounds. Every precondition is
//! checked before the claim is taken.

use super::dot::{
    distance_of, dot_of, hold_target, on_target, path_point, zone_of_point, Centre, Filter, Reach,
    Where, HOLD_ZONES,
};
use super::session::{broadcast, is_active, take_control, Session};
use super::steps::{
    begin_kind, last_step, message_for, round_at, round_count, swing, Step, READ_SLOTS,
    READ_SLOT_SECONDS, ROUND_COUNTDOWN,
};
#[cfg(feature = "dev-tools")]
use super::stream::TickRecord;
use super::stream::{Start, Tick};
use crate::auth::{Authenticator, Outcome};
use crate::capture::IrCapture;
use crate::store::{now_secs, Template, UserTemplates, MAX_TEMPLATES};
use anyhow::{anyhow, Result};
use std::time::{Duration, Instant};

const HOLD_WANTED: usize = 3;
/// How long the path takes when the person keeps up, and how many
/// templates it may take along the way.
const PATH_SECONDS: f32 = 45.0;
const PATH_MAX: usize = 16;
const SAMPLE_SPACING: Duration = Duration::from_millis(500);
const SESSION_LIMIT: Duration = Duration::from_secs(15 * 60);

/// How long a recording runs (dev-tools builds), and how long the range
/// step gives the person to go all the way round.
#[cfg(feature = "dev-tools")]
const RECORD_SECONDS: f32 = 45.0;
/// A recording keeps the frames it saw under the store's `record/<user>/`
/// (root only, for tuning the walk-through; nothing reads them but a
/// developer, and a delete of the user takes them). One frame in five,
/// named by the readings, as 8-bit PGM.
#[cfg(feature = "dev-tools")]
fn save_pgm(dir: &std::path::Path, name: &str, img: &faceauth_engine::Grey) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let _ = std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    let mut out = format!("P5\n{} {}\n255\n", img.width, img.height).into_bytes();
    out.extend_from_slice(&img.data);
    std::fs::write(dir.join(name), out)?;
    Ok(())
}
const RANGE_SECONDS: f32 = 14.0;

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
/// enrolment outcome; the window is summoned at the start and hidden at
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
    // so it closes and the next enrolment is not "already running" (C9).
    if let Some(mut s) = session {
        let message = match &outcome {
            Outcome::Error { message } => message.clone(),
            _ => "The enrolment ended.".to_string(),
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
    let uid = nix::unistd::User::from_name(user)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
        .ok_or_else(|| anyhow!("unknown user {}", user))?;
    if is_active() {
        return Ok(Outcome::Error {
            message: "an enrolment session is already running".into(),
        });
    }
    // The store's one enrolment opener: a set the TPM could not open in
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
                "the face mesh model ({}) is not installed; run `faceauth models fetch`",
                faceauth_engine::mesh::FACE_MESH_FILE
            ),
        });
    }
    let claim = Session::claim(user, uid);
    let payload = serde_json::json!({ "user": user, "start": start.start_at.as_deref().unwrap_or("welcome") }).to_string();
    if let Err(e) = crate::consent::shell_call(
        user,
        &["shell", "summon", "omarchy.faceauth.enrol", &payload],
    ) {
        claim.abandon();
        return Ok(Outcome::Error {
            message: format!("no enrolment window: {}", e),
        });
    }
    let session = session.insert(claim);
    let mut cap = IrCapture::open(&a.cfg)?;
    if let Some(i) = &cap.illuminator {
        i.set(true)?;
    }
    let device = cap.identity.clone();
    let t0 = Instant::now();
    let mut step = Step::from_start(start.start_at.as_deref());
    // The person's centre: learned in the centre step from a still, level
    // look at the screen. Until then the stored level stands in.
    // The centre pose in degrees, learned in the centre step.
    let mut centre = Centre {
        yaw: 0.0,
        level: 0.0,
        x: 0.5,
        y: 0.5,
    };
    let mut centre_samples: Vec<[f32; 4]> = Vec::new();
    let mut still_since: Option<Instant> = None;
    // The person's reach, learned in the range step; the defaults until then.
    let mut reach = Reach::default();
    let mut extents = [0.0f32; 8]; // pose left, right, up, down; place left, right, up, down
    let mut covar = (0.0f32, 0.0f32); // sum of dyaw*dx, sum of dpitch*dy: the axis directions
    let mut range_since: Option<Instant> = None;
    // The path parameter, advanced only while the dot is on the target.
    let mut path_s = 0.0f32;
    let mut last_frame = Instant::now();
    let mut path_taken = 0usize;
    let mut last_taken_pose: Option<(f32, f32)> = None;
    let mut taken = 0usize;
    let mut last_sample = Instant::now() - SAMPLE_SPACING;
    let mut on_since: Option<Instant> = None;
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
    let mut round_lines: Vec<String> = Vec::new();
    let mut round_frames: Vec<crate::consent::RoundFrame> = Vec::new();
    let mut added = 0usize;
    let mut filter = Filter::new();
    let take_template = |u: &mut UserTemplates,
                         a: &mut Authenticator,
                         img: &faceauth_engine::Grey,
                         face: &faceauth_engine::Face,
                         p: &faceauth_engine::pose::Pose,
                         zone: &str|
     -> Result<()> {
        let crop = faceauth_engine::align::align_112(img, &face.landmarks);
        let e = a.pipeline.embedder.embed(&crop)?;
        u.templates.push(Template {
            embedding: e,
            quality: face.score,
            face_width: face.bbox[2],
            created: now_secs(),
            label: format!("{}-{}", start.label, zone),
            device: device.clone(),
            yaw: Some(p.yaw),
            nose_pitch: Some(p.nose_pitch),
        });
        Ok(())
    };
    loop {
        if t0.elapsed() > SESSION_LIMIT {
            return Err(anyhow!("the enrolment session ran out of time"));
        }
        match take_control().as_deref() {
            Some("cancel") => return Err(anyhow!("cancelled from the window")),
            Some("continue") => {
                if step == Step::Welcome {
                    step = Step::Centre;
                } else if step == Step::Bridge {
                    step = Step::Round(0);
                    round_started = None;
                }
            }
            Some("redo") => match step {
                Step::Range => {
                    range_since = None;
                    extents = [0.0; 8];
                    covar = (0.0, 0.0);
                }
                Step::Path => {
                    path_s = 0.0;
                    path_taken = 0;
                }
                Step::Hold(_) => taken = 0,
                Step::Round(_) => round_started = None,
                _ => {}
            },
            _ => {}
        }
        let Some(img) = cap.next(Duration::from_secs(2))? else {
            continue;
        };
        let dt = last_frame.elapsed().as_secs_f32().min(0.25);
        last_frame = Instant::now();
        let short = (img.width.min(img.height)).max(1) as f32;
        let faces = a.pipeline.detector.detect(&img, a.cfg.min_detection)?;
        let face = faces.into_iter().max_by(|p, q| p.score.total_cmp(&q.score));
        let mut tick = Tick::blank(step.name(), "");
        tick.zone = step.zone();
        #[cfg(feature = "dev-tools")]
        {
            tick.record.centre_yaw = centre.yaw;
            tick.record.level = centre.level;
        }
        let Some(face) = face else {
            tick.message = match step {
                Step::Welcome => message_for(step, "far"),
                _ => "No face in view. Sit facing the screen.".into(),
            };
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
            broadcast(&tick);
            continue;
        };
        cap.meter_on(&face);
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
                    log::info!("enrolment for {}: reach learned, turn left {:.0} right {:.0} chin up {:.0} down {:.0} deg, place left {:.3} right {:.3} up {:.3} down {:.3} (axes {:+.0} {:+.0}, covar {:+.1} {:+.1}, place counts x {} y {}); ring at turn {:.0}/{:.0} chin {:.0}/{:.0} deg", user, extents[0], extents[1], extents[2], extents[3], pl, pr, pu, pd, sx, sy, covar.0, covar.1, reach.place_x, reach.place_y, reach.left, reach.right, reach.up, reach.down);
                    step = Step::Path;
                    path_s = 0.0;
                    path_taken = 0;
                    last_taken_pose = None;
                }
            }
            #[cfg(feature = "dev-tools")]
            Step::Record => {
                tick.message = message_for(step, tick.distance);
                tick.on_target = true;
                if cap.frames % 5 == 0 {
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
                        .and_then(|dir| save_pgm(&dir, &name, &img))
                    {
                        log::warn!("recording: cannot save a frame: {}", e);
                    }
                }
                if t0.elapsed().as_secs_f32() > RECORD_SECONDS {
                    cap.stop()?;
                    session.end("done", "Recorded. Nothing was stored.");
                    return Ok(Outcome::Enrolled {
                        added: 0,
                        total: u.templates.len(),
                        consistency_min: 1.0,
                        consistency_mean: 1.0,
                        path: String::new(),
                    });
                }
            }
            Step::Welcome => {
                tick.message = message_for(step, tick.distance);
            }
            Step::Centre => {
                tick.message = message_for(step, tick.distance);
                // Learn the centre from a still second at the right distance:
                // a spread of readings small enough to be one pose.
                if tick.distance == "right" {
                    centre_samples.push([here.yaw, here.pitch, here.x, here.y]);
                    if centre_samples.len() > 60 {
                        centre_samples.remove(0);
                    }
                    let since = *still_since.get_or_insert(Instant::now());
                    let n = centre_samples.len() as f32;
                    let mean = |i: usize| centre_samples.iter().map(|s| s[i]).sum::<f32>() / n;
                    let running = Centre {
                        yaw: mean(0),
                        level: mean(1),
                        x: mean(2),
                        y: mean(3),
                    };
                    let spread = centre_samples
                        .iter()
                        .map(|s| (s[0] - running.yaw).abs().max((s[1] - running.level).abs()))
                        .fold(0.0, f32::max)
                        / 60.0;
                    // The dot is drawn against the running centre so it settles
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
                        && centre_samples.len() >= 40
                        && spread < 0.06
                    {
                        centre = running;
                        log::info!("enrolment for {}: centre learned, yaw {:+.1} pitch {:+.1} deg, place ({:.3}, {:.3})", user, centre.yaw, centre.level, centre.x, centre.y);
                        step = Step::Range;
                        range_since = None;
                        extents = [0.0; 8];
                        covar = (0.0, 0.0);
                    }
                } else {
                    still_since = None;
                    centre_samples.clear();
                }
            }
            Step::Path => {
                let (tx, ty) = path_point(path_s);
                tick.target_x = tx;
                tick.target_y = ty;
                tick.on_target = on_target((dx, dy), (tx, ty)) && tick.distance == "right";
                tick.taken = path_taken;
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
                    if path_taken < PATH_MAX && moved && last_sample.elapsed() >= SAMPLE_SPACING {
                        take_template(&mut u, a, &img, &face, &p, zone_of_point(tx, ty))?;
                        path_taken += 1;
                        added += 1;
                        last_sample = Instant::now();
                        last_taken_pose = Some((here.yaw, here.pitch));
                        tick.taken = path_taken;
                    }
                }
                if path_s >= 1.0 {
                    step = Step::Hold(0);
                    taken = 0;
                    on_since = None;
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
                    let since = *on_since.get_or_insert(Instant::now());
                    if since.elapsed() > Duration::from_millis(400)
                        && last_sample.elapsed() >= SAMPLE_SPACING
                    {
                        take_template(&mut u, a, &img, &face, &p, zone)?;
                        taken += 1;
                        added += 1;
                        last_sample = Instant::now();
                    }
                } else {
                    on_since = None;
                }
                tick.taken = taken;
                if taken >= HOLD_WANTED {
                    step = step.next().unwrap_or(Step::Verify);
                    taken = 0;
                    on_since = None;
                    if step == Step::Verify {
                        let pruned = u.prune_to(MAX_TEMPLATES);
                        if pruned > 0 {
                            log::info!("enrolment for {}: {} near-duplicate template(s) dropped to stay within {}", user, pruned, MAX_TEMPLATES);
                        }
                        a.store.save(&u)?;
                        verify_since = Some(Instant::now());
                    }
                }
            }
            Step::Verify => {
                tick.message = message_for(step, tick.distance);
                tick.on_target = true;
                if last_sample.elapsed() >= SAMPLE_SPACING {
                    let crop = faceauth_engine::align::align_112(&img, &face.landmarks);
                    let e = a.pipeline.embedder.embed(&crop)?;
                    last_sample = Instant::now();
                    if let Some((score, _)) = u.best_match_on(&e, &device) {
                        if score >= a.cfg.accept_threshold {
                            verify_hits += 1;
                        }
                    }
                }
                if verify_hits >= 2 {
                    if last == Step::Verify {
                        cap.stop()?;
                        let (lo, mean, _) = u.self_consistency().unwrap_or((1.0, 1.0, 1.0));
                        // The file the templates rest in: the sealed blob when the
                        // store seals, else the plaintext.
                        let path = if a.store.is_sealed(user) {
                            a.store.sealed_path_for(user)
                        } else {
                            a.store.path_for(user)
                        }
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                        session.end("done", "Recognised. Enrolment complete.");
                        return Ok(Outcome::Enrolled {
                            added,
                            total: u.templates.len(),
                            consistency_min: lo,
                            consistency_mean: mean,
                            path,
                        });
                    }
                    step = Step::Bridge;
                }
                if verify_since
                    .map(|s| s.elapsed() > Duration::from_secs(20))
                    .unwrap_or(false)
                {
                    return Err(anyhow!(
                        "the new templates did not recognise you within 20 s ({} added)",
                        added
                    ));
                }
            }
            Step::Bridge => {
                tick.message = message_for(step, tick.distance);
                tick.on_target = true;
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
                    round_lines.clear();
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
                    if round_lines.len() < 1500 {
                        round_lines
                            .push(crate::consent::round_line(t, &hp, geom, tick.size, m.score));
                    }
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
                                true
                            }
                        };
                        log::info!("round {} of {} for {}: {} {} swung {:.0} deg pitch, {:.0} deg yaw{}", i + 1, round_count(), user, r.kind, n, dpitch, dyaw, match (stored, reads_to) { (true, Some(f)) => format!("; reads on the mesh up to a {:.0} degree floor", f), (false, _) => "; does not read on the mesh even at the minimum floor (sets no floor)".to_string(), _ => String::new() });
                        #[cfg(feature = "dev-tools")]
                        save_round_trace(&a.store, user, r.kind, n, &round_lines);
                        a.store.save(&u)?;
                        round_started = None;
                        match step.next() {
                            Some(s) if step != last => step = s,
                            _ => {
                                cap.stop()?;
                                let (nd, sd) = crate::auth::consent_floors(&u.gesture);
                                log::info!(
                                    "rounds done for {}: floors nod {:.0} deg, shake {:.0} deg",
                                    user,
                                    nd,
                                    sd
                                );
                                let (lo, mean, _) = u.self_consistency().unwrap_or((1.0, 1.0, 1.0));
                                let path = if a.store.is_sealed(user) {
                                    a.store.sealed_path_for(user)
                                } else {
                                    a.store.path_for(user)
                                }
                                .map(|p| p.display().to_string())
                                .unwrap_or_default();
                                session.end("done", "All done. Your nods, shakes and everyday movements are recorded.");
                                return Ok(Outcome::Enrolled {
                                    added,
                                    total: u.templates.len(),
                                    consistency_min: lo,
                                    consistency_mean: mean,
                                    path,
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
