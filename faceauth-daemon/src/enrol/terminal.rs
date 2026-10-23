//! The terminal enrollments, `faceauth enroll --terminal` and `--look`: the
//! looks asked for from a root terminal with no window, under the
//! walk-through's rules (round-4 A6). All the looks run in one request with
//! the camera open throughout, while the terminal prints the prompts. The
//! session first learns whose face it is from a still, straight look once
//! the exposure has settled, whatever looks were asked for. One face in
//! view per frame; that face is followed across every frame and every
//! look, and is identified again by its embedding whenever the track is
//! lost; each look passes a strobed pair through the flash gate before it
//! takes anything; the new templates stay apart from the set until they
//! are checked against the session's reference, and only then join it,
//! pruned, in one save. A terminal that goes away (Ctrl-C) ends the
//! session at once, with nothing stored.

use super::flash::{self, Flash, Seen, FLASH_TRIES};
use super::follow::{
    losses_said, new_set_is_the_face, straight_on, Follow, New, Pause, Read, STRAIGHT_YAW,
};
use crate::auth::{
    pose_bin_accepts_at, Authenticator, Outcome, DOWN_ABOVE_LEVEL, POSES, POSE_HINTS,
    UP_BELOW_LEVEL,
};
use crate::capture::IrCapture;
use crate::store::{now_secs, Template, UserTemplates, MAX_TEMPLATES};
use anyhow::{anyhow, Result};
use faceauth_engine::pose::Pose;
use faceauth_engine::Face;
use std::time::{Duration, Instant};

/// The session's reference: this many embeddings of the face it takes on,
/// this far apart, from frames looking straight at the camera, still, and
/// taken once the exposure has settled, before any look takes a template.
const REFS: usize = 3;
const REF_SPACING: Duration = Duration::from_millis(300);

/// Still, for the reference: the mesh's turn and pitch over its frames
/// within this many degrees of their mean, the walk-through's center step
/// spread (0.06 of 60 degrees).
const STILL_DEG: f32 = 3.6;

/// Level, for the reference: the mesh's pitch within this many degrees of
/// none. The reference user's resting rounds of 2026-09-24 read -11 to +5
/// degrees; a chin-up straight at the camera reads -31 and a chin-down
/// +36 (2026-09-23). The band keeps well clear of both and leaves room for
/// a person or a camera that rests further from none; it is measured on
/// one person and one machine only (the A6 runbook asks for more). The
/// five-point pitch cannot say this: a lid camera looks up at the face,
/// so a chin-up barely moves it.
const LEVEL_BAND_DEG: f32 = 20.0;

/// The exposure has settled when it has not stepped for this long, with
/// the metering on the face: auto-exposure steps about every 0.4 s while
/// it finds the level.
pub(super) const SETTLE: Duration = Duration::from_millis(500);

/// The fewest templates a look keeps; a look that took fewer keeps none.
const LOOK_MIN: usize = 3;

/// How long the session's straight phase may take: the camera opening,
/// the exposure settling and the reference learned from a still, level
/// look, before any posed look starts. Past it without a reference the
/// session ends, saying the camera never saw the face still and straight
/// on. The looks' own time runs from when the reference is learned, which
/// the terminal is told (`Outcome::Learned`), so its prompts wait for it.
pub const STRAIGHT_SECONDS: f32 = 10.0;

/// What the person is told when the terminal that asked went away.
const GONE: &str = "the terminal that asked for the enrollment went away, so nothing was stored";

/// What a look reads of a face: the five-point pose its bins go by, and
/// the mesh's head pose in degrees, which a chin-up moves where the five
/// points barely do.
#[derive(Clone, Copy, Debug)]
pub(super) struct Reading {
    pub pose: Pose,
    pub yaw_deg: f32,
    pub pitch_deg: f32,
}

/// One look the session fills.
struct Look {
    /// The pose it keeps frames in; None for `--look`, which keeps any.
    pose: Option<&'static str>,
    label: String,
    /// The templates, each with whether it was taken straight on.
    taken: Vec<(Template, bool)>,
    /// Whether the flash gate has passed at this look, and how many of its
    /// checks read nothing.
    live: bool,
    unread: usize,
}

impl Look {
    /// The look's name as the person is told it.
    fn name(&self) -> String {
        match self.pose {
            Some(p) => format!("{} look", p),
            None => "look".into(),
        }
    }

    /// The zone its templates are straight on in: the center look, and
    /// `--look`, which asks the person to look at the camera.
    fn zone(&self) -> &'static str {
        self.pose.unwrap_or("centre")
    }
}

/// What the camera loop does after the session has read a frame.
#[derive(Debug, PartialEq)]
pub(super) enum Act {
    Next,
    /// Run the flash check for look `i` at the followed face, last seen at
    /// this box, and hand the verdict to `flashed`.
    Flash(usize, [f32; 4]),
}

/// The looks the session keeps, and what the person is told about any
/// that kept nothing or lost templates to verify.
#[derive(Debug)]
pub(super) struct Kept {
    pub templates: Vec<Template>,
    pub warning: Option<String>,
}

/// One reference frame: its embedding, and its readings.
struct RefFrame {
    embedding: Vec<f32>,
    nose_pitch: f32,
    yaw_deg: f32,
    pitch_deg: f32,
}

/// The session between frames: whose face it is, its reference, the looks.
pub(super) struct Terminal {
    follow: Follow,
    looks: Vec<Look>,
    per_look: usize,
    spacing: Duration,
    threshold: f32,
    /// The person's level from the reference frames: on the five-point
    /// nose pitch for the looks' bins, and on the mesh in degrees for
    /// verify's straight-on check.
    level: f32,
    level_deg: f32,
    device: String,
    refs: Vec<RefFrame>,
    ref_at: Option<Instant>,
    /// When the session started, how long its straight phase may take,
    /// when the reference was learned, and how long the looks may take
    /// from then.
    started: Instant,
    straight_for: Duration,
    learned_at: Option<Instant>,
    looks_for: Duration,
    last_taken: Option<Instant>,
    flash_misses: usize,
    /// For the journal and the hint: frames with more than one face, and
    /// with a face that was not identified; frames in no open look's pose
    /// and the readings they gave.
    crowd: usize,
    not_the_face: usize,
    off_pose: usize,
    pitch: (f32, f32),
    yaw: (f32, f32),
}

impl Terminal {
    /// A session for `poses` in order (none: one look in any pose, under
    /// `label` itself), `per_look` templates each, `spacing` apart,
    /// `started` now: `straight_for` to learn the face, then `looks_for`
    /// for the looks.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        poses: &[&'static str],
        label: &str,
        per_look: usize,
        spacing: Duration,
        threshold: f32,
        device: String,
        started: Instant,
        (straight_for, looks_for): (Duration, Duration),
    ) -> Terminal {
        let looks = if poses.is_empty() {
            vec![Look {
                pose: None,
                label: label.to_string(),
                taken: Vec::new(),
                live: false,
                unread: 0,
            }]
        } else {
            poses
                .iter()
                .map(|p| Look {
                    pose: Some(*p),
                    label: format!("{}-{}", label, p),
                    taken: Vec::new(),
                    live: false,
                    unread: 0,
                })
                .collect()
        };
        Terminal {
            follow: Follow::default(),
            looks,
            per_look,
            spacing,
            threshold,
            level: crate::auth::LEVEL_DEFAULT,
            level_deg: 0.0,
            device,
            refs: Vec::new(),
            ref_at: None,
            started,
            straight_for,
            learned_at: None,
            looks_for,
            last_taken: None,
            flash_misses: 0,
            crowd: 0,
            not_the_face: 0,
            off_pose: 0,
            pitch: (f32::MAX, f32::MIN),
            yaw: (f32::MAX, f32::MIN),
        }
    }

    /// Every look has what it came for.
    pub(super) fn done(&self) -> bool {
        self.looks.iter().all(|l| l.taken.len() >= self.per_look)
    }

    /// Whether the session goes on at `now`: never once the terminal that
    /// asked has gone (Ctrl-C there), which ends it with nothing stored.
    /// Until the reference is learned, for the straight phase's time;
    /// after, until every look has what it came for or the looks' time,
    /// counted from the learning, is up.
    pub(super) fn go_on(
        &self,
        now: Instant,
        terminal_gone: bool,
    ) -> std::result::Result<bool, &'static str> {
        if terminal_gone {
            return Err(GONE);
        }
        Ok(match self.learned_at {
            None => now.saturating_duration_since(self.started) < self.straight_for,
            Some(at) => now.saturating_duration_since(at) < self.looks_for && !self.done(),
        })
    }

    /// Has the session learned whose face it is?
    pub(super) fn learned(&self) -> bool {
        self.learned_at.is_some()
    }

    /// Nothing the session learned from a face before stands: the
    /// reference it builds is one face's, from one still look.
    fn restart_reference(&mut self) {
        self.refs.clear();
        self.ref_at = None;
    }

    /// Read one frame's faces (the detections above the floor) at `now`.
    /// Until the reference is learned a face nobody follows is taken on,
    /// and one taken on, a crowd, a face that is not the followed one or a
    /// face that turns starts the reference over; frames before the
    /// exposure has `settled` add nothing to it, and it is set only from
    /// frames that stayed still. After that only the followed face, or one
    /// identified again at the accept threshold, is read, and its frame
    /// goes to the first look still open whose pose it is in: that look's
    /// flash check first, then a template every `spacing`. A frame the
    /// mesh cannot read (`read` gives None) adds nothing.
    pub(super) fn frame(
        &mut self,
        faces: Vec<Face>,
        now: Instant,
        settled: bool,
        embed: &mut dyn FnMut(&Face) -> Result<Vec<f32>>,
        read: &mut dyn FnMut(&Face) -> Result<Option<Reading>>,
    ) -> Result<std::result::Result<Act, Pause>> {
        let learning = !self.follow.has_reference();
        let face = match self
            .follow
            .read(faces, now, learning, self.threshold, |f| embed(f))?
        {
            Ok(Read::Followed(f)) => f,
            Ok(Read::Adopted(f)) => {
                self.restart_reference();
                f
            }
            Err(pause) => {
                match pause {
                    Pause::NoFace => {}
                    Pause::Crowd => self.crowd += 1,
                    Pause::NotTheFace => self.not_the_face += 1,
                }
                if learning && pause != Pause::NoFace {
                    self.restart_reference();
                }
                return Ok(Err(pause));
            }
        };
        let Some(r) = read(&face)? else {
            return Ok(Ok(Act::Next));
        };
        if learning {
            self.learn(&face, r, now, settled, embed)?;
            return Ok(Ok(Act::Next));
        }
        let (level, per_look) = (self.level, self.per_look);
        let Some(i) = self.looks.iter().position(|l| {
            l.taken.len() < per_look
                && l.pose
                    .is_none_or(|w| pose_bin_accepts_at(w, &r.pose, level))
        }) else {
            self.off_pose += 1;
            let p = r.pose;
            self.pitch = (
                self.pitch.0.min(p.nose_pitch),
                self.pitch.1.max(p.nose_pitch),
            );
            self.yaw = (self.yaw.0.min(p.yaw), self.yaw.1.max(p.yaw));
            return Ok(Ok(Act::Next));
        };
        if !self.looks[i].live {
            return Ok(Ok(Act::Flash(i, face.bbox)));
        }
        if self
            .last_taken
            .is_some_and(|t| now.saturating_duration_since(t) < self.spacing)
        {
            return Ok(Ok(Act::Next));
        }
        let e = embed(&face)?;
        let straight = straight_on(
            self.looks[i].zone(),
            r.pose.yaw,
            r.pitch_deg,
            self.level_deg,
        );
        let look = &mut self.looks[i];
        look.taken.push((
            Template {
                embedding: e,
                quality: face.score,
                face_width: face.bbox[2],
                created: now_secs(),
                label: look.label.clone(),
                device: self.device.clone(),
                yaw: Some(r.pose.yaw),
                nose_pitch: Some(r.pose.nose_pitch),
            },
            straight,
        ));
        self.last_taken = Some(now);
        Ok(Ok(Act::Next))
    }

    /// A frame of the face being learned. The reference is the last `REFS`
    /// frames, `REF_SPACING` apart, looking straight at the camera once the
    /// exposure has settled: the five-point turn within `STRAIGHT_YAW` and
    /// the mesh's pitch within `LEVEL_BAND_DEG` of level. It is set when
    /// they are still; a turned or pitched frame starts it over. The
    /// person's level comes from the same frames.
    fn learn(
        &mut self,
        face: &Face,
        r: Reading,
        now: Instant,
        settled: bool,
        embed: &mut dyn FnMut(&Face) -> Result<Vec<f32>>,
    ) -> Result<()> {
        if !settled {
            return Ok(());
        }
        if r.pose.yaw.abs() > STRAIGHT_YAW || r.pitch_deg.abs() > LEVEL_BAND_DEG {
            self.restart_reference();
            return Ok(());
        }
        if self
            .ref_at
            .is_some_and(|t| now.saturating_duration_since(t) < REF_SPACING)
        {
            return Ok(());
        }
        self.refs.push(RefFrame {
            embedding: embed(face)?,
            nose_pitch: r.pose.nose_pitch,
            yaw_deg: r.yaw_deg,
            pitch_deg: r.pitch_deg,
        });
        self.ref_at = Some(now);
        if self.refs.len() > REFS {
            self.refs.remove(0);
        }
        if self.refs.len() < REFS {
            return Ok(());
        }
        let n = self.refs.len() as f32;
        let mean = |f: fn(&RefFrame) -> f32| self.refs.iter().map(f).sum::<f32>() / n;
        let (yaw, pitch) = (mean(|r| r.yaw_deg), mean(|r| r.pitch_deg));
        let still = self.refs.iter().all(|r| {
            (r.yaw_deg - yaw).abs() <= STILL_DEG && (r.pitch_deg - pitch).abs() <= STILL_DEG
        });
        if still {
            self.level = mean(|r| r.nose_pitch);
            self.level_deg = pitch;
            let refs = std::mem::take(&mut self.refs);
            self.follow
                .set_reference(refs.into_iter().map(|r| r.embedding).collect());
            self.learned_at = Some(now);
        }
        Ok(())
    }

    /// The flash check's verdict for look `i`. The error ends the session
    /// with what the person is told: a refusal at once, and a check that
    /// read nothing `FLASH_TRIES` times in a row. Another face in view ends
    /// the check without counting against the face. The followed face goes
    /// on from where and when the check last saw it.
    pub(super) fn flashed(
        &mut self,
        i: usize,
        verdict: Flash,
    ) -> std::result::Result<(), &'static str> {
        let seen: Option<Seen> = match verdict {
            Flash::Live(seen) => {
                self.looks[i].live = true;
                self.flash_misses = 0;
                Some(seen)
            }
            Flash::Refused => return Err(flash::REFUSED),
            Flash::Unread(seen) => {
                self.flash_misses += 1;
                self.looks[i].unread += 1;
                if self.flash_misses >= FLASH_TRIES {
                    return Err(flash::UNREAD);
                }
                seen
            }
            Flash::Crowd(seen) => seen,
        };
        match seen {
            Some((b, at)) => self.follow.seen_at(b, at),
            None => self.follow.lose(),
        }
        Ok(())
    }

    /// The looks are over. With no reference learned nothing was taken, and
    /// the error says so. A look with fewer than `LOOK_MIN` templates keeps
    /// none and is named in the warning; with none kept at all the error
    /// says why. The rest must be the face the session began with
    /// (`new_set_is_the_face`): a template that is not is dropped and its
    /// look named, and past verify's tripwires the error fails the lot.
    /// Nothing here touches the stored set.
    pub(super) fn finish(self, user: &str) -> std::result::Result<Kept, String> {
        log::info!(
            "terminal enrollment for {}: frames with more than one face {}, with a face not identified {}, in no open look's pose {}",
            user,
            self.crowd,
            self.not_the_face,
            self.off_pose
        );
        let crowd = if self.crowd > 0 {
            " A second face was in view: only one face may be in view."
        } else {
            ""
        };
        if !self.follow.has_reference() {
            return Err(format!(
                "nothing was enrolled: the camera never saw the face still and straight on long enough to learn it.{} Look straight at the camera when it says so.",
                crowd
            ));
        }
        let (kept, missed): (Vec<Look>, Vec<Look>) = self
            .looks
            .into_iter()
            .partition(|l| l.taken.len() >= LOOK_MIN);
        let readings = if self.off_pose > 0 {
            format!(
                " The {} frames in no look's pose read pitch {:.2} to {:.2} and turn {:+.2} to {:+.2}.",
                self.off_pose, self.pitch.0, self.pitch.1, self.yaw.0, self.yaw.1
            )
        } else {
            String::new()
        };
        let why_missed = |l: &Look| {
            match l.pose {
            // The flash never read at this look: that, not the pose, is why
            // it took nothing.
            _ if !l.live && l.unread > 0 => format!(
                "{}: the flash check could not read your face at this look ({} tries), so it took nothing; sit a little closer, out of direct sunlight",
                l.pose.unwrap_or("the look"),
                l.unread
            ),
            None => format!(
                "only {} usable frames; face the camera at normal distance",
                l.taken.len()
            ),
            Some(p) => format!(
                "{}: only {} frames in the pose, and {}; {}",
                p,
                l.taken.len(),
                pose_needs(p, self.level),
                POSE_HINTS[POSES.iter().position(|q| *q == p).unwrap_or(0)]
            ),
        }
        };
        if kept.is_empty() {
            let each: Vec<String> = missed.iter().map(why_missed).collect();
            return Err(format!(
                "nothing was enrolled: {}.{}{}",
                each.join("; "),
                readings,
                crowd
            ));
        }
        let mut warning = (!missed.is_empty()).then(|| {
            let each: Vec<String> = missed.iter().map(why_missed).collect();
            let names: Vec<&str> = missed.iter().filter_map(|l| l.pose).collect();
            format!(
                "No frames were kept for {}: {}.{}{} Run faceauth enroll --terminal --poses {} to add them.",
                names.join(", "),
                each.join("; "),
                readings,
                crowd,
                names.join(",")
            )
        });
        let names: Vec<String> = kept
            .iter()
            .flat_map(|l| std::iter::repeat_n(l.name(), l.taken.len()))
            .collect();
        let taken: Vec<(Template, bool)> = kept.into_iter().flat_map(|l| l.taken).collect();
        let new: Vec<New> = taken
            .iter()
            .zip(&names)
            .map(|((t, straight), look)| New {
                t,
                straight: *straight,
                look,
            })
            .collect();
        let dropped = new_set_is_the_face(&new, self.follow.reference(), self.threshold)
            .map_err(|why| {
                log::warn!("terminal enrollment for {}: verify refused: {}", user, why);
                "The new looks are not all the face that began the enrollment, so nothing was stored."
                    .to_string()
            })?;
        if let Some(said) = losses_said(&new, &dropped) {
            log::info!(
                "terminal enrollment for {}: {} of {} new templates dropped, under the reference at their pose. {}",
                user,
                dropped.len(),
                new.len(),
                said
            );
            warning = Some(warning.map_or(said.clone(), |w| format!("{} {}", w, said)));
        }
        drop(new);
        let templates = taken
            .into_iter()
            .enumerate()
            .filter(|(i, _)| !dropped.contains(i))
            .map(|(_, (t, _))| t)
            .collect();
        Ok(Kept { templates, warning })
    }
}

/// What a pose needs, in the readings the terminal prints.
fn pose_needs(p: &str, level: f32) -> String {
    match p {
        "up" => format!(
            "up needs a pitch reading of {:.2} or less",
            level - UP_BELOW_LEVEL
        ),
        "down" => format!("down needs {:.2} or more", level + DOWN_ABOVE_LEVEL),
        "left" => "left needs a turn reading of -0.18 or less".to_string(),
        "right" => "right needs a turn reading of 0.18 or more".to_string(),
        _ => format!(
            "center needs a turn within 0.12 and a pitch within 0.06 of {:.2}",
            level
        ),
    }
}

/// Enroll from the terminal: `poses` in order, `count` templates each over
/// `seconds` a look, or with no pose one look of `count` over `seconds`.
/// Stored under `label` (`label-pose` for a pose) beside the held set.
/// `terminal_gone` says whether the terminal that asked has hung up; it is
/// asked between frames and before the save. `learned` tells the terminal
/// the straight phase is over and the looks start, once.
#[allow(clippy::too_many_arguments)]
pub fn run(
    a: &mut Authenticator,
    user: &str,
    label: &str,
    seconds: f32,
    count: usize,
    poses: &[String],
    terminal_gone: &dyn Fn() -> bool,
    learned: &mut dyn FnMut(),
) -> Outcome {
    match run_inner(
        a,
        user,
        label,
        seconds,
        count,
        poses,
        terminal_gone,
        learned,
    ) {
        Ok(o) => o,
        Err(e) => Outcome::Error {
            message: e.to_string(),
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn run_inner(
    a: &mut Authenticator,
    user: &str,
    label: &str,
    seconds: f32,
    count: usize,
    poses: &[String],
    terminal_gone: &dyn Fn() -> bool,
    learned: &mut dyn FnMut(),
) -> Result<Outcome> {
    let mut wanted: Vec<&'static str> = Vec::new();
    for p in poses {
        let Some(known) = POSES.iter().find(|q| **q == p.as_str()) else {
            return Ok(Outcome::Error {
                message: format!("unknown pose {:?}; one of {}", p, POSES.join(", ")),
            });
        };
        if !wanted.contains(known) {
            wanted.push(known);
        }
    }
    // The store's one enrollment opener, shared with the walk-through: no
    // plaintext over a sealed set, and a blob this machine can no longer
    // open goes aside only on the credential tool's own verdict (F2).
    let existing = a.store.open_for_enrolment(user)?;
    let uid = crate::store::current_uid(user).ok_or_else(|| anyhow!("unknown user {}", user))?;
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
    let seconds = seconds.clamp(4.0, 60.0);
    let count = count.clamp(3, 40);
    let spacing = Duration::from_millis(
        (((seconds - 2.0).max(1.0) * 1000.0) / count as f32).clamp(150.0, 2000.0) as u64,
    );
    let looks_for = Duration::from_secs_f32(seconds * wanted.len().max(1) as f32);
    let mut cap = IrCapture::open(&a.cfg)?;
    // Every look goes through the flash gate. Without the strobe it cannot
    // run, and templates enrolled here could never be used, unless the
    // administrator has accepted ungated authentication.
    if crate::tier::gate(cap.tier(), a.cfg.liveness_required) == crate::tier::Gate::Refuse {
        cap.stop()?;
        return Err(anyhow!(crate::tier::NO_GATE));
    }
    if let Some(i) = &cap.illuminator {
        i.set(true)?;
    }
    let t0 = Instant::now();
    let mut term = Terminal::new(
        &wanted,
        label,
        count,
        spacing,
        a.cfg.accept_threshold,
        cap.identity.clone(),
        t0,
        (Duration::from_secs_f32(STRAIGHT_SECONDS), looks_for),
    );
    let mut announced = false;
    // When the exposure last stepped, and when the metering first went to
    // a face: the reference waits for both to be `SETTLE` behind.
    let mut exposure = (cap.exposure.exposure, cap.exposure.gain);
    let mut stepped = t0;
    let mut metered: Option<Instant> = None;
    loop {
        if term.learned() && !announced {
            announced = true;
            log::info!(
                "terminal enrollment for {}: the face is learned; the looks start",
                user
            );
            learned();
        }
        match term.go_on(Instant::now(), terminal_gone()) {
            Ok(true) => {}
            Ok(false) => break,
            Err(why) => {
                cap.stop()?;
                log::info!("terminal enrollment for {}: {}", user, why);
                return Ok(Outcome::Error {
                    message: why.into(),
                });
            }
        }
        let Some(img) = cap.next(Duration::from_secs(2))? else {
            continue;
        };
        let now = Instant::now();
        if (cap.exposure.exposure, cap.exposure.gain) != exposure {
            exposure = (cap.exposure.exposure, cap.exposure.gain);
            stepped = now;
        }
        if cap.frames % 3 != 0 {
            continue;
        }
        let faces = a.pipeline.detector.detect(&img, a.cfg.min_detection)?;
        if let [one] = faces.as_slice() {
            cap.meter_on(one);
            metered.get_or_insert(now);
        }
        let settled = now.saturating_duration_since(stepped) >= SETTLE
            && metered.is_some_and(|m| now.saturating_duration_since(m) >= SETTLE);
        let act = {
            let (embedder, mesh) = (&mut a.pipeline.embedder, &mut a.pipeline.mesh);
            let mut embed =
                |f: &Face| embedder.embed(&faceauth_engine::align::align_112(&img, &f.landmarks));
            let mut read = |f: &Face| -> Result<Option<Reading>> {
                let hp = mesh
                    .as_mut()
                    .and_then(|m| m.for_face(&img, f).ok().flatten())
                    .map(|m| faceauth_engine::mesh::head_pose(&m));
                Ok(hp.map(|hp| Reading {
                    pose: faceauth_engine::pose::pose(&f.landmarks),
                    yaw_deg: hp.yaw,
                    pitch_deg: hp.pitch,
                }))
            };
            term.frame(faces, now, settled, &mut embed, &mut read)?
        };
        if let Ok(Act::Flash(i, followed)) = act {
            let verdict = flash::check(
                &mut cap,
                &mut a.pipeline.detector,
                a.cfg.min_detection,
                followed,
            )?;
            if let Err(why) = term.flashed(i, verdict) {
                cap.stop()?;
                return Ok(Outcome::Error {
                    message: why.into(),
                });
            }
        }
    }
    cap.stop()?;
    let kept = match term.finish(user) {
        Ok(k) => k,
        Err(message) => return Ok(Outcome::Error { message }),
    };
    // A terminal gone during the last look stores nothing either.
    if terminal_gone() {
        log::info!("terminal enrollment for {}: {}", user, GONE);
        return Ok(Outcome::Error {
            message: GONE.into(),
        });
    }
    // Verified: the new looks join the set, pruned to its cap in J1's
    // order, and the set is stored once.
    let added = kept.templates.len();
    u.templates.extend(kept.templates);
    let pruned = u.prune_to(MAX_TEMPLATES);
    if pruned > 0 {
        log::info!(
            "enrollment for {}: {} template(s) pruned to stay within {}",
            user,
            pruned,
            MAX_TEMPLATES
        );
    }
    let (lo, mean, _) = u.self_consistency().unwrap_or((1.0, 1.0, 1.0));
    let path = a.store.save(&u)?;
    Ok(Outcome::Enrolled {
        added,
        total: u.templates.len(),
        consistency_min: lo,
        consistency_mean: mean,
        path: path.display().to_string(),
        warning: kept.warning,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const THRESHOLD: f32 = 0.70;
    const LEVEL: f32 = 0.53;

    /// A face at `x` whose five-point pose reads `turn` and a level nose
    /// pitch, whose mesh reads `pitch_deg`, and whose embedding scores
    /// `likeness` against the person who began (a stranger about 0.1, the
    /// person turned a quarter about 0.6).
    fn face(x: f32, turn: f32, pitch_deg: f32, likeness: f32) -> Face {
        Face {
            bbox: [x, 150.0, 90.0, 108.0],
            score: 0.9,
            landmarks: [
                [turn, LEVEL],
                [likeness, pitch_deg],
                [0.0; 2],
                [0.0; 2],
                [0.0; 2],
            ],
            embedding: None,
        }
    }

    fn me(likeness: f32, turn: f32) -> Face {
        face(200.0, turn, 0.0, likeness)
    }

    fn read(f: &Face) -> Result<Option<Reading>> {
        Ok(Some(Reading {
            pose: Pose {
                yaw: f.landmarks[0][0],
                pitch: 0.5,
                roll: 0.0,
                nose_pitch: f.landmarks[0][1],
                mouth_drop: 1.0,
                inter_eye: 40.0,
            },
            yaw_deg: f.landmarks[0][0] * 100.0,
            pitch_deg: f.landmarks[1][1],
        }))
    }

    fn embed(f: &Face) -> Result<Vec<f32>> {
        let c = f.landmarks[1][0];
        Ok(vec![c, 0.0, (1.0 - c * c).max(0.0).sqrt()])
    }

    /// The straight phase's time and the looks' time in the tests.
    const STRAIGHT: Duration = Duration::from_secs(10);
    const LOOKS: Duration = Duration::from_secs(12);

    fn session(poses: &[&'static str], t0: Instant) -> Terminal {
        Terminal::new(
            poses,
            "enrol",
            3,
            Duration::from_millis(200),
            THRESHOLD,
            "test-camera".into(),
            t0,
            (STRAIGHT, LOOKS),
        )
    }

    /// The session's clock and its frames.
    struct Run {
        t: Terminal,
        t0: Instant,
    }

    impl Run {
        fn at_settled(
            &mut self,
            ms: u64,
            faces: Vec<Face>,
            settled: bool,
        ) -> std::result::Result<Act, Pause> {
            self.t
                .frame(
                    faces,
                    self.t0 + Duration::from_millis(ms),
                    settled,
                    &mut |f: &Face| embed(f),
                    &mut |f: &Face| read(f),
                )
                .unwrap()
        }

        fn at(&mut self, ms: u64, faces: Vec<Face>) -> std::result::Result<Act, Pause> {
            self.at_settled(ms, faces, true)
        }

        /// Learn the reference from the person looking straight on, still,
        /// from `ms`: three frames 300 ms apart.
        fn learn(&mut self, ms: u64) {
            for k in 0..3 {
                assert_eq!(self.at(ms + 300 * k, vec![me(1.0, 0.0)]), Ok(Act::Next));
            }
            assert!(self.t.follow.has_reference());
        }

        fn taken(&self, look: usize) -> Vec<f32> {
            self.t.looks[look]
                .taken
                .iter()
                .map(|(t, _)| t.embedding[0])
                .collect()
        }

        fn live(&mut self, look: usize, bbox: [f32; 4], ms: u64) {
            let at = self.t0 + Duration::from_millis(ms);
            self.t.flashed(look, Flash::Live((bbox, at))).unwrap();
        }
    }

    fn run(poses: &[&'static str]) -> Run {
        let t0 = Instant::now();
        Run {
            t: session(poses, t0),
            t0,
        }
    }

    /// A6, the terminal enrollment: one face per frame, and one face across
    /// the frames and the looks. A crowd while the face is learned starts
    /// the reference over; a crowd later takes nothing; someone else in
    /// the chair between the looks is refused wherever they sit, and the
    /// person who began is taken again once identified. Every template is
    /// theirs.
    #[test]
    fn a_terminal_enrolment_reads_only_the_face_it_began_with_across_its_looks() {
        let mut r = run(&["centre", "left"]);
        let other = || face(420.0, 0.0, 0.0, 0.1);
        assert_eq!(r.at(0, vec![me(1.0, 0.0)]), Ok(Act::Next));
        assert_eq!(r.at(100, vec![me(1.0, 0.0), other()]), Err(Pause::Crowd));
        assert!(r.t.refs.is_empty(), "the crowd started the reference over");
        r.learn(200);
        // The center look: its flash check first, then a template every
        // 200 ms from the followed face.
        let bbox = me(1.0, 0.0).bbox;
        assert_eq!(r.at(900, vec![me(1.0, 0.0)]), Ok(Act::Flash(0, bbox)));
        r.live(0, bbox, 950);
        for ms in [1000, 1100, 1200] {
            r.at(ms, vec![me(1.0, 0.0)]).unwrap();
        }
        assert_eq!(r.taken(0).len(), 2, "one frame inside the spacing");
        assert_eq!(r.at(1300, vec![me(1.0, 0.0), other()]), Err(Pause::Crowd));
        r.at(1400, vec![me(1.0, 0.0)]).unwrap();
        assert_eq!(r.taken(0), [1.0, 1.0, 1.0]);
        // Between the looks someone else takes the chair: elsewhere, then
        // turned left at the person's own place. Neither is read.
        for (ms, f) in [(2200, other()), (2800, face(200.0, -0.3, 0.0, 0.1))] {
            assert_eq!(r.at(ms, vec![f]), Err(Pause::NotTheFace), "{} ms", ms);
        }
        // The person who began is back, straight on, and followed into the
        // left look.
        assert_eq!(r.at(3200, vec![me(1.0, 0.0)]), Ok(Act::Next));
        assert_eq!(r.at(3300, vec![me(0.6, -0.3)]), Ok(Act::Flash(1, bbox)));
        r.live(1, bbox, 3350);
        for ms in [3400, 3600, 3800] {
            r.at(ms, vec![me(0.6, -0.3)]).unwrap();
        }
        assert!(r.t.done());
        let kept = r.t.finish("test").unwrap();
        assert_eq!(kept.warning, None);
        let labels: Vec<&str> = kept.templates.iter().map(|t| t.label.as_str()).collect();
        assert_eq!(
            labels,
            [
                "enrol-centre",
                "enrol-centre",
                "enrol-centre",
                "enrol-left",
                "enrol-left",
                "enrol-left"
            ]
        );
        assert!(
            kept.templates.iter().all(|t| t.embedding[0] >= 0.6),
            "a template of someone else was taken"
        );
    }

    /// A6: a look takes nothing until a strobed pair at the followed face
    /// has passed the flash gate there. A refusal ends the session; five
    /// checks in a row that read nothing end it too, and a check another
    /// face walked into is not one of them.
    #[test]
    fn a_terminal_look_takes_nothing_before_its_flash_pass() {
        let mut r = run(&[]);
        r.learn(0);
        let bbox = me(1.0, 0.0).bbox;
        for ms in [1000, 1300, 1600, 1900] {
            assert_eq!(r.at(ms, vec![me(1.0, 0.0)]), Ok(Act::Flash(0, bbox)));
        }
        assert!(r.taken(0).is_empty());
        let seen = Some((bbox, r.t0 + Duration::from_secs(2)));
        for _ in 0..FLASH_TRIES - 1 {
            assert_eq!(r.t.flashed(0, Flash::Unread(seen)), Ok(()));
            assert_eq!(r.t.flashed(0, Flash::Crowd(seen)), Ok(()));
        }
        assert_eq!(r.t.flashed(0, Flash::Unread(seen)), Err(flash::UNREAD));
        let mut r = run(&[]);
        r.learn(0);
        assert_eq!(r.t.flashed(0, Flash::Refused), Err(flash::REFUSED));
    }

    /// A6: the looks stay apart from the set until they are checked
    /// against the session's reference. A turned template under its floor
    /// is dropped and its look named; a look short of frames keeps none and
    /// is named, with how to add it; a straight-on template that is not the
    /// face fails the enrollment, and so does a session that kept nothing.
    #[test]
    fn the_terminal_looks_are_checked_before_they_join() {
        let fill = |r: &mut Run, look: usize, from: u64, faces: &[Face]| {
            let bbox = faces[0].bbox;
            assert_eq!(
                r.at(from, vec![faces[0].clone()]),
                Ok(Act::Flash(look, bbox))
            );
            r.live(look, bbox, from);
            for (k, f) in faces.iter().enumerate() {
                r.at(from + 300 * (k as u64 + 1), vec![f.clone()]).unwrap();
            }
        };
        let mut r = run(&["centre", "left", "right"]);
        r.learn(0);
        // The frames come closer together than the track's gap, so the
        // person is followed from the center into the turn.
        fill(
            &mut r,
            0,
            1000,
            &[me(1.0, 0.0), me(0.98, 0.0), me(0.97, 0.05)],
        );
        fill(
            &mut r,
            1,
            2200,
            &[me(0.6, -0.3), me(0.38, -0.4), me(0.62, -0.3)],
        );
        let kept = r.t.finish("test").unwrap();
        assert_eq!(kept.templates.len(), 5, "the 0.38 at full turn is dropped");
        assert!(kept.templates.iter().all(|t| t.embedding[0] > 0.5));
        let w = kept.warning.expect("the right look is named");
        assert!(
            w.contains("No frames were kept for right") && w.contains("--poses right"),
            "{}",
            w
        );
        assert!(w.contains("the left look lost 1 of 3"), "{}", w);

        let mut r = run(&["centre", "left"]);
        r.learn(0);
        fill(&mut r, 0, 1000, &[me(1.0, 0.0), me(0.6, 0.0), me(1.0, 0.0)]);
        fill(
            &mut r,
            1,
            2200,
            &[me(0.6, -0.3), me(0.6, -0.3), me(0.6, -0.3)],
        );
        assert!(r
            .t
            .finish("test")
            .unwrap_err()
            .starts_with("The new looks are not all the face"));

        let mut r = run(&["left"]);
        r.learn(0);
        let why = r.t.finish("test").unwrap_err();
        assert!(
            why.starts_with("nothing was enrolled: left: only 0 frames"),
            "{}",
            why
        );
        let why = run(&["left"]).t.finish("test").unwrap_err();
        assert!(
            why.contains("never saw the face still and straight on"),
            "{}",
            why
        );

        // A look whose flash check never read took nothing because of the
        // flash, and is named for it, not for its pose.
        let mut r = run(&["centre", "left"]);
        r.learn(0);
        fill(
            &mut r,
            0,
            1000,
            &[me(1.0, 0.0), me(0.98, 0.0), me(0.97, 0.05)],
        );
        let bbox = me(0.6, -0.3).bbox;
        assert_eq!(r.at(2200, vec![me(0.6, -0.3)]), Ok(Act::Flash(1, bbox)));
        let seen = Some((bbox, r.t0 + Duration::from_millis(2200)));
        for _ in 0..2 {
            r.t.flashed(1, Flash::Unread(seen)).unwrap();
        }
        let w =
            r.t.finish("test")
                .unwrap()
                .warning
                .expect("the left look is named");
        assert!(
            w.contains("left: the flash check could not read your face at this look (2 tries)")
                && !w.contains("only 0 frames"),
            "{}",
            w
        );
    }

    /// A6: the reference is a straight, still look taken once the exposure
    /// has settled, whatever looks were asked for. A run whose first look
    /// is turned (`--poses right,up`) learns nothing from the turned
    /// frames, nor from frames before the exposure settles or ones that do
    /// not hold still; it learns from the straight look the terminal asks
    /// for first, and its level from there. A chin-up at the center, level
    /// on the five points, is taken with the slack.
    #[test]
    fn a_turned_first_run_still_takes_a_straight_still_settled_reference() {
        let mut r = run(&["right", "up"]);
        // Turned right at once, a quarter turn, scoring 0.6.
        for k in 0..6 {
            r.at(300 * k, vec![me(0.6, 0.3)]).unwrap();
        }
        assert!(
            !r.t.follow.has_reference(),
            "no reference from a turned face"
        );
        // Straight but before the exposure settles.
        for k in 0..6 {
            r.at_settled(2000 + 300 * k, vec![me(1.0, 0.0)], false)
                .unwrap();
        }
        assert!(
            !r.t.follow.has_reference(),
            "none before the exposure settles"
        );
        // Straight and settled, but the mesh pitch swings by 20 degrees.
        for (k, pitch) in [0.0, 10.0, 20.0].into_iter().enumerate() {
            r.at(4000 + 300 * k as u64, vec![face(200.0, 0.0, pitch, 1.0)])
                .unwrap();
        }
        assert!(!r.t.follow.has_reference(), "none from frames that moved");
        // Still: learned, from straight frames only.
        for k in 0..3 {
            r.at(5000 + 300 * k, vec![face(200.0, 0.0, 2.0, 1.0)])
                .unwrap();
        }
        assert!(r.t.follow.has_reference());
        assert!(r.t.follow.reference().iter().all(|e| e[0] == 1.0));
        assert!((r.t.level_deg - 2.0).abs() < 1e-4, "{}", r.t.level_deg);
        assert!((r.t.level - LEVEL).abs() < 1e-4, "{}", r.t.level);
        // The looks start only now, turned right into the first.
        let bbox = me(1.0, 0.0).bbox;
        assert_eq!(r.at(6000, vec![me(0.6, 0.3)]), Ok(Act::Flash(0, bbox)));

        // `--look`: a straight template at a chin-up the mesh reads, which
        // the five points read level, gets the slack.
        let mut r = run(&[]);
        r.learn(0);
        r.at(1000, vec![me(1.0, 0.0)]).unwrap();
        r.live(0, bbox, 1000);
        for (ms, pitch) in [(1300, 0.0), (1600, -18.0), (1900, 0.0)] {
            r.at(ms, vec![face(200.0, 0.02, pitch, 1.0)]).unwrap();
        }
        let straight: Vec<bool> = r.t.looks[0].taken.iter().map(|(_, s)| *s).collect();
        assert_eq!(straight, [true, false, true]);
    }

    /// A6: a terminal that goes away (Ctrl-C) ends the looks at once, with
    /// nothing stored: its end of the socket hung up reads as gone between
    /// frames, where one still waiting for the reply does not.
    #[test]
    fn the_terminal_going_away_ends_the_looks_with_nothing_stored() {
        use std::os::unix::net::UnixStream;
        let (cli, daemon_end) = UnixStream::pair().unwrap();
        let requester = std::os::fd::OwnedFd::from(daemon_end.try_clone().unwrap());
        let gone = || crate::consent::peer_gone(&requester);
        let t0 = Instant::now();
        let t = session(&["centre"], t0);
        let at = |s: u64| t0 + Duration::from_secs(s);
        assert_eq!(t.go_on(at(1), gone()), Ok(true));
        drop(cli);
        assert_eq!(t.go_on(at(1), gone()), Err(GONE));
        drop(daemon_end);
    }

    /// A6: the straight phase has its own time, before any posed look,
    /// and the looks' time runs from when the face is learned. Runs whose
    /// looks are all turned or pitched (`--poses right,up`, `--poses
    /// left,right`) learn a straight, level reference from the straight
    /// look they begin with, or, with none, end saying the camera never
    /// saw the face still and straight on: a turned look or a chin-up,
    /// level on the five points but not on the mesh, is never learned from.
    #[test]
    fn a_run_learns_a_straight_level_face_first_or_says_it_never_saw_one() {
        let right = || face(200.0, 0.3, 0.0, 0.6);
        let left = || face(200.0, -0.3, 0.0, 0.6);
        let chin_up = || face(200.0, 0.02, -25.0, 0.7);
        for (poses, frames) in [
            (&["right", "up"][..], [right(), chin_up()]),
            (&["left", "right"][..], [left(), right()]),
        ] {
            // Only the posed looks, through the straight phase's time.
            let mut r = run(poses);
            for k in 0..30u64 {
                r.at(300 * k, vec![frames[(k / 15) as usize].clone()])
                    .unwrap();
            }
            assert!(!r.t.learned(), "{:?}: learned from a posed look", poses);
            assert_eq!(r.t.go_on(r.t0 + STRAIGHT, false), Ok(false), "{:?}", poses);
            let why = r.t.finish("test").unwrap_err();
            assert!(
                why.contains("never saw the face still and straight on"),
                "{:?}: {}",
                poses,
                why
            );

            // A person who rests 15 degrees under none, past what one
            // person's resting rounds read, is still level.
            let mut r15 = run(poses);
            for k in 0..3u64 {
                r15.at(300 * k, vec![face(200.0, 0.0, -15.0, 1.0)]).unwrap();
            }
            assert!(r15.t.learned(), "{:?}: a resting pitch of -15", poses);

            // The straight look first: learned, level, and the looks' time
            // counted from then.
            let mut r = run(poses);
            for k in 0..3u64 {
                r.at(4000 + 300 * k, vec![face(200.0, 0.0, -3.0, 1.0)])
                    .unwrap();
            }
            assert!(r.t.learned(), "{:?}", poses);
            assert!(r.t.follow.reference().iter().all(|e| e[0] == 1.0));
            assert!((r.t.level_deg + 3.0).abs() < 1e-4, "{}", r.t.level_deg);
            let learned = r.t0 + Duration::from_millis(4600);
            assert_eq!(r.t.go_on(r.t0 + STRAIGHT, false), Ok(true), "{:?}", poses);
            assert_eq!(r.t.go_on(learned + LOOKS, false), Ok(false), "{:?}", poses);
        }
    }
}
