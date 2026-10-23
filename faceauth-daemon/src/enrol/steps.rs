//! The walk-through's steps in order, what each one tells the person, and
//! the gesture and everyday rounds that follow the looks. Where a session
//! starts decides where it ends.

use super::dot::HOLD_ZONES;
use crate::auth::{POSES, POSE_HINTS};
use crate::store::Template;
use std::time::Instant;

/// The templates a session has taken, each with the step that took it and
/// whether it was taken straight on (`follow::straight_on`), kept out of
/// the user's set until the looks are done. Redo drops what the step at
/// hand took and nothing an earlier step took, so the count is back where
/// that step began (J3). Steps only move forward, so a step's templates
/// are the ones tagged with it.
#[derive(Default)]
pub(super) struct Taken(Vec<(Step, Template, bool)>);

impl Taken {
    pub(super) fn push(&mut self, step: Step, t: Template, straight: bool) {
        self.0.push((step, t, straight));
    }

    /// How many `step` has taken.
    pub(super) fn by(&self, step: Step) -> usize {
        self.0.iter().filter(|(s, _, _)| *s == step).count()
    }

    /// How many the session has taken in all.
    pub(super) fn count(&self) -> usize {
        self.0.len()
    }

    /// Redo: drop what `step` took.
    pub(super) fn redo(&mut self, step: Step) {
        self.0.retain(|(s, _, _)| *s != step);
    }

    /// The templates, in the order they were taken.
    pub(super) fn into_templates(self) -> Vec<Template> {
        self.0.into_iter().map(|(_, t, _)| t).collect()
    }

    /// The templates, for verify to read before any joins the set.
    pub(super) fn templates(&self) -> Vec<&Template> {
        self.0.iter().map(|(_, t, _)| t).collect()
    }

    /// Each template with the step that took it and whether it was taken
    /// straight on, in the order taken, for verify's rule on the set.
    pub(super) fn entries(&self) -> impl Iterator<Item = (Step, &Template, bool)> {
        self.0.iter().map(|(s, t, straight)| (*s, t, *straight))
    }

    /// Drop the templates at `at`, their places in `templates()`: the
    /// looks verify found were not the face the session began with (A6).
    pub(super) fn drop_at(&mut self, at: &[usize]) {
        let mut i = 0;
        self.0.retain(|_| {
            i += 1;
            !at.contains(&(i - 1))
        });
    }
}

/// A zone as the person reads it: the wire value "centre" is spelled
/// "center" in every message; the other zones are the same word.
pub(super) fn zone_word(zone: &str) -> &str {
    if zone == "centre" {
        "center"
    } else {
        zone
    }
}

/// The name of the look a step takes templates for, as the person is
/// told: "path", "left hold", and "first center hold" and "second center
/// hold" for the two at the center. The zone is a wire value ("centre"),
/// so it is spelled for the person here.
pub(super) fn look_name(step: Step) -> String {
    match step {
        Step::Hold(i) => {
            let zone = HOLD_ZONES.get(i).copied().unwrap_or("?");
            let count = |zones: &[&str]| zones.iter().filter(|z| **z == zone).count();
            let word = zone_word(zone);
            if count(&HOLD_ZONES) > 1 {
                let nth = count(&HOLD_ZONES[..i]);
                let ordinal = ["first", "second", "third"]
                    .get(nth)
                    .copied()
                    .unwrap_or("next");
                format!("{} {} hold", ordinal, word)
            } else {
                format!("{} hold", word)
            }
        }
        other => other.name().into(),
    }
}

/// What the step at hand has learned or passed on the way to its
/// templates, which Redo drops with them: the center step's still frames
/// and the reference embeddings taken from them, and a hold's time on
/// target and whether the flash gate has passed at it (A6).
#[derive(Default)]
pub(super) struct Progress {
    pub still_since: Option<Instant>,
    pub centre_samples: Vec<[f32; 4]>,
    pub centre_refs: Vec<Vec<f32>>,
    pub on_since: Option<Instant>,
    pub hold_live: bool,
}

impl Progress {
    /// The center starts its three still seconds over: nothing it learned
    /// from a face before stands, so the reference it builds is one face's.
    pub(super) fn restart_centre(&mut self) {
        self.still_since = None;
        self.centre_samples.clear();
        self.centre_refs.clear();
    }

    /// Redo at `step`. A redone center learns the face again and passes the
    /// flash gate again before it counts; a redone hold waits on target
    /// and passes the flash gate again before it takes anything (A6).
    pub(super) fn redo(&mut self, step: Step) {
        match step {
            Step::Centre => self.restart_centre(),
            Step::Hold(_) => {
                self.on_since = None;
                self.hold_live = false;
            }
            _ => {}
        }
    }
}

/// A session that records a kind of round replaces every earlier
/// session's samples of that kind: the first round of the kind in this
/// session clears them, later rounds add to the fresh set (J4). The
/// everyday rounds count as one kind. A user re-tuning after an
/// exaggerated calibration gets floors from this session alone.
pub(super) fn begin_kind(
    g: &mut crate::store::GestureCal,
    kinds_this_session: &mut Vec<&'static str>,
    stored_as: &'static str,
) {
    let kind = match stored_as {
        "nod" | "shake" => stored_as,
        _ => "everyday",
    };
    if kinds_this_session.contains(&kind) {
        return;
    }
    kinds_this_session.push(kind);
    match kind {
        "nod" => {
            g.nod_deg.clear();
            g.nod_reads_to_deg.clear();
        }
        "shake" => {
            g.shake_deg.clear();
            g.shake_reads_to_deg.clear();
        }
        _ => g.everyday_deg.clear(),
    }
}

/// The gesture and everyday rounds after the looks: what is asked, how
/// many times, for how long, and the kind the store files it under (the
/// two glances are "aside" rounds, the keyboard look a "glance").
pub struct Round {
    pub kind: &'static str,
    pub stored_as: &'static str,
    pub times: usize,
    pub seconds: f32,
    pub prompt: &'static str,
}

pub const ROUNDS: [Round; 8] = [
    Round {
        kind: "nod",
        stored_as: "nod",
        times: 2,
        seconds: 8.0,
        prompt: "Look at the camera and nod twice, the way you would to say yes.",
    },
    Round {
        kind: "shake",
        stored_as: "shake",
        times: 2,
        seconds: 8.0,
        prompt: "Look at the camera and shake your head twice, the way you would to say no.",
    },
    Round {
        kind: "glance-right",
        stored_as: "aside",
        times: 2,
        seconds: 6.0,
        prompt:
            "Something catches your eye to the right. Look at it, then back at the screen. Twice.",
    },
    Round {
        kind: "glance-left",
        stored_as: "aside",
        times: 2,
        seconds: 6.0,
        prompt:
            "Something catches your eye to the left. Look at it, then back at the screen. Twice.",
    },
    Round {
        kind: "keyboard",
        stored_as: "glance",
        times: 1,
        seconds: 8.0,
        prompt: "Look down at your keyboard and back up at the screen, twice.",
    },
    Round {
        kind: "read",
        stored_as: "read",
        times: 1,
        seconds: 12.0,
        prompt: "Read the text as it appears around the screen.",
    },
    Round {
        kind: "talk",
        stored_as: "talk",
        times: 1,
        seconds: 8.0,
        prompt: "Keep facing the screen and say a sentence or two out loud, as if on a call.",
    },
    Round {
        kind: "lean",
        stored_as: "lean",
        times: 1,
        seconds: 8.0,
        prompt: "Lean in toward the screen and sit back, twice.",
    },
];

/// The reading round's slots: the window keeps the texts (`readTexts` in
/// Enrol.qml) and places them at the corners and the center of the
/// screen; the daemon only says which slot is showing.
pub const READ_SLOTS: usize = 5;
/// How long each text slot shows.
pub const READ_SLOT_SECONDS: f32 = 2.4;
/// The pause before a round starts recording.
pub(super) const ROUND_COUNTDOWN: f32 = 2.0;

/// Round `i` in the flat list of (round, repeat) pairs.
pub fn round_at(i: usize) -> Option<(&'static Round, usize)> {
    let mut n = 0;
    for r in &ROUNDS {
        if i < n + r.times {
            return Some((r, i - n + 1));
        }
        n += r.times;
    }
    None
}

pub fn round_count() -> usize {
    ROUNDS.iter().map(|r| r.times).sum()
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Step {
    /// Nothing stored: the dot alone while the person moves through the
    /// full range, for the stream log (dev-tools builds).
    #[cfg(feature = "dev-tools")]
    Record,
    Welcome,
    /// Sit normally, look at the center: the person's center is learned.
    Centre,
    /// All the way round once: the person's reach is learned and the ring
    /// set from it.
    Range,
    Path,
    Hold(usize),
    Verify,
    /// "Next we record how you nod and shake."
    Bridge,
    /// One gesture or everyday round, by index into the flat list.
    Round(usize),
}

impl Step {
    pub(super) fn name(self) -> &'static str {
        match self {
            #[cfg(feature = "dev-tools")]
            Step::Record => "record",
            Step::Welcome => "welcome",
            Step::Centre => "centre",
            Step::Range => "range",
            Step::Path => "path",
            Step::Hold(_) => "hold",
            Step::Verify => "verify",
            Step::Bridge => "bridge",
            Step::Round(_) => "round",
        }
    }

    pub(super) fn zone(self) -> Option<&'static str> {
        match self {
            Step::Hold(i) => HOLD_ZONES.get(i).copied(),
            _ => None,
        }
    }

    /// Whether the step reads the face. Welcome and the Bridge only wait
    /// for Continue, so the camera and its light are off on them (J6).
    pub(super) fn reads_face(self) -> bool {
        !matches!(self, Step::Welcome | Step::Bridge)
    }

    /// The development record mode: it follows whoever is in view and
    /// stores nothing.
    pub(super) fn records(self) -> bool {
        self.name() == "record"
    }

    /// Whether the step learns whose face the session is, and so takes on
    /// a face nobody follows yet: the center step, and the record mode.
    /// Every other step reads only the face the session follows (A6).
    pub(super) fn learns_face(self) -> bool {
        self == Step::Centre || self.records()
    }

    pub fn next(self) -> Option<Step> {
        Some(match self {
            #[cfg(feature = "dev-tools")]
            Step::Record => return None,
            Step::Welcome => Step::Centre,
            Step::Centre => Step::Range,
            Step::Range => Step::Path,
            Step::Path => Step::Hold(0),
            Step::Hold(i) if i + 1 < HOLD_ZONES.len() => Step::Hold(i + 1),
            Step::Hold(_) => Step::Verify,
            Step::Verify => Step::Bridge,
            Step::Bridge => Step::Round(0),
            Step::Round(i) if i + 1 < round_count() => Step::Round(i + 1),
            Step::Round(_) => return None,
        })
    }

    /// The step a session starts at, from the setup script's name for it:
    /// "welcome" (the default) for a first enrollment, "distance" for Add
    /// Look, "bridge" for Tune Gestures. The development start points exist
    /// in a dev-tools build alone: the record mode, and range, path and
    /// hold, which skip the center step and judge the looks against a zero
    /// center. Any other name is refused (round-4 H2).
    pub fn from_start(name: Option<&str>) -> Option<Step> {
        Some(match name.unwrap_or("welcome") {
            "welcome" => Step::Welcome,
            "distance" | "centre" => Step::Centre,
            "bridge" | "gestures" => Step::Bridge,
            #[cfg(feature = "dev-tools")]
            "record" => Step::Record,
            #[cfg(feature = "dev-tools")]
            "range" => Step::Range,
            #[cfg(feature = "dev-tools")]
            "path" => Step::Path,
            #[cfg(feature = "dev-tools")]
            "hold" => Step::Hold(0),
            _ => return None,
        })
    }
}

/// A round's per-frame recording, for the development build's round
/// traces. A release build keeps nothing and never formats a line: the
/// lines are made by the closure `push` is given, which only a dev-tools
/// build calls (round-4 H2).
#[derive(Default)]
pub(super) struct RoundTrace {
    #[cfg(feature = "dev-tools")]
    lines: Vec<String>,
}

impl RoundTrace {
    /// The most lines a round keeps: a minute of frames.
    #[cfg(feature = "dev-tools")]
    const MAX_LINES: usize = 1500;

    pub(super) fn clear(&mut self) {
        #[cfg(feature = "dev-tools")]
        self.lines.clear();
    }

    #[cfg_attr(not(feature = "dev-tools"), allow(unused_variables))]
    pub(super) fn push(&mut self, line: impl FnOnce() -> String) {
        #[cfg(feature = "dev-tools")]
        if self.lines.len() < Self::MAX_LINES {
            self.lines.push(line());
        }
    }

    /// The lines kept.
    #[cfg(feature = "dev-tools")]
    pub(super) fn lines(&self) -> &[String] {
        &self.lines
    }

    /// How many lines are kept: none in a release build.
    #[cfg(test)]
    fn len(&self) -> usize {
        #[cfg(feature = "dev-tools")]
        return self.lines.len();
        #[cfg(not(feature = "dev-tools"))]
        0
    }
}

pub fn message_for(step: Step, distance: &str) -> String {
    match step {
        #[cfg(feature = "dev-tools")]
        Step::Record => "Recording. Move your head through its full range: left, right, up, down, then a couple of slow circles. Nothing is stored.".into(),
        Step::Welcome => "Welcome to FaceAuth enrollment. Follow the instructions on the screen.".into(),
        Step::Centre => match distance {
            "far" => "Sit as you normally do and look at the dashed circle in the center. A little closer.".into(),
            "close" => "Sit as you normally do and look at the dashed circle in the center. A little further back.".into(),
            _ => "Sit as you normally do and look at the dashed circle in the center. Hold still a moment.".into(),
        },
        Step::Range => "Now move your head all the way round, slowly, keeping the screen just in view: left, up, right, down, and back to the center.".into(),
        Step::Path => "Follow the dashed circle with your head and keep the dot inside it. It waits for you.".into(),
        Step::Hold(i) => format!("Hold the dot in the circle: {}.", POSE_HINTS[POSES.iter().position(|p| *p == HOLD_ZONES[i]).unwrap_or(0)]),
        Step::Verify => "Look at the camera.".into(),
        Step::Bridge => "Next we record how you nod and shake your head, and check that your everyday movements don't read as either. Nothing here is an image.".into(),
        Step::Round(i) => round_at(i).map(|(r, _)| r.prompt.to_string()).unwrap_or_default(),
    }
}

/// Where a session started at decides where it ends: a first enrollment
/// runs the looks and the rounds, Add Look stops after verify, Tune
/// Gestures runs the rounds alone.
pub(super) fn last_step(start: Option<&str>) -> Step {
    match start.unwrap_or("welcome") {
        "distance" | "centre" => Step::Verify,
        #[cfg(feature = "dev-tools")]
        "path" | "hold" => Step::Verify,
        _ => Step::Round(round_count().saturating_sub(1)),
    }
}

/// A round's largest 1.5 s swing on one axis of the recorded angles,
/// degrees: kept with the templates for the record (the floors come from
/// the replay, `reads_to_deg`).
pub(super) fn swing(series: &[(f32, f32, f32)], pick: fn(&(f32, f32, f32)) -> f32) -> f32 {
    let mut best = 0f32;
    for i in 0..series.len() {
        let (mut lo, mut hi) = (f32::MAX, f32::MIN);
        for s in &series[i..] {
            if s.0 - series[i].0 > 1.5 {
                break;
            }
            lo = lo.min(pick(s));
            hi = hi.max(pick(s));
        }
        if hi > lo {
            best = best.max(hi - lo);
        }
    }
    best
}

#[cfg(test)]
mod kind_tests {
    use super::begin_kind;
    use crate::store::{EverydayDeg, GestureCal};

    /// J4: Tune Gestures again replaces the earlier session's rounds of
    /// each kind it records, so the floor moves all the way to this
    /// session's, and a kind it does not record keeps its samples.
    #[test]
    fn a_session_replaces_its_kinds_samples_and_keeps_the_rest() {
        let mut g = GestureCal {
            nod_deg: vec![30.0, 32.0],
            nod_reads_to_deg: vec![24.0, 26.0],
            shake_deg: vec![40.0],
            shake_reads_to_deg: vec![30.0],
            everyday_deg: vec![EverydayDeg {
                kind: "read".into(),
                dyaw: 1.0,
                dpitch: 2.0,
            }],
            ..Default::default()
        };
        let mut kinds = Vec::new();
        begin_kind(&mut g, &mut kinds, "nod");
        assert!(g.nod_deg.is_empty() && g.nod_reads_to_deg.is_empty());
        g.nod_reads_to_deg.push(8.0);
        begin_kind(&mut g, &mut kinds, "nod");
        assert_eq!(
            g.nod_reads_to_deg,
            vec![8.0],
            "the second nod round of the session adds"
        );
        assert_eq!(
            g.shake_reads_to_deg,
            vec![30.0],
            "a kind not recorded keeps its samples"
        );
        begin_kind(&mut g, &mut kinds, "read");
        assert!(g.everyday_deg.is_empty());
        begin_kind(&mut g, &mut kinds, "glance-left");
        assert_eq!(
            kinds,
            vec!["nod", "everyday"],
            "the everyday rounds are one kind"
        );
    }
}

#[cfg(test)]
mod taken_tests {
    use super::{Step, Taken};
    use crate::store::Template;

    fn look(label: String) -> Template {
        Template {
            embedding: vec![1.0, 0.0],
            quality: 0.9,
            face_width: 80.0,
            created: 0,
            label,
            device: "test-camera".into(),
            yaw: None,
            nose_pitch: None,
        }
    }

    /// J3: Redo on each step that takes templates drops what that step
    /// took and nothing an earlier step took, so the count is back where
    /// the step began, and only the frames taken after the redo reach the
    /// set.
    #[test]
    fn redo_leaves_the_count_where_the_step_began() {
        let mut taken = Taken::default();
        let mut step = Step::Path;
        let mut steps = 0;
        loop {
            let began = taken.count();
            for n in 0..3 {
                taken.push(step, look(format!("{:?} redone {}", step, n)), false);
            }
            assert_eq!(taken.by(step), 3);
            taken.redo(step);
            assert_eq!(
                taken.count(),
                began,
                "{:?}: Redo is back where the step began",
                step
            );
            assert_eq!(taken.by(step), 0, "{:?}: the step's own count too", step);
            for n in 0..2 {
                taken.push(step, look(format!("{:?} kept {}", step, n)), false);
            }
            steps += 1;
            match step.next() {
                Some(Step::Verify) | None => break,
                Some(next) => step = next,
            }
        }
        assert_eq!(steps, 7, "the path and the six holds");
        assert_eq!(taken.count(), 2 * steps);
        taken.redo(Step::Round(0));
        assert_eq!(
            taken.count(),
            2 * steps,
            "a redo on a step that takes none drops nothing"
        );
        let labels: Vec<String> = taken
            .into_templates()
            .into_iter()
            .map(|t| t.label)
            .collect();
        assert!(
            labels.iter().all(|l| l.contains(" kept ")),
            "no redone frame survives: {:?}",
            labels
        );
        assert_eq!(labels[0], "Path kept 0", "in the order taken");
    }

    /// A6: verify's drops leave the rest in the order taken.
    #[test]
    fn dropped_looks_leave_the_rest_in_order() {
        let mut taken = Taken::default();
        for n in 0..5 {
            taken.push(Step::Hold(n % 2), look(format!("look {}", n)), false);
        }
        taken.drop_at(&[1, 3]);
        let labels: Vec<String> = taken
            .into_templates()
            .into_iter()
            .map(|t| t.label)
            .collect();
        assert_eq!(labels, ["look 0", "look 2", "look 4"]);
    }

    /// The looks verify names are the person's: the two center holds told
    /// apart, the other holds by their direction, and the path.
    #[test]
    fn each_look_is_named_as_the_person_is_told() {
        let names: Vec<String> = (0..6).map(|i| super::look_name(Step::Hold(i))).collect();
        assert_eq!(
            names,
            [
                "first center hold",
                "left hold",
                "right hold",
                "second center hold",
                "up hold",
                "down hold"
            ]
        );
        assert_eq!(super::look_name(Step::Path), "path");
    }
}

#[cfg(test)]
mod progress_tests {
    use super::{Progress, Step};
    use std::time::Instant;

    /// A6: Redo at a hold drops the hold's flash pass and its time on
    /// target, so the redone hold takes nothing until a fresh strobed pair
    /// passes; Redo at the center drops the still frames and the reference
    /// learned from them, so the center is learned, and flashed, again.
    /// Redo elsewhere leaves both alone.
    #[test]
    fn redo_at_a_hold_or_the_centre_takes_a_fresh_flash_pass() {
        let passed = || Progress {
            still_since: Some(Instant::now()),
            centre_samples: vec![[0.0; 4]; 40],
            centre_refs: vec![vec![1.0, 0.0]; 5],
            on_since: Some(Instant::now()),
            hold_live: true,
        };
        for i in 0..6 {
            let mut p = passed();
            p.redo(Step::Hold(i));
            assert!(!p.hold_live, "hold {}: the flash pass stood", i);
            assert_eq!(p.on_since, None, "hold {}", i);
        }
        let mut p = passed();
        p.redo(Step::Centre);
        assert!(p.still_since.is_none() && p.centre_samples.is_empty());
        assert!(p.centre_refs.is_empty());
        for step in [Step::Path, Step::Range, Step::Verify, Step::Round(0)] {
            let mut p = passed();
            p.redo(step);
            assert!(p.hold_live && p.centre_refs.len() == 5, "{:?}", step);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// J6: the camera streams only on steps that read the face. A first
    /// enrollment waits on Welcome and the Bridge with it off, Tune Gestures
    /// waits on the Bridge with it off, and Add Look starts reading at once.
    #[test]
    fn only_the_screens_that_wait_for_a_click_leave_the_camera_off() {
        let mut s = Step::from_start(None).unwrap();
        let mut off = Vec::new();
        loop {
            if !s.reads_face() {
                off.push(s.name());
            }
            match s.next() {
                Some(n) => s = n,
                None => break,
            }
        }
        assert_eq!(off, ["welcome", "bridge"]);
        assert!(
            !Step::from_start(Some("gestures")).unwrap().reads_face(),
            "Tune Gestures opens on the bridge with the camera off"
        );
        assert!(
            Step::from_start(Some("distance")).unwrap().reads_face(),
            "Add Look opens on the center step, reading"
        );
        #[cfg(feature = "dev-tools")]
        assert!(Step::Record.reads_face());
    }

    #[test]
    fn the_steps_run_in_order_and_end_at_verify() {
        let mut s = Step::from_start(None).unwrap();
        let mut names = vec![s.name().to_string()];
        while let Some(n) = s.next() {
            s = n;
            names.push(format!(
                "{}{}",
                s.name(),
                s.zone().map(|z| format!(":{}", z)).unwrap_or_default()
            ));
        }
        assert_eq!(
            &names[..11],
            &[
                "welcome",
                "centre",
                "range",
                "path",
                "hold:centre",
                "hold:left",
                "hold:right",
                "hold:centre",
                "hold:up",
                "hold:down",
                "verify"
            ]
        );
        assert_eq!(names[11], "bridge");
        assert_eq!(names.len(), 12 + round_count(), "then every round");
        assert_eq!(round_count(), 12);
        assert_eq!(round_at(0).map(|(r, n)| (r.kind, n)), Some(("nod", 1)));
        assert_eq!(round_at(1).map(|(r, n)| (r.kind, n)), Some(("nod", 2)));
        assert_eq!(round_at(2).map(|(r, n)| (r.kind, n)), Some(("shake", 1)));
        assert_eq!(round_at(11).map(|(r, n)| (r.kind, n)), Some(("lean", 1)));
        assert!(round_at(12).is_none());
        assert_eq!(
            last_step(Some("distance")),
            Step::Verify,
            "Add Look ends after verify"
        );
        assert_eq!(
            last_step(None),
            Step::Round(11),
            "a first enrollment runs every round"
        );
        assert_eq!(
            Step::from_start(Some("bridge")),
            Some(Step::Bridge),
            "Tune Gestures starts at the bridge"
        );
        assert_eq!(
            Step::from_start(Some("distance")),
            Some(Step::Centre),
            "Add Look starts at the center screen"
        );
        #[cfg(feature = "dev-tools")]
        {
            assert_eq!(Step::from_start(Some("record")), Some(Step::Record));
            assert_eq!(
                Step::Record.next(),
                None,
                "a recording stores nothing and leads nowhere"
            );
        }
        #[cfg(not(feature = "dev-tools"))]
        assert_eq!(
            Step::from_start(Some("record")),
            None,
            "without dev-tools there is no record mode"
        );
    }

    /// H2: a release build refuses the development start points, which
    /// skip the center step, and any name it does not know; the setup
    /// script's three start where they always did. A release build keeps
    /// no round trace and never formats one of its lines.
    #[test]
    fn release_builds_refuse_the_development_start_points_and_keep_no_trace() {
        for dev in ["record", "range", "path", "hold"] {
            assert_eq!(
                Step::from_start(Some(dev)).is_some(),
                cfg!(feature = "dev-tools"),
                "--start {}",
                dev
            );
        }
        assert_eq!(Step::from_start(Some("walkthrough")), None);
        assert_eq!(Step::from_start(Some("")), None);
        assert_eq!(Step::from_start(None), Some(Step::Welcome));
        assert_eq!(Step::from_start(Some("distance")), Some(Step::Centre));
        assert_eq!(Step::from_start(Some("bridge")), Some(Step::Bridge));

        let mut trace = RoundTrace::default();
        let mut formatted = 0;
        for n in 0..10 {
            trace.push(|| {
                formatted += 1;
                format!("frame {}", n)
            });
        }
        let kept = if cfg!(feature = "dev-tools") { 10 } else { 0 };
        assert_eq!(formatted, kept, "lines formatted");
        assert_eq!(trace.len(), kept, "lines kept");
        trace.clear();
        assert_eq!(trace.len(), 0);
    }
}
