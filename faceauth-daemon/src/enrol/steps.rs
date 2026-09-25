//! The walk-through's steps in order, what each one tells the person, and
//! the gesture and everyday rounds that follow the looks. Where a session
//! starts decides where it ends.

use super::dot::HOLD_ZONES;
use crate::auth::{POSES, POSE_HINTS};

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
/// Enrol.qml) and places them at the corners and the centre of the
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
    /// Sit normally, look at the centre: the person's centre is learned.
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

    pub fn from_start(name: Option<&str>) -> Step {
        match name.unwrap_or("welcome") {
            #[cfg(feature = "dev-tools")]
            "record" => Step::Record,
            "distance" | "centre" => Step::Centre,
            "range" => Step::Range,
            "path" => Step::Path,
            "hold" => Step::Hold(0),
            "bridge" | "gestures" => Step::Bridge,
            _ => Step::Welcome,
        }
    }
}

pub fn message_for(step: Step, distance: &str) -> String {
    match step {
        #[cfg(feature = "dev-tools")]
        Step::Record => "Recording. Move your head through its full range: left, right, up, down, then a couple of slow circles. Nothing is stored.".into(),
        Step::Welcome => "Welcome to FaceAuth enrolment. Follow the instructions on the screen.".into(),
        Step::Centre => match distance {
            "far" => "Sit as you normally do and look at the dashed circle in the centre. A little closer.".into(),
            "close" => "Sit as you normally do and look at the dashed circle in the centre. A little further back.".into(),
            _ => "Sit as you normally do and look at the dashed circle in the centre. Hold still a moment.".into(),
        },
        Step::Range => "Now move your head all the way round, slowly, keeping the screen just in view: left, up, right, down, and back to the centre.".into(),
        Step::Path => "Follow the dashed circle with your head and keep the dot inside it. It waits for you.".into(),
        Step::Hold(i) => format!("Hold the dot in the circle: {}.", POSE_HINTS[POSES.iter().position(|p| *p == HOLD_ZONES[i]).unwrap_or(0)]),
        Step::Verify => "Look at the camera.".into(),
        Step::Bridge => "Next we record how you nod and how you shake your head, and make sure ordinary movement is never mistaken for either. Nothing here is an image.".into(),
        Step::Round(i) => round_at(i).map(|(r, _)| r.prompt.to_string()).unwrap_or_default(),
    }
}

/// Where a session started at decides where it ends: a first enrolment
/// runs the looks and the rounds, Add Look stops after verify, Tune
/// Gestures runs the rounds alone.
pub(super) fn last_step(start: Option<&str>) -> Step {
    match start.unwrap_or("welcome") {
        "distance" | "centre" | "path" | "hold" => Step::Verify,
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
mod tests {
    use super::*;

    #[test]
    fn the_steps_run_in_order_and_end_at_verify() {
        let mut s = Step::from_start(None);
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
            "a first enrolment runs every round"
        );
        assert_eq!(
            Step::from_start(Some("bridge")),
            Step::Bridge,
            "Tune Gestures starts at the bridge"
        );
        assert_eq!(
            Step::from_start(Some("distance")),
            Step::Centre,
            "Add Look starts at the centre screen"
        );
        #[cfg(feature = "dev-tools")]
        {
            assert_eq!(Step::from_start(Some("record")), Step::Record);
            assert_eq!(
                Step::Record.next(),
                None,
                "a recording stores nothing and leads nowhere"
            );
        }
        #[cfg(not(feature = "dev-tools"))]
        assert_eq!(
            Step::from_start(Some("record")),
            Step::Welcome,
            "without dev-tools there is no record mode"
        );
    }
}
