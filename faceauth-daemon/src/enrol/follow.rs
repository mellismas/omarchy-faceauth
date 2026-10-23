//! Whose face the walk-through reads (round-4 A6). One face in view at a
//! time; the face the center step learns is followed frame to frame with
//! the tracker the consent window uses; and once the track is lost,
//! nothing counts until a face returns whose embedding matches the
//! session's reference at the accept threshold. Every step that takes a
//! template, moves the path, times a hold, verifies or records a round
//! reads its face through here, and so does the terminal enrollment.
//! Verify's two rules are here too: the new templates must work, and they
//! must be the face the session began with.

use crate::consent::{track, Track};
use crate::store::Template;
use anyhow::Result;
use faceauth_engine::{cosine, Face};
use std::time::{Duration, Instant};

/// How long the followed box outlives frames with no face in them. A
/// turned head or a blink can cost the detector a few frames; nobody takes
/// the chair at the same place and size in that time, and past it the
/// face is identified again before anything counts.
pub(super) const TRACK_GAP: Duration = Duration::from_millis(500);

/// How often a face nobody follows is embedded to see whether it is the
/// one the session began with: a stranger in the chair costs an embedding
/// four times a second, not on every frame.
pub(super) const IDENTIFY_EVERY: Duration = Duration::from_millis(250);

/// How far under the accept threshold a new template may score against
/// the session's reference and still be the same face at another look.
/// The reference is the center step's straight look; the path and the
/// holds turn the head as far as the ring, which costs a genuine face
/// similarity against a straight look, while different people sit around
/// 0.1 to 0.3 on this model. The same reasoning and the same figure as the
/// nod frames' `NOD_FRAME_SLACK`. Provisional: not measured on a corpus;
/// scoring the A6 recordings' turned frames against their straight ones
/// is what would set it. Templates taken looking straight
/// at the camera (`straight_on`) get no slack.
pub(super) const REFERENCE_SLACK: f32 = 0.30;

/// A template is straight on (`straight_on`) only when it was taken for
/// the center look, its turn reads within this on the five-point pose (the
/// terminal enrollment's center band), and its pitch on the mesh within
/// `STRAIGHT_PITCH_DEG` of the person's level. The five-point pitch cannot
/// say level: a lid camera looks up at the face, so a chin-up barely moves
/// it, where the mesh reads a chin-up straight at the camera as -31
/// degrees (measured 2026-09-23). The band is under the least chin-up the
/// up hold takes (its ring is 10 degrees at the least, and the dot is on
/// it within 0.35 of that) and over the center step's own stillness.
pub(super) const STRAIGHT_YAW: f32 = 0.12;
pub(super) const STRAIGHT_PITCH_DEG: f32 = 6.0;

/// Verify's tripwire for drops concentrated in one stretch: this many new
/// templates in a row, in the order taken, under their floor fail the
/// set. A genuine turned look scores low at the far end of the person's
/// reach, one or two frames at a time as the path passes it (a hold's
/// three are the half-a-look rule's); three in a row, half a second apart
/// or more, is a face under the dot for over a second that was not the
/// one the session began with, which is what someone sitting in leaves.
pub(super) const DROP_RUN: usize = 3;

/// Why a frame gives the steps no face.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Pause {
    NoFace,
    /// More than one face above the detection floor: nothing is taken and
    /// nothing moves until one is left.
    Crowd,
    /// One face, not the followed one, and not identified as the face the
    /// session began with.
    NotTheFace,
}

impl Pause {
    pub(super) fn message(self) -> &'static str {
        match self {
            Pause::NoFace => "No face in view. Sit facing the screen.",
            Pause::Crowd => "Only one face in view, please.",
            Pause::NotTheFace => "Look straight at the camera so it can find you again.",
        }
    }
}

/// The face a frame gives the steps.
#[derive(Debug)]
pub(super) enum Read {
    /// The followed face, continuing its box or identified again.
    Followed(Face),
    /// A face taken on while the center step learns whose the session is:
    /// whatever the step learned from a face before goes.
    Adopted(Face),
}

#[derive(Default)]
pub(super) struct Follow {
    /// The face the session began with, as embeddings: the center step's
    /// still frames, or, in a session that starts at the Bridge, the
    /// templates the user holds on this camera.
    reference: Vec<Vec<f32>>,
    /// The followed face's box, and when it was last seen.
    tracked: Option<([f32; 4], Instant)>,
    /// When a face nobody follows was last embedded.
    tried: Option<Instant>,
}

impl Follow {
    pub(super) fn set_reference(&mut self, reference: Vec<Vec<f32>>) {
        self.reference = reference;
    }

    pub(super) fn reference(&self) -> &[Vec<f32>] {
        &self.reference
    }

    pub(super) fn has_reference(&self) -> bool {
        !self.reference.is_empty()
    }

    /// The camera stopped: whoever is in the chair when it opens again is
    /// identified before anything counts.
    pub(super) fn lose(&mut self) {
        self.tracked = None;
    }

    /// The followed face was seen at `bbox` at `at`, on frames the steps
    /// did not read (the flash gate's). `at` is when those frames showed
    /// it, never later, so the gap after it runs from there.
    pub(super) fn seen_at(&mut self, bbox: [f32; 4], at: Instant) {
        if self.tracked.is_some() {
            self.tracked = Some((bbox, at));
        }
    }

    /// The face in `faces` (the detections above the floor) that the steps
    /// may read at `now`. While the center step is `learning` whose face
    /// the session is, a single face nobody follows is taken on. Otherwise
    /// such a face is embedded by `embed` and counts only when it matches
    /// the reference at `threshold`.
    pub(super) fn read(
        &mut self,
        mut faces: Vec<Face>,
        now: Instant,
        learning: bool,
        threshold: f32,
        embed: impl FnOnce(&Face) -> Result<Vec<f32>>,
    ) -> Result<std::result::Result<Read, Pause>> {
        let followed = self
            .tracked
            .filter(|(_, at)| now.saturating_duration_since(*at) <= TRACK_GAP)
            .map(|(b, _)| b);
        if faces.len() > 1 {
            // The followed face keeps its track through a crowd only where
            // one of the faces plainly continues it; nothing is read.
            self.tracked = match followed.map(|b| track(&faces, b)) {
                Some(Track::Found(i)) => Some((faces[i].bbox, now)),
                _ => None,
            };
            return Ok(Err(Pause::Crowd));
        }
        let Some(face) = faces.pop() else {
            return Ok(Err(Pause::NoFace));
        };
        if let Some(b) = followed {
            if track(std::slice::from_ref(&face), b) == Track::Found(0) {
                self.tracked = Some((face.bbox, now));
                return Ok(Ok(Read::Followed(face)));
            }
        }
        self.tracked = None;
        if learning {
            self.tracked = Some((face.bbox, now));
            return Ok(Ok(Read::Adopted(face)));
        }
        if self
            .tried
            .is_some_and(|t| now.saturating_duration_since(t) < IDENTIFY_EVERY)
        {
            return Ok(Err(Pause::NotTheFace));
        }
        self.tried = Some(now);
        let e = embed(&face)?;
        if likeness(&e, &self.reference).is_some_and(|s| s >= threshold) {
            self.tracked = Some((face.bbox, now));
            return Ok(Ok(Read::Followed(face)));
        }
        Ok(Err(Pause::NotTheFace))
    }
}

/// The best similarity of `e` to any of `set`.
fn likeness(e: &[f32], set: &[Vec<f32>]) -> Option<f32> {
    set.iter().map(|r| cosine(r, e)).max_by(f32::total_cmp)
}

/// Verify's look: a live frame of the followed face counts when it matches
/// the new templates at the threshold, which proves they work, and the
/// reference too, which keeps it the face the session began with.
pub(super) fn verify_hit(
    e: &[f32],
    new: &[&Template],
    reference: &[Vec<f32>],
    threshold: f32,
) -> bool {
    let works = new
        .iter()
        .map(|t| cosine(&t.embedding, e))
        .max_by(f32::total_cmp)
        .is_some_and(|s| s >= threshold);
    works && likeness(e, reference).is_some_and(|s| s >= threshold)
}

/// Was a template taken straight on? Only for the center look (`zone`),
/// with its five-point `turn` within `STRAIGHT_YAW` and its mesh
/// `pitch_deg` within `STRAIGHT_PITCH_DEG` of the person's `level_deg`.
/// Decided as the template is taken, from the readings of its frame: the
/// up hold, the path's upper arc and a chin-up that slipped into the
/// center all get the turned slack.
pub(super) fn straight_on(zone: &str, turn: f32, pitch_deg: f32, level_deg: f32) -> bool {
    zone == "centre"
        && turn.abs() <= STRAIGHT_YAW
        && (pitch_deg - level_deg).abs() <= STRAIGHT_PITCH_DEG
}

/// A new template as verify reads it: whether it was taken straight on
/// (`straight_on`), and the look or step that took it, by the name the
/// person is told.
pub(super) struct New<'a> {
    pub t: &'a Template,
    pub straight: bool,
    pub look: &'a str,
}

/// Verify's rule on the new set: every template kept is the face the
/// session began with. A template taken straight on must match the
/// reference at the threshold, any other within `REFERENCE_SLACK` of it.
/// One that does not is dropped and never stored; the places of those to
/// drop, in `new`'s order, are the answer. The tripwires fail the whole
/// set instead, since past them it is no longer a turned look scoring low:
/// a straight-on template that does not match; more than half of any one
/// look's templates dropped; `DROP_RUN` dropped in a row; or more than a
/// quarter of the whole set. The new looks are then kept as one face's or
/// not at all. The error names the look, never a score.
pub(super) fn new_set_is_the_face(
    new: &[New],
    reference: &[Vec<f32>],
    threshold: f32,
) -> std::result::Result<Vec<usize>, String> {
    if new.is_empty() {
        return Err("no templates were taken".into());
    }
    if reference.is_empty() {
        return Err("the session has no reference face".into());
    }
    let mut dropped = Vec::new();
    let mut run = 0;
    for (i, n) in new.iter().enumerate() {
        let floor = if n.straight {
            threshold
        } else {
            threshold - REFERENCE_SLACK
        };
        if likeness(&n.t.embedding, reference).is_some_and(|s| s >= floor) {
            run = 0;
            continue;
        }
        if n.straight {
            return Err(format!(
                "a straight-on template of the {} is not the face the session began with",
                super::steps::zone_word(n.look)
            ));
        }
        run += 1;
        if run >= DROP_RUN {
            return Err(format!(
                "{} templates in a row, up to the {}, are not the face the session began with",
                run, n.look
            ));
        }
        dropped.push(i);
    }
    for (look, lost, of) in losses(new, &dropped) {
        if lost * 2 > of {
            return Err(format!(
                "the {} lost {} of its {} templates: not the face the session began with",
                look, lost, of
            ));
        }
    }
    if dropped.len() * 4 > new.len() {
        return Err(format!(
            "{} of the {} new templates are not the face the session began with",
            dropped.len(),
            new.len()
        ));
    }
    Ok(dropped)
}

/// The looks that lost templates to verify, in the order taken: each
/// look's name, how many it lost and how many it took.
pub(super) fn losses<'a>(new: &[New<'a>], dropped: &[usize]) -> Vec<(&'a str, usize, usize)> {
    let mut out: Vec<(&str, usize, usize)> = Vec::new();
    for (i, n) in new.iter().enumerate() {
        let lost = dropped.contains(&i) as usize;
        match out.iter_mut().find(|(look, _, _)| *look == n.look) {
            Some(e) => {
                e.1 += lost;
                e.2 += 1;
            }
            None => out.push((n.look, lost, 1)),
        }
    }
    out.retain(|(_, lost, _)| *lost > 0);
    out
}

/// What the person is told about the looks verify dropped templates from,
/// for the closing message and the journal; None when it dropped none.
pub(super) fn losses_said(new: &[New], dropped: &[usize]) -> Option<String> {
    let each: Vec<String> = losses(new, dropped)
        .iter()
        .map(|(look, lost, of)| format!("the {} lost {} of {}", look, lost, of))
        .collect();
    (!each.is_empty()).then(|| {
        format!(
            "Some templates were not kept, as not clearly the face the enrollment began with: {}.",
            each.join(", ")
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const THRESHOLD: f32 = 0.70;

    fn face_at(x: f32, y: f32, w: f32) -> Face {
        Face {
            bbox: [x, y, w, w * 1.2],
            score: 0.9,
            landmarks: [[0.0; 2]; 5],
            embedding: None,
        }
    }

    fn unit(v: &[f32]) -> Vec<f32> {
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        v.iter().map(|x| x / n).collect()
    }

    /// The person who began, and someone else: 0.1 apart on this model's
    /// scale, the way different identities score.
    fn person() -> Vec<f32> {
        unit(&[1.0, 0.0, 0.0])
    }

    fn stranger() -> Vec<f32> {
        unit(&[0.1, 1.0, 0.0])
    }

    fn template(e: Vec<f32>, label: &str) -> Template {
        Template {
            embedding: e,
            quality: 0.9,
            face_width: 90.0,
            created: 0,
            label: label.into(),
            device: "test-camera".into(),
            yaw: None,
            nose_pitch: None,
        }
    }

    /// A6: a frame with two faces in view takes no template and moves
    /// nothing, whichever of them is the followed one, and the templates a
    /// hold takes come only from frames with the followed face alone. The
    /// hold here is a run of frames at the right place, as the walk reads
    /// them: a template for every frame the steps are given a face.
    #[test]
    fn two_faces_in_a_frame_take_no_template() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let mut f = Follow::default();
        let me = || face_at(200.0, 150.0, 90.0);
        let other = || face_at(420.0, 160.0, 85.0);
        // The center step takes the one face on and learns it.
        assert!(matches!(
            f.read(vec![me()], at(0), true, THRESHOLD, |_| Ok(person()))
                .unwrap(),
            Ok(Read::Adopted(_))
        ));
        f.set_reference(vec![person()]);
        let frames: Vec<Vec<Face>> = vec![
            vec![me()],
            vec![me(), other()],
            vec![other(), me()],
            vec![me()],
            vec![me(), other()],
            vec![me()],
        ];
        let mut taken = 0;
        for (n, faces) in frames.into_iter().enumerate() {
            let two = faces.len() > 1;
            let read = f
                .read(faces, at(100 + 33 * n as u64), false, THRESHOLD, |_| {
                    panic!("the followed face is never embedded to be told apart")
                })
                .unwrap();
            match read {
                Ok(Read::Followed(face)) => {
                    assert!(!two, "frame {}: a crowd gave the steps a face", n);
                    assert_eq!(face.bbox, me().bbox);
                    taken += 1;
                }
                Ok(Read::Adopted(_)) => panic!("frame {}: adopted outside the center step", n),
                Err(p) => {
                    assert!(two, "frame {}: {:?} with one face", n, p);
                    assert_eq!(p, Pause::Crowd);
                }
            }
        }
        assert_eq!(taken, 3, "one template per frame with one face");
        assert_eq!(Pause::Crowd.message(), "Only one face in view, please.");
    }

    /// A6: once the followed face is lost, nothing is read until a face
    /// matches the session's reference; a different face never resumes
    /// it, however long it sits there or wherever it sits, and the person
    /// who began does.
    #[test]
    fn a_lost_track_pauses_taking_and_a_different_face_never_resumes_it() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let mut f = Follow::default();
        f.set_reference(vec![person()]);
        let here = face_at(200.0, 150.0, 90.0);
        // Identified once, then followed without another embedding.
        assert!(matches!(
            f.read(
                vec![here.clone()],
                at(0),
                false,
                THRESHOLD,
                |_| Ok(person())
            )
            .unwrap(),
            Ok(Read::Followed(_))
        ));
        assert!(matches!(
            f.read(
                vec![face_at(206.0, 152.0, 91.0)],
                at(33),
                false,
                THRESHOLD,
                |_| { panic!("a face continuing the box is not embedded") }
            )
            .unwrap(),
            Ok(Read::Followed(_))
        ));
        // A face somewhere else: the track is lost, and the stranger is
        // refused wherever and however long they sit.
        let mut embedded = 0;
        for (n, place) in [
            (420.0, 160.0),
            (206.0, 152.0),
            (206.0, 152.0),
            (210.0, 150.0),
        ]
        .into_iter()
        .enumerate()
        {
            let r = f
                .read(
                    vec![face_at(place.0, place.1, 90.0)],
                    at(300 + 300 * n as u64),
                    false,
                    THRESHOLD,
                    |_| {
                        embedded += 1;
                        Ok(stranger())
                    },
                )
                .unwrap();
            assert!(
                matches!(r, Err(Pause::NotTheFace)),
                "frame {}: the stranger was read: {:?}",
                n,
                r
            );
        }
        assert_eq!(
            embedded, 4,
            "each look at the stranger was an identification"
        );
        // A frame between identifications is refused without an embedding.
        assert!(matches!(
            f.read(vec![here.clone()], at(1210), false, THRESHOLD, |_| {
                panic!("identified again inside IDENTIFY_EVERY")
            })
            .unwrap(),
            Err(Pause::NotTheFace)
        ));
        // The person who began comes back: read again.
        assert!(matches!(
            f.read(vec![here.clone()], at(1500), false, THRESHOLD, |_| Ok(
                person()
            ))
            .unwrap(),
            Ok(Read::Followed(_))
        ));
        // A face gone for longer than the gap is identified again even at
        // the same place: the stranger who sits down there is refused.
        assert!(matches!(
            f.read(Vec::new(), at(1600), false, THRESHOLD, |_| unreachable!())
                .unwrap(),
            Err(Pause::NoFace)
        ));
        assert!(matches!(
            f.read(
                vec![here.clone()],
                at(1500 + 600),
                false,
                THRESHOLD,
                |_| Ok(stranger())
            )
            .unwrap(),
            Err(Pause::NotTheFace)
        ));
        // The camera stopping loses the track the same way: a moment
        // later, at the same place, the face is not simply followed on.
        assert!(matches!(
            f.read(vec![here.clone()], at(2500), false, THRESHOLD, |_| Ok(
                person()
            ))
            .unwrap(),
            Ok(Read::Followed(_))
        ));
        f.lose();
        assert!(matches!(
            f.read(vec![here], at(2533), false, THRESHOLD, |_| Ok(stranger()))
                .unwrap(),
            Err(Pause::NotTheFace)
        ));
    }

    /// A template of `look`, taken straight on or not.
    fn at(e: Vec<f32>, look: &str) -> Template {
        template(e, &format!("enrol-{}", look))
    }

    /// The new set as verify reads it: each template with whether it was
    /// taken straight on and its look's name.
    fn new_set<'a>(ts: &'a [(Template, bool)]) -> Vec<New<'a>> {
        ts.iter()
            .map(|(t, straight)| New {
                t,
                straight: *straight,
                look: &t.label[6..],
            })
            .collect()
    }

    /// An embedding that scores `c` against `person()`.
    fn scoring(c: f32) -> Vec<f32> {
        vec![c, 0.0, (1.0 - c * c).sqrt()]
    }

    /// A6: verify fails when a foreign embedding is in the new set straight
    /// on, where it has no slack to sit in, or when it fills more than half
    /// of a look; and a live look that matches the new set but not the
    /// reference is not a hit.
    #[test]
    fn a_foreign_embedding_in_the_new_set_fails_verify() {
        let reference = vec![person()];
        // A turned look of the same person: under the threshold against the
        // straight reference, inside the slack.
        let turned_look = unit(&[0.6, 0.0, 0.8]);
        let genuine = vec![
            (at(person(), "centre"), true),
            (at(unit(&[0.95, 0.05, 0.3]), "centre"), true),
            (at(turned_look.clone(), "left"), false),
            (at(turned_look.clone(), "left"), false),
        ];
        assert_eq!(
            new_set_is_the_face(&new_set(&genuine), &reference, THRESHOLD),
            Ok(vec![])
        );

        // Straight at the camera there is no slack: a straight-on look that
        // scores like the turned one is someone else, and fails the set.
        let mut with_centre = genuine.clone();
        with_centre.push((at(turned_look.clone(), "centre"), true));
        let why = new_set_is_the_face(&new_set(&with_centre), &reference, THRESHOLD).unwrap_err();
        assert!(
            why.contains("of the center") && !why.contains('.'),
            "{}",
            why
        );

        // Someone else at the right look, two of its three: past half a look.
        let mut with_foreign = genuine.clone();
        with_foreign.extend([
            (at(stranger(), "right"), false),
            (at(turned_look, "right"), false),
            (at(stranger(), "right"), false),
        ]);
        let why = new_set_is_the_face(&new_set(&with_foreign), &reference, THRESHOLD).unwrap_err();
        assert!(
            why.starts_with("the right lost 2 of its 3") && !why.contains('.'),
            "{}",
            why
        );
        assert!(new_set_is_the_face(&[], &reference, THRESHOLD).is_err());
        assert!(new_set_is_the_face(&new_set(&genuine), &[], THRESHOLD).is_err());

        let set: Vec<&Template> = genuine.iter().map(|(t, _)| t).collect();
        // A live look: the new set must work and the face must be the one
        // that began.
        assert!(verify_hit(&person(), &set, &reference, THRESHOLD));
        let theirs = [template(stranger(), "enrol-centre")];
        let theirs: Vec<&Template> = theirs.iter().collect();
        assert!(
            !verify_hit(&stranger(), &theirs, &reference, THRESHOLD),
            "a set of someone else's templates works for them, and is still refused"
        );
        assert!(!verify_hit(&person(), &theirs, &reference, THRESHOLD));
    }

    /// A6: a template the slack is for, whatever look it was labeled,
    /// scoring under its floor is dropped rather than failing the
    /// enrollment, and the looks that lost any are named. A turned template
    /// at the path's inner ring scoring 0.55 is inside the slack.
    #[test]
    fn a_turned_template_under_its_floor_is_dropped_not_the_enrolment() {
        let reference = vec![person()];
        let mut looks: Vec<(Template, bool)> = Vec::new();
        for zone in ["left", "right", "up", "down"] {
            for c in [0.60, 0.62, 0.58] {
                looks.push((at(scoring(c), zone), false));
            }
        }
        looks.push((at(person(), "centre"), true));
        looks.push((at(scoring(0.55), "centre"), false));
        assert_eq!(
            new_set_is_the_face(&new_set(&looks), &reference, THRESHOLD),
            Ok(vec![])
        );
        // One template at full reach of each of two looks, apart: dropped.
        looks[1].0.embedding = scoring(0.38);
        looks[7].0.embedding = scoring(0.38);
        let new = new_set(&looks);
        let dropped = new_set_is_the_face(&new, &reference, THRESHOLD).unwrap();
        assert_eq!(dropped, [1, 7]);
        assert_eq!(losses(&new, &dropped), [("left", 1, 3), ("up", 1, 3)]);
        let said = losses_said(&new, &dropped).unwrap();
        assert!(
            said.contains("the left lost 1 of 3, the up lost 1 of 3"),
            "{}",
            said
        );
        assert_eq!(losses_said(&new, &[]), None);
    }

    /// A6, the tripwires: dropping stays for a look that dips under its
    /// floor now and then, and a set fails when the drops are the pattern
    /// of someone else sitting in: more than half of one look, or
    /// `DROP_RUN` in a row across looks, even where each look keeps half.
    #[test]
    fn drops_past_half_a_look_or_in_a_run_fail_verify() {
        let reference = vec![person()];
        let low = || scoring(0.30);
        let fine = || scoring(0.60);
        // Two of a three-template hold: past half of it.
        let hold = vec![
            (at(person(), "centre"), true),
            (at(low(), "left"), false),
            (at(fine(), "left"), false),
            (at(low(), "left"), false),
            (at(fine(), "right"), false),
            (at(fine(), "right"), false),
            (at(fine(), "right"), false),
            (at(fine(), "up"), false),
            (at(fine(), "up"), false),
        ];
        let why = new_set_is_the_face(&new_set(&hold), &reference, THRESHOLD).unwrap_err();
        assert!(why.starts_with("the left lost 2 of its 3"), "{}", why);
        // Three in a row across two looks, each of which keeps half.
        let mut run = vec![(at(person(), "centre"), true)];
        for (zone, cs) in [
            ("path", [0.6, 0.6, 0.6, 0.6, 0.3, 0.3]),
            ("left", [0.3, 0.6, 0.6, 0.6, 0.6, 0.6]),
        ] {
            run.extend(cs.iter().map(|&c| (at(scoring(c), zone), false)));
        }
        let why = new_set_is_the_face(&new_set(&run), &reference, THRESHOLD).unwrap_err();
        assert!(
            why.starts_with("3 templates in a row, up to the left"),
            "{}",
            why
        );
        // The same three drops, apart: kept whole but for them.
        run.swap(6, 10);
        assert_eq!(
            new_set_is_the_face(&new_set(&run), &reference, THRESHOLD),
            Ok(vec![5, 7, 10])
        );
    }

    /// A6: straight on is never read off the five points alone. A chin-up
    /// reads level there (a lid camera looks up at the face) but not on the
    /// mesh, so it gets the slack; a template for the up look or any other
    /// but the center gets it whatever it reads; a level center look is
    /// held to the full threshold.
    #[test]
    fn a_chin_up_is_never_straight_on_whatever_the_five_points_read() {
        // The five points read level (turn 0.02); the mesh reads 20
        // degrees of chin-up against a level of 2.
        assert!(!straight_on("centre", 0.02, -18.0, 2.0));
        assert!(!straight_on("up", 0.02, 1.0, 2.0));
        assert!(!straight_on("left", 0.02, 2.0, 2.0));
        assert!(!straight_on("centre", 0.25, 2.0, 2.0), "half turned");
        assert!(straight_on("centre", 0.02, 5.0, 2.0));
        // A chin-up template scoring 0.55 against the straight reference:
        // with the slack, it stays.
        let reference = vec![person()];
        let chin_up = vec![
            (at(person(), "centre"), straight_on("centre", 0.0, 2.0, 2.0)),
            (
                at(scoring(0.55), "centre"),
                straight_on("centre", 0.02, -18.0, 2.0),
            ),
        ];
        assert_eq!(
            new_set_is_the_face(&new_set(&chin_up), &reference, THRESHOLD),
            Ok(vec![])
        );
    }
}
