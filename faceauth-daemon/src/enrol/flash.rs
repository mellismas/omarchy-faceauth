//! The flash gate during enrollment (round-4 A6): one strobed pair at the
//! followed face at the center step and at each hold, through the gate the
//! scan, the confirm and the presence look read their pairs from. A print
//! or a screen is refused there, and the refusal ends the session, so it
//! cannot enroll. Between checks the illuminator is steady, as the rest of
//! the walk-through needs it: the gate writes its random mask when a check
//! starts and puts steady light back when it ends.

use super::follow::TRACK_GAP;
use crate::capture::IrCapture;
use crate::consent::{track, Track};
use crate::strobe::{Gate, StrobeGate, Took};
use anyhow::Result;
use faceauth_engine::Face;
use std::time::{Duration, Instant};

/// How long one check looks for a pair: the presence look's window, which
/// the settle after the mask, the phase lock and a dropped frame fit in.
const FLASH_WINDOW: Duration = Duration::from_millis(2000);

/// How many checks in a row may end with no reading before the session
/// gives up: a face the flash cannot read at a look does not hold the
/// person at that look until the session's time runs out.
pub(super) const FLASH_TRIES: usize = 5;

/// What the person is told when the gate refuses. A verdict, never the
/// measurements behind it (D6).
pub(super) const REFUSED: &str =
    "The camera's flash check says this is not a live face, so nothing was enrolled.";

/// What the person is told when the flash could not be read at a look
/// `FLASH_TRIES` times.
pub(super) const UNREAD: &str =
    "The camera's flash check could not read your face at this look, so nothing was enrolled. Sit a little closer and try again.";

/// Where the followed face was last seen in the check's frames, and when:
/// the walk follows it on from there, and a box it never saw again does
/// not come back with a fresh time.
pub(super) type Seen = ([f32; 4], Instant);

#[derive(Debug)]
pub(super) enum Flash {
    /// A pair at the followed face passed: a live face, seen there then.
    Live(Seen),
    /// The gate refused a pair at the followed face; the journal says
    /// why.
    Refused,
    /// No pair at the followed face gave a verdict in the window; where
    /// and when the check last saw it, unless it lost it.
    Unread(Option<Seen>),
    /// Another face came into view: the check ends with no pass, and the
    /// walk reads the frames until one face is left before a new check
    /// starts at the followed face. Where one of the faces plainly
    /// continued the followed face, if one did.
    Crowd(Option<Seen>),
}

/// What the check does with a lit frame's faces.
#[derive(Debug, PartialEq)]
enum InCheck {
    /// No face, inside the follow's gap: nothing to judge.
    Nothing,
    /// The followed face alone, continuing its box: the pair is judged at
    /// it.
    Judge,
    /// One face, not continuing the followed face's box, or no face for
    /// longer than the follow's gap: the followed face is lost.
    Lost,
    /// More than one face: the check ends. Whether one of them plainly
    /// continued the followed face's box.
    Crowd { continued: bool },
}

/// The followed face during a check: its box and when a frame last showed
/// it there.
struct InView {
    bbox: [f32; 4],
    at: Instant,
}

impl InView {
    /// Read a lit frame's faces at `now`. The followed face moves on only
    /// where a face plainly continues its box, alone or in a crowd, the way
    /// the walk's own reading keeps a track. With no face for longer than
    /// `TRACK_GAP` it is lost, as it would be between two of the walk's
    /// frames: nobody takes the chair at the same place and size inside the
    /// gap, and past it the face is identified again before anything counts.
    fn read(&mut self, faces: &[Face], now: Instant) -> InCheck {
        match (faces.len(), track(faces, self.bbox)) {
            (0, _) if now.saturating_duration_since(self.at) > TRACK_GAP => InCheck::Lost,
            (0, _) => InCheck::Nothing,
            (n, Track::Found(i)) => {
                self.bbox = faces[i].bbox;
                self.at = now;
                if n == 1 {
                    InCheck::Judge
                } else {
                    InCheck::Crowd { continued: true }
                }
            }
            (1, _) => InCheck::Lost,
            _ => InCheck::Crowd { continued: false },
        }
    }

    fn seen(&self) -> Seen {
        (self.bbox, self.at)
    }
}

/// What the check does after one of the gate's frames.
#[derive(Debug, PartialEq)]
enum Next {
    /// Nothing to judge on this frame; read the next.
    Read,
    /// Judge the pair at the followed face.
    Judge,
    /// The followed face is lost.
    Lost,
    /// Another face came into view: the check ends.
    Crowd(Option<Seen>),
}

/// One frame of the check: its faces at `now`, and whether it completes a
/// pair. Every frame moves the followed face on, pair or not, so a check
/// whose pairs are slow to form (a faint flash) still keeps its face
/// within the follow's gap and hands it back seen, not lost; only a pair
/// is judged.
fn on_frame(view: &mut InView, faces: &[Face], now: Instant, pair: bool) -> Next {
    match view.read(faces, now) {
        InCheck::Judge if pair => Next::Judge,
        InCheck::Nothing | InCheck::Judge => Next::Read,
        InCheck::Lost => Next::Lost,
        InCheck::Crowd { continued } => Next::Crowd(continued.then(|| view.seen())),
    }
}

/// One check at the face followed at `followed`, seen there now. Only a
/// lit frame with that face alone in it, continuing its box, is judged: a
/// pair taken with two in view, or at another face, says nothing about the
/// face being enrolled. The face is followed on every frame the gate
/// takes, a pair or not. A frame with two in view ends the check
/// (`Flash::Crowd`) rather than being skipped with the old box kept, and
/// frames with no face for longer than the follow's gap lose the face. On
/// a camera without the strobe the gate runs ungated and passes; the
/// caller has refused that already unless the administrator allowed it.
pub(super) fn check(
    cap: &mut IrCapture,
    detector: &mut faceauth_engine::detect::YuNet,
    min_detection: f32,
    followed: [f32; 4],
) -> Result<Flash> {
    let strobe = cap.tier().gated();
    let mut gate = StrobeGate::start(cap, strobe)?;
    gate.focus_on(followed);
    let t0 = Instant::now();
    let mut view = Some(InView {
        bbox: followed,
        at: t0,
    });
    let (mut pairs, mut faint) = (0usize, 0usize);
    while t0.elapsed() < FLASH_WINDOW {
        let Some(v) = view.as_mut() else { break };
        // Every frame is looked at, the ones that complete no pair too.
        let (faces, pair) = match gate.next_frame_seen(Duration::from_millis(200))? {
            Took::Nothing => continue,
            Took::Frame(img) => (detector.detect(img, min_detection)?, None),
            Took::Pair(pair) => (detector.detect(&pair.lit, min_detection)?, Some(pair)),
        };
        match on_frame(v, &faces, Instant::now(), pair.is_some()) {
            Next::Read => {
                gate.focus_on(v.bbox);
                continue;
            }
            Next::Judge => {}
            Next::Lost => {
                // The followed face gone, or somewhere else: this check
                // says nothing more, and the walk identifies it again.
                view = None;
                continue;
            }
            Next::Crowd(seen) => {
                log::info!("enrollment flash check: another face in view; the check ends");
                return Ok(Flash::Crowd(seen));
            }
        }
        let Some(pair) = pair else { continue };
        gate.focus_on(v.bbox);
        pairs += 1;
        match gate.judge(&pair, &faces[0])? {
            Gate::Pass(fr) => {
                log::debug!("enrollment flash check: pass, pair {} {:?}", pairs, fr);
                return Ok(Flash::Live(v.seen()));
            }
            Gate::NoSignal(fr) => {
                faint += 1;
                log::debug!("enrollment flash check: no signal {:?}", fr);
            }
            Gate::Denied(why, fr) => {
                log::info!("enrollment flash check: refused ({})", why);
                log::debug!("enrollment flash check: refused {:?}", fr);
                return Ok(Flash::Refused);
            }
        }
    }
    log::info!(
        "enrollment flash check: no reading in {} ms: {} frames, {} pairs, {} too faint, the frames {} the mask{}",
        t0.elapsed().as_millis(),
        gate.frames(),
        pairs,
        faint,
        if gate.locked() { "followed" } else { "never followed" },
        if view.is_none() { ", the followed face was lost" } else { "" }
    );
    Ok(Flash::Unread(view.map(|v| v.seen())))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn face_at(x: f32, y: f32, w: f32) -> Face {
        Face {
            bbox: [x, y, w, w * 1.2],
            score: 0.9,
            landmarks: [[0.0; 2]; 5],
            embedding: None,
        }
    }

    /// A6: during the check a pair is judged only at the followed face
    /// alone. A frame with a second face ends the check with no pass,
    /// handing back the followed face's box only where one of the faces
    /// plainly continues it; the old box is never kept across the crowd
    /// for a single face to be taken at later.
    #[test]
    fn a_second_face_during_the_flash_check_ends_it_with_no_pass() {
        let t0 = Instant::now();
        let view = || InView {
            bbox: [200.0, 150.0, 90.0, 108.0],
            at: t0,
        };
        let me = face_at(204.0, 152.0, 91.0);
        let other = face_at(420.0, 160.0, 85.0);
        assert_eq!(view().read(&[], t0), InCheck::Nothing);
        assert_eq!(view().read(std::slice::from_ref(&me), t0), InCheck::Judge);
        assert_eq!(view().read(std::slice::from_ref(&other), t0), InCheck::Lost);
        let mut v = view();
        assert_eq!(
            v.read(&[other.clone(), me.clone()], t0),
            InCheck::Crowd { continued: true }
        );
        assert_eq!(v.bbox, me.bbox);
        // Two faces crossing at the followed face's place: neither plainly
        // continues it.
        let close = face_at(210.0, 150.0, 90.0);
        assert_eq!(
            view().read(&[me, close], t0),
            InCheck::Crowd { continued: false }
        );
        assert_eq!(
            view().read(&[other, face_at(40.0, 40.0, 80.0)], t0),
            InCheck::Crowd { continued: false }
        );
    }

    /// A6: a check whose pairs never form (a faint flash) follows its face
    /// on the frames that are no pair, so at its end the face is handed
    /// back as seen on the last of them, within the follow's gap, not lost;
    /// only a pair is judged.
    #[test]
    fn a_check_that_forms_no_pair_keeps_its_face() {
        let t0 = Instant::now();
        let here = face_at(200.0, 150.0, 90.0);
        let mut v = InView {
            bbox: here.bbox,
            at: t0,
        };
        let mut last = t0;
        // Two seconds of frames at 30 a second, none of them a pair.
        for n in 1..=60u64 {
            last = t0 + Duration::from_millis(33 * n);
            assert_eq!(
                on_frame(&mut v, std::slice::from_ref(&here), last, false),
                Next::Read,
                "frame {}",
                n
            );
        }
        assert_eq!(v.seen(), (here.bbox, last), "seen on the last frame");
        assert_eq!(
            on_frame(&mut v, std::slice::from_ref(&here), last, true),
            Next::Judge
        );
        assert_eq!(
            on_frame(&mut v, &[], last + TRACK_GAP / 2, true),
            Next::Read
        );
        assert_eq!(
            on_frame(&mut v, &[], last + TRACK_GAP * 2, false),
            Next::Lost
        );
    }

    /// A6: the check follows its face under the walk's own gap. Frames
    /// with no face in them keep the box only for `TRACK_GAP`, and the box
    /// keeps the time a frame last showed the face there: a face that sits
    /// down in the same place after the gap is lost, not judged, and a box
    /// handed back after frames with no face is not stamped as fresh.
    #[test]
    fn frames_with_no_face_past_the_gap_lose_the_face_in_the_check() {
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        let here = face_at(200.0, 150.0, 90.0);
        let mut v = InView {
            bbox: here.bbox,
            at: t0,
        };
        assert_eq!(v.read(&[], at(300)), InCheck::Nothing);
        assert_eq!(v.seen(), (here.bbox, t0), "the box keeps its own time");
        assert_eq!(v.read(&[], at(450)), InCheck::Nothing);
        assert_eq!(v.read(std::slice::from_ref(&here), at(480)), InCheck::Judge);
        assert_eq!(v.seen(), (here.bbox, at(480)));
        assert_eq!(v.read(&[], at(900)), InCheck::Nothing);
        assert_eq!(
            v.read(&[], at(480) + TRACK_GAP + Duration::from_millis(1)),
            InCheck::Lost
        );
        let mut v = InView {
            bbox: here.bbox,
            at: t0,
        };
        assert_eq!(v.read(&[], at(700)), InCheck::Lost, "gone past the gap");
    }
}
