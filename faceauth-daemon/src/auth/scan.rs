//! What a scan will score: a face near enough to judge, measured through
//! the flash gate before it is embedded. The attempt and the confirm apply
//! the same rule, so it lives here once.

use super::outcome::Outcome;
use crate::consent::Answer;
use anyhow::Result;
use faceauth_engine::Pipeline;

/// What a gated pair gave at the face: detected first, measured through
/// the gate, and embedded only on a pass (J8).
pub(crate) enum Gated {
    NoFace,
    NoSignal,
    Denied(String),
    /// The face, with its embedding.
    Pass(faceauth_engine::Face),
}

/// The narrowest face, as a fraction of the frame's shorter side, that an
/// attempt scores (40 px on a 480 px side). Measured on the reference
/// laptop on 2026-09-24 with the cutoff off, moving back and forth: every
/// attempt matched at 40 px and nearer (0.75 to 0.95), 35 to 39 px was
/// marginal (0.65 to 0.73), 30 to 34 px missed although the flash still
/// read, and under 30 px the gate refused. The limit is the face's detail,
/// not light: exposure was at its maximum from about 50 px out. The line
/// sits a little inside the measured limit (distance-20260924.txt in the
/// development tree's fa-build). 60 px was tried first and discarded most
/// frames at an ordinary sitting-back distance, so consent never matched
/// and nods never armed. A face under this is treated as no face: never scored, so never a
/// match and never charged against the five-a-minute rule, and the lock
/// screen's probe does not wake the panel for it.
pub const SCAN_MIN_FACE_FRAC: f32 = 0.084;

/// The cutoff in force: `SCAN_MIN_FACE_FRAC`, or in a development build
/// `FACEAUTH_DEV_SCAN_MIN_FRAC` from the environment, for measuring where
/// the camera stops reading a face.
pub fn scan_min_frac() -> f32 {
    #[cfg(feature = "dev-tools")]
    if let Some(v) = std::env::var("FACEAUTH_DEV_SCAN_MIN_FRAC")
        .ok()
        .and_then(|v| v.parse::<f32>().ok())
    {
        return v;
    }
    SCAN_MIN_FACE_FRAC
}

/// Is a face `face_w` pixels wide, in a `w` by `h` frame, near enough to
/// judge?
pub fn scannable(face_w: f32, w: usize, h: usize) -> bool {
    face_w >= scan_min_frac() * w.min(h) as f32
}

/// Detect the face in a pair's lit frame (the best one, or, with `follow`,
/// only a detection that continues that box), put the pair through the
/// gate at it, and embed it only when the gate passed.
pub(crate) fn gated_face(
    gate: &crate::strobe::StrobeGate<'_>,
    pipeline: &mut Pipeline,
    pair: &crate::strobe::Pair,
    min_detection: f32,
    follow: Option<[f32; 4]>,
) -> Result<Gated> {
    use crate::strobe::Gate;
    let mut faces = pipeline.detector.detect(&pair.lit, min_detection)?;
    faces.sort_by(|a, b| b.score.total_cmp(&a.score));
    let Some(mut face) = faces.into_iter().next() else {
        return Ok(Gated::NoFace);
    };
    if let Some(tracked) = follow {
        // The embedded face must be the followed one, not whichever scored best.
        if crate::consent::track(std::slice::from_ref(&face), tracked)
            != crate::consent::Track::Found(0)
        {
            log::debug!("confirm: the scored face is not the followed box");
            return Ok(Gated::NoFace);
        }
    }
    if !scannable(face.bbox[2], pair.lit.width, pair.lit.height) {
        log::debug!("gate: face {:.0} px wide, too far to judge", face.bbox[2]);
        return Ok(Gated::NoFace);
    }
    match gate.judge(pair, &face)? {
        Gate::Pass(fr) => {
            if let Some(fr) = fr {
                log::debug!("gate: pass {:?}", fr);
            }
        }
        Gate::NoSignal(fr) => {
            log::debug!("gate: no signal {:?}", fr);
            return Ok(Gated::NoSignal);
        }
        Gate::Denied(why, fr) => {
            log::debug!("gate: denied {} {:?}", why, fr);
            return Ok(Gated::Denied(why));
        }
    }
    let crop = faceauth_engine::align::align_112(&pair.lit, &face.landmarks);
    face.embedding = Some(pipeline.embedder.embed(&crop)?);
    Ok(Gated::Pass(face))
}

/// How a scan ended: with the camera's verdict, or with an answer from
/// the consent window that arrived before the face matched.
pub enum Scan {
    Done(Outcome),
    Answered(Answer),
}

#[cfg(test)]
mod scannable_tests {
    use super::*;

    /// On the reference camera's 640x480 frames: ordinary sitting (78 to
    /// 96 px) and the measured reliable range down to 40 px are judged; the
    /// marginal 35 to 39 px and beyond are not; the rule follows the
    /// frame's shorter side.
    #[test]
    fn a_face_too_far_to_judge_is_not_scanned() {
        assert!(scannable(78.0, 640, 480));
        assert!(scannable(40.4, 640, 480));
        assert!(!scannable(39.0, 640, 480));
        assert!(!scannable(35.0, 640, 480));
        assert!(scannable(81.0, 1280, 960));
        assert!(!scannable(80.0, 1280, 960));
    }
}
