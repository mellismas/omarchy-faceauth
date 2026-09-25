//! The checks after the nods: a live confirm on fresh strobed pairs, and
//! the identity check on the frames kept from the nod legs. Both run after
//! the gesture, so the nod detectors and their floors never see them.

use super::scan::{gated_face, Gated};
use crate::capture::IrCapture;
use crate::config::Config;
use crate::store::UserTemplates;
use anyhow::Result;
use faceauth_engine::{Grey, Pipeline};
use std::time::{Duration, Instant};

/// The confirm's verdict.
pub enum Confirm {
    /// Two strobed pairs passed the flash gate and matched the templates.
    Live,
    /// Every pair read no strobe signal: nothing to decide on.
    NoSignal,
    /// The gate refused, or the face did not match.
    Refused(String),
}

/// How long the confirm may take before it gives up.
const CONFIRM_SECONDS: f32 = 2.5;

/// The confirm's answer when its window ran out: refused only on two
/// pairs under the threshold (the same two strikes a pass takes);
/// otherwise nothing was decided, whether one good pair came, one weak
/// one, or none at all (J17). A gate denial ends the confirm before this
/// is asked.
pub fn confirm_at_timeout(failed: usize) -> Confirm {
    if failed >= 2 {
        Confirm::Refused("the face that nodded does not match".into())
    } else {
        Confirm::NoSignal
    }
}

/// After the nods: is the followed box a live, enrolled face right now?
/// The gate switches the illuminator to a fresh mask for the confirm and
/// freezes the exposure; lit frames are gated against their unlit
/// predecessor and embedded, and two pairs at or above the accept
/// threshold say yes. One gate refusal or two non-matches say no. Pairs
/// with no signal are skipped; if that is all there was, nothing is
/// decided.
pub fn confirm(
    cap: &mut IrCapture,
    pipeline: &mut Pipeline,
    cfg: &Config,
    templates: &UserTemplates,
    followed: [f32; 4],
) -> Result<Confirm> {
    if cap.illuminator.is_none() {
        // No strobe control: the scan already ran ungated under the
        // administrator's explicit setting, and so does this.
        return Ok(if cfg.liveness_required {
            Confirm::Refused("no strobe control".into())
        } else {
            Confirm::Live
        });
    }
    let t0 = Instant::now();
    let device = cap.identity.clone();
    // A fresh mask for the confirm, and pairs only once the frames follow it (D5).
    let mut gate = crate::strobe::StrobeGate::start(cap, true)?;
    let mut tracked = followed;
    gate.focus_on(tracked);
    let (mut passed, mut failed, mut nosignal, mut pairs) = (0usize, 0usize, 0usize, 0usize);
    let verdict = loop {
        if t0.elapsed().as_secs_f32() > CONFIRM_SECONDS {
            break confirm_at_timeout(failed);
        }
        let Some(pair) = gate.next_frame(Duration::from_secs(1))? else {
            continue;
        };
        let face = match gated_face(&gate, pipeline, &pair, cfg.min_detection, Some(tracked))? {
            Gated::NoFace => continue,
            Gated::NoSignal => {
                pairs += 1;
                nosignal += 1;
                continue;
            }
            Gated::Denied(why) => {
                pairs += 1;
                log::warn!("confirm: liveness denied: {}", why);
                break Confirm::Refused(why);
            }
            Gated::Pass(face) => {
                pairs += 1;
                face
            }
        };
        tracked = face.bbox;
        gate.focus_on(tracked);
        let Some(e) = &face.embedding else { continue };
        match templates.best_match_on(e, &device) {
            Some((score, _)) if score >= cfg.accept_threshold => {
                passed += 1;
                log::debug!("confirm: pair {} matched", passed);
                if passed >= 2 {
                    break Confirm::Live;
                }
                // The second match comes under a fresh mask (C11).
                gate.redraw()?;
            }
            // One pair under the threshold is a frame caught mid-movement
            // as often as a stranger; the refusal, like the pass, takes two.
            Some((score, _)) => {
                failed += 1;
                log::debug!("confirm: pair {} under the threshold ({:.3})", pairs, score);
                if failed >= 2 {
                    break Confirm::Refused("the face that nodded does not match".into());
                }
            }
            None => break Confirm::Refused("no template for this camera".into()),
        }
    };
    // The gate's drop restores steady light, on every exit.
    drop(gate);
    // The pair counts go to the journal on a pass only; on a refusal they
    // would say how close it came (D6).
    match &verdict {
        Confirm::Live => log::info!(
            "confirm: live in {:.2}s ({} pairs, {} no signal, {} matched)",
            t0.elapsed().as_secs_f32(),
            pairs,
            nosignal,
            passed
        ),
        Confirm::NoSignal => log::info!("confirm: no signal in {:.2}s", t0.elapsed().as_secs_f32()),
        Confirm::Refused(w) => log::info!(
            "confirm: refused: {} ({:.2}s)",
            w,
            t0.elapsed().as_secs_f32()
        ),
    }
    log::debug!(
        "confirm detail: {} pairs, {} no signal, {} matched, {} under",
        pairs,
        nosignal,
        passed,
        failed
    );
    Ok(verdict)
}

/// After a live confirm: embed the frames kept from the nod legs and require
/// each to be the enrolled face at the accept threshold (D4). The check runs
/// after the nods, on frames already captured, so the live nod detectors
/// and their floors are untouched. The inner result is the refusal reason.
pub fn nod_frames_match(
    pipeline: &mut Pipeline,
    templates: &UserTemplates,
    frames: &[(Grey, faceauth_engine::Face)],
    device: &str,
    threshold: f32,
) -> Result<std::result::Result<(), String>> {
    let mut embeddings = Vec::with_capacity(frames.len());
    for (img, face) in frames {
        let crop = faceauth_engine::align::align_112(img, &face.landmarks);
        embeddings.push(pipeline.embedder.embed(&crop)?);
    }
    let r = check_nod_embeddings(&embeddings, templates, device, threshold);
    match &r {
        Ok(()) => log::info!(
            "confirm: the {} nod frames are the enrolled face",
            embeddings.len()
        ),
        Err(why) => log::warn!("confirm: {}", why),
    }
    Ok(r)
}

/// How far under the accept threshold a nod frame may score and still count
/// as the user's own face pitched mid-nod (0.40 at the default 0.70; 0.20
/// refused the reference user's own nod on 2026-09-24 at a frame scoring
/// 0.49 with the head pitched down). The frames are kept at the ends
/// of the nod legs, chin down or chin up, which is where the embedder is
/// weakest on an enrolled face; another person's face scores far below
/// this against the user's templates, since different identities sit
/// around 0.1 to 0.3 on this model, and the live confirm just before the
/// nods matched at the full threshold. Set by reasoning, not measured on
/// a corpus; the refusal log carries the scores so it can be.
pub const NOD_FRAME_SLACK: f32 = 0.30;

/// The rule behind `nod_frames_match`, on embeddings: there must be at
/// least one kept frame, every frame must score within `NOD_FRAME_SLACK`
/// of `threshold` against a template usable on `device`, and at least half
/// of them must reach `threshold` itself. One pitched frame under the line
/// is the user mid-nod; a frame far under it, or most of them under it,
/// is someone else nodding.
pub fn check_nod_embeddings(
    embeddings: &[Vec<f32>],
    templates: &UserTemplates,
    device: &str,
    threshold: f32,
) -> std::result::Result<(), String> {
    if embeddings.is_empty() {
        return Err("no frames were kept from the nods".into());
    }
    let floor = threshold - NOD_FRAME_SLACK;
    let mut scores = Vec::with_capacity(embeddings.len());
    for (i, e) in embeddings.iter().enumerate() {
        match templates.best_match_on(e, device) {
            Some((score, _)) if score >= floor => scores.push(score),
            Some((score, _)) => {
                log::debug!("confirm: nod frame {} scored {:.3}", i + 1, score);
                return Err(format!(
                    "nod frame {} of {} is not the enrolled face",
                    i + 1,
                    embeddings.len()
                ));
            }
            None => return Err("no template for this camera".into()),
        }
    }
    let passed = scores.iter().filter(|s| **s >= threshold).count();
    if passed * 2 < scores.len() {
        log::debug!("confirm: nod frame scores {:?}", scores);
        return Err(format!(
            "only {} of {} nod frames are the enrolled face",
            passed,
            scores.len()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod confirm_tests {
    use super::*;

    /// J17: a confirm that ran out of time refuses only after two pairs
    /// under the threshold; one good pair, one weak pair or no pair at
    /// all decides nothing, so it is asked again rather than charged.
    #[test]
    fn a_timed_out_confirm_refuses_only_on_two_strikes() {
        assert!(matches!(confirm_at_timeout(0), Confirm::NoSignal));
        assert!(matches!(confirm_at_timeout(1), Confirm::NoSignal));
        assert!(matches!(confirm_at_timeout(2), Confirm::Refused(_)));
        assert!(matches!(confirm_at_timeout(5), Confirm::Refused(_)));
    }
}

#[cfg(test)]
mod nod_frame_tests {
    use super::*;
    use crate::store::Template;

    fn templates() -> UserTemplates {
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates.push(Template {
            embedding: vec![1.0, 0.0],
            quality: 0.9,
            face_width: 80.0,
            created: 1,
            label: "enrol".into(),
            device: "ipu3:x".into(),
            yaw: None,
            nose_pitch: None,
        });
        u
    }

    /// A confirm whose nod frames embed to another identity refuses, even
    /// though the face present at the confirm matched (D4).
    #[test]
    fn nod_frames_of_another_face_refuse() {
        let u = templates();
        let me = vec![0.95, 0.31];
        let other = vec![0.0, 1.0];
        assert_eq!(
            check_nod_embeddings(&[me.clone(), me.clone()], &u, "ipu3:x", 0.70),
            Ok(())
        );
        let e = check_nod_embeddings(&[me.clone(), other.clone(), me.clone()], &u, "ipu3:x", 0.70)
            .unwrap_err();
        assert!(e.contains("nod frame 2 of 3"), "{}", e);
        assert!(check_nod_embeddings(&[other], &u, "ipu3:x", 0.70).is_err());
        assert!(
            check_nod_embeddings(&[], &u, "ipu3:x", 0.70).is_err(),
            "no frames is not a pass"
        );
        // The user's own face pitched mid-nod: one frame under the
        // threshold but within the slack passes beside frames that reach
        // it; most frames under it do not, and one far under it never does.
        let pitched = vec![0.6, 0.8];
        assert_eq!(
            check_nod_embeddings(
                &[me.clone(), pitched.clone(), me.clone()],
                &u,
                "ipu3:x",
                0.70
            ),
            Ok(())
        );
        assert_eq!(
            check_nod_embeddings(&[me.clone(), pitched.clone()], &u, "ipu3:x", 0.70),
            Ok(()),
            "half at the threshold is enough"
        );
        let e = check_nod_embeddings(
            &[me.clone(), pitched.clone(), pitched.clone()],
            &u,
            "ipu3:x",
            0.70,
        )
        .unwrap_err();
        assert!(e.contains("only 1 of 3"), "{}", e);
        let far = vec![0.3, 0.954];
        let e =
            check_nod_embeddings(&[me.clone(), far, me.clone()], &u, "ipu3:x", 0.70).unwrap_err();
        assert!(e.contains("nod frame 2 of 3"), "{}", e);
        assert!(check_nod_embeddings(&[me], &u, "uvc:other", 0.70)
            .unwrap_err()
            .contains("no template"));
    }
}
