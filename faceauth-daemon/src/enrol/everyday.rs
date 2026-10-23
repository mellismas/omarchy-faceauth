//! The everyday rounds replayed at the floors the gesture rounds derived
//! (round-4 C3). The recorded reading, talking, glancing and leaning must
//! not read as a nod or a shake at the floors the consent window will run,
//! which is what the Bridge screen tells the person the walk-through makes
//! sure of.
//! A floor that lets an everyday round through is raised a degree at a
//! time until none reads. A raise that passes where the person's own
//! recorded gestures stop reading is still kept, and the person is warned.
//! A nod that has to be bigger costs at worst a typed password; reading
//! that approves a request costs the request. An everyday round that reads
//! even at the detector's ceiling cannot be told from a gesture, and the
//! session fails.

use crate::consent::{replay_round, NodDetector, RoundFrame, ShakeDetector};
use crate::store::GestureCal;

/// What the replay settled.
#[derive(Debug, PartialEq)]
pub(super) struct Clearance {
    /// The raised floors, degrees; None where the derived floor already
    /// reads no everyday round.
    pub nod: Option<f32>,
    pub shake: Option<f32>,
    /// The gestures whose raise went past where the person's own recorded
    /// rounds stop reading: those now have to be bigger than the recorded
    /// ones to count.
    pub past_own: Vec<&'static str>,
}

/// Replay `everyday` (each round's kind and frames) at the floors `g`
/// derives, and raise each floor that lets one through. The error says
/// which movement reads as which gesture even at the detector's ceiling.
pub(super) fn clear_everyday(
    g: &GestureCal,
    everyday: &[(&'static str, Vec<RoundFrame>)],
) -> Result<Clearance, String> {
    let (nod0, shake0) =
        g.derived_floors_deg(NodDetector::MESH_MIN_DEG, ShakeDetector::MESH_MIN_DEG);
    // The detectors run apart, so a nod floor never changes what the
    // shake detector counts, nor the other way round.
    let first_clear = |gesture: &'static str, from: f32, ceiling: f32| -> Result<f32, String> {
        let mut floor = from;
        loop {
            let reading = everyday.iter().find(|(_, frames)| {
                let (nods, shakes) = if gesture == "nod" {
                    replay_round(frames, (floor, shake0))
                } else {
                    replay_round(frames, (nod0, floor))
                };
                (if gesture == "nod" { nods } else { shakes }) > 0
            });
            match reading {
                None => return Ok(floor),
                Some((kind, _)) if floor >= ceiling => {
                    return Err(format!(
                        "the {} round reads as a {} even at the detector's ceiling",
                        kind, gesture
                    ))
                }
                Some(_) => floor = (floor + 1.0).min(ceiling),
            }
        }
    };
    let nod = first_clear("nod", nod0, NodDetector::MESH_MAX_DEG)?;
    let shake = first_clear("shake", shake0, ShakeDetector::MESH_MAX_DEG)?;
    // Where the person's own rounds stop reading: the lowest drop-out of
    // the gesture's rounds. With none recorded that read, no raise can be
    // said to keep them.
    let past = |raised: f32, reads_to: &[f32]| {
        reads_to
            .iter()
            .copied()
            .fold(None, |m: Option<f32>, x| Some(m.map_or(x, |m| m.min(x))))
            .is_none_or(|own| raised > own)
    };
    let mut past_own = Vec::new();
    if nod > nod0 && past(nod, &g.nod_reads_to_deg) {
        past_own.push("nod");
    }
    if shake > shake0 && past(shake, &g.shake_reads_to_deg) {
        past_own.push("shake");
    }
    Ok(Clearance {
        nod: (nod > nod0).then_some(nod),
        shake: (shake > shake0).then_some(shake),
        past_own,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consent::{parse_round, reads_to_deg};

    const FPS: f32 = 28.0;
    const BOX: (f32, f32, f32) = (92.0, 252.0, 342.0);

    /// A round of rest, two nods of `amp` degrees at `leg` frames a leg
    /// with the box riding the pitch as a head's does, then rest.
    fn nodding(amp: f32, leg: usize) -> Vec<RoundFrame> {
        let mut pitch: Vec<f32> = vec![0.0; 40];
        for _ in 0..2 {
            for k in 1..=leg {
                pitch.push(amp * k as f32 / leg as f32);
            }
            for k in 1..=leg {
                pitch.push(amp - amp * k as f32 / leg as f32);
            }
        }
        pitch.extend(std::iter::repeat_n(0.0, 30));
        pitch
            .iter()
            .enumerate()
            .map(|(i, &p)| RoundFrame {
                t: i as f32 / FPS,
                yaw: 0.0,
                pitch: p,
                roll: 0.0,
                geom: (BOX.0, BOX.1, BOX.2 + p * 0.6),
            })
            .collect()
    }

    /// Nods read at the floors the consent window runs for `g`.
    fn nods_at_consent_floors(g: &GestureCal, frames: &[RoundFrame]) -> usize {
        replay_round(frames, crate::auth::consent_floors(g)).0
    }

    /// C3: an everyday round that reads as a nod at the derived floor
    /// raises the floor until it reads nothing, and the consent window
    /// then runs at the raised floor. While the raise stays under where the
    /// person's own nods stop reading, nothing is lost and there is no
    /// warning; past it, the raise is kept and the person is warned.
    #[test]
    fn an_everyday_round_that_reads_as_a_nod_raises_the_floor() {
        // Reading with a bobbing head: two quick 20 degree dips.
        let bobbing = nodding(20.0, 8);
        let reads_to = reads_to_deg(&bobbing, true).expect("the bobbing reads as nods");
        assert!(
            replay_round(
                &bobbing,
                (NodDetector::MESH_MIN_DEG, ShakeDetector::MESH_MIN_DEG)
            )
            .0 > 0,
            "it reads as a nod at 8 degrees"
        );
        let everyday = vec![("read", bobbing.clone())];

        // The person's own nods read two degrees past the bobbing, so the
        // derived floor (0.85 of that) lets the bobbing through.
        let mut g = GestureCal {
            nod_reads_to_deg: vec![reads_to + 2.0],
            shake_reads_to_deg: vec![20.0],
            ..Default::default()
        };
        let derived = g.derived_floors_deg(NodDetector::MESH_MIN_DEG, ShakeDetector::MESH_MIN_DEG);
        assert!(
            nods_at_consent_floors(&g, &bobbing) > 0,
            "before the replay the consent window would count the bobbing at {:?}",
            derived
        );
        let c = clear_everyday(&g, &everyday).unwrap();
        let raised = c.nod.expect("the nod floor is raised");
        assert!(raised > derived.0 && raised <= reads_to + 2.0, "{:?}", c);
        assert_eq!(c.shake, None, "nothing shook");
        assert!(
            c.past_own.is_empty(),
            "the person's own nods still read: {:?}",
            c
        );
        g.nod_floor_min_deg = c.nod;
        assert_eq!(crate::auth::consent_floors(&g).0, raised);
        assert_eq!(
            nods_at_consent_floors(&g, &bobbing),
            0,
            "at the stored floors reading never counts as a nod"
        );

        // A person whose own nods stop reading at 9 degrees: the floor
        // still goes up to where the bobbing stops, past their own nods,
        // and they are told.
        let mut g = GestureCal {
            nod_reads_to_deg: vec![9.0],
            ..Default::default()
        };
        let c = clear_everyday(&g, &everyday).unwrap();
        let raised = c.nod.expect("the nod floor is raised");
        assert!(raised > 9.0, "{:?}", c);
        assert_eq!(c.past_own, vec!["nod"]);
        g.nod_floor_min_deg = c.nod;
        assert_eq!(nods_at_consent_floors(&g, &bobbing), 0);
    }

    /// The reference user's rounds of 2026-09-24: at the floors their own
    /// nods and shakes derive, none of the eight everyday rounds reads, so
    /// nothing is raised.
    #[test]
    fn the_reference_everyday_rounds_raise_nothing() {
        let dir = format!("{}/traces/v2", env!("CARGO_MANIFEST_DIR"));
        let read =
            |n: &str| parse_round(&std::fs::read_to_string(format!("{}/{}.txt", dir, n)).unwrap());
        let mut g = GestureCal::default();
        for n in ["nod-1", "nod-2"] {
            g.nod_reads_to_deg.extend(reads_to_deg(&read(n), true));
        }
        for n in ["shake-1", "shake-2"] {
            g.shake_reads_to_deg.extend(reads_to_deg(&read(n), false));
        }
        let everyday: Vec<(&'static str, Vec<RoundFrame>)> = [
            "glance-left-1",
            "glance-left-2",
            "glance-right-1",
            "glance-right-2",
            "keyboard-1",
            "lean-1",
            "read-1",
            "talk-1",
        ]
        .into_iter()
        .map(|n| (n, read(n)))
        .collect();
        assert_eq!(
            clear_everyday(&g, &everyday).unwrap(),
            Clearance {
                nod: None,
                shake: None,
                past_own: Vec::new()
            }
        );
    }
}
