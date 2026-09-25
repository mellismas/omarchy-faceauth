//! Recorded rounds: the per-frame line format and the replay that feeds a
//! recording back through the detectors. The enrolment walk-through and the
//! consent window write the same format, so a round from either replays
//! here.

use super::detector::{NodDetector, ShakeDetector};

/// One frame of a recorded round: the head's angles in degrees and the
/// detector box (width, centre x, centre y). What the detectors read.
#[derive(Clone, Debug)]
pub struct RoundFrame {
    pub t: f32,
    pub yaw: f32,
    pub pitch: f32,
    pub roll: f32,
    pub geom: (f32, f32, f32),
}

/// The header of a round recording (format v3): one line per frame with
/// the mesh's angles in degrees, the detector box, the face's width as a
/// fraction of the frame's shorter side and the mesh's confidence. Numbers
/// only, never an image. The walk-through's rounds and the consent window
/// write the same lines, so either replays through `replay_round`.
pub const ROUND_HEADER: &str = "v3 t yaw pitch roll w cx cy size score";

/// One line of a round recording, as `ROUND_HEADER` lays it out.
pub fn round_line(
    t: f32,
    hp: &faceauth_engine::mesh::HeadPose,
    geom: (f32, f32, f32),
    size: f32,
    score: f32,
) -> String {
    format!(
        "{:.2} {:+.1} {:+.1} {:+.1} {:.0} {:.0} {:.0} {:.3} {:.2}",
        t, hp.yaw, hp.pitch, hp.roll, geom.0, geom.1, geom.2, size, score
    )
}

/// Parse a round recording: a header line naming its format, then one
/// frame per line. The v2 files of 2026-09-24 carry two image-motion
/// columns (`pos_x pos_y`) before the box that nothing reads any more;
/// v3 drops them.
pub fn parse_round(text: &str) -> Vec<RoundFrame> {
    let header = text.lines().next().unwrap_or("");
    let skip = if header.starts_with("v2") { 2 } else { 0 };
    let data = if header.starts_with('v') { 1 } else { 0 };
    text.lines()
        .skip(data)
        .filter_map(|l| {
            let f: Vec<f32> = l
                .split_whitespace()
                .filter_map(|v| v.parse().ok())
                .collect();
            if f.len() < 7 + skip {
                return None;
            }
            Some(RoundFrame {
                t: f[0],
                yaw: f[1],
                pitch: f[2],
                roll: f[3],
                geom: (f[4 + skip], f[5 + skip], f[6 + skip]),
            })
        })
        .collect()
}

/// Replay a mesh recording through the mesh detectors at these floors
/// (degrees): nods and shakes counted.
pub fn replay_round(frames: &[RoundFrame], floors_deg: (f32, f32)) -> (usize, usize) {
    // A recorded round starts at the "go" and the still second before it
    // was not recorded, so the replay credits it; the live nod window
    // does not (D4), it observes the still second inside the window.
    let mut det = NodDetector::mesh(floors_deg.0);
    let mut shake = ShakeDetector::mesh(floors_deg.1);
    det.inner.prior_still = 1.0;
    shake.inner.prior_still = 1.0;
    for f in frames {
        shake.push_with(f.yaw, f.t, Some(f.geom));
        det.push_full(f.pitch, Some(f.yaw), f.t, Some(f.geom));
    }
    (det.nods, shake.shakes)
}

/// Where a recorded gesture round stops reading: the highest floor, in
/// whole degrees from the detector's minimum, at which the mesh detector
/// still counts the round as two of its gesture (`nod` picks which). The
/// walk-through stores this per round and derives the person's floors
/// from the lowest of them (`GestureCal::floors_deg`). None when the
/// round does not read even at the minimum: it cannot set a floor.
pub fn reads_to_deg(frames: &[RoundFrame], nod: bool) -> Option<f32> {
    let (min, max) = if nod {
        (NodDetector::MESH_MIN_DEG, NodDetector::MESH_MAX_DEG)
    } else {
        (ShakeDetector::MESH_MIN_DEG, ShakeDetector::MESH_MAX_DEG)
    };
    let reads = |floor: f32| {
        let floors = if nod {
            (floor, ShakeDetector::MESH_MIN_DEG)
        } else {
            (NodDetector::MESH_MIN_DEG, floor)
        };
        let (nods, shakes) = replay_round(frames, floors);
        if nod {
            nods >= 2
        } else {
            shakes >= 2
        }
    };
    let mut floor = min;
    let mut best = None;
    while floor <= max && reads(floor) {
        best = Some(floor);
        floor += 1.0;
    }
    best
}

#[cfg(test)]
mod mesh_battery {
    use super::*;

    /// The rounds of 2026-09-24 on the mesh: both nod rounds read as two
    /// nods, both shake rounds as two shakes, and the eight everyday
    /// rounds (glances each way, the keyboard, reading, talking, leaning)
    /// read as nothing, at the default floors.
    #[test]
    fn mesh_battery_holds() {
        let dir = format!("{}/traces/v2", env!("CARGO_MANIFEST_DIR"));
        let floors = (NodDetector::MESH_MIN_DEG, ShakeDetector::MESH_MIN_DEG);
        let mut bad = Vec::new();
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "txt").unwrap_or(false))
            .collect();
        files.sort();
        assert!(files.len() >= 12, "the twelve rounds are in {}", dir);
        for p in files {
            let name = p.file_stem().unwrap().to_string_lossy().to_string();
            let frames = parse_round(&std::fs::read_to_string(&p).unwrap());
            let (nods, shakes) = replay_round(&frames, floors);
            eprintln!(
                "mesh battery {:16} {} frames: {} nods, {} shakes",
                name,
                frames.len(),
                nods,
                shakes
            );
            let want_nod = name.starts_with("nod");
            let want_shake = name.starts_with("shake");
            if want_nod && nods < 2 {
                bad.push(format!("{}: {} nods, wanted 2", name, nods));
            }
            if want_shake && shakes < 2 {
                bad.push(format!("{}: {} shakes, wanted 2", name, shakes));
            }
            if !want_nod && nods > 0 {
                bad.push(format!("{}: {} nods from an everyday movement", name, nods));
            }
            if !want_shake && shakes > 0 {
                bad.push(format!(
                    "{}: {} shakes from an everyday movement",
                    name, shakes
                ));
            }
        }
        assert!(bad.is_empty(), "{:#?}", bad);
    }

    /// The floors the walk-through derives from a person's own rounds keep
    /// that person's gestures (round-4 C2). Derived the way the walk-through
    /// does it, from where each reference round stops reading, the floors
    /// still read both nods and both shakes as two, and the eight everyday
    /// rounds as nothing. The swing rule they replace lost shake-1.
    #[test]
    fn the_derived_floors_keep_the_reference_users_own_gestures() {
        let dir = format!("{}/traces/v2", env!("CARGO_MANIFEST_DIR"));
        let read =
            |n: &str| parse_round(&std::fs::read_to_string(format!("{}/{}.txt", dir, n)).unwrap());
        let mut g = crate::store::GestureCal::default();
        for n in ["nod-1", "nod-2"] {
            let r = reads_to_deg(&read(n), true);
            eprintln!("derived floors: {} reads up to {:?} degrees", n, r);
            g.nod_reads_to_deg
                .push(r.expect("the reference nod reads at the minimum"));
        }
        for n in ["shake-1", "shake-2"] {
            let r = reads_to_deg(&read(n), false);
            eprintln!("derived floors: {} reads up to {:?} degrees", n, r);
            g.shake_reads_to_deg
                .push(r.expect("the reference shake reads at the minimum"));
        }
        let floors = g.floors_deg(NodDetector::MESH_MIN_DEG, ShakeDetector::MESH_MIN_DEG);
        // What 0.4 of the larger swing gave the same rounds (13.88, 22.72).
        let swing_rule = (13.88, 22.72);
        eprintln!(
            "derived floors: nod {:.2} shake {:.2} (the swing rule gave nod {} shake {})",
            floors.0, floors.1, swing_rule.0, swing_rule.1
        );
        assert!(
            floors.0 > NodDetector::MESH_MIN_DEG && floors.1 > ShakeDetector::MESH_MIN_DEG,
            "the derivation raises both floors off the minimum for this person: {:?}",
            floors
        );
        let mut bad = Vec::new();
        for n in [
            "nod-1",
            "nod-2",
            "shake-1",
            "shake-2",
            "glance-left-1",
            "glance-left-2",
            "glance-right-1",
            "glance-right-2",
            "keyboard-1",
            "lean-1",
            "read-1",
            "talk-1",
        ] {
            let f = read(n);
            let at_derived = replay_round(&f, floors);
            let at_swing = replay_round(&f, swing_rule);
            eprintln!(
                "derived floors: {:15} derived -> {} nods {} shakes; swing rule -> {} nods {} shakes",
                n, at_derived.0, at_derived.1, at_swing.0, at_swing.1
            );
            let want = if n.starts_with("nod") {
                (2, 0)
            } else if n.starts_with("shake") {
                (0, 2)
            } else {
                (0, 0)
            };
            if at_derived.0 < want.0
                || at_derived.1 < want.1
                || (want == (0, 0) && at_derived != (0, 0))
            {
                bad.push(format!(
                    "{}: {:?} at the derived floors {:?}",
                    n, at_derived, floors
                ));
            }
        }
        assert!(bad.is_empty(), "{:#?}", bad);
        assert_eq!(
            replay_round(&read("shake-1"), swing_rule).1,
            0,
            "the swing rule's floors lose shake-1; if this reads, the margin can be revisited"
        );
    }
}

/// The attack cases on the mesh detectors (round-4 C4), which are the only
/// gesture path since round-4 C3 took the image-motion one out.
#[cfg(test)]
mod mesh_redteam {
    use super::*;

    const FPS: f32 = 28.0;
    const BOX: (f32, f32, f32) = (92.0, 252.0, 342.0);

    /// A pitch series: rest, then two nods of `amp` degrees at `leg`
    /// frames a leg, then rest.
    fn two_nods(amp: f32, leg: usize) -> Vec<f32> {
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
    }

    /// Frames from a pitch series; the box rides the pitch when
    /// `box_moves`, as a head does, and stays put otherwise, as a detector
    /// fit that flips does.
    fn frames(pitch: &[f32], yaw: f32, box_moves: bool) -> Vec<RoundFrame> {
        pitch
            .iter()
            .enumerate()
            .map(|(i, &p)| {
                let cy = if box_moves { BOX.2 + p * 0.6 } else { BOX.2 };
                RoundFrame {
                    t: i as f32 / FPS,
                    yaw,
                    pitch: p,
                    roll: 0.0,
                    geom: (BOX.0, BOX.1, cy),
                }
            })
            .collect()
    }

    fn defaults() -> (f32, f32) {
        (NodDetector::MESH_MIN_DEG, ShakeDetector::MESH_MIN_DEG)
    }

    /// The red team's two cases in mesh form: a pitch that oscillates
    /// while the box stays frozen is not a head and reads as nothing; a
    /// waggled board carries its box and passes the detector by design,
    /// left to the strobed confirm.
    #[test]
    fn a_frozen_box_is_not_a_nod_and_a_waggled_board_is_left_to_the_confirm() {
        let pitch = two_nods(15.0, 8);
        let frozen = replay_round(&frames(&pitch, 0.0, false), defaults());
        let waggled = replay_round(&frames(&pitch, 0.0, true), defaults());
        assert_eq!(frozen, (0, 0), "a frozen box read as a gesture");
        assert!(
            waggled.0 >= 2,
            "the waggled board is meant to pass the detector (the confirm refuses it); it read {} nods",
            waggled.0
        );
    }

    /// The frozen box is refused by the box-motion rule and nothing else:
    /// with `co_motion` off the same frames read as nods. The rule is
    /// what carries the case, so it must stay on in `NodDetector::mesh`.
    #[test]
    fn the_box_motion_rule_is_what_refuses_the_frozen_box() {
        let pitch = two_nods(15.0, 8);
        let mut det = NodDetector::mesh(NodDetector::MESH_MIN_DEG);
        assert!(
            det.inner.co_motion.is_some(),
            "the live detector runs the rule"
        );
        det.inner.co_motion = None;
        det.inner.prior_still = 1.0;
        for f in frames(&pitch, 0.0, false) {
            det.push_full(f.pitch, Some(0.0), f.t, Some(f.geom));
        }
        assert!(
            det.nods >= 2,
            "with the rule off the frozen box read {} nods",
            det.nods
        );
    }

    /// A detector fit that flips: the pitch jumps to a plateau in one
    /// frame, holds, and jumps back, twice, over a box that does not move
    /// (the shape of the 2026-09-22 flicker recording that approved a
    /// request). Nothing, at any nod-sized plateau.
    #[test]
    fn a_plateau_flicker_over_a_still_box_is_not_a_nod() {
        for amp in [10.0f32, 15.0, 25.0] {
            for hold in [1usize, 2, 4, 6] {
                let mut pitch: Vec<f32> = vec![0.0; 40];
                for _ in 0..2 {
                    pitch.extend(std::iter::repeat_n(amp, hold));
                    pitch.extend(std::iter::repeat_n(0.0, hold));
                }
                pitch.extend(std::iter::repeat_n(0.0, 30));
                let got = replay_round(&frames(&pitch, 0.0, false), defaults());
                assert_eq!(
                    got,
                    (0, 0),
                    "a {} degree plateau held {} frames read as {:?}",
                    amp,
                    hold,
                    got
                );
            }
        }
    }

    /// A head held turned toward another screen nods the same way on the
    /// pitch axis, but it is not nodding at the card. The reference nods,
    /// re-centred so their mean yaw is the offset, still read as two held
    /// 30 degrees off (the gate is `YAW_FACING_DEG`, 34.29) and read as
    /// nothing from 36 degrees either way.
    #[test]
    fn a_nod_from_a_head_held_turned_does_not_count_on_the_mesh() {
        let dir = format!("{}/traces/v2", env!("CARGO_MANIFEST_DIR"));
        let mut bad = Vec::new();
        for name in ["nod-1", "nod-2"] {
            let recorded =
                parse_round(&std::fs::read_to_string(format!("{}/{}.txt", dir, name)).unwrap());
            let mean = recorded.iter().map(|f| f.yaw).sum::<f32>() / recorded.len() as f32;
            let held_at = |off: f32| -> (usize, usize) {
                let turned: Vec<RoundFrame> = recorded
                    .iter()
                    .map(|f| RoundFrame {
                        yaw: f.yaw - mean + off,
                        ..f.clone()
                    })
                    .collect();
                replay_round(&turned, defaults())
            };
            let (n0, _) = replay_round(&recorded, defaults());
            if n0 < 2 {
                bad.push(format!("{} lost its nods as recorded: {}", name, n0));
            }
            for off in [30.0f32, -30.0] {
                let (n, _) = held_at(off);
                if n < 2 {
                    bad.push(format!(
                        "{} held {:+.0} degrees off (inside the gate): {} nods",
                        name, off, n
                    ));
                }
            }
            for off in [36.0f32, -36.0, 43.0, -43.0, 60.0, -60.0] {
                let (n, s) = held_at(off);
                if n != 0 {
                    bad.push(format!("{} held {:+.0} degrees off: {} nods", name, off, n));
                }
                if s != 0 {
                    bad.push(format!(
                        "{} held {:+.0} degrees off: {} shakes",
                        name, off, s
                    ));
                }
            }
        }
        assert!(bad.is_empty(), "{:#?}", bad);
    }

    /// The same synthetic nods made with the head turned: the facing gate
    /// refuses them, not the box rule, so the box is allowed to move.
    #[test]
    fn a_synthetic_nod_with_the_head_turned_does_not_count() {
        let pitch = two_nods(20.0, 8);
        assert!(replay_round(&frames(&pitch, 0.0, true), defaults()).0 >= 2);
        for yaw in [40.0f32, -40.0, 70.0] {
            let got = replay_round(&frames(&pitch, yaw, true), defaults());
            assert_eq!(got.0, 0, "nods at yaw {}: {:?}", yaw, got);
        }
    }
}
