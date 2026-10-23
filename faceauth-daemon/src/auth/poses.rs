//! The poses a terminal enrollment asks for, with the pitch bins that
//! accept a frame for each. The enrollment that reads them runs in
//! `enrol::run_terminal`, under the walk-through's rules.

/// The looks a terminal enrollment asks for, in order, and what to tell the
/// person for each. Yaw is the nose offset in inter-eye distances (about
/// 0.35 for a 30 degree turn); nose_pitch is the nose's drop below the eye
/// line in the same units (about 0.5 level, more looking down).
pub const POSES: [&str; 5] = ["centre", "left", "right", "up", "down"];
pub const POSE_HINTS: [&str; 5] = [
    "look straight at the camera",
    "turn your head to the left, about a quarter turn, and hold it",
    "turn your head to the right, about a quarter turn, and hold it",
    "tilt your chin up a little, not much, and hold it",
    "tilt your head down a little, as if reading the keyboard, and hold it",
];

/// The nose_pitch a person reads at level until the enrollment has
/// learned theirs from its straight look: the sweep's typical 0.53
/// (2026-09-23; a lid camera looks up at the face, so the chin-up moves
/// this measure only a little).
pub const LEVEL_DEFAULT: f32 = 0.53;
/// How far below the level reading counts as chin-up, and above as chin-down.
pub const UP_BELOW_LEVEL: f32 = 0.02;
pub const DOWN_ABOVE_LEVEL: f32 = 0.08;

/// Is this frame in the pose a terminal look asked for, with up and down
/// measured against this person's own level? Turn bands are from the
/// pose sweep of 2026-09-23: a quarter turn reads 0.25 to 0.40 on yaw.
pub fn pose_bin_accepts_at(name: &str, p: &faceauth_engine::pose::Pose, level: f32) -> bool {
    match name {
        "centre" => p.yaw.abs() <= 0.12 && (p.nose_pitch - level).abs() <= 0.06,
        "left" => p.yaw <= -0.18 && p.yaw >= -0.60,
        "right" => p.yaw >= 0.18 && p.yaw <= 0.60,
        "up" => p.nose_pitch <= level - UP_BELOW_LEVEL && p.yaw.abs() <= 0.20,
        "down" => p.nose_pitch >= level + DOWN_ABOVE_LEVEL && p.yaw.abs() <= 0.20,
        _ => false,
    }
}

#[cfg(test)]
mod pose_bin_tests {
    use super::*;
    use faceauth_engine::pose::Pose;

    /// The bands at the default level.
    fn pose_bin_accepts(name: &str, p: &Pose) -> bool {
        pose_bin_accepts_at(name, p, LEVEL_DEFAULT)
    }

    fn at(yaw: f32, nose_pitch: f32) -> Pose {
        Pose {
            yaw,
            pitch: 0.5,
            roll: 0.0,
            nose_pitch,
            mouth_drop: 1.0,
            inter_eye: 40.0,
        }
    }

    #[test]
    fn each_pose_takes_its_own_frames_and_no_others() {
        let frontal = at(0.0, LEVEL_DEFAULT);
        assert!(pose_bin_accepts("centre", &frontal));
        for p in ["left", "right", "up", "down"] {
            assert!(
                !pose_bin_accepts(p, &frontal),
                "{} must not take a frontal frame",
                p
            );
        }
        assert!(
            pose_bin_accepts("left", &at(-0.3, 0.5)) && !pose_bin_accepts("right", &at(-0.3, 0.5))
        );
        assert!(
            pose_bin_accepts("right", &at(0.3, 0.5)) && !pose_bin_accepts("centre", &at(0.3, 0.5))
        );
        assert!(
            pose_bin_accepts("up", &at(0.05, 0.50)) && !pose_bin_accepts("centre", &at(0.05, 0.44)),
            "a comfortable chin-up reads a couple of hundredths under level"
        );
        assert!(
            pose_bin_accepts("down", &at(0.05, 0.7)) && !pose_bin_accepts("centre", &at(0.05, 0.7))
        );
        assert!(
            pose_bin_accepts("centre", &at(0.05, 0.55))
                && !pose_bin_accepts("up", &at(0.05, 0.55))
                && !pose_bin_accepts("down", &at(0.05, 0.55)),
            "level is level"
        );
        // Relative to a person who reads higher at level, the same bands move with them.
        assert!(
            pose_bin_accepts_at("up", &at(0.0, 0.57), 0.60)
                && !pose_bin_accepts_at("up", &at(0.0, 0.59), 0.60)
        );
        assert!(
            pose_bin_accepts_at("down", &at(0.0, 0.69), 0.60)
                && !pose_bin_accepts_at("down", &at(0.0, 0.66), 0.60)
        );
        assert!(
            !pose_bin_accepts("left", &at(-0.9, 0.5)),
            "a profile is past what the aligner can use"
        );
        assert!(!pose_bin_accepts("sideways", &frontal));
        assert_eq!(POSES.len(), POSE_HINTS.len());
    }
}
