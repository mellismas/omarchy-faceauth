//! Enrolment: the capture that stores a user's templates, and the poses a
//! guided enrolment asks for with the pitch bins that accept a frame for
//! each.

use super::attempt::Authenticator;
use super::outcome::Outcome;
use crate::capture::IrCapture;
use crate::store::UserTemplates;
use anyhow::Result;
use std::time::{Duration, Instant};

impl Authenticator {
    /// Enrol: capture `count` embeddings over `seconds`, spaced across the
    /// window so they cover different poses, LEDs on, exposure metered on the
    /// face. Stored under `label` beside any existing templates.
    pub fn enroll(
        &mut self,
        user: &str,
        label: &str,
        seconds: f32,
        count: usize,
        pose: Option<&str>,
    ) -> Outcome {
        match self.run_enroll(user, label, seconds, count, pose) {
            Ok(o) => o,
            Err(e) => Outcome::Error {
                message: e.to_string(),
            },
        }
    }

    fn run_enroll(
        &mut self,
        user: &str,
        label: &str,
        seconds: f32,
        count: usize,
        pose: Option<&str>,
    ) -> Result<Outcome> {
        use crate::store::{now_secs, Template, UserTemplates};
        if let Some(p) = pose {
            if !POSES.contains(&p) {
                return Ok(Outcome::Error {
                    message: format!("unknown pose {:?}; one of {}", p, POSES.join(", ")),
                });
            }
        }
        // The store's one enrolment opener, shared with the walk-through:
        // no plaintext over a sealed set, and a blob this machine can no
        // longer open goes aside only on the credential tool's own verdict
        // (F2). Its error becomes the outcome's message.
        let existing = self.store.open_for_enrolment(user)?;
        let uid = crate::store::current_uid(user)
            .ok_or_else(|| anyhow::anyhow!("unknown user {}", user))?;
        let mut u = existing.unwrap_or_else(|| {
            UserTemplates::new(user, uid, faceauth_engine::embed::AURAFACE_FILE)
        });
        if u.model != faceauth_engine::embed::AURAFACE_FILE {
            return Ok(Outcome::Error {
                message: format!(
                    "existing templates are for model {}; delete them first",
                    u.model
                ),
            });
        }
        let t0 = Instant::now();
        let deadline = Duration::from_secs_f32(seconds.clamp(4.0, 60.0));
        let count = count.clamp(3, 40);
        let spacing = Duration::from_millis(
            (((seconds - 2.0).max(1.0) * 1000.0) / count as f32).clamp(150.0, 2000.0) as u64,
        );
        let mut cap = IrCapture::open(&self.cfg)?;
        if let Some(i) = &cap.illuminator {
            i.set(true)?;
        }
        let mut samples: Vec<(Vec<f32>, f32, f32, faceauth_engine::pose::Pose)> = Vec::new();
        let mut last = Instant::now() - spacing;
        let mut seen = 0usize;
        let mut off_pose = 0usize;
        // This person's level, from the centre look already enrolled, so
        // up and down are measured against it rather than a fixed number.
        let level = level_of(&u);
        let (mut lo_seen, mut hi_seen) = (f32::MAX, f32::MIN);
        let (mut yaw_lo, mut yaw_hi) = (f32::MAX, f32::MIN);
        while t0.elapsed() < deadline && samples.len() < count {
            let Some(img) = cap.next(Duration::from_secs(2))? else {
                continue;
            };
            if cap.frames % 3 != 0 {
                continue;
            }
            let faces = self.pipeline.analyse(&img, self.cfg.min_detection, 1)?;
            let Some(face) = faces.first() else { continue };
            seen += 1;
            cap.meter_on(face);
            // Let the metering act before the first sample, then space them out.
            if seen <= 3 || last.elapsed() < spacing {
                continue;
            }
            let p = faceauth_engine::pose::pose(&face.landmarks);
            // A guided round keeps only frames in the pose it asked for.
            if let Some(want) = pose {
                lo_seen = lo_seen.min(p.nose_pitch);
                hi_seen = hi_seen.max(p.nose_pitch);
                yaw_lo = yaw_lo.min(p.yaw);
                yaw_hi = yaw_hi.max(p.yaw);
                if !pose_bin_accepts_at(want, &p, level) {
                    off_pose += 1;
                    continue;
                }
            }
            last = Instant::now();
            if let Some(e) = &face.embedding {
                samples.push((e.clone(), face.score, face.bbox[2], p));
            }
        }
        let device = cap.identity.clone();
        cap.stop()?;
        if samples.len() < 3 {
            let hint = match pose {
                Some(p) if off_pose > 0 => {
                    let want = match p {
                        "up" => format!(
                            "up needs a pitch reading of {:.2} or less",
                            level - UP_BELOW_LEVEL
                        ),
                        "down" => format!("down needs {:.2} or more", level + DOWN_ABOVE_LEVEL),
                        "left" => "left needs a turn reading of -0.18 or less".to_string(),
                        "right" => "right needs a turn reading of 0.18 or more".to_string(),
                        _ => format!(
                            "centre needs a turn within 0.12 and a pitch within 0.06 of {:.2}",
                            level
                        ),
                    };
                    format!("only {} frames in the {} pose; the {} frames read pitch {:.2} to {:.2} and turn {:+.2} to {:+.2}, and {}. {}", samples.len(), p, off_pose, lo_seen, hi_seen, yaw_lo, yaw_hi, want, POSE_HINTS[POSES.iter().position(|q| *q == p).unwrap_or(0)])
                }
                _ => format!(
                    "only {} usable frames; face the camera at normal distance and try again",
                    samples.len()
                ),
            };
            return Ok(Outcome::Error { message: hint });
        }
        let now = now_secs();
        let added = samples.len();
        for (e, q, w, p) in samples {
            u.templates.push(Template {
                embedding: e,
                quality: q,
                face_width: w,
                created: now,
                label: label.to_string(),
                device: device.clone(),
                yaw: Some(p.yaw),
                nose_pitch: Some(p.nose_pitch),
            });
        }
        // Over the cap, the surplus copies of looks already held go, not
        // the new look: coverage is what an identity is for.
        let pruned = u.prune_to(crate::store::MAX_TEMPLATES);
        if pruned > 0 {
            log::info!(
                "enrolment for {}: {} near-duplicate template(s) dropped to stay within {}",
                user,
                pruned,
                crate::store::MAX_TEMPLATES
            );
        }
        let (lo, mean, _) = u.self_consistency().unwrap_or((1.0, 1.0, 1.0));
        let path = self.store.save(&u)?;
        Ok(Outcome::Enrolled {
            added,
            total: u.templates.len(),
            consistency_min: lo,
            consistency_mean: mean,
            path: path.display().to_string(),
        })
    }
}

/// The looks a guided enrolment asks for, in order, and what to tell the
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

/// The nose_pitch a person reads at level: the mean over their centre
/// templates, else over any template that recorded one, else the sweep's
/// typical 0.53 (2026-09-23; a lid camera looks up at the face, so the
/// chin-up moves this measure only a little).
pub const LEVEL_DEFAULT: f32 = 0.53;
/// How far below the level reading counts as chin-up, and above as chin-down.
pub const UP_BELOW_LEVEL: f32 = 0.02;
pub const DOWN_ABOVE_LEVEL: f32 = 0.08;

pub fn level_of(u: &UserTemplates) -> f32 {
    let centre: Vec<f32> = u
        .templates
        .iter()
        .filter(|t| t.label.ends_with("-centre"))
        .filter_map(|t| t.nose_pitch)
        .collect();
    let any: Vec<f32> = u.templates.iter().filter_map(|t| t.nose_pitch).collect();
    let pick = if !centre.is_empty() { centre } else { any };
    if pick.is_empty() {
        LEVEL_DEFAULT
    } else {
        pick.iter().sum::<f32>() / pick.len() as f32
    }
}

/// Is this frame in the pose a guided round asked for, with up and down
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

/// The bands at the default level.
pub fn pose_bin_accepts(name: &str, p: &faceauth_engine::pose::Pose) -> bool {
    pose_bin_accepts_at(name, p, LEVEL_DEFAULT)
}

#[cfg(test)]
mod pose_bin_tests {
    use super::*;
    use faceauth_engine::pose::Pose;

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
