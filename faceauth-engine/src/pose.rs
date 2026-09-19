//! Head pose from the detector's five landmarks: enough to say whether a face
//! is turned toward the camera ("attention") without a landmark model.

/// Landmarks in detector order: right eye, left eye, nose tip, right mouth
/// corner, left mouth corner (image coordinates; "right" is the subject's right,
/// which appears on the image's left for a frontal face).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Pose {
    /// Horizontal nose offset from the eye midpoint, in inter-eye distances.
    /// 0 is frontal; roughly +-0.35 is a 30 degree turn.
    pub yaw: f32,
    /// Vertical nose position between the eye line (0) and the mouth line (1);
    /// about 0.5 is level, higher is looking down, lower is looking up.
    pub pitch: f32,
    /// Eye-line tilt in radians; 0 is level.
    pub roll: f32,
    pub inter_eye: f32,
}

pub fn pose(l: &[[f32; 2]; 5]) -> Pose {
    let (re, le, nose, rm, lm) = (l[0], l[1], l[2], l[3], l[4]);
    let ex = le[0] - re[0];
    let ey = le[1] - re[1];
    let inter_eye = (ex * ex + ey * ey).sqrt().max(1.0);
    let roll = ey.atan2(ex);
    // Rotate the frame so the eye line is horizontal, then measure the nose.
    let (c, s) = (roll.cos(), roll.sin());
    let rot = |p: [f32; 2], o: [f32; 2]| -> [f32; 2] {
        let (dx, dy) = (p[0] - o[0], p[1] - o[1]);
        [c * dx + s * dy, -s * dx + c * dy]
    };
    let eye_mid = [(re[0] + le[0]) / 2.0, (re[1] + le[1]) / 2.0];
    let mouth_mid = [(rm[0] + lm[0]) / 2.0, (rm[1] + lm[1]) / 2.0];
    let n = rot(nose, eye_mid);
    let m = rot(mouth_mid, eye_mid);
    let yaw = n[0] / inter_eye;
    let pitch = if m[1].abs() > 1.0 { n[1] / m[1] } else { 0.5 };
    Pose { yaw, pitch, roll, inter_eye }
}

/// Facing the camera closely enough to count as attention.
pub fn is_attentive(p: &Pose, max_yaw: f32, max_roll_deg: f32) -> bool {
    p.yaw.abs() <= max_yaw && p.roll.abs().to_degrees() <= max_roll_deg && (0.2..=0.85).contains(&p.pitch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frontal_face_is_attentive() {
        // The ArcFace template itself: a frontal, level face.
        let t = crate::align::ARCFACE_112;
        let p = pose(&t);
        assert!(p.yaw.abs() < 0.05, "{:?}", p);
        assert!(p.roll.abs() < 0.02, "{:?}", p);
        assert!((0.4..0.6).contains(&p.pitch), "{:?}", p);
        assert!(is_attentive(&p, 0.25, 25.0));
    }

    #[test]
    fn turned_and_tilted_faces_are_not() {
        let mut turned = crate::align::ARCFACE_112;
        turned[2][0] += 15.0; // nose shifted toward the left eye: yaw
        assert!(!is_attentive(&pose(&turned), 0.25, 25.0));
        let mut tilted = crate::align::ARCFACE_112;
        tilted[1][1] += 25.0; // one eye much lower: roll
        assert!(!is_attentive(&pose(&tilted), 0.25, 25.0));
    }
}
