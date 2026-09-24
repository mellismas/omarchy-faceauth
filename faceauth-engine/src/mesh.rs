//! Dense face landmarks with MediaPipe's face mesh (Apache-2.0): 468 points
//! with a relative depth each, from a 192x192 crop around a detected face.
//! Head pose comes from the mesh's geometry, chin against forehead and
//! cheek against cheek, which holds up where the five detector points do
//! not: seen from below, the detector's nose point slides toward the chin
//! and its pitch reading stops moving.

use crate::image::Grey;
use crate::runtime;
use crate::Face;
use anyhow::{Context, Result};
use ort::session::Session;
use ort::value::Tensor;
use std::path::Path;

pub const FACE_MESH_FILE: &str = "face_landmark.onnx";
const SIDE: usize = 192;
/// The crop is this many times the detector's box, square, on its centre.
const CROP_SCALE: f32 = 1.5;

/// Landmark indices in MediaPipe's canonical face mesh.
pub const FOREHEAD: usize = 10;
pub const CHIN: usize = 152;
pub const NOSE_TIP: usize = 1;
/// Outer eye corners: the subject's right eye is on the image's left for
/// a frontal, unmirrored face.
pub const RIGHT_EYE_OUTER: usize = 33;
pub const LEFT_EYE_OUTER: usize = 263;
pub const RIGHT_CHEEK: usize = 234;
pub const LEFT_CHEEK: usize = 454;
pub const MOUTH_RIGHT: usize = 61;
pub const MOUTH_LEFT: usize = 291;

pub struct FaceMesh {
    session: Session,
    input_name: String,
    /// The converted model keeps TFLite's NHWC input; an NCHW build is
    /// handled too.
    nhwc: bool,
}

/// The mesh in frame coordinates: x and y in pixels, z in the same scale
/// (smaller is nearer the camera), and the model's own confidence that a
/// face was in the crop.
#[derive(Clone, Debug)]
pub struct Mesh {
    pub points: Vec<[f32; 3]>,
    pub score: f32,
}

/// Head pose in degrees. Yaw is positive turned toward the subject's left
/// (the image's right), pitch positive with the chin down, roll positive
/// with the subject's left eye lower.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HeadPose {
    pub yaw: f32,
    pub pitch: f32,
    pub roll: f32,
}

impl FaceMesh {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let session = runtime::session(path, 2)?;
        let input = session.inputs().first().context("face mesh: no input")?;
        let input_name = input.name().to_string();
        let dims: Vec<i64> = input.dtype().tensor_shape().map(|s| s.to_vec()).unwrap_or_default();
        let nhwc = dims.len() == 4 && dims[3] == 3;
        Ok(FaceMesh { session, input_name, nhwc })
    }

    /// The mesh for the face in `bbox` (x, y, w, h in frame pixels), or
    /// None when the model does not believe there is a face in the crop.
    pub fn landmarks(&mut self, img: &Grey, bbox: [f32; 4]) -> Result<Option<Mesh>> {
        let [bx, by, bw, bh] = bbox;
        let side = (bw.max(bh) * CROP_SCALE).max(8.0);
        let (cx, cy) = (bx + bw / 2.0, by + bh / 2.0);
        let (x0, y0) = (cx - side / 2.0, cy - side / 2.0);
        let s = side / SIDE as f32;
        // Output pixel (x, y) samples the frame at (x0 + s x, y0 + s y).
        let m = [[s, 0.0, x0], [0.0, s, y0]];
        let crop = img.warp_affine(&m, SIDE, SIDE);
        let n = SIDE * SIDE;
        let tensor = if self.nhwc {
            let mut v = Vec::with_capacity(n * 3);
            for &p in &crop.data {
                let f = p as f32 / 255.0;
                v.extend_from_slice(&[f, f, f]);
            }
            Tensor::from_array(([1usize, SIDE, SIDE, 3], v))?
        } else {
            Tensor::from_array(([1usize, 3, SIDE, SIDE], crop.to_nchw3(0.0, 255.0)))?
        };
        let outputs = self.session.run(ort::inputs![self.input_name.as_str() => tensor])?;
        let mut points: Option<Vec<f32>> = None;
        let mut score = 1.0f32;
        for i in 0..outputs.len() {
            let Ok((_, data)) = outputs[i].try_extract_tensor::<f32>() else { continue };
            if data.len() == 468 * 3 {
                points = Some(data.to_vec());
            } else if data.len() == 1 {
                // A logit; the sigmoid is the confidence.
                score = 1.0 / (1.0 + (-data[0]).exp());
            }
        }
        let Some(raw) = points else { return Ok(None) };
        if score < 0.5 {
            return Ok(None);
        }
        let points = raw.chunks(3).map(|p| [x0 + p[0] * s, y0 + p[1] * s, p[2] * s]).collect();
        Ok(Some(Mesh { points, score }))
    }

    /// Landmarks for a detection.
    pub fn for_face(&mut self, img: &Grey, face: &Face) -> Result<Option<Mesh>> {
        self.landmarks(img, face.bbox)
    }
}

/// The head's pose from the mesh geometry. Yaw from the cheeks' depth
/// difference over their width, pitch from the chin's depth against the
/// forehead's over their height, roll from the eye line.
pub fn head_pose(m: &Mesh) -> HeadPose {
    let p = &m.points;
    let (rc, lc) = (p[RIGHT_CHEEK], p[LEFT_CHEEK]);
    let (fh, ch) = (p[FOREHEAD], p[CHIN]);
    let (re, le) = (p[RIGHT_EYE_OUTER], p[LEFT_EYE_OUTER]);
    // Turned toward the subject's left: the left cheek recedes (larger z).
    let yaw = (lc[2] - rc[2]).atan2((lc[0] - rc[0]).abs().max(1.0)).to_degrees();
    // Chin down: the chin recedes against the forehead.
    let pitch = (ch[2] - fh[2]).atan2((ch[1] - fh[1]).abs().max(1.0)).to_degrees();
    let roll = (le[1] - re[1]).atan2(le[0] - re[0]).to_degrees();
    HeadPose { yaw, pitch, roll }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mesh_with(points: &[(usize, [f32; 3])]) -> Mesh {
        let mut p = vec![[0.0f32; 3]; 468];
        for &(i, v) in points {
            p[i] = v;
        }
        Mesh { points: p, score: 1.0 }
    }

    #[test]
    fn a_level_frontal_face_reads_zero() {
        let m = mesh_with(&[(RIGHT_CHEEK, [0.0, 50.0, 0.0]), (LEFT_CHEEK, [100.0, 50.0, 0.0]), (FOREHEAD, [50.0, 0.0, 0.0]), (CHIN, [50.0, 120.0, 0.0]), (RIGHT_EYE_OUTER, [20.0, 40.0, 0.0]), (LEFT_EYE_OUTER, [80.0, 40.0, 0.0])]);
        let hp = head_pose(&m);
        assert!(hp.yaw.abs() < 0.01 && hp.pitch.abs() < 0.01 && hp.roll.abs() < 0.01, "{:?}", hp);
    }

    #[test]
    fn the_signs_follow_the_geometry() {
        // Chin nearer the camera than the forehead: chin up, pitch negative.
        let up = mesh_with(&[(RIGHT_CHEEK, [0.0, 50.0, 0.0]), (LEFT_CHEEK, [100.0, 50.0, 0.0]), (FOREHEAD, [50.0, 0.0, 10.0]), (CHIN, [50.0, 100.0, -30.0]), (RIGHT_EYE_OUTER, [20.0, 40.0, 0.0]), (LEFT_EYE_OUTER, [80.0, 40.0, 0.0])]);
        let hp = head_pose(&up);
        assert!(hp.pitch < -15.0, "{:?}", hp);
        // Left cheek receding: turned toward the subject's left, yaw positive.
        let left = mesh_with(&[(RIGHT_CHEEK, [0.0, 50.0, -20.0]), (LEFT_CHEEK, [80.0, 50.0, 20.0]), (FOREHEAD, [50.0, 0.0, 0.0]), (CHIN, [50.0, 120.0, 0.0]), (RIGHT_EYE_OUTER, [20.0, 40.0, 0.0]), (LEFT_EYE_OUTER, [80.0, 40.0, 0.0])]);
        assert!(head_pose(&left).yaw > 15.0);
        // Left eye lower: roll positive.
        let tilt = mesh_with(&[(RIGHT_CHEEK, [0.0, 50.0, 0.0]), (LEFT_CHEEK, [100.0, 50.0, 0.0]), (FOREHEAD, [50.0, 0.0, 0.0]), (CHIN, [50.0, 120.0, 0.0]), (RIGHT_EYE_OUTER, [20.0, 40.0, 0.0]), (LEFT_EYE_OUTER, [80.0, 60.0, 0.0])]);
        assert!(head_pose(&tilt).roll > 15.0);
    }
}
