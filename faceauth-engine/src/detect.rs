//! YuNet face detector (OpenCV Zoo, MIT). Decoding follows OpenCV's
//! `FaceDetectorYN`: three strides, per-cell class and objectness scores,
//! box offsets relative to the cell, and five landmarks.

use crate::image::Grey;
use crate::runtime;
use crate::Face;
use anyhow::{Context, Result};
use ort::session::{Session, SessionOutputs};
use ort::value::Tensor;
use std::path::Path;

pub const YUNET_FILE: &str = "face_detection_yunet_2023mar.onnx";
const STRIDES: [usize; 3] = [8, 16, 32];
const NMS_IOU: f32 = 0.3;

pub struct YuNet {
    session: Session,
    input_name: String,
    /// Fixed input size if the model has static dimensions, else None.
    fixed: Option<(usize, usize)>,
}

impl YuNet {
    /// Load the detector and check, once, that it is the model this decoder
    /// reads: twelve outputs named `cls_8` to `kps_32`. A different
    /// detector (the 2022 YuNet with `loc`, `conf` and `iou`, or anything
    /// else placed in the models directory) is refused here with the names
    /// it lacks, so the daemon fails to start instead of every attempt
    /// dying on a missing output.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let session = runtime::session(path, 2)?;
        let input = session.inputs().first().context("YuNet: no input")?;
        let input_name = input.name().to_string();
        let fixed = match input.dtype().tensor_shape() {
            Some(s) if s.len() == 4 && s[2] > 0 && s[3] > 0 => Some((s[3] as usize, s[2] as usize)),
            _ => None,
        };
        let names: Vec<String> = session
            .outputs()
            .iter()
            .map(|o| o.name().to_string())
            .collect();
        let missing = missing_outputs(&names);
        if !missing.is_empty() {
            anyhow::bail!(
                "YuNet: the model has no outputs named {} (it has {}); this build reads the 2023mar YuNet",
                missing.join(", "),
                names.join(", ")
            );
        }
        Ok(YuNet {
            session,
            input_name,
            fixed,
        })
    }

    /// Faces above `threshold` (score = sqrt(cls * obj)), after NMS, in image coordinates.
    pub fn detect(&mut self, img: &Grey, threshold: f32) -> Result<Vec<Face>> {
        // The network wants a multiple of 32; a fixed-size model wants exactly its size.
        let (net, scale) = match self.fixed {
            Some((fw, fh)) => letterbox(img, fw, fh),
            None => (img.padded_to_multiple(32), 1.0),
        };
        let (w, h) = (net.width, net.height);
        // OpenCV feeds blobFromImage with scale 1, no mean: raw 0..255 floats.
        let tensor = Tensor::from_array(([1usize, 3, h, w], net.to_nchw3(0.0, 1.0)))?;
        let outputs = self
            .session
            .run(ort::inputs![self.input_name.as_str() => tensor])?;

        let mut boxes: Vec<Face> = Vec::new();
        for &stride in &STRIDES {
            let cols = w / stride;
            let rows = h / stride;
            // The decoder reads the runtime's output buffers in place; copying
            // the twelve tensors out first bought nothing.
            let (cls, obj, bbox, kps) = (
                output(&outputs, "cls", stride)?,
                output(&outputs, "obj", stride)?,
                output(&outputs, "bbox", stride)?,
                output(&outputs, "kps", stride)?,
            );
            boxes.extend(decode_stride(
                cls, obj, bbox, kps, stride, cols, rows, threshold, scale,
            )?);
        }
        Ok(nms(boxes, NMS_IOU))
    }
}

/// The twelve outputs the decoder reads.
fn expected_outputs() -> Vec<String> {
    let mut v = Vec::new();
    for stride in STRIDES {
        for name in ["cls", "obj", "bbox", "kps"] {
            v.push(format!("{}_{}", name, stride));
        }
    }
    v
}

/// Which of the twelve expected outputs a model with outputs `names` lacks.
fn missing_outputs(names: &[String]) -> Vec<String> {
    expected_outputs()
        .into_iter()
        .filter(|want| !names.iter().any(|n| n == want))
        .collect()
}

/// One of the model's per-stride outputs (`cls_8`, `kps_32`, ...) as a slice
/// into the runtime's buffer. Looked up, not indexed: `ort`'s index
/// operator panics on a missing name, and a panic here would take the
/// request thread with it.
fn output<'a>(outputs: &'a SessionOutputs<'_>, name: &str, stride: usize) -> Result<&'a [f32]> {
    let key = format!("{}_{}", name, stride);
    let value = outputs
        .get(key.as_str())
        .with_context(|| format!("YuNet: model has no output {}", key))?;
    let (_, data) = value.try_extract_tensor::<f32>()?;
    Ok(data)
}

/// `img` scaled to fit a `fw` x `fh` canvas, anchored top-left, zero on the
/// rest, and the scale applied. At the reference resolution the fixed
/// 640x640 model and the 480x640 oriented frame give a scale of exactly 1,
/// so the rows are copied as they are: the bilinear warp returns the same
/// pixels at unit scale and cost 4.4 ms of a 16 ms detection.
fn letterbox(img: &Grey, fw: usize, fh: usize) -> (Grey, f32) {
    let s = (fw as f32 / img.width as f32).min(fh as f32 / img.height as f32);
    let mut canvas = Grey::new(fw, fh);
    let rw = (img.width as f32 * s) as usize;
    let rh = (img.height as f32 * s) as usize;
    if rw == img.width && rh == img.height {
        for y in 0..rh {
            canvas.data[y * fw..y * fw + rw]
                .copy_from_slice(&img.data[y * img.width..(y + 1) * img.width]);
        }
        return (canvas, s);
    }
    let inv = [[1.0 / s, 0.0, 0.0], [0.0, 1.0 / s, 0.0]];
    let resized = img.warp_affine(&inv, rw, rh);
    for y in 0..rh {
        canvas.data[y * fw..y * fw + rw].copy_from_slice(&resized.data[y * rw..(y + 1) * rw]);
    }
    (canvas, s)
}

/// Decode one stride's outputs into faces. The four tensors must agree on
/// the cell count: a model whose box or landmark output is shorter than its
/// score output is refused rather than read past its end (a panic here
/// would take the request thread with it).
#[allow(clippy::too_many_arguments)]
fn decode_stride(
    cls: &[f32],
    obj: &[f32],
    bbox: &[f32],
    kps: &[f32],
    stride: usize,
    cols: usize,
    rows: usize,
    threshold: f32,
    scale: f32,
) -> Result<Vec<Face>> {
    let cells = cols * rows;
    if cls.len() < cells || obj.len() < cells || bbox.len() < cells * 4 || kps.len() < cells * 10 {
        anyhow::bail!(
            "YuNet: stride {} outputs are short for {}x{} cells (cls {}, obj {}, bbox {}, kps {})",
            stride,
            cols,
            rows,
            cls.len(),
            obj.len(),
            bbox.len(),
            kps.len()
        );
    }
    let mut boxes = Vec::new();
    for r in 0..rows {
        for c in 0..cols {
            let idx = r * cols + c;
            let score = (cls[idx].clamp(0.0, 1.0) * obj[idx].clamp(0.0, 1.0)).sqrt();
            // Kept only when the comparison is defined and says at or
            // above: a NaN score (which `clamp` passes through) compares
            // as nothing, and `NaN < threshold` would have let it through
            // to sort first in the descending order below.
            if !score.partial_cmp(&threshold).is_some_and(|o| o.is_ge()) {
                continue;
            }
            let s = stride as f32;
            let cx = (c as f32 + bbox[idx * 4]) * s;
            let cy = (r as f32 + bbox[idx * 4 + 1]) * s;
            let bw = bbox[idx * 4 + 2].exp() * s;
            let bh = bbox[idx * 4 + 3].exp() * s;
            let mut landmarks = [[0f32; 2]; 5];
            for (n, lm) in landmarks.iter_mut().enumerate() {
                *lm = [
                    (kps[idx * 10 + 2 * n] + c as f32) * s / scale,
                    (kps[idx * 10 + 2 * n + 1] + r as f32) * s / scale,
                ];
            }
            boxes.push(Face {
                bbox: [
                    (cx - bw / 2.0) / scale,
                    (cy - bh / 2.0) / scale,
                    bw / scale,
                    bh / scale,
                ],
                score,
                landmarks,
                embedding: None,
            });
        }
    }
    Ok(boxes)
}

fn iou(a: &[f32; 4], b: &[f32; 4]) -> f32 {
    let x0 = a[0].max(b[0]);
    let y0 = a[1].max(b[1]);
    let x1 = (a[0] + a[2]).min(b[0] + b[2]);
    let y1 = (a[1] + a[3]).min(b[1] + b[3]);
    let inter = (x1 - x0).max(0.0) * (y1 - y0).max(0.0);
    let union = a[2] * a[3] + b[2] * b[3] - inter;
    if union <= 0.0 {
        0.0
    } else {
        inter / union
    }
}

fn nms(mut faces: Vec<Face>, iou_threshold: f32) -> Vec<Face> {
    faces.sort_by(|a, b| b.score.total_cmp(&a.score));
    let mut keep: Vec<Face> = Vec::new();
    for f in faces {
        if keep.iter().all(|k| iou(&k.bbox, &f.bbox) < iou_threshold) {
            keep.push(f);
        }
    }
    keep
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A model whose box or landmark output is shorter than its score
    /// output is an error, not a panic (F9).
    #[test]
    fn short_model_outputs_are_an_error_not_a_panic() {
        let (cols, rows) = (4usize, 2usize);
        let cells = cols * rows;
        let cls = vec![1.0f32; cells];
        let obj = vec![1.0f32; cells];
        let bbox = vec![0.0f32; cells * 4];
        let kps = vec![0.0f32; cells * 10];
        assert_eq!(
            decode_stride(&cls, &obj, &bbox, &kps, 8, cols, rows, 0.5, 1.0)
                .unwrap()
                .len(),
            cells
        );
        let short_bbox = vec![0.0f32; cells * 4 - 1];
        let e = decode_stride(&cls, &obj, &short_bbox, &kps, 8, cols, rows, 0.5, 1.0)
            .unwrap_err()
            .to_string();
        assert!(e.contains("short"), "{}", e);
        let short_kps = vec![0.0f32; 3];
        assert!(decode_stride(&cls, &obj, &bbox, &short_kps, 8, cols, rows, 0.5, 1.0).is_err());
        let short_cls = vec![1.0f32; cells - 1];
        assert!(decode_stride(&short_cls, &obj, &bbox, &kps, 8, cols, rows, 0.5, 1.0).is_err());
    }

    /// A NaN score is never a face: `clamp` passes NaN through, and a
    /// `score < threshold` test would keep it and rank it first.
    #[test]
    fn a_nan_score_does_not_pass_the_threshold() {
        let (cols, rows) = (2usize, 1usize);
        let cells = cols * rows;
        let cls = vec![f32::NAN, 0.9];
        let obj = vec![1.0f32, 0.9];
        let bbox = vec![0.0f32; cells * 4];
        let kps = vec![0.0f32; cells * 10];
        let faces = decode_stride(&cls, &obj, &bbox, &kps, 8, cols, rows, 0.5, 1.0).unwrap();
        assert_eq!(faces.len(), 1);
        assert!(!faces[0].score.is_nan());
        assert!((faces[0].score - 0.9).abs() < 1e-6);
        // Threshold arithmetic aside, a NaN threshold accepts nothing either.
        let none = decode_stride(&cls, &obj, &bbox, &kps, 8, cols, rows, f32::NAN, 1.0).unwrap();
        assert!(none.is_empty());
    }

    /// A model with other output names is refused by name at load time.
    #[test]
    fn a_detector_with_other_output_names_is_named_as_missing() {
        assert!(missing_outputs(&expected_outputs()).is_empty());
        let yunet_2022: Vec<String> = ["loc", "conf", "iou"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let missing = missing_outputs(&yunet_2022);
        assert_eq!(missing.len(), 12);
        assert_eq!(missing[0], "cls_8");
        let mut short = expected_outputs();
        short.retain(|n| n != "kps_32");
        assert_eq!(missing_outputs(&short), vec!["kps_32".to_string()]);
    }

    fn noisy(w: usize, h: usize) -> Grey {
        let mut g = Grey::new(w, h);
        let mut s = 0x2545_f491_4f6c_dd1du64;
        for v in g.data.iter_mut() {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *v = (s >> 56) as u8;
        }
        g
    }

    /// At unit scale the canvas holds the input rows, unchanged, with zero
    /// padding on the right; the warp the letterbox took before gave the
    /// same pixels (it is the identity there) at 200 times the cost.
    #[test]
    fn letterbox_at_unit_scale_is_a_row_copy() {
        let img = noisy(480, 640);
        let (canvas, s) = letterbox(&img, 640, 640);
        assert_eq!(s, 1.0);
        assert_eq!((canvas.width, canvas.height), (640, 640));
        for y in 0..640 {
            assert_eq!(
                &canvas.data[y * 640..y * 640 + 480],
                &img.data[y * 480..(y + 1) * 480]
            );
            assert!(canvas.data[y * 640 + 480..(y + 1) * 640]
                .iter()
                .all(|&v| v == 0));
        }
        // The identity warp itself agrees, so the shortcut changed no pixel.
        let warped = img.warp_affine(&[[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]], 480, 640);
        assert_eq!(warped, img);
    }

    /// Any other frame size still goes through the warp and comes out scaled.
    #[test]
    fn letterbox_scales_other_sizes() {
        let img = noisy(1280, 720);
        let (canvas, s) = letterbox(&img, 640, 640);
        assert_eq!(s, 0.5);
        let inv = [[2.0, 0.0, 0.0], [0.0, 2.0, 0.0]];
        let want = img.warp_affine(&inv, 640, 360);
        for y in 0..360 {
            assert_eq!(
                &canvas.data[y * 640..(y + 1) * 640],
                &want.data[y * 640..(y + 1) * 640]
            );
        }
        assert!(canvas.data[360 * 640..].iter().all(|&v| v == 0));
    }

    #[test]
    fn nms_drops_overlaps_keeps_best() {
        let mk = |x, s| Face {
            bbox: [x, 0.0, 10.0, 10.0],
            score: s,
            landmarks: [[0.0; 2]; 5],
            embedding: None,
        };
        let out = nms(vec![mk(0.0, 0.5), mk(1.0, 0.9), mk(50.0, 0.7)], 0.3);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].score, 0.9);
        assert_eq!(out[1].bbox[0], 50.0);
    }
}
