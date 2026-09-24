//! YuNet face detector (OpenCV Zoo, MIT). Decoding follows OpenCV's
//! `FaceDetectorYN`: three strides, per-cell class and objectness scores,
//! box offsets relative to the cell, and five landmarks.

use crate::image::Grey;
use crate::runtime;
use crate::Face;
use anyhow::{Context, Result};
use ort::session::Session;
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
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let session = runtime::session(path, 2)?;
        let input = session.inputs().first().context("YuNet: no input")?;
        let input_name = input.name().to_string();
        let fixed = match input.dtype().tensor_shape() {
            Some(s) if s.len() == 4 && s[2] > 0 && s[3] > 0 => Some((s[3] as usize, s[2] as usize)),
            _ => None,
        };
        Ok(YuNet {
            session,
            input_name,
            fixed,
        })
    }

    pub fn input_size(&self) -> Option<(usize, usize)> {
        self.fixed
    }

    /// Faces above `threshold` (score = sqrt(cls * obj)), after NMS, in image coordinates.
    pub fn detect(&mut self, img: &Grey, threshold: f32) -> Result<Vec<Face>> {
        // The network wants a multiple of 32; a fixed-size model wants exactly its size.
        let (net, scale) = match self.fixed {
            Some((fw, fh)) => {
                let s = (fw as f32 / img.width as f32).min(fh as f32 / img.height as f32);
                let mut canvas = Grey::new(fw, fh);
                let rw = (img.width as f32 * s) as usize;
                let rh = (img.height as f32 * s) as usize;
                let inv = [[1.0 / s, 0.0, 0.0], [0.0, 1.0 / s, 0.0]];
                let resized = img.warp_affine(&inv, rw, rh);
                for y in 0..rh {
                    canvas.data[y * fw..y * fw + rw]
                        .copy_from_slice(&resized.data[y * rw..(y + 1) * rw]);
                }
                (canvas, s)
            }
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
            let get = |name: &str| -> Result<Vec<f32>> {
                let (_, data) =
                    outputs[format!("{}_{}", name, stride).as_str()].try_extract_tensor::<f32>()?;
                Ok(data.to_vec())
            };
            let (cls, obj, bbox, kps) = (get("cls")?, get("obj")?, get("bbox")?, get("kps")?);
            boxes.extend(decode_stride(
                &cls, &obj, &bbox, &kps, stride, cols, rows, threshold, scale,
            )?);
        }
        Ok(nms(boxes, NMS_IOU))
    }
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
            if score < threshold {
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
