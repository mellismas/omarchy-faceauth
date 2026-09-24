//! Face matching engine for Omarchy FaceAuth: detect, align, embed, compare,
//! on ONNX Runtime loaded from the distro library at run time.
//!
//! Models (see `design/models.md` in the pack): YuNet for detection with five
//! landmarks, a similarity alignment to the ArcFace 112x112 template, and
//! AuraFace-v1 (`glintr100`) for 512-D embeddings. Grey frames are fed as three
//! identical channels.

pub mod align;
pub mod detect;
pub mod embed;
pub mod image;
pub mod liveness;
pub mod mesh;
pub mod motion;
pub mod pose;
pub mod runtime;

use anyhow::{Context, Result};
pub use image::Grey;
use std::path::Path;

/// One face found in a frame, with everything the daemon needs from it.
#[derive(Clone, Debug)]
pub struct Face {
    pub bbox: [f32; 4],
    pub score: f32,
    /// right eye, left eye, nose tip, right mouth corner, left mouth corner (image coordinates)
    pub landmarks: [[f32; 2]; 5],
    pub embedding: Option<Vec<f32>>,
}

pub struct Pipeline {
    pub detector: detect::YuNet,
    pub embedder: embed::ArcFace,
    /// The dense landmarks, when the model is installed; pose readers
    /// fall back to the detector's five points without it.
    pub mesh: Option<mesh::FaceMesh>,
}

impl Pipeline {
    pub fn load(models_dir: impl AsRef<Path>) -> Result<Self> {
        runtime::init()?;
        let d = models_dir.as_ref();
        let mesh_path = d.join(mesh::FACE_MESH_FILE);
        let mesh = if mesh_path.exists() {
            Some(
                mesh::FaceMesh::load(&mesh_path)
                    .with_context(|| format!("load {}", mesh_path.display()))?,
            )
        } else {
            None
        };
        Ok(Pipeline {
            detector: detect::YuNet::load(d.join(detect::YUNET_FILE))?,
            embedder: embed::ArcFace::load(d.join(embed::AURAFACE_FILE))?,
            mesh,
        })
    }

    /// Detect every face above `score_threshold`, embed the `max_embed` best.
    pub fn analyse(
        &mut self,
        img: &Grey,
        score_threshold: f32,
        max_embed: usize,
    ) -> Result<Vec<Face>> {
        let mut faces = self.detector.detect(img, score_threshold)?;
        faces.sort_by(|a, b| b.score.total_cmp(&a.score));
        for f in faces.iter_mut().take(max_embed) {
            let crop = align::align_112(img, &f.landmarks);
            f.embedding = Some(self.embedder.embed(&crop)?);
        }
        Ok(faces)
    }
}

/// Cosine similarity of two L2-normalised embeddings.
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}
