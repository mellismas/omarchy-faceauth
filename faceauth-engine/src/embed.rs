//! ArcFace-style embedding with AuraFace-v1 `glintr100` (Apache-2.0):
//! 112x112 input normalised as `(v - 127.5) / 127.5`, 512-D output, L2-normalised.

use crate::image::Grey;
use crate::runtime;
use anyhow::{ensure, Context, Result};
use ort::session::Session;
use ort::value::Tensor;
use std::path::Path;

pub const AURAFACE_FILE: &str = "glintr100.onnx";

pub struct ArcFace {
    session: Session,
    input_name: String,
    pub dim: usize,
}

impl ArcFace {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let session = runtime::session(path, 4)?;
        let input = session.inputs().first().context("embedder: no input")?;
        let input_name = input.name().to_string();
        let dim = session
            .outputs()
            .first()
            .and_then(|o| o.dtype().tensor_shape().map(|s| s.last().copied().unwrap_or(-1)))
            .filter(|&d| d > 0)
            .map(|d| d as usize)
            .unwrap_or(512);
        Ok(ArcFace { session, input_name, dim })
    }

    pub fn embed(&mut self, crop: &Grey) -> Result<Vec<f32>> {
        ensure!(crop.width == 112 && crop.height == 112, "embedder wants 112x112, got {}x{}", crop.width, crop.height);
        let tensor = Tensor::from_array(([1usize, 3, 112, 112], crop.to_nchw3(127.5, 127.5)))?;
        let outputs = self.session.run(ort::inputs![self.input_name.as_str() => tensor])?;
        let (_, data) = outputs[0].try_extract_tensor::<f32>()?;
        let mut v = data.to_vec();
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            v.iter_mut().for_each(|x| *x /= norm);
        }
        Ok(v)
    }
}
