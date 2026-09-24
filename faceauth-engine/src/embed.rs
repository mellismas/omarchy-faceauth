//! ArcFace-style embedding with AuraFace-v1 `glintr100` (Apache-2.0):
//! 112x112 input normalised as `(v - 127.5) / 127.5`, 512-D output, L2-normalised.

use crate::image::Grey;
use crate::runtime;
use anyhow::{ensure, Context, Result};
use ort::session::Session;
use ort::value::Tensor;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const AURAFACE_FILE: &str = "glintr100.onnx";

pub struct ArcFace {
    /// None between `release` and the next `embed`, which reloads it.
    session: Option<Session>,
    path: PathBuf,
    input_name: String,
    pub dim: usize,
    last_used: Instant,
}

/// Intra-op threads for the recognition session; the trade is written up in
/// `runtime::session`.
pub const THREADS: usize = 2;

impl ArcFace {
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let session = Self::open(&path)?;
        let input = session.inputs().first().context("embedder: no input")?;
        let input_name = input.name().to_string();
        let dim = session
            .outputs()
            .first()
            .and_then(|o| {
                o.dtype()
                    .tensor_shape()
                    .map(|s| s.last().copied().unwrap_or(-1))
            })
            .filter(|&d| d > 0)
            .map(|d| d as usize)
            .unwrap_or(512);
        Ok(ArcFace {
            session: Some(session),
            path,
            input_name,
            dim,
            last_used: Instant::now(),
        })
    }

    fn open(path: &Path) -> Result<Session> {
        runtime::session(path, THREADS)
    }

    /// Drop the session. The model is by far the daemon's memory (the
    /// pipeline holds about 300 MB resident with it and about 60 MB
    /// without), and a laptop that is unlocked and not watching for
    /// presence has no use for it; the next `embed` reloads it in about
    /// 0.4 s. The trim hands the freed pages back to the OS at once instead
    /// of leaving them in the allocator (`bench_ort_pipeline` measures both).
    pub fn release(&mut self) {
        if self.session.take().is_some() {
            // SAFETY: malloc_trim takes no pointers and touches only the
            // allocator's own free lists; it is safe from any thread.
            unsafe {
                libc::malloc_trim(0);
            }
            log::info!("recognition model released; it reloads on the next attempt");
        }
    }

    /// Is the session loaded right now?
    pub fn is_loaded(&self) -> bool {
        self.session.is_some()
    }

    /// Time since the last embed or load, for the daemon's idle rule.
    pub fn idle_for(&self) -> Duration {
        self.last_used.elapsed()
    }

    pub fn embed(&mut self, crop: &Grey) -> Result<Vec<f32>> {
        ensure!(
            crop.width == 112 && crop.height == 112,
            "embedder wants 112x112, got {}x{}",
            crop.width,
            crop.height
        );
        self.last_used = Instant::now();
        if self.session.is_none() {
            let t = Instant::now();
            self.session = Some(Self::open(&self.path)?);
            log::info!(
                "recognition model reloaded in {} ms",
                t.elapsed().as_millis()
            );
        }
        let session = self.session.as_mut().context("embedder: no session")?;
        let tensor = Tensor::from_array(([1usize, 3, 112, 112], crop.to_nchw3(127.5, 127.5)))?;
        let outputs = session.run(ort::inputs![self.input_name.as_str() => tensor])?;
        let (_, data) = outputs[0].try_extract_tensor::<f32>()?;
        let mut v = data.to_vec();
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            v.iter_mut().for_each(|x| *x /= norm);
        }
        Ok(v)
    }
}
