//! ONNX Runtime, loaded dynamically from the distro's `libonnxruntime.so`.

use anyhow::{anyhow, Context, Result};
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use std::path::Path;
use std::sync::OnceLock;

/// Where Arch's `onnxruntime-cpu` installs the library. `ORT_DYLIB_PATH` overrides it.
pub const SYSTEM_LIBRARY: &str = "/usr/lib/libonnxruntime.so";

static INIT: OnceLock<Result<(), String>> = OnceLock::new();

/// Load the runtime once for the process. Safe to call from anywhere.
pub fn init() -> Result<()> {
    let r = INIT.get_or_init(|| {
        let path = std::env::var("ORT_DYLIB_PATH").unwrap_or_else(|_| SYSTEM_LIBRARY.to_string());
        let builder = ort::init_from(&path).map_err(|e| format!("load {}: {}", path, e))?;
        builder.with_name("faceauth").commit();
        log::info!("onnxruntime loaded from {}", path);
        Ok(())
    });
    r.clone().map_err(|e| anyhow!(e))
}

pub fn session(path: impl AsRef<Path>, threads: usize) -> Result<Session> {
    init()?;
    let threads = std::env::var("FACEAUTH_ORT_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(threads);
    let p = path.as_ref();
    // The builder's errors carry the builder back and are not Send; flatten them to text.
    let text = |e: ort::Error<_>| anyhow!("{}", e);
    Session::builder()?
        .with_optimization_level(GraphOptimizationLevel::Level3)
        .map_err(text)?
        .with_intra_threads(threads)
        .map_err(text)?
        // Worker threads spin-wait between operators by default, which triples
        // the CPU time of an inference for a small gain in latency. This runs
        // on laptops, every couple of seconds, for the whole session: sleep.
        .with_intra_op_spinning(false)
        .map_err(text)?
        .with_inter_op_spinning(false)
        .map_err(text)?
        .commit_from_file(p)
        .with_context(|| format!("load model {}", p.display()))
}

/// Human-readable inputs and outputs of a model, for `faceauth engine inspect`.
pub fn describe(path: impl AsRef<Path>) -> Result<String> {
    let s = session(path, 1)?;
    let mut out = String::new();
    for (kind, list) in [("input", s.inputs()), ("output", s.outputs())] {
        for o in list {
            out += &format!("{:<6} {:<12} {:?}\n", kind, o.name(), o.dtype());
        }
    }
    Ok(out)
}
