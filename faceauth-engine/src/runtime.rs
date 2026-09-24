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

/// A session over `path` with `threads` intra-op workers (`FACEAUTH_ORT_THREADS`
/// overrides the count for every session).
///
/// The options are set from `tests/bench_ort.rs` on the reference machine
/// (i7-8650U, the installed models, 2026-09-24; rerun it before changing
/// them). The recognition model is the whole cost. Loading it leaves 430
/// to 630 MB resident depending on the pool sizes, but only 281 MB of that
/// is the session: the rest is the file's parse and the load's temporaries,
/// freed but kept by the allocator, so the trim below hands them back and
/// the pipeline settles at about 300 MB. With the trim, Level1 saves no
/// memory and embeds slower on every thread count (150 to 200 ms against
/// 109 to 145 ms) for more CPU, so Level3 stays; turning weight prepacking
/// off saves nothing either. Per embed, four threads take 109 ms wall for
/// 382 ms of CPU and two take 145 ms for 282 ms; a scan spends the wall
/// time inside a 200 ms frame budget either way, so recognition runs on
/// two and the detector and mesh (9 ms and 4 ms a call) on two. The daemon
/// can give the recognition session back entirely while idle
/// (`ArcFace::release`).
pub fn session(path: impl AsRef<Path>, threads: usize) -> Result<Session> {
    init()?;
    let threads = std::env::var("FACEAUTH_ORT_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(threads);
    let p = path.as_ref();
    // The builder's errors carry the builder back and are not Send; flatten them to text.
    let text = |e: ort::Error<_>| anyhow!("{}", e);
    let session = Session::builder()?
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
        .with_context(|| format!("load model {}", p.display()))?;
    // The load parses the whole file and copies its weights out; the parse
    // is freed but glibc keeps the pages (up to 350 MB for the recognition
    // model) unless asked to return them.
    // SAFETY: malloc_trim takes no pointers and touches only the allocator's
    // own free lists; it is safe from any thread.
    unsafe {
        libc::malloc_trim(0);
    }
    Ok(session)
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
