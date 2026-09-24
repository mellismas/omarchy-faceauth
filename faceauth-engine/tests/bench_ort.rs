//! Resident memory and inference cost of the three ONNX sessions on the
//! installed models, kept in the tree so the numbers quoted in
//! `runtime.rs` can be re-measured when the models or the session options
//! change. Reads `/usr/share/faceauth/models` (or `FACEAUTH_MODELS`); no
//! camera, no daemon. Resident memory does not shrink when a session is
//! dropped, so each variant wants its own process:
//!
//! ```text
//! cargo test --release -p faceauth-engine --test bench_ort -- --ignored --nocapture --test-threads=1 bench_ort_pipeline
//! BENCH_LEVEL=1 BENCH_THREADS=2 cargo test --release -p faceauth-engine --test bench_ort -- --ignored --nocapture bench_ort_recognition_variant
//! ```
use faceauth_engine::{align, embed, Grey, Pipeline};
use std::time::Instant;

fn models_dir() -> String {
    std::env::var("FACEAUTH_MODELS").unwrap_or_else(|_| "/usr/share/faceauth/models".into())
}

/// A field of `/proc/self/status` in kB (or a count).
fn status(key: &str) -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    s.lines()
        .find(|l| l.starts_with(key))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// User plus system CPU of this process, in clock ticks (10 ms).
fn cpu_ticks() -> u64 {
    let s = std::fs::read_to_string("/proc/self/stat").unwrap();
    let rest = &s[s.rfind(')').unwrap() + 2..];
    let f: Vec<&str> = rest.split_whitespace().collect();
    f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()
}

fn frame(w: usize, h: usize) -> Grey {
    let mut g = Grey::new(w, h);
    for (i, v) in g.data.iter_mut().enumerate() {
        *v = ((i * 7 + i / w * 3) % 200) as u8 + 20;
    }
    g
}

/// Per-call wall and CPU time of `f`, after two warm-up calls.
fn time(name: &str, n: usize, mut f: impl FnMut()) {
    f();
    f();
    let (c0, t0) = (cpu_ticks(), Instant::now());
    for _ in 0..n {
        f();
    }
    let wall = t0.elapsed().as_secs_f64() * 1e3 / n as f64;
    let cpu = (cpu_ticks() - c0) as f64 * 10.0 / n as f64;
    println!(
        "{:<36} wall {:>7.1} ms  cpu {:>7.1} ms per call",
        name, wall, cpu
    );
}

extern "C" {
    fn malloc_trim(pad: usize) -> i32;
}

/// The daemon's own configuration: `Pipeline::load` through `runtime.rs`,
/// resident memory at each step, the cost of each model's inference, and
/// what dropping the pipeline gives back.
#[test]
#[ignore]
fn bench_ort_pipeline() {
    faceauth_engine::runtime::init().unwrap();
    let r0 = status("VmRSS:");
    println!(
        "after ort init: rss {} MB, threads {}",
        r0 / 1024,
        status("Threads:")
    );
    let t = Instant::now();
    let mut p = Pipeline::load(models_dir()).unwrap();
    let r1 = status("VmRSS:");
    println!(
        "pipeline load {:.0} ms: rss +{} MB (now {} MB, peak {} MB), threads {}",
        t.elapsed().as_secs_f64() * 1e3,
        (r1 - r0) / 1024,
        r1 / 1024,
        status("VmHWM:") / 1024,
        status("Threads:")
    );
    let img = frame(480, 640);
    let lm = [
        [210.0f32, 300.0],
        [270.0, 300.0],
        [240.0, 335.0],
        [215.0, 365.0],
        [265.0, 365.0],
    ];
    let crop = align::align_112(&img, &lm);
    time("YuNet detect (480x640 -> 640x640)", 30, || {
        let _ = p.detector.detect(&img, 0.6).unwrap();
    });
    time("ArcFace embed 112x112", 20, || {
        let _ = p.embedder.embed(&crop).unwrap();
    });
    if let Some(m) = p.mesh.as_mut() {
        time("FaceMesh landmarks 192x192", 30, || {
            let _ = m.landmarks(&img, [180.0, 260.0, 120.0, 140.0]).unwrap();
        });
    }
    let r2 = status("VmRSS:");
    println!(
        "after inference: rss {} MB, peak {} MB, threads {}",
        r2 / 1024,
        status("VmHWM:") / 1024,
        status("Threads:")
    );
    // The idle rule: release the recognition session, then embed again.
    let before = p.embedder.embed(&crop).unwrap();
    p.embedder.release();
    assert!(!p.embedder.is_loaded());
    let r3 = status("VmRSS:");
    println!(
        "after embedder release: rss {} MB, threads {}",
        r3 / 1024,
        status("Threads:")
    );
    let t = Instant::now();
    let after = p.embedder.embed(&crop).unwrap();
    println!(
        "reload on the next embed: {:.0} ms, rss {} MB, threads {}",
        t.elapsed().as_secs_f64() * 1e3,
        status("VmRSS:") / 1024,
        status("Threads:")
    );
    assert!(p.embedder.is_loaded());
    assert_eq!(before, after, "the reloaded session embeds the same");
    drop(p);
    let r4 = status("VmRSS:");
    unsafe { malloc_trim(0) };
    let r5 = status("VmRSS:");
    println!(
        "after drop: rss {} MB; after malloc_trim: {} MB, threads {}",
        r4 / 1024,
        r5 / 1024,
        status("Threads:")
    );
}

/// The recognition session under one combination of optimisation level
/// (`BENCH_LEVEL` 1, 2 or 3), intra-op threads (`BENCH_THREADS`) and
/// weight prepacking (`BENCH_NOPREPACK=1` turns it off): resident memory,
/// load time and the cost of one embed.
#[test]
#[ignore]
fn bench_ort_recognition_variant() {
    use ort::session::builder::GraphOptimizationLevel;
    use ort::session::Session;
    faceauth_engine::runtime::init().unwrap();
    let level = std::env::var("BENCH_LEVEL").unwrap_or_else(|_| "3".into());
    let threads: usize = std::env::var("BENCH_THREADS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(4);
    let noprepack = std::env::var("BENCH_NOPREPACK")
        .map(|v| v == "1")
        .unwrap_or(false);
    let text = |e: ort::Error<_>| anyhow::anyhow!("{}", e);
    let r0 = status("VmRSS:");
    let t = Instant::now();
    let mut b = Session::builder()
        .unwrap()
        .with_optimization_level(match level.as_str() {
            "1" => GraphOptimizationLevel::Level1,
            "2" => GraphOptimizationLevel::Level2,
            _ => GraphOptimizationLevel::Level3,
        })
        .map_err(text)
        .unwrap()
        .with_intra_threads(threads)
        .map_err(text)
        .unwrap()
        .with_intra_op_spinning(false)
        .map_err(text)
        .unwrap()
        .with_inter_op_spinning(false)
        .map_err(text)
        .unwrap();
    if noprepack {
        b = b
            .with_config_entry("session.disable_prepacking", "1")
            .map_err(text)
            .unwrap();
    }
    let mut s = b
        .commit_from_file(format!("{}/{}", models_dir(), embed::AURAFACE_FILE))
        .unwrap();
    // As runtime::session does after every load.
    unsafe { malloc_trim(0) };
    let load = t.elapsed().as_secs_f64() * 1e3;
    let r1 = status("VmRSS:");
    let crop = frame(112, 112);
    let name = s.inputs().first().unwrap().name().to_string();
    let mut run = || {
        let input =
            ort::value::Tensor::from_array(([1usize, 3, 112, 112], crop.to_nchw3(127.5, 127.5)))
                .unwrap();
        let _ = s.run(ort::inputs![name.as_str() => input]).unwrap();
    };
    run();
    run();
    let n = 20;
    let (c0, t0) = (cpu_ticks(), Instant::now());
    for _ in 0..n {
        run();
    }
    println!(
        "level {} threads {} prepack {}: load {:>5.0} ms, rss +{:>4} MB after load, +{:>4} MB after runs, peak {:>4} MB, embed wall {:>6.1} ms cpu {:>6.1} ms",
        level,
        threads,
        !noprepack,
        load,
        (r1 - r0) / 1024,
        (status("VmRSS:") - r0) / 1024,
        status("VmHWM:") / 1024,
        t0.elapsed().as_secs_f64() * 1e3 / n as f64,
        (cpu_ticks() - c0) as f64 * 10.0 / n as f64
    );
}

/// The three sessions loaded in the daemon's order with independent thread
/// counts (`BENCH_DET`, `BENCH_EMB`, `BENCH_MESH`), and the resident memory
/// after each: the runtime's arena grows differently with the pool size.
#[test]
#[ignore]
fn bench_ort_session_threads() {
    use faceauth_engine::{detect, mesh, runtime};
    let n = |k: &str, d: usize| -> usize {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let (det, emb, msh) = (n("BENCH_DET", 2), n("BENCH_EMB", 2), n("BENCH_MESH", 2));
    runtime::init().unwrap();
    let dir = models_dir();
    let r0 = status("VmRSS:");
    let _mesh = runtime::session(format!("{}/{}", dir, mesh::FACE_MESH_FILE), msh).unwrap();
    let r1 = status("VmRSS:");
    let _det = runtime::session(format!("{}/{}", dir, detect::YUNET_FILE), det).unwrap();
    let r2 = status("VmRSS:");
    let mut e = runtime::session(format!("{}/{}", dir, embed::AURAFACE_FILE), emb).unwrap();
    let r3 = status("VmRSS:");
    if std::env::var("BENCH_TRIM").is_ok() {
        unsafe { malloc_trim(0) };
        println!("after malloc_trim: +{} MB", (status("VmRSS:") - r0) / 1024);
    }
    let crop = frame(112, 112);
    let name = e.inputs().first().unwrap().name().to_string();
    let mut run = || {
        let input =
            ort::value::Tensor::from_array(([1usize, 3, 112, 112], crop.to_nchw3(127.5, 127.5)))
                .unwrap();
        let _ = e.run(ort::inputs![name.as_str() => input]).unwrap();
    };
    run();
    run();
    let (c0, t0) = (cpu_ticks(), Instant::now());
    for _ in 0..10 {
        run();
    }
    println!(
        "det {} emb {} mesh {}: mesh +{} MB, det +{} MB, emb +{} MB, total +{} MB, after runs +{} MB, peak {} MB, threads {}, embed wall {:.1} ms cpu {:.1} ms",
        det,
        emb,
        msh,
        (r1 - r0) / 1024,
        (r2 - r1) / 1024,
        (r3 - r2) / 1024,
        (r3 - r0) / 1024,
        (status("VmRSS:") - r0) / 1024,
        status("VmHWM:") / 1024,
        status("Threads:"),
        t0.elapsed().as_secs_f64() * 1e3 / 10.0,
        (cpu_ticks() - c0) as f64 * 10.0 / 10.0
    );
}
