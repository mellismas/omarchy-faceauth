//! Per-frame costs of the pure-Rust stages, before and after the round-4
//! changes, kept in the tree so the numbers in the code comments can be
//! re-measured. Release only:
//!
//! ```text
//! cargo test --release -p faceauth-engine --test bench_frame -- --ignored --nocapture
//! ```
use faceauth_engine::Grey;
use std::hint::black_box;
use std::time::Instant;

fn bench(name: &str, iters: usize, mut f: impl FnMut()) -> f64 {
    for _ in 0..3 {
        f();
    }
    let mut v: Vec<f64> = (0..iters)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed().as_secs_f64() * 1e6
        })
        .collect();
    v.sort_by(|a, b| a.total_cmp(b));
    let med = v[v.len() / 2];
    println!("{:<48} median {:>8.1} us  (min {:>8.1})", name, med, v[0]);
    med
}

fn noisy(w: usize, h: usize) -> Grey {
    let mut g = Grey::new(w, h);
    let mut s = 0x9e37_79b9_7f4a_7c15u64;
    for v in g.data.iter_mut() {
        s = s
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *v = (s >> 56) as u8;
    }
    g
}

/// The letterbox as it was: a bilinear warp at unit scale, then a row copy.
fn letterbox_by_warp(img: &Grey, fw: usize, fh: usize) -> Grey {
    let s = (fw as f32 / img.width as f32).min(fh as f32 / img.height as f32);
    let mut canvas = Grey::new(fw, fh);
    let rw = (img.width as f32 * s) as usize;
    let rh = (img.height as f32 * s) as usize;
    let inv = [[1.0 / s, 0.0, 0.0], [0.0, 1.0 / s, 0.0]];
    let resized = img.warp_affine(&inv, rw, rh);
    for y in 0..rh {
        canvas.data[y * fw..y * fw + rw].copy_from_slice(&resized.data[y * rw..(y + 1) * rw]);
    }
    canvas
}

/// The letterbox as it is at unit scale: rows copied straight in.
fn letterbox_by_copy(img: &Grey, fw: usize, fh: usize) -> Grey {
    let mut canvas = Grey::new(fw, fh);
    for y in 0..img.height {
        canvas.data[y * fw..y * fw + img.width]
            .copy_from_slice(&img.data[y * img.width..(y + 1) * img.width]);
    }
    canvas
}

/// The tensor as it was: one plane collected, then copied three times.
fn nchw3_by_plane(g: &Grey, mean: f32, scale: f32) -> Vec<f32> {
    let n = g.width * g.height;
    let mut v = Vec::with_capacity(3 * n);
    let plane: Vec<f32> = g.data.iter().map(|&p| (p as f32 - mean) / scale).collect();
    for _ in 0..3 {
        v.extend_from_slice(&plane);
    }
    v
}

#[test]
#[ignore]
fn bench_frame_stages() {
    println!(
        "loadavg: {}",
        std::fs::read_to_string("/proc/loadavg")
            .unwrap_or_default()
            .trim()
    );
    let img = noisy(480, 640);
    let (fw, fh) = (640usize, 640usize);
    bench("letterbox 480x640 -> 640x640, warp (before)", 100, || {
        black_box(letterbox_by_warp(&img, fw, fh));
    });
    bench(
        "letterbox 480x640 -> 640x640, row copy (after)",
        100,
        || {
            black_box(letterbox_by_copy(&img, fw, fh));
        },
    );
    let canvas = letterbox_by_copy(&img, fw, fh);
    bench("to_nchw3 640x640, plane then copies (before)", 100, || {
        black_box(nchw3_by_plane(&canvas, 0.0, 1.0));
    });
    bench("to_nchw3 640x640, one pass (after)", 100, || {
        black_box(canvas.to_nchw3(0.0, 1.0));
    });
    let raw: Vec<u16> = (0..640 * 480).map(|i| ((i * 977) % 1024) as u16).collect();
    bench("capture next: 8-bit copy + oriented (before)", 200, || {
        let mut g8 = Grey::new(640, 480);
        for (o, &v) in g8.data.iter_mut().zip(&raw) {
            *o = (v >> 2) as u8;
        }
        black_box(g8.oriented(true, true, true));
    });
    bench("capture next: fused from_u10_oriented (after)", 200, || {
        black_box(Grey::from_u10_oriented(&raw, 640, 480, true, true, true));
    });
    bench("frame mean, f64 running sum (before)", 200, || {
        black_box(img.data.iter().map(|&v| v as f64).sum::<f64>() / img.data.len() as f64);
    });
    bench("frame mean, integer sum (after)", 200, || {
        black_box(img.mean());
    });
}
