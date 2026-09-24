//! Does ONNX Runtime need writable and executable memory? The unit sets
//! `MemoryDenyWriteExecute=yes`, which is the kernel's MDWE prctl, on the
//! measurement here: with MDWE on in this process (proved by a refused W+X
//! mapping) all three models load and run one inference each. If a later
//! ONNX Runtime needs a JIT, this test fails first and the unit line is
//! what to revisit.
//!
//! Needs the installed models (`/usr/share/faceauth/models`, or
//! `FACEAUTH_MODELS`) and a kernel with the prctl (6.3 or later); without
//! either it prints that it skipped, which is not a pass, unless
//! `FACEAUTH_REQUIRE_MODELS=1` turns the skip into a failure.
use faceauth_engine::{Grey, Pipeline};
use std::path::Path;

const PR_SET_MDWE: i32 = 65;
const PR_GET_MDWE: i32 = 66;
const PR_MDWE_REFUSE_EXEC_GAIN: u64 = 1;

fn skip(why: &str) {
    if std::env::var("FACEAUTH_REQUIRE_MODELS").is_ok() {
        panic!("{}", why);
    }
    eprintln!("SKIPPED (not a pass): {}", why);
}

#[test]
fn onnxruntime_runs_all_three_models_with_write_xor_execute_enforced() {
    let dir =
        std::env::var("FACEAUTH_MODELS").unwrap_or_else(|_| "/usr/share/faceauth/models".into());
    if !Path::new(&dir).join("glintr100.onnx").exists() {
        return skip(&format!("no models under {}", dir));
    }
    // SAFETY: prctl with integer arguments only; it changes this process's
    // own memory policy and nothing else.
    let set = unsafe { libc::prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0u64, 0u64, 0u64) };
    if set != 0 {
        return skip("this kernel has no PR_SET_MDWE");
    }
    // SAFETY: as above, a read of the policy.
    assert_eq!(
        unsafe { libc::prctl(PR_GET_MDWE, 0u64, 0u64, 0u64, 0u64) },
        1
    );
    // SAFETY: an anonymous mapping request that must be refused; on the
    // failure path nothing is mapped, and a success would be unmapped at once.
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            4096,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p != libc::MAP_FAILED {
        // SAFETY: the mapping above, 4096 bytes, unused.
        unsafe { libc::munmap(p, 4096) };
        panic!("MDWE is on but a W+X mapping was granted");
    }
    let mut pipeline = Pipeline::load(&dir).expect("load the three models under MDWE");
    let mut img = Grey::new(640, 480);
    for (i, v) in img.data.iter_mut().enumerate() {
        *v = ((i.wrapping_mul(2654435761)) >> 13) as u8;
    }
    pipeline
        .detector
        .detect(&img, 0.6)
        .expect("detector inference under MDWE");
    let mut crop = Grey::new(112, 112);
    for (i, v) in crop.data.iter_mut().enumerate() {
        *v = (i % 251) as u8;
    }
    let e = pipeline
        .embedder
        .embed(&crop)
        .expect("embedder inference under MDWE");
    assert_eq!(e.len(), 512);
    let mesh = pipeline.mesh.as_mut().expect("the face mesh is installed");
    mesh.landmarks(&img, [200.0, 150.0, 160.0, 200.0])
        .expect("mesh inference under MDWE");
}
