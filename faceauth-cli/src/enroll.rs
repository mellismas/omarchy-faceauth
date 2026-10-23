//! The terminal enrollment: five looks, so the stored identity covers the
//! poses a person uses at the machine rather than one frontal view. Also
//! the note on how the saved templates rest.

use anyhow::{anyhow, Result};
use std::time::Duration;

/// What the saved path says about how the templates rest.
pub(super) fn at_rest_note(path: &str) -> String {
    if path.ends_with(".cred") {
        "Templates are sealed to this machine's TPM, root-only: a copy is useless anywhere else, and only root can open one here.".into()
    } else {
        "Note: templates are plaintext at rest (root 0600): the daemon could not seal them (its log says why).".into()
    }
}

/// How long each look of the terminal enrollment runs, and how many
/// templates it keeps.
const LOOK_SECONDS: f32 = 6.0;
const LOOK_COUNT: usize = 4;

/// The looks from the terminal, one daemon request with the camera open
/// throughout, so the daemon follows the one face from the first look to
/// the last, checks each look with the flash, and stores them once, after
/// checking them against the face it began with (A6). It first learns the
/// face from a straight look, and says so; the looks' prompts print here
/// from then, on the daemon's clock. A look that kept no frames is named
/// at the end, and nothing is asked in between.
pub(super) fn enroll_terminal(
    socket: &std::path::Path,
    user: &str,
    label: &str,
    only: &[String],
) -> Result<()> {
    use faceauth_daemon::auth::{Outcome, POSES, POSE_HINTS};
    if let Some(bad) = only.iter().find(|o| !POSES.contains(&o.as_str())) {
        return Err(anyhow!(
            "unknown look {:?} in --poses; one of {}",
            bad,
            POSES.join(", ")
        ));
    }
    let looks: Vec<(&str, &str)> = POSES
        .iter()
        .zip(POSE_HINTS.iter())
        .filter(|(p, _)| only.is_empty() || only.iter().any(|o| o == *p))
        .map(|(p, h)| (*p, *h))
        .collect();
    let poses: Vec<&str> = looks.iter().map(|(p, _)| *p).collect();
    println!(
        "Enrolling {} in {}, about {} s once it has your face. Keep only your own face in view. The camera first learns your face from a straight look, then keeps frames only in the look each prompt asks for, and only of that face.",
        user,
        if only.is_empty() {
            "five looks".to_string()
        } else {
            format!("these looks: {}", poses.join(", "))
        },
        (LOOK_SECONDS * looks.len() as f32).round()
    );
    // The daemon learns the face from a straight look before any look
    // counts: the center look when there is one, else a look of its own.
    let centre_first = looks[0].0 == "centre";
    if centre_first {
        println!("\nCENTRE: {}. Starting in 2 s.", looks[0].1);
    } else {
        println!("\nSTRAIGHT: look straight at the camera and hold still while it learns your face. Starting in 2 s.");
    }
    std::thread::sleep(Duration::from_secs(2));
    println!("Hold it.");
    let learned = std::sync::atomic::AtomicBool::new(false);
    let outcome = std::thread::scope(|s| {
        let request = s.spawn(|| {
            let heard = || learned.store(true, std::sync::atomic::Ordering::SeqCst);
            faceauth_daemon::server::enroll(
                socket,
                user,
                label,
                LOOK_SECONDS,
                LOOK_COUNT,
                &poses,
                &heard,
            )
        });
        // No pose is asked for until the daemon says it has the face: a
        // turn before then would be learned from, or keep it from learning.
        let wait = |until: &dyn Fn() -> bool| {
            while !until() && !request.is_finished() {
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        wait(&|| learned.load(std::sync::atomic::Ordering::SeqCst));
        if learned.load(std::sync::atomic::Ordering::SeqCst) {
            // Each look's prompt on the daemon's clock from then; the
            // center look goes on from the straight one.
            let started = std::time::Instant::now();
            for (k, (pose, hint)) in looks.iter().enumerate() {
                let at = Duration::from_secs_f32(LOOK_SECONDS * k as f32);
                wait(&|| started.elapsed() >= at);
                if request.is_finished() {
                    break;
                }
                if k == 0 && centre_first {
                    println!("Got your face. Keep looking straight at the camera.");
                } else {
                    println!("\n{}: {}.", pose.to_uppercase(), hint);
                }
            }
        }
        request
            .join()
            .unwrap_or_else(|_| Err(anyhow!("the enrollment request panicked")))
    })?;
    match &outcome {
        Outcome::Enrolled {
            added,
            total,
            consistency_min,
            consistency_mean,
            path,
            warning,
        } => {
            println!("\nSaved {} templates ({} new) to {}", total, added, path);
            println!(
                "Template self-consistency (pairwise cosine): min {:.3} mean {:.3}",
                consistency_min, consistency_mean
            );
            if let Some(w) = warning {
                println!("{}", w);
            }
            println!("{}", at_rest_note(path));
            Ok(())
        }
        Outcome::Error { message } => Err(anyhow!("enrollment failed: {}", message)),
        other => Err(anyhow!(
            "enrollment failed: {}",
            serde_json::to_string(other)?
        )),
    }
}
