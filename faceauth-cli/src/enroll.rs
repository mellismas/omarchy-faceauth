//! The guided enrolment: five short rounds, one per look, so the stored
//! identity covers the poses a person uses at the machine rather than one
//! frontal view. Also the note on how the saved templates rest.

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

/// Five short rounds, one per look, so the identity covers the range of
/// poses a person uses at the machine rather than one frontal view. Each
/// round keeps only frames in its pose; a round that reads nothing in its
/// pose is offered again.
pub(super) fn enroll_guided(
    socket: &std::path::Path,
    user: &str,
    label: &str,
    only: &[String],
) -> Result<()> {
    use faceauth_daemon::auth::{Outcome, POSES, POSE_HINTS};
    println!("Enrolling {} in {}. Each takes about five seconds; the camera reads only frames in the look it asked for.", user, if only.is_empty() { "five looks".to_string() } else { format!("these looks: {}", only.join(", ")) });
    let mut total = 0usize;
    for (pose, hint) in POSES.iter().zip(POSE_HINTS.iter()) {
        if !only.is_empty() && !only.iter().any(|o| o == pose) {
            continue;
        }
        loop {
            println!("\n{}: {}. Starting in 2 s.", pose.to_uppercase(), hint);
            std::thread::sleep(Duration::from_secs(2));
            println!("Hold it.");
            let round_label = format!("{}-{}", label, pose);
            let o =
                faceauth_daemon::server::enroll(socket, user, &round_label, 6.0, 4, Some(pose))?;
            match &o {
                Outcome::Enrolled {
                    added, total: t, ..
                } => {
                    println!("{} frames kept for {}.", added, pose);
                    total = *t;
                    break;
                }
                Outcome::Error { message } => {
                    println!("Not read: {}", message);
                    print!("Press Enter to try {} again, or s to skip it: ", pose);
                    use std::io::Write as _;
                    std::io::stdout().flush()?;
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    if line.trim().eq_ignore_ascii_case("s") {
                        break;
                    }
                }
                other => {
                    println!("{}", serde_json::to_string(other)?);
                    return Err(anyhow!("enrolment stopped"));
                }
            }
        }
    }
    println!("\nSaved: {} templates in all.", total);
    Ok(())
}
