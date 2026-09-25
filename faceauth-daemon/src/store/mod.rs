//! Enrolment templates: fixed-length embeddings, never images.
//!
//! One file per user. On a machine with a TPM 2.0 the file is
//! `<dir>/<user>.cred`: the JSON sealed by `systemd-creds` (AES-256-GCM under
//! a key only this TPM unwraps; no PCR policy, so a kernel or firmware update
//! does not strand the templates), bound to the credential name
//! `faceauth-<user>` so one user's blob cannot be renamed into another's.
//! The credential is scoped to root (`--uid=0`), which systemd only allows
//! with the host secret in the mix (`host+tpm2`, `/var/lib/systemd/
//! credential.secret`, root-only): PID 1 then refuses to unseal or mint one
//! for any caller that is not root. So a copy of the file is useless off
//! this machine, and on it only root can open it or forge one.
//! There is no recovery key anywhere on disk, by design: templates that
//! cannot be unsealed are re-enrolled (enrolment sets an unreadable blob
//! aside and starts fresh). Without a working TPM the file is `<user>.json`,
//! plaintext, root 0600, and every surface says so (`doctor`, enrolment). A
//! plaintext file met by a store that can seal is sealed on first load and
//! the plaintext unlinked from the live tree; filesystem snapshots taken
//! before that still hold it. Sealing is sticky: a store that finds a sealed
//! file but cannot seal (a TPM that failed its probe at startup) refuses to
//! write plaintext rather than downgrade.
//!
//! Several templates per user (glasses, lighting, angle) are kept as separate
//! entries and matched by the best score, which is how variants merge into one
//! identity without averaging away what makes each distinct. Each template
//! records the camera it was enrolled on and only matches on that camera: a
//! camera swapped in for the enrolled one gets nothing to match against.
//! Every template names its camera and every set names the account's uid;
//! a file missing either is from before this was required, does not parse,
//! and reads as unreadable (re-enrol), never as a match.

mod files;
mod seal;
mod templates;
#[cfg(test)]
mod test_support;

pub use files::{current_uid, now_secs, Store};
pub use seal::{classify_creds_failure, is_definitive, Sealing, UnsealFailure};
pub use templates::{
    EverydayDeg, GestureCal, Template, UserTemplates, FORMAT_VERSION, MAX_TEMPLATES,
};
