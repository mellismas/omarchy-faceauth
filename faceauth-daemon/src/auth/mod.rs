//! One authentication attempt: burst, recognise, flash-response gate, decide.
//!
//! The decision needs `required_matches` frames whose best template similarity
//! is at or above the threshold. When the illuminator is available the strobe
//! follows a mask drawn for the attempt and every scored frame is a lit frame
//! whose pair passed the liveness gate; a gate denial ends the attempt as
//! `Denied` immediately.

mod attempt;
mod confirm;
mod consent_flow;
mod cooldown;
mod outcome;
mod poses;
mod rearm;
mod scan;

pub use attempt::{
    consent_floors, mesh_missing, scoring_cap, scoring_over, Authenticator, PROBE_LIKELY_THRESHOLD,
};
pub use confirm::{
    check_nod_embeddings, confirm, confirm_at_timeout, nod_frames_match, Confirm, NOD_FRAME_SLACK,
};
pub use consent_flow::{ConsentSession, Round, NODS_NEEDED};
pub use cooldown::Strikes;
#[cfg(feature = "dev-tools")]
pub use outcome::SweepFrame;
pub use outcome::{consent_denied, denied_text, refused, Cadence, Outcome, Refusal};
pub use poses::{
    level_of, pose_bin_accepts, pose_bin_accepts_at, DOWN_ABOVE_LEVEL, LEVEL_DEFAULT, POSES,
    POSE_HINTS, UP_BELOW_LEVEL,
};
pub use rearm::{Looked, RearmGate};
pub use scan::{scan_min_frac, scannable, Scan, SCAN_MIN_FACE_FRAC};
