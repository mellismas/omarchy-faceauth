//! Consent for elevation: the part of an authentication that proves the person
//! the camera sees *wants this request*, and not merely that they are present.
//!
//! The calling program (sudo, the polkit helper, anything that loads the PAM
//! module) cannot be trusted to relay a "yes": code running as the user can
//! answer any prompt it is shown. So the yes comes from something only the
//! daemon observes: a nod pattern in front of the camera it owns. Around it,
//! for the human: one window on the desktop, opened by the daemon and not by
//! the caller, naming the command and the process asking, with buttons to
//! dismiss it or, when the requester is named, to kill it. Nothing elevates
//! silently, and no
//! window means no elevation (an ssh session gets the password path).

mod detector;
mod passwordless;
mod requester;
mod round;
mod shell;
mod state;
mod wait;
mod window;

pub use detector::{NodDetector, Oscillation, ShakeDetector};
pub use passwordless::{
    enable_passwordless, is_passwordless_command, passwordless_file, passwordless_timer_unit,
    run_passwordless_timer, PASSWORDLESS_MAX_MINUTES,
};
pub use requester::{
    clip, clip_command, polkit_requester, AgentPeer, CallerInfo, PolkitContext, COMMAND_CLIP,
    CONTEXTS,
};
pub(crate) use requester::{comm_of, ppid_of, read_proc, real_uid_of};
pub use round::{parse_round, reads_to_deg, replay_round, round_line, RoundFrame, ROUND_HEADER};
pub use shell::{
    notify, omarchy_path, omarchy_path_from_conf, session_locked, shell_answer, shell_call,
};
pub use state::{
    peer_gone, wipe_string, Answer, ConsentState, Live, NoTurn, Place, Secret, Turn, CONSENT,
    CONSENT_PER_UID,
};
pub use wait::{track, wait_for_nods, Gesture, Track, NOD_FRAMES_KEPT};
pub use window::{Dialog, ACK_DWELL, ACK_WAIT, HEARTBEAT};
