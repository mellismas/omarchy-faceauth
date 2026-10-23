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

mod anchor;
mod bounded;
mod detector;
mod fprint;
mod key;
mod passwordless;
mod requester;
mod round;
mod shell;
mod state;
mod wait;
mod window;

pub use anchor::{
    anchor_command, anchored_lock_state, ANCHOR_HELPER, ANCHOR_LIMIT, ANCHOR_READ,
    ANCHOR_UNIT_PROPERTIES, ANCHOR_WITHIN,
};
pub(crate) use bounded::run_bounded;
pub use detector::{NodDetector, Oscillation, ShakeDetector};
pub use fprint::{
    bus_policy_state, fprint_check, fprint_exit_code, fprint_offer, fprintd_lines, fprintd_reached,
    prints_of, status_of_message, FprintEnd, FprintLane, FprintOff, FprintWatch, BUS_POLICY_NAME,
    BUS_POLICY_TEXT, FPRINT, FPRINT_DEADLINE, FPRINT_MATCHED, FPRINT_SERVICE, FPRINT_TRIES,
    FPRINT_TRY_SECONDS, FPRINT_UNAVAILABLE,
};
pub(crate) use fprint::{send_fprint_status, stale_fprint_checks_stop};
pub(crate) use key::stale_checks_stop;
pub use key::{
    key_check, key_check_stock, key_lines_problem, key_offer, key_user_ok, lock_verdict, Asker,
    Fallback, KeyOff, KeyPolicy, KeyWatch, Unlocked, KEY, KEY_DEADLINE, KEY_FINISH,
    KEY_REPLY_WITHIN, KEY_TOUCHED,
};
pub use passwordless::{
    enable_passwordless, is_passwordless_command, passwordless_file, passwordless_timer_unit,
    run_passwordless_timer, PASSWORDLESS_MAX_MINUTES,
};
pub(crate) use requester::comm_of;
pub use requester::{
    boottime_now, caller_lane, clip, clip_command, forget_cookie_agent, kill_pinned,
    kill_requester, note_cookie_agent, polkit_requester, speaks_cookies, AgentPeer, Asked,
    CallerInfo, PolkitContext, COMMAND_CLIP, CONTEXTS,
};
pub use round::{parse_round, reads_to_deg, replay_round, round_line, RoundFrame, ROUND_HEADER};
pub use shell::{
    hyprland_instance, lock_state_from_monitors, lockstate_exit, notify, omarchy_path,
    omarchy_path_from_conf, session_locked, shell_answer, shell_call_pinned, LockState, Pin,
    LOCKSTATE_LOCKED, LOCKSTATE_UNKNOWN, LOCKSTATE_UNLOCKED, PIN_CHECK, USER_CALL_LIMIT,
    USER_CALL_WITHIN,
};
pub(crate) use state::send_beat;
pub use state::{
    peer_gone, process_exited, wipe_bytes, wipe_string, Answer, ConsentState, FprintStatus, Live,
    NoTurn, Place, Secret, Turn, CHANNEL_EXPIRES, CONSENT, CONSENT_PER_UID, DEFAULT_HOLD_MS,
    LOOK_GAP, QUEUE_UNSEEN,
};
pub use wait::{
    track, wait_for_nods, Gesture, LockQuestion, Track, LOCK_WATCHES_MAX, NOD_FRAMES_KEPT,
};
pub use window::{Dialog, ACK_DWELL, ACK_WAIT, HEARTBEAT};
