//! Presence watch: is the enrolled user in front of the machine?
//!
//! Low duty by construction: every `tick_seconds` the watch takes the camera
//! for a fraction of a second, grabs a few frames with the illuminator on,
//! detects on the last one and, on the identity ticks, strobes one lit/unlit
//! pair through the flash gate and embeds the face to check it against the
//! templates. A print that fails the gate is not the user, so it cannot keep
//! the session marked present. The camera is closed between ticks, so an
//! authentication attempt never waits for more than one tick.
//!
//! Two modes (`[presence] mode`), ruled in the round-4 review (Q9). In the
//! `default` mode any face turned to the screen holds the lock off: a
//! laptop handed to someone stays open while they look at it, and the
//! session locks only once the chair has been empty for `away_seconds`
//! (never by time, when that is "never").
//! Identity is checked every `IDENTIFY_EVERY` ticks there, but only to tell
//! the shell who is holding the clock and to take the shape reference for a
//! hidden face; it never decides the lock. In the `secure` mode identity is
//! checked on every tick, only a face that passes holds the clock, the first
//! failed check locks the session at once, and an empty chair locks after
//! `secure_away_seconds`. Each mode reads its own away time, the one of the
//! mode in force, so a switch at run time takes the other time.
//!
//! State: `Present` (someone the mode accepts is holding the clock),
//! `Stranger` (default mode only: a face whose identity check failed is
//! holding it), `Away` (nobody has held it for the mode's away time, or in the
//! secure mode a check failed; the session is locked once on the
//! transition). In the default mode a face the detector only half sees (a
//! hand over the chin while reading) is not absence: while no face is found,
//! the away clock is held after the last full sighting while the shape
//! under the last face box is unchanged, for the obscured face lock time:
//! `obscured_face_lock` ("never" as shipped) in the default mode and
//! `secure_obscured_face_lock` (2 minutes) in the secure mode. The state
//! is answered over the socket (the `presence_mode` query) to root and the
//! watched user.

mod config;
mod lock;
mod observe;
mod run;
#[cfg(test)]
mod test_support;
mod watch;

pub use config::{
    presence_mode, set_presence_mode, AwayTime, LockWord, ObscuredFaceLock, PresenceConfig,
    PresenceMode, SECURE_OBSCURED_LOCK_MINUTES, SECURE_OBSCURED_LOCK_RANGE,
};
pub use lock::{SessionLock, LOCK_CHECK_TICKS, LOCK_HELPER, SESSION_LOCK};
pub(crate) use observe::{observe_in, probe_look, Observation};
pub use observe::{
    ATTENTIVE_MAX_ROLL_DEG, ATTENTIVE_MAX_YAW, FACE_SETTLE_MAX, LOOK_SEE_BUDGET, NEAR_MISS_SLACK,
    PRESENCE_STROBE_WINDOW,
};
pub use run::{run, snapshot, Snapshot};
pub use watch::{
    partial_holds, same_shape, tick_for, State, DEFAULT_MODE_TICK_SECONDS, IDENTIFY_EVERY,
    SAME_SHAPE,
};
