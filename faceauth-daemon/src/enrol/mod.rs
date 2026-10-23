//! The enrollment walk-through: a guided session that steers the person
//! through the looks the identity needs, with a window drawing a dot they
//! move into targets. The daemon owns the camera, judges every frame and
//! stores the templates; the window (a Quickshell plugin, run as the user)
//! only draws what the daemon tells it, one line per frame: where the face
//! is, how big, which way it is turned, and whether that counts for the
//! step at hand. No image ever leaves the daemon.
//!
//! The session is opened by root (the setup script's `sudo faceauth enroll
//! --guided`), which waits for the outcome. The person's own window
//! watches the stream and sends Continue, Redo and Cancel.
//!
//! The terminal enrollments (`--terminal`, `--look`) run here too, with no
//! window, under the same rules for whose face is read (`terminal`).

mod dot;
mod everyday;
mod flash;
mod follow;
mod session;
mod steps;
mod stream;
mod terminal;
mod walk;

pub use dot::{
    distance_of, dot_of, hold_target, on_target, path_point, zone_of_point, Centre, Filter, Reach,
    Where, HOLD_ZONES, ON_TARGET, ON_TARGET_ACROSS, PLACE_MIN_COVAR, PLACE_MIN_EXTENT, REACH_FLOOR,
    RING_OF_REACH, SIZE_RIGHT, TOP,
};
pub use session::{active_for, add_watcher, control, is_active};
pub use steps::{
    message_for, round_at, round_count, Round, Step, READ_SLOTS, READ_SLOT_SECONDS, ROUNDS,
};
#[cfg(feature = "dev-tools")]
pub use stream::TickRecord;
pub use stream::{Start, Tick};
pub use terminal::{run as run_terminal, STRAIGHT_SECONDS};
pub use walk::run;
