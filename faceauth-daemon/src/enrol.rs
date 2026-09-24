//! The enrolment walk-through: a guided session that steers the person
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

use crate::auth::{Authenticator, Outcome, POSES, POSE_HINTS};
use crate::capture::IrCapture;
use crate::store::{now_secs, Template, UserTemplates, MAX_TEMPLATES};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How the setup script starts a session: the label its templates carry
/// and the screen to begin at ("welcome" for a first enrolment, "distance"
/// for Add Look).
#[derive(Clone, Debug, Deserialize)]
pub struct Start {
    pub label: String,
    #[serde(default)]
    pub start_at: Option<String>,
}

/// One line of the stream the window draws from. Positions are in ring
/// units: 0 is the centre, 1 is the ring. The daemon does the mapping so
/// the window and the judgement agree.
#[derive(Clone, Debug, Serialize)]
pub struct Tick {
    /// "welcome", "centre", "path", "hold", "verify", "done", "failed".
    pub step: &'static str,
    /// For hold steps, the look the target sits at.
    pub zone: Option<&'static str>,
    pub face: bool,
    /// Face width as a fraction of the frame's shorter side, and what it says.
    pub size: f32,
    pub distance: &'static str,
    /// The dot: where the head points, relative to this person's centre.
    pub dot_x: f32,
    pub dot_y: f32,
    /// The target the dot should be in.
    pub target_x: f32,
    pub target_y: f32,
    /// The dot is within the target.
    pub on_target: bool,
    /// The readings behind the dot, for a development build's record only:
    /// the window draws none of them, and a per-frame head-pose stream to
    /// any same-uid watcher is not something the package sends (H23).
    #[cfg(feature = "dev-tools")]
    pub record: TickRecord,
    pub taken: usize,
    pub wanted: usize,
    pub message: String,
    /// For the gesture and everyday rounds: which round, of how many, the
    /// kind, the seconds left in it, whether it is still counting down to
    /// start, and for the reading round which text slot is showing.
    pub round: Option<&'static str>,
    pub round_no: usize,
    pub round_of: usize,
    pub seconds_left: f32,
    pub countdown: bool,
    pub read_slot: Option<usize>,
}

/// The smoothed readings, the raw ones, the mesh's pose and the face's
/// place in the frame (0..1), flattened into the tick in a development
/// build.
#[cfg(feature = "dev-tools")]
#[derive(Clone, Debug, Default, Serialize)]
pub struct TickRecord {
    pub yaw: f32,
    pub pitch: f32,
    pub roll: f32,
    pub raw_yaw: f32,
    pub raw_pitch: f32,
    /// The nose-based tilt, for comparison; `pitch` is the mouth-based one.
    pub nose_pitch: f32,
    /// The dense mesh's head pose in degrees.
    pub mesh_yaw: Option<f32>,
    pub mesh_pitch: Option<f32>,
    pub mesh_roll: Option<f32>,
    pub mesh_score: Option<f32>,
    pub x: f32,
    pub y: f32,
    /// This person's centre, once learned.
    pub centre_yaw: f32,
    pub level: f32,
}

impl Tick {
    fn blank(step: &'static str, message: &str) -> Tick {
        Tick {
            step,
            zone: None,
            face: false,
            size: 0.0,
            distance: "far",
            dot_x: 0.0,
            dot_y: 0.0,
            target_x: 0.0,
            target_y: 0.0,
            on_target: false,
            #[cfg(feature = "dev-tools")]
            record: TickRecord {
                x: 0.5,
                y: 0.5,
                ..Default::default()
            },
            taken: 0,
            wanted: 0,
            message: message.into(),
            round: None,
            round_no: 0,
            round_of: 0,
            seconds_left: 0.0,
            countdown: false,
            read_slot: None,
        }
    }
}

#[cfg(test)]
mod tick_tests {
    use super::Tick;

    /// H23: the stream carries exactly the fields Enrol.qml reads (its
    /// `onRead` parser), and nothing per-frame that the window never draws.
    /// A development build adds the `record` block for tuning.
    #[test]
    fn the_tick_serialises_the_fields_the_window_reads() {
        let tick = Tick::blank("welcome", "hello");
        let v: serde_json::Value = serde_json::to_value(&tick).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        let mut window_reads = vec![
            "step",
            "zone",
            "face",
            "size",
            "distance",
            "dot_x",
            "dot_y",
            "target_x",
            "target_y",
            "on_target",
            "taken",
            "wanted",
            "message",
            "round",
            "round_no",
            "round_of",
            "seconds_left",
            "countdown",
            "read_slot",
        ];
        if cfg!(feature = "dev-tools") {
            window_reads.push("record");
        }
        window_reads.sort_unstable();
        assert_eq!(keys, window_reads);
    }
}

/// A session that records a kind of round replaces every earlier
/// session's samples of that kind: the first round of the kind in this
/// session clears them, later rounds add to the fresh set (J4). The
/// everyday rounds count as one kind. A user re-tuning after an
/// exaggerated calibration gets floors from this session alone.
fn begin_kind(
    g: &mut crate::store::GestureCal,
    kinds_this_session: &mut Vec<&'static str>,
    stored_as: &'static str,
) {
    let kind = match stored_as {
        "nod" | "shake" => stored_as,
        _ => "everyday",
    };
    if kinds_this_session.contains(&kind) {
        return;
    }
    kinds_this_session.push(kind);
    match kind {
        "nod" => {
            g.nod_deg.clear();
            g.nod_reads_to_deg.clear();
        }
        "shake" => {
            g.shake_deg.clear();
            g.shake_reads_to_deg.clear();
        }
        _ => g.everyday_deg.clear(),
    }
}

#[cfg(test)]
mod kind_tests {
    use super::begin_kind;
    use crate::store::{EverydayDeg, GestureCal};

    /// J4: Tune Gestures again replaces the earlier session's rounds of
    /// each kind it records, so the floor moves all the way to this
    /// session's, and a kind it does not record keeps its samples.
    #[test]
    fn a_session_replaces_its_kinds_samples_and_keeps_the_rest() {
        let mut g = GestureCal {
            nod_deg: vec![30.0, 32.0],
            nod_reads_to_deg: vec![24.0, 26.0],
            shake_deg: vec![40.0],
            shake_reads_to_deg: vec![30.0],
            everyday_deg: vec![EverydayDeg {
                kind: "read".into(),
                dyaw: 1.0,
                dpitch: 2.0,
            }],
        };
        let mut kinds = Vec::new();
        begin_kind(&mut g, &mut kinds, "nod");
        assert!(g.nod_deg.is_empty() && g.nod_reads_to_deg.is_empty());
        g.nod_reads_to_deg.push(8.0);
        begin_kind(&mut g, &mut kinds, "nod");
        assert_eq!(
            g.nod_reads_to_deg,
            vec![8.0],
            "the second nod round of the session adds"
        );
        assert_eq!(
            g.shake_reads_to_deg,
            vec![30.0],
            "a kind not recorded keeps its samples"
        );
        begin_kind(&mut g, &mut kinds, "read");
        assert!(g.everyday_deg.is_empty());
        begin_kind(&mut g, &mut kinds, "glance-left");
        assert_eq!(
            kinds,
            vec!["nod", "everyday"],
            "the everyday rounds are one kind"
        );
    }
}

/// The session's user and uid while one runs: who may watch and control it.
static ACTIVE: Mutex<Option<(String, u32)>> = Mutex::new(None);
/// The window watching the stream: one per session. A second watcher
/// replaces the first (the window reconnected), so watchers can never
/// pile up, and the stream is written without blocking: a watcher that
/// stops reading is dropped at the first full buffer instead of stalling
/// the camera loop behind it (J2).
static WATCHERS: Mutex<Vec<UnixStream>> = Mutex::new(Vec::new());
/// Continue, redo and cancel from the window.
static CONTROL: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub fn active_for(user: &str, uid: u32) -> bool {
    ACTIVE
        .lock()
        .map(|a| {
            a.as_ref()
                .map(|(u, id)| u == user && *id == uid)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

pub fn is_active() -> bool {
    ACTIVE.lock().map(|a| a.is_some()).unwrap_or(false)
}

pub fn add_watcher(stream: UnixStream) {
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    if let Ok(mut w) = WATCHERS.lock() {
        w.clear();
        w.push(stream);
    }
}

pub fn control(word: &str) {
    if let Ok(mut c) = CONTROL.lock() {
        c.push(word.to_string());
    }
}

fn take_control() -> Option<String> {
    CONTROL.lock().ok().and_then(|mut c| {
        if c.is_empty() {
            None
        } else {
            Some(c.remove(0))
        }
    })
}

fn broadcast(tick: &Tick) {
    let Ok(mut line) = serde_json::to_string(tick) else {
        return;
    };
    line.push('\n');
    if let Ok(mut w) = WATCHERS.lock() {
        // A short write means the window is not reading: the rest of the
        // line would not follow it in one piece, so the watcher goes.
        w.retain_mut(|s| matches!(s.write(line.as_bytes()), Ok(n) if n == line.len()));
    }
}

/// The face width, as a fraction of the frame's shorter side, that reads
/// as the right distance: from the reference machine's templates (78 to
/// 96 px on a 480 px side).
pub const SIZE_RIGHT: (f32, f32) = (0.14, 0.24);

pub fn distance_of(size: f32) -> &'static str {
    if size < SIZE_RIGHT.0 {
        "far"
    } else if size > SIZE_RIGHT.1 {
        "close"
    } else {
        "right"
    }
}

/// How far the readings move for the dot to reach the ring, one figure
/// per direction, because the tilt measure is lopsided (a lid camera looks
/// up at the face) and every person's reach differs. The defaults are the
/// reference machine's (2026-09-23); a session learns the person's own in
/// the range step and sets the ring at `RING_OF_REACH` of their reach.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Reach {
    /// The pose readings: turn left and right of the centre, chin up and
    /// down of the level.
    pub left: f32,
    pub right: f32,
    pub up: f32,
    pub down: f32,
    /// The face's place in the frame, the same four ways from its centre
    /// place, in frame units, and which way each axis runs (a turn to the
    /// left moves the face one way or the other across the frame
    /// depending on the camera's orientation; learned with the reach).
    pub pos_left: f32,
    pub pos_right: f32,
    pub pos_up: f32,
    pub pos_down: f32,
    pub sign_x: f32,
    pub sign_y: f32,
    /// How much the face's place counts on each axis, 0 to 1: nothing
    /// unless the range step saw it move and saw which way.
    pub place_x: f32,
    pub place_y: f32,
}

impl Default for Reach {
    /// Degrees of head pose from the mesh (a quarter turn is about 40).
    fn default() -> Self {
        Reach {
            left: 25.0,
            right: 25.0,
            up: 20.0,
            down: 25.0,
            pos_left: 0.06,
            pos_right: 0.06,
            pos_up: 0.05,
            pos_down: 0.05,
            sign_x: 1.0,
            sign_y: 1.0,
            place_x: 0.0,
            place_y: 0.0,
        }
    }
}

/// The face must have moved this far across the frame, either way, during
/// the range step for its place to count on that axis, and the direction
/// must be plain (the sum of reading times place clearly one-signed).
pub const PLACE_MIN_EXTENT: f32 = 0.025;
pub const PLACE_MIN_COVAR: f32 = 2.0;

pub const RING_OF_REACH: f32 = 0.70;
/// The least a direction's ring may be: below this the readings' own
/// jitter would put the dot on and off the target by itself.
pub const REACH_FLOOR: Reach = Reach {
    left: 12.0,
    right: 12.0,
    up: 10.0,
    down: 12.0,
    pos_left: 0.03,
    pos_right: 0.03,
    pos_up: 0.03,
    pos_down: 0.03,
    sign_x: 1.0,
    sign_y: 1.0,
    place_x: 0.0,
    place_y: 0.0,
};
/// The dot is on the target within this many ring units along the
/// target's own axis (the radial direction, what the look is about), and
/// within `ON_TARGET_ACROSS` across it: turning the head drags the pitch
/// reading with it, and that cross-talk must not throw a good turn off the
/// target. At the centre both are `ON_TARGET`.
pub const ON_TARGET: f32 = 0.35;
pub const ON_TARGET_ACROSS: f32 = 0.65;

/// Is the dot on the target?
pub fn on_target(dot: (f32, f32), target: (f32, f32)) -> bool {
    let (ex, ey) = (dot.0 - target.0, dot.1 - target.1);
    let r = (target.0 * target.0 + target.1 * target.1).sqrt();
    if r < 0.2 {
        return (ex * ex + ey * ey).sqrt() <= ON_TARGET;
    }
    let (ux, uy) = (target.0 / r, target.1 / r);
    let along = ex * ux + ey * uy;
    let across = -ex * uy + ey * ux;
    along.abs() <= ON_TARGET && across.abs() <= ON_TARGET_ACROSS
}

impl Reach {
    /// The ring from a person's measured extents (as far as they went in
    /// each direction from their centre), pose and place alike.
    pub fn from_extents(left: f32, right: f32, up: f32, down: f32) -> Reach {
        Reach {
            left: (left * RING_OF_REACH).max(REACH_FLOOR.left),
            right: (right * RING_OF_REACH).max(REACH_FLOOR.right),
            up: (up * RING_OF_REACH).max(REACH_FLOOR.up),
            down: (down * RING_OF_REACH).max(REACH_FLOOR.down),
            ..Reach::default()
        }
    }

    /// With the place extents and the axis directions as well. `covar_x`
    /// and `covar_y` are the sums of reading times place over the range
    /// step: their sign is the axis direction, their size whether the
    /// place moved with the reading at all. An axis the face did not move
    /// across, or moved without a plain direction, does not count.
    pub fn with_place(
        mut self,
        pos_left: f32,
        pos_right: f32,
        pos_up: f32,
        pos_down: f32,
        covar_x: f32,
        covar_y: f32,
    ) -> Reach {
        self.pos_left = (pos_left * RING_OF_REACH).max(REACH_FLOOR.pos_left);
        self.pos_right = (pos_right * RING_OF_REACH).max(REACH_FLOOR.pos_right);
        self.pos_up = (pos_up * RING_OF_REACH).max(REACH_FLOOR.pos_up);
        self.pos_down = (pos_down * RING_OF_REACH).max(REACH_FLOOR.pos_down);
        self.sign_x = if covar_x < 0.0 { -1.0 } else { 1.0 };
        self.sign_y = if covar_y < 0.0 { -1.0 } else { 1.0 };
        self.place_x =
            if pos_left.max(pos_right) >= PLACE_MIN_EXTENT && covar_x.abs() >= PLACE_MIN_COVAR {
                1.0
            } else {
                0.0
            };
        self.place_y =
            if pos_up.max(pos_down) >= PLACE_MIN_EXTENT && covar_y.abs() >= PLACE_MIN_COVAR {
                1.0
            } else {
                0.0
            };
        self
    }
}

/// Where the head is, in ring units: the mean of two readings that each
/// fail differently. The pose (turn, chin) is what the templates are
/// about, but the chin-up reading saturates with a lid camera looking up
/// at the face; the face's place in the frame keeps moving when the pose
/// reading has stopped, but a person can move it by shifting in the chair.
/// Averaged, a genuine turn or tilt moves both and reaches the ring; a
/// shift alone reaches half way.
pub struct Where {
    pub yaw: f32,
    pub pitch: f32,
    pub x: f32,
    pub y: f32,
}

pub struct Centre {
    pub yaw: f32,
    pub level: f32,
    pub x: f32,
    pub y: f32,
}

pub fn dot_of(w: &Where, c: &Centre, reach: &Reach) -> (f32, f32) {
    let dyaw = w.yaw - c.yaw;
    let px = if dyaw < 0.0 {
        dyaw / reach.left
    } else {
        dyaw / reach.right
    };
    let d = w.pitch - c.level;
    let py = if d < 0.0 {
        d / reach.up
    } else {
        d / reach.down
    };
    let ex = (w.x - c.x) * reach.sign_x;
    let qx = if ex < 0.0 {
        ex / reach.pos_left
    } else {
        ex / reach.pos_right
    };
    let ey = (w.y - c.y) * reach.sign_y;
    let qy = if ey < 0.0 {
        ey / reach.pos_up
    } else {
        ey / reach.pos_down
    };
    // Where the place counts, the two are averaged; where it does not, the
    // pose reading stands alone.
    let dx = (px + reach.place_x * qx) / (1.0 + reach.place_x);
    let dy = (py + reach.place_y * qy) / (1.0 + reach.place_y);
    (dx.clamp(-1.6, 1.6), dy.clamp(-1.6, 1.6))
}

/// The readings, cleaned: a median of the last three frames throws out
/// one-frame landmark flicker (a tenth of a turn in one frame is the
/// detector, not the head), then a light smoothing.
pub struct Filter {
    last: Vec<[f32; 5]>,
    smooth: Option<[f32; 5]>,
}

impl Filter {
    const ALPHA: f32 = 0.4;

    pub fn new() -> Filter {
        Filter {
            last: Vec::new(),
            smooth: None,
        }
    }

    /// yaw, pitch, size, x, y in; the same out, cleaned.
    pub fn push(&mut self, v: [f32; 5]) -> [f32; 5] {
        self.last.push(v);
        if self.last.len() > 3 {
            self.last.remove(0);
        }
        let mut m = [0.0f32; 5];
        for (i, slot) in m.iter_mut().enumerate() {
            let mut c: Vec<f32> = self.last.iter().map(|s| s[i]).collect();
            c.sort_by(|a, b| a.total_cmp(b));
            *slot = c[c.len() / 2];
        }
        let s = match self.smooth {
            None => m,
            Some(p) => {
                let mut s = [0.0f32; 5];
                for i in 0..5 {
                    s[i] = p[i] + Self::ALPHA * (m[i] - p[i]);
                }
                s
            }
        };
        self.smooth = Some(s);
        s
    }
}

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
}

/// How far up the ring the top target sits. With the mesh's pitch a
/// chin-up reads as cleanly as a chin-down, so the top is the rim.
pub const TOP: f32 = 1.0;

/// The path the target walks, as a point in ring units for `s` in 0..1:
/// from the centre out to the left edge, once round the ring (left, up,
/// right, down, left) and back to the centre, the top flattened to `TOP`.
pub fn path_point(s: f32) -> (f32, f32) {
    let s = s.clamp(0.0, 1.0);
    if s < 0.15 {
        (-(s / 0.15), 0.0)
    } else if s < 0.85 {
        let a = (s - 0.15) / 0.70 * std::f32::consts::TAU;
        // Starting at the left (angle pi), going over the top.
        let ang = std::f32::consts::PI - a;
        let y = -ang.sin();
        (ang.cos(), if y < 0.0 { y * TOP } else { y })
    } else {
        (-(1.0 - (s - 0.85) / 0.15), 0.0)
    }
}

/// The look a point on the ring is nearest to, for the template's label.
pub fn zone_of_point(x: f32, y: f32) -> &'static str {
    if x.abs() < 0.5 && y.abs() < 0.5 {
        "centre"
    } else if x.abs() >= y.abs() {
        if x < 0.0 {
            "left"
        } else {
            "right"
        }
    } else if y < 0.0 {
        "up"
    } else {
        "down"
    }
}

/// The holds after the path: the target sits at each limit in turn.
pub const HOLD_ZONES: [&str; 6] = ["centre", "left", "right", "centre", "up", "down"];
const HOLD_WANTED: usize = 3;
/// How long the path takes when the person keeps up, and how many
/// templates it may take along the way.
const PATH_SECONDS: f32 = 45.0;
const PATH_MAX: usize = 16;
const SAMPLE_SPACING: Duration = Duration::from_millis(500);
const SESSION_LIMIT: Duration = Duration::from_secs(15 * 60);

pub fn hold_target(zone: &str) -> (f32, f32) {
    match zone {
        "left" => (-1.0, 0.0),
        "right" => (1.0, 0.0),
        "up" => (0.0, -TOP),
        "down" => (0.0, 1.0),
        _ => (0.0, 0.0),
    }
}

/// How long a recording runs (dev-tools builds), and how long the range
/// step gives the person to go all the way round.
#[cfg(feature = "dev-tools")]
const RECORD_SECONDS: f32 = 45.0;
/// A recording keeps the frames it saw under the store's `record/<user>/`
/// (root only, for tuning the walk-through; nothing reads them but a
/// developer, and a delete of the user takes them). One frame in five,
/// named by the readings, as 8-bit PGM.
#[cfg(feature = "dev-tools")]
fn save_pgm(dir: &std::path::Path, name: &str, img: &faceauth_engine::Grey) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let _ = std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700));
    let mut out = format!("P5\n{} {}\n255\n", img.width, img.height).into_bytes();
    out.extend_from_slice(&img.data);
    std::fs::write(dir.join(name), out)?;
    Ok(())
}
const RANGE_SECONDS: f32 = 14.0;

/// The gesture and everyday rounds after the looks: what is asked, how
/// many times, for how long, and the kind the store files it under (the
/// two glances are "aside" rounds, the keyboard look a "glance").
pub struct Round {
    pub kind: &'static str,
    pub stored_as: &'static str,
    pub times: usize,
    pub seconds: f32,
    pub prompt: &'static str,
}

pub const ROUNDS: [Round; 8] = [
    Round {
        kind: "nod",
        stored_as: "nod",
        times: 2,
        seconds: 8.0,
        prompt: "Look at the camera and nod twice, the way you would to say yes.",
    },
    Round {
        kind: "shake",
        stored_as: "shake",
        times: 2,
        seconds: 8.0,
        prompt: "Look at the camera and shake your head twice, the way you would to say no.",
    },
    Round {
        kind: "glance-right",
        stored_as: "aside",
        times: 2,
        seconds: 6.0,
        prompt:
            "Something catches your eye to the right. Look at it, then back at the screen. Twice.",
    },
    Round {
        kind: "glance-left",
        stored_as: "aside",
        times: 2,
        seconds: 6.0,
        prompt:
            "Something catches your eye to the left. Look at it, then back at the screen. Twice.",
    },
    Round {
        kind: "keyboard",
        stored_as: "glance",
        times: 1,
        seconds: 8.0,
        prompt: "Look down at your keyboard and back up at the screen, twice.",
    },
    Round {
        kind: "read",
        stored_as: "read",
        times: 1,
        seconds: 12.0,
        prompt: "Read the text as it appears around the screen.",
    },
    Round {
        kind: "talk",
        stored_as: "talk",
        times: 1,
        seconds: 8.0,
        prompt: "Keep facing the screen and say a sentence or two out loud, as if on a call.",
    },
    Round {
        kind: "lean",
        stored_as: "lean",
        times: 1,
        seconds: 8.0,
        prompt: "Lean in toward the screen and sit back, twice.",
    },
];

/// The reading round's slots: the window keeps the texts (`readTexts` in
/// Enrol.qml) and places them at the corners and the centre of the
/// screen; the daemon only says which slot is showing.
pub const READ_SLOTS: usize = 5;
/// How long each text slot shows.
pub const READ_SLOT_SECONDS: f32 = 2.4;
/// The pause before a round starts recording.
const ROUND_COUNTDOWN: f32 = 2.0;

/// Round `i` in the flat list of (round, repeat) pairs.
pub fn round_at(i: usize) -> Option<(&'static Round, usize)> {
    let mut n = 0;
    for r in &ROUNDS {
        if i < n + r.times {
            return Some((r, i - n + 1));
        }
        n += r.times;
    }
    None
}

pub fn round_count() -> usize {
    ROUNDS.iter().map(|r| r.times).sum()
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Step {
    /// Nothing stored: the dot alone while the person moves through the
    /// full range, for the stream log (dev-tools builds).
    #[cfg(feature = "dev-tools")]
    Record,
    Welcome,
    /// Sit normally, look at the centre: the person's centre is learned.
    Centre,
    /// All the way round once: the person's reach is learned and the ring
    /// set from it.
    Range,
    Path,
    Hold(usize),
    Verify,
    /// "Next we record how you nod and shake."
    Bridge,
    /// One gesture or everyday round, by index into the flat list.
    Round(usize),
}

impl Step {
    fn name(self) -> &'static str {
        match self {
            #[cfg(feature = "dev-tools")]
            Step::Record => "record",
            Step::Welcome => "welcome",
            Step::Centre => "centre",
            Step::Range => "range",
            Step::Path => "path",
            Step::Hold(_) => "hold",
            Step::Verify => "verify",
            Step::Bridge => "bridge",
            Step::Round(_) => "round",
        }
    }

    fn zone(self) -> Option<&'static str> {
        match self {
            Step::Hold(i) => HOLD_ZONES.get(i).copied(),
            _ => None,
        }
    }

    pub fn next(self) -> Option<Step> {
        Some(match self {
            #[cfg(feature = "dev-tools")]
            Step::Record => return None,
            Step::Welcome => Step::Centre,
            Step::Centre => Step::Range,
            Step::Range => Step::Path,
            Step::Path => Step::Hold(0),
            Step::Hold(i) if i + 1 < HOLD_ZONES.len() => Step::Hold(i + 1),
            Step::Hold(_) => Step::Verify,
            Step::Verify => Step::Bridge,
            Step::Bridge => Step::Round(0),
            Step::Round(i) if i + 1 < round_count() => Step::Round(i + 1),
            Step::Round(_) => return None,
        })
    }

    pub fn from_start(name: Option<&str>) -> Step {
        match name.unwrap_or("welcome") {
            #[cfg(feature = "dev-tools")]
            "record" => Step::Record,
            "distance" | "centre" => Step::Centre,
            "range" => Step::Range,
            "path" => Step::Path,
            "hold" => Step::Hold(0),
            "bridge" | "gestures" => Step::Bridge,
            _ => Step::Welcome,
        }
    }
}

pub fn message_for(step: Step, distance: &str) -> String {
    match step {
        #[cfg(feature = "dev-tools")]
        Step::Record => "Recording. Move your head through its full range: left, right, up, down, then a couple of slow circles. Nothing is stored.".into(),
        Step::Welcome => "Welcome to FaceAuth enrolment. Follow the instructions on the screen.".into(),
        Step::Centre => match distance {
            "far" => "Sit as you normally do and look at the dashed circle in the centre. A little closer.".into(),
            "close" => "Sit as you normally do and look at the dashed circle in the centre. A little further back.".into(),
            _ => "Sit as you normally do and look at the dashed circle in the centre. Hold still a moment.".into(),
        },
        Step::Range => "Now move your head all the way round, slowly, keeping the screen just in view: left, up, right, down, and back to the centre.".into(),
        Step::Path => "Follow the dashed circle with your head and keep the dot inside it. It waits for you.".into(),
        Step::Hold(i) => format!("Hold the dot in the circle: {}.", POSE_HINTS[POSES.iter().position(|p| *p == HOLD_ZONES[i]).unwrap_or(0)]),
        Step::Verify => "Look at the camera.".into(),
        Step::Bridge => "Next we record how you nod and how you shake your head, and make sure ordinary movement is never mistaken for either. Nothing here is an image.".into(),
        Step::Round(i) => round_at(i).map(|(r, _)| r.prompt.to_string()).unwrap_or_default(),
    }
}

/// Where a session started at decides where it ends: a first enrolment
/// runs the looks and the rounds, Add Look stops after verify, Tune
/// Gestures runs the rounds alone.
fn last_step(start: Option<&str>) -> Step {
    match start.unwrap_or("welcome") {
        "distance" | "centre" | "path" | "hold" => Step::Verify,
        _ => Step::Round(round_count().saturating_sub(1)),
    }
}

/// A round's largest 1.5 s swing on one axis of the recorded angles,
/// degrees: kept with the templates for the record (the floors come from
/// the replay, `reads_to_deg`).
fn swing(series: &[(f32, f32, f32)], pick: fn(&(f32, f32, f32)) -> f32) -> f32 {
    let mut best = 0f32;
    for i in 0..series.len() {
        let (mut lo, mut hi) = (f32::MAX, f32::MIN);
        for s in &series[i..] {
            if s.0 - series[i].0 > 1.5 {
                break;
            }
            lo = lo.min(pick(s));
            hi = hi.max(pick(s));
        }
        if hi > lo {
            best = best.max(hi - lo);
        }
    }
    best
}

/// The per-frame recording of a round, kept in dev-tools builds under the
/// root-only gestures directory, one directory per user: the round header
/// (`consent::ROUND_HEADER`), then one line per frame with the mesh's
/// angles and the box, for designing the detectors. The consent window's
/// recordings share the format, so either replays through the same test.
#[cfg(feature = "dev-tools")]
fn save_round_trace(
    store: &crate::store::Store,
    user: &str,
    kind: &str,
    n: usize,
    lines: &[String],
) {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let res = (|| -> anyhow::Result<()> {
        let dir = store.gestures_dir_for(user)?;
        std::fs::create_dir_all(&dir)?;
        if let Some(parent) = dir.parent() {
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        let name = format!("{}-v3-{}-{}.txt", now_secs(), kind, n);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join(&name))?;
        writeln!(f, "{}", crate::consent::ROUND_HEADER)?;
        for l in lines {
            writeln!(f, "{}", l)?;
        }
        Ok(())
    })();
    if let Err(e) = res {
        log::warn!("round recording for {}: {}", user, e);
    }
}

/// Run a session on the authenticator's camera and store. Returns the
/// enrolment outcome; the window is summoned at the start and hidden at
/// the end, whichever way the session ends.
pub fn run(a: &mut Authenticator, user: &str, start: &Start) -> Outcome {
    let mut session = None;
    let outcome = match run_inner(a, user, start, &mut session) {
        Ok(o) => o,
        Err(e) => Outcome::Error {
            message: e.to_string(),
        },
    };
    // A session still claimed here ended without telling the window (an
    // error after the summon): the window is told now, with the reason,
    // so it closes and the next enrolment is not "already running" (C9).
    if let Some(mut s) = session {
        let message = match &outcome {
            Outcome::Error { message } => message.clone(),
            _ => "The enrolment ended.".to_string(),
        };
        s.end("failed", &message);
    }
    outcome
}

/// The claim on the one enrolment session, from the moment `ACTIVE` is set
/// until the window has been told the session is over. Every way out of
/// the session ends it through `end`, and a way out that forgets is caught
/// by the drop, so the window never stays up over the screen and the
/// watchers never loop for the daemon's life (C9).
struct Session {
    user: String,
    ended: bool,
}

impl Session {
    fn claim(user: &str, uid: u32) -> Session {
        if let Ok(mut act) = ACTIVE.lock() {
            *act = Some((user.to_string(), uid));
        }
        if let Ok(mut c) = CONTROL.lock() {
            c.clear();
        }
        Session {
            user: user.to_string(),
            ended: false,
        }
    }

    /// Tell the window the step the session ended at, release the claim
    /// and hide the window. Once only; later calls do nothing.
    fn end(&mut self, step: &'static str, message: &str) {
        if self.ended {
            return;
        }
        self.ended = true;
        broadcast(&Tick::blank(step, message));
        std::thread::sleep(Duration::from_millis(1500));
        release();
        let _ =
            crate::consent::shell_call(&self.user, &["shell", "hide", "omarchy.faceauth.enrol"]);
    }

    /// The window never opened: release the claim with nothing to tell
    /// and nothing to hide.
    fn abandon(mut self) {
        self.ended = true;
        release();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.end("failed", "The enrolment ended unexpectedly.");
    }
}

/// Clear the claim, the watchers and the control words.
fn release() {
    if let Ok(mut w) = WATCHERS.lock() {
        w.clear();
    }
    if let Ok(mut c) = CONTROL.lock() {
        c.clear();
    }
    if let Ok(mut act) = ACTIVE.lock() {
        *act = None;
    }
}

/// The session proper. Every precondition is checked before the claim;
/// once `session` holds the claim, the window is up and every return
/// goes through `Session::end`, or `run` ends it with the outcome's
/// message.
fn run_inner(
    a: &mut Authenticator,
    user: &str,
    start: &Start,
    session: &mut Option<Session>,
) -> Result<Outcome> {
    let uid = nix::unistd::User::from_name(user)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
        .ok_or_else(|| anyhow!("unknown user {}", user))?;
    if is_active() {
        return Ok(Outcome::Error {
            message: "an enrolment session is already running".into(),
        });
    }
    // The store's one enrolment opener: a set the TPM could not open in
    // time stays where it is and the session fails instead (F2).
    let existing = a.store.open_for_enrolment(user)?;
    let mut u =
        existing.unwrap_or_else(|| UserTemplates::new(user, faceauth_engine::embed::AURAFACE_FILE));
    if u.model != faceauth_engine::embed::AURAFACE_FILE {
        return Ok(Outcome::Error {
            message: format!(
                "existing templates are for model {}; delete them first",
                u.model
            ),
        });
    }
    // The daemon does not start without the mesh (C3), so this cannot
    // fail today; it stays as a precondition, checked before the window
    // is summoned rather than after (C9).
    if a.pipeline.mesh.is_none() {
        return Ok(Outcome::Error {
            message: format!(
                "the face mesh model ({}) is not installed; run `faceauth models fetch`",
                faceauth_engine::mesh::FACE_MESH_FILE
            ),
        });
    }
    let claim = Session::claim(user, uid);
    let payload = serde_json::json!({ "user": user, "start": start.start_at.as_deref().unwrap_or("welcome") }).to_string();
    if let Err(e) = crate::consent::shell_call(
        user,
        &["shell", "summon", "omarchy.faceauth.enrol", &payload],
    ) {
        claim.abandon();
        return Ok(Outcome::Error {
            message: format!("no enrolment window: {}", e),
        });
    }
    let session = session.insert(claim);
    let mut cap = IrCapture::open(&a.cfg)?;
    if let Some(i) = &cap.illuminator {
        i.set(true)?;
    }
    let device = cap.identity.clone();
    let t0 = Instant::now();
    let mut step = Step::from_start(start.start_at.as_deref());
    // The person's centre: learned in the centre step from a still, level
    // look at the screen. Until then the stored level stands in.
    // The centre pose in degrees, learned in the centre step.
    let mut centre = Centre {
        yaw: 0.0,
        level: 0.0,
        x: 0.5,
        y: 0.5,
    };
    let mut centre_samples: Vec<[f32; 4]> = Vec::new();
    let mut still_since: Option<Instant> = None;
    // The person's reach, learned in the range step; the defaults until then.
    let mut reach = Reach::default();
    let mut extents = [0.0f32; 8]; // pose left, right, up, down; place left, right, up, down
    let mut covar = (0.0f32, 0.0f32); // sum of dyaw*dx, sum of dpitch*dy: the axis directions
    let mut range_since: Option<Instant> = None;
    // The path parameter, advanced only while the dot is on the target.
    let mut path_s = 0.0f32;
    let mut last_frame = Instant::now();
    let mut path_taken = 0usize;
    let mut last_taken_pose: Option<(f32, f32)> = None;
    let mut taken = 0usize;
    let mut last_sample = Instant::now() - SAMPLE_SPACING;
    let mut on_since: Option<Instant> = None;
    let mut verify_hits = 0usize;
    let mut verify_since: Option<Instant> = None;
    let last = last_step(start.start_at.as_deref());
    // A round: when it started counting down, the angle series for the
    // swing measure, the recording, and the round as the detectors see it,
    // replayed when it ends to find where it stops reading (the floors
    // come from that).
    let mut round_started: Option<Instant> = None;
    // The kinds this session has recorded so far (J4).
    let mut kinds_this_session: Vec<&'static str> = Vec::new();
    let mut round_angles: Vec<(f32, f32, f32)> = Vec::new(); // t, yaw, pitch in degrees
    let mut round_lines: Vec<String> = Vec::new();
    let mut round_frames: Vec<crate::consent::RoundFrame> = Vec::new();
    let mut added = 0usize;
    let mut filter = Filter::new();
    let take_template = |u: &mut UserTemplates,
                         a: &mut Authenticator,
                         img: &faceauth_engine::Grey,
                         face: &faceauth_engine::Face,
                         p: &faceauth_engine::pose::Pose,
                         zone: &str|
     -> Result<()> {
        let crop = faceauth_engine::align::align_112(img, &face.landmarks);
        let e = a.pipeline.embedder.embed(&crop)?;
        u.templates.push(Template {
            embedding: e,
            quality: face.score,
            face_width: face.bbox[2],
            created: now_secs(),
            label: format!("{}-{}", start.label, zone),
            device: Some(device.clone()),
            yaw: Some(p.yaw),
            nose_pitch: Some(p.nose_pitch),
        });
        Ok(())
    };
    loop {
        if t0.elapsed() > SESSION_LIMIT {
            return Err(anyhow!("the enrolment session ran out of time"));
        }
        match take_control().as_deref() {
            Some("cancel") => return Err(anyhow!("cancelled from the window")),
            Some("continue") => {
                if step == Step::Welcome {
                    step = Step::Centre;
                } else if step == Step::Bridge {
                    step = Step::Round(0);
                    round_started = None;
                }
            }
            Some("redo") => match step {
                Step::Range => {
                    range_since = None;
                    extents = [0.0; 8];
                    covar = (0.0, 0.0);
                }
                Step::Path => {
                    path_s = 0.0;
                    path_taken = 0;
                }
                Step::Hold(_) => taken = 0,
                Step::Round(_) => round_started = None,
                _ => {}
            },
            _ => {}
        }
        let Some(img) = cap.next(Duration::from_secs(2))? else {
            continue;
        };
        let dt = last_frame.elapsed().as_secs_f32().min(0.25);
        last_frame = Instant::now();
        let short = (img.width.min(img.height)).max(1) as f32;
        let faces = a.pipeline.detector.detect(&img, a.cfg.min_detection)?;
        let face = faces.into_iter().max_by(|p, q| p.score.total_cmp(&q.score));
        let mut tick = Tick::blank(step.name(), "");
        tick.zone = step.zone();
        #[cfg(feature = "dev-tools")]
        {
            tick.record.centre_yaw = centre.yaw;
            tick.record.level = centre.level;
        }
        let Some(face) = face else {
            tick.message = match step {
                Step::Welcome => message_for(step, "far"),
                _ => "No face in view. Sit facing the screen.".into(),
            };
            match step {
                Step::Path => {
                    let (tx, ty) = path_point(path_s);
                    tick.target_x = tx;
                    tick.target_y = ty;
                }
                Step::Hold(i) => {
                    let (tx, ty) = hold_target(HOLD_ZONES[i]);
                    tick.target_x = tx;
                    tick.target_y = ty;
                }
                _ => {}
            }
            broadcast(&tick);
            continue;
        };
        cap.meter_on(&face);
        let raw = faceauth_engine::pose::pose(&face.landmarks);
        let size_raw = face.bbox[2] / short;
        let x_raw = (face.bbox[0] + face.bbox[2] / 2.0) / img.width.max(1) as f32;
        let y_raw = (face.bbox[1] + face.bbox[3] / 2.0) / img.height.max(1) as f32;
        // The head pose, in degrees, from the dense mesh: measured
        // 2026-09-23, a chin-up straight at the camera reads -31 and a
        // chin-down +36 where the five-point figures barely moved. Without
        // a mesh on this frame the frame is not read.
        let Some(m) = a
            .pipeline
            .mesh
            .as_mut()
            .and_then(|mesh| mesh.for_face(&img, &face).ok().flatten())
        else {
            tick.face = true;
            tick.message = "Hold on, reading the face.".into();
            broadcast(&tick);
            continue;
        };
        let hp = faceauth_engine::mesh::head_pose(&m);
        let sm = filter.push([hp.yaw, hp.pitch, size_raw, x_raw, y_raw]);
        let p = raw;
        let here = Where {
            yaw: sm[0],
            pitch: sm[1],
            x: sm[3],
            y: sm[4],
        };
        tick.face = true;
        tick.size = sm[2];
        tick.distance = distance_of(tick.size);
        #[cfg(feature = "dev-tools")]
        {
            tick.record = TickRecord {
                yaw: sm[0],
                pitch: sm[1],
                roll: hp.roll,
                raw_yaw: hp.yaw,
                raw_pitch: hp.pitch,
                nose_pitch: raw.nose_pitch,
                mesh_yaw: Some(hp.yaw),
                mesh_pitch: Some(hp.pitch),
                mesh_roll: Some(hp.roll),
                mesh_score: Some(m.score),
                x: sm[3],
                y: sm[4],
                centre_yaw: centre.yaw,
                level: centre.level,
            };
        }
        let (dx, dy) = dot_of(&here, &centre, &reach);
        tick.dot_x = dx;
        tick.dot_y = dy;
        match step {
            Step::Range => {
                tick.message = message_for(step, tick.distance);
                tick.on_target = true;
                let since = *range_since.get_or_insert(Instant::now());
                let dyaw = here.yaw - centre.yaw;
                let dp = here.pitch - centre.level;
                let (ex, ey) = (here.x - centre.x, here.y - centre.y);
                extents[0] = extents[0].max(-dyaw);
                extents[1] = extents[1].max(dyaw);
                extents[2] = extents[2].max(-dp);
                extents[3] = extents[3].max(dp);
                covar.0 += dyaw * ex;
                covar.1 += dp * ey;
                // The place extents are sorted out once the axis directions
                // are known, so they are kept both ways round meanwhile.
                extents[4] = extents[4].max(-ex);
                extents[5] = extents[5].max(ex);
                extents[6] = extents[6].max(-ey);
                extents[7] = extents[7].max(ey);
                if since.elapsed().as_secs_f32() > RANGE_SECONDS {
                    let (sx, sy) = (
                        if covar.0 < 0.0 { -1.0 } else { 1.0 },
                        if covar.1 < 0.0 { -1.0 } else { 1.0 },
                    );
                    // With the sign applied, "left" is the side a left turn moved the face to.
                    let (pl, pr) = if sx > 0.0 {
                        (extents[4], extents[5])
                    } else {
                        (extents[5], extents[4])
                    };
                    let (pu, pd) = if sy > 0.0 {
                        (extents[6], extents[7])
                    } else {
                        (extents[7], extents[6])
                    };
                    reach = Reach::from_extents(extents[0], extents[1], extents[2], extents[3])
                        .with_place(pl, pr, pu, pd, covar.0, covar.1);
                    log::info!("enrolment for {}: reach learned, turn left {:.0} right {:.0} chin up {:.0} down {:.0} deg, place left {:.3} right {:.3} up {:.3} down {:.3} (axes {:+.0} {:+.0}, covar {:+.1} {:+.1}, place counts x {} y {}); ring at turn {:.0}/{:.0} chin {:.0}/{:.0} deg", user, extents[0], extents[1], extents[2], extents[3], pl, pr, pu, pd, sx, sy, covar.0, covar.1, reach.place_x, reach.place_y, reach.left, reach.right, reach.up, reach.down);
                    step = Step::Path;
                    path_s = 0.0;
                    path_taken = 0;
                    last_taken_pose = None;
                }
            }
            #[cfg(feature = "dev-tools")]
            Step::Record => {
                tick.message = message_for(step, tick.distance);
                tick.on_target = true;
                if cap.frames % 5 == 0 {
                    let name = format!(
                        "{:06.2}_yaw{:+.3}_pitch{:.3}_dot{:+.2}_{:+.2}_size{:.3}.pgm",
                        t0.elapsed().as_secs_f32(),
                        raw.yaw,
                        raw.nose_pitch,
                        dx,
                        dy,
                        tick.size
                    );
                    if let Err(e) = a
                        .store
                        .record_dir_for(user)
                        .and_then(|dir| save_pgm(&dir, &name, &img))
                    {
                        log::warn!("recording: cannot save a frame: {}", e);
                    }
                }
                if t0.elapsed().as_secs_f32() > RECORD_SECONDS {
                    cap.stop()?;
                    session.end("done", "Recorded. Nothing was stored.");
                    return Ok(Outcome::Enrolled {
                        added: 0,
                        total: u.templates.len(),
                        consistency_min: 1.0,
                        consistency_mean: 1.0,
                        path: String::new(),
                    });
                }
            }
            Step::Welcome => {
                tick.message = message_for(step, tick.distance);
            }
            Step::Centre => {
                tick.message = message_for(step, tick.distance);
                // Learn the centre from a still second at the right distance:
                // a spread of readings small enough to be one pose.
                if tick.distance == "right" {
                    centre_samples.push([here.yaw, here.pitch, here.x, here.y]);
                    if centre_samples.len() > 60 {
                        centre_samples.remove(0);
                    }
                    let since = *still_since.get_or_insert(Instant::now());
                    let n = centre_samples.len() as f32;
                    let mean = |i: usize| centre_samples.iter().map(|s| s[i]).sum::<f32>() / n;
                    let running = Centre {
                        yaw: mean(0),
                        level: mean(1),
                        x: mean(2),
                        y: mean(3),
                    };
                    let spread = centre_samples
                        .iter()
                        .map(|s| (s[0] - running.yaw).abs().max((s[1] - running.level).abs()))
                        .fold(0.0, f32::max)
                        / 60.0;
                    // The dot is drawn against the running centre so it settles
                    // into the circle as the person does.
                    let (cx, cy) = dot_of(&here, &running, &reach);
                    tick.dot_x = cx;
                    tick.dot_y = cy;
                    #[cfg(feature = "dev-tools")]
                    {
                        tick.record.centre_yaw = running.yaw;
                        tick.record.level = running.level;
                    }
                    tick.on_target = true;
                    if since.elapsed() > Duration::from_millis(3000)
                        && centre_samples.len() >= 40
                        && spread < 0.06
                    {
                        centre = running;
                        log::info!("enrolment for {}: centre learned, yaw {:+.1} pitch {:+.1} deg, place ({:.3}, {:.3})", user, centre.yaw, centre.level, centre.x, centre.y);
                        step = Step::Range;
                        range_since = None;
                        extents = [0.0; 8];
                        covar = (0.0, 0.0);
                    }
                } else {
                    still_since = None;
                    centre_samples.clear();
                }
            }
            Step::Path => {
                let (tx, ty) = path_point(path_s);
                tick.target_x = tx;
                tick.target_y = ty;
                tick.on_target = on_target((dx, dy), (tx, ty)) && tick.distance == "right";
                tick.taken = path_taken;
                tick.wanted = PATH_MAX;
                tick.message = message_for(step, tick.distance);
                if tick.on_target {
                    // The target moves only while the dot is with it.
                    path_s += dt / PATH_SECONDS;
                    let moved = last_taken_pose
                        .map(|(ly, lp)| {
                            (here.yaw - ly).abs() >= 5.0 || (here.pitch - lp).abs() >= 4.0
                        })
                        .unwrap_or(true);
                    if path_taken < PATH_MAX && moved && last_sample.elapsed() >= SAMPLE_SPACING {
                        take_template(&mut u, a, &img, &face, &p, zone_of_point(tx, ty))?;
                        path_taken += 1;
                        added += 1;
                        last_sample = Instant::now();
                        last_taken_pose = Some((here.yaw, here.pitch));
                        tick.taken = path_taken;
                    }
                }
                if path_s >= 1.0 {
                    step = Step::Hold(0);
                    taken = 0;
                    on_since = None;
                }
            }
            Step::Hold(i) => {
                let zone = HOLD_ZONES[i];
                let (tx, ty) = hold_target(zone);
                tick.target_x = tx;
                tick.target_y = ty;
                tick.on_target = on_target((dx, dy), (tx, ty)) && tick.distance == "right";
                tick.wanted = HOLD_WANTED;
                tick.message = message_for(step, tick.distance);
                if tick.on_target {
                    let since = *on_since.get_or_insert(Instant::now());
                    if since.elapsed() > Duration::from_millis(400)
                        && last_sample.elapsed() >= SAMPLE_SPACING
                    {
                        take_template(&mut u, a, &img, &face, &p, zone)?;
                        taken += 1;
                        added += 1;
                        last_sample = Instant::now();
                    }
                } else {
                    on_since = None;
                }
                tick.taken = taken;
                if taken >= HOLD_WANTED {
                    step = step.next().unwrap_or(Step::Verify);
                    taken = 0;
                    on_since = None;
                    if step == Step::Verify {
                        let pruned = u.prune_to(MAX_TEMPLATES);
                        if pruned > 0 {
                            log::info!("enrolment for {}: {} near-duplicate template(s) dropped to stay within {}", user, pruned, MAX_TEMPLATES);
                        }
                        a.store.save(&u)?;
                        verify_since = Some(Instant::now());
                    }
                }
            }
            Step::Verify => {
                tick.message = message_for(step, tick.distance);
                tick.on_target = true;
                if last_sample.elapsed() >= SAMPLE_SPACING {
                    let crop = faceauth_engine::align::align_112(&img, &face.landmarks);
                    let e = a.pipeline.embedder.embed(&crop)?;
                    last_sample = Instant::now();
                    if let Some((score, _)) = u.best_match_on(&e, &device) {
                        if score >= a.cfg.accept_threshold {
                            verify_hits += 1;
                        }
                    }
                }
                if verify_hits >= 2 {
                    if last == Step::Verify {
                        cap.stop()?;
                        let (lo, mean, _) = u.self_consistency().unwrap_or((1.0, 1.0, 1.0));
                        // The file the templates rest in: the sealed blob when the
                        // store seals, else the plaintext.
                        let path = if a.store.is_sealed(user) {
                            a.store.sealed_path_for(user)
                        } else {
                            a.store.path_for(user)
                        }
                        .map(|p| p.display().to_string())
                        .unwrap_or_default();
                        session.end("done", "Recognised. Enrolment complete.");
                        return Ok(Outcome::Enrolled {
                            added,
                            total: u.templates.len(),
                            consistency_min: lo,
                            consistency_mean: mean,
                            path,
                        });
                    }
                    step = Step::Bridge;
                }
                if verify_since
                    .map(|s| s.elapsed() > Duration::from_secs(20))
                    .unwrap_or(false)
                {
                    return Err(anyhow!(
                        "the new templates did not recognise you within 20 s ({} added)",
                        added
                    ));
                }
            }
            Step::Bridge => {
                tick.message = message_for(step, tick.distance);
                tick.on_target = true;
            }
            Step::Round(i) => {
                let Some((r, n)) = round_at(i) else {
                    return Err(anyhow!("no round {}", i));
                };
                tick.round = Some(r.kind);
                tick.round_no = i + 1;
                tick.round_of = round_count();
                tick.on_target = true;
                let started = *round_started.get_or_insert_with(|| {
                    round_angles.clear();
                    round_lines.clear();
                    round_frames.clear();
                    Instant::now()
                });
                let since = started.elapsed().as_secs_f32();
                if since < ROUND_COUNTDOWN {
                    tick.countdown = true;
                    tick.seconds_left = ROUND_COUNTDOWN - since;
                    tick.message = format!("Get ready: {}", r.prompt);
                } else {
                    let t = since - ROUND_COUNTDOWN;
                    tick.seconds_left = (r.seconds - t).max(0.0);
                    tick.message = r.prompt.to_string();
                    if r.kind == "read" {
                        tick.read_slot = Some(((t / READ_SLOT_SECONDS) as usize) % READ_SLOTS);
                    }
                    let geom = (
                        face.bbox[2],
                        face.bbox[0] + face.bbox[2] / 2.0,
                        face.bbox[1] + face.bbox[3] / 2.0,
                    );
                    round_angles.push((t, hp.yaw, hp.pitch));
                    round_frames.push(crate::consent::RoundFrame {
                        t,
                        yaw: hp.yaw,
                        pitch: hp.pitch,
                        roll: hp.roll,
                        geom,
                    });
                    if round_lines.len() < 1500 {
                        round_lines
                            .push(crate::consent::round_line(t, &hp, geom, tick.size, m.score));
                    }
                    if t >= r.seconds {
                        // The round is over: its swings go with the templates
                        // for the record, and its replay through the mesh
                        // detectors says where it stops reading, which is
                        // what the floors derive from (a floor at a fraction
                        // of the swing lost the reference user's own shake).
                        let dpitch = swing(&round_angles, |s| s.2);
                        let dyaw = swing(&round_angles, |s| s.1);
                        let reads_to = match r.stored_as {
                            "nod" => crate::consent::reads_to_deg(&round_frames, true),
                            "shake" => crate::consent::reads_to_deg(&round_frames, false),
                            _ => None,
                        };
                        begin_kind(&mut u.gesture, &mut kinds_this_session, r.stored_as);
                        let stored = match r.stored_as {
                            "nod" => {
                                if dpitch >= crate::consent::NodDetector::MESH_MIN_DEG {
                                    u.gesture.nod_deg.push(dpitch)
                                }
                                if let Some(f) = reads_to {
                                    u.gesture.nod_reads_to_deg.push(f)
                                }
                                reads_to.is_some()
                            }
                            "shake" => {
                                if dyaw >= crate::consent::ShakeDetector::MESH_MIN_DEG {
                                    u.gesture.shake_deg.push(dyaw)
                                }
                                if let Some(f) = reads_to {
                                    u.gesture.shake_reads_to_deg.push(f)
                                }
                                reads_to.is_some()
                            }
                            kind => {
                                u.gesture.everyday_deg.push(crate::store::EverydayDeg {
                                    kind: kind.to_string(),
                                    dyaw,
                                    dpitch,
                                });
                                true
                            }
                        };
                        log::info!("round {} of {} for {}: {} {} swung {:.0} deg pitch, {:.0} deg yaw{}", i + 1, round_count(), user, r.kind, n, dpitch, dyaw, match (stored, reads_to) { (true, Some(f)) => format!("; reads on the mesh up to a {:.0} degree floor", f), (false, _) => "; does not read on the mesh even at the minimum floor (sets no floor)".to_string(), _ => String::new() });
                        #[cfg(feature = "dev-tools")]
                        save_round_trace(&a.store, user, r.kind, n, &round_lines);
                        a.store.save(&u)?;
                        round_started = None;
                        match step.next() {
                            Some(s) if step != last => step = s,
                            _ => {
                                cap.stop()?;
                                let (nd, sd) = crate::auth::consent_floors(&u.gesture);
                                log::info!(
                                    "rounds done for {}: floors nod {:.0} deg, shake {:.0} deg",
                                    user,
                                    nd,
                                    sd
                                );
                                let (lo, mean, _) = u.self_consistency().unwrap_or((1.0, 1.0, 1.0));
                                let path = if a.store.is_sealed(user) {
                                    a.store.sealed_path_for(user)
                                } else {
                                    a.store.path_for(user)
                                }
                                .map(|p| p.display().to_string())
                                .unwrap_or_default();
                                session.end("done", "All done. Your nods, shakes and everyday movements are recorded.");
                                return Ok(Outcome::Enrolled {
                                    added,
                                    total: u.templates.len(),
                                    consistency_min: lo,
                                    consistency_mean: mean,
                                    path,
                                });
                            }
                        }
                    }
                }
            }
        }
        broadcast(&tick);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The session statics are process-wide: tests that touch them take
    /// this so they do not see each other's claim.
    static SESSION_STATICS: Mutex<()> = Mutex::new(());

    /// C9: a claim released without an explicit end (an error after the
    /// summon) still clears the session, so the next enrolment is not
    /// "already running" and the watchers stop looping. A claim abandoned
    /// before the window opened clears it too.
    #[test]
    fn a_dropped_claim_releases_the_session() {
        let _serial = SESSION_STATICS.lock().unwrap_or_else(|e| e.into_inner());
        let sess = Session {
            user: "c9-test".into(),
            ended: false,
        };
        if let Ok(mut act) = ACTIVE.lock() {
            *act = Some(("c9-test".into(), 65534));
        }
        assert!(active_for("c9-test", 65534));
        drop(sess);
        assert!(!is_active(), "the drop ended the session");
        let sess = Session {
            user: "c9-test".into(),
            ended: false,
        };
        if let Ok(mut act) = ACTIVE.lock() {
            *act = Some(("c9-test".into(), 65534));
        }
        sess.abandon();
        assert!(!is_active(), "the abandoned claim is released");
    }

    #[test]
    fn the_steps_run_in_order_and_end_at_verify() {
        let mut s = Step::from_start(None);
        let mut names = vec![s.name().to_string()];
        while let Some(n) = s.next() {
            s = n;
            names.push(format!(
                "{}{}",
                s.name(),
                s.zone().map(|z| format!(":{}", z)).unwrap_or_default()
            ));
        }
        assert_eq!(
            &names[..11],
            &[
                "welcome",
                "centre",
                "range",
                "path",
                "hold:centre",
                "hold:left",
                "hold:right",
                "hold:centre",
                "hold:up",
                "hold:down",
                "verify"
            ]
        );
        assert_eq!(names[11], "bridge");
        assert_eq!(names.len(), 12 + round_count(), "then every round");
        assert_eq!(round_count(), 12);
        assert_eq!(round_at(0).map(|(r, n)| (r.kind, n)), Some(("nod", 1)));
        assert_eq!(round_at(1).map(|(r, n)| (r.kind, n)), Some(("nod", 2)));
        assert_eq!(round_at(2).map(|(r, n)| (r.kind, n)), Some(("shake", 1)));
        assert_eq!(round_at(11).map(|(r, n)| (r.kind, n)), Some(("lean", 1)));
        assert!(round_at(12).is_none());
        assert_eq!(
            last_step(Some("distance")),
            Step::Verify,
            "Add Look ends after verify"
        );
        assert_eq!(
            last_step(None),
            Step::Round(11),
            "a first enrolment runs every round"
        );
        assert_eq!(
            Step::from_start(Some("bridge")),
            Step::Bridge,
            "Tune Gestures starts at the bridge"
        );
        assert_eq!(
            Step::from_start(Some("distance")),
            Step::Centre,
            "Add Look starts at the centre screen"
        );
        #[cfg(feature = "dev-tools")]
        {
            assert_eq!(Step::from_start(Some("record")), Step::Record);
            assert_eq!(
                Step::Record.next(),
                None,
                "a recording stores nothing and leads nowhere"
            );
        }
        #[cfg(not(feature = "dev-tools"))]
        assert_eq!(
            Step::from_start(Some("record")),
            Step::Welcome,
            "without dev-tools there is no record mode"
        );
    }

    #[test]
    fn distance_reads_from_the_face_size() {
        assert_eq!(distance_of(0.10), "far");
        assert_eq!(distance_of(0.18), "right");
        assert_eq!(distance_of(0.30), "close");
        assert_eq!(distance_of(78.0 / 480.0), "right");
        assert_eq!(distance_of(96.0 / 480.0), "right");
    }

    /// The path leaves the centre to the left, goes once round over the
    /// top, and comes back; every point on the ring names a look.
    #[test]
    fn the_path_goes_out_round_and_back() {
        let near =
            |a: (f32, f32), b: (f32, f32)| (a.0 - b.0).abs() < 0.02 && (a.1 - b.1).abs() < 0.02;
        assert!(near(path_point(0.0), (0.0, 0.0)));
        assert!(near(path_point(0.15), (-1.0, 0.0)));
        assert!(
            near(path_point(0.15 + 0.70 * 0.25), (0.0, -TOP)),
            "a quarter of the way round is the top, flattened"
        );
        assert!(near(path_point(0.15 + 0.70 * 0.5), (1.0, 0.0)));
        assert!(near(path_point(0.15 + 0.70 * 0.75), (0.0, 1.0)));
        assert!(near(path_point(0.85), (-1.0, 0.0)));
        assert!(near(path_point(1.0), (0.0, 0.0)));
        assert_eq!(zone_of_point(-1.0, 0.0), "left");
        assert_eq!(zone_of_point(0.0, -1.0), "up");
        assert_eq!(zone_of_point(0.7, 0.7), "right");
        assert_eq!(zone_of_point(0.1, 0.1), "centre");
    }

    /// The dot is drawn against the person's own centre, and the ring is
    /// where the readings say a look begins.
    #[test]
    fn the_dot_is_relative_to_the_persons_centre_and_reach() {
        let r = Reach {
            left: 25.0,
            right: 20.0,
            up: 15.0,
            down: 25.0,
            pos_left: 0.05,
            pos_right: 0.05,
            pos_up: 0.04,
            pos_down: 0.04,
            sign_x: 1.0,
            sign_y: 1.0,
            place_x: 1.0,
            place_y: 1.0,
        };
        let c = Centre {
            yaw: 2.0,
            level: -5.0,
            x: 0.5,
            y: 0.5,
        };
        let at = |yaw: f32, pitch: f32, x: f32, y: f32| dot_of(&Where { yaw, pitch, x, y }, &c, &r);
        assert_eq!(at(2.0, -5.0, 0.5, 0.5), (0.0, 0.0));
        // A genuine turn moves both the pose reading and the face's place, and reaches the ring.
        let (x, _) = at(2.0 - 25.0, -5.0, 0.5 - 0.05, 0.5);
        assert!(
            (x + 1.0).abs() < 0.001,
            "a left turn of the reach puts the dot on the ring: {}",
            x
        );
        let (x, _) = at(2.0 + 20.0, -5.0, 0.5 + 0.05, 0.5);
        assert!(
            (x - 1.0).abs() < 0.001,
            "and the right reach, which may differ"
        );
        let (_, y) = at(2.0, -5.0 - 15.0, 0.5, 0.5 - 0.04);
        assert!(
            (y + 1.0).abs() < 0.001,
            "a chin-up of the up reach puts the dot on the top of the ring: {}",
            y
        );
        // A shift in the chair alone gets half way, not onto the ring.
        let (x, _) = at(2.0, -5.0, 0.5 - 0.05, 0.5);
        assert!((x + 0.5).abs() < 0.001, "{}", x);
        assert_eq!(
            at(500.0, 500.0, 5.0, 5.0),
            (1.6, 1.6),
            "the dot never leaves the screen"
        );
        // A camera whose axes run the other way is handled by the learned signs.
        let flipped = Reach { sign_x: -1.0, ..r };
        let (x, _) = dot_of(
            &Where {
                yaw: 2.0 - 25.0,
                pitch: -5.0,
                x: 0.5 + 0.05,
                y: 0.5,
            },
            &c,
            &flipped,
        );
        assert!((x + 1.0).abs() < 0.001, "{}", x);
        // Where the range step saw no place movement, the pose stands alone.
        let pose_only = Reach {
            place_x: 0.0,
            place_y: 0.0,
            ..r
        };
        let (_, y) = dot_of(
            &Where {
                yaw: 2.0,
                pitch: -5.0 - 15.0,
                x: 0.5,
                y: 0.5 + 0.2,
            },
            &c,
            &pose_only,
        );
        assert!(
            (y + 1.0).abs() < 0.001,
            "a place that does not count cannot fight the reading: {}",
            y
        );
    }

    /// The ring is set at seventy percent of what the person reached, and
    /// never under the floor the readings' jitter demands. The mesh
    /// recording of 2026-09-23 reached 45 degrees each way, 43 up, 45 down.
    #[test]
    fn the_ring_comes_from_the_persons_reach() {
        let r = Reach::from_extents(45.0, 45.0, 43.0, 45.0);
        assert!((r.left - 31.5).abs() < 0.001 && (r.right - 31.5).abs() < 0.001);
        assert!((r.up - 30.1).abs() < 0.001 && (r.down - 31.5).abs() < 0.001);
        let small = Reach::from_extents(2.0, 2.0, 0.0, 1.0);
        assert_eq!(
            (small.left, small.right, small.up, small.down),
            (
                REACH_FLOOR.left,
                REACH_FLOOR.right,
                REACH_FLOOR.up,
                REACH_FLOOR.down
            ),
            "a person who barely moved still gets a usable ring"
        );
        let placed = small.with_place(0.01, 0.2, 0.0, 0.1, -30.0, 5.0);
        assert_eq!(
            (placed.pos_left, placed.pos_up, placed.sign_x, placed.sign_y),
            (REACH_FLOOR.pos_left, REACH_FLOOR.pos_up, -1.0, 1.0)
        );
        assert!((placed.pos_right - 0.14).abs() < 0.001 && (placed.pos_down - 0.07).abs() < 0.001);
        assert_eq!(
            (placed.place_x, placed.place_y),
            (1.0, 1.0),
            "both axes moved plainly"
        );
        let unmoved = small.with_place(0.043, 0.042, 0.003, 0.032, 50.0, -0.4);
        assert_eq!(
            (unmoved.place_x, unmoved.place_y),
            (1.0, 0.0),
            "sideways counted, vertical did not: it moved 0.03 but with no plain direction"
        );
    }

    /// Along the target's axis the dot must be close; across it, where a
    /// turn drags the pitch reading, it may stray further.
    #[test]
    fn on_target_is_tight_along_the_look_and_loose_across_it() {
        assert!(on_target((0.0, 0.0), (0.0, 0.0)));
        assert!(on_target((0.3, 0.1), (0.0, 0.0)) && !on_target((0.4, 0.0), (0.0, 0.0)));
        // Left target: x must be near -1; y may drift by more than a third.
        assert!(on_target((-1.0, 0.5), (-1.0, 0.0)));
        assert!(on_target((-0.75, -0.6), (-1.0, 0.0)));
        assert!(
            !on_target((-0.5, 0.0), (-1.0, 0.0)),
            "too far back toward the centre"
        );
        assert!(!on_target((-1.0, 0.8), (-1.0, 0.0)), "too far across");
        // Top target: y must be near -1.
        assert!(on_target((0.5, -1.0), (0.0, -1.0)) && !on_target((0.0, -0.5), (0.0, -1.0)));
    }

    /// One-frame flicker is thrown out; a real move comes through.
    #[test]
    fn the_filter_drops_one_frame_flicker() {
        let mut f = Filter::new();
        f.push([0.0, 0.0, 0.18, 0.5, 0.5]);
        f.push([0.0, 0.0, 0.18, 0.5, 0.5]);
        let y = f.push([12.0, 0.0, 0.18, 0.5, 0.5])[0];
        assert!(
            y.abs() < 0.001,
            "a single jump of 12 degrees is flicker: {}",
            y
        );
        let y = f.push([0.0, 0.0, 0.18, 0.5, 0.5])[0];
        assert!(y.abs() < 0.001);
        let mut y = 0.0;
        for _ in 0..8 {
            y = f.push([30.0, 0.0, 0.18, 0.5, 0.5])[0];
        }
        assert!(
            y > 28.0,
            "a held turn comes through within a few frames: {}",
            y
        );
    }

    #[test]
    fn watchers_and_control_are_per_session() {
        let _serial = SESSION_STATICS.lock().unwrap_or_else(|e| e.into_inner());
        assert!(!is_active());
        control("continue");
        assert_eq!(take_control().as_deref(), Some("continue"));
        assert_eq!(take_control(), None);
        let (a, b) = UnixStream::pair().unwrap();
        add_watcher(a);
        broadcast(&Tick::blank("welcome", "hi"));
        use std::io::Read as _;
        let mut buf = [0u8; 512];
        b.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let n = (&b).read(&mut buf).unwrap();
        let line = String::from_utf8_lossy(&buf[..n]);
        assert!(
            line.contains("\"step\":\"welcome\"") && line.ends_with('\n'),
            "{}",
            line
        );
        drop(b);
        broadcast(&Tick::blank("welcome", "bye"));
        assert!(
            WATCHERS.lock().unwrap().is_empty(),
            "a hung-up watcher is dropped"
        );
        // J2: one watcher per session, and one that never reads is dropped
        // at the first full buffer rather than stalling the writer.
        let (first, _keep_first) = UnixStream::pair().unwrap();
        add_watcher(first);
        let (second, silent) = UnixStream::pair().unwrap();
        add_watcher(second);
        assert_eq!(
            WATCHERS.lock().unwrap().len(),
            1,
            "the second replaces the first"
        );
        let started = Instant::now();
        let mut n = 0;
        while !WATCHERS.lock().unwrap().is_empty() {
            broadcast(&Tick::blank("path", &"x".repeat(2000)));
            n += 1;
            assert!(n < 100_000, "a silent watcher was never dropped");
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the writer never blocked on the silent watcher ({} lines in {:?})",
            n,
            started.elapsed()
        );
        drop(silent);
    }
}
