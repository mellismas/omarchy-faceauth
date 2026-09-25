//! Where the dot goes: the head's place in ring units from the person's
//! own centre and reach, the path the target walks, the zones it holds
//! at, and whether the dot counts as on target.

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

pub fn hold_target(zone: &str) -> (f32, f32) {
    match zone {
        "left" => (-1.0, 0.0),
        "right" => (1.0, 0.0),
        "up" => (0.0, -TOP),
        "down" => (0.0, 1.0),
        _ => (0.0, 0.0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
