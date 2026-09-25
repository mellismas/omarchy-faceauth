//! The nod and shake detectors: pure state machines over head angles and
//! the face box, kept apart from the camera so a recorded round replays
//! through them exactly as it ran live.

/// One gesture axis as a pure state machine over (signal, time) samples, so
/// it can be replayed from a recorded trace in a test. A gesture is two
/// complete motions: four legs of alternating direction (down, up, down, up
/// or the reverse on the pitch axis; left, right, left, right or the reverse
/// on the yaw axis), each a clear excursion, done together within a short
/// span, from a head that was still just before and does not move its face
/// elsewhere meanwhile. How a person begins and ends (from the centre or
/// from one side) does not matter: four alternating legs is the shape.
///
/// The legs come from a zigzag over the median-filtered signal: an extreme
/// is confirmed once the signal has reversed from it by the threshold, so
/// every counted leg is at least a threshold tall and consecutive legs
/// alternate by construction. The threshold adapts to the signal's own
/// jitter (a face far from the camera is noisier) between a floor and a cap.
pub struct Oscillation {
    name: &'static str,
    pub min_thr: f32,
    pub max_thr: f32,
    /// Longest leg, in seconds: a shake's legs are slower than a nod's.
    pub leg_max_s: f32,
    /// Motion gate: how far, as a fraction of face width, the filtered face
    /// centre may end the gesture from where it began, sideways and up.
    /// The axis the gesture itself moves the box along gets the wider one.
    shift_tol_x: f32,
    shift_tol_y: f32,
    /// Largest leg: bigger is a turn away, not a gesture.
    max_amp: f32,
    /// All four legs, first start to last end, within this.
    pub span_s: f32,
    /// Not moving at all for this long ends the leg where the head is.
    pub rest_s: f32,
    /// Consecutive reversed frames that confirm an extreme.
    pub rev_frames: usize,
    /// Shortest leg.
    pub leg_min_s: f32,
    /// Width change allowed across a gesture (fraction of face width).
    pub width_tol: f32,
    /// Not moving at all: frame-to-frame change under this, in degrees
    /// (`NodDetector::MESH_REST_STEP`).
    pub rest_step: f32,
    /// The whole face box must move with the leg: along x for a shake, y
    /// for a nod, by at least this fraction of the face width between the
    /// leg's start and its extreme. A head that moves carries its box; a
    /// detector fit that switches solutions moves one landmark and leaves
    /// the box where it was (recorded 2026-09-22: box centre moved 1 px
    /// through a fit flip that read as a nod; 9 to 16 px through real nods).
    /// None turns the rule off.
    pub co_motion: Option<(u8, f32)>,
    raw: Vec<f32>,
    settle: Vec<f32>,
    /// Slow-following baseline, for `idle` and the logs.
    pub base: Option<f32>,
    /// The current excursion threshold.
    pub thr: f32,
    jitter: f32,
    last_p: Option<f32>,
    /// Size of the last frame-to-frame change.
    last_step: f32,
    last_t: Option<f32>,
    /// Last confirmed extreme (value, time).
    pivot: Option<(f32, f32)>,
    /// The extreme being tracked in the current direction.
    cand: (f32, f32),
    /// +1 rising from the pivot, -1 falling, 0 not yet left it.
    pub dir: i8,
    /// Consecutive frames reversed from the candidate extreme.
    rev_count: usize,
    /// When the head stopped moving, if it has.
    rest_since: Option<f32>,
    /// Last time the signal sat close to the pivot: where a first leg starts.
    depart: f32,
    /// Completed legs as (start, end, extreme value, amplitude).
    pub legs: Vec<(f32, f32, f32, f32)>,
    last_active: Option<f32>,
    /// Recent (t, face width, centre x, centre y) for the motion gate.
    motion: Vec<(f32, f32, f32, f32)>,
    /// Seconds the face was already steadily in view before t = 0 (the scan
    /// that matched it): counts toward the still second before a first leg.
    pub prior_still: f32,
    /// Completed gestures.
    pub gestures: usize,
}

impl Oscillation {
    /// Legs in a gesture: two complete motions.
    pub const LEGS: usize = 4;
    /// Default span: the user's two nods, with the beat between them, span
    /// up to about three seconds.
    pub const SPAN_S: f32 = 3.0;
    /// Box movement along the gesture axis each leg must carry, in face
    /// widths. Swept 2026-09-22 over the calibration corpus and the
    /// calibrated-floor recording: every recorded nod and shake holds up to
    /// 0.08, a box that does not move is refused from 0.02, and a detector
    /// fit flip moved the box 0.011. 0.04 sits between with margin both ways.
    pub const CO_MOTION: f32 = 0.04;
    /// A leg shorter than this is a flicker (default). A quick nod's leg is
    /// 0.06 s (recorded); one-frame spikes are gone in the median already.
    const LEG_MIN_S: f32 = 0.05;
    /// Default reversal confirmation: one filtered frame is still a flicker.
    const REV_FRAMES: usize = 2;
    /// Default rest: the last leg of a gesture ends at rest, and a glance
    /// holds. The slow top of a real nod is not rest: it keeps creeping.
    const REST_S: f32 = 0.5;
    /// Median window over the raw signal.
    const MEDIAN: usize = 3;
    /// The face must have been still this long before the first leg.
    const STILL_S: f32 = 1.0;
    /// Default: filtered face width may end the gesture this far from where
    /// it began; more is the body moving. A shake narrows the box as the
    /// head turns, so its detector allows more.
    const WIDTH_TOL: f32 = 0.06;
    /// Threshold as a multiple of the noise floor.
    pub const JITTER_MULT: f32 = 4.0;
    const SETTLE_FRAMES: usize = 8;
    /// Baseline time constant in seconds.
    const TAU_S: f32 = 1.5;

    // Seven tuning knobs, each named at the call sites; a builder would only
    // hide which one is being set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &'static str,
        min_thr: f32,
        max_thr: f32,
        leg_max_s: f32,
        shift_tol_x: f32,
        shift_tol_y: f32,
        max_amp: f32,
    ) -> Self {
        Oscillation {
            name,
            min_thr,
            max_thr,
            leg_max_s,
            shift_tol_x,
            shift_tol_y,
            max_amp,
            prior_still: 0.0,
            span_s: Self::SPAN_S,
            rest_s: Self::REST_S,
            rev_frames: Self::REV_FRAMES,
            leg_min_s: Self::LEG_MIN_S,
            width_tol: Self::WIDTH_TOL,
            rest_step: NodDetector::MESH_REST_STEP,
            co_motion: None,
            raw: Vec::new(),
            settle: Vec::new(),
            base: None,
            thr: min_thr,
            jitter: 0.0,
            last_p: None,
            last_step: 0.0,
            last_t: None,
            pivot: None,
            cand: (0.0, 0.0),
            dir: 0,
            rev_count: 0,
            rest_since: None,
            depart: 0.0,
            legs: Vec::new(),
            last_active: None,
            motion: Vec::new(),
            gestures: 0,
        }
    }

    /// True while the head is still or has only just moved: the caller may
    /// look at fewer frames. False once something like a gesture has begun.
    pub fn idle(&self, t: f32) -> bool {
        self.base.is_some() && self.last_active.map(|a| t - a > 1.0).unwrap_or(true)
    }

    fn set_threshold(&mut self) {
        self.thr = (self.jitter * Self::JITTER_MULT).clamp(self.min_thr, self.max_thr);
    }

    /// Did the face box end the span `from..=to` somewhere other than it
    /// began? The box flickers between two fits on alternate frames and rides
    /// with the gesture itself, so the test is the change of the three-frame
    /// median from the start of the span to its end.
    fn moved(&self, from: f32, to: f32, why: &str) -> bool {
        let window: Vec<&(f32, f32, f32, f32)> = self
            .motion
            .iter()
            .filter(|m| m.0 >= from && m.0 <= to)
            .collect();
        if window.len() < 6 {
            return false;
        }
        let med = |i: usize, f: fn(&(f32, f32, f32, f32)) -> f32| {
            let mut v = [f(window[i]), f(window[i + 1]), f(window[i + 2])];
            v.sort_by(|a, b| a.total_cmp(b));
            v[1]
        };
        let last = window.len() - 3;
        let (w0, w1) = (med(0, |m| m.1), med(last, |m| m.1));
        let (x0, x1) = (med(0, |m| m.2), med(last, |m| m.2));
        let (y0, y1) = (med(0, |m| m.3), med(last, |m| m.3));
        let w = w0.max(w1).max(1.0);
        let moved = (w1 - w0).abs() / w > self.width_tol
            || (x1 - x0).abs() / w > self.shift_tol_x
            || (y1 - y0).abs() / w > self.shift_tol_y;
        if moved {
            log::debug!("consent: {} legs rejected, {} (width {:.0} to {:.0}, x {:.0} to {:.0}, y {:.0} to {:.0})", self.name, why, w0, w1, x0, x1, y0, y1);
        }
        moved
    }

    /// A leg just completed at `end`: does the sequence make a gesture?
    fn legs_complete(
        &mut self,
        start: f32,
        end: f32,
        extreme: f32,
        amp: f32,
        at_rest: bool,
    ) -> bool {
        self.legs.push((start, end, extreme, amp));
        while self.legs.len() > 1 && end - self.legs[0].0 > self.span_s {
            self.legs.remove(0);
        }
        if self.legs.len() < Self::LEGS {
            // A head that rests at an extreme mid-sequence was looking at
            // something, not gesturing: the sequence starts over. The one
            // rest allowed is at the midpoint, the beat between the two
            // motions (a glance rests after its first leg, at the thing it
            // looked at).
            if at_rest && self.legs.len() != Self::LEGS / 2 {
                log::debug!(
                    "consent: {} legs rejected, the head rested at {:+.2} after {} leg(s)",
                    self.name,
                    extreme,
                    self.legs.len()
                );
                self.legs.clear();
            }
            return false;
        }
        let first = self.legs[0].0;
        // The head turned; the face ends the gesture the same size and place
        // it began. A lean, a slump or a shift carries it somewhere else.
        if self.moved(first - 0.3, end, "the face moved") {
            self.legs.clear();
            return false;
        }
        // The gesture must follow a still second: someone who has only just
        // sat down or turned to the screen, glancing between it and the
        // keyboard, has not gestured yet. A face seen for less than that
        // second has not been still either.
        if self
            .motion
            .first()
            .map(|m| m.0 - self.prior_still > first - Self::STILL_S + 0.2)
            .unwrap_or(false)
            || self.moved(first - Self::STILL_S, first, "the face had just arrived")
        {
            self.legs.clear();
            return false;
        }
        self.gestures += 1;
        self.legs.clear();
        true
    }

    /// Feed one face frame; returns true when a gesture just completed.
    pub fn push(&mut self, v: f32, t: f32) -> bool {
        self.push_with(v, t, None)
    }

    /// As `push`, with the face's width and centre for the motion gate.
    pub fn push_with(&mut self, v: f32, t: f32, face: Option<(f32, f32, f32)>) -> bool {
        if let Some((w, cx, cy)) = face {
            self.motion.push((t, w, cx, cy));
            if self.motion.len() > 96 {
                self.motion.remove(0);
            }
        }
        self.raw.push(v);
        if self.raw.len() < Self::MEDIAN {
            return false;
        }
        if self.raw.len() > 64 {
            self.raw.remove(0);
        }
        let n = self.raw.len();
        let mut w: Vec<f32> = self.raw[n - Self::MEDIAN..].to_vec();
        w.sort_by(|a, b| a.total_cmp(b));
        let p = w[Self::MEDIAN / 2];
        let dt = self.last_t.map(|l| (t - l).clamp(0.0, 0.5)).unwrap_or(0.04);
        self.last_t = Some(t);
        let Some(b) = self.base else {
            // The baseline and noise floor come from a run of quiet frames;
            // a user who gestures the moment the window appears must not
            // have the gesture measured as noise (it would raise the
            // threshold to its cap and hide the gesture itself).
            self.settle.push(p);
            if self.settle.len() > Self::SETTLE_FRAMES {
                self.settle.remove(0);
            }
            if self.settle.len() >= Self::SETTLE_FRAMES {
                let mut s = self.settle.clone();
                s.sort_by(|a, b| a.total_cmp(b));
                let quiet = s[s.len() - 1] - s[0] <= self.min_thr * 1.5;
                if quiet {
                    let base = s[s.len() / 2];
                    self.jitter = self
                        .settle
                        .windows(2)
                        .map(|w| (w[1] - w[0]).abs())
                        .sum::<f32>()
                        / (self.settle.len() - 1) as f32;
                    self.set_threshold();
                    self.base = Some(base);
                    self.pivot = Some((p, t));
                    self.depart = t;
                }
            }
            return false;
        };
        let e = p - b;
        // The baseline follows the head slowly, whatever it is doing; a
        // gesture is too quick to move it much, a lean is absorbed.
        self.base = Some(b + e * (dt / Self::TAU_S).min(1.0));
        if e.abs() > self.thr / 2.0 {
            self.last_active = Some(t);
        }
        if let Some(lp) = self.last_p {
            let step = (p - lp).abs();
            self.last_step = step;
            // Only clearly-noise steps teach the noise floor: a gesture's own
            // frames, just under the threshold, must not raise it mid-gesture
            // (they did, on the motion signal, and hid the later legs).
            if step < self.thr * 0.25 {
                self.jitter += 0.05 * (step - self.jitter);
                self.set_threshold();
            }
        }
        self.last_p = Some(p);
        let Some((pv, pt)) = self.pivot else {
            return false;
        };
        match self.dir {
            0 => {
                if (p - pv).abs() < self.thr * 0.25 {
                    self.depart = t;
                }
                if p - pv >= self.thr || pv - p >= self.thr {
                    self.dir = if p > pv { 1 } else { -1 };
                    self.cand = (p, t);
                } else if t - pt > 0.5 {
                    // Idle: re-anchor on the drifting head.
                    self.pivot = Some((p, t));
                }
                false
            }
            d => {
                // Strictly further: a rest at the extreme does not extend the
                // leg, so the pause between two nods is not part of either.
                let further = if d > 0 {
                    p > self.cand.0
                } else {
                    p < self.cand.0
                };
                // Not moving at all: a step at the still-face noise level, an
                // absolute of the floor (a still face moves 0.003 of a width
                // between frames; a slow turnaround moves more).
                let still = self.last_step < self.rest_step;
                if further {
                    self.cand = (p, t);
                    self.rev_count = 0;
                    self.rest_since = if still {
                        self.rest_since.or(Some(t))
                    } else {
                        None
                    };
                    return false;
                }
                let reversed = if d > 0 {
                    self.cand.0 - p >= self.thr
                } else {
                    p - self.cand.0 >= self.thr
                };
                let at_rest = if !reversed {
                    self.rev_count = 0;
                    if still {
                        let since = *self.rest_since.get_or_insert(t);
                        t - since >= self.rest_s
                    } else {
                        self.rest_since = None;
                        false
                    }
                } else {
                    self.rest_since = None;
                    self.rev_count += 1;
                    false
                };
                if !at_rest && self.rev_count < self.rev_frames {
                    return false;
                }
                self.rev_count = 0;
                self.rest_since = None;
                // The extreme is confirmed: one leg, from the previous extreme
                // (or from where the head left its rest) to it.
                // A first leg starts where the head left its rest; a later
                // one at the previous extreme.
                let start = if self.legs.is_empty() {
                    self.depart.max(pt)
                } else {
                    pt
                };
                let (cv, ct) = self.cand;
                let dur = ct - start;
                let carried = match self.co_motion {
                    None => true,
                    Some((axis, min)) => {
                        // The box's swing along the axis across the leg,
                        // with a margin either side: the filtered signal
                        // lags the head, so the instants the leg is timed
                        // by fall inside the box's own movement.
                        let (lo_t, hi_t) = (start - 0.2, ct + 0.2);
                        let mut lo = f32::MAX;
                        let mut hi = f32::MIN;
                        let mut w = 1.0f32;
                        for m in self.motion.iter().filter(|m| m.0 >= lo_t && m.0 <= hi_t) {
                            let v = if axis == 1 { m.2 } else { m.3 };
                            lo = lo.min(v);
                            hi = hi.max(v);
                            w = w.max(m.1);
                        }
                        if lo > hi {
                            true
                        } else {
                            let moved = (hi - lo) / w;
                            if moved < min {
                                log::debug!("consent: {} leg rejected, the box did not move with it ({:.3} of width)", self.name, moved);
                            }
                            moved >= min
                        }
                    }
                };
                let amp = (cv - pv).abs();
                self.pivot = Some((cv, ct));
                // Reversed: the next leg is under way. At rest: back to
                // waiting for the head to leave this spot.
                self.dir = if at_rest { 0 } else { -d };
                self.depart = ct;
                self.cand = (p, t);
                if !carried
                    || !(self.leg_min_s..=self.leg_max_s).contains(&dur)
                    || amp > self.max_amp
                {
                    log::debug!(
                        "consent: {} leg rejected (box {}, {:.2}s, {:.2} tall)",
                        self.name,
                        if carried { "carried" } else { "still" },
                        dur,
                        amp
                    );
                    self.legs.clear();
                    return false;
                }
                self.legs_complete(start, ct, cv, amp, at_rest)
            }
        }
    }
}

/// Nods: the pitch axis, in degrees from the face mesh.
pub struct NodDetector {
    pub inner: Oscillation,
    /// Nods counted: two per completed gesture.
    pub nods: usize,
    /// Recent (t, yaw), for the quiet-yaw and facing rules.
    yaw: Vec<(f32, f32)>,
}

impl NodDetector {
    /// On the mesh's pitch, in degrees. From the rounds of 2026-09-24
    /// (`traces/v2`): a nod's legs are 12 to 35 degrees and take 0.23 to
    /// 0.33 s, reversing at once; a look at the keyboard is 17 to 21
    /// degrees a leg but takes 0.9 to 2 s and holds at the bottom, a lean
    /// 18 to 30 over 1.1 to 3.3 s. Size does not separate them; the leg
    /// time does, so a leg may take at most `MESH_LEG_MAX_S`.
    pub const MESH_MIN_DEG: f32 = 8.0;
    pub const MESH_MAX_DEG: f32 = 60.0;
    pub const MESH_LEG_MAX_S: f32 = 0.6;
    /// Still, on the mesh: under this many degrees between frames (a still
    /// head reads 0.7 on average, a turnaround several).
    pub const MESH_REST_STEP: f32 = 1.5;
    /// A nod keeps the head facing the camera: yaw may range this much
    /// over the gesture's span, in degrees. Set on the five-point yaw
    /// measure as 0.25 of it (a still head ranged 0.03, the user's nods up
    /// to 0.11, a head shake 0.6 or more, and a shake's perspective wobble
    /// on the pitch measure would otherwise have read as nods) and
    /// restated in degrees at `YAW_DEG_PER_UNIT`, so the rule did not move.
    pub const YAW_QUIET_DEG: f32 = 21.43;
    /// A nod counts only from a head facing the camera (the presence
    /// watch's attentive yaw): the mean yaw over the nod's span, degrees,
    /// must be within this. A head held turned toward another screen nods
    /// the same way on the pitch axis, but it is not nodding at the card.
    /// 0.40 of the five-point measure, restated as above; the reference
    /// nods held 30 degrees off still read and are refused from 36.
    pub const YAW_FACING_DEG: f32 = 34.29;
    /// Degrees of mesh yaw per unit of the five-point yaw measure (a 30
    /// degree turn read about 0.35 on it). The gesture rules are written
    /// in degrees; the presence watch's `max_yaw` is still in five-point
    /// units and converts with this.
    pub const YAW_DEG_PER_UNIT: f32 = 30.0 / 0.35;

    pub fn mesh(floor_deg: f32) -> Self {
        let floor = floor_deg.max(Self::MESH_MIN_DEG);
        let mut inner = Oscillation::new(
            "nod",
            floor,
            Self::MESH_MAX_DEG.max(floor),
            Self::MESH_LEG_MAX_S,
            0.10,
            0.30,
            Self::MESH_MAX_DEG,
        );
        // The box must ride each leg: a head that nods carries its box, a
        // detector fit that flips does not (1 px through a recorded flip,
        // 9 to 16 px through real nods). See `Oscillation::CO_MOTION`.
        inner.co_motion = Some((2, Oscillation::CO_MOTION));
        NodDetector {
            inner,
            nods: 0,
            yaw: Vec::new(),
        }
    }

    pub fn idle(&self, t: f32) -> bool {
        self.inner.idle(t)
    }

    /// Feed one frame: the pitch, the yaw for the quiet-yaw and facing
    /// rules (None when the caller has none), the time, and the box's
    /// width and centre for the motion rules. True when a nod pair just
    /// completed.
    pub fn push_full(
        &mut self,
        pitch: f32,
        yaw: Option<f32>,
        t: f32,
        face: Option<(f32, f32, f32)>,
    ) -> bool {
        if let Some(y) = yaw {
            self.yaw.push((t, y));
            self.yaw
                .retain(|(yt, _)| t - yt <= Oscillation::SPAN_S + 0.5);
        }
        let hit = self.inner.push_with(pitch, t, face);
        if !hit {
            return false;
        }
        let span: Vec<f32> = self
            .yaw
            .iter()
            .filter(|(yt, _)| t - yt <= Oscillation::SPAN_S)
            .map(|(_, y)| *y)
            .collect();
        if let (Some(lo), Some(hi)) = (
            span.iter().cloned().reduce(f32::min),
            span.iter().cloned().reduce(f32::max),
        ) {
            if hi - lo > Self::YAW_QUIET_DEG {
                log::debug!(
                    "consent: nod rejected, the head turned meanwhile (yaw range {:.0} deg)",
                    hi - lo
                );
                return false;
            }
            let mean = span.iter().sum::<f32>() / span.len() as f32;
            if mean.abs() > Self::YAW_FACING_DEG {
                log::debug!(
                    "consent: nod rejected, the head faced away (mean yaw {:.0} deg)",
                    mean
                );
                return false;
            }
        }
        self.nods += 2;
        true
    }
}

/// Head shakes: the yaw axis, in degrees from the face mesh. A refusal,
/// so a false positive costs a password prompt, not a root shell: the
/// floor can sit lower than a glance at a second monitor only because a
/// glance is one leg and a hold, never four alternating legs.
pub struct ShakeDetector {
    pub inner: Oscillation,
    /// Shakes counted: two per completed gesture.
    pub shakes: usize,
}

impl ShakeDetector {
    /// On the mesh's yaw, in degrees. From the rounds of 2026-09-24: a
    /// shake's legs are 33 to 53 degrees and take about 0.3 s; a glance
    /// aside is as large (32 to 50) but takes 0.8 to 2.2 s and holds at
    /// the side for half a second or more.
    pub const MESH_MIN_DEG: f32 = 15.0;
    pub const MESH_MAX_DEG: f32 = 80.0;
    pub const MESH_LEG_MAX_S: f32 = 0.6;

    pub fn mesh(floor_deg: f32) -> Self {
        let floor = floor_deg.max(Self::MESH_MIN_DEG);
        // A shake slides the box sideways and narrows it by about 7% as
        // the head turns (recorded): not the body moving, so the width
        // tolerance is wider than a nod's. A glance is caught by its hold
        // (the rest rule) and its leg time.
        let mut inner = Oscillation::new(
            "shake",
            floor,
            Self::MESH_MAX_DEG.max(floor),
            Self::MESH_LEG_MAX_S,
            0.60,
            0.30,
            Self::MESH_MAX_DEG,
        );
        inner.width_tol = 0.15;
        // The box must slide with each leg (see the nod detector).
        inner.co_motion = Some((1, Oscillation::CO_MOTION));
        ShakeDetector { inner, shakes: 0 }
    }

    pub fn push_with(&mut self, yaw: f32, t: f32, face: Option<(f32, f32, f32)>) -> bool {
        let hit = self.inner.push_with(yaw, t, face);
        if hit {
            self.shakes += 2;
        }
        hit
    }
}

#[cfg(test)]
mod dwell_tests {
    use super::*;

    /// A head already nodding when the nod window opens: 0.3 s near rest
    /// (the settle), then two nods at mesh scale (15 degrees, 0.27 s legs),
    /// the box riding each leg by 0.08 face widths; `still_first` puts a
    /// full still second in front instead.
    fn nodding(still_first: bool) -> Option<f32> {
        let mut det = NodDetector::mesh(NodDetector::MESH_MIN_DEG);
        assert_eq!(
            det.inner.prior_still, 0.0,
            "the nod window credits no still second"
        );
        let fps = 30.0f32;
        let mut t = 0.0f32;
        let (w, cx, cy0) = (90.0f32, 250.0f32, 340.0f32);
        let mut frames: Vec<(f32, f32)> = Vec::new();
        for _ in 0..(if still_first { 45 } else { 9 }) {
            frames.push((0.0, cy0));
        }
        let leg = 8usize;
        for _ in 0..2 {
            for k in 1..=leg {
                let f = k as f32 / leg as f32;
                frames.push((15.0 * f, cy0 + 7.0 * f));
            }
            for k in 1..=leg {
                let f = k as f32 / leg as f32;
                frames.push((15.0 * (1.0 - f), cy0 + 7.0 * (1.0 - f)));
            }
        }
        for _ in 0..30 {
            frames.push((0.0, cy0));
        }
        for (p, cy) in frames {
            if det.push_full(p, Some(0.0), t, Some((w, cx, cy))) {
                return Some(t);
            }
            t += 1.0 / fps;
        }
        None
    }

    /// D4: a nod under way when the window opens does not count; the same
    /// nod from a head seen still for a second does.
    #[test]
    fn a_nod_under_way_at_the_window_start_does_not_count() {
        assert!(
            nodding(false).is_none(),
            "a nod already in motion at the card is not a nod at it"
        );
        assert!(
            nodding(true).is_some(),
            "the same nod after an observed still second counts"
        );
    }
}
