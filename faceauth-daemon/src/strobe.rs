//! The strobe gate: lit/unlit frame pairs under a fresh random mask, paired
//! only once the frames follow the mask, with the exposure frozen for the
//! spell and steady light restored when it ends. The one place the pairing
//! rule lives; the scan, the confirm after the nods and the presence look
//! all read their pairs from it (H7), so the settle after the mask is
//! written, the phase check, the dropped-frame reset (J8) and the
//! exposure read-back (J19) cannot drift apart between them again.

use crate::capture::IrCapture;
use anyhow::Result;
use faceauth_engine::liveness::{FlashResponse, StrobePhase, Verdict};
use faceauth_engine::{Face, Grey};
use std::time::{Duration, Instant};

/// After the mask is written the sensor takes a few frames to follow it;
/// nothing before this is a pair.
const SETTLE: Duration = Duration::from_millis(150);

/// Strong brightness steps off the mask in one unbroken run of frames,
/// with the frames never once following it, at which a gate reads its
/// stream as brightening on a schedule of its own (C11). A live face under
/// the strobe follows the mask within eight frames and leaves at most
/// three such steps each time the lock starts over; a stream looping a
/// pattern of its own leaves one to four every eight frames for as long
/// as it runs, several dozen in a scan. Only steps of `OFF_MASK_STEP` or
/// more count, and a dropped frame starts the run over, so frame noise
/// alone, at a faint flash contrast or on a stream that drops frames,
/// does not raise the flag (the simulation below). A lamp flickering with
/// the mains does, on a live face, so the flag is only ever logged: the
/// attempt that raised it ends uncharged.
pub const OFF_MASK_STEPS: usize = 8;

/// Did the frames under `phase` step hard in brightness on a schedule of
/// their own and never once follow the mask? What a replayed stream does;
/// a steady scene never steps, and a live face under the strobe follows
/// the mask. Frames seen to follow the mask backwards (`backwards_seen`)
/// are most likely the sensor walking the pattern the other way (J9), so
/// they are not charged; a looping stream reads backwards only by the
/// same chance that would have put it in phase, about one gate in nine.
pub(crate) fn off_mask(phase: &StrobePhase, backwards_seen: bool) -> bool {
    !phase.ever_in_phase() && !backwards_seen && phase.edges_off_mask() >= OFF_MASK_STEPS
}

/// A lit frame with the unlit frame before it, or, on a camera without a
/// strobe the gate may run ungated on, every third frame alone.
pub struct Pair {
    pub lit: Grey,
    pub unlit: Option<Grey>,
    /// Frames the gate has taken so far, this one included.
    pub frame_no: usize,
}

/// What `StrobeGate::next_frame_seen` took.
pub enum Took<'g> {
    /// No frame came in the time allowed.
    Nothing,
    /// A frame that completes no pair.
    Frame(&'g Grey),
    Pair(Pair),
}

/// What the gate says about a pair at a face.
#[derive(Debug)]
pub enum Gate {
    /// Live, or ungated: the frame may be scored.
    Pass(Option<FlashResponse>),
    /// No usable strobe signal at the face: nothing to decide on.
    NoSignal(FlashResponse),
    /// Not a live face, or the sensor's exposure is not what the daemon
    /// wrote.
    Denied(String, FlashResponse),
}

/// The verdict on a measured pair, given the exposure and gain the daemon
/// wrote, which the pair is measured with, and the sensor's own read-back
/// now (J19). They must be equal: a sensor running at settings the daemon
/// did not write skews the lit frame against the unlit one, or the flash
/// response against the exposure it is judged at, whether the change came
/// under the gate or before it began, so the pair is refused. A read-back
/// that failed leaves the pair unverified, and an unverified pair is never
/// passed: it reads as no signal, which an attempt or a confirm neither
/// scores nor charges.
fn judged(fr: FlashResponse, written: (i32, i32), now: Result<(i32, i32)>) -> Gate {
    let now = match now {
        Ok(now) => now,
        Err(e) => {
            log::warn!(
                "strobe gate: the sensor's exposure could not be read back ({:#}); pair not trusted",
                e
            );
            return Gate::NoSignal(fr);
        }
    };
    if now != written {
        log::warn!(
            "strobe gate: the sensor reads exposure and gain {:?}, not the {:?} the daemon wrote; pair refused",
            now,
            written
        );
        return Gate::Denied("exposure changed under the gate".into(), fr);
    }
    match fr.verdict() {
        Verdict::Pass => Gate::Pass(Some(fr)),
        Verdict::NoSignal => Gate::NoSignal(fr),
        v => Gate::Denied(format!("{:?}", v), fr),
    }
}

/// The gate's frames: the one just read and the one before it, in two
/// buffers that trade places, so a frame that is not a pair costs no
/// allocation or copy (C7).
#[derive(Default)]
struct Frames {
    /// The frame just read; the next frame is read into it.
    cur: Grey,
    /// The frame before it, while it can be the unlit half of a pair. A
    /// pair's lit frame never is (the frame after it cannot be a step up
    /// from it), so a pair takes both frames and leaves this empty.
    prev: Option<Grey>,
    /// The sequence number of the frame before `cur`: a lit frame pairs
    /// only when no frame was dropped between the two.
    prev_seq: Option<u32>,
}

impl Frames {
    /// Record the sequence number of the frame just read; true when frames
    /// were dropped since the one before it, whose image is then no
    /// predecessor.
    fn gap(&mut self, seq: u32) -> bool {
        let gap = self.prev_seq.is_some_and(|p| seq != p.wrapping_add(1));
        if gap {
            self.prev = None;
        }
        self.prev_seq = Some(seq);
        gap
    }

    /// The frame just read, with the one before it, when `offered` and
    /// there is one; otherwise the frame just read becomes the next one's
    /// predecessor and the buffer it replaces takes the next frame.
    fn settle(&mut self, offered: bool) -> Option<(Grey, Grey)> {
        if offered {
            if let Some(unlit) = self.prev.take() {
                return Some((std::mem::take(&mut self.cur), unlit));
            }
        }
        let spare = self.prev.take().unwrap_or_default();
        self.prev = Some(std::mem::replace(&mut self.cur, spare));
        None
    }

    /// The frame just read, when it completed no pair: gated, it waits as
    /// the next frame's predecessor; ungated, it stays where it was read.
    fn unpaired(&self) -> &Grey {
        self.prev.as_ref().unwrap_or(&self.cur)
    }

    /// Forget the frames before the next one: it pairs with nothing.
    fn forget(&mut self) {
        self.prev = None;
        self.prev_seq = None;
    }
}

pub struct StrobeGate<'a> {
    cap: &'a mut IrCapture,
    /// None when the gate runs ungated: the sensor has no strobe control,
    /// and the caller has decided that is allowed.
    phase: Option<StrobePhase>,
    buf: Frames,
    started: Instant,
    frames: usize,
    /// Where the face is, widened a little: the phase follows the mean over
    /// this box instead of the whole frame once a caller names it.
    focus: Option<[f32; 4]>,
    /// Whether the gate has warned that the frames follow the mask
    /// backwards: once per gate.
    warned_backwards: bool,
}

impl<'a> StrobeGate<'a> {
    /// Freeze the exposure and, with `strobe`, write a fresh mask. The
    /// caller says whether the strobe runs: the daemon refuses an ungated
    /// scan unless the administrator allowed one, and the presence look
    /// reads an ungated pair as no verdict.
    pub fn start(cap: &'a mut IrCapture, strobe: bool) -> Result<Self> {
        cap.freeze_exposure(true);
        let phase = match (&cap.illuminator, strobe) {
            (Some(i), true) => {
                let phase = StrobePhase::random();
                i.set_pattern(phase.pattern())?;
                Some(phase)
            }
            _ => None,
        };
        Ok(StrobeGate {
            cap,
            phase,
            buf: Frames::default(),
            started: Instant::now(),
            frames: 0,
            focus: None,
            warned_backwards: false,
        })
    }

    /// A fresh mask for the next pair (C11). One mask per attempt lets a
    /// replayed stream that happens to be in phase pass every pair of the
    /// attempt; drawn again after each matched pair, the matches an attempt
    /// needs come under different masks, and a looping recording is in
    /// phase for both about one time in seventy instead of one in nine.
    /// The settle starts over, so a redraw costs the eight frames the next
    /// pair waits for. Ungated, nothing happens.
    pub fn redraw(&mut self) -> Result<()> {
        let Some(phase) = self.phase.as_mut() else {
            return Ok(());
        };
        let pattern = phase.redraw();
        if let Some(i) = &self.cap.illuminator {
            i.set_pattern(pattern)?;
        }
        self.buf.forget();
        self.started = Instant::now();
        Ok(())
    }

    /// Masks drawn so far, counting the first; 0 when ungated.
    pub fn draws(&self) -> usize {
        self.phase.as_ref().map(|p| p.draws()).unwrap_or(0)
    }

    /// Follow the mask on the face at `bbox` rather than on the whole
    /// frame. The illuminator lights the face far more than the room, so a
    /// face that fills little of the frame (sitting back: about 50 px of a
    /// 480 px frame) still steps clearly with the mask where the frame mean
    /// barely moves, and the phase locks there too; the face itself has to
    /// follow the random mask, which a replay has to match as well. The
    /// first call restarts the phase lock, since the measure changes;
    /// later calls move the box with the face.
    pub fn focus_on(&mut self, bbox: [f32; 4]) {
        let (cx, cy) = (bbox[0] + bbox[2] / 2.0, bbox[1] + bbox[3] / 2.0);
        let (w, h) = (bbox[2] * 1.2, bbox[3] * 1.2);
        let widened = [cx - w / 2.0, cy - h / 2.0, w, h];
        if self.focus.is_none() {
            if let Some(phase) = self.phase.as_mut() {
                phase.reset();
            }
            self.buf.forget();
        }
        self.focus = Some(widened);
    }

    /// Is the strobe running?
    pub fn strobed(&self) -> bool {
        self.phase.is_some()
    }

    /// Frames taken so far.
    pub fn frames(&self) -> usize {
        self.frames
    }

    /// Have the frames followed the mask at any point? False when ungated.
    pub fn locked(&self) -> bool {
        self.phase
            .as_ref()
            .map(|p| p.ever_in_phase())
            .unwrap_or(false)
    }

    /// Did the frames step hard in brightness on their own schedule and
    /// never follow the mask (`off_mask`)? The most strong steps off it in
    /// one unbroken run when they did, for the journal; None when they did
    /// not, or ungated.
    pub fn off_mask(&self) -> Option<usize> {
        self.phase
            .as_ref()
            .filter(|p| off_mask(p, self.warned_backwards))
            .map(|p| p.edges_off_mask())
    }

    /// The exposure the pairs are taken at.
    pub fn exposure(&self) -> faceauth_camera::calib::Exposure {
        self.cap.exposure
    }

    /// Take one frame. `Some` when it completes a pair: a lit frame after
    /// an unlit one, the eight frames ending here following the mask, no
    /// frame dropped between the two, and the settle after the mask over.
    /// A dropped frame (a gap in the driver's sequence numbers) starts the
    /// phase lock over: the frames either side of a gap may be any two
    /// of the mask (J8). Frames that follow the mask backwards are never a
    /// pair; the gate warns once that the sensor walks the pattern the
    /// other way (J9). Ungated, every third frame is offered alone.
    pub fn next_frame(&mut self, timeout: Duration) -> Result<Option<Pair>> {
        if !self.cap.next_into(&mut self.buf.cur, timeout)? {
            return Ok(None);
        }
        self.frames += 1;
        let Some(phase) = self.phase.as_mut() else {
            return Ok(if self.frames.is_multiple_of(3) {
                Some(Pair {
                    lit: std::mem::take(&mut self.buf.cur),
                    unlit: None,
                    frame_no: self.frames,
                })
            } else {
                None
            });
        };
        let seq = self.cap.sequence();
        let prev_seq = self.buf.prev_seq;
        if self.buf.gap(seq) {
            log::debug!(
                "strobe gate: frames dropped between {:?} and {}; the phase lock starts over",
                prev_seq,
                seq
            );
            phase.reset();
        }
        // The frame mean, computed once here for the phase check.
        let level = match self.focus {
            Some(b) => self.buf.cur.region_mean(b),
            None => self.buf.cur.mean(),
        };
        let in_phase = phase.push(level);
        if !self.warned_backwards && phase.backwards() {
            self.warned_backwards = true;
            log::warn!(
                "strobe gate: the frames follow the mask backwards: the sensor walks the pattern from bit 0 towards bit 7, the opposite order from the one the gate expects, so this mask never pairs"
            );
        }
        let offered = in_phase && self.started.elapsed() >= SETTLE;
        Ok(self.buf.settle(offered).map(|(lit, unlit)| Pair {
            lit,
            unlit: Some(unlit),
            frame_no: self.frames,
        }))
    }

    /// `next_frame`, handing back the frame just read when it completes no
    /// pair, so a caller can follow the face on every frame and not only
    /// on the pairs: a check whose pairs are slow to form (a faint flash)
    /// still keeps its face within the follow's gap (A6).
    pub fn next_frame_seen(&mut self, timeout: Duration) -> Result<Took<'_>> {
        let before = self.frames;
        Ok(match self.next_frame(timeout)? {
            Some(pair) => Took::Pair(pair),
            None if self.frames == before => Took::Nothing,
            None => Took::Frame(self.buf.unpaired()),
        })
    }

    /// The gate's verdict on `pair` at `face`'s box. The sensor's exposure
    /// and gain are read back with every measured pair and must match what
    /// the daemon wrote and measures the pair with (`judged`), rather than
    /// being trusted as written (J19). The exposure is frozen for the
    /// spell, so what was written is what the capture holds.
    pub fn judge(&self, pair: &Pair, face: &Face) -> Result<Gate> {
        let Some(unlit) = &pair.unlit else {
            return Ok(Gate::Pass(None));
        };
        let written = self.cap.exposure;
        let fr = FlashResponse::measure(
            &pair.lit,
            unlit,
            face,
            written.exposure,
            written.gain.max(16),
        );
        Ok(judged(
            fr,
            (written.exposure as i32, written.gain as i32),
            self.cap.read_back(),
        ))
    }
}

impl Drop for StrobeGate<'_> {
    /// Steady light and free-running exposure, on every exit: a scan that
    /// matched, a confirm that refused early or a look that erred can no
    /// longer leave the pattern running.
    fn drop(&mut self) {
        if let Some(i) = &self.cap.illuminator {
            let _ = i.set(true);
        }
        self.cap.freeze_exposure(false);
    }
}

/// Which pairs the gate offers, on a synthetic lit/unlit sequence: only
/// the ones that follow the mask, and none across a dropped frame (H7,
/// J8). The camera is stood in for by the phase tracker the gate drives.
#[cfg(test)]
mod tests {
    use super::{judged, Frames, Gate};
    use faceauth_engine::liveness::{FlashResponse, StrobePhase};
    use faceauth_engine::Grey;

    /// The brightness sequence a mask produces from bit `start`.
    fn feed(mask: u8, phase: &mut StrobePhase, start: u32, n: usize) -> Vec<bool> {
        (0..n)
            .map(|i| {
                let bit = (mask.rotate_left(start) >> (7 - (i % 8))) & 1;
                phase.push(if bit == 1 { 120.0 } else { 60.0 })
            })
            .collect()
    }

    #[test]
    fn pairs_only_follow_the_mask_and_a_gap_starts_the_lock_over() {
        let mask = 0b1011_0010u8;
        let mut phase = StrobePhase::with_pattern(mask);
        let offered = feed(mask, &mut phase, 0, 24);
        assert!(
            !offered[..8].iter().any(|p| *p),
            "nothing before eight frames have followed the mask"
        );
        let rising: Vec<usize> = (8..24)
            .filter(|&i| {
                let prev = (mask >> (7 - ((i - 1) % 8))) & 1;
                let now = (mask >> (7 - (i % 8))) & 1;
                prev == 0 && now == 1
            })
            .collect();
        for (i, offered) in offered.iter().enumerate().skip(8) {
            assert_eq!(*offered, rising.contains(&i), "frame {}", i);
        }
        // A dropped frame: the gate resets the phase, and the next pair
        // comes only after eight more frames on the mask.
        phase.reset();
        let again = feed(mask, &mut phase, 3, 20);
        assert!(
            !again[..8].iter().any(|p| *p),
            "no pair inside the new lock"
        );
        assert!(again[8..].iter().any(|p| *p), "and pairs again once locked");
        // A stream that brightens on its own schedule is never a pair.
        let mut phase = StrobePhase::with_pattern(mask);
        let stray = feed(0b1010_1010, &mut phase, 0, 32);
        assert!(!stray.iter().any(|p| *p));
    }

    /// A pair a live face gives: flash on the face, a dark surround, skin's
    /// reflectance, nothing clipped.
    fn live_pair() -> FlashResponse {
        FlashResponse {
            face_flash: 30.0,
            ring_flash: 3.0,
            surround: 0.1,
            reflectance: 0.28,
            face_px: 87.0,
            clipped: 0.0,
        }
    }

    /// J19: a pair is judged only when the sensor reads back the exposure
    /// and gain the daemon wrote and measures it with. Read back otherwise,
    /// the pair is refused, whether the settings moved under the gate or a
    /// writer changed them before it began (the read-back then steady, but
    /// not the daemon's); read back not at all, it is never passed.
    #[test]
    fn a_pair_passes_only_under_the_settings_the_gate_began_with() {
        let fr = live_pair();
        let written = (360, 16);
        assert!(matches!(
            judged(fr, written, Ok((360, 16))),
            Gate::Pass(Some(_))
        ));
        for moved in [(300, 16), (360, 32), (0, 0)] {
            match judged(fr, written, Ok(moved)) {
                Gate::Denied(why, _) => assert!(why.contains("exposure changed"), "{}", why),
                other => panic!("{:?}: {:?}", moved, other),
            }
        }
        // Changed before the spell began: every pair reads the same, and
        // every pair is refused.
        for _ in 0..3 {
            assert!(matches!(
                judged(fr, written, Ok((720, 16))),
                Gate::Denied(..)
            ));
        }
        assert!(matches!(
            judged(fr, written, Err(anyhow::anyhow!("G_CTRL failed"))),
            Gate::NoSignal(_)
        ));
        // Held settings do not soften the gate's own verdict.
        let print = FlashResponse {
            reflectance: 1.7,
            ..live_pair()
        };
        assert!(matches!(
            judged(print, written, Ok((360, 16))),
            Gate::Denied(..)
        ));
    }

    /// A frame whose every pixel is `v`, read into `buf` the way the
    /// capture writes a frame in place.
    fn read(buf: &mut Grey, v: u8) {
        buf.width = 4;
        buf.height = 2;
        buf.data.resize(8, 0);
        buf.data.fill(v);
    }

    /// C7: the gate's two buffers trade places on every frame that is not
    /// a pair, so none is allocated or copied; a pair is the frame just
    /// read with the one right before it, and never a frame from before a
    /// dropped one.
    #[test]
    fn frames_trade_buffers_and_pair_only_with_the_frame_before() {
        let mut f = Frames::default();
        read(&mut f.cur, 1);
        assert!(!f.gap(10));
        assert!(
            f.settle(true).is_none(),
            "the first frame has no predecessor"
        );
        read(&mut f.cur, 2);
        assert!(!f.gap(11));
        assert!(f.settle(false).is_none());
        // Two buffers now; from here a frame that is not a pair only swaps.
        let buffers = [f.cur.data.as_ptr(), f.prev.as_ref().unwrap().data.as_ptr()];
        for (v, seq) in (3u8..9).zip(12u32..) {
            read(&mut f.cur, v);
            assert!(
                buffers.contains(&f.cur.data.as_ptr()),
                "a new buffer at {}",
                v
            );
            assert!(!f.gap(seq));
            assert!(f.settle(false).is_none());
            // Kept as the predecessor by moving it, not by a copy: a copy
            // would be a third buffer.
            let kept = f.prev.as_ref().unwrap();
            assert!(buffers.contains(&kept.data.as_ptr()), "a copy at {}", v);
            assert_eq!(kept.data[0], v);
        }
        read(&mut f.cur, 9);
        assert!(!f.gap(18));
        let (lit, unlit) = f.settle(true).expect("a pair");
        assert_eq!((lit.data[0], unlit.data[0]), (9, 8));
        // The frame after a pair's lit frame pairs with nothing before it.
        read(&mut f.cur, 10);
        assert!(!f.gap(19));
        assert!(f.settle(true).is_none());
        // A dropped frame: the frame before the gap is no predecessor.
        read(&mut f.cur, 11);
        assert!(f.gap(21));
        assert!(f.settle(true).is_none());
        read(&mut f.cur, 12);
        assert!(!f.gap(22));
        let (lit, unlit) = f.settle(true).expect("a pair after the gap");
        assert_eq!((lit.data[0], unlit.data[0]), (12, 11));
        // A new mask or a new focus: the next frame pairs with nothing.
        read(&mut f.cur, 13);
        assert!(!f.gap(23));
        assert!(f.settle(false).is_none());
        f.forget();
        read(&mut f.cur, 14);
        assert!(!f.gap(30), "no sequence to compare after forgetting");
        assert!(f.settle(true).is_none());
        // A frame that is no pair is handed back as the one just read,
        // gated and ungated (A6).
        assert_eq!(f.unpaired().data[0], 14);
        let mut ungated = Frames::default();
        read(&mut ungated.cur, 7);
        assert_eq!(ungated.unpaired().data[0], 7);
    }
}

/// C11: the reviews' simulations of an attempt's second phase, on the
/// real phase tracker and `off_mask`: what the off-mask flag says, which
/// the attempt logs and never charges. Frame noise alone, at a faint flash
/// contrast or on a stream that drops frames, does not raise it; a stream
/// looping a fixed pattern of its own at a clear contrast does; and so
/// does a live face under a lamp flickering with the mains, which is why
/// the flag is not charged. Frame counts are at 30 a second: a lock-screen
/// attempt's 4.8 s and a consent scan's 20 s.
#[cfg(test)]
mod off_mask_simulation {
    use super::off_mask;
    use faceauth_engine::liveness::StrobePhase;

    const FRAMES: [usize; 2] = [144, 560];

    /// xorshift64 with Box-Muller: the same runs on every machine.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        /// Uniform in (0, 1).
        fn unit(&mut self) -> f64 {
            ((self.next() >> 11) as f64 + 0.5) / (1u64 << 53) as f64
        }

        /// Normal, mean 0, deviation 1.
        fn normal(&mut self) -> f64 {
            let (a, b) = (self.unit(), self.unit());
            (-2.0 * a.ln()).sqrt() * (std::f64::consts::TAU * b).cos()
        }
    }

    /// Every mask the gate can draw.
    fn masks() -> Vec<u8> {
        (0u16..256)
            .map(|b| b as u8)
            .filter(|b| b.count_ones() == 4 && *b != 0xaa && *b != 0x55)
            .collect()
    }

    /// A scene for one second phase: the lit frames' brightness over the
    /// unlit ones', the frame-to-frame jitter, a dropped frame every so
    /// many (0: never), and the room's own light swinging by `flicker` of
    /// itself every three frames (a lamp on the mains beating with the
    /// frame rate).
    #[derive(Clone, Copy, Debug)]
    struct Scene {
        frames: usize,
        contrast: f64,
        noise: f64,
        drop_every: usize,
        flicker: f64,
    }

    /// One second phase under the drawn mask, on a stream lighting frames
    /// per `lit` from a random rotation, in `scene`; the gate answers each
    /// dropped frame with a reset. Flagged off the mask?
    fn flagged(drawn: u8, lit: u8, scene: Scene, rng: &mut Rng) -> bool {
        let mut phase = StrobePhase::with_pattern(drawn);
        let mut k = rng.next() % 8;
        let beat = std::f64::consts::TAU * rng.unit();
        let mut backwards = false;
        for i in 0..scene.frames {
            if scene.drop_every > 0 && i > 0 && i % scene.drop_every == 0 {
                phase.reset();
                k += 1 + rng.next() % 2;
            }
            let on = lit.rotate_left((k % 8) as u32) >> 7 == 1;
            let room = 100.0
                * (1.0 + scene.flicker * (std::f64::consts::TAU * i as f64 / 3.0 + beat).cos());
            let level = if on {
                room + 100.0 * (scene.contrast - 1.0)
            } else {
                room
            };
            phase.push(level * (1.0 + scene.noise * rng.normal()));
            backwards |= phase.backwards();
            k += 1;
        }
        off_mask(&phase, backwards)
    }

    /// Run `cells` on every core, each from its own seed: how many of each
    /// cell's runs were flagged, and of how many.
    fn tally<C: Sync>(
        cells: &[C],
        run: impl Fn(&C, &mut Rng) -> (usize, usize) + Sync,
    ) -> Vec<(usize, usize)> {
        let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
        let run = &run;
        std::thread::scope(|s| {
            let parts: Vec<_> = (0..threads)
                .map(|t| {
                    s.spawn(move || {
                        (t..cells.len())
                            .step_by(threads)
                            .map(|i| {
                                let mut rng = Rng(0x9e37_79b9_7f4a_7c15 ^ (i as u64 + 1) << 20);
                                (i, run(&cells[i], &mut rng))
                            })
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            let mut out = vec![(0, 0); cells.len()];
            for p in parts {
                for (i, r) in p.join().unwrap() {
                    out[i] = r;
                }
            }
            out
        })
    }

    /// A live face under the strobe, `per_mask` runs for every mask.
    fn live(scene: &Scene, per_mask: usize, rng: &mut Rng) -> (usize, usize) {
        let masks = masks();
        let mut n = 0;
        for &m in &masks {
            for _ in 0..per_mask {
                n += flagged(m, m, *scene, rng) as usize;
            }
        }
        (n, masks.len() * per_mask)
    }

    /// A live face in a steady room: its frames light per the drawn mask,
    /// at a flash contrast from barely under `LIT_STEP` to clear, with 1
    /// to 3 percent noise and frames dropped as often as every third. No
    /// condition flags more than one run in a thousand (each is 1020 runs:
    /// every mask, fifteen times).
    #[test]
    fn a_live_face_at_a_faint_flash_or_dropping_frames_is_not_flagged() {
        let mut cells = Vec::new();
        for frames in FRAMES {
            for noise in [0.01, 0.02, 0.03] {
                for drop_every in [0, 3, 7] {
                    for contrast in [1.05, 1.10, 1.12, 1.13, 1.15, 1.18, 1.20, 1.30] {
                        cells.push(Scene {
                            frames,
                            contrast,
                            noise,
                            drop_every,
                            flicker: 0.0,
                        });
                    }
                }
            }
        }
        let counts = tally(&cells, |scene, rng| live(scene, 15, rng));
        for (scene, &(n, runs)) in cells.iter().zip(&counts) {
            assert!(
                n * 1000 <= runs,
                "{:?}: {} of {} live runs flagged",
                scene,
                n,
                runs
            );
        }
    }

    /// A lamp on the mains that gives off infrared (a bulb or a halogen)
    /// swings the room's light with a three-frame beat: spurious steps keep
    /// the frames from ever following the mask, while the flash's own steps
    /// at the swing's top are hard. Measured here at 1 percent noise, a
    /// live face is flagged in a tenth of runs or more at some contrast,
    /// which is why the flag is logged and never charged (C11). The
    /// exposure smooths the swing in a dim room; this is the bright room.
    #[test]
    fn a_lamp_flickering_with_the_mains_flags_a_live_face() {
        let mut cells = Vec::new();
        for flicker in [0.05, 0.10, 0.20] {
            for contrast in [1.15, 1.20, 1.30, 1.50] {
                cells.push(Scene {
                    frames: 144,
                    contrast,
                    noise: 0.01,
                    drop_every: 0,
                    flicker,
                });
            }
        }
        let counts = tally(&cells, |scene, rng| live(scene, 15, rng));
        let mut worst = 0.0f64;
        for (scene, &(n, runs)) in cells.iter().zip(&counts) {
            println!(
                "flicker {} contrast {}: {} of {} live runs flagged",
                scene.flicker, scene.contrast, n, runs
            );
            worst = worst.max(n as f64 / runs as f64);
        }
        assert!(
            worst >= 0.10,
            "a flickering lamp flagged at most {:.1}% of live runs",
            100.0 * worst
        );
    }

    /// A replay looping a fixed pattern that is neither a rotation of the
    /// drawn mask nor of its mirror (which would follow it, forwards or
    /// backwards), stepping at 1.3 or more with up to 3 percent noise and
    /// no dropped frames: flagged in 95 runs of 100 or more at every
    /// contrast, noise and length. With frames dropped often the runs
    /// between gaps are too short to flag, which is one more reason the
    /// flag is only logged.
    #[test]
    fn a_stream_looping_its_own_pattern_at_a_clear_contrast_is_flagged() {
        let masks = masks();
        let canned = [
            0xaa,
            0b1100_1100,
            0b1111_0000,
            0b1011_0100,
            0b1110_0010,
            0b1001_0110,
        ];
        let rotation = |a: u8, b: u8| (0..8).any(|r| a.rotate_left(r) == b);
        let mut cells = Vec::new();
        for frames in FRAMES {
            for noise in [0.0, 0.01, 0.03] {
                for contrast in [1.3, 1.5, 2.0] {
                    cells.push(Scene {
                        frames,
                        contrast,
                        noise,
                        drop_every: 0,
                        flicker: 0.0,
                    });
                }
            }
        }
        let counts = tally(&cells, |scene, rng| {
            let (mut n, mut runs) = (0, 0);
            for &drawn in &masks {
                for &c in &canned {
                    if rotation(drawn, c) || rotation(drawn.reverse_bits(), c) {
                        continue;
                    }
                    runs += 1;
                    n += flagged(drawn, c, *scene, rng) as usize;
                }
            }
            (n, runs)
        });
        for (scene, &(n, runs)) in cells.iter().zip(&counts) {
            assert!(
                n * 100 >= runs * 95,
                "{:?}: only {} of {} replays flagged",
                scene,
                n,
                runs
            );
        }
    }
}
