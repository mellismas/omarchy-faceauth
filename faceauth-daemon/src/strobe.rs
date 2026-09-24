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

/// A lit frame with the unlit frame before it, or, on a camera without a
/// strobe the gate may run ungated on, every third frame alone.
pub struct Pair {
    pub lit: Grey,
    pub unlit: Option<Grey>,
    /// Frames the gate has taken so far, this one included.
    pub frame_no: usize,
}

/// What the gate says about a pair at a face.
#[derive(Debug)]
pub enum Gate {
    /// Live, or ungated: the frame may be scored.
    Pass(Option<FlashResponse>),
    /// No usable strobe signal at the face: nothing to decide on.
    NoSignal(FlashResponse),
    /// Not a live face, or the sensor's exposure moved under the gate.
    Denied(String, FlashResponse),
}

pub struct StrobeGate<'a> {
    cap: &'a mut IrCapture,
    /// None when the gate runs ungated (no strobe control, or the gate
    /// switched off in the config; the caller has decided that is allowed).
    phase: Option<StrobePhase>,
    /// The frame before this one and its sequence number: a lit frame
    /// pairs with it only when no frame was dropped between them.
    prev: Option<(Grey, u32)>,
    started: Instant,
    frames: usize,
    /// The exposure and gain the sensor reported once the spell began;
    /// a pair measured after they moved is refused (J19).
    baseline: Option<(i32, i32)>,
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
        let baseline = cap.read_back().ok();
        Ok(StrobeGate {
            cap,
            phase,
            prev: None,
            started: Instant::now(),
            frames: 0,
            baseline,
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
        self.prev = None;
        self.started = Instant::now();
        Ok(())
    }

    /// Masks drawn so far, counting the first; 0 when ungated.
    pub fn draws(&self) -> usize {
        self.phase.as_ref().map(|p| p.draws()).unwrap_or(0)
    }

    /// Is the strobe running?
    pub fn strobed(&self) -> bool {
        self.phase.is_some()
    }

    /// Frames taken so far.
    pub fn frames(&self) -> usize {
        self.frames
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
    /// of the mask (J8). Ungated, every third frame is offered alone.
    pub fn next_frame(&mut self, timeout: Duration) -> Result<Option<Pair>> {
        let Some(img) = self.cap.next(timeout)? else {
            return Ok(None);
        };
        self.frames += 1;
        let Some(phase) = self.phase.as_mut() else {
            return Ok(if self.frames.is_multiple_of(3) {
                Some(Pair {
                    lit: img,
                    unlit: None,
                    frame_no: self.frames,
                })
            } else {
                None
            });
        };
        let seq = self.cap.sequence();
        if let Some((_, prev_seq)) = self.prev {
            if seq != prev_seq.wrapping_add(1) {
                log::debug!(
                    "strobe gate: frames dropped between {} and {}; the phase lock starts over",
                    prev_seq,
                    seq
                );
                phase.reset();
                self.prev = None;
            }
        }
        // The frame mean, computed once here for the phase check.
        let in_phase = phase.push(img.mean());
        let Some((p_img, _)) = self.prev.replace((img.clone(), seq)) else {
            return Ok(None);
        };
        if self.started.elapsed() < SETTLE || !in_phase {
            return Ok(None);
        }
        Ok(Some(Pair {
            lit: img,
            unlit: Some(p_img),
            frame_no: self.frames,
        }))
    }

    /// The gate's verdict on `pair` at `face`'s box. The sensor's exposure
    /// and gain are read back with every measured pair: a change under the
    /// gate skews the lit frame against the unlit one, so the pair is
    /// refused rather than trusted as written (J19).
    pub fn judge(&self, pair: &Pair, face: &Face) -> Result<Gate> {
        let Some(unlit) = &pair.unlit else {
            return Ok(Gate::Pass(None));
        };
        let fr = FlashResponse::measure(
            &pair.lit,
            unlit,
            face,
            self.cap.exposure.exposure,
            self.cap.exposure.gain.max(16),
        );
        if let (Some(base), Ok(now)) = (self.baseline, self.cap.read_back()) {
            if now != base {
                log::warn!(
                    "strobe gate: the sensor's exposure moved under the gate ({:?} to {:?}); pair refused",
                    base,
                    now
                );
                return Ok(Gate::Denied("exposure changed under the gate".into(), fr));
            }
        }
        Ok(match fr.verdict() {
            Verdict::Pass => Gate::Pass(Some(fr)),
            Verdict::NoSignal => Gate::NoSignal(fr),
            v => Gate::Denied(format!("{:?}", v), fr),
        })
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
    use faceauth_engine::liveness::StrobePhase;

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
}
