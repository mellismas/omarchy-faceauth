//! Presentation-attack gate built on the illuminator's flash response.
//!
//! Deny-only: it can refuse a frame pair, never accept one on its own. Two
//! physical measurements on `lit - unlit` (the strobe alternating every frame):
//!
//! - **Reflectance.** Paper and card reflect near-infrared several times more
//!   than skin. The face's flash response per unit exposure, normalised for
//!   distance through the face width (flash goes as 1/d^2, width as 1/d), is an
//!   albedo estimate: measured 0.28 for a face and 1.7 for a plain-paper print.
//! - **Surround.** A print's surround is at the print's distance and lights up
//!   with the face; a real head's surround is the room behind it, several times
//!   farther, and the inverse-square falloff leaves it dark. The ring is taken
//!   beside and above the head only; below the chin are the shoulders, as close
//!   as the face. First measurements with the full ring: 0.31 to 0.36 for a face
//!   and 0.44 to 0.54 for a print; re-measured with the trimmed ring in the pack.
//!
//! Thresholds are published constants set from the first measurements with
//! margin; re-measure before changing them and record the runs.

use crate::image::Grey;
use crate::Face;

/// Face width the reflectance was calibrated at, in pixels of the oriented frame.
pub const REFERENCE_FACE_PX: f32 = 87.0;
/// Normalised reflectance above this is not skin (face 0.28, print 1.66).
pub const REFLECTANCE_DENY: f32 = 0.80;
/// Surround-to-face flash ratio above this means the surround is at the face's distance.
pub const SURROUND_DENY: f32 = 0.42;
/// Below this flash response the pair carries no usable signal (LEDs off, or too far).
pub const MIN_FACE_FLASH: f32 = 4.0;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FlashResponse {
    /// Mean lit-minus-unlit over the inner 70% of the face box.
    pub face_flash: f32,
    /// Mean lit-minus-unlit over the ring 1.4x..2.0x the face box.
    pub ring_flash: f32,
    /// ring / face.
    pub surround: f32,
    /// face_flash / (exposure * gain/16), distance-normalised to REFERENCE_FACE_PX.
    pub reflectance: f32,
    pub face_px: f32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing in the flash response rules the pair out.
    Pass,
    /// Too little flash signal to judge (treated as a failed attempt, not an attack).
    NoSignal,
    /// Reflectance says paper or card.
    DenyReflectance,
    /// The surround lit up with the face: a flat object at one distance.
    DenySurround,
}

impl FlashResponse {
    /// `lit` and `unlit` are consecutive frames of the same size in the oriented
    /// orientation; `face` was detected on `lit`; `exposure` and `gain` are the
    /// sensor settings both frames were taken at (gain in the ov7251 scale, 16 = 1x).
    pub fn measure(lit: &Grey, unlit: &Grey, face: &Face, exposure: i64, gain: i64) -> FlashResponse {
        let (fw, fh) = (lit.width as i32, lit.height as i32);
        let flash_at = |x: i32, y: i32| -> f32 {
            if x < 0 || y < 0 || x >= fw || y >= fh {
                return 0.0;
            }
            let i = y as usize * lit.width + x as usize;
            (lit.data[i] as f32 - unlit.data[i] as f32).max(0.0)
        };
        let [bx, by, bw, bh] = face.bbox;
        let (cx, cy) = (bx + bw / 2.0, by + bh / 2.0);
        // Region between `lo` and `hi` times the box, optionally only the part
        // beside and above the face (below the chin are the shoulders, which are
        // as close as the face and lit like it).
        let mean_region = |lo: f32, hi: f32, above_chin_only: bool| -> f32 {
            let (rx_lo, ry_lo, rx_hi, ry_hi) = (bw * lo / 2.0, bh * lo / 2.0, bw * hi / 2.0, bh * hi / 2.0);
            let (x0, x1) = ((cx - rx_hi).max(0.0) as i32, (cx + rx_hi).min(fw as f32 - 1.0) as i32);
            let (y0, y1) = ((cy - ry_hi).max(0.0) as i32, (cy + ry_hi).min(fh as f32 - 1.0) as i32);
            let chin = cy + bh * 0.35;
            let (mut s, mut n) = (0f32, 0usize);
            let mut y = y0;
            while y <= y1 {
                if !(above_chin_only && y as f32 > chin) {
                    let mut x = x0;
                    while x <= x1 {
                        let inside = ((x as f32 - cx).abs() < rx_lo) && ((y as f32 - cy).abs() < ry_lo);
                        if !inside {
                            s += flash_at(x, y);
                            n += 1;
                        }
                        x += 2;
                    }
                }
                y += 2;
            }
            if n == 0 {
                0.0
            } else {
                s / n as f32
            }
        };
        let face_flash = mean_region(0.0, 0.7, false);
        let ring_flash = mean_region(1.4, 2.0, true);
        let surround = if face_flash > 0.0 { ring_flash / face_flash } else { f32::INFINITY };
        let denom = (exposure.max(1) as f32) * (gain.max(1) as f32 / 16.0);
        let raw = face_flash / denom;
        let scale = if bw > 1.0 { (REFERENCE_FACE_PX / bw).powi(2) } else { 1.0 };
        FlashResponse { face_flash, ring_flash, surround, reflectance: raw * scale, face_px: bw }
    }

    pub fn verdict(&self) -> Verdict {
        if self.face_flash < MIN_FACE_FLASH {
            Verdict::NoSignal
        } else if self.reflectance > REFLECTANCE_DENY {
            Verdict::DenyReflectance
        } else if self.surround > SURROUND_DENY {
            Verdict::DenySurround
        } else {
            Verdict::Pass
        }
    }
}

/// The illuminator's frame pattern for one gate, and the check that the
/// frames the camera delivers follow it.
///
/// The sensor lights frames per an 8-frame bitmask. A fixed mask (the
/// alternating 0xaa the gate first used) is one a prerecorded stream can
/// carry: any clip with a 15 percent brightness step every other frame
/// reads as strobed. So each gate draws a fresh mask with four lit and four
/// unlit frames, never plain alternation, and only scores a lit/unlit pair
/// once the last eight frames' brightness has followed a rotation of that
/// mask. A stream that brightens on its own schedule is "no signal", not a
/// pass. A device that honours the control but replays a face is not
/// caught by this (see the README's "Not defended" list); the check makes
/// a canned stream fail, no more.
#[derive(Clone, Debug)]
pub struct StrobePhase {
    pattern: u8,
    /// Brightness class of the frames seen so far, newest last: true is lit.
    bits: Vec<bool>,
    last_mean: Option<f64>,
}

/// A lit frame is at least this much brighter than the frame before it (the
/// same margin every gate path used before the phase check existed).
pub const LIT_STEP: f64 = 1.15;
/// The fall-back mask when the OS gives no randomness: plain alternation,
/// which the phase check still enforces.
pub const ALTERNATING: u8 = 0xaa;

impl StrobePhase {
    /// A fresh random mask: four lit, four unlit, not plain alternation.
    pub fn random() -> Self {
        Self::with_pattern(random_pattern().unwrap_or(ALTERNATING))
    }

    pub fn with_pattern(pattern: u8) -> Self {
        StrobePhase { pattern, bits: Vec::new(), last_mean: None }
    }

    /// The mask to write to `strobe_frame_pattern`.
    pub fn pattern(&self) -> u8 {
        self.pattern
    }

    /// Record one frame's mean brightness. Returns true when this frame is a
    /// lit frame after an unlit one, and the eight frames ending here follow
    /// the mask: the pair is worth measuring. A frame that is neither a clear
    /// step up nor a clear step down keeps the class of the one before it.
    pub fn push(&mut self, mean: f64) -> bool {
        let lit = match self.last_mean {
            None => false,
            Some(p) if mean >= p * LIT_STEP => true,
            Some(p) if mean * LIT_STEP <= p => false,
            Some(_) => self.bits.last().copied().unwrap_or(false),
        };
        let rising = matches!(self.bits.last(), Some(false)) && lit;
        self.last_mean = Some(mean);
        self.bits.push(lit);
        if self.bits.len() > 16 {
            self.bits.remove(0);
        }
        rising && self.in_phase()
    }

    /// Do the last eight frames follow some rotation of the mask?
    pub fn in_phase(&self) -> bool {
        if self.bits.len() < 8 {
            return false;
        }
        let tail = &self.bits[self.bits.len() - 8..];
        let observed = tail.iter().fold(0u8, |acc, &b| (acc << 1) | b as u8);
        (0..8).any(|r| self.pattern.rotate_left(r) == observed)
    }
}

/// A mask with four lit and four unlit frames that is not 0xaa or 0x55,
/// from the OS randomness; None when that cannot be read.
fn random_pattern() -> Option<u8> {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").ok()?;
    let mut b = [0u8; 1];
    for _ in 0..64 {
        f.read_exact(&mut b).ok()?;
        if b[0].count_ones() == 4 && b[0] != 0xaa && b[0] != 0x55 {
            return Some(b[0]);
        }
    }
    None
}

#[cfg(test)]
mod phase_tests {
    use super::*;

    /// Feed a phase tracker the brightness sequence a mask produces, from
    /// bit `start`, and return which frames it offered as pairs.
    fn run(mask: u8, phase: &mut StrobePhase, start: u32, n: usize) -> Vec<bool> {
        (0..n).map(|i| {
            let bit = (mask.rotate_left(start) >> (7 - (i % 8))) & 1;
            phase.push(if bit == 1 { 120.0 } else { 60.0 })
        }).collect()
    }

    #[test]
    fn a_random_mask_is_balanced_and_never_plain_alternation() {
        for _ in 0..50 {
            let p = StrobePhase::random().pattern();
            assert_eq!(p.count_ones(), 4, "{:#04x}", p);
            assert!(p != 0xaa && p != 0x55, "{:#04x}", p);
        }
    }

    #[test]
    fn pairs_count_only_once_the_frames_follow_the_mask() {
        let mask = 0b1011_0100u8;
        let mut phase = StrobePhase::with_pattern(mask);
        let offered = run(mask, &mut phase, 3, 24);
        assert!(offered[..7].iter().all(|o| !o), "nothing before eight frames: {:?}", offered);
        assert!(offered[8..].iter().any(|o| *o), "rising edges in phase are offered: {:?}", offered);
        // Every offer is a lit frame after an unlit one.
        for (i, o) in offered.iter().enumerate() {
            if *o {
                let at = |k: usize| (mask.rotate_left(3) >> (7 - (k % 8))) & 1;
                assert_eq!((at(i - 1), at(i)), (0, 1), "frame {}", i);
            }
        }
    }

    #[test]
    fn a_stream_that_alternates_on_its_own_is_never_in_phase() {
        let mask = 0b1011_0100u8;
        let mut phase = StrobePhase::with_pattern(mask);
        let offered = run(0xaa, &mut phase, 0, 40);
        assert!(offered.iter().all(|o| !o), "a canned alternation must not read as strobed: {:?}", offered);
        let mut phase = StrobePhase::with_pattern(mask);
        let offered = run(0b1100_0011, &mut phase, 0, 40);
        assert!(offered.iter().all(|o| !o), "a stream under another mask must not read as strobed");
    }

    #[test]
    fn a_steady_stream_is_no_signal() {
        let mut phase = StrobePhase::with_pattern(0b1011_0100);
        assert!((0..30).all(|_| !phase.push(90.0)));
        assert!(!phase.in_phase());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn face(x: f32, y: f32, w: f32, h: f32) -> Face {
        Face { bbox: [x, y, w, h], score: 0.9, landmarks: [[0.0; 2]; 5], embedding: None }
    }

    /// A lit frame with a bright disc for the head and a dark surround; unlit black.
    fn head_only(size: usize, level: u8) -> (Grey, Grey) {
        let mut lit = Grey::new(size, size);
        let c = size as f32 / 2.0;
        for y in 0..size {
            for x in 0..size {
                let d = ((x as f32 - c).powi(2) + (y as f32 - c).powi(2)).sqrt();
                if d < size as f32 * 0.2 {
                    lit.data[y * size + x] = level;
                }
            }
        }
        (lit, Grey::new(size, size))
    }

    #[test]
    fn real_head_passes_and_flat_print_is_denied() {
        let (lit, unlit) = head_only(200, 80);
        let f = face(60.0, 60.0, 80.0, 80.0);
        let r = FlashResponse::measure(&lit, &unlit, &f, 267, 16);
        assert!(r.surround < 0.1, "{:?}", r);
        assert!(r.reflectance < REFLECTANCE_DENY, "{:?}", r);
        assert_eq!(r.verdict(), Verdict::Pass);

        // A print: everything at one distance lights up, and it is bright at a short exposure.
        let mut flat = Grey::new(200, 200);
        flat.data.iter_mut().for_each(|v| *v = 130);
        let p = FlashResponse::measure(&flat, &unlit, &f, 66, 16);
        assert!(p.surround > 0.9, "{:?}", p);
        assert_eq!(p.verdict(), Verdict::DenyReflectance);
        let p2 = FlashResponse::measure(&flat, &unlit, &f, 1000, 16);
        assert_eq!(p2.verdict(), Verdict::DenySurround, "{:?}", p2);
    }

    #[test]
    fn no_flash_is_no_signal_not_an_attack() {
        let (lit, _) = head_only(200, 80);
        let f = face(60.0, 60.0, 80.0, 80.0);
        let r = FlashResponse::measure(&lit, &lit, &f, 267, 16);
        assert_eq!(r.verdict(), Verdict::NoSignal);
    }

    #[test]
    fn reflectance_is_distance_normalised() {
        // Same albedo twice as far: half the face width, a quarter of the flash.
        let (lit_near, unlit) = head_only(200, 80);
        let (lit_far, _) = head_only(200, 20);
        let near = FlashResponse::measure(&lit_near, &unlit, &face(60.0, 60.0, 80.0, 80.0), 267, 16);
        let far = FlashResponse::measure(&lit_far, &unlit, &face(80.0, 80.0, 40.0, 40.0), 267, 16);
        assert!((near.reflectance - far.reflectance).abs() / near.reflectance < 0.05, "{:?} vs {:?}", near, far);
    }
}
