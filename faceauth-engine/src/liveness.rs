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
