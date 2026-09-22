//! Real image motion of the face between two frames: how far its pixels
//! shifted, vertically and horizontally, found by cross-correlating the row
//! and column brightness profiles of one region in both frames.
//!
//! This is the signal the gestures are read from, because it cannot be faked
//! by the face detector: a fit that flips between two landmark solutions
//! changes no pixels and measures zero here, while a nod carries the whole
//! face down and up by a tenth of its width (measured on the reference
//! machine: 9 to 16 px on an 88 px face) and a shake slides it sideways.
//! Talking moves the mouth only, which a whole-region profile barely sees.
//! Profiles are zero-mean, unit-variance, so the exposure loop's brightness
//! changes between frames do not register as motion.

use crate::Grey;

/// A pixel rectangle, half-open.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    pub x0: usize,
    pub y0: usize,
    pub x1: usize,
    pub y1: usize,
}

impl Region {
    /// The face box grown by `margin` on each side, clamped to the frame.
    pub fn around(bbox: [f32; 4], margin: f32, width: usize, height: usize) -> Region {
        let [x, y, w, h] = bbox;
        let (mx, my) = (w * margin, h * margin);
        let x0 = (x - mx).max(0.0) as usize;
        let y0 = (y - my).max(0.0) as usize;
        let x1 = ((x + w + mx) as usize).min(width);
        let y1 = ((y + h + my) as usize).min(height);
        Region { x0, y0, x1: x1.max(x0 + 1), y1: y1.max(y0 + 1) }
    }
}

fn normalise(v: &mut [f32]) {
    let n = v.len().max(1) as f32;
    let mean = v.iter().sum::<f32>() / n;
    let var = v.iter().map(|x| (x - mean) * (x - mean)).sum::<f32>() / n;
    let sd = var.sqrt().max(1e-6);
    for x in v.iter_mut() {
        *x = (*x - mean) / sd;
    }
}

/// First differences: what is left of a profile once its smooth shape is
/// gone. The illuminator's falloff (bright centre, dark edges) is a large
/// smooth component fixed to the image, not to the face; correlating raw
/// profiles pins the shift at zero on it. Edges move with the face.
fn gradient(v: &[f32]) -> Vec<f32> {
    v.windows(2).map(|w| w[1] - w[0]).collect()
}

/// Row and column brightness profiles of `r` in `img`, as normalised gradients.
fn profiles(img: &Grey, r: Region) -> (Vec<f32>, Vec<f32>) {
    let mut rows = vec![0f32; r.y1 - r.y0];
    let mut cols = vec![0f32; r.x1 - r.x0];
    for y in r.y0..r.y1 {
        let line = &img.data[y * img.width + r.x0..y * img.width + r.x1];
        let mut s = 0u32;
        for (i, &px) in line.iter().enumerate() {
            s += px as u32;
            cols[i] += px as f32;
        }
        rows[y - r.y0] = s as f32;
    }
    let mut rows = gradient(&rows);
    let mut cols = gradient(&cols);
    normalise(&mut rows);
    normalise(&mut cols);
    (rows, cols)
}

/// The shift `s` (within +-max) that best aligns `b` to `a`: positive when
/// the content of `a` appears further along in `b`. Sub-pixel by a parabola
/// through the peak; the score is the mean product over the overlap.
fn best_shift(a: &[f32], b: &[f32], max: isize) -> f32 {
    let n = a.len() as isize;
    if n < 8 {
        return 0.0;
    }
    let max = max.min(n / 3);
    let score = |s: isize| -> f32 {
        let mut sum = 0f32;
        let mut cnt = 0usize;
        for i in 0..n {
            let j = i + s;
            if j >= 0 && j < n {
                sum += a[i as usize] * b[j as usize];
                cnt += 1;
            }
        }
        if cnt == 0 { -1.0 } else { sum / cnt as f32 }
    };
    let scores: Vec<f32> = (-max..=max).map(score).collect();
    let (mut bi, mut bs) = (0usize, f32::MIN);
    for (i, &s) in scores.iter().enumerate() {
        if s > bs {
            bs = s;
            bi = i;
        }
    }
    // A peak at the search edge or a weak one is not a measurement: the
    // first frames of a round, before exposure settles, produced +-17 px
    // spikes this way on a still face (recorded). Report no motion instead.
    if bi == 0 || bi + 1 >= scores.len() || bs < 0.3 {
        return 0.0;
    }
    let mut shift = bi as f32 - max as f32;
    if bi > 0 && bi + 1 < scores.len() {
        let (l, c, r) = (scores[bi - 1], scores[bi], scores[bi + 1]);
        let denom = l - 2.0 * c + r;
        if denom.abs() > 1e-6 {
            let d = 0.5 * (l - r) / denom;
            if d.abs() <= 1.0 {
                shift += d;
            }
        }
    }
    shift
}

/// How far the content of region `r` moved from `prev` to `cur`, in pixels:
/// (dx, dy), positive right and down.
pub fn shift(prev: &Grey, cur: &Grey, r: Region, max_shift: usize) -> (f32, f32) {
    if prev.width != cur.width || prev.height != cur.height {
        return (0.0, 0.0);
    }
    let (pr, pc) = profiles(prev, r);
    let (cr, cc) = profiles(cur, r);
    let m = max_shift as isize;
    (best_shift(&pc, &cc, m), best_shift(&pr, &cr, m))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scene(w: usize, h: usize, ox: usize, oy: usize) -> Grey {
        // A bright blob with texture, drawn at an offset.
        let mut g = Grey::new(w, h);
        for y in 0..h {
            for x in 0..w {
                let (dx, dy) = (x as f32 - (ox as f32 + 30.0), y as f32 - (oy as f32 + 30.0));
                let d = (dx * dx + dy * dy).sqrt();
                let v = if d < 20.0 { 200.0 - d * 4.0 + ((x * 7 + y * 3) % 11) as f32 } else { 40.0 + ((x * 5 + y * 13) % 7) as f32 };
                g.data[y * w + x] = v as u8;
            }
        }
        g
    }

    #[test]
    fn recovers_a_known_shift() {
        let a = scene(120, 120, 20, 20);
        let b = scene(120, 120, 23, 27);
        let r = Region { x0: 0, y0: 0, x1: 120, y1: 120 };
        let (dx, dy) = shift(&a, &b, r, 20);
        assert!((dx - 3.0).abs() < 0.6, "dx {}", dx);
        assert!((dy - 7.0).abs() < 0.6, "dy {}", dy);
    }

    /// A bright vignette fixed to the image with the face moving through it:
    /// the IR illuminator's falloff. Raw profiles lock onto the vignette and
    /// report no motion; gradients follow the face.
    #[test]
    fn a_fixed_vignette_does_not_hide_the_motion() {
        let vignette = |g: &mut Grey| {
            let (w, h) = (g.width as f32, g.height as f32);
            for y in 0..g.height {
                for x in 0..g.width {
                    let (dx, dy) = ((x as f32 - w / 2.0) / (w / 2.0), (y as f32 - h / 2.0) / (h / 2.0));
                    let gain = (1.0 - 0.8 * (dx * dx + dy * dy)).max(0.1);
                    let i = y * g.width + x;
                    g.data[i] = (g.data[i] as f32 * gain) as u8;
                }
            }
        };
        let mut a = scene(120, 120, 25, 20);
        let mut b = scene(120, 120, 25, 30);
        vignette(&mut a);
        vignette(&mut b);
        let r = Region { x0: 0, y0: 0, x1: 120, y1: 120 };
        let (dx, dy) = shift(&a, &b, r, 24);
        assert!(dx.abs() < 1.0, "dx {}", dx);
        assert!((dy - 10.0).abs() < 1.0, "dy {}", dy);
    }

    #[test]
    fn brightness_change_is_not_motion() {
        let a = scene(120, 120, 20, 20);
        let mut b = a.clone();
        for v in b.data.iter_mut() {
            *v = (*v as f32 * 0.7) as u8;
        }
        let r = Region { x0: 10, y0: 10, x1: 110, y1: 110 };
        let (dx, dy) = shift(&a, &b, r, 20);
        assert!(dx.abs() < 0.3 && dy.abs() < 0.3, "{} {}", dx, dy);
    }
}
