//! Image comparison for the presence watch: how alike one region of two
//! frames is, by zero-mean normalised cross-correlation, so the walk-away
//! lock can tell a person who left (the torso below the face box no longer
//! correlates with the one they filled) from a hand over the face. The
//! per-frame image-motion measure that the gesture detectors once read
//! lived here too; the gestures are read from the face mesh's angles now
//! (round-4 C3) and that measure went with its detectors.

use crate::Grey;

/// A pixel rectangle, half-open.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    pub x0: usize,
    pub y0: usize,
    pub x1: usize,
    pub y1: usize,
}

/// The region under a face box: shoulders and torso, from the box's bottom
/// edge down two box heights, three box widths wide, clamped to the frame.
/// What a person leaves behind when they stand up, and what a hand over
/// the face leaves alone.
pub fn below(bbox: [f32; 4], width: usize, height: usize) -> Region {
    let [x, y, w, h] = bbox;
    let x0 = (x - w).max(0.0) as usize;
    let x1 = ((x + 2.0 * w) as usize).min(width);
    let y0 = ((y + h) as usize).min(height.saturating_sub(1));
    let y1 = ((y + 3.0 * h) as usize).min(height);
    Region {
        x0,
        y0,
        x1: x1.max(x0 + 1),
        y1: y1.max(y0 + 1),
    }
}

/// How alike two frames are inside `r`: zero-mean normalised
/// cross-correlation of the region sampled every fourth pixel, so brightness
/// and exposure changes cancel and only the pattern counts. 1.0 is the same
/// scene, about 0 is unrelated, and a person who has left leaves a region
/// that no longer correlates with the one they filled.
pub fn similarity(a: &Grey, b: &Grey, r: Region) -> f32 {
    if a.width != b.width || a.height != b.height {
        return 0.0;
    }
    let mut va = Vec::new();
    let mut vb = Vec::new();
    let mut y = r.y0;
    while y < r.y1 {
        let mut x = r.x0;
        while x < r.x1 {
            let i = y * a.width + x;
            va.push(a.data[i] as f32);
            vb.push(b.data[i] as f32);
            x += 4;
        }
        y += 4;
    }
    if va.len() < 16 {
        return 0.0;
    }
    normalise(&mut va);
    normalise(&mut vb);
    va.iter().zip(&vb).map(|(p, q)| p * q).sum::<f32>() / va.len() as f32
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

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(width: usize, height: usize, f: impl Fn(usize, usize) -> u8) -> Grey {
        let mut data = vec![0u8; width * height];
        for y in 0..height {
            for x in 0..width {
                data[y * width + x] = f(x, y);
            }
        }
        Grey {
            width,
            height,
            data,
        }
    }

    #[test]
    fn the_same_scene_scores_one_whatever_the_exposure() {
        let a = frame(160, 120, |x, y| ((x * 7 + y * 3) % 200) as u8);
        let b = frame(160, 120, |x, y| (((x * 7 + y * 3) % 200) / 2 + 20) as u8);
        let r = below([60.0, 10.0, 40.0, 30.0], 160, 120);
        assert!(similarity(&a, &a, r) > 0.999);
        assert!(
            similarity(&a, &b, r) > 0.99,
            "half the brightness is the same scene"
        );
    }

    #[test]
    fn a_person_who_left_leaves_an_unrelated_region() {
        // A textured torso below the face, then a flat wall with noise.
        let with = frame(160, 120, |x, y| {
            if y > 40 {
                ((x * 13 + y * 5) % 180) as u8
            } else {
                30
            }
        });
        let without = frame(160, 120, |x, y| (80 + ((x * 31 + y * 17) % 7)) as u8);
        let r = below([60.0, 10.0, 40.0, 30.0], 160, 120);
        assert!(similarity(&with, &without, r) < 0.3);
    }

    #[test]
    fn below_is_under_the_box_and_clamped() {
        let r = below([60.0, 10.0, 40.0, 30.0], 160, 120);
        assert_eq!((r.x0, r.x1, r.y0, r.y1), (20, 140, 40, 100));
        let r = below([150.0, 100.0, 40.0, 30.0], 160, 120);
        assert!(r.x1 <= 160 && r.y1 <= 120 && r.x1 > r.x0 && r.y1 > r.y0);
    }
}
