//! Similarity alignment of a face to the ArcFace 112x112 template from five
//! landmarks (Umeyama, without reflection), as InsightFace does before embedding.

use crate::image::Grey;

/// The ArcFace reference landmarks for a 112x112 crop:
/// right eye, left eye, nose, right mouth corner, left mouth corner.
pub const ARCFACE_112: [[f32; 2]; 5] = [
    [38.2946, 51.6963],
    [73.5318, 51.5014],
    [56.0252, 71.7366],
    [41.5493, 92.3655],
    [70.7299, 92.2041],
];

/// Least-squares similarity (scale, rotation, translation) mapping `src` onto `dst`.
/// Returns the 2x3 matrix `[a -b tx; b a ty]`.
pub fn similarity(src: &[[f32; 2]; 5], dst: &[[f32; 2]; 5]) -> [[f32; 3]; 2] {
    let n = 5.0f32;
    let mean = |p: &[[f32; 2]; 5]| {
        [
            p.iter().map(|q| q[0]).sum::<f32>() / n,
            p.iter().map(|q| q[1]).sum::<f32>() / n,
        ]
    };
    let ms = mean(src);
    let md = mean(dst);
    // For a similarity with rotation matrix [a -b; b a]:
    // a = sum(sx'*dx' + sy'*dy') / sum(|s'|^2), b = sum(sx'*dy' - sy'*dx') / sum(|s'|^2)
    let (mut num_a, mut num_b, mut den) = (0f32, 0f32, 0f32);
    for (s, d) in src.iter().zip(dst) {
        let (sx, sy) = (s[0] - ms[0], s[1] - ms[1]);
        let (dx, dy) = (d[0] - md[0], d[1] - md[1]);
        num_a += sx * dx + sy * dy;
        num_b += sx * dy - sy * dx;
        den += sx * sx + sy * sy;
    }
    let (a, b) = if den > 0.0 {
        (num_a / den, num_b / den)
    } else {
        (1.0, 0.0)
    };
    let tx = md[0] - (a * ms[0] - b * ms[1]);
    let ty = md[1] - (b * ms[0] + a * ms[1]);
    [[a, -b, tx], [b, a, ty]]
}

/// Invert a 2x3 affine.
pub fn invert(m: &[[f32; 3]; 2]) -> [[f32; 3]; 2] {
    let det = m[0][0] * m[1][1] - m[0][1] * m[1][0];
    let d = if det.abs() < 1e-9 { 1.0 } else { det };
    let a = m[1][1] / d;
    let b = -m[0][1] / d;
    let c = -m[1][0] / d;
    let e = m[0][0] / d;
    [
        [a, b, -(a * m[0][2] + b * m[1][2])],
        [c, e, -(c * m[0][2] + e * m[1][2])],
    ]
}

/// The 112x112 aligned crop for a detection's five landmarks, photometrically
/// normalised: the crop's 1st..99th percentiles are stretched to 0..255 so the
/// embedding does not move with the exposure loop or the illuminator level.
pub fn align_112(img: &Grey, landmarks: &[[f32; 2]; 5]) -> Grey {
    let fwd = similarity(landmarks, &ARCFACE_112);
    let mut crop = img.warp_affine(&invert(&fwd), 112, 112);
    normalise_contrast(&mut crop, 0.01, 0.99);
    crop
}

/// Linear stretch of `[lo, hi]` percentiles to `[0, 255]`, in place.
pub fn normalise_contrast(img: &mut Grey, lo: f64, hi: f64) {
    let mut hist = [0u32; 256];
    for &v in &img.data {
        hist[v as usize] += 1;
    }
    let n = img.data.len() as f64;
    let pct = |p: f64| -> u8 {
        let want = ((n * p) as u32).max(1);
        let mut acc = 0u32;
        for (v, &h) in hist.iter().enumerate() {
            acc += h;
            if acc >= want {
                return v as u8;
            }
        }
        255
    };
    let (a, b) = (pct(lo) as f32, pct(hi) as f32);
    let span = (b - a).max(1.0);
    for v in img.data.iter_mut() {
        *v = (((*v as f32 - a) / span * 255.0).clamp(0.0, 255.0) + 0.5) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contrast_stretch_fills_the_range() {
        let mut g = Grey::new(10, 10);
        for (i, v) in g.data.iter_mut().enumerate() {
            *v = 60 + (i % 40) as u8;
        }
        normalise_contrast(&mut g, 0.0, 1.0);
        assert_eq!(*g.data.iter().min().unwrap(), 0);
        assert_eq!(*g.data.iter().max().unwrap(), 255);
    }

    #[test]
    fn template_maps_to_itself() {
        let m = similarity(&ARCFACE_112, &ARCFACE_112);
        assert!((m[0][0] - 1.0).abs() < 1e-4 && m[0][1].abs() < 1e-4 && m[0][2].abs() < 1e-3);
    }

    #[test]
    fn recovers_scale_rotation_translation() {
        let (s, th, tx, ty) = (2.0f32, 0.3f32, 10.0f32, -5.0f32);
        let src: [[f32; 2]; 5] = std::array::from_fn(|i| {
            let [x, y] = ARCFACE_112[i];
            // inverse-transform the template so that fwd(src) == template
            let (xx, yy) = (x - tx, y - ty);
            let (c, sn) = (th.cos(), th.sin());
            [(c * xx + sn * yy) / s, (-sn * xx + c * yy) / s]
        });
        let m = similarity(&src, &ARCFACE_112);
        for (p, q) in src.iter().zip(&ARCFACE_112) {
            let x = m[0][0] * p[0] + m[0][1] * p[1] + m[0][2];
            let y = m[1][0] * p[0] + m[1][1] * p[1] + m[1][2];
            assert!(
                (x - q[0]).abs() < 1e-2 && (y - q[1]).abs() < 1e-2,
                "{:?} -> {:?} vs {:?}",
                p,
                (x, y),
                q
            );
        }
        let inv = invert(&m);
        let x = inv[0][0] * ARCFACE_112[2][0] + inv[0][1] * ARCFACE_112[2][1] + inv[0][2];
        assert!((x - src[2][0]).abs() < 1e-2);
    }
}
