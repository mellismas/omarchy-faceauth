//! 8-bit greyscale images and the few operations the pipeline needs.

/// Row-major 8-bit grey, no padding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grey {
    pub width: usize,
    pub height: usize,
    pub data: Vec<u8>,
}

impl Grey {
    pub fn new(width: usize, height: usize) -> Self {
        Grey {
            width,
            height,
            data: vec![0; width * height],
        }
    }

    #[inline]
    pub fn at(&self, x: usize, y: usize) -> u8 {
        self.data[y * self.width + x]
    }

    /// Bilinear sample with zero outside the image.
    pub fn sample(&self, x: f32, y: f32) -> f32 {
        if x < 0.0 || y < 0.0 || x > (self.width - 1) as f32 || y > (self.height - 1) as f32 {
            return 0.0;
        }
        let x0 = x.floor() as usize;
        let y0 = y.floor() as usize;
        let x1 = (x0 + 1).min(self.width - 1);
        let y1 = (y0 + 1).min(self.height - 1);
        let fx = x - x0 as f32;
        let fy = y - y0 as f32;
        let p = |x: usize, y: usize| self.at(x, y) as f32;
        let top = p(x0, y0) * (1.0 - fx) + p(x1, y0) * fx;
        let bot = p(x0, y1) * (1.0 - fx) + p(x1, y1) * fx;
        top * (1.0 - fy) + bot * fy
    }

    /// Apply `transpose` then flips. The reference IR sensor needs transpose +
    /// both flips to come out upright; the reference RGB sensor needs both flips.
    pub fn oriented(&self, transpose: bool, flip_x: bool, flip_y: bool) -> Grey {
        let (w, h) = if transpose {
            (self.height, self.width)
        } else {
            (self.width, self.height)
        };
        let mut out = Grey::new(w, h);
        for y in 0..self.height {
            for x in 0..self.width {
                let (mut ox, mut oy) = if transpose { (y, x) } else { (x, y) };
                if flip_x {
                    ox = w - 1 - ox;
                }
                if flip_y {
                    oy = h - 1 - oy;
                }
                out.data[oy * w + ox] = self.data[y * self.width + x];
            }
        }
        out
    }

    /// Inverse-map an output pixel grid through a 2x3 affine `m` (output -> input).
    pub fn warp_affine(&self, m: &[[f32; 3]; 2], width: usize, height: usize) -> Grey {
        let mut out = Grey::new(width, height);
        for y in 0..height {
            for x in 0..width {
                let sx = m[0][0] * x as f32 + m[0][1] * y as f32 + m[0][2];
                let sy = m[1][0] * x as f32 + m[1][1] * y as f32 + m[1][2];
                out.data[y * width + x] = (self.sample(sx, sy) + 0.5) as u8;
            }
        }
        out
    }

    /// Zero-pad to a multiple of `m` on the right and bottom.
    pub fn padded_to_multiple(&self, m: usize) -> Grey {
        let w = self.width.div_ceil(m) * m;
        let h = self.height.div_ceil(m) * m;
        if w == self.width && h == self.height {
            return self.clone();
        }
        let mut out = Grey::new(w, h);
        for y in 0..self.height {
            out.data[y * w..y * w + self.width]
                .copy_from_slice(&self.data[y * self.width..(y + 1) * self.width]);
        }
        out
    }

    /// Planar NCHW float tensor with the grey replicated into three channels,
    /// each value `(v - mean) / scale`. The first plane is written once and
    /// the other two are copies of it inside the same allocation: the
    /// detector calls this on a 640x640 canvas for every frame, and a
    /// separate plane first cost a 1.6 MB allocation each time.
    pub fn to_nchw3(&self, mean: f32, scale: f32) -> Vec<f32> {
        let n = self.width * self.height;
        let mut v = Vec::with_capacity(3 * n);
        v.extend(self.data.iter().map(|&p| (p as f32 - mean) / scale));
        v.extend_from_within(0..n);
        v.extend_from_within(0..n);
        v
    }

    /// Mean pixel value inside `bbox` (`[x, y, w, h]`, clamped to the
    /// frame); the whole-frame mean when the box misses the frame.
    pub fn region_mean(&self, bbox: [f32; 4]) -> f64 {
        let x0 = bbox[0].max(0.0) as usize;
        let y0 = bbox[1].max(0.0) as usize;
        let x1 = ((bbox[0] + bbox[2]).max(0.0) as usize).min(self.width);
        let y1 = ((bbox[1] + bbox[3]).max(0.0) as usize).min(self.height);
        if x1 <= x0 || y1 <= y0 {
            return self.mean();
        }
        let mut sum: u64 = 0;
        for y in y0..y1 {
            let row = &self.data[y * self.width + x0..y * self.width + x1];
            sum += row.iter().map(|&v| v as u64).sum::<u64>();
        }
        sum as f64 / ((x1 - x0) * (y1 - y0)) as f64
    }

    /// Mean pixel value. The sum is taken in integers: a frame's total is
    /// far below 2^53, so this equals the floating-point running sum to the
    /// last bit and costs a fraction of it.
    pub fn mean(&self) -> f64 {
        if self.data.is_empty() {
            return 0.0;
        }
        let sum: u64 = self.data.iter().map(|&v| v as u64).sum();
        sum as f64 / self.data.len() as f64
    }

    /// The 8-bit oriented frame straight from a 10-bit sensor buffer (each
    /// sample shifted down two bits, the fixed mapping the capture uses so
    /// consecutive frames compare), with the same orientation as `oriented`.
    /// One pass writing the output row by row, in place of an 8-bit copy
    /// followed by a second pass and a second allocation; the pixels are the
    /// same. Each orientation gets its own loop so the row loop carries no
    /// branch and the shift is a constant.
    pub fn from_u10_oriented(
        px: &[u16],
        width: usize,
        height: usize,
        transpose: bool,
        flip_x: bool,
        flip_y: bool,
    ) -> Grey {
        assert!(px.len() >= width * height, "short sensor buffer");
        let (ow, oh) = if transpose {
            (height, width)
        } else {
            (width, height)
        };
        let mut out = Grey::new(ow, oh);
        if width == 0 || height == 0 {
            return out;
        }
        match (transpose, flip_x) {
            (true, true) => orient_u10::<true, true>(px, width, &mut out, flip_y),
            (true, false) => orient_u10::<true, false>(px, width, &mut out, flip_y),
            (false, true) => orient_u10::<false, true>(px, width, &mut out, flip_y),
            (false, false) => orient_u10::<false, false>(px, width, &mut out, flip_y),
        }
        out
    }

    pub fn write_pgm(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        use std::io::Write;
        let mut f = std::fs::File::create(path)?;
        write!(f, "P5\n{} {}\n255\n", self.width, self.height)?;
        f.write_all(&self.data)
    }

    pub fn read_pgm(path: impl AsRef<std::path::Path>) -> anyhow::Result<Grey> {
        let bytes = std::fs::read(path)?;
        // P5\n<w> <h>\n255\n<data>
        let mut fields = Vec::new();
        let mut i = 0;
        while fields.len() < 4 && i < bytes.len() {
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            let s = i;
            while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            fields.push(String::from_utf8_lossy(&bytes[s..i]).to_string());
        }
        i += 1;
        anyhow::ensure!(
            fields.first().map(String::as_str) == Some("P5"),
            "not a P5 PGM"
        );
        let width: usize = fields[1].parse()?;
        let height: usize = fields[2].parse()?;
        anyhow::ensure!(bytes.len() >= i + width * height, "short PGM");
        Ok(Grey {
            width,
            height,
            data: bytes[i..i + width * height].to_vec(),
        })
    }
}

/// The row loop of `from_u10_oriented` for one transpose and flip_x
/// choice. Undoing the flips and then the transpose finds the source of
/// each output row: a source row as it stands, or a source column walked
/// with the row stride.
fn orient_u10<const TRANSPOSE: bool, const FLIP_X: bool>(
    px: &[u16],
    width: usize,
    out: &mut Grey,
    flip_y: bool,
) {
    let (ow, oh) = (out.width, out.height);
    for (oy, row) in out.data.chunks_exact_mut(ow).enumerate() {
        let iy = if flip_y { oh - 1 - oy } else { oy };
        if TRANSPOSE {
            if FLIP_X {
                // The column from the bottom up; the index wraps once, after
                // the last read.
                let mut idx = (ow - 1) * width + iy;
                for o in row.iter_mut() {
                    *o = (px[idx] >> 2) as u8;
                    idx = idx.wrapping_sub(width);
                }
            } else {
                let mut idx = iy;
                for o in row.iter_mut() {
                    *o = (px[idx] >> 2) as u8;
                    idx += width;
                }
            }
        } else {
            let source = &px[iy * width..(iy + 1) * width];
            if FLIP_X {
                for (o, &v) in row.iter_mut().zip(source.iter().rev()) {
                    *o = (v >> 2) as u8;
                }
            } else {
                for (o, &v) in row.iter_mut().zip(source) {
                    *o = (v >> 2) as u8;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The region mean follows the box, clamps it to the frame, and falls
    /// back to the frame mean when the box misses the frame.
    #[test]
    fn region_mean_averages_the_box_only() {
        let mut g = Grey::new(10, 10);
        for y in 0..10 {
            for x in 0..10 {
                g.data[y * 10 + x] = if (2..6).contains(&x) && (3..7).contains(&y) {
                    200
                } else {
                    0
                };
            }
        }
        assert_eq!(g.region_mean([2.0, 3.0, 4.0, 4.0]), 200.0);
        assert_eq!(g.region_mean([2.0, 3.0, 8.0, 4.0]), 100.0);
        assert_eq!(g.region_mean([-5.0, -5.0, 3.0, 3.0]), g.mean());
        assert_eq!(g.region_mean([20.0, 20.0, 5.0, 5.0]), g.mean());
    }

    #[test]
    fn orientation_matches_the_viewer_mapping() {
        // Viewer: out(ox = H-1-y, oy = W-1-x) = in(x, y): transpose + flip both.
        let mut g = Grey::new(3, 2);
        g.data = vec![1, 2, 3, 4, 5, 6];
        let o = g.oriented(true, true, true);
        assert_eq!((o.width, o.height), (2, 3));
        // in(0,0)=1 -> ox = 2-1-0 = 1, oy = 3-1-0 = 2
        assert_eq!(o.at(1, 2), 1);
        // in(2,1)=6 -> ox = 0, oy = 0
        assert_eq!(o.at(0, 0), 6);
    }

    #[test]
    fn padding_keeps_content() {
        let mut g = Grey::new(3, 3);
        g.data
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = i as u8);
        let p = g.padded_to_multiple(4);
        assert_eq!((p.width, p.height), (4, 4));
        assert_eq!(p.at(2, 2), 8);
        assert_eq!(p.at(3, 3), 0);
    }

    #[test]
    fn identity_warp_is_identity() {
        let mut g = Grey::new(4, 4);
        g.data
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i * 13) as u8);
        let w = g.warp_affine(&[[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]], 4, 4);
        assert_eq!(w, g);
    }

    fn noisy(w: usize, h: usize) -> Grey {
        let mut g = Grey::new(w, h);
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        for v in g.data.iter_mut() {
            s = s
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *v = (s >> 56) as u8;
        }
        g
    }

    /// The single-pass tensor is the old plane-then-copy result, bit for bit.
    #[test]
    fn nchw3_matches_the_plane_copy() {
        let g = noisy(37, 23);
        let n = g.width * g.height;
        let plane: Vec<f32> = g.data.iter().map(|&p| (p as f32 - 127.5) / 127.5).collect();
        let mut want = Vec::with_capacity(3 * n);
        for _ in 0..3 {
            want.extend_from_slice(&plane);
        }
        assert_eq!(g.to_nchw3(127.5, 127.5), want);
    }

    /// The integer mean equals the floating-point running sum the daemon used
    /// before, to the last bit, at the reference frame size.
    #[test]
    fn integer_mean_equals_the_f64_running_sum() {
        for g in [noisy(480, 640), noisy(3, 1), Grey::new(2, 2)] {
            let f64_sum = g.data.iter().map(|&v| v as f64).sum::<f64>() / g.data.len() as f64;
            assert_eq!(g.mean().to_bits(), f64_sum.to_bits());
        }
        assert_eq!(Grey::new(0, 0).mean(), 0.0);
    }

    /// The fused 16-bit conversion and orientation equals the two-pass
    /// result for every combination of transpose and flips (poc_hygiene_2's
    /// equality assertion, generalised).
    #[test]
    fn fused_orientation_equals_the_two_pass_result() {
        let (w, h) = (13usize, 7usize);
        let raw: Vec<u16> = (0..w * h).map(|i| ((i * 977) % 1024) as u16).collect();
        let mut g8 = Grey::new(w, h);
        for (o, &v) in g8.data.iter_mut().zip(&raw) {
            *o = (v >> 2) as u8;
        }
        for t in [false, true] {
            for fx in [false, true] {
                for fy in [false, true] {
                    assert_eq!(
                        Grey::from_u10_oriented(&raw, w, h, t, fx, fy),
                        g8.oriented(t, fx, fy),
                        "transpose {} flip_x {} flip_y {}",
                        t,
                        fx,
                        fy
                    );
                }
            }
        }
    }
}
