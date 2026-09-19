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
        Grey { width, height, data: vec![0; width * height] }
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
        let (w, h) = if transpose { (self.height, self.width) } else { (self.width, self.height) };
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
            out.data[y * w..y * w + self.width].copy_from_slice(&self.data[y * self.width..(y + 1) * self.width]);
        }
        out
    }

    /// Planar NCHW float tensor with the grey replicated into three channels,
    /// each value `(v - mean) / scale`.
    pub fn to_nchw3(&self, mean: f32, scale: f32) -> Vec<f32> {
        let n = self.width * self.height;
        let mut v = Vec::with_capacity(3 * n);
        let plane: Vec<f32> = self.data.iter().map(|&p| (p as f32 - mean) / scale).collect();
        for _ in 0..3 {
            v.extend_from_slice(&plane);
        }
        v
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
        anyhow::ensure!(fields.first().map(String::as_str) == Some("P5"), "not a P5 PGM");
        let width: usize = fields[1].parse()?;
        let height: usize = fields[2].parse()?;
        anyhow::ensure!(bytes.len() >= i + width * height, "short PGM");
        Ok(Grey { width, height, data: bytes[i..i + width * height].to_vec() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        g.data.iter_mut().enumerate().for_each(|(i, v)| *v = i as u8);
        let p = g.padded_to_multiple(4);
        assert_eq!((p.width, p.height), (4, 4));
        assert_eq!(p.at(2, 2), 8);
        assert_eq!(p.at(3, 3), 0);
    }

    #[test]
    fn identity_warp_is_identity() {
        let mut g = Grey::new(4, 4);
        g.data.iter_mut().enumerate().for_each(|(i, v)| *v = (i * 13) as u8);
        let w = g.warp_affine(&[[1.0, 0.0, 0.0], [0.0, 1.0, 0.0]], 4, 4);
        assert_eq!(w, g);
    }
}
