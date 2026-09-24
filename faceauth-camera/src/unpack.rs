//! Pixel unpacking into 10-bit little-endian samples, and the Bayer reduction
//! used for the RGB sensor.

/// Intel IPU3 packed 10-bit (`ip3y`, `ip3b`, ...): 32-byte groups of 25 pixels,
/// each group a little-endian 250-bit stream plus 6 pad bits; a 64-byte block
/// holds two groups (50 pixels). Row stride is `ceil(w / 50) * 64` bytes.
///
/// Decoded per pixel with a clamp at the row width. Two earlier reference
/// implementations got the last pixels of each row wrong by treating the
/// 5-byte/4-pixel formula as valid across group boundaries; it is not.
pub fn ipu3_row_stride(width: usize) -> usize {
    width.div_ceil(50) * 64
}

/// `width * height` (or `width * height * per`) as a usize, or None when
/// dimensions a device reports would overflow it: an implausible frame is
/// refused rather than read through a wrapped size check.
fn plane(width: usize, height: usize, per: usize) -> Option<usize> {
    width.checked_mul(height)?.checked_mul(per)
}

pub fn unpack_ipu3_10(src: &[u8], width: usize, height: usize, dst: &mut [u16]) -> bool {
    let stride = ipu3_row_stride(width);
    let (Some(packed), Some(pixels)) = (stride.checked_mul(height), plane(width, height, 1)) else {
        return false;
    };
    if src.len() < packed || dst.len() < pixels {
        return false;
    }
    for y in 0..height {
        let row = &src[y * stride..y * stride + stride];
        let out = &mut dst[y * width..y * width + width];
        let mut grp = 0;
        while grp * 25 < width {
            let g = &row[grp * 32..grp * 32 + 32];
            for i in 0..25 {
                let x = grp * 25 + i;
                if x >= width {
                    break;
                }
                let bit = 10 * i;
                let by = bit >> 3;
                let sh = bit & 7;
                let v = (g[by] as u32 | ((g[by + 1] as u32) << 8)) >> sh;
                out[x] = (v & 0x3ff) as u16;
            }
            grp += 1;
        }
    }
    true
}

/// 8-bit grey (UVC `GREY`) widened to the 10-bit scale used everywhere else.
pub fn unpack_grey8(src: &[u8], width: usize, height: usize, dst: &mut [u16]) -> bool {
    let Some(pixels) = plane(width, height, 1) else {
        return false;
    };
    if src.len() < pixels || dst.len() < pixels {
        return false;
    }
    for (o, &s) in dst[..width * height].iter_mut().zip(src) {
        *o = (s as u16) << 2;
    }
    true
}

/// `YUYV`: luma only, widened to 10 bits.
pub fn unpack_yuyv_luma(src: &[u8], width: usize, height: usize, dst: &mut [u16]) -> bool {
    let (Some(bytes), Some(pixels)) = (plane(width, height, 2), plane(width, height, 1)) else {
        return false;
    };
    if src.len() < bytes || dst.len() < pixels {
        return false;
    }
    for i in 0..width * height {
        dst[i] = (src[2 * i] as u16) << 2;
    }
    true
}

/// 10-bit or 16-bit little-endian grey (`Y10 `, `Y16 `), normalised to 10 bits.
pub fn unpack_y16(
    src: &[u8],
    width: usize,
    height: usize,
    shift_down: u32,
    dst: &mut [u16],
) -> bool {
    let (Some(bytes), Some(pixels)) = (plane(width, height, 2), plane(width, height, 1)) else {
        return false;
    };
    if src.len() < bytes || dst.len() < pixels {
        return false;
    }
    for i in 0..width * height {
        dst[i] = (u16::from_le_bytes([src[2 * i], src[2 * i + 1]]) >> shift_down) & 0x3ff;
    }
    true
}

#[cfg(feature = "dev-tools")]
/// Bayer 2x2 block reduction: each block becomes one linear (R, G, B) triple on
/// the 10-bit scale after black subtraction, with the two greens averaged.
/// `order` names the top-left pixel of a block: `B` for BGGR, `R` for RGGB,
/// `G` with the second letter for GRBG/GBRG.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BayerOrder {
    Bggr,
    Rggb,
    Grbg,
    Gbrg,
}

#[cfg(feature = "dev-tools")]
/// The last raw row pair of the IPU3 RGB frame is not image data; `rows_out`
/// callers pass `height / 2 - 1` for it.
pub fn bayer_reduce(
    src: &[u16],
    width: usize,
    height: usize,
    order: BayerOrder,
    black: u16,
    out: &mut [[f32; 3]],
) -> usize {
    let w2 = width / 2;
    let h2 = height / 2;
    let (Some(n), Some(pixels)) = (w2.checked_mul(h2), plane(width, height, 1)) else {
        return 0;
    };
    if src.len() < pixels || out.len() < n {
        return 0;
    }
    let b = black as f32;
    for y in 0..h2 {
        let r0 = &src[2 * y * width..2 * y * width + width];
        let r1 = &src[(2 * y + 1) * width..(2 * y + 1) * width + width];
        for x in 0..w2 {
            let (p00, p01, p10, p11) = (
                r0[2 * x] as f32,
                r0[2 * x + 1] as f32,
                r1[2 * x] as f32,
                r1[2 * x + 1] as f32,
            );
            let (r, g, bl) = match order {
                BayerOrder::Bggr => (p11, (p01 + p10) * 0.5, p00),
                BayerOrder::Rggb => (p00, (p01 + p10) * 0.5, p11),
                BayerOrder::Grbg => (p01, (p00 + p11) * 0.5, p10),
                BayerOrder::Gbrg => (p10, (p00 + p11) * 0.5, p01),
            };
            out[y * w2 + x] = [(r - b).max(0.0), (g - b).max(0.0), (bl - b).max(0.0)];
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack_ipu3(px: &[u16], width: usize, height: usize) -> Vec<u8> {
        let stride = ipu3_row_stride(width);
        let mut out = vec![0u8; stride * height];
        for y in 0..height {
            for x in 0..width {
                let grp = x / 25;
                let i = x % 25;
                let bit = 10 * i;
                let v = px[y * width + x] as u32 & 0x3ff;
                // 10 bits shifted by up to 7 span at most 3 bytes, all inside the 32-byte group.
                let base = y * stride + grp * 32 + (bit >> 3);
                let mut acc = 0u32;
                let nbytes = 3.min(32 - (bit >> 3));
                for k in 0..nbytes {
                    acc |= (out[base + k] as u32) << (8 * k);
                }
                acc |= v << (bit & 7);
                for k in 0..nbytes {
                    out[base + k] = (acc >> (8 * k)) as u8;
                }
            }
        }
        out
    }

    #[test]
    fn stride_matches_kernel_formula() {
        assert_eq!(ipu3_row_stride(640), 832);
        assert_eq!(ipu3_row_stride(1296), 1664);
        assert_eq!(ipu3_row_stride(2592), 3328);
    }

    #[test]
    fn ipu3_roundtrip_including_row_tails() {
        // 640 is not a multiple of 25 (25*25 = 625, tail of 15) and 1296 leaves a tail of 21.
        for &(w, h) in &[(640usize, 3usize), (1296, 2), (50, 1), (26, 2)] {
            let px: Vec<u16> = (0..w * h).map(|i| ((i * 37 + 11) % 1024) as u16).collect();
            let packed = pack_ipu3(&px, w, h);
            let mut got = vec![0u16; w * h];
            assert!(unpack_ipu3_10(&packed, w, h, &mut got));
            assert_eq!(got, px, "{}x{}", w, h);
        }
    }

    #[test]
    fn ipu3_rejects_short_buffers() {
        let mut dst = vec![0u16; 640 * 480];
        assert!(!unpack_ipu3_10(&[0u8; 100], 640, 480, &mut dst));
    }

    /// Dimensions whose product overflows are refused, not wrapped into a
    /// size check that passes (F14).
    #[cfg(feature = "dev-tools")]
    #[test]
    fn absurd_dimensions_are_refused_not_wrapped() {
        let mut dst = vec![0u16; 16];
        let src = [0u8; 64];
        let huge = usize::MAX / 2 + 1;
        assert!(!unpack_ipu3_10(&src, huge, 2, &mut dst));
        assert!(!unpack_grey8(&src, huge, 2, &mut dst));
        assert!(!unpack_yuyv_luma(&src, huge, 2, &mut dst));
        assert!(!unpack_y16(&src, huge, 2, 0, &mut dst));
        let src16 = [0u16; 64];
        let mut out = [[0f32; 3]; 16];
        assert_eq!(
            bayer_reduce(&src16, huge, 2, BayerOrder::Bggr, 0, &mut out),
            0
        );
        assert_eq!(
            bayer_reduce(
                &src16,
                usize::MAX,
                usize::MAX,
                BayerOrder::Bggr,
                0,
                &mut out
            ),
            0
        );
    }

    #[cfg(feature = "dev-tools")]
    #[test]
    fn bayer_bggr_picks_the_right_sites() {
        // One 2x2 block: B=100 G=200 / G=300 R=400, black 10.
        let src = [100u16, 200, 300, 400];
        let mut out = [[0f32; 3]; 1];
        assert_eq!(bayer_reduce(&src, 2, 2, BayerOrder::Bggr, 10, &mut out), 1);
        assert_eq!(out[0], [390.0, 240.0, 90.0]);
    }
}
