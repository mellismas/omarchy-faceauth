//! Exposure, white-balance and tone calibration, as measured and signed off on
//! the reference machine (see `kernel/CALIBRATION.md` in the pack).
//!
//! Everything here works on linear 10-bit samples. Nothing here touches a
//! device: the loops compute the next setting and the caller applies it.

/// A rectangular metering window in pixel coordinates.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Window {
    pub x0: usize,
    pub y0: usize,
    pub x1: usize,
    pub y1: usize,
}

impl Window {
    /// The default: the central 50% x 60% of the frame, where a face sits.
    pub fn centre(width: usize, height: usize) -> Self {
        Window {
            x0: width / 4,
            y0: height / 5,
            x1: width * 3 / 4,
            y1: height * 4 / 5,
        }
    }

    pub fn clamp(self, width: usize, height: usize) -> Self {
        Window {
            x0: self.x0.min(width),
            y0: self.y0.min(height),
            x1: self.x1.min(width),
            y1: self.y1.min(height),
        }
    }
}

/// What the meter saw: mean level above black as a fraction of the range,
/// and the fraction of window pixels at or above the saturation level.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct Metering {
    pub mean: f64,
    pub clip: f64,
}

pub const SATURATION_LEVEL: u16 = 1000;

/// Meter a window of a 10-bit frame, subsampled (every 2nd row, every 3rd column).
pub fn meter(px: &[u16], width: usize, black: u16, win: Window) -> Metering {
    let mut count = 0usize;
    let mut sat = 0usize;
    let mut sum = 0f64;
    let mut y = win.y0;
    while y < win.y1 {
        let row = &px[y * width..y * width + width];
        let mut x = win.x0;
        while x < win.x1 {
            let v = row[x] & 1023;
            if v >= SATURATION_LEVEL {
                sat += 1;
            }
            sum += v.saturating_sub(black) as f64;
            count += 1;
            x += 3;
        }
        y += 2;
    }
    if count == 0 {
        return Metering::default();
    }
    Metering {
        mean: sum / count as f64 / (1023.0 - black as f64),
        clip: sat as f64 / count as f64,
    }
}

/// One auto-exposure step: the multiplicative correction toward `target`,
/// backing off when highlights clip.
///
/// - square-root approach so the loop under-shoots rather than oscillates
/// - a clipped share above 5% never brightens; above 15% it darkens
/// - rate limited to 0.8..1.25 per step (a step every 0.5 s)
/// - a 6% deadband so a face leaning in or out does not make it chase
pub fn ae_factor(m: Metering, target: f64) -> f64 {
    if m.mean <= 0.0 {
        return 1.25;
    }
    let mut f = (target / m.mean).sqrt();
    if m.clip > 0.05 && f > 1.0 {
        f = 1.0;
    }
    if m.clip > 0.15 {
        f = f.min(0.9);
    }
    f = f.clamp(0.8, 1.25);
    if (f - 1.0).abs() < 0.06 {
        1.0
    } else {
        f
    }
}

/// Exponential smoothing of the metered mean between steps (alpha 0.4).
#[derive(Clone, Copy, Debug, Default)]
pub struct Smoother {
    acc: Option<f64>,
}

impl Smoother {
    pub fn push(&mut self, v: f64) -> f64 {
        let a = match self.acc {
            None => v,
            Some(a) => a + 0.4 * (v - a),
        };
        self.acc = Some(a);
        a
    }
    pub fn reset(&mut self) {
        self.acc = None;
    }
    pub fn value(&self) -> Option<f64> {
        self.acc
    }
}

/// The three actuators of an exposure loop, in the order they are used when
/// brightening; darkening unwinds them in reverse. `gain` is optional for
/// sensors that expose only exposure (or where analogue gain is not wanted).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Exposure {
    pub exposure: i64,
    pub gain: i64,
    pub dgain: f64,
}

#[derive(Clone, Copy, Debug)]
pub struct ExposureLimits {
    pub exposure: (i64, i64),
    /// `None` when the loop must not drive analogue gain.
    pub gain: Option<(i64, i64)>,
    pub dgain_max: f64,
}

impl Exposure {
    /// Apply a factor: exposure first, then analogue gain, then digital gain when
    /// brightening; digital, then analogue, then exposure when darkening.
    pub fn step(self, f: f64, lim: &ExposureLimits) -> Exposure {
        let mut e = self;
        if f == 1.0 {
            return e;
        }
        let (emin, emax) = lim.exposure;
        if f > 1.0 {
            if e.exposure < emax {
                e.exposure = ((e.exposure as f64 * f) as i64 + 1).min(emax);
            } else if let Some((_, gmax)) = lim.gain.filter(|(_, gmax)| e.gain < *gmax) {
                e.gain = ((e.gain as f64 * f) as i64 + 1).min(gmax);
            } else {
                e.dgain = (e.dgain * f).min(lim.dgain_max);
            }
        } else if e.dgain > 1.0 {
            e.dgain = (e.dgain * f).max(1.0);
        } else if let Some((gmin, _)) = lim.gain.filter(|(gmin, _)| e.gain > *gmin) {
            e.gain = ((e.gain as f64 * f) as i64).max(gmin);
        } else {
            e.exposure = ((e.exposure as f64 * f) as i64).max(emin);
        }
        e
    }
}

/// The IR loop's limits on the reference sensor (ov7251 at 30 fps).
pub const IR_LIMITS: ExposureLimits = ExposureLimits {
    exposure: (1, 1704),
    gain: Some((16, 1023)),
    dgain_max: 4.0,
};
/// The RGB loop's limits on the reference sensor (ov5693 at 1296x972).
pub const RGB_LIMITS: ExposureLimits = ExposureLimits {
    exposure: (1, 1030),
    gain: None,
    dgain_max: 4.0,
};
/// Metering target for both loops.
pub const AE_TARGET: f64 = 0.30;

/// Grey-world white balance on Bayer-reduced RGB: gains that bring the R and B
/// means to the G mean, using mid-tone blocks only (0.08..0.85 of range) so
/// highlights and the black floor do not vote. Smoothed with alpha 0.15.
#[derive(Clone, Copy, Debug)]
pub struct WhiteBalance {
    pub wr: f64,
    pub wb: f64,
}

impl Default for WhiteBalance {
    fn default() -> Self {
        WhiteBalance { wr: 1.0, wb: 1.0 }
    }
}

impl WhiteBalance {
    /// `rgb` is the reduced frame; `range` is `1023 - black`.
    pub fn update(&mut self, rgb: &[[f32; 3]], range: f64) -> &Self {
        let (mut sr, mut sg, mut sb, mut n) = (0f64, 0f64, 0f64, 0usize);
        for p in rgb.iter().step_by(4) {
            let lum = p[1] as f64 / range;
            if !(0.08..=0.85).contains(&lum) {
                continue;
            }
            sr += p[0] as f64;
            sg += p[1] as f64;
            sb += p[2] as f64;
            n += 1;
        }
        let (iwr, iwb) = if n < 50 {
            (self.wr, self.wb)
        } else {
            (
                if sr > 0.0 { sg / sr } else { 1.0 },
                if sb > 0.0 { sg / sb } else { 1.0 },
            )
        };
        self.wr += 0.15 * (iwr - self.wr);
        self.wb += 0.15 * (iwb - self.wb);
        self
    }
}

/// Percentile of a 10-bit frame, subsampled by `step`, never returning 0 for
/// the black point so divisions stay safe.
pub fn percentile(px: &[u16], step: usize, p: f64) -> u16 {
    let mut hist = [0u32; 1024];
    let mut count = 0usize;
    for &v in px.iter().step_by(step.max(1)) {
        hist[(v & 1023) as usize] += 1;
        count += 1;
    }
    let mut acc = 0usize;
    let want = (count as f64 * p) as usize;
    for (v, &h) in hist.iter().enumerate() {
        acc += h as usize;
        if acc >= want {
            return (v as u16).max(1);
        }
    }
    1023
}

/// The signed-off fixed look for the two displays (used by the viewer and by
/// the enrolment preview). The matcher's input is normalised separately.
#[derive(Clone, Copy, Debug)]
pub struct IrLook {
    pub dgain: f64,
    pub brightness: f64,
    pub contrast: f64,
}
pub const IR_LOOK: IrLook = IrLook {
    dgain: 1.0,
    brightness: 0.25,
    contrast: 2.05,
};

#[derive(Clone, Copy, Debug)]
pub struct RgbLook {
    pub r_gain: f64,
    pub g_gain: f64,
    pub b_gain: f64,
    pub saturation: f64,
    pub brightness: f64,
    pub contrast: f64,
    pub gamma: f64,
}
pub const RGB_LOOK: RgbLook = RgbLook {
    r_gain: 1.3,
    g_gain: 1.3,
    b_gain: 1.3,
    saturation: 1.7,
    brightness: -0.05,
    contrast: 1.0,
    gamma: 2.2,
};

/// IR frame to 8-bit grey with black/white stretch and the fixed look.
pub fn ir_to_grey8(px: &[u16], black: u16, white: u16, look: IrLook, out: &mut [u8]) {
    let span = (white.max(black + 1) - black) as f64;
    for (o, &v) in out.iter_mut().zip(px) {
        let mut x = (v as f64 - black as f64) / span * look.dgain + look.brightness;
        x = (x - 0.5) * look.contrast + 0.5;
        *o = if x <= 0.0 {
            0
        } else if x >= 1.0 {
            255
        } else {
            (x * 255.0 + 0.5) as u8
        };
    }
}

/// Bayer-reduced RGB to 8-bit sRGB-ish with white balance, the fixed look and gamma.
pub fn rgb_to_rgb8(
    rgb: &[[f32; 3]],
    black: u16,
    white: u16,
    wb: WhiteBalance,
    dgain: f64,
    look: RgbLook,
    out: &mut [[u8; 3]],
) {
    let span = (white.max(black + 1) - black) as f64;
    let mut lut = [0u8; 1024];
    for (i, l) in lut.iter_mut().enumerate() {
        *l = (255.0 * (i as f64 / 1023.0).powf(1.0 / look.gamma) + 0.5) as u8;
    }
    let tone = |v: f64| -> f64 {
        let v = v / span * dgain + look.brightness;
        (v - 0.5) * look.contrast + 0.5
    };
    for (o, p) in out.iter_mut().zip(rgb) {
        let r = tone(p[0] as f64 * wb.wr * look.r_gain);
        let g = tone(p[1] as f64 * look.g_gain);
        let b = tone(p[2] as f64 * wb.wb * look.b_gain);
        let y = 0.299 * r + 0.587 * g + 0.114 * b;
        let s = look.saturation;
        let q = |v: f64| lut[(v.clamp(0.0, 1.0) * 1023.0) as usize];
        *o = [q(y + s * (r - y)), q(y + s * (g - y)), q(y + s * (b - y))];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ae_factor_rules() {
        let t = AE_TARGET;
        assert_eq!(
            ae_factor(
                Metering {
                    mean: 0.0,
                    clip: 0.0
                },
                t
            ),
            1.25
        );
        assert_eq!(
            ae_factor(
                Metering {
                    mean: 0.30,
                    clip: 0.0
                },
                t
            ),
            1.0
        );
        assert_eq!(
            ae_factor(
                Metering {
                    mean: 0.31,
                    clip: 0.0
                },
                t
            ),
            1.0,
            "deadband"
        );
        assert_eq!(
            ae_factor(
                Metering {
                    mean: 0.05,
                    clip: 0.0
                },
                t
            ),
            1.25,
            "rate limit up"
        );
        assert_eq!(
            ae_factor(
                Metering {
                    mean: 0.90,
                    clip: 0.0
                },
                t
            ),
            0.8,
            "rate limit down"
        );
        assert_eq!(
            ae_factor(
                Metering {
                    mean: 0.10,
                    clip: 0.06
                },
                t
            ),
            1.0,
            "clip blocks brightening"
        );
        assert_eq!(
            ae_factor(
                Metering {
                    mean: 0.10,
                    clip: 0.20
                },
                t
            ),
            0.9,
            "heavy clip darkens"
        );
    }

    #[test]
    fn exposure_actuator_order() {
        let lim = IR_LIMITS;
        let e = Exposure {
            exposure: 1000,
            gain: 16,
            dgain: 1.0,
        };
        let up = e.step(1.25, &lim);
        assert_eq!(
            up,
            Exposure {
                exposure: 1251,
                gain: 16,
                dgain: 1.0
            }
        );
        let at_max = Exposure {
            exposure: 1704,
            gain: 16,
            dgain: 1.0,
        }
        .step(1.25, &lim);
        assert_eq!(at_max.gain, 21, "gain after exposure");
        let all_max = Exposure {
            exposure: 1704,
            gain: 1023,
            dgain: 1.0,
        }
        .step(1.25, &lim);
        assert_eq!(all_max.dgain, 1.25, "dgain last");
        let capped = Exposure {
            exposure: 1704,
            gain: 1023,
            dgain: 4.0,
        }
        .step(1.25, &lim);
        assert_eq!(capped.dgain, 4.0);
        let down = Exposure {
            exposure: 1704,
            gain: 40,
            dgain: 2.0,
        }
        .step(0.8, &lim);
        assert_eq!(
            down,
            Exposure {
                exposure: 1704,
                gain: 40,
                dgain: 1.6
            },
            "dgain unwinds first"
        );
        let down2 = Exposure {
            exposure: 1704,
            gain: 40,
            dgain: 1.0,
        }
        .step(0.8, &lim);
        assert_eq!(down2.gain, 32);
        let down3 = Exposure {
            exposure: 1704,
            gain: 16,
            dgain: 1.0,
        }
        .step(0.8, &lim);
        assert_eq!(down3.exposure, 1363);
        let rgb = Exposure {
            exposure: 1030,
            gain: 0,
            dgain: 1.0,
        }
        .step(1.25, &RGB_LIMITS);
        assert_eq!(rgb.dgain, 1.25, "RGB has no analogue gain");
    }

    #[test]
    fn meter_reads_mean_and_clip() {
        let (w, h) = (100usize, 100usize);
        let mut px = vec![300u16; w * h];
        for v in px.iter_mut().take(w * h / 2) {
            *v = 1023;
        }
        let m = meter(
            &px,
            w,
            0,
            Window {
                x0: 0,
                y0: 0,
                x1: w,
                y1: h,
            },
        );
        assert!((m.clip - 0.5).abs() < 0.05, "{:?}", m);
        assert!(
            (m.mean - (0.5 * 1023.0 + 0.5 * 300.0) / 1023.0).abs() < 0.03,
            "{:?}",
            m
        );
    }

    #[test]
    fn percentile_never_zero() {
        assert_eq!(percentile(&[0u16; 100], 1, 0.005), 1);
        assert_eq!(percentile(&[1023u16; 100], 1, 0.995), 1023);
    }
}
