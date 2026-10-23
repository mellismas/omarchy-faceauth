//! The numbers that were measured on one camera model, gathered in one
//! place. The liveness thresholds, the face sizes and the exposure the
//! camera starts at all depend on the sensor, its illuminator, its lens and
//! how it is mounted, and every one of them was measured on the reference
//! machine (a Surface Book 2's ov7251 behind IPU3). A second camera model
//! gets its own profile from its own measurements, never these numbers
//! reused. Until one exists the daemon's constants read this profile, and
//! the comments on those constants keep the runs they came from.

/// What was measured on one camera model.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CameraProfile {
    /// Which camera these numbers were measured on.
    pub name: &'static str,
    /// Face width the reflectance was calibrated at, in pixels of the
    /// oriented frame (`liveness::REFERENCE_FACE_PX`).
    pub reference_face_px: f32,
    /// Normalized reflectance above this is not skin
    /// (`liveness::REFLECTANCE_DENY`).
    pub reflectance_deny: f32,
    /// Surround-to-face flash ratio above this is a flat object
    /// (`liveness::SURROUND_DENY`).
    pub surround_deny: f32,
    /// Below this flash response a pair carries no signal
    /// (`liveness::MIN_FACE_FLASH`).
    pub min_face_flash: f32,
    /// More of the face clipped than this, and the reflectance cannot be
    /// read (`liveness::MAX_CLIPPED`).
    pub max_clipped: f32,
    /// A lit frame is at least this much brighter than the one before it
    /// (`liveness::LIT_STEP`).
    pub lit_step: f64,
    /// A step up counts as off the mask only at this ratio or more
    /// (`liveness::OFF_MASK_STEP`).
    pub off_mask_step: f64,
    /// The narrowest face an attempt scores, as a fraction of the frame's
    /// shorter side (the daemon's `SCAN_MIN_FACE_FRAC`).
    pub scan_min_face_frac: f32,
    /// The face widths, as fractions of the frame's shorter side, that read
    /// as the right distance in enrollment (the daemon's `SIZE_RIGHT`).
    pub size_right: (f32, f32),
    /// The exposure a camera opens at with nothing remembered, in the
    /// sensor's own units (ov7251 lines).
    pub start_exposure: i64,
    /// Frame orientation as mounted: transpose, flip x, flip y.
    pub orientation: [bool; 3],
}

/// The reference machine: a Surface Book 2's ov7251 IR sensor behind IPU3,
/// 640x480, with the strobe patches. Every number here was measured on it.
pub const OV7251_SURFACE_BOOK_2: CameraProfile = CameraProfile {
    name: "ov7251 on IPU3 (Surface Book 2)",
    reference_face_px: 87.0,
    reflectance_deny: 0.80,
    surround_deny: 0.42,
    min_face_flash: 4.0,
    max_clipped: 0.20,
    lit_step: 1.15,
    off_mask_step: 1.28,
    scan_min_face_frac: 0.084,
    size_right: (0.14, 0.24),
    start_exposure: 500,
    orientation: [true, true, true],
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference profile holds the numbers measured on the reference
    /// machine, and the liveness constants read it. A change to any of them
    /// is a re-measurement, recorded with its runs, not an edit here.
    #[test]
    fn the_reference_profile_holds_the_measured_numbers() {
        let p = OV7251_SURFACE_BOOK_2;
        assert_eq!(p.reference_face_px, 87.0);
        assert_eq!(p.reflectance_deny, 0.80);
        assert_eq!(p.surround_deny, 0.42);
        assert_eq!(p.min_face_flash, 4.0);
        assert_eq!(p.max_clipped, 0.20);
        assert_eq!(p.lit_step, 1.15);
        assert_eq!(p.off_mask_step, 1.28);
        assert_eq!(p.scan_min_face_frac, 0.084);
        assert_eq!(p.size_right, (0.14, 0.24));
        assert_eq!(p.start_exposure, 500);
        assert_eq!(p.orientation, [true, true, true]);
        assert_eq!(crate::liveness::REFLECTANCE_DENY, p.reflectance_deny);
        assert_eq!(crate::liveness::OFF_MASK_STEP, p.off_mask_step);
    }
}
