//! What the camera can prove about a face, decided in one place: its
//! liveness tier, read from the hardware alone and never from a setting,
//! and what that tier lets each lane do. Every lane that authenticates,
//! enrolls or watches asks here instead of reading the illuminator and
//! `liveness_required` on its own, so the rule cannot differ between them;
//! the walk-away watch once did (E4). A lower tier is the camera's limit,
//! and the user is told which one they have (`faceauth doctor`).

use std::sync::atomic::{AtomicU8, Ordering};

/// The camera's liveness tier, from what its illuminator can do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    /// The sensor follows a random flash pattern the daemon picks, frame by
    /// frame (the ov7251 with its strobe controls): the full flash-response
    /// gate runs on every look.
    RandomFlash,
    /// No flash control the daemon can drive: the gate cannot run.
    NoFlash,
}

impl Tier {
    /// The tier of a camera with (`true`) or without the strobe controls.
    pub fn of(strobe: bool) -> Tier {
        if strobe {
            Tier::RandomFlash
        } else {
            Tier::NoFlash
        }
    }

    /// Whether the flash gate runs on this camera.
    pub fn gated(self) -> bool {
        self == Tier::RandomFlash
    }

    /// Whether the secure walk-away mode is offered: its promise, that only
    /// the user's own face holds the clock, rests on gating every look.
    pub fn secure_available(self) -> bool {
        self.gated()
    }

    /// The tier in plain words, for `faceauth doctor` and setup.
    pub fn describe(self) -> &'static str {
        match self {
            Tier::RandomFlash => "random IR flash: every look is checked for a live face",
            Tier::NoFlash => "no IR flash control: nothing checks for a live face, so the secure walk-away mode is not available",
        }
    }
}

/// What a lane that authenticates or enrolls may do on a camera.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// The flash gate runs.
    Run,
    /// The gate cannot run and the administrator has accepted that with
    /// `liveness_required = false`: the lane runs ungated.
    Ungated,
    /// The gate cannot run and it is required (the default): the lane
    /// refuses, with `NO_GATE`.
    Refuse,
}

/// Why a lane refuses on a camera the gate cannot run on.
pub const NO_GATE: &str =
    "liveness gate unavailable (no strobe control) and liveness_required is set";

/// The one rule: the gate runs wherever the camera can run it, with no
/// switch for it (H15); where it cannot, the lane refuses unless the
/// administrator explicitly accepted ungated authentication.
pub fn gate(tier: Tier, liveness_required: bool) -> Gate {
    if tier.gated() {
        Gate::Run
    } else if liveness_required {
        Gate::Refuse
    } else {
        Gate::Ungated
    }
}

/// The tier of the last camera opened: 0 before any open, then 1 + the
/// tier's index. The presence mode switch answers from statics and never
/// opens the camera, so it reads this.
static SEEN: AtomicU8 = AtomicU8::new(0);

/// Note the tier of a camera just opened.
pub(crate) fn note(tier: Tier) {
    SEEN.store(
        match tier {
            Tier::RandomFlash => 1,
            Tier::NoFlash => 2,
        },
        Ordering::SeqCst,
    );
}

/// The tier of the last camera opened; None before the first open.
pub fn seen() -> Option<Tier> {
    match SEEN.load(Ordering::SeqCst) {
        1 => Some(Tier::RandomFlash),
        2 => Some(Tier::NoFlash),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate runs wherever the camera can run it, whatever the setting;
    /// where it cannot, the setting decides between refusing and running
    /// ungated, and refusing is the default.
    #[test]
    fn the_gate_runs_wherever_the_camera_can_run_it() {
        for required in [true, false] {
            assert_eq!(gate(Tier::RandomFlash, required), Gate::Run);
        }
        assert_eq!(gate(Tier::NoFlash, true), Gate::Refuse);
        assert_eq!(gate(Tier::NoFlash, false), Gate::Ungated);
        assert!(crate::config::Config::default().liveness_required);
    }

    /// The tier follows the strobe controls, and only the full tier offers
    /// the secure walk-away mode; the plain words say what a lower tier
    /// gives up.
    #[test]
    fn the_tier_follows_the_hardware() {
        assert_eq!(Tier::of(true), Tier::RandomFlash);
        assert_eq!(Tier::of(false), Tier::NoFlash);
        assert!(Tier::RandomFlash.secure_available());
        assert!(!Tier::NoFlash.secure_available());
        assert!(Tier::NoFlash.describe().contains("live face"));
        assert!(Tier::NoFlash.describe().contains("secure walk-away mode"));
    }
}
