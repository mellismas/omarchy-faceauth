//! The failure cooldown: five failed attempts in a minute earn a hold, and
//! each hold served without a match doubles the next. The lock screen and
//! the consent window share one record per user, so a print gets the same
//! tries on either lane.

use std::time::{Duration, Instant};

/// After this many failed attempts within the window, the user waits.
pub(super) const COOLDOWN_FAILURES: usize = 5;
const COOLDOWN_WINDOW: Duration = Duration::from_secs(60);
const COOLDOWN_HOLD: Duration = Duration::from_secs(30);
/// Each hold served without a match in between doubles the next, up to this
/// many doublings (30 s, 60 s, 120 s, 240 s, 480 s).
const COOLDOWN_MAX_DOUBLINGS: u32 = 4;
/// This long without a failure, and the escalation is forgotten.
const COOLDOWN_QUIET: Duration = Duration::from_secs(600);

/// A user's recent failures and the holds they have earned. A match clears
/// it. Shared by the lock-screen lane and the consent lane: a print held up
/// to either gets the same five tries and the same escalating holds.
#[derive(Default)]
pub struct Strikes {
    times: Vec<Instant>,
    last: Option<Instant>,
    /// The hold in force, if one is.
    until: Option<Instant>,
    /// Holds served since the last match (or the last quiet spell).
    holds: u32,
}

impl Strikes {
    pub(super) fn charge(&mut self, now: Instant) {
        if self.holds > 0
            && self
                .last
                .map(|l| now.duration_since(l) >= COOLDOWN_QUIET)
                .unwrap_or(true)
        {
            // A long quiet spell forgets the escalation, not the failure.
            self.holds = 0;
        }
        self.times.push(now);
        self.last = Some(now);
    }

    /// The hold in force, if any. The first hold takes `COOLDOWN_FAILURES`
    /// failures inside the window; once one has been served, every further
    /// failure starts the next hold at once, twice as long as the last, until
    /// a match or `COOLDOWN_QUIET` without a failure.
    pub(super) fn hold(&mut self, now: Instant) -> Option<Duration> {
        if let Some(u) = self.until {
            if now < u {
                return Some(u - now);
            }
            // Served. The failures are spent; the next one starts a longer hold.
            self.until = None;
            self.holds = self.holds.saturating_add(1);
            self.times.clear();
        }
        self.times
            .retain(|t| now.duration_since(*t) < COOLDOWN_WINDOW);
        let needed = if self.holds > 0 { 1 } else { COOLDOWN_FAILURES };
        if self.times.len() < needed {
            return None;
        }
        let last = self.times.last().copied().unwrap_or(now);
        let length = COOLDOWN_HOLD * 2u32.pow(self.holds.min(COOLDOWN_MAX_DOUBLINGS));
        let until = last + length;
        self.until = Some(until);
        self.times.clear();
        Some(until.saturating_duration_since(now))
    }
}

#[cfg(test)]
mod strikes_tests {
    use super::*;

    fn t(secs: u64) -> Instant {
        // A fixed origin far enough in the past that every test time is after it.
        static ORIGIN: std::sync::LazyLock<Instant> =
            std::sync::LazyLock::new(|| Instant::now() - Duration::from_secs(100_000));
        *ORIGIN + Duration::from_secs(secs)
    }

    #[test]
    fn five_failures_in_a_minute_start_a_hold() {
        let mut s = Strikes::default();
        for i in 0..4 {
            s.charge(t(i));
            assert_eq!(s.hold(t(i)), None, "four failures are free");
        }
        s.charge(t(4));
        let hold = s.hold(t(4)).expect("the fifth starts a hold");
        assert_eq!(hold, COOLDOWN_HOLD);
        assert_eq!(
            s.hold(t(4 + 10)),
            Some(COOLDOWN_HOLD - Duration::from_secs(10))
        );
    }

    #[test]
    fn each_served_hold_doubles_the_next() {
        let mut s = Strikes::default();
        for i in 0..5 {
            s.charge(t(i));
        }
        assert_eq!(s.hold(t(4)), Some(COOLDOWN_HOLD));
        // Served in full: free again, but the next failure is not a fresh budget.
        assert_eq!(s.hold(t(4 + 30)), None);
        s.charge(t(35));
        assert_eq!(
            s.hold(t(35)),
            Some(COOLDOWN_HOLD * 2),
            "one failure after a served hold starts the next, twice as long"
        );
        assert_eq!(s.hold(t(35 + 60)), None);
        s.charge(t(96));
        assert_eq!(s.hold(t(96)), Some(COOLDOWN_HOLD * 4));
        // Ten quiet minutes and the escalation is forgotten: five tries again.
        assert_eq!(s.hold(t(96 + 120)), None);
        s.charge(t(96 + 120 + 600));
        assert_eq!(s.hold(t(96 + 120 + 600)), None);
    }

    #[test]
    fn the_doubling_is_capped() {
        let mut s = Strikes {
            last: Some(t(0)),
            holds: 40,
            ..Default::default()
        };
        for i in 0..5 {
            s.charge(t(i));
        }
        assert_eq!(s.hold(t(4)), Some(COOLDOWN_HOLD * 16));
    }

    #[test]
    fn failures_older_than_the_window_do_not_count() {
        let mut s = Strikes::default();
        for i in 0..4 {
            s.charge(t(i));
        }
        s.charge(t(70));
        assert_eq!(
            s.hold(t(70)),
            None,
            "four of the five are over a minute old"
        );
    }
}
