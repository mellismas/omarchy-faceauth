//! The standing refusal after a user says no. A request inside the spell
//! is refused without a window, so a refusal cannot be worn down by asking
//! again until a tired nod gets through.

use crate::auth::{Outcome, Refusal};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// After the user says no (a shake, a dismissal, a confirm that refused)
/// the no stands for a while, per user, whoever asks: sudo retries a failed
/// authentication three times from the same process, polkit asks again
/// through a fresh helper, and a program can run either again at once. A
/// request in that time is refused without a window, so a refusal cannot
/// be worn down by asking until a tired nod gets through (A5).
static REFUSALS: Mutex<Vec<(u32, Backoff)>> = Mutex::new(Vec::new());

/// The first refusal stands this long; each refusal that follows within
/// `BACKOFF_QUIET` of the last doubles it, up to `BACKOFF_MAX_DOUBLINGS`.
const BACKOFF: Duration = Duration::from_secs(60);
const BACKOFF_MAX_DOUBLINGS: u32 = 3;
const BACKOFF_QUIET: Duration = Duration::from_secs(600);

/// One user's standing refusal.
#[derive(Clone, Copy, Debug, Default)]
struct Backoff {
    until: Option<Instant>,
    /// When the last no was said.
    last: Option<Instant>,
    /// Doublings earned by repeated refusals.
    level: u32,
    /// The user has been told once for this spell.
    notified: bool,
}

impl Backoff {
    /// The user said no now: how long requests are refused for.
    fn refuse(&mut self, now: Instant) -> Duration {
        let repeat = self
            .last
            .is_some_and(|l| now.duration_since(l) < BACKOFF_QUIET);
        self.level = if repeat {
            (self.level + 1).min(BACKOFF_MAX_DOUBLINGS)
        } else {
            0
        };
        let length = BACKOFF * 2u32.pow(self.level);
        self.until = Some(now + length);
        self.last = Some(now);
        self.notified = false;
        length
    }

    /// How much longer the refusal stands, if it does.
    fn standing(&self, now: Instant) -> Option<Duration> {
        self.until
            .filter(|u| *u > now)
            .map(|u| u.saturating_duration_since(now))
    }
}

/// The refusal standing for this uid now, and whether this is the first
/// request refused by it (the one that gets a notice).
pub(super) fn refusal_standing(uid: u32, now: Instant) -> Option<(Duration, bool)> {
    let mut r = REFUSALS.lock().ok()?;
    r.retain(|(_, b)| {
        b.until.is_some_and(|u| u > now)
            || b.last
                .is_some_and(|l| now.duration_since(l) < BACKOFF_QUIET)
    });
    let (_, b) = r.iter_mut().find(|(u, _)| *u == uid)?;
    let left = b.standing(now)?;
    let first = !std::mem::replace(&mut b.notified, true);
    Some((left, first))
}

/// The user said no to a request of this uid's: start or lengthen the
/// standing refusal.
pub(super) fn refused(uid: u32, now: Instant) -> Duration {
    let Ok(mut r) = REFUSALS.lock() else {
        return Duration::ZERO;
    };
    if let Some((_, b)) = r.iter_mut().find(|(u, _)| *u == uid) {
        return b.refuse(now);
    }
    let mut b = Backoff::default();
    let d = b.refuse(now);
    r.push((uid, b));
    d
}

/// Was this the user saying no? A shake, a dismissal or a refused confirm;
/// not a timeout, a wrong password or a request that fell through.
pub(super) fn is_explicit_no(o: &Outcome) -> bool {
    match o {
        Outcome::Refused { reason, .. } | Outcome::ConsentDenied { reason, .. } => {
            Refusal::parse(reason).is_some_and(|r| r.is_explicit_no())
        }
        _ => false,
    }
}

#[cfg(test)]
mod backoff_tests {
    use super::*;

    /// A5: after the user says no, requests are refused without a window
    /// for a minute, whoever asks; repeats double it, up to a bound, and a
    /// quiet spell forgets the doubling.
    #[test]
    fn a_refusal_stands_for_a_minute_and_repeats_double_it() {
        let base = Instant::now();
        let t = |secs: u64| base + Duration::from_secs(secs);
        let mut b = Backoff::default();
        assert_eq!(b.standing(t(0)), None);
        assert_eq!(b.refuse(t(0)), Duration::from_secs(60));
        assert_eq!(
            b.standing(t(10)),
            Some(Duration::from_secs(50)),
            "a second requester, another pid, gets no window"
        );
        assert_eq!(b.standing(t(61)), None);
        assert_eq!(b.refuse(t(70)), Duration::from_secs(120));
        assert_eq!(b.refuse(t(200)), Duration::from_secs(240));
        assert_eq!(b.refuse(t(500)), Duration::from_secs(480));
        assert_eq!(
            b.refuse(t(1000)),
            Duration::from_secs(480),
            "the doubling is capped"
        );
        assert_eq!(
            b.refuse(t(1000 + 601)),
            Duration::from_secs(60),
            "ten quiet minutes forget the escalation"
        );
    }

    /// The per-uid table: one notice per spell, and only the user's own
    /// explicit no starts one.
    #[test]
    fn the_table_notifies_once_per_spell_and_reads_only_an_explicit_no() {
        let uid = 4_000_000_001u32;
        let now = Instant::now();
        assert!(refusal_standing(uid, now).is_none());
        refused(uid, now);
        assert_eq!(
            refusal_standing(uid, now).map(|(_, first)| first),
            Some(true)
        );
        assert_eq!(
            refusal_standing(uid, now).map(|(_, first)| first),
            Some(false)
        );
        assert!(
            refusal_standing(uid + 1, now).is_none(),
            "another user is not refused"
        );
        assert!(refusal_standing(uid, now + Duration::from_secs(61)).is_none());
        for (o, no) in [
            (
                Outcome::ConsentDenied {
                    reason: "shaken".into(),
                    elapsed_ms: 0,
                },
                true,
            ),
            (
                Outcome::Refused {
                    reason: "dismissed".into(),
                    elapsed_ms: 0,
                },
                true,
            ),
            (
                Outcome::ConsentDenied {
                    reason: "confirm: not live".into(),
                    elapsed_ms: 0,
                },
                true,
            ),
            (
                Outcome::ConsentDenied {
                    reason: "no answer".into(),
                    elapsed_ms: 0,
                },
                false,
            ),
            (
                Outcome::ConsentDenied {
                    reason: "wrong password".into(),
                    elapsed_ms: 0,
                },
                false,
            ),
            (
                Outcome::ConsentDenied {
                    reason: "refused a moment ago".into(),
                    elapsed_ms: 0,
                },
                false,
            ),
            (
                Outcome::Match {
                    score: None,
                    frames: 1,
                    elapsed_ms: 0,
                },
                false,
            ),
        ] {
            assert_eq!(is_explicit_no(&o), no, "{:?}", o);
        }
        if let Ok(mut r) = REFUSALS.lock() {
            r.retain(|(u, _)| *u != uid);
        }
    }
}
