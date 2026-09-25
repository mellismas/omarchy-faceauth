//! What an attempt or a consent request ends with, and why a request was
//! refused. A refusal becomes its wire string in one place, so no verdict
//! path depends on matching a string literal.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Outcome {
    /// Enough frames matched; `score` is the best. The score is only sent
    /// to root: to any other caller it is a tuning oracle for a spoof.
    Match {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        score: Option<f32>,
        frames: usize,
        elapsed_ms: u64,
    },
    /// A face was seen but did not match.
    NoMatch {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        score: Option<f32>,
        frames: usize,
        elapsed_ms: u64,
    },
    /// No usable face within the timeout.
    NoFace { elapsed_ms: u64 },
    /// The liveness gate refused: a presentation attack or a flat object.
    Denied { reason: String, elapsed_ms: u64 },
    /// Nothing enrolled for this user.
    NotEnrolled,
    /// Camera or model failure; the caller falls through to the next factor.
    Error { message: String },
    /// Answer to a presence probe: one short look, and never a score.
    Probe {
        face: bool,
        attentive: bool,
        face_px: f32,
        /// Near enough for an attempt to judge (`scannable`); the lock
        /// screen wakes the panel only for such a face.
        scannable: bool,
        /// Likely the asking user: a face near enough to judge whose best
        /// score against their templates on this look, taken without the
        /// flash, reached `PROBE_LIKELY_THRESHOLD`. The lock screen's filter
        /// before a full scan, never a decision. An older daemon's reply
        /// without it reads as true, as the lock screen reads it.
        #[serde(default = "likely_when_unsaid")]
        likely: bool,
        /// The lock screen's probe intervals, from `[unlock]`; the shipped
        /// ones when an older daemon's reply carries none.
        #[serde(default)]
        cadence: Cadence,
        elapsed_ms: u64,
    },
    /// Root only, development builds only: every frame of a pose sweep
    /// scored against the user's templates, with the head pose it was
    /// taken at.
    #[cfg(feature = "dev-tools")]
    Sweep {
        frames: Vec<SweepFrame>,
        templates: usize,
        elapsed_ms: u64,
    },
    /// Answer to a ping: the daemon is up and its models are loaded.
    Pong {
        version: String,
        model: String,
        templates: usize,
        /// Whether this user's templates rest sealed to the TPM.
        #[serde(default)]
        sealed: bool,
        /// The camera identities this user's templates are bound to
        /// (`IrCapture::identity`), sorted and deduplicated; `doctor`
        /// compares them with the live camera's identity.
        #[serde(default)]
        bound: Vec<String>,
        /// This user's gesture floors (nod, shake) in degrees, the ones the
        /// consent window runs at, once the walk-through has recorded them.
        #[serde(default)]
        floors: Option<(f32, f32)>,
        /// Why the templates could not be read, when they could not: a
        /// sealed blob this machine cannot open is not "not enrolled"
        /// (STORE-14).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        load_error: Option<String>,
    },
    /// Enrolment result.
    Enrolled {
        added: usize,
        total: usize,
        consistency_min: f32,
        consistency_mean: f32,
        path: String,
    },
    /// Templates deleted.
    Deleted,
    /// A polkit context was noted for the request the agent is serving.
    Noted,
    /// The presence watch's mode, whether the daemon watches this user,
    /// and, when it does, what the watch last decided (H16).
    PresenceMode {
        mode: String,
        watching: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        state: Option<crate::presence::State>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        away_for: Option<f32>,
    },
    /// Too many failed attempts for this user recently; try again later.
    Cooldown { seconds: u64 },
    /// The consent request ended without an answer that could count: no
    /// window to ask in, the requester gone, no answer inside a caller's
    /// budget. Not a decision; the module ignores it and the caller's stack
    /// falls to its password.
    ConsentDenied { reason: String, elapsed_ms: u64 },
    /// The user said no to a polkit request: a head shake, the window
    /// dismissed, or the confirm after the nods refused. The module fails
    /// the stack on it and the agent cancels the request, so no other prompt
    /// follows. A sudo request gets `ConsentDenied` for the same answer
    /// instead: sudo's terminal prompt is where a password goes next, and a
    /// failure there would only make sudo ask again, ten times.
    Refused { reason: String, elapsed_ms: u64 },
}

/// A probe reply without `likely` came from a daemon that does not compute
/// it; the lock screen then goes on to the full scan, so it reads as true.
fn likely_when_unsaid() -> bool {
    true
}

/// The lock screen's probe intervals in seconds, sent with every probe:
/// `ac` on mains, the others on battery for each power profile. The lock
/// screen picks one from its own power state.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct Cadence {
    pub ac: f32,
    pub performance: f32,
    pub balanced: f32,
    #[serde(rename = "power-saver")]
    pub power_saver: f32,
}

impl Cadence {
    pub fn from_config(u: &crate::config::UnlockConfig) -> Cadence {
        let b = &u.battery_probe_seconds;
        Cadence {
            ac: u.probe_seconds,
            performance: b.performance,
            balanced: b.balanced,
            power_saver: b.power_saver,
        }
    }
}

impl Default for Cadence {
    /// The shipped `[unlock]` intervals.
    fn default() -> Self {
        Cadence::from_config(&crate::config::UnlockConfig::default())
    }
}

impl Outcome {
    /// The outcome as an unprivileged caller may see it: without scores.
    pub fn redacted(self) -> Outcome {
        match self {
            Outcome::Match {
                frames, elapsed_ms, ..
            } => Outcome::Match {
                score: None,
                frames,
                elapsed_ms,
            },
            Outcome::NoMatch {
                frames, elapsed_ms, ..
            } => Outcome::NoMatch {
                score: None,
                frames,
                elapsed_ms,
            },
            #[cfg(feature = "dev-tools")]
            Outcome::Sweep {
                templates,
                elapsed_ms,
                ..
            } => Outcome::Sweep {
                frames: Vec::new(),
                templates,
                elapsed_ms,
            },
            o => o,
        }
    }
}

/// One frame of a pose sweep: when, the best cosine against the templates
/// and which one, and the head pose it was taken at (see `pose::Pose`).
#[cfg(feature = "dev-tools")]
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SweepFrame {
    pub t: f32,
    pub score: f32,
    pub template: usize,
    pub yaw: f32,
    pub pitch: f32,
    pub nose_pitch: f32,
    /// Sideways tilt, degrees.
    pub roll: f32,
    pub face_px: f32,
}

/// Why a consent request ended without an approval. One type inside the
/// daemon, turned into the wire `reason` string once, so a verdict path
/// is never picked by matching a string literal (H14). The strings are
/// what the window and the PAM module read and do not change.
#[derive(Clone, Debug, PartialEq)]
pub enum Refusal {
    /// Two head shakes.
    Shaken,
    /// The window's dismiss or kill button.
    Dismissed,
    /// The confirm after the nods refused, with its reason.
    Confirm(String),
    WrongPassword,
    NoAnswer,
    /// The requester hung up.
    Gone,
    /// The window could not be shown, or never acknowledged the request.
    NoWindow,
    /// The nod window ended without an approval.
    NoNod,
    /// No active graphical session to ask in.
    NoSession,
    /// Another user's request holds the window.
    OtherUser,
    /// This user already has the bound of requests waiting.
    TooMany,
    /// A refusal a moment ago still stands (A5).
    RefusedRecently,
}

impl Refusal {
    /// The `reason` the outcome carries on the wire.
    pub fn wire(&self) -> String {
        match self {
            Refusal::Shaken => "shaken".into(),
            Refusal::Dismissed => "dismissed".into(),
            Refusal::Confirm(why) => format!("confirm: {}", why),
            Refusal::WrongPassword => "wrong password".into(),
            Refusal::NoAnswer => "no answer".into(),
            Refusal::Gone => "requester gone".into(),
            Refusal::NoWindow => "the consent window did not open".into(),
            Refusal::NoNod => "no nod".into(),
            Refusal::NoSession => "no active graphical session to ask in".into(),
            Refusal::OtherUser => "another user's request is on screen".into(),
            Refusal::TooMany => "too many requests waiting".into(),
            Refusal::RefusedRecently => "refused a moment ago".into(),
        }
    }

    /// The refusal a wire `reason` names, if it is one of ours: the one
    /// place a string is read back.
    pub fn parse(reason: &str) -> Option<Refusal> {
        if let Some(why) = reason.strip_prefix("confirm: ") {
            return Some(Refusal::Confirm(why.to_string()));
        }
        Some(match reason {
            "shaken" => Refusal::Shaken,
            "dismissed" => Refusal::Dismissed,
            "wrong password" => Refusal::WrongPassword,
            "no answer" => Refusal::NoAnswer,
            "requester gone" => Refusal::Gone,
            "the consent window did not open" => Refusal::NoWindow,
            "no nod" => Refusal::NoNod,
            "no active graphical session to ask in" => Refusal::NoSession,
            "another user's request is on screen" => Refusal::OtherUser,
            "too many requests waiting" => Refusal::TooMany,
            "refused a moment ago" => Refusal::RefusedRecently,
            _ => return None,
        })
    }

    /// The user's own no (a shake, a dismissal, a confirm that refused):
    /// what starts the standing refusal (A5). Not a timeout, a wrong
    /// password or a request that fell through.
    pub fn is_explicit_no(&self) -> bool {
        matches!(
            self,
            Refusal::Shaken | Refusal::Dismissed | Refusal::Confirm(_)
        )
    }
}

/// A request that ended without a decision: the module ignores it and
/// the caller's stack falls to its password, on either lane.
pub fn consent_denied(why: Refusal, elapsed_ms: u64) -> Outcome {
    Outcome::ConsentDenied {
        reason: why.wire(),
        elapsed_ms,
    }
}

/// What the denied card says the user can do next: kill only when the
/// daemon named a requester it can kill (the window hides Kill otherwise),
/// and never "block", which is no control of the card's (I12).
pub fn denied_text(why: &str, caller: &crate::consent::CallerInfo) -> String {
    if caller.kill_pid > 0 {
        format!("{} Kill the requester, or dismiss.", why)
    } else {
        format!("{} Dismiss.", why)
    }
}

/// The user's no, as the caller's lane can take it: polkit gets a refusal
/// that ends the request; sudo gets a fall-through to its own prompt.
pub fn refused(caller: &crate::consent::CallerInfo, why: Refusal, elapsed_ms: u64) -> Outcome {
    if caller.via == "polkit" {
        Outcome::Refused {
            reason: why.wire(),
            elapsed_ms,
        }
    } else {
        consent_denied(why, elapsed_ms)
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::*;

    /// H14: each refusal maps to the wire string the window and the module
    /// expect, and back; only the user's own no starts a standing refusal.
    #[test]
    fn each_refusal_maps_to_its_wire_string_and_back() {
        let table = [
            (Refusal::Shaken, "shaken", true),
            (Refusal::Dismissed, "dismissed", true),
            (
                Refusal::Confirm("not live".into()),
                "confirm: not live",
                true,
            ),
            (Refusal::WrongPassword, "wrong password", false),
            (Refusal::NoAnswer, "no answer", false),
            (Refusal::Gone, "requester gone", false),
            (Refusal::NoWindow, "the consent window did not open", false),
            (Refusal::NoNod, "no nod", false),
            (
                Refusal::NoSession,
                "no active graphical session to ask in",
                false,
            ),
            (
                Refusal::OtherUser,
                "another user's request is on screen",
                false,
            ),
            (Refusal::TooMany, "too many requests waiting", false),
            (Refusal::RefusedRecently, "refused a moment ago", false),
        ];
        for (r, wire, no) in table {
            assert_eq!(r.wire(), wire);
            assert_eq!(Refusal::parse(wire), Some(r.clone()), "{}", wire);
            assert_eq!(r.is_explicit_no(), no, "{}", wire);
        }
        assert_eq!(Refusal::parse("something else"), None);
        let caller = crate::consent::CallerInfo {
            via: "polkit".into(),
            ..Default::default()
        };
        assert!(matches!(
            refused(&caller, Refusal::Shaken, 1),
            Outcome::Refused { .. }
        ));
        let sudo = crate::consent::CallerInfo {
            via: "sudo".into(),
            ..Default::default()
        };
        assert!(matches!(
            refused(&sudo, Refusal::Shaken, 1),
            Outcome::ConsentDenied { .. }
        ));
    }
}

#[cfg(test)]
mod denied_text_tests {
    use super::*;

    /// I12: the card offers Kill only for a named requester.
    #[test]
    fn the_denied_card_mentions_kill_only_for_a_named_requester() {
        let named = crate::consent::CallerInfo {
            kill_pid: 4242,
            verified: true,
            ..Default::default()
        };
        assert_eq!(
            denied_text("No answer. Refused.", &named),
            "No answer. Refused. Kill the requester, or dismiss."
        );
        let unnamed = crate::consent::CallerInfo::default();
        assert_eq!(denied_text("Refused.", &unnamed), "Refused. Dismiss.");
        assert!(!denied_text("Refused.", &unnamed).contains("block"));
    }
}
