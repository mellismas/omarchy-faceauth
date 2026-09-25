//! What passes between the daemon and the walk-through window: how the
//! setup script starts a session, and the one line per frame the window
//! draws from. Positions are in ring units the daemon computes, so the
//! window and the judgement agree.

use serde::{Deserialize, Serialize};

/// How the setup script starts a session: the label its templates carry
/// and the screen to begin at ("welcome" for a first enrolment, "distance"
/// for Add Look).
#[derive(Clone, Debug, Deserialize)]
pub struct Start {
    pub label: String,
    #[serde(default)]
    pub start_at: Option<String>,
}

/// One line of the stream the window draws from. Positions are in ring
/// units: 0 is the centre, 1 is the ring. The daemon does the mapping so
/// the window and the judgement agree.
#[derive(Clone, Debug, Serialize)]
pub struct Tick {
    /// "welcome", "centre", "path", "hold", "verify", "done", "failed".
    pub step: &'static str,
    /// For hold steps, the look the target sits at.
    pub zone: Option<&'static str>,
    pub face: bool,
    /// Face width as a fraction of the frame's shorter side, and what it says.
    pub size: f32,
    pub distance: &'static str,
    /// The dot: where the head points, relative to this person's centre.
    pub dot_x: f32,
    pub dot_y: f32,
    /// The target the dot should be in.
    pub target_x: f32,
    pub target_y: f32,
    /// The dot is within the target.
    pub on_target: bool,
    /// The readings behind the dot, for a development build's record only:
    /// the window draws none of them, and a per-frame head-pose stream to
    /// any same-uid watcher is not something the package sends (H23).
    #[cfg(feature = "dev-tools")]
    pub record: TickRecord,
    pub taken: usize,
    pub wanted: usize,
    pub message: String,
    /// For the gesture and everyday rounds: which round, of how many, the
    /// kind, the seconds left in it, whether it is still counting down to
    /// start, and for the reading round which text slot is showing.
    pub round: Option<&'static str>,
    pub round_no: usize,
    pub round_of: usize,
    pub seconds_left: f32,
    pub countdown: bool,
    pub read_slot: Option<usize>,
}

/// The smoothed readings, the raw ones, the mesh's pose and the face's
/// place in the frame (0..1), flattened into the tick in a development
/// build.
#[cfg(feature = "dev-tools")]
#[derive(Clone, Debug, Default, Serialize)]
pub struct TickRecord {
    pub yaw: f32,
    pub pitch: f32,
    pub roll: f32,
    pub raw_yaw: f32,
    pub raw_pitch: f32,
    /// The nose-based tilt, for comparison; `pitch` is the mouth-based one.
    pub nose_pitch: f32,
    /// The dense mesh's head pose in degrees.
    pub mesh_yaw: Option<f32>,
    pub mesh_pitch: Option<f32>,
    pub mesh_roll: Option<f32>,
    pub mesh_score: Option<f32>,
    pub x: f32,
    pub y: f32,
    /// This person's centre, once learned.
    pub centre_yaw: f32,
    pub level: f32,
}

impl Tick {
    pub(super) fn blank(step: &'static str, message: &str) -> Tick {
        Tick {
            step,
            zone: None,
            face: false,
            size: 0.0,
            distance: "far",
            dot_x: 0.0,
            dot_y: 0.0,
            target_x: 0.0,
            target_y: 0.0,
            on_target: false,
            #[cfg(feature = "dev-tools")]
            record: TickRecord {
                x: 0.5,
                y: 0.5,
                ..Default::default()
            },
            taken: 0,
            wanted: 0,
            message: message.into(),
            round: None,
            round_no: 0,
            round_of: 0,
            seconds_left: 0.0,
            countdown: false,
            read_slot: None,
        }
    }
}

#[cfg(test)]
mod tick_tests {
    use super::Tick;

    /// H23: the stream carries exactly the fields Enrol.qml reads (its
    /// `onRead` parser), and nothing per-frame that the window never draws.
    /// A development build adds the `record` block for tuning.
    #[test]
    fn the_tick_serialises_the_fields_the_window_reads() {
        let tick = Tick::blank("welcome", "hello");
        let v: serde_json::Value = serde_json::to_value(&tick).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(|k| k.as_str()).collect();
        keys.sort_unstable();
        let mut window_reads = vec![
            "step",
            "zone",
            "face",
            "size",
            "distance",
            "dot_x",
            "dot_y",
            "target_x",
            "target_y",
            "on_target",
            "taken",
            "wanted",
            "message",
            "round",
            "round_no",
            "round_of",
            "seconds_left",
            "countdown",
            "read_slot",
        ];
        if cfg!(feature = "dev-tools") {
            window_reads.push("record");
        }
        window_reads.sort_unstable();
        assert_eq!(keys, window_reads);
    }
}
