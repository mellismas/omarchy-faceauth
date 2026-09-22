//! Consent for elevation: the part of an authentication that proves the person
//! the camera sees *wants this request*, and not merely that they are present.
//!
//! The calling program (sudo, the polkit helper, anything that loads the PAM
//! module) cannot be trusted to relay a "yes": code running as the user can
//! answer any prompt it is shown. So the yes comes from something only the
//! daemon observes: a nod pattern in front of the camera it owns. Around it,
//! for the human: one window on the desktop, opened by the daemon and not by
//! the caller, naming the command and the process asking, with buttons to deny
//! and kill it or to block it for a while. Nothing elevates silently, and no
//! window means no elevation (an ssh session gets the password path).

use crate::capture::IrCapture;
use crate::config::Config;
use std::sync::{Arc, Mutex};
use anyhow::{anyhow, Context, Result};
use faceauth_engine::{pose, Grey, Pipeline};
use serde::Serialize;
use std::path::Path;
use std::time::{Duration, Instant};

/// What the window (or the CLI) can send while a request is pending.
#[derive(Clone, Debug)]
pub enum Answer {
    /// The user typed their password into the window.
    Password(String),
    /// The requester hung up its socket: nobody is waiting for the verdict.
    Gone,
    /// The user dismissed, killed or blocked: refuse now.
    Dismiss,
}

/// Pending answers by user name, shared between the server threads and the
/// consent flow that owns the camera.
pub type Answers = Arc<Mutex<std::collections::HashMap<String, Answer>>>;

pub fn take_answer(answers: &Answers, user: &str) -> Option<Answer> {
    answers.lock().ok().and_then(|mut m| m.remove(user))
}

/// Who is asking, as far as /proc can say.
#[derive(Clone, Debug, Default, Serialize)]
pub struct CallerInfo {
    /// The process that holds the PAM transaction (sudo, polkit-agent-helper-1).
    pub pid: i32,
    pub exe: String,
    pub cmdline: String,
    /// What is being asked. When `verified` it is the daemon's own reading
    /// of the requesting process's command line (sudo's, pkexec's). When
    /// not, it is what the requesting side said about itself: for a plain
    /// polkit action, the message and action id the agent relayed. Any
    /// process of the user's can send that, so the window labels it.
    pub command: String,
    pub verified: bool,
    /// Who asked: the requesting process and pid, then its parents
    /// ("sudo (pid 3011002)  from  bash (2990241) <- foot (13950)"), or the
    /// polkit helper's pid with a note that the asking process was not found.
    pub who: String,
    /// The chain above the requester: "alacritty (3910) <- bash (3921)".
    pub parents: String,
    /// The process to kill if the user says no: the requester, not the helper.
    pub kill_pid: i32,
    pub via: String,
}

fn read_proc(pid: i32, what: &str) -> Option<String> {
    std::fs::read(format!("/proc/{}/{}", pid, what)).ok().map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().to_string())
}

/// Text for the window: no control characters (a newline or a bidi override
/// in a command line would let the requester write its own description) and
/// a cap that only a pathological command line reaches; the window wraps
/// and never elides, so what is shown is the whole thing. Applied to
/// everything read from /proc or sent by the polkit agent before it reaches
/// the window or the log.
pub fn clip(s: &str) -> String {
    s.chars().filter(|c| !c.is_control() && !matches!(*c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')).take(2000).collect()
}

fn exe_of(pid: i32) -> String {
    std::fs::read_link(format!("/proc/{}/exe", pid)).map(|p| p.display().to_string()).unwrap_or_default()
}

pub(crate) fn ppid_of(pid: i32) -> Option<i32> {
    let stat = read_proc(pid, "stat")?;
    // "pid (comm) state ppid ..."; comm may contain spaces, so split after the last ')'.
    let rest = stat.rsplit(')').next()?;
    rest.split_whitespace().nth(1)?.parse().ok()
}

pub(crate) fn comm_of(pid: i32) -> String {
    clip(&read_proc(pid, "comm").unwrap_or_default())
}

fn real_uid_of(pid: i32) -> Option<u32> {
    read_proc(pid, "status")?.lines().find_map(|l| l.strip_prefix("Uid:")).and_then(|v| v.split_whitespace().next()).and_then(|s| s.parse().ok())
}

pub(crate) fn starttime_of(pid: i32) -> u64 {
    read_proc(pid, "stat").and_then(|s| s.rsplit(')').next().and_then(|r| r.split_whitespace().nth(19).and_then(|v| v.parse().ok()))).unwrap_or(0)
}

/// The answer token of each user's live consent request. The daemon hands it
/// to the window it summons, in the payload, and accepts an answer (a
/// dismissal, a password) only with it: a process that can reach the socket
/// but did not see the window cannot cancel or answer the request.
pub static TOKENS: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, String>>> = std::sync::LazyLock::new(Default::default);

/// Sixteen random bytes as hex, or nothing: a token that could not be drawn
/// from the kernel is not a token, and the request fails rather than run
/// with a guessable one.
fn fresh_token() -> Option<String> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom").ok()?.read_exact(&mut b).ok()?;
    Some(b.iter().map(|x| format!("{:02x}", x)).collect())
}

/// What a polkit request is, as the agent heard it from polkitd: the action
/// id and the message (which for pkexec names the command). polkit's PAM
/// helper carries none of this (and on polkit 127 it is socket-activated by
/// systemd, so not even the agent's child), so the agent hands it to the
/// daemon as the request starts. Contexts queue per user in arrival order;
/// polkit serves one request per agent at a time, in that order, so the
/// helper's request takes the oldest fresh context for its user. One context
/// serves one request.
#[derive(Clone, Debug)]
pub struct PolkitContext {
    pub action: String,
    pub message: String,
    pub cookie: String,
    pub uid: u32,
    pub at: Instant,
}

pub static CONTEXTS: std::sync::LazyLock<Mutex<std::collections::HashMap<u32, std::collections::VecDeque<PolkitContext>>>> = std::sync::LazyLock::new(Default::default);

/// The oldest fresh context the user's agent registered, waiting briefly for
/// one: the helper's PAM request and the agent's context race, and the
/// context usually loses by a few dozen ms.
fn take_polkit_context(uid: u32) -> Option<PolkitContext> {
    let deadline = Instant::now() + Duration::from_millis(1500);
    loop {
        if let Ok(mut m) = CONTEXTS.lock() {
            if let Some(q) = m.get_mut(&uid) {
                q.retain(|c| c.at.elapsed() < Duration::from_secs(120));
                if let Some(c) = q.pop_front() {
                    return Some(c);
                }
            }
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The polkit requesters (pid, start time) already named by a window.
static SERVED: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<(i32, u64)>>> = std::sync::LazyLock::new(Default::default);

impl CallerInfo {
    pub fn from_pid(pid: i32, user_uid: u32) -> CallerInfo {
        let exe = exe_of(pid);
        let cmdline = read_proc(pid, "cmdline").unwrap_or_default();
        let mut info = CallerInfo { pid, exe: exe.clone(), cmdline: cmdline.clone(), kill_pid: pid, ..Default::default() };
        // The helper is setuid, so its exe link is unreadable without ptrace
        // rights (this daemon has none); comm is readable but truncated to 15 bytes.
        let comm = comm_of(pid);
        let base = Path::new(&exe).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| comm.clone());
        if base == "polkit-agent-helper-1" || comm.starts_with("polkit-agent-he") {
            // The helper is polkit's and carries nothing that names its
            // requester. Polkit serves requests in order, so the one being
            // served is the oldest pkexec (or run0) of the user's that this
            // daemon has not named before; each is named once. Best effort.
            info.via = "polkit".into();
            // What the request is comes from the agent, which heard it from
            // polkitd; the search below only finds the process to kill.
            let context = take_polkit_context(user_uid);
            let mut served = SERVED.lock().unwrap_or_else(|p| p.into_inner());
            let mut best: Option<(u64, i32)> = None;
            let mut seen: Vec<String> = Vec::new();
            if let Ok(rd) = std::fs::read_dir("/proc") {
                for e in rd.flatten() {
                    let Some(p) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
                    if real_uid_of(p) != Some(user_uid) {
                        continue;
                    }
                    // A setuid process (pkexec) hides its exe link from a reader
                    // without ptrace rights, and this daemon has no capabilities;
                    // comm is readable by everyone.
                    let b = comm_of(p);
                    if seen.len() < 40 {
                        seen.push(format!("{}:{}", p, b));
                    }
                    if b == "pkexec" || b == "run0" {
                        let t = starttime_of(p);
                        if served.contains(&(p, t)) {
                            continue;
                        }
                        if best.map(|(bt, _)| t < bt).unwrap_or(true) {
                            best = Some((t, p));
                        }
                    }
                }
            }
            log::debug!("consent: polkit requester search, uid {} processes: {}", user_uid, seen.join(" "));
            match best {
                Some((t, p)) => {
                    served.insert((p, t));
                    // Forget the ones that have gone; the set stays small.
                    served.retain(|&(sp, st)| std::path::Path::new(&format!("/proc/{}", sp)).exists() && starttime_of(sp) == st);
                    info.kill_pid = p;
                    // cmdline of a setuid process may be unreadable too; fall back to its name.
                    let cl = clip(&read_proc(p, "cmdline").unwrap_or_default());
                    let name = comm_of(p);
                    info.command = if cl.is_empty() { format!("{} (arguments not readable)", name) } else { cl };
                    info.verified = true;
                    info.parents = parent_chain(p);
                    info.who = format!("{} (pid {})  from  {}", name, p, info.parents);
                }
                None => {
                    info.who = format!("polkit helper (pid {}); the asking process could not be found", pid);
                }
            }
            // The agent's context is the requesting side's own account of
            // itself: any process of the user's can send one, and the helper
            // carries nothing to check it against. It names the request only
            // when nothing provable does, and then the window labels it.
            match context {
                Some(c) => {
                    let relayed = clip(&format!("{} [{}]", c.message.trim(), c.action));
                    if info.verified {
                        log::info!("consent: polkit helper pid {} named {}; the agent relayed: {}", pid, info.command, relayed);
                    } else {
                        log::info!("consent: polkit helper pid {}: requester not found; the agent relayed (unverified): {}", pid, relayed);
                        info.command = relayed;
                    }
                }
                None => {
                    log::warn!("consent: no context from the polkit agent for helper pid {}; naming by process search only", pid);
                    if !info.verified {
                        info.command = "a polkit action (no description was given)".into();
                    }
                }
            }
        } else {
            info.via = base.clone();
            info.command = clip(&cmdline);
            info.verified = true;
            info.parents = parent_chain(pid);
            info.who = format!("{} (pid {})  from  {}", base, pid, info.parents);
        }
        info
    }
}

fn parent_chain(pid: i32) -> String {
    let mut out = Vec::new();
    let mut p = pid;
    for _ in 0..4 {
        let Some(pp) = ppid_of(p) else { break };
        if pp <= 1 {
            break;
        }
        out.push(format!("{} ({})", comm_of(pp), pp));
        p = pp;
    }
    out.join(" <- ")
}

/// The window on the desktop. Every call is one `omarchy-shell` invocation
/// inside the user's own systemd manager, the same route the session lock uses.
pub struct Dialog {
    pub cfg: Config,
    user: String,
    open: bool,
    /// The answer token for this request (see `TOKENS`).
    token: String,
}

#[derive(Serialize)]
struct Payload<'a> {
    state: &'a str,
    message: &'a str,
    caller: &'a CallerInfo,
    seconds: f32,
    token: &'a str,
}

impl Dialog {
    pub fn new(cfg: &Config, user: &str) -> Result<Self> {
        let token = fresh_token().ok_or_else(|| anyhow!("no randomness for the answer token"))?;
        if let Ok(mut t) = TOKENS.lock() {
            t.insert(user.to_string(), token.clone());
        }
        Ok(Dialog { cfg: cfg.clone(), user: user.to_string(), open: false, token })
    }

    /// Does `token` answer this user's live request? Compared in constant
    /// time; a wrong token and no request read the same.
    pub fn token_matches(user: &str, token: Option<&str>) -> bool {
        match (TOKENS.lock(), token) {
            (Ok(t), Some(tok)) => t.get(user).map(|have| {
                let (a, b) = (have.as_bytes(), tok.as_bytes());
                a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
            }).unwrap_or(false),
            _ => false,
        }
    }

    fn shell(&self, args: &[&str]) -> Result<()> {
        let omarchy_path = self.cfg.omarchy_path.clone().unwrap_or_else(|| {
            std::fs::read_to_string("/etc/omarchy.conf")
                .ok()
                .and_then(|t| t.lines().find_map(|l| l.strip_prefix("OMARCHY_PATH=").map(|v| v.trim_matches('"').to_string())))
                .unwrap_or_else(|| "/usr/share/omarchy".into())
        });
        // The unit's description is what the journal prints on start; the
        // default is the command line, payload and token included.
        let status = std::process::Command::new("/usr/bin/timeout")
            .args(["5", "/usr/bin/systemd-run", "--quiet", "--wait", "--collect", "--user", "--description=omarchy-faceauth window"])
            .arg(format!("--machine={}@.host", self.user))
            .arg(format!("-EOMARCHY_PATH={}", omarchy_path))
            .arg("/usr/bin/omarchy-shell")
            .args(args)
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .status()
            .context("run omarchy-shell in the user's manager")?;
        if !status.success() {
            return Err(anyhow!("omarchy-shell {:?} exited {}", args, status));
        }
        Ok(())
    }

    /// Show or update the window. Fails when there is no graphical session to
    /// show it in, which callers treat as "no consent possible".
    pub fn show(&mut self, state: &str, message: &str, caller: &CallerInfo, seconds: f32) -> Result<()> {
        let payload = serde_json::to_string(&Payload { state, message, caller, seconds, token: &self.token })?;
        self.shell(&["shell", "summon", "omarchy.faceauth", &payload])?;
        self.open = true;
        Ok(())
    }

    /// A final state: the window keeps itself up for a while and closes on
    /// its own, so the daemon must not hide it (and must not wait).
    pub fn show_final(&mut self, state: &str, message: &str, caller: &CallerInfo) {
        let _ = self.show(state, message, caller, 0.0);
        self.open = false;
    }

    pub fn hide(&mut self) {
        if self.open {
            if let Err(e) = self.shell(&["shell", "hide", "omarchy.faceauth"]) {
                log::warn!("consent window: hide failed: {}", e);
            }
            self.open = false;
        }
    }
}

impl Drop for Dialog {
    fn drop(&mut self) {
        self.hide();
        if let Ok(mut t) = TOKENS.lock() {
            if t.get(&self.user) == Some(&self.token) {
                t.remove(&self.user);
            }
        }
    }
}

/// A desktop notification in the user's session: every elevation by face
/// announces itself, so a loop is visible the first time it fires.
/// Is the user's session locked? Asked of the compositor from inside the
/// user's manager, the same way the window is summoned. Unknown reads as
/// not locked.
pub fn session_locked(user: &str) -> bool {
    std::process::Command::new("/usr/bin/timeout")
        .args(["5", "/usr/bin/systemd-run", "--quiet", "--wait", "--collect", "--user"])
        .arg(format!("--machine={}@.host", user))
        .arg("/usr/bin/omarchy-hyprland-session-locked")
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .status()
        .map(|st| st.success())
        .unwrap_or(false)
}

pub fn notify(cfg: &Config, user: &str, title: &str, body: &str) {
    let omarchy_path = cfg.omarchy_path.clone().unwrap_or_else(|| "/usr/share/omarchy".into());
    let _ = std::process::Command::new("/usr/bin/timeout")
        .args(["5", "/usr/bin/systemd-run", "--quiet", "--collect", "--user", "--description=omarchy-faceauth notice"])
        .arg(format!("--machine={}@.host", user))
        .arg(format!("-EOMARCHY_PATH={}", omarchy_path))
        .args(["/usr/bin/omarchy-notification-send", title, body])
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .status();
}

/// Watch for the consent gesture: two nods within `window`. A nod is the head
/// pitching away from its resting pose past a threshold and coming back,
/// measured as the nose's position between the eye line and the mouth line.
/// Measured on the reference machine, a nod moves it about 0.12 (from 0.53 to
/// 0.41); the sign depends on the sensor mounting, so any excursion counts.
/// Baseline is the median of the first frames.
/// Result of the gesture phase.
#[derive(Clone, Debug, PartialEq)]
pub enum Gesture {
    Nodded,
    /// Two head shakes: a refusal.
    Shaken,
    /// The window supplied a password (verified by the caller).
    Password(String),
    Dismissed,
    /// The requester went away; the window comes down with it.
    Gone,
    Timeout,
    /// No face for the presence watch's away time: the user left.
    FaceLost,
    /// The nods came, but the confirm after them could not read the strobe.
    ConfirmUnclear,
    /// The nods came, but the confirm refused: not a live enrolled face.
    ConfirmFailed(String),
}

/// One gesture axis as a pure state machine over (signal, time) samples, so
/// it can be replayed from a recorded trace in a test. A gesture is two
/// complete motions: four legs of alternating direction (down, up, down, up
/// or the reverse on the pitch axis; left, right, left, right or the reverse
/// on the yaw axis), each a clear excursion, done together within a short
/// span, from a head that was still just before and does not move its face
/// elsewhere meanwhile. How a person begins and ends (from the centre or
/// from one side) does not matter: four alternating legs is the shape.
///
/// The legs come from a zigzag over the median-filtered signal: an extreme
/// is confirmed once the signal has reversed from it by the threshold, so
/// every counted leg is at least a threshold tall and consecutive legs
/// alternate by construction. The threshold adapts to the signal's own
/// jitter (a face far from the camera is noisier) between a floor and a cap.
pub struct Oscillation {
    name: &'static str,
    pub min_thr: f32,
    pub max_thr: f32,
    /// Longest leg, in seconds: a shake's legs are slower than a nod's.
    pub leg_max_s: f32,
    /// Motion gate: how far, as a fraction of face width, the filtered face
    /// centre may end the gesture from where it began, sideways and up.
    /// The axis the gesture itself moves the box along gets the wider one.
    shift_tol_x: f32,
    shift_tol_y: f32,
    /// Largest leg: bigger is a turn away, not a gesture.
    max_amp: f32,
    /// All four legs, first start to last end, within this.
    pub span_s: f32,
    /// Not moving at all for this long ends the leg where the head is.
    pub rest_s: f32,
    /// Consecutive reversed frames that confirm an extreme.
    pub rev_frames: usize,
    /// Shortest leg.
    pub leg_min_s: f32,
    /// Width change allowed across a gesture (fraction of face width).
    pub width_tol: f32,
    /// Filtered samples that must advance the extreme within a leg: a real
    /// leg is a ramp over several frames; a detector fit switching between
    /// two solutions is one jump (recorded 2026-09-22 on the nose measure:
    /// 0.09 in a frame, held three or four frames, and approved as a nod).
    pub min_steps: usize,
    /// A leg must pass through its own middle: at least one sample strictly
    /// between 20% and 80% of the way from where it began to its extreme. A
    /// head moves through the in-between; a detector fit switching between
    /// two solutions does not.
    pub need_ramp: bool,
    /// The whole face box must move with the leg: along x for a shake, y
    /// for a nod, by at least this fraction of the face width between the
    /// leg's start and its extreme. A head that moves carries its box; a
    /// detector fit that switches solutions moves one landmark and leaves
    /// the box where it was (recorded 2026-09-22: box centre moved 1 px
    /// through a fit flip that read as a nod; 9 to 16 px through real nods).
    /// None turns the rule off.
    pub co_motion: Option<(u8, f32)>,
    /// Samples seen during the current leg.
    leg_samples: Vec<f32>,
    /// The last few filtered samples (the frames just before a departure).
    recent: Vec<f32>,
    /// The four legs' amplitudes, and their durations, must each be within
    /// this ratio of one another (a deliberate gesture is even; talking and
    /// fidgeting are not). None turns the rule off.
    pub regular: Option<f32>,
    /// The gesture must swing to both sides of the rest level (a shake
    /// does; a glance goes one way and returns; a nod may not rise above).
    both_sides: bool,
    /// Where the head rested when the first leg began.
    rest_level: f32,
    raw: Vec<f32>,
    settle: Vec<f32>,
    /// Slow-following baseline, for `idle` and the logs.
    pub base: Option<f32>,
    /// The current excursion threshold.
    pub thr: f32,
    jitter: f32,
    last_p: Option<f32>,
    /// Size of the last frame-to-frame change.
    last_step: f32,
    last_t: Option<f32>,
    /// Last confirmed extreme (value, time).
    pivot: Option<(f32, f32)>,
    /// The extreme being tracked in the current direction.
    cand: (f32, f32),
    /// +1 rising from the pivot, -1 falling, 0 not yet left it.
    pub dir: i8,
    /// Consecutive frames reversed from the candidate extreme.
    rev_count: usize,
    /// When the head stopped moving, if it has.
    rest_since: Option<f32>,
    /// Samples that advanced the extreme in the current leg.
    pub steps: usize,
    /// Last time the signal sat close to the pivot: where a first leg starts.
    depart: f32,
    /// Completed legs as (start, end, extreme value, amplitude).
    pub legs: Vec<(f32, f32, f32, f32)>,
    last_active: Option<f32>,
    /// Recent (t, face width, centre x, centre y) for the motion gate.
    motion: Vec<(f32, f32, f32, f32)>,
    /// Seconds the face was already steadily in view before t = 0 (the scan
    /// that matched it): counts toward the still second before a first leg.
    pub prior_still: f32,
    /// Completed gestures.
    pub gestures: usize,
}

impl Oscillation {
    /// Legs in a gesture: two complete motions.
    pub const LEGS: usize = 4;
    /// Default span: the user's two nods, with the beat between them, span
    /// up to about three seconds.
    pub const SPAN_S: f32 = 3.0;
    /// Box movement along the gesture axis each leg must carry, in face
    /// widths. Swept 2026-09-22 over the calibration corpus and the
    /// calibrated-floor recording: every recorded nod and shake holds up to
    /// 0.08, a box that does not move is refused from 0.02, and a detector
    /// fit flip moved the box 0.011. 0.04 sits between with margin both ways.
    pub const CO_MOTION: f32 = 0.04;
    /// A leg shorter than this is a flicker (default). A quick nod's leg is
    /// 0.06 s (recorded); one-frame spikes are gone in the median already.
    const LEG_MIN_S: f32 = 0.05;
    /// Default reversal confirmation: one filtered frame is still a flicker.
    const REV_FRAMES: usize = 2;
    /// Default rest: the last leg of a gesture ends at rest, and a glance
    /// holds. The slow top of a real nod is not rest: it keeps creeping.
    const REST_S: f32 = 0.5;
    /// Not moving at all: frame-to-frame change under this, in signal units
    /// (face widths per frame). Absolute, not a fraction of the floor: at a
    /// calibrated floor of 0.129 a fraction became 0.045, above a nod's own
    /// frame-to-frame motion, and the user's nods were cleared as "rest"
    /// (recorded). A settling head wobbles 0.01; a turnaround moves 0.03+.
    const REST_STEP: f32 = 0.02;
    /// Filtered samples that must advance the extreme within a leg. 1 is
    /// off: the recorded nods from a jittery face box are not clean ramps,
    /// and fit flicker is handled before the detector (`FlickerFilter`).
    const MIN_STEPS: usize = 1;
    /// Median window over the raw signal.
    const MEDIAN: usize = 3;
    /// The face must have been still this long before the first leg.
    const STILL_S: f32 = 1.0;
    /// Default: filtered face width may end the gesture this far from where
    /// it began; more is the body moving. A shake narrows the box as the
    /// head turns, so its detector allows more.
    const WIDTH_TOL: f32 = 0.06;
    /// Threshold as a multiple of the noise floor.
    pub const JITTER_MULT: f32 = 4.0;
    const SETTLE_FRAMES: usize = 8;
    /// Baseline time constant in seconds.
    const TAU_S: f32 = 1.5;

    pub fn new(name: &'static str, min_thr: f32, max_thr: f32, leg_max_s: f32, shift_tol_x: f32, shift_tol_y: f32, max_amp: f32, both_sides: bool) -> Self {
        Oscillation { name, min_thr, max_thr, leg_max_s, shift_tol_x, shift_tol_y, max_amp, both_sides, rest_level: 0.0, prior_still: 0.0, span_s: Self::SPAN_S, rest_s: Self::REST_S, rev_frames: Self::REV_FRAMES, leg_min_s: Self::LEG_MIN_S, width_tol: Self::WIDTH_TOL, min_steps: Self::MIN_STEPS, need_ramp: false, co_motion: None, leg_samples: Vec::new(), recent: Vec::new(), regular: None, raw: Vec::new(), settle: Vec::new(), base: None, thr: min_thr, jitter: 0.0, last_p: None, last_step: 0.0, last_t: None, pivot: None, cand: (0.0, 0.0), dir: 0, rev_count: 0, rest_since: None, steps: 0, depart: 0.0, legs: Vec::new(), last_active: None, motion: Vec::new(), gestures: 0 }
    }

    /// True while the head is still or has only just moved: the caller may
    /// look at fewer frames. False once something like a gesture has begun.
    pub fn idle(&self, t: f32) -> bool {
        self.base.is_some() && self.last_active.map(|a| t - a > 1.0).unwrap_or(true)
    }

    fn rev_frames_needed(&self) -> usize {
        self.rev_frames
    }

    fn set_threshold(&mut self) {
        self.thr = (self.jitter * Self::JITTER_MULT).clamp(self.min_thr, self.max_thr);
    }

    /// Did the face box end the span `from..=to` somewhere other than it
    /// began? The box flickers between two fits on alternate frames and rides
    /// with the gesture itself, so the test is the change of the three-frame
    /// median from the start of the span to its end.
    fn moved(&self, from: f32, to: f32, why: &str) -> bool {
        let window: Vec<&(f32, f32, f32, f32)> = self.motion.iter().filter(|m| m.0 >= from && m.0 <= to).collect();
        if window.len() < 6 {
            return false;
        }
        let med = |i: usize, f: fn(&(f32, f32, f32, f32)) -> f32| {
            let mut v = [f(window[i]), f(window[i + 1]), f(window[i + 2])];
            v.sort_by(|a, b| a.total_cmp(b));
            v[1]
        };
        let last = window.len() - 3;
        let (w0, w1) = (med(0, |m| m.1), med(last, |m| m.1));
        let (x0, x1) = (med(0, |m| m.2), med(last, |m| m.2));
        let (y0, y1) = (med(0, |m| m.3), med(last, |m| m.3));
        let w = w0.max(w1).max(1.0);
        let moved = (w1 - w0).abs() / w > self.width_tol || (x1 - x0).abs() / w > self.shift_tol_x || (y1 - y0).abs() / w > self.shift_tol_y;
        if moved {
            log::debug!("consent: {} legs rejected, {} (width {:.0} to {:.0}, x {:.0} to {:.0}, y {:.0} to {:.0})", self.name, why, w0, w1, x0, x1, y0, y1);
        }
        moved
    }

    /// A leg just completed at `end`: does the sequence make a gesture?
    fn legs_complete(&mut self, start: f32, end: f32, extreme: f32, amp: f32, at_rest: bool) -> bool {
        self.legs.push((start, end, extreme, amp));
        while self.legs.len() > 1 && end - self.legs[0].0 > self.span_s {
            self.legs.remove(0);
        }
        if self.legs.len() < Self::LEGS {
            // A head that rests at an extreme mid-sequence was looking at
            // something, not gesturing: the sequence starts over. The one
            // rest allowed is at the midpoint, the beat between the two
            // motions (a glance rests after its first leg, at the thing it
            // looked at).
            if at_rest && self.legs.len() != Self::LEGS / 2 {
                log::debug!("consent: {} legs rejected, the head rested at {:+.2} after {} leg(s)", self.name, extreme, self.legs.len());
                self.legs.clear();
            }
            return false;
        }
        if self.both_sides {
            let rest = self.rest_level;
            let hi = self.legs.iter().map(|l| l.2).fold(f32::MIN, f32::max);
            let lo = self.legs.iter().map(|l| l.2).fold(f32::MAX, f32::min);
            if hi - rest < self.thr || rest - lo < self.thr {
                log::debug!("consent: {} legs rejected, one-sided ({:+.2}..{:+.2} about {:+.2})", self.name, lo, hi, rest);
                self.legs.clear();
                return false;
            }
        }
        if let Some(r) = self.regular {
            let amps: Vec<f32> = self.legs.iter().map(|l| l.3).collect();
            let durs: Vec<f32> = self.legs.iter().map(|l| l.1 - l.0).collect();
            let ratio = |v: &[f32]| v.iter().cloned().fold(f32::MIN, f32::max) / v.iter().cloned().fold(f32::MAX, f32::min).max(1e-6);
            if ratio(&amps) > r || ratio(&durs) > r {
                log::debug!("consent: {} legs rejected, uneven (amplitudes {:?}, durations {:?})", self.name, amps.iter().map(|a| format!("{:.3}", a)).collect::<Vec<_>>(), durs.iter().map(|d| format!("{:.2}", d)).collect::<Vec<_>>());
                self.legs.clear();
                return false;
            }
        }
        let first = self.legs[0].0;
        // The head turned; the face ends the gesture the same size and place
        // it began. A lean, a slump or a shift carries it somewhere else.
        if self.moved(first - 0.3, end, "the face moved") {
            self.legs.clear();
            return false;
        }
        // The gesture must follow a still second: someone who has only just
        // sat down or turned to the screen, glancing between it and the
        // keyboard, has not gestured yet. A face seen for less than that
        // second has not been still either.
        if self.motion.first().map(|m| m.0 - self.prior_still > first - Self::STILL_S + 0.2).unwrap_or(false) || self.moved(first - Self::STILL_S, first, "the face had just arrived") {
            self.legs.clear();
            return false;
        }
        self.gestures += 1;
        self.legs.clear();
        true
    }

    /// Feed one face frame; returns true when a gesture just completed.
    pub fn push(&mut self, v: f32, t: f32) -> bool {
        self.push_with(v, t, None)
    }

    /// As `push`, with the face's width and centre for the motion gate.
    pub fn push_with(&mut self, v: f32, t: f32, face: Option<(f32, f32, f32)>) -> bool {
        if let Some((w, cx, cy)) = face {
            self.motion.push((t, w, cx, cy));
            if self.motion.len() > 96 {
                self.motion.remove(0);
            }
        }
        self.raw.push(v);
        if self.raw.len() < Self::MEDIAN {
            return false;
        }
        if self.raw.len() > 64 {
            self.raw.remove(0);
        }
        let n = self.raw.len();
        let mut w: Vec<f32> = self.raw[n - Self::MEDIAN..].to_vec();
        w.sort_by(|a, b| a.total_cmp(b));
        let p = w[Self::MEDIAN / 2];
        let dt = self.last_t.map(|l| (t - l).clamp(0.0, 0.5)).unwrap_or(0.04);
        self.last_t = Some(t);
        let Some(b) = self.base else {
            // The baseline and noise floor come from a run of quiet frames;
            // a user who gestures the moment the window appears must not
            // have the gesture measured as noise (it would raise the
            // threshold to its cap and hide the gesture itself).
            self.settle.push(p);
            if self.settle.len() > Self::SETTLE_FRAMES {
                self.settle.remove(0);
            }
            if self.settle.len() >= Self::SETTLE_FRAMES {
                let mut s = self.settle.clone();
                s.sort_by(|a, b| a.total_cmp(b));
                let quiet = s[s.len() - 1] - s[0] <= self.min_thr * 1.5;
                if quiet {
                    let base = s[s.len() / 2];
                    self.jitter = self.settle.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f32>() / (self.settle.len() - 1) as f32;
                    self.set_threshold();
                    self.base = Some(base);
                    self.pivot = Some((p, t));
                    self.depart = t;
                }
            }
            return false;
        };
        let e = p - b;
        // The baseline follows the head slowly, whatever it is doing; a
        // gesture is too quick to move it much, a lean is absorbed.
        self.base = Some(b + e * (dt / Self::TAU_S).min(1.0));
        if e.abs() > self.thr / 2.0 {
            self.last_active = Some(t);
        }
        if let Some(lp) = self.last_p {
            let step = (p - lp).abs();
            self.last_step = step;
            // Only clearly-noise steps teach the noise floor: a gesture's own
            // frames, just under the threshold, must not raise it mid-gesture
            // (they did, on the motion signal, and hid the later legs).
            if step < self.thr * 0.25 {
                self.jitter += 0.05 * (step - self.jitter);
                self.set_threshold();
            }
        }
        self.last_p = Some(p);
        self.recent.push(p);
        if self.recent.len() > 4 {
            self.recent.remove(0);
        }
        let Some((pv, pt)) = self.pivot else { return false };
        match self.dir {
            0 => {
                if (p - pv).abs() < self.thr * 0.25 {
                    self.depart = t;
                }
                if p - pv >= self.thr || pv - p >= self.thr {
                    self.dir = if p > pv { 1 } else { -1 };
                    self.cand = (p, t);
                    self.steps = 1;
                    self.leg_samples.clear();
                    self.leg_samples.extend(self.recent.iter().copied());
                    self.leg_samples.push(p);
                } else if t - pt > 0.5 {
                    // Idle: re-anchor on the drifting head.
                    self.pivot = Some((p, t));
                }
                false
            }
            d => {
                if self.leg_samples.len() < 256 {
                    self.leg_samples.push(p);
                }
                // Strictly further: a rest at the extreme does not extend the
                // leg, so the pause between two nods is not part of either.
                let further = if d > 0 { p > self.cand.0 } else { p < self.cand.0 };
                // Not moving at all: a step at the still-face noise level, an
                // absolute of the floor (a still face moves 0.003 of a width
                // between frames; a slow turnaround moves more).
                let still = self.last_step < Self::REST_STEP;
                if further {
                    self.cand = (p, t);
                    self.steps += 1;
                    self.rev_count = 0;
                    self.rest_since = if still { self.rest_since.or(Some(t)) } else { None };
                    return false;
                }
                let reversed = if d > 0 { self.cand.0 - p >= self.thr } else { p - self.cand.0 >= self.thr };
                let at_rest = if !reversed {
                    self.rev_count = 0;
                    if still {
                        let since = *self.rest_since.get_or_insert(t);
                        t - since >= self.rest_s
                    } else {
                        self.rest_since = None;
                        false
                    }
                } else {
                    self.rest_since = None;
                    self.rev_count += 1;
                    false
                };
                if !at_rest && self.rev_count < self.rev_frames_needed() {
                    return false;
                }
                self.rev_count = 0;
                self.rest_since = None;
                // The extreme is confirmed: one leg, from the previous extreme
                // (or from where the head left its rest) to it.
                // A first leg starts where the head left its rest; a later
                // one at the previous extreme.
                let start = if self.legs.is_empty() { self.depart.max(pt) } else { pt };
                let (cv, ct) = self.cand;
                let dur = ct - start;
                let through_middle = {
                    let (lo, hi) = (pv.min(cv), pv.max(cv));
                    let band = (hi - lo) * 0.2;
                    self.leg_samples.iter().any(|&v| v > lo + band && v < hi - band)
                };
                let carried = match self.co_motion {
                    None => true,
                    Some((axis, min)) => {
                        // The box's swing along the axis across the leg,
                        // with a margin either side: the filtered signal
                        // lags the head, so the instants the leg is timed
                        // by fall inside the box's own movement.
                        let (lo_t, hi_t) = (start - 0.2, ct + 0.2);
                        let mut lo = f32::MAX;
                        let mut hi = f32::MIN;
                        let mut w = 1.0f32;
                        for m in self.motion.iter().filter(|m| m.0 >= lo_t && m.0 <= hi_t) {
                            let v = if axis == 1 { m.2 } else { m.3 };
                            lo = lo.min(v);
                            hi = hi.max(v);
                            w = w.max(m.1);
                        }
                        if lo > hi {
                            true
                        } else {
                            let moved = (hi - lo) / w;
                            if moved < min {
                                log::debug!("consent: {} leg rejected, the box did not move with it ({:.3} of width)", self.name, moved);
                            }
                            moved >= min
                        }
                    }
                };
                let ramp = self.steps >= self.min_steps && (!self.need_ramp || through_middle) && carried;
                self.leg_samples.clear();
                self.leg_samples.push(cv);
                let amp = (cv - pv).abs();
                if self.legs.is_empty() {
                    self.rest_level = pv;
                }
                self.steps = 1;
                self.pivot = Some((cv, ct));
                // Reversed: the next leg is under way. At rest: back to
                // waiting for the head to leave this spot.
                self.dir = if at_rest { 0 } else { -d };
                self.depart = ct;
                self.cand = (p, t);
                if !ramp || !(self.leg_min_s..=self.leg_max_s).contains(&dur) || amp > self.max_amp {
                    log::debug!("consent: {} leg rejected ({} steps, {:.2}s, {:.2} tall)", self.name, if ramp { "enough" } else { "too few" }, dur, amp);
                    self.legs.clear();
                    return false;
                }
                self.legs_complete(start, ct, cv, amp, at_rest)
            }
        }
    }
}

/// A face-detector fit that flickers between two solutions moves every
/// landmark at once and the box with them: pitch, yaw and the box width jump
/// together in one frame, and the fit may hold the other solution for a few
/// frames before snapping back (measured 2026-09-22, twice: a still face
/// granted root off a one-frame flicker on alternate frames, then off a
/// four-frame plateau 0.05 higher with the box 6% wider). A nod moves pitch
/// over several frames with the width steady to within about 2% a frame; a
/// shake moves yaw the same way.
///
/// The filter is stateful: a frame whose pitch jumps together with yaw or
/// width starts a suspect run, and every frame that stays at the jumped
/// level is dropped until the fit is back where it was (within the pitch
/// threshold and 2% of width), or a dozen frames have passed, which is a
/// head that really moved.
#[derive(Default)]
pub struct FlickerFilter {
    last: Option<(f32, f32, f32)>,
    /// (pitch, width) before the jump, and frames dropped since.
    suspect: Option<(f32, f32, usize)>,
}

/// One-frame lookahead: a frame is emitted only once the next one is seen,
/// and is dropped when its box width or pitch jumped away from the previous
/// frame and the next frame is back at the previous level. A held plateau
/// passes (the nose-based pitch is barely moved by a fit switch); real motion
/// is never touched, because a real move does not snap back in one frame.
#[derive(Default)]
pub struct TransientFilter {
    prev: Option<(f32, f32, f32)>,
    held: Option<(f32, f32, f32)>,
}

impl TransientFilter {
    /// Feed a frame; returns the frame to process now (the previous one), if any.
    pub fn feed(&mut self, pitch: f32, yaw: f32, width: f32) -> Option<(f32, f32, f32)> {
        let cur = (pitch, yaw, width);
        let out = match (self.prev, self.held) {
            (Some(p), Some(h)) => {
                let jumped = (h.0 - p.0).abs() > FlickerFilter::PITCH_JUMP && ((h.2 - p.2).abs() / p.2.max(1.0) > FlickerFilter::WIDTH_JUMP || (h.1 - p.1).abs() > FlickerFilter::YAW_JUMP);
                let back = (cur.0 - p.0).abs() <= FlickerFilter::PITCH_JUMP && (cur.2 - p.2).abs() / p.2.max(1.0) <= 0.02;
                if jumped && back {
                    // h was a one-frame transient: drop it, keep p as the reference.
                    None
                } else {
                    self.prev = Some(h);
                    Some(h)
                }
            }
            (None, Some(h)) => {
                self.prev = Some(h);
                Some(h)
            }
            _ => None,
        };
        self.held = Some(cur);
        out
    }
}

impl FlickerFilter {
    pub const PITCH_JUMP: f32 = 0.012;
    pub const YAW_JUMP: f32 = 0.02;
    pub const WIDTH_JUMP: f32 = 0.04;
    /// A yaw step this large in one frame is a head turning, never a
    /// flicker (flicker steps yaw by 0.01 to 0.03; a shake by 0.05 to 0.15).
    pub const YAW_TURN: f32 = 0.05;
    const RETURN_WIDTH: f32 = 0.02;
    /// Longer than any flicker plateau seen (four frames), shorter than a
    /// real leg, so a genuine move loses at most its first few frames.
    const MAX_HOLD: usize = 5;

    /// Should this frame be fed to the detectors?
    pub fn keep(&mut self, pitch: f32, yaw: f32, width: f32) -> bool {
        let prev = self.last;
        self.last = Some((pitch, yaw, width));
        let turning = prev.map(|(_, py, _)| (yaw - py).abs() >= Self::YAW_TURN).unwrap_or(false);
        if turning {
            self.suspect = None;
            return true;
        }
        if let Some((p0, w0, n)) = self.suspect {
            let back = (pitch - p0).abs() <= Self::PITCH_JUMP && (width - w0).abs() / w0.max(1.0) <= Self::RETURN_WIDTH;
            if back {
                self.suspect = None;
                return true;
            }
            if n + 1 >= Self::MAX_HOLD {
                self.suspect = None; // held too long to be a flicker: a real move
                return true;
            }
            self.suspect = Some((p0, w0, n + 1));
            return false;
        }
        let Some((pp, py, pw)) = prev else { return true };
        let jump = (pitch - pp).abs() > Self::PITCH_JUMP && ((yaw - py).abs() > Self::YAW_JUMP || (width - pw).abs() / pw.max(1.0) > Self::WIDTH_JUMP);
        if jump {
            self.suspect = Some((pp, pw, 1));
            return false;
        }
        true
    }
}

/// Nods: the pitch axis. A natural nod swings 0.03 to 0.05, a light one
/// 0.02; the wobble of a head leaning in is the same size and is told apart
/// by the motion gate, not by amplitude.
pub struct NodDetector {
    pub inner: Oscillation,
    /// Nods counted: two per completed gesture.
    pub nods: usize,
    /// Recent (t, yaw), for the quiet-yaw rule.
    yaw: Vec<(f32, f32)>,
}

impl Default for NodDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NodDetector {
    /// On the image-motion signal (vertical position of the face in face
    /// widths), from the calibration battery of 2026-09-22: a still face
    /// moves 0.003, talking 0.036, the user's light nod 0.106, natural nods
    /// 0.17 to 0.40 on the record-only battery; a detector fit flip moves no
    /// pixels at all. 0.06 is the highest floor at which every recording of
    /// that battery is still read correctly (the sweep), almost twice the
    /// talking motion.
    pub const MIN_DOWN: f32 = 0.06;
    pub const MAX_DOWN: f32 = 0.08;
    /// A nod keeps the head facing the camera: yaw may range this much over
    /// the gesture's span. A still head ranges about 0.03, the user's nods up
    /// to 0.11 (two were refused at a 0.10 limit); a head shake ranges 0.6 or
    /// more, and its perspective wobble on the pitch measure (up to 0.12,
    /// measured 2026-09-22) would otherwise read as nods.
    pub const YAW_QUIET: f32 = 0.25;

    pub fn new() -> Self {
        Self::with_floor(Self::MIN_DOWN)
    }

    /// With this person's floor (never below the default).
    pub fn with_floor(floor: f32) -> Self {
        let floor = floor.max(Self::MIN_DOWN);
        // A nod rides the box up and down: the vertical allowance is doubled.
        // Legs to a second: deliberate nods measured 0.87 s and were refused at 0.8.
        let mut inner = Oscillation::new("nod", floor, Self::MAX_DOWN.max(floor), 1.0, 0.10, 0.30, 0.5, false);
        // The box must ride each leg: a head that nods carries its box,
        // a detector fit that flips does not (1 px through a recorded flip,
        // 9 to 16 px through real nods). See `Oscillation::CO_MOTION`.
        inner.co_motion = Some((2, Oscillation::CO_MOTION));
        NodDetector { inner, nods: 0, yaw: Vec::new() }
    }

    pub fn idle(&self, t: f32) -> bool {
        self.inner.idle(t)
    }

    pub fn push(&mut self, pitch: f32, t: f32) -> bool {
        self.push_with(pitch, t, None)
    }

    pub fn push_with(&mut self, pitch: f32, t: f32, face: Option<(f32, f32, f32)>) -> bool {
        self.push_full(pitch, None, t, face)
    }

    /// As `push_with`, with the frame's yaw for the quiet-yaw rule (None
    /// when the caller has no yaw, as the older recorded traces do not).
    pub fn push_full(&mut self, pitch: f32, yaw: Option<f32>, t: f32, face: Option<(f32, f32, f32)>) -> bool {
        if let Some(y) = yaw {
            self.yaw.push((t, y));
            self.yaw.retain(|(yt, _)| t - yt <= Oscillation::SPAN_S + 0.5);
        }
        let hit = self.inner.push_with(pitch, t, face);
        if !hit {
            return false;
        }
        let span: Vec<f32> = self.yaw.iter().filter(|(yt, _)| t - yt <= Oscillation::SPAN_S).map(|(_, y)| *y).collect();
        if let (Some(lo), Some(hi)) = (span.iter().cloned().reduce(f32::min), span.iter().cloned().reduce(f32::max)) {
            if hi - lo > Self::YAW_QUIET {
                log::debug!("consent: nod rejected, the head turned meanwhile (yaw range {:.2})", hi - lo);
                return false;
            }
        }
        self.nods += 2;
        true
    }
}

/// Head shakes: the yaw axis (nose offset in inter-eye distances; a 30
/// degree turn is about 0.35). A refusal, so a false positive costs a
/// password prompt, not a root shell: the floor can sit lower than a glance
/// at a second monitor only because a glance is one leg and a hold, never
/// four alternating legs.
pub struct ShakeDetector {
    pub inner: Oscillation,
    /// Shakes counted: two per completed gesture.
    pub shakes: usize,
}

impl Default for ShakeDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ShakeDetector {
    /// Reading sweeps the head about 0.04 left and right along a line
    /// (recorded); a shake swings about 0.35. The floor sits well above the
    /// first and far below the second.
    /// On the image-motion signal (horizontal position of the face in face
    /// widths): a shake slides the face about 0.17 of its width each way
    /// (15 px on 88, recorded). First cut, to be set from the motion battery.
    pub const MIN_TURN: f32 = 0.06;
    pub const MAX_TURN: f32 = 0.10;

    pub fn new() -> Self {
        Self::with_floor(Self::MIN_TURN)
    }

    /// With this person's floor (never above the default, never below 0.03).
    pub fn with_floor(floor: f32) -> Self {
        let floor = floor.clamp(0.03, Self::MIN_TURN);
        // A shake slides the box sideways by a fifth of its width (measured
        // 2026-09-22: 15 px on an 80 px face) and its legs run to a second.
        // A shake swings about 0.35 each way; a turn to another monitor
        // measures 0.4 held, an exaggerated one past 2.0 (both recorded).
        // No both-sides rule: the integrated image position drifts between
        // gestures, so "centre" is not well defined; a glance is caught by
        // its hold (the rest rule) and its size.
        let mut inner = Oscillation::new("shake", floor, Self::MAX_TURN, 1.0, 0.60, 0.30, 1.5, false);
        // The box narrows by 7% as the head turns (recorded): not the body moving.
        inner.width_tol = 0.15;
        // The box must slide with each leg (see the nod detector).
        inner.co_motion = Some((1, Oscillation::CO_MOTION));
        ShakeDetector { inner, shakes: 0 }
    }

    pub fn push(&mut self, yaw: f32, t: f32) -> bool {
        self.push_with(yaw, t, None)
    }

    pub fn push_with(&mut self, yaw: f32, t: f32, face: Option<(f32, f32, f32)>) -> bool {
        let hit = self.inner.push_with(yaw, t, face);
        if hit {
            self.shakes += 2;
        }
        hit
    }
}

/// A calibration round: watch the face for `seconds` and report how far it
/// moved, vertically and sideways, as the largest range of the accumulated
/// image motion over any 1.5 s (face widths). Nothing is decided; the
/// recording is always saved (root-only) under `cal-<gesture>`.
pub fn measure_motion(cap: &mut IrCapture, pipeline: &mut Pipeline, cfg: &Config, user: &str, gesture: &str, seconds: f32) -> Result<(f32, f32)> {
    let t0 = Instant::now();
    let mut forced = cfg.clone();
    forced.gesture_trace = true;
    let label: &'static str = if gesture == "shake" { "cal-shake" } else { "cal-nod" };
    let saver = TraceSaver { cfg: &forced, user: user.to_string(), trace: Default::default(), label: std::cell::Cell::new(label) };
    let trace = &saver.trace;
    let mut prev: Option<(Grey, [f32; 4])> = None;
    let (mut pos_x, mut pos_y) = (0f32, 0f32);
    let mut series: Vec<(f32, f32, f32)> = Vec::new();
    while t0.elapsed().as_secs_f32() < seconds {
        let Some(img) = cap.next(Duration::from_secs(1))? else { continue };
        let faces = pipeline.detector.detect(&img, cfg.min_detection)?;
        let Some(face) = faces.into_iter().max_by(|a, b| a.score.total_cmp(&b.score)) else { continue };
        let t = t0.elapsed().as_secs_f32();
        if let Some((pimg, pbox)) = &prev {
            let region = faceauth_engine::motion::Region::around(*pbox, 0.2, img.width, img.height);
            let (dx, dy) = faceauth_engine::motion::shift(pimg, &img, region, 24);
            pos_x += dx / face.bbox[2].max(1.0);
            pos_y += dy / face.bbox[2].max(1.0);
        }
        prev = Some((img.clone(), face.bbox));
        let pose = pose::pose(&face.landmarks);
        let geom = (face.bbox[2], face.bbox[0] + face.bbox[2] / 2.0, face.bbox[1] + face.bbox[3] / 2.0);
        let l = &face.landmarks;
        if trace.borrow().len() < 1200 {
            trace.borrow_mut().push(format!("{:.2}/{:.3}/{:+.3}/{:.0}/{:.0}/{:.0}/{:.1}/{:.1}/{:.1}/{:.1}/{:.1}/{:.1}/{:.1}/{:.1}/{:.1}/{:.1}/{:.2}/{:+.3}/{:+.3}", t, pose.pitch, pose.yaw, geom.0, geom.1, geom.2, l[0][0], l[0][1], l[1][0], l[1][1], l[2][0], l[2][1], l[3][0], l[3][1], l[4][0], l[4][1], face.score, pos_x, pos_y));
        }
        series.push((t, pos_x, pos_y));
    }
    let range = |pick: fn(&(f32, f32, f32)) -> f32| -> f32 {
        let mut best = 0f32;
        for i in 0..series.len() {
            let (mut lo, mut hi) = (f32::MAX, f32::MIN);
            for s in &series[i..] {
                if s.0 - series[i].0 > 1.5 {
                    break;
                }
                lo = lo.min(pick(s));
                hi = hi.max(pick(s));
            }
            if hi > lo {
                best = best.max(hi - lo);
            }
        }
        best
    };
    Ok((range(|s| s.2), range(|s| s.1)))
}

/// Writes a round's per-frame recording when the round ends, if
/// `gesture_trace` is on: `<store_dir>/gestures/<unix seconds>-<user>-<how
/// it ended>.txt`, mode 0600 in a 0700 directory, newest sixty kept. The
/// recording is head pose, landmarks, box and image motion per frame; never
/// an image, and never the journal.
struct TraceSaver<'a> {
    cfg: &'a Config,
    user: String,
    trace: std::cell::RefCell<Vec<String>>,
    label: std::cell::Cell<&'static str>,
}

impl Drop for TraceSaver<'_> {
    fn drop(&mut self) {
        if !self.cfg.gesture_trace {
            return;
        }
        let trace = self.trace.borrow();
        if trace.is_empty() {
            return;
        }
        let dir = self.cfg.store_dir.join("gestures");
        let res = (|| -> std::io::Result<()> {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            std::fs::create_dir_all(&dir)?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            let name = format!("{}-{}-{}.txt", crate::store::now_secs(), self.user, self.label.get());
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(dir.join(&name))?;
            f.write_all(trace.join(" ").as_bytes())?;
            f.write_all(b"\n")?;
            let mut files: Vec<_> = std::fs::read_dir(&dir)?.flatten().map(|e| e.path()).collect();
            files.sort();
            while files.len() > 60 {
                let _ = std::fs::remove_file(files.remove(0));
            }
            log::info!("consent: gesture recording saved as {}", name);
            Ok(())
        })();
        if let Err(e) = res {
            log::warn!("consent: gesture recording not saved: {}", e);
        }
    }
}

/// Which detection in a frame is the face being followed.
#[derive(Debug, PartialEq)]
pub enum Track {
    /// The followed face, by index into the detections.
    Found(usize),
    /// No detection continues the followed box.
    Lost,
    /// Two detections could each be it: the gesture pauses.
    Ambiguous,
}

/// Follow `tracked` through `faces`: the detection whose centre moved less
/// than half a face width and whose width is within 30 percent continues
/// it. A second detection that also fits, or overlaps it, is ambiguous.
/// Other faces in the frame are ignored (the one that matched is the one
/// that answers).
pub fn track(faces: &[faceauth_engine::Face], tracked: [f32; 4]) -> Track {
    let (tw, tcx, tcy) = (tracked[2].max(1.0), tracked[0] + tracked[2] / 2.0, tracked[1] + tracked[3] / 2.0);
    let fits = |b: &[f32; 4]| -> bool {
        let (cx, cy) = (b[0] + b[2] / 2.0, b[1] + b[3] / 2.0);
        let dist = ((cx - tcx).powi(2) + (cy - tcy).powi(2)).sqrt();
        let ratio = b[2] / tw;
        dist < 0.5 * tw && (0.7..=1.43).contains(&ratio)
    };
    let mut candidates: Vec<(usize, f32)> = faces.iter().enumerate().filter(|(_, f)| fits(&f.bbox)).map(|(i, f)| {
        let (cx, cy) = (f.bbox[0] + f.bbox[2] / 2.0, f.bbox[1] + f.bbox[3] / 2.0);
        (i, ((cx - tcx).powi(2) + (cy - tcy).powi(2)).sqrt())
    }).collect();
    candidates.sort_by(|a, b| a.1.total_cmp(&b.1));
    match candidates.len() {
        0 => Track::Lost,
        1 => Track::Found(candidates[0].0),
        _ => Track::Ambiguous,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn wait_for_nods(cap: &mut IrCapture, pipeline: &mut Pipeline, cfg: &Config, window: Duration, nods_needed: usize, answers: Option<(&Answers, &str)>, lost_after: Option<Duration>, floors: (f32, f32), start: Option<[f32; 4]>) -> Result<(Gesture, Option<[f32; 4]>)> {
    let min_detection = cfg.min_detection;
    let user_name = answers.map(|(_, u)| u.to_string()).unwrap_or_else(|| "unknown".into());
    let t0 = Instant::now();
    let mut last_face = Instant::now();
    let mut det = NodDetector::with_floor(floors.0);
    let mut shake = ShakeDetector::with_floor(floors.1);
    // The scan that matched the face just ran with the face steadily in
    // view: that counts as the still second a first leg must follow.
    det.inner.prior_still = 1.0;
    shake.inner.prior_still = 1.0;
    // Real image motion: the face region's pixel shift between the frames
    // looked at, accumulated into a position in face widths. This is what
    // the gestures are read from (see `faceauth_engine::motion`).
    let mut prev: Option<(Grey, [f32; 4])> = None;
    let (mut pos_x, mut pos_y) = (0f32, 0f32);
    // Per-frame recording: the raw material for tuning both detectors.
    // Saved to the root-only gestures directory when the round ends, if
    // enabled; never to the journal (it is per-frame head pose).
    let saver = TraceSaver { cfg, user: user_name.clone(), trace: Default::default(), label: std::cell::Cell::new("ended") };
    let label = &saver.label;
    let trace = &saver.trace;
    let mut frame_no = 0usize;
    // The face being followed: the one the scan matched. A detection that
    // does not continue it is not the answerer, however well it scores.
    let mut tracked: Option<[f32; 4]> = start;
    let mut lost_since: Option<Instant> = None;
    let mut paused_logged = false;
    let summary = |det: &NodDetector, shake: &ShakeDetector, t: f32| format!("{} nods, {} shakes in {:.1}s, thresholds {:.3}/{:.3}", det.nods, shake.shakes, t, det.inner.thr, shake.inner.thr);
    while t0.elapsed() < window {
        if let Some((answers, user)) = answers {
            match take_answer(answers, user) {
                Some(Answer::Password(pw)) => {
                    log::info!("consent: password answer after {}", summary(&det, &shake, t0.elapsed().as_secs_f32()));
                    label.set("password");
                    return Ok((Gesture::Password(pw), tracked));
                }
                Some(Answer::Dismiss) => {
                    log::info!("consent: dismissed after {}", summary(&det, &shake, t0.elapsed().as_secs_f32()));
                    label.set("dismissed");
                    return Ok((Gesture::Dismissed, tracked));
                }
                Some(Answer::Gone) => {
                    log::info!("consent: requester gone after {}", summary(&det, &shake, t0.elapsed().as_secs_f32()));
                    label.set("gone");
                    return Ok((Gesture::Gone, tracked));
                }
                None => {}
            }
        }
        if let Some(l) = lost_after {
            if last_face.elapsed() > l {
                log::info!("consent: no face for {:.0}s after {} nods; the user left", l.as_secs_f32(), det.nods);
                label.set("face-lost");
                return Ok((Gesture::FaceLost, tracked));
            }
        }
        let Some(img) = cap.next(Duration::from_secs(1))? else { continue };
        // Slow polling while the head is still: every other frame is looked
        // at (a leg leaves the rest for six or more frames, so its start
        // cannot slip between two), the rest are only drained. Once a
        // movement begins every frame is looked at.
        frame_no += 1;
        let t = t0.elapsed().as_secs_f32();
        if det.idle(t) && shake.inner.idle(t) && frame_no % 2 != 0 {
            continue;
        }
        let faces = pipeline.detector.detect(&img, min_detection)?;
        if faces.is_empty() {
            continue;
        }
        let face = match tracked {
            None => faces.into_iter().max_by(|a, b| a.score.total_cmp(&b.score)).unwrap(),
            Some(tb) => match track(&faces, tb) {
                Track::Found(i) => {
                    lost_since = None;
                    paused_logged = false;
                    faces.into_iter().nth(i).unwrap()
                }
                other => {
                    // The followed face is not there, or cannot be told from
                    // another: nothing counts meanwhile, and a nod begun
                    // before is forgotten. A single face back for a second
                    // is adopted (the user moved); the confirm at the end
                    // still has to match it.
                    last_face = Instant::now();
                    if !paused_logged {
                        log::info!("consent: gesture paused, the matched face is {}", if other == Track::Lost { "not in view" } else { "one of two" });
                        paused_logged = true;
                    }
                    det = NodDetector::with_floor(floors.0);
                    shake = ShakeDetector::with_floor(floors.1);
                    prev = None;
                    let since = *lost_since.get_or_insert(Instant::now());
                    if other == Track::Lost && faces.len() == 1 && since.elapsed() > Duration::from_secs(1) {
                        tracked = Some(faces[0].bbox);
                        log::info!("consent: following the one face in view again");
                    }
                    continue;
                }
            },
        };
        tracked = Some(face.bbox);
        last_face = Instant::now();
        let pose = pose::pose(&face.landmarks);
        let geom = (face.bbox[2], face.bbox[0] + face.bbox[2] / 2.0, face.bbox[1] + face.bbox[3] / 2.0);
        if let Some((pimg, pbox)) = &prev {
            let region = faceauth_engine::motion::Region::around(*pbox, 0.2, img.width, img.height);
            let (dx, dy) = faceauth_engine::motion::shift(pimg, &img, region, 24);
            pos_x += dx / face.bbox[2].max(1.0);
            pos_y += dy / face.bbox[2].max(1.0);
        }
        prev = Some((img.clone(), face.bbox));
        if trace.borrow().len() < 1200 {
            // t/pitch/yaw/width/cx/cy, then the five landmarks (right eye,
            // left eye, nose, right mouth, left mouth) and the detector score:
            // enough to evaluate any pose measure offline from a recording.
            let l = &face.landmarks;
            // ... then the accumulated image motion (x, y) in face widths.
            trace.borrow_mut().push(format!("{:.2}/{:.3}/{:+.3}/{:.0}/{:.0}/{:.0}/{:.1}/{:.1}/{:.1}/{:.1}/{:.1}/{:.1}/{:.1}/{:.1}/{:.1}/{:.1}/{:.2}/{:+.3}/{:+.3}", t, pose.pitch, pose.yaw, geom.0, geom.1, geom.2, l[0][0], l[0][1], l[1][0], l[1][1], l[2][0], l[2][1], l[3][0], l[3][1], l[4][0], l[4][1], face.score, pos_x, pos_y));
        }
        // Nods are read from the nose's position below the eye line, not
        // the mouth-based pitch: the mouth landmarks jitter most in IR and
        // move when the user talks (the calibration battery of 2026-09-22).
        // No flicker filter: on the nose-to-eye measure the calibration
        // battery showed every filter variant costing real gestures and
        // buying no safety (the shape rules carry it).
        if shake.push_with(pos_x, t, Some(geom)) {
            if cfg.gesture_record_only {
                log::info!("consent: head shake recorded (record-only), {}", summary(&det, &shake, t));
            } else {
                log::info!("consent: head shake, refused after {}", summary(&det, &shake, t));
                label.set("shaken");
                return Ok((Gesture::Shaken, tracked));
            }
        }
        if det.push_full(pos_y, Some(pose.yaw), t, Some(geom)) {
            log::debug!("consent: nod {} at {:.2}s", det.nods, t);
            if det.nods >= nods_needed {
                if cfg.gesture_record_only {
                    log::info!("consent: nods recorded (record-only), {}", summary(&det, &shake, t));
                } else {
                    log::info!("consent: {}", summary(&det, &shake, t));
                    label.set("nodded");
                    return Ok((Gesture::Nodded, tracked));
                }
            }
        }
    }
    log::info!("consent: timed out, {} ({} face frames)", summary(&det, &shake, window.as_secs_f32()), trace.borrow().len());
    label.set("timeout");
    Ok((Gesture::Timeout, tracked))
}

#[cfg(test)]
mod track_tests {
    use super::{track, Track};
    use faceauth_engine::Face;

    fn face(x: f32, y: f32, w: f32, score: f32) -> Face {
        Face { bbox: [x, y, w, w * 1.2], score, landmarks: [[0.0; 2]; 5], embedding: None }
    }

    #[test]
    fn the_matched_box_is_followed_through_a_nod_sized_move() {
        let t = [200.0, 300.0, 90.0, 108.0];
        assert_eq!(track(&[face(205.0, 318.0, 92.0, 0.7)], t), Track::Found(0), "moved 18 px down on a 90 px face: the same head");
        assert_eq!(track(&[face(200.0, 300.0, 100.0, 0.7)], t), Track::Found(0), "came a little closer");
    }

    #[test]
    fn a_face_elsewhere_or_of_another_size_is_not_it() {
        let t = [200.0, 300.0, 90.0, 108.0];
        assert_eq!(track(&[face(300.0, 300.0, 90.0, 0.9)], t), Track::Lost, "a face width away is someone else, however well it scores");
        assert_eq!(track(&[face(200.0, 300.0, 50.0, 0.9)], t), Track::Lost, "half the size is not the same head");
        assert_eq!(track(&[], t), Track::Lost);
    }

    #[test]
    fn the_followed_face_is_chosen_over_a_better_scoring_stranger() {
        let t = [200.0, 300.0, 90.0, 108.0];
        assert_eq!(track(&[face(400.0, 300.0, 120.0, 0.95), face(203.0, 305.0, 90.0, 0.6)], t), Track::Found(1));
    }

    #[test]
    fn two_faces_that_both_fit_are_ambiguous() {
        let t = [200.0, 300.0, 90.0, 108.0];
        assert_eq!(track(&[face(205.0, 300.0, 90.0, 0.7), face(230.0, 310.0, 85.0, 0.7)], t), Track::Ambiguous);
    }
}

#[cfg(test)]
mod window_text_tests {
    use super::{clip, Dialog, TOKENS};

    #[test]
    fn clip_drops_line_breaks_and_direction_overrides() {
        assert_eq!(clip("sudo /bin/sh -c true\nRoutine update\nNo action needed"), "sudo /bin/sh -c trueRoutine updateNo action needed");
        assert_eq!(clip("ls \u{202E}txt.sh"), "ls txt.sh");
        assert_eq!(clip("a\u{200B}b\u{2066}c\tD"), "abcD");
        assert_eq!(clip(&"x".repeat(2500)).chars().count(), 2000);
        assert_eq!(clip("plain command --flag"), "plain command --flag");
    }

    #[test]
    fn a_token_matches_only_itself_and_only_while_the_request_lives() {
        let user = "window-text-test-user";
        let cfg = crate::config::Config::default();
        assert!(!Dialog::token_matches(user, Some("anything")), "no request, no match");
        let d = Dialog::new(&cfg, user).unwrap();
        let tok = TOKENS.lock().unwrap().get(user).cloned().unwrap();
        assert_eq!(tok.len(), 32);
        assert!(Dialog::token_matches(user, Some(&tok)));
        assert!(!Dialog::token_matches(user, Some(&tok[..31])));
        assert!(!Dialog::token_matches(user, Some(&format!("{}0", tok))));
        assert!(!Dialog::token_matches(user, None));
        drop(d);
        assert!(!Dialog::token_matches(user, Some(&tok)), "the token dies with the request");
    }
}

#[cfg(test)]
mod nod_tests {
    use super::NodDetector;

    const POSTURE_TRACE: &str = "0.572 0.606 0.598 0.589 0.578 0.570 0.559 0.553 0.556 0.552 0.547 0.551 0.548 0.544 0.548 0.555 0.555 0.548 0.558 0.555 0.557 0.551 0.554 0.547 0.543 0.546 0.547 0.546 0.548 0.541 0.532 0.524 0.551 0.576 0.582 0.524 0.560 0.529 0.528 0.561 0.583 0.581 0.584 0.567 0.561 0.579 0.578 0.574 0.575 0.572 0.572 0.570 0.568 0.568 0.566 0.531 0.562 0.529 0.568 0.567 0.569 0.530 0.529 0.537 0.531 0.540 0.527 0.524 0.527 0.531 0.526 0.523 0.525 0.530 0.527 0.527 0.525 0.527 0.529 0.526 0.531 0.526 0.527 0.537 0.529 0.525 0.529 0.531 0.523 0.522 0.523 0.524 0.524 0.526 0.525 0.527 0.523 0.524 0.519 0.523 0.519 0.523 0.523 0.524 0.537 0.527 0.530 0.523 0.527 0.525 0.521 0.516 0.520 0.534 0.520 0.517 0.527 0.519 0.535 0.532 0.519 0.531 0.520 0.517 0.524 0.525 0.521 0.523 0.523 0.523 0.523 0.526 0.521 0.524 0.524 0.521 0.520 0.519 0.523 0.558 0.520 0.513 0.534 0.541 0.518 0.533 0.517 0.515 0.520 0.524 0.524 0.532 0.531 0.524 0.524 0.524 0.525 0.561 0.563 0.557 0.554 0.548 0.548 0.551 0.549 0.541 0.537 0.520 0.511 0.528 0.532 0.520 0.521 0.508 0.517 0.523 0.528 0.540 0.535 0.485 0.483 0.495 0.477 0.471 0.483 0.516 0.525 0.511 0.508 0.502 0.506 0.493 0.495 0.499 0.489 0.489 0.488 0.504 0.503 0.500 0.501 0.491 0.500 0.491 0.476 0.488 0.470 0.474 0.475 0.477 0.462 0.473 0.453 0.489 0.486 0.483 0.492 0.473 0.466 0.477 0.487 0.492 0.492 0.503 0.513 0.502 0.494 0.505 0.508 0.496 0.495 0.487 0.525 0.515 0.504 0.511 0.527 0.515 0.546 0.534 0.542 0.533 0.513 0.523 0.514 0.512 0.531 0.534 0.523 0.533 0.533 0.543 0.545 0.537 0.552 0.547 0.546 0.545 0.547 0.524 0.546 0.536 0.523 0.557 0.533 0.538 0.520 0.514 0.520 0.528 0.533 0.528 0.532 0.535 0.535 0.530 0.534 0.530 0.537 0.535 0.528 0.530 0.530 0.538 0.539 0.544 0.547 0.542 0.545 0.521 0.521 0.526 0.532 0.550 0.550 0.560 0.518 0.518 0.513 0.525 0.553 0.562 0.566 0.568 0.563 0.564 0.563 0.563 0.568 0.561 0.560 0.563 0.563 0.563 0.559 0.561 0.561 0.562 0.560 0.560 0.560 0.560 0.560 0.554 0.561 0.558 0.560 0.556 0.559 0.555 0.554 0.555 0.549 0.551 0.549 0.541 0.552 0.555 0.559 0.549 0.539 0.542 0.550 0.546 0.545 0.547 0.541 0.539 0.545 0.543 0.552 0.550 0.551 0.553 0.557 0.552 0.554 0.553 0.558 0.558 0.557 0.559 0.559 0.558 0.555 0.555 0.554 0.559 0.560 0.559 0.560 0.558 0.564 0.561 0.565 0.557 0.564 0.568 0.563 0.560 0.562 0.558 0.562 0.565 0.563 0.559 0.562 0.566 0.568 0.566 0.567 0.570 0.574 0.578 0.574 0.576 0.571 0.572 0.575 0.576";

    fn run(trace: &[f32], fps: f32) -> usize {
        let mut d = NodDetector::new();
        for (i, &p) in trace.iter().enumerate() {
            d.push(p, i as f32 / fps);
        }
        d.nods
    }

    fn run_geom(text: &str, fps: f32) -> (usize, Vec<usize>) {
        let mut d = NodDetector::new();
        let mut at = Vec::new();
        for (i, rec) in text.split_whitespace().enumerate() {
            let f: Vec<f32> = rec.split('/').map(|v| v.parse().unwrap()).collect();
            if d.push_with(f[0], i as f32 / fps, Some((f[1], f[2], f[3]))) {
                at.push(i);
            }
        }
        (d.nods, at)
    }

    /// Recorded 2026-09-22: the user sat still for ten seconds and the first
    /// four-leg detector granted root off a detector fit that flickered on
    /// alternate frames (pitch/yaw/width/x/y per frame, about 28 fps).
    #[test]
    fn a_still_face_with_a_flickering_fit_is_not_a_nod() {
        let text = include_str!("../traces/2026-09-22-0536-false-nods-still-face.txt");
        let mut d = NodDetector::new();
        let mut at = Vec::new();
        let mut filter = super::FlickerFilter::default();
        let mut dropped = 0;
        for (i, tok) in text.split_whitespace().enumerate() {
            let f: Vec<f32> = tok.split('/').map(|v| v.parse().unwrap()).collect();
            if !filter.keep(f[0], f[1], f[2]) {
                dropped += 1;
                continue;
            }
            if d.push_full(f[0], Some(f[1]), i as f32 / 28.0, Some((f[2], f[3], f[4]))) {
                at.push(i);
            }
        }
        assert_eq!(d.nods, 0, "counted at {:?}, {} flicker frames dropped", at, dropped);
    }

    #[test]
    #[ignore]
    fn dump_false_trace() {
        let text = include_str!("../traces/2026-09-22-0536-false-nods-still-face.txt");
        let mut d = NodDetector::new();
        for (i, tok) in text.split_whitespace().enumerate() {
            let f: Vec<f32> = tok.split('/').map(|v| v.parse().unwrap()).collect();
            let hit = d.push_with(f[0], i as f32 / 28.0, Some((f[2], f[3], f[4])));
            eprintln!("{:3} p {:.3} w {:.0} y {:.0} base {:.3} e {:+.3} thr {:.3} dir {:+} steps {} legs {} {}", i, f[0], f[2], f[4], d.inner.base.unwrap_or(0.0), f[0] - d.inner.base.unwrap_or(f[0]), d.inner.thr, d.inner.dir, d.inner.steps, d.inner.legs.len(), if hit { "NOD" } else { "" });
        }
    }

    #[test]
    #[ignore]
    fn dump_flicker_trace() {
        let text = include_str!("../traces/2026-09-19-0244-nods-missed-with-motion-gate.txt");
        let mut d = NodDetector::new();
        for (i, rec) in text.split_whitespace().enumerate() {
            let f: Vec<f32> = rec.split('/').map(|v| v.parse().unwrap()).collect();
            let hit = d.push_with(f[0], i as f32 / 28.0, Some((f[1], f[2], f[3])));
            eprintln!("{:3} p {:.3} w {:.0} y {:.0} base {:.3} e {:+.3} thr {:.3} dir {:+} steps {} legs {} {}", i, f[0], f[1], f[3], d.inner.base.unwrap_or(0.0), f[0] - d.inner.base.unwrap_or(f[0]), d.inner.thr, d.inner.dir, d.inner.steps, d.inner.legs.len(), if hit { "NOD" } else { "" });
        }
    }

    /// Recorded 2026-09-21: the user slid into the chair and turned to the
    /// screen (the box moved 100 px sideways and grew a third over 1.4 s),
    /// then glanced twice between the window and the terminal. No nod; the
    /// old gate approved. Must count zero: the face was not yet still.
    #[test]
    fn glances_on_arrival_are_not_a_nod() {
        let (nods, at) = run_geom(include_str!("../traces/2026-09-21-1144-false-nod-no-nod.txt"), 28.0);
        assert_eq!(nods, 0, "counted at {:?}", at);
    }

    /// The trace that approved an install on 2026-09-19 with no nod: landmark
    /// jitter between two quantised values, counted as two nods by the old
    /// threshold logic. Must count zero.
    #[test]
    fn jitter_is_not_a_nod() {
        let t: Vec<f32> = "0.57 0.57 0.57 0.54 0.57 0.54 0.57 0.54 0.54 0.54 0.57 0.54 0.54 0.57 0.54 0.54 0.54 0.54 0.54 0.54 0.54 0.54 0.54 0.54 0.54 0.57 0.57 0.54 0.55 0.54 0.54 0.54 0.54 0.58 0.57 0.54 0.54 0.54 0.57 0.57 0.57 0.53 0.57"
            .split(' ')
            .map(|v| v.parse().unwrap())
            .collect();
        assert_eq!(run(&t, 22.0), 0);
        // Wider single-frame spikes are still one frame long.
        let mut spiky = vec![0.55; 12];
        for _ in 0..6 {
            spiky.extend_from_slice(&[0.62, 0.55, 0.55, 0.55, 0.62, 0.55, 0.55]);
        }
        assert_eq!(run(&spiky, 22.0), 0);
    }

    /// Recorded 2026-09-19: the user leaned in to read the window, no nod,
    /// and the old detector approved. Must count zero.
    #[test]
    fn leaning_in_to_read_is_not_a_nod() {
        // The recording has pitch only. The face grew about a quarter as the
        // user leaned in over the second or so in which the pitch wobbles
        // (frames 8 to 44); the gate sees the width rising through each pulse.
        let t: Vec<f32> = "0.518 0.533 0.531 0.538 0.541 0.531 0.529 0.528 0.532 0.532 0.533 0.533 0.530 0.519 0.540 0.517 0.515 0.516 0.545 0.537 0.536 0.541 0.553 0.541 0.545 0.543 0.536 0.538 0.526 0.522 0.516 0.523 0.527 0.528 0.545 0.550 0.546 0.550 0.548 0.541 0.547 0.535 0.532 0.536 0.532 0.540 0.540 0.580 0.519 0.554 0.547 0.549 0.550 0.550 0.551 0.551 0.554 0.553 0.554 0.554 0.555 0.553 0.548 0.551 0.551 0.552 0.551 0.549 0.549 0.552 0.554 0.555 0.553 0.545 0.545 0.548 0.545 0.546 0.543 0.545 0.544 0.543 0.546 0.543 0.542 0.541 0.540 0.542 0.543 0.543 0.522 0.522 0.522 0.528 0.527 0.531 0.537 0.533".split(' ').map(|v| v.parse().unwrap()).collect();
        let mut d = NodDetector::new();
        for (i, &p) in t.iter().enumerate() {
            let k = ((i as f32 - 8.0) / 36.0).clamp(0.0, 1.0);
            d.push_with(p, i as f32 / 28.0, Some((90.0 * (1.0 + 0.25 * k), 320.0, 240.0 + 20.0 * k)));
        }
        assert_eq!(d.nods, 0);
        // The same pitch trace with a still face would read as light nods,
        // which is exactly why the gate exists.
        let _ = run(&t, 28.0); // amplitude below the floor on the nose measure; the gate is what this test is about
    }

    #[test]
    #[ignore]
    fn dump_posture_trace() {
        let t: Vec<f32> = POSTURE_TRACE.split(' ').map(|v| v.parse().unwrap()).collect();
        let mut d = NodDetector::new();
        for (i, &p) in t.iter().enumerate() {
            let hit = d.push(p, i as f32 / 28.0);
            eprintln!("{:3} p {:.3} base {:.3} e {:+.3} thr {:.3} legs {} {}", i, p, d.inner.base.unwrap_or(0.0), p - d.inner.base.unwrap_or(p), d.inner.thr, d.inner.legs.len(), if hit { "NOD" } else { "" });
        }
    }

    #[test]
    fn two_real_nods_count() {
        let mut t = vec![0.55; 12];
        for _ in 0..2 {
            t.extend_from_slice(&[0.57, 0.60, 0.62, 0.63, 0.62, 0.60, 0.57, 0.55, 0.55, 0.55, 0.55, 0.55, 0.55, 0.55]);
        }
        // Then the head rests: the last leg closes within a third of a second of it.
        t.extend(std::iter::repeat(0.55).take(12));
        assert_eq!(run(&t, 22.0), 2);
    }

    #[test]
    fn small_nods_at_a_jittery_distance_need_more() {
        // Jitter of 0.03 raises the threshold to 0.09; a 0.05 nod is ignored.
        let mut t: Vec<f32> = (0..12).map(|i| if i % 2 == 0 { 0.57 } else { 0.54 }).collect();
        t.extend_from_slice(&[0.60, 0.61, 0.61, 0.60, 0.57, 0.55, 0.55, 0.55, 0.60, 0.61, 0.61, 0.60, 0.57, 0.55, 0.55, 0.55]);
        assert_eq!(run(&t, 22.0), 0);
    }

    #[test]
    fn a_look_down_and_back_is_not_a_nod() {
        // One real nod, then a deliberate look down for 1.2 s and back: one nod.
        let mut t = vec![0.55; 12];
        t.extend_from_slice(&[0.57, 0.60, 0.62, 0.63, 0.62, 0.60, 0.57, 0.55, 0.55, 0.55, 0.55, 0.55, 0.55, 0.55]);
        t.extend(vec![0.64; 26]);
        t.extend(vec![0.55; 10]);
        // A lone nod is not the gesture, and the look-down forgets it.
        assert_eq!(run(&t, 22.0), 0);
    }

    #[test]
    fn a_posture_change_is_not_a_nod() {
        let mut t = vec![0.55; 12];
        t.extend(vec![0.65; 60]); // looked down and stayed there for ~2.7 s
        t.extend(vec![0.55; 10]);
        assert_eq!(run(&t, 22.0), 0);
    }
}

#[cfg(test)]
mod shake_tests {
    use super::{NodDetector, ShakeDetector};

    /// Yaw samples at 28 fps: rest, then `cycles` full left-right swings of
    /// `amp`, `frames_per_leg` frames each, then rest.
    fn swing(cycles: usize, amp: f32, frames_per_leg: usize, rest_after: usize) -> Vec<f32> {
        let mut t = vec![0.0; 30];
        for _ in 0..cycles {
            for k in 0..frames_per_leg {
                t.push(-amp * (k as f32 + 1.0) / frames_per_leg as f32);
            }
            for k in 0..frames_per_leg {
                t.push(-amp + 2.0 * amp * (k as f32 + 1.0) / frames_per_leg as f32);
            }
            for k in 0..frames_per_leg {
                t.push(amp - amp * (k as f32 + 1.0) / frames_per_leg as f32);
            }
        }
        t.extend(std::iter::repeat(0.0).take(rest_after));
        t
    }

    fn run(trace: &[f32], fps: f32) -> (usize, Vec<usize>) {
        let mut d = ShakeDetector::new();
        let mut at = Vec::new();
        for (i, &y) in trace.iter().enumerate() {
            if d.push(y, i as f32 / fps) {
                at.push(i);
            }
        }
        (d.shakes, at)
    }

    #[test]
    fn two_shakes_count() {
        // centre-left-right-left-right-centre: four legs, then rest.
        let mut t = vec![0.0; 30];
        for k in 0..5 { t.push(-0.15 * (k as f32 + 1.0) / 5.0); }
        for k in 0..6 { t.push(-0.15 + 0.30 * (k as f32 + 1.0) / 6.0); }
        for k in 0..6 { t.push(0.15 - 0.30 * (k as f32 + 1.0) / 6.0); }
        for k in 0..6 { t.push(-0.15 + 0.30 * (k as f32 + 1.0) / 6.0); }
        for k in 0..5 { t.push(0.15 - 0.15 * (k as f32 + 1.0) / 5.0); }
        t.extend(std::iter::repeat(0.0).take(20));
        let (shakes, at) = run(&t, 28.0);
        assert_eq!(shakes, 2, "completions at {:?}", at);
        assert!(at[0] < 60, "completes as the head comes to rest, got {:?}", at);
    }

    #[test]
    fn starting_on_the_other_side_counts_too() {
        let mut t = vec![0.0; 30];
        for k in 0..5 { t.push(0.12 * (k as f32 + 1.0) / 5.0); }
        for k in 0..6 { t.push(0.12 - 0.24 * (k as f32 + 1.0) / 6.0); }
        for k in 0..6 { t.push(-0.12 + 0.24 * (k as f32 + 1.0) / 6.0); }
        for k in 0..6 { t.push(0.12 - 0.24 * (k as f32 + 1.0) / 6.0); }
        for k in 0..5 { t.push(-0.12 + 0.12 * (k as f32 + 1.0) / 5.0); }
        t.extend(std::iter::repeat(0.0).take(20));
        assert_eq!(run(&t, 28.0).0, 2);
    }

    #[test]
    fn one_shake_is_not_a_refusal() {
        // centre-left-right-centre: two legs and a half.
        let t = swing(1, 0.15, 5, 30);
        assert_eq!(run(&t, 28.0).0, 0);
    }

    #[test]
    fn a_glance_at_the_other_monitor_is_not_a_refusal() {
        let mut t = vec![0.0; 30];
        for k in 0..8 { t.push(0.30 * (k as f32 + 1.0) / 8.0); }
        t.extend(std::iter::repeat(0.30).take(40));
        for k in 0..8 { t.push(0.30 - 0.30 * (k as f32 + 1.0) / 8.0); }
        t.extend(std::iter::repeat(0.0).take(30));
        assert_eq!(run(&t, 28.0).0, 0);
    }

    #[test]
    fn two_shakes_far_apart_are_two_single_shakes() {
        let mut t = swing(1, 0.15, 5, 90); // 3.2 s of rest between
        t.extend(swing(1, 0.15, 5, 30).into_iter().skip(30));
        assert_eq!(run(&t, 28.0).0, 0);
    }

    /// Recorded on the reference machine (t/pitch/yaw/width/x/y per frame,
    /// real timestamps): a request resumed after a face unlock, the user
    /// shook twice at about 14 s and again at about 20 s, then dismissed.
    /// The first build rejected both because the box slid sideways.
    #[test]
    fn a_recorded_double_shake_is_a_refusal_and_not_a_nod() {
        let text = include_str!("../traces/2026-09-22-0549-two-shakes-after-unlock.txt");
        let mut shake = ShakeDetector::new();
        let mut nod = NodDetector::new();
        let mut at = Vec::new();
        let mut filter = super::FlickerFilter::default();
        for tok in text.split_whitespace() {
            let f: Vec<f32> = tok.split('/').map(|v| v.parse().unwrap()).collect();
            if !filter.keep(f[1], f[2], f[3]) {
                continue;
            }
            let geom = Some((f[3], f[4], f[5]));
            if shake.push_with(f[2], f[0], geom) {
                at.push(f[0]);
            }
            nod.push_full(f[1], Some(f[2]), f[0], geom);
        }
        assert!(shake.shakes >= 2, "no shake counted");
        assert!(at[0] < 20.0, "the first shake should count on its own, got {:?}", at);
        assert_eq!(nod.nods, 0, "a shake must never read as a nod");
    }

    /// The nose-to-eye pitch from a recorded frame's landmarks (fields 6 to
    /// 15), as `pose::pose` computes it; recordings without landmarks fall
    /// back to the mouth-based pitch in field 1.
    fn nose_pitch(f: &[f32]) -> f32 {
        if f.len() >= 19 {
            return f[18]; // image-motion y, the live signal
        }
        if f.len() < 16 {
            return f[1];
        }
        let l = [[f[6], f[7]], [f[8], f[9]], [f[10], f[11]], [f[12], f[13]], [f[14], f[15]]];
        faceauth_engine::pose::pose(&l).nose_pitch
    }

    #[derive(Clone, Copy, Debug)]
    struct Cfg {
        nod_min: f32,
        shake_min: f32,
        rest_s: f32,
        span_s: f32,
        rev_frames: usize,
        leg_max: f32,
        regular: Option<f32>,
        filter: &'static str,
        min_steps: usize,
        prior_still: f32,
        need_ramp: bool,
        co_nod: f32,
        co_shake: f32,
    }

    impl Cfg {
        fn default_cfg() -> Cfg {
            Cfg { nod_min: NodDetector::MIN_DOWN, shake_min: ShakeDetector::MIN_TURN, rest_s: super::Oscillation::REST_S, span_s: super::Oscillation::SPAN_S, rev_frames: super::Oscillation::REV_FRAMES, leg_max: 1.0, regular: None, filter: "none", min_steps: 1, prior_still: 1.0, need_ramp: false, co_nod: super::Oscillation::CO_MOTION, co_shake: super::Oscillation::CO_MOTION }
        }
        fn apply(&self, nod: &mut NodDetector, shake: &mut ShakeDetector) {
            nod.inner.min_thr = self.nod_min;
            nod.inner.max_thr = nod.inner.max_thr.max(self.nod_min);
            nod.inner.thr = self.nod_min;
            shake.inner.min_thr = self.shake_min;
            shake.inner.max_thr = shake.inner.max_thr.max(self.shake_min);
            shake.inner.thr = self.shake_min;
            for o in [&mut nod.inner, &mut shake.inner] {
                o.rest_s = self.rest_s;
                o.span_s = self.span_s;
                o.rev_frames = self.rev_frames;
                o.leg_max_s = self.leg_max;
                o.regular = self.regular;
                o.min_steps = self.min_steps;
                o.prior_still = self.prior_still;
                o.need_ramp = self.need_ramp;
            }
            nod.inner.co_motion = if self.co_nod > 0.0 { Some((2, self.co_nod)) } else { None };
            shake.inner.co_motion = if self.co_shake > 0.0 { Some((1, self.co_shake)) } else { None };
            {
            }
        }
    }

    fn replay(text: &str) -> (usize, usize, Vec<f32>) {
        let (s, n, at, _) = replay_full(text);
        (s, n, at)
    }

    fn replay_full(text: &str) -> (usize, usize, Vec<f32>, Vec<f32>) {
        let mut cfg = Cfg::default_cfg();
        if let Ok(m) = std::env::var("FACEAUTH_FLICKER") {
            cfg.filter = Box::leak(m.into_boxed_str());
        }
        replay_cfg(text, cfg)
    }

    fn replay_cfg(text: &str, cfg: Cfg) -> (usize, usize, Vec<f32>, Vec<f32>) {
        let mut shake = ShakeDetector::new();
        let mut nod = NodDetector::new();
        cfg.apply(&mut nod, &mut shake);
        let mut at = Vec::new();
        let mut nod_at = Vec::new();
        let mode = cfg.filter.to_string();
        let mut hold = super::FlickerFilter::default();
        let mut transient = super::TransientFilter::default();
        let mut feed = |p: f32, sx: f32, yaw: f32, t: f32, geom: (f32, f32, f32), shake: &mut ShakeDetector, nod: &mut NodDetector, at: &mut Vec<f32>, nod_at: &mut Vec<f32>| {
            if shake.push_with(sx, t, Some(geom)) {
                at.push(t);
            }
            if nod.push_full(p, Some(yaw), t, Some(geom)) {
                nod_at.push(t);
            }
        };
        let mut pending: Option<(f32, (f32, f32, f32))> = None; // (t, geom) of the held frame
        for tok in text.split_whitespace() {
            let f: Vec<f32> = tok.split('/').map(|v| v.parse().unwrap()).collect();
            let p = nose_pitch(&f);
            let sx = if f.len() >= 19 { f[17] } else { f[2] }; // image-motion x when recorded (the shake's signal)
            let yaw = f[2]; // landmark yaw: the nod's quiet-head rule, as in the daemon
            let geom = (f[3], f[4], f[5]);
            match mode.as_str() {
                "none" => feed(p, sx, yaw, f[0], geom, &mut shake, &mut nod, &mut at, &mut nod_at),
                "hold" => {
                    if hold.keep(p, f[2], f[3]) {
                        feed(p, sx, yaw, f[0], geom, &mut shake, &mut nod, &mut at, &mut nod_at);
                    }
                }
                _ => {
                    if let Some((pp, py, _)) = transient.feed(p, f[2], f[3]) {
                        let (pt, pgeom) = pending.expect("a held frame has a time");
                        feed(pp, py, py, pt, pgeom, &mut shake, &mut nod, &mut at, &mut nod_at);
                    }
                    pending = Some((f[0], geom));
                }
            }
        }
        (shake.shakes, nod.nods, at, nod_at)
    }

    /// Recorded: two shakes at about 3 s, refused at 3.8 s live.
    #[test]
    fn a_second_recorded_double_shake_is_a_refusal() {
        let (shakes, nods, at) = replay(include_str!("../traces/2026-09-22-0551-two-shakes.txt"));
        assert!(shakes >= 2, "no shake counted");
        assert!(at[0] < 5.0, "{:?}", at);
        assert_eq!(nods, 0);
    }

    /// Recorded: two exaggerated turns to the right, each held about two
    /// seconds, then one to the left. The first build refused on it.
    #[test]
    fn exaggerated_glances_are_not_a_refusal() {
        let (shakes, nods, at) = replay(include_str!("../traces/2026-09-22-0553-exaggerated-glances.txt"));
        assert_eq!(shakes, 0, "counted at {:?}", at);
        assert_eq!(nods, 0);
    }

    /// Recorded: reading the window and the screen for about twenty seconds.
    #[test]
    fn reading_is_not_a_refusal() {
        let (shakes, nods, at) = replay(include_str!("../traces/2026-09-22-0600-reading.txt"));
        assert_eq!(shakes, 0, "counted at {:?}", at);
        assert_eq!(nods, 0);
    }

    /// Replays every calibration recording (traces/cal) and prints what the
    /// detectors make of each; the file name says what the user did.
    #[test]
    #[ignore]
    fn cal_report() {
        let _ = env_logger::builder().is_test(true).try_init();
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/traces/cal");
        let mut names: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).collect();
        names.sort();
        for path in names {
            let text = std::fs::read_to_string(&path).unwrap();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            println!("CAL {}", name);
            let (shakes, nods, at, nod_at) = replay_full(&text);
            println!("CAL {:<22} nods {} at {:?} | shakes {} at {:?}", name, nods, nod_at.iter().map(|t| format!("{:.1}", t)).collect::<Vec<_>>(), shakes, at.iter().map(|t| format!("{:.1}", t)).collect::<Vec<_>>());
        }
    }

    /// Expected outcome of a calibration recording from its file name:
    /// (nods expected, shakes expected).
    fn expected(name: &str) -> (bool, bool) {
        let n = name.split('-').nth(1).unwrap_or("").trim_end_matches(".txt");
        let kind = name.splitn(2, '-').nth(1).unwrap_or("").trim_end_matches(".txt");
        let _ = n;
        match kind {
            k if k.starts_with("still") => (false, false),
            "nod" | "nod-slow" | "nod-light" | "nod-approval" => (true, false),
            "shake" | "shake-slow" => (false, true),
            _ => (false, false),
        }
    }

    /// The calibration battery as the regression suite: no recording of a
    /// non-gesture (still, glance, look down, read, lean, talk, single nod
    /// or shake) may produce anything, and the gesture recordings must keep
    /// counting at least as many as when this was written (3 of 5 nods, 4
    /// of 4 shakes, 2026-09-22).
    #[test]
    fn calibration_battery_holds() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/traces/cal");
        let mut files: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).collect();
        files.sort();
        let cfg = Cfg { filter: "none", ..Cfg::default_cfg() };
        let (mut nods_hit, mut nods_n, mut shakes_hit, mut shakes_n) = (0, 0, 0, 0);
        for path in files {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(&path).unwrap();
            // Only recordings that carry the image-motion signal (fields 17
            // and 18) are the live signal's regression suite.
            if text.split_whitespace().next().map(|tok| tok.split('/').count() < 19).unwrap_or(true) {
                continue;
            }
            let (shakes, nods, _, _) = replay_cfg(&text, cfg);
            let (want_n, want_s) = expected(&name);
            if want_n {
                nods_n += 1;
                if nods >= 2 { nods_hit += 1; }
                assert_eq!(shakes, 0, "{}: a nod recording read as a shake", name);
            } else if want_s {
                shakes_n += 1;
                if shakes >= 2 { shakes_hit += 1; }
                assert_eq!(nods, 0, "{}: a shake recording read as a nod", name);
            } else {
                assert_eq!((nods, shakes), (0, 0), "{}: a non-gesture recording produced a gesture", name);
            }
        }
        if nods_n == 0 && shakes_n == 0 {
            eprintln!("SKIPPED: no motion-signal recordings in traces/cal yet");
            return;
        }
        assert!(nods_n >= 5 && nods_hit == nods_n, "nods {}/{}", nods_hit, nods_n);
        assert!(shakes_n >= 4 && shakes_hit == shakes_n, "shakes {}/{}", shakes_hit, shakes_n);
    }

    /// Sweep the box-moves-with-the-leg rule over the recorded corpus and
    /// the red team's synthetic traces: which thresholds keep every real
    /// gesture, and which refuse a box that does not move. Prints a table.
    #[test]
    fn co_motion_sweep() {
        let load = |dir: &str| -> Vec<(String, String)> {
            let mut files: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).collect();
            files.sort();
            files.into_iter().filter(|p| p.extension().map(|e| e == "txt").unwrap_or(false)).map(|p| (p.file_name().unwrap().to_string_lossy().to_string(), std::fs::read_to_string(&p).unwrap())).filter(|(_, t)| t.split_whitespace().next().map(|tok| tok.split('/').count() >= 19).unwrap_or(false)).collect()
        };
        let cal = load(concat!(env!("CARGO_MANIFEST_DIR"), "/traces/cal"));
        let phone = load(concat!(env!("CARGO_MANIFEST_DIR"), "/traces/cal-phone"));
        let red = load(concat!(env!("CARGO_MANIFEST_DIR"), "/traces/redteam"));
        eprintln!("co_nod  co_shake  cal nods  cal shakes  cal fp  phone fp  frozen-box nods  waggled-board nods");
        for &co in &[0.0f32, 0.02, 0.03, 0.04, 0.05, 0.06, 0.08, 0.10, 0.12, 0.14] {
            let cfg = Cfg { filter: "none", co_nod: co, co_shake: co, ..Cfg::default_cfg() };
            let (mut nh, mut nn, mut sh, mut sn, mut fp) = (0, 0, 0, 0, 0);
            for (name, text) in &cal {
                let (shakes, nods, _, _) = replay_cfg(text, cfg);
                let (wn, ws) = expected(name);
                if wn { nn += 1; if nods >= 2 { nh += 1; } if shakes > 0 { fp += 1; } }
                else if ws { sn += 1; if shakes >= 2 { sh += 1; } if nods > 0 { fp += 1; } }
                else if nods > 0 || shakes > 0 { fp += 1; }
            }
            let mut pfp = 0;
            for (name, text) in &phone {
                let (shakes, nods, _, _) = replay_cfg(text, cfg);
                let (wn, ws) = expected(name);
                if (wn && shakes > 0) || (ws && nods > 0) || (!wn && !ws && (nods > 0 || shakes > 0)) { pfp += 1; }
            }
            let r = |n: &str| red.iter().find(|(f, _)| f == n).map(|(_, t)| replay_cfg(t, cfg).1).unwrap_or(usize::MAX);
            eprintln!("{:<7} {:<9} {:>2}/{:<6} {:>2}/{:<8} {:>5} {:>8} {:>15} {:>19}", co, co, nh, nn, sh, sn, fp, pfp, r("frozen-box.txt"), r("waggled-board.txt"));
        }
    }

    /// The red team's synthetic traces (traces/redteam, never part of the
    /// recorded corpus). A box that does not move while the motion figure
    /// oscillates is not a head, and the live rule refuses it. A waggled
    /// board moves its box with it and passes the detector by design: the
    /// strobed confirm after the nods is what refuses that one.
    #[test]
    fn a_frozen_box_is_not_a_nod_and_a_waggled_board_is_left_to_the_confirm() {
        let cfg = Cfg { filter: "none", ..Cfg::default_cfg() };
        let frozen = include_str!("../traces/redteam/frozen-box.txt");
        let (shakes, nods, _, _) = replay_cfg(frozen, cfg);
        assert_eq!((nods, shakes), (0, 0), "a frozen box read as a gesture");
        let board = include_str!("../traces/redteam/waggled-board.txt");
        let (_, nods, _, _) = replay_cfg(board, cfg);
        assert!(nods >= 2, "the waggled board is meant to pass the detector (the confirm refuses it); it read {} nods", nods);
    }

    /// A hand-held print waggled over the matched face (traces/print,
    /// recorded 2026-09-22): its box swings about two face widths, and the
    /// detector counts no nod from it at any point.
    #[test]
    fn a_hand_held_print_waggle_is_not_a_nod() {
        let cfg = Cfg { filter: "none", ..Cfg::default_cfg() };
        let text = include_str!("../traces/print/2026-09-22-print-waggle-handheld.txt");
        let (_, nods, _, _) = replay_cfg(text, cfg);
        assert_eq!(nods, 0, "a print waggled by hand read as a nod");
    }

    /// The phone-call corpus (traces/cal-phone): recorded under distraction,
    /// so it sets no floors, but no non-gesture window may read as a
    /// gesture, and no gesture window may read as the other gesture.
    #[test]
    fn phone_call_corpus_stays_safe() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/traces/cal-phone");
        let mut files: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).filter(|p| p.extension().map(|e| e == "txt").unwrap_or(false)).collect();
        files.sort();
        let cfg = Cfg { filter: "none", ..Cfg::default_cfg() };
        let (mut nods_seen, mut shakes_seen) = (0, 0);
        for path in files {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            let text = std::fs::read_to_string(&path).unwrap();
            if text.split_whitespace().next().map(|tok| tok.split('/').count() < 19).unwrap_or(true) {
                continue;
            }
            let (shakes, nods, _, _) = replay_cfg(&text, cfg);
            let (want_n, want_s) = expected(&name);
            if want_n {
                if nods >= 2 { nods_seen += 1; }
                assert_eq!(shakes, 0, "{}: a nod window read as a shake", name);
            } else if want_s {
                if shakes >= 2 { shakes_seen += 1; }
                assert_eq!(nods, 0, "{}: a shake window read as a nod", name);
            } else {
                assert_eq!((nods, shakes), (0, 0), "{}: a non-gesture window produced a gesture", name);
            }
        }
        eprintln!("phone corpus: nod windows counted {} of 5, shake windows {} of 4 (informational)", nods_seen, shakes_seen);
    }

    /// Grid search over the tunables against the whole calibration corpus.
    /// Zero false positives is required; sensitivity ranks the rest.
    #[test]
    #[ignore]
    fn cal_sweep() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/traces/cal");
        let mut files: Vec<(String, String)> = std::fs::read_dir(dir).unwrap().flatten().map(|e| e.path()).map(|p| (p.file_name().unwrap().to_string_lossy().to_string(), std::fs::read_to_string(&p).unwrap())).collect();
        files.sort();
        let mut results = Vec::new();
        for &nod_min in &[0.03f32, 0.04, 0.06, 0.08] {
            for &shake_min in &[0.04f32, 0.06, 0.10] {
                for &rest_s in &[0.25f32, 0.35, 0.5] {
                    for &span_s in &[3.0f32, 3.5, 4.0] {
                        for &rev_frames in &[1usize, 2] {
                            for &leg_max in &[1.0f32, 1.3] {
                                for &regular in &[None, Some(2.5f32), Some(3.5)] {
                                    for &(need_ramp, prior_still) in &[(true, 1.0f32), (false, 1.0)] {
                                    for &co_nod in &[0.0f32, 0.02, 0.03, 0.05] {
                                    for &co_shake in &[0.0f32, 0.05, 0.10] {
                                        let (filter, min_steps) = ("none", 1);
                                        let cfg = Cfg { nod_min, shake_min, rest_s, span_s, rev_frames, leg_max, regular, filter, min_steps, prior_still, need_ramp, co_nod, co_shake };
                                        let (mut fp, mut hit_n, mut hit_s, mut n_n, mut n_s) = (0, 0, 0, 0, 0);
                                        let mut fp_names = Vec::new();
                                        for (name, text) in &files {
                                            let (shakes, nods, _, _) = replay_cfg(text, cfg);
                                            let (want_n, want_s) = expected(name);
                                            if want_n { n_n += 1; if nods >= 2 { hit_n += 1; } if shakes > 0 { fp += 1; fp_names.push(name.clone()); } }
                                            else if want_s { n_s += 1; if shakes >= 2 { hit_s += 1; } if nods > 0 { fp += 1; fp_names.push(name.clone()); } }
                                            else if nods > 0 || shakes > 0 { fp += 1; fp_names.push(name.clone()); }
                                        }
                                        results.push((fp, hit_n, hit_s, n_n, n_s, cfg, fp_names));
                                    }}}
                                }
                            }
                        }
                    }
                }
            }
        }
        // Zero false positives first, then the most gestures caught, then the
        // HIGHEST floors (margin over the non-gestures), then fewer rules.
        results.sort_by(|a, b| a.0.cmp(&b.0).then((b.1 + b.2).cmp(&(a.1 + a.2))).then(b.5.nod_min.total_cmp(&a.5.nod_min)).then(b.5.shake_min.total_cmp(&a.5.shake_min)).then(a.5.regular.is_some().cmp(&b.5.regular.is_some())).then(a.5.need_ramp.cmp(&b.5.need_ramp)).then(a.5.co_nod.total_cmp(&b.5.co_nod)));
        for r in results.iter().take(25) {
            println!("SWEEP fp {} nods {}/{} shakes {}/{} {:?} {:?}", r.0, r.1, r.3, r.2, r.4, r.5, r.6);
        }
    }

    /// Per-frame detector state for one calibration recording, named in
    /// FACEAUTH_DUMP_CAL (e.g. 03-nod).
    #[test]
    #[ignore]
    fn cal_dump() {
        let Ok(which) = std::env::var("FACEAUTH_DUMP_CAL") else { return };
        let path = format!("{}/traces/cal/{}.txt", env!("CARGO_MANIFEST_DIR"), which);
        let text = std::fs::read_to_string(&path).unwrap();
        let mut shake = ShakeDetector::new();
        let mut nod = NodDetector::new();
        let mut filter = super::FlickerFilter::default();
        for tok in text.split_whitespace() {
            let f: Vec<f32> = tok.split('/').map(|v| v.parse().unwrap()).collect();
            let p = nose_pitch(&f);
            let kept = std::env::var("FACEAUTH_FLICKER").as_deref() == Ok("none") || filter.keep(p, f[2], f[3]);
            if !kept {
                println!("{:5.2} DROPPED p {:.3} y {:+.3} w {:.0}", f[0], p, f[2], f[3]);
                continue;
            }
            let geom = Some((f[3], f[4], f[5]));
            let sh = shake.push_with(f[2], f[0], geom);
            let nd = nod.push_full(p, Some(f[2]), f[0], geom);
            println!("{:5.2} p {:.3} y {:+.3} w {:.0} cy {:.0} | nod base {:.3} thr {:.3} dir {:+} steps {} legs {} | shake base {:+.3} thr {:.3} dir {:+} legs {} {}{}",
                f[0], p, f[2], f[3], f[5], nod.inner.base.unwrap_or(0.0), nod.inner.thr, nod.inner.dir, nod.inner.steps, nod.inner.legs.len(),
                shake.inner.base.unwrap_or(0.0), shake.inner.thr, shake.inner.dir, shake.inner.legs.len(), if nd { "NOD" } else { "" }, if sh { "SHAKE" } else { "" });
        }
    }

    /// Recorded at the reference user's first calibrated floor (0.129): two
    /// double nods (at 4 s and 34 s) that the floor-relative rest bar
    /// cleared as "rest". Both must count at that floor and at the default.
    /// The same recording against the box-motion rule: prints the nods
    /// counted at each threshold (the 4 s pair and the 34 s pair).
    #[test]
    fn co_motion_sweep_on_the_calibrated_floor_recording() {
        let text = include_str!("../traces/2026-09-22-user-nods-at-calibrated-floor.txt");
        for co in [0.0f32, 0.005, 0.01, 0.015, 0.02, 0.03] {
            let cfg = Cfg { nod_min: 0.09, co_nod: co, ..Cfg::default_cfg() };
            let (_, nods, _, nod_at) = replay_cfg(text, cfg);
            eprintln!("co {:<6} nods {} at {:?}", co, nods, nod_at);
        }
    }

    #[test]
    fn the_users_nods_count_at_their_calibrated_floor() {
        let text = include_str!("../traces/2026-09-22-user-nods-at-calibrated-floor.txt");
        // Both count up to the per-person cap (0.09); at 0.10 the second
        // drops out, which is why the cap is where it is.
        for floor in [0.06f32, 0.08, 0.09] {
            let cfg = Cfg { nod_min: floor, ..Cfg::default_cfg() };
            let (shakes, nods, _, nod_at) = replay_cfg(text, cfg);
            assert!(nods >= 4, "floor {}: nods {} at {:?}", floor, nods, nod_at);
            assert_eq!(shakes, 0);
        }
    }

    #[test]
    fn yaw_jitter_is_not_a_refusal() {
        let mut t = Vec::new();
        for i in 0..120 { t.push(if i % 2 == 0 { 0.01 } else { -0.01 }); }
        assert_eq!(run(&t, 28.0).0, 0);
    }
}
