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
use faceauth_engine::{pose, Pipeline};
use serde::Serialize;
use std::path::Path;
use std::time::{Duration, Instant};

/// What the window (or the CLI) can send while a request is pending.
#[derive(Clone, Debug)]
pub enum Answer {
    /// The user typed their password into the window.
    Password(String),
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
    /// The command being elevated, when it can be named (sudo's arguments, pkexec's).
    pub command: String,
    /// The chain above it: "alacritty (3910) <- bash (3921)".
    pub parents: String,
    /// The process to kill if the user says no: the requester, not the helper.
    pub kill_pid: i32,
    pub via: String,
}

fn read_proc(pid: i32, what: &str) -> Option<String> {
    std::fs::read(format!("/proc/{}/{}", pid, what)).ok().map(|b| String::from_utf8_lossy(&b).replace('\0', " ").trim().to_string())
}

fn exe_of(pid: i32) -> String {
    std::fs::read_link(format!("/proc/{}/exe", pid)).map(|p| p.display().to_string()).unwrap_or_default()
}

fn ppid_of(pid: i32) -> Option<i32> {
    let stat = read_proc(pid, "stat")?;
    // "pid (comm) state ppid ..."; comm may contain spaces, so split after the last ')'.
    let rest = stat.rsplit(')').next()?;
    rest.split_whitespace().nth(1)?.parse().ok()
}

fn comm_of(pid: i32) -> String {
    read_proc(pid, "comm").unwrap_or_default()
}

fn real_uid_of(pid: i32) -> Option<u32> {
    read_proc(pid, "status")?.lines().find_map(|l| l.strip_prefix("Uid:")).and_then(|v| v.split_whitespace().next()).and_then(|s| s.parse().ok())
}

fn starttime_of(pid: i32) -> u64 {
    read_proc(pid, "stat").and_then(|s| s.rsplit(')').next().and_then(|r| r.split_whitespace().nth(19).and_then(|v| v.parse().ok()))).unwrap_or(0)
}

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
            // The helper is polkit's; the requester is the newest pkexec (or other
            // polkit client) running with the user's real uid. Best effort.
            info.via = "polkit".into();
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
                        if best.map(|(bt, _)| t > bt).unwrap_or(true) {
                            best = Some((t, p));
                        }
                    }
                }
            }
            log::debug!("consent: polkit requester search, uid {} processes: {}", user_uid, seen.join(" "));
            match best {
                Some((_, p)) => {
                    info.kill_pid = p;
                    // cmdline of a setuid process may be unreadable too; fall back to its name.
                    let cl = read_proc(p, "cmdline").unwrap_or_default();
                    info.command = if cl.is_empty() { format!("{} (arguments not readable)", comm_of(p)) } else { cl };
                    info.parents = parent_chain(p);
                }
                None => {
                    info.command = "a polkit action".into();
                }
            }
        } else {
            info.via = base.clone();
            info.command = cmdline.clone();
            info.parents = parent_chain(pid);
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
}

#[derive(Serialize)]
struct Payload<'a> {
    state: &'a str,
    message: &'a str,
    caller: &'a CallerInfo,
    seconds: f32,
}

impl Dialog {
    pub fn new(cfg: &Config, user: &str) -> Self {
        Dialog { cfg: cfg.clone(), user: user.to_string(), open: false }
    }

    fn shell(&self, args: &[&str]) -> Result<()> {
        let omarchy_path = self.cfg.omarchy_path.clone().unwrap_or_else(|| {
            std::fs::read_to_string("/etc/omarchy.conf")
                .ok()
                .and_then(|t| t.lines().find_map(|l| l.strip_prefix("OMARCHY_PATH=").map(|v| v.trim_matches('"').to_string())))
                .unwrap_or_else(|| "/usr/share/omarchy".into())
        });
        let status = std::process::Command::new("/usr/bin/timeout")
            .args(["5", "/usr/bin/systemd-run", "--quiet", "--wait", "--collect", "--user"])
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
        let payload = serde_json::to_string(&Payload { state, message, caller, seconds })?;
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
    }
}

/// A desktop notification in the user's session: every elevation by face
/// announces itself, so a loop is visible the first time it fires.
pub fn notify(cfg: &Config, user: &str, title: &str, body: &str) {
    let d = Dialog::new(cfg, user);
    let omarchy_path = cfg.omarchy_path.clone().unwrap_or_else(|| "/usr/share/omarchy".into());
    let _ = std::process::Command::new("/usr/bin/timeout")
        .args(["5", "/usr/bin/systemd-run", "--quiet", "--collect", "--user"])
        .arg(format!("--machine={}@.host", d.user))
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
    /// The window supplied a password (verified by the caller).
    Password(String),
    Dismissed,
    Timeout,
    /// No face for the presence watch's away time: the user left.
    FaceLost,
}

/// Nod detection as a pure state machine over (pitch, time) samples, so the
/// thresholds can be tested against recorded traces.
///
/// Pitch is median-filtered over three frames (landmark jitter is one frame
/// long; a nod is not). The baseline is measured from the first frames and
/// then follows slow posture drift. A nod leaves the baseline by several
/// times the measured jitter for two consecutive frames and then either comes
/// back or swings through to the other side; it lasts a fraction of a second,
/// and a head held away for longer is a posture change that re-arms only once
/// the head is back.
pub struct NodDetector {
    raw: Vec<f32>,
    settle: Vec<f32>,
    pub base: Option<f32>,
    pub down_thr: f32,
    up_thr: f32,
    out_frames: usize,
    in_frames: usize,
    out_since: Option<f32>,
    /// When the pitch first left the baseline in this excursion.
    out_first: f32,
    /// The farthest the pitch got from the baseline during this excursion, signed.
    extreme: f32,
    last_nod: Option<f32>,
    /// After a swing through to the far side, wait for the head to settle
    /// (or re-baseline there if it does not come back) before arming.
    need_return: Option<f32>,
    /// Time of the last frame that left the baseline at all.
    last_active: Option<f32>,
    /// Running mean of |pitch - base| over still frames: the noise floor.
    jitter: f32,
    pub nods: usize,
}

impl NodDetector {
    /// The smallest excursion ever accepted (a natural nod swings 0.03 to 0.05).
    pub const MIN_DOWN: f32 = 0.015;
    /// Excursion threshold as a multiple of the measured jitter.
    pub const JITTER_MULT: f32 = 4.0;
    /// The largest excursion ever required, however jittery the baseline.
    pub const MAX_DOWN: f32 = 0.06;
    const SETTLE_FRAMES: usize = 8;
    const OUT_FRAMES: usize = 2;
    const IN_FRAMES: usize = 2;
    const NOD_MIN_S: f32 = 0.06;
    const NOD_MAX_S: f32 = 0.8;
    const GAP_MIN_S: f32 = 0.15;
    /// Baseline follows the head while it is still (per idle frame).
    const DRIFT: f32 = 0.08;
    /// A head held on the far side of a swing this long has settled there.
    const SETTLE_S: f32 = 0.5;

    fn rebase(&mut self, p: f32) {
        self.base = Some(p);
        self.out_since = None;
        self.out_frames = 0;
        self.in_frames = 0;
        self.need_return = None;
    }

    pub fn new() -> Self {
        NodDetector { raw: Vec::new(), settle: Vec::new(), base: None, down_thr: Self::MIN_DOWN, up_thr: Self::MIN_DOWN / 2.0, out_frames: 0, in_frames: 0, out_since: None, out_first: 0.0, extreme: 0.0, last_nod: None, need_return: None, last_active: None, jitter: 0.0, nods: 0 }
    }

    /// True while the head is still or has only just moved: the caller may
    /// look at fewer frames. False once something like a nod has begun.
    pub fn idle(&self, t: f32) -> bool {
        self.base.is_some() && self.last_active.map(|a| t - a > 1.0).unwrap_or(true)
    }

    fn complete(&mut self, t: f32, since: f32) -> bool {
        self.out_since = None;
        self.out_frames = 0;
        let dur = t - since;
        let gap_ok = self.last_nod.map(|l| t - l >= Self::GAP_MIN_S).unwrap_or(true);
        if (Self::NOD_MIN_S..=Self::NOD_MAX_S).contains(&dur) && gap_ok {
            self.nods += 1;
            self.last_nod = Some(t);
            return true;
        }
        false
    }

    /// Feed one face frame; returns true when a nod just completed.
    pub fn push(&mut self, pitch: f32, t: f32) -> bool {
        self.raw.push(pitch);
        if self.raw.len() < 3 {
            return false;
        }
        let n = self.raw.len();
        let mut w = [self.raw[n - 3], self.raw[n - 2], self.raw[n - 1]];
        w.sort_by(|a, b| a.total_cmp(b));
        let p = w[1];
        let Some(b) = self.base else {
            self.settle.push(p);
            if self.settle.len() >= Self::SETTLE_FRAMES {
                let mut s = self.settle.clone();
                s.sort_by(|a, b| a.total_cmp(b));
                let base = s[s.len() / 2];
                self.jitter = s.iter().map(|v| (v - base).abs()).sum::<f32>() / s.len() as f32;
                self.down_thr = (self.jitter * Self::JITTER_MULT).clamp(Self::MIN_DOWN, Self::MAX_DOWN);
                self.up_thr = self.down_thr / 2.0;
                self.base = Some(base);
            }
            return false;
        };
        let e = p - b;
        let d = e.abs();
        if d > self.up_thr {
            self.last_active = Some(t);
        }
        if self.out_since.is_none() && d < self.down_thr {
            // Not in a nod: let the baseline follow slow posture drift.
            self.base = Some(b + Self::DRIFT * e);
        }
        if d < self.down_thr {
            // The noise floor keeps being measured on frames inside the band,
            // so a flickering landmark raises the bar and a steady one lowers it.
            self.jitter += 0.05 * (d - self.jitter);
            self.down_thr = (self.jitter * Self::JITTER_MULT).clamp(Self::MIN_DOWN, Self::MAX_DOWN);
            self.up_thr = self.down_thr / 2.0;
        }
        if let Some(since) = self.need_return {
            if d < self.up_thr {
                self.need_return = None;
            } else if t - since > Self::SETTLE_S {
                // The head settled on the far side: that is the new baseline.
                self.rebase(p);
            }
            return false;
        }
        let Some(since) = self.out_since else {
            if d > self.down_thr {
                if self.out_frames == 0 {
                    self.out_first = t;
                }
                self.out_frames += 1;
                if self.out_frames >= Self::OUT_FRAMES {
                    self.out_since = Some(self.out_first);
                    self.in_frames = 0;
                    self.extreme = e;
                }
            } else {
                self.out_frames = 0;
            }
            return false;
        };
        if e.abs() > self.extreme.abs() && e.signum() == self.extreme.signum() {
            self.extreme = e;
        }
        // Back at the baseline, or swung through to the other side by a full
        // threshold: either way the head has reversed, which is the nod.
        let swung = e.signum() != self.extreme.signum() && (e - self.extreme).abs() >= self.down_thr * 1.5;
        if d < self.up_thr || swung {
            self.in_frames += 1;
            if self.in_frames >= Self::IN_FRAMES || swung {
                let done = self.complete(t, since);
                if swung {
                    // The head is on the far side now; wait for it to settle.
                    self.need_return = Some(t);
                }
                return done;
            }
        } else {
            self.in_frames = 0;
            if t - since > Self::NOD_MAX_S {
                // Held away too long: a posture change, not a nod. The head
                // is where it is now; measure the next nod from there.
                self.rebase(p);
            }
        }
        false
    }
}

pub fn wait_for_nods(cap: &mut IrCapture, pipeline: &mut Pipeline, min_detection: f32, window: Duration, nods_needed: usize, answers: Option<(&Answers, &str)>, lost_after: Option<Duration>) -> Result<Gesture> {
    let t0 = Instant::now();
    let mut last_face = Instant::now();
    let mut det = NodDetector::new();
    let mut trace: Vec<String> = Vec::new();
    let mut frame_no = 0usize;
    while t0.elapsed() < window {
        if let Some((answers, user)) = answers {
            match take_answer(answers, user) {
                Some(Answer::Password(pw)) => {
                    log::info!("consent: password answer after {} nods in {:.1}s, base {:?}, threshold {:.3}, pitch trace {}", det.nods, t0.elapsed().as_secs_f32(), det.base, det.down_thr, trace.join(" "));
                    return Ok(Gesture::Password(pw));
                }
                Some(Answer::Dismiss) => {
                    log::info!("consent: dismissed after {} nods in {:.1}s, pitch trace {}", det.nods, t0.elapsed().as_secs_f32(), trace.join(" "));
                    return Ok(Gesture::Dismissed);
                }
                None => {}
            }
        }
        if let Some(l) = lost_after {
            if last_face.elapsed() > l {
                log::info!("consent: no face for {:.0}s after {} nods; the user left", l.as_secs_f32(), det.nods);
                return Ok(Gesture::FaceLost);
            }
        }
        let Some(img) = cap.next(Duration::from_secs(1))? else { continue };
        // Slow polling while the head is still: every other frame is looked
        // at (a nod leaves the baseline for six or more frames, so its start
        // cannot slip between two), the rest are only drained. Once a
        // movement begins every frame is looked at.
        frame_no += 1;
        if det.idle(t0.elapsed().as_secs_f32()) && frame_no % 2 != 0 {
            continue;
        }
        let faces = pipeline.detector.detect(&img, min_detection)?;
        let Some(face) = faces.into_iter().max_by(|a, b| a.score.total_cmp(&b.score)) else { continue };
        last_face = Instant::now();
        let p = pose::pose(&face.landmarks).pitch;
        if trace.len() < 400 {
            trace.push(format!("{:.3}", p));
        }
        if det.push(p, t0.elapsed().as_secs_f32()) {
            log::debug!("consent: nod {} at {:.2}s", det.nods, t0.elapsed().as_secs_f32());
            if det.nods >= nods_needed {
                log::info!("consent: {} nods, base {:?}, threshold {:.3}, pitch trace {}", det.nods, det.base, det.down_thr, trace.join(" "));
                return Ok(Gesture::Nodded);
            }
        }
    }
    log::info!("consent: {} nods in {:.1}s ({} face frames), base {:?}, threshold {:.3}, pitch trace {}", det.nods, window.as_secs_f32(), trace.len(), det.base, det.down_thr, trace.join(" "));
    Ok(Gesture::Timeout)
}

#[cfg(test)]
mod nod_tests {
    use super::NodDetector;

    fn run(trace: &[f32], fps: f32) -> usize {
        let mut d = NodDetector::new();
        for (i, &p) in trace.iter().enumerate() {
            d.push(p, i as f32 / fps);
        }
        d.nods
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

    /// Two natural nods recorded 2026-09-19 (swing about 0.035 either side of
    /// the baseline), followed by the head drifting lower. The old threshold
    /// of 0.045 missed both; they must count, and the drift must not.
    #[test]
    fn natural_nods_count() {
        let t: Vec<f32> = "0.552 0.551 0.550 0.550 0.559 0.556 0.550 0.555 0.549 0.559 0.554 0.555 0.561 0.557 0.564 0.555 0.562 0.561 0.550 0.543 0.558 0.531 0.525 0.528 0.522 0.521 0.521 0.526 0.531 0.551 0.580 0.595 0.588 0.592 0.582 0.579 0.550 0.520 0.518 0.515 0.516 0.515 0.518 0.527 0.573 0.575 0.585 0.587 0.591 0.582 0.573 0.571 0.566 0.548 0.546 0.547 0.541 0.541 0.541 0.534 0.539 0.547 0.543 0.542 0.545 0.542 0.543 0.551 0.540 0.536 0.549 0.542 0.542 0.545 0.547 0.537 0.535 0.529 0.523 0.526 0.508 0.529 0.520 0.522 0.524 0.519 0.520 0.516 0.514 0.516 0.510 0.507 0.517 0.515 0.505 0.517 0.510"
            .split(' ')
            .map(|v| v.parse().unwrap())
            .collect();
        let mut d = NodDetector::new();
        let mut at = Vec::new();
        for (i, &p) in t.iter().enumerate() {
            if d.push(p, i as f32 / 22.0) {
                at.push(i);
            }
        }
        assert_eq!(at.len(), 2, "nods at frames {:?}, threshold {:.3}", at, d.down_thr);
        assert!(at[1] < 60, "both nods are within the first 60 frames, got {:?}", at);
    }

    /// Two small natural nods recorded 2026-09-19 at about 28 examined frames
    /// a second (swing 0.03, out of the noise band for only two or three
    /// frames each way). Took 160 frames to count under a 0.10 s minimum
    /// duration; must count within 60 frames of the first movement.
    #[test]
    fn small_quick_nods_count_promptly() {
        let t: Vec<f32> = "0.518 0.516 0.506 0.520 0.525 0.516 0.517 0.520 0.516 0.507 0.519 0.511 0.512 0.514 0.504 0.512 0.507 0.514 0.508 0.527 0.533 0.534 0.535 0.520 0.528 0.545 0.516 0.524 0.525 0.496 0.488 0.486 0.517 0.526 0.514 0.522 0.540 0.548 0.546 0.524 0.512 0.538 0.520 0.530 0.516 0.512 0.504 0.495 0.520 0.519 0.507 0.512 0.506 0.511 0.548 0.548 0.550 0.549 0.547 0.518 0.519 0.509 0.512 0.513 0.510 0.513 0.506 0.512 0.504 0.505 0.508 0.545 0.501 0.511 0.531 0.540 0.543 0.544 0.544 0.542 0.542 0.541 0.548 0.538 0.545 0.546 0.540 0.544 0.543 0.528 0.539 0.530 0.526 0.535 0.528 0.533 0.540 0.537 0.541 0.515 0.540 0.539 0.543 0.540 0.543 0.543 0.543 0.539 0.540 0.518 0.522 0.516 0.525 0.539 0.524 0.528 0.528 0.529 0.540 0.527 0.526 0.527 0.547 0.525 0.527 0.546 0.530 0.546 0.527 0.524 0.540 0.540 0.544 0.545 0.527 0.526 0.525 0.548 0.548 0.550 0.545 0.529 0.546 0.544 0.539 0.550 0.543 0.545 0.525 0.544 0.540 0.543 0.545 0.542 0.524 0.543 0.543 0.524 0.531 0.543".split(' ').map(|v| v.parse().unwrap()).collect();
        let mut d = NodDetector::new();
        let mut at = Vec::new();
        for (i, &p) in t.iter().enumerate() {
            if d.push(p, i as f32 / 28.0) {
                at.push(i);
            }
        }
        assert!(at.len() >= 2, "nods at frames {:?}, threshold {:.3}", at, d.down_thr);
        assert!(at[1] < 85, "second nod within 60 frames of the first movement at 25, got {:?}", at);
    }

    /// Light nods recorded 2026-09-19: dips of 0.017 in a noise floor of
    /// 0.004, never seen at a 0.025 threshold (the user typed the password
    /// after ten seconds). Must count at least two.
    #[test]
    fn light_nods_count() {
        let t: Vec<f32> = "0.528 0.519 0.520 0.533 0.532 0.533 0.530 0.530 0.534 0.537 0.529 0.531 0.532 0.533 0.532 0.534 0.533 0.537 0.538 0.534 0.535 0.532 0.535 0.535 0.535 0.534 0.534 0.536 0.536 0.537 0.539 0.535 0.525 0.516 0.513 0.517 0.535 0.540 0.534 0.526 0.512 0.516 0.532 0.536 0.535 0.537 0.536 0.531 0.534 0.532 0.531 0.531 0.534 0.539 0.534 0.537 0.539 0.536 0.535 0.543 0.536 0.532 0.536 0.536 0.543 0.537 0.539 0.543 0.540 0.539 0.538 0.538 0.539 0.541 0.543 0.542 0.544 0.538 0.541 0.542 0.543 0.545 0.543 0.542 0.544 0.540 0.544 0.540 0.546 0.545 0.541 0.544 0.545 0.542 0.549 0.544 0.542 0.543 0.546 0.548 0.544 0.548 0.546 0.549 0.545 0.544 0.540 0.542 0.545 0.545 0.547 0.543 0.538 0.543 0.550 0.542 0.542 0.538 0.538 0.544 0.545 0.547 0.551 0.546 0.546 0.540 0.544 0.541 0.544 0.539 0.538 0.543 0.540 0.541 0.537 0.545 0.538 0.540 0.539 0.536 0.537 0.541 0.537 0.540 0.539 0.542 0.548 0.542 0.543 0.544 0.542 0.539 0.541 0.546 0.538 0.539 0.545 0.545 0.539 0.543 0.537 0.539 0.539 0.538 0.539 0.532 0.536 0.537 0.540 0.539 0.533 0.538 0.537 0.534 0.541 0.535 0.534 0.534 0.535 0.536 0.533 0.535 0.535 0.533 0.534 0.534 0.539 0.535 0.536 0.535 0.537 0.536 0.536 0.535 0.533 0.535 0.534 0.533 0.537 0.531 0.534 0.532 0.531 0.534 0.534 0.532 0.529 0.536 0.536 0.531 0.533 0.532 0.532 0.534 0.532 0.533 0.537 0.535 0.533 0.532 0.530 0.531 0.528 0.531 0.527 0.533 0.531 0.531 0.531 0.532 0.527 0.528 0.532 0.524 0.524 0.531 0.534 0.535 0.532 0.536 0.553 0.540 0.546 0.546 0.527 0.525 0.519 0.526 0.529 0.539 0.540 0.542 0.543 0.542 0.539 0.541 0.537 0.534 0.535 0.539 0.541 0.533 0.531 0.526 0.523 0.523 0.521 0.521 0.546 0.521 0.524 0.521 0.520 0.530 0.525 0.525 0.534 0.538 0.534 0.535 0.530 0.536 0.537 0.536 0.535 0.538 0.542".split(' ').map(|v| v.parse().unwrap()).collect();
        let mut d = NodDetector::new();
        let mut at = Vec::new();
        for (i, &p) in t.iter().enumerate() {
            if d.push(p, i as f32 / 28.0) {
                at.push(i);
            }
        }
        assert!(at.len() >= 2, "nods at frames {:?}, threshold {:.3}", at, d.down_thr);
    }

    /// Recorded 2026-09-19 after returning from a lock: the head settled
    /// 0.05 to 0.10 below the early baseline and stayed there; the nods only
    /// counted at frame 400 once the old line was crossed. With the baseline
    /// following the posture, they must count well before that.
    #[test]
    fn nods_after_a_posture_change_count() {
        let t: Vec<f32> = "0.572 0.606 0.598 0.589 0.578 0.570 0.559 0.553 0.556 0.552 0.547 0.551 0.548 0.544 0.548 0.555 0.555 0.548 0.558 0.555 0.557 0.551 0.554 0.547 0.543 0.546 0.547 0.546 0.548 0.541 0.532 0.524 0.551 0.576 0.582 0.524 0.560 0.529 0.528 0.561 0.583 0.581 0.584 0.567 0.561 0.579 0.578 0.574 0.575 0.572 0.572 0.570 0.568 0.568 0.566 0.531 0.562 0.529 0.568 0.567 0.569 0.530 0.529 0.537 0.531 0.540 0.527 0.524 0.527 0.531 0.526 0.523 0.525 0.530 0.527 0.527 0.525 0.527 0.529 0.526 0.531 0.526 0.527 0.537 0.529 0.525 0.529 0.531 0.523 0.522 0.523 0.524 0.524 0.526 0.525 0.527 0.523 0.524 0.519 0.523 0.519 0.523 0.523 0.524 0.537 0.527 0.530 0.523 0.527 0.525 0.521 0.516 0.520 0.534 0.520 0.517 0.527 0.519 0.535 0.532 0.519 0.531 0.520 0.517 0.524 0.525 0.521 0.523 0.523 0.523 0.523 0.526 0.521 0.524 0.524 0.521 0.520 0.519 0.523 0.558 0.520 0.513 0.534 0.541 0.518 0.533 0.517 0.515 0.520 0.524 0.524 0.532 0.531 0.524 0.524 0.524 0.525 0.561 0.563 0.557 0.554 0.548 0.548 0.551 0.549 0.541 0.537 0.520 0.511 0.528 0.532 0.520 0.521 0.508 0.517 0.523 0.528 0.540 0.535 0.485 0.483 0.495 0.477 0.471 0.483 0.516 0.525 0.511 0.508 0.502 0.506 0.493 0.495 0.499 0.489 0.489 0.488 0.504 0.503 0.500 0.501 0.491 0.500 0.491 0.476 0.488 0.470 0.474 0.475 0.477 0.462 0.473 0.453 0.489 0.486 0.483 0.492 0.473 0.466 0.477 0.487 0.492 0.492 0.503 0.513 0.502 0.494 0.505 0.508 0.496 0.495 0.487 0.525 0.515 0.504 0.511 0.527 0.515 0.546 0.534 0.542 0.533 0.513 0.523 0.514 0.512 0.531 0.534 0.523 0.533 0.533 0.543 0.545 0.537 0.552 0.547 0.546 0.545 0.547 0.524 0.546 0.536 0.523 0.557 0.533 0.538 0.520 0.514 0.520 0.528 0.533 0.528 0.532 0.535 0.535 0.530 0.534 0.530 0.537 0.535 0.528 0.530 0.530 0.538 0.539 0.544 0.547 0.542 0.545 0.521 0.521 0.526 0.532 0.550 0.550 0.560 0.518 0.518 0.513 0.525 0.553 0.562 0.566 0.568 0.563 0.564 0.563 0.563 0.568 0.561 0.560 0.563 0.563 0.563 0.559 0.561 0.561 0.562 0.560 0.560 0.560 0.560 0.560 0.554 0.561 0.558 0.560 0.556 0.559 0.555 0.554 0.555 0.549 0.551 0.549 0.541 0.552 0.555 0.559 0.549 0.539 0.542 0.550 0.546 0.545 0.547 0.541 0.539 0.545 0.543 0.552 0.550 0.551 0.553 0.557 0.552 0.554 0.553 0.558 0.558 0.557 0.559 0.559 0.558 0.555 0.555 0.554 0.559 0.560 0.559 0.560 0.558 0.564 0.561 0.565 0.557 0.564 0.568 0.563 0.560 0.562 0.558 0.562 0.565 0.563 0.559 0.562 0.566 0.568 0.566 0.567 0.570 0.574 0.578 0.574 0.576 0.571 0.572 0.575 0.576".split(' ').map(|v| v.parse().unwrap()).collect();
        let mut d = NodDetector::new();
        let mut at = Vec::new();
        for (i, &p) in t.iter().enumerate() {
            if d.push(p, i as f32 / 28.0) {
                at.push(i);
            }
        }
        assert!(at.len() >= 2, "nods at frames {:?}", at);
        assert!(at[1] < 300, "second nod before frame 300, got {:?}", at);
    }

    #[test]
    fn two_real_nods_count() {
        let mut t = vec![0.55; 12];
        for _ in 0..2 {
            t.extend_from_slice(&[0.57, 0.60, 0.62, 0.63, 0.62, 0.60, 0.57, 0.55, 0.55, 0.55, 0.55, 0.55, 0.55, 0.55]);
        }
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
        assert_eq!(run(&t, 22.0), 1);
    }

    #[test]
    fn a_posture_change_is_not_a_nod() {
        let mut t = vec![0.55; 12];
        t.extend(vec![0.65; 60]); // looked down and stayed there for ~2.7 s
        t.extend(vec![0.55; 10]);
        assert_eq!(run(&t, 22.0), 0);
    }
}
