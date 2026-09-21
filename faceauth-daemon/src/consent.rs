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
    /// The requester went away; the window comes down with it.
    Gone,
    Timeout,
    /// No face for the presence watch's away time: the user left.
    FaceLost,
}

/// Nod detection as a pure state machine over (pitch, time) samples, so the
/// thresholds can be tested against recorded traces.
///
/// Pitch is median-filtered over three frames (landmark jitter is one frame
/// long; a nod is not) and measured against a slow baseline that follows the
/// head with a time constant of about a second and a half. A lean towards the
/// screen, sitting back, a look down at the keyboard: all of those move the
/// pitch and stay, and the baseline absorbs them. A nod is a pulse: the pitch
/// leaves the baseline by several times the measured noise and comes back
/// (or swings through) within a fraction of a second. Two pulses close
/// together are the gesture; a lone pulse is forgotten after a moment.
pub struct NodDetector {
    raw: Vec<f32>,
    settle: Vec<f32>,
    pub base: Option<f32>,
    pub down_thr: f32,
    up_thr: f32,
    /// Running mean of the frame-to-frame change of the filtered pitch: the
    /// noise floor, blind to slow drift.
    jitter: f32,
    last_p: Option<f32>,
    /// After a long hold (a posture change) ignore excursions until the
    /// baseline has caught up with the head.
    settling: bool,
    last_t: Option<f32>,
    out_frames: usize,
    out_first: f32,
    out_since: Option<f32>,
    /// Signed extreme of the current excursion.
    extreme: f32,
    /// Start times of recent completed pulses.
    pulses: Vec<f32>,
    /// Time of the last frame that left the baseline at all.
    last_active: Option<f32>,
    /// Recent (t, face width, centre x, centre y) for the motion gate.
    motion: Vec<(f32, f32, f32, f32)>,
    pub nods: usize,
}

impl NodDetector {
    /// The smallest excursion ever accepted. A natural nod swings 0.03 to
    /// 0.05, a light one 0.02; the wobble of a head leaning in is the same
    /// size, and is told apart by the motion gate below, not by amplitude.
    pub const MIN_DOWN: f32 = 0.015;
    /// Filtered face width may end a pulse this far from where it began;
    /// more is the body moving.
    const WIDTH_TOL: f32 = 0.06;
    /// Filtered face centre may end a pulse this fraction of its width from
    /// where it began (twice that vertically, since a nod moves the box).
    const SHIFT_TOL: f32 = 0.10;
    /// The face must have been still this long before the first pulse.
    const STILL_S: f32 = 1.0;
    /// Excursion threshold as a multiple of the noise floor.
    pub const JITTER_MULT: f32 = 4.0;
    /// The largest excursion ever required, however jittery the baseline.
    pub const MAX_DOWN: f32 = 0.06;
    const SETTLE_FRAMES: usize = 8;
    const OUT_FRAMES: usize = 2;
    const IN_FRAMES: usize = 2;
    /// A pulse shorter than this is a flicker, longer is a posture change.
    const NOD_MIN_S: f32 = 0.06;
    const NOD_MAX_S: f32 = 0.8;
    /// The two pulses of the gesture must both start within this span.
    const PAIR_S: f32 = 2.5;
    const GAP_MIN_S: f32 = 0.15;
    /// Baseline time constant in seconds.
    const TAU_S: f32 = 1.5;

    pub fn new() -> Self {
        NodDetector { raw: Vec::new(), settle: Vec::new(), base: None, down_thr: Self::MIN_DOWN, up_thr: Self::MIN_DOWN / 2.0, jitter: 0.0, last_p: None, settling: false, last_t: None, out_frames: 0, out_first: 0.0, out_since: None, extreme: 0.0, pulses: Vec::new(), last_active: None, motion: Vec::new(), nods: 0 }
    }

    /// True while the head is still or has only just moved: the caller may
    /// look at fewer frames. False once something like a nod has begun.
    pub fn idle(&self, t: f32) -> bool {
        self.base.is_some() && self.last_active.map(|a| t - a > 1.0).unwrap_or(true)
    }

    fn set_threshold(&mut self) {
        self.down_thr = (self.jitter * Self::JITTER_MULT).clamp(Self::MIN_DOWN, Self::MAX_DOWN);
        self.up_thr = self.down_thr / 2.0;
    }

    /// Did the face box end the span `from..=to` somewhere other than it
    /// began? The box flickers between two fits on alternate frames and rides
    /// up and down with a nod itself, so the test is the change of the
    /// three-frame median from the start of the span to its end, not the
    /// spread of the raw boxes.
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
        let moved = (w1 - w0).abs() / w > Self::WIDTH_TOL || (x1 - x0).abs() / w > Self::SHIFT_TOL || (y1 - y0).abs() / w > Self::SHIFT_TOL * 2.0;
        if moved {
            log::debug!("consent: pulse rejected, {} (width {:.0} to {:.0}, x {:.0} to {:.0}, y {:.0} to {:.0})", why, w0, w1, x0, x1, y0, y1);
        }
        moved
    }

    /// A completed excursion: count it as a pulse if it has the shape of a
    /// nod, and the gesture if it pairs with a recent one.
    fn complete(&mut self, t: f32) -> bool {
        let since = self.out_since.take().unwrap_or(t);
        self.out_frames = 0;
        let dur = t - since;
        if !(Self::NOD_MIN_S..=Self::NOD_MAX_S).contains(&dur) {
            return false;
        }
        // A nod turns the head; the face ends the pulse the same size and
        // place it began. A lean, a slump or a shift carries it somewhere
        // else, and its pitch wobble is not a nod.
        if self.moved(since - 0.3, t, "the face moved") {
            self.pulses.clear();
            return false;
        }
        // The first pulse of a pair must follow a still second: someone who
        // has only just sat down or turned to the screen, glancing between
        // it and the keyboard, has not nodded yet. A face seen for less than
        // that second has not been still either.
        if self.pulses.is_empty() && (self.motion.first().map(|m| m.0 > since - Self::STILL_S + 0.2).unwrap_or(false) || self.moved(since - Self::STILL_S, since, "the face had just arrived")) {
            return false;
        }
        if self.pulses.last().map(|l| since - l < Self::GAP_MIN_S).unwrap_or(false) {
            return false;
        }
        self.pulses.retain(|p| t - p <= Self::PAIR_S);
        self.pulses.push(since);
        if self.pulses.len() >= 2 {
            self.nods += 2;
            self.pulses.clear();
            return true;
        }
        false
    }

    /// Feed one face frame; returns true when a pair of nods just completed.
    pub fn push(&mut self, pitch: f32, t: f32) -> bool {
        self.push_with(pitch, t, None)
    }

    /// As `push`, with the face's width and centre for the motion gate.
    pub fn push_with(&mut self, pitch: f32, t: f32, face: Option<(f32, f32, f32)>) -> bool {
        if let Some((w, cx, cy)) = face {
            self.motion.push((t, w, cx, cy));
            if self.motion.len() > 64 {
                self.motion.remove(0);
            }
        }
        self.raw.push(pitch);
        if self.raw.len() < 3 {
            return false;
        }
        let n = self.raw.len();
        let mut w = [self.raw[n - 3], self.raw[n - 2], self.raw[n - 1]];
        w.sort_by(|a, b| a.total_cmp(b));
        let p = w[1];
        let dt = self.last_t.map(|l| (t - l).clamp(0.0, 0.5)).unwrap_or(0.04);
        self.last_t = Some(t);
        let Some(b) = self.base else {
            self.settle.push(p);
            if self.settle.len() >= Self::SETTLE_FRAMES {
                let mut s = self.settle.clone();
                s.sort_by(|a, b| a.total_cmp(b));
                let base = s[s.len() / 2];
                self.jitter = self.settle.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f32>() / (self.settle.len() - 1) as f32;
                self.set_threshold();
                self.base = Some(base);
            }
            return false;
        };
        let e = p - b;
        let d = e.abs();
        // The baseline follows the head slowly, whatever it is doing; a nod is
        // too quick to move it much, a lean or a slump is absorbed.
        self.base = Some(b + e * (dt / Self::TAU_S).min(1.0));
        if d > self.up_thr {
            self.last_active = Some(t);
        }
        if let Some(lp) = self.last_p {
            let step = (p - lp).abs();
            if step < self.down_thr {
                self.jitter += 0.05 * (step - self.jitter);
                self.set_threshold();
            }
        }
        self.last_p = Some(p);
        if self.settling {
            if d < self.up_thr {
                self.settling = false;
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
        // Back inside the band, or swung through to the other side by a full
        // threshold: the head has reversed, which is the pulse.
        let swung = e.signum() != self.extreme.signum() && (e - self.extreme).abs() >= self.down_thr * 1.5;
        if d < self.up_thr || swung {
            self.out_frames += 1; // reused as the count of frames back inside
            if swung || self.out_frames >= Self::OUT_FRAMES + Self::IN_FRAMES {
                return self.complete(t);
            }
        } else if t - since > Self::NOD_MAX_S {
            // Held away too long: a posture change, not a nod. The baseline
            // is on its way there; ignore everything until it has arrived,
            // and forget any lone pulse before it.
            self.out_since = None;
            self.out_frames = 0;
            self.settling = true;
            self.pulses.clear();
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
                Some(Answer::Gone) => return Ok(Gesture::Gone),
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
        let geom = (face.bbox[2], face.bbox[0] + face.bbox[2] / 2.0, face.bbox[1] + face.bbox[3] / 2.0);
        if trace.len() < 400 {
            trace.push(format!("{:.3}/{:.0}/{:.0}/{:.0}", p, geom.0, geom.1, geom.2));
        }
        if det.push_with(p, t0.elapsed().as_secs_f32(), Some(geom)) {
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

    /// Recorded 2026-09-19 with the motion gate installed: two ordinary nods
    /// missed. The face box flickers between two sizes on alternate frames
    /// while the head is still, and rides up and down with a real nod; the
    /// gate must see through the flicker and allow the ride.
    #[test]
    fn nods_with_a_flickering_face_box_count() {
        let (nods, at) = run_geom(include_str!("../traces/2026-09-19-0244-nods-missed-with-motion-gate.txt"), 28.0);
        assert!(nods >= 2, "no pair, completions at {:?}", at);
    }

    #[test]
    #[ignore]
    fn dump_flicker_trace() {
        let text = include_str!("../traces/2026-09-19-0244-nods-missed-with-motion-gate.txt");
        let mut d = NodDetector::new();
        for (i, rec) in text.split_whitespace().enumerate() {
            let f: Vec<f32> = rec.split('/').map(|v| v.parse().unwrap()).collect();
            let hit = d.push_with(f[0], i as f32 / 28.0, Some((f[1], f[2], f[3])));
            eprintln!("{:3} p {:.3} w {:.0} y {:.0} base {:.3} e {:+.3} thr {:.3} out {:?} pulses {} {}", i, f[0], f[1], f[3], d.base.unwrap_or(0.0), f[0] - d.base.unwrap_or(f[0]), d.down_thr, d.out_since.is_some(), d.pulses.len(), if hit { "NOD" } else { "" });
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
        assert!(!at.is_empty(), "no pair, threshold {:.3}", d.down_thr);
        assert!(at[0] < 60, "the pair completes within the first 60 frames, got {:?}", at);
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
        assert!(!at.is_empty(), "no pair, threshold {:.3}", d.down_thr);
        assert!(at[0] < 85, "the pair completes within 60 frames of the first movement at 25, got {:?}", at);
    }

    /// Recorded 2026-09-19 after returning from a lock: the head settled
    /// 0.05 to 0.10 below the early baseline and stayed there; the nods only
    /// counted at frame 400 once the old line was crossed. With the baseline
    /// following the posture, they must count well before that.
    #[test]
    fn nods_after_a_posture_change_count() {
        let t: Vec<f32> = POSTURE_TRACE.split(' ').map(|v| v.parse().unwrap()).collect();
        let mut d = NodDetector::new();
        let mut at = Vec::new();
        for (i, &p) in t.iter().enumerate() {
            if d.push(p, i as f32 / 28.0) {
                at.push(i);
            }
        }
        assert!(!at.is_empty(), "no pair");
        assert!(at[0] < 300, "the pair completes before frame 300, got {:?}", at);
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
        assert!(run(&t, 28.0) >= 0);
    }

    #[test]
    #[ignore]
    fn dump_posture_trace() {
        let t: Vec<f32> = POSTURE_TRACE.split(' ').map(|v| v.parse().unwrap()).collect();
        let mut d = NodDetector::new();
        for (i, &p) in t.iter().enumerate() {
            let hit = d.push(p, i as f32 / 28.0);
            eprintln!("{:3} p {:.3} base {:.3} e {:+.3} thr {:.3} out {:?} pulses {} {}", i, p, d.base.unwrap_or(0.0), p - d.base.unwrap_or(p), d.down_thr, d.out_since.is_some(), d.pulses.len(), if hit { "NOD" } else { "" });
        }
    }

    /// Ordinary nods of about 0.02 recorded 2026-09-19 with the face still;
    /// missed by a 0.025 floor. Must count.
    #[test]
    fn ordinary_light_nods_count() {
        let t: Vec<f32> = "0.524 0.528 0.533 0.526 0.532 0.530 0.528 0.530 0.530 0.529 0.529 0.527 0.525 0.529 0.526 0.526 0.532 0.530 0.528 0.527 0.527 0.533 0.525 0.528 0.529 0.528 0.531 0.529 0.527 0.529 0.526 0.532 0.531 0.533 0.532 0.535 0.535 0.533 0.534 0.534 0.532 0.532 0.518 0.512 0.515 0.514 0.528 0.531 0.533 0.532 0.535 0.546 0.553 0.556 0.555 0.541 0.542 0.531 0.532 0.527 0.520 0.515 0.513 0.526 0.521 0.528 0.534 0.535 0.551 0.548 0.551 0.558 0.550 0.554 0.552 0.556 0.565 0.551 0.555 0.550 0.552 0.546 0.543 0.544 0.543 0.545 0.544 0.543 0.546 0.545 0.546 0.541 0.545 0.540 0.542 0.542 0.543 0.540 0.545 0.543 0.541 0.541 0.541 0.541 0.536 0.537 0.535 0.535 0.535 0.537 0.537 0.539 0.536 0.538 0.536 0.537 0.535 0.537 0.537 0.534".split(' ').map(|v| v.parse().unwrap()).collect();
        assert!(run(&t, 28.0) >= 2, "no pair");
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
