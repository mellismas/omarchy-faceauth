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
    cfg: Config,
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
}

/// Nod detection as a pure state machine over (pitch, time) samples, so the
/// thresholds can be tested against recorded traces.
///
/// Pitch is median-filtered over three frames (landmark jitter is one frame
/// long; a nod is not). The baseline and the jitter are measured from the
/// first frames, and a nod must leave the baseline by several times that
/// jitter, stay out for three consecutive frames, come back for two, and the
/// nods must be spaced like a head movement, not like a flickering landmark.
pub struct NodDetector {
    raw: Vec<f32>,
    settle: Vec<f32>,
    pub base: Option<f32>,
    pub down_thr: f32,
    up_thr: f32,
    out_frames: usize,
    in_frames: usize,
    out_since: Option<f32>,
    last_nod: Option<f32>,
    /// After a long hold away from baseline, wait for a return before arming.
    need_return: bool,
    /// Time of the last frame that left the baseline at all.
    last_active: Option<f32>,
    pub nods: usize,
}

impl NodDetector {
    /// The smallest excursion ever accepted (a natural nod is about 0.05).
    pub const MIN_DOWN: f32 = 0.045;
    /// Excursion threshold as a multiple of the measured jitter.
    pub const JITTER_MULT: f32 = 3.0;
    const SETTLE_FRAMES: usize = 8;
    const OUT_FRAMES: usize = 3;
    const IN_FRAMES: usize = 2;
    const NOD_MIN_S: f32 = 0.12;
    const NOD_MAX_S: f32 = 0.8;
    const GAP_MIN_S: f32 = 0.25;

    pub fn new() -> Self {
        NodDetector { raw: Vec::new(), settle: Vec::new(), base: None, down_thr: Self::MIN_DOWN, up_thr: Self::MIN_DOWN / 2.0, out_frames: 0, in_frames: 0, out_since: None, last_nod: None, need_return: false, last_active: None, nods: 0 }
    }

    /// True while the head is still or has only just moved: the caller may
    /// look at fewer frames. False once something like a nod has begun.
    pub fn idle(&self, t: f32) -> bool {
        self.base.is_some() && self.last_active.map(|a| t - a > 1.0).unwrap_or(true)
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
                let jitter = s.iter().map(|v| (v - base).abs()).fold(0f32, f32::max);
                self.down_thr = (jitter * Self::JITTER_MULT).max(Self::MIN_DOWN);
                self.up_thr = self.down_thr / 2.0;
                self.base = Some(base);
            }
            return false;
        };
        let d = (p - b).abs();
        if d > self.up_thr {
            self.last_active = Some(t);
        }
        if self.need_return {
            if d < self.up_thr {
                self.need_return = false;
            }
            return false;
        }
        if self.out_since.is_none() {
            if d > self.down_thr {
                self.out_frames += 1;
                if self.out_frames >= Self::OUT_FRAMES {
                    self.out_since = Some(t);
                    self.in_frames = 0;
                }
            } else {
                self.out_frames = 0;
            }
            return false;
        }
        let since = self.out_since.unwrap();
        if d < self.up_thr {
            self.in_frames += 1;
            if self.in_frames >= Self::IN_FRAMES {
                self.out_since = None;
                self.out_frames = 0;
                let dur = t - since;
                let gap_ok = self.last_nod.map(|l| t - l >= Self::GAP_MIN_S).unwrap_or(true);
                if (Self::NOD_MIN_S..=Self::NOD_MAX_S).contains(&dur) && gap_ok {
                    self.nods += 1;
                    self.last_nod = Some(t);
                    return true;
                }
            }
        } else {
            self.in_frames = 0;
            if t - since > Self::NOD_MAX_S {
                // Held away too long: a posture change, not a nod. Re-arm
                // only once the head is back at the baseline.
                self.out_since = None;
                self.out_frames = 0;
                self.need_return = true;
            }
        }
        false
    }
}

pub fn wait_for_nods(cap: &mut IrCapture, pipeline: &mut Pipeline, min_detection: f32, window: Duration, nods_needed: usize, answers: Option<(&Answers, &str)>) -> Result<Gesture> {
    let t0 = Instant::now();
    let mut det = NodDetector::new();
    let mut trace: Vec<String> = Vec::new();
    let mut frame_no = 0usize;
    while t0.elapsed() < window {
        if let Some((answers, user)) = answers {
            match take_answer(answers, user) {
                Some(Answer::Password(pw)) => return Ok(Gesture::Password(pw)),
                Some(Answer::Dismiss) => return Ok(Gesture::Dismissed),
                None => {}
            }
        }
        let Some(img) = cap.next(Duration::from_secs(1))? else { continue };
        // Slow polling while the head is still: every third frame is enough
        // to catch the start of a nod, and the rest are only drained. Once a
        // movement begins every frame is looked at.
        frame_no += 1;
        if det.idle(t0.elapsed().as_secs_f32()) && frame_no % 3 != 0 {
            continue;
        }
        let faces = pipeline.detector.detect(&img, min_detection)?;
        let Some(face) = faces.into_iter().max_by(|a, b| a.score.total_cmp(&b.score)) else { continue };
        let p = pose::pose(&face.landmarks).pitch;
        if trace.len() < 160 {
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
