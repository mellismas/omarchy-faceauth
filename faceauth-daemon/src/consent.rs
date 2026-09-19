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
use anyhow::{anyhow, Context, Result};
use faceauth_engine::{pose, Pipeline};
use serde::Serialize;
use std::path::Path;
use std::time::{Duration, Instant};

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
        let base = Path::new(&exe).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
        if base == "polkit-agent-helper-1" {
            // The helper is polkit's; the requester is the newest pkexec (or other
            // polkit client) running with the user's real uid. Best effort.
            info.via = "polkit".into();
            let mut best: Option<(u64, i32)> = None;
            if let Ok(rd) = std::fs::read_dir("/proc") {
                for e in rd.flatten() {
                    let Some(p) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
                    if real_uid_of(p) != Some(user_uid) {
                        continue;
                    }
                    let b = Path::new(&exe_of(p)).file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                    if b == "pkexec" || b == "run0" {
                        let t = starttime_of(p);
                        if best.map(|(bt, _)| t > bt).unwrap_or(true) {
                            best = Some((t, p));
                        }
                    }
                }
            }
            match best {
                Some((_, p)) => {
                    info.kill_pid = p;
                    info.command = read_proc(p, "cmdline").unwrap_or_default();
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
/// pitching down past a threshold and coming back, measured as the nose's
/// position between the eye line and the mouth line, which rises when the
/// head tips down. Baseline is the median of the first frames.
pub fn wait_for_nods(cap: &mut IrCapture, pipeline: &mut Pipeline, min_detection: f32, window: Duration, nods_needed: usize) -> Result<bool> {
    let t0 = Instant::now();
    let mut baseline: Vec<f32> = Vec::new();
    let mut base: Option<f32> = None;
    let mut down = false;
    let mut nods = 0usize;
    const DOWN: f32 = 0.06;
    const UP: f32 = 0.025;
    let mut trace: Vec<String> = Vec::new();
    while t0.elapsed() < window {
        let Some(img) = cap.next(Duration::from_secs(1))? else { continue };
        let faces = pipeline.detector.detect(&img, min_detection)?;
        let Some(face) = faces.into_iter().max_by(|a, b| a.score.total_cmp(&b.score)) else { continue };
        let p = pose::pose(&face.landmarks).pitch;
        if trace.len() < 120 {
            trace.push(format!("{:.2}", p));
        }
        match base {
            None => {
                baseline.push(p);
                if baseline.len() >= 6 {
                    baseline.sort_by(|a, b| a.total_cmp(b));
                    base = Some(baseline[baseline.len() / 2]);
                }
            }
            Some(b) => {
                if !down && p > b + DOWN {
                    down = true;
                } else if down && p < b + UP {
                    down = false;
                    nods += 1;
                    log::debug!("consent: nod {} at {:.2}s", nods, t0.elapsed().as_secs_f32());
                    if nods >= nods_needed {
                        log::info!("consent: {} nods, base {:.3}, pitch trace {}", nods, b, trace.join(" "));
                        return Ok(true);
                    }
                }
            }
        }
    }
    log::info!("consent: {} nods in {:.1}s, base {:?}, pitch trace {}", nods, window.as_secs_f32(), base, trace.join(" "));
    Ok(false)
}
