//! `faceauth`: the command-line front end. For now the camera subcommands that
//! prove the capture crate on hardware; enrol, test, doctor follow.

use anyhow::{anyhow, bail, Context, Result};
use faceauth_camera::ipu3::SensorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(feature = "dev-tools")]
mod dev;

fn usage() -> ! {
    eprintln!(
        "usage:\n  faceauth cam probe\n  faceauth cam graph\n  faceauth auth [--user NAME] [--socket PATH] [--consent]   (asks a running faceauthd; --consent = window + nod)\n  faceauth probe [--user NAME] [--socket PATH]     (one short look: is a face there?)
  faceauth enroll [--user NAME] [--label TEXT] [--start distance]   (root; the walk-through window, the same one Setup > Security > Face opens; --guided is accepted)
  faceauth enroll [--user NAME] [--label TEXT] --terminal [--poses up,down]   (root; the five looks from the terminal, no window)
  faceauth enroll [--user NAME] [--label TEXT] --look [--seconds N] [--count N]   (root; one look, as the camera sees it, no walk-through)
  faceauth enrol-control continue|redo|cancel [--user NAME]   (from the enrolment window)\n  faceauth templates delete [--user NAME]\n  faceauth models fetch [--manifest FILE] [--dir DIR]   (development: the omarchy-faceauth-models package ships the files)\n  faceauth doctor [--json]\n  faceauth consent-answer [--user NAME] [--dismiss|--ack|--rearm|--passwordless MIN]   (from the consent window; stdin: token line, then password line)\n  faceauth calibrate [--user NAME] --guided              (root; the gesture and everyday rounds in the walk-through window, stored with the templates)\n  faceauth presence on|off [--user NAME] [--away-seconds N]   (root; rewrites the config, restarts the service)\n  faceauth presence mode [default|secure] [--user NAME]   (as the watched user; reads or switches the watch's mode until the next restart; prints {{\"presence\":{{\"mode\":..,\"watching\":..}}}})\n  faceauth presence [--user NAME]                  (the watch's mode and, for the watched user, its state){}",
        dev_usage()
    );
    std::process::exit(2)
}

/// The development tools' usage lines, in a build that has them.
#[cfg(feature = "dev-tools")]
fn dev_usage() -> &'static str {
    dev::USAGE
}

#[cfg(not(feature = "dev-tools"))]
fn dev_usage() -> &'static str {
    ""
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let argv: Vec<&str> = args.iter().map(String::as_str).collect();
    // The bring-up and tuning tools exist only in a development build:
    // the package ships none of them (H2).
    #[cfg(feature = "dev-tools")]
    if let Some(r) = dev::dispatch(&argv) {
        return r;
    }
    match argv.as_slice() {
        ["cam", "probe"] => cam_probe(),
        ["cam", "graph"] => cam_graph(),
        ["enroll", rest @ ..] => {
            // Production path: the daemon owns the camera and the store.
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let label = opt(rest, "--label").unwrap_or("enrol");
            if rest.contains(&"--terminal") {
                let only: Vec<String> = opt(rest, "--poses")
                    .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default();
                return enroll_guided(&socket, &user, label, &only);
            }
            if !rest.contains(&"--look") {
                // The walk-through, and the default: the daemon opens the
                // window Setup > Security > Face uses, the person follows
                // it, and the outcome comes back here. `--guided` still
                // names it for scripts written when it was not the default.
                let start_at = opt(rest, "--start");
                println!(
                    "Enrolling {}: follow the window on your screen. This terminal waits for it.",
                    user
                );
                let o = faceauth_daemon::server::enrol_session(&socket, &user, label, start_at)?;
                return match &o {
                    faceauth_daemon::auth::Outcome::Enrolled {
                        added,
                        total,
                        consistency_min,
                        consistency_mean,
                        path,
                    } => {
                        println!("Saved {} templates ({} new) to {}", total, added, path);
                        println!(
                            "Template self-consistency (pairwise cosine): min {:.3} mean {:.3}",
                            consistency_min, consistency_mean
                        );
                        println!("{}", at_rest_note(path));
                        Ok(())
                    }
                    faceauth_daemon::auth::Outcome::Error { message } => {
                        Err(anyhow!("enrolment failed: {}", message))
                    }
                    other => Err(anyhow!(
                        "enrolment failed: {}",
                        serde_json::to_string(other)?
                    )),
                };
            }
            let seconds: f32 = opt(rest, "--seconds").unwrap_or("12").parse()?;
            let count: usize = opt(rest, "--count").unwrap_or("10").parse()?;
            println!(
                "Enrolling {}: look at the camera and move your head a little over the next {} s.",
                user, seconds as u32
            );
            let o = faceauth_daemon::server::enroll(&socket, &user, label, seconds, count, None)?;
            match &o {
                faceauth_daemon::auth::Outcome::Enrolled {
                    added,
                    total,
                    consistency_min,
                    consistency_mean,
                    path,
                } => {
                    println!("Saved {} templates ({} new) to {}", total, added, path);
                    println!(
                        "Template self-consistency (pairwise cosine): min {:.3} mean {:.3}",
                        consistency_min, consistency_mean
                    );
                    println!("{}", at_rest_note(path));
                    Ok(())
                }
                other => bail!("enrolment failed: {}", serde_json::to_string(other)?),
            }
        }
        ["templates", "delete", rest @ ..] => {
            only_flags(rest, &["--socket", "--user"])?;
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let o = faceauth_daemon::server::delete_templates(&socket, &user)?;
            finish(&o)
        }
        ["models", "fetch", rest @ ..] => models_fetch(rest),
        ["doctor", rest @ ..] => doctor(rest),
        ["enrol-control", word, rest @ ..] => {
            // From the enrolment window: continue, redo or cancel.
            only_flags(rest, &["--socket", "--user"])?;
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let o = faceauth_daemon::server::enrol_control(&socket, &user, word)?;
            finish(&o)
        }
        ["probe", rest @ ..] => {
            only_flags(rest, &["--socket", "--user"])?;
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let o = faceauth_daemon::server::probe(&socket, &user, Duration::from_secs(5))?;
            finish(&o)
        }
        ["presence", mode @ ("on" | "off"), rest @ ..] => {
            // Root: edit the [presence] keys in the config and restart the service.
            let cfg_path = opt(rest, "--config")
                .unwrap_or("/etc/faceauth/config.toml")
                .to_string();
            let user = user_arg(rest)?;
            let away_arg = opt(rest, "--away-seconds").unwrap_or("20");
            let away: f32 = away_arg
                .parse()
                .with_context(|| format!("--away-seconds {}: not a number", away_arg))?;
            // A config that does not parse is not replaced by one that only
            // holds [presence]: the administrator's other keys would go with
            // it. A missing file starts empty (F4).
            let text = match std::fs::read_to_string(&cfg_path) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(e).with_context(|| format!("read {}", cfg_path)),
            };
            let edited = presence_edit(&text, &cfg_path, *mode == "on", &user, away)?;
            write_config_atomically(&cfg_path, &edited)
                .with_context(|| format!("write {} (run as root)", cfg_path))?;
            let st = std::process::Command::new("/usr/bin/systemctl")
                .args(["restart", "faceauth.service"])
                .status()
                .context("run /usr/bin/systemctl")?;
            if !st.success() {
                bail!(
                    "presence watch {} written to {}, but the service did not restart ({}); see `systemctl status faceauth.service`",
                    mode,
                    cfg_path,
                    st
                );
            }
            if *mode == "on" {
                println!(
                    "presence watch on for {} (away after {} s); service restarted",
                    user, away
                );
            } else {
                println!("presence watch off; service restarted");
            }
            Ok(())
        }
        ["calibrate", rest @ ..] if rest.contains(&"--guided") => {
            // Root: the gesture and everyday rounds in the walk-through window.
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            println!("Tuning gestures for {}: follow the window on your screen. This terminal waits for it.", user);
            let o = faceauth_daemon::server::enrol_session(&socket, &user, "tune", Some("bridge"))?;
            match &o {
                faceauth_daemon::auth::Outcome::Enrolled { .. } => {
                    println!("Done. Your nods, shakes and everyday movements are recorded with your templates.");
                    Ok(())
                }
                faceauth_daemon::auth::Outcome::Error { message } => {
                    Err(anyhow!("tuning failed: {}", message))
                }
                other => Err(anyhow!("tuning failed: {}", serde_json::to_string(other)?)),
            }
        }
        ["consent-answer", rest @ ..] => {
            only_flags(
                rest,
                &[
                    "--socket",
                    "--user",
                    "--dismiss",
                    "--ack",
                    "--rearm",
                    "--passwordless",
                ],
            )?;
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            // The token came with the window's payload; without it the daemon
            // treats the answer as nobody's. It arrives on stdin, first line,
            // never on the command line (argv is readable and journaled).
            // The token and the password are wiped after the send with the
            // daemon's own helper; a plain drop leaves the bytes in freed
            // memory (J26).
            let mut token = String::new();
            std::io::stdin().read_line(&mut token)?;
            token.truncate(token.trim_end_matches(['\n', '\r']).len());
            let token_ref = if token.is_empty() {
                None
            } else {
                Some(token.as_str())
            };
            let token = token_ref;
            let o = if rest.contains(&"--ack") {
                faceauth_daemon::server::consent_ack(&socket, &user, token)?
            } else if let Some(m) = opt(rest, "--passwordless") {
                faceauth_daemon::server::consent_passwordless(
                    &socket,
                    &user,
                    m.parse().context("--passwordless takes minutes")?,
                    token,
                )?
            } else if rest.contains(&"--dismiss") {
                faceauth_daemon::server::consent_answer(&socket, &user, None, true, token)?
            } else if rest.contains(&"--rearm") {
                faceauth_daemon::server::consent_rearm(&socket, &user, token)?
            } else {
                let mut pw = String::new();
                std::io::stdin().read_line(&mut pw)?;
                pw.truncate(pw.trim_end_matches(['\n', '\r']).len());
                let r = faceauth_daemon::server::consent_answer(
                    &socket,
                    &user,
                    Some(&pw),
                    false,
                    token,
                );
                faceauth_daemon::consent::wipe_string(&mut pw);
                r?
            };
            let mut token = token.map(String::from).unwrap_or_default();
            faceauth_daemon::consent::wipe_string(&mut token);
            finish(&o)
        }
        ["presence", "mode", rest @ ..] => {
            // As the watched user, over the socket: no argument reads the
            // mode, "default" or "secure" switches it until the next restart.
            // One JSON line for the shell's toggle; a refusal is one line on
            // stderr and exit 1.
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let mode = rest
                .first()
                .filter(|a| !a.starts_with("--"))
                .copied()
                .unwrap_or("query");
            if !matches!(mode, "query" | "default" | "secure") {
                bail!("presence mode: \"default\" or \"secure\" (or nothing, to read it)");
            }
            match faceauth_daemon::server::presence_mode(&socket, &user, mode) {
                Ok(faceauth_daemon::auth::Outcome::PresenceMode { mode, watching, .. }) => {
                    println!(
                        "{}",
                        serde_json::json!({ "presence": { "mode": mode, "watching": watching } })
                    );
                    Ok(())
                }
                Ok(faceauth_daemon::auth::Outcome::Error { message }) => {
                    eprintln!("presence mode: {}", message);
                    std::process::exit(1);
                }
                Ok(other) => {
                    eprintln!(
                        "presence mode: unexpected answer {}",
                        serde_json::to_string(&other)?
                    );
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("presence mode: {:#}", e);
                    std::process::exit(1);
                }
            }
        }
        ["presence", rest @ ..] => {
            // The watch's state, from the daemon: the mode, whether this
            // user is watched, and if so what the watch last decided.
            // Root and the watched user get the decision; anyone else
            // only the mode (H16).
            only_flags(rest, &["--socket", "--user"])?;
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let o = faceauth_daemon::server::presence_mode(&socket, &user, "query")?;
            finish(&o)
        }
        ["auth", rest @ ..] => {
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let t = Instant::now();
            let o = if rest.contains(&"--consent") {
                faceauth_daemon::server::ask_consent(&socket, &user)?
            } else {
                faceauth_daemon::server::ask(&socket, &user, Duration::from_secs(15))?
            };
            println!(
                "{} ({:.2} s round trip)",
                serde_json::to_string(&o)?,
                t.elapsed().as_secs_f64()
            );
            Ok(())
        }
        _ => usage(),
    }
}

fn cam_graph() -> Result<()> {
    use faceauth_camera::media::MediaDevice;
    for path in MediaDevice::enumerate() {
        let md = MediaDevice::open(&path)?;
        let (driver, model, bus) = md.info()?;
        println!("{}: {} {} {}", path.display(), driver, model, bus);
        let ents = md.entities()?;
        for e in &ents {
            println!(
                "  [{}] {:<24} pads {} links {} dev {:?}",
                e.id,
                e.name,
                e.pads,
                e.links,
                e.dev_node()
            );
            for l in md.links(e)? {
                let name = |id: u32| {
                    ents.iter()
                        .find(|x| x.id == id)
                        .map(|x| x.name.clone())
                        .unwrap_or_else(|| id.to_string())
                };
                println!(
                    "      {}:{} -> {}:{} flags 0x{:x}",
                    name(l.source_entity),
                    l.source_pad,
                    name(l.sink_entity),
                    l.sink_pad,
                    l.flags
                );
            }
        }
    }
    Ok(())
}

fn cam_probe() -> Result<()> {
    let p = faceauth_camera::probe()?;
    println!("video nodes:");
    for (path, driver, card, fmts) in &p.video_nodes {
        println!(
            "  {:<14} {:<12} {:<40} {}",
            path.display(),
            driver,
            card,
            fmts.join(" ")
        );
    }
    match &p.ipu3 {
        None => println!("ipu3: none"),
        Some(g) => {
            println!("ipu3: {}", g.media.display());
            for s in &g.sensors {
                println!(
                    "  {:<9} {:<9} {:<16} port {} subdev {} video {} {}x{} mbus 0x{:04x} -> {}",
                    format!("{:?}", s.kind),
                    s.orientation
                        .map(|o| format!("{:?}", o))
                        .unwrap_or_else(|| "-".into()),
                    s.name,
                    s.port,
                    s.subdev.display(),
                    s.video.display(),
                    s.width,
                    s.height,
                    s.mbus_code,
                    faceauth_camera::sys::fourcc_str(s.pixelformat)
                );
                if s.kind == SensorKind::Infrared {
                    // A read of the control list, never an `Illuminator`:
                    // dropping one switches the strobe off under a running
                    // daemon's gate (J22).
                    if faceauth_camera::has_strobe(&s.subdev)? {
                        println!("            illuminator: strobe controls present");
                    } else {
                        println!("            illuminator: no strobe control (ambient only)");
                    }
                }
            }
        }
    }
    Ok(())
}

/// The person a command is about when `--user` is not given: under sudo
/// the person who ran sudo (`SUDO_UID`, the id, not the name any process
/// can set in its environment), otherwise the invoking uid. Never a
/// literal fallback, and never root: root is not authenticated by face,
/// so a command that resolves to it has to be told whom it is for (J23).
fn target_user() -> Result<String> {
    let uid = match std::env::var("SUDO_UID") {
        Ok(v) => v
            .parse::<u32>()
            .with_context(|| format!("SUDO_UID {:?} is not a uid", v))?,
        Err(_) => nix::unistd::getuid().as_raw(),
    };
    if uid == 0 {
        bail!("this command is about a user, and root is never authenticated by face: run it as the user, under sudo from the user's shell, or with --user NAME");
    }
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .ok_or_else(|| anyhow!("no user with uid {}", uid))
}

/// `--user NAME` when given, else the target user. A `--user` with no
/// name is an error, not a fall-through to somebody else (J23).
fn user_arg(rest: &[&str]) -> Result<String> {
    match opt_value(rest, "--user") {
        Ok(Some(u)) => Ok(u.to_string()),
        Ok(None) => target_user(),
        Err(e) => Err(e),
    }
}

/// The value after `key`: `Ok(None)` when the flag is absent, an error
/// when it is the last argument or is followed by another flag.
fn opt_value<'a>(rest: &'a [&str], key: &str) -> Result<Option<&'a str>> {
    let Some(i) = rest.iter().position(|a| *a == key) else {
        return Ok(None);
    };
    match rest.get(i + 1) {
        Some(v) if !v.starts_with("--") => Ok(Some(v)),
        _ => bail!("{} needs a value", key),
    }
}

fn opt<'a>(rest: &'a [&str], key: &str) -> Option<&'a str> {
    opt_value(rest, key).ok().flatten()
}

/// Refuse a flag no subcommand of this name takes: a misspelt `--user`
/// must not fall through to the default user, and a misspelt `--dismiss`
/// must not read as a password answer (J23).
fn only_flags(rest: &[&str], allowed: &[&str]) -> Result<()> {
    if let Some(bad) = rest
        .iter()
        .find(|a| a.starts_with("--") && !allowed.contains(a))
    {
        bail!("unknown flag {}", bad);
    }
    Ok(())
}

/// The exit status for a scripted subcommand, from the daemon's answer:
/// 0 when it did what was asked, 1 when it refused or the answer was a
/// denial, 2 when the daemon could not do it at all (J27).
fn exit_for(o: &faceauth_daemon::auth::Outcome) -> i32 {
    use faceauth_daemon::auth::Outcome;
    match o {
        Outcome::Match { .. }
        | Outcome::Noted
        | Outcome::Deleted
        | Outcome::NotEnrolled
        | Outcome::Enrolled { .. }
        | Outcome::Pong { .. }
        | Outcome::Probe { .. }
        | Outcome::PresenceMode { .. } => 0,
        Outcome::Error { .. } => 2,
        _ => 1,
    }
}

/// Print the daemon's answer as one JSON line and exit with `exit_for`.
fn finish(o: &faceauth_daemon::auth::Outcome) -> Result<()> {
    let line = serde_json::to_string(o)?;
    let code = exit_for(o);
    if code == 0 {
        println!("{}", line);
        Ok(())
    } else {
        eprintln!("{}", line);
        std::process::exit(code)
    }
}

/// What the saved path says about how the templates rest.
fn at_rest_note(path: &str) -> String {
    if path.ends_with(".cred") {
        "Templates are sealed to this machine's TPM, root-only: a copy is useless anywhere else, and only root can open one here.".into()
    } else {
        "Note: templates are plaintext at rest (root 0600): the daemon could not seal them (its log says why).".into()
    }
}

/// Five short rounds, one per look, so the identity covers the range of
/// poses a person uses at the machine rather than one frontal view. Each
/// round keeps only frames in its pose; a round that reads nothing in its
/// pose is offered again.
fn enroll_guided(socket: &std::path::Path, user: &str, label: &str, only: &[String]) -> Result<()> {
    use faceauth_daemon::auth::{Outcome, POSES, POSE_HINTS};
    println!("Enrolling {} in {}. Each takes about five seconds; the camera reads only frames in the look it asked for.", user, if only.is_empty() { "five looks".to_string() } else { format!("these looks: {}", only.join(", ")) });
    let mut total = 0usize;
    for (pose, hint) in POSES.iter().zip(POSE_HINTS.iter()) {
        if !only.is_empty() && !only.iter().any(|o| o == pose) {
            continue;
        }
        loop {
            println!("\n{}: {}. Starting in 2 s.", pose.to_uppercase(), hint);
            std::thread::sleep(Duration::from_secs(2));
            println!("Hold it.");
            let round_label = format!("{}-{}", label, pose);
            let o =
                faceauth_daemon::server::enroll(socket, user, &round_label, 6.0, 4, Some(pose))?;
            match &o {
                Outcome::Enrolled {
                    added, total: t, ..
                } => {
                    println!("{} frames kept for {}.", added, pose);
                    total = *t;
                    break;
                }
                Outcome::Error { message } => {
                    println!("Not read: {}", message);
                    print!("Press Enter to try {} again, or s to skip it: ", pose);
                    use std::io::Write as _;
                    std::io::stdout().flush()?;
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    if line.trim().eq_ignore_ascii_case("s") {
                        break;
                    }
                }
                other => {
                    println!("{}", serde_json::to_string(other)?);
                    return Err(anyhow!("enrolment stopped"));
                }
            }
        }
    }
    println!("\nSaved: {} templates in all.", total);
    Ok(())
}

/// Download the model weights named in the manifest, verify size and SHA-256.
/// A developer command: on an installed system the omarchy-faceauth-models
/// package owns the files under the default directory, and setup never calls
/// this.
fn models_fetch(rest: &[&str]) -> Result<()> {
    let manifest =
        PathBuf::from(opt(rest, "--manifest").unwrap_or("/usr/share/faceauth/models.toml"));
    let dir = PathBuf::from(opt(rest, "--dir").unwrap_or("/usr/share/faceauth/models"));
    let text =
        std::fs::read_to_string(&manifest).with_context(|| manifest.display().to_string())?;
    let doc: toml::Value = toml::from_str(&text)?;
    let models = doc
        .get("model")
        .and_then(|m| m.as_array())
        .ok_or_else(|| anyhow!("manifest has no [[model]] entries"))?;
    std::fs::create_dir_all(&dir)?;
    let mut failed = 0;
    for m in models {
        let name = m
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("model without name"))?;
        let url = m
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("{}: no url", name))?;
        let sha = m
            .get("sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("{}: no sha256", name))?;
        let size = m.get("size").and_then(|v| v.as_integer()).unwrap_or(0) as u64;
        let dest = dir.join(name);
        if dest.exists() && sha256_file(&dest)? == sha {
            println!("{}: present and verified", name);
            continue;
        }
        println!("{}: downloading {} bytes from {}", name, size, url);
        let tmp = dir.join(format!("{}.part", name));
        // Absolute paths and a clean environment: this runs as root.
        let status = std::process::Command::new("/usr/bin/curl")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args(["-sSL", "--fail", "-o"])
            .arg(&tmp)
            .arg(url)
            .status()
            .context("run curl")?;
        if !status.success() {
            println!("{}: download failed ({})", name, status);
            failed += 1;
            continue;
        }
        let got = sha256_file(&tmp)?;
        let len = std::fs::metadata(&tmp)?.len();
        if got != sha || (size > 0 && len != size) {
            println!(
                "{}: VERIFICATION FAILED (sha256 {} size {}), not installed",
                name, got, len
            );
            let _ = std::fs::remove_file(&tmp);
            failed += 1;
            continue;
        }
        std::fs::rename(&tmp, &dest)?;
        println!("{}: verified and installed ({} bytes)", name, len);
    }
    if failed > 0 {
        bail!("{} model(s) failed", failed);
    }
    Ok(())
}

fn sha256_file(p: &std::path::Path) -> Result<String> {
    let out = std::process::Command::new("/usr/bin/sha256sum")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg(p)
        .output()
        .context("run sha256sum")?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.split_whitespace().next().unwrap_or("").to_string())
}

/// The IR sensor as sysfs names it, without opening its node: the subdev's
/// directory name (`v4l-subdev8`) and its `name` attribute (`ov7251 3-0060`).
/// Matched by name, never by number, like the udev rule.
fn ir_sensor_from_sysfs(class_dir: &Path) -> Option<(String, String)> {
    let mut nodes: Vec<_> = std::fs::read_dir(class_dir)
        .ok()?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    nodes.sort();
    for p in nodes {
        let node = p.file_name()?.to_str()?.to_string();
        if !node.starts_with("v4l-subdev") {
            continue;
        }
        let name = std::fs::read_to_string(p.join("name"))
            .ok()?
            .trim()
            .to_string();
        if name.starts_with("ov7251 ") {
            return Some((node, name));
        }
    }
    None
}

/// The udev database's current tags for a character device (`Q:` lines in
/// `/run/udev/data/c<major>:<minor>`). `G:` lines are every tag the device
/// ever carried and stay after a rule takes one away, so they are not read.
fn udev_current_tags(db_dir: &Path, rdev: u64) -> Vec<String> {
    let (major, minor) = (nix::sys::stat::major(rdev), nix::sys::stat::minor(rdev));
    std::fs::read_to_string(db_dir.join(format!("c{}:{}", major, minor)))
        .map(|t| {
            t.lines()
                .filter_map(|l| l.strip_prefix("Q:"))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

/// The kernel's dev_t encoding (glibc's major()/minor() macros).
/// Whether this process could open the node for writing: the ACL as the
/// kernel applies it, which is the grant that matters.
fn user_can_write(dev: &Path) -> bool {
    std::fs::OpenOptions::new().write(true).open(dev).is_ok()
}

/// The verdict on the IR sensor's control node. Right is root:root 0600 with
/// no uaccess tag and no write access for the caller; anything looser lets a
/// process running as the user change the sensor under the daemon.
fn ir_node_verdict(
    mode: u32,
    uid: u32,
    gid: u32,
    current_tags: &[String],
    user_can_write: bool,
) -> (&'static str, String) {
    let root_only = uid == 0 && gid == 0 && mode & 0o077 == 0;
    let uaccess = current_tags.iter().any(|t| t == "uaccess");
    let running_as_root = unsafe { libc_geteuid() } == 0;
    let mut notes = Vec::new();
    if !root_only {
        notes.push(format!("mode {:04o} uid {} gid {} (want root:root 0600: the udev rule 72-faceauth-ir.rules is missing or not applied)", mode, uid, gid));
    }
    if uaccess {
        notes.push("tagged uaccess, so the seat user is granted access on every login".to_string());
    }
    if user_can_write && !running_as_root {
        notes.push("this user can write the sensor's controls (an ACL granted before the rule survives until reboot or `setfacl -b` on the node)".to_string());
    }
    if notes.is_empty() {
        (
            "pass",
            if running_as_root {
                "root-only, no uaccess tag (the ACL was not checked: run doctor as the user for that)".to_string()
            } else {
                "root-only, no uaccess tag, no write access for this user".to_string()
            },
        )
    } else {
        ("warn", notes.join("; "))
    }
}

extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}

/// Whether an error from the camera probe is the node refusing to open.
fn is_permission_denied(e: &anyhow::Error) -> bool {
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>()
            .map(|io| io.kind() == std::io::ErrorKind::PermissionDenied)
            .unwrap_or(false)
    })
}

/// A PAM line that counts: not blank, not a comment.
fn pam_active_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}

/// The verdict on one PAM service file. `pam.lock` must be closed by a live
/// `auth required|requisite pam_deny.so` AFTER the face line: a commented-out
/// pam_deny closes nothing, and one above the face line runs before it. On
/// the elevation services `timeout=` on a consent line is flagged, because
/// the module ignores it and an administrator reading the file would take it
/// for a bound.
fn pam_stack_verdict(id: &str, text: &str) -> (&'static str, String) {
    let want_deny = id == "pam.lock";
    let elevation = id == "pam.sudo" || id == "pam.polkit";
    let face_lines: Vec<&str> = pam_active_lines(text)
        .filter(|l| l.contains("pam_faceauth.so"))
        .collect();
    let has = !face_lines.is_empty();
    let deny_after_face = {
        let mut seen_face = false;
        let mut closed = false;
        for l in pam_active_lines(text) {
            if l.contains("pam_faceauth.so") {
                seen_face = true;
            } else if seen_face && l.contains("pam_deny.so") {
                let mut words = l.split_whitespace();
                let control = (words.next(), words.next());
                if matches!(
                    control,
                    (Some("auth"), Some("required")) | (Some("auth"), Some("requisite"))
                ) {
                    closed = true;
                }
            }
        }
        closed
    };
    let prompt = face_lines.iter().any(|l| {
        l.split_whitespace()
            .any(|w| w == "prompt" || w.starts_with("prompt="))
    });
    let consent = face_lines
        .iter()
        .any(|l| l.split_whitespace().any(|w| w == "consent"));
    let consent_timeout = face_lines.iter().any(|l| {
        l.split_whitespace().any(|w| w == "consent")
            && l.split_whitespace().any(|w| w.starts_with("timeout="))
    });
    let mut st = if !has {
        if id == "pam.greeter" {
            "info"
        } else {
            "warn"
        }
    } else if want_deny && !deny_after_face {
        "fail"
    } else if elevation && !consent {
        // A face line on sudo or polkit without `consent` (a pasted lock
        // line, a misspelt word, the older `prompt`) asks for a plain look,
        // which the daemon refuses from a root caller: the line is dead,
        // not passive (A3).
        "fail"
    } else {
        "pass"
    };
    let mut d = if has {
        "wired".to_string()
    } else {
        "not wired".to_string()
    };
    if has && elevation {
        d += if consent {
            ", consent (window + nod)"
        } else if prompt {
            ", prompt: the daemon refuses a plain look from sudo or polkit; use consent"
        } else {
            ", NO consent or prompt: the daemon refuses a plain look from sudo or polkit; add consent"
        };
    }
    if has && want_deny {
        d += if deny_after_face {
            ", closed by pam_deny"
        } else {
            ", NOT closed by a live 'auth required pam_deny.so' after the face line: an ignored module would read as success"
        };
    }
    if consent_timeout {
        d += ", timeout= on a consent line is ignored (the window waits until answered): remove it";
        if st == "pass" {
            st = "warn";
        }
    }
    (st, d)
}

#[derive(serde::Serialize)]
struct Check {
    id: &'static str,
    status: &'static str,
    detail: String,
}

/// How the daemon answered, as the rows read it.
#[derive(Debug)]
enum DaemonErr {
    /// The socket refused the connection: the ACL admits enrolled users
    /// and root, so for anyone else this is a running daemon, not a
    /// failing one.
    PermissionDenied,
    Other(String),
}

/// The illuminator row: without a strobe control the liveness gate
/// cannot run, and with `liveness_required` (the default) that refuses
/// every attempt, which is a failure, not a warning (J21).
fn illuminator_check(strobe: bool, liveness_required: bool) -> (&'static str, String) {
    if strobe {
        ("pass", "strobe controls present".into())
    } else if liveness_required {
        ("fail", "no strobe control: the liveness gate cannot run and liveness_required refuses every attempt; the ov7251 driver needs kernel patch 0002".into())
    } else {
        ("warn", "no strobe control: the liveness gate cannot run, and liveness_required = false lets a print authenticate".into())
    }
}

/// The daemon rows from its answer to a ping: what each reply and each
/// way of failing to get one means, in one place a table can test (J21,
/// STORE-14).
fn daemon_checks(
    reply: std::result::Result<faceauth_daemon::auth::Outcome, DaemonErr>,
    user: &str,
    socket: &Path,
) -> Vec<Check> {
    use faceauth_daemon::auth::Outcome;
    let mut out = Vec::new();
    let mut push = |id: &'static str, status: &'static str, detail: String| {
        out.push(Check { id, status, detail })
    };
    match reply {
        Ok(Outcome::Pong {
            version,
            model,
            templates,
            sealed,
            unbound,
            floors,
            load_error,
        }) => {
            push(
                "daemon.running",
                "pass",
                format!("faceauthd {} answering on {}", version, socket.display()),
            );
            if let Some(e) = load_error {
                push(
                    "templates.user",
                    "fail",
                    format!("templates for {} cannot be read: {}; re-enrol", user, e),
                );
                return out;
            }
            push(
                "templates.user",
                if templates > 0 { "pass" } else { "warn" },
                format!("{} template(s) for {} ({})", templates, user, model),
            );
            if templates > 0 {
                push(
                    "templates.at_rest",
                    if sealed { "pass" } else { "warn" },
                    if sealed {
                        "sealed to the TPM, root-only: a copy is useless off this machine, and only root can open one here".into()
                    } else {
                        "plaintext at rest (root 0600): the daemon could not seal (its log says why)".into()
                    },
                );
                push(
                    "gestures.calibrated",
                    if floors.is_some() { "pass" } else { "info" },
                    match floors {
                        Some((n, s)) => format!(
                            "this user's floors, the ones the nod window runs at: nod {:.1} deg, shake {:.1} deg",
                            n, s
                        ),
                        None => {
                            "default floors (Tune Gestures in Setup > Security > Face records this user's own)"
                                .into()
                        }
                    },
                );
                push(
                    "templates.camera",
                    if unbound == 0 { "pass" } else { "warn" },
                    if unbound == 0 {
                        "every template is bound to the camera that enrolled it".into()
                    } else {
                        format!("{} of {} template(s) predate camera binding and match on any camera; the next enrolment binds them", unbound, templates)
                    },
                );
            }
        }
        // The daemon is up but holds the camera for a request or an
        // enrolment; the template rows wait for a quiet moment.
        Ok(Outcome::Error { message }) if message == "busy" => {
            push(
                "daemon.running",
                "pass",
                format!("faceauthd answering on {}, busy with the camera (a request or an enrolment is running); run again for the template rows", socket.display()),
            );
        }
        Ok(o) => push(
            "daemon.running",
            "warn",
            format!(
                "unexpected reply {}",
                serde_json::to_string(&o).unwrap_or_default()
            ),
        ),
        Err(DaemonErr::PermissionDenied) => {
            push(
                "daemon.running",
                "pass",
                format!("faceauthd is running on {}; the socket admits enrolled users and root, and {} is not enrolled", socket.display(), user),
            );
            push(
                "templates.user",
                "warn",
                format!(
                    "no template(s) for {}: enrol from Setup > Security > Face",
                    user
                ),
            );
        }
        Err(DaemonErr::Other(e)) => push("daemon.running", "fail", e),
    }
    out
}

/// Stable check identifiers are public API; add, never rename.
fn doctor(rest: &[&str]) -> Result<()> {
    let json = rest.contains(&"--json");
    only_flags(rest, &["--json", "--user"])?;
    let user = user_arg(rest)?;
    let mut checks: Vec<Check> = Vec::new();
    let mut push = |id: &'static str, status: &'static str, detail: String| {
        checks.push(Check { id, status, detail })
    };

    // The daemon's config first: the socket, the models directory and
    // the liveness policy the rows below are judged against (J21).
    let conf = std::fs::read_to_string("/etc/faceauth/config.toml")
        .ok()
        .and_then(|t| toml::from_str::<toml::Value>(&t).ok());
    let conf_str = |key: &str, default: &str| -> String {
        conf.as_ref()
            .and_then(|c| c.get(key))
            .and_then(|v| v.as_str())
            .map(String::from)
            .unwrap_or_else(|| default.into())
    };
    let socket = PathBuf::from(faceauth_daemon::config::SOCKET);
    let models_dir = PathBuf::from(conf_str("models_dir", "/usr/share/faceauth/models"));
    let liveness_required = conf
        .as_ref()
        .and_then(|c| c.get("liveness_required"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    if conf.is_none() {
        push(
            "config.file",
            "warn",
            "/etc/faceauth/config.toml is not readable; the shipped defaults are assumed below"
                .into(),
        );
    }
    // camera
    let sysfs_ir = ir_sensor_from_sysfs(Path::new("/sys/class/video4linux"));
    match faceauth_camera::ipu3::probe() {
        Ok(Some(g)) => match g.ir_sensor() {
            Some(ir) => {
                // A read of the control list, never an `Illuminator`, whose
                // drop would switch the strobe off under the daemon (J22).
                let strobe = faceauth_camera::has_strobe(&ir.subdev).unwrap_or(false);
                push("camera.ir", "pass", format!("{} on {} ({}x{})", ir.name, ir.video.display(), ir.width, ir.height));
                let (st, d) = illuminator_check(strobe, liveness_required);
                push("camera.illuminator", st, d);
                push("camera.rgb", if g.colour_sensor().is_some() { "pass" } else { "warn" }, g.colour_sensor().map(|c| c.name.clone()).unwrap_or_else(|| "no front colour sensor".into()));
            }
            None => push("camera.ir", "fail", "IPU3 graph found but no front IR sensor".into()),
        },
        Ok(None) => push("camera.ir", "unknown", "no IPU3 graph; UVC IR cameras need ir_video in the config".into()),
        // The probe opens every sensor's control node and stops at the first
        // it cannot open. Once the udev rule holds, the IR sensor's node is
        // root-only and doctor runs as the user, so that is the expected
        // outcome, not a fault: the sensor is read from sysfs instead, which
        // needs no access to the node.
        Err(e) if is_permission_denied(&e) => match &sysfs_ir {
            Some((node, name)) => push("camera.ir", "pass", format!("{} on /dev/{}, owned by root (expected once the udev rule is in place; run as root for the illuminator and RGB checks)", name, node)),
            None => push("camera.ir", "fail", format!("{} and no ov7251 IR sensor in sysfs", e)),
        },
        Err(e) => push("camera.ir", "fail", e.to_string()),
    }
    // The node's live state, not the rule file: an access grant made before
    // the rule was installed survives until reboot or `setfacl -b`, so the
    // ACL and the udev database's current tags are what count.
    if let Some((node, _)) = &sysfs_ir {
        let dev = PathBuf::from("/dev").join(node);
        let (st, d) = match std::fs::metadata(&dev) {
            Ok(m) => {
                use std::os::unix::fs::MetadataExt;
                let tags = udev_current_tags(Path::new("/run/udev/data"), m.rdev());
                let (st, d) = ir_node_verdict(
                    m.mode() & 0o777,
                    m.uid(),
                    m.gid(),
                    &tags,
                    user_can_write(&dev),
                );
                (st, format!("/dev/{}: {}", node, d))
            }
            Err(e) => ("unknown", format!("/dev/{}: {}", node, e)),
        };
        push("camera.ir_access", st, d);
    }
    // models
    let manifest = PathBuf::from("/usr/share/faceauth/models.toml");
    match std::fs::read_to_string(&manifest)
        .ok()
        .and_then(|t| toml::from_str::<toml::Value>(&t).ok())
    {
        Some(doc) => {
            for m in doc
                .get("model")
                .and_then(|m| m.as_array())
                .cloned()
                .unwrap_or_default()
            {
                let name = m
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string();
                let sha = m
                    .get("sha256")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let lic = m.get("license").and_then(|v| v.as_str()).unwrap_or("?");
                let p = models_dir.join(&name);
                // Every listed model is load-bearing: the daemon does not
                // start without the file (the mesh included, since the
                // gestures are read from it and nothing else).
                let (st, d) = if !p.exists() {
                    (
                        "fail",
                        "missing: the daemon refuses to start without it; the omarchy-faceauth-models package installs it".to_string(),
                    )
                } else if sha256_file(&p).unwrap_or_default() != sha {
                    ("fail", "checksum mismatch".into())
                } else {
                    ("pass", format!("verified, {}", lic))
                };
                push("models.file", st, format!("{}: {}", name, d));
            }
        }
        None => push(
            "models.manifest",
            "unknown",
            format!("no manifest at {}", manifest.display()),
        ),
    }
    // daemon
    let reply = faceauth_daemon::server::ping(&socket, &user).map_err(|e| {
        if is_permission_denied(&e) {
            DaemonErr::PermissionDenied
        } else {
            DaemonErr::Other(e.to_string())
        }
    });
    for c in daemon_checks(reply, &user, &socket) {
        push(c.id, c.status, c.detail);
    }
    push(
        "liveness.policy",
        if liveness_required { "pass" } else { "warn" },
        format!(
            "liveness_required = {}{}",
            liveness_required,
            if liveness_required {
                ""
            } else {
                ": a print in front of the camera can authenticate"
            }
        ),
    );
    // PAM wiring: the three stacks setup writes. No greeter row: no setup
    // path writes one, and a face line on a passive login is not something
    // to report as wired (J21).
    for (id, path) in [
        ("pam.sudo", "/etc/pam.d/sudo"),
        ("pam.polkit", "/etc/pam.d/polkit-1"),
        ("pam.lock", "/etc/pam.d/omarchy-lock-face"),
    ] {
        match std::fs::read_to_string(path) {
            Ok(t) => {
                let (st, d) = pam_stack_verdict(id, &t);
                push(id, st, d);
            }
            Err(_) => push(id, "warn", "no file (not wired)".into()),
        }
    }
    // TPM
    let tpm =
        std::path::Path::new("/dev/tpmrm0").exists() || std::path::Path::new("/dev/tpm0").exists();
    push(
        "tpm.present",
        if tpm { "pass" } else { "warn" },
        if tpm {
            "TPM device present (templates.at_rest says whether the daemon can use it)".into()
        } else {
            "no TPM device; templates stay plaintext (root 0600)".into()
        },
    );
    // module
    push(
        "pam.module",
        if std::path::Path::new("/usr/lib/security/pam_faceauth.so").exists() {
            "pass"
        } else {
            "fail"
        },
        "/usr/lib/security/pam_faceauth.so".into(),
    );

    if json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
    } else {
        for c in &checks {
            println!("{:<7} {:<20} {}", c.status.to_uppercase(), c.id, c.detail);
        }
    }
    let fails = checks.iter().filter(|c| c.status == "fail").count();
    if fails > 0 {
        std::process::exit(1);
    }
    Ok(())
}

/// The config text with the presence watch switched: `on` sets the user
/// and the away time (and a lock command if none is set), `off` sets only
/// `enabled`, so the administrator's other keys and every comment stay as
/// they are. The result is parsed and validated as the daemon would parse
/// it before anything is written, so a value the daemon would refuse to
/// start on (a zero or negative away time) is refused here instead (E3).
fn presence_edit(text: &str, origin: &str, on: bool, user: &str, away: f32) -> Result<String> {
    if on && (!away.is_finite() || away <= 0.0) {
        bail!(
            "--away-seconds {}: the away time must be a positive number of seconds",
            away
        );
    }
    let mut keys: Vec<(&str, String)> = vec![("enabled", on.to_string())];
    if on {
        keys.push(("user", toml::Value::String(user.to_string()).to_string()));
        keys.push(("away_seconds", format!("{:?}", away as f64)));
    }
    let edited = set_presence_keys(text, &keys);
    let cfg = faceauth_daemon::config::Config::from_text(&edited, origin).with_context(|| {
        format!(
            "the change would leave {} unusable by the daemon; nothing was written",
            origin
        )
    })?;
    let took = cfg.presence.enabled == on
        && (!on || (cfg.presence.user == user && (cfg.presence.away_seconds - away).abs() < 1e-3));
    if !took {
        bail!(
            "the [presence] keys in {} did not take the new values (set elsewhere in the file?); nothing was written",
            origin
        );
    }
    Ok(edited)
}

/// The line range of the `[presence]` table in `text`: the header's index
/// and the index one past the table's last line.
fn presence_section(text: &str) -> Option<(usize, usize)> {
    let lines: Vec<&str> = text.lines().collect();
    let header = lines
        .iter()
        .position(|l| toml_content(l).trim() == "[presence]")?;
    let end = lines[header + 1..]
        .iter()
        .position(|l| toml_content(l).trim_start().starts_with('['))
        .map(|i| header + 1 + i)
        .unwrap_or(lines.len());
    Some((header, end))
}

/// The index within `lines` of the line that sets `key`.
fn find_key(lines: Vec<&str>, key: &str) -> Option<usize> {
    lines.iter().position(|l| {
        let c = toml_content(l);
        let c = c.trim_start();
        c.strip_prefix(key)
            .map(|r| r.trim_start().starts_with('='))
            .unwrap_or(false)
    })
}

/// A line without its trailing comment: the first `#` outside a quoted
/// string starts one.
fn toml_content(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (i, ch) in line.char_indices() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if q == '"' && ch == '\\' {
                    escaped = true;
                } else if ch == q {
                    quote = None;
                }
            }
            None => match ch {
                '"' | '\'' => quote = Some(ch),
                '#' => return &line[..i],
                _ => {}
            },
        }
    }
    line
}

/// `text` with each key set inside its `[presence]` table: a line that
/// already sets the key is rewritten in place, keeping its trailing
/// comment; a key not there yet is added at the end of the table; a file
/// without the table gets one at its end. Every other line is untouched.
fn set_presence_keys(text: &str, keys: &[(&str, String)]) -> String {
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let (header, mut end) = match presence_section(text) {
        Some(r) => r,
        None => {
            if lines.last().map(|l| !l.trim().is_empty()).unwrap_or(false) {
                lines.push(String::new());
            }
            lines.push("[presence]".to_string());
            (lines.len() - 1, lines.len())
        }
    };
    for (key, value) in keys {
        let body: Vec<&str> = lines[header + 1..end].iter().map(String::as_str).collect();
        match find_key(body, key) {
            Some(i) => {
                let old = &lines[header + 1 + i];
                let content_len = toml_content(old).trim_end().len();
                let tail = old[content_len..].to_string();
                lines[header + 1 + i] = format!("{} = {}{}", key, value, tail);
            }
            None => {
                // After the table's last non-blank line, so blank lines
                // that space it from the next table stay where they are.
                let mut at = end;
                while at > header + 1 && lines[at - 1].trim().is_empty() {
                    at -= 1;
                }
                lines.insert(at, format!("{} = {}", key, value));
                end += 1;
            }
        }
    }
    let mut out = lines.join("\n");
    out.push('\n');
    out
}

/// Write the config through a temporary file in the same directory and a
/// rename, so a failure part-way leaves the old file whole (F4).
fn write_config_atomically(path: &str, text: &str) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let p = std::path::Path::new(path);
    let dir = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "config.toml".into()),
        std::process::id()
    ));
    let mode = std::fs::metadata(p)
        .map(|m| m.permissions().mode())
        .unwrap_or(0o644);
    let r = (|| -> Result<()> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, p)?;
        Ok(())
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r
}

/// Whether the daemon's answer to `templates delete` means no templates
/// are left: only `Deleted` and `NotEnrolled` do. Any other answer (busy,
/// a caller refused as remote, a store error) leaves them on disk, and the
/// command must fail so a removal script does not report a deletion that
/// did not happen and skip its own fallback.
#[cfg(test)]
mod arg_tests {
    use super::*;
    use faceauth_daemon::auth::Outcome;

    /// J23: a `--user` with no name, or followed by another flag, is an
    /// error rather than a fall-through; an unknown flag is refused.
    #[test]
    fn a_valueless_user_flag_and_an_unknown_flag_are_refused() {
        assert_eq!(
            opt_value(&["--user", "mike"], "--user").unwrap(),
            Some("mike")
        );
        assert_eq!(opt_value(&["--socket", "/x"], "--user").unwrap(), None);
        assert!(opt_value(&["--user"], "--user").is_err());
        assert!(opt_value(&["--user", "--dismiss"], "--user").is_err());
        assert!(user_arg(&["--user"]).is_err());
        assert_eq!(user_arg(&["--user", "mike"]).unwrap(), "mike");
        assert!(only_flags(&["--user", "mike", "--dismis"], &["--user", "--dismiss"]).is_err());
        assert!(only_flags(&["--user", "mike", "--dismiss"], &["--user", "--dismiss"]).is_ok());
        assert!(only_flags(&["continue"], &[]).is_ok());
    }

    /// J23: the default user is never the literal "user" and never root.
    #[test]
    fn the_default_user_is_resolved_from_a_uid_and_is_never_root() {
        std::env::set_var("SUDO_UID", "0");
        let e = target_user().unwrap_err().to_string();
        assert!(e.contains("root"), "{}", e);
        std::env::set_var("SUDO_UID", "not-a-uid");
        assert!(target_user().is_err());
        std::env::remove_var("SUDO_UID");
        match target_user() {
            Ok(name) => {
                assert_ne!(name, "user");
                assert_ne!(name, "root");
                assert_eq!(
                    nix::unistd::User::from_name(&name).unwrap().unwrap().uid,
                    nix::unistd::getuid()
                );
            }
            Err(e) => assert!(nix::unistd::getuid().is_root(), "{}", e),
        }
    }

    /// J27: the exit status follows the daemon's answer for every scripted
    /// subcommand.
    #[test]
    fn the_exit_status_follows_the_answer() {
        assert_eq!(exit_for(&Outcome::Noted), 0);
        assert_eq!(exit_for(&Outcome::Deleted), 0);
        assert_eq!(exit_for(&Outcome::NotEnrolled), 0);
        assert_eq!(
            exit_for(&Outcome::Probe {
                face: false,
                attentive: false,
                face_px: 0.0,
                elapsed_ms: 1
            }),
            0
        );
        assert_eq!(
            exit_for(&Outcome::PresenceMode {
                mode: "default".into(),
                watching: false,
                state: None,
                away_for: None,
            }),
            0
        );
        assert_eq!(
            exit_for(&Outcome::Error {
                message: "busy".into()
            }),
            2
        );
        assert_eq!(
            exit_for(&Outcome::ConsentDenied {
                reason: "dismissed".into(),
                elapsed_ms: 0
            }),
            1
        );
        assert_eq!(exit_for(&Outcome::NoFace { elapsed_ms: 0 }), 1);
    }
}

#[cfg(test)]
mod presence_edit_tests {
    use super::{presence_edit, set_presence_keys, toml_content};

    const SHIPPED: &str = include_str!("../../packaging/config.toml");

    /// E3: an away time the daemon would refuse to start on is refused
    /// before anything is written.
    #[test]
    fn a_zero_or_negative_away_time_is_refused_before_any_write() {
        for away in [0.0f32, -5.0, f32::NAN, f32::INFINITY] {
            let r = presence_edit(SHIPPED, "test", true, "mike", away);
            assert!(r.is_err(), "away {} accepted", away);
        }
        assert!(presence_edit(SHIPPED, "test", true, "mike", 20.0).is_ok());
    }

    /// E3: the shipped, commented config keeps every comment and every
    /// other key; only the three presence keys change.
    #[test]
    fn a_commented_config_keeps_its_comments() {
        let out = presence_edit(SHIPPED, "test", true, "mike", 30.0).unwrap();
        for line in SHIPPED.lines() {
            let comment = line.find('#').map(|i| &line[i..]);
            if let Some(c) = comment {
                assert!(out.contains(c), "comment lost: {}", c);
            }
            let content = toml_content(line).trim();
            let key = content.split('=').next().unwrap_or("").trim();
            if !matches!(key, "enabled" | "user" | "away_seconds") && !content.is_empty() {
                assert!(out.contains(line), "line changed: {}", line);
            }
        }
        assert!(out.contains("\nenabled = true"), "{}", out);
        assert!(out.contains("\nuser = \"mike\""), "{}", out);
        assert!(out.contains("\naway_seconds = 30.0"), "{}", out);
        assert!(
            out.lines().count() >= SHIPPED.lines().count(),
            "no line dropped"
        );
        let cfg = faceauth_daemon::config::Config::from_text(&out, "test").unwrap();
        assert!(cfg.presence.enabled);
        assert_eq!(cfg.presence.user, "mike");
        assert_eq!(cfg.presence.away_seconds, 30.0);
    }

    /// E3: `off` sets only `enabled`; the user and the away time stay.
    #[test]
    fn off_sets_only_enabled() {
        let on = presence_edit(SHIPPED, "test", true, "mike", 45.0).unwrap();
        let off = presence_edit(&on, "test", false, "somebody-else", 5.0).unwrap();
        let cfg = faceauth_daemon::config::Config::from_text(&off, "test").unwrap();
        assert!(!cfg.presence.enabled);
        assert_eq!(cfg.presence.user, "mike");
        assert_eq!(cfg.presence.away_seconds, 45.0);
        assert_eq!(off.replace("enabled = false", "enabled = true"), on);
    }

    /// A file without the table gets one; a table followed by another
    /// keeps the new keys inside it.
    #[test]
    fn missing_keys_and_tables_are_added_in_place() {
        let out = presence_edit("", "test", true, "mike", 20.0).unwrap();
        let cfg = faceauth_daemon::config::Config::from_text(&out, "test").unwrap();
        assert!(cfg.presence.enabled);
        assert_eq!(cfg.presence.user, "mike");
        let text = "accept_threshold = 0.7\n\n[presence]\nuser = \"al\" # who\n\n[other]\nx = 1\n";
        let out = set_presence_keys(
            text,
            &[("enabled", "true".into()), ("user", "\"mike\"".into())],
        );
        assert_eq!(
            out,
            "accept_threshold = 0.7\n\n[presence]\nuser = \"mike\" # who\nenabled = true\n\n[other]\nx = 1\n"
        );
        assert_eq!(toml_content("user = \"a#b\" # c"), "user = \"a#b\" ");
        assert_eq!(toml_content("user = 'a#b' # c"), "user = 'a#b' ");
    }
}

#[cfg(test)]
mod delete_tests {
    use super::exit_for;
    use faceauth_daemon::auth::Outcome;

    /// F4: a delete exits 0 only on Deleted or NotEnrolled; a daemon
    /// error is 2, a refusal 1 (through the one `exit_for`, J27).
    #[test]
    fn only_deleted_or_not_enrolled_is_a_successful_delete() {
        assert_eq!(exit_for(&Outcome::Deleted), 0);
        assert_eq!(exit_for(&Outcome::NotEnrolled), 0);
        for o in [
            Outcome::Error {
                message: "busy".into(),
            },
            Outcome::Error {
                message: "face authentication is local only: started under sshd-session".into(),
            },
        ] {
            assert_eq!(exit_for(&o), 2, "{:?}", serde_json::to_string(&o));
        }
        assert_eq!(exit_for(&Outcome::NoFace { elapsed_ms: 0 }), 1);
    }
}

#[cfg(test)]
mod doctor_tests {
    use super::*;

    /// J21, STORE-14: every reply and every way of failing to get one maps
    /// to the rows and statuses its label promises.
    #[test]
    fn the_daemon_rows_follow_the_reply() {
        use faceauth_daemon::auth::Outcome;
        let socket = Path::new(faceauth_daemon::config::SOCKET);
        let ids = |checks: &[Check]| -> Vec<(&'static str, &'static str)> {
            checks.iter().map(|c| (c.id, c.status)).collect()
        };
        let pong = |templates: usize, load_error: Option<&str>| Outcome::Pong {
            version: "1".into(),
            model: "m".into(),
            templates,
            sealed: true,
            unbound: 0,
            floors: None,
            load_error: load_error.map(String::from),
        };
        assert_eq!(
            ids(&daemon_checks(Ok(pong(3, None)), "mike", socket)),
            vec![
                ("daemon.running", "pass"),
                ("templates.user", "pass"),
                ("templates.at_rest", "pass"),
                ("gestures.calibrated", "info"),
                ("templates.camera", "pass"),
            ]
        );
        assert_eq!(
            ids(&daemon_checks(
                Ok(pong(0, Some("cannot unseal"))),
                "mike",
                socket
            )),
            vec![("daemon.running", "pass"), ("templates.user", "fail")],
            "an unreadable blob is not zero templates"
        );
        assert_eq!(
            ids(&daemon_checks(
                Err(DaemonErr::PermissionDenied),
                "mike",
                socket
            )),
            vec![("daemon.running", "pass"), ("templates.user", "warn")],
            "a user who is not enrolled sees a running daemon"
        );
        assert_eq!(
            ids(&daemon_checks(
                Ok(Outcome::Error {
                    message: "busy".into()
                }),
                "mike",
                socket
            )),
            vec![("daemon.running", "pass")],
            "a busy daemon is a running daemon"
        );
        assert_eq!(
            ids(&daemon_checks(
                Err(DaemonErr::Other("connect: no such file".into())),
                "mike",
                socket
            )),
            vec![("daemon.running", "fail")]
        );
        assert_eq!(
            ids(&daemon_checks(Ok(Outcome::Noted), "mike", socket)),
            vec![("daemon.running", "warn")]
        );
        assert_eq!(illuminator_check(true, true).0, "pass");
        assert_eq!(
            illuminator_check(false, true).0,
            "fail",
            "no strobe under liveness_required refuses every attempt"
        );
        assert_eq!(illuminator_check(false, false).0, "warn");
    }

    /// E6: only a live `auth required|requisite pam_deny.so` after the face
    /// line closes the lock stack.
    #[test]
    fn a_commented_out_pam_deny_does_not_close_the_lock_stack() {
        let open = "#%PAM-1.0\nauth sufficient pam_faceauth.so socket=/run/faceauth/sock timeout=8\n#auth required pam_deny.so\naccount include system-local-login\n";
        let (st, d) = pam_stack_verdict("pam.lock", open);
        assert_eq!(st, "fail", "{}", d);
        assert!(d.contains("NOT closed"), "{}", d);
        let closed = open.replace("#auth required pam_deny.so", "auth required pam_deny.so");
        assert_eq!(
            pam_stack_verdict("pam.lock", &closed),
            ("pass", "wired, closed by pam_deny".to_string())
        );
        let requisite = open.replace(
            "#auth required pam_deny.so",
            "auth   requisite   pam_deny.so",
        );
        assert_eq!(pam_stack_verdict("pam.lock", &requisite).0, "pass");
        // A pam_deny above the face line runs first and never lets the face line answer.
        let above = "auth required pam_deny.so\nauth sufficient pam_faceauth.so\n";
        assert_eq!(pam_stack_verdict("pam.lock", above).0, "fail");
        // The wrong control word or a different module type does not close the stack.
        let optional = open.replace("#auth required pam_deny.so", "auth optional pam_deny.so");
        assert_eq!(pam_stack_verdict("pam.lock", &optional).0, "fail");
        let account = open.replace("#auth required pam_deny.so", "account required pam_deny.so");
        assert_eq!(pam_stack_verdict("pam.lock", &account).0, "fail");
    }

    /// F11: `timeout=` on a consent line is ignored by the module and doctor says so.
    #[test]
    fn timeout_on_a_consent_line_is_flagged() {
        let stale = "auth sufficient pam_faceauth.so socket=/run/faceauth/sock timeout=60 consent\nauth include system-auth\n";
        let (st, d) = pam_stack_verdict("pam.sudo", stale);
        assert_eq!(st, "warn", "{}", d);
        assert!(
            d.contains("consent (window + nod)")
                && d.contains("timeout= on a consent line is ignored"),
            "{}",
            d
        );
        let clean = "auth sufficient pam_faceauth.so socket=/run/faceauth/sock consent\nauth include system-auth\n";
        assert_eq!(
            pam_stack_verdict("pam.sudo", clean),
            ("pass", "wired, consent (window + nod)".to_string())
        );
        // A plain look keeps its timeout without comment.
        let lock = "auth sufficient pam_faceauth.so timeout=8\nauth required pam_deny.so\n";
        assert!(!pam_stack_verdict("pam.lock", lock).1.contains("timeout="));
        // A commented-out face line is not wired.
        assert_eq!(
            pam_stack_verdict("pam.sudo", "#auth sufficient pam_faceauth.so consent\n").0,
            "warn"
        );
    }

    /// A3: an elevation line without `consent` (a pasted lock line, a
    /// misspelt word) is a failure, not a pass with a note.
    #[test]
    fn an_elevation_line_without_consent_fails() {
        for line in [
            "auth      sufficient pam_faceauth.so socket=/run/faceauth/sock timeout=8\n",
            "auth      sufficient pam_faceauth.so socket=/run/faceauth/sock consnet\n",
        ] {
            let sudo = format!("{}#%PAM-1.0\nauth\t\tinclude\t\tsystem-auth\n", line);
            let (st, d) = pam_stack_verdict("pam.sudo", &sudo);
            assert_eq!(st, "fail", "{}", d);
            assert!(d.contains("NO consent"), "{}", d);
            let polkit = format!(
                "#%PAM-1.0\n{}auth include system-auth\n",
                line.replace("sufficient", "[success=done auth_err=die default=ignore]")
            );
            assert_eq!(pam_stack_verdict("pam.polkit", &polkit).0, "fail");
        }
        // The lock stack is the plain-look caller and needs no consent.
        let lock = "auth sufficient pam_faceauth.so timeout=8\nauth required pam_deny.so\n";
        assert_eq!(pam_stack_verdict("pam.lock", lock).0, "pass");
    }

    /// D3: the IR sensor is found by name in sysfs without opening its node,
    /// so doctor keeps going once the node is root-only.
    #[test]
    fn the_ir_sensor_is_found_by_name_in_sysfs() {
        let dir =
            std::env::temp_dir().join(format!("faceauth-doctor-sysfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (node, name) in [
            ("v4l-subdev2", "ipu3-csi2 0"),
            ("v4l-subdev6", "ov8865 3-0010"),
            ("v4l-subdev8", "ov7251 3-0060"),
            ("v4l-subdev9", "dw9719 3-000c"),
            ("video0", "ipu3-cio2 0"),
        ] {
            std::fs::create_dir_all(dir.join(node)).unwrap();
            std::fs::write(dir.join(node).join("name"), format!("{}\n", name)).unwrap();
        }
        assert_eq!(
            ir_sensor_from_sysfs(&dir),
            Some(("v4l-subdev8".to_string(), "ov7251 3-0060".to_string()))
        );
        std::fs::remove_dir_all(dir.join("v4l-subdev8")).unwrap();
        assert_eq!(ir_sensor_from_sysfs(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// D3: the verdict reads the node's live state. Right is root:root 0600,
    /// no uaccess in the current tags and no write access for the caller.
    #[test]
    fn the_ir_node_verdict_reads_the_live_state() {
        let none: Vec<String> = vec![];
        let seat = vec!["seat".to_string()];
        let uaccess = vec!["seat".to_string(), "uaccess".to_string()];
        assert_eq!(ir_node_verdict(0o600, 0, 0, &seat, false).0, "pass");
        assert_eq!(ir_node_verdict(0o600, 0, 0, &none, false).0, "pass");
        // Before the rule: video group, rw, uaccess tag, and the user holds an ACL.
        let (st, d) = ir_node_verdict(0o660, 0, 983, &uaccess, true);
        assert_eq!(st, "warn");
        assert!(
            d.contains("want root:root 0600") && d.contains("tagged uaccess"),
            "{}",
            d
        );
        // The rule applied to the udev database but the earlier ACL still stands.
        let (st, d) = ir_node_verdict(0o600, 0, 0, &seat, true);
        assert_eq!(st, "warn");
        assert!(d.contains("setfacl -b"), "{}", d);
        // Right mode, stale tag: the next login grants access again.
        assert_eq!(ir_node_verdict(0o600, 0, 0, &uaccess, false).0, "warn");
    }

    /// D3: the probe's error for a root-only node is recognised through the
    /// context anyhow wraps around it, and anything else is still a fault.
    #[test]
    fn a_root_only_node_is_permission_denied_not_a_fault() {
        let denied =
            anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                .context("open /dev/v4l-subdev8")
                .context("IPU3 probe");
        assert!(is_permission_denied(&denied));
        let missing = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context("open /dev/media0");
        assert!(!is_permission_denied(&missing));
        assert!(!is_permission_denied(&anyhow!("no subdev node")));
    }

    /// D3: the udev database's Q: lines are the current tags; G: lines are history.
    #[test]
    fn udev_current_tags_come_from_q_lines() {
        let dir = std::env::temp_dir().join(format!("faceauth-doctor-udev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // 81:22 as the kernel encodes it: major in bits 8..20, minor low byte plus bits 20..32.
        let rdev: u64 = (81 << 8) | 22;
        assert_eq!(
            (nix::sys::stat::major(rdev), nix::sys::stat::minor(rdev)),
            (81, 22)
        );
        std::fs::write(
            dir.join("c81:22"),
            "I:1\nE:ID_PATH=x\nG:seat\nG:uaccess\nQ:seat\nV:1\n",
        )
        .unwrap();
        assert_eq!(udev_current_tags(&dir, rdev), vec!["seat".to_string()]);
        assert!(udev_current_tags(&dir, (81 << 8) | 23).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
