//! `faceauth`: the command-line front end. For now the camera subcommands that
//! prove the capture crate on hardware; enrol, test, doctor follow.

use anyhow::{anyhow, bail, Context, Result};
use args::{finish, only_flags, opt, user_arg};
use cam::{cam_graph, cam_probe};
use doctor::doctor;
use enroll::{at_rest_note, enroll_guided};
use models::models_fetch;
use presence::{
    away_flag, away_keys, away_summary, lock_time_edit, obscured_keys, presence_edit,
    write_config_atomically,
};
use std::path::PathBuf;
use std::time::{Duration, Instant};

mod args;
mod cam;
mod doctor;
mod doctor_host;
mod enroll;
mod models;
mod presence;

#[cfg(feature = "dev-tools")]
mod dev;

fn usage() -> ! {
    eprintln!(
        "usage:\n  faceauth cam probe\n  faceauth cam graph\n  faceauth auth [--user NAME] [--socket PATH] [--consent]   (asks a running faceauthd; --consent = window + nod)\n  faceauth probe [--user NAME] [--socket PATH]     (one short look: is a face there, and is it likely you? the reply carries likely and the lock screen's cadence, never a score)
  faceauth enroll [--user NAME] [--label TEXT] [--start distance]   (root; the walk-through window, the same one Setup > Security > Face opens; --guided is accepted)
  faceauth enroll [--user NAME] [--label TEXT] --terminal [--poses up,down]   (root; the five looks from the terminal, no window)
  faceauth enroll [--user NAME] [--label TEXT] --look [--seconds N] [--count N]   (root; one look, as the camera sees it, no walk-through)
  faceauth enrol-control continue|redo|cancel [--user NAME]   (from the enrolment window)\n  faceauth templates delete [--user NAME]\n  faceauth models fetch [--manifest FILE] [--dir DIR]   (development: the omarchy-faceauth-models package ships the files)\n  faceauth doctor [--json]\n  faceauth consent-answer [--user NAME] [--dismiss|--ack|--rearm|--passwordless MIN]   (from the consent window; stdin: token line, then password line)\n  faceauth calibrate [--user NAME] --guided              (root; the gesture and everyday rounds in the walk-through window, stored with the templates)\n  faceauth presence on|off [--user NAME] [--away-seconds N]   (root; rewrites the config, restarts the service; on keeps the saved away times unless --away-seconds is given)\n  faceauth presence away-time [--default never|SECONDS] [--secure SECONDS]   (root; saves the away times, the walk-away lock stays as it is)\n  faceauth presence obscured-lock [--default never|MIN] [--secure MIN]   (root; saves the obscured face lock times, the walk-away lock stays as it is)\n  faceauth presence mode [default|secure] [--user NAME]   (as the watched user; reads or switches the watch's mode until the next restart; prints {{\"presence\":{{\"mode\":..,\"watching\":..}}}})\n  faceauth presence [--user NAME]                  (the watch's mode and, for the watched user, its state){}",
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
            // A config that does not parse is not replaced by one that only
            // holds [presence]: the administrator's other keys would go with
            // it. A missing file starts empty (F4).
            let text = match std::fs::read_to_string(&cfg_path) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(e).with_context(|| format!("read {}", cfg_path)),
            };
            // Without --away-seconds the saved away times stay, "never"
            // included.
            let away = away_flag(opt(rest, "--away-seconds"))?;
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
                // Already validated by the edit; read again only to report
                // the saved away times, without repeating its warnings.
                let presence = toml::from_str::<faceauth_daemon::config::Config>(&edited)?.presence;
                println!(
                    "presence watch on for {} ({}); service restarted",
                    user,
                    away_summary(&presence)
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
        ["presence", "obscured-lock", rest @ ..] => {
            // Root: save the obscured face lock times without touching
            // whether the walk-away lock is on. The running daemon reads its
            // config at start, so it restarts only when the watch is on.
            let cfg_path = opt(rest, "--config")
                .unwrap_or("/etc/faceauth/config.toml")
                .to_string();
            let keys = obscured_keys(opt(rest, "--default"), opt(rest, "--secure"))?;
            let text = match std::fs::read_to_string(&cfg_path) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(e).with_context(|| format!("read {}", cfg_path)),
            };
            let edited = lock_time_edit(&text, &cfg_path, &keys)?;
            write_config_atomically(&cfg_path, &edited)
                .with_context(|| format!("write {} (run as root)", cfg_path))?;
            let on = faceauth_daemon::config::Config::from_text(&edited, &cfg_path)
                .map(|c| c.presence.enabled)
                .unwrap_or(false);
            if on {
                let st = std::process::Command::new("/usr/bin/systemctl")
                    .args(["restart", "faceauth.service"])
                    .status()
                    .context("run /usr/bin/systemctl")?;
                if !st.success() {
                    bail!(
                        "obscured face lock time written to {}, but the service did not restart ({}); see `systemctl status faceauth.service`",
                        cfg_path,
                        st
                    );
                }
                println!("obscured face lock time saved; service restarted");
            } else {
                println!("obscured face lock time saved; the walk-away lock stays off");
            }
            Ok(())
        }
        ["presence", "away-time", rest @ ..] => {
            // Root: save the away times without touching whether the
            // walk-away lock is on. The running daemon reads its config at
            // start, so it restarts only when the watch is on.
            let cfg_path = opt(rest, "--config")
                .unwrap_or("/etc/faceauth/config.toml")
                .to_string();
            let keys = away_keys(opt(rest, "--default"), opt(rest, "--secure"))?;
            let text = match std::fs::read_to_string(&cfg_path) {
                Ok(t) => t,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(e) => return Err(e).with_context(|| format!("read {}", cfg_path)),
            };
            let edited = lock_time_edit(&text, &cfg_path, &keys)?;
            write_config_atomically(&cfg_path, &edited)
                .with_context(|| format!("write {} (run as root)", cfg_path))?;
            let on = faceauth_daemon::config::Config::from_text(&edited, &cfg_path)
                .map(|c| c.presence.enabled)
                .unwrap_or(false);
            if on {
                let st = std::process::Command::new("/usr/bin/systemctl")
                    .args(["restart", "faceauth.service"])
                    .status()
                    .context("run /usr/bin/systemctl")?;
                if !st.success() {
                    bail!(
                        "away time written to {}, but the service did not restart ({}); see `systemctl status faceauth.service`",
                        cfg_path,
                        st
                    );
                }
                println!("away time saved; service restarted");
            } else {
                println!("away time saved; the walk-away lock stays off");
            }
            Ok(())
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

extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}
