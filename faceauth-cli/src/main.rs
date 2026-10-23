//! `faceauth`: the command line to the daemon. Enrollment, the doctor, the
//! presence settings, and the answers the consent and enrollment windows
//! send; `faceauth --help` lists every command and the flags it takes. A
//! development build adds the bring-up and tuning tools (`dev`).

#![forbid(unsafe_code)]

use anyhow::{anyhow, bail, Context, Result};
use args::{count_arg, finish, only_flags, opt, seconds_arg, user_arg};
use cam::{cam_graph, cam_ir_reset, cam_ir_rule, cam_probe};
use doctor::doctor;
use enroll::{at_rest_note, enroll_terminal};
use faceauth_daemon::consent::{wipe_bytes, Secret};
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

/// The production commands, one line each, with every flag each takes
/// but the two in `USAGE_NOTE`. `check_args` holds the same flags, and a
/// test holds the two to each other (I8).
const USAGE: &str = "usage:
  faceauth cam probe
  faceauth cam graph
  faceauth cam ir-rule   (root; prints the udev rule that locks the IR capture node to root, which face setup writes; exit 3, with the reason, when the node is left open)
  faceauth cam ir-reset   (root; once face removal has deleted that rule, gives the IR capture node back what udev and logind give it: root's, the video group's, no ACL; exit 3, with the reason, when it is left as it is)
  faceauth auth [--user NAME] [--consent]   (asks a running faceauthd; --consent = window + nod)
  faceauth probe [--user NAME]   (one short look: is a face there, and is it likely you? the reply carries likely and the lock screen's cadence, never a score)
  faceauth key-lane [--user NAME]   (the lock screen: is its security key lane there? no camera)
  faceauth fprint-lane [--user NAME]   (the lock screen: does its fingerprint lane go through faceauthd? no camera, no reader)
  faceauth lock-channel [--user NAME]   (the lock screen: holds its reserved channel open for the whole lock; the line unlocked on stdin closes it gracefully, anything else is a drop that keeps the key off approvals)
  faceauth enroll [--user NAME] [--label TEXT] [--start distance] [--guided]   (root; the walk-through window, the same one Setup > Security > Face opens; the default, so --guided changes nothing)
  faceauth enroll [--user NAME] [--label TEXT] --terminal [--poses up,down]   (root; the five looks from the terminal, no window)
  faceauth enroll [--user NAME] [--label TEXT] --look [--seconds N] [--count N]   (root; one look, as the camera sees it, no walk-through)
  faceauth enrol-control continue|redo|cancel [--user NAME]   (from the enrollment window)
  faceauth templates delete [--user NAME]
  faceauth models fetch [--manifest FILE] [--dir DIR]   (developer: downloads the model files over https and checks them against the manifest, into $XDG_DATA_HOME/faceauth/models unless --dir says otherwise; on an installed system the omarchy-faceauth-models package provides them)
  faceauth doctor [--json] [--user NAME]
  faceauth consent-answer [--user NAME] [--dismiss|--ack|--rearm|--key-pin|--passwordless MIN]   (from the consent window; stdin: token line, then password or key PIN line)
  faceauth kill-requester --pid PID --ino ID   (from the consent window's Deny and kill: SIGTERM to that process only while its pidfs id is ID)
  faceauth calibrate [--user NAME] --guided   (root; the gesture and everyday rounds in the walk-through window, stored with the templates)
  faceauth presence on|off [--user NAME] [--away-seconds N]   (root; rewrites the config, restarts the service; on keeps the saved away times unless --away-seconds is given)
  faceauth presence away-time [--default never|SECONDS] [--secure SECONDS]   (root; saves the away times, the walk-away lock stays as it is)
  faceauth presence obscured-lock [--default never|MIN] [--secure MIN]   (root; saves the obscured face lock times, the walk-away lock stays as it is)
  faceauth presence mode [default|secure] [--user NAME]   (as the watched user; reads or switches the watch's mode until the next restart; prints {\"presence\":{\"mode\":..,\"watching\":..}})
  faceauth presence [--user NAME]   (the watch's mode and, for the watched user, its state)";

/// The flags every command of a kind takes, said once after the lines.
const USAGE_NOTE: &str = "\
Every command that asks the daemon also takes --socket PATH, and the presence
settings (on, off, away-time, obscured-lock) take --config FILE.
faceauth help, --help or -h prints this text.";

/// What `run` answers when the words name no command: `main` prints the
/// usage to stderr and exits 2.
const NO_COMMAND: &str = "no such command";

/// The usage, with the development tools' lines in a build that has them.
fn usage_text() -> String {
    format!("{}{}\n\n{}\n", USAGE, dev_usage(), USAGE_NOTE)
}

/// A command line that names no command, or a development tool given no
/// image to read: the usage on stderr, exit 2. A flag a command does not
/// know is refused by `check_args` instead, with exit 1.
fn usage() -> ! {
    eprint!("{}", usage_text());
    std::process::exit(2)
}

/// Help asked for by name: `help`, `--help` or `-h` as the first word, or
/// `--help` or `-h` where a flag goes after a command, which then does not
/// run. Never in a flag's value position, whatever it is: `enroll --label
/// -h` names a look `-h`, and `enroll --label --help` is that flag's value
/// too, which `check_args` then refuses as missing. The values are told
/// apart by the command's own flags (`takes`); after words that name no
/// command, any `--help` or `-h` is help.
fn wants_help(argv: &[&str]) -> bool {
    let is_help = |w: &str| matches!(w, "--help" | "-h");
    match argv.first() {
        None => return false,
        Some(&"help") => return true,
        Some(w) if is_help(w) => return true,
        _ => {}
    }
    let (rest, valued): (&[&str], &[&str]) = match takes(argv) {
        Ok((rest, _, valued)) => (rest, valued),
        Err(_) => (&argv[1..], &[]),
    };
    let mut words = rest.iter();
    while let Some(w) = words.next() {
        if is_help(w) {
            return true;
        }
        if valued.contains(w) {
            // The word after a valued flag is its value, whatever it is.
            words.next();
        }
    }
    false
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
    // Help that was asked for is an answer, not an error: stdout, exit 0 (I8).
    if wants_help(&argv) {
        print!("{}", usage_text());
        return Ok(());
    }
    // The bring-up and tuning tools exist only in a development build:
    // the package ships none of them (H2).
    #[cfg(feature = "dev-tools")]
    if let Some(r) = dev::dispatch(&argv) {
        return r;
    }
    match run(&argv) {
        Err(e) if e.to_string() == NO_COMMAND => usage(),
        r => r,
    }
}

/// What each command takes, checked before any command starts: the
/// flags it takes alone, the flags that take a value, and no other word.
/// The flags of the three enrollments differ, so a flag of one given to
/// another is refused too (J23). A development build checks its tools
/// the same way (`dev::check_args`).
fn check_args(argv: &[&str]) -> Result<()> {
    #[cfg(feature = "dev-tools")]
    if let Some(r) = dev::check_args(argv) {
        return r;
    }
    let (rest, switches, valued) = takes(argv)?;
    only_flags(rest, switches, valued)
}

/// A command's arguments after its words, the flags it takes alone, and
/// the flags it takes with a value.
type Takes<'a> = (
    &'a [&'a str],
    &'static [&'static str],
    &'static [&'static str],
);

/// What the command `argv` names takes; `NO_COMMAND` when it names none.
fn takes<'a>(argv: &'a [&'a str]) -> Result<Takes<'a>> {
    const DAEMON: &[&str] = &["--socket", "--user"];
    Ok(match argv {
        ["cam", "probe" | "graph" | "ir-rule" | "ir-reset", rest @ ..] => (rest, &[], &[]),
        ["auth", rest @ ..] => (rest, &["--consent"], DAEMON),
        ["probe", rest @ ..]
        | ["key-lane", rest @ ..]
        | ["fprint-lane", rest @ ..]
        | ["lock-channel", rest @ ..]
        | ["templates", "delete", rest @ ..] => (rest, &[], DAEMON),
        ["enroll", rest @ ..] if rest.contains(&"--terminal") => (
            rest,
            &["--terminal"],
            &["--socket", "--user", "--label", "--poses"],
        ),
        ["enroll", rest @ ..] if rest.contains(&"--look") => (
            rest,
            &["--look"],
            &["--socket", "--user", "--label", "--seconds", "--count"],
        ),
        ["enroll", rest @ ..] => (
            rest,
            &["--guided"],
            &["--socket", "--user", "--label", "--start"],
        ),
        ["enrol-control", word, rest @ ..] if !word.starts_with('-') => (rest, &[], DAEMON),
        ["models", "fetch", rest @ ..] => (rest, &[], &["--manifest", "--dir"]),
        ["doctor", rest @ ..] => (rest, &["--json"], &["--user"]),
        ["consent-answer", rest @ ..] => (
            rest,
            &["--dismiss", "--ack", "--rearm", "--key-pin"],
            &["--socket", "--user", "--passwordless"],
        ),
        ["kill-requester", rest @ ..] => (rest, &[], &["--pid", "--ino"]),
        ["calibrate", rest @ ..] => (rest, &["--guided"], DAEMON),
        ["presence", "on" | "off", rest @ ..] => {
            (rest, &[], &["--config", "--user", "--away-seconds"])
        }
        ["presence", "away-time" | "obscured-lock", rest @ ..] => {
            (rest, &[], &["--config", "--default", "--secure"])
        }
        ["presence", "mode", word, rest @ ..] if !word.starts_with('-') => (rest, &[], DAEMON),
        ["presence", "mode", rest @ ..] | ["presence", rest @ ..] => (rest, &[], DAEMON),
        _ => bail!("{}", NO_COMMAND),
    })
}

/// The production commands, each started only once its arguments pass
/// `check_args`.
fn run(argv: &[&str]) -> Result<()> {
    check_args(argv)?;
    match argv {
        ["cam", "probe"] => cam_probe(),
        ["cam", "graph"] => cam_graph(),
        ["cam", "ir-rule"] => cam_ir_rule(),
        ["cam", "ir-reset"] => cam_ir_reset(),
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
                return enroll_terminal(&socket, &user, label, &only);
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
                        warning,
                    } => {
                        println!("Saved {} templates ({} new) to {}", total, added, path);
                        println!(
                            "Template self-consistency (pairwise cosine): min {:.3} mean {:.3}",
                            consistency_min, consistency_mean
                        );
                        if let Some(w) = warning {
                            println!("{}", w);
                        }
                        println!("{}", at_rest_note(path));
                        Ok(())
                    }
                    faceauth_daemon::auth::Outcome::Error { message } => {
                        Err(anyhow!("enrollment failed: {}", message))
                    }
                    other => Err(anyhow!(
                        "enrollment failed: {}",
                        serde_json::to_string(other)?
                    )),
                };
            }
            // The daemon's own ranges, refused here rather than clamped
            // there: a length that is not one is never sent.
            let seconds = seconds_arg(rest, 12.0, 4.0, 20.0)?;
            let count = count_arg(rest, 10, 3, 40)?;
            println!(
                "Enrolling {}: keep only your own face in view, look at the camera and move your head a little over the next {} s.",
                user, seconds as u32
            );
            let o = faceauth_daemon::server::enroll(
                &socket,
                &user,
                label,
                seconds,
                count,
                &[],
                &|| {},
            )?;
            match &o {
                faceauth_daemon::auth::Outcome::Enrolled {
                    added,
                    total,
                    consistency_min,
                    consistency_mean,
                    path,
                    warning,
                } => {
                    println!("Saved {} templates ({} new) to {}", total, added, path);
                    println!(
                        "Template self-consistency (pairwise cosine): min {:.3} mean {:.3}",
                        consistency_min, consistency_mean
                    );
                    if let Some(w) = warning {
                        println!("{}", w);
                    }
                    println!("{}", at_rest_note(path));
                    Ok(())
                }
                other => bail!("enrollment failed: {}", serde_json::to_string(other)?),
            }
        }
        ["templates", "delete", rest @ ..] => {
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let o = faceauth_daemon::server::delete_templates(&socket, &user)?;
            finish(&o)
        }
        ["models", "fetch", rest @ ..] => models_fetch(rest),
        ["doctor", rest @ ..] => doctor(rest),
        ["enrol-control", word, rest @ ..] => {
            // From the enrollment window: continue, redo or cancel.
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let o = faceauth_daemon::server::enrol_control(&socket, &user, word)?;
            finish(&o)
        }
        ["probe", rest @ ..] => {
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let o = faceauth_daemon::server::probe(&socket, &user, Duration::from_secs(5))?;
            finish(&o)
        }
        ["lock-channel", rest @ ..] => {
            // The lock screen's reserved channel (round 7, B): exit 0 after
            // the graceful unlock, 1 when the lock screen's end closed
            // without it, 3 when the daemon went away (the lock screen
            // opens another), 4 when the daemon expired it, 2 when it could
            // not open.
            let socket = PathBuf::from(
                opt(rest, "--socket").unwrap_or(faceauth_daemon::config::LOCK_SOCKET),
            );
            let user = user_arg(rest)?;
            use faceauth_daemon::server::ChannelEnd;
            match faceauth_daemon::server::lock_channel(&socket, &user, &std::io::stdin()) {
                Ok(ChannelEnd::Unlocked) => Ok(()),
                Ok(ChannelEnd::InputClosed) => std::process::exit(1),
                Ok(ChannelEnd::DaemonGone) => std::process::exit(3),
                // The daemon expired it after a steady unlock (fix round 8);
                // the CLI waited for the lock screen's word without one.
                Ok(ChannelEnd::Expired) => std::process::exit(4),
                Err(e) => {
                    eprintln!("{:#}", e);
                    std::process::exit(2)
                }
            }
        }
        ["key-lane", rest @ ..] => {
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let o = faceauth_daemon::server::key_lane(&socket, &user)?;
            finish(&o)
        }
        ["fprint-lane", rest @ ..] => {
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let o = faceauth_daemon::server::fprint_lane(&socket, &user)?;
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
                faceauth_daemon::auth::Outcome::Enrolled { warning, .. } => {
                    println!("Done. Your nods, shakes and everyday movements are recorded with your templates.");
                    if let Some(w) = warning {
                        println!("{}", w);
                    }
                    Ok(())
                }
                faceauth_daemon::auth::Outcome::Error { message } => {
                    Err(anyhow!("tuning failed: {}", message))
                }
                other => Err(anyhow!("tuning failed: {}", serde_json::to_string(other)?)),
            }
        }
        ["kill-requester", rest @ ..] => {
            // The card's Deny and kill (round 19): the process the daemon
            // pinned for it, named by pid and pidfs id, and no other.
            let pid: i32 = opt(rest, "--pid")
                .context("kill-requester takes --pid PID")?
                .parse()
                .context("--pid takes a process id")?;
            let ino: u64 = opt(rest, "--ino")
                .context("kill-requester takes --ino ID")?
                .parse()
                .context("--ino takes a pidfs id")?;
            faceauth_daemon::consent::kill_requester(pid, ino)
                .map_err(|e| anyhow::anyhow!("no kill: {}", e))?;
            println!("asked process {} to end", pid);
            Ok(())
        }
        ["consent-answer", rest @ ..] => {
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            // The token came with the window's payload; without it the daemon
            // treats the answer as nobody's. It arrives on stdin, first line,
            // never on the command line (argv is readable and journaled).
            // The token and the password are read into `Secret`s, wiped when
            // dropped, and dropped at the end of this block, before `finish`
            // can exit without running destructors (J26).
            let o = {
                let mut stdin = unbuffered_stdin()?;
                let token_line = secret_line(&mut stdin)?;
                let token = (!token_line.is_empty()).then_some(&*token_line);
                if rest.contains(&"--ack") {
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
                } else if rest.contains(&"--key-pin") {
                    let pin = secret_line(&mut stdin)?;
                    faceauth_daemon::server::consent_key_pin(&socket, &user, &pin, token)?
                } else {
                    let pw = secret_line(&mut stdin)?;
                    faceauth_daemon::server::consent_answer(
                        &socket,
                        &user,
                        Some(&pw),
                        false,
                        token,
                    )?
                }
            };
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
            let (mode, rest) = match rest {
                [m, rest @ ..] if !m.starts_with('-') => (*m, rest),
                _ => ("query", rest),
            };
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            if !matches!(mode, "query" | "default" | "secure") {
                bail!("presence mode: \"default\" or \"secure\" (or nothing, to read it)");
            }
            match faceauth_daemon::server::presence_mode(&socket, &user, mode) {
                Ok(faceauth_daemon::auth::Outcome::PresenceMode {
                    mode,
                    watching,
                    secure_available,
                    ..
                }) => {
                    // `secure_available` only once the daemon knows: false
                    // tells the widget and the binding not to offer secure.
                    let mut presence = serde_json::json!({ "mode": mode, "watching": watching });
                    if let Some(s) = secure_available {
                        presence["secure_available"] = serde_json::json!(s);
                    }
                    println!("{}", serde_json::json!({ "presence": presence }));
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
        _ => bail!("{}", NO_COMMAND),
    }
}

/// Standard input without its buffer: the process-wide one would keep
/// whatever it read ahead, the password line included, for the life of the
/// process and out of reach of any wipe (J26).
fn unbuffered_stdin() -> Result<std::fs::File> {
    use std::os::fd::AsFd;
    let fd = std::io::stdin()
        .as_fd()
        .try_clone_to_owned()
        .context("stdin")?;
    Ok(fd.into())
}

/// Longest answer line: the daemon refuses a request line longer than
/// this, so a longer password could not reach it anyway.
const MAX_ANSWER_LINE: usize = 4096;

/// One answer line, read a byte at a time so nothing after its newline is
/// taken, into a buffer that never grows (one that grew would leave copies
/// in the memory it gave back). The end of the input ends the line too; a
/// carriage return before the newline is dropped (J26).
fn secret_line(input: &mut impl std::io::Read) -> Result<Secret> {
    let mut buf = Vec::with_capacity(MAX_ANSWER_LINE);
    let mut byte = [0u8; 1];
    loop {
        match input.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == b'\n' => break,
            Ok(_) if buf.len() < MAX_ANSWER_LINE => buf.push(byte[0]),
            Ok(_) => {
                wipe_bytes(&mut buf);
                bail!("an answer line is longer than {} bytes", MAX_ANSWER_LINE);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                wipe_bytes(&mut buf);
                return Err(e).context("read stdin");
            }
        }
    }
    while buf.last() == Some(&b'\r') {
        buf.pop();
    }
    match String::from_utf8(buf) {
        Ok(s) => Ok(Secret::new(s)),
        Err(e) => {
            wipe_bytes(&mut e.into_bytes());
            bail!("an answer line is not UTF-8");
        }
    }
}

#[cfg(test)]
mod usage_tests {
    use super::*;

    /// One production usage line: the command's words, alternatives kept
    /// as written (`on|off`), and each flag with the value it is shown
    /// with, if any.
    struct Line {
        words: Vec<&'static str>,
        flags: Vec<(&'static str, Option<&'static str>)>,
    }

    fn usage_lines() -> Vec<Line> {
        USAGE
            .lines()
            .filter_map(|l| l.strip_prefix("  faceauth "))
            .map(|l| {
                let shown = l.split("  (").next().unwrap();
                let tokens: Vec<&str> = shown
                    .split_whitespace()
                    .map(|t| t.trim_matches(|c| c == '[' || c == ']'))
                    .collect();
                let n = tokens.iter().take_while(|t| !t.starts_with('-')).count();
                let mut flags = Vec::new();
                for (i, t) in tokens.iter().enumerate().skip(n) {
                    if !t.starts_with('-') {
                        continue;
                    }
                    let group: Vec<&str> = t.split('|').collect();
                    let value = tokens.get(i + 1).filter(|v| !v.starts_with('-')).copied();
                    for (j, f) in group.iter().enumerate() {
                        flags.push((*f, if j + 1 == group.len() { value } else { None }));
                    }
                }
                Line {
                    words: tokens[..n].to_vec(),
                    flags,
                }
            })
            .collect()
    }

    /// A line's words as a command line would give them: the first of
    /// each set of alternatives.
    fn argv_of(line: &Line) -> Vec<&'static str> {
        line.words
            .iter()
            .map(|w| w.split('|').next().unwrap())
            .collect()
    }

    /// I8: every flag a usage line shows is one its command takes, with the
    /// value shown, and past them the command still refuses what it does
    /// not know; every flag a command takes is on one of its lines or in
    /// the note.
    #[test]
    fn usage_names_nothing_the_build_rejects_and_omits_no_flag() {
        let lines = usage_lines();
        assert!(lines.len() >= 18, "{} usage lines parsed", lines.len());
        for line in &lines {
            let mut argv = argv_of(line);
            for (flag, value) in &line.flags {
                argv.push(flag);
                argv.extend(value.map(|v| v.split('|').next().unwrap()));
            }
            check_args(&argv).unwrap_or_else(|e| panic!("{:?}: {}", argv, e));
            argv.push("--no-such-flag");
            let e = check_args(&argv).unwrap_err().to_string();
            assert!(
                e.starts_with("unknown flag --no-such-flag"),
                "{:?}: {}",
                argv,
                e
            );
            argv.pop();
            let (_, switches, valued) = takes(&argv).unwrap();
            for f in switches.iter().chain(valued) {
                let shown = line.flags.iter().any(|(g, _)| g == f)
                    || USAGE_NOTE.contains(&format!("{} ", f));
                assert!(
                    shown,
                    "{:?} takes {} but its usage line does not say so",
                    argv, f
                );
            }
        }
    }

    /// I8: every arm of `run` is a command `takes` knows and a usage line
    /// shows, and `run` checks the arguments before it matches an arm.
    #[test]
    fn usage_covers_every_production_arm() {
        let src = include_str!("main.rs");
        let body = &src[src.find("\nfn run(").expect("run exists") + 1..];
        let body = &body[..body.find("\n}\n").expect("run ends")];
        let first = body.lines().nth(1).unwrap_or("").trim();
        assert_eq!(
            first, "check_args(argv)?;",
            "run checks before it dispatches"
        );
        let lines = usage_lines();
        let mut arms = 0;
        for l in body.lines().filter(|l| l.starts_with("        [")) {
            let arm = l.trim_start();
            let pattern = &arm[1..arm.find(']').unwrap()];
            // Each position up to `rest @ ..`: its literal words, or none
            // for a binding, which stands for any word.
            let positions: Vec<Vec<&str>> = pattern
                .split(", ")
                .take_while(|p| !p.contains(".."))
                .map(|p| p.split('"').skip(1).step_by(2).collect())
                .collect();
            let sample: Vec<&str> = positions
                .iter()
                .map(|lits| lits.first().copied().unwrap_or("continue"))
                .collect();
            assert!(takes(&sample).is_ok(), "{:?} has no flags in takes", sample);
            let shown = lines.iter().any(|line| {
                positions.iter().enumerate().all(|(i, lits)| {
                    line.words.get(i).is_some_and(|w| {
                        let alts: Vec<&str> = w.split('|').collect();
                        lits.iter().all(|lit| alts.contains(lit))
                    })
                })
            });
            assert!(shown, "no usage line for the arm {:?}", pattern);
            arms += 1;
        }
        assert!(arms >= 16, "{} arms parsed", arms);
    }

    /// I8: help asked for by name is help; any other word is a command.
    #[test]
    fn help_is_asked_for_by_name_anywhere_on_the_line() {
        for argv in [
            &["help"][..],
            &["--help"],
            &["-h"],
            &["enroll", "--help"],
            &["presence", "on", "-h"],
        ] {
            assert!(wants_help(argv), "{:?}", argv);
        }
        for argv in [&[][..], &["doctor"], &["presence", "help"], &["helps"]] {
            assert!(!wants_help(argv), "{:?}", argv);
        }
        // Where a flag goes after a command, help; in a flag's value
        // position, a value: a look labeled -h enrolls, it does not print
        // the usage.
        for argv in [
            &["enroll", "--label", "desk", "-h"][..],
            &["enrol-control", "-h"],
            &["presence", "mode", "-h"],
        ] {
            assert!(wants_help(argv), "{:?}", argv);
        }
        // `--label --help` is not help either: `--help` stands in the
        // label's place, and the command refuses it as a missing label, so
        // a script that passes it gets an error, not the usage and exit 0.
        let label_help = ["enroll", "--user", "alice", "--label", "--help", "--guided"];
        assert!(!wants_help(&label_help));
        assert_eq!(
            check_args(&label_help).unwrap_err().to_string(),
            "--label needs a value"
        );
        let label_h = [
            "enroll", "--user", "alice", "--label", "-h", "--guided", "--start", "distance",
        ];
        for argv in [
            &label_h[..],
            &["enroll", "--label", "-h", "--guided"],
            &[
                "enroll",
                "--user",
                "alice",
                "--label",
                "--help-me",
                "--guided",
            ],
            &["probe", "--user", "-h"],
        ] {
            assert!(!wants_help(argv), "{:?}", argv);
        }
        check_args(&label_h).expect("-h is the label's value");
        let text = usage_text();
        assert!(text.starts_with("usage:\n") && text.ends_with("prints this text.\n"));
    }
}

#[cfg(test)]
mod flag_tests {
    use super::*;

    /// J23: every command refuses a flag it does not take, a flag without
    /// its value and a stray word, and takes what the shipped callers
    /// (Omarchy's setup, menu and windows) send it.
    #[test]
    fn each_command_takes_its_callers_arguments_and_refuses_others() {
        for ok in [
            &["enroll", "--user", "alice", "--guided"][..],
            &[
                "enroll", "--user", "alice", "--label", "desk", "--guided", "--start", "distance",
            ],
            &[
                "enroll",
                "--user",
                "alice",
                "--terminal",
                "--poses",
                "up,down",
            ],
            &["enroll", "--user", "alice", "--look", "--seconds", "8"],
            &["calibrate", "--user", "alice", "--guided"],
            &["presence", "on", "--user", "alice", "--away-seconds", "20"],
            &["presence", "off", "--user", "alice"],
            &["presence", "away-time", "--default", "never"],
            &[
                "presence",
                "obscured-lock",
                "--default",
                "5",
                "--secure",
                "2",
            ],
            &["presence", "mode"],
            &["presence", "mode", "secure"],
            &["presence"],
            &["probe", "--user", "alice"],
            &["key-lane", "--user", "alice"],
            &["fprint-lane", "--user", "alice"],
            &["lock-channel", "--user", "alice"],
            &["enrol-control", "continue", "--user", "alice"],
            &["consent-answer"],
            &["consent-answer", "--passwordless", "15"],
            &["kill-requester", "--pid", "4242", "--ino", "77"],
            &["templates", "delete", "--user", "alice"],
            &["doctor", "--json"],
            &["auth", "--user", "alice", "--consent"],
            &["models", "fetch"],
            &["cam", "probe"],
            &["cam", "ir-rule"],
            &["cam", "ir-reset"],
        ] {
            check_args(ok).unwrap_or_else(|e| panic!("{:?}: {}", ok, e));
        }
        for bad in [
            &["enroll", "--user", "alice", "--guidde"][..],
            &["enroll", "--terminal", "--look"],
            &["enroll", "--look", "--poses", "up"],
            &["enroll", "--start", "distance", "--seconds", "8"],
            &["enroll", "--label"],
            &["presence", "on", "--usr", "alice"],
            &["presence", "off", "--user"],
            &["calibrate", "--guided", "--usr", "alice"],
            &["presence", "mode", "--user", "alice", "secure"],
            &["presence", "mode", "secure", "--socket"],
            &["presence", "of"],
            &["auth", "--consnet"],
            &["auth", "consent"],
            &["models", "fetch", "--dri", "/tmp"],
            &["presence", "away-time", "--defualt", "20"],
            &["presence", "obscured-lock", "--secure"],
            &["doctor", "--jsn"],
            &["consent-answer", "--dismis"],
            &["enrol-control", "--user", "alice"],
            &["cam", "probe", "--all"],
            &["cam", "ir-rule", "--write"],
            &["cam", "ir-reset", "--all"],
        ] {
            assert!(check_args(bad).is_err(), "{:?} was taken", bad);
        }
        assert_eq!(
            check_args(&["no-such-command"]).unwrap_err().to_string(),
            NO_COMMAND
        );
    }
}

#[cfg(test)]
mod answer_tests {
    use super::*;

    /// J26: an answer line is read up to its newline and no further, so
    /// the password line is never read ahead into a buffer nothing wipes;
    /// a carriage return before the newline is dropped, and the end of the
    /// input ends a line.
    #[test]
    fn an_answer_line_is_read_up_to_its_newline_and_no_further() {
        let mut input: &[u8] = b"t0k3n\r\nhunter2\n";
        assert_eq!(&*secret_line(&mut input).unwrap(), "t0k3n");
        assert_eq!(input, b"hunter2\n", "the password line was read ahead");
        assert_eq!(&*secret_line(&mut input).unwrap(), "hunter2");
        assert_eq!(&*secret_line(&mut input).unwrap(), "");
        let mut last: &[u8] = b"no newline";
        assert_eq!(&*secret_line(&mut last).unwrap(), "no newline");
        let mut exact = vec![b'x'; MAX_ANSWER_LINE];
        exact.push(b'\n');
        assert_eq!(secret_line(&mut &exact[..]).unwrap().len(), MAX_ANSWER_LINE);
        let long = vec![b'x'; MAX_ANSWER_LINE + 1];
        assert!(secret_line(&mut &long[..]).is_err());
        assert!(secret_line(&mut &b"\xff\n"[..]).is_err());
    }
}
