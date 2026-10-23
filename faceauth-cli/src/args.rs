//! The argument helpers every subcommand shares, and the exit status a
//! scripted subcommand returns. A flag a command does not know is refused
//! rather than ignored, so a misspelt flag never runs the command without
//! it.

use anyhow::{anyhow, bail, Context, Result};

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
pub(super) fn user_arg(rest: &[&str]) -> Result<String> {
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

pub(super) fn opt<'a>(rest: &'a [&str], key: &str) -> Option<&'a str> {
    opt_value(rest, key).ok().flatten()
}

/// `--seconds N` when given, else `default`: a number of seconds from `lo`
/// to `hi`. Anything else (a word, NaN, a negative, a length no request
/// runs) is refused with the range, before it reaches a conversion that
/// panics on it.
pub(super) fn seconds_arg(rest: &[&str], default: f32, lo: f32, hi: f32) -> Result<f32> {
    let Some(v) = opt(rest, "--seconds") else {
        return Ok(default);
    };
    match v.parse::<f32>() {
        Ok(s) if (lo..=hi).contains(&s) => Ok(s),
        _ => bail!(
            "--seconds takes a number of seconds from {} to {}, not {:?}",
            lo,
            hi,
            v
        ),
    }
}

/// `--count N` when given, else `default`: a whole number from `lo` to
/// `hi`, refused otherwise.
pub(super) fn count_arg(rest: &[&str], default: usize, lo: usize, hi: usize) -> Result<usize> {
    let Some(v) = opt(rest, "--count") else {
        return Ok(default);
    };
    match v.parse::<usize>() {
        Ok(n) if (lo..=hi).contains(&n) => Ok(n),
        _ => bail!(
            "--count takes a whole number from {} to {}, not {:?}",
            lo,
            hi,
            v
        ),
    }
}

/// Refuse anything a command does not take: a flag it does not know, one
/// of its `valued` flags without a value, and a stray word. A misspelt
/// `--user` must not fall through to the default user, a misspelt
/// `--dismiss` must not read as a password answer, and `presence of` must
/// not read the watch's state as if nothing were wrong (J23).
pub(super) fn only_flags(rest: &[&str], switches: &[&str], valued: &[&str]) -> Result<()> {
    flags_and_words(rest, switches, valued, |_| false)
}

/// As `only_flags`, with the words `own` accepts taken as the command's
/// own arguments: a development tool's images or directories.
pub(super) fn flags_and_words(
    rest: &[&str],
    switches: &[&str],
    valued: &[&str],
    own: fn(&str) -> bool,
) -> Result<()> {
    let mut words = rest.iter();
    while let Some(w) = words.next() {
        if switches.contains(w) {
            continue;
        }
        if valued.contains(w) {
            match words.next() {
                Some(v) if !v.starts_with("--") => continue,
                _ => bail!("{} needs a value", w),
            }
        }
        if own(w) {
            continue;
        }
        if w.starts_with('-') {
            bail!(
                "unknown flag {} (faceauth --help lists each command's flags)",
                w
            );
        }
        bail!(
            "unexpected argument {} (faceauth --help lists each command's arguments)",
            w
        );
    }
    Ok(())
}

/// The exit status for a scripted subcommand, from the daemon's answer:
/// 0 when it did what was asked, 1 when it refused or the answer was a
/// denial, 2 when the daemon could not do it at all (J27). Of the answers
/// a `templates delete` gets, only `Deleted` and `NotEnrolled` exit 0; an
/// `Error` (busy, a caller refused as remote, a store error) exits 2, so a
/// removal script does not report a deletion that did not happen and skip
/// its own fallback. `key-lane`'s and `fprint-lane`'s `NotRunning` (no
/// daemon to ask) exits 0: the lock screen reads it from stdout, says
/// faceauth is not running, and goes back to stock Omarchy's fingerprint
/// lane.
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
        | Outcome::KeyLane { .. }
        | Outcome::FprintLane { .. }
        | Outcome::NotRunning
        | Outcome::PresenceMode { .. } => 0,
        Outcome::Error { .. } => 2,
        _ => 1,
    }
}

/// Print the daemon's answer as one JSON line and exit with `exit_for`.
pub(super) fn finish(o: &faceauth_daemon::auth::Outcome) -> Result<()> {
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

#[cfg(test)]
mod arg_tests {
    use super::*;
    use faceauth_daemon::auth::Outcome;

    /// J23: a `--user` with no name, or followed by another flag, is an
    /// error rather than a fall-through; an unknown flag and a stray word
    /// are refused.
    #[test]
    fn a_valueless_user_flag_and_an_unknown_flag_are_refused() {
        assert_eq!(
            opt_value(&["--user", "alice"], "--user").unwrap(),
            Some("alice")
        );
        assert_eq!(opt_value(&["--socket", "/x"], "--user").unwrap(), None);
        assert!(opt_value(&["--user"], "--user").is_err());
        assert!(opt_value(&["--user", "--dismiss"], "--user").is_err());
        assert!(user_arg(&["--user"]).is_err());
        assert_eq!(user_arg(&["--user", "alice"]).unwrap(), "alice");
        let takes = |rest: &[&str]| only_flags(rest, &["--dismiss"], &["--user"]);
        assert!(takes(&["--user", "alice", "--dismiss"]).is_ok());
        assert!(takes(&[]).is_ok());
        for bad in [
            &["--user", "alice", "--dismis"][..],
            &["--usr", "alice"],
            &["-u", "alice"],
            &["--user"],
            &["--user", "--dismiss"],
            &["--dismiss", "alice"],
            &["continue"],
        ] {
            assert!(takes(bad).is_err(), "{:?} was taken", bad);
        }
        assert!(takes(&["--dismis"])
            .unwrap_err()
            .to_string()
            .starts_with("unknown flag --dismis"));
        assert_eq!(
            takes(&["--user"]).unwrap_err().to_string(),
            "--user needs a value"
        );
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
                scannable: false,
                likely: false,
                cadence: Default::default(),
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
                secure_available: None,
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
        // Round 5 (C): the lock screen reads "not running" from stdout.
        assert_eq!(exit_for(&Outcome::NotRunning), 0);
        assert_eq!(
            exit_for(&Outcome::KeyLane {
                available: false,
                reason: None
            }),
            0
        );
        assert_eq!(
            exit_for(&Outcome::FprintLane {
                available: false,
                reason: None
            }),
            0
        );
    }
}

#[cfg(test)]
mod probe_line_tests {
    use faceauth_daemon::auth::Outcome;

    /// `faceauth probe` prints the daemon's reply as one JSON line, so the
    /// lock screen reads `likely` and `cadence` from it; against an older
    /// daemon the line still carries both, as the lock screen would read
    /// their absence (likely, the shipped intervals).
    #[test]
    fn the_probe_line_carries_likely_and_cadence() {
        let cadence = r#""cadence":{"ac":2.5,"performance":3.0,"balanced":6.0,"power-saver":9.0}"#;
        let reply = format!(
            r#"{{"result":"probe","face":true,"attentive":true,"face_px":88.0,"scannable":true,"likely":false,{},"elapsed_ms":455}}"#,
            cadence
        );
        let line =
            serde_json::to_string(&serde_json::from_str::<Outcome>(&reply).unwrap()).unwrap();
        assert!(line.contains(r#""likely":false"#), "{}", line);
        assert!(line.contains(cadence), "{}", line);
        assert!(!line.contains("score"), "{}", line);
        let old = r#"{"result":"probe","face":true,"attentive":true,"face_px":88.0,"scannable":true,"elapsed_ms":455}"#;
        let line = serde_json::to_string(&serde_json::from_str::<Outcome>(old).unwrap()).unwrap();
        assert!(line.contains(r#""likely":true"#), "{}", line);
        assert!(
            line.contains(
                r#""cadence":{"ac":1.0,"performance":2.0,"balanced":3.0,"power-saver":5.0}"#
            ),
            "{}",
            line
        );
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
mod seconds_tests {
    use super::{count_arg, seconds_arg};

    /// A length that is not a number of seconds the request can run is
    /// refused with the range, never handed on to a conversion that
    /// panics on NaN, a negative or an overflow.
    #[test]
    fn a_length_outside_its_range_is_refused_before_anything_runs() {
        assert_eq!(seconds_arg(&[], 12.0, 4.0, 20.0).unwrap(), 12.0);
        assert_eq!(
            seconds_arg(&["--seconds", "8"], 12.0, 4.0, 20.0).unwrap(),
            8.0
        );
        for bad in ["nan", "NaN", "-100", "1e30", "inf", "3", "21", "eight"] {
            let e = seconds_arg(&["--seconds", bad], 12.0, 4.0, 20.0)
                .expect_err(bad)
                .to_string();
            assert!(e.contains("from 4 to 20"), "{}: {}", bad, e);
        }
        assert_eq!(count_arg(&["--count", "10"], 10, 3, 40).unwrap(), 10);
        for bad in ["0", "41", "-1", "many"] {
            assert!(count_arg(&["--count", bad], 10, 3, 40).is_err(), "{}", bad);
        }
    }
}
