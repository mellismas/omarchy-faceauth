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

/// Refuse a flag no subcommand of this name takes: a misspelt `--user`
/// must not fall through to the default user, and a misspelt `--dismiss`
/// must not read as a password answer (J23).
pub(super) fn only_flags(rest: &[&str], allowed: &[&str]) -> Result<()> {
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
