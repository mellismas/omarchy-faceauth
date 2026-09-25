//! Calls into the user's session: the window's shell, the lock question
//! and desktop notices. Each runs inside the user's own systemd manager, so
//! the daemon never switches uid to reach the desktop.

use anyhow::{anyhow, Context, Result};

/// One command inside the user's own systemd manager, the route every
/// call into the user's session takes (the window, a notice, the lock
/// question): `systemd-run --user --machine=<user>@.host` from root, under
/// a five-second timeout, so the daemon never switches uid itself (H18).
/// `description` names the unit in the journal, where the default would
/// be the command line, payload and token included; with `omarchy` the
/// tree the shell was launched from goes in as OMARCHY_PATH; `wait` waits
/// for the command to end and `pipe` brings its stdout back.
fn in_user_manager(
    user: &str,
    description: Option<&str>,
    omarchy: bool,
    wait: bool,
    pipe: bool,
) -> std::process::Command {
    let mut c = std::process::Command::new("/usr/bin/timeout");
    c.args([
        "5",
        "/usr/bin/systemd-run",
        "--quiet",
        "--collect",
        "--user",
    ]);
    if wait {
        c.arg("--wait");
    }
    if pipe {
        c.arg("--pipe");
    }
    if let Some(d) = description {
        c.arg(format!("--description={}", d));
    }
    c.arg(format!("--machine={}@.host", user));
    if omarchy {
        c.arg(format!("-EOMARCHY_PATH={}", omarchy_path()));
    }
    c.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    c
}

/// One `omarchy-shell` invocation inside the user's own systemd manager,
/// the same route the session lock uses.
pub fn shell_call(user: &str, args: &[&str]) -> Result<()> {
    // The shell's answer comes back on stdout (`--pipe`), so a summon the
    // shell could not honour is read here rather than by a change to the
    // shared command (F2).
    let output = in_user_manager(user, Some("omarchy-faceauth window"), true, true, true)
        .arg("/usr/bin/omarchy-shell")
        .args(args)
        .output()
        .context("run omarchy-shell in the user's manager")?;
    shell_answer(args, output.status.success(), &output.stdout)
}

/// What `omarchy-shell` said, read for the daemon's purposes. A failed
/// exit is an error. A summon answered "unknown" is one too: the shell
/// has no such window (a disabled or absent plugin), nothing was shown,
/// and a caller that summoned something must not read the answer as
/// shown. Every other answer is the shell's business.
pub fn shell_answer(args: &[&str], success: bool, stdout: &[u8]) -> Result<()> {
    if !success {
        return Err(anyhow!("omarchy-shell {:?} failed", args));
    }
    let summon = args.len() >= 2 && args[0] == "shell" && args[1] == "summon";
    if summon && String::from_utf8_lossy(stdout).trim() == "unknown" {
        return Err(anyhow!(
            "omarchy-shell has no such window: {}",
            args.get(2).copied().unwrap_or("")
        ));
    }
    Ok(())
}

/// Is the user's session locked? Asked of the compositor from inside the
/// user's manager, the same way the window is summoned. Unknown reads as
/// not locked.
pub fn session_locked(user: &str) -> bool {
    in_user_manager(user, None, false, true, false)
        .arg("/usr/bin/omarchy-hyprland-session-locked")
        .status()
        .map(|st| st.success())
        .unwrap_or(false)
}

/// The Omarchy tree the running shell was launched from:
/// `/etc/omarchy.conf` (written by `omarchy-dev-link` as `export
/// OMARCHY_PATH="..."`, and by hand as a bare assignment), else the
/// package. One resolver for the window, the notices and the lock helper,
/// so a dev-linked desktop is reached the same way by all three.
pub fn omarchy_path() -> String {
    std::fs::read_to_string("/etc/omarchy.conf")
        .ok()
        .and_then(|t| omarchy_path_from_conf(&t))
        .unwrap_or_else(|| "/usr/share/omarchy".into())
}

/// The `OMARCHY_PATH` value in an omarchy.conf text, with or without an
/// `export` prefix and with or without quotes; `None` when the file names
/// nothing usable, so the caller falls through to the package.
pub fn omarchy_path_from_conf(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let l = l.trim();
        let l = l.strip_prefix("export ").map(str::trim_start).unwrap_or(l);
        let v = l
            .strip_prefix("OMARCHY_PATH=")?
            .trim()
            .trim_matches('"')
            .trim_matches('\'');
        (!v.is_empty() && v.starts_with('/')).then(|| v.to_string())
    })
}

/// A desktop notification in the user's session: every elevation by face
/// announces itself, so a loop is visible the first time it fires.
pub fn notify(user: &str, title: &str, body: &str) {
    let _ = in_user_manager(user, Some("omarchy-faceauth notice"), true, false, false)
        .args(["/usr/bin/omarchy-notification-send", title, body])
        .status();
}

#[cfg(test)]
mod shell_answer_tests {
    use super::*;

    /// F2: the "unknown" a summon gets for a window the shell does not
    /// have is read by the daemon, not by a change to the shared command.
    #[test]
    fn a_summon_answered_unknown_is_an_error_and_nothing_else_is() {
        let summon = ["shell", "summon", "omarchy.faceauth", "{}"];
        assert!(shell_answer(&summon, true, b"unknown\n").is_err());
        assert!(shell_answer(&summon, true, b"  unknown  ").is_err());
        assert!(shell_answer(&summon, true, b"ok\n").is_ok());
        assert!(shell_answer(&summon, true, b"").is_ok());
        assert!(
            shell_answer(&summon, false, b"ok\n").is_err(),
            "a failed exit is an error whatever was said"
        );
        let hide = ["shell", "hide", "omarchy.faceauth"];
        assert!(
            shell_answer(&hide, true, b"unknown\n").is_ok(),
            "only a summon has to have shown something"
        );
        assert!(shell_answer(&["shell", "ping"], true, b"unknown").is_ok());
    }
}

#[cfg(test)]
mod window_text_tests {

    #[test]
    fn the_omarchy_path_is_read_in_every_form_the_conf_takes() {
        use super::omarchy_path_from_conf as f;
        assert_eq!(
            f("export OMARCHY_PATH=\"/home/x/omarchy\"\n").as_deref(),
            Some("/home/x/omarchy")
        );
        assert_eq!(
            f("OMARCHY_PATH=/usr/share/omarchy\n").as_deref(),
            Some("/usr/share/omarchy")
        );
        assert_eq!(
            f("# comment\n  export  OMARCHY_PATH='/opt/o'\n").as_deref(),
            Some("/opt/o")
        );
        assert_eq!(f("OMARCHY_PATH=\n"), None);
        assert_eq!(f("OMARCHY_PATH=relative\n"), None);
        assert_eq!(f(""), None);
    }
}
