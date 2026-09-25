//! Passwordless sudo as the approval of a request can grant it: the
//! sudoers.d rule and the timer that removes it. The file and unit names
//! are Omarchy's own, so its toggle and its reboot cleanup undo a spell
//! started here.

use super::requester::CallerInfo;
#[cfg(test)]
use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use std::path::Path;

/// The longest passwordless spell the card may ask for.
pub const PASSWORDLESS_MAX_MINUTES: u32 = 24 * 60;

/// The sudoers.d file and the expiry timer unit Omarchy's own
/// `omarchy-sudo-passwordless` command uses, so its toggle-off, its
/// re-arm and its reboot cleanup all apply to a spell started here.
pub fn passwordless_file(dir: &Path, user: &str) -> std::path::PathBuf {
    dir.join(format!("99-omarchy-nopasswd-{}", user))
}

pub fn passwordless_timer_unit(user: &str) -> String {
    format!("omarchy-nopasswd-expire-{}", user)
}

/// Turn passwordless sudo on for `user` for `minutes`: the NOPASSWD rule
/// as a root-only sudoers.d file, and a transient timer that deletes it.
/// `arm` runs the timer command (systemd-run, as root) first: a timer with
/// no rule to delete is nothing, a rule with no timer would never end.
/// Only then is the rule written, so the spell never outlives its timer.
pub fn enable_passwordless(
    dir: &Path,
    user: &str,
    minutes: u32,
    arm: &dyn Fn(&[String]) -> Result<()>,
) -> Result<std::path::PathBuf> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if user.is_empty()
        || !user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("user name {:?} cannot be written into a sudoers rule", user);
    }
    let file = passwordless_file(dir, user);
    let unit = passwordless_timer_unit(user);
    let args: Vec<String> = vec![
        "--on-active".into(),
        format!("{}m", minutes),
        "--timer-property=AccuracySec=1s".into(),
        format!("--unit={}", unit),
        "--collect".into(),
        "/usr/bin/rm".into(),
        "-f".into(),
        "--".into(),
        file.display().to_string(),
    ];
    if let Err(e) = arm(&args) {
        // The timer could not be armed. A rule from an earlier spell may
        // still be in place with its own timer just stopped (see
        // `run_passwordless_timer`), and a rule with no timer would never
        // end: the rule goes now, as Omarchy's own command does when its
        // timer fails.
        match std::fs::remove_file(&file) {
            Ok(()) => log::warn!(
                "passwordless sudo for {}: the expiry timer could not be armed; the earlier rule was removed",
                user
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => log::error!(
                "passwordless sudo for {}: no expiry timer, and {} could not be removed: {}; remove it as root",
                user,
                file.display(),
                e
            ),
        }
        return Err(e.context("arm the passwordless expiry timer; no rule is in place"));
    }
    let tmp = dir.join(format!(".99-omarchy-nopasswd-{}.tmp", user));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o440)
            .open(&tmp)
            .with_context(|| format!("write {}", tmp.display()))?;
        writeln!(f, "{} ALL=(ALL) NOPASSWD: ALL", user)?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o440))?;
    std::fs::rename(&tmp, &file).with_context(|| format!("place {}", file.display()))?;
    Ok(file)
}

/// Is this request Omarchy's own passwordless-sudo command? Its toggle
/// would fight a spell started from its own card (it removes the rule and
/// stops the timer as it finishes), so the button does not apply to it.
pub fn is_passwordless_command(caller: &CallerInfo) -> bool {
    caller
        .command
        .split_whitespace()
        .any(|w| w == "omarchy-sudo-passwordless" || w.ends_with("/omarchy-sudo-passwordless"))
}

/// `systemd-run` as root, for the expiry timer. An earlier timer of the
/// same name (a spell being extended) is stopped first: the name is the
/// one Omarchy's own command uses, so its toggle-off still applies, and
/// systemd will not start a second unit under it. If the new timer then
/// fails to start, `enable_passwordless` removes the rule.
pub fn run_passwordless_timer(user: &str, args: &[String]) -> Result<()> {
    let unit = format!("{}.timer", passwordless_timer_unit(user));
    let _ = std::process::Command::new("/usr/bin/systemctl")
        .args(["stop", &unit])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output();
    let out = std::process::Command::new("/usr/bin/timeout")
        .args(["-k", "2", "10", "/usr/bin/systemd-run"])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .context("run systemd-run")?;
    if !out.status.success() {
        bail!(
            "systemd-run {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod passwordless_tests {
    use super::*;

    /// Re-arming with a timer that will not start leaves no rule behind:
    /// the earlier spell's rule goes with its stopped timer.
    #[test]
    fn a_failed_re_arm_removes_the_earlier_rule() {
        let dir =
            std::env::temp_dir().join(format!("faceauth-sudoers-rearm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let calls = std::cell::Cell::new(0u32);
        let arm = |_: &[String]| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                Ok(())
            } else {
                Err(anyhow!(
                    "Unit omarchy-nopasswd-expire-mellis.timer already exists"
                ))
            }
        };
        let file = enable_passwordless(&dir, "mellis", 20, &arm).unwrap();
        assert!(file.exists(), "the first spell is in place with its timer");
        let err = enable_passwordless(&dir, "mellis", 40, &arm).unwrap_err();
        assert!(err.to_string().contains("no rule is in place"), "{:#}", err);
        assert!(
            !file.exists(),
            "the earlier rule does not outlive its timer when the re-arm fails"
        );
        assert_eq!(calls.get(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The rule Omarchy's own command writes, root-only, and the timer it
    /// arms; a timer that cannot be armed takes the rule with it.
    #[test]
    fn the_rule_is_written_root_only_with_its_expiry_timer() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("faceauth-sudoers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let seen = std::sync::Mutex::new(Vec::<String>::new());
        let arm = |args: &[String]| {
            seen.lock().unwrap().extend(args.iter().cloned());
            Ok(())
        };
        let file = enable_passwordless(&dir, "mellis", 20, &arm).unwrap();
        assert_eq!(file, dir.join("99-omarchy-nopasswd-mellis"));
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "mellis ALL=(ALL) NOPASSWD: ALL\n"
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o440
        );
        let args = seen.lock().unwrap().join(" ");
        assert!(
            args.contains("--on-active 20m")
                && args.contains("--unit=omarchy-nopasswd-expire-mellis")
                && args.ends_with(&format!("/usr/bin/rm -f -- {}", file.display())),
            "{}",
            args
        );
        // A user name that could break out of the rule is refused.
        assert!(enable_passwordless(&dir, "evil ALL=(ALL)", 5, &arm).is_err());
        // No timer, no rule: the timer is armed before the rule is written.
        let fail = |_: &[String]| Err(anyhow!("no systemd"));
        assert!(enable_passwordless(&dir, "bob", 5, &fail).is_err());
        assert!(!dir.join("99-omarchy-nopasswd-bob").exists());
        let mut c = CallerInfo {
            command: "sudo omarchy-sudo-passwordless".into(),
            ..Default::default()
        };
        assert!(is_passwordless_command(&c));
        c.command = "sudo /usr/bin/omarchy-sudo-passwordless 30".into();
        assert!(is_passwordless_command(&c));
        c.command = "sudo pacman -Syu".into();
        assert!(!is_passwordless_command(&c));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
