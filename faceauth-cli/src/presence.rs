//! The config edits behind `faceauth presence`: the watch switched on or
//! off, the away times, and the obscured face lock times. Only the keys
//! asked for change,
//! the result is validated as the daemon would read it, and the file is
//! replaced atomically, so the administrator's comments and other keys
//! survive.

use anyhow::{bail, Context, Result};
use faceauth_daemon::presence::{AwayTime, PresenceConfig};

/// The `--away-seconds` value for `presence on`, if one was given. Without
/// it `on` writes no away time, so the saved ones ("never" included) stay.
pub(super) fn away_flag(arg: Option<&str>) -> Result<Option<f32>> {
    arg.map(|a| {
        a.parse()
            .with_context(|| format!("--away-seconds {}: not a number", a))
    })
    .transpose()
}

/// The away times, as the `presence on` and `presence away-time` messages
/// report them.
pub(super) fn away_summary(p: &PresenceConfig) -> String {
    let default = match p.away_seconds {
        AwayTime::Seconds(s) => format!("after {} s", s),
        AwayTime::Word(_) => "never".into(),
    };
    format!("away {}, secure {} s", default, p.secure_away_seconds)
}

/// The obscured face lock time keys from `presence obscured-lock`, checked
/// against the ranges the menu and setup offer: `--default never` or
/// minutes from 1, `--secure` minutes from 1 to 10.
pub(super) fn obscured_keys(
    default: Option<&str>,
    secure: Option<&str>,
) -> Result<Vec<(&'static str, String)>> {
    let mut keys = Vec::new();
    if let Some(d) = default {
        if d == "never" {
            keys.push(("obscured_face_lock", "\"never\"".to_string()));
        } else {
            match d.parse::<u32>() {
                Ok(m) if m >= 1 => keys.push(("obscured_face_lock", m.to_string())),
                _ => bail!(
                    "--default {}: \"never\" or a number of minutes, 1 or more",
                    d
                ),
            }
        }
    }
    if let Some(v) = secure {
        let (lo, hi) = faceauth_daemon::presence::SECURE_OBSCURED_LOCK_RANGE;
        match v.parse::<u32>() {
            Ok(m) if (lo..=hi).contains(&m) => {
                keys.push(("secure_obscured_face_lock", m.to_string()))
            }
            _ => bail!("--secure {}: minutes from {} to {}", v, lo, hi),
        }
    }
    if keys.is_empty() {
        bail!("give --default never|MINUTES, --secure MINUTES, or both");
    }
    Ok(keys)
}

/// The away time keys from `presence away-time`, checked as the daemon reads
/// them: `--default never` or a number of seconds above 0, `--secure` a
/// number of seconds above 0. The secure mode has no "never": it promises
/// that only a verified face keeps the session open. Written as the file
/// already writes seconds (`30.0`), so the menu's checks read them back.
pub(super) fn away_keys(
    default: Option<&str>,
    secure: Option<&str>,
) -> Result<Vec<(&'static str, String)>> {
    let seconds = |v: &str| -> Option<String> {
        let s: f64 = v.parse().ok()?;
        (s > 0.0 && (s as f32).is_finite()).then(|| format!("{:?}", s))
    };
    let mut keys = Vec::new();
    if let Some(d) = default {
        if d == "never" {
            keys.push(("away_seconds", "\"never\"".to_string()));
        } else {
            match seconds(d) {
                Some(s) => keys.push(("away_seconds", s)),
                None => bail!("--default {}: \"never\" or a number of seconds above 0", d),
            }
        }
    }
    if let Some(v) = secure {
        match seconds(v) {
            Some(s) => keys.push(("secure_away_seconds", s)),
            None => bail!(
                "--secure {}: a number of seconds above 0 (the secure mode has no \"never\")",
                v
            ),
        }
    }
    if keys.is_empty() {
        bail!("give --default never|SECONDS, --secure SECONDS, or both");
    }
    Ok(keys)
}

/// The config text with lock times set and nothing else, the obscured face
/// lock times or the away times: `enabled` and the user stay as they are, so
/// saving a time never switches the walk-away lock on or off. Validated as
/// the daemon parses it.
pub(super) fn lock_time_edit(text: &str, origin: &str, keys: &[(&str, String)]) -> Result<String> {
    let edited = set_presence_keys(text, keys);
    let before = faceauth_daemon::config::Config::from_text(text, origin).ok();
    let cfg = faceauth_daemon::config::Config::from_text(&edited, origin).with_context(|| {
        format!(
            "the change would leave {} unusable by the daemon; nothing was written",
            origin
        )
    })?;
    if let Some(b) = before {
        if b.presence.enabled != cfg.presence.enabled {
            bail!("setting a lock time must not switch the walk-away lock; nothing was written");
        }
    }
    Ok(edited)
}

/// The config text with the presence watch switched: `on` sets the user,
/// and the default mode's away time only when `--away-seconds` gave one;
/// `off` sets only `enabled`. The administrator's other keys, the saved
/// away times and every comment stay as they are. The result is parsed and
/// validated as the daemon would parse it before anything is written, so a
/// value the daemon would refuse to start on (a zero or negative away time)
/// is refused here instead (E3).
pub(super) fn presence_edit(
    text: &str,
    origin: &str,
    on: bool,
    user: &str,
    away: Option<f32>,
) -> Result<String> {
    if let (true, Some(away)) = (on, away) {
        if !away.is_finite() || away <= 0.0 {
            bail!(
                "--away-seconds {}: the away time must be a positive number of seconds",
                away
            );
        }
    }
    let mut keys: Vec<(&str, String)> = vec![("enabled", on.to_string())];
    if on {
        keys.push(("user", toml::Value::String(user.to_string()).to_string()));
        if let Some(away) = away {
            keys.push(("away_seconds", format!("{:?}", away as f64)));
        }
    }
    let edited = set_presence_keys(text, &keys);
    let cfg = faceauth_daemon::config::Config::from_text(&edited, origin).with_context(|| {
        format!(
            "the change would leave {} unusable by the daemon; nothing was written",
            origin
        )
    })?;
    let away_took =
        |a: f32| matches!(cfg.presence.away_seconds, AwayTime::Seconds(s) if (s - a).abs() < 1e-3);
    let took = cfg.presence.enabled == on
        && (!on || (cfg.presence.user == user && away.map(away_took).unwrap_or(true)));
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
pub(super) fn write_config_atomically(path: &str, text: &str) -> Result<()> {
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

#[cfg(test)]
mod arg_tests {
    use super::*;

    /// J27: the exit status follows the daemon's answer for every scripted
    /// subcommand.
    /// `presence on` writes an away time only when `--away-seconds` gives
    /// one: without it the saved times stay, a default of "never" included,
    /// which is what the menu's Enable row relies on.
    #[test]
    fn the_away_time_stays_unless_given() {
        assert_eq!(away_flag(None).unwrap(), None);
        assert_eq!(away_flag(Some("30")).unwrap(), Some(30.0));
        assert!(away_flag(Some("soon")).is_err());
        let off = "[presence]\nenabled = false\nuser = \"mike\"\naway_seconds = \"never\"\nsecure_away_seconds = 45.0\n";
        let on = presence_edit(off, "test", true, "mike", None).unwrap();
        assert_eq!(on, off.replace("enabled = false", "enabled = true"));
        let cfg = faceauth_daemon::config::Config::from_text(&on, "test").unwrap();
        assert!(cfg.presence.enabled);
        assert_eq!(
            cfg.presence.away_seconds,
            AwayTime::Word(faceauth_daemon::presence::LockWord::Never)
        );
        assert_eq!(cfg.presence.secure_away_seconds, 45.0);
        let on = presence_edit(off, "test", true, "mike", Some(30.0)).unwrap();
        assert!(on.contains("\naway_seconds = 30.0\n"), "{}", on);
        assert!(on.contains("\nsecure_away_seconds = 45.0\n"), "{}", on);
    }

    /// The away time flags take what the daemon reads and nothing else: the
    /// default mode a number of seconds or "never", the secure mode seconds
    /// only. Saving them writes only their keys, in the forms the menu's
    /// checks read back, and never switches the walk-away lock on or off.
    #[test]
    fn away_times_save_only_their_keys_without_switching_the_lock() {
        assert!(away_keys(None, None).is_err());
        assert_eq!(
            away_keys(Some("never"), Some("30")).unwrap(),
            vec![
                ("away_seconds", "\"never\"".to_string()),
                ("secure_away_seconds", "30.0".to_string())
            ]
        );
        assert_eq!(
            away_keys(Some("60"), None).unwrap(),
            vec![("away_seconds", "60.0".to_string())]
        );
        assert_eq!(
            away_keys(None, Some("20")).unwrap(),
            vec![("secure_away_seconds", "20.0".to_string())]
        );
        for bad in ["0", "-5", "soon", "NaN", "inf", "1e300", "Never", ""] {
            assert!(away_keys(Some(bad), None).is_err(), "--default {:?}", bad);
        }
        for bad in ["never", "0", "-20", "soon", "NaN", "inf"] {
            assert!(away_keys(None, Some(bad)).is_err(), "--secure {:?}", bad);
        }
        for enabled in ["false", "true"] {
            let text = format!(
                "[presence]\nenabled = {}\nuser = \"mike\"\naway_seconds = 45.0 # mine\nobscured_face_lock = 30\n",
                enabled
            );
            let out =
                lock_time_edit(&text, "test", &away_keys(Some("30"), Some("60")).unwrap()).unwrap();
            assert_eq!(
                out,
                text.replace("away_seconds = 45.0 # mine", "away_seconds = 30.0 # mine")
                    + "secure_away_seconds = 60.0\n",
                "only the away keys change"
            );
            let cfg = faceauth_daemon::config::Config::from_text(&out, "test").unwrap();
            assert_eq!(cfg.presence.enabled, enabled == "true");
            assert_eq!(cfg.presence.away_seconds, AwayTime::Seconds(30.0));
            assert_eq!(cfg.presence.secure_away_seconds, 60.0);
            let out =
                lock_time_edit(&text, "test", &away_keys(Some("never"), None).unwrap()).unwrap();
            assert!(
                out.contains("\naway_seconds = \"never\" # mine\n"),
                "{}",
                out
            );
            let cfg = faceauth_daemon::config::Config::from_text(&out, "test").unwrap();
            assert_eq!(cfg.presence.enabled, enabled == "true");
            assert_eq!(cfg.presence.secure_away_seconds, 20.0);
        }
        let out =
            lock_time_edit("", "test", &away_keys(Some("never"), Some("30")).unwrap()).unwrap();
        assert_eq!(
            out,
            "[presence]\naway_seconds = \"never\"\nsecure_away_seconds = 30.0\n"
        );
        let cfg = faceauth_daemon::config::Config::from_text(&out, "test").unwrap();
        assert!(!cfg.presence.enabled, "saving a time leaves the lock off");
        assert_eq!(
            cfg.presence
                .away_for(faceauth_daemon::presence::PresenceMode::Default),
            None
        );
    }

    /// The lock time flags take what the menu and setup offer and nothing
    /// else, and saving one never switches the walk-away lock on or off.
    #[test]
    fn obscured_lock_times_save_without_switching_the_lock() {
        assert!(obscured_keys(None, None).is_err());
        assert_eq!(
            obscured_keys(Some("never"), Some("2")).unwrap(),
            vec![
                ("obscured_face_lock", "\"never\"".to_string()),
                ("secure_obscured_face_lock", "2".to_string())
            ]
        );
        assert_eq!(
            obscured_keys(Some("240"), None).unwrap(),
            vec![("obscured_face_lock", "240".to_string())]
        );
        assert!(obscured_keys(Some("0"), None).is_err());
        assert!(obscured_keys(Some("none"), None).is_err());
        assert!(obscured_keys(None, Some("11")).is_err());
        assert!(obscured_keys(None, Some("0")).is_err());
        let off = "[presence]\nenabled = false\nuser = \"mike\"\naway_seconds = 45.0\n";
        let out =
            lock_time_edit(off, "test", &obscured_keys(Some("30"), Some("5")).unwrap()).unwrap();
        let cfg = faceauth_daemon::config::Config::from_text(&out, "test").unwrap();
        assert!(!cfg.presence.enabled, "saving a time leaves the lock off");
        assert_eq!(cfg.presence.away_seconds, AwayTime::Seconds(45.0));
        assert_eq!(
            cfg.presence.obscured_face_lock,
            faceauth_daemon::presence::ObscuredFaceLock::Minutes(30)
        );
        assert_eq!(cfg.presence.secure_obscured_face_lock, 5);
        let out = lock_time_edit("", "test", &obscured_keys(Some("never"), None).unwrap()).unwrap();
        let cfg = faceauth_daemon::config::Config::from_text(&out, "test").unwrap();
        assert!(!cfg.presence.enabled);
        assert_eq!(
            cfg.presence
                .obscured_lock_for(faceauth_daemon::presence::PresenceMode::Default),
            None
        );
    }
}

#[cfg(test)]
mod presence_edit_tests {
    use super::{presence_edit, set_presence_keys, toml_content, AwayTime};

    const SHIPPED: &str = include_str!("../../packaging/config.toml");

    /// E3: an away time the daemon would refuse to start on is refused
    /// before anything is written.
    #[test]
    fn a_zero_or_negative_away_time_is_refused_before_any_write() {
        for away in [0.0f32, -5.0, f32::NAN, f32::INFINITY] {
            let r = presence_edit(SHIPPED, "test", true, "mike", Some(away));
            assert!(r.is_err(), "away {} accepted", away);
        }
        assert!(presence_edit(SHIPPED, "test", true, "mike", Some(20.0)).is_ok());
    }

    /// E3: the shipped, commented config keeps every comment and every
    /// other key; only the three presence keys change.
    #[test]
    fn a_commented_config_keeps_its_comments() {
        let out = presence_edit(SHIPPED, "test", true, "mike", Some(30.0)).unwrap();
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
        assert_eq!(cfg.presence.away_seconds, AwayTime::Seconds(30.0));
    }

    /// `on` without `--away-seconds` writes only `enabled` and the user: the
    /// shipped file's away times stay commented out, at their defaults.
    #[test]
    fn on_without_a_flag_writes_no_away_time() {
        let out = presence_edit(SHIPPED, "test", true, "mike", None).unwrap();
        assert!(
            !out.lines()
                .any(|l| l.starts_with("away_seconds") || l.starts_with("secure_away_seconds")),
            "{}",
            out
        );
        assert_eq!(out.lines().count(), SHIPPED.lines().count());
        let cfg = faceauth_daemon::config::Config::from_text(&out, "test").unwrap();
        assert!(cfg.presence.enabled);
        assert_eq!(cfg.presence.away_seconds, AwayTime::Seconds(20.0));
        assert_eq!(cfg.presence.secure_away_seconds, 20.0);
    }

    /// E3: `off` sets only `enabled`; the user and the away time stay.
    #[test]
    fn off_sets_only_enabled() {
        let on = presence_edit(SHIPPED, "test", true, "mike", Some(45.0)).unwrap();
        let off = presence_edit(&on, "test", false, "somebody-else", Some(5.0)).unwrap();
        let cfg = faceauth_daemon::config::Config::from_text(&off, "test").unwrap();
        assert!(!cfg.presence.enabled);
        assert_eq!(cfg.presence.user, "mike");
        assert_eq!(cfg.presence.away_seconds, AwayTime::Seconds(45.0));
        assert_eq!(off.replace("enabled = false", "enabled = true"), on);
    }

    /// A file without the table gets one; a table followed by another
    /// keeps the new keys inside it.
    #[test]
    fn missing_keys_and_tables_are_added_in_place() {
        let out = presence_edit("", "test", true, "mike", None).unwrap();
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
