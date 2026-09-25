//! The machine checks behind `faceauth doctor`: the IR sensor and its
//! node, the udev tags, and the PAM stacks. They read sysfs, the udev
//! database and the PAM files directly, without asking the daemon.

use super::libc_geteuid;
#[cfg(test)]
use anyhow::anyhow;
use std::path::Path;

/// The IR sensor as sysfs names it, without opening its node: the subdev's
/// directory name (`v4l-subdev8`) and its `name` attribute (`ov7251 3-0060`).
/// Matched by name, never by number, like the udev rule.
pub(super) fn ir_sensor_from_sysfs(class_dir: &Path) -> Option<(String, String)> {
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
pub(super) fn udev_current_tags(db_dir: &Path, rdev: u64) -> Vec<String> {
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
pub(super) fn user_can_write(dev: &Path) -> bool {
    std::fs::OpenOptions::new().write(true).open(dev).is_ok()
}

/// The verdict on the IR sensor's control node. Right is root:root 0600 with
/// no uaccess tag and no write access for the caller; anything looser lets a
/// process running as the user change the sensor under the daemon.
pub(super) fn ir_node_verdict(
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

/// Whether an error from the camera probe is the node refusing to open.
pub(super) fn is_permission_denied(e: &anyhow::Error) -> bool {
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
pub(super) fn pam_stack_verdict(id: &str, text: &str) -> (&'static str, String) {
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

#[cfg(test)]
mod doctor_tests {
    use super::*;

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
