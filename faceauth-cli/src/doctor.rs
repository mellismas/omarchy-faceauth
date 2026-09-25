//! `faceauth doctor`: one row per check, as text or as JSON. The check
//! identifiers are public API, so a row may be added but never renamed.

use super::args::{only_flags, user_arg};
use super::doctor_host::{
    ir_node_verdict, ir_sensor_from_sysfs, is_permission_denied, pam_stack_verdict,
    udev_current_tags, user_can_write,
};
use super::models::sha256_file;
use anyhow::Result;
use std::path::{Path, PathBuf};

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

/// The `templates.camera` row: the cameras the templates are bound to
/// (from the daemon's ping) against the camera in the machine now. The
/// daemon refuses every attempt when they differ, so that is a failure
/// naming both and the way out (re-enrol), not a pass on a set that is
/// merely bound to something. Without a live identity (the doctor could
/// not probe the camera, which as a user it cannot) the row says the
/// binding went unchecked and why (H5).
fn camera_binding_row(
    bound: &[String],
    live: std::result::Result<&str, &str>,
) -> (&'static str, String) {
    match live {
        Err(why) => (
            "info",
            format!(
                "bound to {}; not checked against the camera in the machine ({})",
                bound.join(", "),
                why
            ),
        ),
        Ok(live) if bound.iter().any(|b| b == live) => (
            "pass",
            format!("bound to the camera in the machine ({})", live),
        ),
        Ok(live) => (
            "fail",
            format!(
                "bound to {} but the camera in the machine is {}: the daemon refuses every attempt; re-enrol",
                bound.join(", "),
                live
            ),
        ),
    }
}

/// The daemon rows from its answer to a ping: what each reply and each
/// way of failing to get one means, in one place a table can test (J21,
/// STORE-14). `live` is the identity of the camera in the machine, or why
/// the doctor could not read it.
fn daemon_checks(
    reply: std::result::Result<faceauth_daemon::auth::Outcome, DaemonErr>,
    user: &str,
    socket: &Path,
    live: std::result::Result<&str, &str>,
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
            bound,
            floors,
            load_error,
        }) => {
            push(
                "daemon.running",
                "pass",
                format!("faceauthd {} answering on {}", version, socket.display()),
            );
            if let Some(e) = load_error {
                // The store's own message may already say re-enrol.
                let advice = if e.contains("re-enrol") {
                    ""
                } else {
                    "; re-enrol"
                };
                push(
                    "templates.user",
                    "fail",
                    format!("templates for {} cannot be read: {}{}", user, e, advice),
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
                let (st, d) = camera_binding_row(&bound, live);
                push("templates.camera", st, d);
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
pub(super) fn doctor(rest: &[&str]) -> Result<()> {
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
    // The identity templates bind to, for the templates.camera row, or why
    // the doctor could not read it: the probe opens the sensor's control
    // node, which is root-only once the udev rule holds.
    let mut live: std::result::Result<String, String> =
        Err("the IR camera could not be probed".into());
    match faceauth_camera::ipu3::probe() {
        Ok(Some(g)) => match g.ir_sensor() {
            Some(ir) => {
                // A read of the control list, never an `Illuminator`, whose
                // drop would switch the strobe off under the daemon (J22).
                let strobe = faceauth_camera::has_strobe(&ir.subdev).unwrap_or(false);
                live = Ok(faceauth_daemon::capture::ipu3_identity_of(ir));
                push(
                    "camera.ir",
                    "pass",
                    format!(
                        "{} on {} ({}x{})",
                        ir.name,
                        ir.video.display(),
                        ir.width,
                        ir.height
                    ),
                );
                let (st, d) = illuminator_check(strobe, liveness_required);
                push("camera.illuminator", st, d);
                push(
                    "camera.rgb",
                    if g.colour_sensor().is_some() {
                        "pass"
                    } else {
                        "warn"
                    },
                    g.colour_sensor()
                        .map(|c| c.name.clone())
                        .unwrap_or_else(|| "no front colour sensor".into()),
                );
            }
            None => push(
                "camera.ir",
                "fail",
                "IPU3 graph found but no front IR sensor".into(),
            ),
        },
        Ok(None) => {
            live = Err("no IPU3 graph to read the camera's identity from".into());
            push(
                "camera.ir",
                "unknown",
                "no IPU3 graph; UVC IR cameras need ir_video in the config".into(),
            )
        }
        // The probe opens every sensor's control node and stops at the first
        // it cannot open. Once the udev rule holds, the IR sensor's node is
        // root-only and doctor runs as the user, so that is the expected
        // outcome, not a fault: the sensor is read from sysfs instead, which
        // needs no access to the node.
        Err(e) if is_permission_denied(&e) => {
            live = Err("the camera's node is root-only; run as root to check the binding".into());
            match &sysfs_ir {
                Some((node, name)) => push("camera.ir", "pass", format!("{} on /dev/{}, owned by root (expected once the udev rule is in place; run as root for the illuminator, RGB and template binding checks)", name, node)),
                None => push("camera.ir", "fail", format!("{} and no ov7251 IR sensor in sysfs", e)),
            }
        }
        Err(e) => {
            live = Err(format!("the camera probe failed: {}", e));
            push("camera.ir", "fail", e.to_string())
        }
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
    for c in daemon_checks(
        reply,
        &user,
        &socket,
        live.as_deref().map_err(|e| e.as_str()),
    ) {
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
            bound: vec!["ipu3:acpi:\\_SB_.PCI0.I2C3.CAM3".into()],
            floors: None,
            load_error: load_error.map(String::from),
        };
        let live: std::result::Result<&str, &str> = Ok("ipu3:acpi:\\_SB_.PCI0.I2C3.CAM3");
        assert_eq!(
            ids(&daemon_checks(Ok(pong(3, None)), "mike", socket, live)),
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
                socket,
                live
            )),
            vec![("daemon.running", "pass"), ("templates.user", "fail")],
            "an unreadable blob is not zero templates"
        );
        assert_eq!(
            ids(&daemon_checks(
                Err(DaemonErr::PermissionDenied),
                "mike",
                socket,
                live
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
                socket,
                live
            )),
            vec![("daemon.running", "pass")],
            "a busy daemon is a running daemon"
        );
        assert_eq!(
            ids(&daemon_checks(
                Err(DaemonErr::Other("connect: no such file".into())),
                "mike",
                socket,
                live
            )),
            vec![("daemon.running", "fail")]
        );
        assert_eq!(
            ids(&daemon_checks(Ok(Outcome::Noted), "mike", socket, live)),
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

    /// H5: the binding row compares the bound identities with the live
    /// camera's. A match passes; a different camera fails, naming both and
    /// re-enrolment, since the daemon refuses every attempt; no live
    /// identity is an unchecked row that says why, never a pass.
    #[test]
    fn the_binding_row_compares_bound_and_live_identities() {
        let old = "ipu3:acpi:\\_SB_.PCI0.I2C3.CAM3".to_string();
        let new = "ipu3:acpi:\\_SB_.PCI0.I2C2.CAM1";
        let (st, d) = camera_binding_row(std::slice::from_ref(&old), Ok(&old));
        assert_eq!(st, "pass", "{}", d);
        let (st, d) = camera_binding_row(std::slice::from_ref(&old), Ok(new));
        assert_eq!(st, "fail", "{}", d);
        assert!(
            d.contains(&old) && d.contains(new) && d.contains("re-enrol"),
            "the failure names both identities and the way out: {}",
            d
        );
        let (st, d) = camera_binding_row(&[old.clone(), new.to_string()], Ok(new));
        assert_eq!(
            st, "pass",
            "a set spanning cameras passes on one of them: {}",
            d
        );
        let (st, d) = camera_binding_row(
            std::slice::from_ref(&old),
            Err("the camera's node is root-only"),
        );
        assert_eq!(st, "info", "{}", d);
        assert!(
            d.contains("not checked") && d.contains("root-only") && d.contains(&old),
            "an unchecked row says so, why, and what the set is bound to: {}",
            d
        );
    }
}
