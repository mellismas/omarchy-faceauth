//! `faceauth doctor`: one row per check, as text or as JSON. The check
//! identifiers are public API, so a row may be added but never renamed.

use super::args::user_arg;
use super::doctor_host::{
    anchor_verdict, fprint_bus_policy_verdict, fprint_lines_verdict, fprint_row,
    fprint_service_verdict, fprint_stray_verdict, ir_capture_verdict, ir_lock_left_verdict,
    ir_node_verdict, ir_node_verdict_for, ir_sensor_from_sysfs, is_permission_denied,
    key_cancel_verdict, key_down_verdict, key_lane_verdict, key_lease_verdict, key_row,
    lock_helper_state, lock_helper_verdict, lock_state_verdict, node_denied, pam_stack_verdict,
    polkit_helper_verdict, readers_of_list, udev_current_tags, user_can_write, FprintFacts,
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

/// The sandbox of polkit's socket-activated helper, as systemd has it with
/// its drop-ins, or None when the unit is not there.
fn polkit_helper_props() -> Option<String> {
    let out = std::process::Command::new("/usr/bin/systemctl")
        .args([
            "show",
            "polkit-agent-helper@doctor.service",
            "-p",
            "LoadState",
            "-p",
            "DeviceAllow",
            "-p",
            "ProtectHome",
        ])
        .env_clear()
        .env("PATH", "/usr/bin")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.lines()
        .any(|l| l == "LoadState=loaded")
        .then_some(text)
}

/// The anchor chain for `user`'s only desktop: logind's controller, the
/// bus's pid behind it, and the one Hyprland socket whose listener is that
/// pid, connected without blocking.
fn own_anchor(user: &str) -> (&'static str, String) {
    let uid = nix::unistd::User::from_name(user)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw());
    let Some(uid) = uid else {
        return ("unknown", format!("no user {}", user));
    };
    let controller = faceauth_daemon::lockgate::controller_of(
        Path::new("/run/systemd"),
        uid,
        &faceauth_daemon::lockgate::Bind::OnlyDesktop,
    );
    let pid = controller.as_deref().and_then(|name| {
        let out = std::process::Command::new("/usr/bin/busctl")
            .args([
                "--system",
                "--timeout=2",
                "call",
                "org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus",
                "GetConnectionUnixProcessID",
                "s",
                name,
            ])
            .env_clear()
            .env("PATH", "/usr/bin")
            .output()
            .ok()?;
        faceauth_daemon::lockgate::parse_bus_pid(&out.stdout)
    });
    let matched = pid.map(|pid| {
        let runtime = PathBuf::from(format!("/run/user/{}", uid));
        let by = std::time::Instant::now() + std::time::Duration::from_secs(2);
        faceauth_daemon::lockgate::compositor_sockets(&runtime, uid, by)
            .ok()
            .is_some_and(|sockets| {
                faceauth_daemon::lockgate::compositor_stream(&sockets, pid, by).is_some()
            })
    });
    anchor_verdict(controller.as_deref(), pid, matched)
}

/// The lock state as this user's own session gives it: the one Hyprland
/// instance under `XDG_RUNTIME_DIR`, asked as `faceauth-lockstate` asks
/// it, and why not when there is none to ask.
fn own_lock_state() -> (faceauth_daemon::lockgate::LockState, String) {
    use faceauth_daemon::lockgate::LockState;
    let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) else {
        return (
            LockState::Unknown,
            "no XDG_RUNTIME_DIR in this shell".into(),
        );
    };
    let Some(instance) = faceauth_daemon::consent::hyprland_instance(&runtime) else {
        let n = std::fs::read_dir(runtime.join("hypr")).map_or(0, |d| d.count());
        let why = if n > 1 {
            format!(
                "{} Hyprland instance directories under {}/hypr",
                n,
                runtime.display()
            )
        } else {
            "no Hyprland instance to ask".into()
        };
        return (LockState::Unknown, why);
    };
    let out = std::process::Command::new("/usr/bin/timeout")
        .args(["4", "/usr/bin/hyprctl", "-j", "monitors"])
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("HYPRLAND_INSTANCE_SIGNATURE", &instance)
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let st = faceauth_daemon::consent::lock_state_from_monitors(&o.stdout);
            let why = if st == LockState::Unknown {
                "Hyprland's monitors answer has no lock field this reads".into()
            } else {
                String::new()
            };
            (st, why)
        }
        _ => (LockState::Unknown, "hyprctl gave no answer".into()),
    }
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

/// Why doctor has no live camera identity when the IR sensor's node is
/// root-only.
const ROOT_ONLY: &str = "the camera's node is root-only; run as root to check the binding";

/// The `camera.ir` detail for an IR sensor that sysfs names and whose node
/// is root-only: the expected state once the udev rule holds.
fn root_only_ir(node: &str, name: &str) -> String {
    format!("{} on /dev/{}, owned by root (expected once the udev rule is in place; run as root for the illuminator, RGB and template binding checks)", name, node)
}

/// The `camera.ir` row when the probe found the IPU3 graph without an IR
/// sensor in it, and why doctor then has no live identity. The probe skips
/// a sensor whose node it cannot open and keeps the rest, so for a user,
/// once the udev rule holds, the graph holds only the sensors the seat
/// user may open: an ov7251 in sysfs whose node this user is refused is
/// the expected state, reported as a probe refused on that node is. As
/// root, or with no ov7251 in sysfs, or with one this user may open, the
/// sensor is missing.
fn graph_without_ir(
    root: bool,
    sysfs_ir: Option<&(String, String)>,
    node_denied: bool,
) -> (&'static str, String, String) {
    match sysfs_ir {
        Some((node, name)) if !root && node_denied => {
            ("pass", root_only_ir(node, name), ROOT_ONLY.into())
        }
        _ => (
            "fail",
            "IPU3 graph found but no front IR sensor".into(),
            "the IR camera could not be probed".into(),
        ),
    }
}

/// The illuminator row: without a strobe control the liveness gate
/// cannot run, and with `liveness_required` (the default) that refuses
/// every attempt, which is a failure, not a warning (J21). Either way the
/// secure walk-away mode is not offered on that camera, and the row says so.
fn illuminator_check(strobe: bool, liveness_required: bool) -> (&'static str, String) {
    use faceauth_daemon::tier::{gate, Gate, Tier};
    let tier = Tier::of(strobe);
    match gate(tier, liveness_required) {
        Gate::Run => ("pass", format!("strobe controls present; {}", tier.describe())),
        Gate::Refuse => ("fail", format!("{}; liveness_required refuses every attempt, and the ov7251 driver needs kernel patch 0010, which exposes its strobe output", tier.describe())),
        Gate::Ungated => ("warn", format!("{}; liveness_required = false lets a print authenticate", tier.describe())),
    }
}

/// The `templates.camera` row: the cameras the templates are bound to
/// (from the daemon's ping) against the camera in the machine now. The
/// daemon refuses every attempt when they differ, so that is a failure
/// naming both and the way out (re-enroll), not a pass on a set that is
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
                "bound to {} but the camera in the machine is {}: the daemon refuses every attempt; re-enroll",
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
                // The store's own message may already say re-enroll.
                let advice = if e.contains("re-enroll") {
                    ""
                } else {
                    "; re-enroll"
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
        // enrollment; the template rows wait for a quiet moment.
        Ok(Outcome::Error { message }) if message == "busy" => {
            push(
                "daemon.running",
                "pass",
                format!("faceauthd answering on {}, busy with the camera (a request or an enrollment is running); run again for the template rows", socket.display()),
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
                    "no template(s) for {}: enroll from Setup > Security > Face",
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
    // The flags were checked with every command's (`check_args`).
    let json = rest.contains(&"--json");
    let user = user_arg(rest)?;
    let mut checks: Vec<Check> = Vec::new();
    let mut push = |id: &'static str, status: &'static str, detail: String| {
        checks.push(Check { id, status, detail })
    };

    // The daemon's config first: the models directory and the liveness
    // policy the rows below are judged against (J21). The socket is fixed.
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
    let live: std::result::Result<String, String>;
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
                        .unwrap_or_else(|| "no front color sensor".into()),
                );
            }
            None => {
                let root = nix::unistd::geteuid().is_root();
                let denied = !root
                    && sysfs_ir
                        .as_ref()
                        .is_some_and(|(node, _)| node_denied(&Path::new("/dev").join(node)));
                let (st, d, why) = graph_without_ir(root, sysfs_ir.as_ref(), denied);
                live = Err(why);
                push("camera.ir", st, d);
            }
        },
        Ok(None) => {
            live = Err("no IPU3 graph to read the camera's identity from".into());
            push(
                "camera.ir",
                "unknown",
                "no IPU3 graph; UVC IR cameras need ir_video in the config".into(),
            )
        }
        // The probe skips a sensor whose node it cannot open and fails only
        // when it opened none. Once the udev rule holds, the IR sensor's
        // node is root-only and doctor runs as the user, so a refusal is
        // the expected outcome, not a fault, when no other sensor opened
        // either: the sensor is read from sysfs instead, which needs no
        // access to the node. When the others did open, the graph comes
        // back without the IR sensor (`graph_without_ir`).
        Err(e) if is_permission_denied(&e) => {
            live = Err(ROOT_ONLY.into());
            match &sysfs_ir {
                Some((node, name)) => push("camera.ir", "pass", root_only_ir(node, name)),
                None => push(
                    "camera.ir",
                    "fail",
                    format!("{} and no ov7251 IR sensor in sysfs", e),
                ),
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
    // The IR capture node (fix round 11, Mike's ruling): locked by face
    // setup's rule when faceauth's own detection can say it carries IR
    // alone; otherwise left open, and why.
    if nix::unistd::geteuid().is_root() {
        let (st, d) = match crate::cam::ir_node_now() {
            Ok(node) => {
                let rule = faceauth_camera::irlock::rule_for(&node);
                let file = std::fs::read_to_string(faceauth_camera::irlock::RULE_FILE).ok();
                let dev = PathBuf::from("/dev").join(&node.node);
                let live = match std::fs::metadata(&dev) {
                    Ok(m) => {
                        use std::os::unix::fs::MetadataExt;
                        let tags = udev_current_tags(Path::new("/run/udev/data"), m.rdev());
                        ir_node_verdict_for(
                            "72-faceauth-ir-node.rules",
                            m.mode() & 0o777,
                            m.uid(),
                            m.gid(),
                            &tags,
                            false,
                        )
                    }
                    Err(e) => ("unknown", e.to_string()),
                };
                // What the node itself holds, for a lock that outlived its
                // rule (fix round 13, Codex 6, Opus nit).
                let left = {
                    use std::os::fd::AsFd;
                    faceauth_camera::irlock::open_node(&dev)
                        .and_then(|fd| faceauth_camera::irlock::node_access(fd.as_fd()))
                        .ok()
                        .map(|a| faceauth_camera::irlock::lock_left(&a, crate::cam::video_gid()))
                };
                ir_lock_left_verdict(&node.node, file.is_some(), left).unwrap_or_else(|| {
                    ir_capture_verdict(
                        rule.as_deref().map_err(String::as_str),
                        file.as_deref(),
                        &node.node,
                        live,
                    )
                })
            }
            Err(e) => ("info", format!("left open: {:#}", e)),
        };
        push("camera.ir_capture", st, d);
    } else {
        push(
            "camera.ir_capture",
            "unknown",
            "run as root: what the IR port carries is read from its sensor, whose node is root's"
                .into(),
        );
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
    // The stacks' key lines: while face is set up, every use of the key
    // goes through the daemon; a pam_u2f line beside face, a second key
    // line or a key line with a word the daemon does not mirror is named,
    // with the way out.
    let problems: Vec<String> = [
        ("sudo", "/etc/pam.d/sudo"),
        ("polkit-1", "/etc/pam.d/polkit-1"),
    ]
    .into_iter()
    .filter_map(|(name, path)| {
        let text = std::fs::read_to_string(path).ok()?;
        faceauth_daemon::consent::key_lines_problem(&text).map(|why| format!("{}: {}", name, why))
    })
    .collect();
    if problems.is_empty() {
        push(
            "pam.key_lines",
            "pass",
            "every key line goes through faceauthd (or face is not set up)".into(),
        );
    } else {
        push(
            "pam.key_lines",
            "fail",
            format!(
                "{}; edit the line to Omarchy's form or run Remove > Security > Fido2, then set face up again",
                problems.join("; ")
            ),
        );
    }
    // The lock screen's key lane: the daemon's key-unlock line alone.
    let (st, d) = key_lane_verdict(
        std::fs::read_to_string("/etc/pam.d/omarchy-lock-fido2")
            .ok()
            .as_deref(),
    );
    push("pam.lock_fido2", st, d);
    // The security key on the consent card, per lane, and on the lock
    // screen: offered, and with what it asks of the key, or why not.
    for (id, lane, what) in [
        ("key.sudo", "sudo", "the consent card"),
        ("key.polkit", "polkit", "the consent card"),
        ("key.unlock", "unlock", "the lock screen"),
    ] {
        let (st, d) = key_row(what, faceauth_daemon::consent::key_offer(&user, lane));
        push(id, st, d);
    }
    // The key line with faceauthd down: the check the module runs itself,
    // as stock pam_u2f would (fix round 10, item 6).
    let helpers: Vec<_> = ["/usr/lib/faceauth/faceauth-keycheck"]
        .into_iter()
        .map(|p| {
            let link = std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink());
            (p, lock_helper_state(Path::new(p)), link)
        })
        .collect();
    let (st, d) = key_down_verdict(&helpers);
    push("key.down", st, d);
    // The key's lease, which every key check holds while it runs (fix
    // round 11).
    let lease = std::fs::symlink_metadata(faceauth_daemon::lockgate::KEY_LEASE)
        .ok()
        .map(|m| {
            use std::os::unix::fs::MetadataExt;
            (m.file_type().is_file(), m.uid(), m.mode())
        });
    let (st, d) = key_lease_verdict(lease);
    push("key.lease", st, d);
    // The key check's cancel (round 19): the helper takes pam_u2f's call to
    // the key, so a stopped check cancels the key's wait.
    let fido_call =
        |p: &str| faceauth_daemon::elfsym::dynamic_symbol_of(Path::new(p), "fido_dev_get_assert");
    let (st, d) = key_cancel_verdict(
        fido_call("/usr/lib/faceauth/faceauth-keycheck"),
        fido_call("/usr/lib/security/pam_u2f.so"),
    );
    push("key.cancel", st, d);
    // Polkit's socket-activated helper, where polkit's key line runs with
    // faceauthd down: it needs pam-u2f's drop-in for the key.
    let (st, d) = polkit_helper_verdict(polkit_helper_props().as_deref());
    push("key.down_polkit", st, d);
    // The fingerprint (Mike's 10/12 ruling: it rides with the key): fprintd
    // itself, what the card and the lock screen offer, the lines faceauth
    // owns, and any line that reads the reader outside it.
    let facts = FprintFacts {
        fprintd: Path::new("/usr/lib/fprintd").exists(),
        libfprint: Path::new("/usr/lib/libfprint-2.so.2").exists(),
        pam_fprintd: Path::new("/usr/lib/security/pam_fprintd.so").exists(),
        readers: fprint_readers(&user),
        prints: faceauth_daemon::consent::prints_of(Path::new("/var/lib/fprint"), &user),
        user: &user,
    };
    let (st, d) = fprint_service_verdict(&facts);
    push("fprint.service", st, d);
    let (st, d) = fprint_row(faceauth_daemon::consent::fprint_offer(&user));
    push("fprint.unlock", st, d);
    let (st, d) = fprint_lines_verdict(
        std::fs::read_to_string("/etc/pam.d/omarchy-lock-fingerprint")
            .ok()
            .as_deref(),
    );
    let lock_lane_ours = st == "pass";
    push("pam.fprint_lines", st, d);
    let (strays, face, unknown) = fprint_strays(Path::new("/etc/pam.d"), lock_lane_ours);
    let (st, d) = fprint_stray_verdict(&strays, face, unknown.as_deref());
    push("fprint.stray", st, d);
    let (st, d) = fprint_bus_policy_verdict(
        Path::new("/usr/lib/fprintd").exists(),
        faceauth_daemon::consent::bus_policy_state(Path::new("/usr/share/dbus-1/system.d")),
    );
    push("fprint.bus_policy", st, d);
    // The lock state every key line reads (round 6, Opus N1).
    let desktop = faceauth_daemon::lockgate::graphical_sessions(Path::new("/run/systemd"));
    let (state, why) = if nix::unistd::geteuid().is_root() {
        (
            faceauth_daemon::consent::anchored_lock_state(
                &user,
                &faceauth_daemon::lockgate::Bind::OnlyDesktop,
            ),
            String::new(),
        )
    } else {
        own_lock_state()
    };
    let (st, d) = lock_state_verdict(state, desktop, &why);
    push("lock.state", st, d);
    // The compositor anchor the daemon's anchored question uses (round 7,
    // A).
    let (st, d) = own_anchor(&user);
    push("lock.anchor", st, d);
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
    // The walk-away lock's helper, which the daemon runs by a fixed path:
    // a package that installs it anywhere else leaves the watch unable to
    // lock, and nothing else would say so.
    let helper = faceauth_daemon::presence::LOCK_HELPER;
    let (st, d) = match lock_helper_state(Path::new(helper)) {
        Ok((exists, is_file, mode, uid)) => lock_helper_verdict(mode, uid, is_file, exists),
        Err(e) => ("unknown", e.to_string()),
    };
    push("presence.lock_helper", st, format!("{}: {}", helper, d));

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

/// The readers fprintd sees, from `fprintd-list` in the C locale under a
/// bound, or None when it is not installed or did not answer.
fn fprint_readers(user: &str) -> Option<usize> {
    if !Path::new("/usr/bin/fprintd-list").exists() {
        return None;
    }
    let out = std::process::Command::new("/usr/bin/timeout")
        .args(["-k", "1", "10", "/usr/bin/fprintd-list", user])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    readers_of_list(&text)
}

/// The PAM files in `dir` with an active pam_fprintd line, but for the lock
/// screen's stack when it is faceauth's own (`lock_lane_ours`), each with
/// whether sudo's or polkit's stack reaches it, through what they include
/// as the offer follows it (`consent::fprintd_reached`); whether face is
/// set up on either of those (a consent line); and why their includes
/// could not be followed, if they could not. At most 256 files, each read
/// to 64 KiB.
fn fprint_strays(dir: &Path, lock_lane_ours: bool) -> (Vec<(String, bool)>, bool, Option<String>) {
    use std::io::Read;
    let mut strays = Vec::new();
    let mut face = false;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return (strays, face, None);
    };
    let reached = faceauth_daemon::consent::fprintd_reached(dir, &["sudo", "polkit-1"]);
    let (reached, unknown) = match reached {
        Ok(v) => (v, None),
        Err(why) => (Vec::new(), Some(why)),
    };
    let mut paths: Vec<_> = entries.flatten().take(256).map(|e| e.path()).collect();
    paths.sort();
    for p in paths {
        if !p.is_file() {
            continue;
        }
        let name = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut text = String::new();
        if std::fs::File::open(&p)
            .and_then(|f| f.take(64 * 1024).read_to_string(&mut text))
            .is_err()
        {
            continue;
        }
        let elevation = matches!(name.as_str(), "sudo" | "polkit-1");
        if elevation
            && text
                .lines()
                .map(|l| l.split('#').next().unwrap_or(""))
                .any(|l| {
                    l.contains("pam_faceauth.so") && l.split_whitespace().any(|w| w == "consent")
                })
        {
            face = true;
        }
        if name == "omarchy-lock-fingerprint" && lock_lane_ours {
            continue;
        }
        if faceauth_daemon::consent::fprintd_lines(&text)
            .next()
            .is_some()
        {
            let path = p.display().to_string();
            let theirs = elevation || reached.contains(&path);
            strays.push((path, theirs));
        }
    }
    (strays, face, unknown)
}

#[cfg(test)]
mod doctor_tests {
    use super::*;

    /// M1: `fprint.stray` follows what sudo and polkit include, as the
    /// offer does (`consent::fprintd_reached`), so a pam_fprintd line in
    /// system-auth is theirs; an include it cannot follow is the offer's
    /// reason too.
    #[test]
    fn the_stray_scan_follows_what_sudo_and_polkit_include() {
        let dir =
            std::env::temp_dir().join(format!("faceauth-doctor-include-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("sudo"),
            "auth [success=done default=ignore] pam_faceauth.so consent\nauth include system-auth\n",
        )
        .unwrap();
        std::fs::write(
            dir.join("system-auth"),
            "auth sufficient pam_fprintd.so\nauth required pam_unix.so\n",
        )
        .unwrap();
        let (strays, face, unknown) = fprint_strays(&dir, true);
        assert!(face);
        assert_eq!(unknown, None);
        assert_eq!(
            strays,
            vec![(dir.join("system-auth").display().to_string(), true)]
        );
        std::fs::write(dir.join("polkit-1"), "auth include nowhere\n").unwrap();
        let (_, _, unknown) = fprint_strays(&dir, true);
        assert!(unknown.is_some_and(|w| w.contains("nowhere")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `fprint.stray` reads every PAM file: sudo's and polkit's lines are
    /// marked as theirs, the lock screen's stack is skipped only while it
    /// is faceauth's own, a commented line reads nothing, and face counts
    /// as set up by a consent line on either elevation stack.
    #[test]
    fn the_stray_scan_names_every_file_faceauth_does_not_own() {
        let dir = std::env::temp_dir().join(format!("faceauth-doctor-pamd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("sudo"),
            "auth sufficient pam_fprintd.so\nauth [success=done default=ignore] pam_faceauth.so consent\n",
        )
        .unwrap();
        std::fs::write(dir.join("polkit-1"), "#auth sufficient pam_fprintd.so\n").unwrap();
        std::fs::write(dir.join("sddm"), "auth sufficient pam_fprintd.so\n").unwrap();
        std::fs::write(
            dir.join("omarchy-lock-fingerprint"),
            "auth [success=done ignore=ignore module_unknown=ignore default=die] pam_faceauth.so fprint-unlock\nauth required pam_fprintd.so\n",
        )
        .unwrap();
        let (strays, face, _) = fprint_strays(&dir, true);
        assert!(face);
        let sudo = dir.join("sudo").display().to_string();
        let sddm = dir.join("sddm").display().to_string();
        assert_eq!(strays, vec![(sddm.clone(), false), (sudo.clone(), true)]);
        let (strays, _, _) = fprint_strays(&dir, false);
        assert_eq!(
            strays.len(),
            3,
            "a lock stack not in faceauth's form is a stray"
        );
        std::fs::write(dir.join("sudo"), "auth sufficient pam_fprintd.so\n").unwrap();
        let (_, face, _) = fprint_strays(&dir, true);
        assert!(!face, "no consent line: face is not set up there");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A user's probe skips the root-only IR node and returns the sensors
    /// the seat user may open: with the ov7251 in sysfs and its node
    /// refused, that is the expected state, not a missing sensor. As root,
    /// with no ov7251 in sysfs, or with a node the user may open, a graph
    /// without the IR sensor still fails.
    #[test]
    fn a_users_graph_without_the_root_only_ir_sensor_passes() {
        let ir = ("v4l-subdev8".to_string(), "ov7251 3-0060".to_string());
        let (st, d, why) = graph_without_ir(false, Some(&ir), true);
        assert_eq!(st, "pass");
        assert_eq!(d, root_only_ir("v4l-subdev8", "ov7251 3-0060"));
        assert_eq!(why, ROOT_ONLY);
        for (root, sysfs, denied) in [
            (true, Some(&ir), false),
            (true, Some(&ir), true),
            (false, None, false),
            (false, Some(&ir), false),
        ] {
            let (st, d, _) = graph_without_ir(root, sysfs, denied);
            assert_eq!(
                (st, d.as_str()),
                ("fail", "IPU3 graph found but no front IR sensor"),
                "root {} sysfs {:?} denied {}",
                root,
                sysfs,
                denied
            );
        }
    }

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
            ids(&daemon_checks(Ok(pong(3, None)), "alice", socket, live)),
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
                "alice",
                socket,
                live
            )),
            vec![("daemon.running", "pass"), ("templates.user", "fail")],
            "an unreadable blob is not zero templates"
        );
        assert_eq!(
            ids(&daemon_checks(
                Err(DaemonErr::PermissionDenied),
                "alice",
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
                "alice",
                socket,
                live
            )),
            vec![("daemon.running", "pass")],
            "a busy daemon is a running daemon"
        );
        assert_eq!(
            ids(&daemon_checks(
                Err(DaemonErr::Other("connect: no such file".into())),
                "alice",
                socket,
                live
            )),
            vec![("daemon.running", "fail")]
        );
        assert_eq!(
            ids(&daemon_checks(Ok(Outcome::Noted), "alice", socket, live)),
            vec![("daemon.running", "warn")]
        );
        assert_eq!(illuminator_check(true, true).0, "pass");
        assert_eq!(
            illuminator_check(false, true).0,
            "fail",
            "no strobe under liveness_required refuses every attempt"
        );
        assert_eq!(illuminator_check(false, false).0, "warn");
        // Without the strobe the secure walk-away mode is not offered, and
        // the row says so whichever way liveness_required is set.
        for required in [true, false] {
            let (_, detail) = illuminator_check(false, required);
            assert!(detail.contains("secure walk-away mode"), "{}", detail);
        }
        assert!(!illuminator_check(true, true).1.contains("secure"));
    }

    /// H5: the binding row compares the bound identities with the live
    /// camera's. A match passes; a different camera fails, naming both and
    /// re-enrollment, since the daemon refuses every attempt; no live
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
            d.contains(&old) && d.contains(new) && d.contains("re-enroll"),
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
