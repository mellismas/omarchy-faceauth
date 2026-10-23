//! The fingerprint check against a real fprintd, unprivileged: a private
//! system bus of the test's own (`dbus-daemon`), python-dbusmock's polkitd
//! allowing every action, `fprintd -t` from an extracted prefix with
//! libfprint's `virtual_device` driver, and a print enrolled through it.
//! The check is the one the helper runs (`pamcheck::check_fprint` on the
//! shipped stack's words, pam_fprintd named by its path in the prefix),
//! each in a child process of this test, so one can be stopped mid-verify:
//! a matching scan is a match, three wrong ones are no match, a second
//! claim while one is held finds the reader unavailable without reaching
//! it, and a SIGTERM mid-verify frees the reader for the next claim.
//!
//! The bus's default context is a copy of the system bus's own
//! (`/usr/share/dbus-1/system.conf`), which lets any connection send a
//! signal to any other. pam_fprintd takes fprintd's verify result from a
//! signal it matches by fprintd's well-known name, and sd-bus does not
//! hold a unicast signal to the name's owner, so on that policy a
//! connection that does not own fprintd's name can forge a match. The
//! package's bus policy (`packaging/system.d/faceauth-fprint.conf`) lets
//! the device's signals reach a receiver only from the name's owner. Each
//! test forges one before a real scan: without the policy it approves (the
//! control, so the test can see the attack); with it, it approves nothing,
//! also beside a user-context policy that allows every signal, and the
//! real scan still matches.
//!
//! It runs only with `FACEAUTH_FPRINT_PREFIX` naming the prefix
//! (docs/DEVELOPMENT.md says how to make one, with nothing installed on the
//! system); without it, or without `dbus-daemon` or the system python's
//! `dbus` module, it says so and passes, so the suites stay green
//! elsewhere.

use faceauth_daemon::consent::{fprint_exit_code, FPRINT_MATCHED};
use std::io::{BufRead, BufReader};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

const PAM_TEXT_INFO: i32 = 4;

/// The system bus's own config, whose default context the private bus copies.
const SYSTEM_CONF: &str = "/usr/share/dbus-1/system.conf";

/// The children the test started, stopped and reaped when it ends.
struct Fixture {
    dir: PathBuf,
    children: Vec<Child>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for c in self.children.iter_mut().rev() {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn wait_for(what: &str, within: Duration, cond: impl Fn() -> bool) {
    let by = Instant::now() + within;
    while Instant::now() < by {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{} did not happen within {:?}", what, within);
}

/// Why the test cannot run here, if it cannot.
fn missing(prefix: Option<&Path>) -> Option<String> {
    let Some(p) = prefix else {
        return Some("FACEAUTH_FPRINT_PREFIX is not set".into());
    };
    for f in [
        "usr/lib/fprintd",
        "usr/bin/fprintd-enroll",
        "usr/lib/security/pam_fprintd.so",
        "usr/lib/libfprint-2.so.2",
        "usr/lib/python3.14/site-packages/dbusmock/templates/polkitd.py",
    ] {
        if !p.join(f).exists() {
            return Some(format!("{} has no {}", p.display(), f));
        }
    }
    if !Path::new("/usr/bin/dbus-daemon").exists() {
        return Some("/usr/bin/dbus-daemon is not installed".into());
    }
    if system_default_policy().is_none() {
        return Some(format!("{} has no default policy to copy", SYSTEM_CONF));
    }
    let dbus = Command::new("/usr/bin/python3")
        .args(["-c", "import dbus"])
        .status();
    if !dbus.is_ok_and(|s| s.success()) {
        return Some("the system python has no dbus module (python-dbus)".into());
    }
    None
}

/// The system bus's own default context, as `/usr/share/dbus-1/system.conf`
/// has it, or None when it is not there.
fn system_default_policy() -> Option<String> {
    let text = std::fs::read_to_string(SYSTEM_CONF).ok()?;
    let at = text.find("<policy context=\"default\">")?;
    let len = text[at..].find("</policy>")? + "</policy>".len();
    Some(text[at..at + len].to_string())
}

/// What the private bus carries beyond the system's default context.
#[derive(Clone, Copy)]
struct Policy {
    /// The package's bus policy, included from the tree.
    shipped: bool,
    /// A user-context policy that allows every signal for the test's own
    /// user, standing in for a root policy another package might ship:
    /// the bus applies user contexts after the default one.
    user_allows_signals: bool,
}

/// The private system bus at `sock`: the system's default context, the
/// holes fprintd's and polkit's own files punch (here for the test's user,
/// who runs both), and `policy`'s additions.
fn bus_config(sock: &Path, default: &str, user: &str, policy: Policy) -> String {
    let shipped = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../packaging/system.d/faceauth-fprint.conf"
    );
    format!(
        r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>system</type>
  <listen>unix:path={sock}</listen>
  <auth>EXTERNAL</auth>
  {default}
  <policy context="default">
    <allow own="net.reactivated.Fprint"/>
    <allow own="org.freedesktop.PolicyKit1"/>
    <allow send_destination="net.reactivated.Fprint"/>
    <allow send_destination="org.freedesktop.PolicyKit1"/>
  </policy>
  {user_policy}
  {include}
</busconfig>
"#,
        sock = sock.display(),
        user_policy = if policy.user_allows_signals {
            format!(
                r#"<policy user="{}"><allow receive_type="signal"/><allow receive_interface="net.reactivated.Fprint.Device"/></policy>"#,
                user
            )
        } else {
            String::new()
        },
        include = if policy.shipped {
            format!(r#"<include ignore_missing="yes">{}</include>"#, shipped)
        } else {
            String::new()
        },
    )
}

/// The forging connection: the test's own Python, on the private bus.
const FORGE: &str = r#"
import dbus, dbus.lowlevel
b = dbus.SystemBus()
me = b.get_unique_name()
d = b.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
owner = d.GetNameOwner('net.reactivated.Fprint', dbus_interface='org.freedesktop.DBus')
m = b.get_object('net.reactivated.Fprint', '/net/reactivated/Fprint/Manager')
dev = m.GetDevices(dbus_interface='net.reactivated.Fprint.Manager')[0]
for n in d.ListNames(dbus_interface='org.freedesktop.DBus'):
    if n.startswith(':') and n not in (me, owner):
        s = dbus.lowlevel.SignalMessage(dev, 'net.reactivated.Fprint.Device', 'VerifyStatus')
        s.set_destination(n)
        s.append(dbus.String('verify-match'), dbus.Boolean(True))
        b.send_message(s)
b.flush()
"#;

/// A forged verify result: a connection that does not own fprintd's name
/// sends each other connection on the bus a unicast `VerifyStatus` saying
/// the finger matched, on the reader's own path.
fn forge(bus: &str) {
    let ok = Command::new("/usr/bin/python3")
        .args(["-I", "-c", FORGE])
        .env("DBUS_SYSTEM_BUS_ADDRESS", bus)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success());
    assert!(ok, "the forged signal was sent");
}

/// One command to the virtual reader, on a connection of its own, as the
/// driver takes them.
fn reader(vdev: &Path, cmd: &str) {
    use std::io::Write;
    let mut s = UnixStream::connect(vdev).expect("the virtual reader's socket");
    s.write_all(cmd.as_bytes()).unwrap();
}

/// A check running in a child of this test, its lines (`fafp style N`,
/// `fafp rc N`) on a channel.
struct Check {
    child: Child,
    lines: Receiver<String>,
}

impl Check {
    fn start(bus: &str, confdir: &Path, user: &str) -> Check {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "fprint_check_child",
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("DBUS_SYSTEM_BUS_ADDRESS", bus)
            .env("FAFP_CONFDIR", confdir)
            .env("FAFP_USER", user)
            .env("LC_ALL", "C")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let out = child.stdout.take().unwrap();
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            // libtest writes the test's name and then its output on the
            // same line, so a line is read from its marker on.
            for l in BufReader::new(out).lines().map_while(Result::ok) {
                if let Some(at) = l.find("fafp ") {
                    if tx.send(l[at + 5..].to_string()).is_err() {
                        break;
                    }
                }
            }
        });
        Check { child, lines }
    }

    /// The next line within `within`, or None.
    fn next(&self, within: Duration) -> Option<String> {
        self.lines.recv_timeout(within).ok()
    }

    /// Lines until the answer, which is returned with the styles seen.
    fn answer(&mut self, within: Duration) -> (Option<i32>, Vec<i32>) {
        let by = Instant::now() + within;
        let mut styles = Vec::new();
        while let Some(l) = self.next(by.saturating_duration_since(Instant::now())) {
            if let Some(s) = l.strip_prefix("style ") {
                styles.push(s.parse().unwrap());
            } else if let Some(rc) = l.strip_prefix("rc ") {
                let _ = self.child.wait();
                return (rc.parse().ok(), styles);
            }
        }
        (None, styles)
    }

    /// Wait for pam_fprintd's prompt: its claim landed and it asks.
    fn prompted(&self, within: Duration) -> bool {
        let by = Instant::now() + within;
        while let Some(l) = self.next(by.saturating_duration_since(Instant::now())) {
            if l == format!("style {}", PAM_TEXT_INFO) {
                return true;
            }
        }
        false
    }
}

/// The child's half: one check through the stack in `FAFP_CONFDIR`, its
/// message styles and answer on stdout. Run by the test above alone; with
/// no `FAFP_CONFDIR` it does nothing.
#[test]
#[ignore = "run by fprint_against_a_private_fprintd as its child"]
fn fprint_check_child() {
    let (Ok(confdir), Ok(user)) = (std::env::var("FAFP_CONFDIR"), std::env::var("FAFP_USER"))
    else {
        return;
    };
    let rc =
        faceauth_daemon::pamcheck::check_fprint("faceauth-fprint", &user, &confdir, &mut |s| {
            println!("fafp style {}", s);
        });
    println!("fafp rc {}", rc.unwrap_or(-1));
}

/// One private bus, polkit mock, fprintd and enrolled finger, under
/// `policy`; None, with the reason printed, when the test cannot run here.
struct Bed {
    fx: Fixture,
    bus: String,
    vdev: PathBuf,
    confdir: PathBuf,
    user: String,
}

fn up(name: &str, tag: &str, policy: Policy) -> Option<Bed> {
    let prefix = std::env::var_os("FACEAUTH_FPRINT_PREFIX").map(PathBuf::from);
    if let Some(why) = missing(prefix.as_deref()) {
        println!("SKIP {}: {}", name, why);
        return None;
    }
    let prefix = prefix.unwrap();
    let user = nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()
        .map(|u| u.name)
        .expect("the test's own user");
    // A short tag, not the test's name: the bus's socket path must stay
    // under the 108 bytes a Unix socket address holds.
    let dir = std::env::temp_dir().join(format!("fa-fp-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("state")).unwrap();
    std::fs::create_dir_all(dir.join("run")).unwrap();
    std::fs::create_dir_all(dir.join("pam.d")).unwrap();
    let mut fx = Fixture {
        dir: dir.clone(),
        children: Vec::new(),
    };
    let sock = dir.join("bus");
    let vdev = dir.join("vdev");
    let default = system_default_policy().unwrap();
    std::fs::write(
        dir.join("bus.conf"),
        bus_config(&sock, &default, &user, policy),
    )
    .unwrap();
    fx.children.push(
        Command::new("/usr/bin/dbus-daemon")
            .arg(format!("--config-file={}", dir.join("bus.conf").display()))
            .args(["--nofork", "--nopidfile"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    wait_for("the private bus", Duration::from_secs(5), || sock.exists());
    let bus = format!("unix:path={}", sock.display());
    let site = prefix.join("usr/lib/python3.14/site-packages");
    fx.children.push(
        Command::new("/usr/bin/python3")
            .args(["-m", "dbusmock", "--system", "--template", "polkitd"])
            .env("DBUS_SYSTEM_BUS_ADDRESS", &bus)
            .env("PYTHONPATH", &site)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let allow = || {
        Command::new("/usr/bin/python3")
            .args([
                "-c",
                "import dbus; o=dbus.SystemBus().get_object('org.freedesktop.PolicyKit1','/org/freedesktop/PolicyKit1/Authority'); o.AllowUnknown(True, dbus_interface='org.freedesktop.DBus.Mock')",
            ])
            .env("DBUS_SYSTEM_BUS_ADDRESS", &bus)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    wait_for("the polkit mock", Duration::from_secs(10), allow);
    let libs = prefix.join("usr/lib");
    fx.children.push(
        Command::new(prefix.join("usr/lib/fprintd"))
            .arg("-t")
            .env("DBUS_SYSTEM_BUS_ADDRESS", &bus)
            .env("FP_DRIVERS_ALLOWLIST", "virtual_device")
            .env("FP_VIRTUAL_DEVICE", &vdev)
            .env("STATE_DIRECTORY", dir.join("state"))
            .env("RUNTIME_DIRECTORY", dir.join("run"))
            .env("LD_LIBRARY_PATH", &libs)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let owned = || {
        Command::new("/usr/bin/python3")
            .args([
                "-c",
                "import dbus, sys; sys.exit(0 if dbus.SystemBus().name_has_owner('net.reactivated.Fprint') else 1)",
            ])
            .env("DBUS_SYSTEM_BUS_ADDRESS", &bus)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    };
    wait_for("fprintd on the private bus", Duration::from_secs(15), owned);
    // Enroll one finger through the virtual reader, as `sudo
    // fprintd-enroll` does for real (here as the user, on the private bus).
    let mut enroll = Command::new(prefix.join("usr/bin/fprintd-enroll"))
        .args(["-f", "right-index-finger", &user])
        .env("DBUS_SYSTEM_BUS_ADDRESS", &bus)
        .env("LD_LIBRARY_PATH", &libs)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    wait_for("the reader's socket", Duration::from_secs(15), || {
        vdev.exists()
    });
    let by = Instant::now() + Duration::from_secs(20);
    let enrolled = loop {
        if let Some(st) = enroll.try_wait().unwrap() {
            break st.success();
        }
        assert!(Instant::now() < by, "enrollment did not end");
        reader(&vdev, "SCAN finger-1");
        std::thread::sleep(Duration::from_millis(300));
    };
    assert!(enrolled, "the virtual reader enrolled the finger");
    assert_eq!(
        faceauth_daemon::consent::prints_of(&dir.join("state"), &user),
        Ok(1),
        "the offer's count reads fprintd's own layout"
    );
    // The shipped stack, with pam_fprintd named by its path in the prefix.
    let stack = include_str!("../../packaging/pam.d/faceauth-fprint").replace(
        " pam_fprintd.so ",
        &format!(
            " {} ",
            prefix.join("usr/lib/security/pam_fprintd.so").display()
        ),
    );
    std::fs::write(dir.join("pam.d/faceauth-fprint"), stack).unwrap();
    Some(Bed {
        fx,
        bus,
        vdev,
        confdir: dir.join("pam.d"),
        user,
    })
}

const STEP: Duration = Duration::from_secs(20);

/// How long a forged signal is given to land before the test reads the
/// check's silence as a refusal.
const FORGERY_LANDS: Duration = Duration::from_secs(2);

/// A check asking for a finger takes a forged match: `Some(rc)` when the
/// check answered without a scan, None when it is still asking.
fn forged_answer(bed: &Bed, c: &mut Check) -> Option<i32> {
    forge(&bed.bus);
    let by = Instant::now() + FORGERY_LANDS;
    while let Some(l) = c.next(by.saturating_duration_since(Instant::now())) {
        if let Some(rc) = l.strip_prefix("rc ") {
            return rc.parse().ok();
        }
    }
    None
}

#[test]
fn fprint_against_a_private_fprintd() {
    let Some(bed) = up(
        "fprint_against_a_private_fprintd",
        "main",
        Policy {
            shipped: true,
            user_allows_signals: false,
        },
    ) else {
        return;
    };
    let (bus, vdev, confdir, user) = (&bed.bus, &bed.vdev, &bed.confdir, &bed.user);

    // A forged match approves nothing under the shipped policy, and a
    // matching finger then is a match.
    let mut c = Check::start(bus, confdir, user);
    assert!(c.prompted(STEP), "the check asks for a finger");
    assert_eq!(
        forged_answer(&bed, &mut c),
        None,
        "a forged match from a connection that is not fprintd answered the check"
    );
    reader(vdev, "SCAN finger-1");
    let (rc, _) = c.answer(STEP);
    assert_eq!(rc.map(|r| fprint_exit_code(Some(r))), Some(FPRINT_MATCHED));

    // Three wrong fingers spend the stack's tries: pam_fprintd's
    // PAM_MAXTRIES, which the helper answers as no match.
    const PAM_MAXTRIES: i32 = 11;
    let mut c = Check::start(bus, confdir, user);
    for _ in 0..faceauth_daemon::consent::FPRINT_TRIES {
        assert!(c.prompted(STEP), "each try asks for a finger");
        reader(vdev, "SCAN finger-2");
    }
    let (rc, _) = c.answer(STEP);
    assert_eq!(rc, Some(PAM_MAXTRIES));
    assert_eq!(fprint_exit_code(rc), 1, "no match");

    // A check holds the reader: a second claim answers unavailable at
    // once, never having asked for a finger (the card's "reader busy").
    let mut held = Check::start(bus, confdir, user);
    assert!(held.prompted(STEP));
    let mut busy = Check::start(bus, confdir, user);
    let (rc, styles) = busy.answer(STEP);
    assert_eq!(
        rc.map(|r| fprint_exit_code(Some(r))),
        Some(3),
        "unavailable"
    );
    assert!(
        !styles.contains(&PAM_TEXT_INFO),
        "it never reached the reader"
    );

    // SIGTERM mid-verify ends the check, and fprintd frees the reader for
    // the next claim, which then matches.
    let pid = held.child.id() as i32;
    // SAFETY: a signal to this test's own child, which it has not reaped
    // yet, so the pid is still that child's.
    let sent = unsafe { libc::kill(pid, libc::SIGTERM) };
    assert_eq!(sent, 0);
    let st = held.child.wait().unwrap();
    assert!(!st.success(), "the stopped check is no answer");
    let mut next = Check::start(bus, confdir, user);
    assert!(
        next.prompted(STEP),
        "the reader was freed for the next claim"
    );
    reader(vdev, "SCAN finger-1");
    let (rc, _) = next.answer(STEP);
    assert_eq!(rc.map(|r| fprint_exit_code(Some(r))), Some(FPRINT_MATCHED));
}

/// The control: on the system's default policy without the package's file,
/// the forged match answers the check as a match with no finger on the
/// reader, so the test above can see the attack it holds off.
#[test]
fn a_forged_match_approves_without_the_shipped_policy() {
    let Some(bed) = up(
        "a_forged_match_approves_without_the_shipped_policy",
        "control",
        Policy {
            shipped: false,
            user_allows_signals: false,
        },
    ) else {
        return;
    };
    let mut c = Check::start(&bed.bus, &bed.confdir, &bed.user);
    assert!(c.prompted(STEP), "the check asks for a finger");
    assert_eq!(
        forged_answer(&bed, &mut c).map(|r| fprint_exit_code(Some(r))),
        Some(FPRINT_MATCHED),
        "the forgery is seen: without the policy it reads as a match"
    );
}

/// The package's rules hold beside a user-context policy that allows every
/// signal: the bus applies user and group contexts after the default
/// one, so rules there could be undone by another package's root policy,
/// and the shipped file's are mandatory, which the bus applies last.
#[test]
fn the_shipped_policy_holds_beside_a_policy_that_allows_every_signal() {
    let Some(bed) = up(
        "the_shipped_policy_holds_beside_a_policy_that_allows_every_signal",
        "override",
        Policy {
            shipped: true,
            user_allows_signals: true,
        },
    ) else {
        return;
    };
    let mut c = Check::start(&bed.bus, &bed.confdir, &bed.user);
    assert!(c.prompted(STEP), "the check asks for a finger");
    assert_eq!(
        forged_answer(&bed, &mut c),
        None,
        "a user-context allow let the forged match through"
    );
    reader(&bed.vdev, "SCAN finger-1");
    let (rc, _) = c.answer(STEP);
    assert_eq!(rc.map(|r| fprint_exit_code(Some(r))), Some(FPRINT_MATCHED));
    drop(bed.fx);
}
