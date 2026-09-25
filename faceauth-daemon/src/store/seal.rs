//! Sealing a template file to this machine's TPM through `systemd-creds`,
//! scoped to root. A failed unseal is classified, so enrolment sets a blob
//! aside only when the failure says the blob itself is unreadable.

#[cfg(test)]
use super::files::Store;
#[cfg(test)]
use super::templates::UserTemplates;
#[cfg(test)]
use super::test_support::{temp, tmpl, CAM};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub(super) const SYSTEMD_CREDS: &str = "/usr/bin/systemd-creds";
const TIMEOUT: &str = "/usr/bin/timeout";

/// How templates rest on disk.
#[derive(Clone, Debug, PartialEq)]
pub enum Sealing {
    /// Sealed to this machine's TPM 2.0 through `systemd-creds`.
    Tpm,
    /// Plaintext, root 0600, for the stated reason.
    Plain(String),
}

impl Sealing {
    /// Can this machine seal? A TPM device, `systemd-creds`, and one sealed
    /// round trip of a probe string through both.
    pub fn detect() -> Sealing {
        if !Path::new("/dev/tpmrm0").exists() {
            return Sealing::Plain("no TPM device (/dev/tpmrm0)".into());
        }
        if !Path::new(SYSTEMD_CREDS).exists() {
            return Sealing::Plain(format!("{} not installed", SYSTEMD_CREDS));
        }
        if !Path::new(TIMEOUT).exists() {
            return Sealing::Plain(format!("{} not installed", TIMEOUT));
        }
        match seal(Path::new(SYSTEMD_CREDS), "faceauth-probe", b"probe")
            .and_then(|blob| unseal(Path::new(SYSTEMD_CREDS), "faceauth-probe", &blob))
        {
            Ok(back) if back == b"probe" => Sealing::Tpm,
            Ok(_) => Sealing::Plain("TPM probe round trip returned different bytes".into()),
            Err(e) => Sealing::Plain(format!("TPM probe failed: {}", e)),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Sealing::Tpm => "sealed to the TPM, root-only (systemd-creds host+tpm2, uid 0, name-bound, no PCR policy)".into(),
            Sealing::Plain(why) => format!("plaintext at rest (root 0600): {}", why),
        }
    }
}

fn creds(bin: &Path, args: &[&str], stdin_bytes: &[u8]) -> Result<Vec<u8>> {
    // `-k 5`: a TPM call that ignores SIGTERM is killed five seconds later,
    // so the daemon never hangs on the credential service.
    let mut child = Command::new(TIMEOUT)
        .args(["-k", "5", "30"])
        .arg(bin)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {} {}", TIMEOUT, SYSTEMD_CREDS))?;
    // A write error (the child closed its end) is reported after the child is
    // reaped, never instead of it: no zombies against the unit's TasksMax.
    let write = child
        .stdin
        .take()
        .map(|mut si| si.write_all(stdin_bytes))
        .unwrap_or(Ok(()));
    let out = child.wait_with_output()?;
    if let Err(e) = write {
        if !out.status.success() {
            return Err(creds_failure(args, &out));
        }
        return Err(e).context("write to systemd-creds");
    }
    if !out.status.success() {
        return Err(creds_failure(args, &out));
    }
    Ok(out.stdout)
}

/// The error for a credential tool that ran and failed, carrying whether
/// the failure is the tool's verdict on the blob or a passing condition.
fn creds_failure(args: &[&str], out: &std::process::Output) -> anyhow::Error {
    let stderr = String::from_utf8_lossy(&out.stderr);
    let kind = classify_creds_failure(out.status.code(), &stderr);
    anyhow::anyhow!(
        "systemd-creds {}: {} {}",
        args.first().copied().unwrap_or(""),
        out.status,
        stderr.trim()
    )
    .context(kind)
}

/// Whether a failed unseal says anything about the blob. Enrolment sets a
/// blob aside and starts fresh only on a definitive failure; a passing
/// condition (the TPM busy or unreachable, the tool timed out or could not
/// start, the sandbox refusing the device) must not discard a good set of
/// templates and the calibration in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsealFailure {
    /// The tool ran, read the blob, and refused it: corrupt, sealed under
    /// another key, or bound to another name.
    Definitive,
    /// The tool did not get as far as a verdict.
    Transient,
}

impl std::fmt::Display for UnsealFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            UnsealFailure::Definitive => "the credential cannot be decrypted",
            UnsealFailure::Transient => "the credential service could not be reached",
        })
    }
}

/// `timeout` exits 124 when it killed the tool and 137 when SIGKILL did;
/// 125 to 127 are its own failures to run the command.
pub fn classify_creds_failure(code: Option<i32>, stderr: &str) -> UnsealFailure {
    match code {
        None | Some(124..=127) | Some(137) => return UnsealFailure::Transient,
        _ => {}
    }
    let s = stderr.to_ascii_lowercase();
    const PASSING: [&str; 12] = [
        "timed out",
        "connect",
        "temporarily unavailable",
        "no such file",
        "no such device",
        "not available",
        "resource busy",
        "operation not permitted",
        "input/output error",
        "out of memory",
        "permission denied",
        "not supported",
    ];
    if PASSING.iter().any(|m| s.contains(m)) {
        UnsealFailure::Transient
    } else {
        UnsealFailure::Definitive
    }
}

/// Does this load error say the blob itself is unreadable? The credential
/// tool's own verdict and a parse failure of decrypted bytes are; an I/O or
/// service failure is not.
pub fn is_definitive(e: &anyhow::Error) -> bool {
    if let Some(k) = e.downcast_ref::<UnsealFailure>() {
        return *k == UnsealFailure::Definitive;
    }
    if e.downcast_ref::<std::io::Error>().is_some() {
        return false;
    }
    true
}

/// Seal `plain` to the TPM under credential name `name`, scoped to root; the blob is text.
pub(super) fn seal(bin: &Path, name: &str, plain: &[u8]) -> Result<Vec<u8>> {
    creds(
        bin,
        &[
            "encrypt",
            "--with-key=host+tpm2",
            "--tpm2-pcrs=",
            "--uid=0",
            &format!("--name={}", name),
            "-",
            "-",
        ],
        plain,
    )
}

/// Unseal a blob sealed by `seal`: root-scoped and name-bound, nothing else
/// is accepted.
pub(super) fn unseal(bin: &Path, name: &str, blob: &[u8]) -> Result<Vec<u8>> {
    creds(
        bin,
        &["decrypt", "--uid=0", &format!("--name={}", name), "-", "-"],
        blob,
    )
}

pub(super) fn cred_name(user: &str) -> String {
    format!("faceauth-{}", user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A store that cannot seal must not turn a sealed file into plaintext.
    #[test]
    fn a_plain_store_never_downgrades_a_sealed_file() {
        let dir = temp("sticky");
        // The re-probe must stay plain here: on a machine where PID 1 unseals
        // for any user, Sealing::detect() succeeds even in a user's test run.
        let store = Store::open_with_probe(
            &dir,
            Sealing::Plain("probe failed in this test".into()),
            || Sealing::Plain("still failing".into()),
        )
        .unwrap()
        .without_creds();
        let sealed = store.sealed_path_for("alice").unwrap();
        std::fs::write(&sealed, b"not a real blob").unwrap();
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates.push(tmpl(vec![1.0, 0.0], 1, CAM));
        let e = store.save(&u).unwrap_err().to_string();
        assert!(e.contains("refusing to write them in plaintext"), "{}", e);
        assert!(sealed.exists(), "the sealed file must survive");
        assert!(!store.path_for("alice").unwrap().exists());
        // Loading it fails (it is not a blob), and enrolment's recovery does
        // not set it aside either: on a store that cannot seal, that would be
        // the same downgrade by another route (F2).
        assert!(store.load("alice").is_err());
        let e = store.set_aside_unreadable("alice").unwrap_err().to_string();
        assert!(e.contains("enrolment refused"), "{}", e);
        assert!(
            sealed.exists(),
            "the sealed file must survive the recovery path too"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A failed unseal sets a blob aside only when the tool refused the
    /// blob itself; a service that could not be reached leaves it be, and a
    /// store that cannot seal never sets a sealed blob aside at all (F2).
    #[test]
    fn only_a_definitive_unseal_failure_sets_a_blob_aside() {
        assert_eq!(
            classify_creds_failure(Some(1), "Failed to decrypt credential: Bad message"),
            UnsealFailure::Definitive
        );
        assert_eq!(
            classify_creds_failure(
                Some(1),
                "Embedded credential name 'faceauth-bob' does not match filename"
            ),
            UnsealFailure::Definitive
        );
        assert_eq!(
            classify_creds_failure(Some(124), ""),
            UnsealFailure::Transient,
            "timeout killed it"
        );
        assert_eq!(
            classify_creds_failure(None, ""),
            UnsealFailure::Transient,
            "a signal"
        );
        assert_eq!(
            classify_creds_failure(Some(1), "Failed to connect to TPM: Connection refused"),
            UnsealFailure::Transient
        );
        assert_eq!(
            classify_creds_failure(
                Some(1),
                "Failed to open /dev/tpmrm0: Operation not permitted"
            ),
            UnsealFailure::Transient
        );
        let transient = anyhow::anyhow!("systemd-creds decrypt: exit status: 1 busy")
            .context(UnsealFailure::Transient)
            .context("unseal /x/alice.cred");
        let definitive = anyhow::anyhow!("systemd-creds decrypt: exit status: 1 bad")
            .context(UnsealFailure::Definitive)
            .context("unseal /x/alice.cred");
        assert!(!is_definitive(&transient) && is_definitive(&definitive));
        assert!(
            !is_definitive(&anyhow::Error::from(std::io::Error::other("read"))),
            "an I/O failure says nothing about the blob"
        );

        // A store that can seal, and a sealed blob it could not open.
        let dir = temp("aside");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open_with_probe(&dir, Sealing::Tpm, || Sealing::Tpm)
            .unwrap()
            .without_creds();
        let sealed = store.sealed_path_for("alice").unwrap();
        std::fs::write(&sealed, b"blob").unwrap();
        assert!(store
            .set_aside_if_unreadable("alice", &transient)
            .unwrap()
            .is_none());
        assert!(sealed.exists(), "a transient failure keeps the blob");
        assert!(store
            .set_aside_if_unreadable("alice", &definitive)
            .unwrap()
            .is_some());
        assert!(!sealed.exists(), "a definitive failure sets it aside");

        // A store that cannot seal refuses to replace a sealed set, so the
        // recovery cannot downgrade it (the round-3 PoC, inverted).
        let dir2 = temp("noaside");
        let _ = std::fs::remove_dir_all(&dir2);
        let plain = Store::open_with_probe(
            &dir2,
            Sealing::Plain("TPM probe failed: timeout".into()),
            || Sealing::Plain("still failing".into()),
        )
        .unwrap()
        .without_creds();
        let sealed2 = plain.sealed_path_for("alice").unwrap();
        std::fs::write(&sealed2, b"blob").unwrap();
        let e = plain.check_can_replace("alice").unwrap_err().to_string();
        assert!(e.contains("enrolment refused"), "{}", e);
        assert!(
            plain.set_aside_if_unreadable("alice", &definitive).is_err(),
            "no set-aside on a store that would then write plaintext"
        );
        assert!(sealed2.exists());
        assert!(
            plain.check_can_replace("bob").is_ok(),
            "a user without sealed templates may enrol plain"
        );
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(dir2);
    }

    /// A credential tool that answers with this script's exit code and
    /// stderr, for driving `open_for_enrolment` through a real unseal.
    fn fake_creds(dir: &Path, name: &str, code: i32, stderr: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(name);
        std::fs::write(
            &p,
            format!("#!/bin/sh\necho '{}' >&2\nexit {}\n", stderr, code),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    /// The walk-through and the terminal enrolment open the set the same
    /// way: a TPM that timed out keeps the sealed blob and fails the
    /// enrolment; only the tool's verdict on the blob sets it aside (F2,
    /// round-4 C8).
    #[test]
    fn enrolment_keeps_a_sealed_set_the_tpm_could_not_open_in_time() {
        let dir = temp("openenrol");
        let _ = std::fs::remove_dir_all(&dir);
        let mut store = Store::open_with_probe(&dir, Sealing::Tpm, || Sealing::Tpm).unwrap();
        let sealed = store.sealed_path_for("alice").unwrap();
        std::fs::write(&sealed, b"a good sealed blob").unwrap();

        store.creds_bin = fake_creds(&dir, "creds-timeout.sh", 124, "");
        let e = store.open_for_enrolment("alice").unwrap_err();
        assert!(!is_definitive(&e), "{:#}", e);
        assert!(sealed.exists(), "a timeout keeps the blob");

        store.creds_bin = fake_creds(
            &dir,
            "creds-busy.sh",
            1,
            "Failed to connect to TPM: Connection refused",
        );
        assert!(store.open_for_enrolment("alice").is_err());
        assert!(sealed.exists(), "an unreachable TPM keeps the blob");

        store.creds_bin = fake_creds(
            &dir,
            "creds-bad.sh",
            1,
            "Failed to decrypt credential: Bad message",
        );
        assert!(
            store.open_for_enrolment("alice").unwrap().is_none(),
            "the tool's verdict starts a fresh set"
        );
        assert!(!sealed.exists(), "and sets the old one aside");
        assert!(std::fs::read_dir(&dir).unwrap().flatten().any(|e| e
            .file_name()
            .to_string_lossy()
            .starts_with("alice.cred.unreadable-")));

        // A store that cannot seal refuses before it touches the blob.
        let dir2 = temp("openenrol-plain");
        let _ = std::fs::remove_dir_all(&dir2);
        let plain = Store::open_with_probe(
            &dir2,
            Sealing::Plain("TPM probe failed: timeout".into()),
            || Sealing::Plain("still failing".into()),
        )
        .unwrap()
        .without_creds();
        let sealed2 = plain.sealed_path_for("alice").unwrap();
        std::fs::write(&sealed2, b"blob").unwrap();
        let e = plain.open_for_enrolment("alice").unwrap_err().to_string();
        assert!(e.contains("enrolment refused"), "{}", e);
        assert!(sealed2.exists());
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(dir2);
    }

    /// Runs the real thing when it can (root, TPM). Otherwise it is skipped,
    /// loudly, unless FACEAUTH_REQUIRE_TPM=1 (the release check), which makes
    /// a skip a failure.
    #[test]
    fn sealed_roundtrip_when_this_machine_can() {
        // As a user, the probe makes PID 1 ask polkit, which raises a consent
        // window on the desktop: only root probes.
        let sealing = if nix::unistd::geteuid().is_root() {
            Sealing::detect()
        } else {
            Sealing::Plain("not root".into())
        };
        let Sealing::Tpm = sealing else {
            if std::env::var("FACEAUTH_REQUIRE_TPM").as_deref() == Ok("1") {
                panic!(
                    "FACEAUTH_REQUIRE_TPM=1 and this machine cannot seal: {}",
                    sealing.describe()
                );
            }
            eprintln!("SKIPPED (not a pass): {}", sealing.describe());
            return;
        };
        let dir = temp("sealed");
        let store = Store::open_with(&dir, Sealing::Tpm).unwrap();
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates.push(tmpl(vec![1.0, 0.0], 1, "ipu3:x"));
        // Plaintext left by an older build is sealed on first load.
        let plain = store.path_for("alice").unwrap();
        std::fs::write(&plain, serde_json::to_string(&u).unwrap()).unwrap();
        let back = store.load("alice").unwrap().unwrap();
        assert_eq!(back.templates.len(), 1);
        assert!(!plain.exists(), "plaintext should be gone after sealing");
        let sealed = store.sealed_path_for("alice").unwrap();
        assert!(sealed.exists());
        assert_eq!(
            std::fs::metadata(&sealed).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(
            !std::fs::read_to_string(&sealed)
                .unwrap()
                .contains("embedding"),
            "the sealed file must not carry the JSON"
        );
        // Renamed to another user, the blob does not open (name-bound).
        std::fs::copy(&sealed, dir.join("bob.cred")).unwrap();
        assert!(store.load("bob").is_err());
        assert!(store.delete("alice").unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }
}
