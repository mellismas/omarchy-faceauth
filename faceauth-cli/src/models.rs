//! `faceauth models fetch`: the developer download of the model weights,
//! checked against the manifest's size and SHA-256. On an installed system
//! the models package owns these files.

use super::args::opt;
use anyhow::{anyhow, bail, Context, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The directory the omarchy-faceauth-models package owns. `fetch` writes
/// there only when `--dir` names it; the default is never under /usr/share.
const PACKAGE_DIR: &str = "/usr/share/faceauth/models";

/// How long curl may spend on one file. The largest model is 260 MB, so ten
/// minutes covers a slow link without letting a stalled transfer hang the
/// command forever.
pub(super) const FETCH_MAX_SECONDS: u64 = 600;

/// The download cap when the manifest has no `size` for a model: 1 GiB,
/// well above the largest model, so a runaway response still stops.
pub(super) const FETCH_MAX_BYTES_UNKNOWN: u64 = 1 << 30;

/// Download the model weights named in the manifest, verify size and SHA-256.
/// A developer command: on an installed system the omarchy-faceauth-models
/// package owns the files under `/usr/share/faceauth/models`, and setup
/// never calls this. Without `--dir` the files go under the user's data
/// directory.
pub(super) fn models_fetch(rest: &[&str]) -> Result<()> {
    let manifest =
        PathBuf::from(opt(rest, "--manifest").unwrap_or("/usr/share/faceauth/models.toml"));
    let dir = match opt(rest, "--dir") {
        Some(d) => PathBuf::from(d),
        None => default_dir(std::env::var_os("XDG_DATA_HOME"), std::env::var_os("HOME"))?,
    };
    let text =
        std::fs::read_to_string(&manifest).with_context(|| manifest.display().to_string())?;
    let doc: toml::Value = toml::from_str(&text)?;
    let models = doc
        .get("model")
        .and_then(|m| m.as_array())
        .ok_or_else(|| anyhow!("manifest has no [[model]] entries"))?;
    // Before anything is created: a leaf root makes itself would pass a
    // check on the leaf alone, so the deepest existing level and every
    // level above it are checked first.
    root_target_ok(&dir, nix::unistd::geteuid().is_root())?;
    std::fs::create_dir_all(&dir).with_context(|| dir.display().to_string())?;
    println!("models directory: {}", dir.display());
    let mut failed = 0;
    for m in models {
        let name = m
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("model without name"))?;
        let url = m
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("{}: no url", name))?;
        let sha = m
            .get("sha256")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("{}: no sha256", name))?;
        let size = m.get("size").and_then(|v| v.as_integer()).unwrap_or(0) as u64;
        let dest = dir.join(name);
        if dest.exists() && sha256_file(&dest)? == sha {
            println!("{}: present and verified", name);
            continue;
        }
        println!("{}: downloading {} bytes from {}", name, size, url);
        // Beside the target, so the rename after verification stays on one
        // filesystem; a failed or unverified download never reaches `dest`.
        let tmp = dir.join(format!("{}.part", name));
        let args = curl_args(url, size)?;
        // The .part is opened here, new and never through a symlink, and
        // curl writes to that descriptor: a planted name fails instead of
        // being followed to whatever it points at.
        let _ = std::fs::remove_file(&tmp);
        let part = open_part(&tmp)?;
        // Absolute paths and a clean environment: this may run as root.
        let status = std::process::Command::new("/usr/bin/curl")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args(&args)
            .stdout(std::process::Stdio::from(part))
            .status()
            .context("run curl")?;
        if !status.success() {
            println!("{}: download failed ({})", name, status);
            let _ = std::fs::remove_file(&tmp);
            failed += 1;
            continue;
        }
        let got = sha256_file(&tmp)?;
        let len = std::fs::metadata(&tmp)?.len();
        if got != sha || (size > 0 && len != size) {
            println!(
                "{}: VERIFICATION FAILED (sha256 {} size {}), not installed",
                name, got, len
            );
            let _ = std::fs::remove_file(&tmp);
            failed += 1;
            continue;
        }
        std::fs::rename(&tmp, &dest)?;
        println!("{}: verified and installed ({} bytes)", name, len);
    }
    if failed > 0 {
        bail!("{} model(s) failed", failed);
    }
    println!(
        "done: the files are in {}. An installed system uses the omarchy-faceauth-models package under {}. A development daemon reads models_dir from its config and accepts only a root-owned directory (every level of the path) that group and others cannot write, with root-owned files: install them as root with `install -o root -m 644`; the engine tests read FACEAUTH_MODELS.",
        dir.display(),
        PACKAGE_DIR
    );
    Ok(())
}

/// Where `fetch` writes without `--dir`: `$XDG_DATA_HOME/faceauth/models`,
/// else `$HOME/.local/share/faceauth/models`. Never the package directory,
/// which pacman owns; that takes an explicit `--dir`.
pub(super) fn default_dir(
    xdg_data_home: Option<OsString>,
    home: Option<OsString>,
) -> Result<PathBuf> {
    let base = match xdg_data_home {
        Some(x) if !x.is_empty() && Path::new(&x).is_absolute() => PathBuf::from(x),
        _ => match home {
            Some(h) if !h.is_empty() => PathBuf::from(h).join(".local/share"),
            _ => bail!(
                "neither XDG_DATA_HOME nor HOME is set: pass --dir DIR (the package directory {} is written only when named)",
                PACKAGE_DIR
            ),
        },
    };
    Ok(base.join("faceauth/models"))
}

/// Root writes only under root-owned directories: under `sudo -E` the
/// default lands in the invoking user's home, where any process of theirs
/// can plant a name for root to follow. The deepest existing level of
/// `dir` and every level above it must pass the daemon's ownership rule
/// (root, no group or other write), before anything is created. A non-root
/// run owns its own risk.
pub(super) fn root_target_ok(dir: &Path, euid_is_root: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if !euid_is_root {
        return Ok(());
    }
    let existing = dir
        .ancestors()
        .find(|p| p.exists())
        .ok_or_else(|| anyhow!("{}: no existing directory above it", dir.display()))?;
    let existing = std::fs::canonicalize(existing)
        .with_context(|| format!("resolve {}", existing.display()))?;
    for p in existing.ancestors() {
        let md = std::fs::metadata(p).with_context(|| format!("stat {}", p.display()))?;
        faceauth_daemon::config::models_dir_component_ok(p, md.uid(), md.mode()).with_context(
            || format!("this runs as root and {} is not a root-only path: pass --dir, or run without sudo", dir.display()),
        )?;
    }
    Ok(())
}

/// The `.part` file: created new (O_EXCL) and never through a symlink
/// (O_NOFOLLOW), mode 0644 before umask, so an existing or planted name
/// is an error rather than a target.
fn open_part(tmp: &Path) -> Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
        .open(tmp)
        .with_context(|| format!("create {}", tmp.display()))
}

/// The curl invocation for one model: https only, including on redirect,
/// no URL globbing, a wall-clock limit, and a size cap from the manifest
/// (or a fixed one). The body goes to stdout, which the caller connects to
/// the `.part` file it opened itself. `--fail` turns an HTTP error into a
/// non-zero exit; `-S` shows errors, and the progress meter stays on for a
/// 260 MB file. A URL that is not https is refused before curl runs, which
/// also rules out a URL that starts with `-`.
pub(super) fn curl_args(url: &str, size: u64) -> Result<Vec<OsString>> {
    if !url.starts_with("https://") {
        bail!("{}: not an https URL, refusing to download", url);
    }
    let cap = if size > 0 {
        size
    } else {
        FETCH_MAX_BYTES_UNKNOWN
    };
    let mut args: Vec<OsString> = [
        "--proto",
        "=https",
        "--proto-redir",
        "=https",
        "--globoff",
        "-S",
        "-L",
        "--fail",
        "--max-time",
        &FETCH_MAX_SECONDS.to_string(),
        "--max-filesize",
        &cap.to_string(),
    ]
    .iter()
    .map(OsString::from)
    .collect();
    args.push(OsString::from(url));
    Ok(args)
}

pub(super) fn sha256_file(p: &Path) -> Result<String> {
    let out = std::process::Command::new("/usr/bin/sha256sum")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg(p)
        .output()
        .context("run sha256sum")?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.split_whitespace().next().unwrap_or("").to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strs(v: &[OsString]) -> Vec<String> {
        v.iter().map(|s| s.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn curl_args_restrict_protocol_time_and_size() {
        let a = strs(&curl_args("https://example.org/m.onnx", 1234).unwrap());
        assert_eq!(
            a,
            [
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--globoff",
                "-S",
                "-L",
                "--fail",
                "--max-time",
                "600",
                "--max-filesize",
                "1234",
                "https://example.org/m.onnx",
            ]
        );
        assert!(
            !a.contains(&"-s".to_string()),
            "progress and errors stay visible"
        );
        assert!(
            !a.contains(&"-o".to_string()),
            "curl writes the descriptor we opened"
        );
    }

    #[test]
    fn curl_args_cap_an_unknown_size() {
        let a = strs(&curl_args("https://example.org/m", 0).unwrap());
        let i = a.iter().position(|s| s == "--max-filesize").unwrap();
        assert_eq!(a[i + 1], FETCH_MAX_BYTES_UNKNOWN.to_string());
    }

    #[test]
    fn curl_args_refuse_non_https() {
        for bad in [
            "http://example.org/m",
            "ftp://example.org/m",
            "file:///etc/passwd",
            "-K/etc/x",
            "example.org/m",
        ] {
            assert!(curl_args(bad, 1).is_err(), "{} was taken", bad);
        }
    }

    #[test]
    fn default_dir_prefers_xdg_then_home_and_never_the_package_dir() {
        let xdg = default_dir(Some("/data".into()), Some("/home/a".into())).unwrap();
        assert_eq!(xdg, PathBuf::from("/data/faceauth/models"));
        let home = default_dir(None, Some("/home/a".into())).unwrap();
        assert_eq!(home, PathBuf::from("/home/a/.local/share/faceauth/models"));
        let rel = default_dir(Some("relative".into()), Some("/home/a".into())).unwrap();
        assert_eq!(rel, PathBuf::from("/home/a/.local/share/faceauth/models"));
        let root = default_dir(None, Some("/root".into())).unwrap();
        assert!(!root.starts_with("/usr/share"), "{}", root.display());
        assert!(default_dir(None, None).is_err());
        assert!(default_dir(Some("".into()), Some("".into())).is_err());
    }

    #[test]
    fn root_writes_only_under_root_owned_dirs() {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap();
        let under_home = home.join("faceauth-not-yet/models");
        assert!(
            root_target_ok(&under_home, false).is_ok(),
            "non-root is not restricted"
        );
        if home.starts_with("/home") {
            // Not yet created: the check reaches the user's home and stops there.
            let e = root_target_ok(&under_home, true).unwrap_err();
            assert!(format!("{:#}", e).contains("uid"), "{:#}", e);
            assert!(!under_home.exists(), "nothing was created");
        }
        assert!(root_target_ok(Path::new("/usr/share/faceauth-not-yet/models"), true).is_ok());
    }

    #[test]
    fn the_part_file_is_new_and_never_a_symlink() {
        let base = std::env::temp_dir().join(format!("faceauth-part-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let victim = base.join("victim");
        std::fs::write(&victim, b"keep").unwrap();
        let link = base.join("m.part");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        assert!(open_part(&link).is_err(), "a planted symlink was followed");
        assert_eq!(std::fs::read(&victim).unwrap(), b"keep");
        let fresh = base.join("n.part");
        assert!(open_part(&fresh).is_ok());
        assert!(open_part(&fresh).is_err(), "an existing .part was reopened");
        let _ = std::fs::remove_dir_all(&base);
    }
}
