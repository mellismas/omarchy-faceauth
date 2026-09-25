//! `faceauth models fetch`: the developer download of the model weights,
//! checked against the manifest's size and SHA-256. On an installed system
//! the models package owns these files.

use super::args::opt;
use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;

/// Download the model weights named in the manifest, verify size and SHA-256.
/// A developer command: on an installed system the omarchy-faceauth-models
/// package owns the files under the default directory, and setup never calls
/// this.
pub(super) fn models_fetch(rest: &[&str]) -> Result<()> {
    let manifest =
        PathBuf::from(opt(rest, "--manifest").unwrap_or("/usr/share/faceauth/models.toml"));
    let dir = PathBuf::from(opt(rest, "--dir").unwrap_or("/usr/share/faceauth/models"));
    let text =
        std::fs::read_to_string(&manifest).with_context(|| manifest.display().to_string())?;
    let doc: toml::Value = toml::from_str(&text)?;
    let models = doc
        .get("model")
        .and_then(|m| m.as_array())
        .ok_or_else(|| anyhow!("manifest has no [[model]] entries"))?;
    std::fs::create_dir_all(&dir)?;
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
        let tmp = dir.join(format!("{}.part", name));
        // Absolute paths and a clean environment: this runs as root.
        let status = std::process::Command::new("/usr/bin/curl")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .args(["-sSL", "--fail", "-o"])
            .arg(&tmp)
            .arg(url)
            .status()
            .context("run curl")?;
        if !status.success() {
            println!("{}: download failed ({})", name, status);
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
    Ok(())
}

pub(super) fn sha256_file(p: &std::path::Path) -> Result<String> {
    let out = std::process::Command::new("/usr/bin/sha256sum")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .arg(p)
        .output()
        .context("run sha256sum")?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.split_whitespace().next().unwrap_or("").to_string())
}
