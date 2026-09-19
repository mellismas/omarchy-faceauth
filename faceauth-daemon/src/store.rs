//! Enrolment templates: fixed-length embeddings, never images.
//!
//! One file per user, `<dir>/<user>.json`, root-owned 0600 when the daemon
//! writes it. Several templates per user (glasses, lighting, angle) are kept
//! as separate entries and matched by the best score, which is how variants
//! merge into one identity without averaging away what makes each distinct.
//!
//! Sealing to a TPM is a later step; without one this file is plaintext at
//! rest, which `doctor` and enrolment must say out loud.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const FORMAT_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Template {
    /// L2-normalised embedding.
    pub embedding: Vec<f32>,
    /// Detector score of the frame it came from.
    pub quality: f32,
    /// Face width in pixels in the oriented frame, a proxy for distance.
    pub face_width: f32,
    /// Unix seconds.
    pub created: u64,
    /// Free text: "enrol", "glasses", ...
    pub label: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserTemplates {
    pub version: u32,
    pub user: String,
    /// The account's uid when enrolled. A recreated account with the same name
    /// is a different person; a mismatch on load is treated as not enrolled.
    #[serde(default)]
    pub uid: Option<u32>,
    /// Which recognition model produced these; a model change invalidates them.
    pub model: String,
    pub templates: Vec<Template>,
}

impl UserTemplates {
    pub fn new(user: &str, model: &str) -> Self {
        UserTemplates { version: FORMAT_VERSION, user: user.to_string(), uid: current_uid(user), model: model.to_string(), templates: Vec::new() }
    }

    /// Best cosine similarity of `embedding` against every template, and which one.
    pub fn best_match(&self, embedding: &[f32]) -> Option<(f32, usize)> {
        self.templates
            .iter()
            .enumerate()
            .map(|(i, t)| (faceauth_engine::cosine(&t.embedding, embedding), i))
            .max_by(|a, b| a.0.total_cmp(&b.0))
    }

    /// Pairwise similarity statistics of the stored templates: (min, mean, max).
    pub fn self_consistency(&self) -> Option<(f32, f32, f32)> {
        let n = self.templates.len();
        if n < 2 {
            return None;
        }
        let (mut lo, mut hi, mut sum, mut cnt) = (1f32, -1f32, 0f32, 0usize);
        for i in 0..n {
            for j in i + 1..n {
                let s = faceauth_engine::cosine(&self.templates[i].embedding, &self.templates[j].embedding);
                lo = lo.min(s);
                hi = hi.max(s);
                sum += s;
                cnt += 1;
            }
        }
        Some((lo, sum / cnt as f32, hi))
    }
}

pub struct Store {
    dir: PathBuf,
}

impl Store {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(Store { dir })
    }

    pub fn path_for(&self, user: &str) -> Result<PathBuf> {
        if user.is_empty() || user.contains('/') || user.contains("..") {
            bail!("invalid user name {:?}", user);
        }
        Ok(self.dir.join(format!("{}.json", user)))
    }

    pub fn load(&self, user: &str) -> Result<Option<UserTemplates>> {
        let p = self.path_for(user)?;
        if !p.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
        let t: UserTemplates = serde_json::from_str(&text).with_context(|| format!("parse {}", p.display()))?;
        if t.version != FORMAT_VERSION {
            bail!("{}: template format {} (this build reads {})", p.display(), t.version, FORMAT_VERSION);
        }
        if let (Some(stored), Some(now)) = (t.uid, current_uid(user)) {
            if stored != now {
                log::warn!("{}: templates belong to uid {} but {} is now uid {}; treating as not enrolled", p.display(), stored, user, now);
                return Ok(None);
            }
        }
        Ok(Some(t))
    }

    /// Write atomically (temp file, fsync, rename) with mode 0600.
    pub fn save(&self, t: &UserTemplates) -> Result<PathBuf> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let p = self.path_for(&t.user)?;
        let tmp = p.with_extension("json.tmp");
        {
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(serde_json::to_string_pretty(t)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &p)?;
        Ok(p)
    }

    pub fn delete(&self, user: &str) -> Result<bool> {
        let p = self.path_for(user)?;
        if p.exists() {
            std::fs::remove_file(&p)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub fn current_uid(user: &str) -> Option<u32> {
    nix::unistd::User::from_name(user).ok().flatten().map(|u| u.uid.as_raw())
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_match() {
        let dir = std::env::temp_dir().join(format!("faceauth-store-test-{}", std::process::id()));
        let store = Store::open(&dir).unwrap();
        let mut u = UserTemplates::new("alice", "glintr100");
        u.templates.push(Template { embedding: vec![1.0, 0.0], quality: 0.9, face_width: 80.0, created: 1, label: "enrol".into() });
        u.templates.push(Template { embedding: vec![0.0, 1.0], quality: 0.9, face_width: 80.0, created: 2, label: "enrol".into() });
        let p = store.save(&u).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        let back = store.load("alice").unwrap().unwrap();
        assert_eq!(back.templates.len(), 2);
        assert_eq!(back.best_match(&[0.6, 0.8]).unwrap(), (0.8, 1));
        assert_eq!(back.self_consistency().unwrap(), (0.0, 0.0, 0.0));
        assert!(store.load("nobody").unwrap().is_none());
        assert!(store.path_for("../etc").is_err());
        assert!(store.delete("alice").unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }

    use std::os::unix::fs::PermissionsExt;
}
