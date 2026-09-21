//! Enrolment templates: fixed-length embeddings, never images.
//!
//! One file per user. On a machine with a TPM 2.0 the file is
//! `<dir>/<user>.cred`: the JSON sealed by `systemd-creds` (AES-256-GCM under
//! a key only this TPM unwraps; no PCR policy, so a kernel or firmware update
//! does not strand the templates), bound to the credential name
//! `faceauth-<user>` so one user's blob cannot be renamed into another's.
//! There is no recovery key anywhere on disk, by design: templates that
//! cannot be unsealed are re-enrolled, which takes twelve seconds. Without a
//! working TPM the file is `<user>.json`, plaintext, root 0600, and every
//! surface says so (`doctor`, enrolment). A plaintext file met by a store
//! that can seal is sealed on first load and the plaintext removed.
//!
//! Several templates per user (glasses, lighting, angle) are kept as separate
//! entries and matched by the best score, which is how variants merge into one
//! identity without averaging away what makes each distinct. Each template
//! records the camera it was enrolled on and only matches on that camera: a
//! camera swapped in for the enrolled one gets nothing to match against.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

pub const FORMAT_VERSION: u32 = 1;

const SYSTEMD_CREDS: &str = "/usr/bin/systemd-creds";
const TIMEOUT: &str = "/usr/bin/timeout";

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
    /// The camera this was enrolled on (`IrCapture::identity`); a template
    /// only matches on that camera. None on templates from before binding.
    #[serde(default)]
    pub device: Option<String>,
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

    /// As `best_match`, over the templates usable on camera `device`.
    pub fn best_match_on(&self, embedding: &[f32], device: &str) -> Option<(f32, usize)> {
        self.templates
            .iter()
            .enumerate()
            .filter(|(_, t)| t.usable_on(device))
            .map(|(i, t)| (faceauth_engine::cosine(&t.embedding, embedding), i))
            .max_by(|a, b| a.0.total_cmp(&b.0))
    }

    /// How many templates may match on camera `device`.
    pub fn usable_on(&self, device: &str) -> usize {
        self.templates.iter().filter(|t| t.usable_on(device)).count()
    }

    /// The cameras the templates are bound to, for a message.
    pub fn bound_devices(&self) -> Vec<String> {
        let mut v: Vec<String> = self.templates.iter().filter_map(|t| t.device.clone()).collect();
        v.sort();
        v.dedup();
        v
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

impl Template {
    fn usable_on(&self, device: &str) -> bool {
        self.device.as_deref().map(|d| d == device).unwrap_or(true)
    }
}

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
        match seal("faceauth-probe", b"probe").and_then(|blob| unseal("faceauth-probe", &blob)) {
            Ok(back) if back == b"probe" => Sealing::Tpm,
            Ok(_) => Sealing::Plain("TPM probe round trip returned different bytes".into()),
            Err(e) => Sealing::Plain(format!("TPM probe failed: {}", e)),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Sealing::Tpm => "sealed to the TPM (systemd-creds, name-bound, no PCR policy)".into(),
            Sealing::Plain(why) => format!("plaintext at rest (root 0600): {}", why),
        }
    }
}

fn creds(args: &[&str], stdin_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new(TIMEOUT)
        .arg("30")
        .arg(SYSTEMD_CREDS)
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawn {}", SYSTEMD_CREDS))?;
    if let Some(mut si) = child.stdin.take() {
        si.write_all(stdin_bytes)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("systemd-creds {}: {} {}", args.first().copied().unwrap_or(""), out.status, String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(out.stdout)
}

/// Seal `plain` to the TPM under credential name `name`; the blob is text.
fn seal(name: &str, plain: &[u8]) -> Result<Vec<u8>> {
    creds(&["encrypt", "--with-key=tpm2", "--tpm2-pcrs=", &format!("--name={}", name), "-", "-"], plain)
}

fn unseal(name: &str, blob: &[u8]) -> Result<Vec<u8>> {
    creds(&["decrypt", &format!("--name={}", name), "-", "-"], blob)
}

fn cred_name(user: &str) -> String {
    format!("faceauth-{}", user)
}

#[derive(Clone, PartialEq)]
struct Fingerprint {
    path: PathBuf,
    len: u64,
    mtime: Option<std::time::SystemTime>,
}

fn fingerprint(p: &Path) -> Result<Fingerprint> {
    let m = std::fs::metadata(p)?;
    Ok(Fingerprint { path: p.to_path_buf(), len: m.len(), mtime: m.modified().ok() })
}

pub struct Store {
    dir: PathBuf,
    sealing: Sealing,
    /// Unsealing costs about a second of TPM time; templates are cached per
    /// user against the file they came from, so an attempt pays it only when
    /// the file changed.
    cache: Mutex<HashMap<String, (Fingerprint, UserTemplates)>>,
}

impl Store {
    /// Open the store, detecting whether this machine can seal.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(dir, Sealing::detect())
    }

    pub fn open_with(dir: impl AsRef<Path>, sealing: Sealing) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(Store { dir, sealing, cache: Mutex::new(HashMap::new()) })
    }

    pub fn sealing(&self) -> &Sealing {
        &self.sealing
    }

    fn check_user(user: &str) -> Result<()> {
        if user.is_empty() || user.contains('/') || user.contains("..") || user.chars().any(|c| c.is_control() || c.is_whitespace()) {
            bail!("invalid user name {:?}", user);
        }
        Ok(())
    }

    /// The plaintext file (whether or not it exists).
    pub fn path_for(&self, user: &str) -> Result<PathBuf> {
        Self::check_user(user)?;
        Ok(self.dir.join(format!("{}.json", user)))
    }

    /// The sealed file (whether or not it exists).
    pub fn sealed_path_for(&self, user: &str) -> Result<PathBuf> {
        Self::check_user(user)?;
        Ok(self.dir.join(format!("{}.cred", user)))
    }

    /// Are this user's templates on disk sealed?
    pub fn is_sealed(&self, user: &str) -> bool {
        self.sealed_path_for(user).map(|p| p.exists()).unwrap_or(false)
    }

    fn parse(text: &str, p: &Path, user: &str) -> Result<Option<UserTemplates>> {
        let t: UserTemplates = serde_json::from_str(text).with_context(|| format!("parse {}", p.display()))?;
        if t.version != FORMAT_VERSION {
            bail!("{}: template format {} (this build reads {})", p.display(), t.version, FORMAT_VERSION);
        }
        if t.user != user {
            bail!("{}: templates are for {:?}, not {:?}", p.display(), t.user, user);
        }
        if let (Some(stored), Some(now)) = (t.uid, current_uid(user)) {
            if stored != now {
                log::warn!("{}: templates belong to uid {} but {} is now uid {}; treating as not enrolled", p.display(), stored, user, now);
                return Ok(None);
            }
        }
        Ok(Some(t))
    }

    pub fn load(&self, user: &str) -> Result<Option<UserTemplates>> {
        let sealed = self.sealed_path_for(user)?;
        let plain = self.path_for(user)?;
        if sealed.exists() {
            let fp = fingerprint(&sealed)?;
            if let Ok(c) = self.cache.lock() {
                if let Some((have, t)) = c.get(user) {
                    if *have == fp {
                        return Ok(Some(t.clone()));
                    }
                }
            }
            let blob = std::fs::read(&sealed).with_context(|| format!("read {}", sealed.display()))?;
            let text = unseal(&cred_name(user), &blob).with_context(|| format!("unseal {}", sealed.display()))?;
            let t = Self::parse(&String::from_utf8_lossy(&text), &sealed, user)?;
            if let Some(t) = &t {
                if let Ok(mut c) = self.cache.lock() {
                    c.insert(user.to_string(), (fp, t.clone()));
                }
            }
            return Ok(t);
        }
        if !plain.exists() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&plain).with_context(|| format!("read {}", plain.display()))?;
        let t = Self::parse(&text, &plain, user)?;
        if let (Some(t), Sealing::Tpm) = (&t, &self.sealing) {
            // Found in the clear on a machine that can seal: seal it now.
            match self.save(t) {
                Ok(p) => log::info!("{}: sealed to the TPM as {}, plaintext removed", plain.display(), p.display()),
                Err(e) => log::warn!("{}: could not seal: {}", plain.display(), e),
            }
        }
        Ok(t)
    }

    /// Write atomically (temp file, fsync, rename) with mode 0600: sealed when
    /// this machine can, plaintext otherwise. The other form is removed.
    pub fn save(&self, t: &UserTemplates) -> Result<PathBuf> {
        use std::os::unix::fs::OpenOptionsExt;
        let json = serde_json::to_string_pretty(t)?;
        let (target, bytes, other) = match &self.sealing {
            Sealing::Tpm => (self.sealed_path_for(&t.user)?, seal(&cred_name(&t.user), json.as_bytes())?, self.path_for(&t.user)?),
            Sealing::Plain(_) => (self.path_for(&t.user)?, json.into_bytes(), self.sealed_path_for(&t.user)?),
        };
        let tmp = target.with_extension("tmp");
        {
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &target)?;
        if other.exists() {
            std::fs::remove_file(&other).with_context(|| format!("remove {}", other.display()))?;
        }
        if let Ok(mut c) = self.cache.lock() {
            match fingerprint(&target) {
                Ok(fp) => {
                    c.insert(t.user.clone(), (fp, t.clone()));
                }
                Err(_) => {
                    c.remove(&t.user);
                }
            }
        }
        Ok(target)
    }

    pub fn delete(&self, user: &str) -> Result<bool> {
        let mut any = false;
        for p in [self.sealed_path_for(user)?, self.path_for(user)?] {
            if p.exists() {
                std::fs::remove_file(&p)?;
                any = true;
            }
        }
        if let Ok(mut c) = self.cache.lock() {
            c.remove(user);
        }
        Ok(any)
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
    use std::os::unix::fs::PermissionsExt;

    fn tmpl(e: Vec<f32>, created: u64, device: Option<&str>) -> Template {
        Template { embedding: e, quality: 0.9, face_width: 80.0, created, label: "enrol".into(), device: device.map(String::from) }
    }

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("faceauth-store-{}-{}", name, std::process::id()))
    }

    #[test]
    fn roundtrip_and_match_plain() {
        let dir = temp("plain");
        let store = Store::open_with(&dir, Sealing::Plain("test".into())).unwrap();
        let mut u = UserTemplates::new("alice", "glintr100");
        u.uid = None;
        u.templates.push(tmpl(vec![1.0, 0.0], 1, None));
        u.templates.push(tmpl(vec![0.0, 1.0], 2, None));
        let p = store.save(&u).unwrap();
        assert!(p.ends_with("alice.json"));
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        let back = store.load("alice").unwrap().unwrap();
        assert_eq!(back.templates.len(), 2);
        assert_eq!(back.best_match(&[0.6, 0.8]).unwrap(), (0.8, 1));
        assert_eq!(back.self_consistency().unwrap(), (0.0, 0.0, 0.0));
        assert!(store.load("nobody").unwrap().is_none());
        assert!(store.path_for("../etc").is_err());
        assert!(store.path_for("a b").is_err());
        assert!(!store.is_sealed("alice"));
        assert!(store.delete("alice").unwrap());
        assert!(!p.exists());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_file_for_another_user_is_refused() {
        let dir = temp("other");
        let store = Store::open_with(&dir, Sealing::Plain("test".into())).unwrap();
        let mut u = UserTemplates::new("alice", "glintr100");
        u.uid = None;
        u.templates.push(tmpl(vec![1.0, 0.0], 1, None));
        store.save(&u).unwrap();
        std::fs::rename(dir.join("alice.json"), dir.join("bob.json")).unwrap();
        assert!(store.load("bob").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn templates_match_only_on_their_camera() {
        let mut u = UserTemplates::new("alice", "glintr100");
        u.templates.push(tmpl(vec![1.0, 0.0], 1, Some("ipu3:ov7251 3-0060")));
        u.templates.push(tmpl(vec![0.0, 1.0], 2, None)); // pre-binding: usable anywhere
        assert_eq!(u.usable_on("ipu3:ov7251 3-0060"), 2);
        assert_eq!(u.usable_on("uvc:uvcvideo:Other Cam:usb-1"), 1);
        assert_eq!(u.best_match_on(&[1.0, 0.0], "uvc:uvcvideo:Other Cam:usb-1").unwrap(), (0.0, 1));
        assert_eq!(u.best_match_on(&[1.0, 0.0], "ipu3:ov7251 3-0060").unwrap(), (1.0, 0));
        assert_eq!(u.bound_devices(), vec!["ipu3:ov7251 3-0060".to_string()]);
        let only_bound = UserTemplates { templates: vec![tmpl(vec![1.0, 0.0], 1, Some("ipu3:x"))], ..u.clone() };
        assert_eq!(only_bound.usable_on("uvc:y"), 0);
        assert!(only_bound.best_match_on(&[1.0, 0.0], "uvc:y").is_none());
    }

    /// Runs the real thing when it can (root, TPM); otherwise records why not.
    #[test]
    fn sealed_roundtrip_when_this_machine_can() {
        let sealing = Sealing::detect();
        let Sealing::Tpm = sealing else {
            eprintln!("skipped: {}", sealing.describe());
            return;
        };
        let dir = temp("sealed");
        let store = Store::open_with(&dir, Sealing::Tpm).unwrap();
        let mut u = UserTemplates::new("alice", "glintr100");
        u.uid = None;
        u.templates.push(tmpl(vec![1.0, 0.0], 1, Some("ipu3:x")));
        // Plaintext left by an older build is sealed on first load.
        let plain = store.path_for("alice").unwrap();
        std::fs::write(&plain, serde_json::to_string(&u).unwrap()).unwrap();
        let back = store.load("alice").unwrap().unwrap();
        assert_eq!(back.templates.len(), 1);
        assert!(!plain.exists(), "plaintext should be gone after sealing");
        let sealed = store.sealed_path_for("alice").unwrap();
        assert!(sealed.exists());
        assert_eq!(std::fs::metadata(&sealed).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(!std::fs::read_to_string(&sealed).unwrap().contains("embedding"), "the sealed file must not carry the JSON");
        // Renamed to another user, the blob does not open (name-bound).
        std::fs::copy(&sealed, dir.join("bob.cred")).unwrap();
        assert!(store.load("bob").is_err());
        assert!(store.delete("alice").unwrap());
        let _ = std::fs::remove_dir_all(dir);
    }
}
