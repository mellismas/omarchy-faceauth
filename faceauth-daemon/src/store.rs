//! Enrolment templates: fixed-length embeddings, never images.
//!
//! One file per user. On a machine with a TPM 2.0 the file is
//! `<dir>/<user>.cred`: the JSON sealed by `systemd-creds` (AES-256-GCM under
//! a key only this TPM unwraps; no PCR policy, so a kernel or firmware update
//! does not strand the templates), bound to the credential name
//! `faceauth-<user>` so one user's blob cannot be renamed into another's.
//! The credential is scoped to root (`--uid=0`), which systemd only allows
//! with the host secret in the mix (`host+tpm2`, `/var/lib/systemd/
//! credential.secret`, root-only): PID 1 then refuses to unseal or mint one
//! for any caller that is not root. So a copy of the file is useless off
//! this machine, and on it only root can open it or forge one. (System-scoped
//! credentials, the first cut, were unsealed by PID 1 for any local user; a
//! blob of that kind is still read, and re-sealed root-only on first load.)
//! There is no recovery key anywhere on disk, by design: templates that
//! cannot be unsealed are re-enrolled (enrolment sets an unreadable blob
//! aside and starts fresh). Without a working TPM the file is `<user>.json`,
//! plaintext, root 0600, and every surface says so (`doctor`, enrolment). A
//! plaintext file met by a store that can seal is sealed on first load and
//! the plaintext unlinked from the live tree; filesystem snapshots taken
//! before that still hold it. Sealing is sticky: a store that finds a sealed
//! file but cannot seal (a TPM that failed its probe at startup) refuses to
//! write plaintext rather than downgrade.
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
/// Templates per user. A sealed credential is capped at 1 MiB by systemd
/// (about 90 templates as compact JSON); the cap keeps every store the same
/// size, sealed or not, and four looks of ten is plenty.
pub const MAX_TEMPLATES: usize = 40;

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
    /// This person's gesture sizes, measured at enrolment.
    #[serde(default)]
    pub gesture: GestureCal,
}

/// How far this person's face moves, in face widths, when they nod and
/// when they shake, from calibration rounds (each a recorded double
/// gesture). The floors derive from these: the nod's only ever rises above
/// the default (a lower floor is where false approvals live), the shake's
/// only ever falls below it (a false refusal costs a password prompt).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct GestureCal {
    pub nod: Vec<f32>,
    pub shake: Vec<f32>,
    /// Largest vertical excursion in each everyday-movement round (reading,
    /// a glance at the keyboard, talking): what a nod must stand clear of.
    #[serde(default)]
    pub still_nod: Vec<f32>,
    /// Largest horizontal excursion in the same rounds: what a shake must
    /// stand clear of.
    #[serde(default)]
    pub still_shake: Vec<f32>,
}

impl GestureCal {
    fn typical(v: &[f32]) -> Option<f32> {
        if v.is_empty() {
            return None;
        }
        let mut s = v.to_vec();
        s.sort_by(|a, b| a.total_cmp(b));
        Some(s[s.len() / 2])
    }

    /// The floor an everyday movement of this size demands: half again as
    /// much, so the movement itself never reaches it. Capped so a nervous
    /// reader still has a floor their nod can clear; past the cap the margin
    /// says so.
    pub const STILL_MARGIN: f32 = 1.5;
    pub const NOD_FLOOR_MAX: f32 = 0.15;
    pub const SHAKE_FLOOR_MAX: f32 = 0.12;

    fn largest(v: &[f32]) -> Option<f32> {
        v.iter().copied().fold(None, |m, x| Some(m.map_or(x, |m: f32| m.max(x))))
    }

    /// (nod floor, shake floor) for this person, given the defaults.
    pub fn floors(&self, default_nod: f32, default_shake: f32) -> (f32, f32) {
        // 0.4 of the peak-to-peak, capped: the detector sees single legs, which
        // run 0.14 to 0.21 on a 0.26 nod (recorded), and the floor must sit
        // clearly under the smallest of them.
        // Capped at 0.09: on the reference user's recording, both nods count
        // at every floor up to 0.09 and one drops out at 0.10 (its first
        // departure from rest is the small leg).
        let mut nod = Self::typical(&self.nod).map(|a| (a * 0.4).clamp(default_nod, 0.09)).unwrap_or(default_nod);
        let mut shake = Self::typical(&self.shake).map(|a| (a * 0.5).clamp(0.03, default_shake)).unwrap_or(default_shake);
        // Everyday movement pushes a floor up, never down: whatever this
        // person does while reading or talking must stay under it.
        if let Some(still) = Self::largest(&self.still_nod) {
            nod = nod.max((still * Self::STILL_MARGIN).min(Self::NOD_FLOOR_MAX));
        }
        if let Some(still) = Self::largest(&self.still_shake) {
            shake = shake.max((still * Self::STILL_MARGIN).min(Self::SHAKE_FLOOR_MAX));
        }
        (nod, shake)
    }

    /// How many times larger this person's typical gesture is than their
    /// largest everyday movement on the same axis, per axis; None until both
    /// have been recorded. Under 2.0 the two are not cleanly separable and
    /// the setup says so.
    pub fn margins(&self) -> (Option<f32>, Option<f32>) {
        let m = |g: &[f32], s: &[f32]| match (Self::typical(g), Self::largest(s)) {
            (Some(g), Some(s)) if s > 0.0 => Some(g / s),
            (Some(_), Some(_)) => Some(f32::INFINITY),
            _ => None,
        };
        (m(&self.nod, &self.still_nod), m(&self.shake, &self.still_shake))
    }

    pub fn is_calibrated(&self) -> bool {
        !self.nod.is_empty() && !self.shake.is_empty()
    }
}

impl UserTemplates {
    pub fn new(user: &str, model: &str) -> Self {
        UserTemplates { version: FORMAT_VERSION, user: user.to_string(), uid: current_uid(user), model: model.to_string(), templates: Vec::new(), gesture: GestureCal::default() }
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
        if !Path::new(TIMEOUT).exists() {
            return Sealing::Plain(format!("{} not installed", TIMEOUT));
        }
        match seal("faceauth-probe", b"probe").and_then(|blob| unseal("faceauth-probe", &blob)) {
            Ok((back, _)) if back == b"probe" => Sealing::Tpm,
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

fn creds(args: &[&str], stdin_bytes: &[u8]) -> Result<Vec<u8>> {
    // `-k 5`: a TPM call that ignores SIGTERM is killed five seconds later,
    // so the daemon never hangs on the credential service.
    let mut child = Command::new(TIMEOUT)
        .args(["-k", "5", "30"])
        .arg(SYSTEMD_CREDS)
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
    let write = child.stdin.take().map(|mut si| si.write_all(stdin_bytes)).unwrap_or(Ok(()));
    let out = child.wait_with_output()?;
    if let Err(e) = write {
        if !out.status.success() {
            bail!("systemd-creds {}: {} {}", args.first().copied().unwrap_or(""), out.status, String::from_utf8_lossy(&out.stderr).trim());
        }
        return Err(e).context("write to systemd-creds");
    }
    if !out.status.success() {
        bail!("systemd-creds {}: {} {}", args.first().copied().unwrap_or(""), out.status, String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(out.stdout)
}

/// Seal `plain` to the TPM under credential name `name`, scoped to root; the blob is text.
fn seal(name: &str, plain: &[u8]) -> Result<Vec<u8>> {
    creds(&["encrypt", "--with-key=host+tpm2", "--tpm2-pcrs=", "--uid=0", &format!("--name={}", name), "-", "-"], plain)
}

/// Unseal a blob. Returns the bytes and whether the blob was of the older,
/// system-scoped kind (which the caller should re-seal).
fn unseal(name: &str, blob: &[u8]) -> Result<(Vec<u8>, bool)> {
    match creds(&["decrypt", "--uid=0", &format!("--name={}", name), "-", "-"], blob) {
        Ok(b) => Ok((b, false)),
        Err(e) if e.to_string().contains("scoped to the system") => Ok((creds(&["decrypt", &format!("--name={}", name), "-", "-"], blob)?, true)),
        Err(e) => Err(e),
    }
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
    /// Fixed at open, except that a store which failed its probe re-tries
    /// once before it would otherwise write plaintext over a sealed file.
    sealing: Mutex<Sealing>,
    /// How to re-probe sealing (tests inject one that stays plain).
    probe: fn() -> Sealing,
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
        Self::open_with_probe(dir, sealing, Sealing::detect)
    }

    pub fn open_with_probe(dir: impl AsRef<Path>, sealing: Sealing, probe: fn() -> Sealing) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(Store { dir, sealing: Mutex::new(sealing), probe, cache: Mutex::new(HashMap::new()) })
    }

    pub fn sealing(&self) -> Sealing {
        self.sealing.lock().map(|s| s.clone()).unwrap_or_else(|p| p.into_inner().clone())
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
            let (text, old_kind) = unseal(&cred_name(user), &blob).with_context(|| format!("unseal {}", sealed.display()))?;
            let t = Self::parse(&String::from_utf8_lossy(&text), &sealed, user)?;
            if let Some(t) = &t {
                if old_kind && self.sealing() == Sealing::Tpm {
                    // A system-scoped blob from the first cut: any local user
                    // could have asked PID 1 to open it. Re-seal root-only now.
                    match self.save(t) {
                        Ok(p) => log::info!("{}: re-sealed root-only", p.display()),
                        Err(e) => log::warn!("{}: could not re-seal root-only: {}", sealed.display(), e),
                    }
                    return Ok(Some(t.clone()));
                }
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
        if let (Some(t), Sealing::Tpm) = (&t, &self.sealing()) {
            // Found in the clear on a machine that can seal: seal it now.
            match self.save(t) {
                Ok(p) => log::info!("{}: sealed to the TPM as {}, plaintext removed", plain.display(), p.display()),
                Err(e) => log::warn!("{}: could not seal: {}", plain.display(), e),
            }
        }
        Ok(t)
    }

    /// Write atomically (temp file, fsync, rename) with mode 0600: sealed when
    /// this machine can, plaintext otherwise. Sealing removes the plaintext
    /// form; a plaintext write never removes a sealed file, and is refused
    /// outright when one exists (sticky sealing).
    pub fn save(&self, t: &UserTemplates) -> Result<PathBuf> {
        use std::os::unix::fs::OpenOptionsExt;
        if t.templates.len() > MAX_TEMPLATES {
            bail!("{} templates for {}; the limit is {} (delete some looks first)", t.templates.len(), t.user, MAX_TEMPLATES);
        }
        let sealed_path = self.sealed_path_for(&t.user)?;
        let plain_path = self.path_for(&t.user)?;
        let mut sealing = self.sealing();
        if let (Sealing::Plain(why), true) = (&sealing, sealed_path.exists()) {
            // Sealed templates exist and this process could not seal at
            // start: give the TPM one more chance, then refuse rather than
            // downgrade a sealed store to plaintext.
            let again = (self.probe)();
            if again == Sealing::Tpm {
                log::info!("sealing available again (was: {})", why);
                if let Ok(mut s) = self.sealing.lock() {
                    *s = Sealing::Tpm;
                }
                sealing = Sealing::Tpm;
            } else {
                bail!("templates for {} are sealed and this daemon cannot seal ({}); refusing to write them in plaintext", t.user, why);
            }
        }
        let json = serde_json::to_string(t)?;
        let (target, bytes, remove) = match &sealing {
            Sealing::Tpm => (sealed_path, seal(&cred_name(&t.user), json.as_bytes())?, Some(plain_path)),
            Sealing::Plain(_) => (plain_path, json.into_bytes(), None),
        };
        // A unique staging name per write: two saves for one user cannot
        // rename each other's partial file into place, and a failed write
        // leaves nothing behind.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let tmp = target.with_extension(format!("tmp-{}-{}", std::process::id(), SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
        struct Unlink<'a>(&'a Path, bool);
        impl Drop for Unlink<'_> {
            fn drop(&mut self) {
                if self.1 {
                    let _ = std::fs::remove_file(self.0);
                }
            }
        }
        let mut guard = Unlink(&tmp, true);
        {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &target)?;
        guard.1 = false;
        if let Some(other) = remove {
            if other.exists() {
                std::fs::remove_file(&other).with_context(|| format!("remove {}", other.display()))?;
            }
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

    /// Enrolment's recovery from a blob this machine can no longer open (a
    /// cleared TPM, a firmware reset, a corrupt file): set it aside as
    /// `<user>.cred.unreadable-<unix seconds>` so a fresh set can be written.
    /// Root-only by way of its only caller (enrolment), and never on the
    /// authentication path.
    pub fn set_aside_unreadable(&self, user: &str) -> Result<Option<PathBuf>> {
        let sealed = self.sealed_path_for(user)?;
        if !sealed.exists() {
            return Ok(None);
        }
        let aside = self.dir.join(format!("{}.cred.unreadable-{}", user, now_secs()));
        std::fs::rename(&sealed, &aside).with_context(|| format!("set aside {}", sealed.display()))?;
        if let Ok(mut c) = self.cache.lock() {
            c.remove(user);
        }
        Ok(Some(aside))
    }

    /// Users with templates on disk (sealed or plain): the accounts allowed
    /// to talk to the daemon's socket.
    pub fn enrolled_users(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.dir)
            .map(|rd| rd.flatten().filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".cred").or_else(|| n.strip_suffix(".json"))).map(String::from)).collect())
            .unwrap_or_default();
        v.sort();
        v.dedup();
        v
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

    #[test]
    fn everyday_movement_raises_a_floor_and_sets_the_margin() {
        // Reading bobs 0.05 vertically: 1.5x is 0.075, above the 0.06 default.
        let g = GestureCal { nod: vec![0.26, 0.30], shake: vec![0.33, 0.36], still_nod: vec![0.02, 0.05], still_shake: vec![0.03], ..Default::default() };
        let (n, s) = g.floors(0.06, 0.06);
        assert!((n - 0.09).abs() < 1e-6, "{}", n); // 0.28 * 0.4 = 0.112 capped 0.09; 0.075 from reading is below that
        assert!((s - 0.06).abs() < 1e-6, "{}", s);
        let (mn, ms) = g.margins();
        // "typical" is the upper median: 0.30 of [0.26, 0.30], 0.36 of [0.33, 0.36].
        assert!((mn.unwrap() - 0.30 / 0.05).abs() < 1e-3, "{:?}", mn);
        assert!((ms.unwrap() - 0.36 / 0.03).abs() < 1e-3, "{:?}", ms);
        // A restless reader: 0.10 vertical while reading pushes the nod floor to 0.15 (the cap).
        let restless = GestureCal { nod: vec![0.20], shake: vec![0.30], still_nod: vec![0.10, 0.12], still_shake: vec![0.09], ..Default::default() };
        let (n, s) = restless.floors(0.06, 0.06);
        assert!((n - 0.15).abs() < 1e-6, "{}", n); // 0.12 * 1.5 = 0.18 capped at 0.15
        assert!((s - 0.12).abs() < 1e-6, "{}", s); // 0.09 * 1.5 = 0.135 capped at 0.12
        assert!(restless.margins().0.unwrap() < 2.0, "not separable");
        // A record from before these rounds existed still reads.
        let old: GestureCal = serde_json::from_str(r#"{"nod":[0.2],"shake":[0.3]}"#).unwrap();
        assert!(old.still_nod.is_empty() && old.margins() == (None, None));
    }

    #[test]
    fn calibration_floors_only_tighten_the_nod_and_loosen_the_shake() {
        let none = GestureCal::default();
        assert_eq!(none.floors(0.06, 0.06), (0.06, 0.06));
        assert!(!none.is_calibrated());
        // A big nodder: floor rises to half the typical swing, capped.
        let big = GestureCal { nod: vec![0.30, 0.26, 0.40], shake: vec![0.20, 0.24], ..Default::default() };
        let (n, s) = big.floors(0.06, 0.06);
        assert!((n - 0.09).abs() < 1e-6, "{}", n); // 0.30 * 0.4 = 0.12, capped at 0.09
        assert!((s - 0.06).abs() < 1e-6, "{}", s); // 0.22 * 0.5 = 0.11 > default: stays at default
        // A light nodder: never below the default.
        let light = GestureCal { nod: vec![0.08, 0.09], shake: vec![0.08, 0.07], ..Default::default() };
        let (n, s) = light.floors(0.06, 0.06);
        assert!((n - 0.06).abs() < 1e-6, "{}", n);
        assert!((s - 0.04).abs() < 1e-6, "{}", s); // 0.08 * 0.5, above the 0.03 minimum
        // Stored with the templates and read back.
        let dir = temp("cal");
        let store = Store::open_with(&dir, Sealing::Plain("test".into())).unwrap();
        let mut u = UserTemplates::new("alice", "glintr100");
        u.uid = None;
        u.templates.push(tmpl(vec![1.0, 0.0], 1, None));
        u.gesture = light.clone();
        store.save(&u).unwrap();
        assert_eq!(store.load("alice").unwrap().unwrap().gesture, light);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn too_many_templates_is_a_named_error() {
        let dir = temp("cap");
        let store = Store::open_with(&dir, Sealing::Plain("test".into())).unwrap();
        let mut u = UserTemplates::new("alice", "glintr100");
        u.uid = None;
        for i in 0..=MAX_TEMPLATES as u64 {
            u.templates.push(tmpl(vec![1.0, 0.0], i, None));
        }
        let e = store.save(&u).unwrap_err().to_string();
        assert!(e.contains("limit is 40"), "{}", e);
        assert!(std::fs::read_dir(&dir).unwrap().next().is_none(), "nothing staged or written");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A store that cannot seal must not turn a sealed file into plaintext.
    #[test]
    fn a_plain_store_never_downgrades_a_sealed_file() {
        let dir = temp("sticky");
        // The re-probe must stay plain here: on a machine where PID 1 unseals
        // for any user, Sealing::detect() succeeds even in a user's test run.
        let store = Store::open_with_probe(&dir, Sealing::Plain("probe failed in this test".into()), || Sealing::Plain("still failing".into())).unwrap();
        let sealed = store.sealed_path_for("alice").unwrap();
        std::fs::write(&sealed, b"not a real blob").unwrap();
        let mut u = UserTemplates::new("alice", "glintr100");
        u.uid = None;
        u.templates.push(tmpl(vec![1.0, 0.0], 1, None));
        let e = store.save(&u).unwrap_err().to_string();
        assert!(e.contains("refusing to write them in plaintext"), "{}", e);
        assert!(sealed.exists(), "the sealed file must survive");
        assert!(!store.path_for("alice").unwrap().exists());
        // Loading it fails (it is not a blob), and enrolment's recovery sets it aside.
        assert!(store.load("alice").is_err());
        let aside = store.set_aside_unreadable("alice").unwrap().unwrap();
        assert!(aside.file_name().unwrap().to_string_lossy().starts_with("alice.cred.unreadable-"));
        assert!(!sealed.exists());
        assert!(store.load("alice").unwrap().is_none());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Runs the real thing when it can (root, TPM). Otherwise it is skipped,
    /// loudly, unless FACEAUTH_REQUIRE_TPM=1 (the release check), which makes
    /// a skip a failure.
    #[test]
    fn sealed_roundtrip_when_this_machine_can() {
        // As a user, the probe makes PID 1 ask polkit, which raises a consent
        // window on the desktop: only root probes.
        let sealing = if nix::unistd::geteuid().is_root() { Sealing::detect() } else { Sealing::Plain("not root".into()) };
        let Sealing::Tpm = sealing else {
            if std::env::var("FACEAUTH_REQUIRE_TPM").as_deref() == Ok("1") {
                panic!("FACEAUTH_REQUIRE_TPM=1 and this machine cannot seal: {}", sealing.describe());
            }
            eprintln!("SKIPPED (not a pass): {}", sealing.describe());
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
