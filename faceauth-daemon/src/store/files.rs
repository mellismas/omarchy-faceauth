//! The store on disk: one file per user, loaded through a cache that
//! still checks the owner's uid, written through a staging file, and
//! deleted without a trace. Sealing is sticky: a sealed file is never
//! replaced by plaintext.

use super::seal::{cred_name, is_definitive, seal, unseal, Sealing, SYSTEMD_CREDS};
use super::templates::{UserTemplates, FORMAT_VERSION, MAX_TEMPLATES};
#[cfg(test)]
use super::test_support::{temp, tmpl, CAM};
use anyhow::{bail, Context, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

#[derive(Clone, PartialEq)]
struct Fingerprint {
    path: PathBuf,
    len: u64,
    mtime: Option<std::time::SystemTime>,
}

fn fingerprint(p: &Path) -> Result<Fingerprint> {
    let m = std::fs::metadata(p)?;
    Ok(Fingerprint {
        path: p.to_path_buf(),
        len: m.len(),
        mtime: m.modified().ok(),
    })
}

pub struct Store {
    dir: PathBuf,
    /// Fixed at open, except that a store which failed its probe re-tries
    /// once before it would otherwise write plaintext over a sealed file.
    sealing: Mutex<Sealing>,
    /// How to re-probe sealing (tests inject one that stays plain).
    probe: fn() -> Sealing,
    /// The credential tool. Tests point it at /bin/false: an unseal from a
    /// user's test run makes PID 1 ask polkit, which puts a real consent
    /// window on the desktop.
    pub(super) creds_bin: PathBuf,
    /// Unsealing costs about a second of TPM time; templates are cached per
    /// user against the file they came from, so an attempt pays it only when
    /// the file changed.
    cache: Mutex<HashMap<String, (Fingerprint, UserTemplates)>>,
    /// The account's uid by name (getpwnam for the daemon; tests inject one
    /// they can change). Read on every load, cache hits included: a name
    /// that now belongs to another uid is not enrolled, whatever is cached.
    uid_of: fn(&str) -> Option<u32>,
}

impl Store {
    /// Open the store, detecting whether this machine can seal.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(dir, Sealing::detect())
    }

    pub fn open_with(dir: impl AsRef<Path>, sealing: Sealing) -> Result<Self> {
        Self::open_with_probe(dir, sealing, Sealing::detect)
    }

    pub fn open_with_probe(
        dir: impl AsRef<Path>,
        sealing: Sealing,
        probe: fn() -> Sealing,
    ) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(Store {
            dir,
            sealing: Mutex::new(sealing),
            probe,
            creds_bin: PathBuf::from(SYSTEMD_CREDS),
            cache: Mutex::new(HashMap::new()),
            uid_of: current_uid,
        })
    }

    /// A store that resolves account names through `f` instead of the
    /// password database.
    #[cfg(test)]
    fn with_uid_resolver(mut self, f: fn(&str) -> Option<u32>) -> Self {
        self.uid_of = f;
        self
    }

    /// A store whose credential tool always fails: for tests that must
    /// never reach the credential service.
    #[cfg(test)]
    pub(super) fn without_creds(mut self) -> Self {
        self.creds_bin = PathBuf::from("/bin/false");
        self
    }

    pub fn sealing(&self) -> Sealing {
        self.sealing
            .lock()
            .map(|s| s.clone())
            .unwrap_or_else(|p| p.into_inner().clone())
    }

    fn check_user(user: &str) -> Result<()> {
        if user.is_empty()
            || user.contains('/')
            || user.contains("..")
            || user.chars().any(|c| c.is_control() || c.is_whitespace())
        {
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
        self.sealed_path_for(user)
            .map(|p| p.exists())
            .unwrap_or(false)
    }

    fn parse(&self, text: &str, p: &Path, user: &str) -> Result<Option<UserTemplates>> {
        // A file that does not parse is unreadable, whatever it lacks: a
        // record from before the camera and the uid were required is
        // re-enrolled, never read with the checks those fields carry
        // skipped (H5).
        let t: UserTemplates = serde_json::from_str(text).with_context(|| {
            format!(
                "parse {}: not a template set this build reads; re-enrol",
                p.display()
            )
        })?;
        if t.version != FORMAT_VERSION {
            bail!(
                "{}: template format {} (this build reads {})",
                p.display(),
                t.version,
                FORMAT_VERSION
            );
        }
        if t.user != user {
            bail!(
                "{}: templates are for {:?}, not {:?}",
                p.display(),
                t.user,
                user
            );
        }
        Ok(if self.uid_matches(&t, p) {
            Some(t)
        } else {
            None
        })
    }

    /// Is the account these templates were enrolled under still the one
    /// that has the name? A recreated account with the same name is a
    /// different person. Checked on every load, so a cached set for a
    /// name that changed hands is not enrolled either (F1). A name the
    /// password database no longer has cannot log in at all, so it is
    /// left to the caller rather than refused here.
    fn uid_matches(&self, t: &UserTemplates, p: &Path) -> bool {
        if let Some(now) = (self.uid_of)(&t.user) {
            if t.uid != now {
                log::warn!(
                    "{}: templates belong to uid {} but {} is now uid {}; treating as not enrolled",
                    p.display(),
                    t.uid,
                    t.user,
                    now
                );
                return false;
            }
        }
        true
    }

    pub fn load(&self, user: &str) -> Result<Option<UserTemplates>> {
        let sealed = self.sealed_path_for(user)?;
        let plain = self.path_for(user)?;
        if sealed.exists() {
            let fp = fingerprint(&sealed)?;
            let cached = self.cache.lock().ok().and_then(|c| {
                c.get(user)
                    .filter(|(have, _)| *have == fp)
                    .map(|(_, t)| t.clone())
            });
            if let Some(t) = cached {
                return Ok(if self.uid_matches(&t, &sealed) {
                    Some(t)
                } else {
                    None
                });
            }
            let blob =
                std::fs::read(&sealed).with_context(|| format!("read {}", sealed.display()))?;
            let text = unseal(&self.creds_bin, &cred_name(user), &blob)
                .with_context(|| format!("unseal {}", sealed.display()))?;
            let t = self.parse(&String::from_utf8_lossy(&text), &sealed, user)?;
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
        let text =
            std::fs::read_to_string(&plain).with_context(|| format!("read {}", plain.display()))?;
        let t = self.parse(&text, &plain, user)?;
        if let (Some(t), Sealing::Tpm) = (&t, &self.sealing()) {
            // Found in the clear on a machine that can seal: seal it now.
            match self.save(t) {
                Ok(p) => log::info!(
                    "{}: sealed to the TPM as {}, plaintext removed",
                    plain.display(),
                    p.display()
                ),
                Err(e) => log::warn!("{}: could not seal: {}", plain.display(), e),
            }
        }
        Ok(t)
    }

    /// Write atomically (temp file, fsync, rename, directory fsync) with
    /// mode 0600: sealed when this machine can, plaintext otherwise. Sealing
    /// removes the plaintext form; a plaintext write never removes a sealed
    /// file, and is refused outright when one exists (sticky sealing). A
    /// staging file another process of this daemon left behind (a crash
    /// between create and rename) is removed first. A non-finite number is
    /// refused: JSON has no spelling for it, serde writes `null`, and the
    /// whole set would then fail to parse.
    pub fn save(&self, t: &UserTemplates) -> Result<PathBuf> {
        use std::os::unix::fs::OpenOptionsExt;
        if t.templates.len() > MAX_TEMPLATES {
            bail!(
                "{} templates for {}; the limit is {} (delete some looks first)",
                t.templates.len(),
                t.user,
                MAX_TEMPLATES
            );
        }
        if let Some(what) = non_finite_field(t) {
            bail!(
                "templates for {}: {} is not a finite number; refusing to write an unreadable set",
                t.user,
                what
            );
        }
        self.remove_stale_temps(&t.user, Some(std::process::id()))?;
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
            Sealing::Tpm => (
                sealed_path,
                seal(&self.creds_bin, &cred_name(&t.user), json.as_bytes())?,
                Some(plain_path),
            ),
            Sealing::Plain(_) => (plain_path, json.into_bytes(), None),
        };
        // A unique staging name per write: two saves for one user cannot
        // rename each other's partial file into place, and a failed write
        // leaves nothing behind.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let tmp = target.with_extension(format!(
            "tmp-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
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
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &target)?;
        guard.1 = false;
        if let Some(other) = remove {
            if other.exists() {
                std::fs::remove_file(&other)
                    .with_context(|| format!("remove {}", other.display()))?;
            }
        }
        // The rename and the unlink are directory entries; without a sync
        // of the directory a power cut can leave either name, or both.
        std::fs::File::open(&self.dir)
            .and_then(|d| d.sync_all())
            .with_context(|| format!("sync {}", self.dir.display()))?;
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

    /// Remove `<user>.tmp-<pid>-<n>` staging files, which a crash between
    /// create and rename leaves behind; those of `keep_pid` (a save in
    /// progress by this process) stay.
    fn remove_stale_temps(&self, user: &str, keep_pid: Option<u32>) -> Result<()> {
        Self::check_user(user)?;
        let prefix = format!("{}.tmp-", user);
        let keep = keep_pid.map(|p| format!("{}.tmp-{}-", user, p));
        for e in std::fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            let name = e.file_name();
            let Some(n) = name.to_str() else { continue };
            if !n.starts_with(&prefix) || keep.as_deref().is_some_and(|k| n.starts_with(k)) {
                continue;
            }
            std::fs::remove_file(e.path())
                .with_context(|| format!("remove stale {}", e.path().display()))?;
            log::warn!("{}: stale staging file removed", e.path().display());
        }
        Ok(())
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
        self.check_can_replace(user)?;
        let aside = self
            .dir
            .join(format!("{}.cred.unreadable-{}", user, now_secs()));
        std::fs::rename(&sealed, &aside)
            .with_context(|| format!("set aside {}", sealed.display()))?;
        if let Ok(mut c) = self.cache.lock() {
            c.remove(user);
        }
        Ok(Some(aside))
    }

    /// Enrolment's recovery, narrowed to what it is for: the blob goes aside
    /// only when `e` is the credential tool's verdict on it (or a parse
    /// failure of what it decrypted). A TPM that is busy, missing from the
    /// sandbox, or slow is not a reason to discard a good set (F2).
    pub fn set_aside_if_unreadable(
        &self,
        user: &str,
        e: &anyhow::Error,
    ) -> Result<Option<PathBuf>> {
        if !is_definitive(e) {
            return Ok(None);
        }
        self.set_aside_unreadable(user)
    }

    /// May a fresh set be written for this user? Not when sealed templates
    /// exist and this store cannot seal: writing plaintext beside them, or
    /// after setting them aside, would be the downgrade sticky sealing
    /// refuses. Delete the templates first, deliberately (F2).
    pub fn check_can_replace(&self, user: &str) -> Result<()> {
        if let (Sealing::Plain(why), true) = (self.sealing(), self.is_sealed(user)) {
            bail!("templates for {} are sealed and this daemon cannot seal ({}); enrolment refused rather than downgrade them to plaintext. Delete them first if that is intended", user, why);
        }
        Ok(())
    }

    /// The one way an enrolment opens a user's set, terminal or
    /// walk-through: the store must be allowed to replace what it holds
    /// (`check_can_replace`), and a set it cannot read goes aside only on
    /// the credential tool's own verdict. A TPM that is busy, unreachable
    /// or slow keeps the good set, and the enrolment fails instead of
    /// starting over with nothing (F2, on both paths).
    pub fn open_for_enrolment(&self, user: &str) -> Result<Option<UserTemplates>> {
        self.check_can_replace(user)?;
        match self.load(user) {
            Ok(t) => Ok(t),
            Err(e) => match self.set_aside_if_unreadable(user, &e)? {
                Some(aside) => {
                    log::warn!("enrolment for {}: existing templates unreadable ({}); set aside as {} and starting fresh", user, e, aside.display());
                    Ok(None)
                }
                None => Err(e),
            },
        }
    }

    /// Users with templates on disk (sealed or plain): the accounts allowed
    /// to talk to the daemon's socket.
    pub fn enrolled_users(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.dir)
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| {
                        e.file_name()
                            .to_str()
                            .and_then(|n| {
                                n.strip_suffix(".cred").or_else(|| n.strip_suffix(".json"))
                            })
                            .map(String::from)
                    })
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v.dedup();
        v
    }

    /// The directory a user's gesture recordings go in (dev-tools builds
    /// only): a directory per user, so a delete takes exactly that user's
    /// files and never a neighbour's whose name shares a prefix.
    pub fn gestures_dir_for(&self, user: &str) -> Result<PathBuf> {
        Self::check_user(user)?;
        Ok(self.dir.join("gestures").join(user))
    }

    /// The directory a user's walk-through frame recordings go in
    /// (dev-tools builds only, raw IR frames): per user, like the gestures.
    pub fn record_dir_for(&self, user: &str) -> Result<PathBuf> {
        Self::check_user(user)?;
        Ok(self.dir.join("record").join(user))
    }

    /// Remove everything the store holds about a user: the templates, sealed
    /// or plain, any set-aside blob (`<user>.cred.unreadable-*`), any
    /// staging file a crash left, the gesture recordings (`gestures/<user>/`)
    /// and the walk-through's frame recordings (`record/<user>/`). True when
    /// templates were there.
    pub fn delete(&self, user: &str) -> Result<bool> {
        Self::check_user(user)?;
        self.remove_stale_temps(user, None)?;
        let mut any = false;
        for p in [self.sealed_path_for(user)?, self.path_for(user)?] {
            if p.exists() {
                std::fs::remove_file(&p)?;
                any = true;
            }
        }
        let aside_prefix = format!("{}.cred.unreadable-", user);
        for e in std::fs::read_dir(&self.dir).into_iter().flatten().flatten() {
            let name = e.file_name();
            let Some(n) = name.to_str() else { continue };
            if n.starts_with(&aside_prefix) {
                std::fs::remove_file(e.path())
                    .with_context(|| format!("remove {}", e.path().display()))?;
            }
        }
        for dir in [self.gestures_dir_for(user)?, self.record_dir_for(user)?] {
            if dir.is_dir() {
                std::fs::remove_dir_all(&dir)
                    .with_context(|| format!("remove {}", dir.display()))?;
            }
        }
        if let Ok(mut c) = self.cache.lock() {
            c.remove(user);
        }
        Ok(any)
    }
}

/// The first non-finite number in a set, named, or None when every float
/// in it can be written as JSON.
fn non_finite_field(t: &UserTemplates) -> Option<String> {
    for (i, tp) in t.templates.iter().enumerate() {
        if tp.embedding.iter().any(|v| !v.is_finite()) {
            return Some(format!("template {} embedding", i));
        }
        if !tp.quality.is_finite() || !tp.face_width.is_finite() {
            return Some(format!("template {} quality or face_width", i));
        }
        if tp.yaw.is_some_and(|v| !v.is_finite()) || tp.nose_pitch.is_some_and(|v| !v.is_finite()) {
            return Some(format!("template {} pose", i));
        }
    }
    let g = &t.gesture;
    let floats = g
        .nod_deg
        .iter()
        .chain(&g.shake_deg)
        .chain(&g.nod_reads_to_deg)
        .chain(&g.shake_reads_to_deg)
        .chain(g.everyday_deg.iter().flat_map(|e| [&e.dyaw, &e.dpitch]));
    if floats.into_iter().any(|v| !v.is_finite()) {
        return Some("gesture calibration".into());
    }
    None
}

pub fn current_uid(user: &str) -> Option<u32> {
    nix::unistd::User::from_name(user)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn roundtrip_and_match_plain() {
        let dir = temp("plain");
        let store = Store::open_with(&dir, Sealing::Plain("test".into())).unwrap();
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates.push(tmpl(vec![1.0, 0.0], 1, CAM));
        u.templates.push(tmpl(vec![0.0, 1.0], 2, CAM));
        let p = store.save(&u).unwrap();
        assert!(p.ends_with("alice.json"));
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
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
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates.push(tmpl(vec![1.0, 0.0], 1, CAM));
        store.save(&u).unwrap();
        std::fs::rename(dir.join("alice.json"), dir.join("bob.json")).unwrap();
        assert!(store.load("bob").is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A staging file a crash left behind is removed by the next save and
    /// by delete; a non-finite number is refused rather than written as
    /// `null`.
    #[test]
    fn stale_staging_files_are_removed_and_non_finite_values_refused() {
        let dir = temp("stale");
        let store = Store::open_with(&dir, Sealing::Plain("test".into())).unwrap();
        std::fs::write(dir.join("alice.tmp-1-0"), b"half").unwrap();
        std::fs::write(dir.join("alice.tmp-2-7"), b"half").unwrap();
        std::fs::write(dir.join("alicia.tmp-3-0"), b"hers").unwrap();
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates.push(tmpl(vec![1.0, 0.0], 1, "cam"));
        store.save(&u).unwrap();
        assert!(!dir.join("alice.tmp-1-0").exists() && !dir.join("alice.tmp-2-7").exists());
        assert!(
            dir.join("alicia.tmp-3-0").exists(),
            "a neighbour's file is not touched"
        );
        std::fs::write(dir.join("alice.tmp-9-0"), b"half").unwrap();
        assert!(store.delete("alice").unwrap());
        assert!(!dir.join("alice.tmp-9-0").exists());
        let mut bad = UserTemplates::new("alice", 1000, "glintr100");
        bad.templates.push(tmpl(vec![f32::NAN, 0.0], 1, "cam"));
        let e = store.save(&bad).unwrap_err().to_string();
        assert!(e.contains("not a finite number"), "{}", e);
        assert!(!dir.join("alice.json").exists());
        let mut bad = UserTemplates::new("alice", 1000, "glintr100");
        bad.templates.push(tmpl(vec![1.0, 0.0], 1, "cam"));
        bad.gesture.nod_reads_to_deg = vec![f32::INFINITY];
        assert!(store.save(&bad).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn too_many_templates_is_a_named_error() {
        let dir = temp("cap");
        let store = Store::open_with(&dir, Sealing::Plain("test".into())).unwrap();
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        for i in 0..=MAX_TEMPLATES as u64 {
            u.templates.push(tmpl(vec![1.0, 0.0], i, CAM));
        }
        let e = store.save(&u).unwrap_err().to_string();
        assert!(e.contains("limit is 40"), "{}", e);
        assert!(
            std::fs::read_dir(&dir).unwrap().next().is_none(),
            "nothing staged or written"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A cached set is re-checked against the account on every hit: the
    /// name changing hands reads as not enrolled without a restart (F1).
    #[test]
    fn a_cache_hit_still_checks_the_uid() {
        static UID: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1000);
        fn resolver(_: &str) -> Option<u32> {
            Some(UID.load(std::sync::atomic::Ordering::SeqCst))
        }
        let dir = temp("cacheuid");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open_with(&dir, Sealing::Plain("test".into()))
            .unwrap()
            .without_creds()
            .with_uid_resolver(resolver);
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates.push(tmpl(vec![1.0, 0.0], 1, CAM));
        // The sealed path is the cached one: stage a "sealed" file and seed
        // the cache the way a successful unseal would, with the fingerprint
        // of that file.
        let sealed = store.sealed_path_for("alice").unwrap();
        std::fs::write(&sealed, b"blob").unwrap();
        let fp = fingerprint(&sealed).unwrap();
        store
            .cache
            .lock()
            .unwrap()
            .insert("alice".into(), (fp, u.clone()));
        assert!(
            store.load("alice").unwrap().is_some(),
            "the cached set serves while the uid holds"
        );
        UID.store(1001, std::sync::atomic::Ordering::SeqCst);
        assert!(
            store.load("alice").unwrap().is_none(),
            "the same name on another uid is not enrolled, cache or no cache"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Deleting a user takes the set-aside blobs, the gesture recordings
    /// and the walk-through recordings with the templates, and nobody
    /// else's: not a neighbour whose name extends theirs ("alice") nor one
    /// that adds a hyphen ("al-x") (F5, round-4 F4).
    #[test]
    fn delete_removes_every_trace_of_the_user_and_only_theirs() {
        let dir = temp("deleteall");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open_with(&dir, Sealing::Plain("test".into()))
            .unwrap()
            .without_creds();
        let mut u = UserTemplates::new("al", 1000, "glintr100");
        u.templates.push(tmpl(vec![1.0, 0.0], 1, CAM));
        store.save(&u).unwrap();
        std::fs::write(dir.join("al.cred.unreadable-1700000000"), b"x").unwrap();
        std::fs::write(dir.join("alice.cred.unreadable-1700000000"), b"x").unwrap();
        for user in ["al", "alice", "al-x"] {
            let g = store.gestures_dir_for(user).unwrap();
            std::fs::create_dir_all(&g).unwrap();
            std::fs::write(g.join("1700000001-nodded.txt"), b"x").unwrap();
            std::fs::write(g.join("1700000002-v2-nod-1.txt"), b"x").unwrap();
            let r = store.record_dir_for(user).unwrap();
            std::fs::create_dir_all(&r).unwrap();
            std::fs::write(r.join("012.40_yaw-0.120_pitch0.610.pgm"), b"P5\n").unwrap();
        }
        assert!(store.delete("al").unwrap());
        let left: Vec<String> = walk(&dir);
        assert_eq!(
            left,
            vec![
                "alice.cred.unreadable-1700000000",
                "gestures/al-x/1700000001-nodded.txt",
                "gestures/al-x/1700000002-v2-nod-1.txt",
                "gestures/alice/1700000001-nodded.txt",
                "gestures/alice/1700000002-v2-nod-1.txt",
                "record/al-x/012.40_yaw-0.120_pitch0.610.pgm",
                "record/alice/012.40_yaw-0.120_pitch0.610.pgm",
            ],
            "{:?}",
            left
        );
        assert!(!store.delete("al").unwrap(), "nothing left to delete");
        assert!(
            store.gestures_dir_for("../x").is_err() && store.record_dir_for("a/b").is_err(),
            "a recording directory is never outside the store"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    fn walk(dir: &Path) -> Vec<String> {
        let mut v = Vec::new();
        fn go(root: &Path, d: &Path, v: &mut Vec<String>) {
            for e in std::fs::read_dir(d).unwrap().flatten() {
                let p = e.path();
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                if p.is_dir() {
                    let before = v.len();
                    go(root, &p, v);
                    if v.len() == before {
                        v.push(rel);
                    }
                } else {
                    v.push(rel);
                }
            }
        }
        go(dir, dir, &mut v);
        v.sort();
        v
    }
}
