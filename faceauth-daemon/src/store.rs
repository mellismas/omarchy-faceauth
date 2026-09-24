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
//! this machine, and on it only root can open it or forge one.
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
//! Every template names its camera and every set names the account's uid;
//! a file missing either is from before this was required, does not parse,
//! and reads as unreadable (re-enrol), never as a match.

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
/// size, sealed or not. One walk-through writes up to 34, so the cap holds
/// a full walk-through with a few older looks, and Add Look prunes to it.
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
    /// only matches on that camera. Required: a file without it does not
    /// parse, so no template ever matches on every camera.
    pub device: String,
    /// The head pose the frame was taken at (`pose::Pose` yaw and
    /// nose_pitch), recorded with the template for a later look at which
    /// poses a set covers; nothing reads them yet. None on templates from
    /// before pose was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yaw: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nose_pitch: Option<f32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserTemplates {
    pub version: u32,
    pub user: String,
    /// The account's uid when enrolled. A recreated account with the same name
    /// is a different person; a mismatch on load is treated as not enrolled.
    /// Required: a file without it does not parse, so the check always runs.
    pub uid: u32,
    /// Which recognition model produced these; a model change invalidates them.
    pub model: String,
    pub templates: Vec<Template>,
    /// This person's gesture rounds, recorded in the enrolment walk-through.
    #[serde(default)]
    pub gesture: GestureCal,
}

/// What the enrolment walk-through recorded of this person's gestures, in
/// degrees from the face mesh. The consent window's floors derive from
/// where each gesture round stops reading (`floors_deg`); the swings are
/// kept for the record. A record written before round-4 C3 also carries
/// the image-motion fields of the removed fallback detectors (`nod`,
/// `shake`, `everyday`, `nod_floor_min`, `shake_floor_min`, `still_nod`,
/// `still_shake`): it parses, sets no floor from them, and drops them on
/// the next save.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct GestureCal {
    /// Each nod round's largest pitch swing and each shake round's
    /// largest yaw swing, and every everyday round's swing on both axes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nod_deg: Vec<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shake_deg: Vec<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub everyday_deg: Vec<EverydayDeg>,
    /// Where each recorded gesture round stops reading: the highest floor,
    /// degrees, at which the walk-through's replay of that round through
    /// the mesh detector still counted it as its gesture. The floors
    /// derive from these, not from the swings above: the detector's first
    /// leg runs from rest, about half the peak-to-peak swing, so a fraction
    /// of the swing said nothing about where the round stops reading.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nod_reads_to_deg: Vec<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shake_reads_to_deg: Vec<f32>,
}

/// An everyday round on the mesh: its largest 1.5 s swing in yaw and in
/// pitch, degrees.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct EverydayDeg {
    pub kind: String,
    pub dyaw: f32,
    pub dpitch: f32,
}

impl GestureCal {
    /// The margin under where a person's own gestures stop reading: the
    /// reference user's shake-1 stops at 21 degrees and a lighter shake at
    /// the card is more exposed than the one made for the walk-through.
    pub const MESH_FLOOR_MARGIN: f32 = 0.85;
    /// Caps on a derived mesh floor. The reference rounds (`traces/v2`)
    /// stop reading at 15 degrees for both nods and at 21 for the lighter
    /// shake; a person whose rounds all read far higher still gets a floor
    /// no ordinary gesture would miss.
    pub const NOD_DEG_MAX: f32 = 16.0;
    pub const SHAKE_DEG_MAX: f32 = 24.0;

    /// The mesh detectors' floors, degrees, derived by replay: the highest
    /// floor at which every one of this person's recorded gesture rounds
    /// still reads, times `MESH_FLOOR_MARGIN`, never under the detector's
    /// own minimum nor over the cap. Nothing recorded means the defaults.
    pub fn floors_deg(&self, default_nod: f32, default_shake: f32) -> (f32, f32) {
        let derive = |reads_to: &[f32], default: f32, cap: f32| {
            reads_to
                .iter()
                .copied()
                .fold(None, |m, x| Some(m.map_or(x, |m: f32| m.min(x))))
                .map(|r| (r * Self::MESH_FLOOR_MARGIN).clamp(default, cap))
                .unwrap_or(default)
        };
        (
            derive(&self.nod_reads_to_deg, default_nod, Self::NOD_DEG_MAX),
            derive(&self.shake_reads_to_deg, default_shake, Self::SHAKE_DEG_MAX),
        )
    }

    /// The walk-through recorded at least one nod round and one shake
    /// round that read on the mesh: the person has floors of their own.
    pub fn is_calibrated(&self) -> bool {
        !self.nod_reads_to_deg.is_empty() && !self.shake_reads_to_deg.is_empty()
    }
}

impl UserTemplates {
    /// An empty set for `user`, who is `uid` now; the caller resolves the
    /// account so an unknown name fails there, not as a set with no uid.
    pub fn new(user: &str, uid: u32, model: &str) -> Self {
        UserTemplates {
            version: FORMAT_VERSION,
            user: user.to_string(),
            uid,
            model: model.to_string(),
            templates: Vec::new(),
            gesture: GestureCal::default(),
        }
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
        self.templates
            .iter()
            .filter(|t| t.usable_on(device))
            .count()
    }

    /// The cameras the templates are bound to, for a message.
    pub fn bound_devices(&self) -> Vec<String> {
        let mut v: Vec<String> = self.templates.iter().map(|t| t.device.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// A template whose mean similarity to the rest of the set is under
    /// this is not a look of the same person: the reference set agrees at
    /// 0.90 pairwise, an impostor's frame scores 0.37 to 0.56 against it,
    /// and a garbage crop lower still.
    pub const OUTLIER_MEAN: f32 = 0.5;
    /// A template from a frame the detector scored under this is a poor
    /// crop (the daemon's own floor for a face is 0.6).
    pub const QUALITY_FLOOR: f32 = 0.6;

    /// Trim the set to `max` templates, one at a time, and return how many
    /// went. The order matters: a set pruned by nearest neighbour alone
    /// keeps whatever is least like the rest, so an impostor's frame or a
    /// garbage crop is the last thing to go and the person's own looks go
    /// first. So each round drops, in this order, a template inconsistent
    /// with the set (mean similarity to the others under `OUTLIER_MEAN`),
    /// then one of poor quality (under `QUALITY_FLOOR`), and only then the
    /// template most similar to another (the surplus copy of a look the set
    /// already has), so what remains covers the widest range of looks.
    pub fn prune_to(&mut self, max: usize) -> usize {
        let mut removed = 0;
        while self.templates.len() > max.max(1) {
            let n = self.templates.len();
            let sim = |i: usize, j: usize| {
                faceauth_engine::cosine(&self.templates[i].embedding, &self.templates[j].embedding)
            };
            let mean_to_rest = |i: usize| {
                (0..n).filter(|&j| j != i).map(|j| sim(i, j)).sum::<f32>() / (n - 1) as f32
            };
            let outlier = (0..n)
                .map(|i| (i, mean_to_rest(i)))
                .filter(|&(_, m)| m < Self::OUTLIER_MEAN)
                .min_by(|a, b| a.1.total_cmp(&b.1))
                .map(|(i, _)| i);
            let poor = || {
                (0..n)
                    .map(|i| (i, self.templates[i].quality))
                    .filter(|&(_, q)| {
                        !q.partial_cmp(&Self::QUALITY_FLOOR)
                            .is_some_and(|o| o.is_ge())
                    })
                    .min_by(|a, b| a.1.total_cmp(&b.1))
                    .map(|(i, _)| i)
            };
            let duplicate = || {
                (0..n)
                    .map(|i| {
                        let nearest = (0..n)
                            .filter(|&j| j != i)
                            .map(|j| sim(i, j))
                            .fold(-1.0, f32::max);
                        (i, nearest)
                    })
                    .max_by(|a, b| a.1.total_cmp(&b.1))
                    .map(|(i, _)| i)
                    .unwrap_or(0)
            };
            let victim = outlier.or_else(poor).unwrap_or_else(duplicate);
            self.templates.remove(victim);
            removed += 1;
        }
        removed
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
                let s = faceauth_engine::cosine(
                    &self.templates[i].embedding,
                    &self.templates[j].embedding,
                );
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
        self.device == device
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
fn seal(bin: &Path, name: &str, plain: &[u8]) -> Result<Vec<u8>> {
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
fn unseal(bin: &Path, name: &str, blob: &[u8]) -> Result<Vec<u8>> {
    creds(
        bin,
        &["decrypt", "--uid=0", &format!("--name={}", name), "-", "-"],
        blob,
    )
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
    creds_bin: PathBuf,
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
    fn without_creds(mut self) -> Self {
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

    /// The camera every test template is bound to unless a test says otherwise.
    const CAM: &str = "ipu3:acpi:\\_SB_.PCI0.I2C3.CAM3";

    fn tmpl(e: Vec<f32>, created: u64, device: &str) -> Template {
        Template {
            embedding: e,
            quality: 0.9,
            face_width: 80.0,
            created,
            label: "enrol".into(),
            device: device.to_string(),
            yaw: None,
            nose_pitch: None,
        }
    }

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("faceauth-store-{}-{}", name, std::process::id()))
    }

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

    /// Every template matches only on the camera it names: a set bound to
    /// one camera has nothing to match on another, whatever the score,
    /// and a set spanning two cameras matches each embedding only on its
    /// own (H4, H5).
    #[test]
    fn templates_match_only_on_their_camera() {
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates
            .push(tmpl(vec![1.0, 0.0], 1, "ipu3:ov7251 3-0060"));
        u.templates
            .push(tmpl(vec![0.0, 1.0], 2, "uvc:uvcvideo:1-1:1234:abcd"));
        assert_eq!(u.usable_on("ipu3:ov7251 3-0060"), 1);
        assert_eq!(u.usable_on("uvc:uvcvideo:1-1:1234:abcd"), 1);
        assert_eq!(u.usable_on("uvc:uvcvideo:Other Cam:usb-1"), 0);
        assert_eq!(
            u.best_match_on(&[1.0, 0.0], "ipu3:ov7251 3-0060").unwrap(),
            (1.0, 0)
        );
        assert_eq!(
            u.best_match_on(&[1.0, 0.0], "uvc:uvcvideo:1-1:1234:abcd")
                .unwrap(),
            (0.0, 1),
            "the other camera's template is the only candidate there"
        );
        assert!(
            u.best_match_on(&[1.0, 0.0], "uvc:uvcvideo:Other Cam:usb-1")
                .is_none(),
            "a camera no template names matches nothing"
        );
        assert_eq!(
            u.bound_devices(),
            vec![
                "ipu3:ov7251 3-0060".to_string(),
                "uvc:uvcvideo:1-1:1234:abcd".to_string()
            ]
        );
        let only_bound = UserTemplates {
            templates: vec![tmpl(vec![1.0, 0.0], 1, "ipu3:x")],
            ..u.clone()
        };
        assert_eq!(only_bound.usable_on("uvc:y"), 0);
        assert!(only_bound.best_match_on(&[1.0, 0.0], "uvc:y").is_none());
        assert_eq!(
            only_bound.best_match_on(&[1.0, 0.0], "ipu3:x").unwrap(),
            (1.0, 0)
        );
    }

    /// A file from before the camera and the uid were required (the
    /// development laptop's, or one edited to drop them) does not load:
    /// `load` fails naming re-enrolment, and nothing in it can match on
    /// any camera (H5). A file with both loads.
    #[test]
    fn a_file_without_device_or_uid_does_not_load() {
        let dir = temp("legacy");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open_with(&dir, Sealing::Plain("test".into())).unwrap();
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates.push(tmpl(vec![1.0, 0.0], 1, CAM));
        let full = serde_json::to_string(&u).unwrap();
        let p = store.path_for("alice").unwrap();
        let without = |field: &str| -> String {
            let mut v: serde_json::Value = serde_json::from_str(&full).unwrap();
            match field {
                "uid" => {
                    v.as_object_mut().unwrap().remove("uid");
                }
                "device" => {
                    v["templates"][0].as_object_mut().unwrap().remove("device");
                }
                _ => unreachable!(),
            }
            serde_json::to_string(&v).unwrap()
        };
        for field in ["uid", "device"] {
            std::fs::write(&p, without(field)).unwrap();
            let err = match store.load("alice") {
                Err(e) => format!("{:#}", e),
                Ok(t) => panic!("a file without {} loaded: {:?}", field, t),
            };
            assert!(
                err.contains("re-enrol") && err.contains(field),
                "the error names the missing field and re-enrolment: {}",
                err
            );
        }
        std::fs::write(&p, &full).unwrap();
        let t = store.load("alice").unwrap().expect("a complete file loads");
        assert_eq!(t.uid, 1000);
        assert_eq!(t.best_match_on(&[1.0, 0.0], CAM).unwrap(), (1.0, 0));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A record from before round-4 C3 carries the image-motion fields of
    /// the fallback detectors: it still loads, sets no floor from them,
    /// and sheds them on the next save. Only the walk-through's replay
    /// results make a person calibrated, and they survive the store.
    #[test]
    fn a_record_with_the_image_motion_fields_still_loads_and_sets_no_floor() {
        let old: GestureCal = serde_json::from_str(
            r#"{"nod":[0.26,0.30],"shake":[0.33],"everyday":[{"kind":"read","dy":0.02,"dx":0.03}],"nod_floor_min":0.11,"shake_floor_min":0.05,"still_nod":[0.27],"still_shake":[0.5]}"#,
        )
        .unwrap();
        assert_eq!(old, GestureCal::default());
        assert!(!old.is_calibrated());
        assert_eq!(old.floors_deg(8.0, 15.0), (8.0, 15.0));
        let saved = serde_json::to_string(&old).unwrap();
        assert!(
            !saved.contains("nod_floor_min") && !saved.contains("still_nod"),
            "{}",
            saved
        );
        let cal = GestureCal {
            nod_deg: vec![34.7],
            shake_deg: vec![49.2],
            nod_reads_to_deg: vec![14.0],
            shake_reads_to_deg: vec![20.0],
            ..Default::default()
        };
        assert!(cal.is_calibrated());
        let dir = temp("cal");
        let store = Store::open_with(&dir, Sealing::Plain("test".into())).unwrap();
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        u.templates.push(tmpl(vec![1.0, 0.0], 1, CAM));
        u.gesture = cal.clone();
        store.save(&u).unwrap();
        assert_eq!(store.load("alice").unwrap().unwrap().gesture, cal);
        let _ = std::fs::remove_dir_all(dir);
    }

    fn unit(v: Vec<f32>) -> Vec<f32> {
        let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        v.iter().map(|x| x / n).collect()
    }

    /// Pruning drops the copies of a look the set already has and keeps
    /// the different ones. The looks here agree at 0.8 (a person with and
    /// without glasses, a turned head), as real looks of one face do.
    #[test]
    fn pruning_keeps_the_different_looks() {
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        let mk = |v: Vec<f32>, label: &str| Template {
            label: label.into(),
            ..tmpl(unit(v), 1, CAM)
        };
        u.templates.push(mk(vec![1.0, 0.0, 0.0], "a"));
        u.templates.push(mk(vec![1.0, 0.05, 0.0], "a-copy"));
        u.templates.push(mk(vec![1.0, -0.05, 0.0], "a-copy"));
        u.templates.push(mk(vec![0.8, 0.6, 0.0], "b"));
        u.templates.push(mk(vec![0.8, 0.0, 0.6], "c"));
        assert_eq!(u.prune_to(3), 2);
        let mut kept: Vec<&str> = u.templates.iter().map(|t| t.label.as_str()).collect();
        kept.sort();
        assert_eq!(
            kept,
            vec!["a", "b", "c"],
            "one of each look survives; the near copies go"
        );
        assert_eq!(u.prune_to(10), 0);
    }

    /// An impostor's frame and a garbage crop have no close neighbour, so a
    /// nearest-neighbour prune kept them and dropped the person's own looks.
    /// They go first now: the outlier, then the poor crop, then duplicates.
    #[test]
    fn pruning_drops_the_impostor_and_the_junk_before_the_person() {
        let mut u = UserTemplates::new("alice", 1000, "glintr100");
        let genuine = |v: Vec<f32>, label: &str| Template {
            label: label.into(),
            ..tmpl(unit(v), 1, CAM)
        };
        u.templates
            .push(genuine(vec![1.0, 0.0, 0.0, 0.0], "look-1"));
        u.templates
            .push(genuine(vec![1.0, 0.1, 0.0, 0.0], "look-1b"));
        u.templates
            .push(genuine(vec![0.9, 0.4, 0.0, 0.0], "look-2"));
        u.templates
            .push(genuine(vec![0.9, 0.0, 0.4, 0.0], "look-3"));
        u.templates.push(Template {
            label: "impostor".into(),
            ..tmpl(unit(vec![0.0, 0.0, 0.0, 1.0]), 1, CAM)
        });
        u.templates.push(Template {
            label: "junk".into(),
            quality: 0.31,
            ..tmpl(unit(vec![0.95, 0.3, 0.0, 0.0]), 1, CAM)
        });
        assert_eq!(u.prune_to(5), 1);
        assert!(
            u.templates.iter().all(|t| t.label != "impostor"),
            "the outlier goes first"
        );
        assert_eq!(u.prune_to(4), 1);
        assert!(
            u.templates.iter().all(|t| t.label != "junk"),
            "then the poor crop"
        );
        assert_eq!(u.prune_to(3), 1);
        let mut kept: Vec<&str> = u.templates.iter().map(|t| t.label.as_str()).collect();
        kept.sort();
        assert_eq!(kept, vec!["look-1", "look-2", "look-3"], "then a near copy");
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

    /// The mesh floors sit a margin under the lowest point at which any of
    /// the person's recorded rounds stops reading, never under the
    /// detector's minimum nor over the cap; the swings play no part.
    #[test]
    fn mesh_floors_sit_under_where_the_recorded_rounds_stop_reading() {
        let mut g = GestureCal::default();
        assert_eq!(
            g.floors_deg(8.0, 15.0),
            (8.0, 15.0),
            "nothing recorded: the defaults"
        );
        // The reference user's swings alone (the old input) change nothing.
        g.nod_deg = vec![34.7, 25.7];
        g.shake_deg = vec![49.2, 56.8];
        assert_eq!(g.floors_deg(8.0, 15.0), (8.0, 15.0));
        // The reference rounds: both nods read up to 14 degrees, the shakes
        // to 20 and past 26 (2026-09-24 replay).
        g.nod_reads_to_deg = vec![14.0, 14.0];
        g.shake_reads_to_deg = vec![26.0, 20.0];
        let (n, s) = g.floors_deg(8.0, 15.0);
        assert!(
            (n - 11.9).abs() < 0.01 && (s - 17.0).abs() < 0.01,
            "0.85 of the lowest drop-out: {} {}",
            n,
            s
        );
        // A round that reads only at the minimum keeps the floor there.
        g.nod_reads_to_deg = vec![14.0, 8.0];
        assert_eq!(g.floors_deg(8.0, 15.0).0, 8.0);
        g.nod_reads_to_deg = vec![80.0];
        g.shake_reads_to_deg = vec![120.0];
        assert_eq!(
            g.floors_deg(8.0, 15.0),
            (GestureCal::NOD_DEG_MAX, GestureCal::SHAKE_DEG_MAX),
            "capped so a light gesture still counts"
        );
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
