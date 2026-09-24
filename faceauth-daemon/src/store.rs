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
    /// The head pose the frame was taken at (`pose::Pose` yaw and
    /// nose_pitch), so an identity can be seen to cover the range of looks
    /// a person uses. None on templates from before pose was recorded.
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
    /// Everyday-movement rounds: what the person does when not gesturing,
    /// each with its largest vertical and horizontal excursion.
    #[serde(default)]
    pub everyday: Vec<EverydayRound>,
    /// Floors the verify step found necessary so that this person's
    /// everyday rounds read as nothing when replayed through the detectors;
    /// a floor never sits below its own. None until a session has been
    /// verified.
    #[serde(default)]
    pub nod_floor_min: Option<f32>,
    #[serde(default)]
    pub shake_floor_min: Option<f32>,
    /// The same rounds on the face mesh, in degrees: each nod's largest
    /// pitch swing, each shake's largest yaw swing, and every everyday
    /// round's swing on both axes. The mesh detectors take their floors
    /// from these; the fields above stay for the image-motion detectors.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nod_deg: Vec<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shake_deg: Vec<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub everyday_deg: Vec<EverydayDeg>,
    /// From a short-lived earlier format that kept only the numbers; ignored
    /// once `everyday` has rounds, and dropped on the next save.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub still_nod: Vec<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub still_shake: Vec<f32>,
}

/// An everyday round on the mesh: its largest 1.5 s swing in yaw and in
/// pitch, degrees.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct EverydayDeg {
    pub kind: String,
    pub dyaw: f32,
    pub dpitch: f32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct EverydayRound {
    pub kind: String,
    pub dy: f32,
    pub dx: f32,
}

/// The everyday rounds whose size is worth reporting against the gestures:
/// the small, jittery ones. A glance at the keyboard, a lean-in and a look
/// aside are as big as a gesture and are refused by the detector's shape
/// rules (one leg, a hold at the bottom or the side), not by size. No
/// round's size raises a floor by itself: the verify step replays every
/// round through the detectors, and raises a floor only when an everyday
/// round reads as a gesture, only as far as it takes.
pub const FLOOR_KINDS: [&str; 2] = ["read", "talk"];

impl GestureCal {
    fn typical(v: &[f32]) -> Option<f32> {
        if v.is_empty() {
            return None;
        }
        let mut s = v.to_vec();
        s.sort_by(|a, b| a.total_cmp(b));
        Some(s[s.len() / 2])
    }

    /// How far the verify step may raise a floor to keep everyday movement
    /// from reading as a gesture. Past this the person's own gestures would
    /// go with it, and the check says so instead.
    pub const NOD_FLOOR_MAX: f32 = 0.15;
    pub const SHAKE_FLOOR_MAX: f32 = 0.12;

    fn largest(v: &[f32]) -> Option<f32> {
        v.iter()
            .copied()
            .fold(None, |m, x| Some(m.map_or(x, |m: f32| m.max(x))))
    }

    /// (nod floor, shake floor) for this person, given the defaults.
    pub fn floors(&self, default_nod: f32, default_shake: f32) -> (f32, f32) {
        // 0.4 of the peak-to-peak, capped: the detector sees single legs, which
        // run 0.14 to 0.21 on a 0.26 nod (recorded), and the floor must sit
        // clearly under the smallest of them.
        // Capped at 0.09: on the reference user's recording, both nods count
        // at every floor up to 0.09 and one drops out at 0.10 (its first
        // departure from rest is the small leg).
        let mut nod = Self::typical(&self.nod)
            .map(|a| (a * 0.4).clamp(default_nod, 0.09))
            .unwrap_or(default_nod);
        let mut shake = Self::typical(&self.shake)
            .map(|a| (a * 0.5).clamp(0.03, default_shake))
            .unwrap_or(default_shake);
        // Everyday movement pushes a floor up, never down: what the verify
        // step found necessary for this person's own rounds to read as nothing.
        if let Some(m) = self.nod_floor_min {
            nod = nod.max(m.min(Self::NOD_FLOOR_MAX));
        }
        if let Some(m) = self.shake_floor_min {
            shake = shake.max(m.min(Self::SHAKE_FLOOR_MAX));
        }
        (nod, shake)
    }

    /// The mesh detectors' floors, degrees: 0.4 of this person's typical
    /// gesture swing, never under the detector's own minimum nor over a
    /// cap that would lose a light gesture (recorded 2026-09-24: nods 26
    /// to 35 degrees peak to peak with legs from 12; shakes 49 to 57 with
    /// legs from 33).
    pub fn floors_deg(&self, default_nod: f32, default_shake: f32) -> (f32, f32) {
        let nod = Self::typical(&self.nod_deg)
            .map(|a| (a * 0.4).clamp(default_nod, 16.0))
            .unwrap_or(default_nod);
        let shake = Self::typical(&self.shake_deg)
            .map(|a| (a * 0.4).clamp(default_shake, 24.0))
            .unwrap_or(default_shake);
        (nod, shake)
    }

    /// The floors with no everyday adjustment: the starting point the
    /// verify step raises from.
    pub fn base_floors(&self, default_nod: f32, default_shake: f32) -> (f32, f32) {
        let nod = Self::typical(&self.nod)
            .map(|a| (a * 0.4).clamp(default_nod, 0.09))
            .unwrap_or(default_nod);
        let shake = Self::typical(&self.shake)
            .map(|a| (a * 0.5).clamp(0.03, default_shake))
            .unwrap_or(default_shake);
        (nod, shake)
    }

    /// The largest vertical and horizontal excursion among the jittery
    /// everyday rounds (`FLOOR_KINDS`), the ones a floor stands clear of.
    fn jitter(&self) -> (Option<f32>, Option<f32>) {
        let rounds: Vec<&EverydayRound> = self
            .everyday
            .iter()
            .filter(|r| FLOOR_KINDS.contains(&r.kind.as_str()))
            .collect();
        let ys: Vec<f32> = rounds.iter().map(|r| r.dy).collect();
        let xs: Vec<f32> = rounds.iter().map(|r| r.dx).collect();
        (Self::largest(&ys), Self::largest(&xs))
    }

    /// How many times larger this person's typical gesture is than their
    /// largest everyday movement on the same axis, per axis; None until both
    /// have been recorded. Under 2.0 the two are not cleanly separable and
    /// the setup says so.
    pub fn margins(&self) -> (Option<f32>, Option<f32>) {
        let (sy, sx) = self.jitter();
        let m = |g: &[f32], s: Option<f32>| match (Self::typical(g), s) {
            (Some(g), Some(s)) if s > 0.0 => Some(g / s),
            (Some(_), Some(_)) => Some(f32::INFINITY),
            _ => None,
        };
        (m(&self.nod, sy), m(&self.shake, sx))
    }

    pub fn is_calibrated(&self) -> bool {
        !self.nod.is_empty() && !self.shake.is_empty()
    }
}

impl UserTemplates {
    pub fn new(user: &str, model: &str) -> Self {
        UserTemplates {
            version: FORMAT_VERSION,
            user: user.to_string(),
            uid: current_uid(user),
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
        let mut v: Vec<String> = self
            .templates
            .iter()
            .filter_map(|t| t.device.clone())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// Pairwise similarity statistics of the stored templates: (min, mean, max).
    /// Trim the set to `max` templates by dropping, one at a time, the
    /// template most similar to another (the surplus copy of a look the set
    /// already has), so what remains covers the widest range of looks. The
    /// number removed is returned.
    pub fn prune_to(&mut self, max: usize) -> usize {
        let mut removed = 0;
        while self.templates.len() > max.max(1) {
            let n = self.templates.len();
            let mut worst = (0usize, -1.0f32);
            for i in 0..n {
                let nearest = (0..n)
                    .filter(|&j| j != i)
                    .map(|j| {
                        faceauth_engine::cosine(
                            &self.templates[i].embedding,
                            &self.templates[j].embedding,
                        )
                    })
                    .fold(-1.0, f32::max);
                if nearest > worst.1 {
                    worst = (i, nearest);
                }
            }
            self.templates.remove(worst.0);
            removed += 1;
        }
        removed
    }

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
        match seal(Path::new(SYSTEMD_CREDS), "faceauth-probe", b"probe")
            .and_then(|blob| unseal(Path::new(SYSTEMD_CREDS), "faceauth-probe", &blob))
        {
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

/// Unseal a blob. Returns the bytes and whether the blob was of the older,
/// system-scoped kind (which the caller should re-seal).
fn unseal(bin: &Path, name: &str, blob: &[u8]) -> Result<(Vec<u8>, bool)> {
    match creds(
        bin,
        &["decrypt", "--uid=0", &format!("--name={}", name), "-", "-"],
        blob,
    ) {
        Ok(b) => Ok((b, false)),
        Err(e) if e.to_string().contains("scoped to the system") => Ok((
            creds(
                bin,
                &["decrypt", &format!("--name={}", name), "-", "-"],
                blob,
            )?,
            true,
        )),
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
        let t: UserTemplates =
            serde_json::from_str(text).with_context(|| format!("parse {}", p.display()))?;
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
    /// name that changed hands is not enrolled either (F1).
    fn uid_matches(&self, t: &UserTemplates, p: &Path) -> bool {
        if let (Some(stored), Some(now)) = (t.uid, (self.uid_of)(&t.user)) {
            if stored != now {
                log::warn!(
                    "{}: templates belong to uid {} but {} is now uid {}; treating as not enrolled",
                    p.display(),
                    stored,
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
            let (text, old_kind) = unseal(&self.creds_bin, &cred_name(user), &blob)
                .with_context(|| format!("unseal {}", sealed.display()))?;
            let t = self.parse(&String::from_utf8_lossy(&text), &sealed, user)?;
            if let Some(t) = &t {
                if old_kind && self.sealing() == Sealing::Tpm {
                    // A system-scoped blob from the first cut: any local user
                    // could have asked PID 1 to open it. Re-seal root-only now.
                    match self.save(t) {
                        Ok(p) => log::info!("{}: re-sealed root-only", p.display()),
                        Err(e) => {
                            log::warn!("{}: could not re-seal root-only: {}", sealed.display(), e)
                        }
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

    /// Write atomically (temp file, fsync, rename) with mode 0600: sealed when
    /// this machine can, plaintext otherwise. Sealing removes the plaintext
    /// form; a plaintext write never removes a sealed file, and is refused
    /// outright when one exists (sticky sealing).
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

    /// Remove everything the store holds about a user: the templates, sealed
    /// or plain, any set-aside blob (`<user>.cred.unreadable-*`), the gesture
    /// recordings (`gestures/<secs>-<user>-*.txt`) and the walk-through's
    /// frame recordings (`record/<user>/`). True when templates were there.
    pub fn delete(&self, user: &str) -> Result<bool> {
        Self::check_user(user)?;
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
        for e in std::fs::read_dir(self.dir.join("gestures"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let name = e.file_name();
            let Some(n) = name.to_str() else { continue };
            // `<unix seconds>-<user>-<how it ended>.txt`, the user matched
            // as a whole component so "al" does not take "alice"'s files.
            let is_users = n
                .strip_suffix(".txt")
                .and_then(|stem| stem.split_once('-'))
                .map(|(secs, rest)| {
                    secs.chars().all(|c| c.is_ascii_digit())
                        && rest
                            .strip_prefix(user)
                            .map(|r| r.starts_with('-'))
                            .unwrap_or(false)
                })
                .unwrap_or(false);
            if is_users {
                std::fs::remove_file(e.path())
                    .with_context(|| format!("remove {}", e.path().display()))?;
            }
        }
        let record = self.dir.join("record").join(user);
        if record.is_dir() {
            std::fs::remove_dir_all(&record)
                .with_context(|| format!("remove {}", record.display()))?;
        }
        if let Ok(mut c) = self.cache.lock() {
            c.remove(user);
        }
        Ok(any)
    }
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

    fn tmpl(e: Vec<f32>, created: u64, device: Option<&str>) -> Template {
        Template {
            embedding: e,
            quality: 0.9,
            face_width: 80.0,
            created,
            label: "enrol".into(),
            device: device.map(String::from),
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
        let mut u = UserTemplates::new("alice", "glintr100");
        u.uid = None;
        u.templates.push(tmpl(vec![1.0, 0.0], 1, None));
        u.templates.push(tmpl(vec![0.0, 1.0], 2, None));
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
        u.templates
            .push(tmpl(vec![1.0, 0.0], 1, Some("ipu3:ov7251 3-0060")));
        u.templates.push(tmpl(vec![0.0, 1.0], 2, None)); // pre-binding: usable anywhere
        assert_eq!(u.usable_on("ipu3:ov7251 3-0060"), 2);
        assert_eq!(u.usable_on("uvc:uvcvideo:Other Cam:usb-1"), 1);
        assert_eq!(
            u.best_match_on(&[1.0, 0.0], "uvc:uvcvideo:Other Cam:usb-1")
                .unwrap(),
            (0.0, 1)
        );
        assert_eq!(
            u.best_match_on(&[1.0, 0.0], "ipu3:ov7251 3-0060").unwrap(),
            (1.0, 0)
        );
        assert_eq!(u.bound_devices(), vec!["ipu3:ov7251 3-0060".to_string()]);
        let only_bound = UserTemplates {
            templates: vec![tmpl(vec![1.0, 0.0], 1, Some("ipu3:x"))],
            ..u.clone()
        };
        assert_eq!(only_bound.usable_on("uvc:y"), 0);
        assert!(only_bound.best_match_on(&[1.0, 0.0], "uvc:y").is_none());
    }

    #[test]
    fn everyday_rounds_set_margins_and_only_the_verify_step_raises_a_floor() {
        let ev = |kind: &str, dy: f32, dx: f32| EverydayRound {
            kind: kind.into(),
            dy,
            dx,
        };
        // Sizes alone never move a floor: a talk round with a natural bob of
        // 0.07 (recorded live) would have pushed the nod floor past the 0.09
        // where a real nod drops out.
        let g = GestureCal {
            nod: vec![0.26, 0.30],
            shake: vec![0.33, 0.36],
            everyday: vec![
                ev("read", 0.02, 0.03),
                ev("talk", 0.07, 0.02),
                ev("lean", 0.27, 0.08),
                ev("aside", 0.10, 0.50),
            ],
            ..Default::default()
        };
        assert_eq!(g.floors(0.06, 0.06), (0.09, 0.06));
        let (mn, ms) = g.margins();
        // "typical" is the upper median: 0.30 of [0.26, 0.30], 0.36 of [0.33, 0.36].
        assert!((mn.unwrap() - 0.30 / 0.07).abs() < 1e-3, "{:?}", mn);
        assert!((ms.unwrap() - 0.36 / 0.03).abs() < 1e-3, "{:?}", ms);
        // What the verify step found necessary raises a floor, never lowers
        // one, and never past the cap.
        let verified = GestureCal {
            nod_floor_min: Some(0.11),
            shake_floor_min: Some(0.05),
            ..g.clone()
        };
        assert_eq!(verified.floors(0.06, 0.06), (0.11, 0.06));
        let capped = GestureCal {
            nod_floor_min: Some(0.30),
            shake_floor_min: Some(0.30),
            ..g.clone()
        };
        assert_eq!(
            capped.floors(0.06, 0.06),
            (GestureCal::NOD_FLOOR_MAX, GestureCal::SHAKE_FLOOR_MAX)
        );
        // A record from before these rounds existed still reads, and one from
        // the short-lived numbers-only format reads but raises nothing.
        let old: GestureCal = serde_json::from_str(r#"{"nod":[0.2],"shake":[0.3]}"#).unwrap();
        assert!(old.everyday.is_empty() && old.margins() == (None, None));
        let numbers: GestureCal = serde_json::from_str(
            r#"{"nod":[0.26],"shake":[0.22],"still_nod":[0.27],"still_shake":[0.5]}"#,
        )
        .unwrap();
        assert_eq!(numbers.floors(0.06, 0.06), (0.09, 0.06));
    }

    #[test]
    fn calibration_floors_only_tighten_the_nod_and_loosen_the_shake() {
        let none = GestureCal::default();
        assert_eq!(none.floors(0.06, 0.06), (0.06, 0.06));
        assert!(!none.is_calibrated());
        // A big nodder: floor rises to half the typical swing, capped.
        let big = GestureCal {
            nod: vec![0.30, 0.26, 0.40],
            shake: vec![0.20, 0.24],
            ..Default::default()
        };
        let (n, s) = big.floors(0.06, 0.06);
        assert!((n - 0.09).abs() < 1e-6, "{}", n); // 0.30 * 0.4 = 0.12, capped at 0.09
        assert!((s - 0.06).abs() < 1e-6, "{}", s); // 0.22 * 0.5 = 0.11 > default: stays at default
                                                   // A light nodder: never below the default.
        let light = GestureCal {
            nod: vec![0.08, 0.09],
            shake: vec![0.08, 0.07],
            ..Default::default()
        };
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

    /// Pruning drops the copies of a look the set already has and keeps
    /// the different ones.
    #[test]
    fn pruning_keeps_the_different_looks() {
        let mut u = UserTemplates::new("alice", "glintr100");
        let mk = |v: Vec<f32>| {
            let n = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            tmpl(v.iter().map(|x| x / n).collect(), 1, None)
        };
        u.templates.push(mk(vec![1.0, 0.0, 0.0]));
        u.templates.push(mk(vec![1.0, 0.05, 0.0]));
        u.templates.push(mk(vec![1.0, -0.05, 0.0]));
        u.templates.push(mk(vec![0.0, 1.0, 0.0]));
        u.templates.push(mk(vec![0.0, 0.0, 1.0]));
        assert_eq!(u.prune_to(3), 2);
        let kept: Vec<usize> = u
            .templates
            .iter()
            .map(|t| {
                t.embedding
                    .iter()
                    .enumerate()
                    .max_by(|a, b| a.1.total_cmp(b.1))
                    .unwrap()
                    .0
            })
            .collect();
        assert_eq!(
            kept,
            vec![0, 1, 2],
            "one of each direction survives; the near copies go"
        );
        assert_eq!(u.prune_to(10), 0);
    }

    #[test]
    fn mesh_floors_come_from_the_recorded_swings() {
        let mut g = GestureCal::default();
        assert_eq!(
            g.floors_deg(8.0, 15.0),
            (8.0, 15.0),
            "nothing recorded: the defaults"
        );
        g.nod_deg = vec![34.7, 25.7];
        g.shake_deg = vec![49.2, 56.8];
        let (n, s) = g.floors_deg(8.0, 15.0);
        assert!(
            (n - 13.88).abs() < 0.1 && (s - 22.72).abs() < 0.1,
            "0.4 of the upper median: {} {}",
            n,
            s
        );
        g.nod_deg = vec![80.0];
        g.shake_deg = vec![120.0];
        assert_eq!(
            g.floors_deg(8.0, 15.0),
            (16.0, 24.0),
            "capped so a light gesture still counts"
        );
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
        let mut u = UserTemplates::new("alice", "glintr100");
        u.uid = None;
        u.templates.push(tmpl(vec![1.0, 0.0], 1, None));
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
        let mut u = UserTemplates::new("alice", "glintr100");
        u.uid = Some(1000);
        u.templates.push(tmpl(vec![1.0, 0.0], 1, None));
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

    /// Deleting a user takes the set-aside blobs, the gesture recordings
    /// and the walk-through recordings with the templates, and nobody
    /// else's (F5).
    #[test]
    fn delete_removes_every_trace_of_the_user_and_only_theirs() {
        let dir = temp("deleteall");
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::open_with(&dir, Sealing::Plain("test".into()))
            .unwrap()
            .without_creds();
        let mut u = UserTemplates::new("al", "glintr100");
        u.uid = None;
        u.templates.push(tmpl(vec![1.0, 0.0], 1, None));
        store.save(&u).unwrap();
        std::fs::write(dir.join("al.cred.unreadable-1700000000"), b"x").unwrap();
        std::fs::write(dir.join("alice.cred.unreadable-1700000000"), b"x").unwrap();
        std::fs::create_dir_all(dir.join("gestures")).unwrap();
        std::fs::write(dir.join("gestures/1700000001-al-nodded.txt"), b"x").unwrap();
        std::fs::write(dir.join("gestures/1700000002-alice-nodded.txt"), b"x").unwrap();
        std::fs::write(dir.join("gestures/1700000003-al-with-dash-al-x.txt"), b"x").unwrap();
        std::fs::create_dir_all(dir.join("record/al")).unwrap();
        std::fs::write(dir.join("record/al/frame.pgm"), b"x").unwrap();
        std::fs::create_dir_all(dir.join("record/alice")).unwrap();
        assert!(store.delete("al").unwrap());
        let left: Vec<String> = walk(&dir);
        assert_eq!(
            left,
            vec![
                "alice.cred.unreadable-1700000000",
                "gestures/1700000002-alice-nodded.txt",
                "record/alice"
            ],
            "{:?}",
            left
        );
        assert!(!store.delete("al").unwrap(), "nothing left to delete");
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
