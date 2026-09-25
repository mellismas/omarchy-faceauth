//! Presence watch: is the enrolled user in front of the machine?
//!
//! Low duty by construction: every `tick_seconds` the watch takes the camera
//! for a fraction of a second, grabs a few frames with the illuminator on,
//! detects on the last one and, on the identity ticks, strobes one lit/unlit
//! pair through the flash gate and embeds the face to check it against the
//! templates. A print that fails the gate is not the user, so it cannot keep
//! the session marked present. The camera is closed between ticks, so an
//! authentication attempt never waits for more than one tick.
//!
//! Two modes (`[presence] mode`), ruled in the round-4 review (Q9). In the
//! `default` mode any face turned to the screen holds the lock off: a
//! laptop handed to someone stays open while they look at it, and the
//! session locks only once the chair has been empty for `away_seconds`.
//! Identity is checked every `IDENTIFY_EVERY` ticks there, but only to tell
//! the shell who is holding the clock and to take the shape reference for a
//! hidden face; it never decides the lock. In the `secure` mode identity is
//! checked on every tick, only a face that passes holds the clock, the first
//! failed check locks the session at once, and an empty chair locks after
//! `away_seconds`.
//!
//! State: `Present` (someone the mode accepts is holding the clock),
//! `Stranger` (default mode only: a face whose identity check failed is
//! holding it), `Away` (nobody has held it for `away_seconds`, or in the
//! secure mode a check failed; the session is locked once on the
//! transition). In the default mode a face the detector only half sees (a
//! hand over the chin while reading) is not absence: while no face is found,
//! the away clock is held after the last full sighting while the shape
//! under the last face box is unchanged, for the obscured face lock time:
//! `obscured_face_lock` ("never" as shipped) in the default mode and
//! `secure_obscured_face_lock` (2 minutes) in the secure mode. The state
//! is answered over the socket (the `presence_mode` query) to root and the
//! watched user.

use crate::auth::Authenticator;
use anyhow::Result;
use faceauth_engine::{pose, Grey};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PresenceConfig {
    pub enabled: bool,
    /// Whose presence: the user whose templates are matched.
    pub user: String,
    /// How strict the watch is; see `PresenceMode`. The starting mode; the
    /// watched user may switch it at run time over the socket.
    pub mode: PresenceMode,
    pub tick_seconds: f32,
    /// On battery (no mains supply online) the tick stretches to this.
    /// Zero keeps the mains cadence.
    pub battery_tick_seconds: f32,
    /// Seconds without the user before the session is locked.
    pub away_seconds: f32,
    /// Default mode: the obscured face lock time, how long a face that is
    /// partly covered or turned away (a hand on the chin, a look down) keeps
    /// the session open after the last clear sighting while the same shape
    /// stays in the chair. "never", the shipped value, locks only when the
    /// chair changes; a number is minutes, at least 1.
    pub obscured_face_lock: ObscuredFaceLock,
    /// Secure mode: the same, in minutes, 1 to 10. Secure mode promises that
    /// only a verified face keeps the session open, so this is bounded.
    pub secure_obscured_face_lock: u32,
}

/// The default mode's obscured face lock time: a number of minutes, or the
/// word "never".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ObscuredFaceLock {
    Minutes(u32),
    Word(LockWord),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LockWord {
    Never,
}

/// Secure mode's obscured face lock time, in minutes: the shipped value and the
/// range a config may set (outside it the value is clamped, with a warning).
pub const SECURE_OBSCURED_LOCK_MINUTES: u32 = 2;
pub const SECURE_OBSCURED_LOCK_RANGE: (u32, u32) = (1, 10);

impl PresenceConfig {
    /// The obscured face lock time in `mode`, from the last clear sighting;
    /// None is never.
    pub fn obscured_lock_for(&self, mode: PresenceMode) -> Option<Duration> {
        let minutes = |m: u32| Duration::from_secs(u64::from(m) * 60);
        match mode {
            PresenceMode::Secure => Some(minutes(
                self.secure_obscured_face_lock
                    .clamp(SECURE_OBSCURED_LOCK_RANGE.0, SECURE_OBSCURED_LOCK_RANGE.1),
            )),
            PresenceMode::Default => match self.obscured_face_lock {
                ObscuredFaceLock::Word(LockWord::Never) => None,
                ObscuredFaceLock::Minutes(m) => Some(minutes(m.max(1))),
            },
        }
    }

    /// Warnings for lock times the watch clamps, for the start-up log.
    pub fn obscured_lock_warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        let (lo, hi) = SECURE_OBSCURED_LOCK_RANGE;
        if !(lo..=hi).contains(&self.secure_obscured_face_lock) {
            w.push(format!(
                "secure_obscured_face_lock = {} is outside {} to {} minutes; using {}",
                self.secure_obscured_face_lock,
                lo,
                hi,
                self.secure_obscured_face_lock.clamp(lo, hi)
            ));
        }
        if self.obscured_face_lock == ObscuredFaceLock::Minutes(0) {
            w.push("obscured_face_lock = 0 is under 1 minute; using 1".into());
        }
        w
    }
}

/// Ticks between identity checks in the default mode (detection alone
/// runs every tick, on mains and on battery). The secure mode checks
/// identity on every tick.
pub const IDENTIFY_EVERY: u32 = 3;

/// How long a look keeps trying to find the face when someone was there at
/// the last look: a hand passing over the face (a scratch, a sip) or a turn
/// away for a moment is not an empty chair, so the look waits it out instead
/// of recording a miss. A look at an empty chair stops after the exposure
/// settles, so the camera and the illuminator are not held for nobody.
pub const LOOK_SEE_BUDGET: Duration = Duration::from_secs(2);

/// The default mode's tick. Mike, 2026-09-24: secure mode looks every five
/// seconds, the default mode less often; the default mode only needs to see
/// that someone is there within the away time.
pub const DEFAULT_MODE_TICK_SECONDS: f32 = 10.0;

/// The longest a look spends settling the exposure on the face before its
/// flash reading: a few frames usually, bounded because auto-exposure can
/// hold where a metered face clips a few percent.
pub const FACE_SETTLE_MAX: Duration = Duration::from_millis(500);
/// Whether the watched user's store failed to load on the last check, so
/// the warning is logged once per episode rather than every tick.
static STORE_UNREADABLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Whether the last look found the face beyond the line, so the note is
/// logged once per episode.
static BEYOND_LINE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// A face turned to the screen: yaw within this on the five-point
/// measure (the mesh's degrees convert through `YAW_DEG_PER_UNIT`) and
/// roll within this many degrees. What "attentive" means everywhere a
/// look asks it: the watch, the lock screen's probe and the re-arm gate.
pub const ATTENTIVE_MAX_YAW: f32 = 0.25;
pub const ATTENTIVE_MAX_ROLL_DEG: f32 = 25.0;

impl Default for PresenceConfig {
    fn default() -> Self {
        PresenceConfig {
            enabled: false,
            user: String::new(),
            mode: PresenceMode::Default,
            tick_seconds: 5.0,
            battery_tick_seconds: 10.0,
            away_seconds: 20.0,
            obscured_face_lock: ObscuredFaceLock::Word(LockWord::Never),
            secure_obscured_face_lock: SECURE_OBSCURED_LOCK_MINUTES,
        }
    }
}

/// How strict the walk-away watch is.
///
/// `Default`: any face turned to the screen holds the lock off, whoever it
/// belongs to; the session locks once nobody has held it for
/// `away_seconds`. The enrolled user holds the clock whatever they are
/// looking at; a face whose identity check failed (twice running, so one
/// flaky read does not change the rule) has to be looking at the screen
/// to hold the clock. A hidden face (none found, or one found that neither
/// passes nor looks at the screen, with the same shape in the chair) holds
/// the clock for a while.
///
/// `Secure`: identity is checked on every tick and only a face that passes
/// holds the clock. The first failed check locks the session at once, an
/// empty chair locks after `away_seconds`, and no other face holds the
/// clock, not one the gate read no signal from. The one allowance both
/// modes share is the hidden face: the user's own hand over it, or a look
/// down at a phone, with the same shape still in the chair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceMode {
    Default,
    Secure,
}

impl PresenceMode {
    pub fn parse(s: &str) -> Option<PresenceMode> {
        match s {
            "default" => Some(PresenceMode::Default),
            "secure" => Some(PresenceMode::Secure),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            PresenceMode::Default => "default",
            PresenceMode::Secure => "secure",
        }
    }
}

/// The mode in force, set from the config when the watch starts and
/// changed at run time by the watched user over the socket (it does not
/// persist; the config sets the starting mode at every start).
static MODE: AtomicU8 = AtomicU8::new(0);

pub fn presence_mode() -> PresenceMode {
    if MODE.load(Ordering::SeqCst) == 1 {
        PresenceMode::Secure
    } else {
        PresenceMode::Default
    }
}

pub fn set_presence_mode(mode: PresenceMode) {
    MODE.store(
        if mode == PresenceMode::Secure { 1 } else { 0 },
        Ordering::SeqCst,
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Present,
    Away,
    Stranger,
    Unknown,
}

/// What the watch last decided, for the socket's presence query: the
/// state, how long the user has been unseen, and whether the lock in
/// force is the watch's. Root-only in effect: the query answers it to
/// root and the watched user, since whether the owner is at the desk is
/// a timing signal an attacker on the machine would like.
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Snapshot {
    pub state: State,
    pub attentive: bool,
    pub away_for: Option<f32>,
    pub locked_by_presence: bool,
}

static LAST: Mutex<Option<Snapshot>> = Mutex::new(None);

/// The watch's last decision, or None before its first tick.
pub fn snapshot() -> Option<Snapshot> {
    *LAST.lock().unwrap_or_else(|p| p.into_inner())
}

/// While the session is locked, every this many ticks the watch asks the
/// compositor whether it still is: a password or fingerprint unlock, which
/// leaves no face match behind, resumes the watch this way (C2).
pub const LOCK_CHECK_TICKS: u32 = 3;

/// The one session lock the daemon makes: the walk-away lock, whether
/// the presence watch or a consent request whose user left asked for it.
/// It holds the one record of when the session was locked, runs the lock
/// helper once, and answers the one question both askers have: has the
/// session unlocked since, by a face match newer than the lock or by
/// anything else the compositor reports (a password, a fingerprint)?
pub struct SessionLock {
    inner: Mutex<LockState>,
}

#[derive(Default)]
struct LockState {
    locked_at: Option<Instant>,
    /// When the compositor was last asked, so the askers share one cadence.
    last_check: Option<Instant>,
}

pub static SESSION_LOCK: SessionLock = SessionLock::new();

impl Default for SessionLock {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionLock {
    pub const fn new() -> Self {
        SessionLock {
            inner: Mutex::new(LockState {
                locked_at: None,
                last_check: None,
            }),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, LockState> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// When the session was locked, if it is.
    pub fn locked_at(&self) -> Option<Instant> {
        self.state().locked_at
    }

    /// Lock `user`'s session with the lock helper, unless it is locked
    /// already: when it was locked. `omarchy_path` is the tree the running
    /// shell was launched from, resolved by the daemon (the helper parses
    /// nothing). The helper runs outside the lock's own mutex, so a reader
    /// is never held behind it.
    pub fn lock(&self, user: &str, omarchy_path: &str) -> Result<Instant> {
        if let Some(t) = self.locked_at() {
            return Ok(t);
        }
        lock_session(user, omarchy_path)?;
        Ok(self.adopt(Instant::now()))
    }

    /// The session was locked by other means (the idle lock, a key, the
    /// lid): record it, unless a lock is recorded already. When it counts
    /// from.
    pub fn adopt(&self, at: Instant) -> Instant {
        let mut st = self.state();
        *st.locked_at.get_or_insert(at)
    }

    /// Has the session unlocked since the lock? `matched` is a face match
    /// newer than the lock, which resumes at once; otherwise the
    /// compositor is asked, at most once per `check_every` across every
    /// asker. `None` while it stays locked; how it unlocked once it has,
    /// with the lock forgotten. A lock another asker already saw end
    /// reads as unlocked too.
    pub fn resumed(
        &self,
        now: Instant,
        matched: bool,
        check_every: Duration,
        session_locked: &dyn Fn() -> bool,
    ) -> Option<&'static str> {
        let mut st = self.state();
        if st.locked_at.is_none() {
            return Some("elsewhere");
        }
        if matched {
            st.locked_at = None;
            return Some("by face");
        }
        let due = st
            .last_check
            .map(|c| now.duration_since(c) >= check_every)
            .unwrap_or(true);
        if !due {
            return None;
        }
        st.last_check = Some(now);
        drop(st);
        if session_locked() {
            return None;
        }
        self.state().locked_at = None;
        Some("without a face")
    }
}

/// The watch's state between ticks, and the rules that move it: what
/// `run` drives from the camera, kept apart from it so the rules can be
/// exercised on made-up observations.
pub(crate) struct Watch {
    cfg: PresenceConfig,
    pub(crate) state: State,
    last_seen: Option<Instant>,
    last_full: Option<Instant>,
    partial_logged: bool,
    /// The frame and face box of the last sighting whose identity passed.
    reference: Option<(Grey, [f32; 4])>,
    pub(crate) locked_by_presence: bool,
    /// Whether the last identity checks passed. True until a check fails
    /// (twice running in the default mode, once in the secure mode); a
    /// passing check restores it.
    identity_ok: bool,
    identity_fails: u32,
}

/// What one tick decided.
pub(crate) struct Step {
    pub(crate) state: State,
    /// Lock the session now (the away transition, or an earlier lock that
    /// failed and is retried).
    pub(crate) lock: bool,
    pub(crate) away_for: Option<f32>,
}

impl Watch {
    pub(crate) fn new(cfg: PresenceConfig) -> Watch {
        Watch {
            cfg,
            state: State::Unknown,
            last_seen: None,
            last_full: None,
            partial_logged: false,
            reference: None,
            locked_by_presence: false,
            identity_ok: true,
            identity_fails: 0,
        }
    }

    /// A consent window that ran, or a face match, since the last tick: the
    /// user was at the desk then, and the away clock restarts from it.
    pub(crate) fn note_recent(&mut self, at: Instant) {
        if self.last_seen.map(|l| at > l).unwrap_or(true) {
            self.last_seen = Some(at);
            if self.state != State::Present {
                log::info!("presence: consent or match since the last tick; clock restarts");
            }
        }
    }

    /// The session is locked (by this watch, or by a consent request whose
    /// lock this watch takes over): the camera is left to the lock screen
    /// until `SessionLock::resumed` says it is open again.
    pub(crate) fn locked(&mut self) {
        self.locked_by_presence = true;
        self.state = State::Away;
    }

    /// The session unlocked, by a face match newer than the lock or by
    /// other means. A fresh absence clock either way: after a face the
    /// user is present; after a password nobody has been seen yet, and the
    /// next identity check decides.
    pub(crate) fn resumed(&mut self, now: Instant, by_face: bool) {
        self.locked_by_presence = false;
        self.last_seen = Some(now);
        self.identity_ok = true;
        self.identity_fails = 0;
        self.state = if by_face {
            State::Present
        } else {
            State::Unknown
        };
    }

    /// One look's worth of the rules.
    pub(crate) fn step(&mut self, obs: &Observation, now: Instant, mode: PresenceMode) -> Step {
        let cfg = &self.cfg;
        if let Some(id) = obs.identity {
            if id {
                self.identity_fails = 0;
                self.identity_ok = true;
            } else {
                self.identity_fails += 1;
                // Default: two checks running, so one flaky read does not
                // turn the user into a stranger. Secure: one is enough.
                let strikes = if mode == PresenceMode::Secure { 1 } else { 2 };
                if self.identity_fails >= strikes {
                    self.identity_ok = false;
                }
            }
        }
        // Who holds the clock this look (Q9). Default: any face turned to
        // the screen, so a laptop handed over stays open while it is looked
        // at; the enrolled user holds it whatever they look at, since a
        // check confirmed them and reading a paper beside the screen is
        // not leaving. Secure: only a face that passed this tick's
        // identity check; an unchecked face, or one the gate read no
        // signal from, holds nothing.
        let seen = obs.face
            && match mode {
                PresenceMode::Default => self.identity_ok || obs.attentive,
                PresenceMode::Secure => obs.identity == Some(true),
            };
        // A hidden face may still be the user in the chair: a hand or a
        // sheet over the face leaves the shape under the last face box,
        // standing up replaces it with the wall. Hidden covers a face the
        // detector lost and one it still finds but cannot read (a hand on
        // the chin or a look down at a phone fits no attentive pose and
        // embeds as nobody), so the hold runs for any look that holds
        // nothing, in both modes: the secure mode's first-miss lock is for
        // a chair whose shape has changed, not for the user's own hand.
        // Leaning on a hand or leaning in to read keeps the face turned to
        // the screen while it scores just under the line, or leaves the
        // strobe no signal to read; those are hidden too. Only a face turned
        // to the screen that misses by a wide margin is someone else looking
        // at the session, and the shape under it holds nothing.
        let stranger = obs.face && obs.attentive && obs.identity == Some(false) && !obs.near_miss;
        let hidden = !stranger;
        let held_by_shape = if !seen
            && hidden
            && partial_holds(now, self.last_full, cfg.obscured_lock_for(mode))
        {
            let sim = match (self.reference.as_ref(), obs.frame.as_ref()) {
                (Some(r), Some(f)) => same_shape(r, f),
                _ => 0.0,
            };
            if sim >= SAME_SHAPE {
                if !self.partial_logged {
                    log::info!("presence: the user's face is not seen but the same shape is in the chair ({:.2}); the clock is held", sim);
                    self.partial_logged = true;
                }
                true
            } else {
                if !self.partial_logged {
                    // Logged once per episode so the threshold can be set from
                    // what real hands and sheets score. A scene similarity, not
                    // a match score.
                    log::info!("presence: the user's face is not seen and the shape under the last box differs ({:.2} < {}); the clock runs", sim, SAME_SHAPE);
                    self.partial_logged = true;
                }
                false
            }
        } else {
            false
        };
        // Secure: the first failed check is the lock, whatever the clock
        // says, unless the shape holds. The check runs on every tick there,
        // so a stranger who sits down is out within one tick.
        let missed = mode == PresenceMode::Secure
            && obs.face
            && obs.identity == Some(false)
            && !held_by_shape;
        if held_by_shape {
            self.last_seen = Some(now);
        }
        if seen {
            self.last_seen = Some(now);
            self.last_full = Some(now);
            self.partial_logged = false;
            // The shape reference comes only from a look whose identity
            // passed: a stranger's torso must not become the shape that
            // holds the clock for a hidden face (C1).
            if obs.identity == Some(true) {
                if let (Some(f), Some(b)) = (obs.frame.as_ref(), obs.bbox) {
                    self.reference = Some((f.clone(), b));
                }
            }
        } else if !held_by_shape && (self.state == State::Present || self.state == State::Stranger)
        {
            log::info!("presence: nobody holds the clock this look (face {}, identity {:?}, frame {}, last full sighting {})", obs.face, obs.identity, obs.frame.is_some(), self.last_full.map(|t| format!("{:.0}s ago", now.duration_since(t).as_secs_f32())).unwrap_or_else(|| "never".into()));
        }
        let away_for = self.last_seen.map(|t| now.duration_since(t).as_secs_f32());
        // A face holding the clock whose check failed is reported as a
        // stranger (default mode only; the secure mode has locked by now),
        // so the shell can say who is keeping the session open.
        let next = if missed {
            State::Away
        } else if seen {
            if self.identity_ok {
                State::Present
            } else {
                State::Stranger
            }
        } else if away_for.map(|s| s >= cfg.away_seconds).unwrap_or(false) {
            State::Away
        } else if held_by_shape {
            self.state // the user, face hidden: what the shell shows stays
        } else if obs.face && !self.identity_ok {
            State::Stranger
        } else if self.state == State::Unknown {
            State::Unknown
        } else {
            self.state // in the away window: keep the previous state
        };
        if next != self.state {
            log::info!(
                "presence: {:?} -> {:?}{}",
                self.state,
                next,
                away_for
                    .map(|s| format!(" (unseen {:.0}s)", s))
                    .unwrap_or_default()
            );
        }
        // Lock on the away transition, and keep trying every tick while away
        // until it succeeds: a failed lock must not leave the machine open.
        let lock = next == State::Away && !self.locked_by_presence;
        if next == State::Present {
            self.locked_by_presence = false;
        }
        self.state = next;
        Step {
            state: next,
            lock,
            away_for,
        }
    }
}

/// Does this tick check identity? Identity is the dear part of a tick (the
/// embedder costs several times the detector). The secure mode pays it on
/// every tick, since one failed check is the lock there and a stranger
/// must be out within a tick. The default mode pays it on its cadence
/// while present, and every other tick while a face is there that has not
/// been confirmed.
pub(crate) fn identify_this_tick(mode: PresenceMode, tick: u32, every: u32, state: State) -> bool {
    mode == PresenceMode::Secure
        || tick.is_multiple_of(every.max(1))
        || (state != State::Present && tick.is_multiple_of(2))
}

/// Seconds between looks: the configured tick (the battery tick on
/// battery), and in the default mode never under
/// `DEFAULT_MODE_TICK_SECONDS`.
pub fn tick_for(cfg: &PresenceConfig, mode: PresenceMode, on_battery: bool) -> f32 {
    let base = if on_battery && cfg.battery_tick_seconds > 0.0 {
        cfg.battery_tick_seconds
    } else {
        cfg.tick_seconds
    };
    if mode == PresenceMode::Default {
        base.max(DEFAULT_MODE_TICK_SECONDS)
    } else {
        base
    }
}

pub fn run(auth: Arc<Mutex<Authenticator>>, cfg: PresenceConfig) {
    set_presence_mode(cfg.mode);
    let mut w = Watch::new(cfg.clone());
    let mut tick: u32 = 0;
    log::info!(
        "presence watch on for {} (mode {}, tick {}s, away after {}s, obscured face lock {})",
        cfg.user,
        cfg.mode.name(),
        tick_for(&cfg, cfg.mode, false),
        cfg.away_seconds,
        match cfg.obscured_lock_for(cfg.mode) {
            Some(d) => format!("after {} min", d.as_secs() / 60),
            None => "never".into(),
        }
    );
    for w in cfg.obscured_lock_warnings() {
        log::warn!("presence: {}", w);
    }
    let mut on_battery = false;
    let mut mode = presence_mode();
    loop {
        let tick_s = tick_for(&cfg, mode, on_battery);
        std::thread::sleep(Duration::from_secs_f32(tick_s));
        tick = tick.wrapping_add(1);
        let battery = on_battery_now();
        if battery != on_battery {
            on_battery = battery;
            log::info!(
                "presence: {} (tick {}s)",
                if battery { "on battery" } else { "on mains" },
                if battery && cfg.battery_tick_seconds > 0.0 {
                    cfg.battery_tick_seconds
                } else {
                    cfg.tick_seconds
                }
            );
        }
        let now_mode = presence_mode();
        if now_mode != mode {
            mode = now_mode;
            log::info!("presence: mode is now {}", mode.name());
        }
        let identify = identify_this_tick(mode, tick, IDENTIFY_EVERY, w.state);
        // A consent request that locked the session while the user was
        // away hands the lock to this watch, which then waits for the
        // unlock like one of its own.
        if !w.locked_by_presence && SESSION_LOCK.locked_at().is_some() {
            w.locked();
        }
        // After locking, leave the camera to the lock screen (its own probe
        // wakes the panel); resume once an attempt has matched, or once the
        // session reads as unlocked by other means (a password, a
        // fingerprint), asked every `LOCK_CHECK_TICKS` ticks.
        if w.locked_by_presence {
            let now = Instant::now();
            let matched = SESSION_LOCK.locked_at().is_some_and(|t| {
                auth.lock()
                    .map(|a| a.last_match.get(&cfg.user).is_some_and(|m| *m > t))
                    .unwrap_or(false)
            });
            let check_every =
                Duration::from_secs_f32(tick_s * LOCK_CHECK_TICKS as f32 - tick_s / 2.0);
            let Some(how) = SESSION_LOCK.resumed(now, matched, check_every, &|| {
                crate::consent::session_locked(&cfg.user)
            }) else {
                continue;
            };
            w.resumed(now, matched);
            log::info!("presence: session unlocked {}, watch resumes", how);
        }
        let obs = {
            let mut a = auth.lock().unwrap_or_else(|p| p.into_inner());
            // A consent window that ran while this thread waited for the lock
            // is the user at the desk, not seconds unseen: the walk-away clock
            // restarts from the end of that flow, and from any face match.
            let recent = [a.last_consent.get(&cfg.user), a.last_match.get(&cfg.user)]
                .into_iter()
                .flatten()
                .max()
                .copied();
            if let Some(r) = recent {
                w.note_recent(r);
            }
            let persist = matches!(w.state, State::Present | State::Stranger);
            match observe_in(
                &mut a,
                &cfg,
                identify,
                mode == PresenceMode::Secure,
                persist,
            ) {
                Ok(o) => o,
                Err(e) => {
                    log::warn!("presence tick: {}", e);
                    continue;
                }
            }
        };
        let now = Instant::now();
        let step = w.step(&obs, now, mode);
        if step.lock {
            log::info!("presence: locking the session");
            match SESSION_LOCK.lock(&cfg.user, &crate::consent::omarchy_path()) {
                Ok(_) => w.locked(),
                Err(e) => log::warn!("lock command: {}", e),
            }
        }
        *LAST.lock().unwrap_or_else(|p| p.into_inner()) = Some(Snapshot {
            state: step.state,
            attentive: obs.attentive,
            away_for: step.away_for,
            locked_by_presence: w.locked_by_presence,
        });
    }
}

/// The lock helper the package ships, run as root with the user whose
/// session to lock and the Omarchy tree the shell was launched from. It
/// runs the lock inside the user's own manager and answers with what the
/// compositor says (0 locked, 1 not), so a lock that never happened is
/// not believed.
pub const LOCK_HELPER: &str = "/usr/bin/faceauth-lock-session";

fn lock_session(user: &str, omarchy_path: &str) -> Result<()> {
    let o = std::process::Command::new(LOCK_HELPER)
        .args([user, omarchy_path])
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .output()?;
    if !o.status.success() {
        anyhow::bail!(
            "exited {}: {} {}",
            o.status,
            String::from_utf8_lossy(&o.stdout).trim(),
            String::from_utf8_lossy(&o.stderr).trim()
        );
    }
    Ok(())
}

#[derive(Clone)]
pub(crate) struct Observation {
    pub(crate) face: bool,
    pub(crate) attentive: bool,
    /// The frame this look decided on, and the face box when one was found,
    /// so the watch can keep a reference and compare the next look to it.
    pub(crate) frame: Option<Grey>,
    pub(crate) bbox: Option<[f32; 4]>,
    /// Some(true/false) when an identity check ran.
    pub(crate) identity: Option<bool>,
    /// A failed check that scored within `NEAR_MISS_SLACK` of the accept
    /// threshold: the user's own face half covered by a hand or pitched
    /// over a phone scores there; another person scores far below it.
    pub(crate) near_miss: bool,
}

/// Is the machine running on its battery? True when a battery is present
/// and no mains supply reports itself online; a desktop, with no battery,
/// is never on battery.
fn on_battery_now() -> bool {
    let Ok(dir) = std::fs::read_dir("/sys/class/power_supply") else {
        return false;
    };
    let (mut battery, mut mains_online) = (false, false);
    for e in dir.flatten() {
        let p = e.path();
        let read = |n: &str| {
            std::fs::read_to_string(p.join(n))
                .map(|v| v.trim().to_string())
                .unwrap_or_default()
        };
        match read("type").as_str() {
            "Battery" => battery = true,
            "Mains" | "USB" | "USB_PD" | "USB_C" if read("online") == "1" => {
                mains_online = true;
            }
            _ => {}
        }
    }
    battery && !mains_online
}

/// What the flash gate's verdict lets the identity check do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AfterGate {
    /// The gate refused: not the user, no embedding needed.
    Refused,
    /// The gate passed, or could not run at all (no strobe control, or the
    /// gate switched off in the config): the embedding decides.
    Embed,
    /// The gate ran and read no signal (a bright room, a face far back).
    /// In the secure mode that confirms nothing: the embedding alone must
    /// not hold the clock there (E4), so the look ends unchecked.
    Unconfirmed,
}

/// `gate_ran` is whether the gate could run at all; `verdict` is its
/// answer (`None` for no signal); `strict` is the secure mode.
pub(crate) fn after_gate(gate_ran: bool, verdict: Option<bool>, strict: bool) -> AfterGate {
    match (gate_ran, verdict) {
        (false, _) => AfterGate::Embed,
        (true, Some(false)) => AfterGate::Refused,
        (true, Some(true)) => AfterGate::Embed,
        (true, None) if strict => AfterGate::Unconfirmed,
        (true, None) => AfterGate::Embed,
    }
}

/// One short look: open the camera, LEDs on, a few frames, detect, maybe
/// identify, close. With `strict` (the secure mode) a face the gate read
/// no signal from comes back unchecked (`identity: None`) rather than
/// judged by the embedding alone; without it the embedding decides.
pub(crate) fn observe_in(
    a: &mut Authenticator,
    cfg: &PresenceConfig,
    identify: bool,
    strict: bool,
    persist: bool,
) -> Result<Observation> {
    use crate::capture::IrCapture;
    let mut cap = IrCapture::open_at(&a.cfg, a.last_exposure)?;
    if let Some(i) = &cap.illuminator {
        i.set(true)?;
    }
    // Let exposure react for a handful of frames; the last one is what we look at.
    let mut img = None;
    let deadline = Instant::now() + Duration::from_millis(450);
    while Instant::now() < deadline {
        if let Some(g) = cap.next(Duration::from_millis(500))? {
            img = Some(g);
        }
    }
    let Some(mut img) = img else {
        cap.stop()?;
        return Ok(Observation {
            face: false,
            attentive: false,
            identity: None,
            near_miss: false,
            frame: None,
            bbox: None,
        });
    };
    let mut faces = a.pipeline.detector.detect(&img, a.cfg.min_detection)?;
    // With someone there at the last look, keep looking for up to
    // `LOOK_SEE_BUDGET` before calling it no face (a hand over the face for
    // a moment is not an empty chair).
    if persist && faces.is_empty() {
        let until = Instant::now() + LOOK_SEE_BUDGET;
        while faces.is_empty() && Instant::now() < until {
            if let Some(g) = cap.next(Duration::from_millis(200))? {
                faces = a.pipeline.detector.detect(&g, a.cfg.min_detection)?;
                img = g;
            }
        }
    }
    // The next look starts from where this one's exposure ended, face or
    // no face: a seed that saturates after the light changes is escaped one
    // step per look this way, where saving it only behind a found face left
    // the watch blind until an authentication refreshed it (E4).
    a.last_exposure = Some(cap.exposure);
    let Some(face) = faces.into_iter().max_by(|x, y| x.score.total_cmp(&y.score)) else {
        cap.stop()?;
        return Ok(Observation {
            face: false,
            attentive: false,
            identity: None,
            near_miss: false,
            frame: Some(img),
            bbox: None,
        });
    };
    let p = pose::pose(&face.landmarks);
    // Attention from the mesh when the model is installed: its angles hold
    // where the five points' do not (a chin-up seen from below).
    let attentive = match a
        .pipeline
        .mesh
        .as_mut()
        .and_then(|m| m.for_face(&img, &face).ok().flatten())
    {
        Some(m) => faceauth_engine::mesh::is_attentive(
            &faceauth_engine::mesh::head_pose(&m),
            ATTENTIVE_MAX_YAW * crate::consent::NodDetector::YAW_DEG_PER_UNIT,
            ATTENTIVE_MAX_ROLL_DEG,
        ),
        None => pose::is_attentive(&p, ATTENTIVE_MAX_YAW, ATTENTIVE_MAX_ROLL_DEG),
    };
    // Beyond the line an unlock attempt would not judge, the look does not
    // flash or check identity either: it cannot read the face there, and
    // flashing at someone out of range every tick is what the user saw as
    // being read over and over. The look still reports the face; the
    // default mode holds on it, the secure mode treats it as hidden.
    let near_enough = crate::auth::scannable(face.bbox[2], img.width, img.height);
    if identify && !near_enough {
        if !BEYOND_LINE.swap(true, Ordering::Relaxed) {
            log::info!(
                "presence: face {:.0} px wide, beyond the line; no flash and no identity check until it is nearer",
                face.bbox[2]
            );
        }
    } else if near_enough {
        BEYOND_LINE.store(false, Ordering::Relaxed);
    }
    let identify = identify && near_enough;
    if identify && cap.illuminator.is_some() {
        // Settle the exposure on the face before the flash, as an unlock
        // attempt does (C10). The look's exposure came from the whole frame,
        // and a face near the screen then clips under the strobe: 20 to 23
        // percent of the face blown out, read as no signal, measured live
        // on 2026-09-24 at an ordinary seated distance. Bounded, since
        // auto-exposure can hold where a face clips a few percent.
        cap.meter_on(&face);
        let until = Instant::now() + FACE_SETTLE_MAX;
        let mut steps = 0;
        while Instant::now() < until {
            if cap.next(Duration::from_millis(200))?.is_some() {
                steps += 1;
                if steps >= 3 && cap.metering.clip < 0.05 {
                    break;
                }
            }
        }
        a.last_exposure = Some(cap.exposure);
    }
    let (identity, near_miss) = if identify {
        // Liveness first: one lit/unlit pair under the look's own mask,
        // with exposure frozen for it as the confirm does, since an
        // auto-exposure step inside the pair breaks the phase lock or skews
        // the lit and unlit frames against each other (E4). A refusal is
        // "not the user"; no signal decides nothing in the default mode and
        // ends the look unchecked in the secure mode.
        let gate_ran = cap.illuminator.is_some();
        let verdict = strobe_pair(
            &mut cap,
            &mut a.pipeline.detector,
            a.cfg.min_detection,
            &face,
        )?;
        match after_gate(gate_ran, verdict, strict) {
            AfterGate::Embed => {}
            AfterGate::Refused => {
                cap.stop()?;
                return Ok(Observation {
                    face: true,
                    attentive,
                    identity: Some(false),
                    near_miss: false,
                    frame: Some(img),
                    bbox: Some(face.bbox),
                });
            }
            AfterGate::Unconfirmed => {
                log::info!("presence: the gate read no signal; the look confirms nobody");
                cap.stop()?;
                return Ok(Observation {
                    face: true,
                    attentive,
                    identity: None,
                    near_miss: false,
                    frame: Some(img),
                    bbox: Some(face.bbox),
                });
            }
        }
        let crop = faceauth_engine::align::align_112(&img, &face.landmarks);
        let e = a.pipeline.embedder.embed(&crop)?;
        // Templates only count on the camera they were enrolled on, and a
        // store that cannot be read is nobody, not everybody: the check fails
        // closed rather than skipping the tick with identity still assumed.
        let score = match a.store.load(&cfg.user) {
            Ok(Some(t)) => {
                STORE_UNREADABLE.store(false, Ordering::Relaxed);
                t.best_match_on(&e, &cap.identity)
                    .map(|(s, _)| s)
                    .unwrap_or(-1.0)
            }
            Ok(None) => -1.0,
            Err(e) => {
                // Not a failed check: there is nothing to check against.
                // The look decides nothing, so the watch does not run a
                // check on every tick (the stranger cadence) and hold the
                // camera against the re-enrolment that fixes it. Warned
                // once per episode.
                if !STORE_UNREADABLE.swap(true, Ordering::Relaxed) {
                    log::warn!(
                        "presence: templates unreadable, identity is not checked until they are: {}",
                        e
                    );
                }
                cap.stop()?;
                return Ok(Observation {
                    face: true,
                    attentive,
                    identity: None,
                    near_miss: false,
                    frame: Some(img),
                    bbox: Some(face.bbox),
                });
            }
        };
        if score < a.cfg.accept_threshold {
            // The score itself stays at debug: the journal is readable by
            // wheel on Omarchy, and a scored stream is a tuning oracle.
            log::info!("presence: identity check failed");
            log::debug!(
                "presence: identity score {:.2} (exp {} gain {}, face {:.2})",
                score,
                cap.exposure.exposure,
                cap.exposure.gain,
                face.score
            );
        }
        let passed = score >= a.cfg.accept_threshold;
        (
            Some(passed),
            !passed && score >= a.cfg.accept_threshold - NEAR_MISS_SLACK,
        )
    } else {
        (None, false)
    };
    cap.stop()?;
    log::debug!(
        "presence tick: face {:.2} yaw {:.2} pitch {:.2} roll {:.0} attentive {} identity {:?}",
        face.score,
        p.yaw,
        p.pitch,
        p.roll.to_degrees(),
        attentive,
        identity
    );
    let bbox = face.bbox;
    Ok(Observation {
        face: true,
        attentive,
        identity,
        near_miss,
        frame: Some(img),
        bbox: Some(bbox),
    })
}

/// How long a presence look may strobe for its one reading. The phase lock
/// alone takes about half a second (the settle, then eight frames that
/// follow the mask), so the 0.6 s the look used to allow left room for one
/// pair at best, and many looks at a user sitting in front of the screen
/// read nothing. Two seconds, so a hand or a turn in the middle of a look
/// does not end it unread (Mike, 2026-09-24: "keeps looking until it sees or
/// for 2 sec"). The look returns at the first verdict, so an ordinary look
/// still strobes for about half a second.
pub const PRESENCE_STROBE_WINDOW: Duration = Duration::from_millis(2000);

/// One strobed lit/unlit pair on the open camera, gated at the face:
/// `Some(true)` passed, `Some(false)` refused, `None` no usable pair within
/// the window. The flash is judged where the face is in each lit frame, as
/// an unlock attempt does; the box from before the strobe misses a head
/// that moved. A look that ends without a verdict says why at info (frames,
/// pairs, pairs too faint, whether the frames ever followed the mask); the
/// gate's numbers stay at debug.
fn strobe_pair(
    cap: &mut crate::capture::IrCapture,
    detector: &mut faceauth_engine::detect::YuNet,
    min_detection: f32,
    face: &faceauth_engine::Face,
) -> Result<Option<bool>> {
    use crate::strobe::{Gate, StrobeGate};
    if cap.illuminator.is_none() {
        return Ok(None);
    }
    // The one gate: a fresh random mask per look, a pair only once the
    // frames have followed it (D5), the settle after the mask is written
    // (E4) and steady light back when the look ends, whichever way.
    let mut gate = StrobeGate::start(cap, true)?;
    gate.focus_on(face.bbox);
    let t0 = Instant::now();
    let mut tracked = face.clone();
    let (mut pairs, mut faint) = (0usize, 0usize);
    while t0.elapsed() < PRESENCE_STROBE_WINDOW {
        let Some(pair) = gate.next_frame(Duration::from_millis(200))? else {
            continue;
        };
        let faces = detector.detect(&pair.lit, min_detection)?;
        if let crate::consent::Track::Found(i) = crate::consent::track(&faces, tracked.bbox) {
            tracked = faces[i].clone();
            gate.focus_on(tracked.bbox);
        }
        pairs += 1;
        match gate.judge(&pair, &tracked)? {
            Gate::Pass(fr) => {
                log::debug!(
                    "presence liveness: pass after {} ms, pair {} {:?}",
                    t0.elapsed().as_millis(),
                    pairs,
                    fr
                );
                return Ok(Some(true));
            }
            Gate::NoSignal(fr) => {
                faint += 1;
                log::debug!("presence liveness: no signal {:?}", fr);
            }
            Gate::Denied(why, fr) => {
                log::info!("presence liveness: refused ({})", why);
                log::debug!("presence liveness: refused {:?}", fr);
                return Ok(Some(false));
            }
        }
    }
    log::info!(
        "presence liveness: no reading in {} ms: {} frames, {} pairs, {} too faint, the frames {} the mask",
        t0.elapsed().as_millis(),
        gate.frames(),
        pairs,
        faint,
        if gate.locked() { "followed" } else { "never followed" }
    );
    Ok(None)
}

/// How alike the region under the last face box must look, against the
/// frame of the last full sighting, for "still there, face hidden".
/// Measured 2026-09-22: a hand over part of the face 1.00, a sheet over it
/// 0.95, the face fully covered 0.79, the chair empty -0.34.
pub const SAME_SHAPE: f32 = 0.60;

/// How far under the accept threshold a failed presence check may score and
/// still count as the user's own face partly hidden rather than someone
/// else's (0.45 at the default 0.70). Different people score around 0.1 to
/// 0.3 against a set on this model; a hand on the chin or a face pitched
/// over a phone lands between. Reasoned, not measured on a corpus: the
/// scores are logged at debug so it can be. A near miss holds the clock
/// only through the shape in the chair, never on its own.
pub const NEAR_MISS_SLACK: f32 = 0.25;

/// Is the person still in the chair? No face cleared the threshold, but the
/// shoulders and torso under where the face was look as they did at the
/// last full sighting. A hand over the face leaves them alone; standing up
/// replaces them with the wall.
pub fn same_shape(reference: &(Grey, [f32; 4]), frame: &Grey) -> f32 {
    let r = faceauth_engine::motion::below(reference.1, frame.width, frame.height);
    faceauth_engine::motion::similarity(&reference.0, frame, r)
}

/// Does a hidden-face sighting at `now` hold off the away clock? Only after
/// a clear sighting, and within `limit` of it (None: no limit).
pub fn partial_holds(now: Instant, last_full: Option<Instant>, limit: Option<Duration>) -> bool {
    last_full
        .map(|t| limit.is_none_or(|l| now.duration_since(t) < l))
        .unwrap_or(false)
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    fn obs(face: bool, identity: Option<bool>) -> Observation {
        obs_at(face, true, identity)
    }

    fn obs_at(face: bool, attentive: bool, identity: Option<bool>) -> Observation {
        Observation {
            face,
            attentive,
            frame: None,
            bbox: if face {
                Some([10.0, 10.0, 80.0, 80.0])
            } else {
                None
            },
            identity,
            near_miss: false,
        }
    }

    fn cfg() -> PresenceConfig {
        PresenceConfig {
            user: "alice".into(),
            away_seconds: 20.0,
            ..Default::default()
        }
    }

    /// Drive the watch through `looks`, five seconds apart, and return the
    /// tick (from 1) at which it first asked for the lock.
    fn first_lock(
        w: &mut Watch,
        t0: Instant,
        looks: &[Observation],
        mode: PresenceMode,
    ) -> Option<usize> {
        for (i, o) in looks.iter().enumerate() {
            let now = t0 + Duration::from_secs(5 * (i as u64 + 1));
            let step = w.step(o, now, mode);
            if step.lock {
                return Some(i + 1);
            }
        }
        None
    }

    /// The live cadence, as `run` computes it: the user passes identity
    /// checks for three ticks and leaves; from tick 4 on a stranger (an
    /// attentive face that fails every check it gets) or nobody is in
    /// view. Returns the seconds from the user's last sighting to the lock,
    /// or None when 200 ticks pass without one.
    fn live_cadence(mode: PresenceMode, stranger: bool, tick_s: f32) -> Option<f32> {
        let cfg = PresenceConfig {
            tick_seconds: tick_s,
            ..cfg()
        };
        let mut w = Watch::new(cfg.clone());
        let t0 = Instant::now();
        for tick in 1u32..200 {
            let now = t0 + Duration::from_secs_f32(tick_s * tick as f32);
            let identify = identify_this_tick(mode, tick, IDENTIFY_EVERY, w.state);
            let user_here = tick <= 3;
            let face = user_here || stranger;
            let identity = if identify && face {
                Some(user_here)
            } else {
                None
            };
            if w.step(&obs(face, identity), now, mode).lock {
                return Some(tick_s * (tick - 3) as f32);
            }
        }
        None
    }

    /// Q9: in the default mode any attentive face holds the lock off, so a
    /// stranger who sits down stays unlocked past away_seconds and for as
    /// long as they look at the screen. They are reported as a stranger
    /// once two checks have failed.
    #[test]
    fn default_mode_a_stranger_present_past_away_seconds_stays_unlocked() {
        let mut w = Watch::new(cfg());
        let t0 = Instant::now();
        let mut looks = vec![obs(true, Some(true))];
        looks.extend((0..12).map(|_| obs(true, Some(false))));
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            None,
            "default: a face looking at the screen holds the clock, whoever it is"
        );
        assert_eq!(w.state, State::Stranger);
        assert!(!w.locked_by_presence);
    }

    /// Q9: the secure mode checks identity on every tick and locks on the
    /// first failed check, so a stranger is out within one tick of sitting
    /// down, whatever the away clock says.
    #[test]
    fn secure_mode_locks_within_one_tick_of_the_first_failed_check() {
        let mut w = Watch::new(cfg());
        let t0 = Instant::now();
        let looks = vec![obs(true, Some(true)), obs(true, Some(false))];
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            Some(2),
            "secure: the first failed check is the lock"
        );
        assert_eq!(w.state, State::Away);
        // With the live cadence the check runs on every tick, so the lock
        // comes one tick after the user's last sighting, on mains and on
        // battery alike; the default mode never locks on the stranger.
        assert_eq!(live_cadence(PresenceMode::Secure, true, 5.0), Some(5.0));
        assert_eq!(live_cadence(PresenceMode::Secure, true, 10.0), Some(10.0));
        assert_eq!(live_cadence(PresenceMode::Default, true, 5.0), None);
        assert_eq!(live_cadence(PresenceMode::Default, true, 10.0), None);
    }

    /// An empty chair locks after away_seconds in both modes, from the
    /// user's last sighting: with the live cadence that is the away time to
    /// the second, on mains and on battery.
    #[test]
    fn an_empty_chair_locks_after_away_seconds_in_both_modes() {
        for mode in [PresenceMode::Default, PresenceMode::Secure] {
            let mut w = Watch::new(cfg());
            let t0 = Instant::now();
            let mut looks = vec![obs(true, Some(true))];
            looks.extend((0..8).map(|_| obs(false, None)));
            // Seen at tick 1 (5 s); the clock runs out at 25 s, tick 5.
            assert_eq!(
                first_lock(&mut w, t0, &looks, mode),
                Some(5),
                "{:?}: an empty chair locks at away_seconds",
                mode
            );
            assert_eq!(w.state, State::Away);
            assert_eq!(live_cadence(mode, false, 5.0), Some(20.0), "{:?}", mode);
            assert_eq!(live_cadence(mode, false, 10.0), Some(20.0), "{:?}", mode);
        }
    }

    /// The secure mode identifies on every tick; the default mode on its
    /// cadence while present and every other tick while unconfirmed.
    #[test]
    fn the_secure_mode_checks_identity_on_every_tick() {
        for tick in 1..=12 {
            assert!(identify_this_tick(
                PresenceMode::Secure,
                tick,
                3,
                State::Present
            ));
            assert!(identify_this_tick(
                PresenceMode::Secure,
                tick,
                3,
                State::Unknown
            ));
            assert_eq!(
                identify_this_tick(PresenceMode::Default, tick, 3, State::Present),
                tick % 3 == 0
            );
            assert_eq!(
                identify_this_tick(PresenceMode::Default, tick, 3, State::Unknown),
                tick % 3 == 0 || tick % 2 == 0
            );
        }
    }

    /// Default mode, the attention rule: the enrolled user is held to the
    /// attention setting (off by default), so reading a paper beside the
    /// screen does not lock the desk; a face whose checks failed has to be
    /// looking at the screen to hold the clock. One failed check is
    /// tolerated before that applies.
    #[test]
    fn default_mode_a_stranger_holds_the_clock_only_while_attentive() {
        let t0 = Instant::now();
        // The user, confirmed, then turned away for a minute: still present.
        let mut looks = vec![obs(true, Some(true))];
        looks.extend(
            (0..12).map(|i| obs_at(true, false, if i % 3 == 2 { Some(true) } else { None })),
        );
        let mut w = Watch::new(cfg());
        assert_eq!(first_lock(&mut w, t0, &looks, PresenceMode::Default), None);
        assert_eq!(w.state, State::Present);
        // A stranger turned away: after the second failed check the face no
        // longer holds the clock, and the lock comes at away_seconds from
        // the last look that did (tick 2, the tolerated first miss).
        let looks = vec![
            obs(true, Some(true)),
            obs_at(true, false, Some(false)),
            obs_at(true, false, Some(false)),
            obs_at(true, false, None),
            obs_at(true, false, None),
            obs_at(true, false, None),
            obs_at(true, false, None),
        ];
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            Some(6),
            "default: a stranger not looking at the screen holds nothing"
        );
        // The same stranger looking at the screen holds it.
        let looks = vec![
            obs(true, Some(true)),
            obs_at(true, true, Some(false)),
            obs_at(true, true, Some(false)),
            obs_at(true, true, None),
            obs_at(true, true, None),
            obs_at(true, true, None),
            obs_at(true, true, None),
        ];
        let mut w = Watch::new(cfg());
        assert_eq!(first_lock(&mut w, t0, &looks, PresenceMode::Default), None);
        assert_eq!(w.state, State::Stranger);
    }

    /// Secure mode: only a face that passed this tick's check holds the
    /// clock. An unchecked face (the gate read no signal) holds nothing,
    /// and is not a lock either: the away clock decides.
    #[test]
    fn secure_mode_an_unconfirmed_face_neither_holds_nor_locks() {
        let mut w = Watch::new(cfg());
        let t0 = Instant::now();
        let mut looks = vec![obs(true, Some(true))];
        looks.extend((0..8).map(|_| obs(true, None)));
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            Some(5),
            "secure: an unconfirmed face lets the clock run out"
        );
    }

    /// The secure mode does not accept identity from the embedding alone:
    /// a gate that ran and read no signal ends the look unchecked there,
    /// while the default mode lets the embedding decide as before. A gate
    /// that cannot run (no strobe control, or switched off) is not a
    /// no-signal read, and the embedding decides in both modes (E4).
    #[test]
    fn secure_mode_does_not_take_identity_from_the_embedding_alone() {
        assert_eq!(after_gate(true, None, true), AfterGate::Unconfirmed);
        assert_eq!(after_gate(true, None, false), AfterGate::Embed);
        assert_eq!(after_gate(true, Some(true), true), AfterGate::Embed);
        assert_eq!(after_gate(true, Some(false), true), AfterGate::Refused);
        assert_eq!(after_gate(true, Some(false), false), AfterGate::Refused);
        assert_eq!(after_gate(false, None, true), AfterGate::Embed);
        assert_eq!(after_gate(false, None, false), AfterGate::Embed);
    }

    /// A hidden face (no face found) holds the clock in both modes, and
    /// only with a matching shape. Without a reference frame there is no
    /// shape, so the hold does not apply and the clock runs.
    #[test]
    fn a_hidden_face_holds_the_clock_in_both_modes_and_only_with_a_shape() {
        let mut frame = Grey::new(120, 120);
        frame
            .data
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i % 251) as u8);
        let seen = Observation {
            face: true,
            attentive: true,
            frame: Some(frame.clone()),
            bbox: Some([20.0, 10.0, 40.0, 40.0]),
            identity: Some(true),
            near_miss: false,
        };
        let hidden = Observation {
            face: false,
            attentive: false,
            frame: Some(frame.clone()),
            bbox: None,
            identity: None,
            near_miss: false,
        };
        let mut looks = vec![seen.clone()];
        looks.extend((0..8).map(|_| hidden.clone()));
        let t0 = Instant::now();
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            None,
            "default: the same shape under the box holds the clock"
        );
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            None,
            "secure: the same shape holds it too"
        );
        // The reference is taken only from a look whose identity passed: a
        // sighting between checks holds the clock itself but leaves no
        // shape to hold it for a hidden face (C1), so a stranger's torso
        // never becomes the reference.
        let unchecked = Observation {
            identity: None,
            near_miss: false,
            ..seen.clone()
        };
        let mut looks = vec![unchecked];
        looks.extend((0..8).map(|_| hidden.clone()));
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            Some(5)
        );
        let stranger = Observation {
            identity: Some(false),
            near_miss: false,
            ..seen.clone()
        };
        let mut looks = vec![seen.clone(), stranger.clone(), stranger];
        looks.extend((0..8).map(|_| hidden.clone()));
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            None,
            "the reference from the user's own sighting still holds for the hidden face"
        );
    }

    /// A face the detector still finds but that neither passes its check
    /// nor looks at the screen (a hand on the chin: the mesh reads no
    /// attentive pose and the crop embeds as nobody) is hidden too, and the
    /// same shape holds the clock in both modes. Before the mesh the five
    /// points called that face attentive and it held on its own.
    #[test]
    fn a_partly_hidden_face_holds_the_clock_through_the_shape_in_both_modes() {
        let mut frame = Grey::new(120, 120);
        frame
            .data
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i % 251) as u8);
        let seen = Observation {
            face: true,
            attentive: true,
            frame: Some(frame.clone()),
            bbox: Some([20.0, 10.0, 40.0, 40.0]),
            identity: Some(true),
            near_miss: false,
        };
        let chin = |identity| Observation {
            face: true,
            attentive: false,
            frame: Some(frame.clone()),
            bbox: Some([20.0, 10.0, 40.0, 40.0]),
            identity,
            near_miss: false,
        };
        // Between checks the look carries no verdict; on a check the
        // covered crop fails. Neither holds by itself.
        let mut looks = vec![seen.clone()];
        looks.extend((0..8).map(|i| chin(if i % 3 == 2 { Some(false) } else { None })));
        let t0 = Instant::now();
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            None,
            "default: the shape under the box holds for a face the mesh cannot read"
        );
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            None,
            "secure: the user's own hand over the face is not a stranger"
        );
        // A different scene under the box (the user left, someone else's
        // torso, or the wall) holds nothing.
        let mut other = Grey::new(120, 120);
        other.data.iter_mut().for_each(|v| *v = 200);
        let mut looks = vec![seen];
        looks.extend((0..14).map(|i| Observation {
            frame: Some(other.clone()),
            ..chin(if i % 3 == 2 { Some(false) } else { None })
        }));
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Default),
            Some(10),
            "default: two failed checks, then the clock runs out"
        );
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            Some(4),
            "secure: the first failed check on a changed chair locks at once"
        );
    }

    /// A face turned to the screen that fails its check is a stranger
    /// looking at the session, not a hidden user, whatever the shape under
    /// it: the secure mode locks on the first such check and the default
    /// mode runs its clock once the two strikes are in.
    #[test]
    fn an_attentive_face_that_fails_its_check_gets_no_shape_hold() {
        let mut frame = Grey::new(120, 120);
        frame
            .data
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i % 251) as u8);
        let seen = Observation {
            face: true,
            attentive: true,
            frame: Some(frame.clone()),
            bbox: Some([20.0, 10.0, 40.0, 40.0]),
            identity: Some(true),
            near_miss: false,
        };
        let stranger = Observation {
            identity: Some(false),
            near_miss: false,
            ..seen.clone()
        };
        let mut looks = vec![seen];
        looks.extend((0..8).map(|_| stranger.clone()));
        let t0 = Instant::now();
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            Some(2),
            "secure: the first failed check on a face looking at the screen locks"
        );
    }

    /// Secure mode, the user leaning on a hand or leaning in to read: the
    /// face stays turned to the screen, the check just misses or the strobe
    /// reads nothing, and the same shape in the chair holds the clock. A
    /// face that misses by a wide margin is a stranger and locks at once,
    /// shape or not; a near miss over a changed chair holds nothing.
    #[test]
    fn secure_mode_holds_a_near_miss_or_an_unread_face_through_the_shape() {
        let mut frame = Grey::new(120, 120);
        frame
            .data
            .iter_mut()
            .enumerate()
            .for_each(|(i, v)| *v = (i % 251) as u8);
        let seen = Observation {
            face: true,
            attentive: true,
            frame: Some(frame.clone()),
            bbox: Some([20.0, 10.0, 40.0, 40.0]),
            identity: Some(true),
            near_miss: false,
        };
        let near = Observation {
            identity: Some(false),
            near_miss: true,
            ..seen.clone()
        };
        let unread = Observation {
            identity: None,
            ..seen.clone()
        };
        let t0 = Instant::now();
        for (what, look) in [("near miss", &near), ("no signal", &unread)] {
            let mut looks = vec![seen.clone()];
            looks.extend((0..8).map(|_| look.clone()));
            let mut w = Watch::new(cfg());
            assert_eq!(
                first_lock(&mut w, t0, &looks, PresenceMode::Secure),
                None,
                "secure: a {} with the same shape holds",
                what
            );
        }
        let far = Observation {
            identity: Some(false),
            near_miss: false,
            ..seen.clone()
        };
        let mut looks = vec![seen.clone(), far];
        looks.extend((0..4).map(|_| unread.clone()));
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            Some(2),
            "secure: a wide miss on a face turned to the screen locks at once"
        );
        let mut other = Grey::new(120, 120);
        other.data.iter_mut().for_each(|v| *v = 200);
        let mut looks = vec![seen.clone()];
        looks.extend((0..4).map(|_| Observation {
            frame: Some(other.clone()),
            ..near.clone()
        }));
        let mut w = Watch::new(cfg());
        assert_eq!(
            first_lock(&mut w, t0, &looks, PresenceMode::Secure),
            Some(2),
            "secure: a near miss over a changed chair locks"
        );
    }

    /// Secure mode looks every tick (5 s, 10 s on battery); the default mode
    /// looks every 10 s.
    #[test]
    fn the_default_mode_looks_less_often_than_the_secure_mode() {
        let c = PresenceConfig::default();
        assert_eq!(tick_for(&c, PresenceMode::Secure, false), 5.0);
        assert_eq!(tick_for(&c, PresenceMode::Secure, true), 10.0);
        assert_eq!(tick_for(&c, PresenceMode::Default, false), 10.0);
        assert_eq!(tick_for(&c, PresenceMode::Default, true), 10.0);
    }

    /// While locked, the watch resumes on a face match, or on the session
    /// reading as unlocked by other means, checked every few ticks, with a
    /// fresh absence clock: an empty chair after a password unlock locks
    /// again at away_seconds, and in the secure mode a stranger locks it
    /// again on the first check (C2). The lock is `SessionLock`'s, driven
    /// here at the watch's own cadence.
    #[test]
    fn the_watch_resumes_after_an_unlock_without_a_face() {
        let lock = SessionLock::new();
        let mut w = Watch::new(cfg());
        let t0 = Instant::now();
        let _ = w.step(&obs(true, Some(true)), t0, PresenceMode::Default);
        lock.adopt(t0 + Duration::from_secs(30));
        w.locked();
        assert!(lock.locked_at().is_some() && w.locked_by_presence);
        let still_locked = || true;
        let unlocked = || false;
        let check_every = Duration::from_secs(5 * LOCK_CHECK_TICKS as u64 - 2);
        let mut tick = 0u64;
        let mut now = || {
            tick += 1;
            t0 + Duration::from_secs(30 + 5 * tick)
        };
        for _ in 0..(LOCK_CHECK_TICKS * 2) {
            assert_eq!(
                lock.resumed(now(), false, check_every, &still_locked),
                None,
                "locked and no match: keep waiting"
            );
        }
        // Unlocked by a password: noticed at the next check tick.
        let mut resumed = None;
        for _ in 0..LOCK_CHECK_TICKS {
            let at = now();
            if let Some(how) = lock.resumed(at, false, check_every, &unlocked) {
                w.resumed(at, false);
                resumed = Some(how);
                break;
            }
        }
        assert_eq!(resumed, Some("without a face"));
        assert!(lock.locked_at().is_none() && !w.locked_by_presence);
        assert_eq!(
            w.state,
            State::Unknown,
            "nobody seen yet after a password unlock"
        );
        // An empty chair from here on: the fresh clock runs from the resume
        // and runs out at 20 s, tick 4.
        let resume_at = t0 + Duration::from_secs(30 + 5 * tick);
        let looks: Vec<Observation> = (0..8).map(|_| obs(false, None)).collect();
        assert_eq!(
            first_lock(&mut w, resume_at, &looks, PresenceMode::Default),
            Some(4),
            "the fresh clock runs out after the resume"
        );
        // A face match resumes at once, and reads as present.
        lock.adopt(resume_at + Duration::from_secs(60));
        w.locked();
        let at = resume_at + Duration::from_secs(65);
        assert_eq!(
            lock.resumed(at, true, check_every, &still_locked),
            Some("by face")
        );
        w.resumed(at, true);
        assert_eq!(w.state, State::Present);
        // In the secure mode a stranger after the resume is out on the
        // first check, one tick in.
        lock.adopt(resume_at + Duration::from_secs(120));
        w.locked();
        let at = resume_at + Duration::from_secs(125);
        assert_eq!(
            lock.resumed(at, true, check_every, &still_locked),
            Some("by face")
        );
        w.resumed(at, true);
        let looks: Vec<Observation> = (0..4).map(|_| obs(true, Some(false))).collect();
        assert_eq!(
            first_lock(
                &mut w,
                resume_at + Duration::from_secs(125),
                &looks,
                PresenceMode::Secure
            ),
            Some(1)
        );
    }

    /// One lock, two askers: a consent request that parked behind the lock
    /// and the watch that took it over see the same unlock, whichever asks
    /// first, and the compositor is asked on one shared cadence (H13).
    #[test]
    fn a_consent_park_and_the_watch_see_the_same_unlock() {
        let lock = SessionLock::new();
        let t0 = Instant::now();
        assert_eq!(lock.adopt(t0), t0);
        assert_eq!(
            lock.adopt(t0 + Duration::from_secs(9)),
            t0,
            "a lock already recorded is not moved"
        );
        let asked = std::cell::Cell::new(0u32);
        let locked = || {
            asked.set(asked.get() + 1);
            true
        };
        let unlocked = || {
            asked.set(asked.get() + 1);
            false
        };
        let park = Duration::from_secs(2);
        // The park asks every two seconds, the watch every few ticks; a
        // check by one is a check for both.
        assert_eq!(
            lock.resumed(t0 + Duration::from_secs(1), false, park, &locked),
            None
        );
        assert_eq!(asked.get(), 1);
        assert_eq!(
            lock.resumed(t0 + Duration::from_secs(2), false, park, &locked),
            None
        );
        assert_eq!(asked.get(), 1, "inside the cadence, not asked again");
        assert_eq!(
            lock.resumed(
                t0 + Duration::from_secs(3),
                false,
                Duration::from_secs(15),
                &locked
            ),
            None
        );
        assert_eq!(asked.get(), 1, "the watch shares the park's last check");
        // The park sees the password unlock first.
        assert_eq!(
            lock.resumed(t0 + Duration::from_secs(4), false, park, &unlocked),
            Some("without a face")
        );
        assert!(lock.locked_at().is_none());
        // The watch, asking next, finds the lock gone and resumes too.
        assert_eq!(
            lock.resumed(t0 + Duration::from_secs(5), false, park, &locked),
            Some("elsewhere")
        );
        // A face match newer than the lock resumes without asking.
        lock.adopt(t0 + Duration::from_secs(10));
        let before = asked.get();
        assert_eq!(
            lock.resumed(t0 + Duration::from_secs(11), true, park, &locked),
            Some("by face")
        );
        assert_eq!(asked.get(), before);
    }

    #[test]
    fn the_mode_switch_is_read_by_name() {
        assert_eq!(PresenceMode::parse("secure"), Some(PresenceMode::Secure));
        assert_eq!(PresenceMode::parse("default"), Some(PresenceMode::Default));
        assert_eq!(PresenceMode::parse("Secure"), None);
        set_presence_mode(PresenceMode::Secure);
        assert_eq!(presence_mode(), PresenceMode::Secure);
        set_presence_mode(PresenceMode::Default);
        assert_eq!(presence_mode(), PresenceMode::Default);
    }
}

#[cfg(test)]
mod partial_tests {
    use super::*;

    #[test]
    fn a_partial_face_holds_the_clock_only_after_a_full_sighting_and_only_for_the_hold() {
        let now = Instant::now();
        let two = Some(Duration::from_secs(120));
        assert!(
            !partial_holds(now, None, two),
            "never seen in full: a weak blob is not the user"
        );
        assert!(!partial_holds(now, None, None));
        assert!(partial_holds(now, Some(now - Duration::from_secs(30)), two));
        assert!(!partial_holds(
            now,
            Some(now - Duration::from_secs(121)),
            two
        ));
        assert!(
            partial_holds(now, Some(now - Duration::from_secs(4 * 3600)), None),
            "no limit holds as long as the shape does"
        );
    }

    /// Mike, 2026-09-24: the default mode ships with "never", the secure
    /// mode with two minutes; secure is bounded 1 to 10 minutes, the default
    /// takes "never" or minutes from 1.
    #[test]
    fn obscured_face_lock_defaults_parse_and_clamp() {
        let c = PresenceConfig::default();
        assert_eq!(c.obscured_lock_for(PresenceMode::Default), None);
        assert_eq!(
            c.obscured_lock_for(PresenceMode::Secure),
            Some(Duration::from_secs(120))
        );
        assert!(c.obscured_lock_warnings().is_empty());
        let parse = |t: &str| -> PresenceConfig { toml::from_str(t).unwrap() };
        let c = parse("obscured_face_lock = 30\nsecure_obscured_face_lock = 5");
        assert_eq!(
            c.obscured_lock_for(PresenceMode::Default),
            Some(Duration::from_secs(1800))
        );
        assert_eq!(
            c.obscured_lock_for(PresenceMode::Secure),
            Some(Duration::from_secs(300))
        );
        let c = parse("obscured_face_lock = \"never\"");
        assert_eq!(c.obscured_lock_for(PresenceMode::Default), None);
        let c = parse("obscured_face_lock = 0\nsecure_obscured_face_lock = 60");
        assert_eq!(
            c.obscured_lock_for(PresenceMode::Default),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            c.obscured_lock_for(PresenceMode::Secure),
            Some(Duration::from_secs(600))
        );
        assert_eq!(c.obscured_lock_warnings().len(), 2);
        assert!(toml::from_str::<PresenceConfig>("obscured_face_lock = \"forever\"").is_err());
    }
}
