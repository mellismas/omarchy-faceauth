//! The consent record: the request on screen, the requests queued behind
//! it, and the answer, token and rider each one carries. It is one static
//! behind one lock because the socket threads answer a request that the
//! attempt thread is waiting on.

use super::passwordless::PASSWORDLESS_MAX_MINUTES;
use super::window::ACK_DWELL;
use crate::lockgate::{Bind, Desktop, Facts, LockState, Verdict, BEAT, DROP_CLEARS, UNKNOWN_LIMIT};
use anyhow::Result;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// `key_unlock_hold_ms` as shipped (round 7, B): with the lock screen's
/// reserved channel holding the latch for the whole lock, the hold only
/// lets the unlock settle (a finger still on the key that unlocked it).
pub const DEFAULT_HOLD_MS: u64 = 500;

/// How long the anchored compositor must have said unlocked, look after
/// look, before an open lock channel it contradicts expires (fix round 8,
/// both reviewers): the channel is no longer counted, its thread closes
/// it, and the hold runs as after a graceful close.
pub const CHANNEL_EXPIRES: Duration = UNKNOWN_LIMIT;

/// Looks further apart than this break a steady "unlocked" (the stretch
/// starts over), for a channel's expiry and a drop's release alike.
pub const LOOK_GAP: Duration = Duration::from_secs(2);

/// The daemon's clock for the two times it keeps in atomics: the start
/// and the last refusal at the connection places.
static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

fn epoch_ms() -> u64 {
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// "Never" in those atomics.
const NEVER: u64 = u64::MAX;

/// Write `{"result":"pending"}` to a waiting PAM line's socket, without
/// blocking and without a signal: the daemon is still at work on its
/// request (round 6, item 12). A full socket buffer skips the beat.
pub(crate) fn send_beat(fd: &impl std::os::fd::AsRawFd) {
    let line = b"{\"result\":\"pending\"}\n";
    // SAFETY: `fd` is an open socket for the call; the buffer and its
    // length are a valid slice; MSG_DONTWAIT and MSG_NOSIGNAL make the
    // call neither block nor raise SIGPIPE.
    let _ = unsafe {
        libc::send(
            fd.as_raw_fd(),
            line.as_ptr().cast(),
            line.len(),
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
}

/// A typed password on its way to the PAM check: wiped when dropped, so a
/// copy left in a map or a gesture does not stay readable in freed memory
/// (and from there in swap or a hibernation image) after the check (F12).
/// Copies made before it is wrapped (the request line, the JSON field)
/// are wiped by the server as it builds one.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: String) -> Secret {
        Secret(s)
    }
}

impl std::ops::Deref for Secret {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe_string(&mut self.0);
    }
}

/// Overwrite a string's bytes with zeros before they are freed. A volatile
/// write, so the optimizer cannot drop it as a dead store; the string is
/// left empty, which is valid UTF-8.
pub fn wipe_string(s: &mut String) {
    // SAFETY: zero bytes are valid UTF-8, and the vector is cleared before
    // the borrow ends, so no partial sequence is left behind.
    wipe_bytes(unsafe { s.as_mut_vec() });
}

/// `wipe_string` for bytes that are not yet, or never became, a string.
pub fn wipe_bytes(v: &mut Vec<u8>) {
    for b in v.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusively borrowed byte.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    v.clear();
}

/// What the window (or the CLI) can send while a request is pending, and
/// what the flow reads off the live record between frames.
#[derive(Clone, Debug)]
pub enum Answer {
    /// The user typed their password into the window.
    Password(Secret),
    /// The requester hung up its socket: nobody is waiting for the verdict.
    /// Nothing sends this; `ConsentState::poll` reads it off the request
    /// socket itself.
    Gone,
    /// The user dismissed or killed: refuse now.
    Dismiss,
    /// The card's "Ready to nod" button: the user is back at the card
    /// after a nod window passed unanswered, so the nods may be armed
    /// again. It approves nothing and is ignored wherever nods are
    /// already armed or the face is being scanned.
    Rearm,
    /// The user touched their security key and pam_u2f accepted it: an
    /// approval, as a right password is. Only the key watch writes it
    /// (`ConsentState::key_touched`); the socket's `answer` refuses it.
    Key,
    /// The user's finger matched on the fingerprint reader and pam_fprintd
    /// accepted it: an approval, as the key's touch is. A variant of its
    /// own, not the key's, so two-factor can count the two apart. Only the
    /// fingerprint watch writes it (`ConsentState::fprint_matched`); the
    /// socket's `answer` refuses it.
    Fingerprint,
}

/// The passwordless-sudo rider of the live consent request. The rider is
/// what the card's button asks for: that the approval of this request
/// also turn passwordless sudo on for some minutes. It belongs to the one
/// request on screen and is honored only by the approval of that same
/// request: a request that ends any other way takes its rider with it, so
/// nothing armed at one card can ride on the approval of the next. The
/// record also carries what the daemon knows at arm time, since the arm
/// arrives on the socket thread: whether the lane is sudo (a sudoers rule
/// means nothing to polkit) and whether the nod window is following the
/// enrolled face right now. Both gate the arm, so a program driving the
/// socket cannot arm a rider the person in front of the camera could not.
#[derive(Clone, Debug, Default, PartialEq)]
struct Rider {
    /// The lane the card was shown on: `Some(true)` for sudo. None until
    /// the first payload, so nothing can be armed before a card is up.
    lane: Option<bool>,
    face_present: bool,
    minutes: Option<u32>,
    /// The card has been sent a payload naming these minutes. An arm that
    /// lands after the card's last payload is not honored until the card
    /// has shown it: the nod must be at a card that says what it grants.
    shown: bool,
}

/// What the card's payload says about the key.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct KeyCard {
    /// A key watch is running: a touch approves.
    pub armed: bool,
    /// The lane's key line asks for a PIN: the card shows its PIN field.
    pub pin: bool,
    /// No PIN is waiting or in use: the card asks for it, rather than for
    /// a touch.
    pub pin_wanted: bool,
}

#[cfg(test)]
impl KeyCard {
    /// (armed, PIN lane), as the tests compare them.
    pub(super) fn pair(self) -> (bool, bool) {
        (self.armed, self.pin)
    }
}

/// What the card says about the fingerprint while it is armed: one short
/// word the card turns into its line. pam_fprintd's own messages carry no
/// more than this, and the card needs no more (`consent/fprint.rs`).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub enum FprintStatus {
    /// Place a finger on the reader: the check is asking, or about to.
    #[default]
    Place,
    /// The last finger did not match; the check asks again.
    Retry,
    /// The reader did not answer the check: another program holds it, or
    /// it is not there. The watch asks again a little later.
    Busy,
}

impl FprintStatus {
    /// The word the card's payload carries.
    pub fn word(self) -> &'static str {
        match self {
            FprintStatus::Place => "place",
            FprintStatus::Retry => "retry",
            FprintStatus::Busy => "busy",
        }
    }
}

/// What the card's payload says about the fingerprint.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub(super) struct FprintCard {
    /// A fingerprint watch is running: a matching finger approves.
    pub armed: bool,
    /// What the card says beside it.
    pub status: FprintStatus,
}

/// Which lock screen lane asks, for a latch that begins with an ask: the
/// key's and the fingerprint's are counted apart, so the two lanes the
/// lock screen runs side by side never refuse each other's ask.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum UnlockAsk {
    Key,
    Fprint,
}

/// The one consent request on screen. The answer token is handed to the
/// window in the payload, and an answer, an acknowledgment or a rider is
/// written in here only with it: a process that can reach the socket but
/// did not see the window cannot cancel or answer the request. The record
/// lives exactly as long as the request holds the window (`Turn`), so
/// nothing from one request is left for the next to find.
pub struct Live {
    uid: u32,
    user: String,
    token: String,
    /// The window has drawn the request this token names. The daemon
    /// summons the window through the shell and hears "ok" from the shell,
    /// not from the window: a disabled plugin, a shell that answers for a
    /// window it does not have, or a window replaced by another summon all
    /// leave the shell's answer the same. So the window itself, once it has
    /// drawn the request, sends the token back; until that arrives no nod
    /// is read, and if it does not arrive the request falls to the password.
    /// When it did: a key touch counts only for a check that started a
    /// dwell after the latest acknowledgment.
    acked: Option<Instant>,
    answer: Option<Answer>,
    rider: Rider,
    /// The generation of the key watch running for this request's card
    /// (`KeyWatch`), while one runs: the card says the key works, and a
    /// touch from a check of that watch may answer. Cleared when the watch
    /// ends, when the round waits and when it parks, so a check still out
    /// from an earlier watch answers nothing, even on the same request.
    key_armed: Option<u64>,
    /// The last key watch generation handed out for this request.
    key_gen: u64,
    /// The lane's key line asks for a PIN (`pinverification=1`): the
    /// card shows a PIN field while the key is armed, and a check runs only
    /// with a PIN the card sent.
    key_pin_wanted: bool,
    /// That PIN, for the next check alone, wiped when dropped.
    key_pin: Option<Secret>,
    /// A check is running with the PIN the card sent: the card says to
    /// touch the key, not to type the PIN.
    key_pin_busy: bool,
    /// The card is to be sent again: a key check ended and its PIN is
    /// spent, so the card asks for the PIN once more, or the fingerprint's
    /// status changed.
    card_stale: bool,
    /// The generation of the fingerprint watch running for this request's
    /// card (`FprintWatch`), while one runs, under the key's rules: a
    /// finger from a check of that watch may answer, and only that one.
    fprint_armed: Option<u64>,
    /// The last fingerprint watch generation handed out for this request.
    fprint_gen: u64,
    /// What the card says about the fingerprint while it is armed.
    fprint_status: FprintStatus,
    /// A dup of the requester's socket, polled for its hang-up and told,
    /// every `BEAT`, that the daemon is still at work on it.
    requester: Option<std::os::fd::OwnedFd>,
    /// A pidfd of the process the request is for, when that is not the
    /// one holding the socket: the program polkitd named, whose helper
    /// stays connected after polkitd gives the request up (live test 1,
    /// 2026-10-13: a parked request's card came back at the unlock and took
    /// a nod 7 minutes after its pkexec was gone). Polled for its exit.
    process: Option<std::os::fd::OwnedFd>,
    beat_at: Instant,
}

impl Live {
    /// Has the requester gone: its socket hung up, or the process the
    /// request is for exited?
    fn left(&self) -> bool {
        self.requester.as_ref().is_some_and(peer_gone)
            || self.process.as_ref().is_some_and(process_exited)
    }

    /// Tell the requester the daemon is still at work, if a beat is due.
    /// Every wait loop of the request reads the record between frames, so
    /// the beats stop with the request's own progress: a request stuck
    /// anywhere goes quiet, and its PAM line gives up on it.
    fn beat(&mut self) {
        if self.beat_at.elapsed() >= BEAT {
            self.beat_at = Instant::now();
            if let Some(fd) = &self.requester {
                send_beat(fd);
            }
        }
    }
}

struct Queue {
    live: Option<Live>,
    /// Requests waiting for the window, in arrival order: place id and uid.
    waiting: std::collections::VecDeque<(u64, u32)>,
    next_id: u64,
    /// The users whose lock screen has asked for the key, or said it is
    /// up: their card stays off the key until the daemon has seen the
    /// session unlocked and the hold has passed since (`unlock_holds`).
    latches: Vec<Latch>,
    /// The key fallbacks under way, by user and number: a sudo or polkit
    /// stack's own key line, run by the daemon (`KeyLane::fallback`).
    fallbacks: Vec<(String, u64)>,
    next_fallback: u64,
    /// Since when the verdict on each user has been `Unknown` without a
    /// break (Opus N1).
    doubts: Vec<(String, Instant)>,
    /// When each account's share of the connection places last refused it
    /// (round 7, C): that account alone is latched for a hold.
    refused: Vec<(String, Instant)>,
    /// When a consent request of each account last spent its wait budget
    /// (round 8): for `UNKNOWN_LIMIT` after, that account's key line goes
    /// on to the password, so the face line and the key line together
    /// stay inside the password deadline.
    spent: Vec<(String, Instant)>,
    /// When the last key unlock of any account ended, or its unlock was
    /// seen after it: until the hold has passed since, no account's
    /// approval check runs (round 8, the unlock lane's priority).
    unlock_ended: Option<Instant>,
    /// The next lock channel's id, and the ids of channels expired that
    /// their threads have not closed yet.
    next_channel: u64,
    expired: Vec<u64>,
    /// Moves on when the shared key's priority starts and when the
    /// daemon's connection places refuse a caller, which concern every
    /// account: a commit that looked before taking the record's lock
    /// refuses when it moved meanwhile (fix round 8).
    epoch: u64,
    /// Each account's own epoch, moved by that account's latches and its
    /// share of the places refusing it, and by nothing of another
    /// account's (fix round 10, Opus N2 and Codex 5): one account's
    /// channel churn cannot refuse another's commits.
    epochs: Vec<(String, u64)>,
}

/// A key-unlock latch on one user. Latched by the lock screen's first ask
/// or its word that it is up, and by the daemon's own lock; released only
/// once no ask runs, the compositor has been seen to say unlocked, and
/// the hold (`key_unlock_hold_ms`) has passed since. A touch that unlocked
/// is no evidence of the unlock on its own, and neither is the lock
/// screen hanging up: both are the user's code to fake.
struct Latch {
    user: String,
    /// Key unlock asks under way.
    asking: usize,
    /// Fingerprint unlock asks under way: the lock screen runs its key
    /// and fingerprint lanes side by side, and either keeps the latch.
    fprint_asking: usize,
    /// The lock screen's reserved channels open now (round 7, B), and
    /// their ids.
    channels: usize,
    open_ids: Vec<u64>,
    /// The last look at the compositor for this user: looks further apart
    /// than `LOOK_GAP` break a steady unlock.
    last_look: Option<Instant>,

    /// A channel dropped without its graceful "unlocked": the latch stays
    /// until a later channel closes gracefully, or the compositor has said
    /// unlocked, look after look, for `DROP_CLEARS` (round 8). Until then
    /// the latch reads as unknown.
    dropped: bool,
    /// When the compositor was first seen to say unlocked with no ask
    /// under way, no channel open and no drop: the hold's clock. None
    /// until then; a latch whose clock does not run is unknown, never
    /// held (round 8).
    unlocked_at: Option<Instant>,
    /// Since when every look has found the compositor saying unlocked,
    /// whatever else holds the latch; None after a lock, a doubt, a
    /// channel opening or an ask.
    unlocked_since: Option<Instant>,
    /// The shared key's priority this account holds (fix round 9, Codex 1
    /// and Opus L2): its uid and the id of the session its lock screen
    /// asked from, resolved when it started (fix round 10, Opus N1 and
    /// Codex 4: the one desktop pinned, not "whichever is the one now"),
    /// set only after a fresh anchored Locked check, and ended only by
    /// that account's anchored unlock (then the hold) or by logind's
    /// record for that session no longer saying it is in the foreground
    /// of its seat (`lockgate::session_on_seat_in_front`). No timer ends it.
    priority: Option<(u32, String)>,
}

/// The consent requests of the daemon: the one on screen and the ones
/// waiting behind it, under one lock. Requests of the same user queue and
/// take the window in arrival order; a request of another user is refused
/// at once and falls to its password, so one user's parked request never
/// holds another's sudo open (B1). The condition variable wakes the
/// waiters when the window frees and the window's first show when the
/// acknowledgment lands.
pub struct ConsentState {
    q: Mutex<Queue>,
    cv: std::sync::Condvar,
    /// `key_unlock_hold_ms`: how long a latch outlives the unlock the
    /// daemon saw.
    hold_ms: AtomicU64,
    /// When the daemon started serving (`epoch_ms`), or `NEVER`: for one
    /// hold after it every user counts as latched, since a daemon that
    /// starts knows nothing of the locks before it (Opus N3).
    started_ms: AtomicU64,
    /// When the connection places last refused or dropped a caller, or
    /// `NEVER`: for one hold after it every user counts as latched, so
    /// filling the places can only deny service, never open an approval
    /// (round 6, item 10).
    refused_ms: AtomicU64,
    /// Where logind's records are read for the key's priority: None for
    /// /run/systemd (a test sets its own).
    logind: Mutex<Option<std::path::PathBuf>>,
}

impl std::fmt::Debug for ConsentState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConsentState")
    }
}

pub static CONSENT: ConsentState = ConsentState::new();

/// Consent requests live or waiting, per uid. A user running many things
/// at once (twenty agent sessions each calling sudo from its own terminal)
/// may well have a dozen waiting; the bound is against a runaway same-uid
/// loop holding threads open, not a limit anyone is meant to reach. The
/// unit's TasksMax is sized for this many (packaging/faceauth.service, D6).
pub const CONSENT_PER_UID: usize = 32;

/// Why a request gets no place in the queue, or loses it while waiting.
#[derive(Debug, PartialEq)]
pub enum NoTurn {
    /// Another user's request holds the window.
    OtherUser(u32),
    /// This user already has `CONSENT_PER_UID` requests live or waiting.
    TooMany,
    /// The requester hung up while waiting.
    Gone,
    /// The request ahead has shown no acknowledged card for
    /// `QUEUE_UNSEEN` (its summon stalled, or its card never came): this
    /// one stops waiting and goes on to the password (fix round 10).
    Stalled,
}

/// How long a queued request waits behind requests that show no
/// acknowledged card: a summon read to its limit and the window's
/// acknowledgment waited out, so a card that comes slowly is not given up
/// on. Waits behind a card on screen, acknowledged (the user at work on
/// it), are the user's and have no such bound; the request on screen has
/// its own (fix round 10, Opus N4).
pub const QUEUE_UNSEEN: Duration = Duration::from_millis(
    super::shell::USER_CALL_WITHIN.as_millis() as u64 + super::window::ACK_WAIT.as_millis() as u64,
);

/// A place in the queue, given back when dropped.
#[derive(Debug)]
pub struct Place<'a> {
    id: u64,
    uid: u32,
    state: &'a ConsentState,
}

impl Drop for Place<'_> {
    fn drop(&mut self) {
        let mut q = self.state.lock();
        q.waiting.retain(|(id, _)| *id != self.id);
        self.state.cv.notify_all();
    }
}

/// The window, held for the whole request and released when it ends
/// however it ends. Dropping it forgets the live record.
pub struct Turn<'a> {
    state: &'a ConsentState,
}

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        self.state.lock().live = None;
        self.state.cv.notify_all();
    }
}

/// Has the peer of this socket hung up? `POLLRDHUP` says so the moment it
/// closes, without a thread blocked in a read and without consuming a
/// byte; an error from the poll reads as gone.
pub fn peer_gone(fd: &std::os::fd::OwnedFd) -> bool {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use std::os::fd::AsFd;
    // nix 0.30 does not name POLLRDHUP; the bit is libc's.
    let rdhup = PollFlags::from_bits_retain(libc::POLLRDHUP);
    let hung_up = rdhup | PollFlags::POLLHUP | PollFlags::POLLERR;
    let mut fds = [PollFd::new(fd.as_fd(), rdhup | PollFlags::POLLHUP)];
    match poll(&mut fds, PollTimeout::ZERO) {
        Ok(0) => false,
        Ok(_) => fds[0]
            .revents()
            .map(|r| r.intersects(hung_up))
            .unwrap_or(true),
        Err(_) => true,
    }
}

/// Has the process behind this pidfd exited? A pidfd polls readable once
/// it has; an error from the poll reads as exited.
pub fn process_exited(fd: &std::os::fd::OwnedFd) -> bool {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use std::os::fd::AsFd;
    let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
    match poll(&mut fds, PollTimeout::ZERO) {
        Ok(n) if n > 0 => true,
        Ok(_) => false,
        Err(_) => true,
    }
}

/// A fresh look at the session for a commit: the compositor's word and
/// logind's records, asked under the record's lock.
pub type Look<'a> = &'a dyn Fn() -> (LockState, Desktop);

/// Whether the request's own session is in front, asked at a commit after
/// its look, under the record's lock (fix round 12, Codex 1).
pub type Front<'a> = &'a dyn Fn() -> bool;

impl Default for ConsentState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsentState {
    pub const fn new() -> Self {
        ConsentState {
            q: Mutex::new(Queue {
                live: None,
                waiting: std::collections::VecDeque::new(),
                next_id: 0,
                latches: Vec::new(),
                fallbacks: Vec::new(),
                next_fallback: 0,
                doubts: Vec::new(),
                refused: Vec::new(),
                spent: Vec::new(),
                unlock_ended: None,
                next_channel: 0,
                expired: Vec::new(),
                epoch: 0,
                epochs: Vec::new(),
            }),
            cv: std::sync::Condvar::new(),
            hold_ms: AtomicU64::new(DEFAULT_HOLD_MS),
            started_ms: AtomicU64::new(NEVER),
            refused_ms: AtomicU64::new(NEVER),
            logind: Mutex::new(None),
        }
    }

    /// The configured `key_unlock_hold_ms`.
    pub fn set_key_unlock_hold(&self, hold: Duration) {
        self.hold_ms.store(
            hold.as_millis().min(u128::from(u64::MAX)) as u64,
            Ordering::Relaxed,
        );
    }

    fn hold(&self) -> Duration {
        Duration::from_millis(self.hold_ms.load(Ordering::Relaxed))
    }

    /// The daemon starts serving: every user is latched for one hold.
    pub fn mark_started(&self) {
        self.started_ms.store(epoch_ms(), Ordering::SeqCst);
    }

    /// The connection places refused or dropped a caller: every user is
    /// latched for one hold from now.
    pub fn note_refusal(&self) {
        self.refused_ms.store(epoch_ms(), Ordering::SeqCst);
        self.lock().epoch += 1;
    }

    /// `user`'s share of the places refused them: that account alone is
    /// latched for one hold from now (round 7, C).
    pub fn note_refusal_for(&self, user: &str) {
        let mut q = self.lock();
        q.refused.retain(|(u, _)| u != user);
        q.refused.push((user.to_string(), Instant::now()));
        Self::move_epoch(&mut q, user);
    }

    /// Move `user`'s own epoch on.
    fn move_epoch(q: &mut Queue, user: &str) {
        match q.epochs.iter_mut().find(|(u, _)| u == user) {
            Some((_, e)) => *e += 1,
            None => q.epochs.push((user.to_string(), 1)),
        }
    }

    /// The epochs a commit of `user`'s compares: every account's, and
    /// their own.
    fn epochs_of(q: &Queue, user: &str) -> (u64, u64) {
        let own = q
            .epochs
            .iter()
            .find(|(u, _)| u == user)
            .map_or(0, |(_, e)| *e);
        (q.epoch, own)
    }

    /// Whether `user` counts as saturated now: the daemon's places, or
    /// their own share, refused a caller within one hold.
    fn saturated_in(&self, q: &mut Queue, user: &str, hold: Duration) -> bool {
        q.refused.retain(|(_, at)| at.elapsed() < hold);
        self.within_hold(&self.refused_ms) || q.refused.iter().any(|(u, _)| u == user)
    }

    /// Whether `at` (an `epoch_ms` time, or `NEVER`) is within one hold.
    fn within_hold(&self, at: &AtomicU64) -> bool {
        let at = at.load(Ordering::SeqCst);
        at != NEVER && epoch_ms().saturating_sub(at) < self.hold().as_millis() as u64
    }

    /// The facts of `user`'s latch, under the caller's lock: whether a
    /// latch holds them (their own, the daemon's start, or its connection
    /// places refusing callers), whether the lock screen's reserved
    /// channel is open for them now, and whether the latch's clock runs
    /// (their own latch's hold after a seen unlock, or no latch of their
    /// own: the start's ends by itself, and a refusal reads as saturated).
    fn latch_facts(&self, q: &mut Queue, user: &str, hold: Duration) -> (bool, bool, bool) {
        let open = q.latches.iter().any(|l| l.user == user && l.channels > 0);
        let own = Self::held(q, user, hold);
        let holding = !own
            || q.latches
                .iter()
                .any(|l| l.user == user && l.unlocked_at.is_some());
        let latched = own || self.within_hold(&self.started_ms) || self.saturated_in(q, user, hold);
        (latched, open, holding)
    }

    /// Whether the shared key's priority holds now: an account whose
    /// lock screen asked for the key from a session found locked holds it
    /// until its anchored unlock and the hold after it, or until logind's
    /// records show its session gone (fix round 9, Codex 1 and Opus L2),
    /// and no account's approval check runs or counts meanwhile. One key
    /// may be registered to several accounts, and nothing tells their
    /// checks apart by device, so the lock screen's touch must reach
    /// nothing but its own check, however slow or suspended its retries.
    fn unlock_priority(&self, q: &mut Queue, hold: Duration) -> bool {
        self.end_background_priorities(q);
        q.latches.iter().any(|l| l.priority.is_some())
            || q.unlock_ended.is_some_and(|t| t.elapsed() < hold)
    }

    /// End every priority whose session is no longer in the foreground
    /// of its seat (fix round 10; on a seat, fix round 13, Opus N3):
    /// switched away from (a VT switch to another account), closing or
    /// gone, whatever other sessions the account has. Its unlock check
    /// stops at once on its own (`KeyLane::unlock`), and no other check
    /// starts before it has (`KeyLane::claim`).
    fn end_background_priorities(&self, q: &mut Queue) {
        for l in q.latches.iter_mut() {
            if let Some((uid, id)) = &l.priority {
                if !self.session_on_seat_in_front(*uid, id) {
                    log::info!(
                        "consent: {}'s session {} is no longer in the foreground; the key's priority for it ends",
                        l.user,
                        id
                    );
                    l.priority = None;
                }
            }
        }
    }

    /// The logind records root: a test's, or /run/systemd; None under a
    /// test that set none, which never reads the machine's.
    fn logind_root(&self) -> Option<std::path::PathBuf> {
        let root = self
            .logind
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        match root {
            Some(root) => Some(root),
            None if cfg!(test) => None,
            None => Some(std::path::PathBuf::from("/run/systemd")),
        }
    }

    /// Whether session `id` of `uid`'s is in the foreground of a seat
    /// (`lockgate::session_on_seat_in_front`; fix round 13, Opus N3): a
    /// session with no seat, which logind writes as always active, never
    /// is. A test with no records takes it as in front.
    fn session_on_seat_in_front(&self, uid: u32, id: &str) -> bool {
        match self.logind_root() {
            Some(root) => crate::lockgate::session_on_seat_in_front(&root, uid, id) == Some(true),
            None => true,
        }
    }

    /// The session of `uid`'s that `bind` names for the anchor, resolved
    /// now (`lockgate::controlled_session_of`), if it is in the foreground
    /// of its seat: the rule approvals use (fix round 13, Opus N3), so a
    /// seatless session a user retyped wayland never holds the key's
    /// priority. A test with no records names a session of its own.
    fn session_for_priority(&self, uid: u32, bind: &Bind) -> Option<String> {
        let Some(root) = self.logind_root() else {
            return match bind {
                Bind::Session(id) => Some(id.clone()),
                Bind::OnlyDesktop => Some("test-desktop".into()),
                Bind::Ambiguous => None,
            };
        };
        let id = crate::lockgate::controlled_session_of(&root, uid, bind)?;
        (crate::lockgate::session_on_seat_in_front(&root, uid, &id) == Some(true)).then_some(id)
    }

    /// Whether the session `bind` names for an unlock of `uid`'s (the one
    /// the anchor would ask about) is in the foreground now (fix round 11,
    /// Opus N3): asked before the anchor, so a locked account in the
    /// background starts no unit.
    pub(super) fn unlock_session_in_front(&self, uid: u32, bind: &Bind) -> bool {
        self.session_for_priority(uid, bind).is_some()
    }

    /// Whether the request's own session, the one `bind` names, is in the
    /// foreground now (fix round 11, Opus N2): a session of the request's
    /// own (sudo in a session scope, a text console's), or from the user
    /// manager the user's one desktop. An approval check starts, runs and
    /// commits only while it is, so a touch made at another account's
    /// screen never approves a request left running in the background.
    /// In front means `ACTIVE=1` on a seat: a session with no seat (an SSH
    /// login), which logind always writes as active, counts only while the
    /// desktop its lock question goes to is in front on its seat (fix round
    /// 12, Opus N1). A test with no records takes it as in front.
    pub(super) fn request_session_in_front(&self, uid: u32, bind: &Bind) -> bool {
        let Some(root) = self.logind_root() else {
            return true;
        };
        let id = match bind {
            Bind::Session(id) => Some(id.clone()),
            Bind::OnlyDesktop => crate::lockgate::controlled_session_of(&root, uid, bind),
            Bind::Ambiguous => None,
        };
        let Some(id) = id else {
            return false;
        };
        match crate::lockgate::session_on_seat_in_front(&root, uid, &id) {
            Some(true) => true,
            // A session with no seat (an SSH login) is never in front by
            // itself (fix round 12, Opus N1): only while the desktop its
            // lock question goes to is in front on its seat.
            Some(false) => crate::lockgate::controlled_session_of(&root, uid, bind)
                .filter(|d| *d != id)
                .is_some_and(|d| {
                    crate::lockgate::session_on_seat_in_front(&root, uid, &d) == Some(true)
                }),
            None => false,
        }
    }

    /// Whether `user` still holds the key's priority, its session in the
    /// foreground: their unlock check stops the moment it does not.
    pub(super) fn holds_priority(&self, user: &str) -> bool {
        let mut q = self.lock();
        self.end_background_priorities(&mut q);
        q.latches
            .iter()
            .any(|l| l.user == user && l.priority.is_some())
    }

    /// Read logind's records under `root` (a test's).
    #[cfg(test)]
    pub(crate) fn set_logind_root(&self, root: &std::path::Path) {
        *self.logind.lock().unwrap_or_else(|p| p.into_inner()) = Some(root.to_path_buf());
    }

    /// Whether `user`'s approvals are barred now, under the caller's lock:
    /// a latch of theirs, or the shared key's priority.
    fn barred(&self, q: &mut Queue, user: &str, hold: Duration) -> bool {
        let (latched, _, _) = self.latch_facts(q, user, hold);
        latched || self.unlock_priority(q, hold)
    }

    /// The accounts holding the key's priority, and the sessions their
    /// lock screens asked from: whoever is held off looks at these, so
    /// their unlock is seen (`KeyLane::refresh_priority`).
    pub(super) fn priority_holders(&self) -> Vec<(String, Bind)> {
        self.lock()
            .latches
            .iter()
            .filter_map(|l| {
                l.priority
                    .as_ref()
                    .map(|(_, id)| (l.user.clone(), Bind::Session(id.clone())))
            })
            .collect()
    }

    /// A consent request of `user`'s spent its wait budget (round 8): for
    /// `UNKNOWN_LIMIT` from now their key line goes on to the password.
    pub fn note_budget_spent(&self, user: &str) {
        let mut q = self.lock();
        q.spent.retain(|(u, _)| u != user);
        q.spent.push((user.to_string(), Instant::now()));
    }

    /// Whether a consent request of `user`'s spent its wait budget within
    /// `UNKNOWN_LIMIT`.
    pub fn budget_spent(&self, user: &str) -> bool {
        let mut q = self.lock();
        q.spent.retain(|(_, at)| at.elapsed() < UNKNOWN_LIMIT);
        q.spent.iter().any(|(u, _)| u == user)
    }

    /// The one verdict on `user`'s session (R1), from the compositor's
    /// word and logind's records read now, under the caller's lock. The
    /// answer is shown to the latch on the way: any doubt latches the user
    /// (R2), and the compositor's unlocked with no ask under way starts
    /// the hold's clock. The doubt clock is kept here too.
    fn judge_in(
        &self,
        q: &mut Queue,
        user: &str,
        compositor: LockState,
        desktop: Desktop,
    ) -> Verdict {
        let hold = self.hold();
        let base = crate::lockgate::is_locked(&Facts {
            compositor,
            desktop,
            channel: None,
            latched: false,
            holding: false,
            saturated: false,
        });
        if base != Verdict::Unlocked {
            Self::latch(q, user, None);
        }
        let mut unlock_seen = false;
        let mut q_expired = Vec::new();
        if let Some(l) = q.latches.iter_mut().find(|l| l.user == user) {
            let now = Instant::now();
            let gap = l.last_look.is_none_or(|t| now.duration_since(t) > LOOK_GAP);
            l.last_look = Some(now);
            match compositor {
                LockState::Unlocked => {
                    if gap {
                        l.unlocked_since = Some(now);
                    }
                    let since = *l.unlocked_since.get_or_insert(now);
                    // A drop lets go once the compositor (the anchored one)
                    // has said unlocked, look after look, for DROP_CLEARS.
                    if l.dropped && l.channels == 0 && since.elapsed() >= DROP_CLEARS {
                        log::info!(
                            "consent: {}'s dropped lock channel is let go after a steady unlock",
                            user
                        );
                        l.dropped = false;
                    }
                    // An open channel the compositor has contradicted that
                    // long expires (fix round 8): its threads close them.
                    if l.channels > 0 && since.elapsed() >= CHANNEL_EXPIRES {
                        log::warn!(
                            "consent: {}'s open lock channel expired after a steady unlock",
                            user
                        );
                        q_expired.append(&mut l.open_ids);
                        l.channels = 0;
                        l.dropped = false;
                    }
                    if l.asking + l.fprint_asking == 0
                        && l.channels == 0
                        && !l.dropped
                        && l.unlocked_at.is_none()
                    {
                        l.unlocked_at = Some(now);
                        unlock_seen = l.priority.take().is_some();
                    }
                }
                LockState::Locked | LockState::Unknown => {
                    l.unlocked_at = None;
                    l.unlocked_since = None;
                }
            }
        }
        q.expired.append(&mut q_expired);
        if unlock_seen {
            q.unlock_ended = Some(Instant::now());
        }
        let (latched, open, holding) = self.latch_facts(q, user, hold);
        let verdict = crate::lockgate::is_locked(&Facts {
            compositor,
            desktop,
            channel: Some(open),
            latched,
            holding,
            saturated: self.saturated_in(q, user, hold),
        });
        if verdict == Verdict::Unknown {
            if !q.doubts.iter().any(|(u, _)| u == user) {
                q.doubts.push((user.to_string(), Instant::now()));
            }
        } else {
            q.doubts.retain(|(u, _)| u != user);
        }
        verdict
    }

    /// The one verdict on `user`'s session (R1); see `judge_in`.
    pub fn judge(&self, user: &str, compositor: LockState, desktop: Desktop) -> Verdict {
        let v = self.judge_in(&mut self.lock(), user, compositor, desktop);
        self.cv.notify_all();
        v
    }

    /// Wait up to `timeout` for any change to the record (a channel, an
    /// answer, a latch, a look): what a parked request waits on between
    /// its looks (fix round 8).
    pub fn wait_change(&self, timeout: Duration) {
        let q = self.lock();
        let _ = self.cv.wait_timeout(q, timeout);
    }

    /// How long the verdict on `user` has been `Unknown` without a break.
    pub fn doubt_for(&self, user: &str) -> Duration {
        self.lock()
            .doubts
            .iter()
            .find(|(u, _)| u == user)
            .map_or(Duration::ZERO, |(_, at)| at.elapsed())
    }

    /// The lock screen's reserved channel opens for `user` (round 7, B):
    /// latched, and the card's key and any key line's check taken off the
    /// key, in one step, until a channel closes gracefully, the compositor
    /// says unlocked and the hold has passed.
    /// Its id, for `channel_end` and `channel_expired`.
    pub fn channel_open(&self, user: &str) -> u64 {
        let mut q = self.lock();
        Self::latch(&mut q, user, None);
        q.next_channel += 1;
        let id = q.next_channel;
        if let Some(l) = q.latches.iter_mut().find(|l| l.user == user) {
            l.channels += 1;
            l.open_ids.push(id);
        }
        drop(q);
        self.cv.notify_all();
        id
    }

    /// Channel `id` of `user`'s closes: gracefully, with the lock screen's
    /// "unlocked", which lets the hold start at the compositor's next
    /// unlocked; or dropped, which leaves the user latched until a later
    /// channel closes gracefully or a steady unlock lets it go. A channel
    /// the daemon expired is no longer counted, and its end changes
    /// nothing.
    pub fn channel_end(&self, user: &str, id: u64, graceful: bool) {
        let mut q = self.lock();
        q.expired.retain(|e| *e != id);
        if let Some(l) = q.latches.iter_mut().find(|l| l.user == user) {
            if let Some(i) = l.open_ids.iter().position(|o| *o == id) {
                l.open_ids.remove(i);
                l.channels = l.channels.saturating_sub(1);
                l.unlocked_at = None;
                l.dropped = !graceful;
            }
        }
        drop(q);
        self.cv.notify_all();
    }

    /// `channel_end` for `user`'s oldest open channel.
    pub fn channel_closed(&self, user: &str, graceful: bool) {
        let id = self
            .lock()
            .latches
            .iter()
            .find(|l| l.user == user)
            .and_then(|l| l.open_ids.first().copied());
        if let Some(id) = id {
            self.channel_end(user, id, graceful);
        }
    }

    /// Whether the daemon expired channel `id`: its thread closes it.
    pub fn channel_expired(&self, id: u64) -> bool {
        self.lock().expired.contains(&id)
    }

    /// Channels open for `user` now.
    pub fn channels_open(&self, user: &str) -> usize {
        self.lock()
            .latches
            .iter()
            .find(|l| l.user == user)
            .map_or(0, |l| l.channels)
    }

    /// Whether a latch holds `user` now, under the caller's lock; a latch
    /// whose hold has run out is dropped.
    fn held(q: &mut Queue, user: &str, hold: Duration) -> bool {
        let now = Instant::now();
        q.latches.retain(|l| {
            l.user != user
                || l.asking + l.fprint_asking > 0
                || l.channels > 0
                || l.dropped
                || l.unlocked_at.is_none_or(|t| now < t + hold)
        });
        q.latches.iter().any(|l| l.user == user)
    }

    /// Whether `user`'s card is off the key because of the lock screen:
    /// a key unlock is asked, or the lock screen said it is up, and the
    /// daemon has not yet seen the session unlocked for the hold.
    pub fn unlock_holds(&self, user: &str) -> bool {
        let hold = self.hold();
        Self::held(&mut self.lock(), user, hold)
    }

    /// Latch `user` and take their card off the key and the fingerprint, in
    /// one step under the record's lock: both generations move on, a touch
    /// or a finger waiting in the slot and a PIN are dropped, and a key
    /// fallback under way is cancelled. With `ask`, a key or fingerprint
    /// unlock begins (false, changing nothing, when one of the user's on
    /// that lane is already asked); without, the lock screen or the
    /// daemon's own lock only says the lock is up.
    fn latch(q: &mut Queue, user: &str, ask: Option<UnlockAsk>) -> bool {
        Self::move_epoch(q, user);
        let i = match q.latches.iter().position(|l| l.user == user) {
            Some(i) => i,
            None => {
                q.latches.push(Latch {
                    user: user.to_string(),
                    asking: 0,
                    fprint_asking: 0,
                    channels: 0,
                    open_ids: Vec::new(),
                    dropped: false,
                    unlocked_at: None,
                    unlocked_since: None,
                    last_look: None,
                    priority: None,
                });
                q.latches.len() - 1
            }
        };
        let l = &mut q.latches[i];
        let asks = match ask {
            Some(UnlockAsk::Key) => Some(&mut l.asking),
            Some(UnlockAsk::Fprint) => Some(&mut l.fprint_asking),
            None => None,
        };
        if let Some(asks) = asks {
            if *asks > 0 {
                return false;
            }
            *asks += 1;
        }
        l.unlocked_at = None;
        l.unlocked_since = None;
        if let Some(live) = Self::live_of(q, user) {
            Self::take_key(live);
        }
        q.fallbacks.retain(|(u, _)| u != user);
        true
    }

    /// The card's key and fingerprint off: both generations move on, and a
    /// touch or a finger waiting in the slot and a PIN are dropped. Every
    /// reason the lock screen takes the key from the card (its latch, the
    /// shared priority) takes the reader too, so a finger while locked can
    /// only unlock, as a touch can.
    fn take_key(live: &mut Live) {
        live.key_gen += 1;
        live.key_armed = None;
        live.key_pin = None;
        live.key_pin_busy = false;
        live.fprint_gen += 1;
        live.fprint_armed = None;
        if matches!(live.answer, Some(Answer::Key | Answer::Fingerprint)) {
            live.answer = None;
        }
    }

    /// `user` (`uid`), whose lock screen asked from `bind`, was found
    /// locked by a fresh anchored look: the shared key's priority starts
    /// (fix round 9), pinned to the session `bind` names now (fix round
    /// 10). Every account's card on screen and key fallback are taken off
    /// the key in one step, and none takes it again until the priority
    /// ends. False, and nothing starts, when that session cannot be named
    /// or is not in the foreground: its lock screen is not on screen, so
    /// no touch there is for it.
    pub(super) fn start_priority(&self, user: &str, uid: u32, bind: &Bind) -> bool {
        let Some(id) = self.session_for_priority(uid, bind) else {
            return false;
        };
        let mut q = self.lock();
        let Some(l) = q.latches.iter_mut().find(|l| l.user == user) else {
            return false;
        };
        l.priority = Some((uid, id));
        q.epoch += 1;
        if let Some(live) = q.live.as_mut() {
            Self::take_key(live);
        }
        q.fallbacks.clear();
        drop(q);
        self.cv.notify_all();
        true
    }

    /// The lock screen says it is up, or the daemon locks the session:
    /// latch `user` (see `latch`).
    pub fn latch_lock_screen(&self, user: &str) {
        Self::latch(&mut self.lock(), user, None);
        self.cv.notify_all();
    }

    /// A key unlock of `user`'s begins: latched and the card off the key
    /// in one step. False when one is already asked.
    pub(super) fn begin_key_unlock(&self, user: &str) -> bool {
        let begun = Self::latch(&mut self.lock(), user, Some(UnlockAsk::Key));
        self.cv.notify_all();
        begun
    }

    /// A key unlock of `user`'s has ended, however it ended; the latch
    /// stays until the unlock is seen.
    pub(super) fn end_key_unlock(&self, user: &str) {
        if let Some(l) = self.lock().latches.iter_mut().find(|l| l.user == user) {
            l.asking = l.asking.saturating_sub(1);
        }
    }

    /// A fingerprint unlock of `user`'s begins: latched and the card off the
    /// key and the reader in one step, as a key unlock's ask. False when
    /// one is already asked.
    pub(super) fn begin_fprint_unlock(&self, user: &str) -> bool {
        let begun = Self::latch(&mut self.lock(), user, Some(UnlockAsk::Fprint));
        self.cv.notify_all();
        begun
    }

    /// A fingerprint unlock of `user`'s has ended, however it ended; the
    /// latch stays until the unlock is seen.
    pub(super) fn end_fprint_unlock(&self, user: &str) {
        if let Some(l) = self.lock().latches.iter_mut().find(|l| l.user == user) {
            l.fprint_asking = l.fprint_asking.saturating_sub(1);
        }
    }

    /// What the compositor said of `user`'s session, shown to the latch as
    /// `judge` shows it, with logind's records taken to show a desktop.
    pub fn observe_lock(&self, user: &str, state: LockState) {
        let _ = self.judge(user, state, Desktop::Some);
    }

    /// Whether `user`'s card on screen has the key armed now.
    pub(super) fn card_has_key(&self, user: &str) -> bool {
        Self::live_of(&mut self.lock(), user).is_some_and(|l| l.key_armed.is_some())
    }

    /// A key fallback of `user`'s begins: its number, unless the user's card
    /// has the key armed now (the card on screen takes the touch), a latch
    /// holds the user (the lock screen's channel among its sources). A card arming, a key
    /// unlock and a latch cancel it.
    pub(super) fn begin_fallback(&self, user: &str) -> Option<u64> {
        let hold = self.hold();
        let mut q = self.lock();
        if self.barred(&mut q, user, hold) {
            return None;
        }
        if Self::live_of(&mut q, user).is_some_and(|l| l.key_armed.is_some()) {
            return None;
        }
        q.next_fallback += 1;
        let n = q.next_fallback;
        q.fallbacks.push((user.to_string(), n));
        Some(n)
    }

    /// Whether key fallback `n` of `user`'s may go on: still registered,
    /// no latch, no account's unlock lane.
    pub(super) fn fallback_live(&self, user: &str, n: u64) -> bool {
        let hold = self.hold();
        let mut q = self.lock();
        !self.barred(&mut q, user, hold) && q.fallbacks.iter().any(|(u, m)| u == user && *m == n)
    }

    /// A nod approval of `user`'s commits (fix round 9): the one verdict,
    /// asked afresh (`look`, before the record's lock) and judged under it,
    /// says unlocked, and no latch began while it looked.
    pub(super) fn commit_nod(&self, user: &str, look: Look<'_>) -> bool {
        let epochs = Self::epochs_of(&self.lock(), user);
        let (compositor, desktop) = look();
        let mut q = self.lock();
        Self::epochs_of(&q, user) == epochs
            && self.judge_in(&mut q, user, compositor, desktop) == Verdict::Unlocked
    }

    /// A touch on key fallback `n`: it counts, and the fallback ends, only
    /// while the fallback is still on and the one verdict, asked again now
    /// (`look`: the compositor and logind, asked before the record's lock
    /// and judged under it, a latch begun meanwhile refusing), says
    /// unlocked (R1), and, asked after the look under the lock, the
    /// request's own session is still in front (`front`, fix round 12).
    pub(super) fn fallback_touched(
        &self,
        user: &str,
        n: u64,
        look: Look<'_>,
        front: Front<'_>,
    ) -> bool {
        // The lock question first, without the record's lock (fix round 8,
        // Opus L3); a latch begun meanwhile moves the epoch, and the touch
        // counts for nothing.
        let epochs = {
            let q = self.lock();
            if !q.fallbacks.iter().any(|(u, m)| u == user && *m == n) {
                return false;
            }
            Self::epochs_of(&q, user)
        };
        let (compositor, desktop) = look();
        let mut q = self.lock();
        if Self::epochs_of(&q, user) != epochs
            || !q.fallbacks.iter().any(|(u, m)| u == user && *m == n)
        {
            return false;
        }
        if self.judge_in(&mut q, user, compositor, desktop) != Verdict::Unlocked
            || self.unlock_priority(&mut q, self.hold())
            || !front()
        {
            return false;
        }
        q.fallbacks.retain(|(u, m)| !(u == user && *m == n));
        true
    }

    /// Key fallback `n` of `user`'s has ended.
    pub(super) fn end_fallback(&self, user: &str, n: u64) {
        self.lock()
            .fallbacks
            .retain(|(u, m)| !(u == user && *m == n));
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Queue> {
        self.q.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The live record, if it is `user`'s.
    fn live_of<'q>(q: &'q mut Queue, user: &str) -> Option<&'q mut Live> {
        q.live.as_mut().filter(|l| l.user == user)
    }

    /// The live record if it is `user`'s and `token` is its token.
    fn live_with<'q>(q: &'q mut Queue, user: &str, token: Option<&str>) -> Option<&'q mut Live> {
        let tok = token?;
        Self::live_of(q, user).filter(|l| same_token(&l.token, tok))
    }

    /// A request of `uid` joins the queue: refused at once when another
    /// user's request is live (B1), or when this user already has
    /// `CONSENT_PER_UID` requests live or waiting (B4).
    pub fn join(&self, uid: u32) -> Result<Place<'_>, NoTurn> {
        let mut q = self.lock();
        if let Some(l) = &q.live {
            if l.uid != uid {
                return Err(NoTurn::OtherUser(l.uid));
            }
        }
        if let Some((_, u)) = q.waiting.front() {
            if *u != uid {
                return Err(NoTurn::OtherUser(*u));
            }
        }
        let held = q.waiting.iter().filter(|(_, u)| *u == uid).count()
            + usize::from(q.live.as_ref().is_some_and(|l| l.uid == uid));
        if held >= CONSENT_PER_UID {
            return Err(NoTurn::TooMany);
        }
        let id = q.next_id;
        q.next_id += 1;
        q.waiting.push_back((id, uid));
        Ok(Place {
            id,
            uid,
            state: self,
        })
    }

    /// Wait for the window: until this place is at the head of the queue
    /// and no request is live, then take it. `requester` is a dup of the
    /// request's socket, kept in the record and polled for its hang-up;
    /// a requester that hangs up while waiting gets `Gone` and never a
    /// window. `on_wait` runs once, without the lock, when the request
    /// first has to wait (the notice that says so). A wait behind requests
    /// that show no acknowledged card ends after `QUEUE_UNSEEN` with
    /// `Stalled`; a wait behind a card on screen lasts as long as that card.
    pub fn take_turn<'a>(
        &'a self,
        place: Place<'a>,
        user: &str,
        requester: Option<std::os::fd::OwnedFd>,
        on_wait: &dyn Fn(),
    ) -> Result<Turn<'a>, NoTurn> {
        self.take_turn_within(place, user, requester, None, on_wait, QUEUE_UNSEEN)
    }

    /// `take_turn` for a request on behalf of `process` (a pidfd), which
    /// ends it as `Gone` when it exits, waiting or live, as a hang-up of
    /// `requester` does.
    pub fn take_turn_watching<'a>(
        &'a self,
        place: Place<'a>,
        user: &str,
        requester: Option<std::os::fd::OwnedFd>,
        process: Option<std::os::fd::OwnedFd>,
        on_wait: &dyn Fn(),
    ) -> Result<Turn<'a>, NoTurn> {
        self.take_turn_within(place, user, requester, process, on_wait, QUEUE_UNSEEN)
    }

    /// `take_turn` with `unseen` for `QUEUE_UNSEEN`.
    pub(crate) fn take_turn_within<'a>(
        &'a self,
        place: Place<'a>,
        user: &str,
        requester: Option<std::os::fd::OwnedFd>,
        process: Option<std::os::fd::OwnedFd>,
        on_wait: &dyn Fn(),
        unseen: Duration,
    ) -> Result<Turn<'a>, NoTurn> {
        let mut waited = false;
        let mut beat_at = Instant::now();
        // Since when the requests ahead have shown no acknowledged card:
        // from joining, and again from each time one was seen. A new
        // request taking the window does not restart it, so a line of
        // stalled requests ahead costs this one `unseen` in all.
        let mut unseen_since = Instant::now();
        loop {
            // A request waiting behind another card is still at work.
            if beat_at.elapsed() >= BEAT {
                beat_at = Instant::now();
                if let Some(fd) = &requester {
                    send_beat(fd);
                }
            }
            let q = self.lock();
            let head = q.waiting.front().map(|(id, _)| *id) == Some(place.id);
            if head && q.live.is_none() {
                let mut q = q;
                q.waiting.pop_front();
                q.live = Some(Live {
                    uid: place.uid,
                    user: user.to_string(),
                    token: String::new(),
                    acked: None,
                    answer: None,
                    rider: Rider::default(),
                    key_armed: None,
                    key_gen: 0,
                    key_pin_wanted: false,
                    key_pin: None,
                    key_pin_busy: false,
                    card_stale: false,
                    fprint_armed: None,
                    fprint_gen: 0,
                    fprint_status: FprintStatus::Place,
                    requester,
                    process,
                    beat_at: Instant::now(),
                });
                drop(q);
                self.cv.notify_all();
                return Ok(Turn { state: self });
            }
            if let Some(l) = &q.live {
                if l.uid != place.uid {
                    return Err(NoTurn::OtherUser(l.uid));
                }
                if l.acked.is_some() {
                    unseen_since = Instant::now();
                }
            }
            if unseen_since.elapsed() >= unseen {
                return Err(NoTurn::Stalled);
            }
            if waited {
                let _ = self
                    .cv
                    .wait_timeout(q, Duration::from_millis(300))
                    .unwrap_or_else(|p| p.into_inner());
            } else {
                drop(q);
                waited = true;
                // The notice may take its whole bound; the line hears the
                // daemon is at work first.
                if let Some(fd) = &requester {
                    send_beat(fd);
                    beat_at = Instant::now();
                }
                on_wait();
            }
            if requester.as_ref().is_some_and(peer_gone)
                || process.as_ref().is_some_and(process_exited)
            {
                return Err(NoTurn::Gone);
            }
        }
    }

    /// Tell the live request's requester now that the daemon is still at
    /// work, whenever the last beat went (fix round 10, Opus N3): before a
    /// step that may run up to the line's patience on its own, so steps in
    /// a row never add up to a silence the line gives up on.
    pub fn beat_now(&self, user: &str) {
        let mut q = self.lock();
        if let Some(l) = Self::live_of(&mut q, user) {
            l.beat_at = Instant::now();
            if let Some(fd) = &l.requester {
                send_beat(fd);
            }
        }
    }

    /// Has the live request's requester hung up, or the process it is for
    /// exited?
    pub fn requester_gone(&self, user: &str) -> bool {
        let mut q = self.lock();
        let Some(l) = Self::live_of(&mut q, user) else {
            return false;
        };
        l.beat();
        l.left()
    }

    /// Take the answer waiting for `user`'s live request, or `Gone` when
    /// its requester has hung up. What every wait loop reads between
    /// frames.
    pub fn poll(&self, user: &str) -> Option<Answer> {
        let hold = self.hold();
        let mut q = self.lock();
        // A touch or a finger is consumed under the same lock that latches
        // the lock screen, and never while a latch holds the user.
        let held = Self::held(&mut q, user, hold);
        let l = Self::live_of(&mut q, user)?;
        l.beat();
        if held && matches!(l.answer, Some(Answer::Key | Answer::Fingerprint)) {
            l.answer = None;
        }
        if let Some(a) = l.answer.take() {
            return Some(a);
        }
        l.left().then_some(Answer::Gone)
    }

    /// Take a "Ready to nod" if that is what waits; any other answer is
    /// left for the scan start.
    pub fn take_rearm(&self, user: &str) -> bool {
        let mut q = self.lock();
        let Some(l) = Self::live_of(&mut q, user) else {
            return false;
        };
        if matches!(l.answer, Some(Answer::Rearm)) {
            l.answer = None;
            return true;
        }
        false
    }

    /// Is an answer waiting (or the requester gone), without taking it?
    pub fn answered(&self, user: &str) -> bool {
        let mut q = self.lock();
        Self::live_of(&mut q, user).is_some_and(|l| {
            l.beat();
            l.answer.is_some() || l.left()
        })
    }

    /// The window answers the live request `token` names. A re-arm never
    /// displaces an answer already waiting. Refused, with the reason for
    /// the caller, when the token is not the live request's, and for the
    /// key and the fingerprint, which only a check the daemon itself ran
    /// can answer.
    pub fn answer(
        &self,
        user: &str,
        token: Option<&str>,
        answer: Answer,
    ) -> Result<(), &'static str> {
        if matches!(answer, Answer::Key) {
            return Err("the key answers only through the daemon's own check");
        }
        if matches!(answer, Answer::Fingerprint) {
            return Err("the fingerprint answers only through the daemon's own check");
        }
        let mut q = self.lock();
        let l = Self::live_with(&mut q, user, token).ok_or("no pending request")?;
        if matches!(answer, Answer::Rearm) && l.answer.is_some() {
            return Ok(());
        }
        l.answer = Some(answer);
        drop(q);
        self.cv.notify_all();
        Ok(())
    }

    /// Does `token` answer this user's live request? Compared in constant
    /// time; a wrong token and no request read the same.
    pub fn token_matches(&self, user: &str, token: Option<&str>) -> bool {
        Self::live_with(&mut self.lock(), user, token).is_some()
    }

    /// The window says it has drawn the request `token` names. True when
    /// that is this user's live request.
    pub fn ack(&self, user: &str, token: Option<&str>) -> bool {
        let mut q = self.lock();
        let Some(l) = Self::live_with(&mut q, user, token) else {
            return false;
        };
        l.acked = Some(Instant::now());
        drop(q);
        self.cv.notify_all();
        true
    }

    /// A new `Dialog` for the live request: its token, no acknowledgment,
    /// no rider. False when no request of `user`'s is live.
    pub(super) fn set_token(&self, user: &str, token: &str) -> bool {
        let mut q = self.lock();
        let Some(l) = Self::live_of(&mut q, user) else {
            return false;
        };
        l.token = token.to_string();
        l.acked = None;
        l.rider = Rider::default();
        l.key_armed = None;
        l.key_pin = None;
        l.key_pin_busy = false;
        true
    }

    /// The `Dialog` is gone: its token answers nothing more, and whatever
    /// was armed at its card ends with it, whichever way the request
    /// ended, so nothing rides on the next approval.
    pub(super) fn clear_token(&self, user: &str, token: &str) {
        let mut q = self.lock();
        if let Some(l) = Self::live_with(&mut q, user, Some(token)) {
            l.token.clear();
            l.acked = None;
            l.rider = Rider::default();
            l.key_armed = None;
            l.key_pin = None;
            l.key_pin_busy = false;
        }
    }

    #[cfg(test)]
    pub(super) fn acknowledged(&self, user: &str, token: &str) -> bool {
        Self::live_with(&mut self.lock(), user, Some(token)).is_some_and(|l| l.acked.is_some())
    }

    /// Forget the window's acknowledgment: the next show waits for a
    /// fresh one.
    pub(super) fn reset_ack(&self, user: &str, token: &str) {
        if let Some(l) = Self::live_with(&mut self.lock(), user, Some(token)) {
            l.acked = None;
        }
    }

    /// Wait for the window's acknowledgment of `token` until `deadline`.
    pub(super) fn wait_ack(&self, user: &str, token: &str, deadline: Instant) -> bool {
        let mut q = self.lock();
        loop {
            if let Some(l) = Self::live_with(&mut q, user, Some(token)) {
                l.beat();
                if l.acked.is_some() {
                    return true;
                }
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            q = self
                .cv
                .wait_timeout(q, left.min(Duration::from_millis(100)))
                .unwrap_or_else(|p| p.into_inner())
                .0;
        }
    }

    /// A key watch starts for the request `token` names, with a new
    /// generation that only that watch's checks carry; `pin` says whether
    /// the lane's key line asks for a PIN. None when that is not this
    /// user's live request.
    pub(super) fn arm_key(&self, user: &str, token: &str, pin: bool) -> Option<u64> {
        let mut q = self.lock();
        let l = Self::live_with(&mut q, user, Some(token))?;
        l.key_gen += 1;
        l.key_armed = Some(l.key_gen);
        l.key_pin_wanted = pin;
        let g = l.key_gen;
        // The card on screen takes the key from a fallback under way.
        q.fallbacks.retain(|(u, _)| u != user);
        Some(g)
    }

    /// The watch of `generation` ends; a newer one stays armed.
    pub(super) fn disarm_key(&self, user: &str, token: &str, generation: u64) {
        if let Some(l) = Self::live_with(&mut self.lock(), user, Some(token)) {
            if l.key_armed == Some(generation) {
                l.key_armed = None;
            }
        }
    }

    /// No key or fingerprint watch counts for `user`'s live request from
    /// here: the round waits (a hold, the wait for attention) or parks
    /// behind a lock. Both generations move on, so a check still out
    /// answers nothing and its watch stops it. With `parked`, a touch or a
    /// finger already waiting in the slot and a PIN not yet used are
    /// dropped too: a request parked behind a lock takes no approval from
    /// a card nobody can see. The fingerprint is armed with the nods and
    /// the key, under the key's rules, so it goes off with them.
    pub fn key_off(&self, user: &str, parked: bool) {
        let mut q = self.lock();
        if let Some(l) = Self::live_of(&mut q, user) {
            l.key_gen += 1;
            l.key_armed = None;
            l.fprint_gen += 1;
            l.fprint_armed = None;
            if parked {
                l.key_pin = None;
                l.key_pin_busy = false;
                if matches!(l.answer, Some(Answer::Key | Answer::Fingerprint)) {
                    l.answer = None;
                }
            }
        }
    }

    /// What the card's payload says about the key: whether a watch is
    /// running for the request `token` names, and whether the card should
    /// ask for the key's PIN.
    pub(super) fn key_for_payload(&self, user: &str, token: &str) -> KeyCard {
        Self::live_with(&mut self.lock(), user, Some(token))
            .filter(|l| l.key_armed.is_some())
            .map_or(KeyCard::default(), |l| KeyCard {
                armed: true,
                pin: l.key_pin_wanted,
                pin_wanted: l.key_pin_wanted && l.key_pin.is_none() && !l.key_pin_busy,
            })
    }

    /// The PIN check of the request `token` names has ended, its PIN
    /// spent: the card is to ask for one again.
    pub(super) fn key_pin_spent(&self, user: &str, token: &str) {
        if let Some(l) = Self::live_with(&mut self.lock(), user, Some(token)) {
            l.key_pin_busy = false;
            l.card_stale = true;
        }
    }

    /// Whether the card is to be sent again, because a PIN was spent or the
    /// fingerprint's status changed, and forget it. The name is the key's,
    /// from before the fingerprint shared it.
    pub fn take_key_card_stale(&self, user: &str) -> bool {
        Self::live_of(&mut self.lock(), user)
            .is_some_and(|l| std::mem::replace(&mut l.card_stale, false))
    }

    /// The card sends the key's PIN for the request `token` names. It is
    /// kept for the next check alone. Refused unless the key is armed on
    /// that request and its lane asks for a PIN.
    pub fn set_key_pin(
        &self,
        user: &str,
        token: Option<&str>,
        pin: Secret,
    ) -> Result<(), &'static str> {
        let mut q = self.lock();
        let l = Self::live_with(&mut q, user, token).ok_or("no pending request")?;
        if l.key_armed.is_none() || !l.key_pin_wanted {
            return Err("the key asks for no PIN now");
        }
        l.key_pin = Some(pin);
        Ok(())
    }

    /// The PIN for a check of watch `generation`, taken: one check per PIN,
    /// so a wrong one is never tried twice against the key's retry count.
    pub(super) fn take_key_pin(&self, user: &str, token: &str, generation: u64) -> Option<Secret> {
        let mut q = self.lock();
        let l = Self::live_with(&mut q, user, Some(token))
            .filter(|l| l.key_armed == Some(generation))?;
        let pin = l.key_pin.take();
        l.key_pin_busy = pin.is_some();
        pin
    }

    /// May a check of watch `generation` that started at `started` run, or
    /// its touch count, for the request `token` names? Only while it is
    /// this user's live request, that watch is the one armed, no rider is
    /// waiting to be shown, and the check started a dwell after the card's
    /// latest acknowledgment: a card re-shown or re-acknowledged since
    /// (a rider armed mid-request) stops the check, and the next one waits
    /// out the dwell, so a touch never lands on a card the user has not had
    /// time to read. A new check asks with `started` now.
    pub(super) fn key_may_check(
        &self,
        user: &str,
        token: &str,
        generation: u64,
        started: Instant,
    ) -> bool {
        let hold = self.hold();
        let mut q = self.lock();
        !self.barred(&mut q, user, hold)
            && Self::key_open(&mut q, user, token, generation, started).is_some()
    }

    /// The live record of `key_may_check`, under the caller's lock.
    fn key_open<'q>(
        q: &'q mut Queue,
        user: &str,
        token: &str,
        generation: u64,
        started: Instant,
    ) -> Option<&'q mut Live> {
        Self::live_with(q, user, Some(token)).filter(|l| {
            l.key_armed == Some(generation)
                && !(l.rider.minutes.is_some() && !l.rider.shown)
                && l.acked.is_some_and(|at| started >= at + ACK_DWELL)
        })
    }

    /// A touch of `user`'s key, accepted on a check of watch `generation`
    /// that started at `started`: an approval waiting in the slot, read
    /// wherever the request waits, as a typed password is. It counts only
    /// while `key_may_check` holds for that check, never over an answer
    /// the card already gave (so a dismissal stays a refusal), and only
    /// when the one verdict (R1), asked again at this instant from `look`
    /// (the compositor and logind), says unlocked. The look runs a process
    /// (bounded by its own deadline), so it is taken before the record's
    /// lock, never under it (fix round 8, Opus L3), and asked only for a
    /// touch that would otherwise count; under the lock everything is
    /// checked again, and a latch begun while it looked (the epoch moved)
    /// makes the touch count for nothing, so no park or latch slips
    /// between the look and the commit. False when the touch counted for
    /// nothing.
    pub(super) fn key_touched(
        &self,
        user: &str,
        token: &str,
        generation: u64,
        started: Instant,
        look: Look<'_>,
        front: Front<'_>,
    ) -> bool {
        if !self.key_may_check(user, token, generation, started) {
            return false;
        }
        // The lock question first, without the record's lock (fix round 8,
        // Opus L3), then everything again under it, the epoch included.
        let epochs = Self::epochs_of(&self.lock(), user);
        let (compositor, desktop) = look();
        let mut q = self.lock();
        if Self::epochs_of(&q, user) != epochs {
            return false;
        }
        let Some(l) = Self::key_open(&mut q, user, token, generation, started) else {
            return false;
        };
        if l.answer
            .as_ref()
            .is_some_and(|a| !matches!(a, Answer::Rearm))
        {
            return false;
        }
        if self.judge_in(&mut q, user, compositor, desktop) != Verdict::Unlocked
            || self.unlock_priority(&mut q, self.hold())
            || !front()
        {
            return false;
        }
        let Some(l) = Self::key_open(&mut q, user, token, generation, started) else {
            return false;
        };
        l.answer = Some(Answer::Key);
        drop(q);
        self.cv.notify_all();
        true
    }

    /// A fingerprint watch starts for the request `token` names, with a new
    /// generation that only that watch's checks carry, and the card's
    /// status back at "place a finger". None when that is not this user's
    /// live request. The fallback line that would arm the reader after a
    /// decline (decision 2) is not built: when it is, this cancels a
    /// fingerprint fallback under way, as `arm_key` cancels the key's, so
    /// the card on screen takes the reader from it.
    pub(super) fn arm_fprint(&self, user: &str, token: &str) -> Option<u64> {
        let mut q = self.lock();
        let l = Self::live_with(&mut q, user, Some(token))?;
        l.fprint_gen += 1;
        l.fprint_armed = Some(l.fprint_gen);
        l.fprint_status = FprintStatus::Place;
        Some(l.fprint_gen)
    }

    /// The fingerprint watch of `generation` ends; a newer one stays armed.
    pub(super) fn disarm_fprint(&self, user: &str, token: &str, generation: u64) {
        if let Some(l) = Self::live_with(&mut self.lock(), user, Some(token)) {
            if l.fprint_armed == Some(generation) {
                l.fprint_armed = None;
            }
        }
    }

    /// The fingerprint watch of `generation` gave up for its window (the
    /// tries ran out): it is disarmed, and the card is sent again so its
    /// fingerprint line goes.
    pub(super) fn fprint_spent(&self, user: &str, token: &str, generation: u64) {
        if let Some(l) = Self::live_with(&mut self.lock(), user, Some(token)) {
            if l.fprint_armed == Some(generation) {
                l.fprint_armed = None;
                l.card_stale = true;
            }
        }
    }

    /// What the card's payload says about the fingerprint for the request
    /// `token` names: armed while a watch runs, with its status.
    pub(super) fn fprint_for_payload(&self, user: &str, token: &str) -> FprintCard {
        Self::live_with(&mut self.lock(), user, Some(token))
            .filter(|l| l.fprint_armed.is_some())
            .map_or(FprintCard::default(), |l| FprintCard {
                armed: true,
                status: l.fprint_status,
            })
    }

    /// The fingerprint check of watch `generation` reports `status`: the
    /// card is sent again when it changed. Nothing for a watch no longer
    /// armed.
    pub(super) fn fprint_status(
        &self,
        user: &str,
        token: &str,
        generation: u64,
        status: FprintStatus,
    ) {
        if let Some(l) = Self::live_with(&mut self.lock(), user, Some(token)) {
            if l.fprint_armed == Some(generation) && l.fprint_status != status {
                l.fprint_status = status;
                l.card_stale = true;
            }
        }
    }

    /// May a fingerprint check of watch `generation` that started at
    /// `started` run, or its finger count, for the request `token` names?
    /// The key's rule (`key_may_check`) on the fingerprint's generation:
    /// this user's live request, that watch the one armed, no rider waiting
    /// to be shown, a dwell after the card's latest acknowledgment, and no
    /// latch or unlock priority holding the user.
    pub(super) fn fprint_may_check(
        &self,
        user: &str,
        token: &str,
        generation: u64,
        started: Instant,
    ) -> bool {
        let hold = self.hold();
        let mut q = self.lock();
        !self.barred(&mut q, user, hold)
            && Self::fprint_open(&mut q, user, token, generation, started).is_some()
    }

    /// The live record of `fprint_may_check`, under the caller's lock.
    fn fprint_open<'q>(
        q: &'q mut Queue,
        user: &str,
        token: &str,
        generation: u64,
        started: Instant,
    ) -> Option<&'q mut Live> {
        Self::live_with(q, user, Some(token)).filter(|l| {
            l.fprint_armed == Some(generation)
                && !(l.rider.minutes.is_some() && !l.rider.shown)
                && l.acked.is_some_and(|at| started >= at + ACK_DWELL)
        })
    }

    /// A finger pam_fprintd matched, on a check of watch `generation` that
    /// started at `started`: an approval waiting in the slot, under exactly
    /// the key's commit (`key_touched`): it counts only while
    /// `fprint_may_check` holds for that check, never over an answer the
    /// card already gave, and only when the one verdict, asked afresh from
    /// `look` before the record's lock and judged under it with the
    /// epochs, says unlocked, no unlock priority holds, and the request's
    /// own session is still in front (`front`). False when the finger
    /// counted for nothing.
    pub(super) fn fprint_matched(
        &self,
        user: &str,
        token: &str,
        generation: u64,
        started: Instant,
        look: Look<'_>,
        front: Front<'_>,
    ) -> bool {
        if !self.fprint_may_check(user, token, generation, started) {
            return false;
        }
        let epochs = Self::epochs_of(&self.lock(), user);
        let (compositor, desktop) = look();
        let mut q = self.lock();
        if Self::epochs_of(&q, user) != epochs {
            return false;
        }
        let Some(l) = Self::fprint_open(&mut q, user, token, generation, started) else {
            return false;
        };
        if l.answer
            .as_ref()
            .is_some_and(|a| !matches!(a, Answer::Rearm))
        {
            return false;
        }
        if self.judge_in(&mut q, user, compositor, desktop) != Verdict::Unlocked
            || self.unlock_priority(&mut q, self.hold())
            || !front()
        {
            return false;
        }
        let Some(l) = Self::fprint_open(&mut q, user, token, generation, started) else {
            return false;
        };
        l.answer = Some(Answer::Fingerprint);
        drop(q);
        self.cv.notify_all();
        true
    }

    /// The doubt on `user`, moved back by `by`, as a test stands in for an
    /// unknown lock state that has lasted.
    #[cfg(test)]
    pub(crate) fn backdate_doubt(&self, user: &str, by: Duration) {
        for (u, at) in self.lock().doubts.iter_mut() {
            if u == user {
                *at -= by;
            }
        }
    }

    /// The steady unlock on `user`'s latch, moved back by `by`, as a test
    /// stands in for one that has lasted.
    #[cfg(test)]
    pub(crate) fn backdate_unlocked(&self, user: &str, by: Duration) {
        for l in self.lock().latches.iter_mut() {
            if l.user == user {
                l.unlocked_since = l.unlocked_since.map(|t| t - by);
            }
        }
    }

    /// The last look at `user`'s compositor, moved back by `by`, as a test
    /// stands in for a gap between looks.
    #[cfg(test)]
    pub(crate) fn backdate_last_look(&self, user: &str, by: Duration) {
        for l in self.lock().latches.iter_mut() {
            if l.user == user {
                l.last_look = l.last_look.map(|t| t - by);
            }
        }
    }

    /// `user`'s spent budget, moved back by `by`.
    #[cfg(test)]
    pub(crate) fn backdate_budget_spent(&self, user: &str, by: Duration) {
        for (u, at) in self.lock().spent.iter_mut() {
            if u == user {
                *at -= by;
            }
        }
    }

    /// The card's acknowledgment, moved back by `by`, as a test stands in
    /// for a dwell that has passed.
    #[cfg(test)]
    pub(crate) fn backdate_ack(&self, user: &str, by: Duration) {
        if let Some(l) = Self::live_of(&mut self.lock(), user) {
            l.acked = l.acked.map(|at| at - by);
        }
    }

    /// The armed key generation, as the tests read it.
    #[cfg(test)]
    pub(crate) fn key_armed_now(&self, user: &str) -> Option<u64> {
        Self::live_of(&mut self.lock(), user).and_then(|l| l.key_armed)
    }

    /// The armed fingerprint generation, as the tests read it.
    #[cfg(test)]
    pub(crate) fn fprint_armed_now(&self, user: &str) -> Option<u64> {
        Self::live_of(&mut self.lock(), user).and_then(|l| l.fprint_armed)
    }

    /// A key watch's generation armed past the token, as a test stands in
    /// for a scan that armed one.
    #[cfg(test)]
    pub(crate) fn arm_key_for_test(&self, user: &str) -> Option<u64> {
        let mut q = self.lock();
        let l = Self::live_of(&mut q, user)?;
        l.key_gen += 1;
        l.key_armed = Some(l.key_gen);
        Some(l.key_gen)
    }

    /// The window asks that this user's live request, when approved, also
    /// turn passwordless sudo on for `minutes`. Nothing is written now: the
    /// answer waits on the approval (a nod and its confirm, the password,
    /// or the key), and any other end of the request drops it. Refused, with
    /// the reason for the card, unless `token` names the request the card
    /// is showing, that request is a sudo one, and the enrolled face is in
    /// the nod window now.
    pub fn arm_passwordless(
        &self,
        user: &str,
        token: &str,
        minutes: u32,
    ) -> Result<(), &'static str> {
        if minutes == 0 || minutes > PASSWORDLESS_MAX_MINUTES {
            return Err("minutes out of range");
        }
        let mut q = self.lock();
        let l = Self::live_with(&mut q, user, Some(token)).ok_or("no pending request")?;
        match l.rider.lane {
            None => return Err("no pending request"),
            Some(false) => return Err("only a sudo request can carry it"),
            Some(true) => {}
        }
        if !l.rider.face_present {
            return Err("look at the camera first");
        }
        l.rider.minutes = Some(minutes);
        l.rider.shown = false;
        Ok(())
    }

    /// The rider armed on the request `token` names, if the card has been
    /// shown it, and it is forgotten either way. A rider under another
    /// token is never returned: the approval carries nothing.
    pub fn take_passwordless(&self, user: &str, token: &str) -> Option<u32> {
        let mut q = self.lock();
        let l = Self::live_with(&mut q, user, Some(token))?;
        let minutes = l.rider.minutes.take();
        let shown = std::mem::replace(&mut l.rider.shown, false);
        if !shown {
            if minutes.is_some() {
                log::warn!(
                    "consent: a passwordless rider for {} arrived after the card's last payload; dropped",
                    user
                );
            }
            return None;
        }
        minutes
    }

    /// What the card's payload says about the rider, as the tests read
    /// it: the minutes armed and whether the enrolled face is in frame.
    /// With `mark_shown` sending the minutes counts as showing them;
    /// without it (a payload that waits for no acknowledgment) a rider the
    /// card has not been shown is left out, so that it still reaches the
    /// card on a show that resets the acknowledgment and the dwell
    /// (`rider_snapshot`).
    #[cfg(test)]
    pub(super) fn rider_for_payload(
        &self,
        user: &str,
        token: &str,
        sudo: bool,
        mark_shown: bool,
    ) -> (Option<u32>, bool) {
        let (minutes, face, _) = self.rider_snapshot(user, token, sudo, mark_shown);
        (minutes, face)
    }

    /// `rider_for_payload` and the acknowledgment's reset in one look at
    /// the record, for a show that waits for an acknowledgment
    /// (`mark_shown`): a rider the card has not been shown is marked shown
    /// and the acknowledgment reset under the same lock, so no rider armed
    /// between the two can reach the card while an acknowledgment from
    /// before it still stands. The third value says the acknowledgment
    /// was reset, so the caller forgets its own copy.
    pub(super) fn rider_snapshot(
        &self,
        user: &str,
        token: &str,
        sudo: bool,
        mark_shown: bool,
    ) -> (Option<u32>, bool, bool) {
        let mut q = self.lock();
        let Some(l) = Self::live_with(&mut q, user, Some(token)) else {
            return (None, false, false);
        };
        l.rider.lane = Some(sudo);
        let reset = mark_shown && l.rider.minutes.is_some() && !l.rider.shown;
        if reset {
            l.acked = None;
        }
        if mark_shown {
            l.rider.shown = true;
        }
        let minutes = if l.rider.shown { l.rider.minutes } else { None };
        (minutes, l.rider.face_present, reset)
    }

    /// The nod window says whether it is following the enrolled face.
    /// True when that changed the record.
    pub fn set_face_present(&self, user: &str, present: bool) -> bool {
        let mut q = self.lock();
        Self::live_of(&mut q, user)
            .filter(|l| !l.token.is_empty())
            .map(|l| std::mem::replace(&mut l.rider.face_present, present) != present)
            .unwrap_or(false)
    }

    /// Has a rider been armed that the card has not been shown yet? The
    /// nod window ends on it so the card can be re-shown and the nods
    /// start over.
    pub fn rider_unshown(&self, user: &str) -> bool {
        Self::live_of(&mut self.lock(), user)
            .is_some_and(|l| l.rider.minutes.is_some() && !l.rider.shown)
    }

    /// The nods are done: close arming for this window and say whether a
    /// rider was armed that the card has not shown, in one look at the
    /// record. Arming needs the face in the window (`arm_passwordless`), so
    /// clearing it here refuses any arm after this look, and the answer
    /// covers every arm before it: no rider slips in between the window's
    /// last check and the confirm's show, which would mark it shown with no
    /// nod at a card naming it (Codex's second delta review).
    pub fn close_rider_arming(&self, user: &str) -> bool {
        let mut q = self.lock();
        Self::live_of(&mut q, user)
            .filter(|l| !l.token.is_empty())
            .is_some_and(|l| {
                l.rider.face_present = false;
                l.rider.minutes.is_some() && !l.rider.shown
            })
    }

    /// Does the card name a passwordless rider now? A nod window that starts
    /// under one keeps the dwell and the still second (`wait_for_nods`),
    /// however the rider reached the card.
    pub fn rider_on_card(&self, user: &str) -> bool {
        Self::live_of(&mut self.lock(), user)
            .is_some_and(|l| l.rider.minutes.is_some() && l.rider.shown)
    }

    /// The rider record as the tests read it: (minutes, face present).
    #[cfg(test)]
    pub(super) fn rider_state(&self, user: &str) -> Option<(Option<u32>, bool)> {
        Self::live_of(&mut self.lock(), user)
            .filter(|l| !l.token.is_empty())
            .map(|l| (l.rider.minutes, l.rider.face_present))
    }

    /// The live request's user and uid, as the tests read them.
    #[cfg(test)]
    pub(crate) fn live_user(&self) -> Option<(u32, String)> {
        self.lock().live.as_ref().map(|l| (l.uid, l.user.clone()))
    }

    /// A live record for `user` without a queue or a requester: what a
    /// test needs before it can make a `Dialog` or push an answer.
    #[cfg(test)]
    pub(crate) fn test_live(&self, uid: u32, user: &str) -> Turn<'_> {
        let place = self.join(uid).expect("a free queue");
        self.take_turn(place, user, None, &|| {})
            .expect("the window is free")
    }

    /// An answer written past the token check, as a test stands in for the
    /// window.
    #[cfg(test)]
    pub(crate) fn push_answer(&self, user: &str, answer: Answer) {
        let mut q = self.lock();
        if let Some(l) = Self::live_of(&mut q, user) {
            l.answer = Some(answer);
        }
        drop(q);
        self.cv.notify_all();
    }
}

/// Two tokens compared in constant time; a wrong token and no token read
/// the same.
fn same_token(have: &str, given: &str) -> bool {
    let (a, b) = (have.as_bytes(), given.as_bytes());
    !a.is_empty()
        && a.len() == b.len()
        && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Fix round 12 (Codex 1): the commit asks whether the request's own
/// session is in front after its lock question, under the record's lock,
/// right at the commit: a VT switch while the question was out refuses
/// the touch, on a key line and at a card alike.
#[cfg(test)]
#[test]
fn a_vt_switch_during_the_commits_look_refuses_the_touch() {
    let front = std::cell::Cell::new(true);
    let switch = || {
        front.set(false);
        (LockState::Unlocked, Desktop::Some)
    };
    let st = test_state();
    let n = st.begin_fallback("front-fallback-user").unwrap();
    assert!(!st.fallback_touched("front-fallback-user", n, &switch, &|| front.get()));
    front.set(true);
    let n = st.begin_fallback("front-fallback-user").unwrap();
    assert!(st.fallback_touched(
        "front-fallback-user",
        n,
        &|| (LockState::Unlocked, Desktop::Some),
        &|| front.get()
    ));
    let st = test_state();
    let user = "front-card-user";
    let _turn = st.test_live(1000, user);
    assert!(st.set_token(user, "tok"));
    assert!(st.ack(user, Some("tok")));
    let g = st.arm_key(user, "tok", false).unwrap();
    let later = Instant::now() + super::window::ACK_DWELL * 2;
    front.set(true);
    assert!(!st.key_touched(user, "tok", g, later, &switch, &|| front.get()));
    front.set(true);
    assert!(st.key_touched(
        user,
        "tok",
        g,
        later,
        &|| (LockState::Unlocked, Desktop::Some),
        &|| front.get()
    ));
}

/// Fix round 10 (Opus N3): a step that may run up to the line's patience
/// is preceded by a beat sent then, whenever the last one went: the live
/// request's requester hears the daemon is at work at once, however
/// recently it last did, and a request not live hears nothing.
#[cfg(test)]
#[test]
fn a_beat_now_reaches_the_requester_at_once() {
    use std::io::Read;
    let st = test_state();
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    theirs.set_nonblocking(true).unwrap();
    let place = st.join(1000).unwrap();
    let _turn = st
        .take_turn(place, "beat-now-user", Some(ours.into()), &|| {})
        .unwrap();
    let mut got = String::new();
    let read = |got: &mut String| {
        let mut buf = [0u8; 256];
        while let Ok(n) = (&theirs).read(&mut buf) {
            if n == 0 {
                break;
            }
            got.push_str(std::str::from_utf8(&buf[..n]).unwrap());
        }
    };
    st.beat_now("beat-now-user");
    st.beat_now("beat-now-user");
    st.beat_now("someone-else");
    read(&mut got);
    assert_eq!(got, "{\"result\":\"pending\"}\n".repeat(2));
}

/// A process to stand for a requester: a child of the test, with its pidfd.
#[cfg(test)]
fn requester_process() -> (std::process::Child, std::os::fd::OwnedFd) {
    let mut c = std::process::Command::new("/bin/sleep");
    c.arg("30");
    crate::child::spawn_with_pidfd(&mut c).unwrap()
}

/// Live test 1 (2026-10-13): a request whose requester process is gone is
/// gone, though the process holding its socket is still there (polkit's
/// helper, after polkitd gave the request up): every wait loop's look at
/// the record says so, and the parked request ends rather than wait for
/// an unlock that would bring its card back.
#[cfg(test)]
#[test]
fn a_request_ends_when_its_requester_process_exits() {
    let st = test_state();
    let user = "requester-exit-user";
    let (ours, _theirs) = std::os::unix::net::UnixStream::pair().unwrap();
    let (mut child, pidfd) = requester_process();
    let place = st.join(1000).unwrap();
    let _turn = st
        .take_turn_watching(place, user, Some(ours.into()), Some(pidfd), &|| {})
        .unwrap();
    assert!(!st.requester_gone(user), "the requester is there");
    assert!(!st.answered(user));
    assert!(st.poll(user).is_none());
    child.kill().unwrap();
    child.wait().unwrap();
    assert!(st.requester_gone(user), "its requester process is gone");
    assert!(st.answered(user));
    assert!(matches!(st.poll(user), Some(Answer::Gone)));
}

/// The same while the request waits its turn behind another card: it
/// leaves the queue as `Gone` once its requester process exits.
#[cfg(test)]
#[test]
fn a_queued_request_ends_when_its_requester_process_exits() {
    let st = test_state();
    let live = st.test_live(1000, "requester-exit-queue");
    assert!(st.set_token("requester-exit-queue", "tok"));
    assert!(st.ack("requester-exit-queue", Some("tok")));
    let (mut child, pidfd) = requester_process();
    let place = st.join(1000).unwrap();
    let waiter = std::thread::spawn(move || {
        st.take_turn_within(
            place,
            "requester-exit-queue",
            None,
            Some(pidfd),
            &|| {},
            Duration::from_secs(5),
        )
        .map(|_| ())
    });
    std::thread::sleep(Duration::from_millis(300));
    child.kill().unwrap();
    child.wait().unwrap();
    let t0 = Instant::now();
    while !waiter.is_finished() && t0.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(20));
    }
    let finished = waiter.is_finished();
    drop(live);
    let got = waiter.join().unwrap();
    assert!(
        finished,
        "it left the queue while the card ahead was still up"
    );
    assert!(matches!(got, Err(NoTurn::Gone)), "{:?}", got.err());
}

/// Fix round 10 (Opus N2, Codex 5; Opus's probe): each account's latch
/// moves only that account's epoch, so another account opening and closing
/// its lock channel in a loop while a commit looks refuses nothing of this
/// account's, nod or touch. This account's own latch during its look still
/// refuses it, and so do the shared key's priority starting and the
/// daemon's connection places refusing callers, which concern every
/// account.
#[cfg(test)]
#[test]
fn another_accounts_channel_churn_refuses_no_commit() {
    let (alice, bob) = ("epoch-alice", "epoch-bob");
    let unlocked = (LockState::Unlocked, Desktop::Some);
    let st = test_state();
    let churn = || {
        for _ in 0..3 {
            let id = st.channel_open(alice);
            st.channel_end(alice, id, true);
        }
        unlocked
    };
    assert!(
        st.commit_nod(bob, &churn),
        "alice's churn refuses no nod of bob's"
    );
    let n = st.begin_fallback(bob).expect("bob's key line may run");
    assert!(
        st.fallback_touched(bob, n, &churn, &|| true),
        "nor his key line's touch"
    );
    let st = test_state();
    let own = || {
        st.latch_lock_screen(bob);
        unlocked
    };
    assert!(!st.commit_nod(bob, &own), "his own latch during his look");
    let st = test_state();
    let priority = || {
        st.latch_lock_screen(alice);
        assert!(st.start_priority(alice, 1, &Bind::OnlyDesktop));
        unlocked
    };
    assert!(
        !st.commit_nod(bob, &priority),
        "the key's priority starting"
    );
    let st = test_state();
    let full = || {
        st.note_refusal();
        unlocked
    };
    assert!(!st.commit_nod(bob, &full), "the places refusing callers");
}

/// Fix round 10 (Opus N4): a request queued behind another of the same
/// user's waits, beating, only while that one's card is up and
/// acknowledged (the user's own work); behind one whose card is not shown
/// for `unseen` (a summon stalled, a card that never came), it gives up and
/// goes on to the password.
#[cfg(test)]
#[test]
fn a_queued_request_does_not_wait_behind_a_card_never_shown() {
    let st = test_state();
    let _live = st.test_live(1000, "queue-unseen-user");
    let place = st.join(1000).unwrap();
    let t0 = Instant::now();
    let got = st.take_turn_within(
        place,
        "queue-unseen-user",
        None,
        None,
        &|| {},
        Duration::from_millis(200),
    );
    assert!(matches!(got, Err(NoTurn::Stalled)), "{:?}", got.err());
    assert!(
        t0.elapsed() < Duration::from_millis(900),
        "{:?}",
        t0.elapsed()
    );
    // Behind an acknowledged card it waits on, for the user.
    let st = test_state();
    let live = st.test_live(1000, "queue-seen-user");
    assert!(st.set_token("queue-seen-user", "tok"));
    assert!(st.ack("queue-seen-user", Some("tok")));
    let place = st.join(1000).unwrap();
    let waiter = std::thread::spawn(move || {
        st.take_turn_within(
            place,
            "queue-seen-user",
            None,
            None,
            &|| {},
            Duration::from_millis(200),
        )
        .map(|_| ())
    });
    std::thread::sleep(Duration::from_millis(500));
    drop(live);
    assert!(
        waiter.join().unwrap().is_ok(),
        "it got the window once the card was done"
    );
    // A card summoned and acknowledged at the slowest is not given up on;
    // the password bound with it is the real-scale test's (pam_faceauth).
    assert!(QUEUE_UNSEEN >= super::shell::USER_CALL_WITHIN + super::window::ACK_WAIT);
}

/// A consent state of a test's own, leaked so a `Dialog` can hold it.
#[cfg(test)]
pub(crate) fn test_state() -> &'static ConsentState {
    Box::leak(Box::new(ConsentState::new()))
}
