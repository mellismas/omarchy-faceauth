//! Consent for elevation: the part of an authentication that proves the person
//! the camera sees *wants this request*, and not merely that they are present.
//!
//! The calling program (sudo, the polkit helper, anything that loads the PAM
//! module) cannot be trusted to relay a "yes": code running as the user can
//! answer any prompt it is shown. So the yes comes from something only the
//! daemon observes: a nod pattern in front of the camera it owns. Around it,
//! for the human: one window on the desktop, opened by the daemon and not by
//! the caller, naming the command and the process asking, with buttons to
//! dismiss it or, when the requester is named, to kill it. Nothing elevates
//! silently, and no
//! window means no elevation (an ssh session gets the password path).

use crate::capture::IrCapture;
use crate::config::Config;
use anyhow::{anyhow, bail, Context, Result};
use faceauth_engine::{Grey, Pipeline};
use serde::Serialize;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

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
/// write, so the optimiser cannot drop it as a dead store; the string is
/// left empty, which is valid UTF-8.
pub fn wipe_string(s: &mut String) {
    // SAFETY: zero bytes are valid UTF-8, and the vector is cleared before
    // the borrow ends, so no partial sequence is left behind.
    let v = unsafe { s.as_mut_vec() };
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
}

/// The passwordless-sudo rider of the live consent request. The rider is
/// what the card's button asks for: that the approval of this request
/// also turn passwordless sudo on for some minutes. It belongs to the one
/// request on screen and is honoured only by the approval of that same
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
    /// lands after the card's last payload is not honoured until the card
    /// has shown it: the nod must be at a card that says what it grants.
    shown: bool,
}

/// The one consent request on screen. The answer token is handed to the
/// window in the payload, and an answer, an acknowledgement or a rider is
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
    acked: bool,
    answer: Option<Answer>,
    rider: Rider,
    /// A dup of the requester's socket, polled for its hang-up.
    requester: Option<std::os::fd::OwnedFd>,
}

struct Queue {
    live: Option<Live>,
    /// Requests waiting for the window, in arrival order: place id and uid.
    waiting: std::collections::VecDeque<(u64, u32)>,
    next_id: u64,
}

/// The consent requests of the daemon: the one on screen and the ones
/// waiting behind it, under one lock. Requests of the same user queue and
/// take the window in arrival order; a request of another user is refused
/// at once and falls to its password, so one user's parked request never
/// holds another's sudo open (B1). The condition variable wakes the
/// waiters when the window frees and the window's first show when the
/// acknowledgement lands.
pub struct ConsentState {
    q: Mutex<Queue>,
    cv: std::sync::Condvar,
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
/// loop holding threads open, not a limit anyone is meant to reach.
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
}

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
            }),
            cv: std::sync::Condvar::new(),
        }
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
    /// first has to wait (the notice that says so).
    pub fn take_turn<'a>(
        &'a self,
        place: Place<'a>,
        user: &str,
        requester: Option<std::os::fd::OwnedFd>,
        on_wait: &dyn Fn(),
    ) -> Result<Turn<'a>, NoTurn> {
        let mut waited = false;
        loop {
            let q = self.lock();
            let head = q.waiting.front().map(|(id, _)| *id) == Some(place.id);
            if head && q.live.is_none() {
                let mut q = q;
                q.waiting.pop_front();
                q.live = Some(Live {
                    uid: place.uid,
                    user: user.to_string(),
                    token: String::new(),
                    acked: false,
                    answer: None,
                    rider: Rider::default(),
                    requester,
                });
                drop(q);
                self.cv.notify_all();
                return Ok(Turn { state: self });
            }
            if let Some(l) = &q.live {
                if l.uid != place.uid {
                    return Err(NoTurn::OtherUser(l.uid));
                }
            }
            if waited {
                let _ = self
                    .cv
                    .wait_timeout(q, Duration::from_millis(300))
                    .unwrap_or_else(|p| p.into_inner());
            } else {
                drop(q);
                waited = true;
                on_wait();
            }
            if requester.as_ref().is_some_and(peer_gone) {
                return Err(NoTurn::Gone);
            }
        }
    }

    /// Has the live request's requester hung up?
    pub fn requester_gone(&self, user: &str) -> bool {
        let mut q = self.lock();
        Self::live_of(&mut q, user)
            .and_then(|l| l.requester.as_ref())
            .is_some_and(peer_gone)
    }

    /// Take the answer waiting for `user`'s live request, or `Gone` when
    /// its requester has hung up. What every wait loop reads between
    /// frames.
    pub fn poll(&self, user: &str) -> Option<Answer> {
        let mut q = self.lock();
        let l = Self::live_of(&mut q, user)?;
        if let Some(a) = l.answer.take() {
            return Some(a);
        }
        l.requester
            .as_ref()
            .is_some_and(peer_gone)
            .then_some(Answer::Gone)
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
        Self::live_of(&mut q, user)
            .is_some_and(|l| l.answer.is_some() || l.requester.as_ref().is_some_and(peer_gone))
    }

    /// The window answers the live request `token` names. A re-arm never
    /// displaces an answer already waiting. Refused, with the reason for
    /// the caller, when the token is not the live request's.
    pub fn answer(
        &self,
        user: &str,
        token: Option<&str>,
        answer: Answer,
    ) -> Result<(), &'static str> {
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
        l.acked = true;
        drop(q);
        self.cv.notify_all();
        true
    }

    /// A new `Dialog` for the live request: its token, no acknowledgement,
    /// no rider. False when no request of `user`'s is live.
    fn set_token(&self, user: &str, token: &str) -> bool {
        let mut q = self.lock();
        let Some(l) = Self::live_of(&mut q, user) else {
            return false;
        };
        l.token = token.to_string();
        l.acked = false;
        l.rider = Rider::default();
        true
    }

    /// The `Dialog` is gone: its token answers nothing more, and whatever
    /// was armed at its card ends with it, whichever way the request
    /// ended, so nothing rides on the next approval.
    fn clear_token(&self, user: &str, token: &str) {
        let mut q = self.lock();
        if let Some(l) = Self::live_with(&mut q, user, Some(token)) {
            l.token.clear();
            l.acked = false;
            l.rider = Rider::default();
        }
    }

    #[cfg(test)]
    fn acknowledged(&self, user: &str, token: &str) -> bool {
        Self::live_with(&mut self.lock(), user, Some(token)).is_some_and(|l| l.acked)
    }

    /// Forget the window's acknowledgement: the next show waits for a
    /// fresh one.
    fn reset_ack(&self, user: &str, token: &str) {
        if let Some(l) = Self::live_with(&mut self.lock(), user, Some(token)) {
            l.acked = false;
        }
    }

    /// Wait for the window's acknowledgement of `token` until `deadline`.
    fn wait_ack(&self, user: &str, token: &str, deadline: Instant) -> bool {
        let mut q = self.lock();
        loop {
            if Self::live_with(&mut q, user, Some(token)).is_some_and(|l| l.acked) {
                return true;
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

    /// The window asks that this user's live request, when approved, also
    /// turn passwordless sudo on for `minutes`. Nothing is written now: the
    /// answer waits on the approval (a nod and its confirm, or the
    /// password), and any other end of the request drops it. Refused, with
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

    /// What the card's payload says about the rider: the minutes armed,
    /// and whether the enrolled face is in frame. With `mark_shown`
    /// sending the minutes counts as showing them; without it (a payload
    /// that waits for no acknowledgement) a rider the card has not been
    /// shown is left out, so that it still reaches the card on a show that
    /// resets the acknowledgement and the dwell.
    fn rider_for_payload(
        &self,
        user: &str,
        token: &str,
        sudo: bool,
        mark_shown: bool,
    ) -> (Option<u32>, bool) {
        let mut q = self.lock();
        let Some(l) = Self::live_with(&mut q, user, Some(token)) else {
            return (None, false);
        };
        l.rider.lane = Some(sudo);
        if mark_shown {
            l.rider.shown = true;
        }
        let minutes = if l.rider.shown { l.rider.minutes } else { None };
        (minutes, l.rider.face_present)
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

    /// The rider record as the tests read it: (minutes, face present).
    #[cfg(test)]
    fn rider_state(&self, user: &str) -> Option<(Option<u32>, bool)> {
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

/// Who is asking, as far as /proc can say. The fields the window never
/// reads are kept out of its payload: the raw command line would put a
/// long sudo command past the kernel's argument limit and cost the card
/// the ruling says it keeps (D5).
#[derive(Clone, Debug, Default, Serialize)]
pub struct CallerInfo {
    /// The process that holds the PAM transaction (sudo, polkit-agent-helper-1).
    #[serde(skip)]
    pub pid: i32,
    #[serde(skip)]
    pub exe: String,
    #[serde(skip)]
    pub cmdline: String,
    /// What is being asked. When `verified` it is the daemon's own reading
    /// of the requesting process's command line (sudo's, pkexec's). When
    /// not, it is what the requesting side said about itself: for a plain
    /// polkit action, the message and action id the agent relayed. Any
    /// process of the user's can send that, so the window labels it.
    pub command: String,
    pub verified: bool,
    /// `command` was cut at `COMMAND_CLIP`: the card says so rather
    /// than pass the tail off as the whole (A6). The nod path stays open.
    #[serde(default)]
    pub clipped: bool,
    /// Who asked: the requesting process and pid, then its parents
    /// ("sudo (pid 3011002)  from  bash (2990241) <- foot (13950)"), or the
    /// polkit helper's pid with a note that the asking process was not found.
    pub who: String,
    /// The chain above the requester: "alacritty (3910) <- bash (3921)".
    #[serde(skip)]
    pub parents: String,
    /// The process to kill if the user says no: the requester, not the helper.
    pub kill_pid: i32,
    pub via: String,
    /// On the polkit lane, the requesting process as polkitd named it, when
    /// it did: the server runs the locality check on it as well.
    #[serde(skip)]
    pub requester: Option<i32>,
}

pub(crate) fn real_uid_of(pid: i32) -> Option<u32> {
    read_proc(pid, "status")?
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|s| s.parse().ok())
}

fn cgroup_path_of(pid: i32) -> String {
    read_proc(pid, "cgroup")
        .and_then(|c| {
            c.lines()
                .find_map(|l| l.splitn(3, ':').nth(2).map(str::to_string))
        })
        .unwrap_or_default()
}

/// Which process a polkit request is for, from polkitd's caller and
/// subject pids. The caller is the process that asked polkitd, identified
/// by its D-Bus credentials: `pkexec` itself, or a system service asking
/// on behalf of the process it serves (systemd-timedated for timedatectl).
/// In the second case the service vouches for the subject, so the subject
/// is the requester; otherwise the caller is, and the subject is the
/// caller's own claim about itself.
pub fn polkit_requester(
    caller: Option<i32>,
    subject: Option<i32>,
    is_root_service: &dyn Fn(i32) -> bool,
) -> Option<i32> {
    let caller = caller.filter(|p| *p > 1)?;
    match (is_root_service(caller), subject.filter(|p| *p > 1)) {
        (true, Some(s)) => Some(s),
        _ => Some(caller),
    }
}

pub(crate) fn read_proc(pid: i32, what: &str) -> Option<String> {
    std::fs::read(format!("/proc/{}/{}", pid, what))
        .ok()
        .map(|b| {
            String::from_utf8_lossy(&b)
                .replace('\0', " ")
                .trim()
                .to_string()
        })
}

/// Longest command text shown, in characters. Wider than any real command
/// line (a kernel's argument limit is far larger, but a shown command past
/// this is not read by a person); what is cut is flagged, never hidden (A6).
pub const COMMAND_CLIP: usize = 16_384;

/// Text for the window: nothing that formats or steers the text (a newline
/// or a bidi override in a command line would let the requester write its
/// own description). Characters are kept or dropped by Unicode general
/// category: Cc (controls), Cf (format: zero-width, bidi, joiners), Zl and
/// Zp (line and paragraph separators) go; a tab becomes a space; every
/// other category stays. Cut at `COMMAND_CLIP`; `clip_command` says
/// whether it was. Applied to everything read from /proc or sent by the
/// polkit agent before it reaches the window or the log.
pub fn clip(s: &str) -> String {
    clip_command(s).0
}

/// `clip`, and whether the text was cut.
pub fn clip_command(s: &str) -> (String, bool) {
    let kept: String = s
        .chars()
        .filter_map(|c| {
            if c == '\t' {
                Some(' ')
            } else if is_dropped_category(c) {
                None
            } else {
                Some(c)
            }
        })
        .take(COMMAND_CLIP + 1)
        .collect();
    if kept.chars().count() > COMMAND_CLIP {
        log::info!(
            "consent: a command line of over {} characters is shown cut",
            COMMAND_CLIP
        );
        (kept.chars().take(COMMAND_CLIP).collect(), true)
    } else {
        (kept, false)
    }
}

/// Unicode general categories Cc, Cf, Zl and Zp (Unicode 15). The Cf
/// table is the standard's, listed in full so nothing new that formats or
/// reorders text slips through as "not on the hand list".
fn is_dropped_category(c: char) -> bool {
    if c.is_control() || matches!(c, '\u{2028}' | '\u{2029}') {
        return true;
    }
    const CF: [(u32, u32); 21] = [
        (0x00AD, 0x00AD),
        (0x0600, 0x0605),
        (0x061C, 0x061C),
        (0x06DD, 0x06DD),
        (0x070F, 0x070F),
        (0x0890, 0x0891),
        (0x08E2, 0x08E2),
        (0x180E, 0x180E),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2066, 0x206F),
        (0xFEFF, 0xFEFF),
        (0xFFF9, 0xFFFB),
        (0x110BD, 0x110BD),
        (0x110CD, 0x110CD),
        (0x13430, 0x1343F),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0001, 0xE0001),
        (0xE0020, 0xE007F),
    ];
    let u = c as u32;
    CF.iter().any(|&(lo, hi)| lo <= u && u <= hi)
}

fn exe_of(pid: i32) -> String {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .map(|p| p.display().to_string())
        .unwrap_or_default()
}

pub(crate) fn ppid_of(pid: i32) -> Option<i32> {
    let stat = read_proc(pid, "stat")?;
    // "pid (comm) state ppid ..."; comm may contain spaces, so split after the last ')'.
    let rest = stat.rsplit(')').next()?;
    rest.split_whitespace().nth(1)?.parse().ok()
}

pub(crate) fn comm_of(pid: i32) -> String {
    clip(&read_proc(pid, "comm").unwrap_or_default())
}

/// How long a summoned window has to acknowledge before the request is
/// denied.
pub const ACK_WAIT: Duration = Duration::from_secs(3);

/// After the window acknowledges, how long before a nod leg counts: a nod
/// already in motion when the card appeared was not a nod at this card.
pub const ACK_DWELL: Duration = Duration::from_millis(1500);

/// The longest passwordless spell the card may ask for.
pub const PASSWORDLESS_MAX_MINUTES: u32 = 24 * 60;

/// Two tokens compared in constant time; a wrong token and no token read
/// the same.
fn same_token(have: &str, given: &str) -> bool {
    let (a, b) = (have.as_bytes(), given.as_bytes());
    !a.is_empty()
        && a.len() == b.len()
        && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The sudoers.d file and the expiry timer unit Omarchy's own
/// `omarchy-sudo-passwordless` command uses, so its toggle-off, its
/// re-arm and its reboot cleanup all apply to a spell started here.
pub fn passwordless_file(dir: &Path, user: &str) -> std::path::PathBuf {
    dir.join(format!("99-omarchy-nopasswd-{}", user))
}

pub fn passwordless_timer_unit(user: &str) -> String {
    format!("omarchy-nopasswd-expire-{}", user)
}

/// Turn passwordless sudo on for `user` for `minutes`: the NOPASSWD rule
/// as a root-only sudoers.d file, and a transient timer that deletes it.
/// `arm` runs the timer command (systemd-run, as root) first: a timer with
/// no rule to delete is nothing, a rule with no timer would never end.
/// Only then is the rule written, so the spell never outlives its timer.
pub fn enable_passwordless(
    dir: &Path,
    user: &str,
    minutes: u32,
    arm: &dyn Fn(&[String]) -> Result<()>,
) -> Result<std::path::PathBuf> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    if user.is_empty()
        || !user
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("user name {:?} cannot be written into a sudoers rule", user);
    }
    let file = passwordless_file(dir, user);
    let unit = passwordless_timer_unit(user);
    let args: Vec<String> = vec![
        "--on-active".into(),
        format!("{}m", minutes),
        "--timer-property=AccuracySec=1s".into(),
        format!("--unit={}", unit),
        "--collect".into(),
        "/usr/bin/rm".into(),
        "-f".into(),
        "--".into(),
        file.display().to_string(),
    ];
    if let Err(e) = arm(&args) {
        // The timer could not be armed. A rule from an earlier spell may
        // still be in place with its own timer just stopped (see
        // `run_passwordless_timer`), and a rule with no timer would never
        // end: the rule goes now, as Omarchy's own command does when its
        // timer fails.
        match std::fs::remove_file(&file) {
            Ok(()) => log::warn!(
                "passwordless sudo for {}: the expiry timer could not be armed; the earlier rule was removed",
                user
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => log::error!(
                "passwordless sudo for {}: no expiry timer, and {} could not be removed: {}; remove it as root",
                user,
                file.display(),
                e
            ),
        }
        return Err(e.context("arm the passwordless expiry timer; no rule is in place"));
    }
    let tmp = dir.join(format!(".99-omarchy-nopasswd-{}.tmp", user));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o440)
            .open(&tmp)
            .with_context(|| format!("write {}", tmp.display()))?;
        writeln!(f, "{} ALL=(ALL) NOPASSWD: ALL", user)?;
    }
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o440))?;
    std::fs::rename(&tmp, &file).with_context(|| format!("place {}", file.display()))?;
    Ok(file)
}

/// Is this request Omarchy's own passwordless-sudo command? Its toggle
/// would fight a spell started from its own card (it removes the rule and
/// stops the timer as it finishes), so the button does not apply to it.
pub fn is_passwordless_command(caller: &CallerInfo) -> bool {
    caller
        .command
        .split_whitespace()
        .any(|w| w == "omarchy-sudo-passwordless" || w.ends_with("/omarchy-sudo-passwordless"))
}

/// `systemd-run` as root, for the expiry timer. An earlier timer of the
/// same name (a spell being extended) is stopped first: the name is the
/// one Omarchy's own command uses, so its toggle-off still applies, and
/// systemd will not start a second unit under it. If the new timer then
/// fails to start, `enable_passwordless` removes the rule.
pub fn run_passwordless_timer(user: &str, args: &[String]) -> Result<()> {
    let unit = format!("{}.timer", passwordless_timer_unit(user));
    let _ = std::process::Command::new("/usr/bin/systemctl")
        .args(["stop", &unit])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output();
    let out = std::process::Command::new("/usr/bin/timeout")
        .args(["-k", "2", "10", "/usr/bin/systemd-run"])
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .context("run systemd-run")?;
    if !out.status.success() {
        bail!(
            "systemd-run {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Sixteen random bytes as hex, or nothing: a token that could not be drawn
/// from the kernel is not a token, and the request fails rather than run
/// with a guessable one.
fn fresh_token() -> Option<String> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .ok()?
        .read_exact(&mut b)
        .ok()?;
    Some(b.iter().map(|x| format!("{:02x}", x)).collect())
}

/// What a polkit request is, as the agent heard it from polkitd: the action
/// id and the message (which for pkexec names the command). polkit's PAM
/// helper carries none of this (and on polkit 127 it is socket-activated by
/// systemd, so not even the agent's child), so the agent hands it to the
/// daemon as the request starts. Contexts queue per user in arrival order;
/// polkit serves one request per agent at a time, in that order, so the
/// helper's request takes the oldest fresh context for its user. One context
/// serves one request.
#[derive(Clone, Debug)]
pub struct PolkitContext {
    pub action: String,
    pub message: String,
    /// The peer that sent it, as the kernel reported it.
    pub agent: Option<AgentPeer>,
    /// polkitd's own details, when the agent's Quickshell exposes them:
    /// the process that asked polkitd (from its D-Bus credentials) and the
    /// process the authorization is for.
    pub caller_pid: Option<i32>,
    pub subject_pid: Option<i32>,
    pub at: Instant,
}

/// A process as a kernel fact: its pid and its pidfs inode, which outlives
/// no process and is never reused. It is what systemd writes into the name
/// of a socket-activated instance (polkit's helper) for the peer that
/// connected it, and what the daemon reads from a peer's pidfd.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AgentPeer {
    pub pid: i32,
    pub id: u64,
}

pub static CONTEXTS: std::sync::LazyLock<
    Mutex<std::collections::HashMap<u32, std::collections::VecDeque<PolkitContext>>>,
> = std::sync::LazyLock::new(Default::default);

/// The oldest fresh context sent by this agent (the one that connected the
/// request's helper), waiting briefly for one: the helper's PAM request and
/// the agent's context race, and the context usually loses by a few dozen
/// ms. A context from any other peer, however old, is never this request's.
pub(crate) fn take_polkit_context(agent: AgentPeer) -> Option<PolkitContext> {
    let deadline = Instant::now() + Duration::from_millis(1500);
    loop {
        if let Ok(mut m) = CONTEXTS.lock() {
            for q in m.values_mut() {
                q.retain(|c| c.at.elapsed() < Duration::from_secs(120));
                if let Some(i) = q.iter().position(|c| c.agent == Some(agent)) {
                    return q.remove(i);
                }
            }
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl CallerInfo {
    pub fn from_pid(pid: i32, user_uid: u32, agent: Option<AgentPeer>) -> CallerInfo {
        let exe = exe_of(pid);
        let cmdline = read_proc(pid, "cmdline").unwrap_or_default();
        // The helper is setuid, so its exe link is unreadable without ptrace
        // rights (this daemon has none); comm is readable but truncated to 15 bytes.
        let comm = comm_of(pid);
        // The base name is the requester's own (a process may name its
        // executable anything): clipped like the command it labels.
        let base = Path::new(&exe)
            .file_name()
            .map(|s| clip(&s.to_string_lossy()))
            .unwrap_or_else(|| comm.clone());
        if base == "polkit-agent-helper-1" || comm.starts_with("polkit-agent-he") {
            let agent_comm = agent.map(|a| comm_of(a.pid)).unwrap_or_default();
            let context = agent.and_then(take_polkit_context);
            let mut info = CallerInfo::polkit(pid, user_uid, agent, &agent_comm, context);
            info.exe = exe;
            info.cmdline = cmdline;
            return info;
        }
        let (command, clipped) = clip_command(&cmdline);
        CallerInfo {
            pid,
            exe: exe.clone(),
            cmdline: cmdline.clone(),
            kill_pid: pid,
            via: base.clone(),
            command,
            clipped,
            verified: true,
            parents: parent_chain(pid),
            who: format!("{} (pid {})  from  {}", base, pid, parent_chain(pid)),
            requester: None,
        }
    }

    /// A request through polkit's helper. The helper carries nothing that
    /// names its requester. A scan of the user's processes for one named
    /// `pkexec` is a guess any same-uid process can plant, so nothing found
    /// that way is ever presented as verified. What can be trusted: which
    /// agent connected the helper (read from the helper's unit name and
    /// pinned by the locality check), and, when that agent's Quickshell
    /// exposes them, the pids polkitd attached to the request. polkitd
    /// takes the caller's pid from its D-Bus credentials, so the requester
    /// resolved from it is read from /proc by this daemon, shown as
    /// verified, and offered to kill; the server runs the locality check
    /// on it too. Without those pids the request is described by the
    /// agent's context, labelled by the window as the requesting side's
    /// word, and there is nothing to kill.
    pub fn polkit(
        pid: i32,
        user_uid: u32,
        agent: Option<AgentPeer>,
        agent_comm: &str,
        context: Option<PolkitContext>,
    ) -> CallerInfo {
        let mut info = CallerInfo {
            pid,
            via: "polkit".into(),
            kill_pid: 0,
            verified: false,
            ..Default::default()
        };
        let agent_text = match agent {
            Some(a) => format!("agent {} (pid {})", clip(agent_comm), a.pid),
            None => "agent not known".to_string(),
        };
        let Some(c) = context else {
            log::warn!(
                "consent: no context from the agent that connected polkit helper pid {}",
                pid
            );
            info.command = "a polkit action (no description was given)".into();
            info.who = format!(
                "polkit's helper (pid {}), {}; polkit does not say which process asked",
                pid, agent_text
            );
            return info;
        };
        let relayed = clip(&format!("{} [{}]", c.message.trim(), c.action));
        let is_root_service =
            |p: i32| real_uid_of(p) == Some(0) && cgroup_path_of(p).starts_with("/system.slice/");
        let requester = polkit_requester(c.caller_pid, c.subject_pid, &is_root_service);
        // The requester must be the user's own process (polkitd allows a
        // caller to ask for its own uid or, as root, for anyone), still
        // there, with a command line to read.
        let named = requester.and_then(|rp| {
            let uid = real_uid_of(rp)?;
            if uid != user_uid {
                log::warn!("consent: polkit named requester pid {} with uid {}, not uid {}; not shown as verified", rp, uid, user_uid);
                return None;
            }
            let (cl, clipped) = clip_command(&read_proc(rp, "cmdline").unwrap_or_default());
            if cl.is_empty() {
                return None;
            }
            Some((rp, cl, clipped))
        });
        match named {
            Some((rp, cl, clipped)) => {
                let name = comm_of(rp);
                let parents = parent_chain(rp);
                let asked = match (c.caller_pid, c.subject_pid) {
                    (Some(cp), Some(sp)) if cp != sp && rp == sp => {
                        format!("; asked by {} (pid {})", comm_of(cp), cp)
                    }
                    _ => String::new(),
                };
                log::info!("consent: polkit helper pid {}: requester {} (pid {}) named by polkitd; the agent relayed: {}", pid, name, rp, relayed);
                info.command = cl;
                info.clipped = clipped;
                info.verified = true;
                info.kill_pid = rp;
                info.requester = Some(rp);
                info.parents = parents.clone();
                info.who = format!(
                    "{} (pid {})  from  {}{}; via polkit, {}",
                    name, rp, parents, asked, agent_text
                );
            }
            None => {
                log::info!("consent: polkit helper pid {}: no requester polkitd could name; the agent relayed (unverified): {}", pid, relayed);
                info.command = relayed;
                info.who = format!(
                    "polkit's helper (pid {}), {}; polkit does not say which process asked",
                    pid, agent_text
                );
            }
        }
        info
    }
}

fn parent_chain(pid: i32) -> String {
    let mut out = Vec::new();
    let mut p = pid;
    for _ in 0..4 {
        let Some(pp) = ppid_of(p) else { break };
        if pp <= 1 {
            break;
        }
        out.push(format!("{} ({})", comm_of(pp), pp));
        p = pp;
    }
    out.join(" <- ")
}

/// One command inside the user's own systemd manager, the route every
/// call into the user's session takes (the window, a notice, the lock
/// question): `systemd-run --user --machine=<user>@.host` from root, under
/// a five-second timeout, so the daemon never switches uid itself (H18).
/// `description` names the unit in the journal, where the default would
/// be the command line, payload and token included; with `omarchy` the
/// tree the shell was launched from goes in as OMARCHY_PATH; `wait` waits
/// for the command to end and `pipe` brings its stdout back.
fn in_user_manager(
    user: &str,
    description: Option<&str>,
    omarchy: bool,
    wait: bool,
    pipe: bool,
) -> std::process::Command {
    let mut c = std::process::Command::new("/usr/bin/timeout");
    c.args([
        "5",
        "/usr/bin/systemd-run",
        "--quiet",
        "--collect",
        "--user",
    ]);
    if wait {
        c.arg("--wait");
    }
    if pipe {
        c.arg("--pipe");
    }
    if let Some(d) = description {
        c.arg(format!("--description={}", d));
    }
    c.arg(format!("--machine={}@.host", user));
    if omarchy {
        c.arg(format!("-EOMARCHY_PATH={}", omarchy_path()));
    }
    c.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    c
}

/// One `omarchy-shell` invocation inside the user's own systemd manager,
/// the same route the session lock uses.
pub fn shell_call(user: &str, args: &[&str]) -> Result<()> {
    // The shell's answer comes back on stdout (`--pipe`), so a summon the
    // shell could not honour is read here rather than by a change to the
    // shared command (F2).
    let output = in_user_manager(user, Some("omarchy-faceauth window"), true, true, true)
        .arg("/usr/bin/omarchy-shell")
        .args(args)
        .output()
        .context("run omarchy-shell in the user's manager")?;
    shell_answer(args, output.status.success(), &output.stdout)
}

/// What `omarchy-shell` said, read for the daemon's purposes. A failed
/// exit is an error. A summon answered "unknown" is one too: the shell
/// has no such window (a disabled or absent plugin), nothing was shown,
/// and a caller that summoned something must not read the answer as
/// shown. Every other answer is the shell's business.
pub fn shell_answer(args: &[&str], success: bool, stdout: &[u8]) -> Result<()> {
    if !success {
        return Err(anyhow!("omarchy-shell {:?} failed", args));
    }
    let summon = args.len() >= 2 && args[0] == "shell" && args[1] == "summon";
    if summon && String::from_utf8_lossy(stdout).trim() == "unknown" {
        return Err(anyhow!(
            "omarchy-shell has no such window: {}",
            args.get(2).copied().unwrap_or("")
        ));
    }
    Ok(())
}

/// The window on the desktop. Every call is one `omarchy-shell` invocation
/// inside the user's own systemd manager, the same route the session lock uses.
pub struct Dialog {
    pub cfg: Config,
    user: String,
    open: bool,
    /// The answer token for this request (see `Live`).
    token: String,
    /// The record the token lives in.
    state: &'static ConsentState,
    /// When the window acknowledged this request.
    acked_at: Option<Instant>,
    /// When the card was last shown the "nod" state with an
    /// acknowledgement wait: the dwell runs from here, so nods count only
    /// once the card asking for them has been up for `ACK_DWELL` (D4).
    nod_shown_at: Option<Instant>,
    /// The daemon is waiting for the user to come back to the card after
    /// a nod window passed unanswered; the card offers "Ready to nod".
    waiting: bool,
    /// The last pending state and message sent, for the heartbeat.
    last: Option<(String, String)>,
}

/// While a request waits (for attention, or parked behind a lock) the
/// card is re-sent this often with the same state, so the window's own
/// safety net, which hides a card no daemon has spoken to for five
/// minutes, never fires on a live request (D1).
pub const HEARTBEAT: Duration = Duration::from_secs(60);

#[derive(Serialize)]
struct Payload<'a> {
    state: &'a str,
    message: &'a str,
    caller: &'a CallerInfo,
    token: &'a str,
    /// The nods are not armed and the daemon is waiting for the user to
    /// come back: the card shows a "Ready to nod" button, whose answer
    /// re-arms them (Q8).
    waiting: bool,
    /// The passwordless-sudo minutes the approval of this request will
    /// grant, if the card's button armed them; the card draws its rider
    /// row from this and nothing local, so it always says what a nod does.
    passwordless_minutes: Option<u32>,
    /// The nod window is following the enrolled face right now. The card
    /// greys the passwordless button otherwise, and the daemon refuses an
    /// arm otherwise, so the button and the socket obey one signal.
    face_present: bool,
}

impl Dialog {
    /// A window for `user`'s live request, with a fresh answer token
    /// written into the record. Fails when no request of theirs is live,
    /// or when no token could be drawn.
    pub fn new(cfg: &Config, user: &str, state: &'static ConsentState) -> Result<Self> {
        let token = fresh_token().ok_or_else(|| anyhow!("no randomness for the answer token"))?;
        if !state.set_token(user, &token) {
            bail!("no live consent request for {}", user);
        }
        Ok(Dialog {
            cfg: cfg.clone(),
            user: user.to_string(),
            open: false,
            token,
            state,
            acked_at: None,
            nod_shown_at: None,
            waiting: false,
            last: None,
        })
    }

    /// When the window acknowledged this request, if it has.
    pub fn acked_at(&self) -> Option<Instant> {
        self.acked_at
    }

    /// Is the card up, as far as the daemon knows?
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Re-send the last pending state to the card, so its safety net
    /// keeps counting from now. Nothing when no card is up.
    pub fn heartbeat(&mut self, caller: &CallerInfo) {
        if !self.open {
            return;
        }
        if let Some((state, message)) = self.last.clone() {
            if let Err(e) = self.show_inner(&state, &message, caller, false) {
                log::warn!("consent window: heartbeat failed: {}", e);
            }
        }
    }

    /// This request's answer token, for the rider record.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Forget the window's acknowledgement: the next show waits for a
    /// fresh one and the dwell runs whole from it. Used when what the nod
    /// grants has changed after the card was acknowledged (a rider was
    /// armed), so no nod counts until the card naming the rider is up.
    pub fn reset_ack(&mut self) {
        self.acked_at = None;
        self.state.reset_ack(&self.user, &self.token);
    }

    /// How long a nod must wait before it counts: until `ACK_DWELL` after
    /// the acknowledgement or after the nod card was shown, whichever is
    /// later, and the whole dwell when there is no acknowledgement. The
    /// acknowledgement lands during the scan, so on its own it would be
    /// spent before the nod card is up; the nod show is what the dwell is
    /// for (D4).
    pub fn dwell_left(&self, now: Instant) -> Duration {
        let Some(acked) = self.acked_at else {
            return ACK_DWELL;
        };
        let from = match self.nod_shown_at {
            Some(shown) if shown > acked => shown,
            _ => acked,
        };
        (from + ACK_DWELL).saturating_duration_since(now)
    }

    /// Has the window acknowledged this request?
    #[cfg(test)]
    fn acknowledged(&self) -> bool {
        self.state.acknowledged(&self.user, &self.token)
    }

    fn shell(&self, args: &[&str]) -> Result<()> {
        shell_call(&self.user, args)
    }

    /// Show or update the window. Fails when there is no graphical session to
    /// show it in, which callers treat as "no consent possible".
    /// The first show of a request also waits for the window's own
    /// acknowledgement; without one within `ACK_WAIT` there is no
    /// window on screen that the daemon can vouch for, and that is an error.
    pub fn show(&mut self, state: &str, message: &str, caller: &CallerInfo) -> Result<()> {
        self.waiting = false;
        self.show_inner(state, message, caller, true)
    }

    /// Show the card while the nods are not armed and the daemon waits for
    /// the user to come back to it: the card offers "Ready to nod".
    pub fn show_waiting(&mut self, message: &str, caller: &CallerInfo) -> Result<()> {
        self.waiting = true;
        self.show_inner("scanning", message, caller, true)
    }

    fn show_inner(
        &mut self,
        state: &str,
        message: &str,
        caller: &CallerInfo,
        need_ack: bool,
    ) -> Result<()> {
        // A pending-state show that first carries an armed rider is a card
        // the user has not read: the acknowledgement is reset before the
        // summon, so this show waits for a fresh one and the dwell runs
        // whole from it. The card acknowledges again on a changed rider.
        if need_ack && self.state.rider_unshown(&self.user) {
            self.reset_ack();
        }
        let (passwordless_minutes, face_present) =
            self.state
                .rider_for_payload(&self.user, &self.token, caller.via == "sudo", need_ack);
        let payload = serde_json::to_string(&Payload {
            state,
            message,
            caller,
            token: &self.token,
            waiting: self.waiting,
            passwordless_minutes,
            face_present,
        })?;
        self.shell(&["shell", "summon", "omarchy.faceauth", &payload])?;
        self.open = true;
        self.last = Some((state.to_string(), message.to_string()));
        if need_ack && state == "nod" {
            self.nod_shown_at = Some(Instant::now());
        }
        if need_ack && self.acked_at.is_none() {
            if !self
                .state
                .wait_ack(&self.user, &self.token, Instant::now() + ACK_WAIT)
            {
                self.open = false;
                return Err(anyhow!(
                    "the consent window did not acknowledge the request within {:.0}s",
                    ACK_WAIT.as_secs_f32()
                ));
            }
            self.acked_at = Some(Instant::now());
            log::info!(
                "consent: the window acknowledged the request for {}",
                self.user
            );
        }
        Ok(())
    }

    /// Re-send a pending state to a window that has already acknowledged
    /// the request, with the payload's rider and face fields as they are
    /// now, without waiting for another acknowledgement.
    pub fn show_again(&mut self, state: &str, message: &str, caller: &CallerInfo) -> Result<()> {
        self.show_inner(state, message, caller, false)
    }

    /// A final state: the window keeps itself up for a while and closes on
    /// its own, so the daemon must not hide it (and must not wait).
    pub fn show_final(&mut self, state: &str, message: &str, caller: &CallerInfo) {
        self.waiting = false;
        let _ = self.show_inner(state, message, caller, false);
        self.open = false;
        self.last = None;
    }

    pub fn hide(&mut self) {
        if self.open {
            if let Err(e) = self.shell(&["shell", "hide", "omarchy.faceauth"]) {
                log::warn!("consent window: hide failed: {}", e);
            }
            self.open = false;
            self.last = None;
        }
    }
}

impl Drop for Dialog {
    fn drop(&mut self) {
        self.hide();
        self.state.clear_token(&self.user, &self.token);
    }
}

/// Is the user's session locked? Asked of the compositor from inside the
/// user's manager, the same way the window is summoned. Unknown reads as
/// not locked.
pub fn session_locked(user: &str) -> bool {
    in_user_manager(user, None, false, true, false)
        .arg("/usr/bin/omarchy-hyprland-session-locked")
        .status()
        .map(|st| st.success())
        .unwrap_or(false)
}

/// The Omarchy tree the running shell was launched from:
/// `/etc/omarchy.conf` (written by `omarchy-dev-link` as `export
/// OMARCHY_PATH="..."`, and by hand as a bare assignment), else the
/// package. One resolver for the window, the notices and the lock helper,
/// so a dev-linked desktop is reached the same way by all three.
pub fn omarchy_path() -> String {
    std::fs::read_to_string("/etc/omarchy.conf")
        .ok()
        .and_then(|t| omarchy_path_from_conf(&t))
        .unwrap_or_else(|| "/usr/share/omarchy".into())
}

/// The `OMARCHY_PATH` value in an omarchy.conf text, with or without an
/// `export` prefix and with or without quotes; `None` when the file names
/// nothing usable, so the caller falls through to the package.
pub fn omarchy_path_from_conf(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        let l = l.trim();
        let l = l.strip_prefix("export ").map(str::trim_start).unwrap_or(l);
        let v = l
            .strip_prefix("OMARCHY_PATH=")?
            .trim()
            .trim_matches('"')
            .trim_matches('\'');
        (!v.is_empty() && v.starts_with('/')).then(|| v.to_string())
    })
}

/// A desktop notification in the user's session: every elevation by face
/// announces itself, so a loop is visible the first time it fires.
pub fn notify(user: &str, title: &str, body: &str) {
    let _ = in_user_manager(user, Some("omarchy-faceauth notice"), true, false, false)
        .args(["/usr/bin/omarchy-notification-send", title, body])
        .status();
}

/// Result of the gesture phase.
#[derive(Clone, Debug, PartialEq)]
pub enum Gesture {
    Nodded,
    /// Two head shakes: a refusal.
    Shaken,
    /// The window supplied a password (verified by the caller).
    Password(Secret),
    Dismissed,
    /// The requester went away; the window comes down with it.
    Gone,
    Timeout,
    /// No face for the presence watch's away time: the user left.
    FaceLost,
    /// The nods came, but the confirm after them could not read the strobe.
    ConfirmUnclear,
    /// The nods came, but the confirm refused: not a live enrolled face.
    ConfirmFailed(String),
    /// The window could not be shown, or never acknowledged the request.
    NoWindow,
    /// The card armed a passwordless rider the card has not been shown
    /// yet: the caller re-shows it and starts the nods over.
    RiderArmed,
    /// The session locked under the card (the idle lock, a key, the lid):
    /// nobody can see the card, so nothing is read until the unlock (D2).
    SessionLocked,
    /// The followed face left its place and one face has been back in
    /// view for a second: the scan says whether it is the user before any
    /// nod counts again (E2).
    Moved,
}

/// One gesture axis as a pure state machine over (signal, time) samples, so
/// it can be replayed from a recorded trace in a test. A gesture is two
/// complete motions: four legs of alternating direction (down, up, down, up
/// or the reverse on the pitch axis; left, right, left, right or the reverse
/// on the yaw axis), each a clear excursion, done together within a short
/// span, from a head that was still just before and does not move its face
/// elsewhere meanwhile. How a person begins and ends (from the centre or
/// from one side) does not matter: four alternating legs is the shape.
///
/// The legs come from a zigzag over the median-filtered signal: an extreme
/// is confirmed once the signal has reversed from it by the threshold, so
/// every counted leg is at least a threshold tall and consecutive legs
/// alternate by construction. The threshold adapts to the signal's own
/// jitter (a face far from the camera is noisier) between a floor and a cap.
pub struct Oscillation {
    name: &'static str,
    pub min_thr: f32,
    pub max_thr: f32,
    /// Longest leg, in seconds: a shake's legs are slower than a nod's.
    pub leg_max_s: f32,
    /// Motion gate: how far, as a fraction of face width, the filtered face
    /// centre may end the gesture from where it began, sideways and up.
    /// The axis the gesture itself moves the box along gets the wider one.
    shift_tol_x: f32,
    shift_tol_y: f32,
    /// Largest leg: bigger is a turn away, not a gesture.
    max_amp: f32,
    /// All four legs, first start to last end, within this.
    pub span_s: f32,
    /// Not moving at all for this long ends the leg where the head is.
    pub rest_s: f32,
    /// Consecutive reversed frames that confirm an extreme.
    pub rev_frames: usize,
    /// Shortest leg.
    pub leg_min_s: f32,
    /// Width change allowed across a gesture (fraction of face width).
    pub width_tol: f32,
    /// Not moving at all: frame-to-frame change under this, in degrees
    /// (`NodDetector::MESH_REST_STEP`).
    pub rest_step: f32,
    /// The whole face box must move with the leg: along x for a shake, y
    /// for a nod, by at least this fraction of the face width between the
    /// leg's start and its extreme. A head that moves carries its box; a
    /// detector fit that switches solutions moves one landmark and leaves
    /// the box where it was (recorded 2026-09-22: box centre moved 1 px
    /// through a fit flip that read as a nod; 9 to 16 px through real nods).
    /// None turns the rule off.
    pub co_motion: Option<(u8, f32)>,
    raw: Vec<f32>,
    settle: Vec<f32>,
    /// Slow-following baseline, for `idle` and the logs.
    pub base: Option<f32>,
    /// The current excursion threshold.
    pub thr: f32,
    jitter: f32,
    last_p: Option<f32>,
    /// Size of the last frame-to-frame change.
    last_step: f32,
    last_t: Option<f32>,
    /// Last confirmed extreme (value, time).
    pivot: Option<(f32, f32)>,
    /// The extreme being tracked in the current direction.
    cand: (f32, f32),
    /// +1 rising from the pivot, -1 falling, 0 not yet left it.
    pub dir: i8,
    /// Consecutive frames reversed from the candidate extreme.
    rev_count: usize,
    /// When the head stopped moving, if it has.
    rest_since: Option<f32>,
    /// Last time the signal sat close to the pivot: where a first leg starts.
    depart: f32,
    /// Completed legs as (start, end, extreme value, amplitude).
    pub legs: Vec<(f32, f32, f32, f32)>,
    last_active: Option<f32>,
    /// Recent (t, face width, centre x, centre y) for the motion gate.
    motion: Vec<(f32, f32, f32, f32)>,
    /// Seconds the face was already steadily in view before t = 0 (the scan
    /// that matched it): counts toward the still second before a first leg.
    pub prior_still: f32,
    /// Completed gestures.
    pub gestures: usize,
}

impl Oscillation {
    /// Legs in a gesture: two complete motions.
    pub const LEGS: usize = 4;
    /// Default span: the user's two nods, with the beat between them, span
    /// up to about three seconds.
    pub const SPAN_S: f32 = 3.0;
    /// Box movement along the gesture axis each leg must carry, in face
    /// widths. Swept 2026-09-22 over the calibration corpus and the
    /// calibrated-floor recording: every recorded nod and shake holds up to
    /// 0.08, a box that does not move is refused from 0.02, and a detector
    /// fit flip moved the box 0.011. 0.04 sits between with margin both ways.
    pub const CO_MOTION: f32 = 0.04;
    /// A leg shorter than this is a flicker (default). A quick nod's leg is
    /// 0.06 s (recorded); one-frame spikes are gone in the median already.
    const LEG_MIN_S: f32 = 0.05;
    /// Default reversal confirmation: one filtered frame is still a flicker.
    const REV_FRAMES: usize = 2;
    /// Default rest: the last leg of a gesture ends at rest, and a glance
    /// holds. The slow top of a real nod is not rest: it keeps creeping.
    const REST_S: f32 = 0.5;
    /// Median window over the raw signal.
    const MEDIAN: usize = 3;
    /// The face must have been still this long before the first leg.
    const STILL_S: f32 = 1.0;
    /// Default: filtered face width may end the gesture this far from where
    /// it began; more is the body moving. A shake narrows the box as the
    /// head turns, so its detector allows more.
    const WIDTH_TOL: f32 = 0.06;
    /// Threshold as a multiple of the noise floor.
    pub const JITTER_MULT: f32 = 4.0;
    const SETTLE_FRAMES: usize = 8;
    /// Baseline time constant in seconds.
    const TAU_S: f32 = 1.5;

    // Seven tuning knobs, each named at the call sites; a builder would only
    // hide which one is being set.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name: &'static str,
        min_thr: f32,
        max_thr: f32,
        leg_max_s: f32,
        shift_tol_x: f32,
        shift_tol_y: f32,
        max_amp: f32,
    ) -> Self {
        Oscillation {
            name,
            min_thr,
            max_thr,
            leg_max_s,
            shift_tol_x,
            shift_tol_y,
            max_amp,
            prior_still: 0.0,
            span_s: Self::SPAN_S,
            rest_s: Self::REST_S,
            rev_frames: Self::REV_FRAMES,
            leg_min_s: Self::LEG_MIN_S,
            width_tol: Self::WIDTH_TOL,
            rest_step: NodDetector::MESH_REST_STEP,
            co_motion: None,
            raw: Vec::new(),
            settle: Vec::new(),
            base: None,
            thr: min_thr,
            jitter: 0.0,
            last_p: None,
            last_step: 0.0,
            last_t: None,
            pivot: None,
            cand: (0.0, 0.0),
            dir: 0,
            rev_count: 0,
            rest_since: None,
            depart: 0.0,
            legs: Vec::new(),
            last_active: None,
            motion: Vec::new(),
            gestures: 0,
        }
    }

    /// True while the head is still or has only just moved: the caller may
    /// look at fewer frames. False once something like a gesture has begun.
    pub fn idle(&self, t: f32) -> bool {
        self.base.is_some() && self.last_active.map(|a| t - a > 1.0).unwrap_or(true)
    }

    fn set_threshold(&mut self) {
        self.thr = (self.jitter * Self::JITTER_MULT).clamp(self.min_thr, self.max_thr);
    }

    /// Did the face box end the span `from..=to` somewhere other than it
    /// began? The box flickers between two fits on alternate frames and rides
    /// with the gesture itself, so the test is the change of the three-frame
    /// median from the start of the span to its end.
    fn moved(&self, from: f32, to: f32, why: &str) -> bool {
        let window: Vec<&(f32, f32, f32, f32)> = self
            .motion
            .iter()
            .filter(|m| m.0 >= from && m.0 <= to)
            .collect();
        if window.len() < 6 {
            return false;
        }
        let med = |i: usize, f: fn(&(f32, f32, f32, f32)) -> f32| {
            let mut v = [f(window[i]), f(window[i + 1]), f(window[i + 2])];
            v.sort_by(|a, b| a.total_cmp(b));
            v[1]
        };
        let last = window.len() - 3;
        let (w0, w1) = (med(0, |m| m.1), med(last, |m| m.1));
        let (x0, x1) = (med(0, |m| m.2), med(last, |m| m.2));
        let (y0, y1) = (med(0, |m| m.3), med(last, |m| m.3));
        let w = w0.max(w1).max(1.0);
        let moved = (w1 - w0).abs() / w > self.width_tol
            || (x1 - x0).abs() / w > self.shift_tol_x
            || (y1 - y0).abs() / w > self.shift_tol_y;
        if moved {
            log::debug!("consent: {} legs rejected, {} (width {:.0} to {:.0}, x {:.0} to {:.0}, y {:.0} to {:.0})", self.name, why, w0, w1, x0, x1, y0, y1);
        }
        moved
    }

    /// A leg just completed at `end`: does the sequence make a gesture?
    fn legs_complete(
        &mut self,
        start: f32,
        end: f32,
        extreme: f32,
        amp: f32,
        at_rest: bool,
    ) -> bool {
        self.legs.push((start, end, extreme, amp));
        while self.legs.len() > 1 && end - self.legs[0].0 > self.span_s {
            self.legs.remove(0);
        }
        if self.legs.len() < Self::LEGS {
            // A head that rests at an extreme mid-sequence was looking at
            // something, not gesturing: the sequence starts over. The one
            // rest allowed is at the midpoint, the beat between the two
            // motions (a glance rests after its first leg, at the thing it
            // looked at).
            if at_rest && self.legs.len() != Self::LEGS / 2 {
                log::debug!(
                    "consent: {} legs rejected, the head rested at {:+.2} after {} leg(s)",
                    self.name,
                    extreme,
                    self.legs.len()
                );
                self.legs.clear();
            }
            return false;
        }
        let first = self.legs[0].0;
        // The head turned; the face ends the gesture the same size and place
        // it began. A lean, a slump or a shift carries it somewhere else.
        if self.moved(first - 0.3, end, "the face moved") {
            self.legs.clear();
            return false;
        }
        // The gesture must follow a still second: someone who has only just
        // sat down or turned to the screen, glancing between it and the
        // keyboard, has not gestured yet. A face seen for less than that
        // second has not been still either.
        if self
            .motion
            .first()
            .map(|m| m.0 - self.prior_still > first - Self::STILL_S + 0.2)
            .unwrap_or(false)
            || self.moved(first - Self::STILL_S, first, "the face had just arrived")
        {
            self.legs.clear();
            return false;
        }
        self.gestures += 1;
        self.legs.clear();
        true
    }

    /// Feed one face frame; returns true when a gesture just completed.
    pub fn push(&mut self, v: f32, t: f32) -> bool {
        self.push_with(v, t, None)
    }

    /// As `push`, with the face's width and centre for the motion gate.
    pub fn push_with(&mut self, v: f32, t: f32, face: Option<(f32, f32, f32)>) -> bool {
        if let Some((w, cx, cy)) = face {
            self.motion.push((t, w, cx, cy));
            if self.motion.len() > 96 {
                self.motion.remove(0);
            }
        }
        self.raw.push(v);
        if self.raw.len() < Self::MEDIAN {
            return false;
        }
        if self.raw.len() > 64 {
            self.raw.remove(0);
        }
        let n = self.raw.len();
        let mut w: Vec<f32> = self.raw[n - Self::MEDIAN..].to_vec();
        w.sort_by(|a, b| a.total_cmp(b));
        let p = w[Self::MEDIAN / 2];
        let dt = self.last_t.map(|l| (t - l).clamp(0.0, 0.5)).unwrap_or(0.04);
        self.last_t = Some(t);
        let Some(b) = self.base else {
            // The baseline and noise floor come from a run of quiet frames;
            // a user who gestures the moment the window appears must not
            // have the gesture measured as noise (it would raise the
            // threshold to its cap and hide the gesture itself).
            self.settle.push(p);
            if self.settle.len() > Self::SETTLE_FRAMES {
                self.settle.remove(0);
            }
            if self.settle.len() >= Self::SETTLE_FRAMES {
                let mut s = self.settle.clone();
                s.sort_by(|a, b| a.total_cmp(b));
                let quiet = s[s.len() - 1] - s[0] <= self.min_thr * 1.5;
                if quiet {
                    let base = s[s.len() / 2];
                    self.jitter = self
                        .settle
                        .windows(2)
                        .map(|w| (w[1] - w[0]).abs())
                        .sum::<f32>()
                        / (self.settle.len() - 1) as f32;
                    self.set_threshold();
                    self.base = Some(base);
                    self.pivot = Some((p, t));
                    self.depart = t;
                }
            }
            return false;
        };
        let e = p - b;
        // The baseline follows the head slowly, whatever it is doing; a
        // gesture is too quick to move it much, a lean is absorbed.
        self.base = Some(b + e * (dt / Self::TAU_S).min(1.0));
        if e.abs() > self.thr / 2.0 {
            self.last_active = Some(t);
        }
        if let Some(lp) = self.last_p {
            let step = (p - lp).abs();
            self.last_step = step;
            // Only clearly-noise steps teach the noise floor: a gesture's own
            // frames, just under the threshold, must not raise it mid-gesture
            // (they did, on the motion signal, and hid the later legs).
            if step < self.thr * 0.25 {
                self.jitter += 0.05 * (step - self.jitter);
                self.set_threshold();
            }
        }
        self.last_p = Some(p);
        let Some((pv, pt)) = self.pivot else {
            return false;
        };
        match self.dir {
            0 => {
                if (p - pv).abs() < self.thr * 0.25 {
                    self.depart = t;
                }
                if p - pv >= self.thr || pv - p >= self.thr {
                    self.dir = if p > pv { 1 } else { -1 };
                    self.cand = (p, t);
                } else if t - pt > 0.5 {
                    // Idle: re-anchor on the drifting head.
                    self.pivot = Some((p, t));
                }
                false
            }
            d => {
                // Strictly further: a rest at the extreme does not extend the
                // leg, so the pause between two nods is not part of either.
                let further = if d > 0 {
                    p > self.cand.0
                } else {
                    p < self.cand.0
                };
                // Not moving at all: a step at the still-face noise level, an
                // absolute of the floor (a still face moves 0.003 of a width
                // between frames; a slow turnaround moves more).
                let still = self.last_step < self.rest_step;
                if further {
                    self.cand = (p, t);
                    self.rev_count = 0;
                    self.rest_since = if still {
                        self.rest_since.or(Some(t))
                    } else {
                        None
                    };
                    return false;
                }
                let reversed = if d > 0 {
                    self.cand.0 - p >= self.thr
                } else {
                    p - self.cand.0 >= self.thr
                };
                let at_rest = if !reversed {
                    self.rev_count = 0;
                    if still {
                        let since = *self.rest_since.get_or_insert(t);
                        t - since >= self.rest_s
                    } else {
                        self.rest_since = None;
                        false
                    }
                } else {
                    self.rest_since = None;
                    self.rev_count += 1;
                    false
                };
                if !at_rest && self.rev_count < self.rev_frames {
                    return false;
                }
                self.rev_count = 0;
                self.rest_since = None;
                // The extreme is confirmed: one leg, from the previous extreme
                // (or from where the head left its rest) to it.
                // A first leg starts where the head left its rest; a later
                // one at the previous extreme.
                let start = if self.legs.is_empty() {
                    self.depart.max(pt)
                } else {
                    pt
                };
                let (cv, ct) = self.cand;
                let dur = ct - start;
                let carried = match self.co_motion {
                    None => true,
                    Some((axis, min)) => {
                        // The box's swing along the axis across the leg,
                        // with a margin either side: the filtered signal
                        // lags the head, so the instants the leg is timed
                        // by fall inside the box's own movement.
                        let (lo_t, hi_t) = (start - 0.2, ct + 0.2);
                        let mut lo = f32::MAX;
                        let mut hi = f32::MIN;
                        let mut w = 1.0f32;
                        for m in self.motion.iter().filter(|m| m.0 >= lo_t && m.0 <= hi_t) {
                            let v = if axis == 1 { m.2 } else { m.3 };
                            lo = lo.min(v);
                            hi = hi.max(v);
                            w = w.max(m.1);
                        }
                        if lo > hi {
                            true
                        } else {
                            let moved = (hi - lo) / w;
                            if moved < min {
                                log::debug!("consent: {} leg rejected, the box did not move with it ({:.3} of width)", self.name, moved);
                            }
                            moved >= min
                        }
                    }
                };
                let amp = (cv - pv).abs();
                self.pivot = Some((cv, ct));
                // Reversed: the next leg is under way. At rest: back to
                // waiting for the head to leave this spot.
                self.dir = if at_rest { 0 } else { -d };
                self.depart = ct;
                self.cand = (p, t);
                if !carried
                    || !(self.leg_min_s..=self.leg_max_s).contains(&dur)
                    || amp > self.max_amp
                {
                    log::debug!(
                        "consent: {} leg rejected (box {}, {:.2}s, {:.2} tall)",
                        self.name,
                        if carried { "carried" } else { "still" },
                        dur,
                        amp
                    );
                    self.legs.clear();
                    return false;
                }
                self.legs_complete(start, ct, cv, amp, at_rest)
            }
        }
    }
}

/// Nods: the pitch axis, in degrees from the face mesh.
pub struct NodDetector {
    pub inner: Oscillation,
    /// Nods counted: two per completed gesture.
    pub nods: usize,
    /// Recent (t, yaw), for the quiet-yaw and facing rules.
    yaw: Vec<(f32, f32)>,
}

impl NodDetector {
    /// On the mesh's pitch, in degrees. From the rounds of 2026-09-24
    /// (`traces/v2`): a nod's legs are 12 to 35 degrees and take 0.23 to
    /// 0.33 s, reversing at once; a look at the keyboard is 17 to 21
    /// degrees a leg but takes 0.9 to 2 s and holds at the bottom, a lean
    /// 18 to 30 over 1.1 to 3.3 s. Size does not separate them; the leg
    /// time does, so a leg may take at most `MESH_LEG_MAX_S`.
    pub const MESH_MIN_DEG: f32 = 8.0;
    pub const MESH_MAX_DEG: f32 = 60.0;
    pub const MESH_LEG_MAX_S: f32 = 0.6;
    /// Still, on the mesh: under this many degrees between frames (a still
    /// head reads 0.7 on average, a turnaround several).
    pub const MESH_REST_STEP: f32 = 1.5;
    /// A nod keeps the head facing the camera: yaw may range this much
    /// over the gesture's span, in degrees. Set on the five-point yaw
    /// measure as 0.25 of it (a still head ranged 0.03, the user's nods up
    /// to 0.11, a head shake 0.6 or more, and a shake's perspective wobble
    /// on the pitch measure would otherwise have read as nods) and
    /// restated in degrees at `YAW_DEG_PER_UNIT`, so the rule did not move.
    pub const YAW_QUIET_DEG: f32 = 21.43;
    /// A nod counts only from a head facing the camera (the presence
    /// watch's attentive yaw): the mean yaw over the nod's span, degrees,
    /// must be within this. A head held turned toward another screen nods
    /// the same way on the pitch axis, but it is not nodding at the card.
    /// 0.40 of the five-point measure, restated as above; the reference
    /// nods held 30 degrees off still read and are refused from 36.
    pub const YAW_FACING_DEG: f32 = 34.29;
    /// Degrees of mesh yaw per unit of the five-point yaw measure (a 30
    /// degree turn read about 0.35 on it). The gesture rules are written
    /// in degrees; the presence watch's `max_yaw` is still in five-point
    /// units and converts with this.
    pub const YAW_DEG_PER_UNIT: f32 = 30.0 / 0.35;

    pub fn mesh(floor_deg: f32) -> Self {
        let floor = floor_deg.max(Self::MESH_MIN_DEG);
        let mut inner = Oscillation::new(
            "nod",
            floor,
            Self::MESH_MAX_DEG.max(floor),
            Self::MESH_LEG_MAX_S,
            0.10,
            0.30,
            Self::MESH_MAX_DEG,
        );
        // The box must ride each leg: a head that nods carries its box, a
        // detector fit that flips does not (1 px through a recorded flip,
        // 9 to 16 px through real nods). See `Oscillation::CO_MOTION`.
        inner.co_motion = Some((2, Oscillation::CO_MOTION));
        NodDetector {
            inner,
            nods: 0,
            yaw: Vec::new(),
        }
    }

    pub fn idle(&self, t: f32) -> bool {
        self.inner.idle(t)
    }

    /// Feed one frame: the pitch, the yaw for the quiet-yaw and facing
    /// rules (None when the caller has none), the time, and the box's
    /// width and centre for the motion rules. True when a nod pair just
    /// completed.
    pub fn push_full(
        &mut self,
        pitch: f32,
        yaw: Option<f32>,
        t: f32,
        face: Option<(f32, f32, f32)>,
    ) -> bool {
        if let Some(y) = yaw {
            self.yaw.push((t, y));
            self.yaw
                .retain(|(yt, _)| t - yt <= Oscillation::SPAN_S + 0.5);
        }
        let hit = self.inner.push_with(pitch, t, face);
        if !hit {
            return false;
        }
        let span: Vec<f32> = self
            .yaw
            .iter()
            .filter(|(yt, _)| t - yt <= Oscillation::SPAN_S)
            .map(|(_, y)| *y)
            .collect();
        if let (Some(lo), Some(hi)) = (
            span.iter().cloned().reduce(f32::min),
            span.iter().cloned().reduce(f32::max),
        ) {
            if hi - lo > Self::YAW_QUIET_DEG {
                log::debug!(
                    "consent: nod rejected, the head turned meanwhile (yaw range {:.0} deg)",
                    hi - lo
                );
                return false;
            }
            let mean = span.iter().sum::<f32>() / span.len() as f32;
            if mean.abs() > Self::YAW_FACING_DEG {
                log::debug!(
                    "consent: nod rejected, the head faced away (mean yaw {:.0} deg)",
                    mean
                );
                return false;
            }
        }
        self.nods += 2;
        true
    }
}

/// Head shakes: the yaw axis, in degrees from the face mesh. A refusal,
/// so a false positive costs a password prompt, not a root shell: the
/// floor can sit lower than a glance at a second monitor only because a
/// glance is one leg and a hold, never four alternating legs.
pub struct ShakeDetector {
    pub inner: Oscillation,
    /// Shakes counted: two per completed gesture.
    pub shakes: usize,
}

impl ShakeDetector {
    /// On the mesh's yaw, in degrees. From the rounds of 2026-09-24: a
    /// shake's legs are 33 to 53 degrees and take about 0.3 s; a glance
    /// aside is as large (32 to 50) but takes 0.8 to 2.2 s and holds at
    /// the side for half a second or more.
    pub const MESH_MIN_DEG: f32 = 15.0;
    pub const MESH_MAX_DEG: f32 = 80.0;
    pub const MESH_LEG_MAX_S: f32 = 0.6;

    pub fn mesh(floor_deg: f32) -> Self {
        let floor = floor_deg.max(Self::MESH_MIN_DEG);
        // A shake slides the box sideways and narrows it by about 7% as
        // the head turns (recorded): not the body moving, so the width
        // tolerance is wider than a nod's. A glance is caught by its hold
        // (the rest rule) and its leg time.
        let mut inner = Oscillation::new(
            "shake",
            floor,
            Self::MESH_MAX_DEG.max(floor),
            Self::MESH_LEG_MAX_S,
            0.60,
            0.30,
            Self::MESH_MAX_DEG,
        );
        inner.width_tol = 0.15;
        // The box must slide with each leg (see the nod detector).
        inner.co_motion = Some((1, Oscillation::CO_MOTION));
        ShakeDetector { inner, shakes: 0 }
    }

    pub fn push_with(&mut self, yaw: f32, t: f32, face: Option<(f32, f32, f32)>) -> bool {
        let hit = self.inner.push_with(yaw, t, face);
        if hit {
            self.shakes += 2;
        }
        hit
    }
}

/// One frame of a recorded round: the head's angles in degrees and the
/// detector box (width, centre x, centre y). What the detectors read.
#[derive(Clone, Debug)]
pub struct RoundFrame {
    pub t: f32,
    pub yaw: f32,
    pub pitch: f32,
    pub roll: f32,
    pub geom: (f32, f32, f32),
}

/// The header of a round recording (format v3): one line per frame with
/// the mesh's angles in degrees, the detector box, the face's width as a
/// fraction of the frame's shorter side and the mesh's confidence. Numbers
/// only, never an image. The walk-through's rounds and the consent window
/// write the same lines, so either replays through `replay_round`.
pub const ROUND_HEADER: &str = "v3 t yaw pitch roll w cx cy size score";

/// One line of a round recording, as `ROUND_HEADER` lays it out.
pub fn round_line(
    t: f32,
    hp: &faceauth_engine::mesh::HeadPose,
    geom: (f32, f32, f32),
    size: f32,
    score: f32,
) -> String {
    format!(
        "{:.2} {:+.1} {:+.1} {:+.1} {:.0} {:.0} {:.0} {:.3} {:.2}",
        t, hp.yaw, hp.pitch, hp.roll, geom.0, geom.1, geom.2, size, score
    )
}

/// Parse a round recording: a header line naming its format, then one
/// frame per line. The v2 files of 2026-09-24 carry two image-motion
/// columns (`pos_x pos_y`) before the box that nothing reads any more;
/// v3 drops them.
pub fn parse_round(text: &str) -> Vec<RoundFrame> {
    let header = text.lines().next().unwrap_or("");
    let skip = if header.starts_with("v2") { 2 } else { 0 };
    let data = if header.starts_with('v') { 1 } else { 0 };
    text.lines()
        .skip(data)
        .filter_map(|l| {
            let f: Vec<f32> = l
                .split_whitespace()
                .filter_map(|v| v.parse().ok())
                .collect();
            if f.len() < 7 + skip {
                return None;
            }
            Some(RoundFrame {
                t: f[0],
                yaw: f[1],
                pitch: f[2],
                roll: f[3],
                geom: (f[4 + skip], f[5 + skip], f[6 + skip]),
            })
        })
        .collect()
}

/// Replay a mesh recording through the mesh detectors at these floors
/// (degrees): nods and shakes counted.
pub fn replay_round(frames: &[RoundFrame], floors_deg: (f32, f32)) -> (usize, usize) {
    // A recorded round starts at the "go" and the still second before it
    // was not recorded, so the replay credits it; the live nod window
    // does not (D4), it observes the still second inside the window.
    let mut det = NodDetector::mesh(floors_deg.0);
    let mut shake = ShakeDetector::mesh(floors_deg.1);
    det.inner.prior_still = 1.0;
    shake.inner.prior_still = 1.0;
    for f in frames {
        shake.push_with(f.yaw, f.t, Some(f.geom));
        det.push_full(f.pitch, Some(f.yaw), f.t, Some(f.geom));
    }
    (det.nods, shake.shakes)
}

/// Where a recorded gesture round stops reading: the highest floor, in
/// whole degrees from the detector's minimum, at which the mesh detector
/// still counts the round as two of its gesture (`nod` picks which). The
/// walk-through stores this per round and derives the person's floors
/// from the lowest of them (`GestureCal::floors_deg`). None when the
/// round does not read even at the minimum: it cannot set a floor.
pub fn reads_to_deg(frames: &[RoundFrame], nod: bool) -> Option<f32> {
    let (min, max) = if nod {
        (NodDetector::MESH_MIN_DEG, NodDetector::MESH_MAX_DEG)
    } else {
        (ShakeDetector::MESH_MIN_DEG, ShakeDetector::MESH_MAX_DEG)
    };
    let reads = |floor: f32| {
        let floors = if nod {
            (floor, ShakeDetector::MESH_MIN_DEG)
        } else {
            (NodDetector::MESH_MIN_DEG, floor)
        };
        let (nods, shakes) = replay_round(frames, floors);
        if nod {
            nods >= 2
        } else {
            shakes >= 2
        }
    };
    let mut floor = min;
    let mut best = None;
    while floor <= max && reads(floor) {
        best = Some(floor);
        floor += 1.0;
    }
    best
}

/// Writes a round's per-frame recording when the round ends, if
/// `gesture_trace` is on: `<store_dir>/gestures/<user>/<unix seconds>-<how
/// it ended>.txt`, mode 0600 in a 0700 directory, newest sixty kept. The
/// recording is `ROUND_HEADER` and one line per frame looked at: the head's
/// angles and the box; never an image, and never the journal.
#[cfg_attr(not(feature = "dev-tools"), allow(dead_code))]
struct TraceSaver<'a> {
    cfg: &'a Config,
    user: String,
    trace: std::cell::RefCell<Vec<String>>,
    label: std::cell::Cell<&'static str>,
}

impl Drop for TraceSaver<'_> {
    fn drop(&mut self) {
        // The recordings exist only in a dev-tools build: the package has
        // no key to switch them on.
        #[cfg(feature = "dev-tools")]
        self.save();
    }
}

#[cfg(feature = "dev-tools")]
impl TraceSaver<'_> {
    fn save(&self) {
        if !self.cfg.gesture_trace {
            return;
        }
        let trace = self.trace.borrow();
        if trace.is_empty() {
            return;
        }
        // One directory per user, so a delete of that user takes exactly
        // these and never a neighbour's (the user name may hold hyphens).
        let dir = Path::new(crate::config::STORE_DIR)
            .join("gestures")
            .join(&self.user);
        let res = (|| -> std::io::Result<()> {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            std::fs::create_dir_all(&dir)?;
            std::fs::set_permissions(
                dir.parent().unwrap_or(&dir),
                std::fs::Permissions::from_mode(0o700),
            )?;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            let name = format!("{}-{}.txt", crate::store::now_secs(), self.label.get());
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dir.join(&name))?;
            f.write_all(ROUND_HEADER.as_bytes())?;
            f.write_all(b"\n")?;
            f.write_all(trace.join("\n").as_bytes())?;
            f.write_all(b"\n")?;
            let mut files: Vec<_> = std::fs::read_dir(&dir)?
                .flatten()
                .map(|e| e.path())
                .collect();
            files.sort();
            while files.len() > 60 {
                let _ = std::fs::remove_file(files.remove(0));
            }
            log::info!("consent: gesture recording saved as {}", name);
            Ok(())
        })();
        if let Err(e) = res {
            log::warn!("consent: gesture recording not saved: {}", e);
        }
    }
}

/// Which detection in a frame is the face being followed.
#[derive(Debug, PartialEq)]
pub enum Track {
    /// The followed face, by index into the detections.
    Found(usize),
    /// No detection continues the followed box.
    Lost,
    /// Two detections could each be it: the gesture pauses.
    Ambiguous,
}

/// Follow `tracked` through `faces`: the detection whose centre moved less
/// than half a face width and whose width is within 30 percent continues
/// it. A second detection that also fits, or overlaps it, is ambiguous.
/// Other faces in the frame are ignored (the one that matched is the one
/// that answers).
pub fn track(faces: &[faceauth_engine::Face], tracked: [f32; 4]) -> Track {
    let (tw, tcx, tcy) = (
        tracked[2].max(1.0),
        tracked[0] + tracked[2] / 2.0,
        tracked[1] + tracked[3] / 2.0,
    );
    let fits = |b: &[f32; 4]| -> bool {
        let (cx, cy) = (b[0] + b[2] / 2.0, b[1] + b[3] / 2.0);
        let dist = ((cx - tcx).powi(2) + (cy - tcy).powi(2)).sqrt();
        let ratio = b[2] / tw;
        dist < 0.5 * tw && (0.7..=1.43).contains(&ratio)
    };
    let mut candidates: Vec<(usize, f32)> = faces
        .iter()
        .enumerate()
        .filter(|(_, f)| fits(&f.bbox))
        .map(|(i, f)| {
            let (cx, cy) = (f.bbox[0] + f.bbox[2] / 2.0, f.bbox[1] + f.bbox[3] / 2.0);
            (i, ((cx - tcx).powi(2) + (cy - tcy).powi(2)).sqrt())
        })
        .collect();
    candidates.sort_by(|a, b| a.1.total_cmp(&b.1));
    match candidates.len() {
        0 => Track::Lost,
        1 => Track::Found(candidates[0].0),
        _ => Track::Ambiguous,
    }
}

/// The most recent frames kept from a nod's legs for the identity check
/// after the confirm (D4): two per gesture and a few to spare.
pub const NOD_FRAMES_KEPT: usize = 8;

/// `nod_frames` receives the frame and face at the end of each counted
/// nod leg, and at each counted nod, newest last, capped at
/// `NOD_FRAMES_KEPT`. The caller embeds them after the confirm and
/// requires each to match the templates: the nods must have come from
/// the enrolled face, not merely from the box the confirm later finds
/// live (D4). Nothing about identity is read here; the detectors and
/// their floors are untouched. `seen` is the request's own away clock:
/// every frame that finds the followed box refreshes it, and past
/// `lost_after` without one the user has left (E2).
#[allow(clippy::too_many_arguments)]
pub fn wait_for_nods(
    cap: &mut IrCapture,
    pipeline: &mut Pipeline,
    cfg: &Config,
    window: Duration,
    nods_needed: usize,
    state: Option<(&ConsentState, &str)>,
    lost_after: Option<Duration>,
    floors_deg: (f32, f32),
    start: Option<[f32; 4]>,
    dwell: Duration,
    nod_frames: &mut Vec<(Grey, faceauth_engine::Face)>,
    presence: Option<&dyn Fn(bool)>,
    session_locked: Option<&dyn Fn() -> bool>,
    seen: &std::cell::Cell<Instant>,
) -> Result<(Gesture, Option<[f32; 4]>)> {
    let min_detection = cfg.min_detection;
    #[cfg(feature = "dev-tools")]
    let record_only = cfg.gesture_record_only;
    #[cfg(not(feature = "dev-tools"))]
    let record_only = false;
    let user_name = state
        .map(|(_, u)| u.to_string())
        .unwrap_or_else(|| "unknown".into());
    // The rider record follows the followed face: while this window runs
    // and the matched face is in view the card may arm passwordless sudo,
    // and at no other time. Whichever way the window ends, it ends that.
    struct FaceMark<'a>(Option<(&'a ConsentState, &'a str)>);
    impl FaceMark<'_> {
        fn set(&self, present: bool) -> bool {
            self.0
                .is_some_and(|(state, user)| state.set_face_present(user, present))
        }
    }
    impl Drop for FaceMark<'_> {
        fn drop(&mut self) {
            self.set(false);
        }
    }
    let face_mark = FaceMark(state);
    let t0 = Instant::now();
    // The gestures are read from the head's angles on the face mesh, which
    // the daemon does not start without; the box still has to carry each
    // leg (`co_motion`), so a landmark fit cannot nod on its own.
    let mut det = NodDetector::mesh(floors_deg.0);
    let mut shake = ShakeDetector::mesh(floors_deg.1);
    // No still second is credited from the scan: a first leg must follow
    // a head seen still inside this window, after the dwell, so a nod
    // already under way when the nod card appears is not a nod at it (D4).
    // Per-frame recording: the raw material for tuning both detectors.
    // Saved to the root-only gestures directory when the round ends, if
    // enabled; never to the journal (it is per-frame head pose).
    let saver = TraceSaver {
        cfg,
        user: user_name.clone(),
        trace: Default::default(),
        label: std::cell::Cell::new("ended"),
    };
    let label = &saver.label;
    let trace = &saver.trace;
    let mut frame_no = 0usize;
    // The face being followed: the one the scan matched. A detection that
    // does not continue it is not the answerer, however well it scores.
    let mut tracked: Option<[f32; 4]> = start;
    let mut lost_since: Option<Instant> = None;
    let mut paused_logged = false;
    // Until the dwell has passed frames are drained and nothing is read;
    // the still second before a first leg is then observed inside the
    // window, so a nod already under way at a card that just appeared is
    // not one.
    let mut dwelt = dwell.is_zero();
    if !dwelt {
        log::debug!(
            "consent: nods count only after a {:.1}s dwell",
            dwell.as_secs_f32()
        );
    }
    // The compositor is asked whether the session locked under the card
    // every couple of seconds (the probe spawns a process, so not per
    // frame): a card the lock screen covers is a card nobody nods at.
    let mut last_lock_check = Instant::now();
    let summary = |det: &NodDetector, shake: &ShakeDetector, t: f32| {
        format!(
            "{} nods, {} shakes in {:.1}s, thresholds {:.3}/{:.3}",
            det.nods, shake.shakes, t, det.inner.thr, shake.inner.thr
        )
    };
    while t0.elapsed() < window {
        if let Some((state, user)) = state {
            match state.poll(user) {
                Some(Answer::Password(pw)) => {
                    log::info!(
                        "consent: password answer after {}",
                        summary(&det, &shake, t0.elapsed().as_secs_f32())
                    );
                    label.set("password");
                    return Ok((Gesture::Password(pw), tracked));
                }
                Some(Answer::Dismiss) => {
                    log::info!(
                        "consent: dismissed after {}",
                        summary(&det, &shake, t0.elapsed().as_secs_f32())
                    );
                    label.set("dismissed");
                    return Ok((Gesture::Dismissed, tracked));
                }
                Some(Answer::Gone) => {
                    log::info!(
                        "consent: requester gone after {}",
                        summary(&det, &shake, t0.elapsed().as_secs_f32())
                    );
                    label.set("gone");
                    return Ok((Gesture::Gone, tracked));
                }
                // The nods are armed already: the button changes nothing.
                Some(Answer::Rearm) | None => {}
            }
            // A rider armed since the card's last payload changes what a
            // nod grants: the window ends here, before any frame is read,
            // so the caller can re-show the card and start the nods over.
            if state.rider_unshown(user) {
                log::info!(
                    "consent: passwordless sudo armed after {}; the card is re-shown and the nods start over",
                    summary(&det, &shake, t0.elapsed().as_secs_f32())
                );
                label.set("rider-armed");
                return Ok((Gesture::RiderArmed, tracked));
            }
        }
        if let Some(l) = lost_after {
            if seen.get().elapsed() > l {
                log::info!(
                    "consent: no face for {:.0}s after {} nods; the user left",
                    l.as_secs_f32(),
                    det.nods
                );
                label.set("face-lost");
                return Ok((Gesture::FaceLost, tracked));
            }
        }
        if let Some(locked) = session_locked {
            if last_lock_check.elapsed() > Duration::from_secs(2) {
                last_lock_check = Instant::now();
                if locked() {
                    log::info!(
                        "consent: the session locked under the card after {}; parked",
                        summary(&det, &shake, t0.elapsed().as_secs_f32())
                    );
                    label.set("session-locked");
                    return Ok((Gesture::SessionLocked, tracked));
                }
            }
        }
        let Some(img) = cap.next(Duration::from_secs(1))? else {
            continue;
        };
        if !dwelt {
            if t0.elapsed() < dwell {
                continue;
            }
            dwelt = true;
        }
        // Slow polling while the head is still: every other frame is looked
        // at (a leg leaves the rest for six or more frames, so its start
        // cannot slip between two), the rest are only drained. Once a
        // movement begins every frame is looked at.
        frame_no += 1;
        let t = t0.elapsed().as_secs_f32();
        // Plain modulo kept on purpose; `is_multiple_of` reads worse here.
        #[allow(clippy::manual_is_multiple_of)]
        if det.idle(t) && shake.inner.idle(t) && frame_no % 2 != 0 {
            continue;
        }
        let faces = pipeline.detector.detect(&img, min_detection)?;
        if faces.is_empty() {
            continue;
        }
        let face = match tracked {
            None => faces
                .into_iter()
                .max_by(|a, b| a.score.total_cmp(&b.score))
                .unwrap(),
            Some(tb) => match track(&faces, tb) {
                Track::Found(i) => {
                    lost_since = None;
                    if paused_logged && face_mark.set(true) {
                        if let Some(p) = presence {
                            p(true);
                        }
                    }
                    paused_logged = false;
                    faces.into_iter().nth(i).unwrap()
                }
                other => {
                    // The followed face is not there, or cannot be told from
                    // another: nothing counts meanwhile, and a nod begun
                    // before is forgotten. A face that is not the followed
                    // one does not hold the request open: the away clock
                    // runs from the last sight of the followed face, so a
                    // stranger at the desk cannot keep a request pending
                    // past the presence away time (C1, consent lane). A
                    // single face back for a second is not adopted here,
                    // since the tracker cannot say whose it is: the window
                    // ends and the scan decides before the nods resume (E2).
                    if !paused_logged {
                        log::info!(
                            "consent: gesture paused, the matched face is {}",
                            if other == Track::Lost {
                                "not in view"
                            } else {
                                "one of two"
                            }
                        );
                        paused_logged = true;
                        // The card's passwordless button follows the face:
                        // greyed while the matched face is out of view.
                        if face_mark.set(false) {
                            if let Some(p) = presence {
                                p(false);
                            }
                        }
                    }
                    det = NodDetector::mesh(floors_deg.0);
                    shake = ShakeDetector::mesh(floors_deg.1);
                    let since = *lost_since.get_or_insert(Instant::now());
                    if other == Track::Lost
                        && faces.len() == 1
                        && since.elapsed() > Duration::from_secs(1)
                    {
                        log::info!(
                            "consent: one face in view again after {}; the scan decides whether it is the user",
                            summary(&det, &shake, t0.elapsed().as_secs_f32())
                        );
                        label.set("moved");
                        return Ok((Gesture::Moved, tracked));
                    }
                    continue;
                }
            },
        };
        tracked = Some(face.bbox);
        seen.set(Instant::now());
        let geom = (
            face.bbox[2],
            face.bbox[0] + face.bbox[2] / 2.0,
            face.bbox[1] + face.bbox[3] / 2.0,
        );
        // A frame the mesh cannot read is skipped: nothing else feeds the
        // detectors.
        let Some(m) = pipeline
            .mesh
            .as_mut()
            .and_then(|mesh| mesh.for_face(&img, &face).ok().flatten())
        else {
            continue;
        };
        let hp = faceauth_engine::mesh::head_pose(&m);
        // The per-frame line is built only where a recording can be
        // written: a development build with the trace switched on.
        #[cfg(feature = "dev-tools")]
        if cfg.gesture_trace && trace.borrow().len() < 1200 {
            let size = face.bbox[2] / img.width.min(img.height).max(1) as f32;
            trace
                .borrow_mut()
                .push(round_line(t, &hp, geom, size, m.score));
        }
        if shake.push_with(hp.yaw, t, Some(geom)) {
            if record_only {
                log::info!(
                    "consent: head shake recorded (record-only), {}",
                    summary(&det, &shake, t)
                );
            } else {
                log::info!(
                    "consent: head shake, refused after {}",
                    summary(&det, &shake, t)
                );
                label.set("shaken");
                return Ok((Gesture::Shaken, tracked));
            }
        }
        let legs_before = det.inner.legs.len();
        let counted = det.push_full(hp.pitch, Some(hp.yaw), t, Some(geom));
        if counted || det.inner.legs.len() > legs_before {
            nod_frames.push((img.clone(), face.clone()));
            if nod_frames.len() > NOD_FRAMES_KEPT {
                nod_frames.remove(0);
            }
        }
        if counted {
            log::debug!("consent: nod {} at {:.2}s", det.nods, t);
            if det.nods >= nods_needed {
                if record_only {
                    log::info!(
                        "consent: nods recorded (record-only), {}",
                        summary(&det, &shake, t)
                    );
                } else {
                    log::info!("consent: {}", summary(&det, &shake, t));
                    label.set("nodded");
                    return Ok((Gesture::Nodded, tracked));
                }
            }
        }
    }
    log::info!(
        "consent: timed out, {} ({} face frames)",
        summary(&det, &shake, window.as_secs_f32()),
        trace.borrow().len()
    );
    label.set("timeout");
    Ok((Gesture::Timeout, tracked))
}

/// A consent state of a test's own, leaked so a `Dialog` can hold it.
#[cfg(test)]
pub(crate) fn test_state() -> &'static ConsentState {
    Box::leak(Box::new(ConsentState::new()))
}

#[cfg(test)]
mod track_tests {
    use super::{track, Track};
    use faceauth_engine::Face;

    fn face(x: f32, y: f32, w: f32, score: f32) -> Face {
        Face {
            bbox: [x, y, w, w * 1.2],
            score,
            landmarks: [[0.0; 2]; 5],
            embedding: None,
        }
    }

    #[test]
    fn the_matched_box_is_followed_through_a_nod_sized_move() {
        let t = [200.0, 300.0, 90.0, 108.0];
        assert_eq!(
            track(&[face(205.0, 318.0, 92.0, 0.7)], t),
            Track::Found(0),
            "moved 18 px down on a 90 px face: the same head"
        );
        assert_eq!(
            track(&[face(200.0, 300.0, 100.0, 0.7)], t),
            Track::Found(0),
            "came a little closer"
        );
    }

    #[test]
    fn a_face_elsewhere_or_of_another_size_is_not_it() {
        let t = [200.0, 300.0, 90.0, 108.0];
        assert_eq!(
            track(&[face(300.0, 300.0, 90.0, 0.9)], t),
            Track::Lost,
            "a face width away is someone else, however well it scores"
        );
        assert_eq!(
            track(&[face(200.0, 300.0, 50.0, 0.9)], t),
            Track::Lost,
            "half the size is not the same head"
        );
        assert_eq!(track(&[], t), Track::Lost);
    }

    #[test]
    fn the_followed_face_is_chosen_over_a_better_scoring_stranger() {
        let t = [200.0, 300.0, 90.0, 108.0];
        assert_eq!(
            track(
                &[
                    face(400.0, 300.0, 120.0, 0.95),
                    face(203.0, 305.0, 90.0, 0.6)
                ],
                t
            ),
            Track::Found(1)
        );
    }

    #[test]
    fn two_faces_that_both_fit_are_ambiguous() {
        let t = [200.0, 300.0, 90.0, 108.0];
        assert_eq!(
            track(
                &[face(205.0, 300.0, 90.0, 0.7), face(230.0, 310.0, 85.0, 0.7)],
                t
            ),
            Track::Ambiguous
        );
    }
}

#[cfg(test)]
mod window_text_tests {
    use super::clip;

    #[test]
    fn the_omarchy_path_is_read_in_every_form_the_conf_takes() {
        use super::omarchy_path_from_conf as f;
        assert_eq!(
            f("export OMARCHY_PATH=\"/home/x/omarchy\"\n").as_deref(),
            Some("/home/x/omarchy")
        );
        assert_eq!(
            f("OMARCHY_PATH=/usr/share/omarchy\n").as_deref(),
            Some("/usr/share/omarchy")
        );
        assert_eq!(
            f("# comment\n  export  OMARCHY_PATH='/opt/o'\n").as_deref(),
            Some("/opt/o")
        );
        assert_eq!(f("OMARCHY_PATH=\n"), None);
        assert_eq!(f("OMARCHY_PATH=relative\n"), None);
        assert_eq!(f(""), None);
    }

    #[test]
    fn clip_drops_line_breaks_and_direction_overrides() {
        use super::{clip_command, COMMAND_CLIP};
        assert_eq!(
            clip("sudo /bin/sh -c true\nRoutine update\nNo action needed"),
            "sudo /bin/sh -c trueRoutine updateNo action needed"
        );
        assert_eq!(clip("ls \u{202E}txt.sh"), "ls txt.sh");
        assert_eq!(
            clip("a\u{200B}b\u{2066}c\tD"),
            "abc D",
            "a tab is a space; format characters go"
        );
        // Line and paragraph separators, next line, and the Arabic letter
        // mark: every category that breaks or steers a line, not a hand list.
        assert_eq!(
            clip("a\u{2028}b\u{2029}c\u{0085}d\u{061C}e\u{FEFF}f\u{00AD}g\u{E0041}h"),
            "abcdefgh"
        );
        assert_eq!(clip("plain command --flag"), "plain command --flag");
        assert_eq!(
            clip("caf\u{E9} \u{00A0}x \u{4E2D}\u{6587} \u{1F600}"),
            "caf\u{E9} \u{00A0}x \u{4E2D}\u{6587} \u{1F600}",
            "letters, symbols and other spaces stay"
        );
        // A 2,500-character command is shown whole and unflagged (the old
        // 2,000 cut is gone); a command past the limit is cut and flagged,
        // and neither changes what the request may do (A6, ruling D5).
        let (c, clipped) = clip_command(&"x".repeat(2500));
        assert_eq!((c.chars().count(), clipped), (2500, false));
        let (c, clipped) = clip_command(&"y".repeat(COMMAND_CLIP + 500));
        assert_eq!((c.chars().count(), clipped), (COMMAND_CLIP, true));
        let (c, clipped) = clip_command(&"z".repeat(COMMAND_CLIP));
        assert_eq!((c.chars().count(), clipped), (COMMAND_CLIP, false));
        let (c, clipped) = clip_command(&"w".repeat(20_000));
        assert_eq!(
            (c.chars().count(), clipped),
            (COMMAND_CLIP, true),
            "a 20,000-character command is cut and flagged"
        );
    }

    /// The window payload carries the flag with the caller, so the card can
    /// say the command is cut; the caller is otherwise the same request.
    #[test]
    fn a_clipped_command_is_flagged_in_the_payload() {
        use super::{clip_command, CallerInfo, COMMAND_CLIP};
        let (command, clipped) = clip_command(&"x".repeat(20_000));
        let info = CallerInfo {
            command,
            clipped,
            verified: true,
            ..Default::default()
        };
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["clipped"], serde_json::Value::Bool(true));
        // The flag is a label for the card only: the nod path reads
        // nothing from it, so consent proceeds on a cut command as on any.
        assert!(info.verified && info.kill_pid == 0);
        assert_eq!(
            json["command"].as_str().unwrap().chars().count(),
            COMMAND_CLIP
        );
        let plain = CallerInfo {
            command: "sudo ls".into(),
            verified: true,
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(&plain).unwrap()["clipped"],
            serde_json::Value::Bool(false)
        );
    }

    /// The token answers only its own request, only while that request's
    /// window lives, and a wrong token changes nothing in the record (H9).
    #[test]
    fn a_token_matches_only_itself_and_only_while_the_request_lives() {
        use super::{Answer, Dialog};
        let user = "window-text-test-user";
        let cfg = crate::config::Config::default();
        let st = super::test_state();
        assert!(
            !st.token_matches(user, Some("anything")),
            "no request, no match"
        );
        assert!(
            Dialog::new(&cfg, user, st).is_err(),
            "no live request, no window"
        );
        let _turn = st.test_live(1000, user);
        assert!(
            !st.token_matches(user, Some("anything")),
            "live but no window yet: no token"
        );
        let d = Dialog::new(&cfg, user, st).unwrap();
        let tok = d.token().to_string();
        assert_eq!(tok.len(), 32);
        assert!(st.token_matches(user, Some(&tok)));
        assert!(!st.token_matches(user, Some(&tok[..31])));
        assert!(!st.token_matches(user, Some(&format!("{}0", tok))));
        assert!(!st.token_matches(user, None));
        assert!(!st.token_matches("someone-else", Some(&tok)));
        assert_eq!(
            st.answer(user, Some("wrong"), Answer::Dismiss),
            Err("no pending request")
        );
        assert!(!st.answered(user), "a wrong-token answer changes nothing");
        assert!(!st.ack(user, Some("wrong")));
        assert!(!d.acknowledged());
        assert_eq!(st.answer(user, Some(&tok), Answer::Dismiss), Ok(()));
        assert!(st.answered(user));
        assert!(matches!(st.poll(user), Some(Answer::Dismiss)));
        drop(d);
        assert!(
            !st.token_matches(user, Some(&tok)),
            "the token dies with the request"
        );
    }
}

#[cfg(test)]
mod polkit_context_tests {
    use super::*;

    fn ctx(_uid: u32, agent: Option<AgentPeer>, action: &str) -> PolkitContext {
        PolkitContext {
            action: action.into(),
            message: "m".into(),
            agent,
            caller_pid: None,
            subject_pid: None,
            at: Instant::now(),
        }
    }

    /// A context serves only a request whose helper was connected by the
    /// peer that sent it: not the oldest for the uid, and never one from a
    /// process that merely runs as the user (A8, A5).
    #[test]
    fn a_context_is_matched_to_the_agent_that_sent_it_not_by_arrival_order() {
        let planted = AgentPeer { pid: 900, id: 9000 };
        let shell = AgentPeer { pid: 500, id: 5000 };
        {
            let mut m = CONTEXTS.lock().unwrap();
            let q = m.entry(4242).or_default();
            q.clear();
            q.push_back(ctx(4242, Some(planted), "org.example.benign"));
            q.push_back(ctx(4242, None, "org.example.anonymous"));
            q.push_back(ctx(4242, Some(shell), "org.example.real"));
        }
        assert_eq!(
            take_polkit_context(shell).map(|c| c.action).as_deref(),
            Some("org.example.real")
        );
        // A second request from the same agent finds nothing of its own,
        // and does not fall back to what another peer left behind.
        let t = Instant::now();
        assert!(take_polkit_context(shell).is_none());
        assert!(t.elapsed() >= Duration::from_millis(1400));
        let left: Vec<String> = CONTEXTS
            .lock()
            .unwrap()
            .get(&4242)
            .unwrap()
            .iter()
            .map(|c| c.action.clone())
            .collect();
        assert_eq!(
            left,
            vec![
                "org.example.benign".to_string(),
                "org.example.anonymous".to_string()
            ]
        );
        CONTEXTS.lock().unwrap().remove(&4242);
    }

    /// Without polkitd's pids nothing on the polkit lane is verified,
    /// whatever processes of the user's are named `pkexec`, and there is
    /// nothing to kill.
    #[test]
    fn a_polkit_request_without_polkitds_pids_is_never_presented_as_verified() {
        let agent = AgentPeer { pid: 500, id: 5000 };
        let info = CallerInfo::polkit(
            600,
            1000,
            Some(agent),
            "quickshell",
            Some(ctx(1000, Some(agent), "org.freedesktop.policykit.exec")),
        );
        assert!(!info.verified);
        assert_eq!(info.kill_pid, 0);
        assert_eq!(info.requester, None);
        assert_eq!(info.via, "polkit");
        assert!(
            info.who.contains("agent quickshell (pid 500)"),
            "{}",
            info.who
        );
        assert!(
            info.command.ends_with("[org.freedesktop.policykit.exec]"),
            "{}",
            info.command
        );
        let info = CallerInfo::polkit(600, 1000, None, "", None);
        assert!(!info.verified && info.kill_pid == 0);
        assert!(info.command.contains("no description"), "{}", info.command);
    }

    /// With polkitd's caller pid the requester is read from /proc by the
    /// daemon: this test process stands in for pkexec.
    #[test]
    fn polkitds_caller_pid_names_a_verified_requester() {
        let me = std::process::id() as i32;
        let my_uid = nix::unistd::getuid().as_raw();
        let agent = AgentPeer { pid: 500, id: 5000 };
        let mut c = ctx(my_uid, Some(agent), "org.freedesktop.policykit.exec");
        c.caller_pid = Some(me);
        c.subject_pid = Some(me);
        let info = CallerInfo::polkit(600, my_uid, Some(agent), "quickshell", Some(c.clone()));
        assert!(info.verified, "{}", info.who);
        assert_eq!(info.kill_pid, me);
        assert_eq!(info.requester, Some(me));
        assert!(info.command.contains("faceauth"), "{}", info.command);
        assert!(
            info.who.contains(&format!("(pid {})", me))
                && info.who.contains("via polkit, agent quickshell (pid 500)"),
            "{}",
            info.who
        );
        // A requester of another uid is not the user's and is not shown as verified.
        let info = CallerInfo::polkit(
            600,
            my_uid.wrapping_add(1),
            Some(agent),
            "quickshell",
            Some(c.clone()),
        );
        assert!(!info.verified && info.requester.is_none(), "{}", info.who);
        // A requester that is gone: unverified.
        c.caller_pid = Some(i32::MAX - 1);
        let info = CallerInfo::polkit(600, my_uid, Some(agent), "quickshell", Some(c));
        assert!(!info.verified && info.kill_pid == 0, "{}", info.who);
    }

    #[test]
    fn the_requester_is_the_caller_unless_a_root_service_asked_for_a_subject() {
        let root_service = |p: i32| p == 77;
        assert_eq!(
            polkit_requester(Some(42), Some(42), &root_service),
            Some(42)
        );
        assert_eq!(
            polkit_requester(Some(42), Some(43), &root_service),
            Some(42),
            "a plain caller's subject claim is not followed"
        );
        assert_eq!(
            polkit_requester(Some(77), Some(43), &root_service),
            Some(43),
            "a root service vouches for its subject"
        );
        assert_eq!(polkit_requester(Some(77), None, &root_service), Some(77));
        assert_eq!(
            polkit_requester(None, Some(43), &root_service),
            None,
            "no caller, nothing to trust"
        );
        assert_eq!(polkit_requester(Some(0), Some(43), &root_service), None);
    }
}

#[cfg(test)]
mod window_ack_tests {
    use super::*;

    /// The acknowledgement is accepted only with the live request's token,
    /// and a new request forgets the last one's.
    #[test]
    fn an_acknowledgement_needs_the_live_token_and_is_per_request() {
        let cfg = Config::default();
        let user = "faceauth-ack-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let mut d = Dialog::new(&cfg, user, st).unwrap();
        assert!(!d.acknowledged());
        assert!(!st.ack(user, None));
        assert!(!st.ack(user, Some("not-the-token")));
        assert!(!d.acknowledged());
        let token = d.token().to_string();
        assert!(st.ack(user, Some(&token)));
        assert!(d.acknowledged());
        assert_eq!(
            d.dwell_left(Instant::now()),
            ACK_DWELL,
            "no dwell has run before the show records the acknowledgement"
        );
        // The acknowledgement wakes a show waiting for it through the
        // condition variable, not a poll.
        d.reset_ack();
        assert!(!d.acknowledged());
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            st.ack(user, Some(&token))
        });
        let started = Instant::now();
        assert!(st.wait_ack(user, d.token(), Instant::now() + Duration::from_secs(2)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(t.join().unwrap());
        let old = d.token().to_string();
        drop(d);
        let d2 = Dialog::new(&cfg, user, st).unwrap();
        assert!(!d2.acknowledged(), "a new request starts unacknowledged");
        assert!(!st.ack(user, Some(&old)), "the old token no longer answers");
        assert!(!st.wait_ack(user, d2.token(), Instant::now() + Duration::from_millis(50)));
    }

    #[test]
    fn the_dwell_runs_from_the_acknowledgement() {
        let cfg = Config::default();
        let user = "faceauth-dwell-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let mut d = Dialog::new(&cfg, user, st).unwrap();
        let at = Instant::now();
        d.acked_at = Some(at);
        assert_eq!(d.dwell_left(at), ACK_DWELL);
        assert_eq!(
            d.dwell_left(at + Duration::from_millis(1000)),
            Duration::from_millis(500)
        );
        assert_eq!(d.dwell_left(at + Duration::from_secs(5)), Duration::ZERO);
    }
}

#[cfg(test)]
mod dwell_tests {
    use super::*;

    /// D4: the acknowledgement lands during the scan, so a dwell measured
    /// from it alone is spent before the nod card is up. The dwell runs
    /// from the nod show instead, and whole again on every re-show.
    #[test]
    fn the_dwell_runs_from_the_nod_show_not_the_acknowledgement() {
        let cfg = Config::default();
        let user = "faceauth-nod-dwell-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let mut d = Dialog::new(&cfg, user, st).unwrap();
        let acked = Instant::now();
        d.acked_at = Some(acked);
        // The earliest the hook can run: the settle, the pattern settle
        // and eight frames of phase lock at 30 fps, then the nod show.
        let hook_at = acked + Duration::from_millis(1200 + 150 + 270);
        assert_eq!(
            d.dwell_left(hook_at),
            Duration::ZERO,
            "from the ack alone the dwell has lapsed"
        );
        d.nod_shown_at = Some(hook_at);
        assert_eq!(
            d.dwell_left(hook_at),
            ACK_DWELL,
            "at the hook the whole dwell is left"
        );
        assert_eq!(
            d.dwell_left(hook_at + Duration::from_millis(1000)),
            Duration::from_millis(500)
        );
        assert_eq!(
            d.dwell_left(hook_at + Duration::from_secs(5)),
            Duration::ZERO
        );
        // A re-show later (a rider armed, a re-arm) starts it over.
        let again = hook_at + Duration::from_secs(40);
        d.nod_shown_at = Some(again);
        assert_eq!(d.dwell_left(again), ACK_DWELL);
        // An acknowledgement newer than the nod show wins, as before.
        d.acked_at = Some(again + Duration::from_secs(1));
        assert_eq!(d.dwell_left(again + Duration::from_secs(1)), ACK_DWELL);
    }

    /// A head already nodding when the nod window opens: 0.3 s near rest
    /// (the settle), then two nods at mesh scale (15 degrees, 0.27 s legs),
    /// the box riding each leg by 0.08 face widths; `still_first` puts a
    /// full still second in front instead.
    fn nodding(still_first: bool) -> Option<f32> {
        let mut det = NodDetector::mesh(NodDetector::MESH_MIN_DEG);
        assert_eq!(
            det.inner.prior_still, 0.0,
            "the nod window credits no still second"
        );
        let fps = 30.0f32;
        let mut t = 0.0f32;
        let (w, cx, cy0) = (90.0f32, 250.0f32, 340.0f32);
        let mut frames: Vec<(f32, f32)> = Vec::new();
        for _ in 0..(if still_first { 45 } else { 9 }) {
            frames.push((0.0, cy0));
        }
        let leg = 8usize;
        for _ in 0..2 {
            for k in 1..=leg {
                let f = k as f32 / leg as f32;
                frames.push((15.0 * f, cy0 + 7.0 * f));
            }
            for k in 1..=leg {
                let f = k as f32 / leg as f32;
                frames.push((15.0 * (1.0 - f), cy0 + 7.0 * (1.0 - f)));
            }
        }
        for _ in 0..30 {
            frames.push((0.0, cy0));
        }
        for (p, cy) in frames {
            if det.push_full(p, Some(0.0), t, Some((w, cx, cy))) {
                return Some(t);
            }
            t += 1.0 / fps;
        }
        None
    }

    /// D4: a nod under way when the window opens does not count; the same
    /// nod from a head seen still for a second does.
    #[test]
    fn a_nod_under_way_at_the_window_start_does_not_count() {
        assert!(
            nodding(false).is_none(),
            "a nod already in motion at the card is not a nod at it"
        );
        assert!(
            nodding(true).is_some(),
            "the same nod after an observed still second counts"
        );
    }
}

#[cfg(test)]
mod shell_answer_tests {
    use super::*;

    /// F2: the "unknown" a summon gets for a window the shell does not
    /// have is read by the daemon, not by a change to the shared command.
    #[test]
    fn a_summon_answered_unknown_is_an_error_and_nothing_else_is() {
        let summon = ["shell", "summon", "omarchy.faceauth", "{}"];
        assert!(shell_answer(&summon, true, b"unknown\n").is_err());
        assert!(shell_answer(&summon, true, b"  unknown  ").is_err());
        assert!(shell_answer(&summon, true, b"ok\n").is_ok());
        assert!(shell_answer(&summon, true, b"").is_ok());
        assert!(
            shell_answer(&summon, false, b"ok\n").is_err(),
            "a failed exit is an error whatever was said"
        );
        let hide = ["shell", "hide", "omarchy.faceauth"];
        assert!(
            shell_answer(&hide, true, b"unknown\n").is_ok(),
            "only a summon has to have shown something"
        );
        assert!(shell_answer(&["shell", "ping"], true, b"unknown").is_ok());
    }
}

#[cfg(test)]
mod payload_size_tests {
    use super::*;

    /// D5: the payload carries what the card reads and not the raw command
    /// line, so a command of any length keeps its card. The summon is one
    /// argv string, and the kernel refuses one over 131072 bytes.
    #[test]
    fn the_payload_stays_small_for_any_command() {
        for n in [16_000usize, 100_000, 115_000, 400_000] {
            let raw: String = "sudo cp ".to_string() + &"a/b ".repeat(n / 4);
            let (command, clipped) = clip_command(&raw);
            let caller = CallerInfo {
                pid: 1234,
                exe: "/usr/bin/sudo".into(),
                cmdline: raw.clone(),
                command,
                verified: true,
                clipped,
                who: "sudo (pid 1234)  from  bash (1200) <- foot (1100)".into(),
                parents: "bash (1200) <- foot (1100)".into(),
                kill_pid: 1234,
                via: "sudo".into(),
                requester: Some(1234),
            };
            let json = serde_json::to_string(&Payload {
                state: "scanning",
                message: "Look at the camera.",
                caller: &caller,
                token: "00112233445566778899aabbccddeeff",
                waiting: false,
                passwordless_minutes: None,
                face_present: false,
            })
            .unwrap();
            assert!(
                json.len() < 65_536,
                "cmdline {} bytes: payload {} bytes",
                raw.len(),
                json.len()
            );
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            for read in ["who", "command", "clipped", "verified", "kill_pid", "via"] {
                assert!(
                    v["caller"].get(read).is_some(),
                    "the card reads caller.{}",
                    read
                );
            }
            for unread in ["cmdline", "exe", "pid", "parents", "requester"] {
                assert!(
                    v["caller"].get(unread).is_none(),
                    "caller.{} is not the card's",
                    unread
                );
            }
        }
    }
}

#[cfg(test)]
mod passwordless_tests {
    use super::*;

    /// The rider belongs to one request: it is armed only with that
    /// request's token, on a sudo lane, while the enrolled face is in the
    /// nod window; it is honoured only once the card has been shown it;
    /// and it is gone when that request's Dialog drops.
    #[test]
    fn a_rider_is_bound_to_its_request_and_dies_with_it() {
        let cfg = Config::default();
        let user = "faceauth-passwordless-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let d = Dialog::new(&cfg, user, st).unwrap();
        let token = d.token().to_string();
        assert_eq!(
            st.rider_state(user),
            Some((None, false)),
            "a request begins with an empty rider"
        );
        assert_eq!(
            st.arm_passwordless(user, &token, 15),
            Err("no pending request"),
            "nothing to arm before the card has been shown"
        );
        // The first show starts the record, on a polkit lane here.
        st.rider_for_payload(user, &token, false, true);
        st.set_face_present(user, true);
        assert_eq!(
            st.arm_passwordless(user, &token, 15),
            Err("only a sudo request can carry it")
        );
        // The same request on the sudo lane, with the face away.
        st.rider_for_payload(user, &token, true, true);
        st.set_face_present(user, false);
        assert_eq!(
            st.arm_passwordless(user, &token, 15),
            Err("look at the camera first")
        );
        assert!(st.set_face_present(user, true));
        assert_eq!(
            st.arm_passwordless(user, &token, 0),
            Err("minutes out of range")
        );
        assert_eq!(
            st.arm_passwordless(user, &token, PASSWORDLESS_MAX_MINUTES + 1),
            Err("minutes out of range")
        );
        assert_eq!(
            st.arm_passwordless(user, "not-the-token", 15),
            Err("no pending request"),
            "another token arms nothing"
        );
        assert_eq!(st.arm_passwordless(user, &token, 15), Ok(()));
        assert!(
            st.rider_unshown(user),
            "the nod window must re-show the card"
        );
        assert_eq!(
            st.rider_for_payload(user, &token, true, false),
            (None, true),
            "a payload that waits for no acknowledgement does not carry an unshown rider"
        );
        assert!(st.rider_unshown(user), "and it stays unshown");
        assert_eq!(
            st.take_passwordless(user, &token),
            None,
            "an arm the card has not been shown is not honoured"
        );
        assert_eq!(st.arm_passwordless(user, &token, 15), Ok(()));
        assert_eq!(
            st.rider_for_payload(user, &token, true, true),
            (Some(15), true)
        );
        assert!(!st.rider_unshown(user));
        assert_eq!(
            st.take_passwordless(user, "another-request"),
            None,
            "a Match under another token enables nothing"
        );
        assert_eq!(
            st.rider_state(user),
            Some((Some(15), true)),
            "and another token does not touch the rider"
        );
        assert_eq!(st.take_passwordless(user, &token), Some(15));
        assert_eq!(st.take_passwordless(user, &token), None, "taken once");
        assert_eq!(st.arm_passwordless(user, &token, 45), Ok(()));
        st.rider_for_payload(user, &token, true, true);
        drop(d);
        assert_eq!(
            st.rider_state(user),
            None,
            "the rider goes when the request's Dialog drops, whichever way it ended"
        );
        // A new request starts clean.
        let d2 = Dialog::new(&cfg, user, st).unwrap();
        assert_eq!(st.rider_state(user), Some((None, false)));
        assert_eq!(
            st.arm_passwordless(user, &token, 15),
            Err("no pending request"),
            "the old request's token arms nothing on the new one"
        );
        drop(d2);
    }

    /// The face flag follows only a live record with a window, and the nod
    /// window's guard clears it when the window ends.
    #[test]
    fn the_face_flag_follows_the_live_record_only() {
        let cfg = Config::default();
        let user = "faceauth-passwordless-face-test-user";
        let st = test_state();
        assert!(
            !st.set_face_present(user, true),
            "no record, nothing to set"
        );
        assert_eq!(st.rider_state(user), None);
        let _turn = st.test_live(1000, user);
        assert!(
            !st.set_face_present(user, true),
            "live without a window, nothing to set"
        );
        let d = Dialog::new(&cfg, user, st).unwrap();
        st.rider_for_payload(user, d.token(), true, true);
        assert!(st.set_face_present(user, true));
        assert!(!st.set_face_present(user, true), "unchanged");
        assert!(st.set_face_present(user, false));
        assert!(
            !st.set_face_present("someone-else", true),
            "another user's name reaches nothing"
        );
        drop(d);
        assert_eq!(st.rider_state(user), None);
    }

    /// An arm after the acknowledgement resets it: the next show waits for
    /// a fresh one and the dwell runs whole from it.
    #[test]
    fn an_arm_after_the_ack_restarts_the_ack_and_the_dwell() {
        let cfg = Config::default();
        let user = "faceauth-passwordless-ack-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let mut d = Dialog::new(&cfg, user, st).unwrap();
        let token = d.token().to_string();
        assert!(st.ack(user, Some(&token)));
        let at = Instant::now() - Duration::from_secs(5);
        d.acked_at = Some(at);
        assert_eq!(d.dwell_left(Instant::now()), Duration::ZERO);
        assert!(d.acknowledged());
        d.reset_ack();
        assert_eq!(d.acked_at(), None);
        assert!(
            !d.acknowledged(),
            "the old acknowledgement no longer counts"
        );
        assert_eq!(
            d.dwell_left(Instant::now()),
            ACK_DWELL,
            "the next nod window starts with a full dwell"
        );
        assert!(
            st.ack(user, Some(&token)),
            "the card acknowledges the re-shown request"
        );
        assert!(d.acknowledged());
    }

    /// The payload carries the armed minutes and the face flag, so the
    /// card draws its rider row from the daemon and not from itself.
    #[test]
    fn the_payload_carries_the_rider_and_the_face() {
        let cfg = Config::default();
        let user = "faceauth-passwordless-payload-test-user";
        let caller = CallerInfo {
            via: "sudo".into(),
            ..Default::default()
        };
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let d = Dialog::new(&cfg, user, st).unwrap();
        let tok = d.token();
        st.rider_for_payload(user, tok, true, true);
        st.set_face_present(user, true);
        assert_eq!(st.arm_passwordless(user, tok, 15), Ok(()));
        let (passwordless_minutes, face_present) = st.rider_for_payload(user, tok, true, true);
        let json = serde_json::to_string(&Payload {
            state: "nod",
            message: "",
            caller: &caller,
            token: tok,
            waiting: false,
            passwordless_minutes,
            face_present,
        })
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["passwordless_minutes"], 15);
        assert_eq!(v["face_present"], true);
        st.set_face_present(user, false);
        let (m, f) = st.rider_for_payload(user, tok, true, true);
        assert_eq!((m, f), (Some(15), false));
        let old = tok.to_string();
        drop(d);
        let d2 = Dialog::new(&cfg, user, st).unwrap();
        let (m, f) = st.rider_for_payload(user, d2.token(), true, true);
        assert_eq!((m, f), (None, false), "a fresh record carries nothing");
        assert_eq!(
            st.rider_for_payload(user, &old, true, true),
            (None, false),
            "the old token reaches nothing"
        );
    }

    /// Re-arming with a timer that will not start leaves no rule behind:
    /// the earlier spell's rule goes with its stopped timer.
    #[test]
    fn a_failed_re_arm_removes_the_earlier_rule() {
        let dir =
            std::env::temp_dir().join(format!("faceauth-sudoers-rearm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let calls = std::cell::Cell::new(0u32);
        let arm = |_: &[String]| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                Ok(())
            } else {
                Err(anyhow!(
                    "Unit omarchy-nopasswd-expire-mellis.timer already exists"
                ))
            }
        };
        let file = enable_passwordless(&dir, "mellis", 20, &arm).unwrap();
        assert!(file.exists(), "the first spell is in place with its timer");
        let err = enable_passwordless(&dir, "mellis", 40, &arm).unwrap_err();
        assert!(err.to_string().contains("no rule is in place"), "{:#}", err);
        assert!(
            !file.exists(),
            "the earlier rule does not outlive its timer when the re-arm fails"
        );
        assert_eq!(calls.get(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The rule Omarchy's own command writes, root-only, and the timer it
    /// arms; a timer that cannot be armed takes the rule with it.
    #[test]
    fn the_rule_is_written_root_only_with_its_expiry_timer() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("faceauth-sudoers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let seen = std::sync::Mutex::new(Vec::<String>::new());
        let arm = |args: &[String]| {
            seen.lock().unwrap().extend(args.iter().cloned());
            Ok(())
        };
        let file = enable_passwordless(&dir, "mellis", 20, &arm).unwrap();
        assert_eq!(file, dir.join("99-omarchy-nopasswd-mellis"));
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "mellis ALL=(ALL) NOPASSWD: ALL\n"
        );
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o440
        );
        let args = seen.lock().unwrap().join(" ");
        assert!(
            args.contains("--on-active 20m")
                && args.contains("--unit=omarchy-nopasswd-expire-mellis")
                && args.ends_with(&format!("/usr/bin/rm -f -- {}", file.display())),
            "{}",
            args
        );
        // A user name that could break out of the rule is refused.
        assert!(enable_passwordless(&dir, "evil ALL=(ALL)", 5, &arm).is_err());
        // No timer, no rule: the timer is armed before the rule is written.
        let fail = |_: &[String]| Err(anyhow!("no systemd"));
        assert!(enable_passwordless(&dir, "bob", 5, &fail).is_err());
        assert!(!dir.join("99-omarchy-nopasswd-bob").exists());
        let mut c = CallerInfo {
            command: "sudo omarchy-sudo-passwordless".into(),
            ..Default::default()
        };
        assert!(is_passwordless_command(&c));
        c.command = "sudo /usr/bin/omarchy-sudo-passwordless 30".into();
        assert!(is_passwordless_command(&c));
        c.command = "sudo pacman -Syu".into();
        assert!(!is_passwordless_command(&c));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod mesh_battery {
    use super::*;

    /// The rounds of 2026-09-24 on the mesh: both nod rounds read as two
    /// nods, both shake rounds as two shakes, and the eight everyday
    /// rounds (glances each way, the keyboard, reading, talking, leaning)
    /// read as nothing, at the default floors.
    #[test]
    fn mesh_battery_holds() {
        let dir = format!("{}/traces/v2", env!("CARGO_MANIFEST_DIR"));
        let floors = (NodDetector::MESH_MIN_DEG, ShakeDetector::MESH_MIN_DEG);
        let mut bad = Vec::new();
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "txt").unwrap_or(false))
            .collect();
        files.sort();
        assert!(files.len() >= 12, "the twelve rounds are in {}", dir);
        for p in files {
            let name = p.file_stem().unwrap().to_string_lossy().to_string();
            let frames = parse_round(&std::fs::read_to_string(&p).unwrap());
            let (nods, shakes) = replay_round(&frames, floors);
            eprintln!(
                "mesh battery {:16} {} frames: {} nods, {} shakes",
                name,
                frames.len(),
                nods,
                shakes
            );
            let want_nod = name.starts_with("nod");
            let want_shake = name.starts_with("shake");
            if want_nod && nods < 2 {
                bad.push(format!("{}: {} nods, wanted 2", name, nods));
            }
            if want_shake && shakes < 2 {
                bad.push(format!("{}: {} shakes, wanted 2", name, shakes));
            }
            if !want_nod && nods > 0 {
                bad.push(format!("{}: {} nods from an everyday movement", name, nods));
            }
            if !want_shake && shakes > 0 {
                bad.push(format!(
                    "{}: {} shakes from an everyday movement",
                    name, shakes
                ));
            }
        }
        assert!(bad.is_empty(), "{:#?}", bad);
    }

    /// The floors the walk-through derives from a person's own rounds keep
    /// that person's gestures (round-4 C2). Derived the way the walk-through
    /// does it, from where each reference round stops reading, the floors
    /// still read both nods and both shakes as two, and the eight everyday
    /// rounds as nothing. The swing rule they replace lost shake-1.
    #[test]
    fn the_derived_floors_keep_the_reference_users_own_gestures() {
        let dir = format!("{}/traces/v2", env!("CARGO_MANIFEST_DIR"));
        let read =
            |n: &str| parse_round(&std::fs::read_to_string(format!("{}/{}.txt", dir, n)).unwrap());
        let mut g = crate::store::GestureCal::default();
        for n in ["nod-1", "nod-2"] {
            let r = reads_to_deg(&read(n), true);
            eprintln!("derived floors: {} reads up to {:?} degrees", n, r);
            g.nod_reads_to_deg
                .push(r.expect("the reference nod reads at the minimum"));
        }
        for n in ["shake-1", "shake-2"] {
            let r = reads_to_deg(&read(n), false);
            eprintln!("derived floors: {} reads up to {:?} degrees", n, r);
            g.shake_reads_to_deg
                .push(r.expect("the reference shake reads at the minimum"));
        }
        let floors = g.floors_deg(NodDetector::MESH_MIN_DEG, ShakeDetector::MESH_MIN_DEG);
        // What 0.4 of the larger swing gave the same rounds (13.88, 22.72).
        let swing_rule = (13.88, 22.72);
        eprintln!(
            "derived floors: nod {:.2} shake {:.2} (the swing rule gave nod {} shake {})",
            floors.0, floors.1, swing_rule.0, swing_rule.1
        );
        assert!(
            floors.0 > NodDetector::MESH_MIN_DEG && floors.1 > ShakeDetector::MESH_MIN_DEG,
            "the derivation raises both floors off the minimum for this person: {:?}",
            floors
        );
        let mut bad = Vec::new();
        for n in [
            "nod-1",
            "nod-2",
            "shake-1",
            "shake-2",
            "glance-left-1",
            "glance-left-2",
            "glance-right-1",
            "glance-right-2",
            "keyboard-1",
            "lean-1",
            "read-1",
            "talk-1",
        ] {
            let f = read(n);
            let at_derived = replay_round(&f, floors);
            let at_swing = replay_round(&f, swing_rule);
            eprintln!(
                "derived floors: {:15} derived -> {} nods {} shakes; swing rule -> {} nods {} shakes",
                n, at_derived.0, at_derived.1, at_swing.0, at_swing.1
            );
            let want = if n.starts_with("nod") {
                (2, 0)
            } else if n.starts_with("shake") {
                (0, 2)
            } else {
                (0, 0)
            };
            if at_derived.0 < want.0
                || at_derived.1 < want.1
                || (want == (0, 0) && at_derived != (0, 0))
            {
                bad.push(format!(
                    "{}: {:?} at the derived floors {:?}",
                    n, at_derived, floors
                ));
            }
        }
        assert!(bad.is_empty(), "{:#?}", bad);
        assert_eq!(
            replay_round(&read("shake-1"), swing_rule).1,
            0,
            "the swing rule's floors lose shake-1; if this reads, the margin can be revisited"
        );
    }
}

/// The attack cases on the mesh detectors (round-4 C4), which are the only
/// gesture path since round-4 C3 took the image-motion one out.
#[cfg(test)]
mod mesh_redteam {
    use super::*;

    const FPS: f32 = 28.0;
    const BOX: (f32, f32, f32) = (92.0, 252.0, 342.0);

    /// A pitch series: rest, then two nods of `amp` degrees at `leg`
    /// frames a leg, then rest.
    fn two_nods(amp: f32, leg: usize) -> Vec<f32> {
        let mut pitch: Vec<f32> = vec![0.0; 40];
        for _ in 0..2 {
            for k in 1..=leg {
                pitch.push(amp * k as f32 / leg as f32);
            }
            for k in 1..=leg {
                pitch.push(amp - amp * k as f32 / leg as f32);
            }
        }
        pitch.extend(std::iter::repeat_n(0.0, 30));
        pitch
    }

    /// Frames from a pitch series; the box rides the pitch when
    /// `box_moves`, as a head does, and stays put otherwise, as a detector
    /// fit that flips does.
    fn frames(pitch: &[f32], yaw: f32, box_moves: bool) -> Vec<RoundFrame> {
        pitch
            .iter()
            .enumerate()
            .map(|(i, &p)| {
                let cy = if box_moves { BOX.2 + p * 0.6 } else { BOX.2 };
                RoundFrame {
                    t: i as f32 / FPS,
                    yaw,
                    pitch: p,
                    roll: 0.0,
                    geom: (BOX.0, BOX.1, cy),
                }
            })
            .collect()
    }

    fn defaults() -> (f32, f32) {
        (NodDetector::MESH_MIN_DEG, ShakeDetector::MESH_MIN_DEG)
    }

    /// The red team's two cases in mesh form: a pitch that oscillates
    /// while the box stays frozen is not a head and reads as nothing; a
    /// waggled board carries its box and passes the detector by design,
    /// left to the strobed confirm.
    #[test]
    fn a_frozen_box_is_not_a_nod_and_a_waggled_board_is_left_to_the_confirm() {
        let pitch = two_nods(15.0, 8);
        let frozen = replay_round(&frames(&pitch, 0.0, false), defaults());
        let waggled = replay_round(&frames(&pitch, 0.0, true), defaults());
        assert_eq!(frozen, (0, 0), "a frozen box read as a gesture");
        assert!(
            waggled.0 >= 2,
            "the waggled board is meant to pass the detector (the confirm refuses it); it read {} nods",
            waggled.0
        );
    }

    /// The frozen box is refused by the box-motion rule and nothing else:
    /// with `co_motion` off the same frames read as nods. The rule is
    /// what carries the case, so it must stay on in `NodDetector::mesh`.
    #[test]
    fn the_box_motion_rule_is_what_refuses_the_frozen_box() {
        let pitch = two_nods(15.0, 8);
        let mut det = NodDetector::mesh(NodDetector::MESH_MIN_DEG);
        assert!(
            det.inner.co_motion.is_some(),
            "the live detector runs the rule"
        );
        det.inner.co_motion = None;
        det.inner.prior_still = 1.0;
        for f in frames(&pitch, 0.0, false) {
            det.push_full(f.pitch, Some(0.0), f.t, Some(f.geom));
        }
        assert!(
            det.nods >= 2,
            "with the rule off the frozen box read {} nods",
            det.nods
        );
    }

    /// A detector fit that flips: the pitch jumps to a plateau in one
    /// frame, holds, and jumps back, twice, over a box that does not move
    /// (the shape of the 2026-09-22 flicker recording that approved a
    /// request). Nothing, at any nod-sized plateau.
    #[test]
    fn a_plateau_flicker_over_a_still_box_is_not_a_nod() {
        for amp in [10.0f32, 15.0, 25.0] {
            for hold in [1usize, 2, 4, 6] {
                let mut pitch: Vec<f32> = vec![0.0; 40];
                for _ in 0..2 {
                    pitch.extend(std::iter::repeat_n(amp, hold));
                    pitch.extend(std::iter::repeat_n(0.0, hold));
                }
                pitch.extend(std::iter::repeat_n(0.0, 30));
                let got = replay_round(&frames(&pitch, 0.0, false), defaults());
                assert_eq!(
                    got,
                    (0, 0),
                    "a {} degree plateau held {} frames read as {:?}",
                    amp,
                    hold,
                    got
                );
            }
        }
    }

    /// A head held turned toward another screen nods the same way on the
    /// pitch axis, but it is not nodding at the card. The reference nods,
    /// re-centred so their mean yaw is the offset, still read as two held
    /// 30 degrees off (the gate is `YAW_FACING_DEG`, 34.29) and read as
    /// nothing from 36 degrees either way.
    #[test]
    fn a_nod_from_a_head_held_turned_does_not_count_on_the_mesh() {
        let dir = format!("{}/traces/v2", env!("CARGO_MANIFEST_DIR"));
        let mut bad = Vec::new();
        for name in ["nod-1", "nod-2"] {
            let recorded =
                parse_round(&std::fs::read_to_string(format!("{}/{}.txt", dir, name)).unwrap());
            let mean = recorded.iter().map(|f| f.yaw).sum::<f32>() / recorded.len() as f32;
            let held_at = |off: f32| -> (usize, usize) {
                let turned: Vec<RoundFrame> = recorded
                    .iter()
                    .map(|f| RoundFrame {
                        yaw: f.yaw - mean + off,
                        ..f.clone()
                    })
                    .collect();
                replay_round(&turned, defaults())
            };
            let (n0, _) = replay_round(&recorded, defaults());
            if n0 < 2 {
                bad.push(format!("{} lost its nods as recorded: {}", name, n0));
            }
            for off in [30.0f32, -30.0] {
                let (n, _) = held_at(off);
                if n < 2 {
                    bad.push(format!(
                        "{} held {:+.0} degrees off (inside the gate): {} nods",
                        name, off, n
                    ));
                }
            }
            for off in [36.0f32, -36.0, 43.0, -43.0, 60.0, -60.0] {
                let (n, s) = held_at(off);
                if n != 0 {
                    bad.push(format!("{} held {:+.0} degrees off: {} nods", name, off, n));
                }
                if s != 0 {
                    bad.push(format!(
                        "{} held {:+.0} degrees off: {} shakes",
                        name, off, s
                    ));
                }
            }
        }
        assert!(bad.is_empty(), "{:#?}", bad);
    }

    /// The same synthetic nods made with the head turned: the facing gate
    /// refuses them, not the box rule, so the box is allowed to move.
    #[test]
    fn a_synthetic_nod_with_the_head_turned_does_not_count() {
        let pitch = two_nods(20.0, 8);
        assert!(replay_round(&frames(&pitch, 0.0, true), defaults()).0 >= 2);
        for yaw in [40.0f32, -40.0, 70.0] {
            let got = replay_round(&frames(&pitch, yaw, true), defaults());
            assert_eq!(got.0, 0, "nods at yaw {}: {:?}", yaw, got);
        }
    }
}
