//! The consent record: the request on screen, the requests queued behind
//! it, and the answer, token and rider each one carries. It is one static
//! behind one lock because the socket threads answer a request that the
//! attempt thread is waiting on.

use super::passwordless::PASSWORDLESS_MAX_MINUTES;
use anyhow::Result;
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
    pub(super) fn set_token(&self, user: &str, token: &str) -> bool {
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
    pub(super) fn clear_token(&self, user: &str, token: &str) {
        let mut q = self.lock();
        if let Some(l) = Self::live_with(&mut q, user, Some(token)) {
            l.token.clear();
            l.acked = false;
            l.rider = Rider::default();
        }
    }

    #[cfg(test)]
    pub(super) fn acknowledged(&self, user: &str, token: &str) -> bool {
        Self::live_with(&mut self.lock(), user, Some(token)).is_some_and(|l| l.acked)
    }

    /// Forget the window's acknowledgement: the next show waits for a
    /// fresh one.
    pub(super) fn reset_ack(&self, user: &str, token: &str) {
        if let Some(l) = Self::live_with(&mut self.lock(), user, Some(token)) {
            l.acked = false;
        }
    }

    /// Wait for the window's acknowledgement of `token` until `deadline`.
    pub(super) fn wait_ack(&self, user: &str, token: &str, deadline: Instant) -> bool {
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
    pub(super) fn rider_for_payload(
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

/// A consent state of a test's own, leaked so a `Dialog` can hold it.
#[cfg(test)]
pub(crate) fn test_state() -> &'static ConsentState {
    Box::leak(Box::new(ConsentState::new()))
}
