//! The lock screen's reserved channel (round 7, B). The lock screen opens
//! one long-lived connection on a socket of its own (`lock.sock`, beside
//! the daemon's) when it locks, and holds it for the whole lock. The
//! channel's places sit outside the connection limits (`limits.rs`), at
//! most `PER_UID` per account and `TOTAL` in all, so filling the daemon's
//! places can never keep the lock screen out. While a channel is open its
//! user is latched; the lock screen closes it gracefully with "unlocked"
//! at the unlock, and only that, the compositor's unlocked and the hold
//! release the latch. A channel that drops without the word (the lock
//! screen killed, or the daemon's thread gone) leaves the user latched
//! until a later channel closes gracefully.
//!
//! Wire: the lock screen sends `{"user":U,"lock_channel":true}`, the
//! daemon answers `{"result":"channel_open"}` (or an error, and closes);
//! later the lock screen sends `{"unlocked":true}`, the daemon answers
//! `{"result":"noted"}` and closes. Anything else, or the end, is a drop.

use crate::consent::ConsentState;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Mutex;
use std::time::Duration;

/// How often an open channel's thread looks whether the daemon expired it.
const EXPIRY_POLL: Duration = Duration::from_secs(1);

/// Reserved places one account may hold at once.
pub(crate) const PER_UID: usize = 2;
/// Reserved places in all: two for each of sixteen accounts. The unit's
/// TasksMax counts a thread for each (serve.rs's test).
pub(crate) const TOTAL: usize = 32;

/// The reserved places taken, by uid.
static OPEN: Mutex<Vec<(u32, usize)>> = Mutex::new(Vec::new());

/// One reserved place, given back when dropped.
struct Reserved(u32);

impl Drop for Reserved {
    fn drop(&mut self) {
        let mut open = OPEN.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((_, n)) = open.iter_mut().find(|(u, _)| *u == self.0) {
            *n = n.saturating_sub(1);
        }
        open.retain(|(_, n)| *n > 0);
    }
}

/// A reserved place for `uid`, unless they hold `PER_UID` already or the
/// daemon holds `TOTAL`; the reason when not.
fn reserve(uid: u32) -> Result<Reserved, &'static str> {
    let mut open = OPEN.lock().unwrap_or_else(|p| p.into_inner());
    if open.iter().map(|(_, n)| n).sum::<usize>() >= TOTAL {
        return Err("every reserved place is taken");
    }
    match open.iter_mut().find(|(u, _)| *u == uid) {
        Some((_, n)) if *n >= PER_UID => Err("this account holds two channels already"),
        Some((_, n)) => {
            *n += 1;
            Ok(Reserved(uid))
        }
        None => {
            open.push((uid, 1));
            Ok(Reserved(uid))
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Open {
    user: String,
    lock_channel: bool,
}

/// The channel's accept loop, on a thread of its own: each connection
/// from a user peer gets a reserved place, or a refusal, at once.
pub(super) fn serve_channels(listener: UnixListener, state: &'static ConsentState) {
    for conn in listener.incoming() {
        let Ok(stream) = conn else {
            continue;
        };
        let uid = nix::sys::socket::getsockopt(&stream, nix::sys::socket::sockopt::PeerCredentials)
            .map(|c| c.uid())
            .unwrap_or(0);
        let place = match reserve(uid) {
            Ok(p) => p,
            Err(why) => {
                log::warn!("lock channel from uid {} refused: {}", uid, why);
                let mut s = stream;
                let _ = super::reply(
                    &mut s,
                    &crate::auth::Outcome::Error {
                        message: why.into(),
                    },
                );
                continue;
            }
        };
        let spawned = std::thread::Builder::new()
            .name("lock-channel".into())
            .spawn(move || {
                let _place = place;
                run_channel(stream, uid, state, &|name| super::user_uid(name));
            });
        if let Err(e) = spawned {
            log::warn!("cannot start a lock channel thread: {}", e);
        }
    }
}

/// How a channel ended.
#[derive(Debug, PartialEq)]
pub(crate) enum Ended {
    /// Refused before it opened.
    Refused(String),
    /// Closed with the lock screen's "unlocked".
    Unlocked,
    /// Dropped without it.
    Dropped,
    /// Expired by the daemon after a steady unlock (fix round 8): told so
    /// and closed, its reserved place freed.
    Expired,
}

/// One channel, from its opening line to its end. Only a user peer, for
/// its own name, opens one (`uid_of` names the user's uid).
pub(crate) fn run_channel(
    stream: UnixStream,
    peer_uid: u32,
    state: &ConsentState,
    uid_of: &dyn Fn(&str) -> Option<u32>,
) -> Ended {
    let refuse = |mut s: &UnixStream, why: &str| {
        let _ =
            s.write_all(format!("{{\"result\":\"error\",\"message\":\"{}\"}}\n", why).as_bytes());
        Ended::Refused(why.into())
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    if reader.by_ref().take(4096).read_line(&mut line).is_err() {
        return refuse(&stream, "no opening line");
    }
    let open: Option<Open> = serde_json::from_str(line.trim()).ok();
    let Some(Open {
        user,
        lock_channel: true,
    }) = open
    else {
        return refuse(&stream, "not a lock channel");
    };
    if peer_uid == 0 || uid_of(&user) != Some(peer_uid) {
        return refuse(&stream, "a lock channel is the user's own");
    }
    let id = state.channel_open(&user);
    log::info!("lock channel open for {}", user);
    if (&stream)
        .write_all(b"{\"result\":\"channel_open\"}\n")
        .is_err()
    {
        state.channel_end(&user, id, false);
        return Ended::Dropped;
    }
    // Held for the whole lock: no deadline on the next line, but a look
    // each second whether the daemon expired the channel (fix round 8).
    let _ = stream.set_read_timeout(Some(EXPIRY_POLL));
    line.clear();
    let read = loop {
        match reader.by_ref().take(4096).read_line(&mut line) {
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if state.channel_expired(id) {
                    state.channel_end(&user, id, false);
                    let _ = (&stream).write_all(b"{\"result\":\"expired\"}\n");
                    log::info!("lock channel for {} expired and closed", user);
                    return Ended::Expired;
                }
                if line.len() > 4096 {
                    break Ok(0);
                }
            }
            other => break other,
        }
    };
    let graceful = read.is_ok_and(|n| n > 0) && line.trim() == "{\"unlocked\":true}";
    state.channel_end(&user, id, graceful);
    if graceful {
        let _ = (&stream).write_all(b"{\"result\":\"noted\"}\n");
        log::info!("lock channel for {} closed with the unlock", user);
        Ended::Unlocked
    } else {
        log::warn!(
            "lock channel for {} dropped without the unlock; the user stays latched",
            user
        );
        Ended::Dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uid_of(name: &str) -> Option<u32> {
        (name == "chan-alice").then_some(1000)
    }

    /// Round 7 (B): the lock screen opens its channel for its own name and
    /// the user is latched while it is open; the graceful "unlocked" closes
    /// it, and anything else is a drop that leaves the latch.
    #[test]
    fn a_channel_latches_while_open_and_ends_gracefully_or_dropped() {
        let st: &'static ConsentState = Box::leak(Box::default());
        let (a, b) = UnixStream::pair().unwrap();
        let t = std::thread::spawn(move || run_channel(b, 1000, st, &uid_of));
        let mut a2 = a.try_clone().unwrap();
        a2.write_all(b"{\"user\":\"chan-alice\",\"lock_channel\":true}\n")
            .unwrap();
        let mut r = BufReader::new(a.try_clone().unwrap());
        let mut l = String::new();
        r.read_line(&mut l).unwrap();
        assert_eq!(l, "{\"result\":\"channel_open\"}\n");
        assert_eq!(st.channels_open("chan-alice"), 1);
        a2.write_all(b"{\"unlocked\":true}\n").unwrap();
        assert_eq!(t.join().unwrap(), Ended::Unlocked);
        l.clear();
        r.read_line(&mut l).unwrap();
        assert_eq!(l, "{\"result\":\"noted\"}\n");
        assert_eq!(st.channels_open("chan-alice"), 0);
        // Dropped: the lock screen killed.
        let (a, b) = UnixStream::pair().unwrap();
        let t = std::thread::spawn(move || run_channel(b, 1000, st, &uid_of));
        (&a).write_all(b"{\"user\":\"chan-alice\",\"lock_channel\":true}\n")
            .unwrap();
        let mut l = String::new();
        BufReader::new(&a).read_line(&mut l).unwrap();
        drop(a);
        assert_eq!(t.join().unwrap(), Ended::Dropped);
        assert!(
            st.unlock_holds("chan-alice"),
            "a drop leaves the user latched"
        );
    }

    /// Round 7 (B): a channel is the user's own: root, another user's name
    /// and a line that is not a channel's are refused, and latch nothing.
    #[test]
    fn a_channel_is_the_users_own() {
        let st: &'static ConsentState = Box::leak(Box::default());
        for (uid, line) in [
            (0, "{\"user\":\"chan-alice\",\"lock_channel\":true}\n"),
            (1001, "{\"user\":\"chan-alice\",\"lock_channel\":true}\n"),
            (1000, "{\"user\":\"chan-alice\",\"key_lane\":true}\n"),
            (1000, "{\"user\":\"chan-alice\",\"lock_channel\":false}\n"),
        ] {
            let (a, b) = UnixStream::pair().unwrap();
            (&a).write_all(line.as_bytes()).unwrap();
            assert!(
                matches!(run_channel(b, uid, st, &uid_of), Ended::Refused(_)),
                "{} {}",
                uid,
                line
            );
        }
        assert!(!st.unlock_holds("chan-alice"));
    }

    /// Round 7 (B): two reserved places per account, and a cap in all, so
    /// extra holders cannot grow the daemon without bound; places come
    /// back when channels end.
    #[test]
    fn two_reserved_places_per_account() {
        let uid = 4_000_123;
        let a = reserve(uid).unwrap();
        let b = reserve(uid).unwrap();
        assert!(reserve(uid).is_err(), "a third is refused");
        assert!(reserve(uid + 1).is_ok(), "another account still gets one");
        drop(a);
        let c = reserve(uid).unwrap();
        drop((b, c));
        let held: Vec<Reserved> = (0..TOTAL as u32)
            .filter_map(|i| reserve(5_000_000 + i).ok())
            .collect();
        assert!(reserve(6_000_000).is_err(), "the cap in all");
        drop(held);
    }

    /// Fix round 8 (both reviewers): a channel the daemon expired is told
    /// so and closed, which frees its reserved place, and its end is no
    /// drop.
    #[test]
    fn an_expired_channel_is_closed_and_is_no_drop() {
        use crate::lockgate::{Desktop, LockState};
        let st: &'static ConsentState = Box::leak(Box::default());
        st.set_key_unlock_hold(Duration::from_millis(10));
        let (a, b) = UnixStream::pair().unwrap();
        let t = std::thread::spawn(move || run_channel(b, 1000, st, &uid_of));
        (&a).write_all(b"{\"user\":\"chan-alice\",\"lock_channel\":true}\n")
            .unwrap();
        let mut r = BufReader::new(a.try_clone().unwrap());
        let mut l = String::new();
        r.read_line(&mut l).unwrap();
        assert_eq!(st.channels_open("chan-alice"), 1);
        let _ = st.judge("chan-alice", LockState::Unlocked, Desktop::Some);
        st.backdate_unlocked("chan-alice", crate::consent::CHANNEL_EXPIRES);
        let _ = st.judge("chan-alice", LockState::Unlocked, Desktop::Some);
        let t0 = std::time::Instant::now();
        assert_eq!(t.join().unwrap(), Ended::Expired);
        assert!(t0.elapsed() < Duration::from_secs(3), "{:?}", t0.elapsed());
        l.clear();
        r.read_line(&mut l).unwrap();
        assert_eq!(l, "{\"result\":\"expired\"}\n");
        std::thread::sleep(Duration::from_millis(20));
        let _ = st.judge("chan-alice", LockState::Unlocked, Desktop::Some);
        assert!(!st.unlock_holds("chan-alice"), "no drop: the hold ran out");
    }
}
