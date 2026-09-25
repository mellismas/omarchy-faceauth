//! The listener: a fixed number of connection places, a thread per
//! connection, and an idle thread that releases the recognition model when
//! nobody has used it for a while. A connection that finds no place is
//! refused at once, so a flood cannot queue behind the camera.

#[cfg(test)]
use super::acl::is_enrolled;
use super::acl::{apply_socket_acl, set_enrolled};
use super::handle::handle;
#[cfg(test)]
use super::handle::BUSY_WAIT;
#[cfg(test)]
use super::presence::presence_query;
use super::reply;
use crate::auth::{Authenticator, Outcome};
use anyhow::{Context, Result};
use std::os::unix::net::UnixListener;
#[cfg(test)]
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

/// Connections handled at once; the rest are refused immediately.
const MAX_CONNECTIONS: usize = 8;
/// How often the idle thread looks, and how long the recognition model may sit
/// unused before it is released.
const MODEL_IDLE_TICK: Duration = Duration::from_secs(60);
const MODEL_IDLE_RELEASE: Duration = Duration::from_secs(600);

static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// The daemon's config, for the presence query answered while the
/// authenticator is busy with another request (its mutex is held for a
/// whole consent round).
pub(super) static CFG: std::sync::OnceLock<crate::config::Config> = std::sync::OnceLock::new();

pub fn serve(auth: Arc<Mutex<Authenticator>>, socket: &Path) -> Result<()> {
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let _ = std::fs::remove_file(socket);
    let listener =
        UnixListener::bind(socket).with_context(|| format!("bind {}", socket.display()))?;
    // World-connectable; the peer-credential check below is the access control.
    {
        let users = auth
            .lock()
            .map(|a| a.store.enrolled_users())
            .unwrap_or_default();
        apply_socket_acl(socket, &users);
        set_enrolled(users);
    }
    if let Ok(a) = auth.lock() {
        let _ = CFG.set(a.cfg.clone());
    }
    // The recognition model is the daemon's one large allocation, about
    // 250 MB resident. After ten minutes without an embed it is dropped and
    // the pages handed back; the next attempt reloads it in under half a
    // second. The presence watch keeps it warm by using it, so a watched
    // user never pays the reload, and try_lock keeps this off any request's
    // critical path.
    {
        let auth = Arc::clone(&auth);
        std::thread::Builder::new()
            .name("model-idle".into())
            .spawn(move || loop {
                std::thread::sleep(MODEL_IDLE_TICK);
                if let Ok(mut a) = auth.try_lock() {
                    if a.pipeline.embedder.is_loaded()
                        && a.pipeline.embedder.idle_for() > MODEL_IDLE_RELEASE
                    {
                        a.pipeline.embedder.release();
                    }
                }
            })
            .context("spawn the model idle thread")?;
    }
    log::info!("listening on {}", socket.display());
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                log::warn!("accept: {}", e);
                continue;
            }
        };
        if ACTIVE.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
            let mut s = stream;
            let _ = reply(
                &mut s,
                &Outcome::Error {
                    message: "busy".into(),
                },
            );
            continue;
        }
        let auth = Arc::clone(&auth);
        // The slot is given back on every exit, a panic's unwind included:
        // a handler that dies must not hold a slot for the daemon's life.
        // A consent request gives it back early, once admitted (see handle).
        let slot = Slot::new();
        let spawned = std::thread::Builder::new()
            .name("request".into())
            .spawn(move || {
                if let Err(e) = handle(stream, &auth, &slot) {
                    log::warn!("connection: {}", e);
                }
            });
        if let Err(e) = spawned {
            // The thread was not started, so the slot moved nowhere and was
            // dropped with the closure; the peer is told, not left hanging.
            log::warn!("cannot start a request thread: {}", e);
        }
    }
    Ok(())
}

/// One of the `MAX_CONNECTIONS` places, given back once: on drop, or
/// earlier by `release`. A consent request releases it once admitted: the
/// request lives as long as the user takes to answer, and the places are
/// for the short requests (answers, the window's acknowledgement, probes)
/// that must keep getting through meanwhile (B4).
pub(super) struct Slot {
    held: std::sync::atomic::AtomicBool,
}

impl Slot {
    fn new() -> Slot {
        Slot {
            held: std::sync::atomic::AtomicBool::new(true),
        }
    }

    pub(super) fn release(&self) {
        if self.held.swap(false, Ordering::SeqCst) {
            ACTIVE.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod queue_tests {
    use super::*;

    /// A slot is given back exactly once, whether released early or dropped.
    #[test]
    fn a_slot_is_given_back_once() {
        let before = ACTIVE.load(Ordering::SeqCst);
        ACTIVE.fetch_add(1, Ordering::SeqCst);
        let s = Slot::new();
        s.release();
        assert_eq!(ACTIVE.load(Ordering::SeqCst), before);
        drop(s);
        assert_eq!(
            ACTIVE.load(Ordering::SeqCst),
            before,
            "the drop after a release takes nothing more"
        );
        ACTIVE.fetch_add(1, Ordering::SeqCst);
        drop(Slot::new());
        assert_eq!(ACTIVE.load(Ordering::SeqCst), before);
    }

    /// The bar widget's presence poll is answered while the authenticator
    /// is held for the length of an enrolment walk-through (C5). The query
    /// takes no authenticator at all (its signature is the guarantee); this
    /// holds a lock for the walk-through's whole run on the calling thread
    /// and expects the reply, with the enrolled list read from the static,
    /// well inside the busy wait a locked request would have spent.
    #[test]
    fn a_presence_query_answers_while_the_authenticator_is_held() {
        let user = "c5-poll-user";
        set_enrolled(vec![user.to_string()]);
        let walk_through: Arc<Mutex<()>> = Arc::new(Mutex::new(()));
        let held = walk_through.lock().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let poll = std::thread::spawn(move || {
            let started = Instant::now();
            let outcome = presence_query(1000, 1, user, "query");
            tx.send((outcome, started.elapsed())).unwrap();
        });
        let (outcome, took) = rx
            .recv_timeout(BUSY_WAIT)
            .expect("the poll was answered while the walk-through held its lock");
        assert!(
            matches!(outcome, Outcome::PresenceMode { .. }),
            "a state reply, not busy: {:?}",
            outcome
        );
        assert!(
            took < BUSY_WAIT / 2,
            "answered at once, not after a wait: {:?}",
            took
        );
        // The list is what the poll reads: a deleted user stops "watching"
        // without the store being asked.
        assert!(is_enrolled(user));
        set_enrolled(Vec::new());
        assert!(!is_enrolled(user));
        drop(held);
        poll.join().unwrap();
    }

    /// Three same-uid requests take the window in arrival order; another
    /// user's is refused while one is live (B1); a request past the bound
    /// waits nowhere (B4); a requester that hangs up while waiting never
    /// gets the window (H9, H11).
    #[test]
    fn same_user_requests_take_the_window_in_arrival_order() {
        use crate::consent::{ConsentState, NoTurn};
        let st: &'static ConsentState = Box::leak(Box::new(ConsentState::new()));
        let order = Arc::new(Mutex::new(Vec::new()));
        let first = st.join(1000).unwrap();
        let held = st.take_turn(first, "alice", None, &|| {}).unwrap();
        assert_eq!(st.join(1001).unwrap_err(), NoTurn::OtherUser(1000));
        // Three more of alice's, joined a moment apart, each on its own
        // thread as the daemon runs them.
        let mut threads = Vec::new();
        for n in 1..=3u32 {
            let place = st.join(1000).unwrap();
            let order = Arc::clone(&order);
            threads.push(std::thread::spawn(move || {
                let turn = st.take_turn(place, "alice", None, &|| {}).unwrap();
                order.lock().unwrap().push(n);
                std::thread::sleep(Duration::from_millis(50));
                drop(turn);
            }));
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            st.join(1001).unwrap_err(),
            NoTurn::OtherUser(1000),
            "refused while alice's is live"
        );
        drop(held);
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(*order.lock().unwrap(), vec![1, 2, 3]);
        assert!(st.live_user().is_none(), "the last turn freed the window");
        let _b = st
            .join(1001)
            .expect("free for another user once alice is done");
        // The bound: one past it waits nowhere; a freed place is a place taken.
        let st2: &'static ConsentState = Box::leak(Box::new(ConsentState::new()));
        let places: Vec<_> = (0..crate::consent::CONSENT_PER_UID)
            .map(|i| {
                st2.join(1000)
                    .unwrap_or_else(|e| panic!("place {}: {:?}", i, e))
            })
            .collect();
        const {
            assert!(
                crate::consent::CONSENT_PER_UID >= 20,
                "twenty agent sessions calling sudo at once must all queue"
            )
        };
        assert_eq!(st2.join(1000).unwrap_err(), NoTurn::TooMany);
        drop(places);
        let _p = st2.join(1000).expect("a place freed is a place taken");
        // A requester that hangs up while waiting is Gone, not served.
        let st3: &'static ConsentState = Box::leak(Box::new(ConsentState::new()));
        let live = st3.test_live(1000, "alice");
        let (a, b) = UnixStream::pair().unwrap();
        let place = st3.join(1000).unwrap();
        let waiter = std::thread::spawn(move || {
            st3.take_turn(place, "alice", Some(b.into()), &|| {})
                .map(|_| ())
        });
        std::thread::sleep(Duration::from_millis(100));
        drop(a);
        assert_eq!(waiter.join().unwrap().unwrap_err(), NoTurn::Gone);
        drop(live);
    }

    /// The hang-up is read off the request socket itself: dropping the
    /// requester's end reads as gone at the next poll, a peer that is alive
    /// and silent does not, and a live record with no requester never
    /// reads as gone (H11).
    #[test]
    fn a_dropped_requester_reads_as_gone_and_a_silent_one_does_not() {
        use crate::consent::{peer_gone, Answer, ConsentState};
        let (a, b) = UnixStream::pair().unwrap();
        let b: std::os::fd::OwnedFd = b.into();
        assert!(!peer_gone(&b), "alive and silent");
        drop(a);
        assert!(peer_gone(&b), "hung up");
        let st: &'static ConsentState = Box::leak(Box::new(ConsentState::new()));
        let place = st.join(1000).unwrap();
        let (a, b) = UnixStream::pair().unwrap();
        let _turn = st
            .take_turn(place, "alice", Some(b.into()), &|| {})
            .unwrap();
        assert!(!st.requester_gone("alice"));
        assert!(st.poll("alice").is_none());
        drop(a);
        assert!(st.requester_gone("alice"));
        assert!(matches!(st.poll("alice"), Some(Answer::Gone)));
        assert!(
            st.answered("alice"),
            "a hang-up counts as an answer waiting"
        );
    }
}
