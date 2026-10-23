//! The listener: connection places counted as systemd counts a socket's
//! (`limits.rs`: the daemon's limit and each source's share), a thread per
//! connection, the lock screen's reserved channel on a socket of its own
//! (`channel.rs`), and an idle thread that releases the recognition model
//! when nobody has used it for a while. A connection that finds no place
//! is refused at once, so a flood cannot queue behind the camera.

use super::acl::refresh_socket_acl_at;
#[cfg(test)]
use super::acl::{is_enrolled, set_enrolled, ENROLLED_TEST_LOCK};
use super::handle::handle;
#[cfg(test)]
use super::handle::BUSY_WAIT;
use super::limits::{per_source_limit, Full, Places, Source, ROOT_SHARE};
#[cfg(test)]
use super::presence::presence_query;
use super::reply;
use crate::auth::{Authenticator, Outcome};
use anyhow::{Context, Result};
use std::os::unix::net::UnixListener;
#[cfg(test)]
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

/// The connection places taken now, in all and by source.
static PLACES: Places = Places::new();
/// How often the idle thread looks, and how long the recognition model may sit
/// unused before it is released.
const MODEL_IDLE_TICK: Duration = Duration::from_secs(60);
const MODEL_IDLE_RELEASE: Duration = Duration::from_secs(600);

/// The daemon's config, for the presence query answered while the
/// authenticator is busy with another request (its mutex is held for a
/// whole consent round).
pub(super) static CFG: std::sync::OnceLock<crate::config::Config> = std::sync::OnceLock::new();

pub fn serve(auth: Arc<Mutex<Authenticator>>, socket: &Path) -> Result<()> {
    // A check unit left from before this start (a crash, an upgrade) would
    // hold the key beside this daemon's checks: stopped first (fix round
    // 11, Opus N4).
    if !cfg!(test) {
        match crate::consent::stale_checks_stop().status() {
            Ok(s) if s.success() => {}
            other => log::warn!("leftover key check units were not stopped: {:?}", other),
        }
        // And one left holding the fingerprint reader, which fprintd lets
        // one client claim at a time.
        match crate::consent::stale_fprint_checks_stop().status() {
            Ok(s) if s.success() => {}
            other => log::warn!(
                "leftover fingerprint check units were not stopped: {:?}",
                other
            ),
        }
    }
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let _ = std::fs::remove_file(socket);
    let listener =
        UnixListener::bind(socket).with_context(|| format!("bind {}", socket.display()))?;
    // The lock screen's reserved channel, beside it (round 7, B).
    let lock_socket = super::acl::lock_socket_of(socket);
    let _ = std::fs::remove_file(&lock_socket);
    let channels = UnixListener::bind(&lock_socket)
        .with_context(|| format!("bind {}", lock_socket.display()))?;
    // Mode 0660 with one ACL entry per enrolled user (`apply_socket_acl`):
    // the kernel refuses anyone else at connect, and the peer-credential
    // checks in `handle` decide what a connection may ask.
    refresh_socket_acl_at(&auth, socket);
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
    log::info!(
        "listening on {} and {}",
        socket.display(),
        lock_socket.display()
    );
    // A daemon that starts knows nothing of the locks before it: every user
    // is latched for one hold (Opus N3).
    crate::consent::CONSENT.mark_started();
    std::thread::Builder::new()
        .name("lock-channels".into())
        .spawn(move || super::channel::serve_channels(channels, &crate::consent::CONSENT))
        .context("spawn the lock channel listener")?;
    let (total, configured) = CFG.get().map_or((64, None), |c| {
        (c.max_connections, c.max_connections_per_source)
    });
    for conn in listener.incoming() {
        let stream = match conn {
            Ok(s) => s,
            Err(e) => {
                log::warn!("accept: {}", e);
                continue;
            }
        };
        let source = source_of(&stream);
        let share = match source {
            Source::Root => ROOT_SHARE,
            Source::User(_) => per_source_limit(total, configured, super::acl::enrolled_count()),
        };
        if let Err(full) = PLACES.take(source, total, share) {
            turn_away(
                stream,
                &crate::consent::CONSENT,
                source,
                full,
                (total, share),
            );
            continue;
        }
        let auth = Arc::clone(&auth);
        // The slot is given back on every exit, a panic's unwind included:
        // a handler that dies must not hold a slot for the daemon's life.
        // A consent request gives it back early, once admitted (see handle).
        let slot = Slot::new(source);
        let spawned = std::thread::Builder::new()
            .name("request".into())
            .spawn(move || {
                if let Err(e) = handle(stream, &auth, &slot) {
                    log::warn!("connection: {}", e);
                }
            });
        if let Err(e) = spawned {
            // The thread was not started, so the slot and the stream were
            // dropped with the closure: the slot is back, and the peer reads
            // the connection closing rather than hanging.
            log::warn!("cannot start a request thread: {}", e);
        }
    }
    Ok(())
}

/// The account a connection is charged to (`limits::attribute`): a user
/// peer's uid; for a root peer, polkit's helper's connecting uid, or the
/// account its login uid, real uid and user slice agree on, read through
/// its pidfd so a recycled pid cannot lend an account; else unattributed
/// root.
fn source_of(stream: &std::os::unix::net::UnixStream) -> Source {
    use nix::sys::socket::{getsockopt, sockopt};
    let Ok(cred) = getsockopt(stream, sockopt::PeerCredentials) else {
        return Source::Root;
    };
    if cred.uid() != 0 {
        return Source::User(cred.uid());
    }
    let pidfd = getsockopt(stream, sockopt::PeerPidfd).ok();
    let cgroup = crate::procfs::read(cred.pid(), "cgroup");
    // What polkit's helper is known by beside its cgroup, both readable
    // without ptrace rights (fix round 14, Opus N1, Codex 2): its comm, and
    // the real uid below.
    let comm = crate::procfs::read(cred.pid(), "comm");
    let loginuid = crate::procfs::read(cred.pid(), "loginuid");
    let ruid = crate::procfs::read(cred.pid(), "status")
        .as_deref()
        .and_then(super::limits::real_uid);
    let alive = pidfd
        .as_ref()
        .is_some_and(|fd| !super::locality::process_exited(fd));
    super::limits::attribute(
        0,
        cgroup.as_deref(),
        comm.as_deref(),
        loginuid.as_deref(),
        ruid,
        alive,
    )
}

/// A connection that found no place: answered "busy" at once and logged
/// with its source and the limit it met. A refusal at the daemon's limit
/// latches every user for one hold, a refusal at an account's share that
/// account alone (round 7, C), so filling the places can only deny service
/// and never open an approval (round 6, item 10). The lock screen's channel
/// is outside both limits.
fn turn_away(
    mut stream: std::os::unix::net::UnixStream,
    state: &crate::consent::ConsentState,
    source: Source,
    full: Full,
    (total, share): (usize, usize),
) {
    match (full, source) {
        (Full::Total, _) => {
            log::warn!(
                "connection from {} refused: the daemon's limit of {} places is full",
                source,
                total
            );
            state.note_refusal();
        }
        (Full::Source, Source::User(uid)) => {
            log::warn!(
                "connection from {} refused: its share of {} places is full",
                source,
                share
            );
            if let Some(name) = name_of_uid(uid) {
                state.note_refusal_for(&name);
            }
        }
        (Full::Source, Source::Root) => log::warn!(
            "connection from {} refused: its share of {} places is full",
            source,
            share
        ),
    }
    let _ = reply(
        &mut stream,
        &Outcome::Error {
            message: "busy".into(),
        },
    );
}

/// A request that held its place to the request deadline without a line
/// (round 6, item 10): a place kept from its account's share, so charged
/// to that account alone, latched for one hold as a refusal at its share
/// is (fix round 13, Codex 4). Charged to every account, one account's
/// stalls, staggered under its share, kept everyone's card and key off.
/// Every account is latched only when the daemon's own limit is full
/// (`turn_away`). Unattributed root's, and a uid with no account, latch
/// nobody: no approval is for them, and a place they keep from anyone
/// else is refused, and counted, at the limit.
pub(super) fn note_stall(
    state: &crate::consent::ConsentState,
    source: Source,
    name_of: &dyn Fn(u32) -> Option<String>,
) {
    match source
        .into_uid()
        .and_then(|uid| name_of(uid).map(|n| (uid, n)))
    {
        Some((uid, name)) => {
            log::warn!(
                "a request from uid {} held its place to the deadline without a line: {} is latched for a hold",
                uid,
                name
            );
            state.note_refusal_for(&name);
        }
        None => log::warn!(
            "a request from {} held its place to the deadline without a line",
            source
        ),
    }
}

/// The account name of a uid, from the system's user database.
pub(super) fn name_of_uid(uid: u32) -> Option<String> {
    nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
}

/// One of the `MAX_CONNECTIONS` places, given back once: on drop, or
/// earlier by `release`. A consent request releases it once admitted: the
/// request lives as long as the user takes to answer, and the places are
/// for the short requests (answers, the window's acknowledgment, probes)
/// that must keep getting through meanwhile (B4).
pub(super) struct Slot {
    held: std::sync::atomic::AtomicBool,
    source: Source,
}

impl Slot {
    fn new(source: Source) -> Slot {
        Slot {
            held: std::sync::atomic::AtomicBool::new(true),
            source,
        }
    }

    /// The account this place is charged to.
    pub(super) fn source(&self) -> Source {
        self.source
    }

    pub(super) fn release(&self) {
        if self.held.swap(false, Ordering::SeqCst) {
            PLACES.give(self.source);
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

    /// Round 6, item 10: a caller turned away at the places is told busy,
    /// and every user counts as latched for a hold from then.
    #[test]
    fn a_caller_turned_away_latches_everyone() {
        use crate::lockgate::{Desktop, LockState, Verdict};
        let st: &'static crate::consent::ConsentState =
            Box::leak(Box::new(crate::consent::ConsentState::new()));
        assert_eq!(
            st.judge("alice", LockState::Unlocked, Desktop::Some),
            Verdict::Unlocked
        );
        let (a, b) = UnixStream::pair().unwrap();
        turn_away(a, st, Source::User(1000), Full::Total, (64, 64));
        let mut line = String::new();
        std::io::BufRead::read_line(&mut std::io::BufReader::new(b), &mut line).unwrap();
        assert!(line.starts_with("{\"result\":\"error\""), "{}", line);
        for user in ["alice", "bob"] {
            assert_ne!(
                st.judge(user, LockState::Unlocked, Desktop::Some),
                Verdict::Unlocked,
                "{}",
                user
            );
        }
    }

    /// Fix round 13 (Codex 4): a request held to its deadline without a
    /// line is charged to its source's account alone. Thirteen stalled
    /// connections from one account, staggered so one ends every
    /// thirteenth of the default hold (below the per-source floor of 16,
    /// so none is turned away), keep that account latched and never
    /// another; unattributed root's latch nobody. Only the daemon's own
    /// limit full latches every account.
    #[test]
    fn stalled_requests_latch_their_own_account_alone() {
        use crate::lockgate::{Desktop, LockState, Verdict};
        let st: &'static crate::consent::ConsentState =
            Box::leak(Box::new(crate::consent::ConsentState::new()));
        let name_of = |uid: u32| match uid {
            1000 => Some("alice".to_string()),
            1001 => Some("bob".to_string()),
            _ => None,
        };
        let open =
            |user: &str| st.judge(user, LockState::Unlocked, Desktop::Some) == Verdict::Unlocked;
        assert!(open("alice") && open("bob"));
        let hold = std::time::Duration::from_millis(500);
        for i in 0..13 {
            note_stall(st, Source::User(1000), &name_of);
            assert!(
                !open("alice"),
                "the account that stalled is latched ({})",
                i
            );
            assert!(open("bob"), "another account is not ({})", i);
            std::thread::sleep(hold / 13);
        }
        note_stall(st, Source::Root, &name_of);
        note_stall(st, Source::User(4_000_000), &name_of);
        assert!(
            open("bob"),
            "unattributed root and a uid with no name latch nobody"
        );
        let (a, b) = UnixStream::pair().unwrap();
        turn_away(a, st, Source::User(1000), Full::Total, (64, 64));
        drop(b);
        assert!(
            !open("bob"),
            "the daemon's own limit full latches every account"
        );
    }

    /// A slot is given back exactly once, whether released early or dropped.
    #[test]
    fn a_slot_is_given_back_once() {
        let source = Source::User(4_111_222);
        PLACES.take(source, usize::MAX, usize::MAX).unwrap();
        let s = Slot::new(source);
        s.release();
        assert_eq!(PLACES.taken(source).1, 0);
        drop(s);
        assert_eq!(
            PLACES.taken(source).1,
            0,
            "the drop after a release takes nothing more"
        );
        PLACES.take(source, usize::MAX, usize::MAX).unwrap();
        drop(Slot::new(source));
        assert_eq!(PLACES.taken(source).1, 0);
    }

    /// The bar widget's presence poll is answered while the authenticator
    /// is held for the length of an enrollment walk-through (C5). The query
    /// takes no authenticator at all (its signature is the guarantee); this
    /// holds a lock for the walk-through's whole run on the calling thread
    /// and expects the reply, with the enrolled list read from the static,
    /// well inside the busy wait a locked request would have spent.
    #[test]
    fn a_presence_query_answers_while_the_authenticator_is_held() {
        let user = "c5-poll-user";
        let _list = ENROLLED_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
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

    /// D6: the unit's TasksMax holds every task the daemon can have at
    /// once: the idle base, and a thread for each connection place and for
    /// each consent request one user can have (they wait without a place,
    /// B4, on their own thread and nothing else, H11), each with a call
    /// into the user's session that may be running under it.
    /// Fix round 11 (Codex 1, Opus): a crash and its restart are not an
    /// outage. The unit keeps its runtime directory across an automatic
    /// restart (`RuntimeDirectoryPreserve=restart`), so the PAM module,
    /// finding the directory with nothing listening, knows the daemon is
    /// restarting and goes to the password, not the stock key; and the
    /// kernel picks the daemon late for an OOM kill.
    #[test]
    fn the_unit_keeps_its_runtime_directory_across_a_restart() {
        let unit = include_str!("../../../packaging/faceauth.service");
        let set = |key: &str| {
            unit.lines()
                .filter_map(|l| l.strip_prefix(key))
                .map(str::trim)
                .collect::<Vec<_>>()
        };
        assert_eq!(set("RuntimeDirectory="), ["faceauth"]);
        assert_eq!(set("RuntimeDirectoryPreserve="), ["restart"]);
        assert_eq!(set("OOMScoreAdjust="), ["-500"]);
        assert_eq!(set("Restart="), ["on-failure"]);
    }

    #[test]
    fn the_units_tasks_max_holds_every_request_the_daemon_admits() {
        /// The idle daemon's 7 tasks (TasksCurrent, measured live), the
        /// presence watch's lock call (the helper, `timeout` and
        /// `systemd-run`), the security key's five (the watch, its
        /// `systemd-run`, the `timeout` and `systemctl` of a stop, and the
        /// next watch waiting for that stop), and the lock channel's
        /// listener (round 7).
        const BASE_TASKS: usize = 7 + 3 + 5 + 1;
        /// A request's thread, and the `timeout` and `systemd-run` of a
        /// call into the user's session.
        const TASKS_PER_REQUEST: usize = 3;
        /// A key unlock or a stack's key fallback holds its place with one
        /// task more: its check's `systemd-run` runs beside the lock check
        /// (or the stop) it makes.
        const KEY_UNLOCK_EXTRA: usize = 1;
        /// The nod window's lock watches (consent/wait.rs, `LockWatch`):
        /// at most `LOCK_WATCHES_MAX` hold a thread, the window's own and
        /// one still finishing a look after its window ended, each with
        /// its look's `timeout` and `systemd-run` beside the request's own
        /// call.
        const NOD_LOCK_WATCH: usize = crate::consent::LOCK_WATCHES_MAX * 3;
        let unit = include_str!("../../../packaging/faceauth.service");
        let tasks_max: usize = unit
            .lines()
            .find_map(|l| l.strip_prefix("TasksMax="))
            .expect("the unit sets TasksMax")
            .trim()
            .parse()
            .expect("TasksMax is a number");
        // Round 7 (C): sized for the largest `max_connections` the config
        // takes, and the lock screen's reserved channels, a thread each,
        // outside the limits.
        let max = crate::config::MAX_CONNECTIONS_CAP;
        let most = (max + crate::consent::CONSENT_PER_UID) * TASKS_PER_REQUEST
            + max * KEY_UNLOCK_EXTRA
            + super::super::channel::TOTAL
            + BASE_TASKS
            + NOD_LOCK_WATCH;
        assert!(
            unit.contains(&format!("= {}.", most)),
            "the unit's comment shows the sum, {}",
            most
        );
        assert!(
            most <= tasks_max,
            "up to {} tasks, TasksMax={}",
            most,
            tasks_max
        );
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
