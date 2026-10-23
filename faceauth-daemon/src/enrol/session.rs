//! The one enrollment session at a time: who holds it, the window watching
//! its stream, and the Continue, Redo and Cancel words sent back. The claim
//! is released on every way out, so the window never stays up over the
//! screen after a session ends.

use super::stream::Tick;
use anyhow::{anyhow, Result};
use std::io::Write as _;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a session waits for the window to watch its stream before
/// the camera opens. The window connects once, as soon as it is summoned.
pub(super) const WINDOW_WAIT: Duration = Duration::from_secs(5);

/// The session's user and uid while one runs: who may watch and control it.
static ACTIVE: Mutex<Option<(String, u32)>> = Mutex::new(None);
/// The window watching the stream: one per session. A second watcher
/// replaces the first (the window reconnected), so watchers can never
/// pile up, and the stream is written without blocking: a watcher that
/// stops reading is dropped at the first full buffer instead of stalling
/// the camera loop behind it (J2).
static WATCHERS: Mutex<Vec<UnixStream>> = Mutex::new(Vec::new());
/// Continue, redo and cancel from the window.
static CONTROL: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub fn active_for(user: &str, uid: u32) -> bool {
    ACTIVE
        .lock()
        .map(|a| {
            a.as_ref()
                .map(|(u, id)| u == user && *id == uid)
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

pub fn is_active() -> bool {
    ACTIVE.lock().map(|a| a.is_some()).unwrap_or(false)
}

pub fn add_watcher(stream: UnixStream) {
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    if let Ok(mut w) = WATCHERS.lock() {
        w.clear();
        w.push(stream);
    }
}

pub fn control(word: &str) {
    if let Ok(mut c) = CONTROL.lock() {
        c.push(word.to_string());
    }
}

pub(super) fn take_control() -> Option<String> {
    CONTROL.lock().ok().and_then(|mut c| {
        if c.is_empty() {
            None
        } else {
            Some(c.remove(0))
        }
    })
}

pub(super) fn broadcast(tick: &Tick) {
    let Ok(mut line) = serde_json::to_string(tick) else {
        return;
    };
    line.push('\n');
    if let Ok(mut w) = WATCHERS.lock() {
        // A short write means the window is not reading: the rest of the
        // line would not follow it in one piece, so the watcher goes.
        w.retain_mut(|s| matches!(s.write(line.as_bytes()), Ok(n) if n == line.len()));
    }
}

/// The claim on the one enrollment session, from the moment `ACTIVE` is set
/// until the window has been told the session is over. Every way out of
/// the session ends it through `end`, and a way out that forgets is caught
/// by the drop, so the window never stays up over the screen and the
/// watchers never loop for the daemon's life (C9).
pub(super) struct Session {
    ended: bool,
    /// The user's desktops when the enrollment began (fix round 10,
    /// Codex 6): the window's last call goes to them, or to none.
    pin: Option<crate::consent::Pin>,
}

impl Session {
    pub(super) fn claim(user: &str, uid: u32, pin: Option<crate::consent::Pin>) -> Session {
        if let Ok(mut act) = ACTIVE.lock() {
            *act = Some((user.to_string(), uid));
        }
        if let Ok(mut c) = CONTROL.lock() {
            c.clear();
        }
        Session { ended: false, pin }
    }

    /// Tell the window the step the session ended at, release the claim
    /// and hide the window. Once only; later calls do nothing. The pause
    /// that lets the window show the last line is kept for a window that
    /// watches: a session nobody watches ends at once, so the camera's lock
    /// is not held for it (C9).
    pub(super) fn end(&mut self, step: &'static str, message: &str) {
        if self.ended {
            return;
        }
        self.ended = true;
        if watched() {
            broadcast(&Tick::blank(step, message));
            std::thread::sleep(Duration::from_millis(1500));
        }
        release();
        if let Some(pin) = &self.pin {
            let _ = crate::consent::shell_call_pinned(
                pin,
                &["shell", "hide", "omarchy.faceauth.enrol"],
            );
        }
    }

    /// Wait up to `within` for the window to watch the stream. The camera
    /// opens only for a watched session, as consent waits for the card's
    /// acknowledgment (C9): with no window on screen nobody sees what the
    /// camera is doing or can cancel it.
    pub(super) fn await_window(&self, within: Duration) -> Result<()> {
        let until = Instant::now() + within;
        while !watched() {
            if Instant::now() >= until {
                return Err(anyhow!(
                    "no enrollment window: it did not connect within {} s",
                    within.as_secs()
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    /// Has the window gone? The watcher list empties only when a write to
    /// the window's stream fails, and the window closes itself when its
    /// stream is dropped, so an empty list is no window, for good. Asked on
    /// every pass of the session's loop, camera steps included (C9).
    pub(super) fn window_gone(&self) -> bool {
        !watched()
    }

    /// The window never opened: release the claim with nothing to tell
    /// and nothing to hide.
    pub(super) fn abandon(mut self) {
        self.ended = true;
        release();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.end("failed", "The enrollment ended unexpectedly.");
    }
}

/// Is a window watching the stream?
fn watched() -> bool {
    WATCHERS.lock().map(|w| !w.is_empty()).unwrap_or(false)
}

/// Clear the claim, the watchers and the control words.
fn release() {
    if let Ok(mut w) = WATCHERS.lock() {
        w.clear();
    }
    if let Ok(mut c) = CONTROL.lock() {
        c.clear();
    }
    if let Ok(mut act) = ACTIVE.lock() {
        *act = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The session statics are process-wide: tests that touch them take
    /// this so they do not see each other's claim.
    static SESSION_STATICS: Mutex<()> = Mutex::new(());

    /// C9: a claim released without an explicit end (an error after the
    /// summon) still clears the session, so the next enrollment is not
    /// "already running" and the watchers stop looping. A claim abandoned
    /// before the window opened clears it too.
    #[test]
    fn a_dropped_claim_releases_the_session() {
        let _serial = SESSION_STATICS.lock().unwrap_or_else(|e| e.into_inner());
        let sess = Session {
            ended: false,
            pin: None,
        };
        if let Ok(mut act) = ACTIVE.lock() {
            *act = Some(("c9-test".into(), 65534));
        }
        assert!(active_for("c9-test", 65534));
        drop(sess);
        assert!(!is_active(), "the drop ended the session");
        let sess = Session {
            ended: false,
            pin: None,
        };
        if let Ok(mut act) = ACTIVE.lock() {
            *act = Some(("c9-test".into(), 65534));
        }
        sess.abandon();
        assert!(!is_active(), "the abandoned claim is released");
    }

    /// C9: whatever the session starts at, the walk waits for the window
    /// first and ends when it never connects. That end releases the claim
    /// within the wait, without the pause a watching window gets to show
    /// the last line, so the camera's lock (held until the session
    /// returns) is not kept for a window that is not there.
    #[test]
    fn a_session_whose_window_never_connects_is_released_within_the_wait() {
        let _serial = SESSION_STATICS.lock().unwrap_or_else(|e| e.into_inner());
        let wait = Duration::from_millis(300);
        let started = Instant::now();
        let mut sess = Session::claim("c9-release", 65534, None);
        let e = sess.await_window(wait).expect_err("nobody watched");
        sess.end("failed", &e.to_string());
        assert!(!is_active(), "the claim is released");
        assert!(
            started.elapsed() < wait + Duration::from_millis(1000),
            "released {:?} after the start, for a wait of {:?}",
            started.elapsed(),
            wait
        );
        // A window that watches still gets the pause to show the last line.
        let mut sess = Session::claim("c9-release", 65534, None);
        let (a, b) = UnixStream::pair().unwrap();
        add_watcher(a);
        sess.await_window(wait).expect("watched");
        let ended = Instant::now();
        sess.end("done", "bye");
        assert!(ended.elapsed() >= Duration::from_millis(1500));
        drop(b);
        assert!(!is_active());
    }

    /// C9: a window lost at any step, a camera step included (the shell
    /// restarted, the window crashed), reads as gone at the next write to
    /// its stream, which the session's loop makes on every frame; the loop
    /// then ends the session, frees the camera and stores nothing.
    #[test]
    fn a_window_lost_at_a_camera_step_reads_as_gone_at_the_next_frame() {
        let _serial = SESSION_STATICS.lock().unwrap_or_else(|e| e.into_inner());
        let mut sess = Session::claim("c9-lost", 65534, None);
        let (a, window) = UnixStream::pair().unwrap();
        add_watcher(a);
        sess.await_window(Duration::from_millis(300))
            .expect("watched");
        broadcast(&Tick::blank("path", "follow the dot"));
        assert!(!sess.window_gone());
        drop(window);
        let lost = Instant::now();
        broadcast(&Tick::blank("path", "follow the dot"));
        assert!(sess.window_gone(), "gone at the first frame after");
        sess.end("failed", "the enrollment window closed");
        assert!(!is_active());
        assert!(
            lost.elapsed() < Duration::from_secs(1),
            "{:?}",
            lost.elapsed()
        );
    }

    /// C9: a session no window watches ends before the camera opens, as
    /// "no enrollment window", and releases its claim; one whose window
    /// connects a moment after the summon goes on.
    #[test]
    fn a_session_with_no_watcher_ends_with_no_enrolment_window() {
        let _serial = SESSION_STATICS.lock().unwrap_or_else(|e| e.into_inner());
        let sess = Session::claim("c9-watch", 65534, None);
        let started = Instant::now();
        let e = sess
            .await_window(Duration::from_millis(300))
            .expect_err("nobody watched");
        assert!(e.to_string().starts_with("no enrollment window"), "{}", e);
        assert!(started.elapsed() >= Duration::from_millis(300));
        sess.abandon();
        assert!(!is_active());

        let sess = Session::claim("c9-watch", 65534, None);
        let (a, _b) = UnixStream::pair().unwrap();
        let window = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            add_watcher(a);
        });
        sess.await_window(Duration::from_secs(2))
            .expect("the window connected after the summon");
        window.join().unwrap();
        sess.abandon();
        assert!(!is_active() && !watched());
    }

    #[test]
    fn watchers_and_control_are_per_session() {
        let _serial = SESSION_STATICS.lock().unwrap_or_else(|e| e.into_inner());
        assert!(!is_active());
        control("continue");
        assert_eq!(take_control().as_deref(), Some("continue"));
        assert_eq!(take_control(), None);
        let (a, b) = UnixStream::pair().unwrap();
        add_watcher(a);
        broadcast(&Tick::blank("welcome", "hi"));
        use std::io::Read as _;
        let mut buf = [0u8; 512];
        b.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        let n = (&b).read(&mut buf).unwrap();
        let line = String::from_utf8_lossy(&buf[..n]);
        assert!(
            line.contains("\"step\":\"welcome\"") && line.ends_with('\n'),
            "{}",
            line
        );
        // The window hangs up. Shut down, not only closed: a child another
        // test thread forks in this instant holds a copy of the descriptor
        // until it execs, and a close alone would not hang up while it does
        // (fix round 11: the test's own race, not the daemon's).
        b.shutdown(std::net::Shutdown::Both).unwrap();
        drop(b);
        broadcast(&Tick::blank("welcome", "bye"));
        assert!(
            WATCHERS.lock().unwrap().is_empty(),
            "a hung-up watcher is dropped"
        );
        // J2: one watcher per session, and one that never reads is dropped
        // at the first full buffer rather than stalling the writer.
        let (first, _keep_first) = UnixStream::pair().unwrap();
        add_watcher(first);
        let (second, silent) = UnixStream::pair().unwrap();
        add_watcher(second);
        assert_eq!(
            WATCHERS.lock().unwrap().len(),
            1,
            "the second replaces the first"
        );
        let started = Instant::now();
        let mut n = 0;
        while !WATCHERS.lock().unwrap().is_empty() {
            broadcast(&Tick::blank("path", &"x".repeat(2000)));
            n += 1;
            assert!(n < 100_000, "a silent watcher was never dropped");
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "the writer never blocked on the silent watcher ({} lines in {:?})",
            n,
            started.elapsed()
        );
        drop(silent);
    }
}
