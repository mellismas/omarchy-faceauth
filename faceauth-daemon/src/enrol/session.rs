//! The one enrolment session at a time: who holds it, the window watching
//! its stream, and the Continue, Redo and Cancel words sent back. The claim
//! is released on every way out, so the window never stays up over the
//! screen after a session ends.

use super::stream::Tick;
use std::io::Write as _;
use std::os::unix::net::UnixStream;
use std::sync::Mutex;
use std::time::Duration;
#[cfg(test)]
use std::time::Instant;

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

/// The claim on the one enrolment session, from the moment `ACTIVE` is set
/// until the window has been told the session is over. Every way out of
/// the session ends it through `end`, and a way out that forgets is caught
/// by the drop, so the window never stays up over the screen and the
/// watchers never loop for the daemon's life (C9).
pub(super) struct Session {
    user: String,
    ended: bool,
}

impl Session {
    pub(super) fn claim(user: &str, uid: u32) -> Session {
        if let Ok(mut act) = ACTIVE.lock() {
            *act = Some((user.to_string(), uid));
        }
        if let Ok(mut c) = CONTROL.lock() {
            c.clear();
        }
        Session {
            user: user.to_string(),
            ended: false,
        }
    }

    /// Tell the window the step the session ended at, release the claim
    /// and hide the window. Once only; later calls do nothing.
    pub(super) fn end(&mut self, step: &'static str, message: &str) {
        if self.ended {
            return;
        }
        self.ended = true;
        broadcast(&Tick::blank(step, message));
        std::thread::sleep(Duration::from_millis(1500));
        release();
        let _ =
            crate::consent::shell_call(&self.user, &["shell", "hide", "omarchy.faceauth.enrol"]);
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
        self.end("failed", "The enrolment ended unexpectedly.");
    }
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
    /// summon) still clears the session, so the next enrolment is not
    /// "already running" and the watchers stop looping. A claim abandoned
    /// before the window opened clears it too.
    #[test]
    fn a_dropped_claim_releases_the_session() {
        let _serial = SESSION_STATICS.lock().unwrap_or_else(|e| e.into_inner());
        let sess = Session {
            user: "c9-test".into(),
            ended: false,
        };
        if let Ok(mut act) = ACTIVE.lock() {
            *act = Some(("c9-test".into(), 65534));
        }
        assert!(active_for("c9-test", 65534));
        drop(sess);
        assert!(!is_active(), "the drop ended the session");
        let sess = Session {
            user: "c9-test".into(),
            ended: false,
        };
        if let Ok(mut act) = ACTIVE.lock() {
            *act = Some(("c9-test".into(), 65534));
        }
        sess.abandon();
        assert!(!is_active(), "the abandoned claim is released");
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
