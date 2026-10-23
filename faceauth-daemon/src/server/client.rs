//! The client side of the socket, used by the CLI. The PAM module builds
//! its own five request lines, without serde (`pam_faceauth`).

use crate::auth::Outcome;
use crate::consent::{wipe_string, Secret};
use anyhow::{bail, Context, Result};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// Longest reply read. The daemon's answers are a few hundred bytes; a
/// development build also reads a pose sweep's per-frame list, about 150
/// bytes a frame.
const MAX_REPLY: u64 = if cfg!(feature = "dev-tools") {
    4 << 20
} else {
    64 << 10
};

/// A plain look: one attempt for `user`.
pub fn ask(socket: &Path, user: &str, timeout: Duration) -> Result<Outcome> {
    request(socket, user, false, timeout)
}

pub fn probe(socket: &Path, user: &str, timeout: Duration) -> Result<Outcome> {
    request(socket, user, true, timeout)
}

/// How long to wait for a reply to a request that runs `seconds`: that
/// and 15 s more. A length that is not a number of seconds a request can
/// run is refused before anything is sent, where the conversion would
/// panic on NaN, a negative or an overflow.
fn reply_within(seconds: f32) -> Result<Duration> {
    if !(0.0..=3600.0).contains(&seconds) {
        bail!("{} is not a number of seconds a request can run", seconds);
    }
    Ok(Duration::from_secs_f32(seconds + 15.0))
}

/// Root: a pose sweep, scored per frame (dev-tools builds).
#[cfg(feature = "dev-tools")]
pub fn sweep(socket: &Path, user: &str, seconds: f32) -> Result<Outcome> {
    let within = reply_within(seconds)?;
    send(
        socket,
        serde_json::json!({ "user": user, "sweep_seconds": seconds }),
        Some(within),
    )
}

fn request(socket: &Path, user: &str, probe: bool, timeout: Duration) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "probe": probe }),
        Some(timeout),
    )
}

/// From the lock screen: is its security key lane there for `user`? The
/// daemon answers without the camera. With the daemon down (its socket
/// missing, or nothing listening on it) the answer is `NotRunning`, so the
/// lock screen can say so; every other failure stays an error.
pub fn key_lane(socket: &Path, user: &str) -> Result<Outcome> {
    match send(
        socket,
        serde_json::json!({ "user": user, "key_lane": true }),
        Some(Duration::from_secs(3)),
    ) {
        Err(e) if daemon_down(&e) => Ok(Outcome::NotRunning),
        other => other,
    }
}

/// From the lock screen: does its fingerprint lane go through the daemon
/// for `user`? Asked as `key_lane` is, with the same `NotRunning` for a
/// daemon that is down, which hands the lane back to stock Omarchy's.
pub fn fprint_lane(socket: &Path, user: &str) -> Result<Outcome> {
    match send(
        socket,
        serde_json::json!({ "user": user, "fprint_lane": true }),
        Some(Duration::from_secs(3)),
    ) {
        Err(e) if daemon_down(&e) => Ok(Outcome::NotRunning),
        other => other,
    }
}

/// The connection to the daemon's socket failed.
#[derive(Debug)]
struct ConnectFailed(std::io::Error);

impl std::fmt::Display for ConnectFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for ConnectFailed {}

/// Whether `e` is the connect itself finding no socket, or nothing
/// listening on it: the daemon is down, not busy or broken.
fn daemon_down(e: &anyhow::Error) -> bool {
    e.chain()
        .filter_map(|c| c.downcast_ref::<ConnectFailed>())
        .any(|c| {
            matches!(
                c.0.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            )
        })
}

/// How the lock screen's channel ended, from the CLI's side.
#[derive(Debug, PartialEq)]
pub enum ChannelEnd {
    /// The lock screen wrote "unlocked": the graceful word went to the
    /// daemon.
    Unlocked,
    /// The lock screen's end closed without it: a drop, which keeps the
    /// user latched.
    InputClosed,
    /// The daemon's side closed (a restart): the lock screen opens another.
    DaemonGone,
    /// The daemon expired the channel (the compositor said unlocked for a
    /// while): the CLI waited on the lock screen's word with no channel,
    /// so no other was opened for this lock.
    Expired,
}

/// The lock screen's reserved channel (round 7, B): connect to `socket`
/// (`config::LOCK_SOCKET`), check its listener is root, and hold the
/// channel open for `user` until `input` (the lock screen's pipe to this
/// process) says "unlocked" or closes.
pub fn lock_channel(socket: &Path, user: &str, input: &impl AsFd) -> Result<ChannelEnd> {
    let stream =
        UnixStream::connect(socket).with_context(|| format!("connect {}", socket.display()))?;
    let peer = getsockopt(&stream, PeerCredentials).context("peer credentials")?;
    if peer.uid() != 0 {
        bail!(
            "{} is not the daemon's socket: its listener runs as uid {}, not root",
            socket.display(),
            peer.uid()
        );
    }
    lock_channel_on(stream, user, input)
}

/// The channel on a connected `stream`.
fn lock_channel_on(stream: UnixStream, user: &str, input: &impl AsFd) -> Result<ChannelEnd> {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    let mut body = serde_json::json!({ "user": user, "lock_channel": true });
    let line = request_line(&mut body);
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    (&stream).write_all(line.as_bytes())?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut reply = String::new();
    reader.by_ref().take(MAX_REPLY).read_line(&mut reply)?;
    if reply.trim() != "{\"result\":\"channel_open\"}" {
        bail!("the daemon did not open the lock channel: {}", reply.trim());
    }
    let mut said = Vec::new();
    loop {
        // POLLIN alone: a line or the daemon's end both read as input.
        // (POLLRDHUP, which nix does not name, made `revents` None, so the
        // daemon's end was never seen and the loop spun; fix round 8.)
        let mut fds = [
            PollFd::new(stream.as_fd(), PollFlags::POLLIN),
            PollFd::new(input.as_fd(), PollFlags::POLLIN),
        ];
        poll(&mut fds, PollTimeout::NONE)?;
        if fds[0].revents().is_some_and(|r| !r.is_empty()) {
            let mut word = String::new();
            let _ = reader.by_ref().take(MAX_REPLY).read_line(&mut word);
            if word.trim() == "{\"result\":\"expired\"}" {
                drop(reader);
                drop(stream);
                return wait_for_word(input);
            }
            return Ok(ChannelEnd::DaemonGone);
        }
        if fds[1].revents().is_some_and(|r| !r.is_empty()) {
            let mut byte = [0u8; 1];
            match nix::unistd::read(input.as_fd(), &mut byte) {
                Ok(0) | Err(_) => return Ok(ChannelEnd::InputClosed),
                Ok(_) if byte[0] == b'\n' => {
                    if said.as_slice() == b"unlocked" {
                        (&stream).write_all(b"{\"unlocked\":true}\n")?;
                        let mut ack = String::new();
                        let _ = reader.by_ref().take(MAX_REPLY).read_line(&mut ack);
                        return Ok(ChannelEnd::Unlocked);
                    }
                    said.clear();
                }
                Ok(_) if said.len() < 64 => said.push(byte[0]),
                Ok(_) => said.clear(),
            }
        }
    }
}

/// After an expired channel: hold on, with no channel, until the lock
/// screen's "unlocked" or its end, so it does not open another for this
/// lock (fix round 8).
fn wait_for_word(input: &impl AsFd) -> Result<ChannelEnd> {
    let mut said = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match nix::unistd::read(input.as_fd(), &mut byte) {
            Ok(0) | Err(_) => return Ok(ChannelEnd::Expired),
            Ok(_) if byte[0] == b'\n' => {
                if said.as_slice() == b"unlocked" {
                    return Ok(ChannelEnd::Expired);
                }
                said.clear();
            }
            Ok(_) if said.len() < 64 => said.push(byte[0]),
            Ok(_) => said.clear(),
        }
    }
}

/// From the consent window: it has drawn the request `token` names.
pub fn consent_ack(socket: &Path, user: &str, token: Option<&str>) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "consent_ack": true, "consent_token": token }),
        Some(Duration::from_secs(3)),
    )
}

/// From the consent window: the user pressed "Ready to nod".
pub fn consent_rearm(socket: &Path, user: &str, token: Option<&str>) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "consent_rearm": true, "consent_token": token }),
        None,
    )
}

/// From the consent window: with this request's approval, passwordless
/// sudo for `minutes`.
pub fn consent_passwordless(
    socket: &Path,
    user: &str,
    minutes: u32,
    token: Option<&str>,
) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "consent_passwordless": minutes, "consent_token": token }),
        Some(Duration::from_secs(3)),
    )
}

/// From the consent window: the security key's PIN for the pending
/// request, in the password's field and with its handling.
pub fn consent_key_pin(
    socket: &Path,
    user: &str,
    pin: &str,
    token: Option<&str>,
) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "consent_password": pin, "consent_key_pin": true, "consent_token": token }),
        Some(Duration::from_secs(3)),
    )
}

pub fn consent_answer(
    socket: &Path,
    user: &str,
    password: Option<&str>,
    dismiss: bool,
    token: Option<&str>,
) -> Result<Outcome> {
    let body = match password {
        Some(pw) => {
            serde_json::json!({ "user": user, "consent_password": pw, "consent_token": token })
        }
        None => {
            serde_json::json!({ "user": user, "consent_dismiss": dismiss, "consent_token": token })
        }
    };
    send(socket, body, Some(Duration::from_secs(3)))
}

/// A consent request: the reply comes when the request ends, which may be
/// at once (no window to ask in, another user's request, a standing
/// refusal) or only when the user answers. The client sets no deadline.
pub fn ask_consent(socket: &Path, user: &str) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "consent": true }),
        None,
    )
}

/// From the watched user: switch the presence watch to "default" or
/// "secure" until the daemon restarts, or "query" to read it. Answered
/// with `Outcome::PresenceMode`.
pub fn presence_mode(socket: &Path, user: &str, mode: &str) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "presence_mode": mode }),
        Some(Duration::from_secs(3)),
    )
}

pub fn ping(socket: &Path, user: &str) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "ping": true }),
        Some(Duration::from_secs(3)),
    )
}

/// Root: the enrollment walk-through; returns when it ends.
pub fn enrol_session(
    socket: &Path,
    user: &str,
    label: &str,
    start_at: Option<&str>,
) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "enrol_session": { "label": label, "start_at": start_at } }),
        Some(Duration::from_secs(16 * 60)),
    )
}

/// From the user's window: steer the running session.
pub fn enrol_control(socket: &Path, user: &str, word: &str) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "enrol_control": word }),
        Some(Duration::from_secs(3)),
    )
}

/// Root: a terminal enrollment of `poses` in order, `count` templates over
/// `seconds` each, or with none one look in any pose. One request: the
/// daemon says when it has learned the face from the straight look, and
/// `learned` is called then, before the outcome comes when the looks are
/// done.
pub fn enroll(
    socket: &Path,
    user: &str,
    label: &str,
    seconds: f32,
    count: usize,
    poses: &[&str],
    learned: &dyn Fn(),
) -> Result<Outcome> {
    let within =
        reply_within(crate::enrol::STRAIGHT_SECONDS.max(seconds * poses.len().max(1) as f32))?;
    let stream = connect_and_send(
        socket,
        serde_json::json!({ "user": user, "enroll": label, "seconds": seconds, "count": count, "enroll_poses": poses }),
        Some(within),
    )?;
    replies_until_done(&mut BufReader::new(stream), learned)
}

/// The replies on one connection until the outcome: a `Learned` line is
/// passed to `learned` and the next line read.
fn replies_until_done(reader: &mut impl BufRead, learned: &dyn Fn()) -> Result<Outcome> {
    loop {
        match next_reply(reader)? {
            Outcome::Learned => learned(),
            o => return Ok(o),
        }
    }
}

pub fn delete_templates(socket: &Path, user: &str) -> Result<Outcome> {
    send(
        socket,
        serde_json::json!({ "user": user, "delete_templates": true }),
        Some(Duration::from_secs(3)),
    )
}

/// One request and its reply. The request goes only to a listener that
/// runs as root: the socket's directory is root's, so any other listener
/// there is not the daemon, and the line may carry the user's password or
/// a consent token. The PAM module checks the same (H22).
pub fn send(socket: &Path, body: serde_json::Value, timeout: Option<Duration>) -> Result<Outcome> {
    read_reply(connect_and_send(socket, body, timeout)?)
}

/// Connect to the daemon's socket, check its listener is root, and send
/// the request; the stream, for the replies.
fn connect_and_send(
    socket: &Path,
    mut body: serde_json::Value,
    timeout: Option<Duration>,
) -> Result<UnixStream> {
    let line = request_line(&mut body);
    let mut stream = UnixStream::connect(socket)
        .map_err(ConnectFailed)
        .with_context(|| format!("connect {}", socket.display()))?;
    let peer = getsockopt(&stream, PeerCredentials).context("peer credentials")?;
    if peer.uid() != 0 {
        bail!(
            "{} is not the daemon's socket: its listener runs as uid {}, not root; nothing was sent",
            socket.display(),
            peer.uid()
        );
    }
    stream.set_read_timeout(timeout)?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    stream.write_all(line.as_bytes())?;
    Ok(stream)
}

/// The request as one line, in a `Secret` so it is wiped when dropped. The
/// body's strings, the copies `json!` made of a password or a token, are
/// wiped as soon as the line holds them (J26).
fn request_line(body: &mut serde_json::Value) -> Secret {
    let line = line_in_place(body);
    wipe_value(body);
    Secret::new(line)
}

/// The body's JSON and a newline, written into a string sized first: a
/// string that grew would leave a copy of the line in each buffer it
/// outgrew and freed.
fn line_in_place(body: &serde_json::Value) -> String {
    use std::fmt::Write as _;
    /// Counts the bytes a `Display` writes, keeping none of them.
    struct Count(usize);
    impl std::fmt::Write for Count {
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            self.0 += s.len();
            Ok(())
        }
    }
    let mut n = Count(0);
    // Neither writer can fail: one counts, the other has the room.
    let _ = write!(n, "{}", body);
    let mut line = String::with_capacity(n.0 + 1);
    let _ = writeln!(line, "{}", body);
    line
}

/// Zero every string in a request body.
fn wipe_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => wipe_string(s),
        serde_json::Value::Array(a) => a.iter_mut().for_each(wipe_value),
        serde_json::Value::Object(m) => m.values_mut().for_each(wipe_value),
        _ => {}
    }
}

/// One reply line of at most `MAX_REPLY` bytes. A line without its
/// newline, cut off by the bound or by a peer that hung up, is an error
/// rather than a partial parse.
fn read_reply(stream: impl Read) -> Result<Outcome> {
    next_reply(&mut BufReader::new(stream))
}

/// `read_reply`, one line at a time from a reader that may hold more.
fn next_reply(reader: &mut impl BufRead) -> Result<Outcome> {
    let mut line = String::new();
    reader.take(MAX_REPLY).read_line(&mut line)?;
    if line.is_empty() {
        bail!("the daemon closed the connection without a reply");
    }
    if !line.ends_with('\n') {
        bail!(
            "the daemon's reply was cut off or longer than {} bytes",
            MAX_REPLY
        );
    }
    serde_json::from_str(line.trim()).context("parse reply")
}

#[cfg(test)]
mod send_tests {
    use super::*;

    /// H22: a listener that is not root is sent nothing, since the line may
    /// carry a password. The test's own listener runs as the test's user;
    /// as root it is the daemon's peer, and the request goes through.
    #[test]
    fn a_listener_that_is_not_root_is_sent_nothing() {
        let dir = std::env::temp_dir().join(format!("faceauth-send-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let heard = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut line = String::new();
            let _ = BufReader::new(&s).read_line(&mut line);
            let _ = (&s).write_all(b"{\"result\":\"deleted\"}\n");
            line
        });
        let r = send(
            &path,
            serde_json::json!({ "user": "alice", "consent_password": "hunter2" }),
            Some(Duration::from_secs(5)),
        );
        let line = heard.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        if nix::unistd::getuid().is_root() {
            assert_eq!(r.unwrap(), Outcome::Deleted);
            return;
        }
        let e = r.unwrap_err().to_string();
        assert!(
            e.contains("not root") && e.contains("nothing was sent"),
            "{}",
            e
        );
        assert!(line.is_empty(), "the listener heard {:?}", line);
    }

    /// The fingerprint lane's question tells "faceauth is not running" from
    /// every other failure, as the key lane's does.
    #[test]
    fn fprint_lane_says_when_faceauth_is_not_running() {
        let dir =
            std::env::temp_dir().join(format!("faceauth-fprintlane-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sock");
        assert_eq!(fprint_lane(&path, "alice").unwrap(), Outcome::NotRunning);
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert_eq!(fprint_lane(&path, "alice").unwrap(), Outcome::NotRunning);
        std::fs::remove_file(&path).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut line = String::new();
            let _ = BufReader::new(&s).read_line(&mut line);
            drop(s);
            line
        });
        let r = fprint_lane(&path, "alice");
        let line = server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(r.is_err(), "{:?}", r);
        assert!(
            line.is_empty(),
            "nothing goes to a listener that is not root: {:?}",
            line
        );
    }

    /// Round 5 (C): the lock screen's key-lane ask tells "faceauth is not
    /// running" (its socket missing, or nothing listening on it) from
    /// every other failure, which stays an error: a listener that is not
    /// root, a reply cut short.
    #[test]
    fn key_lane_says_when_faceauth_is_not_running() {
        let dir =
            std::env::temp_dir().join(format!("faceauth-keylane-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sock");
        assert_eq!(
            key_lane(&path, "alice").unwrap(),
            Outcome::NotRunning,
            "no socket"
        );
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        assert_eq!(
            key_lane(&path, "alice").unwrap(),
            Outcome::NotRunning,
            "nothing listening"
        );
        std::fs::remove_file(&path).unwrap();
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut line = String::new();
            let _ = BufReader::new(&s).read_line(&mut line);
            drop(s);
        });
        // Not root (the test's own listener) or a reply cut short: an error.
        let r = key_lane(&path, "alice");
        server.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(r.is_err(), "{:?}", r);
        assert_eq!(
            serde_json::to_string(&Outcome::NotRunning).unwrap(),
            "{\"result\":\"not_running\"}"
        );
    }

    /// Round 7 (B): the lock screen's channel, from the CLI's side. It
    /// opens for the user, holds until the lock screen writes "unlocked"
    /// on its stdin, sends the graceful word and ends; stdin closing (the
    /// lock screen gone) ends it without the word, and the daemon's side
    /// closing ends it so the lock screen opens another.
    #[test]
    fn the_lock_channel_holds_until_the_unlock_or_a_drop() {
        use std::io::{BufRead, BufReader, Write};
        let run = |input_lines: &'static [u8], daemon_closes: bool| {
            let (client, daemon) = UnixStream::pair().unwrap();
            let (mut feed, input) = UnixStream::pair().unwrap();
            let fake = std::thread::spawn(move || {
                let mut r = BufReader::new(daemon.try_clone().unwrap());
                let mut lines = Vec::new();
                let mut l = String::new();
                r.read_line(&mut l).unwrap();
                lines.push(l.clone());
                (&daemon)
                    .write_all(b"{\"result\":\"channel_open\"}\n")
                    .unwrap();
                if daemon_closes {
                    drop(daemon);
                    return lines;
                }
                l.clear();
                if r.read_line(&mut l).unwrap_or(0) > 0 {
                    lines.push(l.clone());
                    let _ = (&daemon).write_all(b"{\"result\":\"noted\"}\n");
                }
                lines
            });
            let feeder = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(50));
                let _ = feed.write_all(input_lines);
                // Closing the lock screen's end.
            });
            let end = lock_channel_on(client, "alice", &input).unwrap();
            feeder.join().unwrap();
            (end, fake.join().unwrap())
        };
        let (end, lines) = run(b"unlocked\n", false);
        assert_eq!(end, ChannelEnd::Unlocked);
        assert_eq!(lines[0], "{\"lock_channel\":true,\"user\":\"alice\"}\n");
        assert_eq!(lines[1], "{\"unlocked\":true}\n");
        let (end, lines) = run(b"", false);
        assert_eq!(end, ChannelEnd::InputClosed, "the lock screen gone: a drop");
        assert_eq!(lines.len(), 1, "no graceful word");
        let (end, _) = run(b"", true);
        assert!(matches!(
            end,
            ChannelEnd::DaemonGone | ChannelEnd::InputClosed
        ));
    }

    /// Fix round 8: a channel the daemon expired (the compositor said
    /// unlocked for a while) leaves the CLI waiting on the lock screen's
    /// word with no channel, so the lock screen, which sees it still
    /// running, does not open another until its next lock.
    #[test]
    fn an_expired_channel_waits_for_the_lock_screens_word() {
        use std::io::{BufRead, BufReader, Write};
        let (client, daemon) = UnixStream::pair().unwrap();
        let (mut feed, input) = UnixStream::pair().unwrap();
        let fake = std::thread::spawn(move || {
            let mut r = BufReader::new(daemon.try_clone().unwrap());
            let mut l = String::new();
            r.read_line(&mut l).unwrap();
            (&daemon)
                .write_all(b"{\"result\":\"channel_open\"}\n")
                .unwrap();
            std::thread::sleep(Duration::from_millis(30));
            (&daemon).write_all(b"{\"result\":\"expired\"}\n").unwrap();
        });
        let t0 = std::time::Instant::now();
        let feeder = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let _ = feed.write_all(b"unlocked\n");
        });
        let end = lock_channel_on(client, "alice", &input).unwrap();
        assert_eq!(end, ChannelEnd::Expired);
        assert!(
            t0.elapsed() >= Duration::from_millis(250),
            "it waited for the word"
        );
        feeder.join().unwrap();
        fake.join().unwrap();
    }

    /// H22: the reply is read up to `MAX_REPLY` bytes and must end in its
    /// newline: a longer one, one cut short and none at all are errors.
    #[test]
    fn a_reply_over_the_bound_or_cut_short_is_an_error() {
        assert_eq!(
            read_reply(&b"{\"result\":\"deleted\"}\n"[..]).unwrap(),
            Outcome::Deleted
        );
        let long = format!(
            "{{\"result\":\"error\",\"message\":\"{}\"}}\n",
            "x".repeat(MAX_REPLY as usize)
        );
        let e = read_reply(long.as_bytes()).unwrap_err().to_string();
        assert!(e.contains("longer than"), "{}", e);
        assert!(read_reply(&b"{\"result\":\"deleted\"}"[..]).is_err());
        assert!(read_reply(&b""[..]).is_err());
    }

    /// J26: the line is written into a string that never grows, so no
    /// outgrown buffer keeps a copy, and every string in the body is wiped
    /// once the line holds it.
    #[test]
    fn the_request_line_is_built_in_place_and_the_body_is_wiped() {
        let mut body = serde_json::json!({
            "user": "alice",
            "consent_password": "p\"w\\\u{1}d",
            "consent_token": "0123456789abcdef",
        });
        let want = format!("{}\n", body);
        let line = line_in_place(&body);
        assert_eq!(line, want);
        assert_eq!(line.capacity(), line.len(), "sized once, never grown");
        let line = request_line(&mut body);
        assert_eq!(&*line, want);
        for key in ["user", "consent_password", "consent_token"] {
            assert_eq!(body[key], "", "{} was left in the body", key);
        }
    }
}

#[cfg(test)]
mod wait_tests {
    use super::reply_within;
    use std::time::Duration;

    /// The root CLI's wait for a reply is refused, not panicked on, for a
    /// length that is not a number of seconds a request runs.
    #[test]
    fn a_wait_that_is_not_a_length_is_refused_not_a_panic() {
        assert_eq!(reply_within(12.0).unwrap(), Duration::from_secs(27));
        for bad in [f32::NAN, -100.0, 1e30, f32::INFINITY] {
            assert!(reply_within(bad).is_err(), "{}", bad);
        }
    }
}

#[cfg(test)]
mod enroll_reply_tests {
    use super::*;

    /// A6: the terminal enrollment's connection says when the face is
    /// learned, before its outcome; the terminal hears of it then and
    /// reads on to the outcome.
    #[test]
    fn the_learned_line_comes_before_the_outcome() {
        let heard = std::cell::Cell::new(0);
        let learned = || heard.set(heard.get() + 1);
        let mut replies: &[u8] =
            b"{\"result\":\"learned\"}\n{\"result\":\"error\",\"message\":\"x\"}\n";
        let o = replies_until_done(&mut replies, &learned).unwrap();
        assert!(matches!(o, Outcome::Error { .. }), "{:?}", o);
        assert_eq!(heard.get(), 1);
        let mut outcome_only: &[u8] = b"{\"result\":\"deleted\"}\n";
        assert_eq!(
            replies_until_done(&mut outcome_only, &learned).unwrap(),
            Outcome::Deleted
        );
        assert_eq!(heard.get(), 1);
        let mut cut: &[u8] = b"{\"result\":\"learned\"}\n";
        assert!(replies_until_done(&mut cut, &learned).is_err());
    }
}
