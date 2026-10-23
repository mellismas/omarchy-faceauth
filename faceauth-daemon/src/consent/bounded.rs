//! A command run into the user's session, or into a unit, with a deadline
//! and a cap on what it writes (fix round 10, Codex 2, Opus N4): the end of
//! a pipe is never waited for, since PID 1, a carrier unit or a user unit
//! may hold it open long after the launcher is gone.

use std::time::{Duration, Instant};

/// How a bounded run ended: its exit code (None when a signal ended it),
/// what it wrote to stdout and stderr, each up to the cap, and whether
/// either went past it.
#[derive(Debug)]
pub struct Ran {
    pub code: Option<i32>,
    pub out: Vec<u8>,
    pub err: Vec<u8>,
    pub overflowed: bool,
}

/// Why a bounded run gave no answer.
#[derive(Debug)]
pub enum Unfinished {
    /// It could not be started.
    NotStarted(std::io::Error),
    /// It was given up at its deadline, what it started killed.
    Expired(Duration),
}

impl std::fmt::Display for Unfinished {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unfinished::NotStarted(e) => write!(f, "did not start: {}", e),
            Unfinished::Expired(d) => write!(f, "did not finish within {:?}; given up", d),
        }
    }
}

/// Run `c` in a process group of its own, with `stdin` written to it (then
/// closed) or nothing on stdin, for at most `within`. Its output is read
/// as it comes and kept up to `cap` bytes on each stream; past the cap it
/// is read and dropped, so a writer never blocks on us, and `overflowed`
/// says so. The run is over when `c` itself exits: what it wrote is in the
/// pipes by then, and whoever else still holds them (PID 1 for a `--pipe`
/// unit until it is collected, a unit of the user's, a process the command
/// left behind) is never waited for. Past the deadline the run's process
/// group is killed, its leader reaped, the pipes closed, and the run gave
/// nothing (`Expired`). A command whose file another process still holds
/// open for writing (ETXTBSY: a child of another thread of this process,
/// forked while the file was being written, that has not yet exec'd) is
/// tried again until the deadline; any other failure to start is
/// `NotStarted`.
pub fn run_bounded(
    mut c: std::process::Command,
    stdin: Option<&[u8]>,
    within: Duration,
    cap: usize,
) -> Result<Ran, Unfinished> {
    use std::io::{Read, Write};
    use std::os::unix::process::CommandExt;
    use std::process::Stdio;
    let by = Instant::now() + within;
    c.stdin(if stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .process_group(0);
    // The leader's own pidfd, taken before its exec, through which its
    // group is killed (fix round 13, Codex 1; `crate::child`).
    let spawner = crate::child::Spawner::arm(&mut c).map_err(Unfinished::NotStarted)?;
    let (mut child, pidfd) = loop {
        match spawner.spawn(&mut c) {
            Ok(run) => break run,
            Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) && Instant::now() < by => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => return Err(Unfinished::NotStarted(e)),
        }
    };
    let (Some(mut out_pipe), Some(mut err_pipe)) = (child.stdout.take(), child.stderr.take())
    else {
        kill_group(&pidfd, &mut child);
        return Err(Unfinished::NotStarted(std::io::Error::other("no pipes")));
    };
    let mut in_pipe = child.stdin.take();
    for fd in [
        Some(std::os::fd::AsRawFd::as_raw_fd(&out_pipe)),
        Some(std::os::fd::AsRawFd::as_raw_fd(&err_pipe)),
        in_pipe.as_ref().map(std::os::fd::AsRawFd::as_raw_fd),
    ]
    .into_iter()
    .flatten()
    {
        nonblocking(fd);
    }
    let mut pending = stdin.unwrap_or_default();
    let mut ran = Ran {
        code: None,
        out: Vec::new(),
        err: Vec::new(),
        overflowed: false,
    };
    let mut buf = [0u8; 4096];
    // One read of at most a buffer from a stream: whether it gave
    // anything. Past the cap the bytes are read and dropped, so a writer
    // never blocks on us.
    let mut read_once = |pipe: &mut dyn Read, kept: &mut Vec<u8>, overflowed: &mut bool| match pipe
        .read(&mut buf)
    {
        Ok(0) | Err(_) => false,
        Ok(n) => {
            let room = cap.saturating_sub(kept.len());
            kept.extend_from_slice(&buf[..n.min(room)]);
            if n > room {
                *overflowed = true;
            }
            true
        }
    };
    // After the command exits, what it wrote is in the pipes: read up to
    // the cap and a buffer more on each, and no further, however much
    // anyone else still holding them writes (fix round 11, Opus N1).
    let last_reads = cap / 4096 + 2;
    loop {
        // The payload goes in as the command takes it; once it is all in,
        // or the command will not take more, stdin is closed.
        if let Some(pipe) = in_pipe.as_mut() {
            match pipe.write(pending) {
                Ok(n) if n < pending.len() => pending = &pending[n..],
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                _ => in_pipe = None,
            }
        }
        // One read per stream per pass, so writers that keep a pipe full
        // never hold the loop past the deadline below (fix round 11, Opus
        // N1, Codex 7).
        let got = read_once(&mut out_pipe, &mut ran.out, &mut ran.overflowed)
            | read_once(&mut err_pipe, &mut ran.err, &mut ran.overflowed);
        match child.try_wait() {
            Ok(Some(status)) => {
                // Reaped, so its group is not signalled now; what it wrote
                // is in the pipes, read to a bound, and nothing more of the
                // run's is read.
                for _ in 0..last_reads {
                    if !(read_once(&mut out_pipe, &mut ran.out, &mut ran.overflowed)
                        | read_once(&mut err_pipe, &mut ran.err, &mut ran.overflowed))
                    {
                        break;
                    }
                }
                ran.code = status.code();
                return Ok(ran);
            }
            Ok(None) if Instant::now() < by => {
                if !got {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            _ => {
                kill_group(&pidfd, &mut child);
                return Err(Unfinished::Expired(within));
            }
        }
    }
}

fn nonblocking(fd: std::os::fd::RawFd) {
    // SAFETY: fcntl on a descriptor this process owns.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }
}

/// Kill the process group this run made (and only it), through its
/// leader's own pidfd (fix round 13, Codex 1: never by a number), and reap
/// the leader.
fn kill_group(pidfd: &std::os::fd::OwnedFd, child: &mut std::process::Child) {
    crate::child::kill_group(pidfd);
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> std::process::Command {
        let mut c = std::process::Command::new("/bin/sh");
        c.args(["-c", script]);
        c
    }

    /// The run is over when the launcher exits, whoever still holds its
    /// pipes; one that never exits is given up at the deadline with its
    /// process group killed and its pipes closed; what it writes is capped;
    /// a payload reaches its stdin.
    #[test]
    fn a_run_is_bounded_by_its_deadline_and_its_cap() {
        let t0 = Instant::now();
        let ran = run_bounded(
            sh("printf abc; sleep 5 & exit 0"),
            None,
            Duration::from_secs(2),
            64,
        )
        .unwrap();
        assert_eq!(
            (ran.code, ran.out.as_slice(), ran.overflowed),
            (Some(0), &b"abc"[..], false)
        );
        assert!(
            t0.elapsed() < Duration::from_millis(700),
            "never at the pipe's end: {:?}",
            t0.elapsed()
        );
        let t0 = Instant::now();
        let held = run_bounded(
            sh("sleep 30 & exec sleep 30"),
            None,
            Duration::from_millis(300),
            64,
        );
        assert!(
            matches!(held, Err(Unfinished::Expired(_))),
            "no answer at the deadline"
        );
        assert!(
            t0.elapsed() < Duration::from_millis(800),
            "{:?}",
            t0.elapsed()
        );
        let big = run_bounded(
            sh("head -c 100000 /dev/zero"),
            None,
            Duration::from_secs(5),
            1000,
        )
        .unwrap();
        assert!(big.overflowed && big.out.len() <= 1000);
        let echo = run_bounded(sh("cat"), Some(b"payload"), Duration::from_secs(2), 64).unwrap();
        assert_eq!(echo.out, b"payload");
        let err = run_bounded(
            sh("echo nope >&2; exit 3"),
            None,
            Duration::from_secs(2),
            64,
        )
        .unwrap();
        assert_eq!((err.code, err.err.as_slice()), (Some(3), &b"nope\n"[..]));
        let missing = std::process::Command::new("/nonexistent/faceauth-test");
        assert!(matches!(
            run_bounded(missing, None, Duration::from_secs(2), 64),
            Err(Unfinished::NotStarted(_))
        ));
    }

    /// Fix round 11 (Opus N1, Codex 7; Opus's flooding probe): writers
    /// that keep the pipe full, in a process group of their own where the
    /// deadline's kill cannot reach them (as a unit of the user's holding
    /// the daemon's stdout through `--pipe` would), do not keep the run
    /// past its deadline: each pass reads each stream once and checks the
    /// deadline. They die of the closed pipe once it is given up.
    #[test]
    fn writers_that_keep_the_pipe_full_do_not_outrun_the_deadline() {
        let flood = "for i in 1 2 3 4 5 6; do /usr/bin/setsid /bin/sh -c 'exec /usr/bin/yes floodfloodflood' & done; exec sleep 30";
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let t0 = Instant::now();
            let ran = run_bounded(sh(flood), None, Duration::from_millis(300), 4096);
            let _ = tx.send((ran.is_err(), t0.elapsed()));
        });
        let (expired, took) = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the run came back, not stuck reading");
        assert!(expired, "given up at the deadline");
        assert!(took < Duration::from_millis(1500), "{:?}", took);
    }
}
