//! Reading the request line. It is bounded in size and in time before
//! anything is authorised, so a slow or oversized peer holds a connection
//! place for a few seconds at most.

use anyhow::Result;
#[cfg(test)]
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// Longest request line accepted, before any authorisation.
const MAX_REQUEST: u64 = 4096;

/// The whole request line must arrive within this, however slowly its
/// bytes come: a peer feeding one byte per read timeout would otherwise
/// hold a connection slot for as long as it liked.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// Read one line of at most `MAX_REQUEST` bytes within `REQUEST_DEADLINE`.
pub(super) fn read_request(stream: &mut UnixStream) -> Result<Option<String>> {
    use std::io::Read;
    let start = Instant::now();
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let left = REQUEST_DEADLINE.saturating_sub(start.elapsed());
        if left.is_zero() {
            return Ok(None);
        }
        stream.set_read_timeout(Some(left))?;
        match stream.read(&mut byte) {
            Ok(0) => return Ok(None),
            Ok(_) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
                }
                if buf.len() as u64 >= MAX_REQUEST {
                    return Ok(None);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(None)
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

#[cfg(test)]
mod request_read_tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn a_whole_line_is_read() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(b"{\"user\":\"x\"}\n").unwrap();
        assert_eq!(
            read_request(&mut b).unwrap().as_deref(),
            Some("{\"user\":\"x\"}\n")
        );
    }

    #[test]
    fn a_line_over_the_limit_or_without_a_newline_is_refused() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(&vec![b'x'; MAX_REQUEST as usize + 10]).unwrap();
        assert_eq!(read_request(&mut b).unwrap(), None);
        let (mut a, mut b) = UnixStream::pair().unwrap();
        a.write_all(b"no newline").unwrap();
        drop(a);
        assert_eq!(read_request(&mut b).unwrap(), None);
    }

    /// The deadline is for the whole line: bytes that keep arriving do not
    /// keep resetting it.
    #[test]
    fn dribbled_bytes_do_not_stretch_the_deadline() {
        let (mut a, mut b) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            for _ in 0..40 {
                if a.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
        });
        let start = Instant::now();
        assert_eq!(read_request(&mut b).unwrap(), None);
        let took = start.elapsed();
        assert!(
            took >= REQUEST_DEADLINE - Duration::from_millis(100)
                && took < REQUEST_DEADLINE + Duration::from_secs(1),
            "took {:?}",
            took
        );
        drop(b);
        writer.join().unwrap();
    }
}
