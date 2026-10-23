//! Reading the request line. It is bounded in size and in time before
//! anything is authorized, so a slow or oversized peer holds a connection
//! place for a few seconds at most.

use anyhow::Result;
#[cfg(test)]
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

/// Longest request line accepted, before any authorization.
const MAX_REQUEST: u64 = 4096;

/// The whole request line must arrive within this, however slowly its
/// bytes come: a peer feeding one byte per read timeout would otherwise
/// hold a connection slot for as long as it liked.
pub(super) const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// Read one line of at most `MAX_REQUEST` bytes within `REQUEST_DEADLINE`.
/// The line may carry a password (F12): it is read into a buffer sized
/// once for the longest line, so no copy is left in a buffer it outgrew,
/// and every way out but the line itself wipes what was read.
pub(super) fn read_request(stream: &mut UnixStream) -> Result<Option<String>> {
    let mut buf = line_buffer();
    let read = read_line_into(stream, &mut buf);
    settle(&mut buf, read)
}

/// The buffer a request line is read into: room for the longest line
/// from the start, so reading never moves it.
fn line_buffer() -> Vec<u8> {
    Vec::with_capacity(MAX_REQUEST as usize)
}

/// Read bytes into `buf` up to and including a newline: true when the
/// line is whole, false when it ran past `MAX_REQUEST` bytes, the peer
/// closed, or the deadline passed first. `buf` never grows past its
/// capacity when that is `MAX_REQUEST`, so it is never reallocated.
fn read_line_into(stream: &mut UnixStream, buf: &mut Vec<u8>) -> Result<bool> {
    use std::io::Read;
    let start = Instant::now();
    let mut byte = [0u8; 1];
    loop {
        let left = REQUEST_DEADLINE.saturating_sub(start.elapsed());
        if left.is_zero() {
            return Ok(false);
        }
        stream.set_read_timeout(Some(left))?;
        match stream.read(&mut byte) {
            Ok(0) => return Ok(false),
            Ok(_) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    return Ok(true);
                }
                if buf.len() as u64 >= MAX_REQUEST {
                    return Ok(false);
                }
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(false)
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

/// The line in `buf` as a string when `read` found one whole, moved out of
/// the buffer rather than copied; otherwise the bytes read are wiped. A
/// line that is not UTF-8 is refused and wiped too: every caller writes
/// UTF-8, and a lossy copy would be built in a buffer that grows.
fn settle(buf: &mut Vec<u8>, read: Result<bool>) -> Result<Option<String>> {
    if matches!(read, Ok(true)) {
        match String::from_utf8(std::mem::take(buf)) {
            Ok(line) => return Ok(Some(line)),
            Err(e) => *buf = e.into_bytes(),
        }
    }
    crate::consent::wipe_bytes(buf);
    read.map(|_| None)
}

/// The one field of a request that may carry a password.
const PASSWORD_KEY: &str = "consent_password";

/// Take the consent password out of the request `line` by hand, before
/// the line is parsed (F12). The parser un-escapes a string holding a `"`
/// or a `\` into a scratch buffer that grows as it goes and is freed
/// unwiped, which would leave the password in the daemon's freed memory.
/// So the field's value is un-escaped here, into a string sized once for
/// it, and its bytes in the line are overwritten with spaces, which the
/// parser then reads as a string with nothing to un-escape. `Ok(None)`
/// when the line has no such field at its top level. An error, before
/// the parser sees the line at all, for any shape the parser would read a
/// password out of without this scan finding it: a line that is not an
/// object (the parser takes a request written as an array, by position),
/// or a top-level key written with an escape (the parser reads
/// `consent\u005fpassword` as the field). An error too for a line whose
/// strings do not end or whose password is not a well-formed string.
pub(super) fn take_password(
    line: &mut String,
) -> std::result::Result<Option<crate::consent::Secret>, ()> {
    let b = line.as_bytes();
    if b.get(skip_space(b, 0)) != Some(&b'{') {
        return Err(());
    }
    let (mut i, mut depth, mut key_next) = (0usize, 0usize, false);
    while i < b.len() {
        match b[i] {
            b'"' => {
                let end = string_end(b, i)?;
                if depth == 1 && key_next && b[i + 1..end].contains(&b'\\') {
                    return Err(());
                }
                if depth == 1 && key_next && &line[i + 1..end] == PASSWORD_KEY {
                    let mut j = skip_space(b, end + 1);
                    if b.get(j) != Some(&b':') {
                        return Err(());
                    }
                    j = skip_space(b, j + 1);
                    if b[j..].starts_with(b"null") {
                        return Ok(None);
                    }
                    if b.get(j) != Some(&b'"') {
                        return Err(());
                    }
                    let value_end = string_end(b, j)?;
                    let pw = unescape(&line[j + 1..value_end])?;
                    // SAFETY: the value's bytes all become spaces, so the
                    // line stays valid UTF-8.
                    let bytes = unsafe { line.as_mut_vec() };
                    bytes[j + 1..value_end].fill(b' ');
                    return Ok(Some(crate::consent::Secret::new(pw)));
                }
                key_next = false;
                i = end;
            }
            b'{' => {
                depth += 1;
                key_next = depth == 1;
            }
            b'[' => depth += 1,
            b'}' | b']' => depth = depth.saturating_sub(1),
            b',' => key_next = depth == 1,
            _ => {}
        }
        i += 1;
    }
    Ok(None)
}

/// The index of the quote that ends the string opening at `start`.
fn string_end(b: &[u8], start: usize) -> std::result::Result<usize, ()> {
    let mut i = start + 1;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'"' => return Ok(i),
            _ => i += 1,
        }
    }
    Err(())
}

fn skip_space(b: &[u8], mut i: usize) -> usize {
    while b
        .get(i)
        .is_some_and(|c| matches!(c, b' ' | b'\t' | b'\r' | b'\n'))
    {
        i += 1;
    }
    i
}

/// A JSON string's contents, `raw`, un-escaped into a string sized for
/// `raw` from the start. An escape is never shorter than what it stands
/// for, so the string never outgrows that and is never moved; what was
/// written is wiped if the escapes turn out not to be well formed.
fn unescape(raw: &str) -> std::result::Result<String, ()> {
    let mut out = String::with_capacity(raw.len());
    let hex4 = |it: &mut std::str::Chars| -> Option<u32> {
        let mut v = 0;
        for _ in 0..4 {
            v = v * 16 + it.next()?.to_digit(16)?;
        }
        Some(v)
    };
    let mut it = raw.chars();
    let ok = (|| -> Option<()> {
        while let Some(c) = it.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            let c = match it.next()? {
                '"' => '"',
                '\\' => '\\',
                '/' => '/',
                'b' => '\u{8}',
                'f' => '\u{c}',
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                'u' => {
                    let hi = hex4(&mut it)?;
                    let code = if (0xd800..0xdc00).contains(&hi) {
                        if it.next()? != '\\' || it.next()? != 'u' {
                            return None;
                        }
                        let lo = hex4(&mut it)?;
                        if !(0xdc00..0xe000).contains(&lo) {
                            return None;
                        }
                        0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
                    } else {
                        hi
                    };
                    char::from_u32(code)?
                }
                _ => return None,
            };
            out.push(c);
        }
        Some(())
    })();
    match ok {
        Some(()) => Ok(out),
        None => {
            crate::consent::wipe_string(&mut out);
            Err(())
        }
    }
}

#[cfg(test)]
mod password_tests {
    use super::*;

    /// F12: the password is taken out of the line by hand, `"` and `\`
    /// and the other escapes included, into a string that never grew; its
    /// bytes in the line become spaces, which the parser reads with nothing
    /// to un-escape, so it builds no copy of its own.
    #[test]
    fn the_password_is_taken_out_of_the_line_before_the_parse() {
        let pw = "p\"w\\d \u{1}\u{e9}\u{1f600}/";
        let body =
            serde_json::json!({ "user": "alice", "consent_password": pw, "consent_token": "t" });
        let mut line = format!("{}\n", body);
        let taken = take_password(&mut line).unwrap().expect("the password");
        assert_eq!(&*taken, pw);
        assert!(!line.contains("p\\\"w"), "{}", line);
        let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let left = v["consent_password"].as_str().unwrap();
        assert!(
            left.bytes().all(|c| c == b' ') && !left.is_empty(),
            "{:?}",
            left
        );
        assert_eq!(v["user"], "alice");
        assert_eq!(v["consent_token"], "t");

        // Sized once: an escape is never shorter than what it stands for.
        let raw = r#"a\"b\\c\u00e9\ud83d\ude00"#;
        let out = unescape(raw).unwrap();
        assert_eq!(out, "a\"b\\c\u{e9}\u{1f600}");
        assert_eq!(out.capacity(), raw.len(), "the string was moved");

        // Only the top-level field counts, and a key-like value is a value.
        let mut elsewhere =
            r#"{"user":"consent_password","enrol_session":{"consent_password":"x"}}"#.to_string();
        assert_eq!(take_password(&mut elsewhere), Ok(None));
        assert!(elsewhere.contains(r#""consent_password":"x""#));
        let mut none = r#"{"user":"alice","consent_password":null}"#.to_string();
        assert_eq!(take_password(&mut none), Ok(None));
        // The shapes the parser would read a password out of that this
        // scan does not look in are refused before the parser runs: a
        // request written as an array, by position, and a top-level key
        // written with an escape, before or after the plain one.
        for odd in [
            r#"["alice",false,null,"p\"w"]"#,
            r#"  ["alice"]"#,
            r#""alice""#,
            r#"{"user":"alice","consent\u005fpassword":"B\"x"}"#,
            r#"{"consent\u005fpassword":"B\"x","consent_password":"A"}"#,
            r#"{"us\u0065r":"alice"}"#,
        ] {
            assert!(take_password(&mut odd.to_string()).is_err(), "{}", odd);
        }
        // An escape in a value, or in a key of a nested object, is not a
        // key of the request's own.
        let mut fine = r#" {"user":"a\"b","enrol_session":{"l\u0061bel":"x"}}"#.to_string();
        assert_eq!(take_password(&mut fine), Ok(None));
        for bad in [
            r#"{"consent_password":"unterminated}"#,
            r#"{"consent_password":"\q"}"#,
            r#"{"consent_password":"\ud83d"}"#,
            r#"{"consent_password":7}"#,
        ] {
            assert!(take_password(&mut bad.to_string()).is_err(), "{}", bad);
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

    /// F12: the longest line, and a line past the limit, are read into
    /// the one buffer the reader starts with: it is never outgrown, so
    /// no copy of a password is left in a buffer it moved out of.
    #[test]
    fn the_line_buffer_is_never_outgrown() {
        for (len, whole) in [
            (MAX_REQUEST as usize - 1, true),
            (MAX_REQUEST as usize + 50, false),
        ] {
            let (mut a, mut b) = UnixStream::pair().unwrap();
            let mut line = vec![b'x'; len];
            if whole {
                line.push(b'\n');
            }
            a.write_all(&line).unwrap();
            drop(a);
            let mut buf = line_buffer();
            let at = buf.as_ptr();
            assert_eq!(read_line_into(&mut b, &mut buf).unwrap(), whole);
            assert_eq!(buf.len(), MAX_REQUEST as usize);
            assert_eq!(buf.as_ptr(), at, "the buffer moved");
        }
    }

    /// F12: a whole line leaves the reader as the string, in the buffer it
    /// was read into, with no copy made; every other way out (a line cut
    /// short, a read error, a line that is not UTF-8) wipes the bytes read
    /// where they lie.
    #[test]
    fn the_bytes_read_leave_as_the_line_or_are_wiped() {
        let said = b"{\"user\":\"x\",\"consent_password\":\"hunter2\"}";
        let mut buf = line_buffer();
        buf.extend_from_slice(said);
        buf.push(b'\n');
        let at = buf.as_ptr();
        let line = settle(&mut buf, Ok(true)).unwrap().expect("the line");
        assert_eq!(line.as_ptr(), at, "the line was copied");
        assert!(buf.is_empty());
        let not_utf8 = [&said[..], b"\xff\n"].concat();
        for (bytes, read) in [
            (&said[..], Ok(false)),
            (&said[..], Err(anyhow::anyhow!("connection reset"))),
            (&not_utf8[..], Ok(true)),
        ] {
            let mut buf = line_buffer();
            buf.extend_from_slice(bytes);
            let (at, n) = (buf.as_ptr(), buf.len());
            let failed = read.is_err();
            let r = settle(&mut buf, read);
            assert_eq!(r.is_err(), failed);
            assert!(matches!(r, Ok(None) | Err(_)), "no line from {:?}", bytes);
            assert_eq!(buf.as_ptr(), at, "the wipe reached the buffer read into");
            // SAFETY: `at` is `buf`'s own allocation, still held, and its
            // first `n` bytes were written by the read and then by the wipe.
            let left = unsafe { std::slice::from_raw_parts(at, n) };
            assert!(left.iter().all(|b| *b == 0), "left: {:?}", left);
        }
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
