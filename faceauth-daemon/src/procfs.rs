//! What the daemon reads about a process from /proc: one reader each for
//! the consent card's description of a requester and the socket's
//! locality check. Every read fails soft, as None, for a process that is
//! gone or a file that cannot be read; the callers decide what that means.

/// The most of a command line the daemon reads (fix round 11, Codex 1).
/// A process can make its command line as long as it likes: where the
/// kernel is built with checkpoint/restore, `prctl(PR_SET_MM, PR_SET_MM_MAP)`
/// lets an unprivileged process point its argument area at any mapping of
/// its own (kernel/sys.c, `prctl_set_mm_map`), and reading
/// `/proc/<pid>/cmdline` copies that area out page by page as it is read
/// (fs/proc/base.c, `get_mm_cmdline`). Read whole, it could exhaust the
/// daemon's memory and restart it on demand. The card shows far less
/// (`consent::COMMAND_CLIP`).
pub(crate) const CMDLINE_CAP: usize = 64 << 10;

/// The cap for one `/proc/<pid>` file, before anything is allocated:
/// `status` and `cgroup` are a few hundred bytes in use (a cgroup path is
/// at most a page per hierarchy), `stat` well under a kilobyte, `comm`
/// 16 bytes, `loginuid` a number.
fn cap_of(what: &str) -> usize {
    match what {
        "cmdline" => CMDLINE_CAP,
        "status" | "cgroup" => 16 << 10,
        "stat" => 4 << 10,
        "comm" | "loginuid" => 64,
        _ => 4 << 10,
    }
}

/// A capped read: the text, NULs as spaces and trimmed, and whether the
/// file went on past the cap.
#[derive(Debug, PartialEq)]
pub(crate) struct Shown {
    pub text: String,
    pub truncated: bool,
}

/// `/proc/<pid>/<what>` under `root`, read to at most its cap.
fn read_capped(root: &std::path::Path, pid: i32, what: &str) -> Option<Shown> {
    use std::io::Read;
    let cap = cap_of(what);
    let file = std::fs::File::open(root.join(pid.to_string()).join(what)).ok()?;
    let mut bytes = Vec::with_capacity(cap.min(4096));
    file.take(cap as u64 + 1).read_to_end(&mut bytes).ok()?;
    let truncated = bytes.len() > cap;
    bytes.truncate(cap);
    Some(Shown {
        text: String::from_utf8_lossy(&bytes)
            .replace('\0', " ")
            .trim()
            .to_string(),
        truncated,
    })
}

/// `read_capped` for parsing: a file that ran past its cap is not read at
/// all, since its last line, or its last field, is cut.
fn read_at(root: &std::path::Path, pid: i32, what: &str) -> Option<String> {
    read_capped(root, pid, what)
        .filter(|s| !s.truncated)
        .map(|s| s.text)
}

/// `read_capped` for display: the text up to the cap, and whether it was
/// cut there, which the card says.
fn read_shown_at(root: &std::path::Path, pid: i32, what: &str) -> Option<Shown> {
    read_capped(root, pid, what)
}

/// `/proc/<pid>/<what>` as text, NULs as spaces and trimmed, for parsing;
/// None for a process gone, a file unreadable, or one longer than its cap.
pub(crate) fn read(pid: i32, what: &str) -> Option<String> {
    read_at(std::path::Path::new("/proc"), pid, what)
}

/// `/proc/<pid>/<what>` for display: up to its cap, marked when cut.
pub(crate) fn read_shown(pid: i32, what: &str) -> Option<Shown> {
    read_shown_at(std::path::Path::new("/proc"), pid, what)
}

/// The real uid, from `status`.
pub(crate) fn real_uid(pid: i32) -> Option<u32> {
    read(pid, "status")?
        .lines()
        .find_map(|l| l.strip_prefix("Uid:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|s| s.parse().ok())
}

/// The parent pid, from `stat`.
pub(crate) fn ppid(pid: i32) -> Option<i32> {
    let stat = read(pid, "stat")?;
    // "pid (comm) state ppid ..."; comm may contain spaces, so split after the last ')'.
    let rest = stat.rsplit(')').next()?;
    rest.split_whitespace().nth(1)?.parse().ok()
}

/// When the process started, as time since boot (suspend included):
/// `stat`'s field 22, in clock ticks of the kernel's `start_boottime`.
pub(crate) fn started_since_boot(pid: i32) -> Option<std::time::Duration> {
    let stat = read(pid, "stat")?;
    let rest = stat.rsplit(')').next()?;
    // Field 3 (state) is the first after the comm; field 22 is the 20th.
    let ticks: u64 = rest.split_whitespace().nth(19)?.parse().ok()?;
    // SAFETY: sysconf takes a constant and has no preconditions.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz <= 0 {
        return None;
    }
    let hz = hz as u64;
    Some(
        std::time::Duration::from_secs(ticks / hz)
            + std::time::Duration::from_nanos((ticks % hz) * 1_000_000_000 / hz),
    )
}

/// The executable's path, from the `exe` link.
pub(crate) fn exe(pid: i32) -> Option<String> {
    std::fs::read_link(format!("/proc/{}/exe", pid))
        .ok()
        .map(|p| p.display().to_string())
}

/// The cgroup path in a `/proc/<pid>/cgroup` listing: the third field of
/// the first line that has one.
pub(crate) fn cgroup_path(listing: &str) -> Option<&str> {
    listing.lines().find_map(|l| l.splitn(3, ':').nth(2))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fix round 11 (Codex 1): a process can make its command line as long
    /// as it likes (`PR_SET_MM_MAP` points its argument area at any mapping
    /// where checkpoint/restore is built in, kernel/sys.c), and the kernel
    /// copies it out page by page as it is read (fs/proc/base.c,
    /// `get_mm_cmdline`). So every read is capped before it allocates: a
    /// fake 8 MiB command line gives at most the cap, marked cut, and a
    /// file read for parsing that runs past its cap is not parsed at all.
    #[test]
    fn a_huge_proc_file_is_read_only_to_its_cap() {
        use std::io::Write;
        let dir = std::env::temp_dir().join(format!("faceauth-procfs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("4242")).unwrap();
        let mut f = std::fs::File::create(dir.join("4242/cmdline")).unwrap();
        f.write_all(b"sudo\0rm\0").unwrap();
        f.set_len(8 << 20).unwrap();
        drop(f);
        let shown = read_shown_at(&dir, 4242, "cmdline").unwrap();
        assert!(shown.truncated);
        assert!(shown.text.len() <= CMDLINE_CAP, "{}", shown.text.len());
        assert!(shown.text.starts_with("sudo rm"));
        assert_eq!(
            read_at(&dir, 4242, "cmdline"),
            None,
            "cut short: not parsed"
        );
        std::fs::write(
            dir.join("4242/status"),
            "Name:\tx\nUid:\t1000\t1000\t1000\t1000\n",
        )
        .unwrap();
        assert_eq!(
            read_at(&dir, 4242, "status").as_deref(),
            Some("Name:\tx\nUid:\t1000\t1000\t1000\t1000")
        );
        std::fs::write(dir.join("4242/comm"), "a".repeat(4096)).unwrap();
        assert_eq!(
            read_at(&dir, 4242, "comm"),
            None,
            "comm is 16 bytes at most"
        );
        let small = read_shown_at(&dir, 4242, "status").unwrap();
        assert!(!small.truncated);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
