//! Children the daemon and its helpers start, and the one way they are
//! signalled (fix round 13, Codex 1): through a pidfd the child took of
//! itself between fork and exec and passed up a socket before it ran
//! anything, never by its pid. A pidfd names one process for its life; a
//! pid can name another once the first is reaped. The PAM module, which
//! links nothing of the daemon's, carries its own copy
//! (`pam_faceauth::spawn_with_pidfd`). As std does for its own pidfd spawn,
//! unstable as of 1.98 (library/std/src/sys/process/unix/unix.rs,
//! `send_pidfd`, `recv_pidfd`).
//!
//! Waits still go through `std::process::Child`: in the daemon and its
//! helpers nothing else reaps a child (SIGCHLD keeps its default, and no
//! code waits on any child but its own), so a child's pid stays its own,
//! a zombie if need be, until its own handle waits for it.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::process::{Child, Command};

/// A socket pair a command is armed with: its child sends a pidfd on
/// itself up `theirs` as the last thing before its exec, and the spawn
/// reads it from `ours`.
pub struct Spawner {
    ours: OwnedFd,
    // Kept open for every spawn of the command; close-on-exec, it is gone
    // from each child once it runs its program.
    _theirs: OwnedFd,
}

impl Spawner {
    /// Arm `cmd`, once however often it is spawned: its child sends a pidfd
    /// on itself before its exec.
    pub fn arm(cmd: &mut Command) -> std::io::Result<Spawner> {
        use std::os::unix::process::CommandExt;
        let mut pair = [-1 as libc::c_int; 2];
        // SAFETY: socketpair fills the two-element array it is given.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                0,
                pair.as_mut_ptr(),
            )
        } != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: socketpair returned two new descriptors that nothing
        // else owns; each OwnedFd is the only owner of its own.
        let (ours, theirs) =
            unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) };
        let up = theirs.as_raw_fd();
        // SAFETY: send_own_pidfd makes only async-signal-safe calls, on a
        // descriptor the spawner keeps open for every spawn of `cmd`.
        unsafe { cmd.pre_exec(move || send_own_pidfd(up)) };
        Ok(Spawner {
            ours,
            _theirs: theirs,
        })
    }

    /// Spawn `cmd`, armed by this spawner: the child and its own pidfd. A
    /// spawn that fails after the child sent one (its exec failed) leaves
    /// nothing behind for the next. A child that started and sent none,
    /// which cannot happen (a failed send fails its pre-exec, and so the
    /// spawn), is an error too, and is left to end by itself: no signal
    /// can reach it but by pid.
    pub fn spawn(&self, cmd: &mut Command) -> std::io::Result<(Child, OwnedFd)> {
        match cmd.spawn() {
            Ok(child) => match recv_pidfd(self.ours.as_raw_fd()) {
                Some(pidfd) => Ok((child, pidfd)),
                None => Err(std::io::Error::other("the child sent no pidfd of itself")),
            },
            Err(e) => {
                while recv_pidfd(self.ours.as_raw_fd()).is_some() {}
                Err(e)
            }
        }
    }
}

/// `cmd` spawned once, with its own pidfd (`Spawner`).
pub fn spawn_with_pidfd(cmd: &mut Command) -> std::io::Result<(Child, OwnedFd)> {
    Spawner::arm(cmd)?.spawn(cmd)
}

/// The room a control message with one descriptor takes.
const ONE_FD_SPACE: usize =
    // SAFETY: CMSG_SPACE is arithmetic on its argument.
    unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>() as u32) } as usize;

/// A control message buffer for one descriptor, aligned as its header.
#[repr(C)]
union OneFd {
    buf: [u8; ONE_FD_SPACE],
    _align: libc::cmsghdr,
}

/// Between fork and exec: a pidfd on this process, sent up `sock` with
/// one byte, then closed here. Async-signal-safe: syscalls on the stack.
fn send_own_pidfd(sock: RawFd) -> std::io::Result<()> {
    let last = std::io::Error::last_os_error;
    // SAFETY: getpid and pidfd_open take values and no pointers.
    let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, libc::getpid(), 0) };
    if pidfd < 0 {
        return Err(last());
    }
    let pidfd = pidfd as libc::c_int;
    // SAFETY: every pointer is to this frame's stack, valid for the call:
    // one byte of payload and a control buffer sized for one descriptor
    // (`OneFd`), filled through the CMSG macros.
    let sent = unsafe {
        let mut byte = *b"P";
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control: OneFd = std::mem::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = std::ptr::addr_of_mut!(control.buf).cast();
        msg.msg_controllen = ONE_FD_SPACE as _;
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        (*hdr).cmsg_level = libc::SOL_SOCKET;
        (*hdr).cmsg_type = libc::SCM_RIGHTS;
        (*hdr).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            (&pidfd as *const libc::c_int).cast::<u8>(),
            libc::CMSG_DATA(hdr),
            std::mem::size_of::<libc::c_int>(),
        );
        libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL)
    };
    let err = last();
    // SAFETY: the pidfd this function opened, closed once.
    unsafe { libc::close(pidfd) };
    if sent == 1 {
        Ok(())
    } else {
        Err(err)
    }
}

/// A pidfd a child sent up `sock` before its exec (`send_own_pidfd`):
/// there already when the spawn returns, so never waited for; None for
/// anything but one descriptor in one message.
fn recv_pidfd(sock: RawFd) -> Option<OwnedFd> {
    // SAFETY: every pointer is to this frame's stack, valid for the call,
    // with the lengths of what it points to; the descriptor copied out is
    // one the kernel just installed in this process, owned by no one else.
    unsafe {
        let mut byte = [0u8];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control: OneFd = std::mem::zeroed();
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = std::ptr::addr_of_mut!(control.buf).cast();
        msg.msg_controllen = ONE_FD_SPACE as _;
        let n = libc::recvmsg(sock, &mut msg, libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT);
        let hdr = libc::CMSG_FIRSTHDR(&msg);
        if n != 1 || hdr.is_null() {
            return None;
        }
        let mut fd: libc::c_int = -1;
        if (*hdr).cmsg_level == libc::SOL_SOCKET
            && (*hdr).cmsg_type == libc::SCM_RIGHTS
            && (*hdr).cmsg_len as usize
                == libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize
        {
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(hdr),
                (&mut fd as *mut libc::c_int).cast::<u8>(),
                std::mem::size_of::<libc::c_int>(),
            );
        }
        if fd < 0 {
            return None;
        }
        let fd = OwnedFd::from_raw_fd(fd);
        (msg.msg_flags & libc::MSG_CTRUNC == 0).then_some(fd)
    }
}

/// `PIDFD_SIGNAL_PROCESS_GROUP` (include/uapi/linux/pidfd.h, Linux 6.9):
/// the signal goes to the process group the pidfd's process leads, found
/// by that process's own `struct pid` (kernel/signal.c,
/// `do_pidfd_send_signal`, `kill_pgrp_info`), never by a number.
const PIDFD_SIGNAL_PROCESS_GROUP: libc::c_uint = 1 << 2;

fn pidfd_send_signal(pidfd: &OwnedFd, sig: libc::c_int, flags: libc::c_uint) -> bool {
    // SAFETY: a pidfd, a signal number, no info pointer, the flags.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            sig,
            std::ptr::null::<libc::siginfo_t>(),
            flags,
        ) == 0
    }
}

/// SIGKILL to the process `pidfd` names, and nothing else.
pub fn kill(pidfd: &OwnedFd) {
    let _ = pidfd_send_signal(pidfd, libc::SIGKILL, 0);
}

/// SIGKILL to the process group the process `pidfd` names leads, through
/// the pidfd; on a kernel without the group scope (before 6.9) to that
/// process alone.
pub fn kill_group(pidfd: &OwnedFd) {
    if !pidfd_send_signal(pidfd, libc::SIGKILL, PIDFD_SIGNAL_PROCESS_GROUP)
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL)
    {
        kill(pidfd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", script]);
        c
    }

    /// The pid a pidfd names, from its fdinfo (`Pid:`; -1 once reaped).
    fn pid_of(pidfd: &OwnedFd) -> Option<i64> {
        std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix("Pid:"))?
            .trim()
            .parse()
            .ok()
    }

    /// Fix round 13 (Codex 1): the pidfd is the child's own, and a kill
    /// through it reaches that child; after a spawn that failed (its exec
    /// did), the next spawn of the same command still gets its own child's,
    /// not the failed one's.
    #[test]
    fn a_childs_pidfd_is_its_own_and_kills_it() {
        let (mut child, pidfd) = spawn_with_pidfd(&mut sh("exec sleep 30")).unwrap();
        assert_eq!(pid_of(&pidfd), Some(i64::from(child.id())));
        kill(&pidfd);
        let st = child.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(st.signal(), Some(libc::SIGKILL));
        let dir = std::env::temp_dir().join(format!("faceauth-child-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let prog = dir.join("later");
        let mut c = Command::new(&prog);
        let spawner = Spawner::arm(&mut c).unwrap();
        assert!(spawner.spawn(&mut c).is_err(), "nothing to exec yet");
        std::fs::write(&prog, "#!/bin/sh\nexec sleep 30\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();
        let (mut child, pidfd) = spawner.spawn(&mut c).unwrap();
        assert_eq!(
            pid_of(&pidfd),
            Some(i64::from(child.id())),
            "the second spawn's own pidfd"
        );
        kill(&pidfd);
        let _ = child.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fix round 13 (Codex 1): a group kill through the leader's pidfd
    /// reaches what the leader left in its group.
    #[test]
    fn a_group_kill_through_the_leaders_pidfd_reaches_its_group() {
        use std::os::unix::process::CommandExt;
        let dir = std::env::temp_dir().join(format!("faceauth-child-group-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pidfile = dir.join("pid");
        let mut c = sh(&format!(
            "sleep 30 & echo $! > '{}'; exec sleep 30",
            pidfile.display()
        ));
        c.process_group(0);
        let (mut child, pidfd) = spawn_with_pidfd(&mut c).unwrap();
        let t0 = std::time::Instant::now();
        let grandchild = loop {
            if let Some(p) = std::fs::read_to_string(&pidfile)
                .ok()
                .and_then(|t| t.trim().parse::<i32>().ok())
            {
                break p;
            }
            assert!(t0.elapsed() < std::time::Duration::from_secs(5));
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        // The grandchild's own pidfd, to watch it without its pid.
        // SAFETY: pidfd_open takes a pid and flags and no pointers.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, grandchild, 0) };
        assert!(raw >= 0);
        // SAFETY: a new descriptor nothing else owns.
        let watch = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        kill_group(&pidfd);
        let _ = child.wait();
        let gone = loop {
            let mut p = libc::pollfd {
                fd: watch.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd, its count, a timeout.
            if unsafe { libc::poll(&mut p, 1, 100) } == 1 {
                break true;
            }
            if t0.elapsed() > std::time::Duration::from_secs(5) {
                break false;
            }
        };
        assert!(gone, "the grandchild in the group was killed too");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
