//! The small checks that decide whether a request is let in at all: a
//! plain look from the user themselves, a lid that is open, and a peer
//! that is not the daemon's own process.

/// May this peer ask for a plain look (a match with no window and no
/// nod)? Only a caller running as the user: a root peer is an elevation
/// stack, and an elevation needs consent.
pub(super) fn admit_plain_look(peer_uid: u32) -> std::result::Result<(), &'static str> {
    if peer_uid == 0 {
        Err("a root caller needs consent")
    } else {
        Ok(())
    }
}

/// Whether every lid the firmware reports is closed, read the way
/// `omarchy-hw-laptop-closed` reads it. No lid at all (a desktop) is open.
pub(super) fn lid_closed() -> bool {
    lid_closed_in(std::path::Path::new("/proc/acpi/button/lid"))
}

fn lid_closed_in(dir: &std::path::Path) -> bool {
    let Ok(lids) = std::fs::read_dir(dir) else {
        return false;
    };
    let mut seen = false;
    for lid in lids.flatten() {
        let Ok(state) = std::fs::read_to_string(lid.path().join("state")) else {
            continue;
        };
        seen = true;
        if !state.contains("closed") {
            return false;
        }
    }
    seen
}

/// Is the peer this very process? Its own PAM stack, if a face line is on
/// it, connects back with the daemon's pid (B6).
pub(super) fn is_own_pid(peer_pid: i32, own: u32) -> bool {
    peer_pid == own as i32
}

#[cfg(test)]
mod plain_look_tests {
    use super::*;

    /// A3: a plain look is admitted from a caller running as the user (the
    /// lock screen) and refused from root (an elevation stack whose face
    /// line lacks `consent`).
    #[test]
    fn a_root_peer_gets_no_plain_look() {
        assert_eq!(admit_plain_look(0), Err("a root caller needs consent"));
        assert_eq!(admit_plain_look(1000), Ok(()));
    }
}

#[cfg(test)]
mod lid_tests {
    use super::lid_closed_in;

    struct Lids(std::path::PathBuf);
    impl Lids {
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for Lids {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn lids(states: &[&str]) -> Lids {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d = std::env::temp_dir().join(format!("faceauth-lid-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        for (i, st) in states.iter().enumerate() {
            let p = d.join(format!("LID{}", i));
            std::fs::create_dir(&p).unwrap();
            std::fs::write(p.join("state"), format!("state:      {}\n", st)).unwrap();
        }
        Lids(d)
    }

    #[test]
    fn a_closed_lid_is_closed() {
        assert!(lid_closed_in(lids(&["closed"]).path()));
    }

    #[test]
    fn an_open_lid_a_missing_lid_and_an_unreadable_one_are_open() {
        assert!(!lid_closed_in(lids(&["open"]).path()));
        assert!(!lid_closed_in(lids(&[]).path()));
        assert!(!lid_closed_in(std::path::Path::new("/nonexistent/lid")));
        let d = lids(&["closed"]);
        std::fs::remove_file(d.path().join("LID0/state")).unwrap();
        assert!(!lid_closed_in(d.path()));
    }

    #[test]
    fn two_lids_are_closed_only_when_both_are() {
        assert!(!lid_closed_in(lids(&["closed", "open"]).path()));
        assert!(lid_closed_in(lids(&["closed", "closed"]).path()));
    }
}

#[cfg(test)]
mod locality_tests {
    use super::*;

    /// A request from the daemon's own pid is refused whatever it asks (B6).
    #[test]
    fn the_daemon_refuses_its_own_pid() {
        let me = std::process::id();
        assert!(is_own_pid(me as i32, me));
        assert!(!is_own_pid(me as i32 + 1, me));
        assert!(!is_own_pid(1, me));
    }
}
