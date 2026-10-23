//! The socket's access list and the enrolled list kept beside it. Both are
//! rebuilt from the store (`refresh_socket_acl`) after a terminal
//! enrollment that stored templates, a deletion and every walk-through
//! outcome; a walk-through grants its own user before it starts, and that
//! refresh at its outcome is what revokes the grant. The refresh goes
//! through a poisoned authenticator mutex (a request panicked holding it)
//! rather than skipping, since the store on disk is still the truth about
//! who is enrolled; and a failed `setfacl` makes the socket root-only
//! instead of leaving the previous list, so a stale grant never outlives
//! the refresh that should have revoked it.

use super::user_uid;
use crate::auth::Authenticator;
use std::path::Path;
use std::sync::{Mutex, RwLock};

/// Who has templates, kept beside the socket ACL: set at start and again
/// after every enrollment and deletion, when the ACL is rebuilt too (a
/// walk-through's grant of its own user changes the ACL alone).
/// The bar widget's presence poll reads it instead of the store, so a poll
/// never waits on the authenticator while an enrollment walk-through or a
/// consent request holds it. Parked polls each kept a connection slot for
/// as long as the session ran, and after eight the window's own Continue,
/// Redo and Cancel were answered "busy" (C5).
static ENROLLED: RwLock<Vec<String>> = RwLock::new(Vec::new());

/// Tests that write `ENROLLED` (a process-wide list) take this first, so
/// two of them running in parallel cannot clobber each other's list.
#[cfg(test)]
pub(super) static ENROLLED_TEST_LOCK: Mutex<()> = Mutex::new(());

/// The setfacl spec for the socket: root through the owner and group
/// entries, one read-write entry per listed uid, nothing for anyone else.
/// Pure, so the tests can check who a given list admits.
fn acl_spec(uids: &[u32]) -> String {
    let mut spec = String::from("u::rw,g::rw,o::-");
    for uid in uids {
        spec.push_str(&format!(",u:{}:rw", uid));
    }
    spec
}

/// Run `setfacl` with `args` on the socket; the status and stderr, or the
/// spawn error, as the failure text.
fn setfacl(socket: &Path, args: &[&str]) -> Result<(), String> {
    match std::process::Command::new("/usr/bin/setfacl")
        .args(args)
        .arg(socket)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
    {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!(
            "{} {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Err(e.to_string()),
    }
}

/// Why `root_only` could not finish, and what that leaves on the socket.
#[derive(Debug, PartialEq)]
pub(super) enum RootOnlyFailure {
    /// The chmod failed: the previous list stands, entries and all.
    Mode(String),
    /// The chmod took but the strip did not: the mask is now empty, so every
    /// named entry admits nobody, but the entries are still listed.
    Strip(String),
}

/// Root only, whatever list the socket held: mode 0600 first (with no
/// group bits the ACL mask caps every named entry to nothing, so this
/// alone shuts the door), then the named entries stripped so a later
/// `getfacl` shows the truth.
pub(super) fn root_only(socket: &Path) -> Result<(), RootOnlyFailure> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| RootOnlyFailure::Mode(format!("chmod 0600: {}", e)))?;
    setfacl(socket, &["-b"]).map_err(|e| RootOnlyFailure::Strip(format!("setfacl -b: {}", e)))
}

/// Who may connect: root, the enrolled users, and the user whose enrollment
/// walk-through is running, by ACL on the socket (mode 0660 plus a
/// read-write entry per uid). Any other account is refused by the kernel
/// before a byte is read. No group, so no re-login at setup: the
/// walk-through grants its own user for its duration (the window and its
/// control calls run as that user, who has no template yet), a finished
/// enrollment keeps the grant, and the refresh after any other outcome or
/// a deletion revokes it. When the list cannot be applied the socket is
/// made root-only rather than left with whatever it held: a revoke that
/// fails open would keep a walk-through's grant or a deleted user's entry.
/// One `setfacl --set` does the whole job: its owner, group and other
/// entries set the mode bits (0660 with the mask over the group bits), so
/// no chmod runs first that could briefly lift the mask a failed strip
/// left behind.
pub fn apply_socket_acl(socket: &Path, users: &[String]) {
    let uids: Vec<u32> = users.iter().filter_map(|u| user_uid(u)).collect();
    let spec = acl_spec(&uids);
    match setfacl(socket, &["--set", &spec]) {
        Ok(()) => log::info!(
            "socket open to root and {} user(s): {}",
            users.len(),
            users.join(" ")
        ),
        Err(e) => match root_only(socket) {
            Ok(()) => log::warn!("setfacl: {}; socket made root-only until the next refresh", e),
            Err(RootOnlyFailure::Strip(strip)) => log::warn!(
                "setfacl: {}; socket mode is 0600 so no listed entry admits anyone, but stripping the list failed ({}); whatever it lists stays until a refresh succeeds",
                e,
                strip
            ),
            Err(RootOnlyFailure::Mode(mode)) => log::warn!(
                "setfacl: {}; making the socket root-only failed too ({}); the previous list stands until a refresh succeeds or the daemon restarts",
                e,
                mode
            ),
        },
    }
}

/// Runs `f` when dropped, however the scope ends: the enrollment
/// walk-through arms one with the refresh before it grants its own user, so
/// a panic inside the walk-through (which unwinds past the refresh written
/// after it) still revokes the grant. The panic drops the authenticator's
/// guard first, poisoning it, and the refresh recovers through
/// `refresh_from`.
pub(super) struct OnDrop<F: FnOnce()>(Option<F>);

impl<F: FnOnce()> OnDrop<F> {
    pub(super) fn new(f: F) -> Self {
        OnDrop(Some(f))
    }
}

impl<F: FnOnce()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            f();
        }
    }
}

/// Rebuild the socket's list and the enrolled list from the store.
pub(super) fn refresh_socket_acl(auth: &Mutex<Authenticator>) {
    refresh_socket_acl_at(auth, Path::new(crate::config::SOCKET));
}

/// The same for a socket at `socket`: the listener passes its own path
/// at start.
pub(super) fn refresh_socket_acl_at(auth: &Mutex<Authenticator>, socket: &Path) {
    let users = refresh_from(auth, socket, |a| a.store.enrolled_users());
    // The lock screen's channel (round 7, B) is for the enrolled users too.
    let lock = lock_socket_of(socket);
    if lock.exists() {
        apply_socket_acl(&lock, &users);
    }
}

/// The lock screen's channel socket beside the daemon's: `lock.sock` in
/// the same directory (`config::LOCK_SOCKET` for the daemon's own).
pub(super) fn lock_socket_of(socket: &Path) -> std::path::PathBuf {
    socket.with_file_name("lock.sock")
}

/// How many users are enrolled, by the list kept at the last enrollment
/// or deletion: what each source's share of the places is split over.
pub(super) fn enrolled_count() -> usize {
    match ENROLLED.read() {
        Ok(e) => e.len(),
        Err(p) => p.into_inner().len(),
    }
}

/// The refresh itself, over any guarded value that can name the enrolled
/// users: the daemon passes the authenticator, the tests a store alone. A
/// poisoned mutex is recovered, not skipped: the panic that poisoned it was
/// one request's, the store on disk is still the truth about who is
/// enrolled, and a revoke must not wait on a restart. The lock is held
/// through the apply so two refreshes cannot interleave and leave the
/// older list on the socket. Returns the list applied.
pub(super) fn refresh_from<T>(
    guarded: &Mutex<T>,
    socket: &Path,
    users_of: impl FnOnce(&T) -> Vec<String>,
) -> Vec<String> {
    let guard = match guarded.lock() {
        Ok(g) => g,
        Err(p) => {
            log::warn!("authenticator lock poisoned by an earlier panic; refreshing the socket list from the store anyway");
            guarded.clear_poison();
            p.into_inner()
        }
    };
    let users = users_of(&guard);
    apply_socket_acl(socket, &users);
    set_enrolled(users.clone());
    users
}

pub(super) fn set_enrolled(users: Vec<String>) {
    match ENROLLED.write() {
        Ok(mut e) => *e = users,
        Err(p) => *p.into_inner() = users,
    }
}

/// Is `user` enrolled, by the list kept at the last enrollment or deletion?
/// No lock but the list's own, so it answers at once during a walk-through.
pub(super) fn is_enrolled(user: &str) -> bool {
    match ENROLLED.read() {
        Ok(e) => e.iter().any(|u| u == user),
        Err(p) => p.into_inner().iter().any(|u| u == user),
    }
}

#[cfg(test)]
mod socket_acl_tests {
    use super::{acl_spec, is_enrolled, refresh_from, root_only, OnDrop, ENROLLED_TEST_LOCK};
    use crate::store::{Sealing, Store};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::path::PathBuf;
    use std::sync::Mutex;

    /// A fresh directory under the system temp dir, named for the test.
    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("faceauth-acl-{}-{}", name, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The socket's ACL as `getfacl` prints it, header and blank lines
    /// dropped.
    fn acl_lines(path: &std::path::Path) -> Vec<String> {
        let out = std::process::Command::new("/usr/bin/getfacl")
            .arg("--omit-header")
            .arg(path)
            .output()
            .expect("getfacl runs");
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect()
    }

    /// The list a walk-through applies is the template-only list plus the
    /// session user, so a first-time user can connect the window and press
    /// Continue; the list applied afterwards is built from the templates
    /// alone, so a failed session leaves that user with no entry.
    #[test]
    fn a_session_admits_its_user_and_the_template_list_after_a_failure_does_not() {
        let enrolled = [1000u32, 1001];
        let session_uid = 1002u32;
        let mut session = enrolled.to_vec();
        session.push(session_uid);
        let spec = acl_spec(&session);
        assert!(spec.contains(",u:1002:rw"), "session spec: {}", spec);
        assert!(spec.contains(",u:1000:rw") && spec.contains(",u:1001:rw"));
        let after_failure = acl_spec(&enrolled);
        assert!(
            !after_failure.contains("1002"),
            "after failure: {}",
            after_failure
        );
        assert!(after_failure.contains(",u:1000:rw") && after_failure.contains(",u:1001:rw"));
    }

    /// Root keeps access through the owner and group entries; nobody else
    /// gets in on an empty list.
    #[test]
    fn an_empty_list_is_root_only() {
        assert_eq!(acl_spec(&[]), "u::rw,g::rw,o::-");
    }

    /// A request that panics holding the authenticator poisons its mutex.
    /// The refresh after it (the one that revokes a walk-through's grant or
    /// a deleted user's entry) must still read the store and replace the
    /// enrolled list, not skip and leave the grant standing until a restart.
    #[test]
    fn a_refresh_goes_through_a_poisoned_lock_and_reads_the_store() {
        let dir = temp("poisoned");
        let user = "acl-poison-user";
        let store = Store::open_with(dir.join("store"), Sealing::Plain("test".into())).unwrap();
        std::fs::write(dir.join("store").join(format!("{}.json", user)), "").unwrap();
        let socket = dir.join("sock");
        std::fs::write(&socket, "").unwrap();
        let guarded = Mutex::new(store);
        // The panic is caught on this thread (its message lands in the
        // test's captured output, no hook to silence), and the guard it
        // drops while unwinding poisons the lock the way a request's would.
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            let _guard = guarded.lock().unwrap();
            panic!("a request panicked holding the authenticator");
        }));
        assert!(unwound.is_err());
        assert!(guarded.is_poisoned(), "the panic poisoned the lock");

        let _list = ENROLLED_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let applied = refresh_from(&guarded, &socket, |s| s.enrolled_users());
        assert_eq!(applied, vec![user.to_string()], "read from the store");
        assert!(is_enrolled(user), "the enrolled list was replaced");
        assert!(!is_enrolled("acl-nobody"));
        assert!(
            !guarded.is_poisoned(),
            "the poison is cleared, so the next refresh does not warn again"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The walk-through arms its revoke before it grants its user. A panic
    /// inside the walk-through unwinds past the refresh written after it;
    /// the armed one runs anyway, and only once when the scope ends
    /// normally.
    #[test]
    fn an_armed_refresh_runs_once_when_its_scope_unwinds_or_ends() {
        let ran = std::cell::Cell::new(0);
        let unwound = catch_unwind(AssertUnwindSafe(|| {
            let _revoke = OnDrop::new(|| ran.set(ran.get() + 1));
            panic!("the walk-through panicked");
        }));
        assert!(unwound.is_err());
        assert_eq!(ran.get(), 1, "the revoke ran on the unwind");
        {
            let revoke = OnDrop::new(|| ran.set(ran.get() + 1));
            drop(revoke);
        }
        assert_eq!(
            ran.get(),
            2,
            "once on a normal end, not again at scope exit"
        );
    }

    /// When the list cannot be applied the fallback is a socket root can
    /// reach and nobody else: mode 0600 and no named entries left from
    /// before, so a walk-through's grant does not survive a failed refresh.
    #[test]
    fn the_fallback_after_a_failed_list_leaves_no_named_entry_and_mode_0600() {
        let dir = temp("root-only");
        let socket = dir.join("sock");
        std::fs::write(&socket, "").unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).unwrap();
        let me = std::fs::metadata(&socket).unwrap().uid();
        let granted = std::process::Command::new("/usr/bin/setfacl")
            .arg("-m")
            .arg(format!("u:{}:rw", me))
            .arg(&socket)
            .output()
            .expect("setfacl runs");
        assert!(
            granted.status.success(),
            "the stale grant is on the file: {}",
            String::from_utf8_lossy(&granted.stderr)
        );
        assert!(
            acl_lines(&socket)
                .iter()
                .any(|l| l.starts_with("user:") && !l.starts_with("user::")),
            "a named entry stands before the fallback: {:?}",
            acl_lines(&socket)
        );

        root_only(&socket).expect("the fallback applies");

        let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode {:o}", mode);
        let lines = acl_lines(&socket);
        assert!(
            lines
                .iter()
                .all(|l| !l.starts_with("user:") || l.starts_with("user::")),
            "no named entry after the fallback: {:?}",
            lines
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
