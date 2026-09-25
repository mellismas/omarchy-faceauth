//! The socket's access list and the enrolled list kept beside it. Both
//! change at the same moments, after an enrolment or a deletion, so a user
//! without templates never reaches the socket at all.

use super::user_uid;
use crate::auth::Authenticator;
use std::path::Path;
use std::sync::{Mutex, RwLock};

/// Who has templates, kept beside the socket ACL: set at start and again
/// after every enrolment and deletion, the same moments the ACL changes.
/// The bar widget's presence poll reads it instead of the store, so a poll
/// never waits on the authenticator while an enrolment walk-through or a
/// consent request holds it. Parked polls each kept a connection slot for
/// as long as the session ran, and after eight the window's own Continue,
/// Redo and Cancel were answered "busy" (C5).
static ENROLLED: RwLock<Vec<String>> = RwLock::new(Vec::new());

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

/// Who may connect: root, the enrolled users, and the user whose enrolment
/// walk-through is running, by ACL on the socket (mode 0660 plus a
/// read-write entry per uid). Any other account is refused by the kernel
/// before a byte is read. No group, so no re-login at setup: the
/// walk-through grants its own user for its duration (the window and its
/// control calls run as that user, who has no template yet), a finished
/// enrolment keeps the grant, and the refresh after any other outcome or
/// a deletion revokes it.
pub fn apply_socket_acl(socket: &Path, users: &[String]) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660)) {
        log::warn!("socket mode: {}", e);
        return;
    }
    let uids: Vec<u32> = users.iter().filter_map(|u| user_uid(u)).collect();
    let spec = acl_spec(&uids);
    match std::process::Command::new("/usr/bin/setfacl")
        .arg("--set")
        .arg(&spec)
        .arg(socket)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
    {
        Ok(o) if o.status.success() => log::info!(
            "socket open to root and {} user(s): {}",
            users.len(),
            users.join(" ")
        ),
        Ok(o) => log::warn!(
            "setfacl: {} {}; socket stays root-only",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        ),
        Err(e) => log::warn!("setfacl: {}; socket stays root-only", e),
    }
}

pub(super) fn refresh_socket_acl(auth: &Mutex<Authenticator>) {
    if let Ok(a) = auth.lock() {
        let users = a.store.enrolled_users();
        apply_socket_acl(Path::new(crate::config::SOCKET), &users);
        set_enrolled(users);
    }
}

pub(super) fn set_enrolled(users: Vec<String>) {
    match ENROLLED.write() {
        Ok(mut e) => *e = users,
        Err(p) => *p.into_inner() = users,
    }
}

/// Is `user` enrolled, by the list kept at the last enrolment or deletion?
/// No lock but the list's own, so it answers at once during a walk-through.
pub(super) fn is_enrolled(user: &str) -> bool {
    match ENROLLED.read() {
        Ok(e) => e.iter().any(|u| u == user),
        Err(p) => p.into_inner().iter().any(|u| u == user),
    }
}

#[cfg(test)]
mod socket_acl_tests {
    use super::acl_spec;

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
}
