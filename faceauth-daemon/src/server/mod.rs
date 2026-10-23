//! The daemon's Unix socket: the PAM module, the CLI, the lock screen, the
//! consent card, the polkit agent and the enrollment window all talk to it.
//! One JSON request line per connection and one JSON reply line, except
//! that a terminal enrollment sends `learned` before its outcome and the
//! enrollment window's watch streams the session's lines until it ends.
//!
//! Request:  {"user": "alice", "consent": true}
//! Reply:    {"result": "match", "frames": 2, "elapsed_ms": 1800}
//!           {"result": "no_match" | "no_face" | "denied" | "refused" | "error", ...}
//!
//! Who may connect is the socket's mode and ACL (`acl`): root, the enrolled
//! users and the user whose walk-through is running. Who may ask what is
//! the peer's credentials (`handle`): a connection asks about its own uid's
//! user, or anyone but root if it is root; enrollment and deletion are root's only;
//! every request must come from a local caller; and scores go to root
//! peers only. The camera is one resource: a request that cannot have it
//! within a moment is answered "busy", and a user's consent requests take
//! the window one at a time in arrival order.

mod acl;
mod admit;
mod backoff;
mod channel;
mod client;
mod handle;
mod limits;
mod locality;
mod presence;
mod read;
mod rounds;
mod serve;

pub use acl::apply_socket_acl;
pub(crate) use admit::lid_closed;
#[cfg(feature = "dev-tools")]
pub use client::sweep;
pub use client::{
    ask, ask_consent, consent_ack, consent_answer, consent_key_pin, consent_passwordless,
    consent_rearm, delete_templates, enrol_control, enrol_session, enroll, fprint_lane, key_lane,
    lock_channel, ping, presence_mode, probe, send, ChannelEnd,
};
pub use handle::request_op;
pub use locality::Locality;
pub use serve::serve;

use crate::auth::Outcome;
/// A user's uid by name: the store's lookup, the daemon's one.
use crate::store::current_uid as user_uid;
use anyhow::Result;
use std::io::Write;
use std::os::unix::net::UnixStream;

fn reply(stream: &mut UnixStream, o: &Outcome) -> Result<()> {
    let mut s = serde_json::to_string(o)?;
    s.push('\n');
    stream.write_all(s.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod root_tests {
    use super::user_uid;

    #[test]
    fn root_resolves_to_uid_zero_so_the_gate_can_refuse_it() {
        assert_eq!(user_uid("root"), Some(0));
        assert_eq!(user_uid("no-such-user-faceauth-test"), None);
    }
}
