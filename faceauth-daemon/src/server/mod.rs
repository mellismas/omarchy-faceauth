//! The Unix socket the PAM module talks to. One JSON request per connection,
//! one JSON reply, newline-terminated.
//!
//! Request:  {"user": "alice"}
//! Reply:    {"result": "match", "score": 0.93, "frames": 2, "elapsed_ms": 1800}
//!           {"result": "no_match" | "no_face" | "denied" | "not_enrolled" | "error", ...}
//!
//! Authorisation is by peer credentials: a connection may ask about its own
//! uid's user, or anything if it is root. Attempts are serialised; a second
//! request while one runs waits its turn (the camera is one resource).

mod acl;
mod admit;
mod backoff;
mod client;
mod handle;
mod locality;
mod presence;
mod read;
mod rounds;
mod serve;

pub use acl::apply_socket_acl;
#[cfg(feature = "dev-tools")]
pub use client::sweep;
pub use client::{
    ask, ask_consent, consent_ack, consent_answer, consent_passwordless, consent_rearm,
    delete_templates, enrol_control, enrol_session, enroll, ping, presence_mode, probe, send,
};
pub use locality::Locality;
pub use serve::serve;

use crate::auth::Outcome;
use anyhow::Result;
use std::io::Write;
use std::os::unix::net::UnixStream;

fn reply(stream: &mut UnixStream, o: &Outcome) -> Result<()> {
    let mut s = serde_json::to_string(o)?;
    s.push('\n');
    stream.write_all(s.as_bytes())?;
    Ok(())
}

fn user_uid(name: &str) -> Option<u32> {
    nix::unistd::User::from_name(name)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
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
