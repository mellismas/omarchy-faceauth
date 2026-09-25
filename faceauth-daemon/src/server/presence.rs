//! The socket side of the presence watch: the mode query and switch. It
//! answers from statics alone and never takes the authenticator, so the bar
//! widget's poll is not held up by a request using the camera.

use super::acl::is_enrolled;
use super::serve::CFG;
use super::user_uid;
use crate::auth::Outcome;

/// May `peer_uid`, asking about `user`, switch the watch on `watched` to
/// `mode`? Only the watched user, for their own watch, while one runs.
/// `"query"` asks without switching: Ok(None), allowed for any user asking
/// about themselves (the uid check above the call already holds).
fn presence_mode_change(
    peer_uid: u32,
    user: &str,
    watched: &crate::presence::PresenceConfig,
    mode: &str,
) -> std::result::Result<Option<crate::presence::PresenceMode>, String> {
    if mode == "query" {
        return Ok(None);
    }
    let Some(m) = crate::presence::PresenceMode::parse(mode) else {
        return Err(format!(
            "unknown presence mode {:?}; \"default\", \"secure\" or \"query\"",
            mode
        ));
    };
    if !watched.enabled || watched.user.is_empty() {
        return Err("the presence watch is off".into());
    }
    if user != watched.user || user_uid(&watched.user) != Some(peer_uid) {
        return Err("only the watched user may set the presence mode".into());
    }
    Ok(Some(m))
}

/// Answer a presence mode request (a read, or a switch) from `peer_uid`.
/// Everything it needs is in the statics: the config, the mode in force and
/// the enrolled list. It takes no authenticator on purpose, so the bar
/// widget's poll is answered in microseconds however long the camera is
/// held, and its connection slot is back at once (C5).
pub(super) fn presence_query(peer_uid: u32, peer_pid: i32, user: &str, mode: &str) -> Outcome {
    let watched = CFG.get().map(|c| c.presence.clone()).unwrap_or_default();
    // "Watching" is what the bar widget and the key binding show up for,
    // so it also needs the user enrolled: a watch configured for a user
    // with no templates never locks for them and offers nothing to switch.
    let enrolled = is_enrolled(user);
    match presence_mode_change(peer_uid, user, &watched, mode) {
        Ok(Some(_)) if !enrolled => Outcome::Error {
            message: format!("{} is not enrolled", user),
        },
        Ok(Some(m)) => {
            crate::presence::set_presence_mode(m);
            log::info!(
                "presence: mode set to {} by uid {} pid {}",
                m.name(),
                peer_uid,
                peer_pid
            );
            presence_state(&watched, user, enrolled)
        }
        Ok(None) => presence_state(&watched, user, enrolled),
        Err(why) => {
            log::warn!(
                "presence mode request from uid {} for {} refused: {}",
                peer_uid,
                user,
                why
            );
            Outcome::Error { message: why }
        }
    }
}

/// The state a presence mode request answers with: the mode in force,
/// whether the daemon's watch is on for `user`, and if it is, what the
/// watch last decided. The decision goes only with `watching`, so it
/// reaches root and the watched user and nobody else (H16).
fn presence_state(
    watched: &crate::presence::PresenceConfig,
    user: &str,
    enrolled: bool,
) -> Outcome {
    let watching = watched.enabled && watched.user == user && enrolled;
    let last = if watching {
        crate::presence::snapshot()
    } else {
        None
    };
    Outcome::PresenceMode {
        mode: crate::presence::presence_mode().name().into(),
        watching,
        state: last.map(|s| s.state),
        away_for: last.and_then(|s| s.away_for),
    }
}

#[cfg(test)]
mod locality_tests {
    use super::*;

    /// The presence mode switch is the watched user's alone, for their own
    /// watch, while a watch runs.
    #[test]
    fn only_the_watched_user_switches_the_presence_mode() {
        use crate::presence::{PresenceConfig, PresenceMode};
        let me = std::env::var("USER").unwrap_or_else(|_| "root".into());
        let my_uid = user_uid(&me).unwrap_or(0);
        let watched = PresenceConfig {
            enabled: true,
            user: me.clone(),
            ..Default::default()
        };
        assert_eq!(
            presence_mode_change(my_uid, &me, &watched, "secure"),
            Ok(Some(PresenceMode::Secure))
        );
        assert_eq!(
            presence_mode_change(my_uid, &me, &watched, "default"),
            Ok(Some(PresenceMode::Default))
        );
        assert!(presence_mode_change(my_uid, &me, &watched, "paranoid")
            .unwrap_err()
            .contains("unknown"));
        assert!(presence_mode_change(my_uid + 1, &me, &watched, "secure")
            .unwrap_err()
            .contains("only the watched user"));
        assert!(presence_mode_change(my_uid, "someone-else", &watched, "secure").is_err());
        let off = PresenceConfig {
            enabled: false,
            ..watched.clone()
        };
        assert!(presence_mode_change(my_uid, &me, &off, "secure")
            .unwrap_err()
            .contains("off"));
        // The read form changes nothing and is answered whether or not the
        // watch is on, with `watching` saying which.
        assert_eq!(
            presence_mode_change(my_uid + 1, &me, &off, "query"),
            Ok(None)
        );
        assert!(matches!(
            presence_state(&watched, &me, true),
            Outcome::PresenceMode { watching: true, .. }
        ));
        assert!(matches!(
            presence_state(&off, &me, true),
            Outcome::PresenceMode {
                watching: false,
                ..
            }
        ));
        assert!(matches!(
            presence_state(&watched, "someone-else", true),
            Outcome::PresenceMode {
                watching: false,
                ..
            }
        ));
        // A watch configured for a user with no templates is not "watching":
        // the widget and the binding stay away until enrolment.
        assert!(matches!(
            presence_state(&watched, &me, false),
            Outcome::PresenceMode {
                watching: false,
                ..
            }
        ));
        // The watch's decision rides on the answer only with `watching`,
        // so another user asking about themselves never learns whether
        // the owner is at the desk (H16).
        assert!(matches!(
            presence_state(&watched, "someone-else", true),
            Outcome::PresenceMode {
                state: None,
                away_for: None,
                ..
            }
        ));
        let before_a_tick = presence_state(&watched, &me, true);
        assert!(matches!(
            before_a_tick,
            Outcome::PresenceMode {
                watching: true,
                state: None,
                ..
            }
        ));
        let json = serde_json::to_string(&before_a_tick).unwrap();
        assert!(
            !json.contains("state"),
            "no decision yet, no field: {}",
            json
        );
    }
}
