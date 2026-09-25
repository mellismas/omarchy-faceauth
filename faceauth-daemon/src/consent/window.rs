//! The consent window as the daemon drives it: the card's states and
//! heartbeat, the answer token it hands the card, and the acknowledgement
//! and dwell that decide when nods begin to count.

#[cfg(test)]
use super::passwordless::PASSWORDLESS_MAX_MINUTES;
#[cfg(test)]
use super::requester::clip_command;
use super::requester::CallerInfo;
use super::shell::shell_call;
use super::state::ConsentState;
#[cfg(test)]
use super::state::{test_state, Answer};
use crate::config::Config;
use anyhow::{anyhow, bail, Result};
use serde::Serialize;
use std::time::{Duration, Instant};

/// How long a summoned window has to acknowledge before the request is
/// denied.
pub const ACK_WAIT: Duration = Duration::from_secs(3);

/// After the window acknowledges, how long before a nod leg counts: a nod
/// already in motion when the card appeared was not a nod at this card.
pub const ACK_DWELL: Duration = Duration::from_millis(1500);

/// Sixteen random bytes as hex, or nothing: a token that could not be drawn
/// from the kernel is not a token, and the request fails rather than run
/// with a guessable one.
fn fresh_token() -> Option<String> {
    use std::io::Read;
    let mut b = [0u8; 16];
    std::fs::File::open("/dev/urandom")
        .ok()?
        .read_exact(&mut b)
        .ok()?;
    Some(b.iter().map(|x| format!("{:02x}", x)).collect())
}

/// The window on the desktop. Every call is one `omarchy-shell` invocation
/// inside the user's own systemd manager, the same route the session lock uses.
pub struct Dialog {
    pub cfg: Config,
    user: String,
    open: bool,
    /// The answer token for this request (see `Live`).
    token: String,
    /// The record the token lives in.
    state: &'static ConsentState,
    /// When the window acknowledged this request.
    acked_at: Option<Instant>,
    /// When the card was last shown the "nod" state with an
    /// acknowledgement wait: the dwell runs from here, so nods count only
    /// once the card asking for them has been up for `ACK_DWELL` (D4).
    nod_shown_at: Option<Instant>,
    /// The daemon is waiting for the user to come back to the card after
    /// a nod window passed unanswered; the card offers "Ready to nod".
    waiting: bool,
    /// The last pending state and message sent, for the heartbeat.
    last: Option<(String, String)>,
}

/// While a request waits (for attention, or parked behind a lock) the
/// card is re-sent this often with the same state, so the window's own
/// safety net, which hides a card no daemon has spoken to for five
/// minutes, never fires on a live request (D1).
pub const HEARTBEAT: Duration = Duration::from_secs(60);

#[derive(Serialize)]
struct Payload<'a> {
    state: &'a str,
    message: &'a str,
    caller: &'a CallerInfo,
    token: &'a str,
    /// The nods are not armed and the daemon is waiting for the user to
    /// come back: the card shows a "Ready to nod" button, whose answer
    /// re-arms them (Q8).
    waiting: bool,
    /// The passwordless-sudo minutes the approval of this request will
    /// grant, if the card's button armed them; the card draws its rider
    /// row from this and nothing local, so it always says what a nod does.
    passwordless_minutes: Option<u32>,
    /// The nod window is following the enrolled face right now. The card
    /// greys the passwordless button otherwise, and the daemon refuses an
    /// arm otherwise, so the button and the socket obey one signal.
    face_present: bool,
}

impl Dialog {
    /// A window for `user`'s live request, with a fresh answer token
    /// written into the record. Fails when no request of theirs is live,
    /// or when no token could be drawn.
    pub fn new(cfg: &Config, user: &str, state: &'static ConsentState) -> Result<Self> {
        let token = fresh_token().ok_or_else(|| anyhow!("no randomness for the answer token"))?;
        if !state.set_token(user, &token) {
            bail!("no live consent request for {}", user);
        }
        Ok(Dialog {
            cfg: cfg.clone(),
            user: user.to_string(),
            open: false,
            token,
            state,
            acked_at: None,
            nod_shown_at: None,
            waiting: false,
            last: None,
        })
    }

    /// When the window acknowledged this request, if it has.
    pub fn acked_at(&self) -> Option<Instant> {
        self.acked_at
    }

    /// Is the card up, as far as the daemon knows?
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Re-send the last pending state to the card, so its safety net
    /// keeps counting from now. Nothing when no card is up.
    pub fn heartbeat(&mut self, caller: &CallerInfo) {
        if !self.open {
            return;
        }
        if let Some((state, message)) = self.last.clone() {
            if let Err(e) = self.show_inner(&state, &message, caller, false) {
                log::warn!("consent window: heartbeat failed: {}", e);
            }
        }
    }

    /// This request's answer token, for the rider record.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Forget the window's acknowledgement: the next show waits for a
    /// fresh one and the dwell runs whole from it. Used when what the nod
    /// grants has changed after the card was acknowledged (a rider was
    /// armed), so no nod counts until the card naming the rider is up.
    pub fn reset_ack(&mut self) {
        self.acked_at = None;
        self.state.reset_ack(&self.user, &self.token);
    }

    /// How long a nod must wait before it counts: until `ACK_DWELL` after
    /// the acknowledgement or after the nod card was shown, whichever is
    /// later, and the whole dwell when there is no acknowledgement. The
    /// acknowledgement lands during the scan, so on its own it would be
    /// spent before the nod card is up; the nod show is what the dwell is
    /// for (D4).
    pub fn dwell_left(&self, now: Instant) -> Duration {
        let Some(acked) = self.acked_at else {
            return ACK_DWELL;
        };
        let from = match self.nod_shown_at {
            Some(shown) if shown > acked => shown,
            _ => acked,
        };
        (from + ACK_DWELL).saturating_duration_since(now)
    }

    /// Has the window acknowledged this request?
    #[cfg(test)]
    fn acknowledged(&self) -> bool {
        self.state.acknowledged(&self.user, &self.token)
    }

    fn shell(&self, args: &[&str]) -> Result<()> {
        shell_call(&self.user, args)
    }

    /// Show or update the window. Fails when there is no graphical session to
    /// show it in, which callers treat as "no consent possible".
    /// The first show of a request also waits for the window's own
    /// acknowledgement; without one within `ACK_WAIT` there is no
    /// window on screen that the daemon can vouch for, and that is an error.
    pub fn show(&mut self, state: &str, message: &str, caller: &CallerInfo) -> Result<()> {
        self.waiting = false;
        self.show_inner(state, message, caller, true)
    }

    /// Show the card while the nods are not armed and the daemon waits for
    /// the user to come back to it: the card offers "Ready to nod".
    pub fn show_waiting(&mut self, message: &str, caller: &CallerInfo) -> Result<()> {
        self.waiting = true;
        self.show_inner("scanning", message, caller, true)
    }

    fn show_inner(
        &mut self,
        state: &str,
        message: &str,
        caller: &CallerInfo,
        need_ack: bool,
    ) -> Result<()> {
        // A pending-state show that first carries an armed rider is a card
        // the user has not read: the acknowledgement is reset before the
        // summon, so this show waits for a fresh one and the dwell runs
        // whole from it. The card acknowledges again on a changed rider.
        if need_ack && self.state.rider_unshown(&self.user) {
            self.reset_ack();
        }
        let (passwordless_minutes, face_present) =
            self.state
                .rider_for_payload(&self.user, &self.token, caller.via == "sudo", need_ack);
        let payload = serde_json::to_string(&Payload {
            state,
            message,
            caller,
            token: &self.token,
            waiting: self.waiting,
            passwordless_minutes,
            face_present,
        })?;
        self.shell(&["shell", "summon", "omarchy.faceauth", &payload])?;
        self.open = true;
        self.last = Some((state.to_string(), message.to_string()));
        if need_ack && state == "nod" {
            self.nod_shown_at = Some(Instant::now());
        }
        if need_ack && self.acked_at.is_none() {
            if !self
                .state
                .wait_ack(&self.user, &self.token, Instant::now() + ACK_WAIT)
            {
                self.open = false;
                return Err(anyhow!(
                    "the consent window did not acknowledge the request within {:.0}s",
                    ACK_WAIT.as_secs_f32()
                ));
            }
            self.acked_at = Some(Instant::now());
            log::info!(
                "consent: the window acknowledged the request for {}",
                self.user
            );
        }
        Ok(())
    }

    /// Re-send a pending state to a window that has already acknowledged
    /// the request, with the payload's rider and face fields as they are
    /// now, without waiting for another acknowledgement.
    pub fn show_again(&mut self, state: &str, message: &str, caller: &CallerInfo) -> Result<()> {
        self.show_inner(state, message, caller, false)
    }

    /// A final state: the window keeps itself up for a while and closes on
    /// its own, so the daemon must not hide it (and must not wait).
    pub fn show_final(&mut self, state: &str, message: &str, caller: &CallerInfo) {
        self.waiting = false;
        let _ = self.show_inner(state, message, caller, false);
        self.open = false;
        self.last = None;
    }

    pub fn hide(&mut self) {
        if self.open {
            if let Err(e) = self.shell(&["shell", "hide", "omarchy.faceauth"]) {
                log::warn!("consent window: hide failed: {}", e);
            }
            self.open = false;
            self.last = None;
        }
    }
}

impl Drop for Dialog {
    fn drop(&mut self) {
        self.hide();
        self.state.clear_token(&self.user, &self.token);
    }
}

#[cfg(test)]
mod window_ack_tests {
    use super::*;

    /// The acknowledgement is accepted only with the live request's token,
    /// and a new request forgets the last one's.
    #[test]
    fn an_acknowledgement_needs_the_live_token_and_is_per_request() {
        let cfg = Config::default();
        let user = "faceauth-ack-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let mut d = Dialog::new(&cfg, user, st).unwrap();
        assert!(!d.acknowledged());
        assert!(!st.ack(user, None));
        assert!(!st.ack(user, Some("not-the-token")));
        assert!(!d.acknowledged());
        let token = d.token().to_string();
        assert!(st.ack(user, Some(&token)));
        assert!(d.acknowledged());
        assert_eq!(
            d.dwell_left(Instant::now()),
            ACK_DWELL,
            "no dwell has run before the show records the acknowledgement"
        );
        // The acknowledgement wakes a show waiting for it through the
        // condition variable, not a poll.
        d.reset_ack();
        assert!(!d.acknowledged());
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            st.ack(user, Some(&token))
        });
        let started = Instant::now();
        assert!(st.wait_ack(user, d.token(), Instant::now() + Duration::from_secs(2)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(t.join().unwrap());
        let old = d.token().to_string();
        drop(d);
        let d2 = Dialog::new(&cfg, user, st).unwrap();
        assert!(!d2.acknowledged(), "a new request starts unacknowledged");
        assert!(!st.ack(user, Some(&old)), "the old token no longer answers");
        assert!(!st.wait_ack(user, d2.token(), Instant::now() + Duration::from_millis(50)));
    }

    #[test]
    fn the_dwell_runs_from_the_acknowledgement() {
        let cfg = Config::default();
        let user = "faceauth-dwell-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let mut d = Dialog::new(&cfg, user, st).unwrap();
        let at = Instant::now();
        d.acked_at = Some(at);
        assert_eq!(d.dwell_left(at), ACK_DWELL);
        assert_eq!(
            d.dwell_left(at + Duration::from_millis(1000)),
            Duration::from_millis(500)
        );
        assert_eq!(d.dwell_left(at + Duration::from_secs(5)), Duration::ZERO);
    }
}

#[cfg(test)]
mod payload_size_tests {
    use super::*;

    /// D5: the payload carries what the card reads and not the raw command
    /// line, so a command of any length keeps its card. The summon is one
    /// argv string, and the kernel refuses one over 131072 bytes.
    #[test]
    fn the_payload_stays_small_for_any_command() {
        for n in [16_000usize, 100_000, 115_000, 400_000] {
            let raw: String = "sudo cp ".to_string() + &"a/b ".repeat(n / 4);
            let (command, clipped) = clip_command(&raw);
            let caller = CallerInfo {
                pid: 1234,
                exe: "/usr/bin/sudo".into(),
                cmdline: raw.clone(),
                command,
                verified: true,
                clipped,
                who: "sudo (pid 1234)  from  bash (1200) <- foot (1100)".into(),
                parents: "bash (1200) <- foot (1100)".into(),
                kill_pid: 1234,
                via: "sudo".into(),
                requester: Some(1234),
            };
            let json = serde_json::to_string(&Payload {
                state: "scanning",
                message: "Look at the camera.",
                caller: &caller,
                token: "00112233445566778899aabbccddeeff",
                waiting: false,
                passwordless_minutes: None,
                face_present: false,
            })
            .unwrap();
            assert!(
                json.len() < 65_536,
                "cmdline {} bytes: payload {} bytes",
                raw.len(),
                json.len()
            );
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            for read in ["who", "command", "clipped", "verified", "kill_pid", "via"] {
                assert!(
                    v["caller"].get(read).is_some(),
                    "the card reads caller.{}",
                    read
                );
            }
            for unread in ["cmdline", "exe", "pid", "parents", "requester"] {
                assert!(
                    v["caller"].get(unread).is_none(),
                    "caller.{} is not the card's",
                    unread
                );
            }
        }
    }
}

#[cfg(test)]
mod window_text_tests {

    /// The token answers only its own request, only while that request's
    /// window lives, and a wrong token changes nothing in the record (H9).
    #[test]
    fn a_token_matches_only_itself_and_only_while_the_request_lives() {
        use super::{Answer, Dialog};
        let user = "window-text-test-user";
        let cfg = crate::config::Config::default();
        let st = super::test_state();
        assert!(
            !st.token_matches(user, Some("anything")),
            "no request, no match"
        );
        assert!(
            Dialog::new(&cfg, user, st).is_err(),
            "no live request, no window"
        );
        let _turn = st.test_live(1000, user);
        assert!(
            !st.token_matches(user, Some("anything")),
            "live but no window yet: no token"
        );
        let d = Dialog::new(&cfg, user, st).unwrap();
        let tok = d.token().to_string();
        assert_eq!(tok.len(), 32);
        assert!(st.token_matches(user, Some(&tok)));
        assert!(!st.token_matches(user, Some(&tok[..31])));
        assert!(!st.token_matches(user, Some(&format!("{}0", tok))));
        assert!(!st.token_matches(user, None));
        assert!(!st.token_matches("someone-else", Some(&tok)));
        assert_eq!(
            st.answer(user, Some("wrong"), Answer::Dismiss),
            Err("no pending request")
        );
        assert!(!st.answered(user), "a wrong-token answer changes nothing");
        assert!(!st.ack(user, Some("wrong")));
        assert!(!d.acknowledged());
        assert_eq!(st.answer(user, Some(&tok), Answer::Dismiss), Ok(()));
        assert!(st.answered(user));
        assert!(matches!(st.poll(user), Some(Answer::Dismiss)));
        drop(d);
        assert!(
            !st.token_matches(user, Some(&tok)),
            "the token dies with the request"
        );
    }
}

#[cfg(test)]
mod dwell_tests {
    use super::*;

    /// D4: the acknowledgement lands during the scan, so a dwell measured
    /// from it alone is spent before the nod card is up. The dwell runs
    /// from the nod show instead, and whole again on every re-show.
    #[test]
    fn the_dwell_runs_from_the_nod_show_not_the_acknowledgement() {
        let cfg = Config::default();
        let user = "faceauth-nod-dwell-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let mut d = Dialog::new(&cfg, user, st).unwrap();
        let acked = Instant::now();
        d.acked_at = Some(acked);
        // The earliest the hook can run: the settle, the pattern settle
        // and eight frames of phase lock at 30 fps, then the nod show.
        let hook_at = acked + Duration::from_millis(1200 + 150 + 270);
        assert_eq!(
            d.dwell_left(hook_at),
            Duration::ZERO,
            "from the ack alone the dwell has lapsed"
        );
        d.nod_shown_at = Some(hook_at);
        assert_eq!(
            d.dwell_left(hook_at),
            ACK_DWELL,
            "at the hook the whole dwell is left"
        );
        assert_eq!(
            d.dwell_left(hook_at + Duration::from_millis(1000)),
            Duration::from_millis(500)
        );
        assert_eq!(
            d.dwell_left(hook_at + Duration::from_secs(5)),
            Duration::ZERO
        );
        // A re-show later (a rider armed, a re-arm) starts it over.
        let again = hook_at + Duration::from_secs(40);
        d.nod_shown_at = Some(again);
        assert_eq!(d.dwell_left(again), ACK_DWELL);
        // An acknowledgement newer than the nod show wins, as before.
        d.acked_at = Some(again + Duration::from_secs(1));
        assert_eq!(d.dwell_left(again + Duration::from_secs(1)), ACK_DWELL);
    }
}

#[cfg(test)]
mod passwordless_tests {
    use super::*;

    /// The rider belongs to one request: it is armed only with that
    /// request's token, on a sudo lane, while the enrolled face is in the
    /// nod window; it is honoured only once the card has been shown it;
    /// and it is gone when that request's Dialog drops.
    #[test]
    fn a_rider_is_bound_to_its_request_and_dies_with_it() {
        let cfg = Config::default();
        let user = "faceauth-passwordless-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let d = Dialog::new(&cfg, user, st).unwrap();
        let token = d.token().to_string();
        assert_eq!(
            st.rider_state(user),
            Some((None, false)),
            "a request begins with an empty rider"
        );
        assert_eq!(
            st.arm_passwordless(user, &token, 15),
            Err("no pending request"),
            "nothing to arm before the card has been shown"
        );
        // The first show starts the record, on a polkit lane here.
        st.rider_for_payload(user, &token, false, true);
        st.set_face_present(user, true);
        assert_eq!(
            st.arm_passwordless(user, &token, 15),
            Err("only a sudo request can carry it")
        );
        // The same request on the sudo lane, with the face away.
        st.rider_for_payload(user, &token, true, true);
        st.set_face_present(user, false);
        assert_eq!(
            st.arm_passwordless(user, &token, 15),
            Err("look at the camera first")
        );
        assert!(st.set_face_present(user, true));
        assert_eq!(
            st.arm_passwordless(user, &token, 0),
            Err("minutes out of range")
        );
        assert_eq!(
            st.arm_passwordless(user, &token, PASSWORDLESS_MAX_MINUTES + 1),
            Err("minutes out of range")
        );
        assert_eq!(
            st.arm_passwordless(user, "not-the-token", 15),
            Err("no pending request"),
            "another token arms nothing"
        );
        assert_eq!(st.arm_passwordless(user, &token, 15), Ok(()));
        assert!(
            st.rider_unshown(user),
            "the nod window must re-show the card"
        );
        assert_eq!(
            st.rider_for_payload(user, &token, true, false),
            (None, true),
            "a payload that waits for no acknowledgement does not carry an unshown rider"
        );
        assert!(st.rider_unshown(user), "and it stays unshown");
        assert_eq!(
            st.take_passwordless(user, &token),
            None,
            "an arm the card has not been shown is not honoured"
        );
        assert_eq!(st.arm_passwordless(user, &token, 15), Ok(()));
        assert_eq!(
            st.rider_for_payload(user, &token, true, true),
            (Some(15), true)
        );
        assert!(!st.rider_unshown(user));
        assert_eq!(
            st.take_passwordless(user, "another-request"),
            None,
            "a Match under another token enables nothing"
        );
        assert_eq!(
            st.rider_state(user),
            Some((Some(15), true)),
            "and another token does not touch the rider"
        );
        assert_eq!(st.take_passwordless(user, &token), Some(15));
        assert_eq!(st.take_passwordless(user, &token), None, "taken once");
        assert_eq!(st.arm_passwordless(user, &token, 45), Ok(()));
        st.rider_for_payload(user, &token, true, true);
        drop(d);
        assert_eq!(
            st.rider_state(user),
            None,
            "the rider goes when the request's Dialog drops, whichever way it ended"
        );
        // A new request starts clean.
        let d2 = Dialog::new(&cfg, user, st).unwrap();
        assert_eq!(st.rider_state(user), Some((None, false)));
        assert_eq!(
            st.arm_passwordless(user, &token, 15),
            Err("no pending request"),
            "the old request's token arms nothing on the new one"
        );
        drop(d2);
    }

    /// The face flag follows only a live record with a window, and the nod
    /// window's guard clears it when the window ends.
    #[test]
    fn the_face_flag_follows_the_live_record_only() {
        let cfg = Config::default();
        let user = "faceauth-passwordless-face-test-user";
        let st = test_state();
        assert!(
            !st.set_face_present(user, true),
            "no record, nothing to set"
        );
        assert_eq!(st.rider_state(user), None);
        let _turn = st.test_live(1000, user);
        assert!(
            !st.set_face_present(user, true),
            "live without a window, nothing to set"
        );
        let d = Dialog::new(&cfg, user, st).unwrap();
        st.rider_for_payload(user, d.token(), true, true);
        assert!(st.set_face_present(user, true));
        assert!(!st.set_face_present(user, true), "unchanged");
        assert!(st.set_face_present(user, false));
        assert!(
            !st.set_face_present("someone-else", true),
            "another user's name reaches nothing"
        );
        drop(d);
        assert_eq!(st.rider_state(user), None);
    }

    /// An arm after the acknowledgement resets it: the next show waits for
    /// a fresh one and the dwell runs whole from it.
    #[test]
    fn an_arm_after_the_ack_restarts_the_ack_and_the_dwell() {
        let cfg = Config::default();
        let user = "faceauth-passwordless-ack-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let mut d = Dialog::new(&cfg, user, st).unwrap();
        let token = d.token().to_string();
        assert!(st.ack(user, Some(&token)));
        let at = Instant::now() - Duration::from_secs(5);
        d.acked_at = Some(at);
        assert_eq!(d.dwell_left(Instant::now()), Duration::ZERO);
        assert!(d.acknowledged());
        d.reset_ack();
        assert_eq!(d.acked_at(), None);
        assert!(
            !d.acknowledged(),
            "the old acknowledgement no longer counts"
        );
        assert_eq!(
            d.dwell_left(Instant::now()),
            ACK_DWELL,
            "the next nod window starts with a full dwell"
        );
        assert!(
            st.ack(user, Some(&token)),
            "the card acknowledges the re-shown request"
        );
        assert!(d.acknowledged());
    }

    /// The payload carries the armed minutes and the face flag, so the
    /// card draws its rider row from the daemon and not from itself.
    #[test]
    fn the_payload_carries_the_rider_and_the_face() {
        let cfg = Config::default();
        let user = "faceauth-passwordless-payload-test-user";
        let caller = CallerInfo {
            via: "sudo".into(),
            ..Default::default()
        };
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let d = Dialog::new(&cfg, user, st).unwrap();
        let tok = d.token();
        st.rider_for_payload(user, tok, true, true);
        st.set_face_present(user, true);
        assert_eq!(st.arm_passwordless(user, tok, 15), Ok(()));
        let (passwordless_minutes, face_present) = st.rider_for_payload(user, tok, true, true);
        let json = serde_json::to_string(&Payload {
            state: "nod",
            message: "",
            caller: &caller,
            token: tok,
            waiting: false,
            passwordless_minutes,
            face_present,
        })
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["passwordless_minutes"], 15);
        assert_eq!(v["face_present"], true);
        st.set_face_present(user, false);
        let (m, f) = st.rider_for_payload(user, tok, true, true);
        assert_eq!((m, f), (Some(15), false));
        let old = tok.to_string();
        drop(d);
        let d2 = Dialog::new(&cfg, user, st).unwrap();
        let (m, f) = st.rider_for_payload(user, d2.token(), true, true);
        assert_eq!((m, f), (None, false), "a fresh record carries nothing");
        assert_eq!(
            st.rider_for_payload(user, &old, true, true),
            (None, false),
            "the old token reaches nothing"
        );
    }
}
