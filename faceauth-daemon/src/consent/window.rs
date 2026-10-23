//! The consent window as the daemon drives it: the card's states and
//! heartbeat, the answer token it hands the card, and the acknowledgment
//! that says the card is up before any answer counts.

#[cfg(test)]
use super::passwordless::PASSWORDLESS_MAX_MINUTES;
#[cfg(test)]
use super::requester::clip_command;
use super::requester::CallerInfo;
use super::shell::{shell_call_pinned, shell_summon_pinned, Pin};
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

/// After the window acknowledges, how long before a check of the security
/// key or the fingerprint counts: a touch or a finger already under way
/// when the card appeared was not meant for this card. Nods have no dwell
/// (Mike, 2026-10-19): finding the face takes longer than this already.
/// A card naming a passwordless rider keeps it for nods too
/// (`ConsentState::rider_on_card`): the rider can reach the card with no
/// scan before its nods.
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
    /// The daemon is waiting for the user to come back to the card after
    /// a nod window passed unanswered; the card offers "Ready to nod".
    waiting: bool,
    /// The last pending state and message sent, for the heartbeat.
    last: Option<(String, String)>,
    /// The user's desktops when the request's card was made, as its work
    /// began (fix round 10, Codex 6; at its first show in round 9): every
    /// show, call and notice checks they are still exactly the user's live
    /// desktops before it is dispatched, and each unit checks again as it
    /// starts. None when there was no desktop then: nothing is dispatched.
    pin: Option<Pin>,
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
    /// grays the passwordless button otherwise, and the daemon refuses an
    /// arm otherwise, so the button and the socket obey one signal.
    face_present: bool,
    /// A key watch is running for this request: a touch of the user's
    /// security key approves it, and the card says so.
    key_armed: bool,
    /// The lane's key line asks for a PIN: the card shows a PIN field
    /// beside the key line.
    key_pin: bool,
    /// No PIN is waiting or in use: the card asks for the PIN, not for a
    /// touch.
    key_pin_wanted: bool,
    /// A fingerprint watch is running for this request: a matching finger
    /// approves it, and the card says so on a line of its own.
    fprint_armed: bool,
    /// What that line says: `place` (place a finger), `retry` (no match,
    /// try again) or `busy` (the reader did not answer).
    fprint_status: &'static str,
    /// The daemon holds no acknowledgment for this show and waits for one:
    /// the card acknowledges once it has drawn this payload, even for a
    /// request it already showed (the card coming back after the unlock).
    ack_wanted: bool,
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
            waiting: false,
            last: None,
            pin: Pin::take(user).ok(),
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

    /// Forget the window's acknowledgment: the next show waits for a
    /// fresh one. Used when what the nod grants has changed after the card
    /// was acknowledged (a rider was armed), so no nod counts until the
    /// card naming the rider has acknowledged.
    pub fn reset_ack(&mut self) {
        self.acked_at = None;
        self.state.reset_ack(&self.user, &self.token);
    }

    /// Has the window acknowledged this request?
    #[cfg(test)]
    fn acknowledged(&self) -> bool {
        self.state.acknowledged(&self.user, &self.token)
    }

    /// The card's pin, taken when it was made.
    fn pinned(&self) -> Result<&Pin> {
        self.pin.as_ref().ok_or_else(|| {
            anyhow!(
                "{} had no graphical session when the request began; nothing is run in their manager",
                self.user
            )
        })
    }

    /// A notice about this request, under the card's pin.
    pub fn notify(&self, title: &str, body: &str) {
        if let Ok(pin) = self.pinned() {
            self.beat();
            super::shell::notify(pin, title, body);
        }
    }

    /// Tell the request's PAM line now that the daemon is at work (fix
    /// round 10, Opus N3): before every call into the session, each of
    /// which may run up to `USER_CALL_WITHIN`, so calls in a row never add
    /// up to a silence the line gives up on.
    pub fn beat(&self) {
        self.state.beat_now(&self.user);
    }

    fn shell(&self, args: &[&str]) -> Result<()> {
        let pin = self.pinned()?;
        self.beat();
        shell_call_pinned(pin, args)
    }

    /// Show or update the window. Fails when there is no graphical session to
    /// show it in, which callers treat as "no consent possible".
    /// The first show of a request also waits for the window's own
    /// acknowledgment; without one within `ACK_WAIT` there is no
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
        // the user has not read: the acknowledgment is reset in the same
        // look at the record that marks the rider shown, before the summon,
        // so this show waits for a fresh one. The card acknowledges again
        // on a changed rider.
        let (passwordless_minutes, face_present, ack_reset) =
            self.state
                .rider_snapshot(&self.user, &self.token, caller.via == "sudo", need_ack);
        if ack_reset {
            self.acked_at = None;
        }
        let key = self.state.key_for_payload(&self.user, &self.token);
        let fprint = self.state.fprint_for_payload(&self.user, &self.token);
        let payload = serde_json::to_string(&Payload {
            state,
            message,
            caller,
            token: &self.token,
            waiting: self.waiting,
            passwordless_minutes,
            face_present,
            key_armed: key.armed,
            key_pin: key.pin,
            key_pin_wanted: key.pin_wanted,
            fprint_armed: fprint.armed,
            fprint_status: fprint.status.word(),
            ack_wanted: need_ack && self.acked_at.is_none(),
        })?;
        let pin = self.pinned()?;
        self.beat();
        shell_summon_pinned(pin, "omarchy.faceauth", &payload)?;
        self.open = true;
        self.last = Some((state.to_string(), message.to_string()));
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
    /// now, without waiting for another acknowledgment.
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

    /// The acknowledgment is accepted only with the live request's token,
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
        // The acknowledgment wakes a show waiting for it through the
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
                kill_ino: 0,
                via: "sudo".into(),
                requester: Some(1234),
                requester_fd: None,
                bind: Default::default(),
            };
            let json = serde_json::to_string(&Payload {
                state: "scanning",
                message: "Look at the camera.",
                caller: &caller,
                token: "00112233445566778899aabbccddeeff",
                waiting: false,
                passwordless_minutes: None,
                face_present: false,
                key_armed: false,
                key_pin: false,
                key_pin_wanted: false,
                fprint_armed: false,
                fprint_status: "place",
                ack_wanted: true,
            })
            .unwrap();
            assert!(
                json.len() < 65_536,
                "cmdline {} bytes: payload {} bytes",
                raw.len(),
                json.len()
            );
            let v: serde_json::Value = serde_json::from_str(&json).unwrap();
            for read in [
                "who", "command", "clipped", "verified", "kill_pid", "kill_ino", "via",
            ] {
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
mod passwordless_tests {
    use super::*;

    /// A nod window whose card names a passwordless rider keeps the dwell
    /// and the still second (`wait_for_nods`), however the rider reached the
    /// card: re-shown after the nods began, or carried by the first nod show
    /// when it was armed between the match and that show (Codex's delta
    /// review of 1126adf). The window reads it from the record, not from
    /// how the caller got there.
    /// Arming closes with the nods: one look at the record says whether a
    /// rider was armed since the window's last check, and refuses any arm
    /// after it, so none reaches the confirm's show, which would mark it
    /// shown with no nod at a card naming it (Codex's second delta review).
    #[test]
    fn arming_closes_with_the_nods() {
        let cfg = Config::default();
        let user = "faceauth-rider-close-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let d = Dialog::new(&cfg, user, st).unwrap();
        let token = d.token().to_string();
        st.rider_for_payload(user, &token, true, true);
        assert!(st.set_face_present(user, true));
        assert!(
            !st.close_rider_arming(user),
            "nothing armed, the nods stand"
        );
        assert_eq!(
            st.arm_passwordless(user, &token, 15),
            Err("look at the camera first"),
            "closed: no arm after the nods"
        );
        assert!(st.set_face_present(user, true));
        assert_eq!(st.arm_passwordless(user, &token, 15), Ok(()));
        assert!(
            st.close_rider_arming(user),
            "an arm since the last check sends the card back"
        );
        st.rider_snapshot(user, &token, true, true);
        assert!(st.set_face_present(user, true));
        assert!(
            !st.close_rider_arming(user),
            "a rider the card has shown is the one the nods answered"
        );
        drop(d);
    }

    #[test]
    fn a_card_naming_a_rider_is_known_to_the_nod_window() {
        let cfg = Config::default();
        let user = "faceauth-rider-on-card-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let d = Dialog::new(&cfg, user, st).unwrap();
        let token = d.token().to_string();
        st.rider_for_payload(user, &token, true, true);
        assert!(!st.rider_on_card(user), "no rider, nothing to guard");
        assert!(st.set_face_present(user, true));
        assert_eq!(
            st.arm_passwordless(user, &token, PASSWORDLESS_MAX_MINUTES),
            Ok(())
        );
        assert!(
            !st.rider_on_card(user),
            "armed but not yet shown: the window ends on it instead"
        );
        // Any show that waits for an acknowledgment marks it shown, the
        // first nod show among them.
        let (shown, _, reset) = st.rider_snapshot(user, &token, true, true);
        assert_eq!(shown, Some(PASSWORDLESS_MAX_MINUTES));
        assert!(reset);
        assert!(
            st.rider_on_card(user),
            "the card names it: the nods after this show are guarded"
        );
        drop(d);
    }

    /// The rider belongs to one request: it is armed only with that
    /// request's token, on a sudo lane, while the enrolled face is in the
    /// nod window; it is honored only once the card has been shown it;
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
            "a payload that waits for no acknowledgment does not carry an unshown rider"
        );
        assert!(st.rider_unshown(user), "and it stays unshown");
        assert_eq!(
            st.take_passwordless(user, &token),
            None,
            "an arm the card has not been shown is not honored"
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

    /// An arm after the acknowledgment resets it: the next show waits for
    /// a fresh one.
    #[test]
    fn an_arm_after_the_ack_restarts_the_ack() {
        let cfg = Config::default();
        let user = "faceauth-passwordless-ack-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let mut d = Dialog::new(&cfg, user, st).unwrap();
        let token = d.token().to_string();
        assert!(st.ack(user, Some(&token)));
        let at = Instant::now() - Duration::from_secs(5);
        d.acked_at = Some(at);
        assert!(d.acknowledged());
        d.reset_ack();
        assert_eq!(d.acked_at(), None);
        assert!(!d.acknowledged(), "the old acknowledgment no longer counts");
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
            key_armed: false,
            key_pin: false,
            key_pin_wanted: false,
            fprint_armed: false,
            fprint_status: "place",
            ack_wanted: false,
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

    /// The payload says the key works exactly while a watch is armed on
    /// this request, asks for its PIN only when the lane's line does, and
    /// a new request starts with both off.
    #[test]
    fn the_payload_says_whether_the_key_is_armed() {
        let cfg = Config::default();
        let user = "faceauth-key-payload-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let d = Dialog::new(&cfg, user, st).unwrap();
        let tok = d.token().to_string();
        assert_eq!(
            st.key_for_payload(user, &tok).pair(),
            (false, false),
            "a request starts with the key off"
        );
        let g = st.arm_key(user, &tok, false).unwrap();
        assert_eq!(st.key_for_payload(user, &tok).pair(), (true, false));
        assert_eq!(
            st.key_for_payload(user, "another-token").pair(),
            (false, false)
        );
        st.disarm_key(user, &tok, g);
        assert_eq!(
            st.key_for_payload(user, &tok).pair(),
            (false, false),
            "off once the watch ends"
        );
        st.arm_key(user, &tok, true).unwrap();
        assert_eq!(
            st.key_for_payload(user, &tok).pair(),
            (true, true),
            "a PIN lane asks for the PIN"
        );
        drop(d);
        let d2 = Dialog::new(&cfg, user, st).unwrap();
        assert_eq!(
            st.key_for_payload(user, d2.token()).pair(),
            (false, false),
            "nothing armed carries over to the next request"
        );
    }

    /// The payload says the fingerprint works exactly while its watch is
    /// armed on this request, carries the watch's status, sends the card
    /// again when the status changes, and a new request starts with it off.
    #[test]
    fn the_payload_says_whether_the_fingerprint_is_armed() {
        use crate::consent::state::FprintStatus;
        let cfg = Config::default();
        let user = "faceauth-fprint-payload-test-user";
        let st = test_state();
        let _turn = st.test_live(1000, user);
        let d = Dialog::new(&cfg, user, st).unwrap();
        let tok = d.token().to_string();
        assert!(
            !st.fprint_for_payload(user, &tok).armed,
            "a request starts with it off"
        );
        let g = st.arm_fprint(user, &tok).unwrap();
        let card = st.fprint_for_payload(user, &tok);
        assert!(card.armed);
        assert_eq!(card.status.word(), "place");
        assert!(!st.fprint_for_payload(user, "another-token").armed);
        assert!(!st.take_key_card_stale(user));
        st.fprint_status(user, &tok, g, FprintStatus::Retry);
        assert_eq!(st.fprint_for_payload(user, &tok).status.word(), "retry");
        assert!(
            st.take_key_card_stale(user),
            "a changed status sends the card again"
        );
        st.fprint_status(user, &tok, g, FprintStatus::Retry);
        assert!(!st.take_key_card_stale(user), "an unchanged one does not");
        st.fprint_status(user, &tok, g + 7, FprintStatus::Busy);
        assert_eq!(
            st.fprint_for_payload(user, &tok).status.word(),
            "retry",
            "a watch no longer armed reports nothing"
        );
        st.disarm_fprint(user, &tok, g);
        assert!(
            !st.fprint_for_payload(user, &tok).armed,
            "off once the watch ends"
        );
        st.arm_fprint(user, &tok).unwrap();
        st.key_off(user, false);
        assert!(
            !st.fprint_for_payload(user, &tok).armed,
            "a hold or the wait for attention takes it off with the key"
        );
        drop(d);
        let d2 = Dialog::new(&cfg, user, st).unwrap();
        assert!(
            !st.fprint_for_payload(user, d2.token()).armed,
            "nothing armed carries over to the next request"
        );
    }
}
