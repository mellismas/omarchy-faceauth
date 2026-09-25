//! The consent flow as the authenticator runs it: the request opens its
//! window first, then scans for the face, then waits for the nod, and parks
//! whenever the user leaves. It lives apart from the plain attempt because
//! one request can span several rounds with the camera.

use super::attempt::{consent_floors, faillock_reset, Authenticator};
use super::confirm::{confirm, nod_frames_match, Confirm};
use super::cooldown::COOLDOWN_FAILURES;
use super::outcome::{consent_denied, denied_text, refused, Outcome, Refusal};
use super::rearm::{attention_wait, hold_wait, RearmGate};
use super::scan::Scan;
use crate::capture::IrCapture;
use crate::consent::{notify, wait_for_nods, Answer, ConsentState, Dialog, Gesture, CONSENT};
use crate::presence::{presence_mode, PresenceConfig, PresenceMode};
use crate::store::UserTemplates;
use anyhow::Result;
use faceauth_engine::Pipeline;
use std::time::{Duration, Instant};

/// The nods that approve a request: one gesture, which the detector
/// counts as two nods (down-up, down-up). Fixed, so the card's "Nod 2
/// times" and the count the window needs cannot disagree (H15).
pub const NODS_NEEDED: usize = 2;

/// A consent request has no deadline: like the lock screen it waits,
/// looking for attention, until it is answered or the requester goes
/// away.
pub struct ConsentSession {
    pub user: String,
    pub caller: crate::consent::CallerInfo,
    pub dialog: Dialog,
    pub started: Instant,
    templates: UserTemplates,
    /// When the enrolled user was last known to be at the card: set as the
    /// request starts and refreshed only by a scan match, a passing identity
    /// look, and the nod window's frames of the matched box. The request's
    /// own away clock runs from it, wherever the round is (a scan, the wait
    /// for attention, a hold), so a stranger who takes the chair while a
    /// card is up is locked out at the presence away time like anyone
    /// else (E2). The server resets it when a parked request resumes at an
    /// unlock.
    pub user_seen_at: std::cell::Cell<Instant>,
}

pub enum Round {
    Done(Outcome),
    /// No face for the away time: lock, park, come back.
    FaceLost,
    /// The session locked under the card by other means (the idle lock, a
    /// key, the lid): park without locking again, come back at the unlock.
    SessionLocked,
}

impl Authenticator {
    /// An elevation request: the window goes up first, so nothing happens
    /// silently; then the face must match, then the nod must come.
    /// Start a consent request: open the window, load the templates, mark the
    /// user pending. Errors are final outcomes.
    /// With `open_window` false (the session is locked) the window is not
    /// summoned; the caller shows it when the request resumes.
    pub fn consent_begin(
        &mut self,
        user: &str,
        caller: crate::consent::CallerInfo,
        open_window: bool,
    ) -> std::result::Result<ConsentSession, Outcome> {
        // The request has no deadline: gestures are read for
        // `consent_seconds` after each match, and when that passes unanswered
        // the camera drops to the presence rhythm and an attentive face
        // re-arms it, as the lock screen does.
        let mut dialog = match Dialog::new(&self.cfg, user, &CONSENT) {
            Ok(d) => d,
            Err(e) => {
                return Err(Outcome::Error {
                    message: e.to_string(),
                })
            }
        };
        if open_window {
            if let Err(e) = dialog.show("scanning", "Look at the camera.", &caller) {
                log::warn!("consent: no window for {}: {}", user, e);
                return Err(consent_denied(Refusal::NoWindow, 0));
            }
        }
        let templates = match self.store.load(user) {
            Ok(Some(t)) => t,
            // The window is already up with this request's token: bring it
            // down, or it keeps that token as pending and ignores the next
            // request's summon (seen live when a store failed to load).
            Ok(None) => {
                dialog.hide();
                return Err(Outcome::NotEnrolled);
            }
            Err(e) => {
                dialog.hide();
                return Err(Outcome::Error {
                    message: e.to_string(),
                });
            }
        };
        self.last_consent.insert(user.to_string(), Instant::now());
        Ok(ConsentSession {
            user: user.to_string(),
            caller,
            dialog,
            started: Instant::now(),
            templates,
            user_seen_at: std::cell::Cell::new(Instant::now()),
        })
    }

    /// One round with the camera: scan until the face matches, then watch for
    /// the nod. Ends with a verdict, or with the user gone (no face for the
    /// presence watch's away time) so the caller can lock the session, park
    /// without the camera and come back for another round.
    pub fn consent_round(&mut self, s: &mut ConsentSession) -> Round {
        let cfg = self.cfg.clone();
        let state = &CONSENT;
        let user = s.user.clone();
        let started = s.started;
        let lost_after = lost_after_for(&cfg.presence, &s.user, presence_mode());
        let msg = format!("Recognised. Nod {} times to allow this, shake your head to refuse, or type your password.", NODS_NEEDED);
        let floors_deg = consent_floors(&s.templates.gesture);
        let seen = &s.user_seen_at;
        let dialog_cell = std::cell::RefCell::new(&mut s.dialog);
        let caller_ref = &s.caller;
        let gesture_cell: std::cell::RefCell<Option<Gesture>> = std::cell::RefCell::new(None);
        let gesture: Option<Gesture>;
        let outcome;
        loop {
            // An answer already waiting (typed during a hold or a wait)
            // goes to the scan start, which takes it before touching the
            // camera; it is the user's, whether or not the camera saw them.
            let answered = state.answered(&user);
            // The request's own away clock (E2): a scan that ended without
            // the user, however it ended, does not start the clock over.
            if let Some(l) = lost_after {
                if !answered && seen.get().elapsed() > l {
                    log::info!(
                        "consent: the user has not been seen for {:.0}s; the user left",
                        l.as_secs_f32()
                    );
                    return Round::FaceLost;
                }
            }
            // A hold (the cooldown counts the lock screen's failures and this
            // lane's together) pauses the face checks, not the request: the
            // window stays up with its password box, and when the hold is
            // over the scan resumes on its own.
            if let Some(hold) = self.hold_for(&user) {
                if !answered {
                    log::warn!(
                        "consent for {}: {} recent failures; face checks paused for {}s",
                        user,
                        COOLDOWN_FAILURES,
                        hold.as_secs()
                    );
                    let _ = dialog_cell.borrow_mut().show("password", &format!("Too many failed face checks. They pause for {} seconds; type your password, or wait.", hold.as_secs().max(1)), caller_ref);
                    if let Some(r) = self.wait_for_hold(&user, hold, state, seen, lost_after) {
                        return r;
                    }
                    continue;
                }
            }
            // A card the lock screen covers is a card nobody nods at, and
            // the lock screen needs the camera: park until the unlock (D2).
            if crate::consent::session_locked(&user) {
                log::info!("consent: the session is locked; the request parks until the unlock");
                return Round::SessionLocked;
            }
            let templates_ref = &s.templates;
            let mut hook = |cap: &mut IrCapture,
                            pipeline: &mut Pipeline,
                            matched: &faceauth_engine::Face|
             -> Result<bool> {
                // The scan just matched the enrolled face: from here until
                // the nod window ends the card may arm passwordless sudo,
                // and the payload says so. The match is the user at the
                // card, so the away clock starts over.
                state.set_face_present(&user, true);
                seen.set(Instant::now());
                // No window the daemon can vouch for, no nods: the request
                // ends and the caller's stack falls to its password.
                if let Err(e) = dialog_cell.borrow_mut().show("nod", &msg, caller_ref) {
                    log::warn!(
                        "consent for {}: the window is not there to nod at: {}",
                        user,
                        e
                    );
                    *gesture_cell.borrow_mut() = Some(Gesture::NoWindow);
                    return Ok(false);
                }
                let window = cfg.consent_seconds.max(10.0);
                let mut nod_frames = Vec::new();
                let mut start = Some(matched.bbox);
                // The card follows the face: when the nod window loses or
                // regains the matched face the card is told, so its
                // passwordless button greys and ungreys with the daemon's
                // own view. The show carries no ack wait.
                let presence = |_present: bool| {
                    let _ = dialog_cell.borrow_mut().show_again("nod", &msg, caller_ref);
                };
                let locked = || crate::consent::session_locked(&user);
                let (g, followed) = loop {
                    let dwell = dialog_cell.borrow().dwell_left(Instant::now());
                    let (g, followed) = wait_for_nods(
                        cap,
                        pipeline,
                        &cfg,
                        Duration::from_secs_f32(window),
                        NODS_NEEDED,
                        Some((state, user.as_str())),
                        lost_after,
                        floors_deg,
                        start,
                        dwell,
                        &mut nod_frames,
                        Some(&presence),
                        Some(&locked),
                        seen,
                    )?;
                    if g != Gesture::RiderArmed {
                        break (g, followed);
                    }
                    // The card armed passwordless sudo: what the nod grants
                    // changed, so the card is shown again naming it. The
                    // show resets the acknowledgement and waits for a fresh
                    // one; the dwell then runs whole and the nods start
                    // over at a card that says what they approve.
                    nod_frames.clear();
                    start = followed;
                    state.set_face_present(&user, true);
                    let mut d = dialog_cell.borrow_mut();
                    if let Err(e) = d.show("nod", &msg, caller_ref) {
                        log::warn!(
                            "consent for {}: the window did not re-acknowledge the passwordless rider: {}",
                            user,
                            e
                        );
                        *gesture_cell.borrow_mut() = Some(Gesture::NoWindow);
                        return Ok(false);
                    }
                };
                let g = if g == Gesture::Nodded {
                    // The nods came from the followed box; before they count,
                    // that box must be live and enrolled, right now, and the
                    // frames kept from the nods themselves must be the
                    // enrolled face too (D4): a face swapped in for the
                    // gesture and out again before the confirm is refused.
                    let _ = dialog_cell
                        .borrow_mut()
                        .show("confirming", "Confirming.", caller_ref);
                    match confirm(
                        cap,
                        pipeline,
                        &cfg,
                        templates_ref,
                        followed.unwrap_or(matched.bbox),
                    )? {
                        Confirm::Live => match nod_frames_match(
                            pipeline,
                            templates_ref,
                            &nod_frames,
                            &cap.identity,
                            cfg.accept_threshold,
                        )? {
                            Ok(()) => Gesture::Nodded,
                            Err(why) => Gesture::ConfirmFailed(why),
                        },
                        Confirm::NoSignal => Gesture::ConfirmUnclear,
                        Confirm::Refused(why) => Gesture::ConfirmFailed(why),
                    }
                } else {
                    g
                };
                let ok = matches!(g, Gesture::Nodded | Gesture::Password(_));
                *gesture_cell.borrow_mut() = Some(g);
                Ok(ok)
            };
            let scan = cfg.consent_scan_seconds;
            let (g, o) = match self.run_with_answers(
                &s.templates,
                Some(&mut hook),
                scan,
                Some((state, user.as_str())),
            ) {
                Ok(Scan::Done(o)) => (gesture_cell.borrow_mut().take(), o),
                // The window answered before the face matched: the answer
                // is the user's whether or not the camera saw them (J18).
                Ok(Scan::Answered(a)) => (
                    Some(match a {
                        Answer::Password(pw) => Gesture::Password(pw),
                        Answer::Dismiss => Gesture::Dismissed,
                        Answer::Gone | Answer::Rearm => Gesture::Gone,
                    }),
                    Outcome::NoFace {
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    },
                ),
                Err(e) => (
                    None,
                    Outcome::Error {
                        message: e.to_string(),
                    },
                ),
            };
            match (&g, &o) {
                // Nobody is waiting for the verdict: no verdict, and the
                // window comes down when the session drops.
                (Some(Gesture::Gone), _) => {
                    return Round::Done(consent_denied(
                        Refusal::Gone,
                        started.elapsed().as_millis() as u64,
                    ))
                }
                (Some(Gesture::NoWindow), _) => {
                    return Round::Done(consent_denied(
                        Refusal::NoWindow,
                        started.elapsed().as_millis() as u64,
                    ))
                }
                (Some(Gesture::FaceLost), _) => return Round::FaceLost,
                (Some(Gesture::SessionLocked), _) => return Round::SessionLocked,
                // The followed face left its place and a single face is back
                // in view: whether it is the user is the scan's to say, not
                // the tracker's, so the round scans again before any nod
                // counts (E2).
                (Some(Gesture::Moved), _) => {
                    log::info!(
                        "consent: the matched face moved; scanning again before the nods resume"
                    );
                    let _ = dialog_cell.borrow_mut().show(
                        "scanning",
                        "Look at the camera again, or type your password.",
                        caller_ref,
                    );
                    continue;
                }
                (None, Outcome::NoFace { .. }) if lost_after.is_some() => return Round::FaceLost,
                // The confirm could not read the strobe (a bright room, the
                // user leaned away): not a refusal. Ask for the face and go
                // round again.
                (Some(Gesture::ConfirmUnclear), _) => {
                    log::info!(
                        "consent: the confirm saw no strobe signal; asking for the face again"
                    );
                    let _ = dialog_cell.borrow_mut().show(
                        "scanning",
                        "Could not confirm. Face the camera and nod again, or type your password.",
                        caller_ref,
                    );
                    let beat = || dialog_cell.borrow_mut().heartbeat(caller_ref);
                    if let Some(r) =
                        self.wait_for_attention(&user, state, lost_after, false, seen, &beat)
                    {
                        return r;
                    }
                    continue;
                }
                // The confirm refused: the thing that nodded is not a live
                // enrolled face. A failure, charged like a refused scan.
                (Some(Gesture::ConfirmFailed(why)), _) => {
                    log::warn!("consent: the confirm after the nods refused ({})", why);
                    let _ = self.charge(&user);
                    outcome = refused(
                        &s.caller,
                        Refusal::Confirm(why.clone()),
                        started.elapsed().as_millis() as u64,
                    );
                    gesture = g;
                    break;
                }
                // The nod window passed with nobody answering: no verdict,
                // and the nods stay unarmed. The camera drops to the
                // presence rhythm, and the request is re-armed when the
                // enrolled face has been away from the card and is back
                // and attentive, or by the card's own "Ready to nod" (Q8):
                // a face that merely stays in view does not re-arm it.
                (Some(Gesture::Timeout), _) => {
                    log::info!("consent: no answer in the nod window; the nods are disarmed until the user is back at the card");
                    let _ = dialog_cell.borrow_mut().show_waiting(
                        "No nod seen. Press Ready to nod and look at the camera, or type your password.",
                        caller_ref,
                    );
                    let beat = || dialog_cell.borrow_mut().heartbeat(caller_ref);
                    if let Some(r) =
                        self.wait_for_attention(&user, state, lost_after, true, seen, &beat)
                    {
                        return r;
                    }
                    continue;
                }
                (None, Outcome::NoMatch { .. }) | (None, Outcome::NoFace { .. }) => {
                    if matches!(o, Outcome::NoMatch { .. }) && self.charge(&user).is_some() {
                        continue; // the loop top shows the hold
                    }
                    let _ = dialog_cell.borrow_mut().show(
                        "scanning",
                        "Face not recognised. Look at the camera, or type your password.",
                        caller_ref,
                    );
                    let beat = || dialog_cell.borrow_mut().heartbeat(caller_ref);
                    if let Some(r) =
                        self.wait_for_attention(&user, state, lost_after, false, seen, &beat)
                    {
                        return r;
                    }
                    continue;
                }
                // A liveness refusal is a verdict for a plain attempt, but the
                // window is waiting for the user: it keeps waiting (nothing is
                // approved by it), and the log keeps the refusal.
                (None, Outcome::Denied { reason, .. }) => {
                    log::info!(
                        "consent: scan refused ({}); the window keeps waiting",
                        reason
                    );
                    if self.charge(&user).is_some() {
                        continue; // the loop top shows the hold
                    }
                    let _ = dialog_cell.borrow_mut().show(
                        "scanning",
                        "Not accepted. Look straight at the camera, or type your password.",
                        caller_ref,
                    );
                    let beat = || dialog_cell.borrow_mut().heartbeat(caller_ref);
                    if let Some(r) =
                        self.wait_for_attention(&user, state, lost_after, false, seen, &beat)
                    {
                        return r;
                    }
                    continue;
                }
                _ => {
                    gesture = g;
                    outcome = o;
                    break;
                }
            }
        }
        Round::Done(self.consent_finish(s, gesture, outcome))
    }

    /// Turn a gesture and a face outcome into the verdict, show it, notify.
    /// Waiting is not scanning. After a round that found nobody to accept,
    /// the camera stays off but for a short look every two seconds, like the
    /// presence watch's, until a face is turned to the camera (then the next
    /// round scans it), the window answers (the next round takes the answer),
    /// or nobody has been there for the presence away time (the user left).
    /// Sit out a hold without scanning: until it is over, or the window
    /// answers (a password or a dismissal, which the next scan start takes).
    /// The chair is still watched at the presence rhythm, so a user who
    /// left during the hold, or a stranger who took the chair, ends the
    /// round with the user gone at the away time (E2).
    fn wait_for_hold(
        &mut self,
        user: &str,
        hold: Duration,
        state: &ConsentState,
        seen: &std::cell::Cell<Instant>,
        lost_after: Option<Duration>,
    ) -> Option<Round> {
        let look_cfg = crate::presence::PresenceConfig {
            user: user.to_string(),
            ..Default::default()
        };
        let strict = crate::presence::presence_mode() == crate::presence::PresenceMode::Secure;
        let mut look =
            |identify: bool| crate::presence::observe_in(self, &look_cfg, identify, strict, false);
        hold_wait(
            &mut look,
            state,
            user,
            Instant::now() + hold,
            seen,
            lost_after,
            Duration::from_millis(200),
        )
    }

    /// Wait, at the presence rhythm, for the request to be re-armed: by
    /// an answer from the card, or by the enrolled face attentive at the
    /// camera. With `need_away` the face must first have been away from
    /// the card (absent, turned away, or not the user) for a look. Ends
    /// with a round when the user left for the away time or the session
    /// locked. `beat` re-sends the card now and then (D1). The identity
    /// look is the presence watch's for the mode in force: in the secure
    /// mode a face the gate read no signal from re-arms nothing.
    fn wait_for_attention(
        &mut self,
        user: &str,
        state: &ConsentState,
        lost_after: Option<Duration>,
        need_away: bool,
        seen: &std::cell::Cell<Instant>,
        beat: &dyn Fn(),
    ) -> Option<Round> {
        let look_cfg = crate::presence::PresenceConfig {
            user: user.to_string(),
            ..Default::default()
        };
        let mode = crate::presence::presence_mode();
        let strict = mode == crate::presence::PresenceMode::Secure;
        let mut look =
            |identify: bool| crate::presence::observe_in(self, &look_cfg, identify, strict, false);
        let locked = || crate::consent::session_locked(user);
        attention_wait(
            &mut look,
            state,
            user,
            &locked,
            beat,
            RearmGate::new(need_away, mode),
            lost_after,
            seen,
            Duration::from_millis(200),
        )
    }

    pub fn consent_finish(
        &mut self,
        s: &mut ConsentSession,
        gesture: Option<Gesture>,
        outcome: Outcome,
    ) -> Outcome {
        let user = s.user.as_str();
        let caller = &s.caller;
        // A password typed at any point is checked against the system stack;
        // a good one approves exactly like a nod.
        let password_ok = match &gesture {
            Some(Gesture::Password(pw)) => crate::pamcheck::check("system-auth", user, pw),
            _ => false,
        };
        let outcome = match (&gesture, outcome) {
            // Anything that is not an approval ends as a consent refusal, so
            // the module ignores it and the terminal password is the floor.
            (Some(Gesture::Timeout), o @ Outcome::Match { .. }) => {
                consent_denied(Refusal::NoAnswer, elapsed_of(&o))
            }
            // A shake or a dismissal is the answer no: the window had the
            // password box, so closing it without either is a refusal that
            // ends the request, not a hand-off to another prompt.
            (Some(Gesture::Dismissed), o) => refused(caller, Refusal::Dismissed, elapsed_of(&o)),
            (Some(Gesture::Shaken), o) => refused(caller, Refusal::Shaken, elapsed_of(&o)),
            (Some(Gesture::Password(_)), o) if !password_ok => {
                // A face was seen and the password behind it was wrong: it
                // counts against the same budget as a failed scan.
                let _ = self.charge(user);
                consent_denied(Refusal::WrongPassword, elapsed_of(&o))
            }
            (_, o) => o,
        };
        let outcome = if password_ok {
            Outcome::Match {
                score: Some(1.0),
                frames: 0,
                elapsed_ms: s.started.elapsed().as_millis() as u64,
            }
        } else {
            outcome
        };
        self.last_consent.insert(user.to_string(), Instant::now());
        if !matches!(outcome, Outcome::Match { .. }) {
            // Whatever the card asked for rides on an approval only.
            let _ = CONSENT.take_passwordless(user, s.dialog.token());
        }
        match &outcome {
            Outcome::Match { frames, .. } => {
                self.last_match.insert(user.to_string(), Instant::now());
                self.failures.remove(user);
                let how = if *frames == 0 {
                    "password"
                } else {
                    "face and nod"
                };
                if *frames > 0 {
                    faillock_reset(user);
                }
                s.dialog.show_final("approved", "Allowed.", caller);
                notify(
                    user,
                    &format!("Root access granted by {}", how),
                    &format!("{}\n{}", caller.command, caller.parents),
                );
                log::info!(
                    "consent granted ({}) for {}: {} [{}]",
                    how,
                    user,
                    caller.command,
                    caller.parents
                );
                // The card's passwordless button: the same approval turns
                // passwordless sudo on for the minutes asked, the way
                // Omarchy's own command would, with no further request.
                // Only the rider armed at this request's own card, and
                // shown on it, counts; the arm itself was refused unless
                // the lane was sudo and the face was in the nod window.
                if let Some(minutes) = CONSENT.take_passwordless(user, s.dialog.token()) {
                    if crate::consent::is_passwordless_command(caller) {
                        log::info!("passwordless sudo for {} not armed from the passwordless command's own request", user);
                        notify(
                            user,
                            "Passwordless sudo: use the command's own answer",
                            "The button does not apply to omarchy-sudo-passwordless itself.",
                        );
                    } else {
                        match crate::consent::enable_passwordless(
                            std::path::Path::new("/etc/sudoers.d"),
                            user,
                            minutes,
                            &|args| crate::consent::run_passwordless_timer(user, args),
                        ) {
                            Ok(_) => {
                                log::warn!("passwordless sudo on for {} for {} min, by the card's button and this approval", user, minutes);
                                notify(user, &format!("Passwordless sudo on for {} minutes", minutes), "Any process running as you can use sudo without asking until then. Setup > Security > Passwordless Sudo turns it off early.");
                            }
                            Err(e) => {
                                log::warn!("passwordless sudo for {} not enabled: {:#}", user, e);
                                notify(user, "Passwordless sudo not enabled", &format!("{:#}", e));
                            }
                        }
                    }
                }
            }
            Outcome::Refused { reason, .. } | Outcome::ConsentDenied { reason, .. }
                if matches!(
                    Refusal::parse(reason),
                    Some(Refusal::Shaken | Refusal::Dismissed)
                ) =>
            {
                // The user closed the window, or shook their head at it: the
                // answer is no, and the window goes away without a verdict on it.
                let _ = CONSENT.take_passwordless(user, s.dialog.token());
                s.dialog.hide();
                let how = if Refusal::parse(reason) == Some(Refusal::Shaken) {
                    "Refused by head shake"
                } else {
                    "Refused: dismissed"
                };
                notify(
                    user,
                    how,
                    &format!("{}\n{}", caller.command, caller.parents),
                );
                log::warn!(
                    "consent refused for {}: {} [{}] ({})",
                    user,
                    caller.command,
                    caller.parents,
                    reason
                );
            }
            Outcome::Refused { reason, .. } | Outcome::ConsentDenied { reason, .. }
                if matches!(Refusal::parse(reason), Some(Refusal::Confirm(_))) =>
            {
                s.dialog.show_final(
                    "denied",
                    "The nod did not come from a live, enrolled face. Refused.",
                    caller,
                );
                notify(
                    user,
                    "Refused: the nod was not a live, enrolled face",
                    &format!("{}\n{}", caller.command, caller.parents),
                );
                log::warn!(
                    "consent refused for {}: {} [{}] ({})",
                    user,
                    caller.command,
                    caller.parents,
                    reason
                );
            }
            Outcome::Cooldown { seconds } => {
                s.dialog.show_final(
                    "denied",
                    &format!(
                        "Too many failed attempts. Try again in {} seconds, or use your password.",
                        seconds
                    ),
                    caller,
                );
                notify(
                    user,
                    "Refused: too many failed attempts",
                    &format!("{}\n{}", caller.command, caller.parents),
                );
                log::warn!(
                    "consent refused for {}: {} [{}] (cooldown {}s)",
                    user,
                    caller.command,
                    caller.parents,
                    seconds
                );
            }
            Outcome::ConsentDenied { .. } => {
                let why = match gesture {
                    Some(Gesture::Password(_)) => "Wrong password. Refused.",
                    _ => "No answer. Refused.",
                };
                s.dialog
                    .show_final("denied", &denied_text(why, caller), caller);
                let how = match gesture {
                    Some(Gesture::Password(_)) => "Refused: wrong password",
                    _ => "Refused: no answer",
                };
                notify(
                    user,
                    how,
                    &format!("{}\n{}", caller.command, caller.parents),
                );
                log::warn!(
                    "consent refused for {}: {} [{}] ({})",
                    user,
                    caller.command,
                    caller.parents,
                    why
                );
            }
            _ => {
                s.dialog
                    .show_final("denied", &denied_text("Refused.", caller), caller);
                notify(
                    user,
                    "Refused",
                    &format!("{}\n{}", caller.command, caller.parents),
                );
            }
        }
        outcome
    }
}

fn elapsed_of(o: &Outcome) -> u64 {
    match o {
        Outcome::Match { elapsed_ms, .. }
        | Outcome::NoMatch { elapsed_ms, .. }
        | Outcome::NoFace { elapsed_ms, .. }
        | Outcome::Denied { elapsed_ms, .. }
        | Outcome::ConsentDenied { elapsed_ms, .. }
        | Outcome::Refused { elapsed_ms, .. } => *elapsed_ms,
        _ => 0,
    }
}

/// The consent round's away clock for `user`: the walk-away lock's away
/// time in `mode`, the mode in force, while the watch is on for this user.
/// None (no watch for them, or the default mode set to "never") means the
/// round never ends with the user gone.
fn lost_after_for(presence: &PresenceConfig, user: &str, mode: PresenceMode) -> Option<Duration> {
    if presence.enabled && presence.user == user {
        presence.away_for(mode)
    } else {
        None
    }
}

#[cfg(test)]
mod lost_after_tests {
    use super::*;
    use crate::presence::{AwayTime, LockWord};

    /// The consent round's clock is the walk-away lock's away time for the
    /// mode in force, and runs only while the watch is on for this user.
    #[test]
    fn the_consent_away_clock_follows_the_mode_in_force() {
        let mut p = PresenceConfig {
            enabled: true,
            user: "alice".into(),
            away_seconds: AwayTime::Seconds(45.0),
            secure_away_seconds: 30.0,
            ..Default::default()
        };
        let default = PresenceMode::Default;
        let secure = PresenceMode::Secure;
        assert_eq!(
            lost_after_for(&p, "alice", default),
            Some(Duration::from_secs(45))
        );
        assert_eq!(
            lost_after_for(&p, "alice", secure),
            Some(Duration::from_secs(30))
        );
        assert_eq!(lost_after_for(&p, "bob", secure), None);
        p.away_seconds = AwayTime::Word(LockWord::Never);
        assert_eq!(lost_after_for(&p, "alice", default), None);
        assert_eq!(
            lost_after_for(&p, "alice", secure),
            Some(Duration::from_secs(30))
        );
        p.enabled = false;
        assert_eq!(lost_after_for(&p, "alice", secure), None);
    }
}
