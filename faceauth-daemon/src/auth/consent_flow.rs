//! The consent flow as the authenticator runs it: the request opens its
//! window first, then scans for the face, then waits for the nod, and parks
//! whenever the user leaves. It lives apart from the plain attempt because
//! one request can span several rounds with the camera.

use super::attempt::{consent_floors, faillock_reset, Authenticator};
use super::confirm::{confirm, nod_frames_match, Confirm};
use super::cooldown::COOLDOWN_FAILURES;
use super::outcome::{consent_denied, denied_text, refused, Outcome, Refusal};
use super::rearm::{attention_wait, gone_after_unscored, hold_wait, Pace, RearmGate, UserSeen};
use super::scan::Scan;
use crate::capture::IrCapture;
use crate::consent::{wait_for_nods, Answer, ConsentState, Dialog, Gesture, CONSENT, FPRINT, KEY};
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
    /// request starts and restarted by a scan match, the nod window's
    /// frames of the matched box, and any look the presence watch's rules
    /// would hold (in the default mode, any face turned to the screen,
    /// checked or not). The request's
    /// own away clock runs from it, wherever the round is (a scan, the wait
    /// for attention, a hold), by the presence watch's rules for who holds
    /// the clock: a chair the watch would hold keeps the card, and one it
    /// would not (a stranger in the secure mode, nobody) is locked out at
    /// the presence away time (E2). The server resets it when a parked
    /// request resumes at an unlock.
    pub user_seen_at: UserSeen,
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
            user_seen_at: UserSeen::new(Instant::now()),
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
        let watched = is_watched(&cfg.presence, &s.user);
        let msg = format!("Recognized. Nod {} times to allow this, shake your head to refuse, or type your password.", NODS_NEEDED);
        let floors_deg = consent_floors(&s.templates.gesture);
        // The away clock holds wherever the presence watch's would: the
        // round runs a copy of the watch as it stands on its own looks.
        s.user_seen_at.follow_watch(&cfg.presence, presence_mode());
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
                    let beat = || dialog_cell.borrow_mut().heartbeat(caller_ref);
                    if let Some(r) = self.wait_for_hold(
                        Whose {
                            user: &user,
                            bind: &caller_ref.bind,
                        },
                        hold,
                        state,
                        seen,
                        lost_after,
                        &beat,
                    ) {
                        return r;
                    }
                    continue;
                }
            }
            // A card the lock screen covers is a card nobody nods at, and
            // the lock screen needs the camera: park until the unlock (D2).
            if crate::consent::session_locked(&user, &caller_ref.bind) {
                log::info!("consent: the session is locked; the request parks until the unlock");
                return Round::SessionLocked;
            }
            // The key is asked while the nods are armed, for this scan and
            // the nod window after it, never in a hold or a wait, and its
            // check is stopped (the key freed) before the round goes on:
            // after a refusal on sudo the stack's key-fallback line is next.
            // The card learns of the key from its payload, so it is sent
            // again when the key arms. The fingerprint is armed with them
            // under the key's rules (Mike's 10/12 ruling: they all ride
            // together), one long check for the window rather than one
            // every two seconds, and finished with the key, so the reader
            // is free before the round goes on.
            let token = dialog_cell.borrow().token().to_string();
            let key = std::cell::RefCell::new(KEY.arm(
                state,
                &user,
                &token,
                &caller_ref.via,
                &caller_ref.bind,
            ));
            let fprint = std::cell::RefCell::new(FPRINT.arm(
                state,
                &user,
                &token,
                &caller_ref.via,
                &caller_ref.bind,
            ));
            if key.borrow().is_some() || fprint.borrow().is_some() {
                dialog_cell.borrow_mut().heartbeat(caller_ref);
            }
            let end_key = || {
                if let Some(watch) = key.borrow_mut().take() {
                    watch.finish();
                }
                if let Some(watch) = fprint.borrow_mut().take() {
                    watch.finish();
                }
            };
            let templates_ref = &s.templates;
            let mut hook = |cap: &mut IrCapture,
                            pipeline: &mut Pipeline,
                            matched: &faceauth_engine::Face,
                            frame: &faceauth_engine::Grey|
             -> Result<bool> {
                // The scan just matched the enrolled face: from here until
                // the nod window ends the card may arm passwordless sudo,
                // and the payload says so. The match is the user at the
                // card: the away clock starts over, and the watch, the
                // card's copy and the live one alike, has seen the user
                // there, at this frame and box, so its shape hold runs
                // from here (a hand on the chin at the card later is still
                // the user).
                state.set_face_present(&user, true);
                let now = Instant::now();
                seen.sighted(now, frame, matched.bbox);
                // Only the watched user's sighting is noted for the watch.
                // Another user's frame would sit in memory for nobody, and
                // would take the one slot, overwriting the watched user's
                // own pending sighting.
                if watched {
                    crate::presence::note_sighting(&user, now, frame, matched.bbox);
                }
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
                // passwordless button grays and ungreys with the daemon's
                // own view. The show carries no ack wait.
                let refresh = || {
                    let _ = dialog_cell.borrow_mut().show_again("nod", &msg, caller_ref);
                };
                let presence = |_present: bool| refresh();
                // The lock question owns what it asks about, so the nod
                // window's watch can ask it from a thread of its own.
                let locked: crate::consent::LockQuestion = {
                    let (user, bind) = (user.clone(), caller_ref.bind.clone());
                    std::sync::Arc::new(move || crate::consent::session_locked(&user, &bind))
                };
                let (g, followed) = loop {
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
                        &mut nod_frames,
                        Some(&presence),
                        Some(std::sync::Arc::clone(&locked)),
                        seen,
                        Some(&refresh),
                    )?;
                    if g != Gesture::RiderArmed {
                        break (g, followed);
                    }
                    // The card armed passwordless sudo: what the nod grants
                    // changed, so the card is shown again naming it. The
                    // show resets the acknowledgment and waits for a fresh
                    // one, and the nods start over at a card that says what
                    // they approve.
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
                // From the nods to the commit, each step may run up to the
                // line's patience on its own: a beat before each (fix round
                // 10, Opus N3), so a slow one never sends a good nod to the
                // password. The "Confirming" show beats before its summon.
                state.beat_now(&user);
                end_key();
                let g = if g == Gesture::Nodded {
                    // The nods came from the followed box; before they count,
                    // that box must be live and enrolled, right now, and the
                    // frames kept from the nods themselves must be the
                    // enrolled face too (D4): a face swapped in for the
                    // gesture and out again before the confirm is refused.
                    let _ = dialog_cell
                        .borrow_mut()
                        .show("confirming", "Confirming.", caller_ref);
                    state.beat_now(&user);
                    match confirm(
                        cap,
                        pipeline,
                        &cfg,
                        templates_ref,
                        followed.unwrap_or(matched.bbox),
                    )? {
                        Confirm::Live => {
                            state.beat_now(&user);
                            match nod_frames_match(
                                pipeline,
                                templates_ref,
                                &nod_frames,
                                &cap.identity,
                                cfg.accept_threshold,
                            )? {
                                Ok(()) => Gesture::Nodded,
                                Err(why) => Gesture::ConfirmFailed(why),
                            }
                        }
                        Confirm::NoSignal => Gesture::ConfirmUnclear,
                        Confirm::Refused(why) => Gesture::ConfirmFailed(why),
                    }
                } else {
                    g
                };
                // A nod approval commits only on a fresh anchored look, as
                // a key touch's does (fix round 9, Codex 3, Opus M1): a
                // lock that landed during the nods or the confirm parks the
                // request rather than approving it.
                if g == Gesture::Nodded {
                    state.beat_now(&user);
                }
                let g = if g == Gesture::Nodded
                    && !KEY.nod_may_commit(state, &user, &caller_ref.bind)
                {
                    log::info!(
                        "consent for {}: the session read as locked at the nod's commit; the request parks",
                        user
                    );
                    Gesture::SessionLocked
                } else {
                    g
                };
                let ok = matches!(
                    g,
                    Gesture::Nodded | Gesture::Password(_) | Gesture::Key | Gesture::Fingerprint
                );
                *gesture_cell.borrow_mut() = Some(g);
                Ok(ok)
            };
            let scan = cfg.consent_scan_seconds;
            // A PIN spent by a key check during the scan: the card is sent
            // again so it asks for the PIN, as the nod window does.
            let rescan_card = || dialog_cell.borrow_mut().heartbeat(caller_ref);
            let (g, o) = match self.run_with_answers(
                &s.templates,
                Some(&mut hook),
                scan,
                Some((state, user.as_str())),
                Some(&rescan_card),
            ) {
                Ok(Scan::Done(o)) => (gesture_cell.borrow_mut().take(), o),
                Ok(Scan::Answered(a)) => answered_early(a, started.elapsed().as_millis() as u64),
                Err(e) => (
                    None,
                    Outcome::Error {
                        message: e.to_string(),
                    },
                ),
            };
            end_key();
            match (&g, &o) {
                // Nobody is waiting for the verdict: no verdict, and the
                // window comes down when the session drops. Polkit's stack
                // ends on it rather than go on to its key line
                // (`server::rounds::gone_now`).
                (Some(Gesture::Gone), _) => {
                    return Round::Done(crate::auth::refused(
                        caller_ref,
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
                // A scan that scored nothing is the user gone only when the
                // request's away clock has run out and the watch's own look
                // finds nobody there, or not the user: a bright room reads
                // no signal with the user at the desk. Otherwise the wait
                // below keeps looking (E2).
                (None, Outcome::NoFace { .. })
                    if lost_after
                        .is_some_and(|l| self.gone_after_unscored_scan(&user, seen, l)) =>
                {
                    return Round::FaceLost
                }
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
                    if let Some(r) = self.wait_for_attention(
                        Whose {
                            user: &user,
                            bind: &caller_ref.bind,
                        },
                        state,
                        lost_after,
                        false,
                        seen,
                        &beat,
                    ) {
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
                    if let Some(r) = self.wait_for_attention(
                        Whose {
                            user: &user,
                            bind: &caller_ref.bind,
                        },
                        state,
                        lost_after,
                        true,
                        seen,
                        &beat,
                    ) {
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
                        "Face not recognized. Look at the camera, or type your password.",
                        caller_ref,
                    );
                    let beat = || dialog_cell.borrow_mut().heartbeat(caller_ref);
                    if let Some(r) = self.wait_for_attention(
                        Whose {
                            user: &user,
                            bind: &caller_ref.bind,
                        },
                        state,
                        lost_after,
                        false,
                        seen,
                        &beat,
                    ) {
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
                    if let Some(r) = self.wait_for_attention(
                        Whose {
                            user: &user,
                            bind: &caller_ref.bind,
                        },
                        state,
                        lost_after,
                        false,
                        seen,
                        &beat,
                    ) {
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

    /// Sit out a hold without scanning: until it is over, or the window
    /// answers (a password or a dismissal, which the next scan start takes).
    /// The chair is still watched at the presence rhythm, so a user who
    /// left during the hold, or a stranger who took the chair, ends the
    /// round with the user gone at the away time (E2). `beat` re-sends the
    /// card now and then through the hold's minutes (D1).
    fn wait_for_hold(
        &mut self,
        who: Whose<'_>,
        hold: Duration,
        state: &ConsentState,
        seen: &UserSeen,
        lost_after: Option<Duration>,
        beat: &dyn Fn(),
    ) -> Option<Round> {
        let (user, bind) = (who.user, who.bind);
        let look_cfg = crate::presence::PresenceConfig {
            user: user.to_string(),
            ..Default::default()
        };
        let strict = crate::presence::presence_mode() == crate::presence::PresenceMode::Secure;
        let pace = Pace::live(self.cfg.presence.battery_tick_seconds);
        let mut look =
            |identify: bool| crate::presence::observe_in(self, &look_cfg, identify, strict, false);
        let locked = || crate::consent::session_locked(user, bind);
        hold_wait(
            &mut look,
            state,
            user,
            &locked,
            Instant::now() + hold,
            seen,
            lost_after,
            beat,
            &pace,
        )
    }

    /// After a scan that scored nothing with a walk-away watch on: has the
    /// user left? One look of the watch's own, for the mode in force, when
    /// the away clock has run out (`gone_after_unscored`).
    fn gone_after_unscored_scan(
        &mut self,
        user: &str,
        seen: &UserSeen,
        lost_after: Duration,
    ) -> bool {
        let look_cfg = crate::presence::PresenceConfig {
            user: user.to_string(),
            ..Default::default()
        };
        let strict = crate::presence::presence_mode() == crate::presence::PresenceMode::Secure;
        let mut look =
            |identify: bool| crate::presence::observe_in(self, &look_cfg, identify, strict, false);
        gone_after_unscored(&mut look, seen, lost_after, Instant::now())
    }

    /// Wait, at the presence rhythm, for the request to be re-armed: by
    /// an answer from the card, or by the enrolled face attentive at the
    /// camera. With `need_away` the face must first have been away from
    /// the card (absent, turned away, or not the user) for a look. Ends
    /// with a round when the user left for the away time or the session
    /// locked. `beat` re-sends the card now and then (D1). The identity
    /// look is the presence watch's for the mode in force: in the secure
    /// mode a face the gate read no signal from re-arms nothing. On
    /// battery the looks come at the watch's battery tick (D3).
    fn wait_for_attention(
        &mut self,
        who: Whose<'_>,
        state: &ConsentState,
        lost_after: Option<Duration>,
        need_away: bool,
        seen: &UserSeen,
        beat: &dyn Fn(),
    ) -> Option<Round> {
        let (user, bind) = (who.user, who.bind);
        let look_cfg = crate::presence::PresenceConfig {
            user: user.to_string(),
            ..Default::default()
        };
        let mode = crate::presence::presence_mode();
        let strict = mode == crate::presence::PresenceMode::Secure;
        let pace = Pace::live(self.cfg.presence.battery_tick_seconds);
        let mut look =
            |identify: bool| crate::presence::observe_in(self, &look_cfg, identify, strict, false);
        let locked = || crate::consent::session_locked(user, bind);
        attention_wait(
            &mut look,
            state,
            user,
            &locked,
            beat,
            RearmGate::new(need_away, mode),
            lost_after,
            seen,
            &pace,
        )
    }

    /// Turn a gesture and a face outcome into the verdict, show it, notify.
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
        let (outcome, charged) = verdict(
            caller,
            &gesture,
            outcome,
            password_ok,
            s.started.elapsed().as_millis() as u64,
        );
        if charged {
            let _ = self.charge(user);
        }
        self.last_consent.insert(user.to_string(), Instant::now());
        if !matches!(outcome, Outcome::Match { .. }) {
            // Whatever the card asked for rides on an approval only.
            let _ = CONSENT.take_passwordless(user, s.dialog.token());
        }
        match &outcome {
            Outcome::Match { frames, .. } => {
                self.last_match.insert(user.to_string(), Instant::now());
                self.failures.remove(user);
                let how = match gesture {
                    Some(Gesture::Key) => "security key",
                    Some(Gesture::Fingerprint) => "fingerprint",
                    _ if *frames == 0 => "password",
                    _ => "face and nod",
                };
                // A key touch leaves the faillock counter as pam_u2f on
                // sudo's own stack leaves it, and a finger as pam_fprintd
                // does.
                if *frames > 0 {
                    faillock_reset(user);
                }
                s.dialog.show_final("approved", "Allowed.", caller);
                s.dialog.notify(
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
                        s.dialog.notify(
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
                                s.dialog.notify(&format!("Passwordless sudo on for {} minutes", minutes), "Any process running as you can use sudo without asking until then. Setup > Security > Passwordless Sudo turns it off early.");
                            }
                            Err(e) => {
                                log::warn!("passwordless sudo for {} not enabled: {:#}", user, e);
                                s.dialog
                                    .notify("Passwordless sudo not enabled", &format!("{:#}", e));
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
                s.dialog
                    .notify(how, &format!("{}\n{}", caller.command, caller.parents));
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
                s.dialog.notify(
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
                s.dialog.notify(
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
                s.dialog
                    .notify(how, &format!("{}\n{}", caller.command, caller.parents));
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
                s.dialog.notify(
                    "Refused",
                    &format!("{}\n{}", caller.command, caller.parents),
                );
            }
        }
        outcome
    }
}

/// An answer from the card that came before the face matched: the scan
/// ends with the user's answer, whether or not the camera saw them, and
/// no face outcome behind it (J18). A password typed then is checked like
/// one typed at the nod card, so a wrong one is "wrong password", not a
/// liveness refusal.
/// Whose request a wait is for: the user, and the session its lock
/// question is about (round 8, Codex 3).
#[derive(Clone, Copy)]
struct Whose<'a> {
    user: &'a str,
    bind: &'a crate::lockgate::Bind,
}

fn answered_early(a: Answer, elapsed_ms: u64) -> (Option<Gesture>, Outcome) {
    let g = match a {
        Answer::Password(pw) => Gesture::Password(pw),
        Answer::Key => Gesture::Key,
        Answer::Fingerprint => Gesture::Fingerprint,
        Answer::Dismiss => Gesture::Dismissed,
        Answer::Gone | Answer::Rearm => Gesture::Gone,
    };
    (Some(g), Outcome::NoFace { elapsed_ms })
}

/// The verdict on a request's gesture and face outcome, and whether it is
/// charged against the user's cooldown. `password_ok` is the system
/// stack's word on a typed password; a good one approves exactly like a
/// nod, after `elapsed_ms` of the request, and so does a key touch, which
/// pam_u2f checked before it became the gesture.
fn verdict(
    caller: &crate::consent::CallerInfo,
    gesture: &Option<Gesture>,
    outcome: Outcome,
    password_ok: bool,
    elapsed_ms: u64,
) -> (Outcome, bool) {
    if password_ok {
        return (
            Outcome::Match {
                score: Some(1.0),
                frames: 0,
                elapsed_ms,
            },
            false,
        );
    }
    match (gesture, outcome) {
        // A finger approves exactly as a touch does: pam_fprintd checked it
        // before it became the gesture.
        (Some(Gesture::Key | Gesture::Fingerprint), _) => (
            Outcome::Match {
                score: None,
                frames: 0,
                elapsed_ms,
            },
            false,
        ),
        // A nod window that timed out after a match ends as a consent
        // refusal, so the module ignores it and the password is the floor.
        (Some(Gesture::Timeout), o @ Outcome::Match { .. }) => {
            (consent_denied(Refusal::NoAnswer, elapsed_of(&o)), false)
        }
        // A shake or a dismissal is the answer no: the window had the
        // password box, so closing it without either is a refusal that
        // ends the request, not a hand-off to another prompt.
        (Some(Gesture::Dismissed), o) => {
            (refused(caller, Refusal::Dismissed, elapsed_of(&o)), false)
        }
        (Some(Gesture::Shaken), o) => (refused(caller, Refusal::Shaken, elapsed_of(&o)), false),
        // A password that was wrong is charged to the cooldown like a
        // failed scan, whether the face had matched before it or not.
        (Some(Gesture::Password(_)), o) => {
            (consent_denied(Refusal::WrongPassword, elapsed_of(&o)), true)
        }
        (_, o) => (o, false),
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
    if is_watched(presence, user) {
        presence.away_for(mode)
    } else {
        None
    }
}

/// Whether the presence watch runs for `user`. Not `lost_after_for`'s
/// Some: a watched user whose away time is "never" still has a watch,
/// whose shape hold takes the card's sightings.
fn is_watched(presence: &PresenceConfig, user: &str) -> bool {
    presence.enabled && presence.user == user
}

#[cfg(test)]
mod verdict_tests {
    use super::*;
    use crate::consent::{CallerInfo, Secret};

    /// J18: a password typed before the face matched is the user's answer.
    /// The scan ends with it, and a wrong one ends the request as a
    /// consent refusal, "wrong password", charged like a failed scan, on
    /// either lane, never as a liveness refusal; a right one approves.
    #[test]
    fn a_wrong_password_before_the_match_is_refused_as_a_wrong_password() {
        for via in ["sudo", "polkit"] {
            let caller = CallerInfo {
                via: via.into(),
                ..Default::default()
            };
            let (g, o) = answered_early(Answer::Password(Secret::new("not it".into())), 1200);
            assert!(matches!(g, Some(Gesture::Password(_))), "{:?}", g);
            assert!(matches!(o, Outcome::NoFace { .. }), "{:?}", o);
            let (v, charged) = verdict(&caller, &g, o.clone(), false, 1500);
            match &v {
                Outcome::ConsentDenied { reason, elapsed_ms } => {
                    assert_eq!(Refusal::parse(reason), Some(Refusal::WrongPassword));
                    assert_eq!(*elapsed_ms, 1200);
                }
                other => panic!("{}: {:?}", via, other),
            }
            assert!(charged, "{}", via);
            let (v, charged) = verdict(&caller, &g, o, true, 1500);
            assert!(
                matches!(
                    v,
                    Outcome::Match {
                        frames: 0,
                        elapsed_ms: 1500,
                        ..
                    }
                ),
                "{:?}",
                v
            );
            assert!(!charged);
        }
    }

    /// The other answers the card can give before a match: a dismissal is
    /// the user's no, and a hang-up is nobody waiting; neither is charged.
    #[test]
    fn a_dismissal_or_a_hang_up_before_the_match_is_not_charged() {
        let caller = CallerInfo {
            via: "polkit".into(),
            ..Default::default()
        };
        let (g, o) = answered_early(Answer::Dismiss, 900);
        assert!(matches!(g, Some(Gesture::Dismissed)));
        let (v, charged) = verdict(&caller, &g, o, false, 1000);
        assert!(
            matches!(&v, Outcome::Refused { reason, .. } if Refusal::parse(reason) == Some(Refusal::Dismissed)),
            "{:?}",
            v
        );
        assert!(!charged);
        for a in [Answer::Gone, Answer::Rearm] {
            let (g, _) = answered_early(a, 900);
            assert!(matches!(g, Some(Gesture::Gone)), "{:?}", g);
        }
    }

    /// A key touch approves like a right password, on either lane and
    /// whatever the face did: taken at a scan start (before the match, or
    /// after a hold or a nod window that timed out) or at the nod card
    /// after the match. It is never charged, carries no face score, and
    /// leaves the frames at none.
    #[test]
    fn a_key_touch_approves_whatever_the_face_did() {
        for via in ["sudo", "polkit"] {
            let caller = CallerInfo {
                via: via.into(),
                ..Default::default()
            };
            let (g, early) = answered_early(Answer::Key, 700);
            assert!(matches!(g, Some(Gesture::Key)), "{:?}", g);
            let at_card = Outcome::Match {
                score: Some(0.9),
                frames: 2,
                elapsed_ms: 3000,
            };
            for o in [early, at_card] {
                let (v, charged) = verdict(&caller, &g, o, false, 4000);
                assert_eq!(
                    v,
                    Outcome::Match {
                        score: None,
                        frames: 0,
                        elapsed_ms: 4000
                    },
                    "{}",
                    via
                );
                assert!(!charged, "{}", via);
            }
        }
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
        assert!(
            is_watched(&p, "alice") && !is_watched(&p, "bob"),
            "a card sighting is kept for the watched user alone, \"never\" or not"
        );
        p.enabled = false;
        assert_eq!(lost_after_for(&p, "alice", secure), None);
        assert!(!is_watched(&p, "alice"));
    }
}
