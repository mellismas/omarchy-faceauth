//! A stopped key check cancels the key's wait (round 19, live test 2).
//!
//! A FIDO key that has been asked for a touch waits for it, blinking,
//! until it is touched, its own timeout passes (about 30 s), or the
//! program that asked cancels on the same channel. A check stopped by a
//! kill never cancels, so the key went on blinking after a nod or a face
//! approved the card, and answered the next check "busy" until it timed
//! out. pam_u2f keeps the device it asks to itself and offers no cancel,
//! so this helper exports libfido2's `fido_dev_get_assert` itself: the
//! dynamic linker binds pam_u2f's call here before libfido2's, and this
//! notes the device the request is in flight on, then hands every
//! argument to libfido2's own call and its answer back, untouched. A stop
//! (SIGTERM, from systemd's stop of the check's unit or from the PAM
//! module) cancels that request with libfido2's `fido_dev_cancel`, so the
//! key goes dark at once, and the helper then exits. A stopped check never
//! reports a touch. `elfsym` and doctor's `key.cancel` hold both ends: the
//! export here, the import in pam_u2f.

use std::ffi::{c_char, c_int, c_void};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering::SeqCst};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

/// libfido2's `fido_dev_get_assert`: the device, the assertion, the PIN.
pub(crate) type GetAssert = unsafe extern "C" fn(*mut c_void, *mut c_void, *const c_char) -> c_int;
/// libfido2's `fido_dev_cancel`.
type Cancel = unsafe extern "C" fn(*mut c_void) -> c_int;

/// libfido2's code for an internal error, which pam_u2f takes as a failed
/// check: the answer to a request after a stop, or with no libfido2.
const FIDO_ERR_INTERNAL: c_int = -9;
/// CTAP2's code for a request cancelled while it waited (libfido2 passes
/// it through).
#[cfg(test)]
const FIDO_ERR_KEEPALIVE_CANCEL: c_int = 0x2d;

/// How long a stop waits for a cancelled request to end, sending the
/// cancel again while it waits, before the helper exits anyway: well
/// inside the unit's `TimeoutStopSec=` and the PAM module's grace.
pub(crate) const GRACE: Duration = Duration::from_millis(500);
/// How often the cancel goes again while the request has not ended (one
/// sent just as the request went out can reach the key first).
const AGAIN: Duration = Duration::from_millis(50);

/// The device of the request in flight, as an address; 0 for none. Set
/// and cleared only by `ask_noted`, around libfido2's own call, and read
/// by the stop under the same lock, so a device is never cancelled after
/// pam_u2f has it back to close.
static IN_FLIGHT: Mutex<usize> = Mutex::new(0);
/// The check's end, decided once (Codex 19, 3): still running, stopped
/// (the handler moves it there), or a touch claimed for the report
/// (`claim_touch`). A stop and a touch each win only by coming first, so
/// a stopped check never reports a touch and a stop after a claimed touch
/// does not take it back.
static STATE: AtomicU8 = AtomicU8::new(RUNNING);
const RUNNING: u8 = 0;
const STOPPED: u8 = 1;
const TOUCHED: u8 = 2;
/// pam_u2f asked the key through this wrapper at least once.
static CAUGHT: AtomicBool = AtomicBool::new(false);
/// The write end of the pipe the handler wakes the stop with.
static WAKE: AtomicI32 = AtomicI32::new(-1);

fn slot() -> MutexGuard<'static, usize> {
    IN_FLIGHT.lock().unwrap_or_else(|p| p.into_inner())
}

/// libfido2's two calls, from the copy pam_u2f loaded with it.
struct Fido {
    get_assert: GetAssert,
    cancel: Cancel,
}

fn fido() -> Option<&'static Fido> {
    static FIDO: OnceLock<Option<Fido>> = OnceLock::new();
    FIDO.get_or_init(|| {
        let lib = c"libfido2.so.1";
        // SAFETY: dlopen with a NUL-terminated name; RTLD_NOLOAD returns
        // the copy pam_u2f's own link loaded, and the plain open loads it
        // only if that is somehow not there.
        let handle = unsafe {
            let h = libc::dlopen(lib.as_ptr(), libc::RTLD_NOW | libc::RTLD_NOLOAD);
            if h.is_null() {
                libc::dlopen(lib.as_ptr(), libc::RTLD_NOW)
            } else {
                h
            }
        };
        if handle.is_null() {
            return None;
        }
        // SAFETY: dlsym on a live handle with NUL-terminated names. The
        // handle's own lookup finds libfido2's definitions, never this
        // executable's wrapper.
        let (ga, ca) = unsafe {
            (
                libc::dlsym(handle, c"fido_dev_get_assert".as_ptr()),
                libc::dlsym(handle, c"fido_dev_cancel".as_ptr()),
            )
        };
        if ga.is_null() || ca.is_null() {
            return None;
        }
        // SAFETY: both are libfido2's functions with these C signatures
        // (fido_dev_get_assert(3), fido_dev_open(3)).
        unsafe {
            Some(Fido {
                get_assert: std::mem::transmute::<*mut c_void, GetAssert>(ga),
                cancel: std::mem::transmute::<*mut c_void, Cancel>(ca),
            })
        }
    })
    .as_ref()
}

/// pam_u2f's request to the key, which the dynamic linker binds here
/// (the helper's link exports this name, `build.rs`): noted in flight
/// for a stop, and done by libfido2's own call.
///
/// # Safety
/// The arguments are pam_u2f's for libfido2, passed on as they came.
#[no_mangle]
pub unsafe extern "C" fn fido_dev_get_assert(
    dev: *mut c_void,
    assert: *mut c_void,
    pin: *const c_char,
) -> c_int {
    let Some(f) = fido() else {
        return FIDO_ERR_INTERNAL;
    };
    // SAFETY: the caller's contract, passed on unchanged.
    unsafe { ask_noted(dev, assert, pin, f.get_assert) }
}

/// `real` asked with pam_u2f's arguments, its device noted in flight
/// meanwhile; none asked once a stop has been asked.
///
/// # Safety
/// As `real`'s, with these arguments.
pub(crate) unsafe fn ask_noted(
    dev: *mut c_void,
    assert: *mut c_void,
    pin: *const c_char,
    real: GetAssert,
) -> c_int {
    CAUGHT.store(true, SeqCst);
    {
        let mut s = slot();
        if STATE.load(SeqCst) == STOPPED {
            return FIDO_ERR_INTERNAL;
        }
        *s = dev as usize;
    }
    // SAFETY: the caller's contract.
    let answer = unsafe { real(dev, assert, pin) };
    *slot() = 0;
    answer
}

/// The device of the request in flight, 0 for none.
#[cfg(test)]
pub(crate) fn in_flight() -> usize {
    *slot()
}

/// Whether pam_u2f has asked the key through this wrapper.
#[cfg(test)]
pub(crate) fn caught() -> bool {
    CAUGHT.load(SeqCst)
}

/// Ask the stop, as the handler does: it wins unless a touch was claimed.
fn stop_now() {
    let _ = STATE.compare_exchange(RUNNING, STOPPED, SeqCst, SeqCst);
}

#[cfg(test)]
pub(crate) fn ask_stop() {
    stop_now();
}

/// Whether the check was stopped before a touch was claimed.
#[cfg(test)]
pub(crate) fn stop_asked() -> bool {
    STATE.load(SeqCst) == STOPPED
}

/// Claim the touch for the report: true only while no stop came first,
/// and then no stop after it changes the answer. Both check paths report
/// a touch only through this.
pub(crate) fn claim_touch() -> bool {
    STATE
        .compare_exchange(RUNNING, TOUCHED, SeqCst, SeqCst)
        .is_ok()
}

/// Cancel the request in flight with `cancel` (given its device), again
/// every `AGAIN` while it has not ended, for up to `grace`; at once when
/// nothing is in flight. The lock is held across each cancel, so the
/// request cannot end and its device be closed while one is sent.
pub(crate) fn cancel_in_flight(cancel: &dyn Fn(usize), grace: Duration) {
    let by = Instant::now() + grace;
    loop {
        {
            let s = slot();
            if *s == 0 {
                return;
            }
            cancel(*s);
        }
        if Instant::now() >= by {
            return;
        }
        std::thread::sleep(AGAIN.min(by.saturating_duration_since(Instant::now())));
    }
}

/// The stop thread's work once woken: cancel the request in flight, then
/// end the helper with `after`, unless a touch was claimed before the
/// stop (Opus 19b G3), whose report then ends the helper itself; the
/// watchdog still bounds it.
fn stop_then(cancel: &dyn Fn(usize), after: fn()) {
    cancel_in_flight(cancel, GRACE);
    if STATE.load(SeqCst) != TOUCHED {
        after();
    }
}

/// libfido2's cancel on the device `dev` names.
fn cancel_with_libfido2(dev: usize) {
    if let Some(f) = fido() {
        // SAFETY: `dev` is the device of a request in flight, which pam_u2f
        // cannot close while `cancel_in_flight` holds the lock this runs
        // under; fido_dev_cancel(3) is meant for a request another thread
        // is waiting on.
        unsafe { (f.cancel)(dev as *mut c_void) };
    }
}

/// The SIGTERM handler: async-signal-safe throughout (atomics, alarm(2),
/// write(2)), and it leaves errno as it found it. The alarm is the
/// watchdog (Codex 19, 2): whatever the stop thread is blocked on, a
/// libfido2 cancel included, SIGALRM's default action ends the helper a
/// second later, so no stop outlives that, even with no reaper left.
extern "C" fn on_term(_: c_int) {
    // SAFETY: __errno_location returns this thread's errno slot.
    let errno = unsafe { *libc::__errno_location() };
    stop_now();
    // Armed once, on the first stop (Codex 19b N2): a SIGTERM after it
    // must not move the deadline on.
    if !WATCHDOG.swap(true, SeqCst) {
        // SAFETY: alarm(2) is async-signal-safe.
        unsafe { libc::alarm(1) };
    }
    let fd = WAKE.load(SeqCst);
    if fd >= 0 {
        let b = 1u8;
        // SAFETY: write(2) is async-signal-safe; one byte from the stack to
        // the pipe `arm` made, whose write end never blocks (a full pipe
        // means a wake is already waiting).
        unsafe { libc::write(fd, std::ptr::addr_of!(b).cast(), 1) };
    }
    // SAFETY: as above.
    unsafe { *libc::__errno_location() = errno };
}

/// The watchdog has been armed, by the first stop.
static WATCHDOG: AtomicBool = AtomicBool::new(false);
/// The stop thread found the handlers in place before it took SIGTERM.
static HANDLED_FIRST: AtomicBool = AtomicBool::new(false);

/// Whether the handlers were in place before the stop thread unblocked
/// SIGTERM (Codex 19b N3).
#[cfg(test)]
pub(crate) fn handler_before_unblock() -> bool {
    HANDLED_FIRST.load(SeqCst)
}

/// The stop thread's id, once it is up and takes SIGTERM (0 before).
static STOP_TID: AtomicI32 = AtomicI32::new(0);
/// Whether the stop thread found SIGTERM unblocked for itself.
static STOP_TAKES_TERM: AtomicBool = AtomicBool::new(false);

/// The stop thread's id and whether it takes SIGTERM, once it is up.
#[cfg(test)]
pub(crate) fn stop_thread() -> Option<(i32, bool)> {
    let tid = STOP_TID.load(SeqCst);
    (tid != 0).then(|| (tid, STOP_TAKES_TERM.load(SeqCst)))
}

/// The watchdog's end: the helper is gone, whatever it was blocked on.
extern "C" fn on_alarm(_: c_int) {
    // SAFETY: _exit is async-signal-safe and ends the process at once.
    unsafe { libc::_exit(1) }
}

fn sigset_of(signals: &[c_int]) -> libc::sigset_t {
    // SAFETY: a zeroed sigset_t emptied and filled by libc's own calls.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        for &sig in signals {
            libc::sigaddset(&mut set, sig);
        }
        set
    }
}

/// Take SIGTERM as a stop: the handler marks it and wakes a thread of the
/// helper's own, which cancels the request in flight (`GRACE` at most)
/// and then runs `after` (the helper exits).
///
/// SIGTERM stays blocked in the thread that calls this, the one pam_u2f
/// later waits on the key in, and in every thread it starts (Opus 19 F1):
/// a stop delivered there ends libfido2's ppoll with EINTR, which fails
/// the request with no cancel, and the key keeps waiting. The stop thread
/// unblocks it for itself first thing, whatever mask the helper inherited
/// (Codex 19, 4), so it is the one thread that takes a SIGTERM.
///
/// False when the pipe, the handlers or the thread could not be set up,
/// with the caller's mask as it was; the helper then has SIGTERM's default
/// action, which in the check's unit, where the helper is its PID
/// namespace's init, is none, and systemd's SIGKILL ends it a second
/// after the stop (Opus 19 F5).
pub(crate) fn arm(after: fn()) -> bool {
    let mut fds = [0 as c_int; 2];
    // SAFETY: pipe2 fills a two-element array.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return false;
    }
    let [read_end, write_end] = fds;
    let close_both = || {
        // SAFETY: closing the two ends this function opened.
        unsafe {
            libc::close(read_end);
            libc::close(write_end);
        }
    };
    // SAFETY: fcntl on the write end this function just made (Codex 19, 5:
    // repeated SIGTERMs must never block the handler on a full pipe).
    let nonblocking = unsafe {
        let flags = libc::fcntl(write_end, libc::F_GETFL);
        flags >= 0 && libc::fcntl(write_end, libc::F_SETFL, flags | libc::O_NONBLOCK) == 0
    };
    if !nonblocking {
        close_both();
        return false;
    }
    // The handlers, and the pipe they wake, are in place before the stop
    // thread takes SIGTERM (Codex 19b N3). SIGALRM, the watchdog, gets a
    // handler of its own, since the helper's unit makes it its PID
    // namespace's init, which ignores a default action.
    WAKE.store(write_end, SeqCst);
    // SAFETY: zeroed sigactions with a handler set and an empty mask are
    // valid arguments, and both handlers are async-signal-safe.
    let handled = unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_term as extern "C" fn(c_int) as usize;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut sa.sa_mask);
        let term_handled = libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut()) == 0;
        let mut alarm: libc::sigaction = std::mem::zeroed();
        alarm.sa_sigaction = on_alarm as extern "C" fn(c_int) as usize;
        libc::sigemptyset(&mut alarm.sa_mask);
        term_handled && libc::sigaction(libc::SIGALRM, &alarm, std::ptr::null_mut()) == 0
    };
    let term = sigset_of(&[libc::SIGTERM]);
    // SAFETY: a zeroed sigset_t for the old mask, filled by the call.
    let mut before: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: this thread's own mask, the old one kept for a failure.
    if !handled || unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &term, &mut before) } != 0 {
        WAKE.store(-1, SeqCst);
        close_both();
        return false;
    }
    let spawned = std::thread::Builder::new()
        .name("keycheck-stop".into())
        .spawn(move || {
            // SAFETY: sigaction with no new action only reads.
            let ours = unsafe {
                let mut now: libc::sigaction = std::mem::zeroed();
                libc::sigaction(libc::SIGTERM, std::ptr::null(), &mut now) == 0
                    && now.sa_sigaction == on_term as extern "C" fn(c_int) as usize
            };
            HANDLED_FIRST.store(ours, SeqCst);
            let mine = sigset_of(&[libc::SIGTERM, libc::SIGALRM]);
            // SAFETY: this thread's own mask, and a read of it back.
            let takes = unsafe {
                let mut now: libc::sigset_t = std::mem::zeroed();
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &mine, std::ptr::null_mut()) == 0
                    && libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut now) == 0
                    && libc::sigismember(&now, libc::SIGTERM) == 0
            };
            STOP_TAKES_TERM.store(takes, SeqCst);
            // SAFETY: gettid has no arguments and cannot fail.
            STOP_TID.store(unsafe { libc::syscall(libc::SYS_gettid) } as i32, SeqCst);
            let mut b = 0u8;
            loop {
                // SAFETY: a one-byte read into a local, from the pipe's
                // read end, which this thread alone uses.
                let n = unsafe { libc::read(read_end, std::ptr::addr_of_mut!(b).cast(), 1) };
                if n == 1 {
                    break;
                }
                if n < 0
                    && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                {
                    continue;
                }
                return;
            }
            stop_then(&cancel_with_libfido2, after);
        });
    if spawned.is_err() {
        // SAFETY: the caller's mask back as it was. The handlers stay: a
        // stop still marks the check stopped and arms the watchdog.
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &before, std::ptr::null_mut()) };
        WAKE.store(-1, SeqCst);
        close_both();
        return false;
    }
    // SIGALRM is unblocked here too, so the watchdog can land anywhere.
    let alrm = sigset_of(&[libc::SIGALRM]);
    // SAFETY: this thread's own mask.
    unsafe { libc::pthread_sigmask(libc::SIG_UNBLOCK, &alrm, std::ptr::null_mut()) == 0 }
}

/// The helper's end after a stop: no touch is reported, and nothing runs
/// on past it.
pub(crate) fn exit_stopped() {
    // SAFETY: _exit ends the process at once; the key's lease goes with it.
    unsafe { libc::_exit(1) }
}

/// Forget a stop and any request, for the next test.
#[cfg(test)]
pub(crate) fn reset() {
    STATE.store(RUNNING, SeqCst);
    WATCHDOG.store(false, SeqCst);
    *slot() = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{c_char, c_int, c_void};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst};
    use std::time::{Duration, Instant};

    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// A fake libfido2 request: it waits until a cancel comes, then ends as
    /// libfido2 ends a cancelled one.
    static CANCELLED: AtomicBool = AtomicBool::new(false);
    static RELEASED: AtomicBool = AtomicBool::new(false);
    static ASKED: AtomicBool = AtomicBool::new(false);
    static SEEN: [AtomicUsize; 3] = [
        AtomicUsize::new(0),
        AtomicUsize::new(0),
        AtomicUsize::new(0),
    ];

    unsafe extern "C" fn waits_for_cancel(
        dev: *mut c_void,
        _: *mut c_void,
        _: *const c_char,
    ) -> c_int {
        SEEN[0].store(dev as usize, SeqCst);
        while !CANCELLED.load(SeqCst) {
            std::thread::sleep(Duration::from_millis(2));
        }
        FIDO_ERR_KEEPALIVE_CANCEL
    }

    unsafe extern "C" fn ignores_cancel(_: *mut c_void, _: *mut c_void, _: *const c_char) -> c_int {
        while !RELEASED.load(SeqCst) {
            std::thread::sleep(Duration::from_millis(2));
        }
        FIDO_ERR_KEEPALIVE_CANCEL
    }

    unsafe extern "C" fn answers_at_once(
        dev: *mut c_void,
        a: *mut c_void,
        pin: *const c_char,
    ) -> c_int {
        ASKED.store(true, SeqCst);
        SEEN[0].store(dev as usize, SeqCst);
        SEEN[1].store(a as usize, SeqCst);
        SEEN[2].store(pin as usize, SeqCst);
        7
    }

    fn wait_in_flight(dev: usize) {
        let by = Instant::now() + Duration::from_secs(2);
        while in_flight() != dev {
            assert!(Instant::now() < by, "the request never went out");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn fresh() {
        reset();
        CANCELLED.store(false, SeqCst);
        RELEASED.store(false, SeqCst);
        ASKED.store(false, SeqCst);
        for s in &SEEN {
            s.store(0, SeqCst);
        }
    }

    /// Round 19: a stop cancels the request in flight, on its own device,
    /// and the request ends; after a stop no request reaches the key; a
    /// stop with nothing in flight, or after the request returned, cancels
    /// nothing; a request that does not end on the cancel is asked again
    /// and given up at the grace; and pam_u2f's arguments and libfido2's
    /// answer pass through untouched.
    #[test]
    fn a_stop_cancels_the_request_in_flight_and_nothing_else() {
        let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());

        fresh();
        // SAFETY: the fake takes the pointers as numbers and touches none.
        let asking = std::thread::spawn(|| unsafe {
            ask_noted(
                0x1234 as *mut c_void,
                std::ptr::null_mut(),
                std::ptr::null(),
                waits_for_cancel,
            )
        });
        wait_in_flight(0x1234);
        ask_stop();
        let cancelled_for = AtomicUsize::new(0);
        let t0 = Instant::now();
        cancel_in_flight(
            &|dev| {
                cancelled_for.store(dev, SeqCst);
                CANCELLED.store(true, SeqCst);
            },
            Duration::from_millis(500),
        );
        assert_eq!(
            cancelled_for.load(SeqCst),
            0x1234,
            "the request's own device"
        );
        assert_eq!(asking.join().unwrap(), FIDO_ERR_KEEPALIVE_CANCEL);
        assert!(
            t0.elapsed() < Duration::from_millis(300),
            "{:?}",
            t0.elapsed()
        );
        assert_eq!(in_flight(), 0);
        assert!(stop_asked());

        // After a stop, nothing more reaches the key.
        // SAFETY: as above.
        let r = unsafe {
            ask_noted(
                0x5678 as *mut c_void,
                std::ptr::null_mut(),
                std::ptr::null(),
                answers_at_once,
            )
        };
        assert!(!ASKED.load(SeqCst), "a request after the stop went out");
        assert_ne!(r, 0);
        assert_eq!(in_flight(), 0);

        // Nothing in flight: nothing to cancel, and no wait.
        fresh();
        let t0 = Instant::now();
        cancel_in_flight(
            &|_| panic!("nothing was in flight"),
            Duration::from_millis(500),
        );
        assert!(t0.elapsed() < Duration::from_millis(50));

        // A request that has returned is no longer in flight, and what
        // went in and came out is libfido2's own.
        fresh();
        // SAFETY: as above.
        let r = unsafe {
            ask_noted(
                0x9abc as *mut c_void,
                0x11 as *mut c_void,
                0x22 as *const c_char,
                answers_at_once,
            )
        };
        assert_eq!(r, 7);
        assert_eq!(
            [
                SEEN[0].load(SeqCst),
                SEEN[1].load(SeqCst),
                SEEN[2].load(SeqCst)
            ],
            [0x9abc, 0x11, 0x22]
        );
        assert!(caught());
        assert_eq!(in_flight(), 0);
        ask_stop();
        cancel_in_flight(
            &|_| panic!("the request had returned"),
            Duration::from_millis(500),
        );

        // A request that keeps waiting: the cancel goes again, and the stop
        // gives up at its grace.
        fresh();
        // SAFETY: as above.
        let stubborn = std::thread::spawn(|| unsafe {
            ask_noted(
                0x4242 as *mut c_void,
                std::ptr::null_mut(),
                std::ptr::null(),
                ignores_cancel,
            )
        });
        wait_in_flight(0x4242);
        ask_stop();
        let sent = AtomicUsize::new(0);
        let t0 = Instant::now();
        cancel_in_flight(
            &|_| {
                sent.fetch_add(1, SeqCst);
            },
            Duration::from_millis(200),
        );
        let took = t0.elapsed();
        assert!(
            took >= Duration::from_millis(200) && took < Duration::from_millis(400),
            "{:?}",
            took
        );
        assert!(sent.load(SeqCst) >= 2, "the cancel went once");
        RELEASED.store(true, SeqCst);
        stubborn.join().unwrap();
        fresh();
    }

    /// Round 19 (Codex 19, 3): a touch and a stop each win only by coming
    /// first. A stop asked first leaves no touch to report; a touch claimed
    /// first is reported, and a stop after it does not take it back.
    #[test]
    fn a_touch_and_a_stop_each_win_only_by_coming_first() {
        let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        fresh();
        ask_stop();
        assert!(!claim_touch(), "a touch after the stop");
        assert!(stop_asked());
        fresh();
        assert!(claim_touch());
        ask_stop();
        assert!(!stop_asked(), "a stop after the touch took it back");
        assert!(!claim_touch(), "a touch claimed twice");
        fresh();
    }

    static ENDED: AtomicBool = AtomicBool::new(false);

    fn ended() {
        ENDED.store(true, SeqCst);
    }

    /// Opus 19b G3: the stop ends the helper only when it won; a touch
    /// claimed first is left for its report, which ends the helper itself.
    #[test]
    fn a_stop_after_a_claimed_touch_leaves_the_report_alone() {
        let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        fresh();
        ENDED.store(false, SeqCst);
        assert!(claim_touch());
        stop_then(&|_| panic!("nothing was in flight"), ended);
        assert!(!ENDED.load(SeqCst), "a stop cut off a claimed touch");
        fresh();
        ask_stop();
        stop_then(&|_| panic!("nothing was in flight"), ended);
        assert!(ENDED.load(SeqCst), "a stop that won ends the helper");
        fresh();
    }

    static AFTER: AtomicBool = AtomicBool::new(false);

    fn after_stop() {
        AFTER.store(true, SeqCst);
    }

    /// Round 19: SIGTERM, how systemd and the PAM module stop a check,
    /// reaches the stop: it is marked asked, and what comes after it runs
    /// on the helper's own thread, never in the handler.
    ///
    /// Opus 19 F1: SIGTERM stays blocked in the thread that called `arm`,
    /// the one pam_u2f waits on the key in: there a stop would end
    /// libfido2's ppoll with EINTR, a failed request with no cancel. The
    /// stop thread unblocks it for itself, whatever mask the helper was
    /// started with (Codex 19, 4), so it is the one thread SIGTERM reaches.
    /// The handler sets a one-second alarm (Codex 19, 2), with a handler of
    /// its own, since the check's unit runs the helper as its PID
    /// namespace's init, which ignores a default action; and the wake pipe
    /// never blocks the handler (Codex 19, 5).
    #[test]
    fn sigterm_reaches_only_the_stop_thread() {
        let _g = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        fresh();
        // SAFETY: plain signal-set calls on locals; the mask is this
        // thread's own.
        let blocked_here = |sig: c_int| unsafe {
            let mut now: libc::sigset_t = std::mem::zeroed();
            libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut now);
            libc::sigismember(&now, sig) == 1
        };
        // SAFETY: as above, blocking TERM in this thread as a caller might,
        // so the stop thread inherits it blocked.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&mut set);
            libc::sigaddset(&mut set, libc::SIGTERM);
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        }
        assert!(arm(after_stop));
        assert!(
            blocked_here(libc::SIGTERM),
            "SIGTERM stays off the waiting thread"
        );
        assert!(
            !blocked_here(libc::SIGALRM),
            "the watchdog can land anywhere"
        );
        let by = Instant::now() + Duration::from_secs(2);
        while stop_thread().is_none() {
            assert!(Instant::now() < by, "the stop thread never came up");
            std::thread::sleep(Duration::from_millis(1));
        }
        let (tid, takes_term) = stop_thread().unwrap();
        assert!(
            takes_term,
            "the stop thread takes SIGTERM, even inherited blocked"
        );
        // SAFETY: fcntl F_GETFL on the pipe arm made; sigaction only reads.
        unsafe {
            let flags = libc::fcntl(WAKE.load(SeqCst), libc::F_GETFL);
            assert!(
                flags >= 0 && flags & libc::O_NONBLOCK != 0,
                "the handler's pipe never blocks"
            );
            let mut alrm: libc::sigaction = std::mem::zeroed();
            libc::sigaction(libc::SIGALRM, std::ptr::null(), &mut alrm);
            assert!(
                alrm.sa_sigaction != libc::SIG_DFL && alrm.sa_sigaction != libc::SIG_IGN,
                "the watchdog has a handler of its own"
            );
        }
        // SAFETY: tgkill sends SIGTERM to the stop thread alone, as the
        // kernel would deliver a process's SIGTERM with every other thread
        // blocking it; the handler sets the state, an alarm and a byte.
        unsafe { libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, libc::SIGTERM) };
        let by = Instant::now() + Duration::from_secs(2);
        while !AFTER.load(SeqCst) {
            assert!(Instant::now() < by, "the stop never ran");
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            handler_before_unblock(),
            "the handlers were in place before the stop thread took SIGTERM"
        );
        // Codex 19b N2: a second SIGTERM does not move the watchdog on.
        std::thread::sleep(Duration::from_millis(300));
        on_term(libc::SIGTERM);
        // SAFETY: getitimer reads the alarm's timer into a local.
        let left_us = unsafe {
            let mut t: libc::itimerval = std::mem::zeroed();
            libc::getitimer(libc::ITIMER_REAL, &mut t);
            t.it_value.tv_sec * 1_000_000 + t.it_value.tv_usec
        };
        assert!(
            left_us > 0 && left_us <= 750_000,
            "the watchdog keeps its first deadline: {} us left",
            left_us
        );
        // SAFETY: alarm(0) cancels the watchdog and says what was left.
        let left = unsafe { libc::alarm(0) };
        assert_eq!(left, 1, "the handler set the one-second watchdog");
        assert!(stop_asked());
        fresh();
    }
}
