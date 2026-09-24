# Omarchy FaceAuth

Face authentication for [Omarchy](https://github.com/omacom/omarchy) with the
infrared camera that Windows Hello laptops carry. The lock screen opens when
you look at it. `sudo` and polkit requests open a window that names what is
being run; two nods approve it, two head shakes refuse it, or you type your
password into the window. Rust, MIT, no system libraries beyond libc, libpam,
systemd and Arch's `onnxruntime-cpu`.

This repository is the daemon, the PAM module and the command-line tool. The
Omarchy side (lock screen stack, consent window, setup and removal, menu
entries, manual page) is a series of commits to `omacom/omarchy`; the package
recipe is `omarchy-faceauth` in `omacom/omarchy-pkgs`. Nothing here activates
on its own: the PAM stacks are written only by `omarchy setup security face`.

## How it behaves

- **Lock screen.** A third PAM stack, `omarchy-lock-face`, answered by the
  face module and closed by `pam_deny`. Looking at the machine is the act;
  there is no prompt. While the panel is blank the daemon takes one short look
  every two seconds and wakes it only for an attentive face.
- **`sudo` and polkit.** Every request opens a window with two lines: what
  is being asked, and who asked. For `sudo` and for `pkexec` the first line
  is the full command line as the daemon reads it from `/proc` ("Run as
  root: ..."); the second is the requesting process, its pid and its
  parents. For any other polkit action the daemon has nothing to read (the
  helper is polkit's and polkit does not say who asked), so the first line
  is polkit's own description as the agent relayed it, labelled
  "Unverified:", and the second says the asking process was not found.
  Control and direction-override characters are stripped from both lines
  and nothing else is cut: a long command scrolls in the card rather than
  being elided, up to the daemon's limit on the line. Nothing elevates
  until the window has acknowledged the request to the daemon, the face
  matches, the daemon sees two nods from that same face, and a strobed
  confirm shows it live and enrolled; two head shakes refuse; the password
  typed into the window approves. Buttons dismiss, or deny and kill the
  requester when the daemon could name it. The request has no deadline: nods are read for
  `consent_seconds` (90 by default) after a match, then the camera drops to
  the presence rhythm and an attentive face re-arms it, the lock screen's
  cycle. With the walk-away lock on, walking away locks the session and
  the request resumes when your face unlocks it; with it off the window
  waits. Requests queue and get the window in turn, and a
  waiting one is announced by a desktop notice. Every approval and every
  refusal posts a notice.
- **Gestures.** With the face mesh model installed, both are read from the
  head's angles in degrees (pitch for the nod, yaw for the shake), taken
  from MediaPipe's dense landmarks on the matched face; without it, from
  real image motion of the face between frames. Either way the face box
  must move along the gesture's axis during each leg: that catches a
  frozen box and a landmark fit that flipped between two solutions, not
  ordinary jitter, so a fit cannot nod on its own. A gesture is four
  alternating legs done together, from a head that was still just before;
  a glance, a look down, reading, talking and leaning in are all rejected
  by shape (see Measured, below). The enrolment walk-through records two
  nods, two shakes and the everyday movements and sets the person's floors
  from them: the nod's only ever rises above the default, the shake's only
  ever falls below it.
- **Walk-away lock** (opt-in, `sudo faceauth presence on`): one short look
  every five seconds (ten on battery), and on every third look a strobed
  pair through the flash gate and an identity check; lock when the camera
  has not seen the enrolled user for the away time. A print that fails the
  gate is not the user and cannot keep the session marked present. A hidden face is not absence on its own:
  when no face clears the threshold, the shoulders and torso under where the
  face was are compared with the last full sighting, and while that shape
  is still in the chair (a hand over the chin while reading) the clock is
  held, for up to two minutes after the last full sighting. Standing up
  replaces the shape with the wall. Two modes. In the default mode the
  away timer wins: a face that is not the enrolled user never counts as
  present, so a stranger in the chair, or a photo propped there, never
  holds the lock off past the away time. In secure mode the session locks
  as soon as the enrolled user is not in frame. A tray toggle for the mode
  is to come.
- **Every failure falls back to the password**, from a covered camera to a
  stopped service: the module returns `PAM_IGNORE` for everything but a
  match and one other thing. On a polkit consent line the answer no (a head
  shake, a dismissed window, a confirm that refused) is `PAM_AUTH_ERR`, the
  line is written `[success=done auth_err=die default=ignore]`, and the
  agent cancels the request on it, so polkit reports "Not authorized" and
  no password dialog follows. A sudo request takes the same answer as "not
  by face": the terminal prompt is where a password goes next, and a
  failure there would only make sudo ask again.

## What it defends against, and what it does not

- **A photo on a phone** is never seen as a face: the IR camera sees only its
  own illuminator reflected in the glass.
- **A paper print** is refused by two physical measurements taken with the
  illuminator strobed: paper reflects the strobe several times more strongly
  than skin, and a print's surround lights up with the face while a real
  head's background stays dark.
- **Elevation is never passive.** A face in front of the camera approves
  nothing; the nod is measured by the daemon on its own camera, and no key,
  click or socket message stands in for it. The daemon reads no nods until
  the window has acknowledged the request over the socket, and none in a
  short dwell after that, so a request swapped in mid-nod needs fresh nods.
  The nod is read from the face that matched: the daemon follows that box
  through the gesture and ignores other faces, the box must move with each
  leg (a frozen box, or a landmark fit that flipped, is not a head
  moving), and after the second nod the
  illuminator strobes again and two lit/unlit pairs must pass the flash
  gate and match the templates on that box before anything is approved. A
  print held up and waggled passes the detector and fails the confirm.
  Window answers carry a
  per-request token, handed to the window in its payload and returned on
  the answer's stdin. It is readable by a process running as you (the
  payload is an argument to the summon), which buys that process a
  dismissal or one password check, never an approval.
- **Bad-password lockouts.** A face match clears the account's
  `pam_faillock` counter, as a correct password would: the guesser who
  caused the lockout does not have the face. Our line answers before
  faillock's own reset module runs, so the daemon does it.
- **Remote callers.** A request whose caller the daemon cannot show to be
  local (an `sshd` in its ancestry, a logind session marked remote, or any
  shape it cannot verify) is refused before any window or camera. On the
  polkit lane the process judged is not polkit's root helper but the agent
  that connected it, read from the helper's systemd unit instance and
  pinned by pidfd, and the requesting process polkitd names must be local
  too. A same-uid process inside your own desktop session counts as local,
  and so does one that your own session services spawned for a remote
  shell (`systemd-run --user` from an SSH login, D-Bus activation, a user
  timer): provenance cannot tell those apart, so such a process can raise
  a window. What stands between that and root is the window naming the
  request, and the nod, which a remote shell cannot produce.
- **Root peers are trusted.** A socket peer with effective uid 0 may ask
  about any user, and enrol, delete and calibrate. The PAM module never
  sends those request shapes, and root itself is never authenticated by
  face.
- **The sandbox limits accidents, not a compromised daemon.** The unit's
  hardening narrows what a bug in the root daemon can reach by mistake. A
  daemon under an attacker's control still runs as root, and `/run` is
  writable in its mount namespace (that is how the faillock reset works).
  The structural answer, a dedicated user plus a small root helper, is not
  built.
- **Lid closed.** The camera is in the lid, so a consent request with it
  closed is answered before the camera is taken and the stack falls through
  to the password at once, as the fingerprint stack does through its PAM
  gate. The check lives in the daemon rather than the stack so nothing
  else's setup or removal can strip it. The lock screen is not gated: it
  has its own presence handling.
- **Templates** are 512-number embeddings, never images, root-only in
  `/var/lib/faceauth`, sealed to the TPM as a root-scoped systemd credential
  when the machine has one (a copy is useless anywhere else, and only root
  can open one here), plaintext with a `doctor` warning when it does not.
  Each template is bound to the camera that made it. There is no recovery
  key: templates that cannot be unsealed are re-enrolled.
- **The socket** is open to root and the enrolled users only (mode 0660 plus
  an access-list entry per enrolled uid). Match scores go to root callers
  only, never to the journal.
- **Rate limit**, shared by the lock screen and the consent window: five
  failed attempts in a minute, counted only when a face was seen (a
  non-match, a liveness refusal, a wrong password behind a match), then a
  thirty-second hold. Once a hold has been served every further failure
  starts the next at once, twice as long, up to eight minutes, until a
  match or ten quiet minutes. At the lock screen a hold is a refusal; in
  the consent window it pauses the face checks with the window still up,
  so the password box is there and the scan resumes when the hold is over.
- **Not defended**: a look-alike, a 3D mask, malware already running as you
  with your password, a video rendered on a display the IR camera can see
  (not measured; not claimed), a substituted or replaying camera that feeds
  the daemon recorded IR frames (the strobe pattern is fixed today; a
  per-request random pattern is being built and will narrow this, not
  close it), and anything a setuid-root binary you can run does as uid 0
  (on a stock system those are sudo, pkexec and polkit's helper, each of
  which authenticates first).
- **The false-accept rate is unmeasured.** The 0.70 threshold was set on
  one subject's face and one print; no other person's face has been scored
  against it, so how often a stranger would match is not known. Data is to
  be collected. `required_matches` is a spike filter over correlated
  frames, not a false-accept control.
- **No trusted-path marker.** A process running as you can draw a window
  that imitates the card and collect a password typed into it, and the
  real card carries nothing that such a window could not copy. An
  unprompted password window is only as trustworthy as the session it
  appears in: type a password into it only for a request you just made,
  and prefer the nod, which a fake window gains nothing from.

## Setup

`omarchy setup security face` does all of this; by hand:

```
sudo faceauth models fetch                 # ~260 MB, checksummed, once
sudo systemctl enable --now faceauth.service
sudo faceauth enroll --user $USER --guided # the walk-through window; --label for another look
faceauth auth --user $USER                 # {"result":"match",...} means it works
sudo faceauth calibrate --user $USER --guided   # the gesture rounds again (Tune Gestures)
faceauth doctor                            # every part, one row each
```

`enroll --guided` opens the enrolment walk-through: a full-screen window
on the laptop's own panel that draws a dot for where your head points and
a ring for the target, fed by the daemon with one line per analysed
frame (position, size, yaw, pitch, roll and whether the step is
satisfied); no image leaves the daemon. The steps are welcome, centre (sit
normally and look at the centre; the dot's size says too close or too
far), range (turn the head all the way round once so the ring is set from
your reach), path (follow the ring from the centre out to the edge and
round), hold (centre, left, right, centre, up, down, each held while
templates are taken), verify (look at the camera), then twelve gesture and
everyday rounds: two nods, two shakes, two glances right, two glances
left, a look at the keyboard, reading text placed around the screen,
talking while facing the screen, and leaning in. Each round's head swing
is recorded in degrees from the face mesh and the floors come from the
nods and shakes. Add Look starts at the centre step and stops after
verify; `calibrate --guided` (Tune Gestures in the menu) runs the rounds
alone. `enroll --terminal` is the older path, five looks prompted in the
terminal with no window; `calibrate` without `--guided` does the same for
the rounds.

Then the PAM lines from `packaging/pam-example.txt`: `omarchy-lock-face` for
the lock screen (closed by `pam_deny`), and one `consent` line at the top of
`sudo` and `polkit-1`. Removal is `omarchy remove security face`, which
restores the original PAM files and deletes the templates unless told to
keep them.

Development builds: `cargo build --features faceauth-cli/dev-tools`
compiles the tuning tools in (`faceauth sweep`, `faceauth pose`, the
walk-through's record mode and the per-frame gesture recordings); the
package is built without the feature and none of that code is in the
shipped binaries. See [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md),
"Development builds".

`doctor` rows: `camera.ir`, `camera.rgb`, `camera.illuminator`,
`models.manifest`, `models.file`, `daemon.running`, `templates.user`,
`templates.at_rest`, `templates.camera`, `gestures.calibrated`,
`liveness.policy`, `pam.sudo`, `pam.polkit`, `pam.lock`, `pam.greeter`,
`pam.faillock`, `pam.module`, `tpm.present`.

## Configuration

`/etc/faceauth/config.toml`, every key optional; `packaging/config.toml`
lists the defaults. The ones worth knowing: `accept_threshold` (cosine, 0.70)
and `required_matches` (2); `liveness` and `liveness_required` (a print can
pass on a camera without the strobe control if the latter is false);
`ir_video` and `ir_subdev` to name a UVC IR camera instead of detecting an
IPU3 one; `ir_orientation`; `consent_nods` (2); `gesture_trace` (write each
consent or calibration round's per-frame recording, plaintext under the
root-only store, for tuning; off) and
`gesture_record_only` (recognise but never act; for recording a battery);
the `[presence]` table for the walk-away lock.

## Command line

```
faceauth doctor [--json]
faceauth enroll [--user NAME] [--label TEXT] --guided [--start distance]
faceauth enroll [--user NAME] [--label TEXT] --terminal [--poses up,down]
faceauth calibrate [--user NAME] [--guided]
faceauth auth [--user NAME] [--consent]
faceauth templates delete [--user NAME]
faceauth presence on|off [--user NAME] [--away-seconds N]
faceauth models fetch
faceauth cam probe | cam test | engine live | verify ...   (development)
```

## Measured

On the reference machine (Surface Book 2, Intel IPU3, ov7251 IR sensor).
Lock screen opens in under two seconds; `sudo` approved by nod in three to
four seconds; a shake refuses in about two. Idle cost of the walk-away
watch about a twentieth of a core. Gestures are tuned and regression-tested
on recorded batteries in `faceauth-daemon/traces/cal` (twenty labelled
windows: still, nods, shakes, glances, looking down, reading, leaning,
talking, single gestures) and `traces/cal-phone` (the same, recorded during
a phone call): every nod and shake window counts, nothing else does. A
recorded battery of your own: `tools/battery.sh`. The measurements behind
every threshold are in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Layout

| Crate | What it is |
| --- | --- |
| `faceauth-camera` | V4L2 and media-controller capture, Intel IPU3 pipeline setup and 10-bit unpack, UVC greyscale decoders, exposure control, the IR illuminator as a V4L2 control. |
| `faceauth-engine` | Detect (YuNet), align, embed (glintr100, 512-D), cosine match, dense face mesh (MediaPipe face landmark, 468 points) and head pose from it, image motion; ONNX Runtime loaded at run time from `/usr/lib/libonnxruntime.so`. |
| `faceauth-daemon` | `faceauthd`: authentication (settle, strobe, liveness gate, two matching frames), consent (window, gesture detectors, password check against `system-auth`), presence, the sealed template store, the socket. |
| `faceauth-cli` | `faceauth`. |
| `pam_faceauth` | The PAM module; links only libc and libpam. |
| `packaging/` | Service unit, default config, lock helper, PAM example. |

Models are not in the repository or the package: `models.toml` names them
with checksums, sizes and licences, and `faceauth models fetch` verifies
them. The face mesh is Google's MediaPipe face landmark model
(Apache-2.0), converted one-to-one to ONNX and hosted on this project's
GitHub releases; its head pose drives the gestures, the attention check
that wakes a request, and the off-axis looks that enrolment takes so the
match holds when the head is turned.

## Build

```
cargo build --release --locked
cargo test --release --locked        # FACEAUTH_REQUIRE_TPM=1 to insist on the sealing test (root)
```

Concurrent IR+RGB capture and the illuminator on Intel IPU3 laptops need the
two kernel patches shipped in `linux-omarchy`; a UVC IR camera needs nothing.

## Where the shell lives

The daemon summons the consent window through `omarchy-shell` in the user's
manager, and finds Omarchy's tree the way Omarchy does: `OMARCHY_PATH` from
`/etc/omarchy.conf`, else `/usr/share/omarchy`. A packaged install points
at `/usr/share/omarchy`; a tree dev-linked from a home directory is the
user's own choice and is writable by anything running as them, window
included.
