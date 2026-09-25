# Omarchy FaceAuth

Face authentication for [Omarchy](https://github.com/omacom/omarchy) with an
infrared camera whose illuminator the kernel exposes as a control. The lock
screen opens when you look at it. `sudo` and polkit requests open a window
that names what is being run; two nods approve it, two head shakes refuse
it, or you type your password into the window. Rust, MIT. The package
depends on libc, libpam, systemd (`systemd-creds`, `systemd-run`), Arch's
`onnxruntime` (the CPU build or any that provides it), `curl`, `coreutils`,
`tpm2-tss` and `acl`, all used at run time.

Tested on one machine: a Surface Book 2 (Intel IPU3, ov7251 IR sensor)
running a kernel with the patches described under "Hardware" below.
UVC IR modules, the kind most Windows Hello laptops use, are not supported:
their emitter is not a V4L2 control, so the liveness gate cannot run and the
daemon refuses.

This repository is the daemon, the PAM module and the command-line tool. The
Omarchy side (lock screen stack, consent window, setup and removal, menu
entries, manual page) is a series of commits to `omacom/omarchy`; the
package recipe is `omarchy-faceauth` in `omacom/omarchy-pkgs`, and the
models come from `omarchy-faceauth-models`. Installing the package changes
one thing on its own: a udev rule makes the IR sensor's control node
root-only. The PAM stacks are written only by `omarchy setup security face`.

## The Security Contract

One claim per bullet, each with where the code keeps it.

- **The lock screen looks, it does not prompt.** A third PAM stack,
  `omarchy-lock-face`, answered by the face module and closed by
  `pam_deny`. While the panel is blank the daemon takes one short look every
  three seconds and wakes it only for an attentive face
  (`auth::Authenticator::probe`, the lock shell's `Service.qml`).
- **A request is approved by the daemon's own camera, never by a message.**
  Nothing elevates until the consent window has acknowledged the request
  over the socket, the face matches, the daemon sees two nods from that same
  face, none in a short dwell after the card appears and none from a head
  that was not still first, and a strobed confirm shows it live and enrolled.
  Two shakes refuse; the password typed into the window approves
  (`auth::consent_round`, `auth::consent_finish`, `auth::confirm`, `consent::NodDetector`).
- **Elevation is never passive**, except during a passwordless spell you
  started from the card (below). A face in front of the camera approves
  nothing, and no key, click or socket message stands in for the nod.
- **The card says what is asked and who asked.** For `sudo` and `pkexec`
  the first line is the command line the daemon reads from `/proc`, the
  second the requesting process and its parents. For any other polkit
  action the daemon marks the requester verified only when the agent could
  relay polkitd's process ids; otherwise the description is labelled
  "Unverified:" and nothing can be killed from the card. Control and
  direction-override characters are stripped; a long command scrolls, and
  past the daemon's limit it is cut and the card says so
  (`consent::Payload`, `consent::polkit_requester`).
- **Gestures are read from the head's angles**, pitch for the nod and yaw
  for the shake, from MediaPipe's dense landmarks on the matched face; the
  daemon refuses to start without that model. The face box must move along
  the gesture's axis during each leg, so a frozen box or a landmark fit that
  flipped cannot nod. A gesture is four alternating legs from a still head;
  a glance, a look down, reading, talking and leaning in are rejected by
  shape, and the recorded rounds pin that (`consent::NodDetector`,
  `consent::ShakeDetector`, tests `mesh_battery_holds`, `mesh_redteam`).
  The walk-through replays each recorded nod and shake to find where it
  stops reading and sets the person's floor at 0.85 of the lowest, never
  under 8 degrees for a nod and 15 for a shake, never over 16 and 24
  (`store::GestureCal::floors_deg`).
- **No deadline, no unattended nod loop.** Nods are read for
  `consent_seconds` (90) after a match, then disarmed. They are armed again
  when your face, checked to be yours, has been away from the card and is
  back and attentive, when you press Ready to nod, or when your face unlocks
  the screen; a face that merely stays in view does not re-arm them. A
  screen lock under the card parks the request until the unlock; with the
  walk-away lock on, walking away locks the session and the request resumes
  when your face unlocks it. The daemon re-sends the card every minute, and
  a card the daemon has gone quiet on hides itself without answering.
  Requests queue one at a time; approvals, refusals and waiting requests
  post a notice (`auth::run_with_answers`, `auth::consent_round`).
- **The answer token buys no approval.** Window answers carry a per-request
  token, handed to the window in its payload and returned on the answer's
  stdin. It is readable by a process running as you. With it a process can
  do exactly four things to the live request: acknowledge the card as
  drawn, dismiss the request, submit one password for the daemon to check
  against the PAM stack, and ask for the passwordless-sudo rider on a sudo
  request while the enrolled face is in the nod window. A rider armed that
  way is not hidden: the daemon re-shows the card naming it, waits for a
  fresh acknowledgement, and starts the dwell and the nods over
  (`server::consent_answer`, `consent::arm_passwordless`).
- **Passwordless sudo from the card.** The card can turn Omarchy's
  passwordless sudo on for a number of minutes (at most 24 hours) as part
  of the approval it is showing: the nod or password that approves the
  request also writes `/etc/sudoers.d/99-omarchy-nopasswd-<user>` and a
  timer that deletes it, the same rule and timer as
  `omarchy-sudo-passwordless`. Until the timer fires any process running as
  you uses sudo without a window, a face or a nod. The rider belongs to the
  one request it was armed on and dies with it; it is refused on the polkit
  lane and whenever the daemon is not following the enrolled face, and the
  card greys the control on the same signal. This is the only file outside
  `/var/lib/faceauth` and `/run/faceauth` the daemon writes
  (`consent::enable_passwordless`, `packaging/faceauth.service`).
- **Every failure falls back to the password.** The module returns
  `PAM_IGNORE` for everything but a match and one other thing: on a polkit
  consent line the answer no (a shake, a dismissed window, a confirm that
  refused) is `PAM_AUTH_ERR`, the line is written
  `[success=done auth_err=die default=ignore]`, and the agent cancels the
  request, so polkit reports "Not authorized" and no password dialog
  follows. A sudo request takes the same answer as "not by face" and the
  terminal prompt is where a password goes next. The module never converses
  with the application, so it never sees a password
  (`pam_faceauth/src/lib.rs`, `packaging/pam-example.txt`).
- **A photo on a phone** was never seen as a face in the tests made: the
  IR camera sees its own illuminator reflected in the glass, and a display
  emits almost nothing in the near infrared. A video rendered on a display
  the IR camera can see is not measured and not claimed.
- **A paper print** is refused by two physical measurements taken with the
  illuminator strobed: paper reflects the strobe several times more
  strongly than skin, and a print's surround lights up with the face while a
  real head's background stays dark. Both need the flash on the face to be
  readable; when it clips the sensor the pair is discarded rather than read,
  so a clipped print is never accepted on the reflectance cue, but it is not
  refused by it either until the exposure has come down enough to read it.
  A print held up and waggled passes the detector and fails the strobed
  confirm (`liveness::FlashResponse`, `auth::confirm`).
- **Replay.** Each attempt draws a random strobe mask from 68 patterns in
  nine distinguishable classes, scores only frames that follow it, and
  draws a fresh mask after every matching pair, so the two matches an
  attempt needs come under different masks: a recording that ignores the
  strobe control passes about one attempt in seventy; a device that reads
  the control and replays a face in step is not caught
  (`liveness::StrobePhase`).
- **Walk-away lock** (opt-in, `sudo faceauth presence on`): one short look
  every five seconds in secure mode (ten on battery) and every ten in the
  default mode, and a look at someone who was there keeps trying for up to
  two seconds before it counts as unseen. In the default mode any face turned
  to the screen holds the lock off, whoever it belongs to (a laptop handed
  to someone stays unlocked while they look at it), and the session locks
  once nobody has been in front of it for the away time; identity is
  checked on every third look only to report who is holding it. In secure
  mode identity is checked on every look and only the enrolled user's face
  holds the lock off: the first look that finds another face locks the
  session at once, an empty chair locks after the away time, and no other
  face holds the clock. Both modes make one allowance, the hidden face: a
  hand over the face, a head resting on a hand, leaning in to read or a
  look down at a phone reads as no face, a face turned away, a face the
  strobe cannot read, or a face that misses the match by a little, and it
  holds the clock while the shape in the chair under it is unchanged. How
  long it holds is the obscured face lock time, a setting per mode: never as
  shipped in the default mode (`obscured_face_lock = "never"`, or minutes),
  two minutes in secure mode (`secure_obscured_face_lock`, 1 to 10). Setup
  asks for both, and `sudo faceauth presence obscured-lock` changes them
  without switching the walk-away lock on. Only a face turned to the screen that
  misses by a wide margin is someone else, and in secure mode it locks at
  once. A print that fails the gate is not the user in either mode.
  Switch modes from the bar's walk-away widget or with Super+Alt+L; the
  switch lasts until the service restarts, and `[presence] mode` sets the
  starting mode (`presence::run`, `presence::PresenceMode`).
- **Bad-password lockouts.** A face match clears the account's
  `pam_faillock` counter, as a correct password would: the guesser who
  caused the lockout does not have the face (`auth::faillock_reset`).
- **Remote callers.** A request whose caller the daemon cannot show to be
  local (an `sshd` in its ancestry, a logind session marked remote, or any
  shape it cannot verify) is refused before any window or camera. On the
  polkit lane the process judged is the agent that connected the helper,
  read from the helper's unit instance and pinned by pidfd, and the process
  polkitd names must be local too. A request typed into an ssh session
  never reaches the camera. A same-uid process inside your own desktop
  session counts as local, and so does one your own session services
  spawned for a remote shell (`systemd-run --user` from an SSH login, D-Bus
  activation, a user timer): provenance cannot tell those apart, so such a
  process can raise a window, which is why the card names the request and
  why the nod, which a remote shell cannot produce, stands between it and
  root (`server::locality`).
- **Root peers are trusted.** A socket peer with effective uid 0 may ask
  about any user, and enrol, delete and calibrate. The PAM module builds
  only the plain look and the consent request, pinned by a test, and root
  itself is never authenticated by face (`server::handle`,
  `pam_faceauth::request_line`).
- **Rate limit**, shared by the lock screen and the consent window: five
  failed attempts in a minute, counted only when a face was seen, then a
  thirty-second hold that doubles on repeats up to eight minutes until a
  match or ten quiet minutes. At the lock screen a hold is a refusal; in
  the consent window it pauses the face checks with the password box still
  there. A consent scan scores a face for no longer than a lock-screen
  attempt does, and after a no (a shake, a dismissal, a confirm that
  refused) requests are refused without a window for a minute, doubling on
  repeats up to eight minutes (`auth::Strikes`, `server::refusal_standing`).
- **Templates** are 512-number embeddings, never images, root-only in
  `/var/lib/faceauth`, sealed to the TPM as a root-scoped systemd credential
  when the machine has one and plaintext with a `doctor` warning when it
  does not. Each template is bound to the camera that made it, named by the
  sensor's firmware node, and a recreated account with the same name is not
  enrolled. There is no recovery key: templates that cannot be unsealed are
  re-enrolled (`store`).
- **The socket** is open to root and the enrolled users only (mode 0660
  plus an access-list entry per enrolled uid). Match scores go to root
  callers only, never to the journal (`server::apply_socket_acl`).
- **Lid closed.** A consent request with the lid closed is answered before
  the camera is taken and the stack falls through to the password at once
  (`server::lid_closed`).
- **The sandbox limits accidents, not a compromised daemon.** The unit's
  hardening narrows what a bug in the root daemon can reach by mistake; a
  daemon under an attacker's control still runs as root. The structural
  answer, a dedicated user plus a small root helper, is not built.
- **Not defended**: a look-alike, a 3D mask, malware already running as you
  with your password, a video on a display the IR camera can see, a
  substituted camera that replays a face in step with the strobe, a process
  that holds the IR port's capture node (the udev rule closes the sensor's
  controls, not the CIO2 capture node; a face attempt then falls to the
  password until it lets go, and such a process can plausibly take ambient
  IR frames with the illuminator off), and anything a setuid-root binary you
  can run does as uid 0.
- **The false-accept rate is unmeasured.** The 0.70 threshold was set on
  one subject's face and one print; no other person's face has been scored
  against it. `required_matches` is a spike filter over correlated frames,
  not a false-accept control.
- **No trusted-path marker.** A process running as you can draw a window
  that imitates the card and collect a password typed into it. Type a
  password into the card only for a request you just made, and prefer the
  nod, which a fake window gains nothing from.
- **The consent window depends on Quickshell.** The polkit card is drawn
  by Omarchy's Quickshell polkit agent and needs a Quickshell that passes
  the request's details to the agent and serialises overlapping requests.
  Quickshell 0.3.1 as released does neither; the fixes travel with the
  Omarchy package as patches to it. On a Quickshell without them two
  overlapping polkit requests leave the second hanging until it is killed,
  killing it can crash the shell (which also draws the bar, the card and
  the lock screen), and every polkit card reads "Unverified:" with nothing
  to kill. Neither failure grants anything: the request falls to the
  password or is cancelled.

## Setup and Commands

`omarchy setup security face` does all of this; by hand:

```
# the models come with the omarchy-faceauth-models package (about 260 MB, checksummed by pacman)
sudo systemctl enable --now faceauth.service
sudo faceauth enroll --user $USER          # the walk-through window; --label for another look
faceauth auth --user $USER                 # {"result":"match",...} means it works
sudo faceauth calibrate --user $USER --guided   # the gesture rounds again (Tune Gestures)
faceauth doctor                            # every part, one row each
```

`enroll --guided` opens the walk-through: a full-screen window that draws a
dot for where your head points and a ring for the target, fed by the daemon
with one line per analysed frame and never an image. It takes the looks the
match needs (centre, the range of your reach, a path, held turns, a
verification), then twelve gesture and everyday rounds; the floors come from
the nods and shakes. Add Look records more looks; `calibrate --guided` (Tune
Gestures in the menu) runs the rounds alone. `enroll --terminal` is five
looks prompted in the terminal with no window; it records no rounds, so a
person enrolled that way runs at the default floors until Tune Gestures. The
steps are described in the manual and in `docs/DEVELOPMENT.md`.

Then the PAM lines from `packaging/pam-example.txt`: `omarchy-lock-face`
for the lock screen (closed by `pam_deny`), one `sufficient` consent line at
the top of `sudo`, and one `[success=done auth_err=die default=ignore]`
consent line at the top of `polkit-1`. Removal is
`omarchy remove security face`, which strips the lines and deletes the
templates unless told to keep them.

```
faceauth doctor [--json]
faceauth enroll [--user NAME] [--label TEXT] [--start distance]      the walk-through window (default)
faceauth enroll [--user NAME] [--label TEXT] --terminal [--poses up,down]
faceauth enroll [--user NAME] [--label TEXT] --look [--seconds N] [--count N]   one look, no walk-through
faceauth calibrate [--user NAME] --guided
faceauth auth [--user NAME] [--socket PATH] [--consent]
faceauth probe [--user NAME]                   one short look: is a face there?
faceauth templates delete [--user NAME]
faceauth presence on|off [--user NAME] [--away-seconds N]
faceauth presence mode [default|secure]        read or switch the walk-away mode until the next restart
faceauth presence                              the watch's current state
faceauth cam probe | cam graph | cam test | engine inspect|test|live | liveness capture | verify
                                               hardware bring-up tools; they ship, and they need root for the camera
```

`faceauth doctor` reports one row per part: the cameras and their access
(`camera.ir`, `camera.ir_access`, `camera.rgb`, `camera.illuminator`), the
models, the daemon, the templates and how they rest, the gesture floors, the
liveness policy, each PAM stack and the TPM. Configuration is
`/etc/faceauth/config.toml`; `packaging/config.toml` names every key with
its default and ships with every line commented out. Development builds
(`cargo build --features faceauth-cli/dev-tools`) add the tuning tools and
the per-frame gesture recordings described in
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md); the package is built without
them.

## Hardware and Measurements

The IR illuminator is driven through a V4L2 strobe control that the stock
ov7251 driver does not have; the last patch of a ten-patch series for
linux-media (`media: i2c: ov7251: expose the strobe output as a flash
control`) adds it, and it is not yet in `linux-omarchy` or any other shipped
kernel. Without it face authentication refuses and the password is used.
The ipu3-cio2 patches before it fix seven bugs in the CIO2 driver and then
let the RGB camera stream at the same time (`media: ipu3-cio2: support
concurrent streams on multiple CSI-2 ports`), so a consent window during a
video call does not kill the call's camera. Setup checks for the strobe control (`faceauth doctor`, row
`camera.illuminator`) before it changes anything.

Models are not in the repository: the `omarchy-faceauth-models` package
installs the YuNet detector (MIT), the glintr100 recognition model
(Apache-2.0) and Google's MediaPipe face landmark model (Apache-2.0,
converted one-to-one to ONNX and hosted on this project's GitHub releases)
from the project's `models-N` release; `models.toml` names them with
checksums, sizes and licences, and `faceauth doctor` verifies the installed
files against it. ONNX Runtime is loaded at run time from
`/usr/lib/libonnxruntime.so`.

What is tested, and what was measured, on the reference machine with one
enrolled subject:

- The gesture detectors are regression-tested on recorded rounds in
  `faceauth-daemon/traces/v2` (the face mesh path, the only one; one
  subject, twelve rounds): every gesture round must read as two, every
  everyday round as none, the floors the walk-through derives must keep the
  recorded user's own gestures, and a red-team module adds a frozen box, a
  waggled board, a plateau flicker, a turned head and an off-axis nod, none
  of which may read. `tools/battery.sh` records consent windows of your own
  in the same format.
- The liveness thresholds come from 110 lit/unlit pairs each of the face
  and a print; the accept threshold from one subject's genuine attempts
  and one print. Both are written up with their scope in
  `docs/DEVELOPMENT.md`; the mesh floors, the leg time and the rest step
  are stated there with the rounds they came from.
- Timings and idle cost were last measured before the strobed confirm and
  the mesh were added (the lock screen opened in under two seconds, a nod
  approved sudo in about two), and the walk-away watch's cost was measured
  at an older cadence. They have not been re-measured on the shipped build;
  `tools/power-measure.sh` is the tool for it.

## Layout

| Crate | What it is |
| --- | --- |
| `faceauth-camera` | V4L2 and media-controller capture, Intel IPU3 pipeline setup and 10-bit unpack, UVC greyscale decoders, the exposure loop, the IR illuminator as a V4L2 control. |
| `faceauth-engine` | Detect (YuNet), align, embed (glintr100, 512-D), cosine match, dense face mesh (MediaPipe face landmark, 468 points) and head pose from it, the flash-response gate, the region comparison for the walk-away lock. |
| `faceauth-daemon` | `faceauthd`: authentication (settle, strobe, liveness gate, two matching frames), consent (window, gesture detectors, password check against `system-auth`), presence, the sealed template store, the socket. |
| `faceauth-cli` | `faceauth`. |
| `pam_faceauth` | The PAM module; links libc and libpam, and never converses. |
| `packaging/` | Service unit, default config, udev rule, lock helper, PAM example. |

Build: `cargo build --release --locked`; `cargo test --release --locked`
(`FACEAUTH_REQUIRE_TPM=1` insists on the sealing test, which needs root).

The daemon summons the consent window through `omarchy-shell` in the user's
manager, and finds Omarchy's tree the way Omarchy does: `OMARCHY_PATH` from
`/etc/omarchy.conf`, else `/usr/share/omarchy`. A tree dev-linked from a home
directory is writable by anything running as the user, window included.
