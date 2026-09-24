# Development reference

How the source tree is laid out, how to build and test it, how to run a
daemon of your own, what the tuning tools report, and the measurements the
shipped thresholds rest on. The README is the document to read first. The
history of how each decision was reached is in the git log, not here.

## Workspace layout

The Rust workspace has five crates. `faceauth-camera` is V4L2 and
media-controller capture: the Intel IPU3 graph, the packed 10-bit unpack, the
UVC greyscale decoders, the exposure loop and the IR illuminator as a V4L2
control. `faceauth-engine` is detection (YuNet), alignment, embedding
(glintr100, 512 dimensions), cosine matching, the dense face mesh (MediaPipe
face landmark, 468 points) with head pose from it, the flash-response
liveness gate and the region comparison the walk-away lock uses.
`faceauth-daemon` builds
`faceauthd`: authentication, consent, presence, the template store and the
socket. `faceauth-cli` builds `faceauth`. `pam_faceauth` is the PAM module
and links only libc and libpam.

Beside the crates: `packaging/` holds the service unit, the default config,
the udev rule for the IR sensor, the lock helper and the PAM example;
`models.toml` is the model manifest; `tools/` holds the battery and power
scripts; `tests/` holds the shell test for the lock helper; and
`faceauth-daemon/traces/` holds the recorded gesture rounds the unit tests
replay. Nothing under `traces/` is an image: every file is numbers per
frame.

## Building

```
cargo build --release --locked
cargo test --release --locked
```

The build needs Arch's `onnxruntime-cpu`; the engine loads
`/usr/lib/libonnxruntime.so` at run time through `ort` with `load-dynamic`,
so nothing links it at build time. The few V4L2, media and subdev structs the
camera crate uses are spelled out by hand and size- and offset-checked
against the kernel headers in unit tests, so the build needs no libclang or
bindgen.

### The dev-tools feature

`cargo build --features faceauth-cli/dev-tools` compiles the tuning tools
in. The feature lives on `faceauth-daemon` and the CLI's feature turns it on
there. It gates `faceauth sweep` and `faceauth pose` (root; score and pose
per frame while the head moves), the walk-through's record mode
(`faceauth enroll --guided --start record`, which stores no templates and
keeps one IR frame in five under `/var/lib/faceauth/record/<user>/`, root only),
and the per-frame gesture recordings that the `gesture_trace` setting asks
for. Without the feature the recording hooks compile to nothing, `sweep` and
`pose` are unknown commands, and `--start record` is refused; the package is
built without it, so none of that code is in the shipped binaries. Test both
ways when you touch the daemon:

```
cargo test -p faceauth-daemon
cargo test -p faceauth-daemon --features dev-tools
cargo test -p faceauth-cli --features dev-tools
```

## Tests

Every crate has unit tests and `cargo test --locked` at the root runs them
all. The store's sealing test needs a TPM and root; without both it prints
that it skipped, and `FACEAUTH_REQUIRE_TPM=1` (the release check) turns the
skip into a failure. The lock helper has a shell test,
`tests/lock-session-test.sh`, which stubs `systemd-run` and checks that the
helper resolves the Omarchy tree from every form `omarchy.conf` takes and
answers 0 only when the compositor reports a session lock.

The gesture detectors are regression-tested on recorded rounds in
`faceauth-daemon/traces/v2`, replayed frame by frame through the same
detector code the daemon runs. There is one gesture path, the face mesh's
angles, and the daemon refuses to start without the mesh model
(`auth::mesh_missing`), so one corpus and one synthetic module guard it:

`mesh_battery_holds` replays `traces/v2`, twelve rounds recorded through the
enrolment walk-through with the face mesh (format in its README: yaw, pitch
and roll in degrees plus the detector box; the files carry two image-motion
columns from the detectors that were removed, which nothing reads). Both
nod rounds must read as two nods, both shake rounds as two shakes, and the
eight everyday rounds (glances each way, the keyboard, reading, talking,
leaning) as nothing, at the default mesh floors.
`the_derived_floors_keep_the_reference_users_own_gestures` derives the
floors from those rounds the way the walk-through does and requires the
same reads at the derived floors.

`mesh_redteam` is the attack module, synthetic in degrees and box geometry:
a frozen box whose pitch oscillates reads as nothing and the box-motion
rule is what refuses it (with the rule off it reads as nods); a waggled
board carries its box and passes the detector by design, because the
strobed confirm after the nods is what refuses it; a plateau flicker over a
still box reads as nothing at any nod-sized height; the recorded nods
re-centred 30 degrees off still read and are refused from 36 either way;
and a synthetic nod made with the head turned reads as nothing.

Recordings of your own come from the daemon: a walk-through round or a
consent window with `gesture_trace` on writes `consent::ROUND_HEADER` and
one line per frame in the same format, so a live misfire drops straight
into a test. Whenever a gesture misfires live, pull the recording, add it
with a one-line label, and let the suite fail before you touch a detector.

## The consent lane, step by step

What the daemon does between a `sudo` and its approval, in the order the
code runs it, so a change to one step can be checked against the others
(`auth::consent_begin`, `auth::consent_round`, `auth::consent_finish`).

1. The request arrives from the PAM module with `consent` set. The daemon
   refuses it before any window if the caller is not local, if another
   user's request is live, or if a refusal from a recent no is still
   standing (`server::locality`, `server::refusal_standing`).
2. The window is summoned in the user's own manager with a payload that
   names the request and carries a per-request token. Nothing is read from
   the camera until the window has answered `--ack` with that token: the
   card is on screen before a nod can count.
3. A short dwell follows the acknowledgement, and the nod detector arms
   only once the head has been still. A nod already under way when the
   card appears is not counted.
4. The scan matches the face, follows that box, and reads nods and shakes
   from the mesh angles on it. Nods are read for `consent_seconds` after a
   match; when that passes unanswered they are disarmed and the camera
   drops to the presence rhythm. They are re-armed by a face that was away
   and is back and attentive (checked to be the user first), by the card's
   Ready to nod button (`--rearm`), or by a face unlock of the lock screen.
5. After the second nod the illuminator draws a fresh mask and two lit and
   unlit pairs must pass the flash gate and match the templates on that
   box (`auth::confirm`). Only then does `consent_finish` answer match,
   reset faillock and, if a rider was armed, write the passwordless rule.
6. A password typed into the card is checked once against `system-auth`
   (`pamcheck::check`) and counts as an approval; a wrong one is charged
   like a non-match.

The passwordless rider (`consent::arm_passwordless`,
`consent::take_passwordless`, `consent::enable_passwordless`): the card asks
for it with the token while the enrolled face is in the nod window, on the
sudo lane only. The daemon then re-shows the card naming the rider, waits
for a fresh acknowledgement and starts the dwell and the nods over. The
rider belongs to the request it was armed on and is dropped with it, so a
request that ends without approval leaves nothing armed for the next one.
The rule and the timer that removes it are the same ones
`omarchy-sudo-passwordless` writes.

Requests from the same user queue and take the window in turn; a request
from another user while one is live is refused at once, so the window on
screen is always one user's (`server::handle`).

## The enrolment walk-through

`faceauth enroll --guided` (root; `omarchy setup security face` runs it)
opens a full-screen window on the laptop's own panel that draws a dot for
where the head points and a ring for the target, fed by the daemon with one
line per analysed frame (position, size, yaw, pitch, roll and whether the
step is satisfied); no image leaves the daemon. The steps: welcome; centre
(sit normally, look at the centre; the dot's size says too close or too
far); range (turn the head all the way round once so the ring is set from
the person's reach); path (follow the ring from the centre out to the edge
and round); hold (centre, left, right, centre, up, down, each held while
templates are taken); verify (look at the camera); then twelve gesture and
everyday rounds: two nods, two shakes, two glances right, two glances left,
a look at the keyboard, reading text placed around the screen, talking
while facing the screen, and leaning in. Each round is recorded in degrees
from the face mesh and stored with the templates; the floors come from the
nods and shakes as described under Tuning tools. Add Look starts at the
centre step and stops after verify; `calibrate --guided` runs the rounds
alone. Continue, Redo and Cancel come from the window over the socket
(`faceauth enrol-control`), per session and per user.

## A daemon of your own

The daemon takes its config path as its one argument and defaults to
`/etc/faceauth/config.toml`. The store (`/var/lib/faceauth`) and the socket
(`/run/faceauth/sock`) are fixed and are not config keys, so a development
daemon does not run beside the packaged one: it replaces it. Stop the
service first, then run the build from the workspace root:

```
sudo systemctl stop faceauth.service
cargo build --features faceauth-cli/dev-tools
sudo ./target/debug/faceauthd /path/to/dev/config.toml
sudo ./target/debug/faceauth auth
```

`faceauth-cli/dev-tools` switches the daemon and camera crates' `dev-tools`
features on with it. The development config needs only the keys it changes;
`models_dir` is the one most builds set, and the two development-only keys
(`gesture_trace`, `gesture_record_only`) exist in that build alone. Root is
needed because the udev rule makes the IR sensor's subdev root-only and
enrolment and deletion are accepted from root alone. The development daemon
serves the packaged socket, so PAM, sudo and the lock screen talk to it while
it is up; templates it enrols land in the packaged store, sealed to the TPM
where there is one, and the walk-away watch runs on whatever the config
says. Start the service again when the build is done. `FACEAUTH_MODELS`
points the CLI's direct-camera commands (`cam test`, `engine live`,
`liveness capture`, `verify --store`) at a models directory; those commands
never touch a daemon.

## Tuning tools and what their output means

`faceauth cam probe` lists the IPU3 graph by entity name, classifying each
sensor by its media-bus code and its `camera_orientation` control, and says
whether the IR sensor exposes the strobe control and its frame pattern. On a
UVC IR module there is no strobe control: the liveness gate cannot run, and
with the default `liveness_required = true` the daemon refuses every attempt
on such a camera. Do not read a probe that finds a UVC camera as a working
setup.

`faceauth cam test --seconds N --led on|off|alt --snapshot DIR` streams the
cameras and prints a line per second: frame count and rate per camera, the
exposure loop's exposure and gain, the white-balance gains and the meter
readings. `--exposure LINES` freezes exposure, which is how a print of a
fixed-exposure IR frame is made for a spoof test. `--ir-only` skips the RGB
sensor.

`faceauth engine live --models DIR --led on` runs detect, align and embed on
a live IR stream and prints, per analysed frame, the detector score, the
box, the pipeline time and the cosine similarity against the previous frame
and the first. A same-person similarity that decays as the exposure loop
climbs means the crop normalisation is not doing its job; it should hold
above 0.7 across the ramp and above 0.9 frame to frame.

`faceauth liveness capture --models DIR --label TEXT --save DIR` settles
exposure with the LEDs steady, freezes it, switches the strobe to a random mask (0xaa only when the OS gives no randomness), pairs each lit frame with the unlit one before it and
logs the flash-response cues per pair to a CSV: the face's flash response
normalised by exposure, gain and face size (the reflectance cue), the ring
flash divided by the face flash (the surround cue), and the eye glint
statistic. Run it once on a real face and once on a print at the same
distance to see the separation the gate relies on.

`faceauth sweep` (dev-tools, root) asks the running daemon to score every
frame for twenty seconds while the user follows on-screen cues to turn
slowly left, right, up and down, and prints the score binned by yaw with
the pass rate at the threshold. It shows how far a person can turn before
the match falls off, which is what the off-axis looks at enrolment exist to
fix. `faceauth pose` (dev-tools, root) is a live readout of the pose
measures a few seconds at a time, so a person can see what a turn or a tilt
reads as.

`faceauth calibrate --guided` (root; Tune Gestures in the menu) runs the
walk-through's twelve rounds alone: two nods, two shakes, two glances each
way, a look at the keyboard, reading, talking and leaning in. Each round is
recorded in degrees from the face mesh and stored with the person's
templates, and each gesture round is replayed through the mesh detector to
find the highest floor at which it still reads; the person's floor is 0.85
of the lowest of those, never under the detector's minimum nor over the
cap (`GestureCal::floors_deg`). `faceauth doctor` reports those floors on
its `gestures.calibrated` row, and they are the floors the nod window runs
at (`auth::consent_floors`). The everyday rounds are recorded and stored
but not yet replayed against the floors (round-4 STORE-5).

`tools/battery.sh [USER] [OUTDIR]` records a battery of consent windows: it
turns on `gesture_trace` and `gesture_record_only` in the live config
(root, with a backup beside it), restarts the service, runs the labelled
windows through `faceauth auth --consent` (which grants nothing), restores
the config and collects the recordings under their item names.
`gesture_trace` writes each consent round's per-frame recording (the mesh's
angles and the box, format v3) to `/var/lib/faceauth/gestures/<user>/`, root-only,
newest sixty kept; `gesture_record_only` makes the daemon
recognise gestures without acting on them, so a recording captures each
gesture to its rest instead of ending at the decision. Both are off in the
shipped config and the recording hooks exist only in dev-tools builds.

`tools/power-measure.sh` reads the battery meter over timed phases. Its
whole-system figures are dominated by whatever else the machine is doing; a
clean comparison needs a quiet machine and phases of minutes, not seconds.

## Models

Weights are never vendored. `models.toml` names each model with its URL,
SHA-256, size, licence, provenance and input contract, and `faceauth models
fetch` downloads each file with `curl` by absolute path in a clean
environment, verifies the size and hash, and installs it under
`/usr/share/faceauth/models` (or `--dir`). `faceauth doctor` re-checks the
hashes on its `models.file` rows.

Three models: the YuNet detector from OpenCV Zoo (MIT), the glintr100
recognition model from fal's AuraFace-v1 (Apache-2.0; only that one file,
since the repository's bundled detector and landmark models are
InsightFace-derived and non-commercial), and the MediaPipe face landmark
model (Apache-2.0). The last is Google's `face_landmark.tflite` converted
one-to-one to ONNX with tf2onnx, opset 13, and published on this project's
GitHub release `models-1` with its licence text and a NOTICE describing the
conversion; the manifest records the original file's hash and size beside
the converted one's. The engine loads the mesh when the file is present;
the daemon refuses to start without it, naming the file and the package,
because the gestures are read from the head's angles and nothing else. The
CLI's engine tools load a pipeline without it.

## The kernel dependency

The IR illuminator is driven through a V4L2 strobe control that the stock
ov7251 driver does not have. Kernel patch 0002 (`media: i2c: ov7251: expose
the strobe output as a flash control`) adds `strobe_output_enable` and a
frame-pattern bitmask; without it `cam probe` reports no illuminator, the
liveness gate cannot run, and the daemon refuses. Patch 0001 (`media:
ipu3-cio2: support concurrent streams`) gives each CIO2 queue its own DMA
channel so the RGB camera can stream while the IR camera does, which is
what keeps a consent window from killing a video call's camera. Neither is
in a shipped kernel yet; both are kept with their measurements and review
history in the project's kernel pack, outside this source tree. The daemon
needs read and write access to `/dev/media*`, `/dev/video*` and
`/dev/v4l-subdev*`; the packaged unit gets that through `DeviceAllow`, and
the udev rule in `packaging/` makes the IR sensor's subdev root 0600 so an
ordinary user cannot drive the strobe or take IR frames through it.

## Measurements behind the thresholds

Everything below was measured on one machine, a Surface Book 2 (Intel IPU3,
ov7251 IR sensor at 640x480), with one enrolled subject. The impostor side
is one life-size paper print and one phone screen. That is the honest scope:
before the accept threshold is trusted as a `sudo` factor on other faces, it
needs other people measured.

**Accept threshold 0.70, two matching frames.** Genuine attempts score 0.86
to 0.96 on the best template; the ten enrolment templates agree with each
other at 0.90 minimum and 0.945 mean over 45 pairs. A visible-light print of
the enrolled face is detected (scores 0.84 to 0.91) and reaches the
recogniser, which puts it at 0.37 to 0.56. A partially blocked genuine face
once reached 0.797 on a single frame, which is why `required_matches` is 2
and not 1, and why the threshold is expected to rise once more subjects are
measured. The threshold is not a liveness defence: a print made from an IR
frame of the enrolled face scores far closer, and a 1.5x life-size print of
a fixed-exposure IR frame, held at the lock screen for twelve minutes, was
refused by the gate or failed to match on every frame that passed it.

**Liveness cues.** `REFLECTANCE_DENY` is 0.80 and `SURROUND_DENY` 0.42 in
`faceauth-engine/src/liveness.rs`, from 110 lit/unlit pairs each of the face
and the print at the same distance. The reflectance cue (face flash response
over exposure times gain, normalised by face size so it is distance-free)
read 0.28 for the face and 1.66 to 2.2 for the print. The surround cue
(flash on a ring 1.4 to 2.0 face widths out, over flash on the face) read
0.31 to 0.36 for the face and 0.44 to 0.54 for the print, because a print's
surround is at the print's distance while a head's surround is the room
behind it. Paper reflects near infrared several times more strongly than
skin, so the exposure loop settled at 267 on the face and 66 on the print.
The eye-glint statistic did not separate them at this face size and is not
used. The gate is deny-only; a pair with too little face flash
(`MIN_FACE_FLASH`) decides nothing. The phone screen never reaches the
recogniser at all: a display emits almost nothing in the near infrared and
its glass mirrors the illuminator. The gate has not been measured against a
video rendered on a display the IR camera can see, and is not claimed to
stop that.

**Gesture floors, mesh.** From the `traces/v2` rounds: a nod's legs are 12
to 35 degrees of pitch and take 0.23 to 0.33 s, reversing at once; a look at
the keyboard is 17 to 21 degrees a leg but takes 0.9 to 2 s and holds at the
bottom; a lean is 18 to 30 degrees over 1.1 to 3.3 s. A shake's legs are 33
to 53 degrees of yaw in about 0.3 s; a glance aside is as large but takes
0.8 to 2.2 s and holds at the side. Size does not separate a gesture from an
everyday movement; leg time does, so a leg may take at most `MESH_LEG_MAX_S`
(0.6 s). The floors are `MESH_MIN_DEG` 8 for the nod and 15 for the shake;
the walk-through sets a person's floor to 0.85 of the lowest floor at which
their recorded gesture rounds still read, never under those minimums and
never over 16 and 24 degrees. A still head reads about
0.7 degrees between frames, a turnaround several, so rest is under
`MESH_REST_STEP` (1.5).

**Presence.** The watch takes one look every 5 s on mains and 10 s on
battery, with an identity and liveness check every third look in default mode and on every look in secure mode; camera duty
is about 14 and 7 percent. Detection costs about 14 ms a frame and the
embedder about 0.35 core-seconds a run, so a watch that identifies every
tick from a cold exposure is expensive and wrong: ticks start from the
exposure the last attempt settled on. A hidden face is not absence, in
either mode: when a look holds nothing (no face, or a face that neither
matches nor faces the screen, which is what a hand on the chin or a look
down at a phone gives the mesh), the torso under the last full sighting is
compared by normalised cross-correlation, and `SAME_SHAPE` 0.60 holds the
away clock for up to `PARTIAL_GRACE_S` (120 s) and stays the secure mode's
first-miss lock. Measured: a hand over part of the face 1.00, a
sheet over it 0.95, the face fully covered 0.79, the chair empty -0.34.

**Timing.** The exposure loop settles on a face in about 1.2 s; a lock
screen attempt matches in under two seconds from the panel becoming secure;
the strobed confirm after the second nod takes about 0.6 s for two pairs.
Unsealing a template file costs about a second of TPM time on a cold daemon
and is cached against the file afterwards.

## Decisions carried into the code

The daemon owns the cameras. No loopback node sits in the authentication
path, so frames never leave the process that scores them, which removes the
frame-injection surface and the exclusive-access problem together. The
graph is found by entity name and sensors by what they produce: device
numbers move across boots and module reloads; entity names, media-bus codes
and the orientation control do not. Calibration is pure: `calib` computes
the next setting from a frame and the device layer applies it, so the loops
are unit-tested without hardware.

Templates are sealed with `systemd-creds` to the TPM, scoped to root with
the host secret in the mix, with no recovery key anywhere on disk: a
template that cannot be unsealed is set aside and re-enrolled. Each
template records the camera that enrolled it and matches only there. Match
scores go to root callers only, never to the lock screen's helper or a user
shell, and never to the journal at info level, because a visible score is a
hill-climbing oracle for a spoof. The socket is 0660 with a per-user ACL
for each enrolled user, refreshed on every enrolment and deletion.

A consent request has no deadline: the reply arrives when the user answers
the window or never, a caller must set no read deadline, and the daemon
notices a caller that hung up. Nothing elevates until the window has
acknowledged the request, the face has matched, the daemon has seen the
nods from that same face, and a strobed confirm has shown it live and
enrolled. Locality is a positive, fail-closed check from `/proc` and logind:
an sshd ancestor is remote, root in the system slice is local, a process in
a logind session is local only if that session is on a seat and not marked
remote, and any read error or vanished caller is remote. Every failure that
is not a decision returns `PAM_IGNORE` so the password path is untouched;
only a refusal on a polkit consent line is `PAM_AUTH_ERR`.

The daemon never switches uid. Anything that must run in the user's session
(the lock command, the consent window, the notices) runs inside the user's
own systemd manager through `systemd-run --machine=user@.host --user`,
because the hardened unit has an empty capability set and a PAM session
opened from inside the sandbox fails. A transient test unit must never be
given `RuntimeDirectory=faceauth`: systemd removes that directory when the
unit exits and takes the live socket with it.

## Conventions

Comments are full sentences in plain English that say why, not what, and
name the measurement or the failure that led to a rule. No em dashes. A
constant that came from a recording names the corpus in its doc comment.
Review identifiers and dates belong in commit messages, not in code.

`cargo fmt` and `cargo clippy` run clean, and a clippy fix that would change
behaviour is not applied as a lint fix: it gets its own commit with its own
test, or a targeted allow with the reason in a sentence. The same goes for
any inline suppression.

Gesture floors and liveness thresholds are never moved by hand. A floor
changes only when the recorded rounds show the new value is correct on
every file and the suite is updated in the same change. When a gesture
misfires live, the recording becomes a test first. Detector changes are
checked against the mesh battery and the red-team module; there is no
other gesture signal.

A UVC camera is not a supported configuration and the docs must not say
otherwise: a UVC IR module has no strobe control, so with the default
config every attempt on one refuses. Anything measured is stated with its
scope (which machine, how many subjects, what impostor) and a claim that
outruns its measurement is cut rather than softened.
