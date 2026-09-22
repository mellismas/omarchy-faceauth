# Development log

The record of how Omarchy FaceAuth was built and measured, in the order it
happened, mistakes included. Each section is dated. The README is the
document to read first; this is where its numbers come from.

## Camera crate, first hardware run (2026-09-18 17:33)

`faceauth cam probe` on the Surface Book 2 finds the IPU3 graph by entity name and
classifies the sensors by media-bus code and the `camera_orientation` control:

```
  Colour    Back      ov8865 3-0010    port 0  /dev/v4l-subdev8  /dev/video0  3264x2448 -> ip3b
  Colour    Front     ov5693 2-0036    port 1  /dev/v4l-subdev6  /dev/video1  1296x972  -> ip3b
  Infrared  -         ov7251 3-0060    port 2  /dev/v4l-subdev7  /dev/video2  640x480   -> ip3y
            illuminator: strobe control present (pattern: true)
```

`faceauth cam test --seconds 8 --led on` enables the sensor links, sets the formats
through the CSI-2 receivers, streams both cameras with mmap buffers, unpacks the
IPU3 packed 10-bit frames, runs the exposure loops and the grey-world white
balance, and drives the illuminator through `strobe_output_enable`:

```
t=  7.1s IR  215 fr (30.2 fps) exp=1704 gain= 86 dg=1.00 ... | RGB  215 fr (30.2 fps) exp=1030 wb=1.30/1.99 meter 0.30/0.05 | led=1
```

Both at the sensor rate (the test loop services them in turn, so RGB shows the IR
cadence; the daemon gives each camera a thread). Snapshots in
`faceauth-camera/proof/`: the IR frame is the raw sensor orientation (mounted
rotated 90 degrees on this machine; the viewer rotates it and the daemon will carry
a per-sensor rotation in its config), the RGB frame is the Bayer 2x2 reduction with
the signed-off look.

## Engine crate, first run on the IR camera (2026-09-18 20:20)

`faceauth engine live --led on` streams the IR sensor, orients the frame, converts
to 8-bit, and runs detect, align and embed on every fifth frame (release build):

```
t= 5.5s face score 0.83 bbox 50x76 at (302,337) 132 ms | vs prev 0.933 vs first 0.721 | exp=881 gain=16 meter 0.31
90 frames analysed, mean 133.1 ms per frame (detect + align + embed)
```

- Arch's `onnxruntime-cpu` 1.29 loads under `ort` 2.0.0-rc.13 with `load-dynamic`.
- 130 ms per frame for the whole pipeline; the recognition model is 261 MB and takes
  most of it. A five-frame authentication burst is under a second.
- The aligned crop is contrast-normalised on its own percentiles before embedding.
  Without that, same-person similarity to the first frame decayed from 0.9 to 0.08 as
  the exposure loop climbed; with it, it holds at 0.72 to 0.85 across the ramp and
  0.90 to 0.96 frame to frame, with the face only about 50 pixels wide at desk distance.
- The exposure loop meters on the detected face box (mapped back to raw sensor
  coordinates), and settles at exposure 881, gain 16 with the illuminator on. The
  centre window had driven it to maximum because most of the window is dark room.
- Model manifest with checksums and licences: `models.toml`. Weights live outside the
  repo (`FACEAUTH_MODELS` or `/usr/share/faceauth/models`).

Proof in `faceauth-engine/proof/`: the detected frame, the aligned 112x112 crop, and
the run log.

## Enrolment and first attack test (2026-09-18 20:50)

`faceauth enroll` captures ten embeddings over a 12 s burst with the illuminator on
and face-box metering (samples spaced across the window), and stores them as
templates (`faceauth-daemon/src/store.rs`: JSON, mode 0600, several templates per
user matched by best score). `faceauth verify` runs a five-frame burst and reports
the best cosine against the templates, optionally logging every frame to a CSV
with a label for the threshold analysis.

| Test | Frames | Cosine (best template) | Time |
| --- | --- | --- | --- |
| Genuine, run 1 | 5 | 0.942 to 0.955 | 2.1 s capture |
| Genuine, run 2 | 5 | 0.863 to 0.936 | 2.1 s capture |
| Enrolment self-consistency, 10 templates | 45 pairs | min 0.902, mean 0.945, max 0.982 | |
| Phone showing a photo of the enrolled face | 0 faces in 8 s | no detection, no score | |
| Life-size print of the enrolled face, run 1 | 5 | 0.365 to 0.531 | 4.8 s |
| Life-size print of the enrolled face, run 2 | 5 | 0.454 to 0.556 | 4.7 s |

The phone-screen replay never reaches the recognizer. In the IR frame
(`faceauth-engine/proof/attack-phone-screen-ir-2026-09-18.png`) the screen is a
starburst of the illuminator's own reflection with no image on it: a display emits
almost nothing in the near infrared and its glass mirrors the LEDs. That is the
physics the design leans on, confirmed on the first try. The print (a visible-light, smiling photo on plain paper) is detected at scores
0.84 to 0.91 and reaches the recognizer, which puts it at 0.37 to 0.56: well under
the genuine 0.86 to 0.96, so a provisional accept threshold of 0.70 has margin on
both sides for this one subject and this one print. That margin is not a liveness
defence: a print made from an IR frame of the enrolled face would score far closer.
The liveness gate is required regardless, and the print run is its first data
(`faceauth-engine/proof/attack-print-*.png`, `scores-2026-09-18.csv`).

## Liveness: the flash response, first measurements (2026-09-18 21:30)

`faceauth liveness capture` settles exposure on the subject with the LEDs steady,
freezes it, switches the strobe to the alternating pattern (0xaa), pairs each lit
frame with the unlit one before it, and measures the flash response (lit minus
unlit). 110 pairs each for the real face and the same life-size print, same
distance, same room (night: the unlit frames are black, 4/255, so there is no
ambient near-infrared to divide by and the lit/unlit ratio image is not usable
here; it stays in the plan for daylight).

| Cue | Real face | Print | Separated |
| --- | --- | --- | --- |
| Reflectance: face flash response / (exposure x gain/16) | 0.282 to 0.285 | 1.89 to 2.23 | yes, 7x |
| Surround: flash on a ring 1.4 to 2.0x the face box / flash on the face | 0.309 to 0.363 | 0.444 to 0.539 | yes |
| Exposure the face-box loop settled at | 267 | 66 | |
| Glint at the eye landmarks (peak / local mean, 11x11) | 1.5 to 2.7 | 1.3 to 1.9 | no |

Why these work: paper reflects near-infrared several times more strongly than
skin, so at the same distance a print needs a fraction of the exposure; and a
print's surround is at the print's distance while a real head's surround is the
room behind it, several times farther, which the inverse-square falloff of the
flash makes dark. The glint is visible by eye in the lit frames of the real face
but is one pixel wide at this face size, and the 11x11 statistic does not resolve
it; a proper corneal-reflection detector is later work.

The gate in `faceauth-engine/src/liveness.rs` is deny-only and uses the first two
cues, with reflectance normalised by face size (flash goes as 1/d^2 and face width
as 1/d, so reflectance x (87 / face_px)^2 is a distance-free albedo estimate: 0.28
for the face, 1.66 for the print). Thresholds are set from these two runs with
margin and will be re-measured with more subjects, prints and distances; they are
published, not hidden. Data: `faceauth-engine/proof/flash-*.csv`, crops in
`flash-*-lit-unlit-diff-2026-09-18.png`.

## The whole stack, first end-to-end run (2026-09-19 00:51)

`faceauthd` running with a test config (models and store under `~/Work/fa-build`,
socket in a scratch directory), asked over the socket by `faceauth auth`, which
is the same request the PAM module sends. Each attempt: open the IR camera, LEDs
on, find the face and settle exposure on it (1.2 s), freeze exposure, switch the
strobe to alternate, then for every lit frame run the flash-response gate on its
lit/unlit pair and score the face against the templates until two frames pass
the threshold.

```
{"result":"match","score":0.9545612,"frames":2,"elapsed_ms":1689}
{"result":"match","score":0.9487176,"frames":2,"elapsed_ms":1672}
{"result":"match","score":0.94712895,"frames":2,"elapsed_ms":1694}
```

Three genuine attempts, three matches at 0.95, 1.7 s each from request to
verdict, every scored frame having passed the liveness gate. Earlier in the
same session, with the sitter looking down at a phone in profile and well back:
`no_match` at 0.13 to 0.50 over 33 frames in 6 s, which is the correct answer.
Asking about another user from an unprivileged connection is refused by the
peer-credential check before any camera work.

Packaging: `packaging/faceauth.service` (plain `Type=simple` at boot, hardened,
device access limited to video and media nodes), `packaging/config.toml`, and
`packaging/pam-example.txt` (the lock-screen stack and the opt-in sudo/polkit
lines, always `sufficient`, never `required`).

## sudo by face on the reference machine (2026-09-19 01:17)

Installed to the system paths (`/usr/bin/faceauthd`, `/usr/bin/faceauth`,
`/usr/lib/security/pam_faceauth.so`, `/usr/share/faceauth/models`,
`/etc/faceauth/config.toml`, `/var/lib/faceauth/<user>.json` root 0600,
`/etc/systemd/system/faceauth.service`), service enabled and running under the
hardened unit (707 MB resident: the recognition model). One line at the top of
`/etc/pam.d/sudo`, backed up first to `/var/backups/faceauth/sudo.pre-face`:

```
auth      sufficient pam_faceauth.so socket=/run/faceauth/sock timeout=8
```

`sudo -k; sudo true` in a terminal: no password prompt, command runs; the
daemon logged the request from sudo's process (uid 0) and a match at 0.946 in
1.7 s. Note for testers: `sudo -n` never runs PAM when policy requires
authentication, so it cannot exercise the module; use a terminal.

Fail-safe check: with the service stopped, the same `sudo true` prompts for the
password as before (pam_faceauth returns PAM_IGNORE when it cannot connect).

## Lock screen by face (2026-09-19 01:33)

`/etc/pam.d/omarchy-lock-face` (pam_faceauth `sufficient`, closed by pam_deny)
plus a 75-line change to the Omarchy shell's lock plugin
(`../omarchy/0001-lock-face-authentication-as-a-third-PAM-stack.patch`, on a branch of
the upstream checkout at 8675600): a third PamContext beside password and
fingerprint, detected by the presence of the PAM file, started when the session
lock is secure and on wake, stopped on blank, retried every 1.5 s. The contract is
PR 7935's, so either backend fits it. The existing lock-screen shell tests pass.

Locked through the shell's IPC, unlocked by face with no keyboard input:

```
lock-requested 01:33:07.984  ->  secure 01:33:08.535
daemon: attempt for mellis (uid 1000)  01:33:08.544
daemon: Match { score: 0.855, frames: 2, elapsed_ms: 1805 }
unlocked 01:33:10.353            (1.8 s after the lock became secure)
```

Negative test, same session: locked with the face covered for about 25 s, then
uncovered. Three attempts ran to their 6 s timeout as `no_match` (best scores
0.19, 0.10, 0.16 on 7, 1 and 8 partially visible faces), then the fourth matched
at 0.875 on two frames in 1.8 s; unlocked 33 s after locking, with no keyboard
input at any point. A tunable to revisit for the presence phase: an attempt that
has scored several frames well below the threshold could end early instead of
spending the full timeout, so the retry loop notices a returning face sooner.

The desktop ran the checkout's shell for this test (launched with `OMARCHY_PATH`
pointed at the checkout); `omarchy dev link` plus a reboot is the sanctioned way.

## Elevation as a deliberate act: the prompt (2026-09-19 01:42)

The owner's rule: the lock screen may open because he is looking at it, but
sudo and polkit must not elevate just because he is sitting there. So
`pam_faceauth` gained a `prompt` option, used on the sudo and polkit lines and
not on the lock-screen one. With it the module asks through the PAM
conversation:

```
Press Enter to authenticate by face, or type your password:
```

- Enter on the empty line is the act: the scan runs. Measured on a
  pseudo-terminal: prompt shown, Enter at 2.0 s, daemon match at 0.837, sudo
  exit 0 at 3.9 s.
- A typed password is handed to the module behind us as `PAM_AUTHTOK` (Arch's
  `pam_unix ... try_first_pass`) and no scan runs. Measured: a wrong password
  drew "Sorry, try again." and a re-prompt, with zero requests reaching the
  daemon.
- A caller with no conversation gets no scan (`PAM_IGNORE`), so nothing
  non-interactive elevates on presence.

The response buffer is wiped before it is freed, since it may hold a password.

## Measured, one surface at a time (2026-09-19 02:12 to 02:23)

With the presence watch off and nothing else touching the camera:

| Test | Result |
| --- | --- |
| sudo, Enter at the prompt | prompt shown, match 0.868 in 1.85 s, sudo exit 0 at 1.9 s after Enter |
| polkit (`pkexec true`), Enter in the dialog | match 0.868 in 1.85 s, command ran 14 ms later |
| lock screen, face unblocked | secure to unlocked 1.8 s; settle 1.25 s at exposure 360, 2 lit pairs, 2 scored, 2 matched |
| lock screen, face fully blocked | no face in 105 frames, attempt ends at 3.5 s; unblocked: match in 1.9 s |
| lock screen, face partially blocked (earlier run) | 33 frames scored, best 0.797, one frame above 0.70 |
| lock screen, blocked past the panel blank, then return | probe wakes the panel 3 s after the return, unlock 1.8 s after that |

Three things came out of the measurements and are now in the code:

- **Attempt timeout 3.5 s** (was 6). The shell's PAM helper discards a reply that
  arrives after about five seconds: a match reported at 5.94 s was dropped and the
  next attempt did the unlock. Long attempts are pointless under a retry loop anyway.
- **The probe.** The lock plugin stops scanning when the panel blanks (5 s), so a
  returning user waited for a key press. Now, while blank, the plugin asks the
  daemon every 3 s for one half-second, detector-only look (`{"probe":true}` on the
  socket, `faceauth probe` on the CLI); a face wakes the panel and the wake starts
  the scan. Camera duty while away: about 15 percent, no identity work.
- **Threshold margin.** A partially blocked face reached 0.797 on one frame, above
  the 0.70 line; the two-matching-frames rule held it. That margin is thinner than
  the print test suggested. Keep `required_matches = 2`, and expect the threshold
  to rise once more subjects are measured.

Also: `pam_faceauth` now writes one line per decision to the auth log (never the
password), and the attempt logs a detail line: settle exposure, frame, lit-pair,
face and scored counts, and the per-frame score trail.

## Auto-lock, measured (2026-09-19 02:56)

The presence watch is on: one half-second look every 2 s (detector each tick,
identity every third), away after 10 s unseen. Its lock helper runs the lock
command inside the user's own systemd manager (`systemd-run --machine=user@.host
--user -E OMARCHY_PATH=...`): the hardened unit has no CAP_SETUID and `runuser`
opens a PAM session whose modules fail under the sandbox, so the daemon never
switches uid itself. Two guards from the earlier runs: after locking, the watch
stops looking until an attempt matches (the lock screen's own probe owns the
camera while the panel is blank), and it takes two consecutive failed identity
checks before the user stops counting as present.

```
02:56:08.67  presence: Unknown -> Present
02:56:34.18  presence: Present -> Away (unseen 10s); locking the session
02:56:34.37  shell: lock-requested        02:56:34.93 secure=true
02:56:37.95  attempt: Match 0.807 (3.0 s); presence: session unlocked by face, watch resumes
```

Walk away, locked at ten seconds from inside the daemon; sit back down, open
without touching anything. The first scan after the lock took 3.0 s instead of
1.8 because it raced the watch's final tick for the camera; the watch is paused
from then until the match.

## Lock-screen UI, Omarchy commands, doctor (2026-09-19 03:30)

- **Lock screen**: a face icon inside the field's left edge (pulses while a scan
  runs, dims while the panel is blank and only the probe watches), mirroring the
  fingerprint icon on the right; under the field, the active player's track with
  previous / play-pause / next, usable without unlocking. Proof:
  `../omarchy/lock-screen-face-and-media-2026-09-19.png`.
- **Enrolment through the daemon** (`{"enroll": label}` on the socket): the CLI
  never touches the camera in production; the direct path stays for development
  (`--store`). Also `ping` and `delete_templates` requests, all under the same
  peer-credential rule.
- **`faceauth models fetch`** downloads the manifest's weights with `curl` and
  verifies size and SHA-256 before installing; **`faceauth doctor`** reports
  camera, illuminator, models (checksummed), daemon, templates, each PAM stack
  (and whether the lock stack is closed by pam_deny and whether the elevation
  lines carry the prompt), faillock, TPM and the module, with stable ids and
  `--json`. Fail exits 1; Unknown is not Fail.
- **Omarchy side** (`../omarchy/faceauth-omarchy-series.patch`, four commits on
  the checkout): `omarchy-capture-ir-camera-list` (MIPI sensors by their Y10 pad
  format through the media controller, UVC by greyscale-only format lists, a
  configured override first), `omarchy-hw-ir-camera`, `omarchy-setup-security-face`
  (install, fetch models, enable the service, enrol, verify, and only then wire
  PAM with backups outside `/etc/pam.d`), `omarchy-remove-security-face`
  (restore originals, delete templates unless `--keep-templates`, abort on unknown
  flags, PAM first whatever else is chosen), and the two menu entries. Omarchy's
  CLI test suite passes with them.
- **Packaging**: `../packaging/omarchy-faceauth/PKGBUILD` and `.install` for
  omarchy-pkgs. Installing never touches PAM; `pre_remove` strips any remaining
  reference so a stack never points at a missing module.

`faceauth doctor` on the reference machine:

```
PASS    camera.ir            ov7251 3-0060 on /dev/video2 (640x480)
PASS    camera.illuminator   strobe control present
PASS    camera.rgb           ov5693 2-0036
PASS    models.file          face_detection_yunet_2023mar.onnx: verified, MIT
PASS    models.file          glintr100.onnx: verified, Apache-2.0
PASS    daemon.running       faceauthd 0.1.0 answering on /run/faceauth/sock
PASS    templates.user       10 template(s) for mellis (glintr100.onnx)
WARN    templates.at_rest    templates are plaintext at rest (root 0600); TPM sealing not implemented   (as of this section; sealed since 2026-09-21, see below)
PASS    pam.sudo             wired, prompt (Enter to scan)
PASS    pam.polkit           wired, prompt (Enter to scan)
PASS    pam.lock             wired, closed by pam_deny
WARN    pam.faillock         a face match bypasses pam_faillock and never resets its counter
WARN    tpm.present          no TPM device; templates cannot be sealed
PASS    pam.module           /usr/lib/security/pam_faceauth.so
```

## Security review and what changed (2026-09-19 03:45)

An adversarial review (Opus, read-only, with live probes against the socket)
found the core property intact: no path returns PAM_SUCCESS without a genuine
match from the daemon. It found four high and four medium findings. Fixed in
this commit:

- **Unbounded pre-authorisation read** (any uid could grow a root process until
  the OOM killer fired): requests are read through a 4 KiB cap and must end in a
  newline; error replies never echo request bytes; at most 8 connections at
  once; `MemoryMax=1536M`, `TasksMax=64` in the unit.
- **Enrolment and deletion were unauthenticated** (anything running as the user,
  including over ssh to a locked machine, could enrol a new face): the daemon
  now takes both only from root; `omarchy-setup-security-face` runs them under
  sudo, and refuses to run as root itself so the templates belong to the user.
- **Camera-mutex starvation**: a request waits at most 1.5 s for the camera and
  then answers `busy` instead of queueing; enrolment is clamped to 20 s.
- **The verdict was a substring match** on a reply that could contain reflected
  bytes: the module now requires the reply to begin with the match object.
- **No liveness gate on cameras without the strobe control** looked identical to
  a gated match: `liveness_required = true` by default refuses to authenticate
  there; setting it false is an explicit acceptance that a print can pass, and
  `doctor` reports it.
- **Auto-lock**: the helper calls the lock command by absolute path with a 15 s
  bound, the daemon retries the lock every tick while away until it succeeds, and
  an empty user argument means the presence user.
- **Cooldown**: five failed attempts for a user within a minute hold that user
  for 30 s, so a print at the lock screen does not get unlimited tries.
- Typed passwords are zeroed in every copy; auth-log lines strip control
  characters; the presence state file is root-only; `FACEAUTH_DUMP` exists only
  in debug builds; the lock plugin probes by absolute path; a polkit override that
  setup created is deleted on removal; `Deleted` is its own outcome.
- **Unit**: runs with an empty capability set (verified: CapEff 0), no network,
  `SystemCallFilter=@system-service`, `ProtectHome=yes`, `UMask=0077`, and the
  W^X concession for ONNX Runtime named in a comment. The session-lock helper was
  re-verified under that exact sandbox.

Accepted for now, and written into the threat model rather than hidden:

- **The Enter prompt is not consent against hostile code running as the user.**
  A malicious process can drive sudo on a pty or answer the polkit agent's
  conversation with an empty line and scan while the owner sits there. Against
  that attacker it lowers the bar versus a password. The remedy is a
  confirmation the daemon verifies itself (a gesture challenge such as a nod or
  double blink) rather than one the calling application relays; that is a design
  decision for the owner.
- **No impostor distribution yet.** All evidence is one subject and one print.
  Before this ships as a sudo factor it needs other people's faces measured.
- Templates outlive an account of the same name (no uid in the file); TPM
  sealing waits on a machine that has one. (Both fixed since: the file
  carries the uid, and templates are sealed on a machine with a TPM; see
  2026-09-21, night.)

Lesson from the verification itself: never give an ad-hoc `systemd-run` test
`RuntimeDirectory=faceauth`; systemd removes that directory when the transient
unit exits and takes the live daemon's socket with it.

## Consent for elevation (2026-09-19 04:30)

The owner's rule after the review: nothing elevates silently, and the yes must
be something no program can forge. Built:

- **One window per elevation, opened by the daemon.** A `consent` request
  (the PAM option `consent`, for the sudo and polkit lines) makes the daemon
  summon `omarchy.faceauth`, a shell overlay it drives through the user's own
  systemd manager: "Root access requested", the command, the requester and its
  parent chain from `/proc` (for polkit: the newest `pkexec`/`run0` with the
  user's real uid), then "Look at the camera", then "Recognised. Nod 2 times to
  allow this", then allowed or refused. Buttons: deny and kill the requester,
  block it for ten minutes (later requests from the same executable are killed
  without a window), dismiss. No graphical session, no window, no elevation: the
  request is refused and PAM falls through to the password.
- **The yes is a nod.** After the match, the daemon watches its own camera for
  the head pitching down and back twice within five seconds (`consent.rs`,
  pitch from the five landmarks). The window cannot approve; the buttons only
  refuse. Code running as the user can press Enter, register a polkit agent or
  type into the real dialog; it cannot nod.
- **Every elevation by face announces itself** with a desktop notification
  naming the command and the caller.
- The window never takes exclusive keyboard focus and closes itself after 30 s
  (a version that did hold focus once left the keyboard dead when a hide call
  was lost).

Live on the reference machine (2026-09-19 morning): the sudo and polkit lines
carry `consent` with `timeout=20`. Measured through the real stacks: `sudo true`
allowed in 7.7 s (match 0.886, two nods); `pkexec true` allowed in 9.4 s. A
first version reopened the camera between the match and the nod phase, and the
two to three second restart ate the start of the gesture window; the nod phase
now runs on the still-open camera with steady light and an eight-second window.

Calibrated on the owner (2026-09-19, after the dev-link reboot): a nod moves
the pitch measure by about 0.12 (0.53 to 0.41 and back) on this sensor, and the
sign depends on the mounting, so any excursion beyond 0.06 that returns within
0.03 of the resting pose counts as one nod. First run with the corrected
detector: match 0.887, two nods, allowed, 5.1 s from request to yes, notification
delivered. A run with no nod: refused at 8.3 s. The requester chain shown for a
CLI request was `bash <- claude <- foot <- Hyprland`.

Dev-shell lesson: Hyprland spawns keybinds with the packaged `OMARCHY_PATH`, so
a checkout shell launched by hand makes `omarchy-shell` from a keybind say "not
running" and Super+Space finds nothing. `omarchy dev link` plus a reboot is the
only way every layer agrees; running the checkout shell live is for short tests.

## Lit lock, masked notifications, greeter, uid binding, package build (2026-09-19 05:30)

- **A presence lock keeps the panel lit for ten minutes** (`lock lockPresence`
  IPC, used by the lock helper) instead of five seconds, so the waiting screen
  is visible from across the desk. While lit with nobody there, three failed
  scans switch the loop to the cheap probe, so the camera and LEDs are not
  driven for ten minutes; a face brings the scan back.
- **Notifications that arrive while locked** show on the lock screen by app
  name and count only. Screenshot: `omarchy-action · 1 notification` above the
  field, no body.
- **Greeter**: `omarchy setup security face --greeter` wires `/etc/pam.d/sddm`
  (face only, no nod: logging in is not elevation); off by default since most
  installs log in automatically; `doctor` reports it as info.
- **Templates are bound to the uid** they were enrolled under; a recreated
  account with the same name reads as not enrolled.
- **faillock**: decided and documented: a face match does not reset the
  password's failure counter; `doctor` warns.
- **Package**: `makepkg` builds `omarchy-faceauth 0.1.0-1` (5.5 MiB) from a
  tarball of `src/` with the tests in `check()`; contents listed in
  `design/pr-omarchy-pkgs.md`. PR drafts for both repositories in `design/`.
- Manual page for Omarchy: `manual/52-face-authentication.md` in the series.

## Decisions carried into the code

- **The daemon owns the cameras.** No v4l2loopback node in the authentication path:
  frames never leave the process that scores them, which removes the frame-injection
  surface, the `exclusive_caps` question and the `fuser` problem in one move. A
  loopback republish can come later as an optional feature for other consumers.
- **Graph by name, sensors by what they produce.** Device numbers move across boots
  and module reloads; entity names and media-bus codes do not. Front/back comes from
  the orientation control, which the IPU3 sensor drivers fill from ACPI.
- **Calibration is pure.** `calib` computes the next setting from a frame; the
  device layer applies it. Same numbers as the C viewer, unit-tested.
- **Hand-written ABI.** The few V4L2, media and subdev structs are spelled out and
  size/offset-checked against the kernel headers, so the crate needs no libclang or
  bindgen at build time.

## Build and run

```
cd src && cargo build
./target/debug/faceauth cam probe
./target/debug/faceauth cam test --seconds 8 --led on --snapshot /tmp/camtest
```

Needs read/write access to `/dev/media*`, `/dev/video*` and `/dev/v4l-subdev*`
(the `video` group on Omarchy). The kernel patches in `../kernel/` must be loaded
for concurrent IR+RGB and for the illuminator control.

## 2026-09-19, later: password in the window, one request at a time, nod detector rebuilt

- **The consent window takes the password.** A field under the message sends
  it to the daemon over the stdin of `faceauth consent-answer` (never argv);
  the daemon checks it against the `system-auth` PAM stack (`pamcheck.rs`,
  libpam linked directly, the copy wiped afterwards) and a good one approves
  exactly like a nod. Dismiss, kill, block and Escape send a dismissal, so the
  request ends at once instead of at a timeout. Answers are accepted only from
  the user's own uid, only while that user's request is pending, and go through
  a slot outside the camera lock so they never wait for it.
- **The window stays until acknowledged.** The daemon watches for the whole
  budget the PAM module gives it (the module sends its `timeout` in the request,
  minus three seconds so the module always sees the verdict): a scan until the
  face matches, then the nod watch for all the time left; a scan that finds no
  one starts over. While the head is still it looks at every third frame and
  drains the rest; the moment the pitch leaves the baseline it looks at every
  frame. Nothing ends the request but a nod, a good password, a dismissal, a
  kill or the module's own limit. Module clamp is now 1..600 s; use
  `timeout=120 consent` or more in the PAM lines.
- **Stacked requests cannot share a verdict.** Measured: two `auth --consent`
  fired at once; the second got `busy` after 1.5 s (module ignores it, so that
  caller falls to its own password) while the first ran its full window. The
  authenticator mutex serialises everything, each PAM transaction has its own
  connection and reply, and there is no recent-match grace: `last_match` is only
  recorded. `sudo`'s own timestamp cache is the one thing that skips PAM; set
  `Defaults timestamp_timeout=0` in sudoers to route every `sudo` through the
  window.
- **The nod detector misfired once** (an install approved with no nod: the
  landmark pitch flickered between two quantised values 0.03 apart and the old
  threshold logic counted two excursions). Rebuilt as a state machine with unit
  tests against that exact trace: three-frame median, baseline and jitter
  measured over the first eight frames, threshold the larger of 0.045 and three
  times the jitter, three frames out and two back, a nod lasting 0.12 to 0.8 s,
  0.25 s between nods, and a long hold away from the baseline (a look down at
  the keyboard) re-arms only after the head comes back. Also measured: a real
  nod then a deliberate look-down counts one.
- **The polkit agent dialog stays hidden** while `pam_faceauth ... consent` is
  in `/etc/pam.d/polkit-1` and PAM has not asked for a password. It held
  exclusive keyboard focus over the consent window, which is why the field and
  buttons were dead. When PAM does ask for a password (module ignored), the
  agent dialog appears as before.

Retuned the same night from a recorded trace of two natural nods (swing about
0.035 either side of the baseline, missed at a 0.045 threshold): the excursion
threshold is the larger of 0.025 and three times the measured jitter, capped at
0.06; a nod completes on a return to the baseline or a swing through to the
other side; the baseline follows slow posture drift while the head is still.
Six recorded traces are unit tests. Measured after: `sudo true` approved by
two natural nods within two seconds of the match. A presence lock that fires
first (a hat the model does not know reads as a stranger for ten seconds) takes
the camera, and the consent request then falls to the password: enrol the hat
as a look.

Second retune the same night, from two more recorded traces: nods that leave
the noise band for only two or three frames (a 0.10 s minimum duration had
rejected them, now 0.06 s timed from the first frame out) and light nods of
0.017 in a noise floor of 0.004 (never seen at a fixed 0.025 floor). The floor
is now 0.015, the noise floor is measured continuously on frames inside the
band and the threshold is four times it, capped at 0.06, so a flickering
landmark raises the bar and a steady one lowers it. Eight recorded traces are
unit tests. Measured: `sudo true` approved 4.5 s after the request, match at
1.9 s and both light nods 2.4 s later.

**Presence and consent windows.** The presence watch cannot tick while a
consent flow holds the camera, so a long window used to read as time unseen and
the next tick locked the session at once. Now the walk-away clock restarts from
the end of any consent flow and from any face match. Measured: a 22 s consent
window (nod held back on purpose), then no transition and no lock.

## 2026-09-19, later still: the request survives a walk-away lock

A consent request holds the camera, so the presence watch cannot see the user
leave. The request now watches for that itself: no face for the presence
watch's away time (during the scan or the nod watch) locks the session through
the same helper, hands the lock to the presence watch, and parks the request
without the camera. The window shows "Locked while you were away". Parked, it
wakes on a face match newer than the lock (the lock screen unlocking by face),
on a password or a dismissal from the window, or when the caller's budget is
out; on the user's return it runs another camera round ("Welcome back") and
takes the nod. Measured end to end: left the desk, locked after 14 s, unlocked
by face, request resumed, nodded, approved at 45 s with no timeout.

Budgets: the caller's limit is the only bound. The PAM module now defaults to
ten minutes for `consent` (clamp 1..600) and the CLI uses the same; a
`timeout=` in the PAM line overrides it.

Nod detector: the baseline follows posture drift whenever no nod is in
progress, a head held away for longer than a nod re-baselines there, and a
swing that does not come back settles as the new baseline after half a second.
Nine recorded traces are unit tests. Whenever nods feel finicky, pull the
`consent:` pitch trace from the journal and add it as a test.

## Checkpoint, end of 2026-09-19

**Nod detector, current design.** Median-filtered pitch against a slow
baseline (time constant 1.5 s) that absorbs leans and slumps; a nod is a pulse
that leaves the band by four times the frame-to-frame noise (floor 0.015,
cap 0.06) and comes back or swings through within 0.06 to 0.8 s; two pulses
within 2.5 s are the gesture; a hold longer than a nod is a posture change that
forgets any lone pulse and waits for the baseline to settle. A motion gate
rejects a pulse when the face box changed width by more than 6 % or shifted by
more than 10 % of its width around the pulse (a lean's wobble is the same size
as a light nod; the gate is what tells them apart). Ten recorded traces are
unit tests in `consent.rs`; raw traces with geometry go under
`faceauth-daemon/traces/`.

**Open, first thing next session.** With the gate installed the nods were not
seen (trace `2026-09-19-0244-nods-missed-with-motion-gate.txt`, format
pitch/width/cx/cy). The trace shows the detector flickering between two
face boxes, 95 px and 89 px wide with pitch 0.559 and 0.511, frame by frame:
that is landmark jitter, and the 6 % width tolerance trips on it, so every
pulse is rejected. Fix: median-filter the width and centre over three frames
like the pitch (the flicker is one frame long), and compare the filtered
trend, not the raw extremes; then re-measure with the user's ordinary light
nods. The same flicker is what the pitch median filter already removes.

**Also open.** Two Omarchy shell tests fail on this branch and are ours:
`bin-style-test` (omarchy-capture-ir-camera-list uses a raw command where a
helper exists) and `privileged-heredoc-test` (omarchy-setup-security-face line
75: the heredoc annotation says `paths=none` but `face_line` is path-shaped;
name it and say why root using it is safe). Three others fail on quattro too
(kernel migration, runtime smoke handler count, snapper's iso checkout) and
are not ours.

**Done today, all measured:** password in the window; window stays until
acknowledged; polkit agent hidden during consent; stacked requests serialised;
request survives a walk-away lock (locks, parks, resumes on the face unlock);
presence clock restarts after a consent flow; blank lock panel wakes only for
an attentive face; ten-minute default budget.

## 2026-09-21: nods count again

The motion gate compared the raw extremes of the face box across a pulse, and
the box flickers between two fits (95 and 89 px) on alternate frames and rides
14 px up and down with the nod itself, so every pulse was rejected. Now the
gate compares the three-frame median of the width and centre at the start of
the pulse with the same at its end: a nod ends where it began, a lean or a
shift does not. Tolerances unchanged (6 % width, 10 % of width sideways, 20 %
vertically). The missed-nod trace of 2026-09-19 is a test and counts; the
synthetic lean-in test grows the face a quarter over the second in which its
pitch wobbles, and still counts zero.

Measured: sudo approved by nod in 4.2 s (match 1.5 s); a second run in 8.4 s,
where the first nod swung the pitch only 0.01 (under the 0.015 floor) though
the box centre rode 14 px, and the second swung 0.04. Possible follow-up: use
the box's vertical ride, normalised by width, as a second nod signal for very
light nods.

Later the same morning a request was approved with no nod: the user slid into
the chair and turned to the screen (box 100 px sideways, a third larger, over
1.4 s), then glanced twice between the window and the terminal, at 0.06 to
0.07 swing with the box still. By pitch alone that is a nod pair. Now the
first pulse of a pair only counts if the box has been still for the second
before it (same median test), and a face seen for less than that second has
not been still. That trace is a test and counts zero; the missed-nod trace
still counts.

## 2026-09-21: power

The presence watch idled at 15 to 17 % of one core on mains (2 s tick). Where
it went, measured per thread and with the CLI on saved frames: YuNet at
640×640 costs only 14 ms (0.03 core-s); the embedder (glintr100) costs about
0.35 core-s per run, and it ran every tick because the watch flapped Present
to Stranger: the tick's 450 ms of frames is not enough for exposure to settle
from the default (an attempt settles at 1.2 s), so its embeddings were poor
and the identity check failed, and while unconfirmed the watch identified on
every tick. Fixes: ticks start from the exposure the last attempt or tick
settled on with a face in view (`IrCapture::open_at`, `last_exposure` on the
authenticator); while unconfirmed the identity check runs every other tick;
failed checks log their score; ONNX worker threads sleep instead of spinning
(one detect+embed: 0.65 core-s spinning, 0.41 not; latency 132 vs 141 ms);
and on battery (no mains supply online) the tick stretches to 5 s and the
identity check to every sixth tick (`battery_tick_seconds`,
`battery_identify_every`; zero keeps the mains cadence).

Measured after: 5.9 % of a core idle on battery (5 s tick), one identity
failure in a minute (score 0.17, a real turn-away). Whole-system draw from
the battery meter (tools/power-measure.sh, 60 s phases) was dominated by
other work on the machine and did not resolve the daemon; the one clean pair
was the 5 s versus 2 s tick, 0.6 W apart whole-system, 1.5 W package. A
clean run needs a quiet machine and longer phases. A dynamic-shape YuNet
(all Reshapes use -1, Resizes use scales; only the declared input pins 640)
runs a half-size frame in 1.8 ms versus 14, kept in mind, not needed.

## 2026-09-21, later: a consent request has no deadline

A request that sat unanswered ended at 43 s, not because of the ten-minute
budget but because the PAM lines on this machine still said `timeout=60` (the module handed the daemon 57 s) and, before
that ran out, a liveness refusal during a scan round (the user far from the
camera, not facing it, score 0.15; then `DenySurround`) was taken as the
verdict. The user's rule, restated: **the window does not time out. It sits
there and waits.**

Now: a consent line ignores `timeout=` (logged once) and the module sets no
read deadline on the socket; the request carries no budget, and the daemon
takes none as "wait" (`NO_BUDGET`, four months, so every derived duration is
representable); a liveness refusal during a consent round shows "Not
accepted. Look straight at the camera, or type your password." and the round
repeats. The CLI's `auth --consent` waits the same way.

The protocol, for anyone writing a caller: **a consent reply arrives when the
user answers the window, or never.** A caller must not set a read deadline
and must be prepared to wait; the only thing that ends an unanswered request
from the caller's side is closing the socket. The daemon checks the request
socket for a hang-up between rounds and every 300 ms while parked, and takes
the window down when the requester is gone (sudo interrupted, polkit helper
gone): `ConsentDenied { reason: "requester gone" }` in the log. sudo's own
`passwd_timeout` (default five minutes) bounds its password prompt, not a
module blocked in `pam_authenticate`; polkit's helper has no limit.

Also found: the setup script wrote `timeout=8 prompt` for sudo and polkit,
the pre-consent design, so a fresh install would have got the Enter prompt and
no window. It now writes `socket=/run/faceauth/sock consent`; the PAM example
says the same.

Two false hang-ups found on the way, both in the watcher's blocking peek:
`EINTR` (the daemon reaps the window's helper processes) and `EAGAIN` (the
request socket carries the handler's five-second read timeout, which the
cloned descriptor shares). Both now mean "still waiting". Measured: a CLI
request killed at 3 s ends with `requester gone` at 2.6 s and the window is
hidden; the install dialog sat unanswered ten minutes and still took the
password.

## 2026-09-21, evening: requests queue

A second consent request arriving while one is open used to get "busy" and
fall to the password. Now it waits its turn on a lock held for the whole
first request (parked spells included), then opens its own window;
`consent: request from pid N waits its turn behind another` in the log, and
a requester that hangs up while queued ends there. The polkit requester is
named as the oldest pkexec (or run0) of the user's that no window has named
yet, since polkit serves in order; each is named once (`SERVED`).

Known upstream limit: two polkit requests within about half a second of each
other race inside Quickshell's agent (0.3.1), which makes a flow of both at
once and loses the second's completion; that pkexec hangs until the shell
restarts. Requests a few seconds apart are served in order.

**Waiting is not scanning.** During a seven-minute unanswered wait the camera
streamed and strobed without pause: a face it could not accept was always in
view (the user at the other desk, seen at an angle), so every 20 s scan round
ended in no match or a liveness refusal and the next began at once. Now a
round that finds nobody to accept is followed by the presence watch's short
look every two seconds (camera open 450 ms, no identity), and the next scan
round starts only when a face is turned to the camera; nobody at all for the
presence away time ends the round as the user leaving. `consent: a face
turned to the camera after N looks; scanning` in the log.

**Shell crash, agent lost.** Quickshell 0.3.1 crashed twice today (SIGSEGV,
identical stacks): polkitd cancels an authentication, libpolkit-agent fires
the request's cancellable, and Quickshell's cancel callback uses a request
it has freed. Quickshell's frames are stripped on Arch, so that much is the
shape of the stack, not a symbol. The first time the cancel was ours (the
daemon's request killed a pkexec left hanging by the concurrent-requests
race); the second had no polkit activity for 15 s before it. After the crash
handler relaunches the shell, the relaunch asks polkitd for the agent slot
while the crashed instance is still being dumped and still holds it, gets
"an authentication agent already exists", and never asks again: every pkexec
after that failed for want of an agent, which is what the invisible password
prompt and the queued request that never surfaced were. Fixed on the Omarchy
side: the agent lives in a Loader and is made afresh every three seconds
while unregistered (measured with a stub holding the slot: registered within
eight seconds of its release). The crash and the single registration attempt
are upstream Quickshell matters.

**A request that arrives while the session is locked.** The install request
of 12:51 arrived four minutes into a walk-away lock; the daemon summoned its
window over the lock screen and scanned, contending with the lock screen's
own face attempts, and when the user came back and dismissed it the verdict
read "No answer in time. Refused." and the window was put back up with that
on it: the "old dialog" seen on return. Now the daemon asks the compositor
(`omarchy-hyprland-session-locked`, run in the user's manager like the
summon) whether the session is locked when a request arrives; if so the
request parks at once, unseen and without the camera, and adopts the lock so
the presence watch does not lock again. While parked, any unlock resumes it:
a face match newer than the lock, or the compositor reporting the session
unlocked (polled every two seconds, so a password unlock works too). A
dismissal closes the window and stays closed; the verdict wording no longer
claims a timeout.

First attempt at this showed the plain scanning window over the lock screen
and then ended the request three seconds later: the window was summoned by
the request's setup before the lock check, and hiding it made the window
answer with a dismissal (its close path does that for any pending request).
Now a request that arrives locked never summons the window; it is shown
first on resume. Measured: locked at 13:49:59, request parked, face unlock
at 13:50:07, "Welcome back" at 13:50:08, approved by nod at 13:50:12.

## 2026-09-21, night: sealed templates, local callers only, camera binding, no scores on the wire

Four changes, prompted by reading the other face PR against Omarchy (#11612,
built on Facelock) and the Facelock source behind it. The comparison is in the
project notes; what follows is what changed here and how each was measured.

**Templates are sealed to the TPM.** The Surface Book 2's TPM 2.0 was
firmware-disabled for a Windows dual boot; enabling it (Windows here has no
BitLocker, so nothing depended on it) gave `/dev/tpmrm0`. The store now seals
each user's template JSON through `systemd-creds encrypt --with-key=tpm2
--tpm2-pcrs=` into `<user>.cred`, bound to the credential name
`faceauth-<user>`, and reads it back with `systemd-creds decrypt`. No new
crates, no crypto of our own: systemd is already a dependency and its
credential format is AES-256-GCM under a key only this TPM unwraps. No PCR
policy in this first cut, so a kernel or firmware update does not strand the
templates; binding to PCR 7 can come once Secure Boot is on.

What that buys, precisely, because the first draft of this section claimed
more than the first cut delivered: a copy of the file is useless anywhere but
this machine (a backup, an imaged partition, a support tarball, a synced
folder), and on this machine only root can open it. The first cut sealed
system-scoped credentials, and PID 1 serves those to any local caller over
`/run/systemd/io.systemd.Credentials` (mode 0666): the review unsealed a
blob as the ordinary user, and minted one. So the credential is now scoped
to root (`--uid=0`), which systemd allows only with the host secret in the
mix (`--with-key=host+tpm2`; `/var/lib/systemd/credential.secret`, root-only,
0400). Measured: root and the daemon's sandbox open the blob; the user gets
`InteractiveAuthenticationRequired` trying to open or to mint one. The trade
is that one root-only secret file on disk, which is worth it: a program that
can read it is already root. Older system-scoped blobs are still read and
re-sealed root-only on first load. A live USB booted on this hardware, once
the LUKS volume is unlocked, still unseals (nothing binds to boot state, and
the host secret is on the volume). The thief with the powered-off laptop
gets nothing, because the root volume needs its passphrase; that holds only
while it does (enrolling the LUKS key in the TPM for convenience would end
it).

There is no recovery key anywhere on disk, on purpose: Facelock's TPM mode
keeps a plaintext copy of its key beside the sealed one (and its reseal
command recommends it), which reduces the TPM to file permissions. Here a
template that cannot be unsealed is re-enrolled: enrolment sets an unreadable
blob aside as `<user>.cred.unreadable-<time>` and starts fresh, so a cleared
TPM, a firmware reset, or Windows clearing the security processor means
re-enrolment and nothing else; the password path is unaffected. Sealing is
sticky: a daemon that finds a sealed file but failed its TPM probe at start
(which happened once tonight, before the unit allowed `/dev/tpmrm0`) refuses
to write plaintext over it, re-trying the TPM once first. A plaintext
`<user>.json` met by a store that can seal is sealed on first load and the
plaintext unlinked from the live tree. Unlinked, not erased: snapper took a
snapshot of `/` this morning, `/var/lib` is inside it, and the pre-migration
plaintext sits in `/.snapshots/3` until that snapshot is deleted; on a
copy-on-write filesystem free-block residue is a second copy no overwrite
reliably removes. A machine that ever held plaintext templates should be
treated as still holding them until its old snapshots are gone. Unsealing
costs about a second of TPM time, so the daemon caches templates against the
file they came from; the cache is memory, and the unit now sets `LimitCORE=0`
so a crash does not write it to disk. Swap (a 15.5 GiB swapfile behind zram
here) and hibernation can still put daemon memory on the encrypted volume;
accepted in writing rather than closed. Templates per user are capped at 40,
because a sealed credential tops out at 1 MiB (about 90 templates) and the
plaintext path should not behave differently. The daemon's sandbox needed
one line: `DeviceAllow=/dev/tpmrm0 rw`. A stale copy of the unit in
`/etc/systemd/system` from the first dev install shadowed the packaged one
for a while (moved aside to `/var/backups/faceauth`).

Measured: `mellis.json` (221 KB) became `mellis.cred` (299 KB, 0600) on the
first ping after the restart; a fresh daemon's first attempt paid 1.8 s for
the unseal, the next 0.57 s; a copy of the blob renamed to another user does
not open. `doctor` reports `templates.at_rest` from the daemon's own answer.

**Face authentication is local only, as far as it can be shown.** The first
cut of this check asked two negative questions (an `sshd` in the ancestry? a
logind session marked remote?) and the review of it walked past both with one
command: `systemd-run --user --pipe sudo ...` from an SSH shell is forked by
the user's own manager, so no sshd is above it and it sits in `app.slice`
with no session scope. Rewritten as a positive, fail-closed check, above
every request type (probes, pings and window answers included), from
`/proc` and logind rather than from anything the caller controls: an sshd
ancestor is remote; root in `system.slice` is local; a process in a logind
session scope is local only if logind puts that session on a seat and not
remote; a process inside the target user's own manager (every desktop app,
and the lock screen's PAM helper, which has no session scope of its own) is
local only if that user has a live session on a seat that logind does not
mark remote; anything else, and any read error, timeout or vanished caller
(the peer pidfd is polled after the reads), is remote. The concession is
written in the code comment rather than left to be found: a same-uid process
inside the user manager counts as local whenever the user has a local
session, and provenance cannot separate a same-uid remote shell that borrowed
the manager's fork from a local one. What stands between that and root is
the consent window, which names the requester, and the nod, which a remote
shell cannot produce. The trap #11612 fell into is the same one: Facelock
refuses any caller without a resolvable logind session, Quickshell's helper
has none, and the PR's fix was to turn the check off globally.

Window answers now carry a per-request token. The daemon puts it in the
payload it summons the window with, the window hands it back with every
dismissal or password, and an answer without it is refused: a process that
can reach the socket but did not see the window cannot cancel or answer a
request (the review cancelled a live parked request with one unprivileged
socket write before this).

Measured, sshd started for the test and stopped after: `ssh localhost sudo
true` with a pty put `refused: started under sshd-session (pid 136184)` in
the journal and a password prompt on the SSH side, no window on the desktop.
(`sudo -n` proves nothing: sudo refuses non-interactive password auth before
it calls PAM at all.) The positive check's other branches are unit-tested
against recorded cgroup strings and the running test process.

**Templates are bound to the camera that enrolled them.** Each template
records `IrCapture::identity` (`ipu3:<sensor entity>` on IPU3 machines,
`uvc:<driver>:<card>:<bus>` elsewhere) and only matches on that camera, in
attempts and in the presence watch; an attempt on a camera with nothing
usable is an error, logged with both names, so a camera swapped in for the
enrolled one has nothing to match against. Templates from before this carry
no device and match anywhere, which on this machine was all twenty of them,
so the binding was inert until re-enrolment; and since enrolment appends, one
unbound template would keep the door open for every camera. Enrolment
through the daemon now binds any unbound templates to the camera it just
used (they were enrolled on this machine's one IR camera), and `doctor` has a
`templates.camera` row that says how many are unbound. Adopted from Facelock,
which has it on by default.

**No scores for callers, and none in the journal.** Match and no-match
replies carry the best cosine score only to root; any other peer (the lock
screen's helper, the CLI as a user) gets the verdict, frames and time. A score
visible to an unprivileged process is a hill-climbing oracle for tuning a
spoof. The first cut kept the scores in the daemon's log, which on Omarchy is
readable by group `wheel`, so the owner's account read every per-frame trail
with threshold markers and the presence watch's identity score every few
seconds, with exposure and gain: strictly more than the wire ever gave. Those
lines are debug now; info carries counts. Measured: `faceauth auth` as the
user answers `{"result":"match","frames":2,"elapsed_ms":1771}`.

For the record, two things the comparison first flagged as gaps and were not:
the daemon already rate-limits (five failures in a minute, counted only when a
face was seen, then a thirty-second hold), and the IR camera probe already
uses the greyscale-only-formats rule Facelock arrived at after two webcams
with "ir" in their names matched a name heuristic. And one honest limit,
stated because a reviewer will find it: the flash-response liveness gate has
been measured against a phone screen and a paper print, not against a video
rendered on a display an IR camera can see. It is not claimed to stop that.

## 2026-09-22: a head shake refuses, and the nod is re-tuned on a recorded battery

**The shake.** A refusal by gesture, the pair to the nod: two head shakes
(left-right-left-right, or starting on the other side) at the consent
window end the request as refused and take the window down, the same as the
Dismiss button. Both gestures are read by one detector (`Oscillation` in
`consent.rs`): four legs of alternating direction, each a clear excursion,
done together within a short span, from a head that was still just before
and does not move its face elsewhere meanwhile. A rest is allowed only at
the midpoint, between the two motions; a rest after the first or third leg
is what a glance does (it turns, holds, comes back) and ends the sequence.
A shake must swing to both sides of centre, since a glance goes one way
and returns, and has a size ceiling, since a turn to another monitor
measures far past any shake. A shake is the safe direction (a false one
costs a password prompt), so its floor sits lower than the nod's.

**What went wrong first, in order.** The first detector build approved
root twice with the user sitting still: the face-detector fit flickered
between two solutions, which steps the mouth-based pitch measure by 0.02 to
0.05 for a frame (or holds it for four), and four such steps within the
span read as legs. A filter on those jumps fixed the recorded cases and
then, in the calibration battery, turned out to throw away the middle of
real shakes (the box narrows as the head turns, which looked like the same
jump). A nod was also mis-read from the perspective wobble of a shake
(fixed: a nod requires yaw to stay quiet over its span), and a "no rest
mid-gesture" rule refused the beat between the user's two nods (fixed: the
midpoint rest).

**The battery.** Twenty labelled consent windows through the CLI (which
grants nothing), each about 14 s: still (2), nod (3), slow nod, light nod,
shake (3), slow shake, glance (2), look down (2), read, lean in, talk, a
single nod, a single shake. Every frame is recorded at debug level as
`t/pitch/yaw/width/cx/cy` plus the five landmarks and the detector score,
so any pose measure can be evaluated offline from the same recording; the
recordings live in `faceauth-daemon/traces/cal/` and replay in
`cal_report` (per file, with rejection reasons under `RUST_LOG=debug`),
`cal_dump` (per frame) and `cal_sweep` (a grid over the tunables, ranked by
zero false positives then sensitivity). The first thing the battery showed
was that the mouth-based pitch is the wrong signal: on a still face it
wanders as much in a second and a half as a nod moves it, and talking moves
the mouth landmarks it depends on (talking read as four nods). The nose's
position below the eye line, in inter-eye distances, is steady to a
thousandth per frame on a still face and unmoved by talking; the nod
detector reads that now. On it, every filter variant cost real gestures
and bought no safety, so there is none: the shape rules carry it.

**Where it stands** (the battery is the regression suite,
`calibration_battery_holds`): zero false positives on every non-gesture
recording, including talking, reading, both look-downs, both glances, the
lean and the singles; three of five nod recordings and four of four shakes
count. The two missed nods are a noisy small zigzag and the light nod,
whose swing (0.02) sits under the floor (0.025); lowering the floor is
where false approvals live, so they stay missed until per-person
calibration at enrolment (two nods and two shakes recorded, thresholds
raised toward the person's own amplitude for the nod, loosened for the
shake, the shape rules fixed) can set the floor from their samples rather
than from one user's. Live on the tuned build: the install approved by nod
in 3.3 s, a labelled polkit request in 3.1 s.

**The window names the request.** polkit's PAM helper carries nothing
about the request, and on polkit 127 it is socket-activated by systemd, so
it is not even the agent's child; the daemon's process search named
requests "a polkit action" often. The agent, which hears the action id and
the message from polkitd, now tells the daemon as each request starts
(`faceauth consent-context`, queued per user in arrival order, single use;
polkit serves one request per agent at a time, in that order), and the
window shows polkit's own message: "Authentication is needed to run
`/usr/bin/true …` as the super user". Measured on the first try after the
fix landed (the first version keyed on the helper's parent pid, which is
systemd, and never matched).

**The socket is open to root and the enrolled users only.** It was 0666 with
the daemon's own uid check as the only guard; the review asked for 0660 and
a group. A group would need a re-login at setup, so the daemon sets an ACL
instead: mode 0660, plus a read-write entry for each user with templates,
applied at start and refreshed on every enrolment and deletion. Any other
account is refused by the kernel before a byte is read. One consequence a
reviewer will want stated: a caller that is uid 0 is trusted for enrolment
and deletion, and any setuid-root binary the user can run is uid 0 to the
socket. On a stock system those are sudo, pkexec and polkit's helper, each
of which authenticates first; a setuid binary that does not is a problem
for the whole machine, not this daemon.

## 2026-09-22, afternoon: gestures read from image motion

Two more false approvals on a still face ended the landmark path. The
second was on the nose-to-eye measure itself: the detector fit flipped
between two solutions 0.09 apart, each held for three or four frames, with
the face box unmoved, and no rule on that signal (a ramp through the middle,
box co-motion, a stricter arrival, regularity; all swept over the battery)
separated it from a real nod without losing most real nods. The signal
reports where a landmark was placed, not whether anything moved.

The gestures are now read from real image motion: between the frames looked
at, the face region's row and column brightness profiles are cross-correlated
(as gradients, so the illuminator's fixed falloff does not pin the shift at
zero; that was the first cut's failure, measured on a live nod at a
hundredth of a width and fixed with a synthetic-vignette test) to find how
far the pixels shifted, sub-pixel by a parabola through the peak. The shifts
accumulate into a position in face widths, vertical for the nod detector and
horizontal for the shake detector; the four-leg shape rules are unchanged.
A fit flip changes no pixels and measures zero. Talking moves the mouth
only, which a whole-region profile barely sees.

The battery, re-recorded with the new signal in every frame
(`traces/cal`, fields 17 and 18): a still face moves 0.003 of its width,
talking 0.036, reading 0.08 and looking down 0.15 (single legs with holds,
which the shape rules refuse), the user's light nod 0.106, natural nods
0.20 to 0.28, shakes 0.18 to 0.24 sideways. Live, on the untuned first cut,
every nod recording was approved (slow and light included) and every shake
refused, with nothing from the twelve non-gesture windows; offline the same,
and a sweep finds the full result at every setting of the other tunables
with the floors at 0.03 and 0.04. The floor ships at 0.04 for the nod and 0.06 for the shake, the
values the battery was recorded under: a gesture recording ends at the live
decision, so a higher floor (0.05 was tried, for margin over talking) loses
the last leg of recordings that were cut at 0.04, and cannot be judged from
them. The next battery is to be recorded with the daemon not deciding (a
high `consent_nods` in the config), so each gesture is captured to its rest
and the floors can be set with margin. Also found on the way: the adaptive
noise floor, built for the jittery landmark signal, learned from a nod's own
frames when they fell just under the threshold and raised it mid-gesture;
it now learns only from steps well below the floor, and "rest" is an
absolute stillness (0.35 of the floor per frame: a settling head wobbles 0.01, a turnaround moves 0.03 or more) rather than a fraction of
the adapted threshold.
`calibration_battery_holds` now requires five of five nods and four of four
shakes, at zero false positives, and skips any recording without the motion
fields. The earlier corpora are kept under `~/Work/fa-build/` (round 1
without landmarks, round 2 with, round 3 with the pre-gradient motion).

**Recording, and a corpus from a phone call.** Per-frame recording is now a
config knob (`gesture_trace`), written to `<store_dir>/gestures/`, root-only,
newest sixty kept, and nothing per-frame goes to the journal at any level
(the debug override that put head pose there during tuning is gone).
`gesture_record_only` recognises gestures without acting on them, so a
battery captures each gesture to its rest; the battery script sets both,
runs the twenty windows, restores the config and collects the recordings.
The first run with it was recorded while the user was on a phone call, by
accident; kept as `traces/cal-phone` on purpose, as the corpus for varying
conditions: talking through it, phone in hand, attention elsewhere, the
still windows moving 0.04 vertically and 0.30 sideways. It sets no floors
(a nod window there may not hold a deliberate nod) and its test asks only
the safety question, which holds: no non-gesture window produces a
gesture, and no gesture window reads as the other. Under that distraction
two of five nod windows and two of four shake windows still counted. The
clean battery, for the floors, is still to be recorded.

**The clean battery, and the floors with margin.** Recorded off the phone,
in record-only mode, every window its full 14 s. Three fixes came out of
it before the floors could be read: the first frames of a round, before
exposure settles, produced ±17 px sideways spikes (a correlation peak at the
search edge; a peak at the edge or a weak one now reads as no motion); the
replay fed the nod's quiet-head rule the image-motion x instead of the
landmark yaw the daemon uses, and a nod slides the box sideways as well as
down, so two nods were refused as "turned"; and the shake's both-sides rule
measured "centre" as the integrated position at the first leg's start,
which drifts between gestures, so two shakes read as one-sided (a glance is
caught by its hold and its size; the rule is off). After those: six of six
nod windows, four of four shakes, nothing from the eleven non-gesture
windows, on full-length recordings. The sweep, re-ranked to prefer the
highest floors among the fully-correct settings, puts the nod floor at
0.06 (from 0.04; talking moves 0.036, the light nod 0.17) and the shake at
0.06. Installed and approved by nod at the new floor.

## 2026-09-22, evening: calibration at enrolment

`faceauth calibrate` (root; the Omarchy setup runs it right after the
verification scan) raises the window four times, asks for two nods and two
head shakes, and for each measures how far the face moved (the largest
range of the image-motion signal over any 1.5 s, the same measure the
batteries are surveyed with) with the daemon deciding nothing. Each round's
recording is saved to the root-only gestures directory as `cal-nod` or
`cal-shake`. The amplitudes are stored with the person's templates
(`GestureCal`), and their floors derive from the median: the nod's floor is
half the typical nod, never below the default and capped at 0.15, so it only
ever tightens the approval gesture; the shake's is half the typical shake,
never above the default and never below 0.03, so it only ever loosens the
refusal. A round that moved less than the default floor is reported but not
stored, so a missed attempt cannot lower anything. `doctor` reports the
person's floors (`gestures.calibrated`).

First run, the reference user: nods 0.26 and 0.26, shakes 0.33 and 0.36;
floors nod 0.129, shake 0.060. A casual nod recorded earlier at 0.106 would
sit under that floor; the light nod of the clean battery (0.17) clears it.
The factor is one number if that trade turns out wrong.

Then the first live nod at that floor was missed, twice, and the recording
of it (two clean double nods, legs 0.14 to 0.21) showed the "rest" bar was a
fraction of the floor: at 0.129 it was 0.045 per frame, above a nod's own
motion, and the sequence was cleared as resting. It is an absolute 0.02 now.
The per-person factor is 0.4 of the peak-to-peak (the detector sees single
legs) and capped at 0.09: on that recording both nods count at every floor
up to 0.09 and one drops out at 0.10, its first departure from rest being
the small leg. The reference user's floor is 0.09.

**Camera binding, closed on the reference machine.** An Add Look through
the daemon (`faceauth enroll --label desk`) added ten templates and stamped
the twenty earlier ones with the IR sensor's identity (`ipu3:ov7251
3-0060`); `doctor`'s `templates.camera` row passes. The pairwise
self-consistency minimum fell to 0.10 with the new look, one frame caught
off angle; a match still needs two frames over the threshold, so it costs
nothing on its own, and it is the look to delete and redo if unlocks ever
slow down.
