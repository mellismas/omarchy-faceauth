# Omarchy FaceAuth: source

Rust workspace for the face-authentication stack. Builds with stable Rust and no
system libraries beyond libc; the kernel ABI it needs is hand-written in
`faceauth-camera/src/sys.rs` and pinned by layout tests.

| Crate | What it is | State |
| --- | --- | --- |
| `faceauth-camera` | Capture: V4L2 nodes and subdevices, media-controller graph, Intel IPU3 pipeline setup and 10-bit unpack, UVC decoders, the exposure / white-balance / tone calibration from `kernel/CALIBRATION.md`, the IR illuminator as a V4L2 control. | Working on the reference machine (see below). UVC path written, not yet exercised on hardware. |
| `faceauth-engine` | Detect (YuNet), align (five-point similarity to the ArcFace template, contrast-normalised crop), embed (AuraFace glintr100, 512-D), cosine match; ONNX Runtime loaded dynamically from Arch's `onnxruntime-cpu`. | Working on the IR camera (see below). Presentation-attack gate not started. |
| `faceauth-daemon` | `faceauthd`: config, camera capture per attempt (idle otherwise), the authentication flow (settle on the face, alternate the strobe, gate every lit frame, score until two match), template store, Unix socket with peer-credential checks. | Working end to end (see below). Presence state machine and TPM sealing not started. |
| `faceauth-cli` | `faceauth` command: `cam probe`, `cam graph`, `cam test`, `engine inspect`, `engine test`, `engine live`; later `enroll`, `test`, `doctor`. | Camera and engine subcommands working. |
| `pam_faceauth` | The PAM module: opens the socket, asks, maps `match` to `PAM_SUCCESS` and everything else to `PAM_IGNORE`, panics firewalled; links only libc and libpam. | Built and unit-tested; not yet wired into a PAM stack. |

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
WARN    templates.at_rest    templates are plaintext at rest (root 0600); TPM sealing not implemented
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
  sealing waits on a machine that has one.

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
