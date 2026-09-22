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
- **`sudo` and polkit.** Every request opens a window that names the command
  and the process asking (polkit requests are named from polkit's own
  message, handed to the daemon by the agent as the request starts). Nothing
  elevates until the face matches and the daemon sees two nods; two head
  shakes refuse; the password typed into the window approves. Buttons dismiss,
  deny and kill the requester, or block it for ten minutes. The window waits
  without a time limit; if you walk away the session locks and the request
  resumes when your face unlocks it. Requests queue and get their windows in
  turn. Every approval and every refusal posts a desktop notice.
- **Gestures.** Both are read from real image motion of the face between
  frames (how far its pixels shifted, vertically for the nod, sideways for
  the shake), not from landmark angles, because a face detector's fit can
  flip between two solutions and fake an angle while moving no pixels. A
  gesture is four alternating legs done together, from a head that was still
  just before; a glance, a look down, reading, talking and leaning in are all
  rejected by shape (see Measured, below). Setup records two nods and two
  shakes and sets the person's floors from them: the nod's only ever rises
  above the default, the shake's only ever falls below it.
- **Walk-away lock** (opt-in, `sudo faceauth presence on`): one short look
  every two seconds (five on battery); lock when the camera has not seen the
  enrolled user for the away time.
- **Every failure falls back to the password**, from a covered camera to a
  stopped service: the module returns `PAM_IGNORE` for everything but a match.

## What it defends against, and what it does not

- **A photo on a phone** is never seen as a face: the IR camera sees only its
  own illuminator reflected in the glass.
- **A paper print** is refused by two physical measurements taken with the
  illuminator strobed: paper reflects the strobe several times more strongly
  than skin, and a print's surround lights up with the face while a real
  head's background stays dark.
- **Elevation is never passive.** A face in front of the camera approves
  nothing; the nod is measured by the daemon on its own camera, and no key,
  click or socket message stands in for it. Window answers carry a
  per-request token that only the window the daemon summoned holds.
- **Remote callers.** A request whose caller the daemon cannot show to be
  local (an `sshd` in its ancestry, a logind session marked remote, or any
  shape it cannot verify) is refused before any window or camera. A same-uid
  process inside your own desktop session counts as local; what stands
  between that and root is the window naming the request, and the nod.
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
- **Rate limit**: five failed attempts in a minute, counted only when a face
  was seen, then a thirty-second hold.
- **Not defended**: a look-alike, a 3D mask, malware already running as you
  with your password, a video rendered on a display the IR camera can see
  (not measured; not claimed), and anything a setuid-root binary you can run
  does as uid 0 (on a stock system those are sudo, pkexec and polkit's
  helper, each of which authenticates first). A face match does not reset
  `pam_faillock`'s counter.

## Setup

`omarchy setup security face` does all of this; by hand:

```
sudo faceauth models fetch                 # ~260 MB, checksummed, once
sudo systemctl enable --now faceauth.service
sudo faceauth enroll --user $USER          # 12 s at the camera; --label for another look
faceauth auth --user $USER                 # {"result":"match",...} means it works
sudo faceauth calibrate --user $USER       # two nods, two shakes
faceauth doctor                            # every part, one row each
```

Then the PAM lines from `packaging/pam-example.txt`: `omarchy-lock-face` for
the lock screen (closed by `pam_deny`), and one `consent` line at the top of
`sudo` and `polkit-1`. Removal is `omarchy remove security face`, which
restores the original PAM files and deletes the templates unless told to
keep them.

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
consent round's per-frame recording, root-only, for tuning; off) and
`gesture_record_only` (recognise but never act; for recording a battery);
the `[presence]` table for the walk-away lock.

## Command line

```
faceauth doctor [--json]
faceauth enroll [--user NAME] [--label TEXT]
faceauth calibrate [--user NAME] [--rounds N]
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
| `faceauth-engine` | Detect (YuNet), align, embed (glintr100, 512-D), cosine match, head pose, image motion; ONNX Runtime loaded at run time from `/usr/lib/libonnxruntime.so`. |
| `faceauth-daemon` | `faceauthd`: authentication (settle, strobe, liveness gate, two matching frames), consent (window, gesture detectors, password check against `system-auth`), presence, the sealed template store, the socket. |
| `faceauth-cli` | `faceauth`. |
| `pam_faceauth` | The PAM module; links only libc and libpam. |
| `packaging/` | Service unit, default config, lock helper, PAM example. |

Models are not in the repository or the package: `models.toml` names them
with checksums and `faceauth models fetch` verifies them.

## Build

```
cargo build --release --locked
cargo test --release --locked        # FACEAUTH_REQUIRE_TPM=1 to insist on the sealing test (root)
```

Concurrent IR+RGB capture and the illuminator on Intel IPU3 laptops need the
two kernel patches shipped in `linux-omarchy`; a UVC IR camera needs nothing.
