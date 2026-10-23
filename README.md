# Omarchy FaceAuth

Face authentication for [Omarchy](https://github.com/omacom/omarchy) on an infrared camera whose illuminator the kernel exposes as a control. The lock screen opens when you look at it. A `sudo` or polkit request opens a card naming what is being run, which two nods or your password approve and two head shakes refuse. Rust, MIT. Tested on one machine, a Surface Book 2 (Intel IPU3, ov7251 IR sensor), with the kernel patch under Hardware below. UVC IR modules are not supported. Their emitter is not a V4L2 control, so the liveness gate cannot run and the daemon refuses.

This workspace is the daemon `faceauthd`, the PAM module `pam_faceauth` and the `faceauth` command; the lock screen's stack, the card, the enrollment window, setup and removal are changes to `omacom/omarchy`. The Arch package depends on `onnxruntime` (any build with `libonnxruntime.so`, API 17 or newer), `pam`, `systemd`, `coreutils`, `tpm2-tss` and `acl`. The models are the optional `omarchy-faceauth-models` package, which setup installs once its camera check passes and without which the daemon does not start. `curl` serves only `faceauth models fetch`. By itself the package changes one thing, a udev rule that makes the IR sensor's control node root-only, and `omarchy setup security face` writes the PAM stacks and enables the service.

## Install

`omarchy setup security face` does all of this. By hand:

```
sudo faceauth doctor                     # camera.ir and camera.illuminator must pass
sudo pacman -S omarchy-faceauth-models   # about 260 MB, checksummed by pacman
sudo systemctl enable --now faceauth.service
sudo faceauth enroll --user $USER        # the walk-through window
faceauth auth --user $USER               # {"result":"match",...} means it works
```

Then add the stacks in `packaging/pam-example.txt`. `omarchy remove security face` strips them and deletes the templates unless told to keep them. The walk-through takes the center, your reach, a path, held turns and a verification, then twelve gesture and everyday rounds. Add Look (`--start distance --label NAME`) stops after the verification, `calibrate --guided` (Tune Gestures) runs the rounds alone, and `enroll --terminal` (five looks) or `--look` (one) records no rounds, leaving the default floors until Tune Gestures.

## Commands

`faceauth --help` prints every command and flag on stdout. The commands are `doctor`, `enroll`, `calibrate`, `auth`, `probe`, `templates delete`, `presence` (bare, `on`, `off`, `away-time`, `obscured-lock`, `mode`), `cam probe`, `cam graph`, `cam ir-rule`, `cam ir-reset` and `models fetch`, plus `enrol-control` and `consent-answer` for the windows; an unknown flag is an error. `faceauth doctor` gives one row per part, from `camera.ir`, `camera.ir_access`, `camera.ir_capture`, `camera.rgb` and `camera.illuminator` through the models, daemon, templates, gesture floors, liveness policy, PAM stacks, TPM and the walk-away lock helper. `packaging/config.toml` names every key with its default. A `--features faceauth-cli/dev-tools` build adds the tuning tools in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Security

Templates are 512-number embeddings, never images, root-only in `/var/lib/faceauth` and sealed to the TPM where the machine has one. Every failure falls back to the password: the module answers `PAM_IGNORE` to everything but a match, and the one refusal it sends, your no at a polkit card, cancels that request without a password dialog. The lock screen only looks and never prompts. Nothing elevates without two nods from the followed face at the daemon's own camera, or your password typed into the card, and a request typed into an ssh session never reaches the camera. Each attempt draws a random strobe mask, so a recording that ignores the strobe passes about one attempt in seventy, a phone was never seen as a face in the tests made, and a paper print is refused on its reflectance. Not defended: a look-alike, a 3D mask, malware running as you with your password, a video on a display the IR camera sees, a camera that replays in step with the strobe, and a process holding the IR capture node where face setup could not lock it to root (setup locks it when faceauth's own detection says it carries infrared alone; `faceauth doctor` says which). The false-accept rate is unmeasured, and a process running as you can draw a fake card, so type a password only for a request you just made and prefer the nod. The polkit card also needs Quickshell changes no release or package carries yet (Quickshell issue #1016, open PR #800); without them every polkit card reads "Unverified:".

[docs/SECURITY.md](docs/SECURITY.md) states the whole contract, one claim per bullet with the file and function behind it.

## Hardware

The stock ov7251 driver lacks the strobe control. The last patch of a ten-patch linux-media series (`media: i2c: ov7251: expose the strobe output as a flash control`) adds it and is in no shipped kernel yet; the nine before it fix the CIO2 driver and let the RGB camera stream alongside the IR one. The models package installs YuNet (MIT), glintr100 (Apache-2.0) and MediaPipe's face landmark model (Apache-2.0, converted to ONNX, on this project's `models-1` release). `faceauth doctor` checks them against `models.toml`, and `.github/workflows/models.yml` checks its URLs on every push and weekly.

## Development

[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) covers the workspace, the build and tests, the consent lane, the enrollment walk-through, the tuning tools and the measurements behind each threshold.

On the reference machine with one enrolled subject, the gesture detectors are regression-tested on the twelve rounds in `faceauth-daemon/traces/v2` and a red-team module. The liveness thresholds come from 110 lit/unlit pairs each of a face and a print, and the accept threshold from one subject and one print. `docs/DEVELOPMENT.md` gives each with its scope and the probe's cost (2026-09-25). Unlock and approval latency and idle power have not been measured since the strobed confirm (2026-09-22) and the face mesh (2026-09-23). Build with `cargo build --release --locked` and test with `cargo test --release --locked`.
