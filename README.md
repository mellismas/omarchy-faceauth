# Omarchy FaceAuth: source

Rust workspace for the face-authentication stack. Builds with stable Rust and no
system libraries beyond libc; the kernel ABI it needs is hand-written in
`faceauth-camera/src/sys.rs` and pinned by layout tests.

| Crate | What it is | State |
| --- | --- | --- |
| `faceauth-camera` | Capture: V4L2 nodes and subdevices, media-controller graph, Intel IPU3 pipeline setup and 10-bit unpack, UVC decoders, the exposure / white-balance / tone calibration from `kernel/CALIBRATION.md`, the IR illuminator as a V4L2 control. | Working on the reference machine (see below). UVC path written, not yet exercised on hardware. |
| `faceauth-engine` | Detect (YuNet), align (five-point similarity to the ArcFace template, contrast-normalised crop), embed (AuraFace glintr100, 512-D), cosine match; ONNX Runtime loaded dynamically from Arch's `onnxruntime-cpu`. | Working on the IR camera (see below). Presentation-attack gate not started. |
| `faceauth-daemon` | Root service owning the cameras and templates; Unix socket for the PAM module; enrolment; presence state machine. | Placeholder. |
| `faceauth-cli` | `faceauth` command: `cam probe`, `cam graph`, `cam test`, `engine inspect`, `engine test`, `engine live`; later `enroll`, `test`, `doctor`. | Camera and engine subcommands working. |
| `pam_faceauth` | The PAM module: opens the socket, asks, maps the reply, never touches a camera or a model, panics firewalled to `PAM_IGNORE`. | Placeholder. |

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
