# Omarchy FaceAuth: source

Rust workspace for the face-authentication stack. Builds with stable Rust and no
system libraries beyond libc; the kernel ABI it needs is hand-written in
`faceauth-camera/src/sys.rs` and pinned by layout tests.

| Crate | What it is | State |
| --- | --- | --- |
| `faceauth-camera` | Capture: V4L2 nodes and subdevices, media-controller graph, Intel IPU3 pipeline setup and 10-bit unpack, UVC decoders, the exposure / white-balance / tone calibration from `kernel/CALIBRATION.md`, the IR illuminator as a V4L2 control. | Working on the reference machine (see below). UVC path written, not yet exercised on hardware. |
| `faceauth-engine` | Detect, align, embed, match, presentation-attack gate on ONNX Runtime. | Placeholder. |
| `faceauth-daemon` | Root service owning the cameras and templates; Unix socket for the PAM module; enrolment; presence state machine. | Placeholder. |
| `faceauth-cli` | `faceauth` command: `cam probe`, `cam graph`, `cam test`; later `enroll`, `test`, `doctor`. | Camera subcommands working. |
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
