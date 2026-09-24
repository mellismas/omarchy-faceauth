//! The bring-up and tuning tools: direct camera access, the engine on
//! still frames and live, the pose sweep and readout, the liveness
//! capture, the terminal-only enrolment into a development store and the
//! verify loop. None of it ships: the package build has no `dev-tools`
//! feature, so the shipped CLI is the commands a user or a setup script
//! runs and nothing a reviewer has to read past (H2). One of these tools,
//! `enroll --store`, writes templates that match on any camera, which is
//! why it must not exist in the package.

use super::*;
use faceauth_camera::calib::{self, Exposure, Window};
use faceauth_camera::unpack::{bayer_reduce, BayerOrder};
use faceauth_camera::{Camera, Frame, Illuminator};
use std::io::Write;

pub(super) const USAGE: &str = "\n  faceauth cam test [--seconds N] [--led on|off|alt] [--snapshot DIR] [--ir-only] [--exposure LINES]\n  faceauth engine inspect MODEL.onnx\n  faceauth engine test --models DIR IMAGE.pgm [IMAGE2.pgm]\n  faceauth engine mesh --models DIR IMAGE.pgm\n  faceauth engine live --models DIR [--seconds N] [--led on|off] [--save DIR]\n  faceauth liveness capture --models DIR --label TEXT --save DIR [--seconds N]\n  faceauth sweep [--user NAME] [--seconds N] [--log FILE] [--threshold T]   (root; scores per frame while you turn your head)\n  faceauth pose [--user NAME] [--rounds N] [--seconds N]   (root; a live pose readout)\n  faceauth enroll --store DIR ...                   (direct camera access; templates match on any camera)\n  faceauth verify --store DIR [--user NAME] [--seconds N] [--label TEXT --log scores.csv]";

/// The development commands, or None when `argv` is not one of them.
pub(super) fn dispatch(argv: &[&str]) -> Option<Result<()>> {
    match run(argv) {
        Err(e) if e.to_string() == NOT_A_DEV_COMMAND => None,
        r => Some(r),
    }
}

const NOT_A_DEV_COMMAND: &str = "not a development command";

fn run(argv: &[&str]) -> Result<()> {
    match argv {
        ["cam", "test", rest @ ..] => cam_test(rest),
        ["engine", "inspect", model] => {
            faceauth_engine::runtime::init()?;
            print!("{}", faceauth_engine::runtime::describe(model)?);
            Ok(())
        }
        ["engine", "test", rest @ ..] => engine_test(rest),
        ["engine", "mesh", rest @ ..] => {
            // The dense landmarks and the head pose from them, on a still
            // frame: detect, mesh, pose, and the five-point pose beside it.
            let dir = models_dir(rest);
            let img = faceauth_engine::Grey::read_pgm(
                rest.iter()
                    .find(|a| a.ends_with(".pgm"))
                    .ok_or_else(|| anyhow!("IMAGE.pgm"))?,
            )?;
            let mut p = faceauth_engine::Pipeline::load(&dir)?;
            let Some(mesh) = p.mesh.as_mut() else {
                bail!(
                    "no {} in {}",
                    faceauth_engine::mesh::FACE_MESH_FILE,
                    dir.display()
                )
            };
            let faces = p.detector.detect(&img, 0.5)?;
            let Some(face) = faces.iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
                println!("no face");
                return Ok(());
            };
            let five = faceauth_engine::pose::pose(&face.landmarks);
            let t = Instant::now();
            let m = mesh.for_face(&img, face)?;
            let took = t.elapsed();
            println!("face {:.0}px det {:.2}; five-point yaw {:+.3} nose_pitch {:.3} mouth_drop {:.3} roll {:+.1}", face.bbox[2], face.score, five.yaw, five.nose_pitch, five.mouth_drop, five.roll.to_degrees());
            match m {
                Some(m) => {
                    let hp = faceauth_engine::mesh::head_pose(&m);
                    println!(
                        "mesh score {:.3} in {:.1} ms: yaw {:+.1} pitch {:+.1} roll {:+.1} deg",
                        m.score,
                        took.as_secs_f32() * 1000.0,
                        hp.yaw,
                        hp.pitch,
                        hp.roll
                    );
                    for (name, i) in [
                        ("forehead", faceauth_engine::mesh::FOREHEAD),
                        ("chin", faceauth_engine::mesh::CHIN),
                        ("nose", faceauth_engine::mesh::NOSE_TIP),
                        ("r-eye", faceauth_engine::mesh::RIGHT_EYE_OUTER),
                        ("l-eye", faceauth_engine::mesh::LEFT_EYE_OUTER),
                        ("r-cheek", faceauth_engine::mesh::RIGHT_CHEEK),
                        ("l-cheek", faceauth_engine::mesh::LEFT_CHEEK),
                    ] {
                        let q = m.points[i];
                        println!("  {:8} ({:.0}, {:.0}, z {:+.0})", name, q[0], q[1], q[2]);
                    }
                }
                None => println!("mesh: no face in the crop"),
            }
            Ok(())
        }
        ["engine", "live", rest @ ..] => engine_live(rest),
        ["enroll", rest @ ..] if rest.contains(&"--store") => enroll(rest),
        ["sweep", rest @ ..] => {
            // Root: how the match falls off with head pose, against the
            // templates as they are. The user turns slowly left, right, up
            // and down; every frame is scored and binned by yaw.
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let seconds: f32 = opt(rest, "--seconds").unwrap_or("20").parse()?;
            let threshold: f32 = opt(rest, "--threshold").unwrap_or("0.70").parse()?;
            println!("Pose sweep for {}: {} s. Follow the cues; move slowly and keep your eyes on the screen.", user, seconds as u32);
            // Cues on a timer while the daemon records: five equal phases.
            let cues = [
                "Face the camera",
                "Turn LEFT, about a quarter turn, and hold",
                "Turn RIGHT, about a quarter turn, and hold",
                "Chin UP a little, and hold",
                "Chin DOWN, as if reading the keyboard",
                "Tilt your head LEFT, ear toward shoulder",
                "Tilt your head RIGHT, ear toward shoulder",
            ];
            let phase = seconds / cues.len() as f32;
            std::thread::spawn(move || {
                for c in cues {
                    println!("\n>>> {}", c);
                    std::thread::sleep(Duration::from_secs_f32(phase));
                }
                println!("\n>>> Done.");
            });
            let o = faceauth_daemon::server::sweep(&socket, &user, seconds)?;
            let faceauth_daemon::auth::Outcome::Sweep {
                frames,
                templates,
                elapsed_ms,
            } = &o
            else {
                println!("{}", serde_json::to_string(&o)?);
                return Ok(());
            };
            if let Some(path) = opt(rest, "--log") {
                use std::io::Write as _;
                let mut f = std::fs::OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(path)?;
                let stamp = faceauth_daemon::store::now_secs();
                for fr in frames {
                    writeln!(
                        f,
                        "{},{:.2},{:.3},{},{:.3},{:.3},{:.3},{:.0},{:.0}",
                        stamp,
                        fr.t,
                        fr.score,
                        fr.template,
                        fr.yaw,
                        fr.pitch,
                        fr.nose_pitch,
                        fr.face_px,
                        fr.roll
                    )?;
                }
                println!("{} frames appended to {}", frames.len(), path);
            }
            println!(
                "{} frames in {:.1} s against {} templates; threshold {:.2}",
                frames.len(),
                *elapsed_ms as f32 / 1000.0,
                templates,
                threshold
            );
            let mut bins: std::collections::BTreeMap<i32, Vec<f32>> = Default::default();
            for fr in frames {
                bins.entry((fr.yaw * 10.0).round() as i32)
                    .or_default()
                    .push(fr.score);
            }
            println!(
                "{:>6} {:>6} {:>6} {:>6} {:>6} {:>5}",
                "yaw", "frames", "min", "mean", "max", "pass"
            );
            for (b, v) in &bins {
                let n = v.len() as f32;
                let mean = v.iter().sum::<f32>() / n;
                let min = v.iter().cloned().fold(1.0, f32::min);
                let max = v.iter().cloned().fold(-1.0, f32::max);
                let pass = v.iter().filter(|s| **s >= threshold).count() as f32 / n * 100.0;
                println!(
                    "{:>6.1} {:>6} {:>6.3} {:>6.3} {:>6.3} {:>4.0}%",
                    *b as f32 / 10.0,
                    v.len(),
                    min,
                    mean,
                    max,
                    pass
                );
            }
            let mut pbins: std::collections::BTreeMap<i32, Vec<f32>> = Default::default();
            for fr in frames {
                pbins
                    .entry((fr.nose_pitch * 10.0).round() as i32)
                    .or_default()
                    .push(fr.score);
            }
            println!(
                "{:>6} {:>6} {:>6} {:>6} {:>5}",
                "npitch", "frames", "min", "mean", "pass"
            );
            for (b, v) in &pbins {
                let n = v.len() as f32;
                let mean = v.iter().sum::<f32>() / n;
                let min = v.iter().cloned().fold(1.0, f32::min);
                let pass = v.iter().filter(|s| **s >= threshold).count() as f32 / n * 100.0;
                println!(
                    "{:>6.1} {:>6} {:>6.3} {:>6.3} {:>4.0}%",
                    *b as f32 / 10.0,
                    v.len(),
                    min,
                    mean,
                    pass
                );
            }
            let mut rbins: std::collections::BTreeMap<i32, Vec<f32>> = Default::default();
            for fr in frames {
                rbins
                    .entry((fr.roll / 10.0).round() as i32 * 10)
                    .or_default()
                    .push(fr.score);
            }
            println!(
                "{:>6} {:>6} {:>6} {:>6} {:>5}",
                "roll", "frames", "min", "mean", "pass"
            );
            for (b, v) in &rbins {
                let n = v.len() as f32;
                let mean = v.iter().sum::<f32>() / n;
                let min = v.iter().cloned().fold(1.0, f32::min);
                let pass = v.iter().filter(|s| **s >= threshold).count() as f32 / n * 100.0;
                println!(
                    "{:>6} {:>6} {:>6.3} {:>6.3} {:>4.0}%",
                    b,
                    v.len(),
                    min,
                    mean,
                    pass
                );
            }
            Ok(())
        }
        ["pose", rest @ ..] => {
            // Root: a live readout of the pose measures, a few seconds at a
            // time, so a person can see what a turn or a tilt reads.
            let socket =
                PathBuf::from(opt(rest, "--socket").unwrap_or(faceauth_daemon::config::SOCKET));
            let user = user_arg(rest)?;
            let rounds: usize = opt(rest, "--rounds").unwrap_or("8").parse()?;
            let seconds: f32 = opt(rest, "--seconds").unwrap_or("3").parse()?;
            println!("Pose readout for {}: {} rounds of {} s. Turn is yaw (negative left), pitch is nose_pitch (higher is chin down). Move and watch.", user, rounds, seconds);
            println!(
                "{:>5} {:>7} {:>7} {:>7} {:>7} {:>7} {:>6}",
                "round", "frames", "turn", "turn+-", "pitch", "pitch+-", "score"
            );
            for r in 1..=rounds {
                let o = faceauth_daemon::server::sweep(&socket, &user, seconds)?;
                let faceauth_daemon::auth::Outcome::Sweep { frames, .. } = &o else {
                    println!("{}", serde_json::to_string(&o)?);
                    continue;
                };
                if frames.is_empty() {
                    println!("{:>5} {:>7}", r, "no face");
                    continue;
                }
                let n = frames.len() as f32;
                let mean = |f: &dyn Fn(&faceauth_daemon::auth::SweepFrame) -> f32| {
                    frames.iter().map(f).sum::<f32>() / n
                };
                let (yaw, pitch, score) = (
                    mean(&|f| f.yaw),
                    mean(&|f| f.nose_pitch),
                    mean(&|f| f.score),
                );
                let spread = |f: &dyn Fn(&faceauth_daemon::auth::SweepFrame) -> f32| {
                    let v: Vec<f32> = frames.iter().map(f).collect();
                    (
                        v.iter().cloned().fold(f32::MAX, f32::min),
                        v.iter().cloned().fold(f32::MIN, f32::max),
                    )
                };
                let (ylo, yhi) = spread(&|f| f.yaw);
                let (plo, phi) = spread(&|f| f.nose_pitch);
                println!(
                    "{:>5} {:>7} {:>+7.2} {:>7} {:>7.2} {:>7} {:>6.2}",
                    r,
                    frames.len(),
                    yaw,
                    format!("{:+.2}..{:+.2}", ylo, yhi),
                    pitch,
                    format!("{:.2}..{:.2}", plo, phi),
                    score
                );
            }
            Ok(())
        }
        ["liveness", "capture", rest @ ..] => liveness_capture(rest),
        ["verify", rest @ ..] => verify(rest),
        _ => bail!("{}", NOT_A_DEV_COMMAND),
    }
}

struct Loop {
    /// Metering window in raw frame coordinates; None = centre window.
    window: Option<Window>,
    cam: Camera,
    frame: Frame,
    frames: u64,
    /// The camera crate's own exposure loop, the one the daemon runs, so
    /// the bring-up tools meter the way the daemon does (J10).
    ae: calib::AutoExposure,
    exposure: Exposure,
    metering: calib::Metering,
    /// Hold the exposure where it started instead of metering: for a frame
    /// meant to look like the gate's own, which freezes exposure too.
    fixed: bool,
}

impl Loop {
    fn new(mut cam: Camera, start: Exposure) -> Result<Self> {
        // Nothing here multiplies the frame by a digital gain either.
        cam.limits.dgain_max = 1.0;
        cam.set_exposure(start)?;
        cam.start()?;
        let ae = calib::AutoExposure::new(start, cam.limits);
        Ok(Loop {
            window: None,
            cam,
            frame: Frame::new(0, 0),
            frames: 0,
            ae,
            exposure: start,
            metering: Default::default(),
            fixed: false,
        })
    }

    /// Capture one frame; the loop steps the exposure on its own cadence.
    fn tick(&mut self) -> Result<bool> {
        if !self.cam.capture(&mut self.frame, Duration::from_secs(2))? {
            return Ok(false);
        }
        self.frames += 1;
        if !self.fixed {
            let w = self
                .window
                .unwrap_or_else(|| Window::centre(self.frame.width, self.frame.height))
                .clamp(self.frame.width, self.frame.height);
            if let Some(next) = self.ae.observe(&self.frame.px, self.frame.width, w) {
                self.cam.set_exposure(next)?;
                self.ae.exposure = next;
                self.exposure = next;
            }
            self.metering = self.ae.metering;
        }
        Ok(true)
    }
}

fn cam_test(rest: &[&str]) -> Result<()> {
    let mut seconds = 10u64;
    let mut led = "off";
    let mut snapshot: Option<PathBuf> = None;
    let mut ir_only = false;
    let mut exposure: Option<i64> = None;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match *a {
            "--seconds" => seconds = it.next().ok_or_else(|| anyhow!("--seconds N"))?.parse()?,
            "--exposure" => {
                exposure = Some(
                    it.next()
                        .ok_or_else(|| anyhow!("--exposure LINES"))?
                        .parse()?,
                )
            }
            "--led" => led = it.next().ok_or_else(|| anyhow!("--led on|off|alt"))?,
            "--snapshot" => {
                snapshot = Some(PathBuf::from(
                    it.next().ok_or_else(|| anyhow!("--snapshot DIR"))?,
                ))
            }
            "--ir-only" => ir_only = true,
            _ => usage(),
        }
    }
    let g = faceauth_camera::ipu3::probe()?
        .ok_or_else(|| anyhow!("no IPU3 graph found (UVC path not wired into cam test yet)"))?;
    let ir = g
        .ir_sensor()
        .ok_or_else(|| anyhow!("no front IR sensor on the IPU3 graph"))?;
    let rgb = g.colour_sensor();

    let (iw, ih) = g.configure(ir, None)?;
    let ir_cam = Camera::open(&ir.video, &ir.subdev, iw, ih, ir.pixelformat, 6)?;
    log::info!(
        "IR  {} {}x{} exposure {:?} gain {:?}",
        ir.name,
        iw,
        ih,
        ir_cam.limits.exposure,
        ir_cam.limits.gain
    );
    let illum = Illuminator::open(&ir.subdev)?;
    let mut ir_loop = Loop::new(
        ir_cam,
        Exposure {
            exposure: exposure.unwrap_or(500),
            gain: 16,
            dgain: 1.0,
        },
    )?;
    ir_loop.fixed = exposure.is_some();

    let mut rgb_loop = match (rgb, ir_only) {
        (Some(r), false) => {
            // The reference RGB sensor overruns its link at its default 2592x972 mode.
            let (rw, rh) = g.configure(r, Some((1296, 972)))?;
            let cam = Camera::open(&r.video, &r.subdev, rw, rh, r.pixelformat, 6)?;
            log::info!(
                "RGB {} {}x{} exposure {:?}",
                r.name,
                rw,
                rh,
                cam.limits.exposure
            );
            Some(Loop::new(
                cam,
                Exposure {
                    exposure: 1030,
                    gain: 0,
                    dgain: 1.0,
                },
            )?)
        }
        _ => None,
    };

    match (led, &illum) {
        ("on", Some(i)) => i.set(true)?,
        ("alt", Some(i)) => i.set_pattern(0xaa)?,
        ("off", Some(i)) => i.set(false)?,
        ("off", None) => {}
        (_, None) => bail!("--led requested but the IR sensor has no strobe control"),
        (other, _) => bail!("--led {}: expected on, off or alt", other),
    }

    let t0 = Instant::now();
    let mut last_log = Instant::now();
    let mut wb = calib::WhiteBalance::default();
    let mut rgb_reduced: Vec<[f32; 3]> = Vec::new();
    let mut ir_black = 0u16;
    let mut ir_white = 1023u16;
    let mut rgb_black = 25u16;
    while t0.elapsed() < Duration::from_secs(seconds) {
        if !ir_loop.tick()? {
            log::warn!("IR: no frame in 2 s");
        }
        if let Some(r) = rgb_loop.as_mut() {
            // Poll the RGB node without blocking the IR cadence.
            if !r.tick()? {
                log::warn!("RGB: no frame in 2 s");
            }
        }
        if ir_loop.frames % 15 == 0 && ir_loop.frame.width > 0 {
            ir_black = calib::percentile(&ir_loop.frame.px, 7, 0.005);
            ir_white = calib::percentile(&ir_loop.frame.px, 7, 0.995);
        }
        if let Some(r) = rgb_loop.as_mut() {
            if r.frames % 15 == 0 && r.frame.width > 0 {
                rgb_black = calib::percentile(&r.frame.px, 13, 0.005);
                let n = (r.frame.width / 2) * (r.frame.height / 2);
                rgb_reduced.resize(n, [0.0; 3]);
                bayer_reduce(
                    &r.frame.px,
                    r.frame.width,
                    r.frame.height,
                    BayerOrder::Bggr,
                    rgb_black,
                    &mut rgb_reduced,
                );
                wb.update(&rgb_reduced, 1023.0 - rgb_black as f64);
            }
        }
        if last_log.elapsed() >= Duration::from_secs(1) {
            last_log = Instant::now();
            let el = t0.elapsed().as_secs_f64();
            let mut line = format!(
                "t={:5.1}s IR {:4} fr ({:4.1} fps) exp={:4} gain={:3} dg={:.2} blk={} wht={} meter {:.2}/{:.2}",
                el,
                ir_loop.frames,
                ir_loop.frames as f64 / el,
                ir_loop.exposure.exposure,
                ir_loop.exposure.gain,
                ir_loop.exposure.dgain,
                ir_black,
                ir_white,
                ir_loop.metering.mean,
                ir_loop.metering.clip
            );
            if let Some(r) = &rgb_loop {
                line += &format!(
                    " | RGB {:4} fr ({:4.1} fps) exp={:4} dg={:.2} blk={} wb={:.2}/{:.2} meter {:.2}/{:.2}",
                    r.frames,
                    r.frames as f64 / el,
                    r.exposure.exposure,
                    r.exposure.dgain,
                    rgb_black,
                    wb.wr,
                    wb.wb,
                    r.metering.mean,
                    r.metering.clip
                );
            }
            if let Some(i) = &illum {
                line += &format!(" | led={}", i.is_on()? as u8);
            }
            println!("{}", line);
        }
    }

    if let Some(dir) = snapshot {
        std::fs::create_dir_all(&dir)?;
        let f = &ir_loop.frame;
        let mut grey = vec![0u8; f.width * f.height];
        calib::ir_to_grey8(&f.px, ir_black, ir_white, calib::IR_LOOK, &mut grey);
        write_pgm(&dir.join("ir.pgm"), f.width, f.height, &grey)?;
        if let Some(r) = &rgb_loop {
            let (w2, h2) = (r.frame.width / 2, r.frame.height / 2 - 1);
            let n = (r.frame.width / 2) * (r.frame.height / 2);
            rgb_reduced.resize(n, [0.0; 3]);
            bayer_reduce(
                &r.frame.px,
                r.frame.width,
                r.frame.height,
                BayerOrder::Bggr,
                rgb_black,
                &mut rgb_reduced,
            );
            let mut out = vec![[0u8; 3]; w2 * h2];
            calib::rgb_to_rgb8(
                &rgb_reduced[..w2 * h2],
                rgb_black,
                1023,
                wb,
                r.exposure.dgain,
                calib::RGB_LOOK,
                &mut out,
            );
            write_ppm(&dir.join("rgb.ppm"), w2, h2, &out)?;
        }
        println!("snapshots written to {}", dir.display());
    }
    if let Some(i) = &illum {
        i.set(false)?;
    }
    ir_loop.cam.stop()?;
    if let Some(r) = rgb_loop.as_mut() {
        r.cam.stop()?;
    }
    Ok(())
}

fn write_pgm(path: &PathBuf, w: usize, h: usize, data: &[u8]) -> Result<()> {
    let mut f = std::fs::File::create(path).with_context(|| path.display().to_string())?;
    write!(f, "P5\n{} {}\n255\n", w, h)?;
    f.write_all(data)?;
    Ok(())
}

fn write_ppm(path: &PathBuf, w: usize, h: usize, data: &[[u8; 3]]) -> Result<()> {
    let mut f = std::fs::File::create(path).with_context(|| path.display().to_string())?;
    write!(f, "P6\n{} {}\n255\n", w, h)?;
    for p in data {
        f.write_all(p)?;
    }
    Ok(())
}

fn models_dir(rest: &[&str]) -> PathBuf {
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        if *a == "--models" {
            if let Some(d) = it.next() {
                return PathBuf::from(d);
            }
        }
    }
    std::env::var("FACEAUTH_MODELS")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/usr/share/faceauth/models"))
}

/// Detect and embed faces in one or two PGM images; with two, print their similarity.
fn engine_test(rest: &[&str]) -> Result<()> {
    use faceauth_engine::{Grey, Pipeline};
    let dir = models_dir(rest);
    let images: Vec<&str> = rest
        .iter()
        .copied()
        .filter(|a| a.ends_with(".pgm"))
        .collect();
    if images.is_empty() {
        usage();
    }
    let t = Instant::now();
    let mut p = Pipeline::load(&dir)?;
    println!(
        "models loaded from {} in {:.0} ms",
        dir.display(),
        t.elapsed().as_secs_f64() * 1e3
    );
    let mut embeddings = Vec::new();
    for path in &images {
        let img = Grey::read_pgm(path)?;
        let t = Instant::now();
        let faces = p.analyse(&img, 0.5, 1)?;
        let ms = t.elapsed().as_secs_f64() * 1e3;
        println!(
            "{}: {}x{} {} face(s) in {:.1} ms",
            path,
            img.width,
            img.height,
            faces.len(),
            ms
        );
        for f in &faces {
            println!("  score {:.3} bbox [{:.0} {:.0} {:.0} {:.0}] eyes ({:.0},{:.0}) ({:.0},{:.0}) nose ({:.0},{:.0})",
                f.score, f.bbox[0], f.bbox[1], f.bbox[2], f.bbox[3],
                f.landmarks[0][0], f.landmarks[0][1], f.landmarks[1][0], f.landmarks[1][1], f.landmarks[2][0], f.landmarks[2][1]);
        }
        if let Some(e) = faces.first().and_then(|f| f.embedding.clone()) {
            embeddings.push(e);
        }
    }
    if embeddings.len() == 2 {
        println!(
            "cosine similarity: {:.4}",
            faceauth_engine::cosine(&embeddings[0], &embeddings[1])
        );
    }
    Ok(())
}

/// Stream the IR camera, run the pipeline on each frame, report timings and
/// the similarity of successive embeddings (same person, so it should stay high).
fn engine_live(rest: &[&str]) -> Result<()> {
    use faceauth_engine::{Grey, Pipeline};
    let dir = models_dir(rest);
    let mut seconds = 10u64;
    let mut led = "on";
    let mut save: Option<PathBuf> = None;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match *a {
            "--seconds" => seconds = it.next().ok_or_else(|| anyhow!("--seconds N"))?.parse()?,
            "--led" => led = it.next().ok_or_else(|| anyhow!("--led on|off"))?,
            "--save" => {
                save = Some(PathBuf::from(
                    it.next().ok_or_else(|| anyhow!("--save DIR"))?,
                ))
            }
            "--models" => {
                it.next();
            }
            _ => usage(),
        }
    }
    let mut p = Pipeline::load(&dir)?;
    let g = faceauth_camera::ipu3::probe()?.ok_or_else(|| anyhow!("no IPU3 graph"))?;
    let ir = g.ir_sensor().ok_or_else(|| anyhow!("no IR sensor"))?;
    let (iw, ih) = g.configure(ir, None)?;
    let cam = Camera::open(&ir.video, &ir.subdev, iw, ih, ir.pixelformat, 6)?;
    let illum = Illuminator::open(&ir.subdev)?;
    let mut lp = Loop::new(
        cam,
        Exposure {
            exposure: 500,
            gain: 16,
            dgain: 1.0,
        },
    )?;
    if let Some(i) = &illum {
        i.set(led == "on")?;
    }
    let t0 = Instant::now();
    let mut black = 0u16;
    let mut white = 1023u16;
    let mut last: Option<Vec<f32>> = None;
    let mut first: Option<Vec<f32>> = None;
    let mut n = 0usize;
    let mut sum_ms = 0f64;
    let mut best_crop: Option<(f32, Grey)> = None;
    let neutral = calib::IrLook {
        dgain: 1.0,
        brightness: 0.0,
        contrast: 1.0,
    };
    while t0.elapsed() < Duration::from_secs(seconds) {
        if !lp.tick()? {
            continue;
        }
        if lp.frames % 15 == 0 {
            black = calib::percentile(&lp.frame.px, 7, 0.005);
            white = calib::percentile(&lp.frame.px, 7, 0.995);
        }
        if lp.frames % 5 != 0 {
            continue;
        }
        let f = &lp.frame;
        let mut g8 = Grey::new(f.width, f.height);
        calib::ir_to_grey8(&f.px, black, white, neutral, &mut g8.data);
        // Reference IR sensor mounting: transpose plus both flips brings the face upright.
        let img = g8.oriented(true, true, true);
        let t = Instant::now();
        let faces = p.analyse(&img, 0.5, 1)?;
        let ms = t.elapsed().as_secs_f64() * 1e3;
        n += 1;
        sum_ms += ms;
        let Some(face) = faces.first() else {
            println!(
                "t={:4.1}s no face ({:.0} ms) exp={} gain={}",
                t0.elapsed().as_secs_f64(),
                ms,
                lp.exposure.exposure,
                lp.exposure.gain
            );
            continue;
        };
        // Meter on the face: map the oriented-frame box back to raw sensor coordinates
        // (orientation was transpose + both flips: raw x = W-1-oy, raw y = H-1-ox).
        {
            let (rw, rh) = (f.width as f32, f.height as f32);
            let [bx, by, bw, bh] = face.bbox;
            let (ox0, oy0, ox1, oy1) = (
                bx.max(0.0),
                by.max(0.0),
                (bx + bw).max(0.0),
                (by + bh).max(0.0),
            );
            let x0 = (rw - 1.0 - oy1).max(0.0) as usize;
            let x1 = (rw - 1.0 - oy0).max(0.0) as usize;
            let y0 = (rh - 1.0 - ox1).max(0.0) as usize;
            let y1 = (rh - 1.0 - ox0).max(0.0) as usize;
            lp.window = Some(Window {
                x0,
                y0,
                x1: x1.max(x0 + 1),
                y1: y1.max(y0 + 1),
            });
        }
        let e = face.embedding.clone().unwrap();
        let sim_prev = last.as_ref().map(|l| faceauth_engine::cosine(l, &e));
        let sim_first = first.as_ref().map(|l| faceauth_engine::cosine(l, &e));
        println!(
            "t={:4.1}s face score {:.2} bbox {:.0}x{:.0} at ({:.0},{:.0}) {:.0} ms | vs prev {} vs first {} | exp={} gain={} meter {:.2}",
            t0.elapsed().as_secs_f64(), face.score, face.bbox[2], face.bbox[3], face.bbox[0], face.bbox[1], ms,
            sim_prev.map(|s| format!("{:.3}", s)).unwrap_or("-".into()),
            sim_first.map(|s| format!("{:.3}", s)).unwrap_or("-".into()),
            lp.exposure.exposure, lp.exposure.gain, lp.metering.mean
        );
        if first.is_none() {
            first = Some(e.clone());
        }
        last = Some(e);
        if best_crop
            .as_ref()
            .map(|(s, _)| face.score > *s)
            .unwrap_or(true)
        {
            best_crop = Some((
                face.score,
                faceauth_engine::align::align_112(&img, &face.landmarks),
            ));
            if let Some(dir) = &save {
                std::fs::create_dir_all(dir)?;
                img.write_pgm(dir.join("frame.pgm"))?;
            }
        }
    }
    if let Some(i) = &illum {
        i.set(false)?;
    }
    if let (Some(dir), Some((s, crop))) = (&save, &best_crop) {
        crop.write_pgm(dir.join("crop-112.pgm"))?;
        println!("best crop (score {:.2}) saved to {}", s, dir.display());
    }
    if n > 0 {
        println!(
            "{} frames analysed, mean {:.1} ms per frame (detect + align + embed)",
            n,
            sum_ms / n as f64
        );
    }
    lp.cam.stop()?;
    Ok(())
}

/// One embedded face from a capture burst.
struct Sample {
    embedding: Vec<f32>,
    score: f32,
    face_width: f32,
}

/// Stream the IR camera with the illuminator on and face-box metering, and
/// collect up to `want` embeddings of the best-scoring detections within `seconds`.
/// This is the capture the daemon runs for both enrolment and verification.
fn capture_burst(
    p: &mut faceauth_engine::Pipeline,
    seconds: u64,
    want: usize,
    min_score: f32,
    quiet: bool,
    spacing_ms: u64,
) -> Result<Vec<Sample>> {
    use faceauth_engine::Grey;
    let g = faceauth_camera::ipu3::probe()?.ok_or_else(|| anyhow!("no IPU3 graph"))?;
    let ir = g.ir_sensor().ok_or_else(|| anyhow!("no IR sensor"))?;
    let (iw, ih) = g.configure(ir, None)?;
    let cam = Camera::open(&ir.video, &ir.subdev, iw, ih, ir.pixelformat, 6)?;
    let illum = Illuminator::open(&ir.subdev)?;
    let mut lp = Loop::new(
        cam,
        Exposure {
            exposure: 500,
            gain: 16,
            dgain: 1.0,
        },
    )?;
    if let Some(i) = &illum {
        i.set(true)?;
    }
    let t0 = Instant::now();
    let (mut black, mut white) = (0u16, 1023u16);
    let neutral = calib::IrLook {
        dgain: 1.0,
        brightness: 0.0,
        contrast: 1.0,
    };
    let mut out: Vec<Sample> = Vec::new();
    let mut seen = 0usize;
    let mut last_sample = Instant::now();
    while t0.elapsed() < Duration::from_secs(seconds) && out.len() < want {
        if !lp.tick()? {
            continue;
        }
        if lp.frames % 15 == 0 {
            black = calib::percentile(&lp.frame.px, 7, 0.005);
            white = calib::percentile(&lp.frame.px, 7, 0.995);
        }
        // Let the exposure settle for the first second, then sample every third frame.
        if t0.elapsed() < Duration::from_millis(1000) || lp.frames % 3 != 0 {
            continue;
        }
        let f = &lp.frame;
        let mut g8 = Grey::new(f.width, f.height);
        calib::ir_to_grey8(&f.px, black, white, neutral, &mut g8.data);
        let img = g8.oriented(true, true, true);
        let faces = p.analyse(&img, min_score, 1)?;
        let Some(face) = faces.first() else { continue };
        seen += 1;
        {
            let (rw, rh) = (f.width as f32, f.height as f32);
            let [bx, by, bw, bh] = face.bbox;
            let (ox0, oy0, ox1, oy1) = (
                bx.max(0.0),
                by.max(0.0),
                (bx + bw).max(0.0),
                (by + bh).max(0.0),
            );
            let x0 = (rw - 1.0 - oy1).max(0.0) as usize;
            let x1 = (rw - 1.0 - oy0).max(0.0) as usize;
            let y0 = (rh - 1.0 - ox1).max(0.0) as usize;
            let y1 = (rh - 1.0 - ox0).max(0.0) as usize;
            lp.window = Some(Window {
                x0,
                y0,
                x1: x1.max(x0 + 1),
                y1: y1.max(y0 + 1),
            });
        }
        // Skip frames before the face-box metering has had a chance to act, and
        // space samples out so an enrolment covers different poses.
        if seen <= 2
            || (!out.is_empty() && last_sample.elapsed() < Duration::from_millis(spacing_ms))
        {
            continue;
        }
        last_sample = Instant::now();
        if !quiet {
            println!(
                "  t={:4.1}s sample {} score {:.2} face {:.0}px exp={} gain={}",
                t0.elapsed().as_secs_f64(),
                out.len() + 1,
                face.score,
                face.bbox[2],
                lp.exposure.exposure,
                lp.exposure.gain
            );
        }
        out.push(Sample {
            embedding: face.embedding.clone().unwrap(),
            score: face.score,
            face_width: face.bbox[2],
        });
    }
    if let Some(i) = &illum {
        i.set(false)?;
    }
    lp.cam.stop()?;
    Ok(out)
}

fn enroll(rest: &[&str]) -> Result<()> {
    use faceauth_daemon::store::{now_secs, Template, UserTemplates};
    let dir = models_dir(rest);
    let store = dev_store(opt(rest, "--store").ok_or_else(|| anyhow!("--store DIR"))?)?;
    let user = user_arg(rest)?;
    let label = opt(rest, "--label").unwrap_or("enrol").to_string();
    let seconds: u64 = opt(rest, "--seconds").unwrap_or("12").parse()?;
    let count: usize = opt(rest, "--count").unwrap_or("10").parse()?;
    let mut p = faceauth_engine::Pipeline::load(&dir)?;
    println!(
        "Enrolling {}: look at the camera and move your head a little over the next {} s.",
        user, seconds
    );
    let spacing = ((seconds.saturating_sub(2)) * 1000 / count.max(1) as u64).clamp(100, 2000);
    let samples = capture_burst(&mut p, seconds, count, 0.6, false, spacing)?;
    if samples.len() < 3 {
        bail!(
            "only {} usable frames; sit closer, face the camera, and try again",
            samples.len()
        );
    }
    let mut u = store
        .load(&user)?
        .unwrap_or_else(|| UserTemplates::new(&user, faceauth_engine::embed::AURAFACE_FILE));
    if u.model != faceauth_engine::embed::AURAFACE_FILE {
        bail!(
            "existing templates are for model {}, delete them first",
            u.model
        );
    }
    let now = now_secs();
    for s in &samples {
        // Development path (direct camera): unbound templates, usable on any camera.
        u.templates.push(Template {
            embedding: s.embedding.clone(),
            quality: s.score,
            face_width: s.face_width,
            created: now,
            label: label.clone(),
            device: None,
            yaw: None,
            nose_pitch: None,
        });
    }
    let (lo, mean, hi) = u.self_consistency().unwrap_or((1.0, 1.0, 1.0));
    let path = store.save(&u)?;
    println!(
        "Saved {} templates ({} new) to {}",
        u.templates.len(),
        samples.len(),
        path.display()
    );
    println!(
        "Template self-consistency (pairwise cosine): min {:.3} mean {:.3} max {:.3}",
        lo, mean, hi
    );
    println!("{}", at_rest_note(&path.display().to_string()));
    Ok(())
}

fn verify(rest: &[&str]) -> Result<()> {
    let dir = models_dir(rest);
    let store = dev_store(opt(rest, "--store").ok_or_else(|| anyhow!("--store DIR"))?)?;
    let user = user_arg(rest)?;
    let seconds: u64 = opt(rest, "--seconds").unwrap_or("5").parse()?;
    let u = store
        .load(&user)?
        .ok_or_else(|| anyhow!("no templates for {}", user))?;
    let mut p = faceauth_engine::Pipeline::load(&dir)?;
    let t = Instant::now();
    let samples = capture_burst(&mut p, seconds, 5, 0.6, true, 0)?;
    let elapsed = t.elapsed().as_secs_f64();
    if samples.is_empty() {
        println!("no face in {:.1} s", elapsed);
        return Ok(());
    }
    let mut best = -1f32;
    let label = opt(rest, "--label").unwrap_or("genuine");
    let mut log = match opt(rest, "--log") {
        Some(path) => Some(
            std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(path)?,
        ),
        None => None,
    };
    for (i, s) in samples.iter().enumerate() {
        let (score, idx) = u.best_match(&s.embedding).unwrap();
        best = best.max(score);
        println!(
            "frame {}: face {:.0}px det {:.2} best template #{} cosine {:.3}",
            i + 1,
            s.face_width,
            s.score,
            idx,
            score
        );
        if let Some(f) = log.as_mut() {
            use std::io::Write;
            writeln!(
                f,
                "{},{},{},{:.3},{:.3},{:.0}",
                faceauth_daemon::store::now_secs(),
                label,
                i + 1,
                score,
                s.score,
                s.face_width
            )?;
        }
    }
    println!(
        "best {:.3} over {} frames in {:.1} s ({} templates)",
        best,
        samples.len(),
        elapsed,
        u.templates.len()
    );
    Ok(())
}

/// Flash-response experiment. Runs the strobe in the alternating pattern (0xaa),
/// pairs each lit frame with the unlit frame before it, aligns both with the lit
/// frame's landmarks, and writes the crops plus the per-pair statistics that the
/// liveness gate will be built on. The key quantity is the ratio image lit/unlit:
/// on a flat print the albedo cancels and the ratio is smooth, on a face the
/// geometry does not cancel and the ratio carries the relief.
fn liveness_capture(rest: &[&str]) -> Result<()> {
    use faceauth_engine::{align, Grey};
    let dir = models_dir(rest);
    let label = opt(rest, "--label").unwrap_or("unlabelled").to_string();
    let save = PathBuf::from(opt(rest, "--save").ok_or_else(|| anyhow!("--save DIR"))?);
    let seconds: u64 = opt(rest, "--seconds").unwrap_or("8").parse()?;
    std::fs::create_dir_all(&save)?;
    let mut p = faceauth_engine::Pipeline::load(&dir)?;
    let g = faceauth_camera::ipu3::probe()?.ok_or_else(|| anyhow!("no IPU3 graph"))?;
    let ir = g.ir_sensor().ok_or_else(|| anyhow!("no IR sensor"))?;
    let (iw, ih) = g.configure(ir, None)?;
    let cam = Camera::open(&ir.video, &ir.subdev, iw, ih, ir.pixelformat, 6)?;
    let illum =
        Illuminator::open(&ir.subdev)?.ok_or_else(|| anyhow!("IR sensor has no strobe control"))?;
    // Settle exposure on the subject with the LEDs steady (face-box metering),
    // then freeze it: the loop must not chase the alternation.
    let mut lp = Loop::new(
        cam,
        Exposure {
            exposure: 500,
            gain: 16,
            dgain: 1.0,
        },
    )?;
    illum.set(true)?;
    let settle = Instant::now();
    let neutral = calib::IrLook {
        dgain: 1.0,
        brightness: 0.0,
        contrast: 1.0,
    };
    while settle.elapsed() < Duration::from_millis(5000) {
        if !lp.tick()? || lp.frames % 5 != 0 {
            continue;
        }
        let f = &lp.frame;
        let mut g8 = Grey::new(f.width, f.height);
        calib::ir_to_grey8(&f.px, 0, 1023, neutral, &mut g8.data);
        let img = g8.oriented(true, true, true);
        if let Some(face) = p
            .detector
            .detect(&img, 0.5)?
            .into_iter()
            .max_by(|a, b| a.score.total_cmp(&b.score))
        {
            let (rw, rh) = (f.width as f32, f.height as f32);
            let [bx, by, bw, bh] = face.bbox;
            let (ox0, oy0, ox1, oy1) = (
                bx.max(0.0),
                by.max(0.0),
                (bx + bw).max(0.0),
                (by + bh).max(0.0),
            );
            let x0 = (rw - 1.0 - oy1).max(0.0) as usize;
            let x1 = (rw - 1.0 - oy0).max(0.0) as usize;
            let y0 = (rh - 1.0 - ox1).max(0.0) as usize;
            let y1 = (rh - 1.0 - ox0).max(0.0) as usize;
            lp.window = Some(Window {
                x0,
                y0,
                x1: x1.max(x0 + 1),
                y1: y1.max(y0 + 1),
            });
        }
    }
    println!(
        "exposure settled at {} gain {} (face-box mean {:.2})",
        lp.exposure.exposure, lp.exposure.gain, lp.metering.mean
    );
    illum.set_pattern(0xaa)?;
    let t0 = Instant::now();
    let mut prev: Option<(Grey, f64)> = None;
    let mut pairs = 0usize;
    let mut csv = String::from("label,pair,lit_mean,unlit_mean,flash_gain,ratio_hp,diff_hp,glint_r,glint_l,glint_native_r,glint_native_l,surround,reflectance,face_px,exposure\n");
    while t0.elapsed() < Duration::from_secs(seconds) {
        if !lp.cam.capture(&mut lp.frame, Duration::from_secs(2))? {
            continue;
        }
        lp.frames += 1;
        if t0.elapsed() < Duration::from_millis(700) {
            continue;
        }
        let f = &lp.frame;
        // Linear 8-bit (fixed mapping, no per-frame stretch) so lit/unlit are comparable.
        let mut g8 = Grey::new(f.width, f.height);
        for (o, &v) in g8.data.iter_mut().zip(&f.px) {
            *o = (v >> 2) as u8;
        }
        let img = g8.oriented(true, true, true);
        let mean = img.data.iter().map(|&v| v as f64).sum::<f64>() / img.data.len() as f64;
        let Some((prev_img, prev_mean)) = prev.replace((img.clone(), mean)) else {
            continue;
        };
        // A lit frame is the brighter of two consecutive frames by a clear margin.
        if mean < prev_mean * 1.15 {
            continue;
        }
        let (lit, unlit) = (&img, &prev_img);
        let faces = p.detector.detect(lit, 0.6)?;
        let Some(face) = faces.into_iter().max_by(|a, b| a.score.total_cmp(&b.score)) else {
            continue;
        };
        let fwd = align::similarity(&face.landmarks, &align::ARCFACE_112);
        let inv = align::invert(&fwd);
        let lit_c = lit.warp_affine(&inv, 112, 112);
        let unlit_c = unlit.warp_affine(&inv, 112, 112);
        // Statistics on the central face region (exclude the border the warp may leave empty).
        let idx = |x: usize, y: usize| y * 112 + x;
        let (mut sl, mut su, mut n) = (0f64, 0f64, 0usize);
        for y in 16..96 {
            for x in 16..96 {
                sl += lit_c.data[idx(x, y)] as f64;
                su += unlit_c.data[idx(x, y)] as f64;
                n += 1;
            }
        }
        let (lm, um) = (sl / n as f64, su / n as f64);
        let flash_gain = if um > 0.5 { lm / um } else { f64::INFINITY };
        // Log-ratio and difference images, then their high-pass energy: subtract a
        // 9x9 box blur and take the standard deviation of what remains.
        let mut ratio = vec![0f32; 112 * 112];
        let mut diff = vec![0f32; 112 * 112];
        for i in 0..112 * 112 {
            let l = lit_c.data[i] as f32 + 1.0;
            let u = unlit_c.data[i] as f32 + 1.0;
            ratio[i] = (l / u).ln();
            diff[i] = l - u;
        }
        let hp_energy = |m: &[f32]| -> f64 {
            let mut acc = 0f64;
            let mut cnt = 0usize;
            for y in 16..96 {
                for x in 16..96 {
                    let mut s = 0f32;
                    for dy in 0..9 {
                        for dx in 0..9 {
                            s += m[idx(x + dx - 4, y + dy - 4)];
                        }
                    }
                    let hp = m[idx(x, y)] - s / 81.0;
                    acc += (hp * hp) as f64;
                    cnt += 1;
                }
            }
            (acc / cnt as f64).sqrt()
        };
        let ratio_hp = hp_energy(&ratio);
        let diff_hp = hp_energy(&diff) / lm.max(1.0);
        // Corneal glint: the brightest pixel within 6 px of each eye landmark in the
        // difference image, relative to the local mean. A real eye mirrors the LED.
        let glint = |ex: f32, ey: f32| -> f64 {
            let (x, y) = (
                fwd[0][0] * ex + fwd[0][1] * ey + fwd[0][2],
                fwd[1][0] * ex + fwd[1][1] * ey + fwd[1][2],
            );
            let (cx, cy) = (x.round() as i32, y.round() as i32);
            let (mut mx, mut sum, mut cnt) = (0f32, 0f32, 0usize);
            for dy in -6..=6 {
                for dx in -6..=6 {
                    let (px, py) = (cx + dx, cy + dy);
                    if px < 0 || py < 0 || px >= 112 || py >= 112 {
                        continue;
                    }
                    let v = diff[idx(px as usize, py as usize)];
                    mx = mx.max(v);
                    sum += v;
                    cnt += 1;
                }
            }
            if cnt == 0 {
                0.0
            } else {
                (mx / (sum / cnt as f32).max(1.0)) as f64
            }
        };
        let glint_r = glint(face.landmarks[0][0], face.landmarks[0][1]);
        let glint_l = glint(face.landmarks[1][0], face.landmarks[1][1]);
        // Full-resolution cues on the flash response (lit minus unlit) of the oriented frame.
        let (fw, fh) = (lit.width, lit.height);
        let flash_at = |x: i32, y: i32| -> f32 {
            if x < 0 || y < 0 || x >= fw as i32 || y >= fh as i32 {
                return 0.0;
            }
            let i = y as usize * fw + x as usize;
            (lit.data[i] as f32 - unlit.data[i] as f32).max(0.0)
        };
        let [bx, by, bw, bh] = face.bbox;
        let (cx, cy) = (bx + bw / 2.0, by + bh / 2.0);
        // Face region: the inner 70% of the box. Surround: a ring from 1.4x to 2.0x the
        // box, which on a real head is the space beside the ears and above the hair.
        let mean_region = |scale_lo: f32, scale_hi: f32| -> f32 {
            let (mut s, mut n) = (0f32, 0usize);
            let (rx_lo, ry_lo, rx_hi, ry_hi) = (
                bw * scale_lo / 2.0,
                bh * scale_lo / 2.0,
                bw * scale_hi / 2.0,
                bh * scale_hi / 2.0,
            );
            let (x0, x1) = (
                (cx - rx_hi).max(0.0) as i32,
                (cx + rx_hi).min(fw as f32 - 1.0) as i32,
            );
            let (y0, y1) = (
                (cy - ry_hi).max(0.0) as i32,
                (cy + ry_hi).min(fh as f32 - 1.0) as i32,
            );
            let mut y = y0;
            while y <= y1 {
                let mut x = x0;
                while x <= x1 {
                    let inside_lo =
                        ((x as f32 - cx).abs() < rx_lo) && ((y as f32 - cy).abs() < ry_lo);
                    if !inside_lo {
                        s += flash_at(x, y);
                        n += 1;
                    }
                    x += 2;
                }
                y += 2;
            }
            if n == 0 {
                0.0
            } else {
                s / n as f32
            }
        };
        let face_flash = mean_region(0.0, 0.7);
        let ring_flash = mean_region(1.4, 2.0);
        let _ = (face_flash, ring_flash);
        // Glint at native resolution: brightest flash pixel within 5 px of each eye
        // landmark over the mean of that neighbourhood.
        let glint_native = |ex: f32, ey: f32| -> f32 {
            let (cx, cy) = (ex.round() as i32, ey.round() as i32);
            let (mut mx, mut sum, mut cnt) = (0f32, 0f32, 0usize);
            for dy in -5..=5 {
                for dx in -5..=5 {
                    let v = flash_at(cx + dx, cy + dy);
                    mx = mx.max(v);
                    sum += v;
                    cnt += 1;
                }
            }
            mx / (sum / cnt as f32).max(1.0)
        };
        let fr = faceauth_engine::liveness::FlashResponse::measure(
            lit,
            unlit,
            &face,
            lp.exposure.exposure,
            lp.exposure.gain.max(16),
        );
        let surround = fr.surround;
        let reflectance = fr.reflectance;
        let gn_r = glint_native(face.landmarks[0][0], face.landmarks[0][1]);
        let gn_l = glint_native(face.landmarks[1][0], face.landmarks[1][1]);
        pairs += 1;
        println!("pair {:2} lit {:5.1} gain {:4.2} ratio_hp {:.4} diff_hp {:.4} glint {:.2}/{:.2} native {:.2}/{:.2} surround {:.3} refl {:.4} face {:.0}px exp {} verdict {:?}", pairs, lm, flash_gain, ratio_hp, diff_hp, glint_r, glint_l, gn_r, gn_l, surround, reflectance, bw, lp.exposure.exposure, fr.verdict());
        csv += &format!(
            "{},{},{:.1},{:.1},{:.3},{:.4},{:.4},{:.2},{:.2},{:.2},{:.2},{:.3},{:.4},{:.0},{}\n",
            label,
            pairs,
            lm,
            um,
            flash_gain,
            ratio_hp,
            diff_hp,
            glint_r,
            glint_l,
            gn_r,
            gn_l,
            surround,
            reflectance,
            bw,
            lp.exposure.exposure
        );
        if pairs <= 3 {
            lit_c.write_pgm(save.join(format!("{}-{}-lit.pgm", label, pairs)))?;
            unlit_c.write_pgm(save.join(format!("{}-{}-unlit.pgm", label, pairs)))?;
            let mut r8 = Grey::new(112, 112);
            let (rmin, rmax) = ratio
                .iter()
                .fold((f32::MAX, f32::MIN), |(a, b), &v| (a.min(v), b.max(v)));
            for (o, &v) in r8.data.iter_mut().zip(&ratio) {
                *o = (((v - rmin) / (rmax - rmin).max(1e-3)) * 255.0) as u8;
            }
            r8.write_pgm(save.join(format!("{}-{}-ratio.pgm", label, pairs)))?;
            let mut d8 = Grey::new(112, 112);
            for (o, &v) in d8.data.iter_mut().zip(&diff) {
                *o = v.clamp(0.0, 255.0) as u8;
            }
            d8.write_pgm(save.join(format!("{}-{}-diff.pgm", label, pairs)))?;
        }
    }
    illum.set(false)?;
    lp.cam.stop()?;
    std::fs::write(save.join(format!("{}.csv", label)), csv)?;
    println!(
        "{} lit/unlit pairs; crops and {}.csv in {}",
        pairs,
        label,
        save.display()
    );
    Ok(())
}

/// The development `--store DIR` store: plaintext unless running as root.
/// As a user, probing the TPM makes PID 1 ask polkit, which puts a real
/// "decrypt a system credential" window on the desktop during a dev run or
/// a test (F13); root probes as the daemon does.
fn dev_store(dir: &str) -> Result<faceauth_daemon::store::Store> {
    use faceauth_daemon::store::{Sealing, Store};
    if unsafe { libc_geteuid() } == 0 {
        Store::open(dir)
    } else {
        Store::open_with(dir, Sealing::Plain("development store, not root".into()))
    }
}
