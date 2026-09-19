//! `faceauth`: the command-line front end. For now the camera subcommands that
//! prove the capture crate on hardware; enrol, test, doctor follow.

use anyhow::{anyhow, bail, Context, Result};
use faceauth_camera::calib::{self, Exposure, Smoother, Window, AE_TARGET};
use faceauth_camera::ipu3::SensorKind;
use faceauth_camera::unpack::{bayer_reduce, BayerOrder};
use faceauth_camera::{Camera, Frame, Illuminator};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

fn usage() -> ! {
    eprintln!(
        "usage:\n  faceauth cam probe\n  faceauth engine inspect MODEL.onnx\n  faceauth engine test --models DIR IMAGE.pgm [IMAGE2.pgm]\n  faceauth engine live --models DIR [--seconds N] [--led on|off] [--save DIR]\n  faceauth cam graph\n  faceauth cam test [--seconds N] [--led on|off|alt] [--snapshot DIR] [--ir-only]\n"
    );
    std::process::exit(2)
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).format_timestamp_millis().init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["cam", "probe"] => cam_probe(),
        ["cam", "graph"] => cam_graph(),
        ["cam", "test", rest @ ..] => cam_test(rest),
        ["engine", "inspect", model] => {
            faceauth_engine::runtime::init()?;
            print!("{}", faceauth_engine::runtime::describe(model)?);
            Ok(())
        }
        ["engine", "test", rest @ ..] => engine_test(rest),
        ["engine", "live", rest @ ..] => engine_live(rest),
        _ => usage(),
    }
}

fn cam_graph() -> Result<()> {
    use faceauth_camera::media::MediaDevice;
    for path in MediaDevice::enumerate() {
        let md = MediaDevice::open(&path)?;
        let (driver, model, bus) = md.info()?;
        println!("{}: {} {} {}", path.display(), driver, model, bus);
        let ents = md.entities()?;
        for e in &ents {
            println!("  [{}] {:<24} pads {} links {} dev {:?}", e.id, e.name, e.pads, e.links, e.dev_node());
            for l in md.links(e)? {
                let name = |id: u32| ents.iter().find(|x| x.id == id).map(|x| x.name.clone()).unwrap_or_else(|| id.to_string());
                println!("      {}:{} -> {}:{} flags 0x{:x}", name(l.source_entity), l.source_pad, name(l.sink_entity), l.sink_pad, l.flags);
            }
        }
    }
    Ok(())
}

fn cam_probe() -> Result<()> {
    let p = faceauth_camera::probe()?;
    println!("video nodes:");
    for (path, driver, card, fmts) in &p.video_nodes {
        println!("  {:<14} {:<12} {:<40} {}", path.display(), driver, card, fmts.join(" "));
    }
    match &p.ipu3 {
        None => println!("ipu3: none"),
        Some(g) => {
            println!("ipu3: {}", g.media.display());
            for s in &g.sensors {
                println!(
                    "  {:<9} {:<9} {:<16} port {} subdev {} video {} {}x{} mbus 0x{:04x} -> {}",
                    format!("{:?}", s.kind),
                    s.orientation.map(|o| format!("{:?}", o)).unwrap_or_else(|| "-".into()),
                    s.name,
                    s.port,
                    s.subdev.display(),
                    s.video.display(),
                    s.width,
                    s.height,
                    s.mbus_code,
                    faceauth_camera::sys::fourcc_str(s.pixelformat)
                );
                if s.kind == SensorKind::Infrared {
                    match Illuminator::open(&s.subdev)? {
                        Some(i) => println!("            illuminator: strobe control present (pattern: {})", i.has_pattern()),
                        None => println!("            illuminator: no strobe control (ambient only)"),
                    }
                }
            }
        }
    }
    Ok(())
}

struct Loop {
    /// Metering window in raw frame coordinates; None = centre window.
    window: Option<Window>,
    cam: Camera,
    frame: Frame,
    frames: u64,
    smoother: Smoother,
    exposure: Exposure,
    metering: calib::Metering,
    last_step: Instant,
}

impl Loop {
    fn new(mut cam: Camera, start: Exposure) -> Result<Self> {
        cam.set_exposure(start)?;
        cam.start()?;
        Ok(Loop { window: None, cam, frame: Frame::new(0, 0), frames: 0, smoother: Smoother::default(), exposure: start, metering: Default::default(), last_step: Instant::now() })
    }

    /// Capture one frame; every 0.5 s run an exposure step.
    fn tick(&mut self, black: u16) -> Result<bool> {
        if !self.cam.capture(&mut self.frame, Duration::from_secs(2))? {
            return Ok(false);
        }
        self.frames += 1;
        if self.last_step.elapsed() >= Duration::from_millis(500) {
            self.last_step = Instant::now();
            let w = self.window.unwrap_or_else(|| Window::centre(self.frame.width, self.frame.height)).clamp(self.frame.width, self.frame.height);
            let mut m = calib::meter(&self.frame.px, self.frame.width, black, w);
            m.mean *= self.exposure.dgain;
            if m.mean > 0.95 {
                m.clip = m.clip.max(0.2);
            }
            let smoothed = calib::Metering { mean: self.smoother.push(m.mean), clip: m.clip };
            self.metering = smoothed;
            let f = calib::ae_factor(smoothed, AE_TARGET);
            if f != 1.0 {
                let next = self.exposure.step(f, &self.cam.limits);
                self.cam.set_exposure(next)?;
                self.exposure = next;
            }
        }
        Ok(true)
    }
}

fn cam_test(rest: &[&str]) -> Result<()> {
    let mut seconds = 10u64;
    let mut led = "off";
    let mut snapshot: Option<PathBuf> = None;
    let mut ir_only = false;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match *a {
            "--seconds" => seconds = it.next().ok_or_else(|| anyhow!("--seconds N"))?.parse()?,
            "--led" => led = it.next().ok_or_else(|| anyhow!("--led on|off|alt"))?,
            "--snapshot" => snapshot = Some(PathBuf::from(it.next().ok_or_else(|| anyhow!("--snapshot DIR"))?)),
            "--ir-only" => ir_only = true,
            _ => usage(),
        }
    }
    let g = faceauth_camera::ipu3::probe()?.ok_or_else(|| anyhow!("no IPU3 graph found (UVC path not wired into cam test yet)"))?;
    let ir = g.ir_sensor().ok_or_else(|| anyhow!("no front IR sensor on the IPU3 graph"))?;
    let rgb = g.colour_sensor();

    let (iw, ih) = g.configure(ir, None)?;
    let ir_cam = Camera::open(&ir.video, &ir.subdev, iw, ih, ir.pixelformat, 6)?;
    log::info!("IR  {} {}x{} exposure {:?} gain {:?}", ir.name, iw, ih, ir_cam.limits.exposure, ir_cam.limits.gain);
    let illum = Illuminator::open(&ir.subdev)?;
    let mut ir_loop = Loop::new(ir_cam, Exposure { exposure: 500, gain: 16, dgain: 1.0 })?;

    let mut rgb_loop = match (rgb, ir_only) {
        (Some(r), false) => {
            // The reference RGB sensor overruns its link at its default 2592x972 mode.
            let (rw, rh) = g.configure(r, Some((1296, 972)))?;
            let cam = Camera::open(&r.video, &r.subdev, rw, rh, r.pixelformat, 6)?;
            log::info!("RGB {} {}x{} exposure {:?}", r.name, rw, rh, cam.limits.exposure);
            Some(Loop::new(cam, Exposure { exposure: 1030, gain: 0, dgain: 1.0 })?)
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
        if !ir_loop.tick(ir_black)? {
            log::warn!("IR: no frame in 2 s");
        }
        if let Some(r) = rgb_loop.as_mut() {
            // Poll the RGB node without blocking the IR cadence.
            if !r.tick(rgb_black)? {
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
                bayer_reduce(&r.frame.px, r.frame.width, r.frame.height, BayerOrder::Bggr, rgb_black, &mut rgb_reduced);
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
            bayer_reduce(&r.frame.px, r.frame.width, r.frame.height, BayerOrder::Bggr, rgb_black, &mut rgb_reduced);
            let mut out = vec![[0u8; 3]; w2 * h2];
            calib::rgb_to_rgb8(&rgb_reduced[..w2 * h2], rgb_black, 1023, wb, r.exposure.dgain, calib::RGB_LOOK, &mut out);
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
    std::env::var("FACEAUTH_MODELS").map(PathBuf::from).unwrap_or_else(|_| PathBuf::from("/usr/share/faceauth/models"))
}

/// Detect and embed faces in one or two PGM images; with two, print their similarity.
fn engine_test(rest: &[&str]) -> Result<()> {
    use faceauth_engine::{Grey, Pipeline};
    let dir = models_dir(rest);
    let images: Vec<&str> = rest.iter().copied().filter(|a| a.ends_with(".pgm")).collect();
    if images.is_empty() {
        usage();
    }
    let t = Instant::now();
    let mut p = Pipeline::load(&dir)?;
    println!("models loaded from {} in {:.0} ms", dir.display(), t.elapsed().as_secs_f64() * 1e3);
    let mut embeddings = Vec::new();
    for path in &images {
        let img = Grey::read_pgm(path)?;
        let t = Instant::now();
        let faces = p.analyse(&img, 0.5, 1)?;
        let ms = t.elapsed().as_secs_f64() * 1e3;
        println!("{}: {}x{} {} face(s) in {:.1} ms", path, img.width, img.height, faces.len(), ms);
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
        println!("cosine similarity: {:.4}", faceauth_engine::cosine(&embeddings[0], &embeddings[1]));
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
            "--save" => save = Some(PathBuf::from(it.next().ok_or_else(|| anyhow!("--save DIR"))?)),
            "--models" => { it.next(); }
            _ => usage(),
        }
    }
    let mut p = Pipeline::load(&dir)?;
    let g = faceauth_camera::ipu3::probe()?.ok_or_else(|| anyhow!("no IPU3 graph"))?;
    let ir = g.ir_sensor().ok_or_else(|| anyhow!("no IR sensor"))?;
    let (iw, ih) = g.configure(ir, None)?;
    let cam = Camera::open(&ir.video, &ir.subdev, iw, ih, ir.pixelformat, 6)?;
    let illum = Illuminator::open(&ir.subdev)?;
    let mut lp = Loop::new(cam, Exposure { exposure: 500, gain: 16, dgain: 1.0 })?;
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
    let neutral = calib::IrLook { dgain: 1.0, brightness: 0.0, contrast: 1.0 };
    while t0.elapsed() < Duration::from_secs(seconds) {
        if !lp.tick(black)? {
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
            println!("t={:4.1}s no face ({:.0} ms) exp={} gain={}", t0.elapsed().as_secs_f64(), ms, lp.exposure.exposure, lp.exposure.gain);
            continue;
        };
        // Meter on the face: map the oriented-frame box back to raw sensor coordinates
        // (orientation was transpose + both flips: raw x = W-1-oy, raw y = H-1-ox).
        {
            let (rw, rh) = (f.width as f32, f.height as f32);
            let [bx, by, bw, bh] = face.bbox;
            let (ox0, oy0, ox1, oy1) = (bx.max(0.0), by.max(0.0), (bx + bw).max(0.0), (by + bh).max(0.0));
            let x0 = (rw - 1.0 - oy1).max(0.0) as usize;
            let x1 = (rw - 1.0 - oy0).max(0.0) as usize;
            let y0 = (rh - 1.0 - ox1).max(0.0) as usize;
            let y1 = (rh - 1.0 - ox0).max(0.0) as usize;
            lp.window = Some(Window { x0, y0, x1: x1.max(x0 + 1), y1: y1.max(y0 + 1) });
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
        if best_crop.as_ref().map(|(s, _)| face.score > *s).unwrap_or(true) {
            best_crop = Some((face.score, faceauth_engine::align::align_112(&img, &face.landmarks)));
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
        println!("{} frames analysed, mean {:.1} ms per frame (detect + align + embed)", n, sum_ms / n as f64);
    }
    lp.cam.stop()?;
    Ok(())
}
