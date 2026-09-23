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
        "usage:\n  faceauth cam probe\n  faceauth engine inspect MODEL.onnx\n  faceauth engine test --models DIR IMAGE.pgm [IMAGE2.pgm]\n  faceauth engine live --models DIR [--seconds N] [--led on|off] [--save DIR]\n  faceauth liveness capture --models DIR --label TEXT --save DIR [--seconds N]\n  faceauth auth [--user NAME] [--socket PATH] [--consent]   (asks a running faceauthd; --consent = window + nod)\n  faceauth probe [--user NAME] [--socket PATH]     (one short look: is a face there?)\n  faceauth enroll [--user NAME] [--label TEXT] [--seconds N] [--count N]   (through the daemon)\n  faceauth enroll --store DIR ...                   (direct camera access, development)\n  faceauth templates delete [--user NAME]\n  faceauth models fetch [--manifest FILE] [--dir DIR]\n  faceauth doctor [--json]\n  faceauth consent-answer [--user NAME] [--dismiss]   (from the consent window; stdin: token line, then password line)\n  faceauth consent-context --action ID --message TEXT [--cookie C]   (from the polkit agent, as a request starts)\n  faceauth calibrate [--user NAME] [--gestures-only]   (root; two nods, two shakes and five everyday movements, stored with the templates)\n  faceauth presence on|off [--user NAME] [--away-seconds N]   (root; rewrites the config, restarts the service)\n  faceauth presence                                (current state)\n  faceauth verify --store DIR [--user NAME] [--seconds N] [--label TEXT --log scores.csv]\n  faceauth cam graph\n  faceauth cam test [--seconds N] [--led on|off|alt] [--snapshot DIR] [--ir-only]\n"
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
        ["enroll", rest @ ..] if !rest.contains(&"--store") => {
            // Production path: the daemon owns the camera and the store.
            let socket = PathBuf::from(opt(rest, "--socket").unwrap_or("/run/faceauth/sock"));
            let user = opt(rest, "--user").map(String::from).unwrap_or_else(target_user);
            let label = opt(rest, "--label").unwrap_or("enrol");
            let seconds: f32 = opt(rest, "--seconds").unwrap_or("12").parse()?;
            let count: usize = opt(rest, "--count").unwrap_or("10").parse()?;
            println!("Enrolling {}: look at the camera and move your head a little over the next {} s.", user, seconds as u32);
            let o = faceauth_daemon::server::enroll(&socket, &user, label, seconds, count)?;
            match &o {
                faceauth_daemon::auth::Outcome::Enrolled { added, total, consistency_min, consistency_mean, path } => {
                    println!("Saved {} templates ({} new) to {}", total, added, path);
                    println!("Template self-consistency (pairwise cosine): min {:.3} mean {:.3}", consistency_min, consistency_mean);
                    println!("{}", at_rest_note(path));
                    Ok(())
                }
                other => bail!("enrolment failed: {}", serde_json::to_string(other)?),
            }
        }
        ["enroll", rest @ ..] => enroll(rest),
        ["templates", "delete", rest @ ..] => {
            let socket = PathBuf::from(opt(rest, "--socket").unwrap_or("/run/faceauth/sock"));
            let user = opt(rest, "--user").map(String::from).unwrap_or_else(target_user);
            let o = faceauth_daemon::server::delete_templates(&socket, &user)?;
            println!("{}", serde_json::to_string(&o)?);
            Ok(())
        }
        ["models", "fetch", rest @ ..] => models_fetch(rest),
        ["doctor", rest @ ..] => doctor(rest),
        ["probe", rest @ ..] => {
            let socket = PathBuf::from(opt(rest, "--socket").unwrap_or("/run/faceauth/sock"));
            let user = opt(rest, "--user").map(String::from).unwrap_or_else(target_user);
            let o = faceauth_daemon::server::probe(&socket, &user, Duration::from_secs(5))?;
            println!("{}", serde_json::to_string(&o)?);
            Ok(())
        }
        ["presence", mode @ ("on" | "off"), rest @ ..] => {
            // Root: rewrite the [presence] keys in the config and restart the service.
            let cfg_path = opt(rest, "--config").unwrap_or("/etc/faceauth/config.toml").to_string();
            let user = opt(rest, "--user").map(String::from).unwrap_or_else(target_user);
            let away: f32 = opt(rest, "--away-seconds").unwrap_or("20").parse()?;
            let text = std::fs::read_to_string(&cfg_path).unwrap_or_default();
            let mut doc: toml::Table = toml::from_str(&text).unwrap_or_default();
            let mut presence = doc.get("presence").and_then(|v| v.as_table()).cloned().unwrap_or_default();
            presence.insert("enabled".into(), toml::Value::Boolean(*mode == "on"));
            presence.insert("user".into(), toml::Value::String(user.clone()));
            presence.insert("away_seconds".into(), toml::Value::Float(away as f64));
            // An existing lock command is the administrator's (a dev tree's
            // path rides in its third argument); only a missing one is set.
            if !presence.contains_key("lock_command") {
                presence.insert("lock_command".into(), toml::Value::Array(vec![toml::Value::String("/usr/bin/faceauth-lock-session".into()), toml::Value::String(user.clone())]));
            }
            doc.insert("presence".into(), toml::Value::Table(presence));
            std::fs::write(&cfg_path, toml::to_string_pretty(&doc)?).with_context(|| format!("write {} (run as root)", cfg_path))?;
            let st = std::process::Command::new("systemctl").args(["restart", "faceauth.service"]).status();
            println!("presence watch {} for {} (away after {} s); service restart: {}", mode, user, away, st.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string()));
            Ok(())
        }
        ["calibrate", rest @ ..] => {
            // Root: two nods, two shakes and three everyday movements, each a
            // recorded round stored with the templates; the person's floors
            // derive from them, and the margins say whether the two are apart.
            let socket = PathBuf::from(opt(rest, "--socket").unwrap_or("/run/faceauth/sock"));
            let user = opt(rest, "--user").map(String::from).unwrap_or_else(target_user);
            let gestures_only = rest.contains(&"--gestures-only");
            println!("Calibrating for {}.\n", user);
            println!("Why: a nod approves root access and a head shake refuses it, so the daemon needs to");
            println!("know how you move. It records two nods and two shakes to learn the size of yours, and");
            println!("then five ordinary movements (reading, a glance at the keyboard, talking to the screen, leaning in, a");
            println!("look to the side) to learn what");
            println!("must never count. That is how an everyday movement cannot approve or refuse something");
            println!("on your behalf. Each round is a recording of head motion for a few seconds, never an");
            println!("image, stored root-only with your templates. The window will ask for each round.\n");
            let round_name = |kind: &str| match kind { "nod" => "nod", "shake" => "shake", "read" => "reading", "glance" => "glance at the keyboard", "talk" => "talking", "lean" => "leaning in", _ => "look to the side" };
            // Run the rounds of `kinds`, then check every round of the session.
            // A kind being redone replaces this session's earlier rounds of it.
            let run = |kinds: &[&str], first_ever: bool, replace: bool| -> Result<Option<(Vec<faceauth_daemon::auth::RoundCheck>, bool)>> {
                let mut last = None;
                let mut first = first_ever;
                for (gesture, rounds, seconds) in faceauth_daemon::auth::CALIBRATION_ROUNDS {
                    if !kinds.contains(&gesture) {
                        continue;
                    }
                    for i in 1..=rounds {
                        // Replacing: the first round of a redone kind withdraws the earlier ones.
                        let o = faceauth_daemon::server::calibrate(&socket, &user, gesture, seconds, first, replace && i == 1)?;
                        first = false;
                        match &o {
                            faceauth_daemon::auth::Outcome::Calibrated { amplitude, sideways, stored, nod_floor, shake_floor, nod_margin, shake_margin, .. } => {
                                let what = round_name(gesture);
                                if matches!(gesture, "nod" | "shake") {
                                    println!("  {} {}/{}: moved {:.2} of a face width{}", what, i, rounds, amplitude, if *stored { "" } else { " (too small to count; not stored)" });
                                } else if faceauth_daemon::store::FLOOR_KINDS.contains(&gesture) {
                                    println!("  {}: moved up to {:.2} vertically, {:.2} sideways (the floors stand clear of this)", what, amplitude, sideways);
                                } else {
                                    println!("  {}: moved up to {:.2} vertically, {:.2} sideways (a big single move; refused by its shape, not its size)", what, amplitude, sideways);
                                }
                                last = Some((*nod_floor, *shake_floor, *nod_margin, *shake_margin));
                            }
                            other => println!("  {} {}/{}: {}", gesture, i, rounds, serde_json::to_string(other)?),
                        }
                    }
                }
                if let Some((n, s, nm, sm)) = last {
                    println!("\nFloors for {}: nod {:.3}, shake {:.3} (defaults {:.3} / {:.3}).", user, n, s, faceauth_daemon::consent::NodDetector::MIN_DOWN, faceauth_daemon::consent::ShakeDetector::MIN_TURN);
                    for (name, m) in [("nod", nm), ("shake", sm)] {
                        if let Some(m) = m {
                            if m >= 2.0 {
                                println!("Your {} is {:.1} times your largest everyday movement on that axis: clearly apart.", name, m);
                            } else {
                                println!("WARNING: your {} is only {:.1} times your largest everyday movement on that axis.", name, m);
                                println!("  The floor has been raised to keep that movement from counting, so a {} now has to be", name);
                                println!("  deliberate. If it stops being recognised, run this again with a bigger {} or a calmer read.", name);
                            }
                        }
                    }
                }
                // The proof: every round replayed through the real detectors at
                // these floors, the way a request would read it.
                println!("\nChecking every round against those floors...");
                match faceauth_daemon::server::calibrate_verify(&socket, &user)? {
                    faceauth_daemon::auth::Outcome::Verified { rounds, all_ok, nod_floor, shake_floor } => {
                        println!("  floors after the everyday rounds: nod {:.3}, shake {:.3}", nod_floor, shake_floor);
                        for r in &rounds {
                            let read = match (r.nods, r.shakes) { (0, 0) => "nothing".to_string(), (n, 0) => format!("{} nod(s)", n), (0, s) => format!("{} shake(s)", s), (n, s) => format!("{} nod(s) and {} shake(s)", n, s) };
                            println!("  {:<24} read as {:<24} {}", round_name(&r.kind), read, if r.ok { "ok" } else { "NOT OK" });
                        }
                        Ok(Some((rounds, all_ok)))
                    }
                    other => {
                        println!("  could not check: {}", serde_json::to_string(&other)?);
                        Ok(None)
                    }
                }
            };
            let all_kinds: Vec<&str> = faceauth_daemon::auth::CALIBRATION_ROUNDS.iter().map(|r| r.0).filter(|k| !gestures_only || matches!(*k, "nod" | "shake")).collect();
            let mut result = run(&all_kinds, true, false)?;
            let mut passes = 0;
            loop {
                let Some((rounds, all_ok)) = &result else { break };
                if *all_ok {
                    println!("\nEvery gesture round reads as its gesture and no everyday round reads as one. Calibration holds.");
                    break;
                }
                let mut redo: Vec<&str> = Vec::new();
                for r in rounds.iter().filter(|r| !r.ok) {
                    let k: &str = match r.kind.as_str() { "nod" => "nod", "shake" => "shake", "read" => "read", "glance" => "glance", "talk" => "talk", "lean" => "lean", _ => "aside" };
                    if !redo.contains(&k) {
                        redo.push(k);
                    }
                }
                println!("\nSome rounds do not read the way they should at these floors: {}.", redo.iter().map(|k| round_name(k)).collect::<Vec<_>>().join(", "));
                println!("A gesture that was not read wants to be a little clearer; an everyday movement that read as a");
                println!("gesture wants to be as ordinary as you would really do it.");
                passes += 1;
                if passes > 3 {
                    println!("Three redos already; keeping what there is. Run this again later.");
                    break;
                }
                print!("Redo those rounds now? [Enter = redo, a = accept as is and finish] ");
                use std::io::Write as _;
                std::io::stdout().flush()?;
                let mut answer = String::new();
                let interactive = std::io::stdin().read_line(&mut answer).map(|n| n > 0).unwrap_or(false);
                if !interactive || answer.trim().eq_ignore_ascii_case("a") {
                    println!("Kept as is.");
                    break;
                }
                println!();
                result = run(&redo, false, true)?;
            }
            Ok(())
        }
        ["consent-context", rest @ ..] => {
            // From the polkit agent: the action and message polkitd gave it.
            let socket = PathBuf::from(opt(rest, "--socket").unwrap_or("/run/faceauth/sock"));
            let user = opt(rest, "--user").map(String::from).unwrap_or_else(target_user);
            let o = faceauth_daemon::server::consent_context(&socket, &user, opt(rest, "--action").unwrap_or(""), opt(rest, "--message").unwrap_or(""), opt(rest, "--cookie").unwrap_or(""))?;
            println!("{}", serde_json::to_string(&o)?);
            Ok(())
        }
        ["consent-answer", rest @ ..] => {
            let socket = PathBuf::from(opt(rest, "--socket").unwrap_or("/run/faceauth/sock"));
            let user = opt(rest, "--user").map(String::from).unwrap_or_else(target_user);
            // The token came with the window's payload; without it the daemon
            // treats the answer as nobody's. It arrives on stdin, first line,
            // never on the command line (argv is readable and journaled).
            let mut token = String::new();
            std::io::stdin().read_line(&mut token)?;
            let token = token.trim_end_matches(['\n', '\r']).to_string();
            let token = if token.is_empty() { None } else { Some(token.as_str()) };
            let o = if rest.contains(&"--dismiss") {
                faceauth_daemon::server::consent_answer(&socket, &user, None, true, token)?
            } else {
                let mut pw = String::new();
                std::io::stdin().read_line(&mut pw)?;
                let pw = pw.trim_end_matches(['\n', '\r']).to_string();
                let r = faceauth_daemon::server::consent_answer(&socket, &user, Some(&pw), false, token);
                drop(pw);
                r?
            };
            println!("{}", serde_json::to_string(&o)?);
            Ok(())
        }
        ["presence"] => {
            let f = "/run/faceauth/presence.json";
            match std::fs::read_to_string(f) {
                Ok(t) => println!("{}", t.trim()),
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => println!("presence state is root-only ({}); run with sudo", f),
                Err(e) => println!("no presence state ({}): {}", f, e),
            }
            Ok(())
        }
        ["auth", rest @ ..] => {
            let socket = PathBuf::from(opt(rest, "--socket").unwrap_or("/run/faceauth/sock"));
            let user = opt(rest, "--user").map(String::from).unwrap_or_else(target_user);
            let t = Instant::now();
            let o = if rest.contains(&"--consent") {
                faceauth_daemon::server::ask_consent(&socket, &user)?
            } else {
                faceauth_daemon::server::ask(&socket, &user, Duration::from_secs(15))?
            };
            println!("{} ({:.2} s round trip)", serde_json::to_string(&o)?, t.elapsed().as_secs_f64());
            Ok(())
        }
        ["liveness", "capture", rest @ ..] => liveness_capture(rest),
        ["verify", rest @ ..] => verify(rest),
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

/// One embedded face from a capture burst.
struct Sample {
    embedding: Vec<f32>,
    score: f32,
    face_width: f32,
}

/// Stream the IR camera with the illuminator on and face-box metering, and
/// collect up to `want` embeddings of the best-scoring detections within `seconds`.
/// This is the capture the daemon runs for both enrolment and verification.
fn capture_burst(p: &mut faceauth_engine::Pipeline, seconds: u64, want: usize, min_score: f32, quiet: bool, spacing_ms: u64) -> Result<Vec<Sample>> {
    use faceauth_engine::Grey;
    let g = faceauth_camera::ipu3::probe()?.ok_or_else(|| anyhow!("no IPU3 graph"))?;
    let ir = g.ir_sensor().ok_or_else(|| anyhow!("no IR sensor"))?;
    let (iw, ih) = g.configure(ir, None)?;
    let cam = Camera::open(&ir.video, &ir.subdev, iw, ih, ir.pixelformat, 6)?;
    let illum = Illuminator::open(&ir.subdev)?;
    let mut lp = Loop::new(cam, Exposure { exposure: 500, gain: 16, dgain: 1.0 })?;
    if let Some(i) = &illum {
        i.set(true)?;
    }
    let t0 = Instant::now();
    let (mut black, mut white) = (0u16, 1023u16);
    let neutral = calib::IrLook { dgain: 1.0, brightness: 0.0, contrast: 1.0 };
    let mut out: Vec<Sample> = Vec::new();
    let mut seen = 0usize;
    let mut last_sample = Instant::now();
    while t0.elapsed() < Duration::from_secs(seconds) && out.len() < want {
        if !lp.tick(black)? {
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
            let (ox0, oy0, ox1, oy1) = (bx.max(0.0), by.max(0.0), (bx + bw).max(0.0), (by + bh).max(0.0));
            let x0 = (rw - 1.0 - oy1).max(0.0) as usize;
            let x1 = (rw - 1.0 - oy0).max(0.0) as usize;
            let y0 = (rh - 1.0 - ox1).max(0.0) as usize;
            let y1 = (rh - 1.0 - ox0).max(0.0) as usize;
            lp.window = Some(Window { x0, y0, x1: x1.max(x0 + 1), y1: y1.max(y0 + 1) });
        }
        // Skip frames before the face-box metering has had a chance to act, and
        // space samples out so an enrolment covers different poses.
        if seen <= 2 || (!out.is_empty() && last_sample.elapsed() < Duration::from_millis(spacing_ms)) {
            continue;
        }
        last_sample = Instant::now();
        if !quiet {
            println!("  t={:4.1}s sample {} score {:.2} face {:.0}px exp={} gain={}", t0.elapsed().as_secs_f64(), out.len() + 1, face.score, face.bbox[2], lp.exposure.exposure, lp.exposure.gain);
        }
        out.push(Sample { embedding: face.embedding.clone().unwrap(), score: face.score, face_width: face.bbox[2] });
    }
    if let Some(i) = &illum {
        i.set(false)?;
    }
    lp.cam.stop()?;
    Ok(out)
}

/// The person a command is about when `--user` is not given: under sudo
/// that is the person who ran sudo, not root (`sudo faceauth calibrate`
/// from the menu tunes their gestures, not root's).
fn target_user() -> String {
    std::env::var("SUDO_USER").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "user".into())
}

fn opt<'a>(rest: &'a [&str], key: &str) -> Option<&'a str> {
    rest.iter().position(|a| *a == key).and_then(|i| rest.get(i + 1).copied())
}

fn enroll(rest: &[&str]) -> Result<()> {
    use faceauth_daemon::store::{now_secs, Store, Template, UserTemplates};
    let dir = models_dir(rest);
    let store = Store::open(opt(rest, "--store").ok_or_else(|| anyhow!("--store DIR"))?)?;
    let user = opt(rest, "--user").map(String::from).unwrap_or_else(target_user);
    let label = opt(rest, "--label").unwrap_or("enrol").to_string();
    let seconds: u64 = opt(rest, "--seconds").unwrap_or("12").parse()?;
    let count: usize = opt(rest, "--count").unwrap_or("10").parse()?;
    let mut p = faceauth_engine::Pipeline::load(&dir)?;
    println!("Enrolling {}: look at the camera and move your head a little over the next {} s.", user, seconds);
    let spacing = ((seconds.saturating_sub(2)) * 1000 / count.max(1) as u64).clamp(100, 2000);
    let samples = capture_burst(&mut p, seconds, count, 0.6, false, spacing)?;
    if samples.len() < 3 {
        bail!("only {} usable frames; sit closer, face the camera, and try again", samples.len());
    }
    let mut u = store.load(&user)?.unwrap_or_else(|| UserTemplates::new(&user, faceauth_engine::embed::AURAFACE_FILE));
    if u.model != faceauth_engine::embed::AURAFACE_FILE {
        bail!("existing templates are for model {}, delete them first", u.model);
    }
    let now = now_secs();
    for s in &samples {
        // Development path (direct camera): unbound templates, usable on any camera.
        u.templates.push(Template { embedding: s.embedding.clone(), quality: s.score, face_width: s.face_width, created: now, label: label.clone(), device: None });
    }
    let (lo, mean, hi) = u.self_consistency().unwrap_or((1.0, 1.0, 1.0));
    let path = store.save(&u)?;
    println!("Saved {} templates ({} new) to {}", u.templates.len(), samples.len(), path.display());
    println!("Template self-consistency (pairwise cosine): min {:.3} mean {:.3} max {:.3}", lo, mean, hi);
    println!("{}", at_rest_note(&path.display().to_string()));
    Ok(())
}

/// What the saved path says about how the templates rest.
fn at_rest_note(path: &str) -> String {
    if path.ends_with(".cred") {
        "Templates are sealed to this machine's TPM, root-only: a copy is useless anywhere else, and only root can open one here.".into()
    } else {
        "Note: templates are plaintext at rest (root 0600): the daemon could not seal them (its log says why).".into()
    }
}

fn verify(rest: &[&str]) -> Result<()> {
    use faceauth_daemon::store::Store;
    let dir = models_dir(rest);
    let store = Store::open(opt(rest, "--store").ok_or_else(|| anyhow!("--store DIR"))?)?;
    let user = opt(rest, "--user").map(String::from).unwrap_or_else(target_user);
    let seconds: u64 = opt(rest, "--seconds").unwrap_or("5").parse()?;
    let u = store.load(&user)?.ok_or_else(|| anyhow!("no templates for {}", user))?;
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
        Some(path) => Some(std::fs::OpenOptions::new().append(true).create(true).open(path)?),
        None => None,
    };
    for (i, s) in samples.iter().enumerate() {
        let (score, idx) = u.best_match(&s.embedding).unwrap();
        best = best.max(score);
        println!("frame {}: face {:.0}px det {:.2} best template #{} cosine {:.3}", i + 1, s.face_width, s.score, idx, score);
        if let Some(f) = log.as_mut() {
            use std::io::Write;
            writeln!(f, "{},{},{},{:.3},{:.3},{:.0}", faceauth_daemon::store::now_secs(), label, i + 1, score, s.score, s.face_width)?;
        }
    }
    println!("best {:.3} over {} frames in {:.1} s ({} templates)", best, samples.len(), elapsed, u.templates.len());
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
    let illum = Illuminator::open(&ir.subdev)?.ok_or_else(|| anyhow!("IR sensor has no strobe control"))?;
    // Settle exposure on the subject with the LEDs steady (face-box metering),
    // then freeze it: the loop must not chase the alternation.
    let mut lp = Loop::new(cam, Exposure { exposure: 500, gain: 16, dgain: 1.0 })?;
    illum.set(true)?;
    let settle = Instant::now();
    let neutral = calib::IrLook { dgain: 1.0, brightness: 0.0, contrast: 1.0 };
    while settle.elapsed() < Duration::from_millis(5000) {
        if !lp.tick(0)? || lp.frames % 5 != 0 {
            continue;
        }
        let f = &lp.frame;
        let mut g8 = Grey::new(f.width, f.height);
        calib::ir_to_grey8(&f.px, 0, 1023, neutral, &mut g8.data);
        let img = g8.oriented(true, true, true);
        if let Some(face) = p.detector.detect(&img, 0.5)?.into_iter().max_by(|a, b| a.score.total_cmp(&b.score)) {
            let (rw, rh) = (f.width as f32, f.height as f32);
            let [bx, by, bw, bh] = face.bbox;
            let (ox0, oy0, ox1, oy1) = (bx.max(0.0), by.max(0.0), (bx + bw).max(0.0), (by + bh).max(0.0));
            let x0 = (rw - 1.0 - oy1).max(0.0) as usize;
            let x1 = (rw - 1.0 - oy0).max(0.0) as usize;
            let y0 = (rh - 1.0 - ox1).max(0.0) as usize;
            let y1 = (rh - 1.0 - ox0).max(0.0) as usize;
            lp.window = Some(Window { x0, y0, x1: x1.max(x0 + 1), y1: y1.max(y0 + 1) });
        }
    }
    println!("exposure settled at {} gain {} (face-box mean {:.2})", lp.exposure.exposure, lp.exposure.gain, lp.metering.mean);
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
        let Some((prev_img, prev_mean)) = prev.replace((img.clone(), mean)) else { continue };
        // A lit frame is the brighter of two consecutive frames by a clear margin.
        if mean < prev_mean * 1.15 {
            continue;
        }
        let (lit, unlit) = (&img, &prev_img);
        let faces = p.detector.detect(lit, 0.6)?;
        let Some(face) = faces.into_iter().max_by(|a, b| a.score.total_cmp(&b.score)) else { continue };
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
            let (x, y) = (fwd[0][0] * ex + fwd[0][1] * ey + fwd[0][2], fwd[1][0] * ex + fwd[1][1] * ey + fwd[1][2]);
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
            if cnt == 0 { 0.0 } else { (mx / (sum / cnt as f32).max(1.0)) as f64 }
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
            let (rx_lo, ry_lo, rx_hi, ry_hi) = (bw * scale_lo / 2.0, bh * scale_lo / 2.0, bw * scale_hi / 2.0, bh * scale_hi / 2.0);
            let (x0, x1) = ((cx - rx_hi).max(0.0) as i32, (cx + rx_hi).min(fw as f32 - 1.0) as i32);
            let (y0, y1) = ((cy - ry_hi).max(0.0) as i32, (cy + ry_hi).min(fh as f32 - 1.0) as i32);
            let mut y = y0;
            while y <= y1 {
                let mut x = x0;
                while x <= x1 {
                    let inside_lo = ((x as f32 - cx).abs() < rx_lo) && ((y as f32 - cy).abs() < ry_lo);
                    if !inside_lo {
                        s += flash_at(x, y);
                        n += 1;
                    }
                    x += 2;
                }
                y += 2;
            }
            if n == 0 { 0.0 } else { s / n as f32 }
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
        let fr = faceauth_engine::liveness::FlashResponse::measure(lit, unlit, &face, lp.exposure.exposure, lp.exposure.gain.max(16));
        let surround = fr.surround;
        let reflectance = fr.reflectance;
        let gn_r = glint_native(face.landmarks[0][0], face.landmarks[0][1]);
        let gn_l = glint_native(face.landmarks[1][0], face.landmarks[1][1]);
        pairs += 1;
        println!("pair {:2} lit {:5.1} gain {:4.2} ratio_hp {:.4} diff_hp {:.4} glint {:.2}/{:.2} native {:.2}/{:.2} surround {:.3} refl {:.4} face {:.0}px exp {} verdict {:?}", pairs, lm, flash_gain, ratio_hp, diff_hp, glint_r, glint_l, gn_r, gn_l, surround, reflectance, bw, lp.exposure.exposure, fr.verdict());
        csv += &format!("{},{},{:.1},{:.1},{:.3},{:.4},{:.4},{:.2},{:.2},{:.2},{:.2},{:.3},{:.4},{:.0},{}\n", label, pairs, lm, um, flash_gain, ratio_hp, diff_hp, glint_r, glint_l, gn_r, gn_l, surround, reflectance, bw, lp.exposure.exposure);
        if pairs <= 3 {
            lit_c.write_pgm(save.join(format!("{}-{}-lit.pgm", label, pairs)))?;
            unlit_c.write_pgm(save.join(format!("{}-{}-unlit.pgm", label, pairs)))?;
            let mut r8 = Grey::new(112, 112);
            let (rmin, rmax) = ratio.iter().fold((f32::MAX, f32::MIN), |(a, b), &v| (a.min(v), b.max(v)));
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
    println!("{} lit/unlit pairs; crops and {}.csv in {}", pairs, label, save.display());
    Ok(())
}

/// Download the model weights named in the manifest, verify size and SHA-256.
fn models_fetch(rest: &[&str]) -> Result<()> {
    let manifest = PathBuf::from(opt(rest, "--manifest").unwrap_or("/usr/share/faceauth/models.toml"));
    let dir = PathBuf::from(opt(rest, "--dir").unwrap_or("/usr/share/faceauth/models"));
    let text = std::fs::read_to_string(&manifest).with_context(|| manifest.display().to_string())?;
    let doc: toml::Value = toml::from_str(&text)?;
    let models = doc.get("model").and_then(|m| m.as_array()).ok_or_else(|| anyhow!("manifest has no [[model]] entries"))?;
    std::fs::create_dir_all(&dir)?;
    let mut failed = 0;
    for m in models {
        let name = m.get("name").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("model without name"))?;
        let url = m.get("url").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("{}: no url", name))?;
        let sha = m.get("sha256").and_then(|v| v.as_str()).ok_or_else(|| anyhow!("{}: no sha256", name))?;
        let size = m.get("size").and_then(|v| v.as_integer()).unwrap_or(0) as u64;
        let dest = dir.join(name);
        if dest.exists() && sha256_file(&dest)? == sha {
            println!("{}: present and verified", name);
            continue;
        }
        println!("{}: downloading {} bytes from {}", name, size, url);
        let tmp = dir.join(format!("{}.part", name));
        // Absolute paths and a clean environment: this runs as root.
        let status = std::process::Command::new("/usr/bin/curl").env_clear().env("PATH", "/usr/bin:/bin").args(["-sSL", "--fail", "-o"]).arg(&tmp).arg(url).status().context("run curl")?;
        if !status.success() {
            println!("{}: download failed ({})", name, status);
            failed += 1;
            continue;
        }
        let got = sha256_file(&tmp)?;
        let len = std::fs::metadata(&tmp)?.len();
        if got != sha || (size > 0 && len != size) {
            println!("{}: VERIFICATION FAILED (sha256 {} size {}), not installed", name, got, len);
            let _ = std::fs::remove_file(&tmp);
            failed += 1;
            continue;
        }
        std::fs::rename(&tmp, &dest)?;
        println!("{}: verified and installed ({} bytes)", name, len);
    }
    if failed > 0 {
        bail!("{} model(s) failed", failed);
    }
    Ok(())
}

fn sha256_file(p: &std::path::Path) -> Result<String> {
    let out = std::process::Command::new("/usr/bin/sha256sum").env_clear().env("PATH", "/usr/bin:/bin").arg(p).output().context("run sha256sum")?;
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text.split_whitespace().next().unwrap_or("").to_string())
}

#[derive(serde::Serialize)]
struct Check {
    id: &'static str,
    status: &'static str,
    detail: String,
}

/// Stable check identifiers are public API; add, never rename.
fn doctor(rest: &[&str]) -> Result<()> {
    let json = rest.contains(&"--json");
    let user = target_user();
    let mut checks: Vec<Check> = Vec::new();
    let mut push = |id: &'static str, status: &'static str, detail: String| checks.push(Check { id, status, detail });

    // camera
    match faceauth_camera::ipu3::probe() {
        Ok(Some(g)) => match g.ir_sensor() {
            Some(ir) => {
                let strobe = faceauth_camera::Illuminator::open(&ir.subdev).ok().flatten().is_some();
                push("camera.ir", "pass", format!("{} on {} ({}x{})", ir.name, ir.video.display(), ir.width, ir.height));
                push("camera.illuminator", if strobe { "pass" } else { "warn" }, if strobe { "strobe control present".into() } else { "no strobe control: ambient light only, liveness gate off".into() });
                push("camera.rgb", if g.colour_sensor().is_some() { "pass" } else { "warn" }, g.colour_sensor().map(|c| c.name.clone()).unwrap_or_else(|| "no front colour sensor".into()));
            }
            None => push("camera.ir", "fail", "IPU3 graph found but no front IR sensor".into()),
        },
        Ok(None) => push("camera.ir", "unknown", "no IPU3 graph; UVC IR cameras need ir_video in the config".into()),
        Err(e) => push("camera.ir", "fail", e.to_string()),
    }
    // models
    let manifest = PathBuf::from("/usr/share/faceauth/models.toml");
    let models_dir = PathBuf::from(std::env::var("FACEAUTH_MODELS").unwrap_or_else(|_| "/usr/share/faceauth/models".into()));
    match std::fs::read_to_string(&manifest).ok().and_then(|t| toml::from_str::<toml::Value>(&t).ok()) {
        Some(doc) => {
            for m in doc.get("model").and_then(|m| m.as_array()).cloned().unwrap_or_default() {
                let name = m.get("name").and_then(|v| v.as_str()).unwrap_or("?").to_string();
                let sha = m.get("sha256").and_then(|v| v.as_str()).unwrap_or("").to_string();
                let lic = m.get("license").and_then(|v| v.as_str()).unwrap_or("?");
                let p = models_dir.join(&name);
                let (st, d) = if !p.exists() { ("fail", "missing".to_string()) } else if sha256_file(&p).unwrap_or_default() != sha { ("fail", "checksum mismatch".into()) } else { ("pass", format!("verified, {}", lic)) };
                push("models.file", st, format!("{}: {}", name, d));
            }
        }
        None => push("models.manifest", "unknown", format!("no manifest at {}", manifest.display())),
    }
    // daemon
    let socket = PathBuf::from("/run/faceauth/sock");
    match faceauth_daemon::server::ping(&socket, &user) {
        Ok(faceauth_daemon::auth::Outcome::Pong { version, model, templates, sealed, unbound, floors }) => {
            push("daemon.running", "pass", format!("faceauthd {} answering on {}", version, socket.display()));
            push("templates.user", if templates > 0 { "pass" } else { "warn" }, format!("{} template(s) for {} ({})", templates, user, model));
            if templates > 0 {
                push("templates.at_rest", if sealed { "pass" } else { "warn" }, if sealed { "sealed to the TPM, root-only: a copy is useless off this machine, and only root can open one here".into() } else { "plaintext at rest (root 0600): the daemon could not seal (its log says why)".into() });
                push("gestures.calibrated", if floors.is_some() { "pass" } else { "info" }, match floors { Some((n, s)) => format!("this user's floors: nod {:.3}, shake {:.3}", n, s), None => "default floors (run 'sudo faceauth calibrate' for this user's own)".into() });
                push("templates.camera", if unbound == 0 { "pass" } else { "warn" }, if unbound == 0 { "every template is bound to the camera that enrolled it".into() } else { format!("{} of {} template(s) predate camera binding and match on any camera; the next enrolment binds them", unbound, templates) });
            }
        }
        Ok(o) => push("daemon.running", "warn", format!("unexpected reply {}", serde_json::to_string(&o).unwrap_or_default())),
        Err(e) => push("daemon.running", "fail", format!("{}", e)),
    }
    match std::fs::read_to_string("/etc/faceauth/config.toml").ok().and_then(|t| toml::from_str::<toml::Value>(&t).ok()) {
        Some(c) => {
            let req = c.get("liveness_required").and_then(|v| v.as_bool()).unwrap_or(true);
            let on = c.get("liveness").and_then(|v| v.as_bool()).unwrap_or(true);
            push("liveness.policy", if on && req { "pass" } else { "warn" }, format!("liveness = {}, liveness_required = {}{}", on, req, if !(on && req) { ": a print in front of the camera can authenticate" } else { "" }));
        }
        None => push("liveness.policy", "unknown", "config not readable".into()),
    }
    // PAM wiring
    for (id, path, want_deny) in [("pam.sudo", "/etc/pam.d/sudo", false), ("pam.polkit", "/etc/pam.d/polkit-1", false), ("pam.lock", "/etc/pam.d/omarchy-lock-face", true), ("pam.greeter", "/etc/pam.d/sddm", false)] {
        match std::fs::read_to_string(path) {
            Ok(t) => {
                let has = t.lines().any(|l| l.contains("pam_faceauth.so") && !l.trim_start().starts_with('#'));
                let deny = t.lines().any(|l| l.contains("pam_deny.so"));
                let prompt = t.lines().any(|l| l.contains("pam_faceauth.so") && l.contains("prompt"));
                let consent = t.lines().any(|l| l.contains("pam_faceauth.so") && l.contains("consent"));
                let elevation = id == "pam.sudo" || id == "pam.polkit";
                let st = if !has { if id == "pam.greeter" { "info" } else { "warn" } } else if want_deny && !deny { "fail" } else { "pass" };
                let mut d = if has { "wired".to_string() } else { "not wired".to_string() };
                if has && elevation { d += if consent { ", consent (window + nod)" } else if prompt { ", prompt (Enter to scan)" } else { ", NO consent or prompt: scans on presence" }; }
                if has && want_deny { d += if deny { ", closed by pam_deny" } else { ", NOT closed by pam_deny: an ignored module would read as success" }; }
                push(id, st, d);
            }
            Err(_) => push(id, "warn", "no file (not wired)".into()),
        }
    }
    push("pam.faillock", "warn", "a face match bypasses pam_faillock and never resets its counter; a locked-out password stays locked out".into());
    // TPM
    let tpm = std::path::Path::new("/dev/tpmrm0").exists() || std::path::Path::new("/dev/tpm0").exists();
    push("tpm.present", if tpm { "pass" } else { "warn" }, if tpm { "TPM device present (templates.at_rest says whether the daemon can use it)".into() } else { "no TPM device; templates stay plaintext (root 0600)".into() });
    // module
    push("pam.module", if std::path::Path::new("/usr/lib/security/pam_faceauth.so").exists() { "pass" } else { "fail" }, "/usr/lib/security/pam_faceauth.so".into());

    if json {
        println!("{}", serde_json::to_string_pretty(&checks)?);
    } else {
        for c in &checks {
            println!("{:<7} {:<20} {}", c.status.to_uppercase(), c.id, c.detail);
        }
    }
    let fails = checks.iter().filter(|c| c.status == "fail").count();
    if fails > 0 {
        std::process::exit(1);
    }
    Ok(())
}
