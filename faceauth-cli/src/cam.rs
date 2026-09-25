//! `faceauth cam probe` and `faceauth cam graph`: what the capture crate
//! finds on this machine, read straight from the media and video nodes.

use anyhow::Result;
use faceauth_camera::ipu3::SensorKind;

pub(super) fn cam_graph() -> Result<()> {
    use faceauth_camera::media::MediaDevice;
    for path in MediaDevice::enumerate() {
        let md = MediaDevice::open(&path)?;
        let (driver, model, bus) = md.info()?;
        println!("{}: {} {} {}", path.display(), driver, model, bus);
        let ents = md.entities()?;
        for e in &ents {
            println!(
                "  [{}] {:<24} pads {} links {} dev {:?}",
                e.id,
                e.name,
                e.pads,
                e.links,
                e.dev_node()
            );
            for l in md.links(e)? {
                let name = |id: u32| {
                    ents.iter()
                        .find(|x| x.id == id)
                        .map(|x| x.name.clone())
                        .unwrap_or_else(|| id.to_string())
                };
                println!(
                    "      {}:{} -> {}:{} flags 0x{:x}",
                    name(l.source_entity),
                    l.source_pad,
                    name(l.sink_entity),
                    l.sink_pad,
                    l.flags
                );
            }
        }
    }
    Ok(())
}

pub(super) fn cam_probe() -> Result<()> {
    let p = faceauth_camera::probe()?;
    println!("video nodes:");
    for (path, driver, card, fmts) in &p.video_nodes {
        println!(
            "  {:<14} {:<12} {:<40} {}",
            path.display(),
            driver,
            card,
            fmts.join(" ")
        );
    }
    match &p.ipu3 {
        None => println!("ipu3: none"),
        Some(g) => {
            println!("ipu3: {}", g.media.display());
            for s in &g.sensors {
                println!(
                    "  {:<9} {:<9} {:<16} port {} subdev {} video {} {}x{} mbus 0x{:04x} -> {}",
                    format!("{:?}", s.kind),
                    s.orientation
                        .map(|o| format!("{:?}", o))
                        .unwrap_or_else(|| "-".into()),
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
                    // A read of the control list, never an `Illuminator`:
                    // dropping one switches the strobe off under a running
                    // daemon's gate (J22).
                    if faceauth_camera::has_strobe(&s.subdev)? {
                        println!("            illuminator: strobe controls present");
                    } else {
                        println!("            illuminator: no strobe control (ambient only)");
                    }
                }
            }
        }
    }
    Ok(())
}
