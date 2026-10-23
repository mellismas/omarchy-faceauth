//! `faceauth cam probe` and `faceauth cam graph`: what the capture crate
//! finds on this machine, read straight from the media and video nodes.
//! `faceauth cam ir-rule`: the udev rule that locks the IR capture node to
//! root (fix round 11, Mike's ruling; `faceauth_camera::irlock`), which
//! face setup writes.

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

/// The capture node faceauth reads its IR frames from, as the daemon finds
/// it (`capture.rs`): the config's `ir_video`, with the formats it lists,
/// else the IPU3 graph's IR sensor's CIO2 node, which carries the one
/// format whose media-bus code is the sensor's (a CIO2 port streams only
/// that: drivers/media/pci/intel/ipu3/ipu3-cio2.c,
/// `cio2_video_link_validate`; the node lists every CIO2 format, colour
/// ones included, whatever sensor is on its port, `cio2_v4l2_enum_fmt`).
pub(super) fn ir_node_now() -> Result<faceauth_camera::irlock::IrNode> {
    use anyhow::anyhow;
    use faceauth_camera::irlock::node_facts;
    let class = std::path::Path::new("/sys/class/video4linux");
    let conf = std::fs::read_to_string("/etc/faceauth/config.toml")
        .ok()
        .and_then(|t| toml::from_str::<toml::Value>(&t).ok());
    let base = |p: &std::path::Path| {
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| anyhow!("{}: not a device node", p.display()))
    };
    if let Some(v) = conf
        .as_ref()
        .and_then(|c| c.get("ir_video"))
        .and_then(|v| v.as_str())
    {
        // The node itself, never a link's name for it (fix round 12, Codex
        // 3, Opus N3): the canonical path, opened, and its device number
        // from that descriptor, which the class entry must carry.
        let path = std::fs::canonicalize(v).map_err(|e| anyhow!("ir_video {}: {}", v, e))?;
        let vd = faceauth_camera::v4l2::VideoDevice::open(&path)?;
        let formats = vd.formats()?.into_iter().map(|(f, _)| f).collect();
        return Ok(node_facts(
            class,
            &base(&path)?,
            formats,
            vd.device_number(),
        ));
    }
    let g = faceauth_camera::ipu3::probe()?
        .ok_or_else(|| anyhow!("no IR camera: no ir_video in the config and no IPU3 graph"))?;
    let ir = g
        .ir_sensor()
        .ok_or_else(|| anyhow!("no IR sensor in the IPU3 graph"))?;
    // The CIO2 entity's own device number, from the media controller.
    Ok(node_facts(
        class,
        &base(&ir.video)?,
        vec![ir.pixelformat],
        Some((ir.cio2.major, ir.cio2.minor)),
    ))
}

/// The video group's id, which udev gives capture nodes
/// (50-udev-default.rules); None where there is no such group.
pub(super) fn video_gid() -> Option<u32> {
    nix::unistd::Group::from_name("video")
        .ok()
        .flatten()
        .map(|g| g.gid.as_raw())
}

/// `faceauth cam ir-reset` (root; fix round 13, Codex 6, Opus nit): once
/// face removal has deleted the rule, the IR capture node faceauth's own
/// detection names is given back what udev and logind give a capture node
/// (`irlock::give_back`): root's, the video group's, no ACL, so the add
/// event after has uaccess write the seat user's entry afresh. Exit 0 when
/// it was given back or had nothing the lock left; the reason on stderr
/// and exit 3 when it is left as it is.
pub(super) fn cam_ir_reset() -> Result<()> {
    use faceauth_camera::irlock::{give_back, GiveBack, RULE_FILE};
    let rule_file = std::fs::symlink_metadata(RULE_FILE).is_ok();
    let why = match ir_node_now() {
        Ok(node) => match give_back(&node, rule_file, video_gid()) {
            Ok(GiveBack::Open) => {
                println!(
                    "/dev/{} holds nothing of the lock; left as it is",
                    node.node
                );
                return Ok(());
            }
            Ok(GiveBack::Reset { gid, mode }) => {
                println!(
                    "/dev/{} given back: root, group {}, mode {:04o}, no ACL; an add event has udev write the seat user's access",
                    node.node, gid, mode
                );
                return Ok(());
            }
            Err(why) => why,
        },
        Err(e) => format!("{:#}", e),
    };
    eprintln!("the IR capture node is left as it is: {}", why);
    std::process::exit(3);
}

/// `faceauth cam ir-rule`: the rule on stdout, or the reason the node is
/// left open on stderr and exit 3.
pub(super) fn cam_ir_rule() -> Result<()> {
    let why = match ir_node_now() {
        Ok(node) => match faceauth_camera::irlock::rule_for(&node) {
            Ok(rule) => {
                println!("{}", rule);
                return Ok(());
            }
            Err(why) => why,
        },
        Err(e) => format!("{:#}", e),
    };
    eprintln!("the IR capture node is left open: {}", why);
    std::process::exit(3);
}
