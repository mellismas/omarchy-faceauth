//! The IR capture node's lock (Mike's ruling, fix round 11).
//!
//! The packaged rule (`72-faceauth-ir.rules`) makes the IR sensor's
//! control node root's. The capture node its frames arrive on, which the
//! seat user could otherwise stream from, is locked too, but narrowly: at
//! setup, exactly the node faceauth itself reads its IR frames from (its
//! own detection: the config's `ir_video`, else the IPU3 graph's IR sensor,
//! `ipu3.rs`, whose `Y10` media-bus code means infrared), and only when
//! that node carries infrared or grey formats and no colour one. The rule
//! pins the node by attributes that do not move between boots (a CIO2
//! port's name and the IPU3's PCI function; a USB camera's port, vendor,
//! product and node index), never by its number. The setup script writes
//! it to `RULE_FILE` and face removal deletes it, then gives the node back
//! what udev and logind give a capture node (`give_back`, fix round 13: the
//! lock's mode shut the seat user's ACL entry, which uaccess never redoes,
//! and only an add event sets a video node's group). Anything unclear leaves
//! the node open, with the reason doctor gives. Nothing here ever names
//! an RGB webcam, a CSI-2 receiver subdev or a media device: the rule
//! matches `video*` nodes only.

use std::path::{Path, PathBuf};

/// Where the setup script writes the rule. The name sorts it between
/// 70-uaccess.rules, which adds the tag, and 73-seat-late.rules, which
/// turns the tag into an ACL, as the packaged rule does.
pub const RULE_FILE: &str = "/etc/udev/rules.d/72-faceauth-ir-node.rules";

/// How a node is pinned in its rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pin {
    /// A function of a PCI device (the IPU3's CIO2), by its address.
    Pci { slot: String },
    /// A USB camera, by the interface the node is on (fix round 12: two
    /// interfaces of one camera can each have capture index 0), and the
    /// camera's port and its vendor and product ids.
    Usb {
        interface: String,
        port: String,
        vendor: String,
        product: String,
    },
}

/// What is known about the node faceauth reads its IR frames from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrNode {
    /// The node's name under /dev (`video1`).
    pub node: String,
    /// Its `name` attribute (`ipu3-cio2 1`).
    pub name: String,
    /// Its `index` attribute: its place among its device's nodes.
    pub index: Option<u32>,
    /// The formats a stream on it can carry.
    pub formats: Vec<u32>,
    /// How to pin it, when sysfs says.
    pub pin: Option<Pin>,
    /// The class entry's `dev` is the device number of the node that was
    /// opened and checked (fix round 12, Codex 3, Opus N3).
    pub same_node: bool,
    /// The class entry's device number (major, minor).
    pub dev: Option<(u32, u32)>,
}

/// Whether a pixel format is infrared or grey: luma only, of any depth or
/// packing. Every other format counts as colour.
pub fn is_ir_format(f: u32) -> bool {
    use crate::sys::*;
    [
        V4L2_PIX_FMT_GREY,
        V4L2_PIX_FMT_Y10,
        V4L2_PIX_FMT_Y16,
        V4L2_PIX_FMT_IPU3_Y10,
        fourcc(b'Y', b'1', b'2', b' '),
        fourcc(b'Y', b'1', b'0', b'P'),
        fourcc(b'Y', b'1', b'0', b'B'),
        fourcc(b'Y', b'8', b'I', b' '),
        fourcc(b'Y', b'1', b'2', b'I'),
        fourcc(b'Y', b'1', b'6', b'I'),
    ]
    .contains(&f)
}

/// The facts sysfs gives about `node` under `class` (/sys/class/video4linux)
/// with `formats` as the formats it carries, read from the device whose
/// number (major, minor) is `rdev`.
pub fn node_facts(class: &Path, node: &str, formats: Vec<u32>, rdev: Option<(u32, u32)>) -> IrNode {
    let dir = class.join(node);
    let attr = |p: &Path, n: &str| {
        std::fs::read_to_string(p.join(n))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let subsystem = |d: &Path| {
        std::fs::read_link(d.join("subsystem"))
            .ok()
            .and_then(|l| l.file_name().map(|n| n.to_string_lossy().into_owned()))
    };
    let device: Option<PathBuf> = std::fs::canonicalize(dir.join("device")).ok();
    let pin = device.as_deref().and_then(|d| {
        let base = d.file_name()?.to_string_lossy().into_owned();
        match subsystem(d).as_deref() {
            Some("pci") => Some(Pin::Pci { slot: base }),
            Some("usb") if base.contains(':') => {
                let parent = d.parent()?;
                (subsystem(parent).as_deref() == Some("usb")).then_some(())?;
                Some(Pin::Usb {
                    interface: base,
                    port: parent.file_name()?.to_string_lossy().into_owned(),
                    vendor: attr(parent, "idVendor")?,
                    product: attr(parent, "idProduct")?,
                })
            }
            _ => None,
        }
    });
    let dev = attr(&dir, "dev").and_then(|d| {
        let (major, minor) = d.split_once(':')?;
        Some((major.parse::<u32>().ok()?, minor.parse::<u32>().ok()?))
    });
    IrNode {
        node: node.to_string(),
        name: attr(&dir, "name").unwrap_or_default(),
        index: attr(&dir, "index").and_then(|s| s.parse().ok()),
        formats,
        pin,
        same_node: dev.is_some() && dev == rdev,
        dev,
    }
}

/// A value udev can match as written: letters, digits, spaces and
/// `:._-`, nothing that quotes, globs or escapes.
fn safe(v: &str) -> bool {
    !v.is_empty()
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b" :._-".contains(&b))
}

/// The rule that locks `n` to root, or why it is left open: one line, or
/// for a USB camera two, the first marking the node by its interface and
/// the second locking only what it marked, since udev matches one line's
/// parent keys on one ancestor alone (udev(7), "KERNELS", "ATTRS").
pub fn rule_for(n: &IrNode) -> Result<String, String> {
    if !n.same_node {
        return Err(format!(
            "/dev/{} is not the node whose formats were read (the class entry's device number differs)",
            n.node
        ));
    }
    if n.formats.is_empty() {
        return Err(format!(
            "/dev/{} offers no format faceauth could read",
            n.node
        ));
    }
    let colour: Vec<String> = n
        .formats
        .iter()
        .filter(|f| !is_ir_format(**f))
        .map(|f| crate::sys::fourcc_str(*f).trim().to_string())
        .collect();
    if !colour.is_empty() {
        return Err(format!(
            "/dev/{} offers colour formats too ({}), so it may be a webcam's",
            n.node,
            colour.join(", ")
        ));
    }
    const LOCK: &str = r#"TAG-="uaccess", GROUP="root", MODE="0600""#;
    match &n.pin {
        Some(Pin::Pci { slot }) => {
            if !safe(&n.name) || !safe(slot) {
                return Err(format!(
                    "/dev/{}'s attributes are not ones udev could match safely",
                    n.node
                ));
            }
            Ok(format!(
                r#"ACTION!="remove", SUBSYSTEM=="video4linux", KERNEL=="video*", ATTR{{name}}=="{}", SUBSYSTEMS=="pci", KERNELS=="{}", {}"#,
                n.name, slot, LOCK
            ))
        }
        Some(Pin::Usb {
            interface,
            port,
            vendor,
            product,
        }) => {
            let Some(index) = n.index else {
                return Err(format!(
                    "/dev/{} has no index, nothing stable to pin it by among its camera's nodes",
                    n.node
                ));
            };
            if ![interface, port, vendor, product].iter().all(|v| safe(v)) {
                return Err(format!(
                    "/dev/{}'s attributes are not ones udev could match safely",
                    n.node
                ));
            }
            Ok(format!(
                concat!(
                    r#"ACTION!="remove", SUBSYSTEM=="video4linux", KERNEL=="video*", ATTR{{index}}=="{}", SUBSYSTEMS=="usb", KERNELS=="{}", ENV{{FACEAUTH_IR_NODE}}="1""#,
                    "\n",
                    r#"ACTION!="remove", SUBSYSTEM=="video4linux", KERNEL=="video*", ENV{{FACEAUTH_IR_NODE}}=="1", SUBSYSTEMS=="usb", KERNELS=="{}", ATTRS{{idVendor}}=="{}", ATTRS{{idProduct}}=="{}", {}"#
                ),
                index, interface, port, vendor, product, LOCK
            ))
        }
        None => Err(format!(
            "/dev/{} is not on a PCI or USB device sysfs names, so there is nothing stable to pin it by",
            n.node
        )),
    }
}

/// A node's access ACL as the kernel keeps it (`system.posix_acl_access`:
/// a little-endian version 2 header and 8-byte entries of tag, permissions
/// and id; include/uapi/linux/posix_acl_xattr.h, posix_acl.h): how many
/// named users it grants, and its mask's permissions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Acl {
    pub named_users: usize,
    pub mask: Option<u16>,
}

/// `Acl` from the xattr's bytes; None for anything not of that form.
pub fn parse_acl(b: &[u8]) -> Option<Acl> {
    const ACL_USER: u16 = 0x02;
    const ACL_MASK: u16 = 0x10;
    let (head, entries) = b.split_at_checked(4)?;
    if u32::from_le_bytes(head.try_into().ok()?) != 2 || !entries.len().is_multiple_of(8) {
        return None;
    }
    let mut acl = Acl {
        named_users: 0,
        mask: None,
    };
    for e in entries.as_chunks::<8>().0 {
        match u16::from_le_bytes([e[0], e[1]]) {
            ACL_USER => acl.named_users += 1,
            ACL_MASK => acl.mask = Some(u16::from_le_bytes([e[2], e[3]])),
            _ => {}
        }
    }
    Some(acl)
}

/// What the kernel holds of a node's access: whether it is a character
/// device, its device number, mode bits, group and access ACL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeAccess {
    pub char_device: bool,
    pub rdev: (u32, u32),
    pub mode: u32,
    pub gid: u32,
    pub acl: Option<Acl>,
}

/// `path` opened as a path only, without following a link: what the
/// give-back reads and changes, so it changes the node it read.
pub fn open_node(path: &Path) -> std::io::Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    // SAFETY: a NUL-terminated path and flags.
    let fd = unsafe {
        libc::open(
            c.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a new descriptor nothing else owns.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// The node's own path through its descriptor (`/proc/self/fd/N`), for
/// the calls that take a path: it reaches the inode the descriptor holds,
/// whatever the name now names.
fn fd_path(fd: std::os::fd::BorrowedFd<'_>) -> std::ffi::CString {
    use std::os::fd::AsRawFd;
    std::ffi::CString::new(format!("/proc/self/fd/{}", fd.as_raw_fd())).unwrap_or_default()
}

/// The access ACL's xattr name.
const ACL_XATTR: &std::ffi::CStr = c"system.posix_acl_access";

/// `NodeAccess` of the node `fd` holds (opened by `open_node`).
pub fn node_access(fd: std::os::fd::BorrowedFd<'_>) -> std::io::Result<NodeAccess> {
    use std::os::fd::AsRawFd;
    // SAFETY: an all-zero stat is a valid out-parameter.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a descriptor and a valid out-pointer.
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buf = [0u8; 4 + 8 * 64];
    let path = fd_path(fd);
    // SAFETY: a path, a name, a buffer and its length.
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            ACL_XATTR.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    Ok(NodeAccess {
        char_device: st.st_mode & libc::S_IFMT == libc::S_IFCHR,
        rdev: (libc::major(st.st_rdev), libc::minor(st.st_rdev)),
        mode: st.st_mode & 0o7777,
        gid: st.st_gid,
        acl: usize::try_from(n).ok().and_then(|n| parse_acl(&buf[..n])),
    })
}

/// Whether `a` is still what the IR capture node's lock left (fix round
/// 13, Codex 6, Opus nit): root's group on a node udev gives the video
/// group, which 50-udev-default.rules sets on add events only (systemd
/// v262 rules.d/50-udev-default.rules.in; on a change no rule sets a group
/// or mode and udev applies none, src/udev/udev-node.c,
/// `udev_node_apply_permissions_impl`); or named users under a mask
/// without read and write, which chmod 0600 made of the seat user's
/// entry and which uaccess, finding the entry there, never recalculates
/// (src/shared/acl-util.c, `devnode_acl`).
pub fn lock_left(a: &NodeAccess, video_gid: Option<u32>) -> bool {
    let rw = 0o6;
    (video_gid.is_some_and(|v| v != 0) && a.gid == 0)
        || a.acl
            .is_some_and(|acl| acl.named_users > 0 && acl.mask.is_some_and(|m| m & rw != rw))
}

/// What giving the node back does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GiveBack {
    /// Nothing the lock left: left as it is.
    Open,
    /// Owner root, this group and mode, and no access ACL.
    Reset { gid: u32, mode: u32 },
}

/// What `give_back` does with node `n` (faceauth's own detection's,
/// `node_facts`), `rule_file` whether `RULE_FILE` is there, `a` the
/// opened node's access, and `video_gid` the video group's id: the decision
/// alone. Only a node face setup locks (`rule_for`: IR alone, the node
/// checked, never a webcam's), only the one opened, a character device, and
/// only with no rule file to lock it again. What it is given is what udev
/// and logind give a capture node: root's, the video group (or root's, with
/// none) with read and write for it (`udev_node_apply_permissions_impl`
/// "upgrades" a mode for a group to 0660), and no ACL, so the add event
/// after has uaccess write the seat user's entry afresh, mask and all.
pub fn give_back_plan(
    n: &IrNode,
    rule_file: bool,
    a: &NodeAccess,
    video_gid: Option<u32>,
) -> Result<GiveBack, String> {
    if rule_file {
        return Err(format!(
            "{} is still there, and would lock /dev/{} again",
            RULE_FILE, n.node
        ));
    }
    rule_for(n).map_err(|why| format!("not a node face setup locks: {}", why))?;
    if !a.char_device {
        return Err(format!("/dev/{} is not a character device", n.node));
    }
    if n.dev != Some(a.rdev) {
        return Err(format!(
            "/dev/{} is not the node whose formats were read (its device number differs)",
            n.node
        ));
    }
    if !lock_left(a, video_gid) {
        return Ok(GiveBack::Open);
    }
    Ok(match video_gid.filter(|&g| g != 0) {
        Some(gid) => GiveBack::Reset { gid, mode: 0o660 },
        None => GiveBack::Reset {
            gid: 0,
            mode: 0o600,
        },
    })
}

/// Drop the node's access ACL, then set its owner and mode, all through
/// `fd` (`open_node`).
pub fn reset_node(
    fd: std::os::fd::BorrowedFd<'_>,
    uid: u32,
    gid: u32,
    mode: u32,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let path = fd_path(fd);
    // SAFETY: a path and a name.
    if unsafe { libc::removexattr(path.as_ptr(), ACL_XATTR.as_ptr()) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::ENODATA) {
            return Err(e);
        }
    }
    // SAFETY: a descriptor, an empty path for the descriptor itself, ids
    // and the flag that says so.
    if unsafe { libc::fchownat(fd.as_raw_fd(), c"".as_ptr(), uid, gid, libc::AT_EMPTY_PATH) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a path and a mode.
    if unsafe { libc::chmod(path.as_ptr(), mode) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Give the IR capture node back once its rule is gone (fix round 13,
/// Codex 6, Opus nit): `/dev/<n.node>` opened without following a link,
/// decided by `give_back_plan`, and reset through that descriptor.
pub fn give_back(n: &IrNode, rule_file: bool, video_gid: Option<u32>) -> Result<GiveBack, String> {
    use std::os::fd::AsFd;
    let dev = Path::new("/dev").join(&n.node);
    let fd = open_node(&dev).map_err(|e| format!("{}: {}", dev.display(), e))?;
    let a = node_access(fd.as_fd()).map_err(|e| format!("{}: {}", dev.display(), e))?;
    let plan = give_back_plan(n, rule_file, &a, video_gid)?;
    if let GiveBack::Reset { gid, mode } = plan {
        reset_node(fd.as_fd(), 0, gid, mode).map_err(|e| format!("{}: {}", dev.display(), e))?;
    }
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::*;
    use std::collections::HashMap;
    use std::os::unix::fs::symlink;

    /// A fake sysfs: `class/<node>` with its attributes and a `device`
    /// link into `devices/`, where each device has a `subsystem` link.
    struct Fake(std::path::PathBuf);

    impl Fake {
        fn new(name: &str) -> Fake {
            let root = std::env::temp_dir().join(format!(
                "faceauth-irlock-{}-{}",
                name,
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("class")).unwrap();
            Fake(root)
        }
        fn device(&self, rel: &str, subsystem: &str, attrs: &[(&str, &str)]) {
            let d = self.0.join("devices").join(rel);
            std::fs::create_dir_all(&d).unwrap();
            symlink(format!("../../bus/{}", subsystem), d.join("subsystem")).unwrap();
            for (k, v) in attrs {
                std::fs::write(d.join(k), format!("{}\n", v)).unwrap();
            }
        }
        fn node(&self, node: &str, dev: &str, attrs: &[(&str, &str)]) {
            let n = self.0.join("class").join(node);
            std::fs::create_dir_all(&n).unwrap();
            symlink(self.0.join("devices").join(dev), n.join("device")).unwrap();
            for (k, v) in attrs {
                std::fs::write(n.join(k), format!("{}\n", v)).unwrap();
            }
        }
        fn class(&self) -> std::path::PathBuf {
            self.0.join("class")
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// One device as udev sees it at an event: its own kernel name,
    /// subsystem and attributes, then its ancestors', nearest first.
    struct Seen {
        kernel: &'static str,
        attrs: HashMap<&'static str, &'static str>,
        parents: Vec<(
            &'static str,
            &'static str,
            HashMap<&'static str, &'static str>,
        )>,
    }

    /// Whether `rules` lock `dev`, read the way udev(7) reads them: each
    /// line's match keys must all hold; the parent keys of one line
    /// (`KERNELS`, `SUBSYSTEMS`, `ATTRS`) must all hold on the same device
    /// or ancestor; an `ENV{}=` a line sets is seen by the lines after it.
    /// Only the keys this module writes are known.
    fn locks(rules: &str, dev: &Seen) -> bool {
        let mut env: HashMap<String, String> = HashMap::new();
        let mut locked = false;
        for line in rules
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        {
            let mut parent: Vec<(String, String)> = Vec::new();
            let mut sets: Vec<(String, String)> = Vec::new();
            let mut ok = true;
            for tok in line.split(", ") {
                let (key, op, val) = ["==", "!=", "-=", "="]
                    .iter()
                    .find_map(|op| {
                        let at = tok.find(op)?;
                        Some((&tok[..at], *op, tok[at + op.len()..].trim_matches('"')))
                    })
                    .unwrap();
                match (key, op) {
                    ("ACTION", "!=") => ok &= val != "add",
                    ("SUBSYSTEM", "==") => ok &= val == "video4linux",
                    ("KERNEL", "==") => ok &= dev.kernel.starts_with(val.trim_end_matches('*')),
                    (k, "==") if k.starts_with("ATTR{") => {
                        ok &= dev.attrs.get(&k[5..k.len() - 1]) == Some(&val)
                    }
                    (k, "==") if k.starts_with("ENV{") => {
                        ok &= env.get(&k[4..k.len() - 1]).map(String::as_str) == Some(val)
                    }
                    ("KERNELS" | "SUBSYSTEMS", "==") => parent.push((key.into(), val.into())),
                    (k, "==") if k.starts_with("ATTRS{") => parent.push((k.into(), val.into())),
                    (k, "=") if k.starts_with("ENV{") => {
                        sets.push((k[4..k.len() - 1].into(), val.into()))
                    }
                    ("TAG", "-=") | ("GROUP", "=") | ("MODE", "=") => {
                        sets.push((key.into(), val.into()))
                    }
                    other => panic!("a key this reader does not know: {:?}", other),
                }
            }
            let one_parent = parent.is_empty()
                || dev.parents.iter().any(|(k, sub, attrs)| {
                    parent.iter().all(|(key, val)| match key.as_str() {
                        "KERNELS" => k == val,
                        "SUBSYSTEMS" => sub == val,
                        a => attrs.get(&a[6..a.len() - 1]).is_some_and(|v| v == val),
                    })
                });
            if ok && one_parent {
                for (k, v) in sets {
                    match k.as_str() {
                        "TAG" | "GROUP" | "MODE" => locked = true,
                        _ => {
                            env.insert(k, v);
                        }
                    }
                }
            }
        }
        locked
    }

    /// The Surface Book 2's IR port: the CIO2 capture node `ipu3-cio2 1`,
    /// a function of the IPU3's PCI device, carrying only the IR sensor's
    /// Y10 (a stream on a CIO2 port carries the format whose media-bus
    /// code matches the sensor's: drivers/media/pci/intel/ipu3/ipu3-cio2.c,
    /// `cio2_video_link_validate`). Locked to root, pinned by its name and
    /// the PCI function, never by number.
    #[test]
    fn the_ipu3_ir_port_is_locked_by_name_and_pci_function() {
        let f = Fake::new("ipu3");
        f.device("pci0000:00/0000:00:14.3", "pci", &[]);
        f.node(
            "video1",
            "pci0000:00/0000:00:14.3",
            &[("name", "ipu3-cio2 1"), ("index", "0"), ("dev", "81:1")],
        );
        let n = node_facts(
            &f.class(),
            "video1",
            vec![V4L2_PIX_FMT_IPU3_Y10],
            Some((81, 1)),
        );
        assert_eq!(
            n.pin,
            Some(Pin::Pci {
                slot: "0000:00:14.3".into()
            })
        );
        assert_eq!(
            rule_for(&n).unwrap(),
            r#"ACTION!="remove", SUBSYSTEM=="video4linux", KERNEL=="video*", ATTR{name}=="ipu3-cio2 1", SUBSYSTEMS=="pci", KERNELS=="0000:00:14.3", TAG-="uaccess", GROUP="root", MODE="0600""#
        );
    }

    /// Fix round 12 (Codex 3, Opus N3): two interfaces of one UVC camera
    /// (RGB on 1.0, IR on 1.2) can each have capture index 0
    /// (drivers/media/v4l2-core/v4l2-dev.c numbers per parent device; the
    /// UVC driver registers a chain per interface), and udev matches a
    /// line's parent keys on one ancestor alone (udev(7)), so a rule that
    /// names the camera's port and ids with an index locks both. The IR
    /// node is pinned by its interface on one line, which marks it, and by
    /// the camera's port and ids on the next, which locks only what the
    /// first marked. Its RGB sibling and another camera in the port stay
    /// open.
    #[test]
    fn a_uvc_ir_node_is_locked_by_its_interface_not_its_siblings() {
        let f = Fake::new("uvc");
        f.device(
            "pci0000:00/0000:00:14.0/usb1/1-5",
            "usb",
            &[("idVendor", "04f2"), ("idProduct", "b6dd")],
        );
        f.device("pci0000:00/0000:00:14.0/usb1/1-5/1-5:1.0", "usb", &[]);
        f.device("pci0000:00/0000:00:14.0/usb1/1-5/1-5:1.2", "usb", &[]);
        f.node(
            "video0",
            "pci0000:00/0000:00:14.0/usb1/1-5/1-5:1.0",
            &[
                ("name", "Integrated Camera"),
                ("index", "0"),
                ("dev", "81:0"),
            ],
        );
        f.node(
            "video2",
            "pci0000:00/0000:00:14.0/usb1/1-5/1-5:1.2",
            &[
                ("name", "Integrated IR Camera"),
                ("index", "0"),
                ("dev", "81:2"),
            ],
        );
        let n = node_facts(&f.class(), "video2", vec![V4L2_PIX_FMT_GREY], Some((81, 2)));
        assert_eq!(
            n.pin,
            Some(Pin::Usb {
                interface: "1-5:1.2".into(),
                port: "1-5".into(),
                vendor: "04f2".into(),
                product: "b6dd".into()
            })
        );
        let rule = rule_for(&n).unwrap();
        assert_eq!(
            rule,
            concat!(
                r#"ACTION!="remove", SUBSYSTEM=="video4linux", KERNEL=="video*", ATTR{index}=="0", SUBSYSTEMS=="usb", KERNELS=="1-5:1.2", ENV{FACEAUTH_IR_NODE}="1""#,
                "\n",
                r#"ACTION!="remove", SUBSYSTEM=="video4linux", KERNEL=="video*", ENV{FACEAUTH_IR_NODE}=="1", SUBSYSTEMS=="usb", KERNELS=="1-5", ATTRS{idVendor}=="04f2", ATTRS{idProduct}=="b6dd", TAG-="uaccess", GROUP="root", MODE="0600""#
            )
        );
        let camera: HashMap<_, _> = [("idVendor", "04f2"), ("idProduct", "b6dd")].into();
        let seen = |kernel: &'static str, iface: &'static str| Seen {
            kernel,
            attrs: [("index", "0")].into(),
            parents: vec![
                (iface, "usb", HashMap::new()),
                ("1-5", "usb", camera.clone()),
                ("0000:00:14.0", "pci", HashMap::new()),
            ],
        };
        let (ir, rgb) = (seen("video2", "1-5:1.2"), seen("video0", "1-5:1.0"));
        assert!(locks(&rule, &ir), "the IR node is locked");
        assert!(!locks(&rule, &rgb), "its RGB sibling, also index 0, is not");
        // Codex's reproduction: the round 11 rule, port and ids and index on
        // one line, locks both.
        let round11 = r#"ACTION!="remove", SUBSYSTEM=="video4linux", KERNEL=="video*", ATTR{index}=="0", SUBSYSTEMS=="usb", KERNELS=="1-5", ATTRS{idVendor}=="04f2", ATTRS{idProduct}=="b6dd", TAG-="uaccess", GROUP="root", MODE="0600""#;
        assert!(locks(round11, &ir) && locks(round11, &rgb));
    }

    /// Fix round 12 (Codex 3, Opus N3): the node whose formats were read is
    /// the node pinned. The class entry's `dev` must be the opened node's
    /// device number; a link named like another node (`/dev/ir/video0` to
    /// video2) would otherwise pin video0, perhaps the RGB webcam.
    #[test]
    fn the_node_checked_is_the_node_pinned() {
        let f = Fake::new("dev");
        f.device("pci0000:00/0000:00:14.3", "pci", &[]);
        f.node(
            "video0",
            "pci0000:00/0000:00:14.3",
            &[("name", "ipu3-cio2 0"), ("index", "0"), ("dev", "81:0")],
        );
        let wrong = node_facts(
            &f.class(),
            "video0",
            vec![V4L2_PIX_FMT_IPU3_Y10],
            Some((81, 2)),
        );
        let why = rule_for(&wrong).unwrap_err();
        assert!(why.contains("not the node"), "{}", why);
        let unknown = node_facts(&f.class(), "video0", vec![V4L2_PIX_FMT_IPU3_Y10], None);
        assert!(rule_for(&unknown).unwrap_err().contains("not the node"));
        assert!(rule_for(&node_facts(
            &f.class(),
            "video0",
            vec![V4L2_PIX_FMT_IPU3_Y10],
            Some((81, 0))
        ))
        .is_ok());
    }

    /// Anything unclear stays open, with the reason doctor gives: a node
    /// that offers a colour format beside IR (it could be a webcam's), no
    /// format at all, nothing stable to pin it by, or an attribute udev
    /// could not match safely.
    /// The ACL bytes the kernel keeps for a node the lock left: the seat
    /// user's entry, granted before the rule, under a mask chmod 0600 shut
    /// (include/uapi/linux/posix_acl_xattr.h, posix_acl.h).
    fn acl(entries: &[(u16, u16, u32)]) -> Vec<u8> {
        let mut b = 2u32.to_le_bytes().to_vec();
        for (tag, perm, id) in entries {
            b.extend_from_slice(&tag.to_le_bytes());
            b.extend_from_slice(&perm.to_le_bytes());
            b.extend_from_slice(&id.to_le_bytes());
        }
        b
    }

    /// Fix round 13 (Codex 6, Opus nit): what the lock leaves behind. A
    /// node udev gives the video group (50-udev-default.rules, on add
    /// only) left in root's group; or the seat user's ACL entry under a
    /// mask with no read and write, which uaccess, finding the entry there,
    /// never recalculates (systemd v262 src/shared/acl-util.c,
    /// `devnode_acl`). Anything else is open, a node with no seat user and
    /// so no entry included.
    #[test]
    fn what_the_lock_leaves_is_told_from_an_open_node() {
        const U: u32 = u32::MAX;
        let shut = acl(&[
            (0x01, 6, U),
            (0x02, 6, 1000),
            (0x04, 6, U),
            (0x10, 0, U),
            (0x20, 0, U),
        ]);
        let open = acl(&[
            (0x01, 6, U),
            (0x02, 6, 1000),
            (0x04, 6, U),
            (0x10, 6, U),
            (0x20, 0, U),
        ]);
        let at = |mode: u32, gid: u32, acl: Option<&[u8]>| NodeAccess {
            char_device: true,
            rdev: (81, 0),
            mode,
            gid,
            acl: acl.and_then(parse_acl),
        };
        let video = Some(985);
        assert!(
            lock_left(&at(0o600, 0, None), video),
            "root's group, video's to give"
        );
        assert!(
            lock_left(&at(0o600, 985, Some(&shut)), video),
            "a shut mask"
        );
        assert!(
            lock_left(&at(0o600, 0, Some(&shut)), None),
            "a shut mask, no video group"
        );
        assert!(
            !lock_left(&at(0o660, 985, Some(&open)), video),
            "what udev and uaccess give"
        );
        assert!(
            !lock_left(&at(0o660, 985, None), video),
            "no seat user: no entry"
        );
        assert!(
            !lock_left(&at(0o600, 0, None), None),
            "no video group, no seat user"
        );
        assert_eq!(parse_acl(&[1, 0, 0, 0]), None, "not version 2");
        assert_eq!(parse_acl(&shut[..7]), None, "a torn entry");
    }

    /// Fix round 13 (Codex 6): only the node checked is given back, only
    /// with no rule file to lock it again, and only what the lock left.
    #[test]
    fn only_the_node_checked_is_given_back() {
        let f = Fake::new("give");
        f.device("pci0000:00/0000:00:14.3", "pci", &[]);
        f.node(
            "video1",
            "pci0000:00/0000:00:14.3",
            &[("name", "ipu3-cio2 1"), ("index", "0"), ("dev", "81:1")],
        );
        let n = node_facts(
            &f.class(),
            "video1",
            vec![V4L2_PIX_FMT_IPU3_Y10],
            Some((81, 1)),
        );
        let locked = NodeAccess {
            char_device: true,
            rdev: (81, 1),
            mode: 0o600,
            gid: 0,
            acl: None,
        };
        let video = Some(985);
        assert_eq!(
            give_back_plan(&n, false, &locked, video),
            Ok(GiveBack::Reset {
                gid: 985,
                mode: 0o660
            })
        );
        assert_eq!(
            give_back_plan(&n, false, &locked, None),
            Ok(GiveBack::Open),
            "no video group, no ACL: what devtmpfs and udev leave anyway"
        );
        const U: u32 = u32::MAX;
        let shut = NodeAccess {
            acl: parse_acl(&acl(&[
                (0x01, 6, U),
                (0x02, 6, 1000),
                (0x04, 6, U),
                (0x10, 0, U),
                (0x20, 0, U),
            ])),
            ..locked.clone()
        };
        assert_eq!(
            give_back_plan(&n, false, &shut, None),
            Ok(GiveBack::Reset {
                gid: 0,
                mode: 0o600
            }),
            "no video group, a shut mask: root's 0600 with no ACL, as devtmpfs makes it"
        );
        let open = NodeAccess {
            mode: 0o660,
            gid: 985,
            ..locked.clone()
        };
        assert_eq!(give_back_plan(&n, false, &open, video), Ok(GiveBack::Open));
        let why = give_back_plan(&n, true, &locked, video).unwrap_err();
        assert!(why.contains("still there"), "{}", why);
        let other = NodeAccess {
            rdev: (81, 2),
            ..locked.clone()
        };
        assert!(give_back_plan(&n, false, &other, video)
            .unwrap_err()
            .contains("not the node"));
        let file = NodeAccess {
            char_device: false,
            ..locked.clone()
        };
        assert!(give_back_plan(&n, false, &file, video)
            .unwrap_err()
            .contains("not a character device"));
        let webcam = node_facts(&f.class(), "video1", vec![V4L2_PIX_FMT_YUYV], Some((81, 1)));
        assert!(
            give_back_plan(&webcam, false, &locked, video)
                .unwrap_err()
                .contains("colour"),
            "never a node face setup does not lock"
        );
    }

    /// Fix round 13 (Codex 6): the reset itself, on a file of the test's
    /// own: its access ACL goes (so uaccess writes the seat user's entry
    /// afresh, with its mask), then its owner and mode are set, all
    /// through the descriptor opened without following a link.
    #[test]
    fn a_reset_drops_the_acl_and_sets_owner_and_mode() {
        use std::os::fd::AsFd;
        use std::os::unix::fs::MetadataExt;
        let dir =
            std::env::temp_dir().join(format!("faceauth-irlock-reset-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let node = dir.join("video1");
        std::fs::write(&node, "").unwrap();
        // SAFETY: getuid and getgid have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let shut = acl(&[
            (0x01, 6, u32::MAX),
            (0x02, 6, uid),
            (0x04, 6, u32::MAX),
            (0x10, 0, u32::MAX),
            (0x20, 0, u32::MAX),
        ]);
        let path = std::ffi::CString::new(node.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a path, a name, a buffer and its length, no flags.
        let set = unsafe {
            libc::setxattr(
                path.as_ptr(),
                c"system.posix_acl_access".as_ptr(),
                shut.as_ptr().cast(),
                shut.len(),
                0,
            )
        };
        if set != 0 {
            // A filesystem without ACLs: nothing to show here.
            eprintln!(
                "no ACLs on {}: {}",
                dir.display(),
                std::io::Error::last_os_error()
            );
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let fd = open_node(&node).unwrap();
        let before = node_access(fd.as_fd()).unwrap();
        assert!(before
            .acl
            .is_some_and(|a| a.named_users == 1 && a.mask == Some(0)));
        reset_node(fd.as_fd(), uid, gid, 0o640).unwrap();
        let after = node_access(fd.as_fd()).unwrap();
        assert_eq!(after.acl, None, "the ACL is gone");
        let md = std::fs::metadata(&node).unwrap();
        assert_eq!((md.mode() & 0o777, md.uid(), md.gid()), (0o640, uid, gid));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn anything_unclear_is_left_open_with_its_reason() {
        let f = Fake::new("open");
        f.device("pci0000:00/0000:00:14.3", "pci", &[]);
        f.node(
            "video1",
            "pci0000:00/0000:00:14.3",
            &[("name", "ipu3-cio2 1"), ("index", "0"), ("dev", "81:1")],
        );
        let colour = node_facts(
            &f.class(),
            "video1",
            vec![V4L2_PIX_FMT_GREY, V4L2_PIX_FMT_YUYV],
            Some((81, 1)),
        );
        let why = rule_for(&colour).unwrap_err();
        assert!(why.contains("colour") && why.contains("YUYV"), "{}", why);
        let none = node_facts(&f.class(), "video1", vec![], Some((81, 1)));
        assert!(rule_for(&none).unwrap_err().contains("no format"));
        f.device("platform/thing", "platform", &[]);
        f.node(
            "video4",
            "platform/thing",
            &[("name", "ir"), ("index", "0"), ("dev", "81:4")],
        );
        let unpinned = node_facts(&f.class(), "video4", vec![V4L2_PIX_FMT_GREY], Some((81, 4)));
        assert_eq!(unpinned.pin, None);
        assert!(rule_for(&unpinned).unwrap_err().contains("stable"));
        f.node(
            "video6",
            "pci0000:00/0000:00:14.3",
            &[("name", "ipu3-cio2 \"1\""), ("index", "0"), ("dev", "81:6")],
        );
        let odd = node_facts(
            &f.class(),
            "video6",
            vec![V4L2_PIX_FMT_IPU3_Y10],
            Some((81, 6)),
        );
        assert!(rule_for(&odd).unwrap_err().contains("safely"));
        assert!(
            rule_for(&node_facts(
                &f.class(),
                "video9",
                vec![V4L2_PIX_FMT_GREY],
                Some((81, 9))
            ))
            .is_err(),
            "no such node"
        );
        // Every IR or grey format counts; every other format is colour.
        for ir in [
            V4L2_PIX_FMT_GREY,
            V4L2_PIX_FMT_Y10,
            V4L2_PIX_FMT_Y16,
            V4L2_PIX_FMT_IPU3_Y10,
        ] {
            assert!(is_ir_format(ir));
        }
        for colour in [
            V4L2_PIX_FMT_YUYV,
            V4L2_PIX_FMT_IPU3_SGRBG10,
            fourcc(b'M', b'J', b'P', b'G'),
        ] {
            assert!(!is_ir_format(colour));
        }
    }
}
