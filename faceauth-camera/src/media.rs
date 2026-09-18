//! Media-controller graph access: entity enumeration, link setup, and the
//! mapping from an entity to its `/dev` node.

use crate::sys::*;
use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Entity {
    pub id: u32,
    pub name: String,
    pub pads: u16,
    pub links: u16,
    pub major: u32,
    pub minor: u32,
}

impl Entity {
    /// The `/dev` node behind this entity, resolved through sysfs.
    pub fn dev_node(&self) -> Option<PathBuf> {
        if self.major == 0 {
            return None;
        }
        let uevent = std::fs::read_to_string(format!("/sys/dev/char/{}:{}/uevent", self.major, self.minor)).ok()?;
        uevent.lines().find_map(|l| l.strip_prefix("DEVNAME=")).map(|n| Path::new("/dev").join(n))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Link {
    pub source_entity: u32,
    pub source_pad: u16,
    pub sink_entity: u32,
    pub sink_pad: u16,
    pub flags: u32,
}

impl Link {
    pub fn enabled(&self) -> bool {
        self.flags & MEDIA_LNK_FL_ENABLED != 0
    }
}

pub struct MediaDevice {
    file: File,
    path: PathBuf,
}

impl MediaDevice {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().read(true).write(true).open(&path).with_context(|| format!("open {}", path.display()))?;
        Ok(MediaDevice { file, path })
    }

    /// Every `/dev/media*` on the system, in name order.
    pub fn enumerate() -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = std::fs::read_dir("/dev")
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| p.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with("media")).unwrap_or(false))
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn info(&self) -> Result<(String, String, String)> {
        let mut i: media_device_info = unsafe { std::mem::zeroed() };
        unsafe { media_ioc_device_info(self.file.as_raw_fd(), &mut i) }.context("MEDIA_IOC_DEVICE_INFO")?;
        Ok((cstr(&i.driver), cstr(&i.model), cstr(&i.bus_info)))
    }

    pub fn entities(&self) -> Result<Vec<Entity>> {
        let mut out = Vec::new();
        let mut id = MEDIA_ENT_ID_FLAG_NEXT;
        loop {
            let mut d: media_entity_desc = unsafe { std::mem::zeroed() };
            d.id = id;
            match unsafe { media_ioc_enum_entities(self.file.as_raw_fd(), &mut d) } {
                Ok(_) => {}
                Err(nix::errno::Errno::EINVAL) => break,
                Err(e) => return Err(e).context("MEDIA_IOC_ENUM_ENTITIES"),
            }
            let (major, minor) = d.dev_major_minor();
            out.push(Entity { id: d.id, name: cstr(&d.name), pads: d.pads, links: d.links, major, minor });
            id = d.id | MEDIA_ENT_ID_FLAG_NEXT;
        }
        Ok(out)
    }

    pub fn entity_by_name(&self, name: &str) -> Result<Option<Entity>> {
        Ok(self.entities()?.into_iter().find(|e| e.name == name))
    }

    /// Links leaving this entity. The kernel reports outgoing links only, so a
    /// sink's inputs are found by enumerating its sources.
    pub fn links(&self, entity: &Entity) -> Result<Vec<Link>> {
        let mut pads = vec![media_pad_desc::default(); entity.pads as usize];
        let mut links = vec![media_link_desc::default(); entity.links as usize];
        let mut e: media_links_enum = unsafe { std::mem::zeroed() };
        e.entity = entity.id;
        e.pads = pads.as_mut_ptr();
        e.links = links.as_mut_ptr();
        unsafe { media_ioc_enum_links(self.file.as_raw_fd(), &mut e) }.with_context(|| format!("MEDIA_IOC_ENUM_LINKS {}", entity.name))?;
        Ok(links
            .iter()
            .map(|l| Link {
                source_entity: l.source.entity,
                source_pad: l.source.index,
                sink_entity: l.sink.entity,
                sink_pad: l.sink.index,
                flags: l.flags,
            })
            .collect())
    }

    pub fn setup_link(&self, link: &Link, enable: bool) -> Result<()> {
        let mut d = media_link_desc::default();
        d.source.entity = link.source_entity;
        d.source.index = link.source_pad;
        d.sink.entity = link.sink_entity;
        d.sink.index = link.sink_pad;
        d.flags = if enable { MEDIA_LNK_FL_ENABLED } else { 0 };
        match unsafe { media_ioc_setup_link(self.file.as_raw_fd(), &mut d) } {
            Ok(_) => Ok(()),
            Err(e) => bail!("MEDIA_IOC_SETUP_LINK {}:{} -> {}:{}: {}", link.source_entity, link.source_pad, link.sink_entity, link.sink_pad, e),
        }
    }
}
