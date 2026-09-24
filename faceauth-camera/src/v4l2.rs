//! Thin, safe wrappers over the V4L2 video-node and subdevice ioctls.
//!
//! Every ioctl call here follows the one rule in `sys`: the fd is an open
//! V4L2 node and the struct is the one the ioctl number names. The SAFETY
//! lines below say what else, if anything, a call relies on.

use crate::sys::*;
use anyhow::{anyhow, bail, Context, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::mman::{mmap, munmap, MapFlags, ProtFlags};
use std::fs::{File, OpenOptions};
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::time::Duration;

/// A capture format as the node reports it after `S_FMT`.
#[derive(Clone, Debug)]
pub struct Format {
    pub width: u32,
    pub height: u32,
    pub pixelformat: u32,
    pub bytesperline: u32,
    pub sizeimage: u32,
    pub multiplanar: bool,
}

struct MappedBuffer {
    ptr: NonNull<libc::c_void>,
    len: usize,
}

/// A V4L2 capture node with mmap streaming.
pub struct VideoDevice {
    file: File,
    path: PathBuf,
    buf_type: u32,
    format: Option<Format>,
    buffers: Vec<MappedBuffer>,
    streaming: bool,
}

/// One dequeued frame. Re-queued on drop.
pub struct FrameRef<'a> {
    dev: &'a VideoDevice,
    index: u32,
    pub sequence: u32,
    pub bytesused: usize,
    data: &'a [u8],
}

impl FrameRef<'_> {
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

impl Drop for FrameRef<'_> {
    fn drop(&mut self) {
        // Best effort: a failed requeue surfaces as a stalled stream on the next poll.
        let _ = self.dev.queue(self.index);
    }
}

impl VideoDevice {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        let caps = {
            let mut c = v4l2_capability::default();
            // SAFETY: the `sys` rule; the kernel fills a struct we own.
            unsafe { vidioc_querycap(file.as_raw_fd(), &mut c) }
                .with_context(|| format!("{}: QUERYCAP", path.display()))?;
            c
        };
        let dc = if caps.device_caps != 0 {
            caps.device_caps
        } else {
            caps.capabilities
        };
        let buf_type = if dc & V4L2_CAP_VIDEO_CAPTURE_MPLANE != 0 {
            V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
        } else if dc & V4L2_CAP_VIDEO_CAPTURE != 0 {
            V4L2_BUF_TYPE_VIDEO_CAPTURE
        } else {
            bail!("{}: not a video capture device", path.display());
        };
        if dc & V4L2_CAP_STREAMING == 0 {
            bail!("{}: no streaming I/O", path.display());
        }
        Ok(VideoDevice {
            file,
            path,
            buf_type,
            format: None,
            buffers: Vec::new(),
            streaming: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn multiplanar(&self) -> bool {
        self.buf_type == V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE
    }

    pub fn driver_and_card(&self) -> Result<(String, String, String)> {
        let mut c = v4l2_capability::default();
        // SAFETY: the `sys` rule; the kernel fills a struct we own.
        unsafe { vidioc_querycap(self.file.as_raw_fd(), &mut c) }?;
        Ok((cstr(&c.driver), cstr(&c.card), cstr(&c.bus_info)))
    }

    /// Pixel formats the node offers, in enumeration order.
    pub fn formats(&self) -> Result<Vec<(u32, String)>> {
        let mut out = Vec::new();
        for index in 0.. {
            let mut d = v4l2_fmtdesc {
                index,
                type_: self.buf_type,
                ..Default::default()
            };
            // SAFETY: the `sys` rule; EINVAL past the last format is the
            // enumeration's end, not an error.
            match unsafe { vidioc_enum_fmt(self.file.as_raw_fd(), &mut d) } {
                Ok(_) => out.push((d.pixelformat, cstr(&d.description))),
                Err(nix::errno::Errno::EINVAL) => break,
                Err(e) => return Err(e).context("ENUM_FMT"),
            }
        }
        Ok(out)
    }

    /// Negotiate a format. The driver may adjust it; the result is what it settled on.
    pub fn set_format(&mut self, width: u32, height: u32, pixelformat: u32) -> Result<Format> {
        if self.streaming || !self.buffers.is_empty() {
            bail!("set_format while buffers are allocated");
        }
        let mut f = v4l2_format::zeroed(self.buf_type);
        if self.multiplanar() {
            let mp = f.pix_mp_mut();
            mp.width = width;
            mp.height = height;
            mp.pixelformat = pixelformat;
            mp.field = V4L2_FIELD_NONE;
            mp.num_planes = 1;
        } else {
            let p = f.pix_mut();
            p.width = width;
            p.height = height;
            p.pixelformat = pixelformat;
            p.field = V4L2_FIELD_NONE;
        }
        // SAFETY: the `sys` rule; `f` is a whole `v4l2_format` whichever
        // union member the node reads.
        unsafe { vidioc_s_fmt(self.file.as_raw_fd(), &mut f) }.with_context(|| {
            format!(
                "{}: S_FMT {}x{} {}",
                self.path.display(),
                width,
                height,
                fourcc_str(pixelformat)
            )
        })?;
        let fmt = if self.multiplanar() {
            let mp = f.pix_mp();
            if mp.num_planes != 1 {
                bail!(
                    "{}: {} planes, only single-plane formats are supported",
                    self.path.display(),
                    mp.num_planes
                );
            }
            Format {
                width: mp.width,
                height: mp.height,
                pixelformat: mp.pixelformat,
                bytesperline: mp.plane_fmt[0].bytesperline,
                sizeimage: mp.plane_fmt[0].sizeimage,
                multiplanar: true,
            }
        } else {
            let p = f.pix();
            Format {
                width: p.width,
                height: p.height,
                pixelformat: p.pixelformat,
                bytesperline: p.bytesperline,
                sizeimage: p.sizeimage,
                multiplanar: false,
            }
        };
        if fmt.pixelformat != pixelformat {
            bail!(
                "{}: driver substituted {} for {}",
                self.path.display(),
                fourcc_str(fmt.pixelformat),
                fourcc_str(pixelformat)
            );
        }
        self.format = Some(fmt.clone());
        Ok(fmt)
    }

    pub fn format(&self) -> Option<&Format> {
        self.format.as_ref()
    }

    /// Request and map `count` buffers, and queue them all.
    pub fn request_buffers(&mut self, count: u32) -> Result<usize> {
        if self.format.is_none() {
            bail!("request_buffers before set_format");
        }
        let mut r = v4l2_requestbuffers {
            count,
            type_: self.buf_type,
            memory: V4L2_MEMORY_MMAP,
            ..Default::default()
        };
        // SAFETY: the `sys` rule.
        unsafe { vidioc_reqbufs(self.file.as_raw_fd(), &mut r) }.context("REQBUFS")?;
        if r.count == 0 {
            bail!("{}: driver granted no buffers", self.path.display());
        }
        for index in 0..r.count {
            let (offset, length) = self.query_buffer(index)?;
            // SAFETY: a read-only shared mapping of a buffer the driver
            // reported at this offset and length; it is unmapped only in
            // `Drop`, after every borrow of it has ended.
            let ptr = unsafe {
                mmap(
                    None,
                    NonZeroUsize::new(length).ok_or_else(|| anyhow!("zero-length buffer"))?,
                    ProtFlags::PROT_READ,
                    MapFlags::MAP_SHARED,
                    self.file.as_fd(),
                    offset as libc::off_t,
                )
            }
            .context("mmap")?;
            self.buffers.push(MappedBuffer { ptr, len: length });
        }
        for index in 0..r.count {
            self.queue(index)?;
        }
        Ok(r.count as usize)
    }

    fn query_buffer(&self, index: u32) -> Result<(u64, usize)> {
        let mut plane = v4l2_plane::default();
        let mut b = v4l2_buffer {
            index,
            type_: self.buf_type,
            memory: V4L2_MEMORY_MMAP,
            ..Default::default()
        };
        if self.multiplanar() {
            b.m = &mut plane as *mut v4l2_plane as u64;
            b.length = 1;
        }
        // SAFETY: the `sys` rule; for a multiplanar node `m` points at
        // `plane`, which outlives the call and is the one plane `length`
        // announces.
        unsafe { vidioc_querybuf(self.file.as_raw_fd(), &mut b) }.context("QUERYBUF")?;
        if self.multiplanar() {
            Ok((plane.m & 0xffff_ffff, plane.length as usize))
        } else {
            Ok((b.m & 0xffff_ffff, b.length as usize))
        }
    }

    fn queue(&self, index: u32) -> Result<()> {
        let mut plane = v4l2_plane::default();
        let mut b = v4l2_buffer {
            index,
            type_: self.buf_type,
            memory: V4L2_MEMORY_MMAP,
            ..Default::default()
        };
        if self.multiplanar() {
            b.m = &mut plane as *mut v4l2_plane as u64;
            b.length = 1;
        }
        // SAFETY: as in `query_buffer`.
        unsafe { vidioc_qbuf(self.file.as_raw_fd(), &mut b) }.context("QBUF")?;
        Ok(())
    }

    pub fn stream_on(&mut self) -> Result<()> {
        if self.buffers.is_empty() {
            bail!("stream_on before request_buffers");
        }
        let t = self.buf_type;
        // SAFETY: the `sys` rule; the argument is one u32.
        unsafe { vidioc_streamon(self.file.as_raw_fd(), &t) }
            .with_context(|| format!("{}: STREAMON", self.path.display()))?;
        self.streaming = true;
        Ok(())
    }

    pub fn stream_off(&mut self) -> Result<()> {
        if !self.streaming {
            return Ok(());
        }
        let t = self.buf_type;
        // SAFETY: the `sys` rule; the argument is one u32.
        unsafe { vidioc_streamoff(self.file.as_raw_fd(), &t) }.context("STREAMOFF")?;
        self.streaming = false;
        Ok(())
    }

    /// Wait up to `timeout` for a frame, then dequeue it. `Ok(None)` on
    /// timeout. A buffer the driver flags as an error, or hands back empty,
    /// is requeued and the wait goes on: a transfer error on a UVC camera
    /// costs one frame, not the attempt, and an empty buffer never
    /// re-delivers whatever the mapping last held.
    pub fn next_frame(&self, timeout: Duration) -> Result<Option<FrameRef<'_>>> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            let fd: BorrowedFd = self.file.as_fd();
            let mut pfd = [PollFd::new(fd, PollFlags::POLLIN)];
            let ms = PollTimeout::try_from(left).unwrap_or(PollTimeout::MAX);
            let n = loop {
                match poll(&mut pfd, ms) {
                    Ok(n) => break n,
                    Err(nix::errno::Errno::EINTR) => continue,
                    Err(e) => return Err(e).context("poll"),
                }
            };
            if n == 0 {
                return Ok(None);
            }
            let mut plane = v4l2_plane::default();
            let mut b = v4l2_buffer {
                type_: self.buf_type,
                memory: V4L2_MEMORY_MMAP,
                ..Default::default()
            };
            if self.multiplanar() {
                b.m = &mut plane as *mut v4l2_plane as u64;
                b.length = 1;
            }
            // SAFETY: as in `query_buffer`.
            unsafe { vidioc_dqbuf(self.file.as_raw_fd(), &mut b) }.context("DQBUF")?;
            let buf = self
                .buffers
                .get(b.index as usize)
                .ok_or_else(|| anyhow!("DQBUF returned index {}", b.index))?;
            let used = if self.multiplanar() {
                plane.bytesused as usize
            } else {
                b.bytesused as usize
            };
            if !buffer_is_usable(b.flags, used) {
                log::debug!(
                    "{}: frame {} skipped (flags 0x{:x}, {} bytes)",
                    self.path.display(),
                    b.sequence,
                    b.flags,
                    used
                );
                self.queue(b.index)?;
                continue;
            }
            let used = used.min(buf.len);
            // SAFETY: the mapping is MAP_SHARED read-only and lives as long as
            // `self`; the driver does not write a dequeued buffer until it is
            // queued again, which `FrameRef::drop` does after this borrow ends.
            let data = unsafe { std::slice::from_raw_parts(buf.ptr.as_ptr() as *const u8, used) };
            return Ok(Some(FrameRef {
                dev: self,
                index: b.index,
                sequence: b.sequence,
                bytesused: used,
                data,
            }));
        }
    }
}

/// Is a dequeued buffer a frame worth reading? Not when the driver flagged
/// it as an error, and not when it says no bytes were written: that buffer
/// holds stale pixels from an earlier frame or nothing at all.
pub fn buffer_is_usable(flags: u32, bytesused: usize) -> bool {
    flags & V4L2_BUF_FLAG_ERROR == 0 && bytesused > 0
}

impl VideoDevice {}

impl Drop for VideoDevice {
    fn drop(&mut self) {
        let _ = self.stream_off();
        for b in self.buffers.drain(..) {
            // SAFETY: each mapping was made by `request_buffers` with this
            // pointer and length, and no `FrameRef` can outlive `self`.
            unsafe {
                let _ = munmap(b.ptr, b.len);
            }
        }
    }
}

/// A V4L2 control as `QUERY_EXT_CTRL` describes it.
#[derive(Clone, Debug)]
pub struct ControlInfo {
    pub id: u32,
    pub name: String,
    pub type_: u32,
    pub min: i64,
    pub max: i64,
    pub step: u64,
    pub default: i64,
    pub flags: u32,
}

impl ControlInfo {
    /// The `v4l2-ctl` spelling: lower case, non-alphanumerics folded to `_`.
    pub fn key(&self) -> String {
        control_key(&self.name)
    }
}

pub fn control_key(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut last_us = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_us = false;
        } else if !last_us {
            out.push('_');
            last_us = true;
        }
    }
    out.trim_matches('_').to_string()
}

/// Controls on any V4L2 file: a video node or a `/dev/v4l-subdevN`.
pub struct Controls {
    file: File,
    path: PathBuf,
}

impl Controls {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        Ok(Controls { file, path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn list(&self) -> Result<Vec<ControlInfo>> {
        let mut out = Vec::new();
        let mut q = v4l2_query_ext_ctrl {
            id: V4L2_CTRL_FLAG_NEXT_CTRL,
            ..Default::default()
        };
        loop {
            // SAFETY: the `sys` rule; EINVAL past the last control ends the walk.
            match unsafe { vidioc_query_ext_ctrl(self.file.as_raw_fd(), &mut q) } {
                Ok(_) => {}
                Err(nix::errno::Errno::EINVAL) => break,
                Err(e) => return Err(e).context("QUERY_EXT_CTRL"),
            }
            out.push(ControlInfo {
                id: q.id,
                name: cstr(&q.name),
                type_: q.type_,
                min: q.minimum,
                max: q.maximum,
                step: q.step,
                default: q.default_value,
                flags: q.flags,
            });
            q.id |= V4L2_CTRL_FLAG_NEXT_CTRL;
        }
        Ok(out)
    }

    pub fn find(&self, key: &str) -> Result<Option<ControlInfo>> {
        Ok(self.list()?.into_iter().find(|c| c.key() == key))
    }

    pub fn get(&self, id: u32) -> Result<i32> {
        let mut c = v4l2_control { id, value: 0 };
        // SAFETY: the `sys` rule.
        unsafe { vidioc_g_ctrl(self.file.as_raw_fd(), &mut c) }
            .with_context(|| format!("{}: G_CTRL 0x{:08x}", self.path.display(), id))?;
        Ok(c.value)
    }

    pub fn set(&self, id: u32, value: i32) -> Result<i32> {
        let mut c = v4l2_control { id, value };
        // SAFETY: the `sys` rule.
        unsafe { vidioc_s_ctrl(self.file.as_raw_fd(), &mut c) }
            .with_context(|| format!("{}: S_CTRL 0x{:08x} = {}", self.path.display(), id, value))?;
        Ok(c.value)
    }
}

/// A sensor or bridge subdevice: format on a pad plus its controls.
pub struct Subdev {
    pub controls: Controls,
}

impl Subdev {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Ok(Subdev {
            controls: Controls::open(path)?,
        })
    }

    pub fn path(&self) -> &Path {
        self.controls.path()
    }

    pub fn get_format(&self, pad: u32) -> Result<(u32, u32, u32)> {
        let mut f = v4l2_subdev_format {
            which: V4L2_SUBDEV_FORMAT_ACTIVE,
            pad,
            ..Default::default()
        };
        // SAFETY: the `sys` rule, on a subdev node.
        unsafe { vidioc_subdev_g_fmt(self.controls.file.as_raw_fd(), &mut f) }
            .with_context(|| format!("{}: SUBDEV_G_FMT pad {}", self.path().display(), pad))?;
        Ok((f.format.width, f.format.height, f.format.code))
    }

    pub fn set_format(
        &self,
        pad: u32,
        width: u32,
        height: u32,
        code: u32,
    ) -> Result<(u32, u32, u32)> {
        let mut f = v4l2_subdev_format {
            which: V4L2_SUBDEV_FORMAT_ACTIVE,
            pad,
            ..Default::default()
        };
        f.format.width = width;
        f.format.height = height;
        f.format.code = code;
        f.format.field = V4L2_FIELD_NONE;
        // SAFETY: the `sys` rule, on a subdev node.
        unsafe { vidioc_subdev_s_fmt(self.controls.file.as_raw_fd(), &mut f) }.with_context(
            || {
                format!(
                    "{}: SUBDEV_S_FMT pad {} {}x{} 0x{:04x}",
                    self.path().display(),
                    pad,
                    width,
                    height,
                    code
                )
            },
        )?;
        Ok((f.format.width, f.format.height, f.format.code))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An error-flagged buffer and an empty one are skipped; a partial
    /// payload without the flag is still read (the decoder decides).
    #[test]
    fn error_flagged_and_empty_buffers_are_not_frames() {
        assert!(buffer_is_usable(0, 307_200));
        assert!(buffer_is_usable(0x1 | 0x4, 100));
        assert!(!buffer_is_usable(V4L2_BUF_FLAG_ERROR, 307_200));
        assert!(!buffer_is_usable(0, 0));
        assert!(!buffer_is_usable(V4L2_BUF_FLAG_ERROR, 0));
    }

    #[test]
    fn control_keys_match_v4l2_ctl() {
        assert_eq!(control_key("Strobe Output Enable"), "strobe_output_enable");
        assert_eq!(control_key("Strobe Frame Pattern"), "strobe_frame_pattern");
        assert_eq!(control_key("Exposure"), "exposure");
        assert_eq!(control_key("Vertical Blanking"), "vertical_blanking");
        assert_eq!(control_key("Link Frequency"), "link_frequency");
    }
}
