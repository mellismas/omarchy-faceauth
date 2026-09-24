//! Hand-written kernel ABI for the handful of V4L2, media-controller and
//! subdevice ioctls this crate needs.
//!
//! Written by hand rather than generated so the crate builds without libclang
//! and so every struct here is one the code actually uses. Layouts are the
//! x86_64 ones from `linux/videodev2.h`, `linux/media.h` and
//! `linux/v4l2-subdev.h`; `layout_tests` pins sizes and offsets to the values
//! printed by a C program against the 7.2 headers.

#![allow(non_camel_case_types, dead_code)]

use nix::{ioctl_read, ioctl_readwrite, ioctl_write_ptr};

pub const V4L2_BUF_TYPE_VIDEO_CAPTURE: u32 = 1;
pub const V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE: u32 = 9;
pub const V4L2_MEMORY_MMAP: u32 = 1;
pub const V4L2_FIELD_NONE: u32 = 1;
pub const V4L2_CAP_VIDEO_CAPTURE: u32 = 0x1;
pub const V4L2_CAP_VIDEO_CAPTURE_MPLANE: u32 = 0x1000;
pub const V4L2_CAP_STREAMING: u32 = 0x0400_0000;

pub const V4L2_CTRL_FLAG_NEXT_CTRL: u32 = 0x8000_0000;
pub const V4L2_CTRL_FLAG_EXECUTE_ON_WRITE: u32 = 0x200;
pub const V4L2_CTRL_TYPE_INTEGER: u32 = 1;
pub const V4L2_CTRL_TYPE_BOOLEAN: u32 = 2;
pub const V4L2_CTRL_TYPE_MENU: u32 = 3;
pub const V4L2_CTRL_TYPE_BITMASK: u32 = 8;

pub const V4L2_CID_USER_BASE: u32 = 0x0098_0900;
pub const V4L2_CID_EXPOSURE: u32 = 0x0098_0911;
pub const V4L2_CID_GAIN: u32 = 0x0098_0913;
pub const V4L2_CID_EXPOSURE_AUTO: u32 = 0x009a_0901;
pub const V4L2_CID_EXPOSURE_ABSOLUTE: u32 = 0x009a_0902;
pub const V4L2_CID_FLASH_STROBE_OE: u32 = 0x009c_090e;
pub const V4L2_CID_VBLANK: u32 = 0x009e_0901;
pub const V4L2_CID_ANALOGUE_GAIN: u32 = 0x009e_0903;

pub const MEDIA_ENT_ID_FLAG_NEXT: u32 = 0x8000_0000;
pub const MEDIA_LNK_FL_ENABLED: u32 = 0x1;
pub const MEDIA_PAD_FL_SINK: u32 = 0x1;
pub const MEDIA_PAD_FL_SOURCE: u32 = 0x2;
pub const V4L2_SUBDEV_FORMAT_ACTIVE: u32 = 1;

pub const MEDIA_BUS_FMT_Y10_1X10: u32 = 0x200a;
pub const MEDIA_BUS_FMT_SBGGR10_1X10: u32 = 0x3007;
pub const MEDIA_BUS_FMT_SGRBG10_1X10: u32 = 0x300a;

pub const fn fourcc(a: u8, b: u8, c: u8, d: u8) -> u32 {
    (a as u32) | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24)
}
pub const V4L2_PIX_FMT_IPU3_Y10: u32 = fourcc(b'i', b'p', b'3', b'y');
pub const V4L2_PIX_FMT_IPU3_SBGGR10: u32 = fourcc(b'i', b'p', b'3', b'b');
pub const V4L2_PIX_FMT_IPU3_SGBRG10: u32 = fourcc(b'i', b'p', b'3', b'g');
pub const V4L2_PIX_FMT_IPU3_SGRBG10: u32 = fourcc(b'i', b'p', b'3', b'G');
pub const V4L2_PIX_FMT_IPU3_SRGGB10: u32 = fourcc(b'i', b'p', b'3', b'r');
pub const V4L2_PIX_FMT_GREY: u32 = fourcc(b'G', b'R', b'E', b'Y');
pub const V4L2_PIX_FMT_Y10: u32 = fourcc(b'Y', b'1', b'0', b' ');
pub const V4L2_PIX_FMT_Y16: u32 = fourcc(b'Y', b'1', b'6', b' ');
pub const V4L2_PIX_FMT_YUYV: u32 = fourcc(b'Y', b'U', b'Y', b'V');
pub const V4L2_PIX_FMT_MJPEG: u32 = fourcc(b'M', b'J', b'P', b'G');

pub fn fourcc_str(f: u32) -> String {
    f.to_le_bytes()
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '?'
            }
        })
        .collect()
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct v4l2_capability {
    pub driver: [u8; 16],
    pub card: [u8; 32],
    pub bus_info: [u8; 32],
    pub version: u32,
    pub capabilities: u32,
    pub device_caps: u32,
    pub reserved: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct v4l2_fmtdesc {
    pub index: u32,
    pub type_: u32,
    pub flags: u32,
    pub description: [u8; 32],
    pub pixelformat: u32,
    pub mbus_code: u32,
    pub reserved: [u32; 3],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct v4l2_pix_format {
    pub width: u32,
    pub height: u32,
    pub pixelformat: u32,
    pub field: u32,
    pub bytesperline: u32,
    pub sizeimage: u32,
    pub colorspace: u32,
    pub priv_: u32,
    pub flags: u32,
    pub ycbcr_enc: u32,
    pub quantization: u32,
    pub xfer_func: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct v4l2_plane_pix_format {
    pub sizeimage: u32,
    pub bytesperline: u32,
    pub reserved: [u16; 6],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct v4l2_pix_format_mplane {
    pub width: u32,
    pub height: u32,
    pub pixelformat: u32,
    pub field: u32,
    pub colorspace: u32,
    pub plane_fmt: [v4l2_plane_pix_format; 8],
    pub num_planes: u8,
    pub flags: u8,
    pub ycbcr_enc: u8,
    pub quantization: u8,
    pub xfer_func: u8,
    pub reserved: [u8; 7],
}

/// `struct v4l2_format` with the union spelled out as raw storage plus typed
/// accessors. The union is 200 bytes; the two members used here are both
/// smaller and start at its beginning.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct v4l2_format {
    pub type_: u32,
    pub _pad: u32,
    pub raw: [u8; 200],
}

impl v4l2_format {
    pub fn zeroed(type_: u32) -> Self {
        v4l2_format {
            type_,
            _pad: 0,
            raw: [0; 200],
        }
    }
    pub fn pix(&self) -> &v4l2_pix_format {
        // SAFETY: repr(C) POD, in-bounds, 4-byte aligned (raw starts at offset 8).
        unsafe { &*(self.raw.as_ptr() as *const v4l2_pix_format) }
    }
    pub fn pix_mut(&mut self) -> &mut v4l2_pix_format {
        unsafe { &mut *(self.raw.as_mut_ptr() as *mut v4l2_pix_format) }
    }
    pub fn pix_mp(&self) -> &v4l2_pix_format_mplane {
        unsafe { &*(self.raw.as_ptr() as *const v4l2_pix_format_mplane) }
    }
    pub fn pix_mp_mut(&mut self) -> &mut v4l2_pix_format_mplane {
        unsafe { &mut *(self.raw.as_mut_ptr() as *mut v4l2_pix_format_mplane) }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct v4l2_requestbuffers {
    pub count: u32,
    pub type_: u32,
    pub memory: u32,
    pub capabilities: u32,
    pub flags: u8,
    pub reserved: [u8; 3],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct v4l2_plane {
    pub bytesused: u32,
    pub length: u32,
    /// union { mem_offset: u32, userptr: u64, fd: i32 }
    pub m: u64,
    pub data_offset: u32,
    pub reserved: [u32; 11],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct v4l2_buffer {
    pub index: u32,
    pub type_: u32,
    pub bytesused: u32,
    pub flags: u32,
    pub field: u32,
    pub _pad: u32,
    pub timestamp: [i64; 2],
    pub timecode: [u8; 16],
    pub sequence: u32,
    pub memory: u32,
    /// union { offset: u32, userptr: u64, planes: *mut v4l2_plane, fd: i32 }
    pub m: u64,
    pub length: u32,
    pub reserved2: u32,
    pub request_fd: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct v4l2_control {
    pub id: u32,
    pub value: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct v4l2_query_ext_ctrl {
    pub id: u32,
    pub type_: u32,
    pub name: [u8; 32],
    pub minimum: i64,
    pub maximum: i64,
    pub step: u64,
    pub default_value: i64,
    pub flags: u32,
    pub elem_size: u32,
    pub elems: u32,
    pub nr_of_dims: u32,
    pub dims: [u32; 4],
    pub reserved: [u32; 32],
}

impl Default for v4l2_query_ext_ctrl {
    fn default() -> Self {
        // SAFETY: all-zero is a valid value for a POD struct of integers.
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct v4l2_mbus_framefmt {
    pub width: u32,
    pub height: u32,
    pub code: u32,
    pub field: u32,
    pub colorspace: u32,
    pub ycbcr_enc: u16,
    pub quantization: u16,
    pub xfer_func: u16,
    pub flags: u16,
    pub reserved: [u16; 10],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct v4l2_subdev_format {
    pub which: u32,
    pub pad: u32,
    pub format: v4l2_mbus_framefmt,
    pub stream: u32,
    pub reserved: [u32; 7],
}

impl Default for v4l2_subdev_format {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct media_device_info {
    pub driver: [u8; 16],
    pub model: [u8; 32],
    pub serial: [u8; 40],
    pub bus_info: [u8; 32],
    pub media_version: u32,
    pub hw_revision: u32,
    pub driver_version: u32,
    pub reserved: [u32; 31],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct media_entity_desc {
    pub id: u32,
    pub name: [u8; 32],
    pub type_: u32,
    pub revision: u32,
    pub flags: u32,
    pub group_id: u32,
    pub pads: u16,
    pub links: u16,
    pub reserved: [u32; 4],
    /// union: for V4L entities `{ major: u32, minor: u32 }` at its start.
    pub rest: [u8; 184],
}

impl media_entity_desc {
    pub fn dev_major_minor(&self) -> (u32, u32) {
        let major = u32::from_ne_bytes(self.rest[0..4].try_into().unwrap());
        let minor = u32::from_ne_bytes(self.rest[4..8].try_into().unwrap());
        (major, minor)
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct media_pad_desc {
    pub entity: u32,
    pub index: u16,
    pub _pad: u16,
    pub flags: u32,
    pub reserved: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct media_link_desc {
    pub source: media_pad_desc,
    pub sink: media_pad_desc,
    pub flags: u32,
    pub reserved: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct media_links_enum {
    pub entity: u32,
    pub _pad: u32,
    pub pads: *mut media_pad_desc,
    pub links: *mut media_link_desc,
    pub reserved: [u32; 4],
}

// V4L2 ioctls: magic 'V'.
ioctl_read!(vidioc_querycap, b'V', 0, v4l2_capability);
ioctl_readwrite!(vidioc_enum_fmt, b'V', 2, v4l2_fmtdesc);
ioctl_readwrite!(vidioc_g_fmt, b'V', 4, v4l2_format);
ioctl_readwrite!(vidioc_s_fmt, b'V', 5, v4l2_format);
ioctl_readwrite!(vidioc_reqbufs, b'V', 8, v4l2_requestbuffers);
ioctl_readwrite!(vidioc_querybuf, b'V', 9, v4l2_buffer);
ioctl_readwrite!(vidioc_qbuf, b'V', 15, v4l2_buffer);
ioctl_readwrite!(vidioc_dqbuf, b'V', 17, v4l2_buffer);
ioctl_write_ptr!(vidioc_streamon, b'V', 18, u32);
ioctl_write_ptr!(vidioc_streamoff, b'V', 19, u32);
ioctl_readwrite!(vidioc_g_ctrl, b'V', 27, v4l2_control);
ioctl_readwrite!(vidioc_s_ctrl, b'V', 28, v4l2_control);
ioctl_readwrite!(vidioc_query_ext_ctrl, b'V', 103, v4l2_query_ext_ctrl);
// Subdevice ioctls share the magic and the low numbers with the video ones.
ioctl_readwrite!(vidioc_subdev_g_fmt, b'V', 4, v4l2_subdev_format);
ioctl_readwrite!(vidioc_subdev_s_fmt, b'V', 5, v4l2_subdev_format);
// Media controller: magic '|'.
ioctl_readwrite!(media_ioc_device_info, b'|', 0, media_device_info);
ioctl_readwrite!(media_ioc_enum_entities, b'|', 1, media_entity_desc);
ioctl_readwrite!(media_ioc_enum_links, b'|', 2, media_links_enum);
ioctl_readwrite!(media_ioc_setup_link, b'|', 3, media_link_desc);

pub fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod layout_tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn sizes_match_headers() {
        assert_eq!(size_of::<v4l2_capability>(), 104);
        assert_eq!(size_of::<v4l2_fmtdesc>(), 64);
        assert_eq!(size_of::<v4l2_format>(), 208);
        assert_eq!(size_of::<v4l2_pix_format>(), 48);
        assert_eq!(size_of::<v4l2_pix_format_mplane>(), 192);
        assert_eq!(size_of::<v4l2_plane_pix_format>(), 20);
        assert_eq!(size_of::<v4l2_requestbuffers>(), 20);
        assert_eq!(size_of::<v4l2_buffer>(), 88);
        assert_eq!(size_of::<v4l2_plane>(), 64);
        assert_eq!(size_of::<v4l2_control>(), 8);
        assert_eq!(size_of::<v4l2_query_ext_ctrl>(), 232);
        assert_eq!(size_of::<v4l2_mbus_framefmt>(), 48);
        assert_eq!(size_of::<v4l2_subdev_format>(), 88);
        assert_eq!(size_of::<media_device_info>(), 256);
        assert_eq!(size_of::<media_entity_desc>(), 256);
        assert_eq!(size_of::<media_pad_desc>(), 20);
        assert_eq!(size_of::<media_link_desc>(), 52);
        assert_eq!(size_of::<media_links_enum>(), 40);
    }

    #[test]
    fn offsets_match_headers() {
        assert_eq!(offset_of!(v4l2_format, raw), 8);
        assert_eq!(offset_of!(v4l2_pix_format_mplane, plane_fmt), 20);
        assert_eq!(offset_of!(v4l2_pix_format_mplane, num_planes), 180);
        assert_eq!(offset_of!(v4l2_pix_format, bytesperline), 16);
        assert_eq!(offset_of!(v4l2_buffer, timestamp), 24);
        assert_eq!(offset_of!(v4l2_buffer, sequence), 56);
        assert_eq!(offset_of!(v4l2_buffer, m), 64);
        assert_eq!(offset_of!(v4l2_buffer, length), 72);
        assert_eq!(offset_of!(v4l2_plane, m), 8);
        assert_eq!(offset_of!(v4l2_plane, data_offset), 16);
        assert_eq!(offset_of!(v4l2_query_ext_ctrl, minimum), 40);
        assert_eq!(offset_of!(v4l2_query_ext_ctrl, flags), 72);
        assert_eq!(offset_of!(v4l2_capability, capabilities), 84);
        assert_eq!(offset_of!(v4l2_fmtdesc, pixelformat), 44);
        assert_eq!(offset_of!(media_entity_desc, pads), 52);
        assert_eq!(offset_of!(media_entity_desc, reserved), 56);
        assert_eq!(offset_of!(media_entity_desc, rest), 72);
        assert_eq!(offset_of!(media_pad_desc, flags), 8);
        assert_eq!(offset_of!(media_link_desc, sink), 20);
        assert_eq!(offset_of!(media_link_desc, flags), 40);
        assert_eq!(offset_of!(media_links_enum, pads), 8);
        assert_eq!(offset_of!(media_links_enum, links), 16);
        assert_eq!(offset_of!(v4l2_subdev_format, format), 8);
        assert_eq!(offset_of!(v4l2_subdev_format, stream), 56);
    }

    #[test]
    fn ioctl_numbers_match_headers_x86_64() {
        use nix::{request_code_read, request_code_readwrite, request_code_write};
        assert_eq!(
            request_code_read!(b'V', 0, size_of::<v4l2_capability>()),
            0x8068_5600
        );
        assert_eq!(
            request_code_readwrite!(b'V', 5, size_of::<v4l2_format>()),
            0xc0d0_5605
        );
        assert_eq!(
            request_code_readwrite!(b'V', 17, size_of::<v4l2_buffer>()),
            0xc058_5611
        );
        assert_eq!(request_code_write!(b'V', 18, size_of::<u32>()), 0x4004_5612);
        assert_eq!(
            request_code_readwrite!(b'V', 28, size_of::<v4l2_control>()),
            0xc008_561c
        );
        assert_eq!(
            request_code_readwrite!(b'V', 103, size_of::<v4l2_query_ext_ctrl>()),
            0xc0e8_5667
        );
        assert_eq!(
            request_code_readwrite!(b'V', 5, size_of::<v4l2_subdev_format>()),
            0xc058_5605
        );
        assert_eq!(
            request_code_readwrite!(b'|', 1, size_of::<media_entity_desc>()),
            0xc100_7c01
        );
        assert_eq!(
            request_code_readwrite!(b'|', 2, size_of::<media_links_enum>()),
            0xc028_7c02
        );
        assert_eq!(
            request_code_readwrite!(b'|', 3, size_of::<media_link_desc>()),
            0xc034_7c03
        );
    }

    #[test]
    fn fourccs() {
        assert_eq!(V4L2_PIX_FMT_IPU3_Y10, 0x7933_7069);
        assert_eq!(V4L2_PIX_FMT_IPU3_SBGGR10, 0x6233_7069);
        assert_eq!(V4L2_PIX_FMT_GREY, 0x5945_5247);
        assert_eq!(fourcc_str(V4L2_PIX_FMT_IPU3_Y10), "ip3y");
    }
}
