//! What an ELF file's dynamic symbol table says of one name (round 19):
//! whether the file imports it, exports it, or has nothing by it. Doctor
//! and the package's tests use it to hold the key check's libfido2
//! wrapper to its two ends: the helper exports `fido_dev_get_assert`, and
//! pam_u2f imports it, so the dynamic linker binds pam_u2f's call to the
//! wrapper (`keycheck_cancel.rs`).

use std::path::Path;

/// What a file's dynamic symbol table says of a name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sym {
    /// Used, and defined elsewhere: the dynamic linker binds it.
    Imported,
    /// Defined here, global or weak, and visible to other objects.
    Exported,
    /// Not in the table, or there and neither of the above.
    Absent,
}

/// The dynamic symbol `name` in the ELF file at `path`; None when the file
/// cannot be read or is not a whole 64-bit little-endian ELF file.
pub fn dynamic_symbol_of(path: &Path, name: &str) -> Option<Sym> {
    dynamic_symbol(&std::fs::read(path).ok()?, name)
}

/// The dynamic symbol `name` in the ELF file `elf`, from its section
/// table's `SHT_DYNSYM` and the string table that section links; None for
/// anything that is not a whole 64-bit little-endian ELF file. Every
/// offset is checked against the bytes before it is read.
pub fn dynamic_symbol(elf: &[u8], name: &str) -> Option<Sym> {
    const SHT_DYNSYM: u32 = 11;
    const SHT_STRTAB: u32 = 3;
    const SHDR: usize = 64;
    const SYM: usize = 24;
    if elf.get(..6)? != b"\x7fELF\x02\x01" {
        return None;
    }
    let shoff = usize::try_from(u64_at(elf, 0x28)?).ok()?;
    let shentsize = usize::from(u16_at(elf, 0x3a)?);
    let shnum = usize::from(u16_at(elf, 0x3c)?);
    if shentsize != SHDR || shnum == 0 {
        return None;
    }
    let table = elf.get(shoff..shoff.checked_add(shnum.checked_mul(SHDR)?)?)?;
    let header =
        |i: usize| table.get(i.checked_mul(SHDR)?..i.checked_mul(SHDR)?.checked_add(SHDR)?);
    // A section's bytes, read only for the two sections used: others (a
    // `.bss` among them) may name sizes no file holds.
    let bytes = |h: &[u8]| -> Option<&[u8]> {
        let off = usize::try_from(u64_at(h, 0x18)?).ok()?;
        let size = usize::try_from(u64_at(h, 0x20)?).ok()?;
        elf.get(off..off.checked_add(size)?)
    };
    let mut found = Sym::Absent;
    let mut dynsym = None;
    for i in 0..shnum {
        let h = header(i)?;
        if u32_at(h, 4)? == SHT_DYNSYM {
            dynsym = Some(h);
        }
    }
    let Some(dynsym) = dynsym else {
        return Some(found);
    };
    let syms = bytes(dynsym)?;
    let strtab = header(usize::try_from(u32_at(dynsym, 0x28)?).ok()?)?;
    if u32_at(strtab, 4)? != SHT_STRTAB || syms.len() % SYM != 0 {
        return None;
    }
    let strings = bytes(strtab)?;
    for s in syms.as_chunks::<SYM>().0 {
        let at = usize::try_from(u32_at(s, 0)?).ok()?;
        let tail = strings.get(at..)?;
        let end = tail.iter().position(|&b| b == 0)?;
        if &tail[..end] != name.as_bytes() {
            continue;
        }
        let bind = s[4] >> 4;
        let visible = s[5] & 0x3 == 0;
        let shndx = u16_at(s, 6)?;
        found = match (shndx, bind) {
            (0, _) => Sym::Imported,
            (_, 1 | 2) if visible => Sym::Exported,
            _ => found,
        };
        if found != Sym::Absent {
            break;
        }
    }
    Some(found)
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        b.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        b.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        b.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Round 19: imports and exports are read off real ELF files, and
    /// bytes that are not a whole 64-bit little-endian ELF file read as
    /// nothing, never as a symbol and never as a panic.
    #[test]
    fn dynamic_symbols_are_read_and_anything_else_is_none() {
        let me = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        assert!(
            ["malloc", "write", "pthread_create"]
                .iter()
                .any(|n| dynamic_symbol(&me, n) == Some(Sym::Imported)),
            "the test binary takes something from libc"
        );
        assert_eq!(
            dynamic_symbol(&me, "faceauth_no_such_symbol"),
            Some(Sym::Absent)
        );
        if let Ok(libc) = std::fs::read("/usr/lib/libc.so.6") {
            assert_eq!(dynamic_symbol(&libc, "malloc"), Some(Sym::Exported));
        }
        assert_eq!(
            dynamic_symbol(b"plain text, not an ELF file", "malloc"),
            None
        );
        assert_eq!(dynamic_symbol(&[], "malloc"), None);
        // A file cut short anywhere reads as nothing.
        let step = (me.len() / 512).max(1);
        for len in (0..me.len()).step_by(step) {
            assert_eq!(dynamic_symbol(&me[..len], "malloc"), None, "cut at {}", len);
        }
        // A section table placed past the end is nothing.
        let mut bad = me.clone();
        bad[0x28..0x30].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(dynamic_symbol(&bad, "malloc"), None);
        assert_eq!(
            dynamic_symbol_of(std::path::Path::new("/nonexistent/faceauth"), "malloc"),
            None
        );
    }
}
