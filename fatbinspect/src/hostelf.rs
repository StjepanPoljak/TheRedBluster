//! Locate fatbins in a host ELF (see docs/sm50-formats.md §1).

use crate::fatbin;
use crate::util::{err, parse_elf, read_pod};
use object::elf;
use object::read::elf::ElfFile64;
use object::{Endianness, Object, ObjectSection, ObjectSegment, RelocationFlags};
use std::io;

pub const FATBINC_MAGIC: u32 = 0x466243b1;

/// `__fatBinC_Wrapper_t`
#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FatBinPtr {
    pub magic: u32,
    pub version: u32,
    pub fatbin_data: u64,
    pub filename_or_bin: u64
}

/// How a fatbin was found.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Locator {
    /// Via `.nvFatBinSegment[index]`, pointing at virtual address `va`.
    Wrapper { index: usize, version: u32, va: u64 },
    /// By scanning `.nv_fatbin` for headers; no wrapper points at it.
    Scan
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct FatbinLoc {
    /// File offset of the fatbin header.
    pub offset: usize,
    pub via: Locator
}

/// Map a virtual address to a file offset through the PT_LOAD segments.
fn va_to_offset(elf: &ElfFile64<Endianness>, va: u64) -> Option<usize> {
    elf.segments().find_map(|seg| {
        let (file_off, file_size) = seg.file_range();
        let start = seg.address();
        if va >= start && va - start < file_size {
            file_off.checked_add(va - start).map(|off| off as usize)
        } else {
            None
        }
    })
}

/// Addend of the R_X86_64_RELATIVE relocation that patches the u64 at `va`.
fn relative_reloc_at(elf: &ElfFile64<Endianness>, va: u64) -> Option<u64> {
    elf.dynamic_relocations()?.find_map(|(off, rel)| {
        let is_relative = matches!(rel.flags(),
            RelocationFlags::Elf { r_type } if r_type == elf::R_X86_64_RELATIVE);
        (off == va && is_relative).then(|| rel.addend() as u64)
    })
}

/// Find fatbin headers via the wrapper array in `.nvFatBinSegment`.
/// Returns `None` if any wrapper is invalid or cannot be resolved to a file offset.
fn find_via_wrappers(elf: &ElfFile64<Endianness>, data: &[u8]) -> io::Result<Option<Vec<FatbinLoc>>> {
    let Some(sec) = elf.section_by_name(".nvFatBinSegment") else {
        return Ok(None);
    };
    let Some((sec_off, sec_size)) = sec.file_range() else {
        return Ok(None);
    };
    let ptr_size = std::mem::size_of::<FatBinPtr>();
    let mut locs = Vec::new();

    for index in 0..(sec_size as usize / ptr_size) {
        let ptr: FatBinPtr = read_pod(data, (sec_off as usize).saturating_add(index * ptr_size))?;
        if ptr.magic != FATBINC_MAGIC {
            return Ok(None);
        }

        // lld leaves 0 in place and only emits the relocation.
        let mut va = ptr.fatbin_data;
        if va == 0 {
            let field_va = sec.address().wrapping_add((index * ptr_size) as u64 + 8);
            va = relative_reloc_at(elf, field_va).unwrap_or(0);
        }

        match va_to_offset(elf, va) {
            Some(offset) if va != 0 => locs.push(FatbinLoc {
                offset,
                via: Locator::Wrapper { index, version: ptr.version, va }
            }),
            _ => return Ok(None)
        }
    }

    Ok(Some(locs))
}

/// Scan `.nv_fatbin` for fatbin headers.
fn find_via_scan(elf: &ElfFile64<Endianness>, data: &[u8]) -> io::Result<Option<Vec<FatbinLoc>>> {
    let Some((offset, size)) = elf.section_by_name(".nv_fatbin").and_then(|s| s.file_range()) else {
        return Ok(None);
    };
    let (offset, size) = (offset as usize, size as usize);
    Ok(Some(fatbin::scan(crate::util::bytes(data, offset, size)?, offset)?
        .into_iter()
        .map(|offset| FatbinLoc { offset, via: Locator::Scan })
        .collect()))
}

/// Find all fatbins in a host ELF, ordered by file offset.
///
/// Not every fatbin in `.nv_fatbin` has a wrapper (e.g. the first of 11 in
/// libnvjpeg 12.3), so this is the union of the scan and the wrappers.
pub fn find_fatbins(data: &[u8]) -> io::Result<Vec<FatbinLoc>> {
    let elf = parse_elf(data)?;
    let wrapped = find_via_wrappers(&elf, data)?;
    let scanned = find_via_scan(&elf, data)?;
    if wrapped.is_none() && scanned.is_none() {
        return err("No .nvFatBinSegment or .nv_fatbin section found.");
    }

    // Wrappers first, so a fatbin found both ways keeps its wrapper info.
    let mut locs: Vec<FatbinLoc> = Vec::new();
    for loc in wrapped.unwrap_or_default().into_iter().chain(scanned.unwrap_or_default()) {
        if !locs.iter().any(|l| l.offset == loc.offset) {
            locs.push(loc);
        }
    }
    locs.sort_by_key(|l| l.offset);
    Ok(locs)
}

/// Find and parse all fatbins in a host ELF.
pub fn parse_fatbins(data: &[u8]) -> io::Result<Vec<fatbin::FatBin>> {
    find_fatbins(data)?
        .into_iter()
        .map(|loc| fatbin::parse_at(data, loc.offset))
        .collect()
}
