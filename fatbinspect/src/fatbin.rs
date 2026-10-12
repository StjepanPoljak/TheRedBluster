//! Fatbin container: header + entries (see docs/sm50-formats.md §2).

use crate::compress::{self, Compression};
use crate::util::{DataLoc, bytes, err, read_pod};
use std::borrow::Cow;
use std::io;

pub const FATBIN_MAGIC: u32 = 0xba55ed50;

pub const KIND_PTX: u16 = 1;
pub const KIND_ELF: u16 = 2;

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FatBinHdr {
    pub magic: u32,
    pub version: u16,
    pub header_size: u16,
    pub fatbin_size: u64
}

#[repr(C)]
#[derive(Copy, Clone, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FatBinInfo {
    pub kind: u16,
    pub version: u16,
    pub header_size: u32,
    pub padded_payload_size: u64,
    pub compressed_size: u32,
    pub options_desc_offset: u32,
    pub code_version_minor: u16,
    pub code_version_major: u16,
    pub arch: u32,
    pub identifier_offset: u32,
    pub ident_len: u32,
    pub flags: u64,
    pub reserved: u64,
    pub uncompressed_size: u64
}

pub struct FatBinEntry {
    /// File offset of the entry header.
    pub offset: usize,
    pub info: FatBinInfo,
    /// The padded payload.
    pub payload: DataLoc
}

impl FatBinEntry {
    pub fn compression(&self) -> Option<Compression> {
        Compression::from_flags(self.info.flags)
    }

    /// The payload bytes, decompressed if needed. Uncompressed payloads are
    /// borrowed from `data` (the whole file) and still include padding.
    pub fn payload_bytes<'a>(&self, data: &'a [u8]) -> io::Result<Cow<'a, [u8]>> {
        let payload = &data[self.payload.range()];
        let Some(c) = self.compression() else {
            return Ok(Cow::Borrowed(payload));
        };
        let stored = payload.get(..self.info.compressed_size as usize)
            .ok_or_else(|| io::Error::other("compressed_size exceeds the payload"))?;
        Ok(Cow::Owned(compress::decompress(c, stored, self.info.uncompressed_size as usize)?))
    }
}

pub struct FatBin {
    /// File offset of the fatbin header.
    pub offset: usize,
    pub hdr: FatBinHdr,
    pub entries: Vec<FatBinEntry>
}

impl FatBin {
    /// Header plus entries.
    pub fn size(&self) -> usize {
        self.hdr.header_size as usize + self.hdr.fatbin_size as usize
    }
}

/// Parse the fatbin starting at `data[0]`, which is at file offset `base`.
pub fn parse(data: &[u8], base: usize) -> io::Result<FatBin> {
    let hdr: FatBinHdr = read_pod(data, 0)?;
    if hdr.magic != FATBIN_MAGIC {
        return err(format!("Invalid magic in FatBinHdr at {:#x}: {:#x}", base, hdr.magic));
    }

    let mut curr_off = hdr.header_size as usize;
    let Some(end_off) = curr_off.checked_add(hdr.fatbin_size as usize) else {
        return err(format!("Invalid fatbin_size at {:#x}: {:#x}", base, hdr.fatbin_size));
    };
    bytes(data, 0, end_off)?;
    let mut entries = Vec::<FatBinEntry>::new();

    while curr_off < end_off {
        let info: FatBinInfo = read_pod(data, curr_off)?;
        if (info.header_size as usize) < std::mem::size_of::<FatBinInfo>() {
            return err(format!("Invalid FatBin entry header_size at {:#x}: {:#x}",
                        base + curr_off, info.header_size));
        }
        let payload_offset = curr_off + info.header_size as usize;
        let payload_size = info.padded_payload_size as usize;
        bytes(data, payload_offset, payload_size)?;

        entries.push(FatBinEntry {
            offset: base + curr_off,
            info,
            payload: DataLoc { offset: base + payload_offset, size: payload_size }
        });
        curr_off = payload_offset + payload_size;
    }

    Ok(FatBin { offset: base, hdr, entries })
}

/// Parse the fatbin at file offset `offset` of `data` (the whole file).
pub fn parse_at(data: &[u8], offset: usize) -> io::Result<FatBin> {
    match data.get(offset..) {
        Some(rest) => parse(rest, offset),
        None => err(format!("FatBin offset {:#x} is past the end of the file", offset))
    }
}

/// Find consecutive, 8-byte aligned fatbin headers in `data` (at file offset
/// `base`). Returns their file offsets.
pub fn scan(data: &[u8], base: usize) -> io::Result<Vec<usize>> {
    let hdr_size = std::mem::size_of::<FatBinHdr>();
    let mut offsets = Vec::new();
    let mut off = 0;

    while off + hdr_size <= data.len() {
        let hdr: FatBinHdr = read_pod(data, off)?;
        if hdr.magic == FATBIN_MAGIC {
            offsets.push(base + off);
            let next = (off + hdr.header_size as usize).checked_add(hdr.fatbin_size as usize)
                .and_then(|next| next.max(off + 8).checked_next_multiple_of(8));
            match next {
                Some(next) => off = next,
                None => break
            }
        } else {
            off += 8;
        }
    }

    Ok(offsets)
}

/// Parse a standalone fatbin file: one or more consecutive fatbins.
pub fn parse_file(data: &[u8]) -> io::Result<Vec<FatBin>> {
    let offsets = scan(data, 0)?;
    if offsets.first() != Some(&0) {
        return err("Not a fatbin: no fatbin header at offset 0.");
    }
    offsets.into_iter().map(|off| parse(&data[off..], off)).collect()
}
