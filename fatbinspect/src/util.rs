use object::Endianness;
use object::read::elf::ElfFile64;
use std::io;

/// A byte range in the input file.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DataLoc {
    pub offset: usize,
    pub size: usize
}

impl DataLoc {
    pub fn end(&self) -> usize {
        self.offset + self.size
    }

    pub fn range(&self) -> std::ops::Range<usize> {
        self.offset..self.end()
    }
}

pub fn err<T>(msg: impl Into<String>) -> io::Result<T> {
    Err(io::Error::other(msg.into()))
}

/// Bounds-checked `data[off..off + len]`.
pub fn bytes(data: &[u8], off: usize, len: usize) -> io::Result<&[u8]> {
    off.checked_add(len)
        .and_then(|end| data.get(off..end))
        .ok_or_else(|| io::Error::other(format!(
            "Truncated input: {:#x}..{:#x} is past the end ({:#x})",
            off, off.saturating_add(len), data.len())))
}

pub fn read_pod<T: bytemuck::Pod>(data: &[u8], off: usize) -> io::Result<T> {
    Ok(bytemuck::pod_read_unaligned(bytes(data, off, std::mem::size_of::<T>())?))
}

pub fn parse_elf(data: &[u8]) -> io::Result<ElfFile64<'_, Endianness>> {
    ElfFile64::<Endianness>::parse(data)
        .or_else(|e| err(format!("Not a 64-bit ELF file: {}", e)))
}

pub fn read_le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

pub fn read_le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

pub fn read_le64(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..(o + 8)].try_into().unwrap())
}

pub fn write_le16(b: &mut [u8], o: usize, val: u16) {
    b[o..(o + 2)].copy_from_slice(&val.to_le_bytes());
}

pub fn write_le32(b: &mut [u8], o: usize, val: u32) {
    b[o..(o + 4)].copy_from_slice(&val.to_le_bytes());
}

pub fn write_le64(b: &mut [u8], o: usize, val: u64) {
    b[o..(o + 8)].copy_from_slice(&val.to_le_bytes());
}
