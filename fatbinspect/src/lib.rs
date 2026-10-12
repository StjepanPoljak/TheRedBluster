//! Parsers for CUDA host binaries, fatbins and cubins.
//!
//! Parsers take the bytes of one object plus `base`, the file offset of those
//! bytes, and return absolute file offsets. They never print.

pub mod compress;
pub mod cubin;
pub mod decode;
pub mod fatbin;
pub mod hostelf;
pub mod util;

use object::elf;
use object::read::elf::FileHeader;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InputKind {
    /// Host ELF with embedded fatbins.
    Host,
    /// Raw fatbin (`nvcc -fatbin`).
    Fatbin,
    /// CUDA ELF (`EM_CUDA`).
    Cubin
}

impl InputKind {
    pub fn name(self) -> &'static str {
        match self {
            InputKind::Host => "host binary",
            InputKind::Fatbin => "fatbin",
            InputKind::Cubin => "cubin"
        }
    }
}

/// Guess the input kind from its contents.
pub fn detect(data: &[u8]) -> Option<InputKind> {
    if util::read_pod::<u32>(data, 0).ok()? == fatbin::FATBIN_MAGIC {
        return Some(InputKind::Fatbin);
    }
    let elf = util::parse_elf(data).ok()?;
    if elf.elf_header().e_machine(elf.endian()) == elf::EM_CUDA {
        Some(InputKind::Cubin)
    } else {
        Some(InputKind::Host)
    }
}
