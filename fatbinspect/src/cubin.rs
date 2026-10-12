//! Cubin (CUDA ELF) sections and kernels (see docs/sm50-formats.md §3).

use crate::util::{DataLoc, err, parse_elf};
use object::elf;
use object::read::elf::{FileHeader, SectionHeader};
use object::{Object, ObjectSection, ObjectSymbol, SymbolIndex};
use std::io;

/// `.nv.shared.<fn>` in `ET_REL` cubins: no file data, like `SHT_NOBITS`.
pub const SHT_CUDA_SHARED: u32 = 0x7000000a;

/// `st_other` bit marking a kernel entry point.
pub const STO_CUDA_ENTRY: u8 = 0x10;

pub struct Section {
    pub index: usize,
    pub name: String,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_entsize: u64,
    pub sh_addralign: u64,
    /// `sh_size`; also set for sections without file data (e.g. shared memory).
    pub size: u64,
    /// `None` for sections without file data (`SHT_NOBITS`).
    pub file: Option<DataLoc>
}

pub struct Kernel {
    /// Function name (mangled), i.e. the `.text.<fn>` suffix.
    pub name: String,
    pub section_index: usize,
    /// Function symbol (`sh_info` bits 0–23 of `.text.<fn>`).
    pub symbol_index: usize,
    pub text: DataLoc,
    /// From `EIATTR_REGCOUNT` in `.nv.info`, else `sh_info` bits 24–31
    /// (sm_90 leaves those 0).
    pub regs: u32,
    pub barriers: u32,
    pub is_entry: bool
}

pub struct Cubin {
    pub osabi: u8,
    pub abi_version: u8,
    pub e_type: u16,
    /// CUDA toolkit version × 10 + minor (124 = 12.4).
    pub e_version: u32,
    pub e_flags: u32,
    /// Real ELF size: the end of the furthest header table or section data.
    /// A cubin in a fatbin entry is followed by padding.
    pub size: usize,
    pub sections: Vec<Section>,
    pub kernels: Vec<Kernel>,
    /// Symbol names by symbol index (index 0 is the null symbol).
    pub symbols: Vec<String>
}

impl Cubin {
    /// Real SM number (`EF_CUDA_SM`, ABI v7).
    pub fn sm(&self) -> u32 {
        self.e_flags & 0xff
    }

    pub fn section_by_name(&self, name: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.name == name)
    }

    pub fn symbol_name(&self, index: usize) -> Option<&str> {
        self.symbols.get(index).map(|s| s.as_str())
    }
}

/// Parse the cubin `data`, which is at file offset `base`.
pub fn parse(data: &[u8], base: usize) -> io::Result<Cubin> {
    let elf = parse_elf(data)?;
    let endian = elf.endian();
    let header = elf.elf_header();
    if header.e_machine(endian) != elf::EM_CUDA {
        return err("Not a cubin (e_machine is not EM_CUDA).");
    }

    let shnum = header.shnum(endian, data).or_else(|e| err(format!("Bad section count: {}", e)))?;
    let phnum = header.phnum(endian, data).or_else(|e| err(format!("Bad segment count: {}", e)))?;
    let table_end = |off: u64, num: u32, entsize: u16| {
        (off as usize).saturating_add(num as usize * entsize as usize)
    };
    let mut size = table_end(header.e_shoff(endian), shnum, header.e_shentsize(endian))
        .max(table_end(header.e_phoff(endian), phnum, header.e_phentsize(endian)))
        .max(std::mem::size_of::<elf::FileHeader64<object::Endianness>>());

    let mut sections = Vec::new();
    let mut kernels = Vec::new();

    for section in elf.sections() {
        let index = section.index().0;
        let name = String::from(section.name().unwrap_or("?"));
        let shdr = section.elf_section_header();

        let sh_type = shdr.sh_type(endian).0;
        let file = match section.file_range().filter(|_| sh_type != SHT_CUDA_SHARED) {
            Some((off, len)) if off.saturating_add(len) > data.len() as u64 => {
                return err(format!("Section '{}' extends past the end of the cubin.", name));
            },
            Some((off, len)) => {
                size = size.max((off + len) as usize);
                Some(DataLoc { offset: base + off as usize, size: len as usize })
            },
            None => None
        };

        if let (Some(fn_name), Some(text)) = (name.strip_prefix(".text."), file) {
            let sh_info = shdr.sh_info(endian);
            let sh_flags = shdr.sh_flags(endian).0;
            let symbol_index = (sh_info & 0xffffff) as usize;
            let is_entry = elf.symbol_by_index(SymbolIndex(symbol_index))
                .map(|sym| sym.elf_symbol().st_other.0 & STO_CUDA_ENTRY != 0)
                .unwrap_or(false);
            kernels.push(Kernel {
                name: String::from(fn_name),
                section_index: index,
                symbol_index,
                text,
                regs: sh_info >> 24,
                barriers: ((sh_flags >> 20) & 0x7f) as u32,
                is_entry
            });
        }

        sections.push(Section {
            index,
            name,
            sh_type,
            sh_flags: shdr.sh_flags(endian).0,
            sh_link: shdr.sh_link(endian),
            sh_info: shdr.sh_info(endian),
            sh_entsize: shdr.sh_entsize(endian),
            sh_addralign: shdr.sh_addralign(endian),
            size: shdr.sh_size(endian),
            file
        });
    }

    // EIATTR_REGCOUNT overrides the register count in sh_info.
    if let Some(loc) = sections.iter().find(|s| s.name == ".nv.info").and_then(|s| s.file) {
        let records = crate::decode::parse_nvinfo(&data[loc.offset - base..loc.end() - base]).unwrap_or_default();
        for rec in records.iter().filter(|r| r.attr == crate::decode::EIATTR_REGCOUNT) {
            if let [sym, regs] = rec.words()[..] {
                for k in kernels.iter_mut().filter(|k| k.symbol_index == sym as usize) {
                    k.regs = regs;
                }
            }
        }
    }

    let mut symbols = Vec::new();
    for sym in elf.symbols() {
        let i = sym.index().0;
        if symbols.len() <= i {
            symbols.resize(i + 1, String::new());
        }
        symbols[i] = String::from(sym.name().unwrap_or("?"));
    }

    let ident = header.e_ident();
    Ok(Cubin {
        osabi: ident.os_abi.0,
        abi_version: ident.abi_version,
        e_type: header.e_type(endian).0,
        e_version: header.e_version(endian),
        e_flags: header.e_flags(endian).0,
        size: size.min(data.len()),
        sections,
        kernels,
        symbols
    })
}
