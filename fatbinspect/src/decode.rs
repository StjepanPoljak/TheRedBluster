//! Decoding of fatbin and cubin metadata (see docs/sm50-formats.md).
//!
//! Functions that take `bytes` index it with the offsets of a parsed object, so
//! `bytes` must be the buffer the object was parsed from (with its `base`).

use crate::cubin::{Cubin, Kernel};
use crate::fatbin::{self, FatBinEntry};
use crate::util::{err, read_pod};
use std::io;

// ---------------------------------------------------------------------------
// Fatbin entries (§2.2, §2.3)

pub fn entry_kind_name(kind: u16) -> &'static str {
    match kind {
        fatbin::KIND_PTX => "PTX",
        fatbin::KIND_ELF => "ELF",
        4 => "old cubin",
        _ => "unknown"
    }
}

const ENTRY_FLAGS: &[(u64, &str)] = &[
    (0x0001, "64-bit"),
    (0x0002, "debug"),
    (0x0010, "linux"),
    (0x0020, "macOS"),
    (0x0040, "windows"),
    (0x1000, "zlib"),
    (0x2000, "LZ4"),
    (0x4000, "LZ4v2"),
    (0x8000, "zstd")
];

/// Names of the set entry flags; unknown bits are shown in hex.
pub fn entry_flag_names(flags: u64) -> Vec<String> {
    let mut names: Vec<String> = ENTRY_FLAGS.iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| String::from(*name))
        .collect();
    let unknown = ENTRY_FLAGS.iter().fold(flags, |f, (bit, _)| f & !bit);
    if unknown != 0 {
        names.push(format!("{:#x}", unknown));
    }
    names
}

/// A string in the entry header area at entry-relative `offset`.
fn entry_string(data: &[u8], entry: &FatBinEntry, offset: u32, len: u32) -> Option<String> {
    let header_end = entry.offset + entry.info.header_size as usize;
    let start = entry.offset.checked_add(offset as usize)?;
    let end = start.checked_add(len as usize)?;
    if offset == 0 || end > header_end {
        return None;
    }
    let bytes = data.get(start..end)?;
    Some(String::from_utf8_lossy(bytes).trim_end_matches('\0').to_string())
}

/// `fatbinary --ident` string.
pub fn entry_ident(data: &[u8], entry: &FatBinEntry) -> Option<String> {
    entry_string(data, entry, entry.info.identifier_offset, entry.info.ident_len)
}

/// ptxas options (`fatbinary --cmdline`), from the options descriptor.
pub fn entry_ptxas_options(data: &[u8], entry: &FatBinEntry) -> Option<String> {
    let desc = entry.info.options_desc_offset;
    if desc == 0 || desc as usize + 8 > entry.info.header_size as usize {
        return None;
    }
    let [offset, len]: [u32; 2] = read_pod(data, entry.offset + desc as usize).ok()?;
    entry_string(data, entry, offset, len)
}

// ---------------------------------------------------------------------------
// Cubin ELF header (§3.1, §3.2)

/// `e_version` as a toolkit version: 124 → "12.4".
pub fn toolkit_version(e_version: u32) -> String {
    format!("{}.{}", e_version / 10, e_version % 10)
}

/// Decoded `e_flags` (ABI v7).
pub fn e_flags_names(flags: u32) -> Vec<String> {
    let mut names = vec![format!("sm_{}", flags & 0xff)];
    let virt = (flags >> 16) & 0xff;
    if virt != 0 {
        names.push(format!("virtual compute_{}", virt));
    }
    for (bit, name) in [(0x100, "texmode unified"), (0x200, "texmode independent"),
                        (0x400, "64-bit address"), (0x800, "accelerators"), (0x1000, "sw flag v2")] {
        if flags & bit != 0 {
            names.push(String::from(name));
        }
    }
    let unknown = flags & !0x00ff_1fff;
    if unknown != 0 {
        names.push(format!("{:#x}", unknown));
    }
    names
}

pub fn osabi_name(osabi: u8) -> String {
    match osabi {
        0x33 => String::from("CUDA"),
        0x41 => String::from("CUDA v2"),
        x => format!("{:#x}", x)
    }
}

// ---------------------------------------------------------------------------
// Section types (§3.3); names as cuobjdump prints them.

pub fn section_type_name(sh_type: u32) -> String {
    let name = match sh_type {
        0 => "NULL",
        1 => "PROGBITS",
        2 => "SYMTAB",
        3 => "STRTAB",
        4 => "RELA",
        5 => "HASH",
        6 => "DYNAMIC",
        7 => "NOTE",
        8 => "NOBITS",
        9 => "REL",
        11 => "DYNSYM",
        0x7000_0000 => "CUDA_INFO",
        0x7000_0001 => "CUDA_CALLGRAPH",
        0x7000_000a => "CUDA_SHARED",
        0x7000_000b => "CUDA_RELOCINFO",
        t @ 0x7000_0064..=0x7000_0075 => return format!("CUDA_CONSTANT_B{}", t - 0x7000_0064),
        t => return format!("{:#x}", t)
    };
    String::from(name)
}

// ---------------------------------------------------------------------------
// .nv.info records (§3.6)

pub const EIFMT_NVAL: u8 = 1;
pub const EIFMT_BVAL: u8 = 2;
pub const EIFMT_HVAL: u8 = 3;
pub const EIFMT_SVAL: u8 = 4;

pub fn eifmt_name(format: u8) -> Option<&'static str> {
    match format {
        EIFMT_NVAL => Some("EIFMT_NVAL"),
        EIFMT_BVAL => Some("EIFMT_BVAL"),
        EIFMT_HVAL => Some("EIFMT_HVAL"),
        EIFMT_SVAL => Some("EIFMT_SVAL"),
        _ => None
    }
}

/// EIATTR codes (CuAssembler `CuNVInfo.py`). The codes seen in toolkit
/// libraries are checked against `cuobjdump -elf` by the tests.
const EIATTR_NAMES: [&str; 0x51] = [
    "EIATTR_ERROR", "EIATTR_PAD", "EIATTR_IMAGE_SLOT", "EIATTR_JUMPTABLE_RELOCS",
    "EIATTR_CTAIDZ_USED", "EIATTR_MAX_THREADS", "EIATTR_IMAGE_OFFSET", "EIATTR_IMAGE_SIZE",
    "EIATTR_TEXTURE_NORMALIZED", "EIATTR_SAMPLER_INIT", "EIATTR_PARAM_CBANK", "EIATTR_SMEM_PARAM_OFFSETS",
    "EIATTR_CBANK_PARAM_OFFSETS", "EIATTR_SYNC_STACK", "EIATTR_TEXID_SAMPID_MAP", "EIATTR_EXTERNS",
    "EIATTR_REQNTID", "EIATTR_FRAME_SIZE", "EIATTR_MIN_STACK_SIZE", "EIATTR_SAMPLER_FORCE_UNNORMALIZED",
    "EIATTR_BINDLESS_IMAGE_OFFSETS", "EIATTR_BINDLESS_TEXTURE_BANK", "EIATTR_BINDLESS_SURFACE_BANK", "EIATTR_KPARAM_INFO",
    "EIATTR_SMEM_PARAM_SIZE", "EIATTR_CBANK_PARAM_SIZE", "EIATTR_QUERY_NUMATTRIB", "EIATTR_MAXREG_COUNT",
    "EIATTR_EXIT_INSTR_OFFSETS", "EIATTR_S2RCTAID_INSTR_OFFSETS", "EIATTR_CRS_STACK_SIZE", "EIATTR_NEED_CNP_WRAPPER",
    "EIATTR_NEED_CNP_PATCH", "EIATTR_EXPLICIT_CACHING", "EIATTR_ISTYPEP_USED", "EIATTR_MAX_STACK_SIZE",
    "EIATTR_SUQ_USED", "EIATTR_LD_CACHEMOD_INSTR_OFFSETS", "EIATTR_LOAD_CACHE_REQUEST", "EIATTR_ATOM_SYS_INSTR_OFFSETS",
    "EIATTR_COOP_GROUP_INSTR_OFFSETS", "EIATTR_COOP_GROUP_MASK_REGIDS", "EIATTR_SW1850030_WAR", "EIATTR_WMMA_USED",
    "EIATTR_HAS_PRE_V10_OBJECT", "EIATTR_ATOMF16_EMUL_INSTR_OFFSETS", "EIATTR_ATOM16_EMUL_INSTR_REG_MAP", "EIATTR_REGCOUNT",
    "EIATTR_SW2393858_WAR", "EIATTR_INT_WARP_WIDE_INSTR_OFFSETS", "EIATTR_SHARED_SCRATCH", "EIATTR_STATISTICS",
    "EIATTR_INDIRECT_BRANCH_TARGETS", "EIATTR_SW2861232_WAR", "EIATTR_SW_WAR", "EIATTR_CUDA_API_VERSION",
    "EIATTR_NUM_MBARRIERS", "EIATTR_MBARRIER_INSTR_OFFSETS", "EIATTR_COROUTINE_RESUME_ID_OFFSETS", "EIATTR_SAM_REGION_STACK_SIZE",
    "EIATTR_PER_REG_TARGET_PERF_STATS", "EIATTR_CTA_PER_CLUSTER", "EIATTR_EXPLICIT_CLUSTER", "EIATTR_MAX_CLUSTER_RANK",
    "EIATTR_INSTR_REG_MAP", "EIATTR_RESERVED_SMEM_USED", "EIATTR_RESERVED_SMEM_0_SIZE", "EIATTR_UCODE_SECTION_DATA",
    "EIATTR_UNUSED_LOAD_BYTE_OFFSET", "EIATTR_KPARAM_INFO_V2", "EIATTR_SYSCALL_OFFSETS", "EIATTR_SW_WAR_MEMBAR_SYS_INSTR_OFFSETS",
    "EIATTR_GRAPHICS_GLOBAL_CBANK", "EIATTR_SHADER_TYPE", "EIATTR_VRC_CTA_INIT_COUNT", "EIATTR_TOOLS_PATCH_FUNC",
    "EIATTR_NUM_BARRIERS", "EIATTR_TEXMODE_INDEPENDENT", "EIATTR_PERF_STATISTICS", "EIATTR_AT_ENTRY_FRAGMENTS",
    "EIATTR_SPARSE_MMA_MASK"
];

pub fn eiattr_name(attr: u8) -> Option<&'static str> {
    EIATTR_NAMES.get(attr as usize).copied()
}

pub const EIATTR_PARAM_CBANK: u8 = 0x0a;
pub const EIATTR_REQNTID: u8 = 0x10;
pub const EIATTR_MAX_THREADS: u8 = 0x05;
pub const EIATTR_FRAME_SIZE: u8 = 0x11;
pub const EIATTR_MIN_STACK_SIZE: u8 = 0x12;
pub const EIATTR_KPARAM_INFO: u8 = 0x17;
pub const EIATTR_CBANK_PARAM_SIZE: u8 = 0x19;
pub const EIATTR_MAXREG_COUNT: u8 = 0x1b;
pub const EIATTR_EXIT_INSTR_OFFSETS: u8 = 0x1c;
pub const EIATTR_S2RCTAID_INSTR_OFFSETS: u8 = 0x1d;
pub const EIATTR_CRS_STACK_SIZE: u8 = 0x1e;
pub const EIATTR_MAX_STACK_SIZE: u8 = 0x23;
pub const EIATTR_REGCOUNT: u8 = 0x2f;
pub const EIATTR_CUDA_API_VERSION: u8 = 0x37;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NvInfoValue {
    /// `EIFMT_NVAL`
    None,
    /// `EIFMT_BVAL` / `EIFMT_HVAL`
    Half(u16),
    /// `EIFMT_SVAL`
    Bytes(Vec<u8>)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NvInfoRecord {
    /// Offset within the section.
    pub offset: usize,
    pub format: u8,
    pub attr: u8,
    pub value: NvInfoValue
}

impl NvInfoRecord {
    /// SVAL payload as little-endian u32 words (trailing bytes ignored).
    pub fn words(&self) -> Vec<u32> {
        match &self.value {
            NvInfoValue::Bytes(b) => b.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect(),
            NvInfoValue::Half(h) => vec![*h as u32],
            NvInfoValue::None => Vec::new()
        }
    }
}

/// Parse a `.nv.info` / `.nv.info.<fn>` section.
pub fn parse_nvinfo(bytes: &[u8]) -> io::Result<Vec<NvInfoRecord>> {
    let mut records = Vec::new();
    let mut off = 0;
    while off < bytes.len() {
        let Some(&[format, attr, lo, hi]) = bytes.get(off..off + 4) else {
            return err(format!(".nv.info record at {:#x} is truncated", off));
        };
        let half = u16::from_le_bytes([lo, hi]);
        let (value, next) = match format {
            EIFMT_NVAL => (NvInfoValue::None, off + 4),
            EIFMT_BVAL | EIFMT_HVAL => (NvInfoValue::Half(half), off + 4),
            EIFMT_SVAL => {
                let Some(payload) = bytes.get(off + 4..off + 4 + half as usize) else {
                    return err(format!(".nv.info record at {:#x} is truncated", off));
                };
                (NvInfoValue::Bytes(payload.to_vec()), off + 4 + half as usize)
            },
            f => return err(format!(".nv.info record at {:#x} has unknown format {}", off, f))
        };
        records.push(NvInfoRecord { offset: off, format, attr, value });
        off = next;
    }
    Ok(records)
}

/// `.nv.info` records of section `index` of `cubin`.
pub fn section_nvinfo(cubin: &Cubin, bytes: &[u8], index: usize) -> io::Result<Vec<NvInfoRecord>> {
    let Some(loc) = cubin.sections.iter().find(|s| s.index == index).and_then(|s| s.file) else {
        return Ok(Vec::new());
    };
    match bytes.get(loc.range()) {
        Some(data) => parse_nvinfo(data),
        None => err("Section is outside the buffer.")
    }
}

/// `KPARAM_INFO`: one kernel parameter.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Param {
    pub index: u32,
    pub ordinal: u16,
    /// Offset within the parameter area.
    pub offset: u16,
    pub size: u32,
    pub log_align: u8,
    pub space: u8,
    pub cbank: u8,
    pub is_cbank: bool
}

impl Param {
    pub fn from_record(rec: &NvInfoRecord) -> Option<Param> {
        let NvInfoValue::Bytes(b) = &rec.value else { return None };
        if rec.attr != EIATTR_KPARAM_INFO || b.len() < 12 {
            return None;
        }
        let w = u32::from_le_bytes(b[8..12].try_into().unwrap());
        Some(Param {
            index: u32::from_le_bytes(b[0..4].try_into().unwrap()),
            ordinal: u16::from_le_bytes([b[4], b[5]]),
            offset: u16::from_le_bytes([b[6], b[7]]),
            size: w >> 18,
            log_align: (w & 0xff) as u8,
            space: ((w >> 8) & 0xf) as u8,
            cbank: ((w >> 12) & 0x1f) as u8,
            is_cbank: (w >> 17) & 1 != 0
        })
    }
}

/// Human-readable value of a record. `sym` names a symbol index.
pub fn format_nvinfo_value(rec: &NvInfoRecord, sym: &dyn Fn(u32) -> String) -> String {
    let words = rec.words();
    let hex_words = || words.iter().map(|w| format!("{:#x}", w)).collect::<Vec<_>>().join(" ");
    match (&rec.value, rec.attr) {
        (NvInfoValue::None, _) => String::new(),
        (NvInfoValue::Half(h), _) => format!("{:#x}", h),
        (_, EIATTR_REGCOUNT) if words.len() == 2 => format!("function {} registers {}", sym(words[0]), words[1]),
        (_, EIATTR_FRAME_SIZE | EIATTR_MIN_STACK_SIZE | EIATTR_MAX_STACK_SIZE) if words.len() == 2 =>
            format!("function {} size {:#x}", sym(words[0]), words[1]),
        (_, EIATTR_PARAM_CBANK) if words.len() == 2 =>
            format!("{} offset {:#x} size {:#x}", sym(words[0]), words[1] & 0xffff, words[1] >> 16),
        (_, EIATTR_KPARAM_INFO) => match Param::from_record(rec) {
            Some(p) => format!("ordinal {} offset {:#x} size {:#x} align 2^{} space {} cbank {:#x}{}",
                p.ordinal, p.offset, p.size, p.log_align, p.space, p.cbank, if p.is_cbank { " CBANK" } else { "" }),
            None => hex_words()
        },
        (_, EIATTR_REQNTID | EIATTR_MAX_THREADS) if words.len() == 3 =>
            format!("{} x {} x {}", words[0], words[1], words[2]),
        (_, EIATTR_CUDA_API_VERSION) if words.len() == 1 => format!("{} ({})", words[0], toolkit_version(words[0])),
        (NvInfoValue::Bytes(b), _) if b.len() % 4 != 0 =>
            b.iter().map(|x| format!("{:02x}", x)).collect::<Vec<_>>().join(" "),
        _ => hex_words()
    }
}

// ---------------------------------------------------------------------------
// Per-kernel summary (§3.4, §3.5, §3.6)

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KernelInfo {
    pub regs: u32,
    pub barriers: u32,
    pub code_size: usize,
    pub is_entry: bool,
    /// Parameters ordered by ordinal.
    pub params: Vec<Param>,
    /// `PARAM_CBANK`: offset of the parameters in constant bank 0.
    pub param_base: Option<u32>,
    /// `CBANK_PARAM_SIZE`
    pub param_size: Option<u32>,
    /// `.nv.shared.<fn>` size.
    pub shared: u64,
    /// `.nv.local.<fn>` size.
    pub local: u64,
    /// `.nv.constant0.<fn>` size.
    pub const0: u64,
    pub frame_size: Option<u32>,
    pub min_stack_size: Option<u32>,
    pub max_stack_size: Option<u32>,
    pub crs_stack_size: Option<u32>,
    pub max_reg_count: Option<u32>,
    pub reqntid: Option<[u32; 3]>,
    pub max_threads: Option<[u32; 3]>,
    pub exit_offsets: Vec<u32>
}

/// Summarise `kernel` from its sections and the `.nv.info` records.
pub fn kernel_info(cubin: &Cubin, bytes: &[u8], kernel: &Kernel) -> io::Result<KernelInfo> {
    let section_size = |prefix: &str| cubin.section_by_name(&format!("{}{}", prefix, kernel.name))
        .map_or(0, |s| s.size);
    let mut info = KernelInfo {
        regs: kernel.regs,
        barriers: kernel.barriers,
        code_size: kernel.text.size,
        is_entry: kernel.is_entry,
        shared: section_size(".nv.shared."),
        local: section_size(".nv.local."),
        const0: section_size(".nv.constant0."),
        ..KernelInfo::default()
    };

    let triple = |w: &[u32]| (w.len() == 3).then(|| [w[0], w[1], w[2]]);
    if let Some(s) = cubin.section_by_name(&format!(".nv.info.{}", kernel.name)) {
        for rec in section_nvinfo(cubin, bytes, s.index)? {
            let words = rec.words();
            match rec.attr {
                EIATTR_KPARAM_INFO => info.params.extend(Param::from_record(&rec)),
                EIATTR_PARAM_CBANK if words.len() == 2 => info.param_base = Some(words[1] & 0xffff),
                EIATTR_CBANK_PARAM_SIZE => info.param_size = words.first().copied(),
                EIATTR_MAXREG_COUNT => info.max_reg_count = words.first().copied(),
                EIATTR_CRS_STACK_SIZE => info.crs_stack_size = words.first().copied(),
                EIATTR_REQNTID => info.reqntid = triple(&words),
                EIATTR_MAX_THREADS => info.max_threads = triple(&words),
                EIATTR_EXIT_INSTR_OFFSETS => info.exit_offsets.extend(words),
                _ => ()
            }
        }
    }
    info.params.sort_by_key(|p| p.ordinal);

    // Global records are keyed by the function symbol.
    if let Some(s) = cubin.section_by_name(".nv.info") {
        for rec in section_nvinfo(cubin, bytes, s.index)? {
            let words = rec.words();
            if words.len() != 2 || words[0] as usize != kernel.symbol_index {
                continue;
            }
            match rec.attr {
                EIATTR_FRAME_SIZE => info.frame_size = Some(words[1]),
                EIATTR_MIN_STACK_SIZE => info.min_stack_size = Some(words[1]),
                EIATTR_MAX_STACK_SIZE => info.max_stack_size = Some(words[1]),
                _ => ()
            }
        }
    }
    Ok(info)
}

// ---------------------------------------------------------------------------
// Maxwell/Pascal control words (§3.5)

/// sm_5x and sm_6x pack 3 instructions + 1 control word into 32-byte bundles.
pub fn has_control_words(sm: u32) -> bool {
    (50..70).contains(&sm)
}

/// Scheduling controls of one instruction (21 bits of a control word).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Control {
    /// Stall cycles, 0–15.
    pub stall: u8,
    /// Yield hint. Stored inverted: bit 4 = 0 means yield.
    pub yield_hint: bool,
    /// Write barrier set by this instruction (0–5), or `None` (7).
    pub write_barrier: Option<u8>,
    /// Read barrier set by this instruction (0–5), or `None` (7).
    pub read_barrier: Option<u8>,
    /// Barriers waited on before issue (bit n = barrier n).
    pub wait_mask: u8,
    /// Operand reuse cache flags.
    pub reuse: u8
}

impl Control {
    pub fn from_bits(bits: u32) -> Control {
        let barrier = |b: u32| if b == 7 { None } else { Some(b as u8) };
        Control {
            stall: (bits & 0xf) as u8,
            yield_hint: bits & 0x10 == 0,
            write_barrier: barrier((bits >> 5) & 7),
            read_barrier: barrier((bits >> 8) & 7),
            wait_mask: ((bits >> 11) & 0x3f) as u8,
            reuse: ((bits >> 17) & 0xf) as u8
        }
    }

    pub fn to_bits(&self) -> u32 {
        let barrier = |b: Option<u8>| b.map_or(7, |b| b as u32 & 7);
        (self.stall as u32 & 0xf)
            | if self.yield_hint { 0 } else { 0x10 }
            | barrier(self.write_barrier) << 5
            | barrier(self.read_barrier) << 8
            | (self.wait_mask as u32 & 0x3f) << 11
            | (self.reuse as u32 & 0xf) << 17
    }
}

impl std::fmt::Display for Control {
    /// `B------:R-:W-:Y:S06:U----` (wait mask, read/write barrier, yield, stall, reuse).
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mask: String = (0..6).map(|i| if self.wait_mask & (1 << i) != 0 { (b'0' + i) as char } else { '-' }).collect();
        let barrier = |b: Option<u8>| b.map_or('-', |b| (b'0' + b) as char);
        let reuse: String = (0..4).map(|i| if self.reuse & (1 << i) != 0 { (b'0' + i) as char } else { '-' }).collect();
        write!(f, "B{}:R{}:W{}:{}:S{:02}:U{}", mask, barrier(self.read_barrier), barrier(self.write_barrier),
            if self.yield_hint { 'Y' } else { '-' }, self.stall, reuse)
    }
}

pub fn decode_control_word(word: u64) -> [Control; 3] {
    [0, 1, 2].map(|i| Control::from_bits(((word >> (21 * i)) & 0x1f_ffff) as u32))
}

/// Encode three controls, keeping bit 63 of `orig`.
pub fn encode_control_word(controls: &[Control; 3], orig: u64) -> u64 {
    let mut word = orig & (1 << 63);
    for (i, c) in controls.iter().enumerate() {
        word |= (c.to_bits() as u64) << (21 * i);
    }
    word
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_word_roundtrip() {
        // First bundle of k.cubin `reverse` and the `log` example.
        for w in [0x001ffc00e22007f6u64, 0x001fc400fe2007f6, 0x001fbc00fe2007f2, 0x801f8000fc0007ff] {
            assert_eq!(encode_control_word(&decode_control_word(w), w), w);
        }
        // First instruction (MOV R1, c[0x0][0x20]): stall 6, no yield, no barriers.
        let c = decode_control_word(0x001fc400fe2007f6)[0];
        assert_eq!(c, Control { stall: 6, yield_hint: false, write_barrier: None, read_barrier: None, wait_mask: 0, reuse: 0 });
        assert_eq!(c.to_string(), "B------:R-:W-:-:S06:U----");
    }

    #[test]
    fn nvinfo_records() {
        // REGCOUNT (SVAL, fn 9, 8 regs), MAXREG_COUNT (HVAL 0xff), CTAIDZ_USED (NVAL)
        let bytes = [4, 0x2f, 8, 0, 9, 0, 0, 0, 8, 0, 0, 0, 3, 0x1b, 0xff, 0, 1, 0x04, 0, 0];
        let recs = parse_nvinfo(&bytes).unwrap();
        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].words(), [9, 8]);
        assert_eq!(recs[1].value, NvInfoValue::Half(0xff));
        assert_eq!(eiattr_name(recs[2].attr), Some("EIATTR_CTAIDZ_USED"));
        assert!(parse_nvinfo(&bytes[..10]).is_err());
        assert!(parse_nvinfo(&[9, 0, 0, 0]).is_err());
    }

    #[test]
    fn flag_names() {
        assert_eq!(entry_flag_names(0x2011), ["64-bit", "linux", "LZ4"]);
        assert_eq!(entry_flag_names(0x10013), ["64-bit", "debug", "linux", "0x10000"]);
        assert_eq!(e_flags_names(0x320532), ["sm_50", "virtual compute_50", "texmode unified", "64-bit address"]);
        assert_eq!(section_type_name(0x70000064), "CUDA_CONSTANT_B0");
        assert_eq!(toolkit_version(124), "12.4");
    }
}
