//! Decoded views (Phase 4), shared by `--info` and interactive mode.

use fatbinspect::InputKind;
use fatbinspect::cubin::{self, Cubin};
use fatbinspect::decode::{self, Control};
use fatbinspect::fatbin::{self, FatBinEntry};
use fatbinspect::hostelf;
use fatbinspect::util::read_le64;
use std::io;

/// Decoded entry header fields, one per line, indented by `indent`.
pub fn print_entry_decoded(data: &[u8], entry: &FatBinEntry, indent: usize) {
    let info = &entry.info;
    println!("{:indent$}kind: {} ({})", "", info.kind, decode::entry_kind_name(info.kind));
    println!("{:indent$}arch: sm_{}", "", info.arch);
    let version = if info.kind == fatbin::KIND_PTX { "PTX ISA" } else { "code version" };
    println!("{:indent$}{}: {}.{}", "", version, info.code_version_major, info.code_version_minor);
    println!("{:indent$}flags: {:#x} ({})", "", info.flags, decode::entry_flag_names(info.flags).join(", "));
    if let Some(c) = entry.compression() {
        println!("{:indent$}compression: {}, {} -> {} bytes", "", c.name(), info.compressed_size, info.uncompressed_size);
    }
    if let Some(ident) = decode::entry_ident(data, entry) {
        println!("{:indent$}ident: {:?}", "", ident);
    }
    if let Some(options) = decode::entry_ptxas_options(data, entry) {
        println!("{:indent$}ptxas options: {:?}", "", options);
    }
}

pub fn print_cubin_header(c: &Cubin, indent: usize) {
    let type_name = match c.e_type {
        1 => "ET_REL",
        2 => "ET_EXEC",
        _ => "?"
    };
    println!("{:indent$}ELF: type {} ({}), OSABI {}, ABI version {}, toolkit {} ({})", "",
        c.e_type, type_name, decode::osabi_name(c.osabi), c.abi_version, c.e_version, decode::toolkit_version(c.e_version));
    println!("{:indent$}e_flags: {:#x} ({})", "", c.e_flags, decode::e_flags_names(c.e_flags).join(", "));
}

/// Section table in `cuobjdump -elf` column order.
pub fn print_section_table(c: &Cubin, indent: usize) {
    println!("{:indent$}{:>5} {:>8} {:>8} {:>3} {:>5} {:>17} {:>8} {:>4} {:>8} Name", "",
        "Index", "Offset", "Size", "ES", "Align", "Type", "Flags", "Link", "Info");
    for s in &c.sections {
        // Offsets as parsed: file offsets, or within a decompressed cubin.
        let offset = s.file.map_or(String::from("-"), |l| format!("{:x}", l.offset));
        println!("{:indent$}{:>5x} {:>8} {:>8x} {:>3x} {:>5x} {:>17} {:>8x} {:>4x} {:>8x} {}", "",
            s.index, offset, s.size, s.sh_entsize, s.sh_addralign, decode::section_type_name(s.sh_type),
            s.sh_flags, s.sh_link, s.sh_info, s.name);
    }
}

pub fn print_kernels(c: &Cubin, bytes: &[u8], indent: usize) -> io::Result<()> {
    for k in &c.kernels {
        let info = decode::kernel_info(c, bytes, k)?;
        println!("{:indent$}{}{}", "", k.name, if info.is_entry { " (entry)" } else { "" });
        let i2 = indent + 4;
        println!("{:i2$}.text @{:#x} size {:#x}, registers {}, barriers {}", "",
            k.text.offset, info.code_size, info.regs, info.barriers);
        println!("{:i2$}shared {:#x}, local {:#x}, constant0 {:#x}, stack {:#x}, frame {:#x}", "",
            info.shared, info.local, info.const0,
            info.min_stack_size.unwrap_or(0), info.frame_size.unwrap_or(0));
        if let Some(n) = info.max_reg_count {
            println!("{:i2$}max registers: {}", "", if n == 0xff { String::from("unlimited") } else { n.to_string() });
        }
        if let Some([x, y, z]) = info.reqntid {
            println!("{:i2$}reqntid: {} x {} x {}", "", x, y, z);
        }
        if let Some([x, y, z]) = info.max_threads {
            println!("{:i2$}max threads: {} x {} x {}", "", x, y, z);
        }
        let base = info.param_base.map_or(String::new(), |b| format!(" at c[0x0][{:#x}]", b));
        println!("{:i2$}params: {} ({:#x} bytes{})", "", info.params.len(), info.param_size.unwrap_or(0), base);
        for p in &info.params {
            println!("{:i2$}    [{}] offset {:#x} size {:#x}", "", p.ordinal, p.offset, p.size);
        }
        if !info.exit_offsets.is_empty() {
            let exits: Vec<String> = info.exit_offsets.iter().map(|o| format!("{:#x}", o)).collect();
            println!("{:i2$}EXIT at {}", "", exits.join(" "));
        }
    }
    Ok(())
}

/// All `.nv.info*` sections, record by record.
pub fn print_nvinfo(c: &Cubin, bytes: &[u8], indent: usize) -> io::Result<()> {
    let sym = |i: u32| c.symbol_name(i as usize)
        .filter(|n| !n.is_empty())
        .map_or(format!("sym {:#x}", i), String::from);
    for s in c.sections.iter().filter(|s| s.name.starts_with(".nv.info")) {
        println!("{:indent$}{}", "", s.name);
        for rec in decode::section_nvinfo(c, bytes, s.index)? {
            let attr = decode::eiattr_name(rec.attr).map_or(format!("EIATTR_{:#04x}", rec.attr), String::from);
            let format = decode::eifmt_name(rec.format).unwrap_or("?").trim_start_matches("EIFMT_");
            println!("{:indent$}    {:04x} {:<36} {} {}", "", rec.offset, attr, format,
                decode::format_nvinfo_value(&rec, &sym));
        }
    }
    Ok(())
}

/// Header, sections, kernels and `.nv.info` of one cubin.
pub fn print_cubin(c: &Cubin, bytes: &[u8], indent: usize) -> io::Result<()> {
    print_cubin_header(c, indent);
    println!("{:indent$}sections:", "");
    print_section_table(c, indent + 4);
    println!("{:indent$}kernels:", "");
    print_kernels(c, bytes, indent + 4)?;
    println!("{:indent$}.nv.info:", "");
    print_nvinfo(c, bytes, indent + 4)
}

/// One 8-byte word of a `.text` section, with its control fields on
/// sm_5x/6x. `index` counts words from the start of the section.
pub fn format_text_word(sm: u32, words: &[u64], index: usize) -> String {
    if !decode::has_control_words(sm) {
        return String::new();
    }
    let slot = index % 4;
    if slot == 0 {
        return String::from("  ---- control ----");
    }
    let ctrl = words[index - slot];
    format!("  {}", decode::decode_control_word(ctrl)[slot - 1])
}

/// Section words as u64 (for control lookups).
pub fn words_of(bytes: &[u8]) -> Vec<u64> {
    bytes.chunks_exact(8).map(|w| read_le64(w, 0)).collect()
}

/// Parse a control in the `B------:R-:W-:Y:S06:U----` form.
pub fn parse_control(s: &str) -> Option<Control> {
    let parts: Vec<&str> = s.trim().split(':').collect();
    let [b, r, w, y, st, u] = parts[..] else { return None };
    let bits = |field: &str, prefix: char, width: usize| -> Option<u8> {
        let chars: Vec<char> = field.strip_prefix(prefix)?.chars().collect();
        if chars.len() != width {
            return None;
        }
        chars.iter().enumerate().try_fold(0u8, |acc, (i, ch)| match ch {
            '-' => Some(acc),
            d if d.to_digit(10) == Some(i as u32) => Some(acc | 1 << i),
            _ => None
        })
    };
    let barrier = |field: &str, prefix: char| -> Option<Option<u8>> {
        match field.strip_prefix(prefix)? {
            "-" => Some(None),
            d => d.parse::<u8>().ok().filter(|&n| n <= 5).map(Some)
        }
    };
    Some(Control {
        wait_mask: bits(b, 'B', 6)?,
        read_barrier: barrier(r, 'R')?,
        write_barrier: barrier(w, 'W')?,
        yield_hint: match y { "Y" => true, "-" => false, _ => return None },
        stall: st.strip_prefix('S')?.parse::<u8>().ok().filter(|&n| n <= 15)?,
        reuse: bits(u, 'U', 4)?
    })
}

/// `--info`: everything decoded for the input.
pub fn run(path: &str, kind: InputKind, data: &[u8]) -> io::Result<()> {
    println!("{} ({})", path, kind.name());
    let fatbins = match kind {
        InputKind::Host => hostelf::parse_fatbins(data)?,
        InputKind::Fatbin => fatbin::parse_file(data)?,
        InputKind::Cubin => return print_cubin(&cubin::parse(data, 0)?, data, 2)
    };
    for (i, fb) in fatbins.iter().enumerate() {
        println!("  fatbin[{}] @{:#x} version {} header_size {:#x} size {:#x}", i,
            fb.offset, fb.hdr.version, fb.hdr.header_size, fb.size());
        for (j, entry) in fb.entries.iter().enumerate() {
            println!("    entry[{}] @{:#x} payload @{:#x} size {:#x}", j, entry.offset, entry.payload.offset, entry.payload.size);
            print_entry_decoded(data, entry, 6);
            if entry.info.kind != fatbin::KIND_ELF {
                continue;
            }
            // Decoded cubin offsets are relative to the cubin.
            match entry.payload_bytes(data).and_then(|b| cubin::parse(&b, 0).map(|c| (c, b))) {
                Ok((c, bytes)) => print_cubin(&c, &bytes, 6)?,
                Err(e) => println!("      ({})", e)
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_text_roundtrip() {
        for w in [0x001ffc00e22007f6u64, 0x001fbc00fe2007f2, 0x001f8000fc0007ff, 0x001fc400fc2007f1] {
            for c in decode::decode_control_word(w) {
                assert_eq!(parse_control(&c.to_string()), Some(c));
            }
        }
        assert_eq!(parse_control("B0-2---:R1:W-:Y:S15:U-1-3").map(|c| (c.wait_mask, c.read_barrier, c.stall, c.reuse)),
                   Some((0b101, Some(1), 15, 0b1010)));
        for bad in ["", "B------:R-:W-:Y:S16:U----", "B1-----:R-:W-:Y:S01:U----", "B------:R6:W-:Y:S01:U----"] {
            assert_eq!(parse_control(bad), None, "{}", bad);
        }
    }
}
