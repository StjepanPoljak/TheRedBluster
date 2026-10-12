//! `--list`: tree of fatbins → entries → kernels.

use fatbinspect::InputKind;
use fatbinspect::cubin::{self, Cubin};
use fatbinspect::fatbin::{self, FatBin, FatBinEntry};
use fatbinspect::hostelf::{self, Locator};
use std::io;

fn print_kernels(cubin: &Cubin, indent: usize) {
    if cubin.kernels.is_empty() {
        println!("{:indent$}(no kernels)", "");
    }
    for k in &cubin.kernels {
        println!("{:indent$}{} .text @{:#x} size {:#x} regs {} barriers {}{}", "",
            k.name, k.text.offset, k.text.size, k.regs, k.barriers,
            if k.is_entry { " entry" } else { "" });
    }
}

fn print_entry(data: &[u8], j: usize, entry: &FatBinEntry) {
    let info = &entry.info;
    let kind = match info.kind {
        fatbin::KIND_ELF => "cubin",
        fatbin::KIND_PTX => "ptx",
        _ => "unknown"
    };
    let compressed = entry.compression()
        .map(|c| format!(", {}-compressed", c.name()))
        .unwrap_or_default();
    println!("    entry[{}] {} sm_{} @{:#x} size {:#x} flags {:#x}{}",
        j, kind, info.arch, entry.payload.offset, entry.payload.size, info.flags, compressed);

    if info.kind != fatbin::KIND_ELF {
        return;
    }
    // Compressed cubins: offsets are within the decompressed cubin.
    let base = if entry.compression().is_some() { 0 } else { entry.payload.offset };
    match entry.payload_bytes(data).and_then(|bytes| cubin::parse(&bytes, base)) {
        Ok(cubin) => {
            if entry.compression().is_some() {
                println!("      (offsets are within the decompressed cubin)");
            }
            print_kernels(&cubin, 6)
        },
        Err(e) => println!("      ({})", e)
    }
}

fn print_fatbin(data: &[u8], i: usize, fb: &FatBin, via: Option<Locator>) {
    let via = match via {
        Some(Locator::Wrapper { index, version, va }) =>
            format!(" via wrapper[{}] v{} va {:#x}", index, version, va),
        Some(Locator::Scan) => String::from(" via scan"),
        None => String::new()
    };
    println!("  fatbin[{}] @{:#x} size {:#x}{}", i, fb.offset, fb.size(), via);
    for (j, entry) in fb.entries.iter().enumerate() {
        print_entry(data, j, entry);
    }
}

pub fn run(path: &str, kind: InputKind, data: &[u8]) -> io::Result<()> {
    println!("{} ({})", path, kind.name());
    match kind {
        InputKind::Host => {
            for (i, loc) in hostelf::find_fatbins(data)?.into_iter().enumerate() {
                let fb = fatbin::parse_at(data, loc.offset)?;
                print_fatbin(data, i, &fb, Some(loc.via));
            }
        },
        InputKind::Fatbin => {
            for (i, fb) in fatbin::parse_file(data)?.iter().enumerate() {
                print_fatbin(data, i, fb, None);
            }
        },
        InputKind::Cubin => {
            let cubin = cubin::parse(data, 0)?;
            println!("  sm_{} size {:#x}", cubin.sm(), cubin.size);
            print_kernels(&cubin, 4);
        }
    }
    Ok(())
}
