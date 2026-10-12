use crate::extract::{self, Item};
use crate::info;
use fatbinspect::InputKind;
use fatbinspect::cubin::{self, Cubin};
use fatbinspect::decode;
use fatbinspect::fatbin::{self, FatBin, FatBinEntry};
use fatbinspect::hostelf;
use fatbinspect::util::{DataLoc, err, read_le64};
use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use std::io;
use std::path::Path;

pub fn separator() {
    println!("-------------------------");
}

/// The cubin currently being looked at: a fatbin entry, or the whole input file.
struct Target {
    label: String,
    /// File name prefix for extracted kernels.
    prefix: String,
    payload: DataLoc,
    entry: Option<(usize, usize)>
}

impl Target {
    fn from_entry(fatbins: &[FatBin], f: usize, e: usize) -> Target {
        Target {
            label: format!("FatBin[{}].entry[{}]", f, e),
            prefix: extract::entry_prefix(f, e),
            payload: fatbins[f].entries[e].payload,
            entry: Some((f, e))
        }
    }

    fn load(&self, fatbins: &[FatBin], data: &[u8]) -> io::Result<Loaded> {
        let decompressed = match self.entry {
            Some((f, e)) if fatbins[f].entries[e].compression().is_some() =>
                Some(fatbins[f].entries[e].payload_bytes(data)?.into_owned()),
            _ => None
        };
        let cubin = match &decompressed {
            Some(bytes) => cubin::parse(bytes, 0),
            None => cubin::parse(&data[self.payload.range()], self.payload.offset)
        }.or_else(|_| err("Payload is not a cubin ELF file."))?;
        Ok(Loaded { cubin, decompressed })
    }
}

/// The target's cubin. Compressed entries are decompressed into a copy; their
/// offsets are then within the copy, and they can't be modified.
struct Loaded {
    cubin: Cubin,
    decompressed: Option<Vec<u8>>
}

impl Loaded {
    /// The bytes the cubin's offsets refer to.
    fn bytes<'a>(&'a self, data: &'a [u8]) -> &'a [u8] {
        self.decompressed.as_deref().unwrap_or(data)
    }

    /// Just the cubin's bytes.
    fn cubin_bytes<'a>(&'a self, target: &Target, data: &'a [u8]) -> &'a [u8] {
        self.decompressed.as_deref().unwrap_or(&data[target.payload.range()])
    }
}

fn print_fatbin_hdrs(fatbins: &[FatBin]) {
    for (i, FatBin{offset, hdr, ..}) in fatbins.iter().enumerate() {
        separator();
        println!("{:4}[{:2}]: version: {:#x}", "", i, hdr.version);
        println!("{:10}header_size: {}", "", hdr.header_size);
        println!("{:10}fatbin_size: {}", "", hdr.fatbin_size);
        println!("{:10}offset: {:#x}", "", offset);
    }
    separator();
}

fn print_fatbin_entries(fatbin: &FatBin, data: &[u8]) {
    separator();
    for (i, entry) in fatbin.entries.iter().enumerate() {
        let FatBinEntry{ info, payload, .. } = entry;
        println!("{:4}[{:2}]: address: {:#08x}", "", i, payload.offset);
        println!("{:10}kind: {:#04x} ({})", "", info.kind, decode::entry_kind_name(info.kind));
        println!("{:10}version: {}", "", info.version);
        println!("{:10}padded_payload_size: {}", "", info.padded_payload_size);
        println!("{:10}compressed_size: {}", "", info.compressed_size);
        println!("{:10}options_desc_offset: {:#08x}", "", info.options_desc_offset);
        println!("{:10}code_version_minor: {}", "", info.code_version_minor);
        println!("{:10}code_version_major: {}", "", info.code_version_major);
        println!("{:10}arch: {:#08x} (sm_{})", "", info.arch, info.arch);
        println!("{:10}identifier_offset: {:#08x}", "", info.identifier_offset);
        println!("{:10}ident_len: {:#08x}", "", info.ident_len);
        println!("{:10}flags: {:#016x} ({})", "", info.flags, decode::entry_flag_names(info.flags).join(", "));
        println!("{:10}reserved: {:#016x}", "", info.reserved);
        println!("{:10}uncompressed_size: {}", "", info.uncompressed_size);
        if let Some(ident) = decode::entry_ident(data, entry) {
            println!("{:10}ident: {:?}", "", ident);
        }
        if let Some(options) = decode::entry_ptxas_options(data, entry) {
            println!("{:10}ptxas options: {:?}", "", options);
        }

        separator();
    }
}

fn print_entry_sections(cubin: &Cubin) {
    separator();
    cubin.sections.iter().enumerate().for_each(|(i, s)| println!("{:4}[{:4}] {}", "", i, s.name));
    separator();
}

/// Read a line with editable initial text; `None` on Ctrl-C / Ctrl-D.
fn prompt_initial(rl: &mut DefaultEditor, msg: &str, initial: &str) -> io::Result<Option<String>> {
    match rl.readline_with_initial(msg, (initial, "")) {
        Ok(line) => Ok(Some(line)),
        Err(ReadlineError::Interrupted | ReadlineError::Eof) => Ok(None),
        Err(e) => err(format!("Readline error: {}", e))
    }
}

/// Read a line; `None` on Ctrl-C / Ctrl-D.
fn prompt(rl: &mut DefaultEditor, msg: &str) -> io::Result<Option<String>> {
    match rl.readline(msg) {
        Ok(line) => Ok(Some(line)),
        Err(ReadlineError::Interrupted | ReadlineError::Eof) => Ok(None),
        Err(e) => err(format!("Readline error: {}", e))
    }
}

/// Prompt for an index in `0..len`.
fn select_index(rl: &mut DefaultEditor, what: &str, len: usize) -> io::Result<Option<usize>> {
    if len == 0 {
        println!("No {} available.", what);
        separator();
        return Ok(None);
    }

    let Some(buf) = prompt(rl, &format!("Select {} (0-{}): ", what, len - 1))? else {
        return Ok(None);
    };
    separator();

    match buf.trim().parse::<usize>() {
        Ok(choice) if choice < len => Ok(Some(choice)),
        Ok(choice) => {
            println!("Invalid {} selection: {}", what, choice);
            separator();
            Ok(None)
        },
        Err(_) => {
            println!("Invalid input: {}", buf.trim());
            separator();
            Ok(None)
        }
    }
}

fn select_fatbin(rl: &mut DefaultEditor, fatbins: &[FatBin]) -> io::Result<Option<usize>> {
    print_fatbin_hdrs(fatbins);
    select_index(rl, "FatBin", fatbins.len())
}

fn select_fatbin_entry(rl: &mut DefaultEditor, fatbin: &FatBin, data: &[u8]) -> io::Result<Option<usize>> {
    print_fatbin_entries(fatbin, data);
    select_index(rl, "FatBin entry", fatbin.entries.len())
}

fn select_entry_section(rl: &mut DefaultEditor, cubin: &Cubin) -> io::Result<Option<String>> {
    print_entry_sections(cubin);
    Ok(select_index(rl, "FatBin entry section", cubin.sections.len())?
        .map(|choice| cubin.sections[choice].name.clone()))
}

fn dump_entry(payload: DataLoc, data: &[u8]) {
    separator();
    for (i, w64) in data[payload.range()].chunks_exact(8).enumerate() {
        println!("{:08x}: {:016x}", payload.offset + i * 8, read_le64(w64, 0x0));
    }
    separator();
}

/// Whether words of `section` are Maxwell/Pascal bundles (control + 3 insns).
fn is_bundled_text(cubin: &Cubin, section: &str) -> bool {
    section.starts_with(".text.") && decode::has_control_words(cubin.sm())
}

fn dump_entry_section(cubin: &Cubin, data: &[u8], section: &str) -> Option<DataLoc> {
    separator();
    match cubin.section_by_name(section).map(|s| s.file) {
        Some(Some(loc)) => {
            let words = info::words_of(&data[loc.range()]);
            let sm = if is_bundled_text(cubin, section) { cubin.sm() } else { 0 };
            for (i, w64) in words.iter().enumerate() {
                println!("{:8}[{:4}] {:08x}: {:016x}{}", "", i, loc.offset + i * 8, w64,
                    info::format_text_word(sm, &words, i));
            }
            separator();
            return Some(loc);
        },
        Some(None) => println!("Section '{}' has no data in the file.", section),
        None => println!("Section '{}' not found.", section)
    }
    separator();
    None
}

fn modify_entry_section(rl: &mut DefaultEditor, cubin: &Cubin, data: &mut [u8], section: &str) -> io::Result<()> {
    let Some(loc) = dump_entry_section(cubin, data, section) else {
        return Ok(());
    };
    let count = loc.size / 8;
    if count == 0 {
        println!("Section '{}' is empty.", section);
        separator();
        return Ok(());
    }

    let Some(buf) = prompt(rl, &format!("Select instruction (0-{}): ", count - 1))? else {
        return Ok(());
    };
    separator();
    match buf.trim().parse::<usize>() {
        Ok(insn) if insn < count => {
            let addr = loc.offset + (insn * 8);
            let old = read_le64(data, addr);
            if insn % 4 == 0 && is_bundled_text(cubin, section) {
                let Some(new) = edit_control_word(rl, old)? else {
                    return Ok(());
                };
                data[addr..addr + 8].copy_from_slice(&new.to_le_bytes());
                separator();
                return Ok(());
            }
            let Some(buf) = prompt_initial(rl, "Edit value: ", &format!("{:x}", old))? else {
                return Ok(());
            };
            if let Ok(new) = u64::from_str_radix(buf.trim(), 16) {
                data[addr..addr + 8].copy_from_slice(&new.to_le_bytes());
            } else {
                separator();
                println!("Invalid input: {}", buf.trim());
            }
        },
        Ok(insn) => println!("Selected instruction [{}] not in section range: {:#08x}..{:#08x}",
            insn, loc.offset, loc.end()),
        Err(_) => println!("Invalid input: {}", buf.trim())
    }
    separator();
    Ok(())
}

/// Edit a control word, raw or one instruction's controls at a time.
/// Returns the new value, or `None` if cancelled or invalid.
fn edit_control_word(rl: &mut DefaultEditor, old: u64) -> io::Result<Option<u64>> {
    let mut controls = decode::decode_control_word(old);
    for (i, c) in controls.iter().enumerate() {
        println!("insn {}: {}", i, c);
    }
    let Some(mode) = prompt(rl, "Edit (r)aw value or (f)ields? [r]: ")? else {
        return Ok(None);
    };
    match mode.trim() {
        "" | "r" => {
            let Some(buf) = prompt_initial(rl, "Edit value: ", &format!("{:x}", old))? else {
                return Ok(None);
            };
            match u64::from_str_radix(buf.trim(), 16) {
                Ok(new) => Ok(Some(new)),
                Err(_) => {
                    println!("Invalid input: {}", buf.trim());
                    Ok(None)
                }
            }
        },
        "f" => {
            println!("Format: B<wait mask>:R<read barrier>:W<write barrier>:<Y|->:S<stall>:U<reuse> (empty = keep)");
            for (i, c) in controls.iter_mut().enumerate() {
                let Some(buf) = prompt_initial(rl, &format!("insn {}: ", i), &c.to_string())? else {
                    return Ok(None);
                };
                if buf.trim().is_empty() {
                    continue;
                }
                match info::parse_control(&buf) {
                    Some(new) => *c = new,
                    None => {
                        println!("Invalid control: {}", buf.trim());
                        return Ok(None);
                    }
                }
            }
            let new = decode::encode_control_word(&controls, old);
            println!("New value: {:016x}", new);
            Ok(Some(new))
        },
        other => {
            println!("Invalid input: {}", other);
            Ok(None)
        }
    }
}

/// Write extracted items into the current directory.
fn extract_items(items: io::Result<Vec<Item>>) {
    separator();
    match items {
        Ok(items) if items.is_empty() => println!("Nothing to extract."),
        Ok(items) => for item in &items {
            match extract::write_item(Path::new("."), item) {
                Ok(path) => println!("Wrote {} ({} bytes)", path.display(), item.data.len()),
                Err(e) => println!("Failed to write {}: {}", item.name, e)
            }
        },
        Err(e) => println!("{}", e)
    }
    separator();
}

/// Load the current target's cubin, printing the error if it isn't one.
fn with_cubin(target: &Target, fatbins: &[FatBin], data: &[u8]) -> Option<Loaded> {
    match target.load(fatbins, data) {
        Ok(loaded) => {
            if loaded.decompressed.is_some() {
                separator();
                println!("(decompressed copy; offsets are within the decompressed cubin)");
            }
            Some(loaded)
        },
        Err(e) => {
            separator();
            println!("{}", e);
            separator();
            None
        }
    }
}

pub fn run(path: &str, kind: InputKind, mut data: Vec<u8>) -> io::Result<()> {
    let fatbins: Vec<FatBin> = match kind {
        InputKind::Host => hostelf::parse_fatbins(&data)?,
        InputKind::Fatbin => fatbin::parse_file(&data)?,
        InputKind::Cubin => {
            cubin::parse(&data, 0)?;
            Vec::new()
        }
    };
    // A cubin input is always the target; there is nothing to select.
    let file_target = (kind == InputKind::Cubin).then(|| Target {
        label: String::from("cubin"),
        prefix: Path::new(path).file_stem().map_or(String::from("cubin"), |s| s.to_string_lossy().into_owned()),
        payload: DataLoc { offset: 0, size: data.len() },
        entry: None
    });

    let mut rl = DefaultEditor::new().or_else(|e| err(format!("Readline error: {}", e)))?;
    let mut fatbin: Option<usize> = None;
    let mut entry: Option<usize> = None;
    let mut section: Option<String> = None;

    loop {
        let mut invalid = false;
        let entry_target = fatbin.zip(entry).map(|(f, e)| Target::from_entry(&fatbins, f, e));
        let target = file_target.as_ref().or(entry_target.as_ref());

        if file_target.is_none() {
            println!("[ 1] Print FatBin info");
            println!("[ 2] Select FatBin");
        }

        if let Some(f) = fatbin {
            println!("[ 3] Print FatBin[{}] entries", f);
            println!("[ 4] Select FatBin[{}] entry", f);
        }

        if let Some(t) = target {
            println!("[ 5] Dump {}", t.label);
            println!("[ 6] Print {} sections", t.label);
            println!("[ 7] Select {} section", t.label);

            if let Some(ref sec) = section {
                println!("[ 8] Dump '{}' from {}", sec, t.label);
                println!("[ 9] Modify '{}' from {}", sec, t.label);
                println!("[10] Save changes");
            }
        }

        if let (Some(f), InputKind::Host) = (fatbin, kind) {
            println!("[11] Extract FatBin[{}] to file", f);
        }
        if let Some(t) = entry_target.as_ref() {
            println!("[12] Extract {} to file", t.label);
        }
        if let (Some(t), Some(fn_name)) = (target, section.as_deref().and_then(|s| s.strip_prefix(".text."))) {
            println!("[13] Extract kernel '{}' from {} to file", fn_name, t.label);
        }
        if let Some(t) = target {
            println!("[14] Print {} header, sections and kernels", t.label);
            println!("[15] Print {} .nv.info", t.label);
        }

        println!("[ 0] Exit");
        separator();
        let Some(buf) = prompt(&mut rl, "> ")? else {
            break;
        };

        let Ok(choice) = buf.trim().parse::<u32>() else {
            separator();
            println!("Invalid input: {}", buf.trim());
            separator();
            continue;
        };

        match (choice, fatbin, target, &section) {
            (1, ..) if file_target.is_none() => print_fatbin_hdrs(&fatbins),
            (2, ..) if file_target.is_none() => {
                fatbin = select_fatbin(&mut rl, &fatbins)?;
                entry = None;
                section = None;
            },
            (3, Some(f), ..) => print_fatbin_entries(&fatbins[f], &data),
            (4, Some(f), ..) => {
                entry = select_fatbin_entry(&mut rl, &fatbins[f], &data)?;
                section = None;
            },
            (5, _, Some(t), _) => dump_entry(t.payload, &data),
            (6, _, Some(t), _) => if let Some(l) = with_cubin(t, &fatbins, &data) {
                print_entry_sections(&l.cubin);
            },
            (7, _, Some(t), _) => if let Some(l) = with_cubin(t, &fatbins, &data) {
                section = select_entry_section(&mut rl, &l.cubin)?;
            },
            (8, _, Some(t), Some(sec)) => if let Some(l) = with_cubin(t, &fatbins, &data) {
                dump_entry_section(&l.cubin, l.bytes(&data), sec);
            },
            (9, _, Some(t), Some(sec)) => match with_cubin(t, &fatbins, &data) {
                Some(Loaded { decompressed: Some(_), .. }) => {
                    println!("Modifying compressed entries is not supported.");
                    separator();
                },
                Some(l) => modify_entry_section(&mut rl, &l.cubin, &mut data, sec)?,
                None => ()
            },
            (10, _, Some(_), Some(_)) => {
                std::fs::write(path, &data)?;
                separator();
                println!("Successfully saved changes.");
                separator();
            },
            (11, Some(f), ..) if kind == InputKind::Host =>
                extract_items(Ok(vec![extract::fatbin_item(&data, f, &fatbins[f])])),
            (12, Some(f), Some(_), _) if file_target.is_none() => if let Some(e) = entry {
                extract_items(extract::entry_item(&data, f, e, &fatbins[f].entries[e]).map(|i| vec![i]));
            },
            (13, _, Some(t), Some(sec)) if sec.starts_with(".text.") =>
                if let Some(l) = with_cubin(t, &fatbins, &data) {
                    extract_items(extract::kernel_items(&t.prefix, l.cubin_bytes(t, &data),
                        sec.strip_prefix(".text.")));
                },
            (14, _, Some(t), _) => if let Some(l) = with_cubin(t, &fatbins, &data) {
                let bytes = l.bytes(&data);
                info::print_cubin_header(&l.cubin, 0);
                separator();
                info::print_section_table(&l.cubin, 0);
                separator();
                if let Err(e) = info::print_kernels(&l.cubin, bytes, 0) {
                    println!("{}", e);
                }
                separator();
            },
            (15, _, Some(t), _) => if let Some(l) = with_cubin(t, &fatbins, &data) {
                if let Err(e) = info::print_nvinfo(&l.cubin, l.bytes(&data), 0) {
                    println!("{}", e);
                }
                separator();
            },
            (0, ..) => break,
            _ => invalid = true
        }

        if invalid {
            separator();
            println!("Invalid choice: {}", choice);
            separator();
        }
    }

    Ok(())
}
