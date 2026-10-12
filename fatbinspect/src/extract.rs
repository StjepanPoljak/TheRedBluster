//! Non-interactive extraction. Interactive mode uses the same item builders.

use fatbinspect::InputKind;
use fatbinspect::cubin;
use fatbinspect::fatbin::{self, FatBin, FatBinEntry};
use fatbinspect::hostelf;
use fatbinspect::util::err;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Copy, Clone, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum What {
    /// Whole fatbins (host input only)
    Fatbin,
    /// Cubin ELFs from fatbin entries
    Cubin,
    /// PTX from fatbin entries
    Ptx,
    /// Kernel `.text` raw binaries
    Text,
    /// Everything that applies to the input
    All
}

/// A file to be written.
pub struct Item {
    pub name: String,
    pub data: Vec<u8>
}

/// Make a symbol name safe to use in a file name.
pub fn sanitize(name: &str) -> String {
    const MAX: usize = 200;
    let mut s: String = name.chars()
        .map(|c| if c.is_ascii_alphanumeric() || "_.$-".contains(c) { c } else { '_' })
        .collect();
    if s.len() > MAX {
        // FNV-1a, so that long names that share a prefix stay distinct.
        let hash = name.bytes().fold(0xcbf29ce484222325u64, |h, b| (h ^ b as u64).wrapping_mul(0x100000001b3));
        s.truncate(MAX);
        s.push_str(&format!("~{:08x}", hash as u32));
    }
    s
}

pub fn entry_prefix(fatbin: usize, entry: usize) -> String {
    format!("fatbin{}.entry{}", fatbin, entry)
}

pub fn fatbin_item(data: &[u8], index: usize, fb: &FatBin) -> Item {
    Item {
        name: format!("fatbin{}.fatbin", index),
        data: data[fb.offset..fb.offset + fb.size()].to_vec()
    }
}

/// The entry payload, decompressed if needed, without padding.
fn entry_payload(data: &[u8], entry: &FatBinEntry) -> io::Result<Vec<u8>> {
    let mut bytes = entry.payload_bytes(data)?.into_owned();

    match entry.info.kind {
        fatbin::KIND_ELF => {
            let size = cubin::parse(&bytes, 0)?.size;
            bytes.truncate(size);
        },
        fatbin::KIND_PTX => {
            let len = bytes.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
            bytes.truncate(len);
        },
        kind => return err(format!("unsupported entry kind {}", kind))
    }
    Ok(bytes)
}

/// The cubin or PTX of a fatbin entry.
pub fn entry_item(data: &[u8], fatbin: usize, index: usize, entry: &FatBinEntry) -> io::Result<Item> {
    let ext = if entry.info.kind == fatbin::KIND_PTX { "ptx" } else { "cubin" };
    Ok(Item {
        name: format!("{}.sm_{}.{}", entry_prefix(fatbin, index), entry.info.arch, ext),
        data: entry_payload(data, entry)?
    })
}

/// `.text.<fn>` raw binaries of a cubin, optionally only kernel `only`.
pub fn kernel_items(prefix: &str, cubin_data: &[u8], only: Option<&str>) -> io::Result<Vec<Item>> {
    let cubin = cubin::parse(cubin_data, 0)?;
    Ok(cubin.kernels.iter()
        .filter(|k| only.is_none_or(|name| k.name == name))
        .map(|k| Item {
            name: format!("{}.{}.sm_{}.bin", prefix, sanitize(&k.name), cubin.sm()),
            data: cubin_data[k.text.range()].to_vec()
        })
        .collect())
}

pub struct Selection<'a> {
    pub fatbin: bool,
    pub cubin: bool,
    pub ptx: bool,
    pub text: bool,
    pub kernel: Option<&'a str>
}

impl<'a> Selection<'a> {
    /// Resolve `--what` for an input kind. `--kernel` alone means `--what text`.
    pub fn new(kind: InputKind, what: &[What], kernel: Option<&'a str>) -> io::Result<Selection<'a>> {
        let what = if what.is_empty() {
            if kernel.is_some() { &[What::Text][..] } else { &[What::All][..] }
        } else {
            what
        };
        let has = |w| what.contains(&w) || what.contains(&What::All);
        let sel = Selection {
            fatbin: has(What::Fatbin) && kind == InputKind::Host,
            cubin: has(What::Cubin) && kind != InputKind::Cubin,
            ptx: has(What::Ptx) && kind != InputKind::Cubin,
            text: has(What::Text),
            kernel
        };

        let applicable: &[What] = match kind {
            InputKind::Host => &[What::Fatbin, What::Cubin, What::Ptx, What::Text, What::All],
            InputKind::Fatbin => &[What::Cubin, What::Ptx, What::Text, What::All],
            InputKind::Cubin => &[What::Text, What::All]
        };
        if let Some(w) = what.iter().find(|w| !applicable.contains(w)) {
            return err(format!("--what {} does not apply to {} input.",
                format!("{:?}", w).to_lowercase(), kind.name()));
        }
        if kernel.is_some() && !sel.text {
            return err("--kernel needs --what text (or all).");
        }
        Ok(sel)
    }
}

/// Build the items selected by `sel`. Entries that can't be extracted are
/// reported through `warn` and skipped.
pub fn collect(kind: InputKind, stem: &str, data: &[u8], sel: &Selection,
               warn: &mut dyn FnMut(String)) -> io::Result<Vec<Item>> {
    let fatbins = match kind {
        InputKind::Host => hostelf::parse_fatbins(data)?,
        InputKind::Fatbin => fatbin::parse_file(data)?,
        InputKind::Cubin => return kernel_items(stem, data, sel.kernel)
    };

    let mut items = Vec::new();
    for (i, fb) in fatbins.iter().enumerate() {
        if sel.fatbin {
            items.push(fatbin_item(data, i, fb));
        }

        for (j, entry) in fb.entries.iter().enumerate() {
            let wanted = match entry.info.kind {
                fatbin::KIND_ELF => sel.cubin || sel.text,
                fatbin::KIND_PTX => sel.ptx,
                _ => false
            };
            if !wanted {
                continue;
            }

            let item = match entry_item(data, i, j, entry) {
                Ok(item) => item,
                Err(e) => {
                    warn(format!("{}: {}; skipped.", entry_prefix(i, j), e));
                    continue;
                }
            };
            if entry.info.kind == fatbin::KIND_ELF && sel.text {
                items.extend(kernel_items(&entry_prefix(i, j), &item.data, sel.kernel)?);
            }
            if entry.info.kind == fatbin::KIND_PTX || sel.cubin {
                items.push(item);
            }
        }
    }
    Ok(items)
}

pub fn write_item(dir: &Path, item: &Item) -> io::Result<PathBuf> {
    let path = dir.join(&item.name);
    std::fs::write(&path, &item.data)?;
    Ok(path)
}

/// Write items into `outdir`, or the single item to stdout.
pub fn write(items: &[Item], outdir: &Path, stdout: bool) -> io::Result<()> {
    if stdout {
        let [item] = items else {
            return err(format!("--stdout needs exactly one item, but {} matched.", items.len()));
        };
        return io::stdout().lock().write_all(&item.data);
    }

    std::fs::create_dir_all(outdir)?;
    for item in items {
        let path = write_item(outdir, item)?;
        println!("{} ({} bytes)", path.display(), item.data.len());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sanitize;

    #[test]
    fn sanitize_names() {
        assert_eq!(sanitize("_Z3addPKfS0_Pfi"), "_Z3addPKfS0_Pfi");
        assert_eq!(sanitize("a/b c<int>"), "a_b_c_int_");
        let long = "x".repeat(300);
        let s = sanitize(&long);
        assert_eq!(s.len(), 209);
        assert!(s.starts_with(&"x".repeat(200)) && s[200..].starts_with('~'));
        assert_ne!(s, sanitize(&format!("{}y", long)));
    }
}
