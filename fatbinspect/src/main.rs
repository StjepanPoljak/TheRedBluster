mod extract;
mod info;
mod interactive;
mod list;

use clap::{ArgGroup, Parser};
use fatbinspect::util::err;
use fatbinspect::{InputKind, cubin, detect};
use extract::What;
use std::io::{self};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(version, about)]
#[command(group(ArgGroup::new("format").required(true).multiple(false)))]
#[command(group(ArgGroup::new("action").multiple(false)))]
struct Args {
    /// CUDA Binary
    #[arg(short, long, group = "format")]
    binary: Option<String>,

    /// Fatbin
    #[arg(short, long, group = "format")]
    fatbin: Option<String>,

    /// Cubin
    #[arg(short, long, group = "format")]
    cubin: Option<String>,

    /// Interactive (default when no other action is given)
    #[arg(short, long, group = "action")]
    interactive: bool,

    /// Extract fatbins, cubins, PTX and kernel .text to files
    #[arg(short, long, group = "action")]
    extract: bool,

    /// List fatbins, entries and kernels
    #[arg(short, long, group = "action")]
    list: bool,

    /// List sections (cubin input)
    #[arg(short, long, group = "action")]
    sections: bool,

    /// Print decoded headers, sections, kernels and .nv.info
    #[arg(short = 'I', long, group = "action")]
    info: bool,

    /// Output directory for --extract
    #[arg(short, long, value_name = "DIR", default_value = ".", requires = "extract")]
    outdir: PathBuf,

    /// What to extract [default: all, or text with --kernel]
    #[arg(long, value_enum, value_delimiter = ',', requires = "extract")]
    what: Vec<What>,

    /// Only extract the .text of this kernel (mangled name)
    #[arg(short, long, value_name = "NAME", requires = "extract")]
    kernel: Option<String>,

    /// Write the single extracted item to stdout
    #[arg(long, requires = "extract", conflicts_with = "outdir")]
    stdout: bool
}

fn flag(kind: InputKind) -> &'static str {
    match kind {
        InputKind::Host => "--binary",
        InputKind::Fatbin => "--fatbin",
        InputKind::Cubin => "--cubin"
    }
}

fn main() -> std::process::ExitCode {
    match run(Args::parse()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> io::Result<()> {
    let (path, kind) = match (args.binary, args.fatbin, args.cubin) {
        (Some(p), ..) => (p, InputKind::Host),
        (_, Some(p), _) => (p, InputKind::Fatbin),
        (.., Some(p)) => (p, InputKind::Cubin),
        _ => unreachable!("clap requires one input")
    };

    let data = std::fs::read(&path)?;
    match detect(&data) {
        Some(found) if found != kind => {
            return err(format!("{}: looks like a {}, not a {}; use {}.",
                path, found.name(), kind.name(), flag(found)));
        },
        Some(_) => (),
        None => return err(format!("{}: not an ELF file or fatbin.", path))
    }

    if args.list {
        return list::run(&path, kind, &data);
    }

    if args.info {
        return info::run(&path, kind, &data);
    }

    if args.extract {
        let sel = extract::Selection::new(kind, &args.what, args.kernel.as_deref())?;
        let stem = Path::new(&path).file_stem().map_or(String::from("cubin"), |s| s.to_string_lossy().into_owned());
        let items = extract::collect(kind, &stem, &data, &sel, &mut |w| eprintln!("warning: {}", w))?;
        if items.is_empty() {
            return match args.kernel {
                Some(k) => err(format!("No kernel named '{}'.", k)),
                None => err("Nothing to extract.")
            };
        }
        return extract::write(&items, &args.outdir, args.stdout);
    }

    if !args.sections {
        return interactive::run(&path, kind, data);
    }

    if kind == InputKind::Cubin && args.sections {
        info::print_section_table(&cubin::parse(&data, 0)?, 0);
        return Ok(());
    }

    err("This action is not implemented yet for the given input.")
}
