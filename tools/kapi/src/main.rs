//! kapi - Kernel API Specification Tool
//!
//! This tool extracts and displays kernel API specifications from multiple sources:
//! - Kernel source code (KAPI macros)
//! - Compiled vmlinux binaries (`.kapi_specs` ELF section)
//! - Running kernel via debugfs

use anyhow::Result;
use clap::Parser;
use std::io::{self, Write};

mod formatter;
mod extractor;

use formatter::{OutputFormat, create_formatter};
use extractor::{ApiExtractor, VmlinuxExtractor, SourceExtractor, DebugfsExtractor};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the vmlinux file
    #[arg(long, value_name = "PATH", group = "input")]
    vmlinux: Option<String>,

    /// Path to kernel source directory or file
    #[arg(long, value_name = "PATH", group = "input")]
    source: Option<String>,

    /// Path to debugfs (defaults to /sys/kernel/debug if not specified)
    #[arg(long, value_name = "PATH", group = "input")]
    debugfs: Option<String>,

    /// Optional: Name of specific API to show details for
    api_name: Option<String>,

    /// Output format
    #[arg(long, short = 'f', default_value = "plain")]
    format: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let output_format: OutputFormat = args.format.parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    let extractor: Box<dyn ApiExtractor> = match (args.vmlinux, args.source, args.debugfs.clone()) {
        (Some(vmlinux_path), None, None) => {
            Box::new(VmlinuxExtractor::new(&vmlinux_path)?)
        }
        (None, Some(source_path), None) => {
            Box::new(SourceExtractor::new(&source_path)?)
        }
        (None, None, Some(_) | None) => {
            // If debugfs is specified or no input is provided, use debugfs
            Box::new(DebugfsExtractor::new(args.debugfs)?)
        }
        _ => {
            anyhow::bail!("Please specify only one of --vmlinux, --source, or --debugfs")
        }
    };

    display_apis(extractor.as_ref(), args.api_name, output_format)
}

fn display_apis(extractor: &dyn ApiExtractor, api_name: Option<String>, output_format: OutputFormat) -> Result<()> {
    let mut formatter = create_formatter(output_format);
    let mut stdout = io::stdout();

    formatter.begin_document(&mut stdout)?;

    if let Some(api_name_req) = api_name {
        // Use the extractor to display API details
        if let Some(_spec) = extractor.extract_by_name(&api_name_req)? {
            extractor.display_api_details(&api_name_req, &mut *formatter, &mut stdout)?;
        } else if output_format == OutputFormat::Plain {
            writeln!(stdout, "\nAPI '{}' not found.", api_name_req)?;
            writeln!(stdout, "\nAvailable APIs:")?;
            for spec in extractor.extract_all()? {
                writeln!(stdout, "  {} ({})", spec.name, spec.api_type)?;
            }
        }
    } else {
        // Display list of APIs using the extractor
        let all_specs = extractor.extract_all()?;
        let syscalls: Vec<_> = all_specs.iter().filter(|s| s.api_type == "syscall").collect();
        let ioctls: Vec<_> = all_specs.iter().filter(|s| s.api_type == "ioctl").collect();
        let functions: Vec<_> = all_specs.iter().filter(|s| s.api_type == "function").collect();
        let sysfs: Vec<_> = all_specs.iter().filter(|s| s.api_type == "sysfs").collect();

        if !syscalls.is_empty() {
            formatter.begin_api_list(&mut stdout, "System Calls")?;
            for spec in syscalls {
                formatter.api_item(&mut stdout, &spec.name, &spec.api_type)?;
            }
            formatter.end_api_list(&mut stdout)?;
        }

        if !ioctls.is_empty() {
            formatter.begin_api_list(&mut stdout, "IOCTLs")?;
            for spec in ioctls {
                formatter.api_item(&mut stdout, &spec.name, &spec.api_type)?;
            }
            formatter.end_api_list(&mut stdout)?;
        }

        if !functions.is_empty() {
            formatter.begin_api_list(&mut stdout, "Functions")?;
            for spec in functions {
                formatter.api_item(&mut stdout, &spec.name, &spec.api_type)?;
            }
            formatter.end_api_list(&mut stdout)?;
        }

        if !sysfs.is_empty() {
            formatter.begin_api_list(&mut stdout, "Sysfs Attributes")?;
            for spec in sysfs {
                formatter.api_item(&mut stdout, &spec.name, &spec.api_type)?;
            }
            formatter.end_api_list(&mut stdout)?;
        }

        formatter.total_specs(&mut stdout, all_specs.len())?;
    }

    formatter.end_document(&mut stdout)?;

    Ok(())
}

