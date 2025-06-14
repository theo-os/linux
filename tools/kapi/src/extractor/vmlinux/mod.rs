use anyhow::{Context, Result};
use goblin::elf::Elf;
use std::fs;
use std::io::Write;
use crate::formatter::OutputFormatter;
use super::{ApiExtractor, ApiSpec};

mod binary_utils;
use binary_utils::{sizes, DataReader,
    param_spec_layout_size, return_spec_layout_size, error_spec_layout_size,
    lock_spec_layout_size, constraint_spec_layout_size};

pub struct VmlinuxExtractor {
    kapi_data: Vec<u8>,
    specs: Vec<KapiSpec>,
}

#[derive(Debug)]
struct KapiSpec {
    name: String,
    api_type: String,
    offset: usize,
}

impl VmlinuxExtractor {
    pub fn new(vmlinux_path: String) -> Result<Self> {
        let vmlinux_data = fs::read(&vmlinux_path)
            .with_context(|| format!("Failed to read vmlinux file: {}", vmlinux_path))?;

        let elf = Elf::parse(&vmlinux_data)
            .context("Failed to parse ELF file")?;

        // Find the .kapi_specs section
        let kapi_section = elf.section_headers
            .iter()
            .find(|sh| {
                if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                    name == ".kapi_specs"
                } else {
                    false
                }
            })
            .context("Could not find .kapi_specs section in vmlinux")?;

        // Find __start_kapi_specs and __stop_kapi_specs symbols
        let mut start_addr = None;
        let mut stop_addr = None;

        for sym in &elf.syms {
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                match name {
                    "__start_kapi_specs" => start_addr = Some(sym.st_value),
                    "__stop_kapi_specs" => stop_addr = Some(sym.st_value),
                    _ => {}
                }
            }
        }

        let start = start_addr.context("Could not find __start_kapi_specs symbol")?;
        let stop = stop_addr.context("Could not find __stop_kapi_specs symbol")?;

        if stop <= start {
            anyhow::bail!("No kernel API specifications found in vmlinux");
        }

        // Calculate the offset within the file
        let section_vaddr = kapi_section.sh_addr;
        let file_offset = kapi_section.sh_offset + (start - section_vaddr);
        let data_size = (stop - start) as usize;

        if file_offset as usize + data_size > vmlinux_data.len() {
            anyhow::bail!("Invalid offset/size for .kapi_specs data");
        }

        // Extract the raw data
        let kapi_data = vmlinux_data[file_offset as usize..(file_offset as usize + data_size)].to_vec();

        // Parse the specifications
        let specs = parse_kapi_specs(&kapi_data)?;

        Ok(VmlinuxExtractor {
            kapi_data,
            specs,
        })
    }

}

impl ApiExtractor for VmlinuxExtractor {
    fn extract_all(&self) -> Result<Vec<ApiSpec>> {
        // For vmlinux extractor, we return basic info only
        // Detailed parsing happens in display_api_details
        Ok(self.specs.iter().map(|spec| {
            ApiSpec {
                name: spec.name.clone(),
                api_type: spec.api_type.clone(),
                description: None,
                long_description: None,
                version: None,
                context_flags: vec![],
                param_count: None,
                error_count: None,
                examples: None,
                notes: None,
                since_version: None,
            }
        }).collect())
    }

    fn extract_by_name(&self, name: &str) -> Result<Option<ApiSpec>> {
        Ok(self.specs.iter()
            .find(|s| s.name == name)
            .map(|spec| ApiSpec {
                name: spec.name.clone(),
                api_type: spec.api_type.clone(),
                description: None,
                long_description: None,
                version: None,
                context_flags: vec![],
                param_count: None,
                error_count: None,
                examples: None,
                notes: None,
                since_version: None,
            }))
    }

    fn display_api_details(
        &self,
        api_name: &str,
        formatter: &mut dyn OutputFormatter,
        writer: &mut dyn Write,
    ) -> Result<()> {
        if let Some(spec) = self.specs.iter().find(|s| s.name == api_name) {
            // Parse the binary data into an ApiSpec
            let api_spec = parse_binary_to_api_spec(&self.kapi_data, spec.offset)?;
            // Use the common display function
            super::display_api_spec(&api_spec, formatter, writer)?;
        }
        Ok(())
    }
}

fn parse_kapi_specs(data: &[u8]) -> Result<Vec<KapiSpec>> {
    let mut specs = Vec::new();

    // The kernel_api_spec struct size in the kernel is 308064 bytes
    // This is calculated as sizeof(struct kernel_api_spec) which includes:
    // - Basic fields (name, version, description, etc.)
    // - Arrays for parameters, errors, locks, constraints
    // - Additional metadata fields
    // TODO: This should ideally be read from kernel headers or made configurable
    let struct_size = 308064;

    let mut offset = 0;
    while offset + struct_size <= data.len() {
        // Try to read the name at this offset
        if let Some(name) = read_cstring(data, offset, 128) {
            if is_valid_api_name(&name) {
                let api_type = if name.starts_with("sys_") {
                    "syscall"
                } else if name.contains("ioctl") || name.contains("IOCTL") {
                    "ioctl"
                } else {
                    "other"
                };

                specs.push(KapiSpec {
                    name: name.to_string(),
                    api_type: api_type.to_string(),
                    offset,
                });
            }
        }

        offset += struct_size;
    }

    // Handle any remaining data that might be a partial spec
    if offset < data.len() && data.len() - offset >= 128 {
        if let Some(name) = read_cstring(data, offset, 128) {
            if is_valid_api_name(&name) {
                let api_type = if name.starts_with("sys_") {
                    "syscall"
                } else if name.contains("ioctl") || name.contains("IOCTL") {
                    "ioctl"
                } else {
                    "other"
                };

                specs.push(KapiSpec {
                    name: name.to_string(),
                    api_type: api_type.to_string(),
                    offset,
                });
            }
        }
    }

    Ok(specs)
}

fn read_cstring(data: &[u8], offset: usize, max_len: usize) -> Option<String> {
    if offset + max_len > data.len() {
        return None;
    }

    let bytes = &data[offset..offset + max_len];
    if let Some(null_pos) = bytes.iter().position(|&b| b == 0) {
        if null_pos > 0 {
            if let Ok(s) = std::str::from_utf8(&bytes[..null_pos]) {
                return Some(s.to_string());
            }
        }
    }
    None
}

fn is_valid_api_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 100 {
        return false;
    }

    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        && (name.starts_with("sys_")
            || name.contains("ioctl")
            || name.contains("IOCTL")
            || name.starts_with("do_")
            || name.starts_with("__"))
}

fn parse_binary_to_api_spec(data: &[u8], offset: usize) -> Result<ApiSpec> {
    let mut reader = DataReader::new(data, offset);

    // Read name
    let name = reader.read_cstring(sizes::NAME)
        .ok_or_else(|| anyhow::anyhow!("Failed to read API name"))?;

    // Read version
    let version = reader.read_u32()
        .map(|v| v.to_string());

    // Read description
    let description = reader.read_cstring(sizes::DESC)
        .filter(|s| !s.is_empty());

    // Read long description
    let long_description = reader.read_cstring(sizes::DESC * 4)
        .filter(|s| !s.is_empty());

    // Read context flags
    let context_flags = if let Some(flags) = reader.read_u32() {
        let mut flag_strings = Vec::new();

        const KAPI_CTX_PROCESS: u32 = 1 << 0;
        const KAPI_CTX_SOFTIRQ: u32 = 1 << 1;
        const KAPI_CTX_HARDIRQ: u32 = 1 << 2;
        const KAPI_CTX_NMI: u32 = 1 << 3;
        const KAPI_CTX_USER: u32 = 1 << 4;
        const KAPI_CTX_KERNEL: u32 = 1 << 5;
        const KAPI_CTX_SLEEPABLE: u32 = 1 << 6;
        const KAPI_CTX_ATOMIC: u32 = 1 << 7;
        const KAPI_CTX_PREEMPTIBLE: u32 = 1 << 8;
        const KAPI_CTX_MIGRATION_DISABLED: u32 = 1 << 9;

        // Build the flag string similar to source format
        let mut parts = Vec::new();
        if flags & KAPI_CTX_PROCESS != 0 { parts.push("KAPI_CTX_PROCESS"); }
        if flags & KAPI_CTX_SOFTIRQ != 0 { parts.push("KAPI_CTX_SOFTIRQ"); }
        if flags & KAPI_CTX_HARDIRQ != 0 { parts.push("KAPI_CTX_HARDIRQ"); }
        if flags & KAPI_CTX_NMI != 0 { parts.push("KAPI_CTX_NMI"); }
        if flags & KAPI_CTX_USER != 0 { parts.push("KAPI_CTX_USER"); }
        if flags & KAPI_CTX_KERNEL != 0 { parts.push("KAPI_CTX_KERNEL"); }
        if flags & KAPI_CTX_SLEEPABLE != 0 { parts.push("KAPI_CTX_SLEEPABLE"); }
        if flags & KAPI_CTX_ATOMIC != 0 { parts.push("KAPI_CTX_ATOMIC"); }
        if flags & KAPI_CTX_PREEMPTIBLE != 0 { parts.push("KAPI_CTX_PREEMPTIBLE"); }
        if flags & KAPI_CTX_MIGRATION_DISABLED != 0 { parts.push("KAPI_CTX_MIGRATION_DISABLED"); }

        if !parts.is_empty() {
            flag_strings.push(parts.join(" | "));
        }
        flag_strings
    } else {
        vec![]
    };

    // Read parameter count
    let param_count = reader.read_u32();

    // Skip parameters for now (to match source output)
    if let Some(count) = param_count {
        if count > 0 && count <= sizes::MAX_PARAMS as u32 {
            reader.skip(param_spec_layout_size() * count as usize);
            reader.skip(param_spec_layout_size() * (sizes::MAX_PARAMS - count as usize));
        } else {
            reader.skip(param_spec_layout_size() * sizes::MAX_PARAMS);
        }
    }

    // Skip return spec
    reader.skip(return_spec_layout_size());

    // Read error count
    let error_count = reader.read_u32();

    // Skip errors
    if let Some(count) = error_count {
        if count > 0 && count <= sizes::MAX_ERRORS as u32 {
            reader.skip(error_spec_layout_size() * count as usize);
            reader.skip(error_spec_layout_size() * (sizes::MAX_ERRORS - count as usize));
        } else {
            reader.skip(error_spec_layout_size() * sizes::MAX_ERRORS);
        }
    }

    // Skip locks
    if let Some(lock_count) = reader.read_u32() {
        if lock_count > 0 && lock_count <= sizes::MAX_CONSTRAINTS as u32 {
            reader.skip(lock_spec_layout_size() * lock_count as usize);
            reader.skip(lock_spec_layout_size() * (sizes::MAX_CONSTRAINTS - lock_count as usize));
        } else {
            reader.skip(lock_spec_layout_size() * sizes::MAX_CONSTRAINTS);
        }
    }

    // Skip constraints
    if let Some(constraint_count) = reader.read_u32() {
        if constraint_count > 0 && constraint_count <= sizes::MAX_CONSTRAINTS as u32 {
            reader.skip(constraint_spec_layout_size() * constraint_count as usize);
            reader.skip(constraint_spec_layout_size() * (sizes::MAX_CONSTRAINTS - constraint_count as usize));
        } else {
            reader.skip(constraint_spec_layout_size() * sizes::MAX_CONSTRAINTS);
        }
    }

    // Read examples
    let examples = reader.read_cstring(sizes::DESC * 2)
        .filter(|s| !s.is_empty());

    // Read notes
    let notes = reader.read_cstring(sizes::DESC)
        .filter(|s| !s.is_empty());

    // Read since_version
    let since_version = reader.read_cstring(32)
        .filter(|s| !s.is_empty());

    // Determine API type from name
    let api_type = if name.starts_with("sys_") {
        "syscall"
    } else if name.contains("ioctl") || name.contains("IOCTL") {
        "ioctl"
    } else {
        "other"
    }.to_string();

    Ok(ApiSpec {
        name,
        api_type,
        description,
        long_description,
        version,
        context_flags,
        param_count,
        error_count,
        examples,
        notes,
        since_version,
    })
}

// Old display_api_details_from_binary function removed - now using parse_binary_to_api_spec + display_api_spec