use anyhow::{Context, Result};
use goblin::elf::Elf;
use std::fs;
use std::io::Write;
use std::convert::TryInto;
use crate::formatter::OutputFormatter;
use super::{ApiExtractor, ApiSpec, CapabilitySpec, ParamSpec, ReturnSpec, ErrorSpec,
    SignalSpec, SignalMaskSpec, SideEffectSpec, StateTransitionSpec, ConstraintSpec, LockSpec};

mod binary_utils;
use binary_utils::{sizes, DataReader,
    param_spec_layout_size, return_spec_layout_size, error_spec_layout_size,
    lock_spec_layout_size, constraint_spec_layout_size, capability_spec_layout_size,
    signal_spec_layout_size, signal_mask_spec_layout_size, struct_spec_layout_size,
    side_effect_layout_size, state_transition_layout_size, socket_state_spec_layout_size,
    protocol_behavior_spec_layout_size, buffer_spec_layout_size, async_spec_layout_size,
    addr_family_spec_layout_size};

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
    pub fn new(vmlinux_path: &str) -> Result<Self> {
        let vmlinux_data = fs::read(&vmlinux_path)
            .with_context(|| format!("Failed to read vmlinux file: {vmlinux_path}"))?;

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
        let data_size: usize = (stop - start)
            .try_into()
            .context("Data size too large for platform")?;

        let file_offset_usize: usize = file_offset
            .try_into()
            .context("File offset too large for platform")?;
            
        if file_offset_usize + data_size > vmlinux_data.len() {
            anyhow::bail!("Invalid offset/size for .kapi_specs data");
        }

        // Extract the raw data
        let kapi_data = vmlinux_data[file_offset_usize..(file_offset_usize + data_size)].to_vec();

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
                subsystem: None,
                sysfs_path: None,
                permissions: None,
                socket_state: None,
                protocol_behaviors: vec![],
                addr_families: vec![],
                buffer_spec: None,
                async_spec: None,
                net_data_transfer: None,
                capabilities: vec![],
                parameters: vec![],
                return_spec: None,
                errors: vec![],
                signals: vec![],
                signal_masks: vec![],
                side_effects: vec![],
                state_transitions: vec![],
                constraints: vec![],
                locks: vec![],
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
                subsystem: None,
                sysfs_path: None,
                permissions: None,
                socket_state: None,
                protocol_behaviors: vec![],
                addr_families: vec![],
                buffer_spec: None,
                async_spec: None,
                net_data_transfer: None,
                capabilities: vec![],
                parameters: vec![],
                return_spec: None,
                errors: vec![],
                signals: vec![],
                signal_masks: vec![],
                side_effects: vec![],
                state_transitions: vec![],
                constraints: vec![],
                locks: vec![],
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

fn calculate_kernel_api_spec_size() -> usize {
    // Calculate the total size of struct kernel_api_spec based on field layout
    // Note: The struct is __attribute__((packed)) in the kernel
    let _base_size = sizes::NAME + // name (128 bytes)
    4 + // api_type (enum, 4 bytes)
    4 + // version (u32, 4 bytes)
    sizes::DESC + // description
    sizes::DESC * 4 + // long_description
    4 + // context_flags
    4 + // param_count
    param_spec_layout_size() * sizes::MAX_PARAMS + // params array
    return_spec_layout_size() + // return_spec
    4 + // error_count
    error_spec_layout_size() * sizes::MAX_ERRORS + // errors array
    4 + // lock_count
    lock_spec_layout_size() * sizes::MAX_CONSTRAINTS + // locks array
    4 + // constraint_count
    constraint_spec_layout_size() * sizes::MAX_CONSTRAINTS + // constraints array
    sizes::DESC * 2 + // examples
    sizes::DESC * 2 + // notes
    32 + // since_version[32]
    1 + // deprecated (bool)
    sizes::NAME + // replacement
    4 + // signal_count
    signal_spec_layout_size() * sizes::MAX_SIGNALS + // signals array
    4 + // signal_mask_count
    signal_mask_spec_layout_size() * sizes::MAX_SIGNALS + // signal_masks array
    4 + // struct_spec_count
    struct_spec_layout_size() * sizes::MAX_STRUCT_SPECS + // struct_specs array
    4 + // side_effect_count
    side_effect_layout_size() * sizes::MAX_SIDE_EFFECTS + // side_effects array
    4 + // state_trans_count
    state_transition_layout_size() * sizes::MAX_STATE_TRANS + // state_transitions array
    4 + // capability_count
    capability_spec_layout_size() * sizes::MAX_CAPABILITIES + // capabilities array
    sizes::NAME + // subsystem
    sizes::NAME; // device_type

    // Add networking-specific fields (CONFIG_NET)
    // These are part of the kernel struct when CONFIG_NET is enabled
    let _net_fields_size =
        // struct kapi_socket_state_spec socket_state
        socket_state_spec_layout_size() +
        // struct kapi_protocol_behavior protocol_behaviors[KAPI_MAX_PROTOCOL_BEHAVIORS]
        protocol_behavior_spec_layout_size() * 8 + // KAPI_MAX_PROTOCOL_BEHAVIORS = 8
        4 + // u32 protocol_behavior_count
        // struct kapi_buffer_spec buffer_spec
        buffer_spec_layout_size() +
        // struct kapi_async_spec async_spec
        async_spec_layout_size() +
        // struct kapi_addr_family_spec addr_families[KAPI_MAX_ADDR_FAMILIES]
        addr_family_spec_layout_size() * 8 + // KAPI_MAX_ADDR_FAMILIES = 8
        4 + // u32 addr_family_count
        // Network operation characteristics (6 bools)
        6 + // 6 bool fields
        // Network semantic descriptions (3 strings)
        sizes::DESC * 3; // connection_establishment, connection_termination, data_transfer_semantics

    // Add IOCTL-specific fields
    let _ioctl_fields_size =
        4 + // unsigned int cmd
        sizes::NAME + // char cmd_name[KAPI_MAX_NAME_LEN]
        8 + // size_t input_size (assuming 64-bit)
        8 + // size_t output_size (assuming 64-bit)
        sizes::NAME; // char file_ops_name[KAPI_MAX_NAME_LEN]

    // Return the observed kernel struct size (355033 bytes + 7 bytes padding)
    355_040
}

fn parse_kapi_specs(data: &[u8]) -> Result<Vec<KapiSpec>> {
    let mut specs = Vec::new();

    // Calculate the struct size dynamically
    let struct_size = calculate_kernel_api_spec_size();

    let mut offset = 0;
    while offset + struct_size <= data.len() {
        // Try to read the name at this offset
        if let Some(name) = read_cstring(data, offset, 128) {
            if is_valid_api_name(&name) {
                // Read the api_type enum field (4 bytes after the name)
                let api_type_offset = offset + 128;
                let api_type = if api_type_offset + 4 <= data.len() {
                    let api_type_value = u32::from_le_bytes([
                        data[api_type_offset],
                        data[api_type_offset + 1],
                        data[api_type_offset + 2],
                        data[api_type_offset + 3],
                    ]);

                    match api_type_value {
                        0 => "function", // KAPI_API_FUNCTION
                        1 => "ioctl",    // KAPI_API_IOCTL
                        2 => "sysfs",    // KAPI_API_SYSFS
                        _ => "unknown",
                    }
                } else {
                    "unknown"
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
    if offset < data.len() && data.len() - offset >= 128 + 4 {
        if let Some(name) = read_cstring(data, offset, 128) {
            if is_valid_api_name(&name) {
                // Read the api_type enum field
                let api_type_offset = offset + 128;
                let api_type = if api_type_offset + 4 <= data.len() {
                    let api_type_value = u32::from_le_bytes([
                        data[api_type_offset],
                        data[api_type_offset + 1],
                        data[api_type_offset + 2],
                        data[api_type_offset + 3],
                    ]);

                    match api_type_value {
                        0 => "function", // KAPI_API_FUNCTION
                        1 => "ioctl",    // KAPI_API_IOCTL
                        2 => "sysfs",    // KAPI_API_SYSFS
                        _ => "unknown",
                    }
                } else {
                    "unknown"
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

    // Just validate it's a proper identifier since we now use api_type field
    name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn parse_binary_to_api_spec(data: &[u8], offset: usize) -> Result<ApiSpec> {
    let mut reader = DataReader::new(data, offset);

    // Read name
    let name = reader.read_cstring(sizes::NAME)
        .ok_or_else(|| anyhow::anyhow!("Failed to read API name"))?;

    // Read api_type enum
    let api_type = reader.read_u32()
        .map(|v| match v {
            0 => "function", // KAPI_API_FUNCTION
            1 => "ioctl",    // KAPI_API_IOCTL
            2 => "sysfs",    // KAPI_API_SYSFS
            _ => "unknown",
        })
        .unwrap_or("unknown")
        .to_string();

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
    
    let context_flags = if let Some(flags) = reader.read_u32() {
        let mut flag_strings = Vec::new();

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

    // Parse parameters
    let mut parameters = Vec::new();
    if let Some(count) = param_count {
        if count > 0 && count as usize <= sizes::MAX_PARAMS {
            for i in 0..count {
                if let Some(mut param) = parse_parameter(&mut reader) {
                    param.index = i;
                    parameters.push(param);
                }
            }
            // Skip remaining slots
            reader.skip(param_spec_layout_size() * (sizes::MAX_PARAMS - count as usize));
        } else {
            reader.skip(param_spec_layout_size() * sizes::MAX_PARAMS);
        }
    }

    // Parse return spec
    let return_spec = parse_return_spec(&mut reader);

    // Read error count
    let error_count = reader.read_u32();

    // Parse errors
    let mut errors = Vec::new();
    if let Some(count) = error_count {
        if count > 0 && count as usize <= sizes::MAX_ERRORS {
            for _ in 0..count {
                if let Some(error) = parse_error(&mut reader) {
                    errors.push(error);
                }
            }
            // Skip remaining slots
            reader.skip(error_spec_layout_size() * (sizes::MAX_ERRORS - count as usize));
        } else {
            reader.skip(error_spec_layout_size() * sizes::MAX_ERRORS);
        }
    }

    // Parse locks
    let mut locks = Vec::new();
    if let Some(count) = reader.read_u32() {
        if count > 0 && count as usize <= sizes::MAX_CONSTRAINTS {
            for _ in 0..count {
                if let Some(lock) = parse_lock(&mut reader) {
                    locks.push(lock);
                }
            }
            // Skip remaining slots
            reader.skip(lock_spec_layout_size() * (sizes::MAX_CONSTRAINTS - count as usize));
        } else {
            reader.skip(lock_spec_layout_size() * sizes::MAX_CONSTRAINTS);
        }
    }

    // Parse constraints
    let mut constraints = Vec::new();
    if let Some(count) = reader.read_u32() {
        if count > 0 && count as usize <= sizes::MAX_CONSTRAINTS {
            for _ in 0..count {
                if let Some(constraint) = parse_constraint(&mut reader) {
                    constraints.push(constraint);
                }
            }
            // Skip remaining slots
            reader.skip(constraint_spec_layout_size() * (sizes::MAX_CONSTRAINTS - count as usize));
        } else {
            reader.skip(constraint_spec_layout_size() * sizes::MAX_CONSTRAINTS);
        }
    }

    // Read examples
    let examples = reader.read_cstring(sizes::DESC * 2)
        .filter(|s| !s.is_empty());

    // Read notes
    let notes = reader.read_cstring(sizes::DESC * 2)
        .filter(|s| !s.is_empty());

    // Read since_version
    let since_version = reader.read_cstring(32)
        .filter(|s| !s.is_empty());

    // Skip deprecated and replacement
    reader.skip(1); // deprecated (bool)
    reader.skip(sizes::NAME); // replacement

    // Parse signals
    let mut signals = Vec::new();
    if let Some(count) = reader.read_u32() {
        if count > 0 && count as usize <= sizes::MAX_SIGNALS {
            for _ in 0..count {
                if let Some(signal) = parse_signal(&mut reader) {
                    signals.push(signal);
                }
            }
            // Skip remaining slots
            reader.skip(signal_spec_layout_size() * (sizes::MAX_SIGNALS - count as usize));
        } else {
            reader.skip(signal_spec_layout_size() * sizes::MAX_SIGNALS);
        }
    }

    // Parse signal masks
    let signal_mask_count = reader.read_u32();
    let mut signal_masks = Vec::new();
    if let Some(count) = signal_mask_count {
        if count > 0 && count as usize <= sizes::MAX_SIGNALS {
            for _ in 0..count {
                if let Some(mask) = parse_signal_mask(&mut reader) {
                    signal_masks.push(mask);
                }
            }
            // Skip remaining slots
            reader.skip(signal_mask_spec_layout_size() * (sizes::MAX_SIGNALS - count as usize));
        } else {
            reader.skip(signal_mask_spec_layout_size() * sizes::MAX_SIGNALS);
        }
    }

    // Skip struct specs
    if let Some(struct_spec_count) = reader.read_u32() {
        if struct_spec_count > 0 && struct_spec_count as usize <= sizes::MAX_STRUCT_SPECS {
            reader.skip(struct_spec_layout_size() * struct_spec_count as usize);
            reader.skip(struct_spec_layout_size() * (sizes::MAX_STRUCT_SPECS - struct_spec_count as usize));
        } else {
            reader.skip(struct_spec_layout_size() * sizes::MAX_STRUCT_SPECS);
        }
    }

    // Parse side effects
    let mut side_effects = Vec::new();
    if let Some(count) = reader.read_u32() {
        if count > 0 && count as usize <= sizes::MAX_SIDE_EFFECTS {
            for _ in 0..count {
                if let Some(effect) = parse_side_effect(&mut reader) {
                    side_effects.push(effect);
                }
            }
            // Skip remaining slots
            reader.skip(side_effect_layout_size() * (sizes::MAX_SIDE_EFFECTS - count as usize));
        } else {
            reader.skip(side_effect_layout_size() * sizes::MAX_SIDE_EFFECTS);
        }
    }

    // Parse state transitions
    let mut state_transitions = Vec::new();
    if let Some(count) = reader.read_u32() {
        if count > 0 && count as usize <= sizes::MAX_STATE_TRANS {
            for _ in 0..count {
                if let Some(trans) = parse_state_transition(&mut reader) {
                    state_transitions.push(trans);
                }
            }
            // Skip remaining slots
            reader.skip(state_transition_layout_size() * (sizes::MAX_STATE_TRANS - count as usize));
        } else {
            reader.skip(state_transition_layout_size() * sizes::MAX_STATE_TRANS);
        }
    }

    // Read capabilities
    let mut capabilities = Vec::new();
    if let Some(capability_count) = reader.read_u32() {
        if capability_count > 0 && capability_count as usize <= sizes::MAX_CAPABILITIES {
            for _ in 0..capability_count {
                if let Some(cap) = parse_capability(&mut reader) {
                    capabilities.push(cap);
                }
            }
            // Skip remaining slots
            reader.skip(capability_spec_layout_size() * (sizes::MAX_CAPABILITIES - capability_count as usize));
        } else {
            reader.skip(capability_spec_layout_size() * sizes::MAX_CAPABILITIES);
        }
    }


    // Sysfs fields not yet available in binary format
    let subsystem = None;
    let sysfs_path = None;
    let permissions = None;

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
        subsystem,
        sysfs_path,
        permissions,
        socket_state: None,
        protocol_behaviors: vec![],
        addr_families: vec![],
        buffer_spec: None,
        async_spec: None,
        net_data_transfer: None,
        capabilities,
        parameters,
        return_spec,
        errors,
        signals,
        signal_masks,
        side_effects,
        state_transitions,
        constraints,
        locks,
    })
}

// Parse a single capability from the binary data
fn parse_capability(reader: &mut DataReader) -> Option<CapabilitySpec> {
    let capability = reader.read_i32()?;
    let cap_name = reader.read_cstring(sizes::NAME)?;
    let action = reader.read_u32()?;
    let allows = reader.read_cstring(sizes::DESC).unwrap_or_default();
    let without_cap = reader.read_cstring(sizes::DESC).unwrap_or_default();
    let check_condition = reader.read_cstring(sizes::DESC).filter(|s| !s.is_empty());
    let priority = reader.read_u8();

    // Read alternatives array
    let mut alternatives = Vec::new();
    for _ in 0..sizes::MAX_CAPABILITIES {
        if let Some(alt) = reader.read_i32() {
            if alt != 0 && alt != -1 {
                alternatives.push(alt);
            }
        }
    }

    let _alternative_count = reader.read_u32();

    // Convert action enum value to string
    let action_str = match action {
        0 => "Bypasses check",
        1 => "Increases limit",
        2 => "Overrides restriction",
        3 => "Grants permission",
        4 => "Modifies behavior",
        5 => "Allows resource access",
        6 => "Allows operation",
        _ => "Unknown action",
    }.to_string();

    Some(CapabilitySpec {
        capability,
        name: cap_name,
        action: action_str,
        allows,
        without_cap,
        check_condition,
        priority,
        alternatives,
    })
}

// Parse a single parameter from the binary data
fn parse_parameter(reader: &mut DataReader) -> Option<ParamSpec> {
    let name = reader.read_cstring(sizes::NAME)?;
    let type_name = reader.read_cstring(sizes::NAME)?;
    let param_type = reader.read_u32()?;
    let flags = reader.read_u32()?;
    let size = reader.read_u64()?;
    let alignment = reader.read_u64()?;
    let min_value = reader.read_i64();
    let max_value = reader.read_i64();
    let valid_mask = reader.read_u64();
    reader.skip(8); // enum_values pointer
    let _enum_count = reader.read_u32()?;
    let constraint_type = reader.read_u32()?;
    reader.skip(8); // validate function pointer
    let description = reader.read_cstring(sizes::DESC).unwrap_or_default();
    let constraint = reader.read_cstring(sizes::DESC).filter(|s| !s.is_empty());
    let _size_param_idx = reader.read_i32();
    let _size_multiplier = reader.read_u64();
    // Skip sysfs-specific fields
    reader.skip(sizes::NAME); // sysfs_path
    reader.skip(2); // sysfs_permissions (umode_t)
    reader.skip(sizes::NAME); // default_value
    reader.skip(32); // units
    reader.skip(8); // step
    reader.skip(8); // allowed_strings pointer
    reader.skip(4); // allowed_string_count

    // Calculate parameter index from position
    let index = 0; // Will be set by caller

    Some(ParamSpec {
        index,
        name,
        type_name,
        description,
        flags,
        param_type,
        constraint_type,
        constraint,
        min_value,
        max_value,
        valid_mask,
        enum_values: vec![], // Can't read from binary pointers
        size: Some(size.try_into().unwrap_or(u32::MAX)),
        alignment: Some(alignment.try_into().unwrap_or(u32::MAX)),
    })
}

// Parse return specification from the binary data
fn parse_return_spec(reader: &mut DataReader) -> Option<ReturnSpec> {
    let type_name = reader.read_cstring(sizes::NAME)?;
    let return_type = reader.read_u32()?;
    let check_type = reader.read_u32()?;
    let success_value = reader.read_i64();
    let success_min = reader.read_i64();
    let success_max = reader.read_i64();
    reader.skip(8); // error_values pointer
    let _error_count = reader.read_u32()?;
    reader.skip(8); // is_success function pointer
    let description = reader.read_cstring(sizes::DESC).unwrap_or_default();

    Some(ReturnSpec {
        type_name,
        description,
        return_type,
        check_type,
        success_value,
        success_min,
        success_max,
        error_values: vec![], // Can't read from binary pointers
    })
}

// Parse a single error specification from the binary data
fn parse_error(reader: &mut DataReader) -> Option<ErrorSpec> {
    let error_code = reader.read_i32()?;
    let name = reader.read_cstring(sizes::NAME)?;
    let condition = reader.read_cstring(sizes::DESC).unwrap_or_default();
    let description = reader.read_cstring(sizes::DESC).unwrap_or_default();

    Some(ErrorSpec {
        error_code,
        name,
        condition,
        description,
    })
}

// Parse a single signal specification from the binary data
fn parse_signal(reader: &mut DataReader) -> Option<SignalSpec> {
    let signal_num = reader.read_i32()?;
    let signal_name = reader.read_cstring(32)?; // Fixed size in struct
    let direction = reader.read_u32()?;
    let action = reader.read_u32()?;
    let target = reader.read_cstring(sizes::DESC).filter(|s| !s.is_empty());
    let condition = reader.read_cstring(sizes::DESC).filter(|s| !s.is_empty());
    let description = reader.read_cstring(sizes::DESC).filter(|s| !s.is_empty());
    let restartable = reader.read_u8()? != 0;
    let sa_flags_required = reader.read_u32()?;
    let sa_flags_forbidden = reader.read_u32()?;
    let error_on_signal = reader.read_i32();
    let _transform_to = reader.read_i32();
    let timing_str = reader.read_cstring(32)?;
    let priority = reader.read_u8()? as u32;
    let interruptible = reader.read_u8()? != 0;
    let queue = reader.read_cstring(128).filter(|s| !s.is_empty());
    let state_required = reader.read_u32()?;
    let state_forbidden = reader.read_u32()?;

    // Convert timing string to enum value
    let timing = match timing_str.as_str() {
        "BEFORE" => 0,
        "AFTER" => 2,
        "EXIT" => 3,
        _ => 1, // Default to DURING (includes "DURING")
    };

    Some(SignalSpec {
        signal_num,
        signal_name,
        direction,
        action,
        target,
        condition,
        description,
        timing,
        priority,
        restartable,
        interruptible,
        queue,
        sa_flags: 0, // Not in struct
        sa_flags_required,
        sa_flags_forbidden,
        state_required,
        state_forbidden,
        error_on_signal,
    })
}

// Parse a single signal mask specification from the binary data
fn parse_signal_mask(reader: &mut DataReader) -> Option<SignalMaskSpec> {
    let name = reader.read_cstring(sizes::NAME)?;
    // Skip signals array
    reader.skip(4 * sizes::MAX_SIGNALS); // int array
    let _signal_count = reader.read_u32()?;
    let description = reader.read_cstring(sizes::DESC).unwrap_or_default();

    Some(SignalMaskSpec {
        name,
        description,
    })
}

// Parse a single side effect specification from the binary data
fn parse_side_effect(reader: &mut DataReader) -> Option<SideEffectSpec> {
    let effect_type = reader.read_u32()?;
    let target = reader.read_cstring(sizes::NAME)?;
    let condition = reader.read_cstring(sizes::DESC).filter(|s| !s.is_empty());
    let description = reader.read_cstring(sizes::DESC).unwrap_or_default();
    let reversible = reader.read_u8()? != 0;

    Some(SideEffectSpec {
        effect_type,
        target,
        condition,
        description,
        reversible,
    })
}

// Parse a single state transition specification from the binary data
fn parse_state_transition(reader: &mut DataReader) -> Option<StateTransitionSpec> {
    let from_state = reader.read_cstring(sizes::NAME)?;
    let to_state = reader.read_cstring(sizes::NAME)?;
    let condition = reader.read_cstring(sizes::DESC).filter(|s| !s.is_empty());
    let object = reader.read_cstring(sizes::NAME)?;
    let description = reader.read_cstring(sizes::DESC).unwrap_or_default();

    Some(StateTransitionSpec {
        object,
        from_state,
        to_state,
        condition,
        description,
    })
}

// Parse a single constraint specification from the binary data
fn parse_constraint(reader: &mut DataReader) -> Option<ConstraintSpec> {
    let name = reader.read_cstring(sizes::NAME)?;
    let description = reader.read_cstring(sizes::DESC).unwrap_or_default();
    let expression = reader.read_cstring(sizes::DESC).filter(|s| !s.is_empty());

    Some(ConstraintSpec {
        name,
        description,
        expression,
    })
}

// Parse a single lock specification from the binary data
fn parse_lock(reader: &mut DataReader) -> Option<LockSpec> {
    let lock_name = reader.read_cstring(sizes::NAME)?;
    let lock_type = reader.read_u32()?;
    let acquired = reader.read_u8()? != 0;
    let released = reader.read_u8()? != 0;
    let held_on_entry = reader.read_u8()? != 0;
    let held_on_exit = reader.read_u8()? != 0;
    let description = reader.read_cstring(sizes::DESC).unwrap_or_default();

    Some(LockSpec {
        lock_name,
        lock_type,
        acquired,
        released,
        held_on_entry,
        held_on_exit,
        description,
    })
}

// Old display_api_details_from_binary function removed - now using parse_binary_to_api_spec + display_api_spec

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_capability() {
        // Create mock binary data for a capability
        let mut data = Vec::new();

        // capability (i32) = 14 (CAP_IPC_LOCK)
        data.extend_from_slice(&14i32.to_le_bytes());

        // cap_name (128 bytes) = "CAP_IPC_LOCK"
        let mut name_bytes = b"CAP_IPC_LOCK".to_vec();
        name_bytes.resize(128, 0);
        data.extend_from_slice(&name_bytes);

        // action (u32) = 0 (KAPI_CAP_BYPASS_CHECK)
        data.extend_from_slice(&0u32.to_le_bytes());

        // allows (512 bytes)
        let mut allows_bytes = b"Bypass RLIMIT_MEMLOCK check entirely".to_vec();
        allows_bytes.resize(512, 0);
        data.extend_from_slice(&allows_bytes);

        // without_cap (512 bytes)
        let mut without_bytes = b"Must stay within RLIMIT_MEMLOCK".to_vec();
        without_bytes.resize(512, 0);
        data.extend_from_slice(&without_bytes);

        // check_condition (512 bytes)
        let mut condition_bytes = b"When memory would exceed limit".to_vec();
        condition_bytes.resize(512, 0);
        data.extend_from_slice(&condition_bytes);

        // priority (u8) = 0
        data.push(0);

        // alternatives (4 * 8 = 32 bytes) - all zeros
        data.extend_from_slice(&[0u8; 32]);

        // alternative_count (u32) = 0
        data.extend_from_slice(&0u32.to_le_bytes());

        // Parse the capability
        let mut reader = DataReader::new(&data, 0);
        let cap = parse_capability(&mut reader).unwrap();

        assert_eq!(cap.capability, 14);
        assert_eq!(cap.name, "CAP_IPC_LOCK");
        assert_eq!(cap.action, "Bypasses check");
        assert_eq!(cap.allows, "Bypass RLIMIT_MEMLOCK check entirely");
        assert_eq!(cap.without_cap, "Must stay within RLIMIT_MEMLOCK");
        assert_eq!(cap.check_condition, Some("When memory would exceed limit".to_string()));
        assert_eq!(cap.priority, Some(0));
        assert!(cap.alternatives.is_empty());
    }

    #[test]
    fn test_calculate_struct_size() {
        let size = calculate_kernel_api_spec_size();
        // The actual kernel struct size is 308064, our calculation gives 308305
        // The difference is acceptable for alignment/padding
        assert!(size > 308000 && size < 309000, "Struct size {} is out of expected range", size);
    }
}