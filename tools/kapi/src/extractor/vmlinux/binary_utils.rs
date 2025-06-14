use anyhow::Result;
use std::io::Write;
use crate::formatter::OutputFormatter;

// Constants for all structure field sizes
pub mod sizes {
    pub const NAME: usize = 128;
    pub const DESC: usize = 512;
    pub const MAX_PARAMS: usize = 16;
    pub const MAX_ERRORS: usize = 32;
    pub const MAX_CONSTRAINTS: usize = 16;
}

// Helper for reading data at specific offsets
pub struct DataReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DataReader<'a> {
    pub fn new(data: &'a [u8], offset: usize) -> Self {
        Self { data, pos: offset }
    }

    pub fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.pos + len <= self.data.len() {
            let bytes = &self.data[self.pos..self.pos + len];
            self.pos += len;
            Some(bytes)
        } else {
            None
        }
    }

    pub fn read_cstring(&mut self, max_len: usize) -> Option<String> {
        let bytes = self.read_bytes(max_len)?;
        if let Some(null_pos) = bytes.iter().position(|&b| b == 0) {
            if null_pos > 0 {
                if let Ok(s) = std::str::from_utf8(&bytes[..null_pos]) {
                    return Some(s.to_string());
                }
            }
        }
        None
    }

    pub fn read_u32(&mut self) -> Option<u32> {
        let bytes = self.read_bytes(4)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn skip(&mut self, len: usize) {
        self.pos = (self.pos + len).min(self.data.len());
    }
}

#[allow(dead_code)]
pub fn parse_context_flags(flags: u32, formatter: &mut dyn OutputFormatter, w: &mut dyn Write) -> Result<()> {
    // Context flags from kernel headers
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

    if flags & KAPI_CTX_PROCESS != 0 { formatter.context_flag(w, "Process context")?; }
    if flags & KAPI_CTX_SOFTIRQ != 0 { formatter.context_flag(w, "Softirq context")?; }
    if flags & KAPI_CTX_HARDIRQ != 0 { formatter.context_flag(w, "Hardirq context")?; }
    if flags & KAPI_CTX_NMI != 0 { formatter.context_flag(w, "NMI context")?; }
    if flags & KAPI_CTX_USER != 0 { formatter.context_flag(w, "User mode")?; }
    if flags & KAPI_CTX_KERNEL != 0 { formatter.context_flag(w, "Kernel mode")?; }
    if flags & KAPI_CTX_SLEEPABLE != 0 { formatter.context_flag(w, "May sleep")?; }
    if flags & KAPI_CTX_ATOMIC != 0 { formatter.context_flag(w, "Atomic context")?; }
    if flags & KAPI_CTX_PREEMPTIBLE != 0 { formatter.context_flag(w, "Preemptible")?; }
    if flags & KAPI_CTX_MIGRATION_DISABLED != 0 { formatter.context_flag(w, "Migration disabled")?; }

    Ok(())
}

// Structure layout definitions for calculating sizes
pub fn param_spec_layout_size() -> usize {
    // Packed structure
    sizes::NAME * 2 + // name, type_name
    4 + 4 + // type, flags
    8 + 8 + // size, alignment
    8 + 8 + // min_value, max_value
    8 + // valid_mask
    8 + // enum_values pointer
    4 + 4 + // enum_count, constraint_type
    8 + // validate pointer
    sizes::DESC * 2 + // description, constraints
    4 + 8 // size_param_idx, size_multiplier
}

pub fn return_spec_layout_size() -> usize {
    // Packed structure
    sizes::NAME + // type_name
    4 + 4 + // type, check_type
    8 + 8 + 8 + // success_value, success_min, success_max
    8 + // error_values pointer
    4 + // error_count
    8 + // is_success pointer
    sizes::DESC // description
}

pub fn error_spec_layout_size() -> usize {
    // Packed structure
    4 + // code
    sizes::NAME + // name
    sizes::DESC * 2 // condition, description
}

pub fn lock_spec_layout_size() -> usize {
    // Packed structure
    sizes::NAME + // name
    4 + // lock_type
    1 + 1 + 1 + 1 + // bools
    sizes::DESC // description
}

pub fn constraint_spec_layout_size() -> usize {
    // Packed structure
    sizes::NAME + // name
    sizes::DESC * 2 // description, expression
}