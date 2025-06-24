
// Constants for all structure field sizes
pub mod sizes {
    pub const NAME: usize = 128;
    pub const DESC: usize = 512;
    pub const MAX_PARAMS: usize = 16;
    pub const MAX_ERRORS: usize = 32;
    pub const MAX_CONSTRAINTS: usize = 16;
    pub const MAX_CAPABILITIES: usize = 8;
    pub const MAX_SIGNALS: usize = 16;
    pub const MAX_STRUCT_SPECS: usize = 8;
    pub const MAX_SIDE_EFFECTS: usize = 16;
    pub const MAX_STATE_TRANS: usize = 16;
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

    pub fn read_u8(&mut self) -> Option<u8> {
        let bytes = self.read_bytes(1)?;
        Some(bytes[0])
    }

    pub fn read_i32(&mut self) -> Option<i32> {
        let bytes = self.read_bytes(4)?;
        Some(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn read_u64(&mut self) -> Option<u64> {
        let bytes = self.read_bytes(8)?;
        Some(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7]
        ]))
    }

    pub fn read_i64(&mut self) -> Option<i64> {
        let bytes = self.read_bytes(8)?;
        Some(i64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7]
        ]))
    }

    pub fn skip(&mut self, len: usize) {
        self.pos = (self.pos + len).min(self.data.len());
    }
}

// Structure layout definitions for calculating sizes
pub fn param_spec_layout_size() -> usize {
    // Packed structure from struct kapi_param_spec
    sizes::NAME + // name
    sizes::NAME + // type_name
    4 + // type (enum)
    4 + // flags
    8 + // size (size_t)
    8 + // alignment (size_t)
    8 + // min_value
    8 + // max_value
    8 + // valid_mask
    8 + // enum_values pointer
    4 + // enum_count
    4 + // constraint_type (enum)
    8 + // validate function pointer
    sizes::DESC + // description
    sizes::DESC + // constraints
    4 + // size_param_idx
    8 + // size_multiplier (size_t)
    // sysfs-specific fields
    sizes::NAME + // sysfs_path
    2 + // sysfs_permissions (umode_t)
    sizes::NAME + // default_value
    32 + // units
    8 + // step
    8 + // allowed_strings pointer
    4 // allowed_string_count
}

pub fn return_spec_layout_size() -> usize {
    // Packed structure from struct kapi_return_spec
    sizes::NAME + // type_name
    4 + // type (enum)
    4 + // check_type (enum)
    8 + // success_value
    8 + // success_min
    8 + // success_max
    8 + // error_values pointer
    4 + // error_count
    8 + // is_success function pointer
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

pub fn capability_spec_layout_size() -> usize {
    // Packed structure from struct kapi_capability_spec
    4 + // capability (int)
    sizes::NAME + // cap_name
    4 + // action (enum)
    sizes::DESC + // allows
    sizes::DESC + // without_cap
    sizes::DESC + // check_condition
    1 + // priority (u8)
    4 * sizes::MAX_CAPABILITIES + // alternative array
    4 // alternative_count
}

pub fn signal_spec_layout_size() -> usize {
    // Packed structure from struct kapi_signal_spec
    4 + // signal_num
    32 + // signal_name[32]
    4 + // direction (u32)
    4 + // action (enum)
    sizes::DESC + // target
    sizes::DESC + // condition
    sizes::DESC + // description
    1 + // restartable (bool)
    4 + // sa_flags_required
    4 + // sa_flags_forbidden
    4 + // error_on_signal
    4 + // transform_to
    32 + // timing[32]
    1 + // priority (u8)
    1 + // interruptible (bool)
    128 + // queue_behavior[128]
    4 + // state_required
    4 // state_forbidden
}

pub fn signal_mask_spec_layout_size() -> usize {
    // Packed structure from struct kapi_signal_mask_spec
    sizes::NAME + // mask_name
    4 * sizes::MAX_SIGNALS + // signals array
    4 + // signal_count
    sizes::DESC // description
}

pub fn struct_field_layout_size() -> usize {
    // Packed structure from struct kapi_struct_field
    sizes::NAME + // name
    4 + // type (enum)
    sizes::NAME + // type_name
    8 + // offset (size_t)
    8 + // size (size_t)
    4 + // flags
    4 + // constraint_type (enum)
    8 + // min_value (s64)
    8 + // max_value (s64)
    8 + // valid_mask (u64)
    sizes::DESC // description
}

pub fn struct_spec_layout_size() -> usize {
    // Packed structure from struct kapi_struct_spec
    sizes::NAME + // name
    8 + // size (size_t)
    8 + // alignment (size_t)
    4 + // field_count
    struct_field_layout_size() * sizes::MAX_PARAMS + // fields array
    sizes::DESC // description
}

pub fn side_effect_layout_size() -> usize {
    // Packed structure from struct kapi_side_effect
    4 + // type (u32)
    sizes::NAME + // target
    sizes::DESC + // condition
    sizes::DESC + // description
    1 // reversible (bool)
}

pub fn state_transition_layout_size() -> usize {
    // Packed structure from struct kapi_state_transition
    sizes::NAME + // from_state
    sizes::NAME + // to_state
    sizes::DESC + // condition
    sizes::NAME + // object
    sizes::DESC // description
}

pub fn socket_state_spec_layout_size() -> usize {
    // struct kapi_socket_state_spec
    sizes::NAME * sizes::MAX_CONSTRAINTS + // required_states array
    sizes::NAME * sizes::MAX_CONSTRAINTS + // forbidden_states array
    sizes::NAME + // resulting_state
    sizes::DESC + // condition
    sizes::NAME + // applicable_protocols
    4 + // required_count
    4   // forbidden_count
}

pub fn protocol_behavior_spec_layout_size() -> usize {
    // struct kapi_protocol_behavior
    sizes::NAME + // applicable_protocols
    sizes::DESC + // behavior
    sizes::NAME + // protocol_flags
    sizes::DESC   // flag_description
}

pub fn buffer_spec_layout_size() -> usize {
    // struct kapi_buffer_spec
    sizes::DESC + // buffer_behaviors
    8 + // min_buffer_size (size_t)
    8 + // max_buffer_size (size_t)
    8   // optimal_buffer_size (size_t)
}

pub fn async_spec_layout_size() -> usize {
    // struct kapi_async_spec
    sizes::NAME + // supported_modes
    4   // nonblock_errno (int)
}

pub fn addr_family_spec_layout_size() -> usize {
    // struct kapi_addr_family_spec
    4 + // family (int)
    sizes::NAME + // family_name
    8 + // addr_struct_size (size_t)
    8 + // min_addr_len (size_t)
    8 + // max_addr_len (size_t)
    sizes::DESC + // addr_format
    1 + // supports_wildcard (bool)
    1 + // supports_multicast (bool)
    1 + // supports_broadcast (bool)
    sizes::DESC + // special_addresses
    4 + // port_range_min (u32)
    4   // port_range_max (u32)
}