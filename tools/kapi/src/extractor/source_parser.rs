use anyhow::{Context, Result};
use regex::Regex;
use std::fs;
use std::path::Path;
use std::collections::HashMap;
use walkdir::WalkDir;
use std::io::Write;
use crate::formatter::OutputFormatter;
use super::{ApiExtractor, ApiSpec, CapabilitySpec, display_api_spec,
    SocketStateSpec, ProtocolBehaviorSpec, AddrFamilySpec, BufferSpec, AsyncSpec,
    StateTransitionSpec, SideEffectSpec, ParamSpec, ReturnSpec, ErrorSpec, LockSpec, ConstraintSpec};

#[derive(Debug, Clone)]
pub struct SourceApiSpec {
    pub name: String,
    pub api_type: ApiType,
    pub parsed_fields: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ApiType {
    Syscall,
    Ioctl,
    Function,
    Sysfs,
    Unknown,
}

impl ApiType {
    fn from_name(name: &str) -> Self {
        if name.starts_with("sys_") {
            ApiType::Syscall
        } else if name.contains("ioctl") || name.contains("IOCTL") {
            ApiType::Ioctl
        } else if name.starts_with("do_") || name.starts_with("__") {
            ApiType::Function
        } else {
            ApiType::Unknown
        }
    }
}

pub struct SourceParser {
    // Regex patterns for matching KAPI specifications
    spec_start_pattern: Regex,
    spec_end_pattern: Regex,
    ioctl_spec_pattern: Regex,
    sysfs_spec_pattern: Regex,
    // Networking-specific patterns
    socket_state_req_pattern: Regex,
    socket_state_result_pattern: Regex,
    socket_state_cond_pattern: Regex,
    socket_state_protos_pattern: Regex,
    protocol_behavior_pattern: Regex,
    protocol_flags_pattern: Regex,
    addr_family_pattern: Regex,
    addr_format_pattern: Regex,
    addr_features_pattern: Regex,
    addr_special_pattern: Regex,
    addr_ports_pattern: Regex,
    buffer_spec_pattern: Regex,
    async_spec_pattern: Regex,
    net_data_transfer_pattern: Regex,
}

impl SourceParser {
    pub fn new() -> Result<Self> {
        Ok(SourceParser {
            // Match DEFINE_KERNEL_API_SPEC(function_name)
            spec_start_pattern: Regex::new(r"DEFINE_KERNEL_API_SPEC\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)")?,
            // Match KAPI_END_SPEC
            spec_end_pattern: Regex::new(r"KAPI_END_SPEC")?,
            // Match IOCTL specifications
            ioctl_spec_pattern: Regex::new(r#"DEFINE_IOCTL_API_SPEC\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*,\s*([^,]+)\s*,\s*"([^"]+)"\s*\)"#)?,
            // Match SYSFS specifications
            sysfs_spec_pattern: Regex::new(r"DEFINE_SYSFS_API_SPEC\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)")?,
            // Networking-specific patterns
            socket_state_req_pattern: Regex::new(r"KAPI_SOCKET_STATE_REQ\s*\(\s*([^)]+)\s*\)")?,
            socket_state_result_pattern: Regex::new(r"KAPI_SOCKET_STATE_RESULT\s*\(\s*([^)]+)\s*\)")?,
            socket_state_cond_pattern: Regex::new(r#"KAPI_SOCKET_STATE_COND\s*\(\s*"([^"]*)"\s*\)"#)?,
            socket_state_protos_pattern: Regex::new(r"KAPI_SOCKET_STATE_PROTOS\s*\(\s*([^)]+)\s*\)")?,
            protocol_behavior_pattern: Regex::new(r#"KAPI_PROTOCOL_BEHAVIOR\s*\(\s*(\d+)\s*,\s*([^,]+)\s*,\s*"([^"]*(?:\s*"[^"]*)*?)"\s*\)"#)?,
            protocol_flags_pattern: Regex::new(r#"KAPI_PROTOCOL_FLAGS\s*\(\s*(\d+)\s*,\s*"([^"]*)"\s*\)"#)?,
            addr_family_pattern: Regex::new(r#"KAPI_ADDR_FAMILY\s*\(\s*(\d+)\s*,\s*([^,]+)\s*,\s*"([^"]+)"\s*,\s*([^,]+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)"#)?,
            addr_format_pattern: Regex::new(r#"KAPI_ADDR_FORMAT\s*\(\s*"([^"]*)"\s*\)"#)?,
            addr_features_pattern: Regex::new(r"KAPI_ADDR_FEATURES\s*\(\s*(true|false)\s*,\s*(true|false)\s*,\s*(true|false)\s*\)")?,
            addr_special_pattern: Regex::new(r#"KAPI_ADDR_SPECIAL\s*\(\s*"([^"]*(?:\s*"[^"]*)*?)"\s*\)"#)?,
            addr_ports_pattern: Regex::new(r"KAPI_ADDR_PORTS\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)")?,
            buffer_spec_pattern: Regex::new(r"KAPI_BUFFER_SPEC\s*\(\s*(\d+)\s*\)")?,
            async_spec_pattern: Regex::new(r"KAPI_ASYNC_SPEC\s*\(\s*([^,]+)\s*,\s*(\d+)\s*\)")?,
            net_data_transfer_pattern: Regex::new(r#"KAPI_NET_DATA_TRANSFER\s*\(\s*"([^"]*)"\s*\)"#)?,
        })
    }

    /// Parse a single source file for KAPI specifications
    pub fn parse_file(&self, path: &Path) -> Result<Vec<SourceApiSpec>> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read file: {}", path.display()))?;

        self.parse_content(&content, path)
    }

    /// Parse file content for KAPI specifications
    pub fn parse_content(&self, content: &str, _file_path: &Path) -> Result<Vec<SourceApiSpec>> {
        let mut specs = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        // First, look for standard KAPI specs
        for (i, line) in lines.iter().enumerate() {
            if let Some(captures) = self.spec_start_pattern.captures(line) {
                let api_name = captures.get(1).unwrap().as_str().to_string();

                // Find the end of this specification
                if let Some(spec_content) = self.extract_spec_block(&lines, i) {
                    let mut spec = SourceApiSpec {
                        name: api_name.clone(),
                        api_type: ApiType::from_name(&api_name),
                        parsed_fields: HashMap::new(),
                    };

                    // Parse the fields
                    self.parse_spec_fields(&spec_content, &mut spec.parsed_fields)?;

                    specs.push(spec);
                }
            }

            // Also look for IOCTL specs
            if let Some(captures) = self.ioctl_spec_pattern.captures(line) {
                let spec_name = captures.get(1).unwrap().as_str().to_string();
                let cmd = captures.get(2).unwrap().as_str().to_string();
                let cmd_name = captures.get(3).unwrap().as_str().to_string();

                // Find the end of this IOCTL specification
                if let Some(spec_content) = self.extract_ioctl_spec_block(&lines, i) {
                    let mut spec = SourceApiSpec {
                        name: spec_name,
                        api_type: ApiType::Ioctl,
                        parsed_fields: HashMap::new(),
                    };

                    // Add IOCTL-specific fields
                    spec.parsed_fields.insert("cmd".to_string(), cmd);
                    spec.parsed_fields.insert("cmd_name".to_string(), cmd_name);

                    // Parse other fields
                    self.parse_spec_fields(&spec_content, &mut spec.parsed_fields)?;

                    specs.push(spec);
                }
            }

            // Also look for SYSFS specs
            if let Some(captures) = self.sysfs_spec_pattern.captures(line) {
                let attr_name = captures.get(1).unwrap().as_str().to_string();

                // Find the end of this specification
                if let Some(spec_content) = self.extract_spec_block(&lines, i) {
                    let mut spec = SourceApiSpec {
                        name: attr_name,
                        api_type: ApiType::Sysfs,
                        parsed_fields: HashMap::new(),
                    };

                    // Parse the fields
                    self.parse_spec_fields(&spec_content, &mut spec.parsed_fields)?;

                    specs.push(spec);
                }
            }
        }

        Ok(specs)
    }

    /// Extract a complete KAPI specification block from the source
    fn extract_spec_block(&self, lines: &[&str], start_idx: usize) -> Option<String> {
        let mut spec_lines = Vec::new();

        for (_i, line) in lines.iter().enumerate().skip(start_idx) {
            spec_lines.push((*line).to_string());

            // Check for end of spec
            if self.spec_end_pattern.is_match(line) {
                return Some(spec_lines.join("\n"));
            }
        }

        None
    }

    /// Extract a complete IOCTL specification block
    fn extract_ioctl_spec_block(&self, lines: &[&str], start_idx: usize) -> Option<String> {
        let mut spec_lines = Vec::new();
        let mut brace_count = 0;

        for (i, line) in lines.iter().enumerate().skip(start_idx) {
            spec_lines.push((*line).to_string());

            // Count braces
            for ch in line.chars() {
                match ch {
                    '{' => brace_count += 1,
                    '}' => brace_count -= 1,
                    _ => {}
                }
            }

            // Check for end patterns
            if line.contains("KAPI_END_IOCTL_SPEC") || line.contains("KAPI_IOCTL_END_SPEC") {
                return Some(spec_lines.join("\n"));
            }

            // Alternative end: closing brace with semicolon at top level
            if brace_count == 0 && line.contains("};") && i > start_idx {
                return Some(spec_lines.join("\n"));
            }
        }

        None
    }

    /// Parse individual KAPI fields from the specification
    fn parse_spec_fields(&self, content: &str, fields: &mut HashMap<String, String>) -> Result<()> {
        // Parse KAPI_DESCRIPTION
        if let Some(captures) = Regex::new(r#"KAPI_DESCRIPTION\s*\(\s*"([^"]*)"\s*\)"#)?.captures(content) {
            fields.insert("description".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Parse KAPI_LONG_DESC (handle multi-line)
        if let Some(captures) = Regex::new(r#"KAPI_LONG_DESC\s*\(\s*"([^"]*(?:\s*"[^"]*)*?)"\s*\)"#)?.captures(content) {
            let long_desc = captures.get(1).unwrap().as_str()
                .replace("\"\n\t\t       \"", " ")
                .replace("\"\n\t\t    \"", " ")
                .replace("\"\n\t\t   \"", " ")
                .replace("\"\n\t\t  \"", " ")
                .replace("\"\n\t\t \"", " ")
                .replace("\"\n\t\t\"", " ");
            fields.insert("long_description".to_string(), long_desc);
        }

        // Parse KAPI_CONTEXT
        if let Some(captures) = Regex::new(r"KAPI_CONTEXT\s*\(([^)]+)\)")?.captures(content) {
            fields.insert("context".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Parse KAPI_NOTES (handle multi-line)
        if let Some(captures) = Regex::new(r#"KAPI_NOTES\s*\(\s*"([^"]*(?:\s*"[^"]*)*?)"\s*\)"#)?.captures(content) {
            let notes = captures.get(1).unwrap().as_str()
                .replace("\"\n\t\t   \"", "\n")
                .replace("\"\n\t\t  \"", "\n")
                .replace("\"\n\t\t \"", "\n")
                .replace("\"\n\t\t\"", "\n")
                .replace("\\n", "\n")
                .replace("\\\"", "\"")
                .trim()
                .to_string();
            fields.insert("notes".to_string(), notes);
        }

        // Parse KAPI_EXAMPLES (handle multi-line)
        if let Some(captures) = Regex::new(r#"KAPI_EXAMPLES\s*\(\s*"([^"]*(?:\s*"[^"]*)*?)"\s*\)"#)?.captures(content) {
            let examples = captures.get(1).unwrap().as_str()
                .replace("\"\n\t\t      \"", "")
                .replace("\"\n\t\t     \"", "")
                .replace("\"\n\t\t    \"", "")
                .replace("\"\n\t\t   \"", "")
                .replace("\"\n\t\t  \"", "")
                .replace("\"\n\t\t \"", "")
                .replace("\"\n\t\t\"", "")
                .replace("\\n\\n", "\n\n")
                .replace("\\n", "\n")
                .replace("\\\"", "\"")
                .replace("\\\\", "\\")
                .trim()
                .to_string();
            fields.insert("examples".to_string(), examples);
        }

        // Parse KAPI_SINCE_VERSION
        if let Some(captures) = Regex::new(r#"KAPI_SINCE_VERSION\s*\(\s*"([^"]*)"\s*\)"#)?.captures(content) {
            fields.insert("since_version".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Parse parameter count
        let param_regex = Regex::new(r"KAPI_PARAM\s*\(\s*(\d+)\s*,")?;
        let mut max_param_idx = 0;
        for captures in param_regex.captures_iter(content) {
            if let Ok(idx) = captures.get(1).unwrap().as_str().parse::<usize>() {
                max_param_idx = max_param_idx.max(idx + 1);
            }
        }
        if max_param_idx > 0 {
            fields.insert("param_count".to_string(), max_param_idx.to_string());
        }

        // Parse error count
        let error_regex = Regex::new(r"KAPI_ERROR\s*\(\s*(\d+)\s*,")?;
        let mut max_error_idx = 0;
        for captures in error_regex.captures_iter(content) {
            if let Ok(idx) = captures.get(1).unwrap().as_str().parse::<usize>() {
                max_error_idx = max_error_idx.max(idx + 1);
            }
        }
        if max_error_idx > 0 {
            fields.insert("error_count".to_string(), max_error_idx.to_string());
        }

        // Parse other counts
        if content.contains(".error_count =") {
            if let Some(captures) = Regex::new(r"\.error_count\s*=\s*(\d+)")?.captures(content) {
                fields.insert("error_count".to_string(), captures.get(1).unwrap().as_str().to_string());
            }
        }

        // Parse capability count
        if let Some(captures) = Regex::new(r"KAPI_CAPABILITY_COUNT\s*\(\s*(\d+)\s*\)")?.captures(content) {
            fields.insert("capability_count".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Also check for .capability_count = N
        if content.contains(".capability_count =") {
            if let Some(captures) = Regex::new(r"\.capability_count\s*=\s*(\d+)")?.captures(content) {
                fields.insert("capability_count".to_string(), captures.get(1).unwrap().as_str().to_string());
            }
        }

        // Parse capabilities
        let cap_regex = Regex::new(r#"KAPI_CAPABILITY\s*\(\s*(\d+)\s*,\s*(\d+)\s*,\s*"([^"]+)"\s*,\s*([A-Z_]+)\s*\)"#)?;
        let mut capabilities = Vec::new();
        for captures in cap_regex.captures_iter(content) {
            let idx = captures.get(1).unwrap().as_str().parse::<usize>().unwrap_or(0);
            let cap_id = captures.get(2).unwrap().as_str();
            let cap_name = captures.get(3).unwrap().as_str();
            let cap_action = captures.get(4).unwrap().as_str();

            // Store capability info - we'll parse the details separately
            let cap_key = format!("capability_{}", idx);
            fields.insert(format!("{}_id", cap_key), cap_id.to_string());
            fields.insert(format!("{}_name", cap_key), cap_name.to_string());
            fields.insert(format!("{}_action", cap_key), cap_action.to_string());
            capabilities.push(idx);
        }

        // Pre-compile capability regex patterns
        let cap_allows_pattern = Regex::new(r#"KAPI_CAP_ALLOWS\s*\(\s*"([^"]*)"\s*\)"#)?;
        let cap_without_pattern = Regex::new(r#"KAPI_CAP_WITHOUT\s*\(\s*"([^"]*)"\s*\)"#)?;
        let cap_condition_pattern = Regex::new(r#"KAPI_CAP_CONDITION\s*\(\s*"([^"]*)"\s*\)"#)?;
        let cap_priority_pattern = Regex::new(r"KAPI_CAP_PRIORITY\s*\(\s*(\d+)\s*\)")?;

        // Parse capability details for each found capability
        for idx in capabilities {
            let cap_key = format!("capability_{}", idx);

            // Find the capability block and parse its fields
            if let Some(cap_start) = content.find(&format!("KAPI_CAPABILITY({},", idx)) {
                if let Some(cap_end) = content[cap_start..].find("KAPI_CAPABILITY_END") {
                    let cap_content = &content[cap_start..cap_start + cap_end];

                    // Parse KAPI_CAP_ALLOWS
                    if let Some(captures) = cap_allows_pattern.captures(cap_content) {
                        fields.insert(format!("{}_allows", cap_key), captures.get(1).unwrap().as_str().to_string());
                    }

                    // Parse KAPI_CAP_WITHOUT
                    if let Some(captures) = cap_without_pattern.captures(cap_content) {
                        fields.insert(format!("{}_without", cap_key), captures.get(1).unwrap().as_str().to_string());
                    }

                    // Parse KAPI_CAP_CONDITION
                    if let Some(captures) = cap_condition_pattern.captures(cap_content) {
                        fields.insert(format!("{}_condition", cap_key), captures.get(1).unwrap().as_str().to_string());
                    }

                    // Parse KAPI_CAP_PRIORITY
                    if let Some(captures) = cap_priority_pattern.captures(cap_content) {
                        fields.insert(format!("{}_priority", cap_key), captures.get(1).unwrap().as_str().to_string());
                    }
                }
            }
        }

        if content.contains(".param_count =") {
            if let Some(captures) = Regex::new(r"\.param_count\s*=\s*(\d+)")?.captures(content) {
                fields.insert("param_count".to_string(), captures.get(1).unwrap().as_str().to_string());
            }
        }

        // Parse .since_version
        if let Some(captures) = Regex::new(r#"\.since_version\s*=\s*"([^"]*)""#)?.captures(content) {
            fields.insert("since_version".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Parse .notes (handle multi-line)
        if let Some(captures) = Regex::new(r#"\.notes\s*=\s*"([^"]*(?:\s*"[^"]*)*?)""#)?.captures(content) {
            let notes = captures.get(1).unwrap().as_str()
                .replace("\"\n\t\t \"", " ")
                .replace("\"\n\t\t\"", " ")
                .replace("\"\n\t \"", " ")  // Handle single tab + space
                .trim()
                .to_string();
            fields.insert("notes".to_string(), notes);
        }

        // Parse .examples (handle multi-line)
        if let Some(captures) = Regex::new(r#"\.examples\s*=\s*"([^"]*(?:\s*"[^"]*)*?)""#)?.captures(content) {
            let examples = captures.get(1).unwrap().as_str()
                .replace("\\n\"\n\t\t    \"", "\n")
                .replace("\\n", "\n");
            fields.insert("examples".to_string(), examples);
        }

        // Parse sysfs-specific fields
        // Parse KAPI_SUBSYSTEM
        if let Some(captures) = Regex::new(r#"KAPI_SUBSYSTEM\s*\(\s*"([^"]*)"\s*\)"#)?.captures(content) {
            fields.insert("subsystem".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Parse .subsystem =
        if let Some(captures) = Regex::new(r#"\.subsystem\s*=\s*"([^"]*)""#)?.captures(content) {
            fields.insert("subsystem".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Parse KAPI_PATH (for sysfs path)
        if let Some(captures) = Regex::new(r#"KAPI_PATH\s*\(\s*"([^"]*)"\s*\)"#)?.captures(content) {
            fields.insert("sysfs_path".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Parse KAPI_PERMISSIONS
        if let Some(captures) = Regex::new(r"KAPI_PERMISSIONS\s*\(\s*(\d+)\s*\)")?.captures(content) {
            fields.insert("permissions".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Parse networking-specific fields

        // Parse socket state fields
        if let Some(captures) = self.socket_state_req_pattern.captures(content) {
            fields.insert("socket_state_req".to_string(), captures.get(1).unwrap().as_str().to_string());
        }
        if let Some(captures) = self.socket_state_result_pattern.captures(content) {
            fields.insert("socket_state_result".to_string(), captures.get(1).unwrap().as_str().to_string());
        }
        if let Some(captures) = self.socket_state_cond_pattern.captures(content) {
            fields.insert("socket_state_cond".to_string(), captures.get(1).unwrap().as_str().to_string());
        }
        if let Some(captures) = self.socket_state_protos_pattern.captures(content) {
            fields.insert("socket_state_protos".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Parse protocol behaviors
        let mut protocol_behaviors = Vec::new();
        for captures in self.protocol_behavior_pattern.captures_iter(content) {
            let idx = captures.get(1).unwrap().as_str().parse::<usize>().unwrap_or(0);
            let protos = captures.get(2).unwrap().as_str();
            let behavior = captures.get(3).unwrap().as_str()
                .replace("\"\n\t\t\"", " ")
                .replace("\"\n\t\"", " ");

            fields.insert(format!("protocol_behavior_{}_protos", idx), protos.to_string());
            fields.insert(format!("protocol_behavior_{}_desc", idx), behavior);
            protocol_behaviors.push(idx);
        }
        if !protocol_behaviors.is_empty() {
            fields.insert("protocol_behavior_indices".to_string(),
                         protocol_behaviors.iter().map(ToString::to_string).collect::<Vec<_>>().join(","));
        }

        // Parse protocol flags (associated with behaviors)
        for captures in self.protocol_flags_pattern.captures_iter(content) {
            let idx = captures.get(1).unwrap().as_str().parse::<usize>().unwrap_or(0);
            let flags = captures.get(2).unwrap().as_str();
            fields.insert(format!("protocol_behavior_{}_flags", idx), flags.to_string());
        }

        // Parse address families
        let mut addr_families = Vec::new();
        for captures in self.addr_family_pattern.captures_iter(content) {
            let idx = captures.get(1).unwrap().as_str().parse::<usize>().unwrap_or(0);
            let family = captures.get(2).unwrap().as_str();
            let name = captures.get(3).unwrap().as_str();
            let struct_size = captures.get(4).unwrap().as_str();
            let min_len = captures.get(5).unwrap().as_str();
            let max_len = captures.get(6).unwrap().as_str();

            fields.insert(format!("addr_family_{}_id", idx), family.to_string());
            fields.insert(format!("addr_family_{}_name", idx), name.to_string());
            fields.insert(format!("addr_family_{}_struct_size", idx), struct_size.to_string());
            fields.insert(format!("addr_family_{}_min_len", idx), min_len.to_string());
            fields.insert(format!("addr_family_{}_max_len", idx), max_len.to_string());
            addr_families.push(idx);
        }
        if !addr_families.is_empty() {
            fields.insert("addr_family_indices".to_string(),
                         addr_families.iter().map(ToString::to_string).collect::<Vec<_>>().join(","));
        }

        // Parse address family details - these appear after KAPI_ADDR_FAMILY within the block
        for idx in &addr_families {
            // Find the KAPI_ADDR_FAMILY block for this index
            if let Some(family_start) = content.find(&format!("KAPI_ADDR_FAMILY({},", idx)) {
                if let Some(family_end) = content[family_start..].find("KAPI_ADDR_FAMILY_END") {
                    let family_content = &content[family_start..family_start + family_end];

                    // Parse KAPI_ADDR_FORMAT
                    if let Some(captures) = self.addr_format_pattern.captures(family_content) {
                        fields.insert(format!("addr_family_{}_format", idx), captures.get(1).unwrap().as_str().to_string());
                    }

                    // Parse KAPI_ADDR_FEATURES
                    if let Some(captures) = self.addr_features_pattern.captures(family_content) {
                        fields.insert(format!("addr_family_{}_wildcard", idx), captures.get(1).unwrap().as_str().to_string());
                        fields.insert(format!("addr_family_{}_multicast", idx), captures.get(2).unwrap().as_str().to_string());
                        fields.insert(format!("addr_family_{}_broadcast", idx), captures.get(3).unwrap().as_str().to_string());
                    }

                    // Parse KAPI_ADDR_SPECIAL
                    if let Some(captures) = self.addr_special_pattern.captures(family_content) {
                        let special = captures.get(1).unwrap().as_str()
                            .replace("\"\n\t\t\t  \"", " ")
                            .replace("\"\n\t\t\t\"", " ");
                        fields.insert(format!("addr_family_{}_special", idx), special);
                    }

                    // Parse KAPI_ADDR_PORTS
                    if let Some(captures) = self.addr_ports_pattern.captures(family_content) {
                        fields.insert(format!("addr_family_{}_port_min", idx), captures.get(1).unwrap().as_str().to_string());
                        fields.insert(format!("addr_family_{}_port_max", idx), captures.get(2).unwrap().as_str().to_string());
                    }
                }
            }
        }

        // Parse KAPI_ADDR_FAMILY_COUNT
        if let Some(captures) = Regex::new(r"KAPI_ADDR_FAMILY_COUNT\s*\(\s*(\d+)\s*\)")?.captures(content) {
            fields.insert("addr_family_count".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Parse KAPI_PROTOCOL_BEHAVIOR_COUNT
        if let Some(captures) = Regex::new(r"KAPI_PROTOCOL_BEHAVIOR_COUNT\s*\(\s*(\d+)\s*\)")?.captures(content) {
            fields.insert("protocol_behavior_count".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Parse buffer spec
        if let Some(captures) = self.buffer_spec_pattern.captures(content) {
            fields.insert("buffer_spec_behaviors".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Parse async spec
        if let Some(captures) = self.async_spec_pattern.captures(content) {
            fields.insert("async_spec_modes".to_string(), captures.get(1).unwrap().as_str().to_string());
            fields.insert("async_spec_errno".to_string(), captures.get(2).unwrap().as_str().to_string());
        }

        // Parse net data transfer
        if let Some(captures) = self.net_data_transfer_pattern.captures(content) {
            fields.insert("net_data_transfer".to_string(), captures.get(1).unwrap().as_str().to_string());
        }

        // Parse various count fields that appear in networking specs
        let count_fields = [
            ("lock_count", r"KAPI_LOCK_COUNT\s*\(\s*(\d+)\s*\)"),
            ("signal_count", r"KAPI_SIGNAL_COUNT\s*\(\s*(\d+)\s*\)"),
            ("side_effect_count", r"KAPI_SIDE_EFFECT_COUNT\s*\(\s*(\d+)\s*\)"),
            ("state_trans_count", r"KAPI_STATE_TRANS_COUNT\s*\(\s*(\d+)\s*\)"),
            ("constraint_count", r"KAPI_CONSTRAINT_COUNT\s*\(\s*(\d+)\s*\)"),
        ];

        for (field_name, pattern) in count_fields.iter() {
            if let Some(captures) = Regex::new(pattern)?.captures(content) {
                fields.insert((*field_name).to_string(), captures.get(1).unwrap().as_str().to_string());
            }
        }

        // Parse state transitions
        let state_trans_pattern = Regex::new(r#"KAPI_STATE_TRANS\s*\(\s*(\d+)\s*,\s*"([^"]+)"\s*,\s*\n?\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*\n?\s*"([^"]+)"\s*\)(?s).*?KAPI_STATE_TRANS_END"#)?;
        let state_trans_cond_pattern = Regex::new(r#"KAPI_STATE_TRANS_COND\s*\(\s*"([^"]*)"\s*\)"#)?;
        let mut state_transitions = Vec::new();
        for captures in state_trans_pattern.captures_iter(content) {
            let idx = captures.get(1).unwrap().as_str().parse::<usize>().unwrap_or(0);
            let object = captures.get(2).unwrap().as_str();
            let from_state = captures.get(3).unwrap().as_str();
            let to_state = captures.get(4).unwrap().as_str();
            let description = captures.get(5).unwrap().as_str();
            let block = captures.get(0).unwrap().as_str();

            // Parse condition within the state transition block
            let condition = state_trans_cond_pattern.captures(block)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str())
                .map(ToString::to_string);

            fields.insert(format!("state_trans_{}_object", idx), object.to_string());
            fields.insert(format!("state_trans_{}_from", idx), from_state.to_string());
            fields.insert(format!("state_trans_{}_to", idx), to_state.to_string());
            if let Some(cond) = condition {
                fields.insert(format!("state_trans_{}_condition", idx), cond);
            }
            fields.insert(format!("state_trans_{}_desc", idx), description.to_string());
            state_transitions.push(idx);
        }

        if !state_transitions.is_empty() {
            fields.insert("state_trans_indices".to_string(),
                         state_transitions.iter().map(ToString::to_string).collect::<Vec<_>>().join(","));
        }

        // Parse side effects
        let side_effect_pattern = Regex::new(r#"KAPI_SIDE_EFFECT\s*\(\s*(\d+)\s*,\s*([^,]+)\s*,\s*\n?\s*"([^"]+)"\s*,\s*\n?\s*"([^"]+)"\s*\)(?s).*?KAPI_SIDE_EFFECT_END"#)?;
        let effect_cond_pattern = Regex::new(r#"KAPI_EFFECT_CONDITION\s*\(\s*"([^"]*)"\s*\)"#)?;
        let effect_reversible_pattern = Regex::new(r"KAPI_EFFECT_REVERSIBLE")?;
        let mut side_effects = Vec::new();
        for captures in side_effect_pattern.captures_iter(content) {
            let idx = captures.get(1).unwrap().as_str().parse::<usize>().unwrap_or(0);
            let effect_type = captures.get(2).unwrap().as_str().trim();
            let target = captures.get(3).unwrap().as_str();
            let description = captures.get(4).unwrap().as_str();
            let block = captures.get(0).unwrap().as_str();

            // Parse additional fields within the side effect block

            let condition = effect_cond_pattern.captures(block)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str())
                .map(ToString::to_string);

            let reversible = effect_reversible_pattern.is_match(block);

            fields.insert(format!("side_effect_{}_type", idx), effect_type.to_string());
            fields.insert(format!("side_effect_{}_target", idx), target.to_string());
            if let Some(cond) = condition {
                fields.insert(format!("side_effect_{}_condition", idx), cond);
            }
            fields.insert(format!("side_effect_{}_desc", idx), description.to_string());
            fields.insert(format!("side_effect_{}_reversible", idx), reversible.to_string());
            side_effects.push(idx);
        }

        if !side_effects.is_empty() {
            fields.insert("side_effect_indices".to_string(),
                         side_effects.iter().map(ToString::to_string).collect::<Vec<_>>().join(","));
        }

        // Parse parameters
        let param_pattern = Regex::new(r#"KAPI_PARAM\s*\(\s*(\d+)\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)(?s).*?KAPI_PARAM_END"#)?;
        let param_flags_pattern = Regex::new(r"KAPI_PARAM_FLAGS\s*\(\s*([^)]+)\s*\)")?;
        let param_type_pattern = Regex::new(r"KAPI_PARAM_TYPE\s*\(\s*([^)]+)\s*\)")?;
        let param_constraint_type_pattern = Regex::new(r"KAPI_PARAM_CONSTRAINT_TYPE\s*\(\s*([^)]+)\s*\)")?;
        let param_constraint_pattern = Regex::new(r#"KAPI_PARAM_CONSTRAINT\s*\(\s*"([^"]*)"\s*\)"#)?;
        let param_range_pattern = Regex::new(r"KAPI_PARAM_RANGE\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)")?;
        let mut parameters = Vec::new();
        for captures in param_pattern.captures_iter(content) {
            let idx = captures.get(1).unwrap().as_str().parse::<usize>().unwrap_or(0);
            let name = captures.get(2).unwrap().as_str();
            let type_name = captures.get(3).unwrap().as_str();
            let description = captures.get(4).unwrap().as_str();
            let block = captures.get(0).unwrap().as_str();

            // Parse additional fields within the param block

            let flags = param_flags_pattern.captures(block)
                .and_then(|c| c.get(1))
                .map_or_else(String::new, |m| m.as_str().to_string());

            let param_type = param_type_pattern.captures(block)
                .and_then(|c| c.get(1))
                .map_or_else(String::new, |m| m.as_str().to_string());

            let constraint_type = param_constraint_type_pattern.captures(block)
                .and_then(|c| c.get(1))
                .map_or_else(String::new, |m| m.as_str().to_string());

            let constraint = param_constraint_pattern.captures(block)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str())
                .map(ToString::to_string);

            fields.insert(format!("param_{}_name", idx), name.to_string());
            fields.insert(format!("param_{}_type", idx), type_name.to_string());
            fields.insert(format!("param_{}_desc", idx), description.to_string());
            fields.insert(format!("param_{}_flags", idx), flags);
            fields.insert(format!("param_{}_param_type", idx), param_type);
            fields.insert(format!("param_{}_constraint_type", idx), constraint_type);
            if let Some(con) = constraint {
                fields.insert(format!("param_{}_constraint", idx), con);
            }

            if let Some(range_caps) = param_range_pattern.captures(block) {
                fields.insert(format!("param_{}_min", idx), range_caps.get(1).unwrap().as_str().to_string());
                fields.insert(format!("param_{}_max", idx), range_caps.get(2).unwrap().as_str().to_string());
            }

            parameters.push(idx);
        }

        if !parameters.is_empty() {
            fields.insert("param_indices".to_string(),
                         parameters.iter().map(ToString::to_string).collect::<Vec<_>>().join(","));
        }

        // Parse return specification
        let return_pattern = Regex::new(r#"KAPI_RETURN\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)(?s).*?KAPI_RETURN_END"#)?;
        if let Some(captures) = return_pattern.captures(content) {
            let type_name = captures.get(1).unwrap().as_str();
            let description = captures.get(2).unwrap().as_str();
            let block = captures.get(0).unwrap().as_str();

            fields.insert("return_type".to_string(), type_name.to_string());
            fields.insert("return_desc".to_string(), description.to_string());

            // Parse additional return fields
            let ret_type_pattern = Regex::new(r"KAPI_RETURN_TYPE\s*\(\s*([^)]+)\s*\)")?;
            let check_type_pattern = Regex::new(r"KAPI_RETURN_CHECK_TYPE\s*\(\s*([^)]+)\s*\)")?;
            let success_pattern = Regex::new(r"KAPI_RETURN_SUCCESS\s*\(\s*([^)]+)\s*\)")?;

            if let Some(caps) = ret_type_pattern.captures(block) {
                fields.insert("return_return_type".to_string(), caps.get(1).unwrap().as_str().to_string());
            }
            if let Some(caps) = check_type_pattern.captures(block) {
                fields.insert("return_check_type".to_string(), caps.get(1).unwrap().as_str().to_string());
            }
            if let Some(caps) = success_pattern.captures(block) {
                fields.insert("return_success".to_string(), caps.get(1).unwrap().as_str().to_string());
            }
        }

        // Parse errors
        let error_pattern = Regex::new(r#"KAPI_ERROR\s*\(\s*(\d+)\s*,\s*([^,]+)\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*\n?\s*"([^"]+)"\s*\)"#)?;
        let mut errors = Vec::new();
        for captures in error_pattern.captures_iter(content) {
            let idx = captures.get(1).unwrap().as_str().parse::<usize>().unwrap_or(0);
            let error_code = captures.get(2).unwrap().as_str();
            let name = captures.get(3).unwrap().as_str();
            let condition = captures.get(4).unwrap().as_str();
            let description = captures.get(5).unwrap().as_str();

            fields.insert(format!("error_{}_code", idx), error_code.to_string());
            fields.insert(format!("error_{}_name", idx), name.to_string());
            fields.insert(format!("error_{}_condition", idx), condition.to_string());
            fields.insert(format!("error_{}_desc", idx), description.to_string());
            errors.push(idx);
        }

        if !errors.is_empty() {
            fields.insert("error_indices".to_string(),
                         errors.iter().map(ToString::to_string).collect::<Vec<_>>().join(","));
        }

        // Parse locks
        let lock_pattern = Regex::new(r#"KAPI_LOCK\s*\(\s*(\d+)\s*,\s*"([^"]+)"\s*,\s*([^)]+)\s*\)(?s).*?KAPI_LOCK_END"#)?;
        let lock_desc_pattern = Regex::new(r#"KAPI_LOCK_DESC\s*\(\s*"([^"]*)"\s*\)"#)?;
        let mut locks = Vec::new();
        for captures in lock_pattern.captures_iter(content) {
            let idx = captures.get(1).unwrap().as_str().parse::<usize>().unwrap_or(0);
            let lock_name = captures.get(2).unwrap().as_str();
            let lock_type = captures.get(3).unwrap().as_str();
            let block = captures.get(0).unwrap().as_str();

            fields.insert(format!("lock_{}_name", idx), lock_name.to_string());
            fields.insert(format!("lock_{}_type", idx), lock_type.to_string());

            // Parse lock description
            if let Some(desc_caps) = lock_desc_pattern.captures(block) {
                fields.insert(format!("lock_{}_desc", idx), desc_caps.get(1).unwrap().as_str().to_string());
            }

            // Parse lock flags
            if block.contains("KAPI_LOCK_HELD_ENTRY") {
                fields.insert(format!("lock_{}_held_entry", idx), "true".to_string());
            }
            if block.contains("KAPI_LOCK_HELD_EXIT") {
                fields.insert(format!("lock_{}_held_exit", idx), "true".to_string());
            }
            if block.contains("KAPI_LOCK_ACQUIRED") {
                fields.insert(format!("lock_{}_acquired", idx), "true".to_string());
            }
            if block.contains("KAPI_LOCK_RELEASED") {
                fields.insert(format!("lock_{}_released", idx), "true".to_string());
            }

            locks.push(idx);
        }

        if !locks.is_empty() {
            fields.insert("lock_indices".to_string(),
                         locks.iter().map(ToString::to_string).collect::<Vec<_>>().join(","));
        }

        // Parse constraints
        let constraint_pattern = Regex::new(r#"KAPI_CONSTRAINT\s*\(\s*(\d+)\s*,\s*"([^"]+)"\s*,\s*\n?\s*"([^"]*(?:\s*"[^"]*)*?)"\s*\)(?s).*?KAPI_CONSTRAINT_END"#)?;
        let constraint_expr_pattern = Regex::new(r#"KAPI_CONSTRAINT_EXPR\s*\(\s*"([^"]*)"\s*\)"#)?;
        let mut constraints = Vec::new();
        for captures in constraint_pattern.captures_iter(content) {
            let idx = captures.get(1).unwrap().as_str().parse::<usize>().unwrap_or(0);
            let name = captures.get(2).unwrap().as_str();
            let description = captures.get(3).unwrap().as_str()
                .replace("\"\n\t\t\t\"", " ")
                .replace("\"\n\t\t\"", " ")
                .replace("\"\n\t\"", " ")
                .trim()
                .to_string();
            let block = captures.get(0).unwrap().as_str();

            fields.insert(format!("constraint_{}_name", idx), name.to_string());
            fields.insert(format!("constraint_{}_desc", idx), description);

            // Parse constraint expression if present
            if let Some(expr_caps) = constraint_expr_pattern.captures(block) {
                fields.insert(format!("constraint_{}_expr", idx), expr_caps.get(1).unwrap().as_str().to_string());
            }

            constraints.push(idx);
        }

        if !constraints.is_empty() {
            fields.insert("constraint_indices".to_string(),
                         constraints.iter().map(ToString::to_string).collect::<Vec<_>>().join(","));
        }

        Ok(())
    }

    /// Scan a directory tree for files containing KAPI specifications
    pub fn scan_directory(&self, dir: &Path, extensions: &[&str]) -> Result<Vec<SourceApiSpec>> {
        let mut all_specs = Vec::new();

        for entry in WalkDir::new(dir)
            .follow_links(true)
            .into_iter()
            .filter_map(Result::ok)
        {
            let path = entry.path();

            // Skip non-files
            if !path.is_file() {
                continue;
            }

            // Check file extension
            if let Some(ext) = path.extension() {
                if extensions.iter().any(|&e| ext == e) {
                    // Try to parse the file
                    match self.parse_file(path) {
                        Ok(specs) => {
                            if !specs.is_empty() {
                                all_specs.extend(specs);
                            }
                        }
                        Err(_e) => {}
                    }
                }
            }
        }

        Ok(all_specs)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_syscall_spec() {
        let parser = SourceParser::new().unwrap();

        let content = r#"
DEFINE_KERNEL_API_SPEC(sys_mlock)
    KAPI_DESCRIPTION("Lock pages in memory")
    KAPI_LONG_DESC("Locks pages in the specified address range into RAM")
    KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE)

    KAPI_PARAM(0, "start", "unsigned long", "Starting address")
    KAPI_PARAM_END

    KAPI_PARAM(1, "len", "size_t", "Length of range")
    KAPI_PARAM_END

    .param_count = 2,
    .error_count = 3,

KAPI_END_SPEC
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", content).unwrap();

        let specs = parser.parse_content(content, temp_file.path()).unwrap();

        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "sys_mlock");
        assert_eq!(specs[0].api_type, ApiType::Syscall);
        assert_eq!(specs[0].parsed_fields.get("description").unwrap(), "Lock pages in memory");
        assert_eq!(specs[0].parsed_fields.get("param_count").unwrap(), "2");
    }

    #[test]
    fn test_parse_ioctl_spec() {
        let parser = SourceParser::new().unwrap();

        let content = r#"
DEFINE_IOCTL_API_SPEC(binder_write_read, BINDER_WRITE_READ, "BINDER_WRITE_READ")
    KAPI_DESCRIPTION("Perform read/write operations on binder")
    KAPI_CONTEXT(KAPI_CTX_PROCESS | KAPI_CTX_SLEEPABLE)

    KAPI_PARAM(0, "write_size", "binder_size_t", "Bytes to write")
    KAPI_PARAM_END

KAPI_END_IOCTL_SPEC
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", content).unwrap();

        let specs = parser.parse_content(content, temp_file.path()).unwrap();

        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "binder_write_read");
        assert_eq!(specs[0].api_type, ApiType::Ioctl);
        assert_eq!(specs[0].parsed_fields.get("cmd_name").unwrap(), "BINDER_WRITE_READ");
    }

    #[test]
    fn test_parse_sysfs_spec() {
        let parser = SourceParser::new().unwrap();

        let content = r#"
DEFINE_SYSFS_API_SPEC(nr_requests)
    KAPI_DESCRIPTION("Number of allocatable requests")
    KAPI_LONG_DESC("This controls how many requests may be allocated")
    KAPI_SUBSYSTEM("block")
    KAPI_PATH("/sys/block/<disk>/queue/nr_requests")
    KAPI_PERMISSIONS(0644)
    .param_count = 1,
KAPI_END_SPEC
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        write!(temp_file, "{}", content).unwrap();

        let specs = parser.parse_content(content, temp_file.path()).unwrap();

        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].name, "nr_requests");
        assert_eq!(specs[0].api_type, ApiType::Sysfs);
        assert_eq!(specs[0].parsed_fields.get("description").unwrap(), "Number of allocatable requests");
        assert_eq!(specs[0].parsed_fields.get("subsystem").unwrap(), "block");
        assert_eq!(specs[0].parsed_fields.get("sysfs_path").unwrap(), "/sys/block/<disk>/queue/nr_requests");
        assert_eq!(specs[0].parsed_fields.get("permissions").unwrap(), "0644");
    }
}

// SourceExtractor implementation
pub struct SourceExtractor {
    specs: Vec<SourceApiSpec>,
}

impl SourceExtractor {
    pub fn new(path: &str) -> Result<Self> {
        let parser = SourceParser::new()?;
        let path_obj = Path::new(&path);

        let specs = if path_obj.is_file() {
            parser.parse_file(path_obj)?
        } else if path_obj.is_dir() {
            parser.scan_directory(path_obj, &["c", "h"])?
        } else {
            anyhow::bail!("Path does not exist: {}", path_obj.display())
        };

        Ok(SourceExtractor { specs })
    }

    fn convert_capability_action(action: &str) -> String {
        match action {
            "KAPI_CAP_BYPASS_CHECK" => "Bypasses check".to_string(),
            "KAPI_CAP_INCREASE_LIMIT" => "Increases limit".to_string(),
            "KAPI_CAP_OVERRIDE_RESTRICTION" => "Overrides restriction".to_string(),
            "KAPI_CAP_GRANT_PERMISSION" => "Grants permission".to_string(),
            "KAPI_CAP_MODIFY_BEHAVIOR" => "Modifies behavior".to_string(),
            "KAPI_CAP_ACCESS_RESOURCE" => "Allows resource access".to_string(),
            "KAPI_CAP_PERFORM_OPERATION" => "Allows operation".to_string(),
            _ => action.to_string(),
        }
    }

    fn parse_state_transitions(source_spec: &SourceApiSpec) -> Vec<StateTransitionSpec> {
        let mut transitions = Vec::new();

        if let Some(indices_str) = source_spec.parsed_fields.get("state_trans_indices") {
            for idx_str in indices_str.split(',') {
                if let Ok(idx) = idx_str.parse::<usize>() {
                    let object = source_spec.parsed_fields.get(&format!("state_trans_{}_object", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let from_state = source_spec.parsed_fields.get(&format!("state_trans_{}_from", idx))
                        .cloned()
                        .unwrap_or_else(|| "any".to_string());
                    let to_state = source_spec.parsed_fields.get(&format!("state_trans_{}_to", idx))
                        .cloned()
                        .unwrap_or_else(|| "changed".to_string());
                    let condition = source_spec.parsed_fields.get(&format!("state_trans_{}_condition", idx))
                        .cloned();
                    let description = source_spec.parsed_fields.get(&format!("state_trans_{}_desc", idx))
                        .cloned()
                        .unwrap_or_else(String::new);

                    transitions.push(StateTransitionSpec {
                        object,
                        from_state,
                        to_state,
                        condition,
                        description,
                    });
                }
            }
        }

        transitions
    }

    fn parse_side_effects(source_spec: &SourceApiSpec) -> Vec<SideEffectSpec> {
        let mut effects = Vec::new();

        if let Some(indices_str) = source_spec.parsed_fields.get("side_effect_indices") {
            for idx_str in indices_str.split(',') {
                if let Ok(idx) = idx_str.parse::<usize>() {
                    let effect_type_str = source_spec.parsed_fields.get(&format!("side_effect_{}_type", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let target = source_spec.parsed_fields.get(&format!("side_effect_{}_target", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let condition = source_spec.parsed_fields.get(&format!("side_effect_{}_condition", idx))
                        .cloned();
                    let description = source_spec.parsed_fields.get(&format!("side_effect_{}_desc", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let reversible = source_spec.parsed_fields.get(&format!("side_effect_{}_reversible", idx))
                        .is_some_and(|s| s == "true");

                    // Convert effect type string to u32
                    let effect_type = Self::parse_effect_type(&effect_type_str);

                    effects.push(SideEffectSpec {
                        effect_type,
                        target,
                        condition,
                        description,
                        reversible,
                    });
                }
            }
        }

        effects
    }

    fn parse_effect_type(effect_type_str: &str) -> u32 {
        // Parse effect type flags
        let mut effect_type = 0u32;
        let parts: Vec<&str> = effect_type_str.split('|').map(str::trim).collect();

        for part in parts {
            match part {
                "KAPI_EFFECT_MODIFY_STATE" => effect_type |= 1 << 0,
                "KAPI_EFFECT_ALLOCATE_MEMORY" => effect_type |= 1 << 1,
                "KAPI_EFFECT_FREE_MEMORY" => effect_type |= 1 << 2,
                "KAPI_EFFECT_IO_OPERATION" => effect_type |= 1 << 3,
                "KAPI_EFFECT_SIGNAL_SEND" => effect_type |= 1 << 4,
                "KAPI_EFFECT_PROCESS_CREATE" => effect_type |= 1 << 5,
                "KAPI_EFFECT_PROCESS_TERMINATE" => effect_type |= 1 << 6,
                "KAPI_EFFECT_FILE_CREATE" => effect_type |= 1 << 7,
                "KAPI_EFFECT_FILE_DELETE" => effect_type |= 1 << 8,
                "KAPI_EFFECT_RESOURCE_CREATE" => effect_type |= 1 << 9,
                "KAPI_EFFECT_RESOURCE_DESTROY" => effect_type |= 1 << 10,
                "KAPI_EFFECT_LOCK_ACQUIRE" => effect_type |= 1 << 11,
                "KAPI_EFFECT_LOCK_RELEASE" => effect_type |= 1 << 12,
                "KAPI_EFFECT_NETWORK_IO" => effect_type |= 1 << 13,
                "KAPI_EFFECT_SYSTEM_STATE" => effect_type |= 1 << 14,
                _ => {} // Unknown effect type
            }
        }

        effect_type
    }

    fn parse_parameters(source_spec: &SourceApiSpec) -> Vec<ParamSpec> {
        let mut params = Vec::new();

        if let Some(indices_str) = source_spec.parsed_fields.get("param_indices") {
            for idx_str in indices_str.split(',') {
                if let Ok(idx) = idx_str.parse::<u32>() {
                    let name = source_spec.parsed_fields.get(&format!("param_{}_name", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let type_name = source_spec.parsed_fields.get(&format!("param_{}_type", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let description = source_spec.parsed_fields.get(&format!("param_{}_desc", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let flags_str = source_spec.parsed_fields.get(&format!("param_{}_flags", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let param_type_str = source_spec.parsed_fields.get(&format!("param_{}_param_type", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let constraint_type_str = source_spec.parsed_fields.get(&format!("param_{}_constraint_type", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let constraint = source_spec.parsed_fields.get(&format!("param_{}_constraint", idx))
                        .cloned();
                    let min_value = source_spec.parsed_fields.get(&format!("param_{}_min", idx))
                        .and_then(|s| s.parse::<i64>().ok());
                    let max_value = source_spec.parsed_fields.get(&format!("param_{}_max", idx))
                        .and_then(|s| s.parse::<i64>().ok());

                    params.push(ParamSpec {
                        index: idx,
                        name,
                        type_name,
                        description,
                        flags: Self::parse_param_flags(&flags_str),
                        param_type: Self::parse_param_type(&param_type_str),
                        constraint_type: Self::parse_constraint_type(&constraint_type_str),
                        constraint,
                        min_value,
                        max_value,
                        valid_mask: None,
                        enum_values: Vec::new(),
                        size: None,
                        alignment: None,
                    });
                }
            }
        }

        params
    }

    fn parse_return_spec(source_spec: &SourceApiSpec) -> Option<ReturnSpec> {
        if let (Some(type_name), Some(description)) = (
            source_spec.parsed_fields.get("return_type"),
            source_spec.parsed_fields.get("return_desc")
        ) {
            let return_type_str = source_spec.parsed_fields.get("return_return_type")
                .cloned()
                .unwrap_or_else(String::new);
            let check_type_str = source_spec.parsed_fields.get("return_check_type")
                .cloned()
                .unwrap_or_else(String::new);
            let success_value = source_spec.parsed_fields.get("return_success")
                .and_then(|s| s.parse::<i64>().ok());

            Some(ReturnSpec {
                type_name: type_name.clone(),
                description: description.clone(),
                return_type: Self::parse_return_type(&return_type_str),
                check_type: Self::parse_check_type(&check_type_str),
                success_value,
                success_min: None,
                success_max: None,
                error_values: Vec::new(),
            })
        } else {
            None
        }
    }

    fn parse_errors(source_spec: &SourceApiSpec) -> Vec<ErrorSpec> {
        let mut errors = Vec::new();

        if let Some(indices_str) = source_spec.parsed_fields.get("error_indices") {
            for idx_str in indices_str.split(',') {
                if let Ok(idx) = idx_str.parse::<usize>() {
                    let error_code_str = source_spec.parsed_fields.get(&format!("error_{}_code", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let name = source_spec.parsed_fields.get(&format!("error_{}_name", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let condition = source_spec.parsed_fields.get(&format!("error_{}_condition", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let description = source_spec.parsed_fields.get(&format!("error_{}_desc", idx))
                        .cloned()
                        .unwrap_or_else(String::new);

                    // Parse error code (handle -EINVAL format)
                    let error_code = if error_code_str.starts_with("-E") {
                        // Map common error codes
                        match error_code_str.as_str() {
                            "-EINVAL" => -22,
                            "-ENOMEM" => -12,
                            "-EBUSY" => -16,
                            "-ENODEV" => -19,
                            "-ENOENT" => -2,
                            "-EPERM" => -1,
                            "-EACCES" => -13,
                            "-EFAULT" => -14,
                            "-EAGAIN" => -11,
                            "-EEXIST" => -17,
                            _ => 0,
                        }
                    } else {
                        error_code_str.parse::<i32>().unwrap_or(0)
                    };

                    errors.push(ErrorSpec {
                        error_code,
                        name,
                        condition,
                        description,
                    });
                }
            }
        }

        errors
    }

    fn parse_locks(source_spec: &SourceApiSpec) -> Vec<LockSpec> {
        let mut locks = Vec::new();

        if let Some(indices_str) = source_spec.parsed_fields.get("lock_indices") {
            for idx_str in indices_str.split(',') {
                if let Ok(idx) = idx_str.parse::<usize>() {
                    let lock_name = source_spec.parsed_fields.get(&format!("lock_{}_name", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let lock_type_str = source_spec.parsed_fields.get(&format!("lock_{}_type", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let description = source_spec.parsed_fields.get(&format!("lock_{}_desc", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let held_on_entry = source_spec.parsed_fields.get(&format!("lock_{}_held_entry", idx))
                        .is_some_and(|s| s == "true");
                    let held_on_exit = source_spec.parsed_fields.get(&format!("lock_{}_held_exit", idx))
                        .is_some_and(|s| s == "true");
                    let acquired = source_spec.parsed_fields.get(&format!("lock_{}_acquired", idx))
                        .is_some_and(|s| s == "true");
                    let released = source_spec.parsed_fields.get(&format!("lock_{}_released", idx))
                        .is_some_and(|s| s == "true");

                    locks.push(LockSpec {
                        lock_name,
                        lock_type: Self::parse_lock_type(&lock_type_str),
                        acquired,
                        released,
                        held_on_entry,
                        held_on_exit,
                        description,
                    });
                }
            }
        }

        locks
    }

    fn parse_constraints(source_spec: &SourceApiSpec) -> Vec<ConstraintSpec> {
        let mut constraints = Vec::new();

        if let Some(indices_str) = source_spec.parsed_fields.get("constraint_indices") {
            for idx_str in indices_str.split(',') {
                if let Ok(idx) = idx_str.parse::<usize>() {
                    let name = source_spec.parsed_fields.get(&format!("constraint_{}_name", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let description = source_spec.parsed_fields.get(&format!("constraint_{}_desc", idx))
                        .cloned()
                        .unwrap_or_else(String::new);
                    let expression = source_spec.parsed_fields.get(&format!("constraint_{}_expr", idx))
                        .cloned();

                    constraints.push(ConstraintSpec {
                        name,
                        description,
                        expression,
                    });
                }
            }
        }

        constraints
    }

    fn parse_param_flags(flags_str: &str) -> u32 {
        let mut flags = 0u32;
        let parts: Vec<&str> = flags_str.split('|').map(str::trim).collect();

        for part in parts {
            match part {
                "KAPI_PARAM_IN" => flags |= 1 << 0,
                "KAPI_PARAM_OUT" => flags |= 1 << 1,
                "KAPI_PARAM_INOUT" => flags |= (1 << 0) | (1 << 1),
                "KAPI_PARAM_USER" => flags |= 1 << 2,
                "KAPI_PARAM_OPTIONAL" => flags |= 1 << 3,
                _ => {}
            }
        }

        flags
    }

    fn parse_param_type(type_str: &str) -> u32 {
        match type_str.trim() {
            "KAPI_TYPE_INT" => 1,
            "KAPI_TYPE_UINT" => 2,
            "KAPI_TYPE_PTR" => 3,
            "KAPI_TYPE_STRUCT" => 4,
            "KAPI_TYPE_ENUM" => 5,
            "KAPI_TYPE_FLAGS" => 6,
            "KAPI_TYPE_FD" => 7,
            "KAPI_TYPE_STRING" => 8,
            _ => 0,
        }
    }

    fn parse_constraint_type(type_str: &str) -> u32 {
        match type_str.trim() {
            "KAPI_CONSTRAINT_RANGE" => 1,
            "KAPI_CONSTRAINT_MASK" => 2,
            "KAPI_CONSTRAINT_ENUM" => 3,
            "KAPI_CONSTRAINT_SIZE" => 4,
            "KAPI_CONSTRAINT_ALIGNMENT" => 5,
            _ => 0, // Default to NONE (includes "KAPI_CONSTRAINT_NONE")
        }
    }

    fn parse_return_type(type_str: &str) -> u32 {
        match type_str.trim() {
            "KAPI_TYPE_INT" => 1,
            "KAPI_TYPE_UINT" => 2,
            "KAPI_TYPE_PTR" => 3,
            "KAPI_TYPE_FD" => 7,
            _ => 0,
        }
    }

    fn parse_check_type(type_str: &str) -> u32 {
        match type_str.trim() {
            "KAPI_RETURN_SUCCESS_CHECK" => 1,
            "KAPI_RETURN_ERROR_CHECK" => 2,
            "KAPI_RETURN_RANGE_CHECK" => 3,
            "KAPI_RETURN_PTR_CHECK" => 4,
            _ => 0,
        }
    }

    fn parse_lock_type(type_str: &str) -> u32 {
        match type_str.trim() {
            "KAPI_LOCK_MUTEX" => 1,
            "KAPI_LOCK_SPINLOCK" => 2,
            "KAPI_LOCK_RWLOCK" => 3,
            "KAPI_LOCK_SEMAPHORE" => 4,
            "KAPI_LOCK_RCU" => 5,
            _ => 0,
        }
    }

    fn parse_context_flags(flags_str: &str) -> Vec<String> {
        let mut result = Vec::new();
        let parts: Vec<&str> = flags_str.split('|').map(str::trim).collect();

        for part in parts {
            match part {
                "KAPI_CTX_PROCESS" => result.push("Process context".to_string()),
                "KAPI_CTX_SOFTIRQ" => result.push("Softirq context".to_string()),
                "KAPI_CTX_HARDIRQ" => result.push("Hardirq context".to_string()),
                "KAPI_CTX_NMI" => result.push("NMI context".to_string()),
                "KAPI_CTX_USER" => result.push("User mode".to_string()),
                "KAPI_CTX_KERNEL" => result.push("Kernel mode".to_string()),
                "KAPI_CTX_SLEEPABLE" => result.push("May sleep".to_string()),
                "KAPI_CTX_ATOMIC" => result.push("Atomic context".to_string()),
                "KAPI_CTX_PREEMPTIBLE" => result.push("Preemptible".to_string()),
                "KAPI_CTX_MIGRATION_DISABLED" => result.push("Migration disabled".to_string()),
                _ => {} // Ignore unknown flags
            }
        }

        result
    }

    fn convert_to_api_spec(&self, source_spec: &SourceApiSpec) -> ApiSpec {
        let mut capabilities = Vec::new();

        // Extract capabilities
        if let Some(cap_count_str) = source_spec.parsed_fields.get("capability_count") {
            if let Ok(cap_count) = cap_count_str.parse::<usize>() {
                for i in 0..cap_count {
                    let cap_key = format!("capability_{}", i);

                    if let (Some(id_str), Some(name), Some(action)) = (
                        source_spec.parsed_fields.get(&format!("{}_id", cap_key)),
                        source_spec.parsed_fields.get(&format!("{}_name", cap_key)),
                        source_spec.parsed_fields.get(&format!("{}_action", cap_key))
                    ) {
                        let cap_id = id_str.parse::<i32>().unwrap_or(0);
                        capabilities.push(CapabilitySpec {
                            capability: cap_id,
                            name: name.clone(),
                            action: Self::convert_capability_action(action),
                            allows: source_spec.parsed_fields.get(&format!("{}_allows", cap_key))
                                .cloned()
                                .unwrap_or_else(String::new),
                            without_cap: source_spec.parsed_fields.get(&format!("{}_without", cap_key))
                                .cloned()
                                .unwrap_or_else(String::new),
                            check_condition: source_spec.parsed_fields.get(&format!("{}_condition", cap_key))
                                .cloned(),
                            priority: source_spec.parsed_fields.get(&format!("{}_priority", cap_key))
                                .and_then(|s| s.parse::<u8>().ok()),
                            alternatives: Vec::new(), // Not parsed from source yet
                        });
                    }
                }
            }
        }

        // Parse socket state
        let socket_state = if source_spec.parsed_fields.contains_key("socket_state_req") ||
                              source_spec.parsed_fields.contains_key("socket_state_result") {
            Some(SocketStateSpec {
                required_states: source_spec.parsed_fields.get("socket_state_req")
                    .map(|s| vec![s.clone()])
                    .unwrap_or_default(),
                forbidden_states: Vec::new(), // Not parsed yet
                resulting_state: source_spec.parsed_fields.get("socket_state_result").cloned(),
                condition: source_spec.parsed_fields.get("socket_state_cond").cloned(),
                applicable_protocols: source_spec.parsed_fields.get("socket_state_protos").cloned(),
            })
        } else {
            None
        };

        // Parse protocol behaviors
        let mut protocol_behaviors = Vec::new();
        if let Some(indices_str) = source_spec.parsed_fields.get("protocol_behavior_indices") {
            for idx_str in indices_str.split(',') {
                if let Ok(idx) = idx_str.parse::<usize>() {
                    if let (Some(protos), Some(desc)) = (
                        source_spec.parsed_fields.get(&format!("protocol_behavior_{}_protos", idx)),
                        source_spec.parsed_fields.get(&format!("protocol_behavior_{}_desc", idx))
                    ) {
                        protocol_behaviors.push(ProtocolBehaviorSpec {
                            applicable_protocols: protos.clone(),
                            behavior: desc.clone(),
                            protocol_flags: source_spec.parsed_fields.get(&format!("protocol_behavior_{}_flags", idx)).cloned(),
                            flag_description: None, // Could be enhanced to parse flag descriptions
                        });
                    }
                }
            }
        }

        // Parse address families
        let mut addr_families = Vec::new();
        if let Some(indices_str) = source_spec.parsed_fields.get("addr_family_indices") {
            for idx_str in indices_str.split(',') {
                if let Ok(idx) = idx_str.parse::<usize>() {
                    if let (Some(family_str), Some(name), Some(struct_size_str), Some(min_len_str), Some(max_len_str)) = (
                        source_spec.parsed_fields.get(&format!("addr_family_{}_id", idx)),
                        source_spec.parsed_fields.get(&format!("addr_family_{}_name", idx)),
                        source_spec.parsed_fields.get(&format!("addr_family_{}_struct_size", idx)),
                        source_spec.parsed_fields.get(&format!("addr_family_{}_min_len", idx)),
                        source_spec.parsed_fields.get(&format!("addr_family_{}_max_len", idx))
                    ) {
                        // Parse AF_INET etc as integers
                        let family = if family_str.starts_with("AF_") {
                            // This is a constant name, we'd need to map it to the actual value
                            // For now, use a placeholder
                            match family_str.as_str() {
                                "AF_UNIX" => 1,
                                "AF_INET" => 2,
                                "AF_INET6" => 10,
                                "AF_NETLINK" => 16,
                                "AF_PACKET" => 17,
                                "AF_BLUETOOTH" => 31,
                                _ => 0,
                            }
                        } else {
                            family_str.parse::<i32>().unwrap_or(0)
                        };

                        // For sizeof() expressions, we'll store the string as-is
                        let struct_size = if struct_size_str.starts_with("sizeof(") {
                            // Map common struct sizes - this is a limitation of static parsing
                            match struct_size_str.as_str() {
                                "sizeof(struct sockaddr_un)" => 110,
                                "sizeof(struct sockaddr_in)" => 16,
                                "sizeof(struct sockaddr_in6)" => 28,
                                "sizeof(struct sockaddr_nl)" => 12,
                                "sizeof(struct sockaddr_ll)" => 20,
                                "sizeof(struct sockaddr)" => 16, // generic sockaddr
                                _ => 0,
                            }
                        } else {
                            struct_size_str.parse::<usize>().unwrap_or(0)
                        };

                        addr_families.push(AddrFamilySpec {
                            family,
                            family_name: name.clone(),
                            addr_struct_size: struct_size,
                            min_addr_len: min_len_str.parse::<usize>().unwrap_or(0),
                            max_addr_len: max_len_str.parse::<usize>().unwrap_or(0),
                            addr_format: source_spec.parsed_fields.get(&format!("addr_family_{}_format", idx)).cloned(),
                            supports_wildcard: source_spec.parsed_fields.get(&format!("addr_family_{}_wildcard", idx))
                                .is_some_and(|s| s == "true"),
                            supports_multicast: source_spec.parsed_fields.get(&format!("addr_family_{}_multicast", idx))
                                .is_some_and(|s| s == "true"),
                            supports_broadcast: source_spec.parsed_fields.get(&format!("addr_family_{}_broadcast", idx))
                                .is_some_and(|s| s == "true"),
                            special_addresses: source_spec.parsed_fields.get(&format!("addr_family_{}_special", idx)).cloned(),
                            port_range_min: source_spec.parsed_fields.get(&format!("addr_family_{}_port_min", idx))
                                .and_then(|s| s.parse::<u32>().ok()).unwrap_or(0),
                            port_range_max: source_spec.parsed_fields.get(&format!("addr_family_{}_port_max", idx))
                                .and_then(|s| s.parse::<u32>().ok()).unwrap_or(0),
                        });
                    }
                }
            }
        }

        // Parse buffer spec
        let buffer_spec = if source_spec.parsed_fields.contains_key("buffer_spec_behaviors") {
            Some(BufferSpec {
                buffer_behaviors: source_spec.parsed_fields.get("buffer_spec_behaviors").cloned(),
                min_buffer_size: None,
                max_buffer_size: None,
                optimal_buffer_size: None,
            })
        } else {
            None
        };

        // Parse async spec
        let async_spec = if source_spec.parsed_fields.contains_key("async_spec_modes") {
            Some(AsyncSpec {
                supported_modes: source_spec.parsed_fields.get("async_spec_modes").cloned(),
                nonblock_errno: source_spec.parsed_fields.get("async_spec_errno")
                    .and_then(|s| s.parse::<i32>().ok()),
            })
        } else {
            None
        };

        ApiSpec {
            name: source_spec.name.clone(),
            api_type: match source_spec.api_type {
                ApiType::Syscall => "syscall".to_string(),
                ApiType::Ioctl => "ioctl".to_string(),
                ApiType::Function => "function".to_string(),
                ApiType::Sysfs => "sysfs".to_string(),
                ApiType::Unknown => "unknown".to_string(),
            },
            description: source_spec.parsed_fields.get("description").cloned(),
            long_description: source_spec.parsed_fields.get("long_description").cloned(),
            version: source_spec.parsed_fields.get("version").cloned(),
            context_flags: source_spec.parsed_fields.get("context")
                .map(|c| Self::parse_context_flags(c))
                .unwrap_or_default(),
            param_count: source_spec.parsed_fields.get("param_count")
                .and_then(|s| s.parse::<u32>().ok()),
            error_count: source_spec.parsed_fields.get("error_count")
                .and_then(|s| s.parse::<u32>().ok()),
            examples: source_spec.parsed_fields.get("examples").cloned(),
            notes: source_spec.parsed_fields.get("notes").cloned(),
            since_version: source_spec.parsed_fields.get("since_version").cloned(),
            // Sysfs-specific fields
            subsystem: source_spec.parsed_fields.get("subsystem").cloned(),
            sysfs_path: source_spec.parsed_fields.get("sysfs_path").cloned(),
            permissions: source_spec.parsed_fields.get("permissions").cloned(),
            // Networking-specific fields
            socket_state,
            protocol_behaviors,
            addr_families,
            buffer_spec,
            async_spec,
            net_data_transfer: source_spec.parsed_fields.get("net_data_transfer").cloned(),
            capabilities,
            parameters: Self::parse_parameters(source_spec),
            return_spec: Self::parse_return_spec(source_spec),
            errors: Self::parse_errors(source_spec),
            signals: vec![],
            signal_masks: vec![],
            side_effects: Self::parse_side_effects(source_spec),
            state_transitions: Self::parse_state_transitions(source_spec),
            constraints: Self::parse_constraints(source_spec),
            locks: Self::parse_locks(source_spec),
        }
    }
}

impl ApiExtractor for SourceExtractor {
    fn extract_all(&self) -> Result<Vec<ApiSpec>> {
        Ok(self.specs.iter()
            .map(|s| self.convert_to_api_spec(s))
            .collect())
    }

    fn extract_by_name(&self, name: &str) -> Result<Option<ApiSpec>> {
        Ok(self.specs.iter()
            .find(|s| s.name == name)
            .map(|s| self.convert_to_api_spec(s)))
    }

    fn display_api_details(
        &self,
        api_name: &str,
        formatter: &mut dyn OutputFormatter,
        writer: &mut dyn Write,
    ) -> Result<()> {
        if let Some(spec) = self.specs.iter().find(|s| s.name == api_name) {
            let api_spec = self.convert_to_api_spec(spec);
            display_api_spec(&api_spec, formatter, writer)?;
        }
        Ok(())
    }
}