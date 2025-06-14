use anyhow::{Context, Result};
use regex::Regex;
use std::fs;
use std::path::Path;
use std::collections::HashMap;
use walkdir::WalkDir;
use std::io::Write;
use crate::formatter::OutputFormatter;
use super::{ApiExtractor, ApiSpec, display_api_spec};

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
        }

        Ok(specs)
    }

    /// Extract a complete KAPI specification block from the source
    fn extract_spec_block(&self, lines: &[&str], start_idx: usize) -> Option<String> {
        let mut spec_lines = Vec::new();
        let mut brace_count = 0;
        let mut in_spec = false;

        for (_i, line) in lines.iter().enumerate().skip(start_idx) {
            spec_lines.push(line.to_string());

            // Count braces to handle nested structures
            for ch in line.chars() {
                match ch {
                    '{' => {
                        brace_count += 1;
                        in_spec = true;
                    }
                    '}' => {
                        brace_count -= 1;
                    }
                    _ => {}
                }
            }

            // Check for end of spec
            if self.spec_end_pattern.is_match(line) {
                return Some(spec_lines.join("\n"));
            }

            // Alternative end: closing brace with semicolon
            if in_spec && brace_count == 0 && line.contains("};") {
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
            spec_lines.push(line.to_string());

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
                .replace("\"\n\t\t       \"", " ")
                .replace("\"\n\t\t    \"", " ")
                .replace("\"\n\t\t   \"", " ")
                .replace("\"\n\t\t  \"", " ")
                .replace("\"\n\t\t \"", " ")
                .replace("\"\n\t\t\"", " ")
                .trim()
                .to_string();
            fields.insert("notes".to_string(), notes);
        }

        // Parse KAPI_EXAMPLES (handle multi-line)
        if let Some(captures) = Regex::new(r#"KAPI_EXAMPLES\s*\(\s*"([^"]*(?:\s*"[^"]*)*?)"\s*\)"#)?.captures(content) {
            let examples = captures.get(1).unwrap().as_str()
                .replace("\\n\"\n\t\t    \"", "\n")
                .replace("\\n\"\n\t\t   \"", "\n")
                .replace("\\n\"\n\t\t  \"", "\n")
                .replace("\\n\"\n\t\t \"", "\n")
                .replace("\\n\"\n\t\t\"", "\n")
                .replace("\\n", "\n")
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

        Ok(())
    }

    /// Scan a directory tree for files containing KAPI specifications
    pub fn scan_directory(&self, dir: &Path, extensions: &[&str]) -> Result<Vec<SourceApiSpec>> {
        let mut all_specs = Vec::new();

        for entry in WalkDir::new(dir)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
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
                        Err(e) => {
                            eprintln!("Warning: Failed to parse {}: {}", path.display(), e);
                        }
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
}

// SourceExtractor implementation
pub struct SourceExtractor {
    specs: Vec<SourceApiSpec>,
}

impl SourceExtractor {
    pub fn new(path: String) -> Result<Self> {
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

    fn convert_to_api_spec(&self, source_spec: &SourceApiSpec) -> ApiSpec {
        ApiSpec {
            name: source_spec.name.clone(),
            api_type: match source_spec.api_type {
                ApiType::Syscall => "syscall".to_string(),
                ApiType::Ioctl => "ioctl".to_string(),
                ApiType::Function => "function".to_string(),
                ApiType::Unknown => "unknown".to_string(),
            },
            description: source_spec.parsed_fields.get("description").cloned(),
            long_description: source_spec.parsed_fields.get("long_description").cloned(),
            version: source_spec.parsed_fields.get("version").cloned(),
            context_flags: source_spec.parsed_fields.get("context")
                .map(|c| vec![c.clone()])
                .unwrap_or_default(),
            param_count: source_spec.parsed_fields.get("param_count")
                .and_then(|s| s.parse::<u32>().ok()),
            error_count: source_spec.parsed_fields.get("error_count")
                .and_then(|s| s.parse::<u32>().ok()),
            examples: source_spec.parsed_fields.get("examples").cloned(),
            notes: source_spec.parsed_fields.get("notes").cloned(),
            since_version: source_spec.parsed_fields.get("since_version").cloned(),
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