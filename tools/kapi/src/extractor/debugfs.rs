use anyhow::{Context, Result, bail};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use crate::formatter::OutputFormatter;

use super::{ApiExtractor, ApiSpec, display_api_spec};

/// Extractor for kernel API specifications from debugfs
pub struct DebugfsExtractor {
    debugfs_path: PathBuf,
}

impl DebugfsExtractor {
    /// Create a new debugfs extractor with the specified debugfs path
    pub fn new(debugfs_path: Option<String>) -> Result<Self> {
        let path = match debugfs_path {
            Some(p) => PathBuf::from(p),
            None => PathBuf::from("/sys/kernel/debug"),
        };

        // Check if the debugfs path exists
        if !path.exists() {
            bail!("Debugfs path does not exist: {}", path.display());
        }

        // Check if kapi directory exists
        let kapi_path = path.join("kapi");
        if !kapi_path.exists() {
            bail!("Kernel API debugfs interface not found at: {}", kapi_path.display());
        }

        Ok(Self {
            debugfs_path: path,
        })
    }

    /// Parse the list file to get all available API names
    fn parse_list_file(&self) -> Result<Vec<String>> {
        let list_path = self.debugfs_path.join("kapi/list");
        let content = fs::read_to_string(&list_path)
            .with_context(|| format!("Failed to read {}", list_path.display()))?;

        let mut apis = Vec::new();
        let mut in_list = false;

        for line in content.lines() {
            if line.contains("===") {
                in_list = true;
                continue;
            }

            if in_list && line.starts_with("Total:") {
                break;
            }

            if in_list && !line.trim().is_empty() {
                // Extract API name from lines like "sys_read - Read from a file descriptor"
                if let Some(name) = line.split(" - ").next() {
                    apis.push(name.trim().to_string());
                }
            }
        }

        Ok(apis)
    }

    /// Parse a single API specification file
    fn parse_spec_file(&self, api_name: &str) -> Result<ApiSpec> {
        let spec_path = self.debugfs_path.join(format!("kapi/specs/{}", api_name));
        let content = fs::read_to_string(&spec_path)
            .with_context(|| format!("Failed to read {}", spec_path.display()))?;

        let mut spec = ApiSpec {
            name: api_name.to_string(),
            api_type: "unknown".to_string(),
            description: None,
            long_description: None,
            version: None,
            context_flags: Vec::new(),
            param_count: None,
            error_count: None,
            examples: None,
            notes: None,
            since_version: None,
        };

        // Parse the content
        let mut collecting_multiline = false;
        let mut multiline_buffer = String::new();
        let mut multiline_field = "";

        for line in content.lines() {
            // Handle section headers
            if line.starts_with("Parameters (") {
                if let Some(count_str) = line.strip_prefix("Parameters (").and_then(|s| s.strip_suffix("):")) {
                    spec.param_count = count_str.parse().ok();
                }
                continue;
            } else if line.starts_with("Errors (") {
                if let Some(count_str) = line.strip_prefix("Errors (").and_then(|s| s.strip_suffix("):")) {
                    spec.error_count = count_str.parse().ok();
                }
                continue;
            } else if line.starts_with("Examples:") {
                collecting_multiline = true;
                multiline_field = "examples";
                multiline_buffer.clear();
                continue;
            } else if line.starts_with("Notes:") {
                collecting_multiline = true;
                multiline_field = "notes";
                multiline_buffer.clear();
                continue;
            }

            // Handle multiline sections
            if collecting_multiline {
                if line.trim().is_empty() && multiline_buffer.ends_with("\n\n") {
                    collecting_multiline = false;
                    match multiline_field {
                        "examples" => spec.examples = Some(multiline_buffer.trim().to_string()),
                        "notes" => spec.notes = Some(multiline_buffer.trim().to_string()),
                        _ => {}
                    }
                    multiline_buffer.clear();
                } else {
                    if !multiline_buffer.is_empty() {
                        multiline_buffer.push('\n');
                    }
                    multiline_buffer.push_str(line);
                }
                continue;
            }

            // Parse regular fields
            if let Some(desc) = line.strip_prefix("Description: ") {
                spec.description = Some(desc.to_string());
            } else if let Some(long_desc) = line.strip_prefix("Long description: ") {
                spec.long_description = Some(long_desc.to_string());
            } else if let Some(version) = line.strip_prefix("Version: ") {
                spec.version = Some(version.to_string());
            } else if let Some(since) = line.strip_prefix("Since: ") {
                spec.since_version = Some(since.to_string());
            } else if let Some(flags) = line.strip_prefix("Context flags: ") {
                spec.context_flags = flags.split_whitespace()
                    .map(|s| s.to_string())
                    .collect();
            }
        }

        // Determine API type based on name
        if api_name.starts_with("sys_") {
            spec.api_type = "syscall".to_string();
        } else if api_name.contains("_ioctl") || api_name.starts_with("ioctl_") {
            spec.api_type = "ioctl".to_string();
        } else {
            spec.api_type = "function".to_string();
        }

        Ok(spec)
    }
}

impl ApiExtractor for DebugfsExtractor {
    fn extract_all(&self) -> Result<Vec<ApiSpec>> {
        let api_names = self.parse_list_file()?;
        let mut specs = Vec::new();

        for name in api_names {
            match self.parse_spec_file(&name) {
                Ok(spec) => specs.push(spec),
                Err(e) => eprintln!("Warning: Failed to parse spec for {}: {}", name, e),
            }
        }

        Ok(specs)
    }

    fn extract_by_name(&self, name: &str) -> Result<Option<ApiSpec>> {
        let api_names = self.parse_list_file()?;

        if api_names.contains(&name.to_string()) {
            Ok(Some(self.parse_spec_file(name)?))
        } else {
            Ok(None)
        }
    }

    fn display_api_details(
        &self,
        api_name: &str,
        formatter: &mut dyn OutputFormatter,
        writer: &mut dyn Write,
    ) -> Result<()> {
        if let Some(spec) = self.extract_by_name(api_name)? {
            display_api_spec(&spec, formatter, writer)?;
        } else {
            writeln!(writer, "API '{}' not found in debugfs", api_name)?;
        }

        Ok(())
    }
}