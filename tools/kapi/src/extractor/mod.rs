use anyhow::Result;
use std::io::Write;
use crate::formatter::OutputFormatter;

pub mod vmlinux;
pub mod source_parser;
pub mod debugfs;

pub use vmlinux::VmlinuxExtractor;
pub use source_parser::SourceExtractor;
pub use debugfs::DebugfsExtractor;

/// Common API specification information that all extractors should provide
#[derive(Debug, Clone)]
pub struct ApiSpec {
    pub name: String,
    pub api_type: String,
    pub description: Option<String>,
    pub long_description: Option<String>,
    pub version: Option<String>,
    pub context_flags: Vec<String>,
    pub param_count: Option<u32>,
    pub error_count: Option<u32>,
    pub examples: Option<String>,
    pub notes: Option<String>,
    pub since_version: Option<String>,
}

/// Trait for extracting API specifications from different sources
pub trait ApiExtractor {
    /// Extract all API specifications from the source
    fn extract_all(&self) -> Result<Vec<ApiSpec>>;

    /// Extract a specific API specification by name
    fn extract_by_name(&self, name: &str) -> Result<Option<ApiSpec>>;

    /// Display detailed information about a specific API
    fn display_api_details(
        &self,
        api_name: &str,
        formatter: &mut dyn OutputFormatter,
        writer: &mut dyn Write,
    ) -> Result<()>;
}

/// Helper function to display an ApiSpec using a formatter
pub fn display_api_spec(
    spec: &ApiSpec,
    formatter: &mut dyn OutputFormatter,
    writer: &mut dyn Write,
) -> Result<()> {
    formatter.begin_api_details(writer, &spec.name)?;

    if let Some(desc) = &spec.description {
        formatter.description(writer, desc)?;
    }

    if let Some(long_desc) = &spec.long_description {
        formatter.long_description(writer, long_desc)?;
    }

    if let Some(version) = &spec.since_version {
        formatter.since_version(writer, version)?;
    }

    if !spec.context_flags.is_empty() {
        formatter.begin_context_flags(writer)?;
        for flag in &spec.context_flags {
            formatter.context_flag(writer, flag)?;
        }
        formatter.end_context_flags(writer)?;
    }

    if let Some(param_count) = spec.param_count {
        formatter.begin_parameters(writer, param_count)?;
        formatter.end_parameters(writer)?;
    }

    if let Some(error_count) = spec.error_count {
        formatter.begin_errors(writer, error_count)?;
        formatter.end_errors(writer)?;
    }

    if let Some(notes) = &spec.notes {
        formatter.notes(writer, notes)?;
    }

    if let Some(examples) = &spec.examples {
        formatter.examples(writer, examples)?;
    }

    formatter.end_api_details(writer)?;

    Ok(())
}