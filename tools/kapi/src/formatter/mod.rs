use std::io::Write;

mod plain;
mod json;
mod rst;

pub use plain::PlainFormatter;
pub use json::JsonFormatter;
pub use rst::RstFormatter;


#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OutputFormat {
    Plain,
    Json,
    Rst,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "plain" => Ok(OutputFormat::Plain),
            "json" => Ok(OutputFormat::Json),
            "rst" => Ok(OutputFormat::Rst),
            _ => Err(format!("Unknown output format: {}", s)),
        }
    }
}

pub trait OutputFormatter {
    fn begin_document(&mut self, w: &mut dyn Write) -> std::io::Result<()>;
    fn end_document(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn begin_api_list(&mut self, w: &mut dyn Write, title: &str) -> std::io::Result<()>;
    fn api_item(&mut self, w: &mut dyn Write, name: &str, api_type: &str) -> std::io::Result<()>;
    fn end_api_list(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn total_specs(&mut self, w: &mut dyn Write, count: usize) -> std::io::Result<()>;

    fn begin_api_details(&mut self, w: &mut dyn Write, name: &str) -> std::io::Result<()>;
    fn end_api_details(&mut self, w: &mut dyn Write) -> std::io::Result<()>;
    fn description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()>;
    fn long_description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()>;

    fn begin_context_flags(&mut self, w: &mut dyn Write) -> std::io::Result<()>;
    fn context_flag(&mut self, w: &mut dyn Write, flag: &str) -> std::io::Result<()>;
    fn end_context_flags(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn begin_parameters(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()>;
    fn end_parameters(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn begin_errors(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()>;
    fn end_errors(&mut self, w: &mut dyn Write) -> std::io::Result<()>;

    fn examples(&mut self, w: &mut dyn Write, examples: &str) -> std::io::Result<()>;
    fn notes(&mut self, w: &mut dyn Write, notes: &str) -> std::io::Result<()>;
    fn since_version(&mut self, w: &mut dyn Write, version: &str) -> std::io::Result<()>;
}

pub fn create_formatter(format: OutputFormat) -> Box<dyn OutputFormatter> {
    match format {
        OutputFormat::Plain => Box::new(PlainFormatter::new()),
        OutputFormat::Json => Box::new(JsonFormatter::new()),
        OutputFormat::Rst => Box::new(RstFormatter::new()),
    }
}