use super::OutputFormatter;
use std::io::Write;
use serde::Serialize;

pub struct JsonFormatter {
    data: JsonData,
}

#[derive(Serialize)]
struct JsonData {
    #[serde(skip_serializing_if = "Option::is_none")]
    apis: Option<Vec<JsonApi>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_details: Option<JsonApiDetails>,
}

#[derive(Serialize)]
struct JsonApi {
    name: String,
    api_type: String,
}

#[derive(Serialize)]
struct JsonApiDetails {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    long_description: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    context_flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    examples: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    since_version: Option<String>,
}


impl JsonFormatter {
    pub fn new() -> Self {
        JsonFormatter {
            data: JsonData {
                apis: None,
                api_details: None,
            }
        }
    }
}

impl OutputFormatter for JsonFormatter {
    fn begin_document(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn end_document(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(&self.data)?;
        writeln!(w, "{}", json)?;
        Ok(())
    }

    fn begin_api_list(&mut self, _w: &mut dyn Write, _title: &str) -> std::io::Result<()> {
        self.data.apis = Some(Vec::new());
        Ok(())
    }

    fn api_item(&mut self, _w: &mut dyn Write, name: &str, api_type: &str) -> std::io::Result<()> {
        if let Some(apis) = &mut self.data.apis {
            apis.push(JsonApi {
                name: name.to_string(),
                api_type: api_type.to_string(),
            });
        }
        Ok(())
    }

    fn end_api_list(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn total_specs(&mut self, _w: &mut dyn Write, _count: usize) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_api_details(&mut self, _w: &mut dyn Write, name: &str) -> std::io::Result<()> {
        self.data.api_details = Some(JsonApiDetails {
            name: name.to_string(),
            description: None,
            long_description: None,
            context_flags: Vec::new(),
            examples: None,
            notes: None,
            since_version: None,
        });
        Ok(())
    }

    fn end_api_details(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }


    fn description(&mut self, _w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.description = Some(desc.to_string());
        }
        Ok(())
    }

    fn long_description(&mut self, _w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.long_description = Some(desc.to_string());
        }
        Ok(())
    }

    fn begin_context_flags(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn context_flag(&mut self, _w: &mut dyn Write, flag: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.context_flags.push(flag.to_string());
        }
        Ok(())
    }

    fn end_context_flags(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_parameters(&mut self, _w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        Ok(())
    }


    fn end_parameters(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_errors(&mut self, _w: &mut dyn Write, _count: u32) -> std::io::Result<()> {
        Ok(())
    }

    fn end_errors(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn examples(&mut self, _w: &mut dyn Write, examples: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.examples = Some(examples.to_string());
        }
        Ok(())
    }

    fn notes(&mut self, _w: &mut dyn Write, notes: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.notes = Some(notes.to_string());
        }
        Ok(())
    }

    fn since_version(&mut self, _w: &mut dyn Write, version: &str) -> std::io::Result<()> {
        if let Some(details) = &mut self.data.api_details {
            details.since_version = Some(version.to_string());
        }
        Ok(())
    }
}