use super::OutputFormatter;
use std::io::Write;

pub struct RstFormatter {
    current_section_level: usize,
}

impl RstFormatter {
    pub fn new() -> Self {
        RstFormatter {
            current_section_level: 0,
        }
    }

    fn section_char(&self, level: usize) -> char {
        match level {
            0 => '=',
            1 => '-',
            2 => '~',
            3 => '^',
            _ => '"',
        }
    }
}

impl OutputFormatter for RstFormatter {
    fn begin_document(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn end_document(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_api_list(&mut self, w: &mut dyn Write, title: &str) -> std::io::Result<()> {
        writeln!(w, "\n{}", title)?;
        writeln!(w, "{}", self.section_char(0).to_string().repeat(title.len()))?;
        writeln!(w)
    }

    fn api_item(&mut self, w: &mut dyn Write, name: &str, api_type: &str) -> std::io::Result<()> {
        writeln!(w, "* **{}** (*{}*)", name, api_type)
    }

    fn end_api_list(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn total_specs(&mut self, w: &mut dyn Write, count: usize) -> std::io::Result<()> {
        writeln!(w, "\n**Total specifications found:** {}", count)
    }

    fn begin_api_details(&mut self, w: &mut dyn Write, name: &str) -> std::io::Result<()> {
        self.current_section_level = 0;
        writeln!(w, "\n{}", name)?;
        writeln!(w, "{}", self.section_char(0).to_string().repeat(name.len()))?;
        writeln!(w)
    }

    fn end_api_details(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }


    fn description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        writeln!(w, "**{}**", desc)?;
        writeln!(w)
    }

    fn long_description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        writeln!(w, "{}", desc)?;
        writeln!(w)
    }

    fn begin_context_flags(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        self.current_section_level = 1;
        let title = "Execution Context";
        writeln!(w, "{}", title)?;
        writeln!(w, "{}", self.section_char(1).to_string().repeat(title.len()))?;
        writeln!(w)
    }

    fn context_flag(&mut self, w: &mut dyn Write, flag: &str) -> std::io::Result<()> {
        writeln!(w, "* {}", flag)
    }

    fn end_context_flags(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w)
    }

    fn begin_parameters(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        self.current_section_level = 1;
        let title = format!("Parameters ({})", count);
        writeln!(w, "{}", title)?;
        writeln!(w, "{}", self.section_char(1).to_string().repeat(title.len()))?;
        writeln!(w)
    }


    fn end_parameters(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_errors(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        self.current_section_level = 1;
        let title = format!("Possible Errors ({})", count);
        writeln!(w, "{}", title)?;
        writeln!(w, "{}", self.section_char(1).to_string().repeat(title.len()))?;
        writeln!(w)
    }

    fn end_errors(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn examples(&mut self, w: &mut dyn Write, examples: &str) -> std::io::Result<()> {
        self.current_section_level = 1;
        let title = "Examples";
        writeln!(w, "{}", title)?;
        writeln!(w, "{}", self.section_char(1).to_string().repeat(title.len()))?;
        writeln!(w)?;
        writeln!(w, ".. code-block:: c")?;
        writeln!(w)?;
        for line in examples.lines() {
            writeln!(w, "   {}", line)?;
        }
        writeln!(w)
    }

    fn notes(&mut self, w: &mut dyn Write, notes: &str) -> std::io::Result<()> {
        self.current_section_level = 1;
        let title = "Notes";
        writeln!(w, "{}", title)?;
        writeln!(w, "{}", self.section_char(1).to_string().repeat(title.len()))?;
        writeln!(w)?;
        writeln!(w, "{}", notes)?;
        writeln!(w)
    }

    fn since_version(&mut self, w: &mut dyn Write, version: &str) -> std::io::Result<()> {
        writeln!(w, ":Available since: {}", version)?;
        writeln!(w)
    }
}