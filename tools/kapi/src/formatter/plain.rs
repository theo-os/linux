use super::OutputFormatter;
use std::io::Write;

pub struct PlainFormatter;

impl PlainFormatter {
    pub fn new() -> Self {
        PlainFormatter
    }
}

impl OutputFormatter for PlainFormatter {
    fn begin_document(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn end_document(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_api_list(&mut self, w: &mut dyn Write, title: &str) -> std::io::Result<()> {
        writeln!(w, "\n{}:", title)?;
        writeln!(w, "{}", "-".repeat(title.len() + 1))
    }

    fn api_item(&mut self, w: &mut dyn Write, name: &str, _api_type: &str) -> std::io::Result<()> {
        writeln!(w, "  {}", name)
    }

    fn end_api_list(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn total_specs(&mut self, w: &mut dyn Write, count: usize) -> std::io::Result<()> {
        writeln!(w, "\nTotal specifications found: {}", count)
    }

    fn begin_api_details(&mut self, w: &mut dyn Write, name: &str) -> std::io::Result<()> {
        writeln!(w, "\nDetailed information for {}:", name)?;
        writeln!(w, "{}=", "=".repeat(25 + name.len()))
    }

    fn end_api_details(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }


    fn description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        writeln!(w, "Description: {}", desc)
    }

    fn long_description(&mut self, w: &mut dyn Write, desc: &str) -> std::io::Result<()> {
        writeln!(w, "\nDetailed Description:")?;
        writeln!(w, "{}", desc)
    }

    fn begin_context_flags(&mut self, w: &mut dyn Write) -> std::io::Result<()> {
        writeln!(w, "\nExecution Context:")
    }

    fn context_flag(&mut self, w: &mut dyn Write, flag: &str) -> std::io::Result<()> {
        writeln!(w, "  - {}", flag)
    }

    fn end_context_flags(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_parameters(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        writeln!(w, "\nParameters ({}):", count)
    }


    fn end_parameters(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn begin_errors(&mut self, w: &mut dyn Write, count: u32) -> std::io::Result<()> {
        writeln!(w, "\nPossible Errors ({}):", count)
    }

    fn end_errors(&mut self, _w: &mut dyn Write) -> std::io::Result<()> {
        Ok(())
    }

    fn examples(&mut self, w: &mut dyn Write, examples: &str) -> std::io::Result<()> {
        writeln!(w, "\nExamples:")?;
        writeln!(w, "{}", examples)
    }

    fn notes(&mut self, w: &mut dyn Write, notes: &str) -> std::io::Result<()> {
        writeln!(w, "\nNotes:")?;
        writeln!(w, "{}", notes)
    }

    fn since_version(&mut self, w: &mut dyn Write, version: &str) -> std::io::Result<()> {
        writeln!(w, "\nAvailable since: {}", version)
    }
}