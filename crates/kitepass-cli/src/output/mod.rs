use anyhow::Result;
use serde::Serialize;

use crate::cli::OutputFormat;

pub fn print_data<T: Serialize>(format: &OutputFormat, value: &T) -> Result<()> {
    let value = serde_json::to_value(value)?;

    match format {
        OutputFormat::Text => kitepass_output::print_text(&value)?,
        OutputFormat::Json => kitepass_output::print_json(&value)?,
    }
    Ok(())
}
