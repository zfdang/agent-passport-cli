/// Output formatting for the Kitepass CLI.
///
/// Supports two modes:
/// - `text`: human-readable tables via `tabled`
/// - `json`: machine-readable JSON via `serde_json`

pub fn print_json<T: serde::Serialize>(value: &T) -> Result<(), serde_json::Error> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{json}");
    Ok(())
}
