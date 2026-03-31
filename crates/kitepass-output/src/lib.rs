use serde::Serialize;
use serde_json::{Map, Value};
use tabled::{builder::Builder, settings::Style};

/// Output formatting for the Kitepass CLI.
///
/// Supports two modes:
/// - `text`: human-readable tables via `tabled`
/// - `json`: machine-readable JSON via `serde_json`
pub fn print_json<T: Serialize>(value: &T) -> Result<(), serde_json::Error> {
    println!("{}", render_json(value)?);
    Ok(())
}

pub fn print_text<T: Serialize>(value: &T) -> Result<(), serde_json::Error> {
    println!("{}", render_text(value)?);
    Ok(())
}

pub fn render_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(value)
}

pub fn render_text<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(value)?;
    Ok(render_value(&value))
}

fn render_value(value: &Value) -> String {
    match value {
        Value::Array(items) => render_array(items),
        Value::Object(map) => render_object(map),
        Value::Null => "null".to_string(),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(string) => string.clone(),
    }
}

fn render_array(items: &[Value]) -> String {
    if items.is_empty() {
        return "No records found.".to_string();
    }

    if items.iter().all(Value::is_object) {
        let mut headers = Vec::new();
        for item in items {
            let object = item.as_object().expect("object already checked");
            for key in object.keys() {
                if !headers.contains(key) {
                    headers.push(key.clone());
                }
            }
        }

        let mut builder = Builder::default();
        builder.push_record(headers.iter().map(String::as_str));
        for item in items {
            let object = item.as_object().expect("object already checked");
            builder.push_record(
                headers
                    .iter()
                    .map(|header| stringify_value(object.get(header).unwrap_or(&Value::Null))),
            );
        }
        return builder.build().with(Style::rounded()).to_string();
    }

    items
        .iter()
        .map(render_value)
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_object(map: &Map<String, Value>) -> String {
    if map.is_empty() {
        return "{}".to_string();
    }

    let mut builder = Builder::default();
    builder.push_record(["field", "value"]);
    for (field, value) in map {
        builder.push_record([field.to_string(), stringify_value(value)]);
    }
    builder.build().with(Style::rounded()).to_string()
}

fn stringify_value(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(boolean) => boolean.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(string) => string.clone(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string_pretty(value)
            .unwrap_or_else(|_| "<serialization error>".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_text_formats_objects_as_key_value_tables() {
        let rendered = render_text(&serde_json::json!({
            "wallet_id": "wal_123",
            "status": "active"
        }))
        .expect("text rendering should succeed");

        assert!(rendered.contains("wallet_id"));
        assert!(rendered.contains("wal_123"));
        assert!(rendered.contains("status"));
    }

    #[test]
    fn render_text_formats_arrays_of_objects_as_tables() {
        let rendered = render_text(&serde_json::json!([
            {"wallet_id": "wal_123", "status": "active"},
            {"wallet_id": "wal_456", "status": "frozen"}
        ]))
        .expect("text rendering should succeed");

        assert!(rendered.contains("wallet_id"));
        assert!(rendered.contains("wal_456"));
        assert!(rendered.contains("frozen"));
    }
}
