//! crates/volta-server/src/jcs.rs - RFC 8785 (JCS) canonical JSON.
//!
//! Dual licensed under AGPL-3.0-only OR Apache-2.0.
//!
//! The subset volta emits: objects (keys sorted), arrays,
//! strings, booleans, null, and integers. String escaping follows
//! RFC 8785 section 3.2.2 (only the mandatory escapes); numbers
//! in volta's own documents are integers, so the ECMAScript
//! number serialization reduces to the integer form.

use serde_json::Value;

/// Canonicalize a JSON value per RFC 8785.
#[must_use]
pub fn canonicalize(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                if let Some(member) = map.get(*key) {
                    write_value(member, out);
                }
            }
            out.push('}');
        }
    }
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            ch if (ch as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", ch as u32));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_sorted_and_compact() {
        let value = json!({"b": 1, "a": {"d": [true, null], "c": "x"}});
        assert_eq!(
            canonicalize(&value),
            "{\"a\":{\"c\":\"x\",\"d\":[true,null]},\"b\":1}"
        );
    }
}
