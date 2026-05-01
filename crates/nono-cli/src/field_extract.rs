//! Shared `--field <PATH>` extraction helper.
//!
//! Several CLI subcommands (`profile show`, `profile diff`, `inspect`)
//! emit large JSON documents that users typically post-process with
//! `jq -r '.<field>'` to capture a single value into a shell variable.
//! `--field` builds the same capture into nono itself so minimal CI /
//! container images don't have to ship `jq` just to read one key.
//!
//! Semantics mirror `jq -r`:
//!   - Primitives (string / number / bool / null) render raw, without
//!     surrounding JSON quotes — friendly for direct shell capture.
//!   - Composites (objects / arrays) render as JSON, honoring `--compact`
//!     so streaming consumers stay first-class.
//!   - Missing fields raise a `NonoError` rather than silently emitting
//!     nothing — typos shouldn't sail through into shell scripts.

use nono::{NonoError, Result};

/// Extract a single field from a JSON document, formatted for shell
/// consumption. The `field` argument accepts either a top-level key
/// (`name`) or a `/`-prefixed JSON Pointer (`/security/groups/0`).
///
/// `compact` controls how composite sub-values render: `true` produces
/// streaming-friendly single-line JSON, `false` produces pretty-printed
/// multi-line JSON. The flag has no effect on primitive values, which
/// always render raw.
pub fn extract_field_output(
    value: &serde_json::Value,
    field: &str,
    compact: bool,
) -> Result<String> {
    let pointer = if field.starts_with('/') {
        field.to_string()
    } else {
        format!("/{field}")
    };
    let target = value.pointer(&pointer).ok_or_else(|| {
        NonoError::ConfigParse(format!(
            "field {field:?} not found in JSON output \
             (use a top-level key or a JSON-Pointer path like /security/groups/0)"
        ))
    })?;
    Ok(match target {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Null => "null".to_string(),
        composite => if compact {
            serde_json::to_string(composite)
        } else {
            serde_json::to_string_pretty(composite)
        }
        .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_field_unwraps_primitive_string_without_quotes() {
        let val = serde_json::json!({"name": "default"});
        let out = extract_field_output(&val, "name", false).expect("string");
        assert_eq!(out, "default");
    }

    #[test]
    fn extract_field_emits_null_literal() {
        let val = serde_json::json!({"x": null});
        assert_eq!(
            extract_field_output(&val, "x", false).expect("null"),
            "null"
        );
    }

    #[test]
    fn extract_field_serializes_composites_with_compact_flag() {
        let val = serde_json::json!({"arr": [1, 2, 3]});
        let pretty = extract_field_output(&val, "arr", false).expect("pretty");
        assert!(pretty.contains('\n'));
        let compact = extract_field_output(&val, "arr", true).expect("compact");
        assert_eq!(compact, "[1,2,3]");
    }

    #[test]
    fn extract_field_supports_pointer_paths() {
        let val = serde_json::json!({"a": {"b": [10, 20]}});
        assert_eq!(
            extract_field_output(&val, "/a/b/1", false).expect("pointer"),
            "20"
        );
    }

    #[test]
    fn extract_field_errors_on_missing_path() {
        // Silent fallback would let typos sail through. The error
        // message should name the missing field and hint at pointer
        // syntax so users know what they typed wrong.
        let val = serde_json::json!({"name": "default"});
        let err = extract_field_output(&val, "wrongkey", false).expect_err("missing");
        let msg = err.to_string();
        assert!(msg.contains("wrongkey"), "names the missing field: {msg}");
        assert!(
            msg.contains("JSON-Pointer") || msg.contains("top-level key"),
            "hints at pointer syntax: {msg}"
        );
    }
}
