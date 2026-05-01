//! `nono dry-run-schema` — emit the JSON Schema describing
//! `--dry-run-json` output.
//!
//! Tooling that consumes `nono run --dry-run-json` (CI policy linters,
//! editor integrations, audit pipelines) needs a schema document to
//! validate against. Without one, every consumer reverse-engineers
//! the shape from the implementation, which is brittle and divergent.
//!
//! The schema is statically defined here and pinned to
//! `schema_version: 1` of the runtime output. Adding a new key is an
//! additive change (existing consumers still validate); removing or
//! renaming a key requires bumping `schema_version` so old consumers
//! see the boundary explicitly.

use crate::cli::DryRunSchemaArgs;
use nono::{NonoError, Result};
use std::io::Write;

/// JSON Schema (draft 2020-12) for the `--dry-run-json` output. Kept
/// as a raw string literal so the schema doc is the source of truth
/// and isn't reconstructed at run time. The matching key list lives
/// in `output::capabilities_to_json` + the
/// `capabilities_to_json_emits_stable_top_level_keys` test.
const DRY_RUN_JSON_SCHEMA: &str = r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://nono.dev/schemas/dry-run-json/v1.json",
  "title": "nono --dry-run-json output",
  "description": "JSON document emitted by `nono run --dry-run-json` (and `shell` / `wrap` variants) describing the resolved capability set without applying the sandbox. Stable within schema_version 1; new keys are additive, removals or renames bump the version.",
  "type": "object",
  "required": [
    "schema_version",
    "command",
    "filesystem",
    "unix_sockets",
    "network",
    "tcp_connect_ports",
    "tcp_bind_ports",
    "localhost_ports",
    "signal_mode",
    "process_info_mode",
    "ipc_mode",
    "extensions_enabled",
    "platform_rules_count",
    "allowed_commands",
    "blocked_commands",
    "secrets_count",
    "env_filter",
    "override_deny_paths",
    "network_profile",
    "allow_domain",
    "listen_ports",
    "capability_elevation",
    "allow_launch_services_active",
    "allow_gpu_active"
  ],
  "properties": {
    "schema_version": {
      "type": "integer",
      "const": 1,
      "description": "Schema version. Bumped on incompatible changes; additive key growth keeps the same number."
    },
    "command": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Resolved program path followed by argv. Equivalent to what would be exec'd if this were not a dry-run."
    },
    "filesystem": {
      "type": "array",
      "description": "Filesystem capability grants. Each entry covers a path with an access mode (read / write / read+write) and an attribution source (user / profile / group / system)."
    },
    "unix_sockets": {
      "type": "array",
      "description": "AF_UNIX socket grants."
    },
    "network": {
      "type": "object",
      "description": "Resolved network mode. One of: Blocked, AllowAll, or ProxyOnly { port, bind_ports }."
    },
    "tcp_connect_ports": {
      "type": "array",
      "items": { "type": "integer", "minimum": 0, "maximum": 65535 },
      "description": "Outbound TCP connect allowlist (Linux Landlock V4+ enforces; macOS Seatbelt parity)."
    },
    "tcp_bind_ports": {
      "type": "array",
      "items": { "type": "integer", "minimum": 0, "maximum": 65535 },
      "description": "Inbound TCP bind allowlist."
    },
    "localhost_ports": {
      "type": "array",
      "items": { "type": "integer", "minimum": 0, "maximum": 65535 },
      "description": "Bidirectional localhost-pinned ports (covers both bind and connect)."
    },
    "signal_mode": { "description": "Signal isolation mode." },
    "process_info_mode": { "description": "Process info visibility mode." },
    "ipc_mode": { "description": "IPC isolation mode." },
    "extensions_enabled": {
      "type": "object",
      "description": "Per-extension opt-in flags."
    },
    "platform_rules_count": {
      "type": "integer",
      "minimum": 0,
      "description": "Number of resolved platform-specific rules."
    },
    "allowed_commands": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Explicit command allowlist (overrides the policy blocklist for matching basenames)."
    },
    "blocked_commands": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Resolved command blocklist."
    },
    "secrets_count": {
      "type": "integer",
      "minimum": 0,
      "description": "Number of secrets the proxy was wired to inject. The actual values are NEVER serialized — only the count."
    },
    "env_filter": {
      "description": "Environment variable filter. Tagged: { type: 'inherit_all' } or { type: 'restricted', allowed_keys: [...] }."
    },
    "override_deny_paths": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Canonicalized paths that have been exempted from sensitive-path deny groups."
    },
    "network_profile": {
      "type": ["string", "null"],
      "description": "Active network profile name, or null if none was selected."
    },
    "allow_domain": {
      "type": "array",
      "items": { "type": "string" },
      "description": "Domain allowlist enforced at the proxy layer."
    },
    "listen_ports": {
      "type": "array",
      "items": { "type": "integer", "minimum": 0, "maximum": 65535 }
    },
    "capability_elevation": {
      "type": "boolean",
      "description": "Whether `--capability-elevation` is active for this run."
    },
    "allow_launch_services_active": {
      "type": "boolean",
      "description": "Whether the macOS launch-services shim is active."
    },
    "allow_gpu_active": {
      "type": "boolean",
      "description": "Whether GPU access is granted."
    }
  }
}
"#;

/// Dispatch `nono dry-run-schema`. Either prints the schema to stdout,
/// writes it to the path given by `--output`, or extracts one field
/// from it via `--field` (mutually exclusive with `--output`).
pub fn run_dry_run_schema(args: &DryRunSchemaArgs) -> Result<()> {
    if let Some(ref field) = args.field {
        // Parse the static schema once, navigate to the requested
        // field, render it with the shared jq-r-lite extractor.
        // Same shell-friendly semantics as the rest of the --field
        // surfaces: primitives raw, composites JSON honoring
        // --compact.
        let value: serde_json::Value = serde_json::from_str(DRY_RUN_JSON_SCHEMA)
            .map_err(|e| NonoError::ConfigParse(format!("Failed to parse schema document: {e}")))?;
        let extracted = crate::field_extract::extract_field_output(&value, field, args.compact)?;
        println!("{extracted}");
        return Ok(());
    }
    match args.output.as_deref() {
        Some(path) => {
            std::fs::write(path, DRY_RUN_JSON_SCHEMA).map_err(|e| {
                NonoError::ConfigParse(format!("Failed to write schema to {}: {e}", path.display()))
            })?;
            // Confirmation goes to stderr so stdout stays empty (so
            // wrapping pipelines can still rely on stdout-empty-means-
            // wrote-to-file semantics if they want to).
            eprintln!("Schema written to {}", path.display());
        }
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle
                .write_all(DRY_RUN_JSON_SCHEMA.as_bytes())
                .map_err(|e| {
                    NonoError::ConfigParse(format!("Failed to write schema to stdout: {e}"))
                })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_parses_as_valid_json() {
        // The schema lives as a raw string literal, so a typo in the
        // JSON itself is the obvious latent bug. Round-tripping
        // through serde proves the literal is well-formed.
        let value: serde_json::Value =
            serde_json::from_str(DRY_RUN_JSON_SCHEMA).expect("schema must parse as JSON");
        assert!(
            value.is_object(),
            "schema root must be a JSON object, got {value:?}"
        );
    }

    #[test]
    fn schema_declares_jsonschema_draft_and_id() {
        let value: serde_json::Value = serde_json::from_str(DRY_RUN_JSON_SCHEMA).expect("parse");
        let obj = value.as_object().expect("object");
        // `$schema` is what makes consumers pick the right validator.
        // Without it, ad-hoc tooling has to guess the dialect.
        assert!(
            obj.get("$schema")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .contains("json-schema.org"),
            "schema must declare its $schema dialect URL"
        );
        // `$id` lets the schema be referenced by URL — important
        // for editor integrations that fetch schemas remotely.
        assert!(obj.contains_key("$id"), "schema must declare a stable $id");
    }

    #[test]
    fn schema_required_list_matches_runtime_output_keys() {
        // Load-bearing regression guard: the schema's `required`
        // array MUST equal the set of keys actually emitted by
        // `output::capabilities_to_json`. Otherwise consumers
        // would validate against a schema that says "X is required"
        // while the runtime never emits X (or vice versa).
        //
        // The matching runtime test
        // `capabilities_to_json_emits_stable_top_level_keys` lists
        // the canonical key set; we mirror it here. Adding a key
        // means updating both sides.
        let value: serde_json::Value = serde_json::from_str(DRY_RUN_JSON_SCHEMA).expect("parse");
        let required: Vec<&str> = value["required"]
            .as_array()
            .expect("required is array")
            .iter()
            .map(|v| v.as_str().expect("required entry is string"))
            .collect();

        let runtime_keys = [
            "schema_version",
            "command",
            "filesystem",
            "unix_sockets",
            "network",
            "tcp_connect_ports",
            "tcp_bind_ports",
            "localhost_ports",
            "signal_mode",
            "process_info_mode",
            "ipc_mode",
            "extensions_enabled",
            "platform_rules_count",
            "allowed_commands",
            "blocked_commands",
            "secrets_count",
            "env_filter",
            "override_deny_paths",
            "network_profile",
            "allow_domain",
            "listen_ports",
            "capability_elevation",
            "allow_launch_services_active",
            "allow_gpu_active",
        ];

        for k in runtime_keys {
            assert!(
                required.contains(&k),
                "schema's `required` list missing runtime key {k:?}"
            );
        }
        assert_eq!(
            required.len(),
            runtime_keys.len(),
            "schema's required list and runtime keys must be 1:1"
        );
    }

    #[test]
    fn schema_pins_schema_version_to_one() {
        // The whole point of `schema_version` is consumer-side
        // validation. Pinning the version `const` in the schema
        // catches accidental version bumps that aren't accompanied
        // by intentional schema work.
        let value: serde_json::Value = serde_json::from_str(DRY_RUN_JSON_SCHEMA).expect("parse");
        let const_val = &value["properties"]["schema_version"]["const"];
        assert_eq!(*const_val, serde_json::json!(1));
    }
}
