//! CLI-specific query extensions for the sandbox
//!
//! This module provides query functions and output formatting for the
//! `nono why` command.

use crate::config;
use colored::Colorize;
use nono::{AccessMode, CapabilitySet, NonoError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Structured description of the capability that matched or nearly matched
/// a query.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityMatch {
    /// Granted path for the capability.
    pub path: String,
    /// Granted access mode.
    pub access: String,
    /// Capability source such as user, profile, group:<name>, or system.
    pub source: String,
}

/// Result of querying whether an operation is permitted
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum QueryResult {
    /// The operation is allowed
    #[serde(rename = "allowed")]
    Allowed {
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        granted_path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        access: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        source: Option<String>,
    },
    /// The operation is denied
    #[serde(rename = "denied")]
    Denied {
        reason: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        details: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        policy_source: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        matching_capability: Option<CapabilityMatch>,
        #[serde(skip_serializing_if = "Option::is_none")]
        suggested_flag: Option<String>,
    },
    /// Not running inside a sandbox
    #[serde(rename = "not_sandboxed")]
    NotSandboxed { message: String },
}

/// Query whether a path operation is permitted
///
/// `overridden_paths` contains canonicalized paths that have been exempted from
/// deny groups via `override_deny`. The sensitive-path check is skipped for any
/// query path that is equal to or a child of an overridden path.
pub fn query_path(
    path: &Path,
    requested: AccessMode,
    caps: &CapabilitySet,
    overridden_paths: &[std::path::PathBuf],
) -> Result<QueryResult> {
    // Canonicalize the path for proper comparison
    let canonical = if path.exists() {
        path.canonicalize()
            .map_err(|e| NonoError::PathCanonicalization {
                path: path.to_path_buf(),
                source: e,
            })?
    } else {
        // For non-existent paths, try to canonicalize the parent
        if let Some(parent) = path.parent() {
            if parent.exists() {
                let parent_canonical =
                    parent
                        .canonicalize()
                        .map_err(|e| NonoError::PathCanonicalization {
                            path: parent.to_path_buf(),
                            source: e,
                        })?;
                parent_canonical.join(path.file_name().unwrap_or_default())
            } else {
                path.to_path_buf()
            }
        } else {
            path.to_path_buf()
        }
    };

    // Check if this path is covered by an override_deny exemption
    let is_overridden = overridden_paths
        .iter()
        .any(|op| canonical == *op || canonical.starts_with(op));

    // Check if this is a sensitive path (CLI security policy), but skip
    // the check for paths that have been explicitly overridden.
    if !is_overridden {
        if let Some(matched) = config::check_sensitive_path(&canonical.to_string_lossy())? {
            return Ok(QueryResult::Denied {
                reason: "sensitive_path".to_string(),
                details: Some(format!(
                    "Blocked by policy group '{}': {} Use policy.override_deny to exempt specific paths when appropriate.",
                    matched.group_name, matched.description
                )),
                policy_source: Some(format!("group:{}", matched.group_name)),
                matching_capability: None,
                suggested_flag: None,
            });
        }
    }

    // Check capabilities. Prefer the most specific matching grant so broad system
    // reads (e.g. /private on macOS) do not shadow explicit user grants.
    let mut best_covering: Option<&nono::FsCapability> = None;
    let mut best_sufficient: Option<&nono::FsCapability> = None;
    let mut best_covering_score = 0usize;
    let mut best_sufficient_score = 0usize;

    for cap in caps.fs_capabilities() {
        let covers = if cap.is_file {
            cap.resolved == canonical
        } else {
            canonical.starts_with(&cap.resolved)
        };

        if !covers {
            continue;
        }

        let score = cap.resolved.as_os_str().len();
        if score >= best_covering_score {
            best_covering = Some(cap);
            best_covering_score = score;
        }

        let sufficient = matches!(
            (cap.access, requested),
            (AccessMode::ReadWrite, _)
                | (AccessMode::Read, AccessMode::Read)
                | (AccessMode::Write, AccessMode::Write)
        );

        if sufficient && score >= best_sufficient_score {
            best_sufficient = Some(cap);
            best_sufficient_score = score;
        }
    }

    if let Some(cap) = best_sufficient {
        return Ok(QueryResult::Allowed {
            reason: "granted_path".to_string(),
            granted_path: Some(cap.resolved.display().to_string()),
            access: Some(cap.access.to_string()),
            source: Some(cap.source.to_string()),
        });
    }

    if let Some(cap) = best_covering {
        return Ok(QueryResult::Denied {
            reason: "insufficient_access".to_string(),
            details: Some(format!(
                "Path is covered by '{}', which grants {} access from {} but {} was requested",
                cap.resolved.display(),
                cap.access,
                cap.source,
                requested
            )),
            policy_source: None,
            matching_capability: Some(CapabilityMatch {
                path: cap.resolved.display().to_string(),
                access: cap.access.to_string(),
                source: cap.source.to_string(),
            }),
            suggested_flag: Some(suggested_flag_for_path(&canonical, requested)),
        });
    }

    Ok(QueryResult::Denied {
        reason: "path_not_granted".to_string(),
        details: Some(format!(
            "Path is not covered by any capability: {}",
            canonical.display()
        )),
        policy_source: None,
        matching_capability: None,
        suggested_flag: Some(suggested_flag_for_path(&canonical, requested)),
    })
}

/// One row of the `nono why --explain` table: a capability that covers
/// the queried path, plus whether it would have been *sufficient* for
/// the requested access mode (so users can see near-misses).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExplainedMatch {
    /// Resolved capability path.
    pub path: String,
    /// Granted access mode (`read`, `write`, `read+write`).
    pub access: String,
    /// Capability source (user / profile / group:<name> / system).
    pub source: String,
    /// Whether this capability alone would satisfy the requested
    /// access mode. `false` rows are near-misses — they cover the
    /// path but with insufficient access.
    pub sufficient: bool,
}

/// Like [`query_path`], but also returns every fs capability that
/// covers the queried path (sorted longest-prefix-first), so users
/// running `nono why --explain` can see *all* matches, not just the
/// best one. The first item of the returned tuple is byte-for-byte
/// identical to what `query_path` would have returned for the same
/// inputs — `--explain` is purely additive.
pub fn query_path_explained(
    path: &Path,
    requested: AccessMode,
    caps: &CapabilitySet,
    overridden_paths: &[std::path::PathBuf],
) -> Result<(QueryResult, Vec<ExplainedMatch>)> {
    let result = query_path(path, requested, caps, overridden_paths)?;

    // Re-canonicalize using the same lenient logic as `query_path` so
    // the explain pass sees the same "search space" the verdict was
    // computed against. Returning the raw input path here would cause
    // the second-pass match list to disagree with the verdict for
    // symlinked / non-existent inputs.
    let canonical = canonicalize_for_query(path)?;

    let mut matches: Vec<ExplainedMatch> = caps
        .fs_capabilities()
        .iter()
        .filter(|cap| {
            if cap.is_file {
                cap.resolved == canonical
            } else {
                canonical.starts_with(&cap.resolved)
            }
        })
        .map(|cap| {
            let sufficient = matches!(
                (cap.access, requested),
                (AccessMode::ReadWrite, _)
                    | (AccessMode::Read, AccessMode::Read)
                    | (AccessMode::Write, AccessMode::Write)
            );
            ExplainedMatch {
                path: cap.resolved.display().to_string(),
                access: cap.access.to_string(),
                source: cap.source.to_string(),
                sufficient,
            }
        })
        .collect();

    // Longest-path first so the explainer reads top-down from "most
    // specific match" to "broadest covering grant" — matches how
    // `query_path` itself picks a winner.
    matches.sort_by_key(|m| std::cmp::Reverse(m.path.len()));

    Ok((result, matches))
}

/// Lenient canonicalization shared by `query_path` and
/// `query_path_explained`: if the path itself doesn't exist we fall
/// back to canonicalizing the parent, so a query against a yet-to-be-
/// created file still resolves against its real directory.
fn canonicalize_for_query(path: &Path) -> Result<std::path::PathBuf> {
    if path.exists() {
        return path
            .canonicalize()
            .map_err(|e| NonoError::PathCanonicalization {
                path: path.to_path_buf(),
                source: e,
            });
    }
    if let Some(parent) = path.parent() {
        if parent.exists() {
            let parent_canonical =
                parent
                    .canonicalize()
                    .map_err(|e| NonoError::PathCanonicalization {
                        path: parent.to_path_buf(),
                        source: e,
                    })?;
            return Ok(parent_canonical.join(path.file_name().unwrap_or_default()));
        }
    }
    Ok(path.to_path_buf())
}

/// Parse a `host:port` shorthand for `nono why --net`.
///
/// Accepts:
///   - `host:port` — literal split on the LAST colon (so `[::1]:443` works
///     once we add v6 brackets later, but a bare `::1` would be ambiguous).
///   - `[host]:port` — bracketed IPv6 form, port required.
///   - `host` — port defaults to 443 to match `--port`'s default.
///
/// Rejects empty host, missing port, non-numeric port, port == 0.
pub fn parse_host_port(input: &str, default_port: u16) -> Result<(String, u16)> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(NonoError::ConfigParse(
            "--net requires a non-empty host[:port]".to_string(),
        ));
    }

    // Bracketed IPv6 form `[addr]:port` — port is mandatory here.
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((host, after)) = rest.split_once(']') {
            if host.is_empty() {
                return Err(NonoError::ConfigParse(
                    "--net IPv6 host inside brackets is empty".to_string(),
                ));
            }
            let port_part = after.strip_prefix(':').ok_or_else(|| {
                NonoError::ConfigParse(format!(
                    "--net bracketed IPv6 form requires a port: `[{host}]:<port>`",
                ))
            })?;
            let port: u16 = port_part
                .parse()
                .map_err(|_| NonoError::ConfigParse(format!("--net invalid port `{port_part}`")))?;
            if port == 0 {
                return Err(NonoError::ConfigParse(
                    "--net port must be in 1..=65535".to_string(),
                ));
            }
            return Ok((host.to_string(), port));
        }
        return Err(NonoError::ConfigParse(
            "--net unmatched `[` in IPv6 address".to_string(),
        ));
    }

    // Plain `host:port` — split on the LAST colon so v4-mapped or future
    // patterns survive without ambiguity for the common case.
    if let Some((host, port_part)) = trimmed.rsplit_once(':') {
        if host.is_empty() {
            return Err(NonoError::ConfigParse(
                "--net host portion is empty".to_string(),
            ));
        }
        let port: u16 = port_part
            .parse()
            .map_err(|_| NonoError::ConfigParse(format!("--net invalid port `{port_part}`")))?;
        if port == 0 {
            return Err(NonoError::ConfigParse(
                "--net port must be in 1..=65535".to_string(),
            ));
        }
        return Ok((host.to_string(), port));
    }

    // Bare host — fall back to the caller's default port.
    Ok((trimmed.to_string(), default_port))
}

/// Query whether a TCP port is allowed under the resolved per-port
/// allowlists. Mirrors what Landlock V4+ enforces on Linux.
///
/// Resolution order (first hit wins):
///   1. `localhost_ports` — bidirectional IPC pin (highest precedence).
///   2. `tcp_connect_ports` — outbound allow.
///   3. `tcp_bind_ports` — inbound bind allow.
///   4. Otherwise: deny if network is blocked / proxy-only, allow if
///      network is generally open.
pub fn query_tcp_port(port: u16, caps: &CapabilitySet) -> QueryResult {
    if caps.localhost_ports().contains(&port) {
        return QueryResult::Allowed {
            reason: "tcp_localhost_pinned".to_string(),
            granted_path: None,
            access: Some(format!("localhost-only IPC on port {port}")),
            source: Some("policy:localhost_ports".to_string()),
        };
    }

    if caps.tcp_connect_ports().contains(&port) {
        return QueryResult::Allowed {
            reason: "tcp_connect_allowed".to_string(),
            granted_path: None,
            access: Some(format!("outbound TCP connect on port {port}")),
            source: Some("policy:tcp_connect_ports".to_string()),
        };
    }

    if caps.tcp_bind_ports().contains(&port) {
        return QueryResult::Allowed {
            reason: "tcp_bind_allowed".to_string(),
            granted_path: None,
            access: Some(format!("local TCP bind on port {port}")),
            source: Some("policy:tcp_bind_ports".to_string()),
        };
    }

    if caps.is_network_blocked() {
        QueryResult::Denied {
            reason: "tcp_port_not_allowlisted".to_string(),
            details: Some(format!(
                "Port {port} is not in tcp_connect_ports, tcp_bind_ports, \
                 or localhost_ports, and the resolved network mode blocks \
                 unfiltered outbound. Add `--allow-port {port}` (bind), \
                 `--allow-connect-port {port}` (connect), or relax with \
                 `--allow-net` to permit the port."
            )),
            policy_source: None,
            matching_capability: None,
            suggested_flag: Some(format!("--allow-connect-port {port}")),
        }
    } else {
        QueryResult::Allowed {
            reason: "network_unrestricted".to_string(),
            granted_path: None,
            access: Some(format!(
                "Network is not filtered by port — TCP port {port} is reachable"
            )),
            source: None,
        }
    }
}

/// Bind-only variant of [`query_tcp_port`]. Walks the same allowlists
/// but ignores `tcp_connect_ports` entirely — those grants only
/// authorize outbound, so they must NOT cause a `--tcp-bind` query to
/// say "yes" when the user is asking specifically about whether the
/// child process can listen on the port.
///
/// Resolution order:
///   1. `localhost_ports` — bidirectional IPC (covers bind + connect).
///   2. `tcp_bind_ports` — inbound bind allow.
///   3. Otherwise: deny if network is blocked / proxy-only, allow if
///      network is generally open (no per-port bind filter applied).
pub fn query_tcp_bind_port(port: u16, caps: &CapabilitySet) -> QueryResult {
    if caps.localhost_ports().contains(&port) {
        return QueryResult::Allowed {
            reason: "tcp_localhost_pinned".to_string(),
            granted_path: None,
            access: Some(format!(
                "localhost-only IPC on port {port} (covers bind + connect)"
            )),
            source: Some("policy:localhost_ports".to_string()),
        };
    }

    if caps.tcp_bind_ports().contains(&port) {
        return QueryResult::Allowed {
            reason: "tcp_bind_allowed".to_string(),
            granted_path: None,
            access: Some(format!("local TCP bind on port {port}")),
            source: Some("policy:tcp_bind_ports".to_string()),
        };
    }

    if caps.is_network_blocked() {
        QueryResult::Denied {
            reason: "tcp_bind_not_allowlisted".to_string(),
            details: Some(format!(
                "Port {port} is not in tcp_bind_ports or localhost_ports, \
                 and the resolved network mode blocks unfiltered bind. Add \
                 `--allow-port {port}` (bind) or `--allow-localhost-port \
                 {port}` (bidirectional localhost) to permit binding. \
                 (`tcp_connect_ports` grants are intentionally ignored \
                 here — they authorize outbound only.)"
            )),
            policy_source: None,
            matching_capability: None,
            suggested_flag: Some(format!("--allow-port {port}")),
        }
    } else {
        QueryResult::Allowed {
            reason: "network_unrestricted".to_string(),
            granted_path: None,
            access: Some(format!(
                "Network is not filtered by bind allowlist — TCP bind on \
                 port {port} is permitted"
            )),
            source: None,
        }
    }
}

/// Query whether running a command is permitted by the resolved policy.
///
/// Mirrors the lookup performed at exec time: the explicit allow-list takes
/// precedence over the blocklist (so `--allow-command rm` unblocks `rm`).
/// The query operates on the basename of `name`, matching the runtime check
/// — `nono why --command /bin/rm` and `nono why --command rm` resolve the
/// same way.
pub fn query_command(name: &str, caps: &CapabilitySet) -> Result<QueryResult> {
    let allowed: Vec<String> = caps.allowed_commands().to_vec();
    let blocked: Vec<String> = caps.blocked_commands().to_vec();

    if let Some(matched) = config::check_blocked_command(name, &allowed, &blocked)? {
        return Ok(QueryResult::Denied {
            reason: "blocked_command".to_string(),
            details: Some(format!(
                "Command '{matched}' is blocked by the resolved policy. \
                 Override with `--allow-command {matched}` if you understand the risk."
            )),
            policy_source: Some("policy:blocked_commands".to_string()),
            matching_capability: None,
            suggested_flag: Some(format!("--allow-command {matched}")),
        });
    }

    let basename = std::path::Path::new(name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string());

    let explicitly_allowed = allowed.iter().any(|a| a == &basename);
    Ok(QueryResult::Allowed {
        reason: if explicitly_allowed {
            "command_explicitly_allowed".to_string()
        } else {
            "command_not_blocked".to_string()
        },
        granted_path: None,
        access: None,
        source: if explicitly_allowed {
            Some("policy:allowed_commands".to_string())
        } else {
            None
        },
    })
}

/// Query whether network access is permitted
pub fn query_network(host: &str, port: u16, caps: &CapabilitySet) -> QueryResult {
    if caps.is_network_blocked() {
        QueryResult::Denied {
            reason: "network_blocked".to_string(),
            details: Some(format!(
                "Network access is blocked. Connection to {}:{} would be denied.",
                host, port
            )),
            policy_source: None,
            matching_capability: None,
            suggested_flag: None,
        }
    } else {
        QueryResult::Allowed {
            reason: "network_allowed".to_string(),
            granted_path: None,
            access: Some(format!("Connection to {}:{} would be allowed", host, port)),
            source: None,
        }
    }
}

/// Print a query result in human-readable format
pub fn print_result(result: &QueryResult) {
    match result {
        QueryResult::Allowed {
            reason,
            granted_path,
            access,
            source,
        } => {
            println!("{}", "ALLOWED".green().bold());
            println!("  Reason: {}", reason);
            if let Some(path) = granted_path {
                println!("  Granted by: {}", path);
            }
            if let Some(acc) = access {
                println!("  Access: {}", acc);
            }
            if let Some(src) = source {
                println!("  Source: {}", src);
            }
        }
        QueryResult::Denied {
            reason,
            details,
            policy_source,
            matching_capability,
            suggested_flag,
        } => {
            println!("{}", "DENIED".red().bold());
            println!("  Reason: {}", reason);
            if let Some(d) = details {
                println!("  Details: {}", d);
            }
            if let Some(policy) = policy_source {
                println!("  Policy: {}", policy);
            }
            if let Some(cap) = matching_capability {
                println!(
                    "  Closest match: {} ({}, {})",
                    cap.path, cap.access, cap.source
                );
            }
            if let Some(flag) = suggested_flag {
                println!("  Suggested fix: {}", flag);
            }
        }
        QueryResult::NotSandboxed { message } => {
            println!("{}", "NOT SANDBOXED".yellow().bold());
            println!("  {}", message);
        }
    }
}

fn suggested_flag_for_path(path: &Path, requested: AccessMode) -> String {
    let (flag, target) = suggested_flag_parts(path, requested);
    format!("{flag} {}", target.display())
}

pub(crate) fn suggested_flag_parts(path: &Path, requested: AccessMode) -> (&'static str, PathBuf) {
    let flag = if path.is_file() {
        match requested {
            AccessMode::Read => "--read-file",
            AccessMode::Write => "--write-file",
            AccessMode::ReadWrite => "--allow-file",
        }
    } else {
        match requested {
            AccessMode::Read => "--read",
            AccessMode::Write => "--write",
            AccessMode::ReadWrite => "--allow",
        }
    };

    let target = if path.exists() || path.is_dir() || path.parent().is_none() {
        path.to_path_buf()
    } else if let Some(parent) = path.parent() {
        // Never suggest granting access to the root filesystem
        if parent == Path::new("/") {
            path.to_path_buf()
        } else {
            parent.to_path_buf()
        }
    } else {
        path.to_path_buf()
    };

    (flag, target)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nono::{CapabilitySource, FsCapability};
    use std::path::PathBuf;
    use tempfile::tempdir;

    #[test]
    fn test_query_path_granted() {
        let dir = tempdir().expect("Failed to create temp dir");
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: dir.path().to_path_buf(),
            resolved: dir.path().canonicalize().expect("Failed to canonicalize"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let test_file = dir.path().join("test.txt");
        std::fs::write(&test_file, "test").expect("Failed to write test file");
        let expected_grant = dir
            .path()
            .canonicalize()
            .expect("Failed to canonicalize dir");

        let result = query_path(&test_file, AccessMode::Read, &caps, &[]).expect("Query failed");
        match result {
            QueryResult::Allowed {
                source,
                granted_path,
                access,
                ..
            } => {
                assert_eq!(source.as_deref(), Some("user"));
                assert_eq!(
                    granted_path.as_deref(),
                    Some(expected_grant.to_string_lossy().as_ref())
                );
                assert_eq!(access.as_deref(), Some("read+write"));
            }
            _ => panic!("expected allowed result"),
        }
    }

    #[test]
    fn test_query_path_denied() {
        let caps = CapabilitySet::new();
        let path = PathBuf::from("/some/random/path");

        let result = query_path(&path, AccessMode::Read, &caps, &[]).expect("Query failed");
        match result {
            QueryResult::Denied {
                reason,
                suggested_flag,
                matching_capability,
                ..
            } => {
                assert_eq!(reason, "path_not_granted");
                assert_eq!(suggested_flag.as_deref(), Some("--read /some/random"));
                assert!(matching_capability.is_none());
            }
            _ => panic!("expected denied result"),
        }
    }

    #[test]
    fn test_query_path_prefers_more_specific_sufficient_capability() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_canon = dir.path().canonicalize().expect("Failed to canonicalize");

        let mut caps = CapabilitySet::new();
        let parent = dir_canon
            .parent()
            .expect("tempdir has parent")
            .to_path_buf();

        // Broad read-only capability.
        caps.add_fs(FsCapability {
            original: parent.clone(),
            resolved: parent,
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::System,
        });

        // More specific read-write user capability.
        caps.add_fs(FsCapability {
            original: dir_canon.clone(),
            resolved: dir_canon.clone(),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        let test_file = dir_canon.join("test.txt");
        std::fs::write(&test_file, "test").expect("Failed to write test file");

        let result = query_path(&test_file, AccessMode::Write, &caps, &[]).expect("Query failed");
        assert!(matches!(result, QueryResult::Allowed { .. }));
    }

    #[test]
    fn test_query_path_reports_near_miss_with_source_and_fix() {
        let dir = tempdir().expect("Failed to create temp dir");
        let dir_canon = dir.path().canonicalize().expect("Failed to canonicalize");
        let test_file = dir.path().join("test.txt");
        std::fs::write(&test_file, "test").expect("Failed to write test file");
        let test_file_canon = test_file
            .canonicalize()
            .expect("Failed to canonicalize file");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: dir_canon.clone(),
            resolved: dir_canon,
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::Group("dev".to_string()),
        });

        let result = query_path(&test_file, AccessMode::Write, &caps, &[]).expect("Query failed");
        match result {
            QueryResult::Denied {
                reason,
                matching_capability,
                suggested_flag,
                details,
                ..
            } => {
                let expected_flag = format!("--write-file {}", test_file_canon.display());
                assert_eq!(reason, "insufficient_access");
                assert_eq!(suggested_flag.as_deref(), Some(expected_flag.as_str()));
                let capability = matching_capability.expect("expected matching capability");
                assert_eq!(capability.access, "read");
                assert_eq!(capability.source, "group:dev");
                assert!(details
                    .as_deref()
                    .is_some_and(|d| d.contains("group:dev") && d.contains("write was requested")));
            }
            _ => panic!("expected denied result"),
        }
    }

    #[test]
    fn test_query_path_sensitive_policy_includes_policy_source() {
        let _lock = match crate::test_env::ENV_LOCK.lock() {
            Ok(lock) => lock,
            Err(poisoned) => poisoned.into_inner(),
        };
        let ssh_path = PathBuf::from(format!(
            "{}/.ssh",
            crate::config::validated_home().expect("HOME should be valid in test")
        ));
        let caps = CapabilitySet::new();

        let result = query_path(&ssh_path, AccessMode::Read, &caps, &[]).expect("Query failed");
        match result {
            QueryResult::Denied {
                reason,
                policy_source,
                suggested_flag,
                details,
                ..
            } => {
                assert_eq!(reason, "sensitive_path");
                assert!(policy_source
                    .as_deref()
                    .is_some_and(|policy| policy.starts_with("group:")));
                assert!(details
                    .as_deref()
                    .is_some_and(|detail| detail.contains("policy.override_deny")));
                assert!(suggested_flag.is_none());
            }
            _ => panic!("expected denied result"),
        }
    }

    #[test]
    fn test_query_network_allowed() {
        let caps = CapabilitySet::new(); // Network allowed by default
        let result = query_network("example.com", 443, &caps);
        assert!(matches!(result, QueryResult::Allowed { .. }));
    }

    #[test]
    fn test_query_network_blocked() {
        let caps = CapabilitySet::new().block_network();
        let result = query_network("example.com", 443, &caps);
        assert!(matches!(result, QueryResult::Denied { .. }));
    }

    #[test]
    fn test_query_command_blocked_returns_denied_with_suggested_flag() {
        let caps = CapabilitySet::new().block_command("rm");
        let result = query_command("rm", &caps).expect("query_command failed");
        match result {
            QueryResult::Denied {
                reason,
                suggested_flag,
                policy_source,
                ..
            } => {
                assert_eq!(reason, "blocked_command");
                assert_eq!(
                    suggested_flag.as_deref(),
                    Some("--allow-command rm"),
                    "should hint at the override flag",
                );
                assert_eq!(policy_source.as_deref(), Some("policy:blocked_commands"));
            }
            other => panic!("expected denied, got {:?}", other),
        }
    }

    #[test]
    fn test_query_command_strips_path_prefix_to_basename() {
        // Mirror runtime behavior: /bin/rm should resolve like rm.
        let caps = CapabilitySet::new().block_command("rm");
        let result = query_command("/bin/rm", &caps).expect("query_command failed");
        assert!(
            matches!(result, QueryResult::Denied { .. }),
            "absolute path to rm must still resolve as blocked"
        );
    }

    #[test]
    fn test_query_command_allow_overrides_block() {
        // Explicit allow-list wins over the blocklist for the same name.
        let caps = CapabilitySet::new().block_command("rm").allow_command("rm");
        let result = query_command("rm", &caps).expect("query_command failed");
        match result {
            QueryResult::Allowed { reason, source, .. } => {
                assert_eq!(reason, "command_explicitly_allowed");
                assert_eq!(source.as_deref(), Some("policy:allowed_commands"));
            }
            other => panic!("expected allowed, got {:?}", other),
        }
    }

    #[test]
    fn query_path_explained_lists_all_covers_with_sufficiency_flags() {
        // Build a CapabilitySet with two grants on overlapping prefixes:
        // a Read on the parent dir + a ReadWrite on a subdir. Querying a
        // file inside the subdir should see BOTH grants in the explain
        // output, sorted longest-prefix first, with sufficiency flags
        // matching what `query_path` would have considered.
        let dir = tempdir().expect("tempdir");
        let sub = dir.path().join("inner");
        std::fs::create_dir_all(&sub).expect("create sub");
        let target = sub.join("file.txt");
        std::fs::write(&target, "x").expect("write target");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: dir.path().to_path_buf(),
            resolved: dir.path().canonicalize().expect("canon dir"),
            access: AccessMode::Read,
            is_file: false,
            source: CapabilitySource::User,
        });
        caps.add_fs(FsCapability {
            original: sub.clone(),
            resolved: sub.canonicalize().expect("canon sub"),
            access: AccessMode::ReadWrite,
            is_file: false,
            source: CapabilitySource::User,
        });

        // Querying for Write access: the broad Read parent is a
        // near-miss (insufficient), the narrower ReadWrite is sufficient.
        let (verdict, matches) =
            query_path_explained(&target, AccessMode::Write, &caps, &[]).expect("query");
        assert!(matches!(verdict, QueryResult::Allowed { .. }));
        assert_eq!(matches.len(), 2, "both covers must be listed: {matches:?}");

        // Longest-prefix first ⇒ the inner subdir leads.
        let canonical_sub = sub.canonicalize().expect("canon sub").display().to_string();
        let canonical_outer = dir
            .path()
            .canonicalize()
            .expect("canon outer")
            .display()
            .to_string();
        assert_eq!(matches[0].path, canonical_sub);
        assert!(matches[0].sufficient, "sub is ReadWrite ⇒ sufficient");
        assert_eq!(matches[1].path, canonical_outer);
        assert!(
            !matches[1].sufficient,
            "outer is Read-only, not sufficient for Write"
        );
    }

    #[test]
    fn query_path_explained_returns_empty_matches_when_nothing_covers() {
        let caps = CapabilitySet::new();
        let path = std::path::Path::new("/usr/bin");
        let (_verdict, matches) =
            query_path_explained(path, AccessMode::Read, &caps, &[]).expect("query");
        assert!(
            matches.is_empty(),
            "empty caps ⇒ nothing covers ⇒ empty list"
        );
    }

    #[test]
    fn parse_host_port_accepts_plain_host_port() {
        let (host, port) = parse_host_port("api.openai.com:443", 8080).expect("parse");
        assert_eq!(host, "api.openai.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_host_port_falls_back_to_default_when_port_omitted() {
        let (host, port) = parse_host_port("example.com", 1234).expect("parse");
        assert_eq!(host, "example.com");
        assert_eq!(port, 1234, "no `:` in input ⇒ default port");
    }

    #[test]
    fn parse_host_port_handles_bracketed_ipv6() {
        let (host, port) = parse_host_port("[::1]:8080", 0).expect("parse");
        assert_eq!(host, "::1");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_host_port_rejects_empty_input() {
        assert!(parse_host_port("", 443).is_err());
        assert!(parse_host_port("   ", 443).is_err());
    }

    #[test]
    fn parse_host_port_rejects_non_numeric_port() {
        assert!(parse_host_port("example.com:abc", 443).is_err());
    }

    #[test]
    fn parse_host_port_rejects_zero_port() {
        // Port 0 is meaningful in a few syscalls but never a valid query
        // target — surface it as an error to avoid silent confusion.
        assert!(parse_host_port("example.com:0", 443).is_err());
    }

    #[test]
    fn parse_host_port_rejects_empty_host_in_split() {
        assert!(parse_host_port(":443", 443).is_err());
    }

    #[test]
    fn query_tcp_port_localhost_pin_takes_precedence() {
        // localhost_ports applies regardless of network mode, so even
        // with --block-net the port should resolve as allowed.
        let caps = CapabilitySet::new()
            .block_network()
            .allow_localhost_port(8080);
        match query_tcp_port(8080, &caps) {
            QueryResult::Allowed { reason, source, .. } => {
                assert_eq!(reason, "tcp_localhost_pinned");
                assert_eq!(source.as_deref(), Some("policy:localhost_ports"));
            }
            other => panic!("expected allowed, got {other:?}"),
        }
    }

    #[test]
    fn query_tcp_port_connect_list_attributed_correctly() {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_tcp_connect_port(443);
        match query_tcp_port(443, &caps) {
            QueryResult::Allowed { reason, source, .. } => {
                assert_eq!(reason, "tcp_connect_allowed");
                assert_eq!(source.as_deref(), Some("policy:tcp_connect_ports"));
            }
            other => panic!("expected allowed, got {other:?}"),
        }
    }

    #[test]
    fn query_tcp_port_blocked_network_with_no_allowlist_denies_with_hint() {
        let caps = CapabilitySet::new().block_network();
        match query_tcp_port(443, &caps) {
            QueryResult::Denied {
                reason,
                suggested_flag,
                ..
            } => {
                assert_eq!(reason, "tcp_port_not_allowlisted");
                assert_eq!(
                    suggested_flag.as_deref(),
                    Some("--allow-connect-port 443"),
                    "should hint at connect-port override"
                );
            }
            other => panic!("expected denied, got {other:?}"),
        }
    }

    #[test]
    fn query_tcp_port_unfiltered_network_lets_any_port_through() {
        // Default `CapabilitySet` is AllowAll on network — any port
        // resolves as allowed without source attribution.
        let caps = CapabilitySet::new();
        match query_tcp_port(12345, &caps) {
            QueryResult::Allowed { reason, source, .. } => {
                assert_eq!(reason, "network_unrestricted");
                assert!(
                    source.is_none(),
                    "no source attribution when network is unfiltered"
                );
            }
            other => panic!("expected allowed, got {other:?}"),
        }
    }

    #[test]
    fn parse_host_port_rejects_bracketed_form_without_port() {
        assert!(parse_host_port("[::1]", 443).is_err());
        assert!(parse_host_port("[::1]:", 443).is_err());
    }

    #[test]
    fn test_query_command_unrelated_name_is_allowed() {
        // Commands that aren't on either list are allowed by default and
        // should NOT be tagged as `command_explicitly_allowed`.
        let caps = CapabilitySet::new().block_command("rm");
        let result = query_command("echo", &caps).expect("query_command failed");
        match result {
            QueryResult::Allowed { reason, source, .. } => {
                assert_eq!(reason, "command_not_blocked");
                assert!(
                    source.is_none(),
                    "no source attribution when command isn't on any list"
                );
            }
            other => panic!("expected allowed, got {:?}", other),
        }
    }

    #[test]
    fn query_tcp_bind_port_localhost_pin_takes_precedence() {
        let caps = CapabilitySet::new()
            .block_network()
            .allow_localhost_port(8080);
        match query_tcp_bind_port(8080, &caps) {
            QueryResult::Allowed {
                reason,
                source,
                access,
                ..
            } => {
                assert_eq!(reason, "tcp_localhost_pinned");
                assert_eq!(source.as_deref(), Some("policy:localhost_ports"));
                // Localhost binding doc string should mention bind+connect
                // so the user knows the grant is bidirectional.
                assert!(access.unwrap_or_default().contains("bind + connect"));
            }
            other => panic!("expected allowed, got {other:?}"),
        }
    }

    #[test]
    fn query_tcp_bind_port_bind_list_attributed() {
        let mut caps = CapabilitySet::new().block_network();
        caps.add_tcp_bind_port(8080);
        match query_tcp_bind_port(8080, &caps) {
            QueryResult::Allowed { reason, source, .. } => {
                assert_eq!(reason, "tcp_bind_allowed");
                assert_eq!(source.as_deref(), Some("policy:tcp_bind_ports"));
            }
            other => panic!("expected allowed, got {other:?}"),
        }
    }

    #[test]
    fn query_tcp_bind_port_ignores_connect_list() {
        // Critical contract: a tcp_connect_ports grant must NOT make a
        // bind-only query come back allowed. Otherwise the flag would be
        // a false positive — the whole reason `--tcp-bind` exists is to
        // distinguish bind from connect grants on the same port.
        let mut caps = CapabilitySet::new().block_network();
        caps.add_tcp_connect_port(8080);
        match query_tcp_bind_port(8080, &caps) {
            QueryResult::Denied {
                reason,
                suggested_flag,
                ..
            } => {
                assert_eq!(reason, "tcp_bind_not_allowlisted");
                assert_eq!(
                    suggested_flag.as_deref(),
                    Some("--allow-port 8080"),
                    "bind hint should suggest --allow-port (not --allow-connect-port)"
                );
            }
            other => panic!(
                "expected denied — connect grant must not satisfy a bind query — got {other:?}"
            ),
        }
    }

    #[test]
    fn query_tcp_bind_port_unfiltered_network_lets_any_port_through() {
        let caps = CapabilitySet::new();
        match query_tcp_bind_port(12345, &caps) {
            QueryResult::Allowed { reason, source, .. } => {
                assert_eq!(reason, "network_unrestricted");
                assert!(source.is_none());
            }
            other => panic!("expected allowed, got {other:?}"),
        }
    }
}
