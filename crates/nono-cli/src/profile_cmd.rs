//! Profile subcommand implementations
//!
//! Handles `nono profile init|list|show|diff|validate|groups|schema|guide`:
//! creation, inspection, comparison, validation, and documentation of
//! nono profiles and the group-based policy rules they reference.

use crate::cli::{
    ProfileCmdArgs, ProfileCommands, ProfileDiffArgs, ProfileGroupsArgs, ProfileGuideArgs,
    ProfileInitArgs, ProfileListArgs, ProfileSchemaArgs, ProfileShowArgs, ProfileValidateArgs,
};
use crate::config::embedded;
use crate::policy::{self, AllowOps, DenyOps, Group};
use crate::profile::{self, Profile, WorkdirAccess};
use crate::theme;
use colored::Colorize;
use nono::{NonoError, Result};
use std::collections::BTreeSet;
use std::fs;
use std::io::Write;

/// Serialize a value to pretty-printed JSON, propagating serialization errors.
fn to_json(val: &serde_json::Value) -> Result<String> {
    serde_json::to_string_pretty(val)
        .map_err(|e| NonoError::ProfileParse(format!("JSON serialization failed: {e}")))
}

/// Serialize a value as compact (no whitespace) JSON. Used by callers
/// that pass `--compact` so they can stream the result into `jq -c`.
fn to_json_compact(val: &serde_json::Value) -> Result<String> {
    serde_json::to_string(val)
        .map_err(|e| NonoError::ProfileParse(format!("JSON serialization failed: {e}")))
}

// `--field <PATH>` extraction lives in `crate::field_extract` and is
// shared with `nono inspect --field` and any other future JSON-emitting
// command. Imported here so existing call sites keep working.
use crate::field_extract::extract_field_output;

/// Prefix used for all profile command output
fn prefix() -> colored::ColoredString {
    let t = theme::current();
    theme::fg("nono profile", t.brand).bold()
}

/// Dispatch to the appropriate profile subcommand.
pub fn run_profile(args: ProfileCmdArgs) -> Result<()> {
    match args.command {
        ProfileCommands::Init(args) => cmd_init(args),
        ProfileCommands::List(args) => cmd_list(args),
        ProfileCommands::Show(args) => cmd_show(args),
        ProfileCommands::Diff(args) => cmd_diff(args),
        ProfileCommands::Validate(args) => cmd_validate(args),
        ProfileCommands::Groups(args) => cmd_groups(args),
        ProfileCommands::Schema(args) => cmd_schema(args),
        ProfileCommands::Guide(args) => cmd_guide(args),
    }
}

// ---------------------------------------------------------------------------
// nono profile init
// ---------------------------------------------------------------------------

fn cmd_init(args: ProfileInitArgs) -> Result<()> {
    // Validate profile name
    if !profile::is_valid_profile_name(&args.name) {
        return Err(NonoError::ProfileParse(format!(
            "Invalid profile name '{}': must be alphanumeric with hyphens, no leading/trailing hyphens",
            args.name
        )));
    }

    // Determine output path
    let output_path = match &args.output {
        Some(path) => path.clone(),
        None => profile::get_user_profile_path(&args.name)?,
    };

    // Check for existing file
    if output_path.exists() && !args.force {
        return Err(NonoError::ProfileParse(format!(
            "Profile file already exists: {}\nUse --force to overwrite",
            output_path.display()
        )));
    }

    // Validate --extends target exists in any of the three sources the
    // resolver knows about (user dir, pack store, built-in).
    if let Some(ref base) = args.extends {
        if !profile_exists(base) {
            return Err(NonoError::ProfileParse(extends_target_not_found_message(
                base,
            )));
        }
    }

    // Validate --groups against embedded policy
    if !args.groups.is_empty() {
        let pol = policy::load_embedded_policy()?;
        for group in &args.groups {
            if !pol.groups.contains_key(group.as_str()) {
                return Err(NonoError::ProfileParse(format!(
                    "Unknown security group '{}'. Use `nono profile groups` to list available groups",
                    group
                )));
            }
        }
    }

    // Build skeleton JSON
    let skeleton = build_skeleton(&args);

    // Ensure parent directory exists
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            NonoError::ProfileParse(format!(
                "Failed to create directory {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    // Write file
    let json = serde_json::to_string_pretty(&skeleton)
        .map_err(|e| NonoError::ProfileParse(format!("JSON serialization failed: {e}")))?;

    fs::write(&output_path, format!("{json}\n")).map_err(|e| {
        NonoError::ProfileParse(format!(
            "Failed to write profile to {}: {}",
            output_path.display(),
            e
        ))
    })?;

    eprintln!(
        "{} Created profile at {}",
        prefix(),
        output_path.display().to_string().bold()
    );
    eprintln!(
        "{} Validate with: nono profile validate {}",
        prefix(),
        output_path.display()
    );
    eprintln!(
        "{} For editor autocomplete: nono profile schema -o nono-profile.schema.json",
        prefix()
    );

    Ok(())
}

/// Build a skeleton profile JSON value with controlled field ordering.
fn build_skeleton(args: &ProfileInitArgs) -> serde_json::Value {
    let mut root = serde_json::Map::new();

    if let Some(ref base) = args.extends {
        root.insert(
            "extends".to_string(),
            serde_json::Value::String(base.clone()),
        );
    }

    // meta
    let mut meta = serde_json::Map::new();
    meta.insert(
        "name".to_string(),
        serde_json::Value::String(args.name.clone()),
    );
    if let Some(ref desc) = args.description {
        meta.insert(
            "description".to_string(),
            serde_json::Value::String(desc.clone()),
        );
    }
    root.insert("meta".to_string(), serde_json::Value::Object(meta));

    // security
    let mut security = serde_json::Map::new();
    let groups: Vec<serde_json::Value> = args
        .groups
        .iter()
        .map(|g| serde_json::Value::String(g.clone()))
        .collect();
    security.insert("groups".to_string(), serde_json::Value::Array(groups));
    root.insert("security".to_string(), serde_json::Value::Object(security));

    // workdir
    let mut workdir = serde_json::Map::new();
    workdir.insert(
        "access".to_string(),
        serde_json::Value::String("readwrite".to_string()),
    );
    root.insert("workdir".to_string(), serde_json::Value::Object(workdir));

    // filesystem (minimal has allow + read; full adds all fields)
    let mut filesystem = serde_json::Map::new();
    filesystem.insert("allow".to_string(), serde_json::Value::Array(vec![]));
    filesystem.insert("read".to_string(), serde_json::Value::Array(vec![]));
    if args.full {
        filesystem.insert("write".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert("allow_file".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert("read_file".to_string(), serde_json::Value::Array(vec![]));
        filesystem.insert("write_file".to_string(), serde_json::Value::Array(vec![]));
    }
    root.insert(
        "filesystem".to_string(),
        serde_json::Value::Object(filesystem),
    );

    // Full skeleton adds additional sections
    if args.full {
        // policy
        let mut pol = serde_json::Map::new();
        pol.insert(
            "exclude_groups".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_allow_read".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_allow_write".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_allow_readwrite".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_deny_access".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "add_deny_commands".to_string(),
            serde_json::Value::Array(vec![]),
        );
        pol.insert(
            "override_deny".to_string(),
            serde_json::Value::Array(vec![]),
        );
        root.insert("policy".to_string(), serde_json::Value::Object(pol));

        // network
        // NOTE: network_profile is intentionally omitted. Emitting null would
        // clear an inherited proxy profile (e.g., "developer" from python-dev),
        // silently broadening network access. Absent = inherit from base.
        let mut network = serde_json::Map::new();
        network.insert("block".to_string(), serde_json::Value::Bool(false));
        network.insert("allow_domain".to_string(), serde_json::Value::Array(vec![]));
        network.insert("credentials".to_string(), serde_json::Value::Array(vec![]));
        network.insert("open_port".to_string(), serde_json::Value::Array(vec![]));
        network.insert("listen_port".to_string(), serde_json::Value::Array(vec![]));
        network.insert(
            "custom_credentials".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );
        root.insert("network".to_string(), serde_json::Value::Object(network));

        // env_credentials
        root.insert(
            "env_credentials".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );

        // hooks
        root.insert(
            "hooks".to_string(),
            serde_json::Value::Object(serde_json::Map::new()),
        );

        // rollback
        let mut rollback = serde_json::Map::new();
        rollback.insert(
            "exclude_patterns".to_string(),
            serde_json::Value::Array(vec![]),
        );
        rollback.insert(
            "exclude_globs".to_string(),
            serde_json::Value::Array(vec![]),
        );
        root.insert("rollback".to_string(), serde_json::Value::Object(rollback));

        // NOTE: open_urls, allow_launch_services, and allow_gpu are intentionally
        // omitted. Emitting them would replace inherited values from base profiles like
        // claude-code (which grants OAuth2 origins, launch services, and GPU access).
        // Absent = inherit from base. Authors who need to override these
        // should add them explicitly.
    }

    serde_json::Value::Object(root)
}

/// Check if a profile exists (built-in, user, or pack-provided).
///
/// Mirrors the resolver in `profile::load_profile_inner`: user dir →
/// pack-store → built-in. Without the pack-store check, formerly-builtin
/// profiles that have moved to registry packs (claude-code, codex)
/// would falsely fail `nono profile init --extends <name>` validation
/// even when `nono profile show <name>` resolves them fine.
fn profile_exists(name: &str) -> bool {
    if profile::builtin::get_builtin(name).is_some() {
        return true;
    }
    if let Ok(path) = profile::get_user_profile_path(name) {
        if path.exists() {
            return true;
        }
    }
    profile::find_pack_store_profile(name).is_some()
}

/// Update the validation error so users know all three sources were
/// considered. Used by `cmd_init`'s `--extends` check.
fn extends_target_not_found_message(name: &str) -> String {
    format!(
        "Base profile '{name}' not found (built-in, user, or installed pack). \
         If it's provided by a registry pack, run `nono pull <namespace>/<pack>` first."
    )
}

// ---------------------------------------------------------------------------
// nono profile schema
// ---------------------------------------------------------------------------

fn cmd_schema(args: ProfileSchemaArgs) -> Result<()> {
    let schema = embedded::embedded_profile_schema();

    if let Some(ref field) = args.field {
        // Same shell-friendly extraction as the rest of the --field
        // surfaces. Parse the embedded schema once, navigate via
        // JSON Pointer, render through the shared jq-r-lite helper.
        let value: serde_json::Value = serde_json::from_str(schema).map_err(|e| {
            NonoError::ProfileParse(format!("Failed to parse schema document: {e}"))
        })?;
        let extracted = crate::field_extract::extract_field_output(&value, field, args.compact)?;
        println!("{extracted}");
        return Ok(());
    }

    match args.output {
        Some(path) => {
            fs::write(&path, schema).map_err(|e| {
                NonoError::ProfileParse(format!(
                    "Failed to write schema to {}: {}",
                    path.display(),
                    e
                ))
            })?;
            eprintln!(
                "{} Schema written to {}",
                prefix(),
                path.display().to_string().bold()
            );
        }
        None => {
            let stdout = std::io::stdout();
            let mut handle = stdout.lock();
            handle
                .write_all(schema.as_bytes())
                .map_err(|e| NonoError::ProfileParse(format!("Failed to write to stdout: {e}")))?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// nono profile guide
// ---------------------------------------------------------------------------

fn cmd_guide(args: ProfileGuideArgs) -> Result<()> {
    let guide = embedded::embedded_profile_guide();

    if args.list_sections {
        let sections = parse_guide_sections(guide);
        for (title, _) in &sections {
            println!("## {title}");
        }
        return Ok(());
    }

    if let Some(ref query) = args.section {
        let sections = parse_guide_sections(guide);
        let matched = find_guide_section(&sections, query).ok_or_else(|| {
            NonoError::ProfileParse(format!(
                "section {query:?} not found. Use `nono profile guide --list-sections` \
                 to see available sections"
            ))
        })?;
        // Reprint the heading so `--section X` output is
        // self-describing (matches what `--list-sections` showed).
        println!("## {}", matched.0);
        print!("{}", matched.1);
        return Ok(());
    }

    if let Some(ref needle) = args.search {
        let sections = parse_guide_sections(guide);
        let hits = search_guide_sections(&sections, needle);
        if hits.is_empty() {
            return Err(NonoError::ProfileParse(format!(
                "no guide content matches {needle:?}. Use `nono profile guide \
                 --list-sections` to see available sections"
            )));
        }
        for (title, line_hits) in &hits {
            println!("## {title}");
            for (idx, line) in line_hits {
                println!("  {idx:>4}: {line}");
            }
        }
        return Ok(());
    }

    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    handle
        .write_all(guide.as_bytes())
        .map_err(|e| NonoError::ProfileParse(format!("Failed to write to stdout: {e}")))?;
    Ok(())
}

/// Split the embedded guide on `## ` headings. The doc is
/// markdown-ish (the title is the line text after the `## `, the
/// body is every line until the next `## ` or EOF). Lines before
/// the first `## ` heading (the document preamble) are dropped —
/// they're either the H1 title or front-matter that doesn't fit
/// section-extraction. Pure parser so it's unit-testable without
/// touching the embedded literal.
fn parse_guide_sections(guide: &str) -> Vec<(String, String)> {
    let mut sections: Vec<(String, String)> = Vec::new();
    let mut current_title: Option<String> = None;
    let mut current_body = String::new();
    for line in guide.split_inclusive('\n') {
        // `## ` is the section delimiter. Skip H1 (`# `) and deeper
        // headings (`### `, etc.) — they belong inside the
        // enclosing section.
        if let Some(rest) = line.strip_prefix("## ") {
            if let Some(t) = current_title.take() {
                sections.push((t, std::mem::take(&mut current_body)));
            }
            // Strip trailing newline from the title for cleaner
            // output (the heading line will be reprinted by the
            // caller).
            current_title = Some(rest.trim_end_matches('\n').to_string());
        } else if current_title.is_some() {
            current_body.push_str(line);
        }
    }
    if let Some(t) = current_title {
        sections.push((t, current_body));
    }
    sections
}

/// Find the first section whose title contains `query` as a
/// case-insensitive substring. Returns `None` for no match so the
/// caller can surface a helpful `--list-sections` hint.
fn find_guide_section<'a>(
    sections: &'a [(String, String)],
    query: &str,
) -> Option<&'a (String, String)> {
    let q = query.to_lowercase();
    sections
        .iter()
        .find(|(title, _)| title.to_lowercase().contains(&q))
}

/// Walk every section, return the lines that match `needle` as a
/// case-insensitive substring grouped by section title. Only
/// sections with at least one hit are returned. Line numbers are
/// 1-based and relative to the section body (so the user sees a
/// useful position cue without having to count from the document
/// start). The title heading itself is intentionally NOT searched —
/// `--section` already covers heading-based lookup, and double-
/// counting would clutter the output. Pure helper so it's unit-
/// testable without touching the embedded literal.
fn search_guide_sections<'a>(
    sections: &'a [(String, String)],
    needle: &str,
) -> Vec<(&'a str, Vec<(usize, &'a str)>)> {
    let q = needle.to_lowercase();
    let mut out: Vec<(&'a str, Vec<(usize, &'a str)>)> = Vec::new();
    for (title, body) in sections {
        let hits: Vec<(usize, &'a str)> = body
            .lines()
            .enumerate()
            .filter(|(_, l)| l.to_lowercase().contains(&q))
            .map(|(i, l)| (i.saturating_add(1), l))
            .collect();
        if !hits.is_empty() {
            out.push((title.as_str(), hits));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// nono profile groups
// ---------------------------------------------------------------------------

pub(crate) fn cmd_groups(args: ProfileGroupsArgs) -> Result<()> {
    let pol = policy::load_embedded_policy()?;

    match args.name {
        Some(name) => {
            // `--names-only` is meaningful only for the list shape.
            // In detail mode we'd be printing one name (the one the
            // user already passed in), which is tautological —
            // error out so the user notices the mismatch.
            if args.names_only {
                return Err(NonoError::ProfileParse(
                    "--names-only is only honored when listing groups; \
                     drop the group name argument to use it"
                        .to_string(),
                ));
            }
            // `--search` is also list-shape only — the detail view
            // is already a single document so filtering it is a
            // no-op or self-contradiction depending on whether the
            // group's content happens to match.
            if args.search.is_some() {
                return Err(NonoError::ProfileParse(
                    "--search is only honored when listing groups; \
                     drop the group name argument to use it"
                        .to_string(),
                ));
            }
            cmd_groups_detail(&pol, &name, args.json, args.compact, args.field.as_deref())
        }
        None => cmd_groups_list(
            &pol,
            args.json,
            args.compact,
            args.all_platforms,
            args.field.as_deref(),
            args.names_only,
            args.search.as_deref(),
        ),
    }
}

fn cmd_groups_list(
    pol: &policy::Policy,
    json: bool,
    compact: bool,
    all_platforms: bool,
    field: Option<&str>,
    names_only: bool,
    search: Option<&str>,
) -> Result<()> {
    let mut groups: Vec<(&String, &Group)> = pol.groups.iter().collect();
    groups.sort_by_key(|(name, _)| name.as_str());

    if !all_platforms {
        groups.retain(|(_, g)| policy::group_matches_platform(g));
    }

    // `--search` is human-only (rejected in clap if combined with
    // `--json` / `--compact` / `--field`). It composes with
    // `--names-only` to give shell-loop ergonomics.
    if let Some(needle) = search {
        let hits = search_groups(&groups, needle);
        if hits.is_empty() {
            return Err(NonoError::ProfileParse(format!(
                "no groups match {needle:?}. Use `nono profile groups` \
                 to see all groups"
            )));
        }
        if names_only {
            for (name, _, _) in &hits {
                println!("{name}");
            }
            return Ok(());
        }
        let t = theme::current();
        println!("{}: {} groups matching {:?}", prefix(), hits.len(), needle);
        println!();
        for (name, group, where_matched) in &hits {
            let platform = group.platform.as_deref().unwrap_or("cross-platform");
            let required = if group.required { "  required" } else { "" };
            println!(
                "  {:<36} {:<42} {}{}",
                theme::fg(name, t.text).bold(),
                theme::fg(&group.description, t.subtext),
                theme::fg(platform, t.overlay),
                theme::fg(required, t.yellow),
            );
            println!("    [matched in: {}]", where_matched.join(", "));
        }
        return Ok(());
    }

    if names_only {
        for (name, _) in &groups {
            println!("{name}");
        }
        return Ok(());
    }

    if json {
        let arr: Vec<serde_json::Value> = groups
            .iter()
            .map(|(name, g)| {
                serde_json::json!({
                    "name": name,
                    "description": g.description,
                    "platform": g.platform.as_deref().unwrap_or("cross-platform"),
                    "required": g.required,
                    "allow": count_allow(&g.allow),
                    "deny": count_deny(&g.deny),
                })
            })
            .collect();
        let val = serde_json::Value::Array(arr);
        if let Some(field) = field {
            // Same shell-friendly extraction as `profile show --field`.
            // For the array shape, JSON Pointer paths like `/0/name`
            // reach individual entries.
            let extracted = crate::field_extract::extract_field_output(&val, field, compact)?;
            println!("{extracted}");
            return Ok(());
        }
        let rendered = if compact {
            to_json_compact(&val)?
        } else {
            to_json(&val)?
        };
        println!("{rendered}");
        return Ok(());
    }

    let t = theme::current();
    println!(
        "{}: {} groups{}",
        prefix(),
        groups.len(),
        if all_platforms {
            " (all platforms)"
        } else {
            ""
        }
    );
    println!();

    for (name, group) in &groups {
        let platform = group.platform.as_deref().unwrap_or("cross-platform");
        let required = if group.required { "  required" } else { "" };
        println!(
            "  {:<36} {:<42} {}{}",
            theme::fg(name, t.text).bold(),
            theme::fg(&group.description, t.subtext),
            theme::fg(platform, t.overlay),
            theme::fg(required, t.yellow),
        );
    }

    Ok(())
}

fn cmd_groups_detail(
    pol: &policy::Policy,
    name: &str,
    json: bool,
    compact: bool,
    field: Option<&str>,
) -> Result<()> {
    let group = pol.groups.get(name).ok_or_else(|| {
        NonoError::ProfileParse(format!(
            "group '{}' not found in policy.json. Use `nono profile groups` to list available groups",
            name
        ))
    })?;

    if json {
        let val = group_to_json(name, group);
        if let Some(field) = field {
            let extracted = crate::field_extract::extract_field_output(&val, field, compact)?;
            println!("{extracted}");
            return Ok(());
        }
        let rendered = if compact {
            to_json_compact(&val)?
        } else {
            to_json(&val)?
        };
        println!("{rendered}");
        return Ok(());
    }

    let t = theme::current();
    println!("{}: group '{}'", prefix(), theme::fg(name, t.text).bold());
    println!();
    println!(
        "  {}  {}",
        theme::fg("Description:", t.subtext),
        theme::fg(&group.description, t.text)
    );
    println!(
        "  {}     {}",
        theme::fg("Platform:", t.subtext),
        theme::fg(
            group.platform.as_deref().unwrap_or("cross-platform"),
            t.text
        )
    );
    println!(
        "  {}     {}",
        theme::fg("Required:", t.subtext),
        theme::fg(if group.required { "yes" } else { "no" }, t.text)
    );

    if let Some(ref allow) = group.allow {
        print_path_section("allow.read", &allow.read, t);
        print_path_section("allow.write", &allow.write, t);
        print_path_section("allow.readwrite", &allow.readwrite, t);
    }

    if let Some(ref deny) = group.deny {
        print_path_section("deny.access", &deny.access, t);
        if deny.unlink {
            println!();
            println!("  {}", theme::fg("deny.unlink:", t.red).bold());
            println!("    {}", theme::fg("enabled", t.red));
        }
        if !deny.commands.is_empty() {
            println!();
            println!("  {}", theme::fg("deny.commands:", t.red).bold());
            for cmd in &deny.commands {
                println!("    {}", theme::fg(cmd, t.text));
            }
        }
    }

    if let Some(ref pairs) = group.symlink_pairs {
        if !pairs.is_empty() {
            println!();
            println!("  {}", theme::fg("symlink_pairs:", t.subtext).bold());
            let mut sorted: Vec<(&String, &String)> = pairs.iter().collect();
            sorted.sort_by_key(|(k, _)| k.as_str());
            for (from, to) in sorted {
                println!(
                    "    {} -> {}",
                    theme::fg(from, t.text),
                    theme::fg(to, t.subtext)
                );
            }
        }
    }

    Ok(())
}

fn print_path_section(label: &str, paths: &[String], t: &theme::Theme) {
    if paths.is_empty() {
        return;
    }
    let color = if label.starts_with("deny") {
        t.red
    } else {
        t.green
    };
    println!();
    println!("  {}", theme::fg(&format!("{label}:"), color).bold());
    for raw in paths {
        match policy::expand_path(raw) {
            Ok(expanded) => {
                let exp_str = expanded.display().to_string();
                if exp_str == *raw {
                    println!("    {}", theme::fg(raw, t.text));
                } else {
                    println!(
                        "    {:<36} -> {}",
                        theme::fg(raw, t.text),
                        theme::fg(&exp_str, t.subtext)
                    );
                }
            }
            Err(_) => {
                println!(
                    "    {:<36} -> {}",
                    theme::fg(raw, t.text),
                    theme::fg("<expansion failed>", t.red)
                );
            }
        }
    }
}

fn count_allow(allow: &Option<AllowOps>) -> serde_json::Value {
    match allow {
        Some(a) => serde_json::json!({
            "read": a.read.len(),
            "write": a.write.len(),
            "readwrite": a.readwrite.len(),
        }),
        None => serde_json::json!({}),
    }
}

fn count_deny(deny: &Option<DenyOps>) -> serde_json::Value {
    match deny {
        Some(d) => serde_json::json!({
            "access": d.access.len(),
            "commands": d.commands.len(),
            "unlink": d.unlink,
        }),
        None => serde_json::json!({}),
    }
}

fn group_to_json(name: &str, group: &Group) -> serde_json::Value {
    let mut val = serde_json::json!({
        "name": name,
        "description": group.description,
        "platform": group.platform.as_deref().unwrap_or("cross-platform"),
        "required": group.required,
    });

    if let Some(ref allow) = group.allow {
        let mut allow_val = serde_json::Map::new();
        if !allow.read.is_empty() {
            allow_val.insert("read".into(), expand_paths_json(&allow.read));
        }
        if !allow.write.is_empty() {
            allow_val.insert("write".into(), expand_paths_json(&allow.write));
        }
        if !allow.readwrite.is_empty() {
            allow_val.insert("readwrite".into(), expand_paths_json(&allow.readwrite));
        }
        val["allow"] = serde_json::Value::Object(allow_val);
    }

    if let Some(ref deny) = group.deny {
        let mut deny_val = serde_json::Map::new();
        if !deny.access.is_empty() {
            deny_val.insert("access".into(), expand_paths_json(&deny.access));
        }
        if !deny.commands.is_empty() {
            deny_val.insert("commands".into(), serde_json::json!(deny.commands));
        }
        if deny.unlink {
            deny_val.insert("unlink".into(), serde_json::json!(true));
        }
        val["deny"] = serde_json::Value::Object(deny_val);
    }

    if let Some(ref pairs) = group.symlink_pairs {
        if !pairs.is_empty() {
            val["symlink_pairs"] = serde_json::json!(pairs);
        }
    }

    val
}

fn expand_paths_json(paths: &[String]) -> serde_json::Value {
    let arr: Vec<serde_json::Value> = paths
        .iter()
        .map(|raw| {
            let expanded = policy::expand_path(raw)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<expansion failed>".to_string());
            serde_json::json!({
                "raw": raw,
                "expanded": expanded,
            })
        })
        .collect();
    serde_json::Value::Array(arr)
}

/// Filter the (already-platform-filtered) group list to the
/// entries whose name, description, or any path / command in
/// `allow.{read,write,readwrite}`, `deny.access`, or
/// `deny.commands` contains `needle` as a case-insensitive
/// substring. Returns each match alongside the list of field
/// labels that carried a hit (in a stable order so output is
/// deterministic for tests and easier to skim). Pure helper so
/// the matching logic is unit-testable without rebuilding the
/// embedded policy.
fn search_groups<'a>(
    groups: &[(&'a String, &'a Group)],
    needle: &str,
) -> Vec<(&'a String, &'a Group, Vec<&'static str>)> {
    let q = needle.to_lowercase();
    let mut out: Vec<(&'a String, &'a Group, Vec<&'static str>)> = Vec::new();
    for (name, group) in groups {
        let mut where_matched: Vec<&'static str> = Vec::new();
        if name.to_lowercase().contains(&q) {
            where_matched.push("name");
        }
        if group.description.to_lowercase().contains(&q) {
            where_matched.push("description");
        }
        if let Some(ref allow) = group.allow {
            if allow.read.iter().any(|p| p.to_lowercase().contains(&q)) {
                where_matched.push("allow.read");
            }
            if allow.write.iter().any(|p| p.to_lowercase().contains(&q)) {
                where_matched.push("allow.write");
            }
            if allow
                .readwrite
                .iter()
                .any(|p| p.to_lowercase().contains(&q))
            {
                where_matched.push("allow.readwrite");
            }
        }
        if let Some(ref deny) = group.deny {
            if deny.access.iter().any(|p| p.to_lowercase().contains(&q)) {
                where_matched.push("deny.access");
            }
            if deny.commands.iter().any(|c| c.to_lowercase().contains(&q)) {
                where_matched.push("deny.commands");
            }
        }
        if !where_matched.is_empty() {
            out.push((*name, *group, where_matched));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// nono profile list
// ---------------------------------------------------------------------------

/// Determine the actual source of a loaded profile.
///
/// Load precedence is user-first (profile/mod.rs), so a user file with a
/// built-in name shadows the built-in. We must check the filesystem to
/// report the real source accurately.
fn profile_source(name: &str) -> &'static str {
    let builtin_names = profile::builtin::list_builtin();
    let is_pack = profile::list_pack_store_profiles()
        .iter()
        .any(|(n, _)| n == name);
    if profile::is_user_override(name) {
        if is_pack {
            "user (overrides pack)"
        } else if builtin_names.contains(&name.to_string()) {
            "user (overrides built-in)"
        } else {
            "user"
        }
    } else if is_pack {
        "pack"
    } else if builtin_names.contains(&name.to_string()) {
        "built-in"
    } else {
        "user"
    }
}

/// Substring-match `needle` (already lowercased) against the
/// profile-list fields and return the labels of every field that
/// hit. Pure helper so the matching logic is unit-testable
/// without touching the embedded profile catalogue. Field order
/// is fixed (name → description → extends → source → pack) so
/// the rendered `[matched in: …]` line is deterministic.
fn match_profile_fields(
    name: &str,
    description: Option<&str>,
    extends: &[String],
    source: &str,
    pack: Option<&str>,
    needle_lower: &str,
) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    if name.to_lowercase().contains(needle_lower) {
        out.push("name");
    }
    if let Some(d) = description {
        if d.to_lowercase().contains(needle_lower) {
            out.push("description");
        }
    }
    if extends
        .iter()
        .any(|e| e.to_lowercase().contains(needle_lower))
    {
        out.push("extends");
    }
    if source.to_lowercase().contains(needle_lower) {
        out.push("source");
    }
    if let Some(p) = pack {
        if p.to_lowercase().contains(needle_lower) {
            out.push("pack");
        }
    }
    out
}

pub(crate) fn cmd_list(args: ProfileListArgs) -> Result<()> {
    let builtin_names = profile::builtin::list_builtin();
    let all_names = profile::list_profiles();
    // (install_as -> pack ref) for the catalogue. Used to bucket pack
    // profiles under their own section and surface the providing pack.
    let pack_profiles: std::collections::HashMap<String, String> =
        profile::list_pack_store_profiles().into_iter().collect();

    let mut builtin_profiles: Vec<(String, Result<Profile>)> = Vec::new();
    let mut user_profiles: Vec<(String, Result<Profile>)> = Vec::new();
    let mut pack_entries: Vec<(String, String, Result<Profile>)> = Vec::new();

    for name in &all_names {
        // Use the no-migrate loader so listing never triggers an
        // install prompt for pack-provided profiles whose pack happens
        // to be installed via the resolver self-heal path.
        let p = profile::load_profile_no_migrate(name);
        // Categorize by actual source. Precedence: user override > pack
        // store > built-in. User overrides of either built-in or pack
        // names go under user section to make shadowing visible.
        if profile::is_user_override(name) {
            user_profiles.push((name.clone(), p));
        } else if let Some(pack_ref) = pack_profiles.get(name) {
            pack_entries.push((name.clone(), pack_ref.clone(), p));
        } else if builtin_names.contains(name) {
            builtin_profiles.push((name.clone(), p));
        } else {
            user_profiles.push((name.clone(), p));
        }
    }

    if let Some(needle) = args.search.as_deref() {
        let q = needle.to_lowercase();

        // Match each bucket independently so we keep the same
        // built-in → packs → user grouping in the rendered output;
        // users rely on that ordering for shell pipelines and to
        // recognize where a profile lives.
        let m_builtin: Vec<(&String, &Result<Profile>, Vec<&'static str>)> = builtin_profiles
            .iter()
            .filter_map(|(name, result)| {
                let source = profile_source(name);
                let extends = profile::load_profile_extends(name).unwrap_or_default();
                let desc = result
                    .as_ref()
                    .ok()
                    .and_then(|p| p.meta.description.as_deref());
                let m = match_profile_fields(name, desc, &extends, source, None, &q);
                if m.is_empty() {
                    None
                } else {
                    Some((name, result, m))
                }
            })
            .collect();
        let m_pack: Vec<(&String, &String, &Result<Profile>, Vec<&'static str>)> = pack_entries
            .iter()
            .filter_map(|(name, pack, result)| {
                let source = profile_source(name);
                let extends = profile::load_profile_extends(name).unwrap_or_default();
                let desc = result
                    .as_ref()
                    .ok()
                    .and_then(|p| p.meta.description.as_deref());
                let m = match_profile_fields(name, desc, &extends, source, Some(pack), &q);
                if m.is_empty() {
                    None
                } else {
                    Some((name, pack, result, m))
                }
            })
            .collect();
        let m_user: Vec<(&String, &Result<Profile>, Vec<&'static str>)> = user_profiles
            .iter()
            .filter_map(|(name, result)| {
                let source = profile_source(name);
                let extends = profile::load_profile_extends(name).unwrap_or_default();
                let desc = result
                    .as_ref()
                    .ok()
                    .and_then(|p| p.meta.description.as_deref());
                let m = match_profile_fields(name, desc, &extends, source, None, &q);
                if m.is_empty() {
                    None
                } else {
                    Some((name, result, m))
                }
            })
            .collect();

        let total = m_builtin.len() + m_pack.len() + m_user.len();
        if total == 0 {
            return Err(NonoError::ProfileParse(format!(
                "no profiles match {needle:?}. Use `nono profile list` \
                 to see all profiles"
            )));
        }

        if args.names_only {
            for (name, _, _) in &m_builtin {
                println!("{name}");
            }
            for (name, _, _, _) in &m_pack {
                println!("{name}");
            }
            for (name, _, _) in &m_user {
                println!("{name}");
            }
            return Ok(());
        }

        let t = theme::current();
        println!("{}: {} profiles matching {:?}", prefix(), total, needle);

        if !m_builtin.is_empty() {
            println!();
            println!("  {}", theme::fg("Built-in:", t.subtext).bold());
            for (name, result, where_matched) in &m_builtin {
                print_profile_line(name, result, t);
                println!("    [matched in: {}]", where_matched.join(", "));
            }
        }
        if !m_pack.is_empty() {
            println!();
            println!("  {}", theme::fg("Packs:", t.subtext).bold());
            for (name, pack_ref, result, where_matched) in &m_pack {
                print_pack_profile_line(name, pack_ref, result, t);
                println!("    [matched in: {}]", where_matched.join(", "));
            }
        }
        if !m_user.is_empty() {
            println!();
            println!(
                "  {}",
                theme::fg("User (~/.config/nono/profiles/):", t.subtext).bold()
            );
            for (name, result, where_matched) in &m_user {
                print_profile_line(name, result, t);
                println!("    [matched in: {}]", where_matched.join(", "));
            }
        }
        return Ok(());
    }

    if args.names_only {
        // Newline-delimited names, in the same order the JSON
        // mode emits them: built-in → packs → user. Profiles
        // that fail to load still get listed by name (the failure
        // doesn't change identity); the JSON / human paths
        // surface the error inline, but `--names-only` is for
        // discovery, not diagnostics.
        for (name, _) in &builtin_profiles {
            println!("{name}");
        }
        for (name, _, _) in &pack_entries {
            println!("{name}");
        }
        for (name, _) in &user_profiles {
            println!("{name}");
        }
        return Ok(());
    }

    if args.json {
        let format_entry = |name: &str, result: &Result<Profile>| {
            let source = profile_source(name);
            let extends = profile::load_profile_extends(name).unwrap_or_default();
            let pack = pack_profiles.get(name).cloned();
            match result {
                Ok(p) => serde_json::json!({
                    "name": name,
                    "source": source,
                    "pack": pack,
                    "description": p.meta.description.as_deref().unwrap_or(""),
                    "extends": extends,
                }),
                Err(e) => serde_json::json!({
                    "name": name,
                    "source": source,
                    "pack": pack,
                    "error": format!("{}", e),
                }),
            }
        };

        let arr: Vec<serde_json::Value> = builtin_profiles
            .iter()
            .map(|(n, p)| format_entry(n, p))
            .chain(pack_entries.iter().map(|(n, _, p)| format_entry(n, p)))
            .chain(user_profiles.iter().map(|(n, p)| format_entry(n, p)))
            .collect();
        let val = serde_json::Value::Array(arr);
        if let Some(ref field) = args.field {
            // Same shell-friendly extraction as `profile show --field`.
            // For the array shape, JSON Pointer paths like `/0/name`
            // reach individual entries.
            let extracted = crate::field_extract::extract_field_output(&val, field, args.compact)?;
            println!("{extracted}");
            return Ok(());
        }
        let rendered = if args.compact {
            to_json_compact(&val)?
        } else {
            to_json(&val)?
        };
        println!("{rendered}");
        return Ok(());
    }

    let t = theme::current();
    let total = builtin_profiles.len() + pack_entries.len() + user_profiles.len();
    println!("{}: {} profiles", prefix(), total);

    if !builtin_profiles.is_empty() {
        println!();
        println!("  {}", theme::fg("Built-in:", t.subtext).bold());
        for (name, result) in &builtin_profiles {
            print_profile_line(name, result, t);
        }
    }

    if !pack_entries.is_empty() {
        println!();
        println!("  {}", theme::fg("Packs:", t.subtext).bold());
        for (name, pack_ref, result) in &pack_entries {
            print_pack_profile_line(name, pack_ref, result, t);
        }
    }

    if !user_profiles.is_empty() {
        println!();
        println!(
            "  {}",
            theme::fg("User (~/.config/nono/profiles/):", t.subtext).bold()
        );
        for (name, result) in &user_profiles {
            print_profile_line(name, result, t);
        }
    }

    Ok(())
}

/// Like `print_profile_line` but appends the providing pack ref so the
/// user sees `claude-code  Anthropic Claude Code …  always-further/claude`.
fn print_pack_profile_line(name: &str, pack_ref: &str, result: &Result<Profile>, t: &theme::Theme) {
    match result {
        Ok(p) => {
            let desc = p.meta.description.as_deref().unwrap_or("").to_string();
            let pack_label = format!("from {pack_ref}");
            println!(
                "    {:<16} {:<42} {}",
                theme::fg(name, t.text).bold(),
                theme::fg(&desc, t.subtext),
                theme::fg(&pack_label, t.overlay),
            );
        }
        Err(e) => {
            println!(
                "    {:<16} {}",
                theme::fg(name, t.text).bold(),
                theme::fg(&format!("[error: {}]", e), t.red),
            );
        }
    }
}

fn print_profile_line(name: &str, result: &Result<Profile>, t: &theme::Theme) {
    match result {
        Ok(p) => {
            let desc = p.meta.description.as_deref().unwrap_or("").to_string();
            let extends = profile::load_profile_extends(name)
                .map(|v| format!("extends {}", v.join(", ")))
                .unwrap_or_default();
            println!(
                "    {:<16} {:<42} {}",
                theme::fg(name, t.text).bold(),
                theme::fg(&desc, t.subtext),
                theme::fg(&extends, t.overlay),
            );
        }
        Err(e) => {
            println!(
                "    {:<16} {}",
                theme::fg(name, t.text).bold(),
                theme::fg(&format!("[error: {}]", e), t.red),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// nono profile show
// ---------------------------------------------------------------------------

pub(crate) fn cmd_show(args: ProfileShowArgs) -> Result<()> {
    // `--watch` polls the same profile name repeatedly, so the
    // user can edit the on-disk JSON and see the rendered
    // resolution refresh. Conflicts with json/compact/field at
    // the clap layer, so reaching this branch only ever runs
    // the human-readable render. Recurse with watch cleared so
    // the body stays one block and we don't have to
    // hand-extract the render logic.
    if let Some(spec) = args.watch.as_deref() {
        let interval = crate::session_commands::parse_duration_to_secs(spec)?;
        let dur = std::time::Duration::from_secs(interval);
        let mut iterations_remaining: Option<u64> = args.max_iterations;
        loop {
            print!("\x1b[2J\x1b[H");
            std::io::Write::flush(&mut std::io::stdout()).ok();
            println!(
                "nono profile show {}  -  refreshed {}  (every {}s)",
                &args.profile,
                chrono::Local::now().format("%H:%M:%S"),
                interval,
            );
            println!();
            // Clone the args, drop the watch fields so the body
            // doesn't recurse infinitely, and let the existing
            // render run end-to-end. load_profile_no_migrate
            // re-reads from disk on every call, so the rendered
            // output reflects the current file state.
            let mut once = args.clone();
            once.watch = None;
            once.max_iterations = None;
            cmd_show(once)?;

            if let Some(ref mut remaining) = iterations_remaining {
                *remaining = remaining.saturating_sub(1);
                if *remaining == 0 {
                    return Ok(());
                }
            }
            std::thread::sleep(dur);
        }
    }

    let raw_extends = profile::load_profile_extends(&args.profile);
    let profile = profile::load_profile_no_migrate(&args.profile)?;

    if matches!(args.format, Some(crate::cli::ProfileShowFormat::Manifest)) {
        let workdir = std::env::current_dir().map_err(|e| {
            NonoError::ConfigParse(format!("cannot determine working directory: {e}"))
        })?;
        let manifest = resolve_to_manifest(&profile, &workdir)?;
        let json = manifest.to_json()?;
        println!("{json}");
        return Ok(());
    }

    if args.json {
        let val = profile_to_json(&args.profile, &profile, &raw_extends);
        if let Some(ref field) = args.field {
            // Field extraction short-circuits the full-document render
            // — we want the raw value, not the document with one key
            // highlighted. `--compact` still controls how composite
            // sub-values get serialized.
            let extracted = extract_field_output(&val, field, args.compact)?;
            println!("{extracted}");
            return Ok(());
        }
        let rendered = if args.compact {
            to_json_compact(&val)?
        } else {
            to_json(&val)?
        };
        println!("{rendered}");
        return Ok(());
    }

    let t = theme::current();
    println!(
        "{}: profile '{}'",
        prefix(),
        theme::fg(&args.profile, t.text).bold()
    );

    // Meta
    if let Some(ref desc) = profile.meta.description {
        println!();
        println!(
            "  {}  {}",
            theme::fg("Description:", t.subtext),
            theme::fg(desc, t.text)
        );
    }
    if let Some(ref extends) = raw_extends {
        println!(
            "  {}      {}",
            theme::fg("Extends:", t.subtext),
            theme::fg(&extends.join(", "), t.text)
        );
    }

    // Security groups
    if !profile.security.groups.is_empty() {
        println!();
        println!("  {}", theme::fg("Security groups:", t.subtext).bold());
        for g in &profile.security.groups {
            println!("    {}", theme::fg(g, t.text));
        }
    }

    if !profile.security.allowed_commands.is_empty() {
        println!();
        println!(
            "  {}",
            theme::fg("Allowed commands (deprecated, startup-only):", t.subtext).bold()
        );
        for cmd in &profile.security.allowed_commands {
            println!("    {}", theme::fg(cmd, t.text));
        }
    }

    if let Some(mode) = &profile.security.signal_mode {
        println!("  {}   {:?}", theme::fg("Signal mode:", t.subtext), mode);
    }

    if let Some(mode) = &profile.security.process_info_mode {
        println!("  {} {:?}", theme::fg("Process info:", t.subtext), mode);
    }

    if let Some(mode) = &profile.security.ipc_mode {
        println!("  {}     {:?}", theme::fg("IPC mode:", t.subtext), mode);
    }

    if let Some(elev) = profile.security.capability_elevation {
        println!(
            "  {} {}",
            theme::fg("Capability elevation:", t.subtext),
            theme::fg(if elev { "enabled" } else { "disabled" }, t.text)
        );
    }
    if let Some(policy) = profile.security.wsl2_proxy_policy {
        println!(
            "  {} {}",
            theme::fg("WSL2 proxy policy:", t.subtext),
            theme::fg(&format!("{policy:?}"), t.text)
        );
    }

    // Filesystem
    let fs = &profile.filesystem;
    let has_fs = !fs.allow.is_empty()
        || !fs.read.is_empty()
        || !fs.write.is_empty()
        || !fs.allow_file.is_empty()
        || !fs.read_file.is_empty()
        || !fs.write_file.is_empty();

    if has_fs {
        println!();
        println!("  {}", theme::fg("Filesystem:", t.subtext).bold());
        print_fs_paths("allow (r+w)", &fs.allow, t, args.raw);
        print_fs_paths("read", &fs.read, t, args.raw);
        print_fs_paths("write", &fs.write, t, args.raw);
        print_fs_paths("allow_file (r+w)", &fs.allow_file, t, args.raw);
        print_fs_paths("read_file", &fs.read_file, t, args.raw);
        print_fs_paths("write_file", &fs.write_file, t, args.raw);
    }

    // Policy patches
    let pp = &profile.policy;
    let has_policy = !pp.exclude_groups.is_empty()
        || !pp.add_allow_read.is_empty()
        || !pp.add_allow_write.is_empty()
        || !pp.add_allow_readwrite.is_empty()
        || !pp.add_deny_access.is_empty()
        || !pp.add_deny_commands.is_empty()
        || !pp.override_deny.is_empty();

    if has_policy {
        println!();
        println!("  {}", theme::fg("Policy patches:", t.subtext).bold());
        if !pp.exclude_groups.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("exclude_groups", t.yellow),
                pp.exclude_groups.join(", ")
            );
        }
        print_fs_paths("add_allow_read", &pp.add_allow_read, t, args.raw);
        print_fs_paths("add_allow_write", &pp.add_allow_write, t, args.raw);
        print_fs_paths("add_allow_readwrite", &pp.add_allow_readwrite, t, args.raw);
        print_fs_paths("add_deny_access", &pp.add_deny_access, t, args.raw);
        if !pp.add_deny_commands.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("add_deny_commands (deprecated, startup-only)", t.yellow),
                pp.add_deny_commands.join(", ")
            );
        }
        if !pp.override_deny.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("override_deny", t.yellow),
                pp.override_deny.join(", ")
            );
        }
    }

    // Network
    let net = &profile.network;
    let has_net = net.block
        || net.resolved_network_profile().is_some()
        || !net.allow_domain.is_empty()
        || !net.resolved_credentials().is_empty()
        || !net.open_port.is_empty()
        || !net.listen_port.is_empty()
        || net.upstream_proxy.is_some()
        || !net.upstream_bypass.is_empty();

    if has_net {
        println!();
        println!("  {}", theme::fg("Network:", t.subtext).bold());
        if net.block {
            println!("    {}", theme::fg("network blocked", t.red));
        }
        if let Some(np) = net.resolved_network_profile() {
            println!(
                "    {}: {}",
                theme::fg("network_profile", t.subtext),
                theme::fg(np, t.text)
            );
        }
        if !net.allow_domain.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("allow_domain", t.subtext),
                net.allow_domain.join(", ")
            );
        }
        if !net.resolved_credentials().is_empty() {
            println!(
                "    {}: {}",
                theme::fg("credentials", t.subtext),
                net.resolved_credentials().join(", ")
            );
        }
        if !net.open_port.is_empty() {
            let ports: Vec<String> = net.open_port.iter().map(|p| p.to_string()).collect();
            println!(
                "    {}: {}",
                theme::fg("open_port", t.subtext),
                ports.join(", ")
            );
        }
        if !net.listen_port.is_empty() {
            let ports: Vec<String> = net.listen_port.iter().map(|p| p.to_string()).collect();
            println!(
                "    {}: {}",
                theme::fg("listen_port", t.subtext),
                ports.join(", ")
            );
        }
        if let Some(ref ep) = net.upstream_proxy {
            println!(
                "    {}: {}",
                theme::fg("upstream_proxy", t.subtext),
                theme::fg(ep, t.text)
            );
        }
        if !net.upstream_bypass.is_empty() {
            println!(
                "    {}: {}",
                theme::fg("upstream_bypass", t.subtext),
                net.upstream_bypass.join(", ")
            );
        }
    }

    // Workdir
    if profile.workdir.access != WorkdirAccess::None {
        println!();
        println!(
            "  {}  {:?}",
            theme::fg("Workdir access:", t.subtext).bold(),
            profile.workdir.access
        );
    }

    // Rollback
    let rb = &profile.rollback;
    if !rb.exclude_patterns.is_empty() || !rb.exclude_globs.is_empty() {
        println!();
        println!("  {}", theme::fg("Rollback exclusions:", t.subtext).bold());
        for p in &rb.exclude_patterns {
            println!("    {}", theme::fg(p, t.text));
        }
        for g in &rb.exclude_globs {
            println!(
                "    {} {}",
                theme::fg("glob:", t.overlay),
                theme::fg(g, t.text)
            );
        }
    }

    // Open URLs
    if let Some(ref urls) = profile.open_urls {
        println!();
        println!("  {}", theme::fg("Open URLs:", t.subtext).bold());
        if urls.allow_localhost {
            println!("    {}", theme::fg("localhost allowed", t.text));
        }
        for origin in &urls.allow_origins {
            println!("    {}", theme::fg(origin, t.text));
        }
    }

    // Raw Seatbelt rules — surfaced prominently so it is obvious a profile uses them.
    // Shown on all platforms so cross-platform auditing is possible.
    if !profile.unsafe_macos_seatbelt_rules.is_empty() {
        println!();
        println!(
            "  {}",
            theme::fg(
                "Raw Seatbelt rules (unsafe_macos_seatbelt_rules):",
                t.yellow
            )
            .bold()
        );
        for rule in &profile.unsafe_macos_seatbelt_rules {
            println!("    {}", theme::fg(rule, t.text));
        }
    }

    Ok(())
}

fn print_fs_paths(label: &str, paths: &[String], t: &theme::Theme, raw: bool) {
    if paths.is_empty() {
        return;
    }
    println!("    {}:", theme::fg(label, t.subtext));
    for p in paths {
        if raw {
            println!("      {}", theme::fg(p, t.text));
        } else {
            match policy::expand_path(p) {
                Ok(expanded) => {
                    let exp_str = expanded.display().to_string();
                    if exp_str == *p {
                        println!("      {}", theme::fg(p, t.text));
                    } else {
                        println!(
                            "      {:<36} -> {}",
                            theme::fg(p, t.text),
                            theme::fg(&exp_str, t.subtext)
                        );
                    }
                }
                Err(_) => {
                    println!("      {}", theme::fg(p, t.text));
                }
            }
        }
    }
}

fn profile_to_json(
    name: &str,
    profile: &Profile,
    raw_extends: &Option<Vec<String>>,
) -> serde_json::Value {
    let mut val = serde_json::json!({
        "name": name,
        "description": profile.meta.description.as_deref().unwrap_or(""),
        "extends": raw_extends.as_ref().map(|v| serde_json::json!(v)).unwrap_or(serde_json::Value::Null),
    });

    // Security
    val["security"] = serde_json::json!({
        "groups": profile.security.groups,
        "allowed_commands": profile.security.allowed_commands,
        "signal_mode": format!("{:?}", profile.security.signal_mode),
        "process_info_mode": format!("{:?}", profile.security.process_info_mode),
        "ipc_mode": format!("{:?}", profile.security.ipc_mode),
        "capability_elevation": profile.security.capability_elevation,
        "wsl2_proxy_policy": format!("{:?}", profile.security.wsl2_proxy_policy),
    });

    // Filesystem
    val["filesystem"] = serde_json::json!({
        "allow": profile.filesystem.allow,
        "read": profile.filesystem.read,
        "write": profile.filesystem.write,
        "allow_file": profile.filesystem.allow_file,
        "read_file": profile.filesystem.read_file,
        "write_file": profile.filesystem.write_file,
    });

    // Policy patches
    val["policy"] = serde_json::json!({
        "exclude_groups": profile.policy.exclude_groups,
        "add_allow_read": profile.policy.add_allow_read,
        "add_allow_write": profile.policy.add_allow_write,
        "add_allow_readwrite": profile.policy.add_allow_readwrite,
        "add_deny_access": profile.policy.add_deny_access,
        "add_deny_commands": profile.policy.add_deny_commands,
        "override_deny": profile.policy.override_deny,
    });

    // Network
    val["network"] = serde_json::json!({
        "block": profile.network.block,
        "network_profile": profile.network.resolved_network_profile(),
        "allow_domain": profile.network.allow_domain,
        "credentials": profile.network.resolved_credentials(),
        "open_port": profile.network.open_port,
        "listen_port": profile.network.listen_port,
        "upstream_proxy": profile.network.upstream_proxy,
        "upstream_bypass": profile.network.upstream_bypass,
    });

    // Workdir
    val["workdir"] = serde_json::json!({
        "access": format!("{:?}", profile.workdir.access),
    });

    // Rollback
    val["rollback"] = serde_json::json!({
        "exclude_patterns": profile.rollback.exclude_patterns,
        "exclude_globs": profile.rollback.exclude_globs,
    });

    // Env credentials
    if !profile.env_credentials.mappings.is_empty() {
        val["env_credentials"] = serde_json::json!(profile.env_credentials.mappings);
    }

    // Hooks
    if !profile.hooks.hooks.is_empty() {
        let hooks: serde_json::Map<String, serde_json::Value> = profile
            .hooks
            .hooks
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    serde_json::json!({
                        "event": v.event,
                        "matcher": v.matcher,
                        "script": v.script,
                    }),
                )
            })
            .collect();
        val["hooks"] = serde_json::Value::Object(hooks);
    }

    // Open URLs
    if let Some(ref urls) = profile.open_urls {
        val["open_urls"] = serde_json::json!({
            "allow_origins": urls.allow_origins,
            "allow_localhost": urls.allow_localhost,
        });
    }

    // Allow launch services
    if let Some(als) = profile.allow_launch_services {
        val["allow_launch_services"] = serde_json::json!(als);
    }

    if let Some(ag) = profile.allow_gpu {
        val["allow_gpu"] = serde_json::json!(ag);
    }

    if !profile.unsafe_macos_seatbelt_rules.is_empty() {
        val["unsafe_macos_seatbelt_rules"] = serde_json::json!(profile.unsafe_macos_seatbelt_rules);
    }

    val
}

// ---------------------------------------------------------------------------
// nono profile diff
// ---------------------------------------------------------------------------

pub(crate) fn cmd_diff(args: ProfileDiffArgs) -> Result<()> {
    // `--watch` polls both profiles repeatedly so users can edit
    // one and watch the diff refresh. Conflicts with json/compact/
    // field/quiet at the clap layer, so reaching this branch only
    // ever runs the human-readable diff.
    if let Some(spec) = args.watch.as_deref() {
        let interval = crate::session_commands::parse_duration_to_secs(spec)?;
        let dur = std::time::Duration::from_secs(interval);
        let mut iterations_remaining: Option<u64> = args.max_iterations;
        loop {
            print!("\x1b[2J\x1b[H");
            std::io::Write::flush(&mut std::io::stdout()).ok();
            println!(
                "nono profile diff {} {}  -  refreshed {}  (every {}s)",
                &args.profile1,
                &args.profile2,
                chrono::Local::now().format("%H:%M:%S"),
                interval,
            );
            println!();
            // Recurse with watch cleared so the existing diff
            // body runs end-to-end. load_profile_no_migrate
            // re-reads from disk on each call.
            let mut once = args.clone();
            once.watch = None;
            once.max_iterations = None;
            cmd_diff(once)?;

            if let Some(ref mut remaining) = iterations_remaining {
                *remaining = remaining.saturating_sub(1);
                if *remaining == 0 {
                    return Ok(());
                }
            }
            std::thread::sleep(dur);
        }
    }

    let p1 = profile::load_profile_no_migrate(&args.profile1)?;
    let p2 = profile::load_profile_no_migrate(&args.profile2)?;

    if args.quiet {
        // Compare via canonical JSON serialization. `Profile` only
        // derives `Serialize`, not `PartialEq`, so a JSON-value
        // round-trip is the cheapest "are these equal?" check
        // available without a deeper refactor — and it captures
        // exactly the surface that the human and JSON diffs
        // already operate on, so semantics stay aligned.
        let p1_json = serde_json::to_value(&p1).map_err(|e| {
            NonoError::ProfileParse(format!("failed to serialize {}: {e}", args.profile1))
        })?;
        let p2_json = serde_json::to_value(&p2).map_err(|e| {
            NonoError::ProfileParse(format!("failed to serialize {}: {e}", args.profile2))
        })?;
        std::process::exit(if p1_json == p2_json { 0 } else { 1 });
    }

    if args.json {
        let val = diff_to_json(&args.profile1, &args.profile2, &p1, &p2);
        if let Some(ref field) = args.field {
            // Same shell-friendly extraction as `show --field` —
            // typo'd paths surface as a `ProfileParse` error rather
            // than empty output. See `extract_field_output` for
            // the jq-r semantics.
            let extracted = extract_field_output(&val, field, args.compact)?;
            println!("{extracted}");
            return Ok(());
        }
        let rendered = if args.compact {
            to_json_compact(&val)?
        } else {
            to_json(&val)?
        };
        println!("{rendered}");
        return Ok(());
    }

    let t = theme::current();
    println!(
        "{}: diff '{}' vs '{}'",
        prefix(),
        theme::fg(&args.profile1, t.text).bold(),
        theme::fg(&args.profile2, t.text).bold()
    );

    let mut any_diff = false;

    // Groups
    let g1: BTreeSet<&str> = p1.security.groups.iter().map(|s| s.as_str()).collect();
    let g2: BTreeSet<&str> = p2.security.groups.iter().map(|s| s.as_str()).collect();
    let added_groups: BTreeSet<&&str> = g2.difference(&g1).collect();
    let removed_groups: BTreeSet<&&str> = g1.difference(&g2).collect();

    if !added_groups.is_empty() || !removed_groups.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Groups", t.subtext).bold());
        for g in &removed_groups {
            println!("    {} {}", theme::fg("-", t.red), theme::fg(g, t.red));
        }
        for g in &added_groups {
            println!("    {} {}", theme::fg("+", t.green), theme::fg(g, t.green));
        }
    }

    // Filesystem
    let fs_diffs = diff_string_vecs(&[
        ("allow", &p1.filesystem.allow, &p2.filesystem.allow),
        ("read", &p1.filesystem.read, &p2.filesystem.read),
        ("write", &p1.filesystem.write, &p2.filesystem.write),
        (
            "allow_file",
            &p1.filesystem.allow_file,
            &p2.filesystem.allow_file,
        ),
        (
            "read_file",
            &p1.filesystem.read_file,
            &p2.filesystem.read_file,
        ),
        (
            "write_file",
            &p1.filesystem.write_file,
            &p2.filesystem.write_file,
        ),
    ]);

    if !fs_diffs.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Filesystem", t.subtext).bold());
        for (label, sign, path) in &fs_diffs {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(path, color)
            );
        }
    }

    // Policy patches
    let pp_diffs = diff_string_vecs(&[
        (
            "exclude_groups",
            &p1.policy.exclude_groups,
            &p2.policy.exclude_groups,
        ),
        (
            "add_allow_read",
            &p1.policy.add_allow_read,
            &p2.policy.add_allow_read,
        ),
        (
            "add_allow_write",
            &p1.policy.add_allow_write,
            &p2.policy.add_allow_write,
        ),
        (
            "add_allow_readwrite",
            &p1.policy.add_allow_readwrite,
            &p2.policy.add_allow_readwrite,
        ),
        (
            "add_deny_access",
            &p1.policy.add_deny_access,
            &p2.policy.add_deny_access,
        ),
        (
            "add_deny_commands",
            &p1.policy.add_deny_commands,
            &p2.policy.add_deny_commands,
        ),
        (
            "override_deny",
            &p1.policy.override_deny,
            &p2.policy.override_deny,
        ),
    ]);

    if !pp_diffs.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Policy patches", t.subtext).bold());
        for (label, sign, val) in &pp_diffs {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(val, color)
            );
        }
    }

    // Security scalar fields
    any_diff |= diff_scalar_option(
        "capability_elevation",
        &p1.security.capability_elevation.map(|v| format!("{v}")),
        &p2.security.capability_elevation.map(|v| format!("{v}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "wsl2_proxy_policy",
        &p1.security.wsl2_proxy_policy.map(|v| format!("{v:?}")),
        &p2.security.wsl2_proxy_policy.map(|v| format!("{v:?}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "signal_mode",
        &p1.security.signal_mode.map(|v| format!("{v:?}")),
        &p2.security.signal_mode.map(|v| format!("{v:?}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "process_info_mode",
        &p1.security.process_info_mode.map(|v| format!("{v:?}")),
        &p2.security.process_info_mode.map(|v| format!("{v:?}")),
        t,
    );
    any_diff |= diff_scalar_option(
        "ipc_mode",
        &p1.security.ipc_mode.map(|v| format!("{v:?}")),
        &p2.security.ipc_mode.map(|v| format!("{v:?}")),
        t,
    );

    // Network
    let mut net_diffs: Vec<(String, String)> = Vec::new();
    if p1.network.block != p2.network.block {
        net_diffs.push((
            format!("- block: {}", p1.network.block),
            format!("+ block: {}", p2.network.block),
        ));
    }
    let np1 = p1.network.resolved_network_profile().unwrap_or("");
    let np2 = p2.network.resolved_network_profile().unwrap_or("");
    if np1 != np2 {
        if !np1.is_empty() {
            net_diffs.push((format!("- network_profile: {np1}"), String::new()));
        }
        if !np2.is_empty() {
            net_diffs.push((String::new(), format!("+ network_profile: {np2}")));
        }
    }

    let net_vec_diffs = diff_string_vecs(&[
        (
            "allow_domain",
            &p1.network.allow_domain,
            &p2.network.allow_domain,
        ),
        (
            "credentials",
            p1.network.resolved_credentials(),
            p2.network.resolved_credentials(),
        ),
        (
            "upstream_bypass",
            &p1.network.upstream_bypass,
            &p2.network.upstream_bypass,
        ),
    ]);

    let port1: Vec<String> = p1.network.open_port.iter().map(|p| p.to_string()).collect();
    let port2: Vec<String> = p2.network.open_port.iter().map(|p| p.to_string()).collect();
    let port_diffs = diff_string_vecs(&[("open_port", &port1, &port2)]);
    let listen1: Vec<String> = p1
        .network
        .listen_port
        .iter()
        .map(|p| p.to_string())
        .collect();
    let listen2: Vec<String> = p2
        .network
        .listen_port
        .iter()
        .map(|p| p.to_string())
        .collect();
    let listen_diffs = diff_string_vecs(&[("listen_port", &listen1, &listen2)]);

    if !net_diffs.is_empty()
        || !net_vec_diffs.is_empty()
        || !port_diffs.is_empty()
        || !listen_diffs.is_empty()
    {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Network", t.subtext).bold());
        for (rem, add) in &net_diffs {
            if !rem.is_empty() {
                println!("    {}", theme::fg(rem, t.red));
            }
            if !add.is_empty() {
                println!("    {}", theme::fg(add, t.green));
            }
        }
        for (label, sign, val) in net_vec_diffs
            .iter()
            .chain(port_diffs.iter())
            .chain(listen_diffs.iter())
        {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(val, color)
            );
        }
    }

    any_diff |= diff_scalar_option(
        "upstream_proxy",
        &p1.network.upstream_proxy,
        &p2.network.upstream_proxy,
        t,
    );

    // Workdir
    if p1.workdir.access != p2.workdir.access {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Workdir", t.subtext).bold());
        println!(
            "    {}",
            theme::fg(&format!("- access: {:?}", p1.workdir.access), t.red)
        );
        println!(
            "    {}",
            theme::fg(&format!("+ access: {:?}", p2.workdir.access), t.green)
        );
    }

    // Allowed commands
    let cmd1: BTreeSet<&str> = p1
        .security
        .allowed_commands
        .iter()
        .map(|s| s.as_str())
        .collect();
    let cmd2: BTreeSet<&str> = p2
        .security
        .allowed_commands
        .iter()
        .map(|s| s.as_str())
        .collect();
    let added_cmds: BTreeSet<&&str> = cmd2.difference(&cmd1).collect();
    let removed_cmds: BTreeSet<&&str> = cmd1.difference(&cmd2).collect();

    if !added_cmds.is_empty() || !removed_cmds.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Allowed commands", t.subtext).bold());
        for c in &removed_cmds {
            println!("    {} {}", theme::fg("-", t.red), theme::fg(c, t.red));
        }
        for c in &added_cmds {
            println!("    {} {}", theme::fg("+", t.green), theme::fg(c, t.green));
        }
    }

    // Rollback
    let rb_diffs = diff_string_vecs(&[
        (
            "exclude_patterns",
            &p1.rollback.exclude_patterns,
            &p2.rollback.exclude_patterns,
        ),
        (
            "exclude_globs",
            &p1.rollback.exclude_globs,
            &p2.rollback.exclude_globs,
        ),
    ]);
    if !rb_diffs.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Rollback", t.subtext).bold());
        for (label, sign, val) in &rb_diffs {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(val, color)
            );
        }
    }

    // Open URLs
    let ou1_origins: Vec<String> = p1
        .open_urls
        .as_ref()
        .map(|u| u.allow_origins.clone())
        .unwrap_or_default();
    let ou2_origins: Vec<String> = p2
        .open_urls
        .as_ref()
        .map(|u| u.allow_origins.clone())
        .unwrap_or_default();
    let ou_diffs = diff_string_vecs(&[("allow_origins", &ou1_origins, &ou2_origins)]);
    let ou1_localhost = p1.open_urls.as_ref().is_some_and(|u| u.allow_localhost);
    let ou2_localhost = p2.open_urls.as_ref().is_some_and(|u| u.allow_localhost);

    if !ou_diffs.is_empty() || ou1_localhost != ou2_localhost {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Open URLs", t.subtext).bold());
        for (label, sign, val) in &ou_diffs {
            let color = if *sign == "+" { t.green } else { t.red };
            println!(
                "    {} {} {}",
                theme::fg(sign, color),
                theme::fg(label, t.subtext),
                theme::fg(val, color)
            );
        }
        if ou1_localhost != ou2_localhost {
            println!(
                "    {}",
                theme::fg(&format!("- allow_localhost: {ou1_localhost}"), t.red)
            );
            println!(
                "    {}",
                theme::fg(&format!("+ allow_localhost: {ou2_localhost}"), t.green)
            );
        }
    }

    // Allow launch services
    any_diff |= diff_scalar_option(
        "allow_launch_services",
        &p1.allow_launch_services.map(|v| format!("{v}")),
        &p2.allow_launch_services.map(|v| format!("{v}")),
        t,
    );

    any_diff |= diff_scalar_option(
        "allow_gpu",
        &p1.allow_gpu.map(|v| format!("{v}")),
        &p2.allow_gpu.map(|v| format!("{v}")),
        t,
    );

    // Env credentials
    let ec1: BTreeSet<(&String, &String)> = p1.env_credentials.mappings.iter().collect();
    let ec2: BTreeSet<(&String, &String)> = p2.env_credentials.mappings.iter().collect();
    let ec_added: BTreeSet<&(&String, &String)> = ec2.difference(&ec1).collect();
    let ec_removed: BTreeSet<&(&String, &String)> = ec1.difference(&ec2).collect();
    if !ec_added.is_empty() || !ec_removed.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Env credentials", t.subtext).bold());
        for (k, v) in &ec_removed {
            println!(
                "    {} {} -> {}",
                theme::fg("-", t.red),
                theme::fg(k, t.red),
                theme::fg(v, t.red)
            );
        }
        for (k, v) in &ec_added {
            println!(
                "    {} {} -> {}",
                theme::fg("+", t.green),
                theme::fg(k, t.green),
                theme::fg(v, t.green)
            );
        }
    }

    // Hooks
    let h1: BTreeSet<&String> = p1.hooks.hooks.keys().collect();
    let h2: BTreeSet<&String> = p2.hooks.hooks.keys().collect();
    let hooks_added: BTreeSet<&&String> = h2.difference(&h1).collect();
    let hooks_removed: BTreeSet<&&String> = h1.difference(&h2).collect();
    // Check for hooks present in both but with different config
    let hooks_changed: Vec<&String> = h1
        .intersection(&h2)
        .filter(|k| {
            let a = &p1.hooks.hooks[**k];
            let b = &p2.hooks.hooks[**k];
            a.event != b.event || a.matcher != b.matcher || a.script != b.script
        })
        .copied()
        .collect();
    if !hooks_added.is_empty() || !hooks_removed.is_empty() || !hooks_changed.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Hooks", t.subtext).bold());
        for h in &hooks_removed {
            println!("    {} {}", theme::fg("-", t.red), theme::fg(h, t.red));
        }
        for h in &hooks_added {
            println!("    {} {}", theme::fg("+", t.green), theme::fg(h, t.green));
        }
        for h in &hooks_changed {
            println!(
                "    {} {} (changed)",
                theme::fg("~", t.yellow),
                theme::fg(h, t.yellow)
            );
        }
    }

    // Custom credentials
    let cc1: BTreeSet<&String> = p1.network.custom_credentials.keys().collect();
    let cc2: BTreeSet<&String> = p2.network.custom_credentials.keys().collect();
    let cc_added: BTreeSet<&&String> = cc2.difference(&cc1).collect();
    let cc_removed: BTreeSet<&&String> = cc1.difference(&cc2).collect();
    let cc_changed: Vec<&String> = cc1
        .intersection(&cc2)
        .filter(|k| p1.network.custom_credentials[**k] != p2.network.custom_credentials[**k])
        .copied()
        .collect();
    if !cc_added.is_empty() || !cc_removed.is_empty() || !cc_changed.is_empty() {
        any_diff = true;
        println!();
        println!("  {}:", theme::fg("Custom credentials", t.subtext).bold());
        for c in &cc_removed {
            println!("    {} {}", theme::fg("-", t.red), theme::fg(c, t.red));
        }
        for c in &cc_added {
            println!("    {} {}", theme::fg("+", t.green), theme::fg(c, t.green));
        }
        for c in &cc_changed {
            let old = &p1.network.custom_credentials[*c];
            let new = &p2.network.custom_credentials[*c];
            println!(
                "    {} {} (changed)",
                theme::fg("~", t.yellow),
                theme::fg(c, t.yellow)
            );
            if old.upstream != new.upstream {
                println!(
                    "      {} upstream: {}",
                    theme::fg("-", t.red),
                    theme::fg(&old.upstream, t.red)
                );
                println!(
                    "      {} upstream: {}",
                    theme::fg("+", t.green),
                    theme::fg(&new.upstream, t.green)
                );
            }
            if old.credential_key != new.credential_key {
                let old_key = old.credential_key.as_deref().unwrap_or("<none>");
                let new_key = new.credential_key.as_deref().unwrap_or("<none>");
                println!(
                    "      {} credential_key: {}",
                    theme::fg("-", t.red),
                    theme::fg(old_key, t.red)
                );
                println!(
                    "      {} credential_key: {}",
                    theme::fg("+", t.green),
                    theme::fg(new_key, t.green)
                );
            }
            if old.inject_mode != new.inject_mode {
                println!(
                    "      {} inject_mode: {:?}",
                    theme::fg("-", t.red),
                    old.inject_mode
                );
                println!(
                    "      {} inject_mode: {:?}",
                    theme::fg("+", t.green),
                    new.inject_mode
                );
            }
            if old.inject_header != new.inject_header {
                println!(
                    "      {} inject_header: {}",
                    theme::fg("-", t.red),
                    theme::fg(&old.inject_header, t.red)
                );
                println!(
                    "      {} inject_header: {}",
                    theme::fg("+", t.green),
                    theme::fg(&new.inject_header, t.green)
                );
            }
            if old.credential_format != new.credential_format {
                println!(
                    "      {} credential_format: {}",
                    theme::fg("-", t.red),
                    theme::fg(&old.credential_format, t.red)
                );
                println!(
                    "      {} credential_format: {}",
                    theme::fg("+", t.green),
                    theme::fg(&new.credential_format, t.green)
                );
            }
            if old.path_pattern != new.path_pattern {
                println!(
                    "      {} path_pattern: {:?}",
                    theme::fg("-", t.red),
                    old.path_pattern
                );
                println!(
                    "      {} path_pattern: {:?}",
                    theme::fg("+", t.green),
                    new.path_pattern
                );
            }
            if old.path_replacement != new.path_replacement {
                println!(
                    "      {} path_replacement: {:?}",
                    theme::fg("-", t.red),
                    old.path_replacement
                );
                println!(
                    "      {} path_replacement: {:?}",
                    theme::fg("+", t.green),
                    new.path_replacement
                );
            }
            if old.query_param_name != new.query_param_name {
                println!(
                    "      {} query_param_name: {:?}",
                    theme::fg("-", t.red),
                    old.query_param_name
                );
                println!(
                    "      {} query_param_name: {:?}",
                    theme::fg("+", t.green),
                    new.query_param_name
                );
            }
            if old.env_var != new.env_var {
                println!("      {} env_var: {:?}", theme::fg("-", t.red), old.env_var);
                println!(
                    "      {} env_var: {:?}",
                    theme::fg("+", t.green),
                    new.env_var
                );
            }
        }
    }

    if !any_diff {
        println!();
        println!("  {}", theme::fg("(no differences)", t.subtext));
    }

    Ok(())
}

/// Print a diff for an optional scalar field. Returns true if there was a difference.
fn diff_scalar_option(
    label: &str,
    v1: &Option<String>,
    v2: &Option<String>,
    t: &theme::Theme,
) -> bool {
    if v1 == v2 {
        return false;
    }
    println!();
    println!("  {}:", theme::fg(label, t.subtext).bold());
    if let Some(ref old) = v1 {
        println!("    {}", theme::fg(&format!("- {old}"), t.red));
    }
    if let Some(ref new) = v2 {
        println!("    {}", theme::fg(&format!("+ {new}"), t.green));
    }
    true
}

fn diff_string_vecs<'a>(
    pairs: &[(&'a str, &[String], &[String])],
) -> Vec<(&'a str, &'static str, String)> {
    let mut result = Vec::new();
    for (label, v1, v2) in pairs {
        let s1: BTreeSet<&str> = v1.iter().map(|s| s.as_str()).collect();
        let s2: BTreeSet<&str> = v2.iter().map(|s| s.as_str()).collect();
        for removed in s1.difference(&s2) {
            result.push((*label, "-", removed.to_string()));
        }
        for added in s2.difference(&s1) {
            result.push((*label, "+", added.to_string()));
        }
    }
    result
}

fn diff_to_json(name1: &str, name2: &str, p1: &Profile, p2: &Profile) -> serde_json::Value {
    let g1: BTreeSet<&str> = p1.security.groups.iter().map(|s| s.as_str()).collect();
    let g2: BTreeSet<&str> = p2.security.groups.iter().map(|s| s.as_str()).collect();

    let groups_added: Vec<&str> = g2.difference(&g1).copied().collect();
    let groups_removed: Vec<&str> = g1.difference(&g2).copied().collect();

    let diff_vec = |v1: &[String], v2: &[String]| -> serde_json::Value {
        let s1: BTreeSet<&str> = v1.iter().map(|s| s.as_str()).collect();
        let s2: BTreeSet<&str> = v2.iter().map(|s| s.as_str()).collect();
        let added: Vec<&str> = s2.difference(&s1).copied().collect();
        let removed: Vec<&str> = s1.difference(&s2).copied().collect();
        serde_json::json!({ "added": added, "removed": removed })
    };

    let ou1 = p1.open_urls.as_ref();
    let ou2 = p2.open_urls.as_ref();

    serde_json::json!({
        "profile1": name1,
        "profile2": name2,
        "groups": {
            "added": groups_added,
            "removed": groups_removed,
        },
        "allowed_commands": diff_vec(
            &p1.security.allowed_commands,
            &p2.security.allowed_commands,
        ),
        "capability_elevation": {
            "profile1": p1.security.capability_elevation,
            "profile2": p2.security.capability_elevation,
            "changed": p1.security.capability_elevation != p2.security.capability_elevation,
        },
        "wsl2_proxy_policy": {
            "profile1": format!("{:?}", p1.security.wsl2_proxy_policy),
            "profile2": format!("{:?}", p2.security.wsl2_proxy_policy),
            "changed": p1.security.wsl2_proxy_policy != p2.security.wsl2_proxy_policy,
        },
        "filesystem": diff_fs_json(&p1.filesystem, &p2.filesystem),
        "workdir": {
            "profile1": format!("{:?}", p1.workdir.access),
            "profile2": format!("{:?}", p2.workdir.access),
            "changed": p1.workdir.access != p2.workdir.access,
        },
        "network": {
            "block": {
                "profile1": p1.network.block,
                "profile2": p2.network.block,
                "changed": p1.network.block != p2.network.block,
            },
            "network_profile": {
                "profile1": p1.network.resolved_network_profile(),
                "profile2": p2.network.resolved_network_profile(),
                "changed": p1.network.resolved_network_profile() != p2.network.resolved_network_profile(),
            },
            "allow_domain": diff_vec(&p1.network.allow_domain, &p2.network.allow_domain),
            "credentials": diff_vec(p1.network.resolved_credentials(), p2.network.resolved_credentials()),
            "open_port": {
                "profile1": p1.network.open_port,
                "profile2": p2.network.open_port,
                "changed": p1.network.open_port != p2.network.open_port,
            },
            "listen_port": {
                "profile1": p1.network.listen_port,
                "profile2": p2.network.listen_port,
                "changed": p1.network.listen_port != p2.network.listen_port,
            },
            "upstream_proxy": {
                "profile1": p1.network.upstream_proxy,
                "profile2": p2.network.upstream_proxy,
                "changed": p1.network.upstream_proxy != p2.network.upstream_proxy,
            },
            "upstream_bypass": diff_vec(
                &p1.network.upstream_bypass,
                &p2.network.upstream_bypass,
            ),
            "custom_credentials": diff_custom_credentials_json(
                &p1.network.custom_credentials,
                &p2.network.custom_credentials,
            ),
        },
        "env_credentials": {
            "profile1": p1.env_credentials.mappings,
            "profile2": p2.env_credentials.mappings,
            "changed": p1.env_credentials.mappings != p2.env_credentials.mappings,
        },
        "hooks": diff_hooks_json(&p1.hooks.hooks, &p2.hooks.hooks),
        "rollback": {
            "exclude_patterns": diff_vec(&p1.rollback.exclude_patterns, &p2.rollback.exclude_patterns),
            "exclude_globs": diff_vec(&p1.rollback.exclude_globs, &p2.rollback.exclude_globs),
        },
        "open_urls": {
            "allow_origins": diff_vec(
                &ou1.map(|u| u.allow_origins.clone()).unwrap_or_default(),
                &ou2.map(|u| u.allow_origins.clone()).unwrap_or_default(),
            ),
            "allow_localhost": {
                "profile1": ou1.is_some_and(|u| u.allow_localhost),
                "profile2": ou2.is_some_and(|u| u.allow_localhost),
                "changed": ou1.is_some_and(|u| u.allow_localhost) != ou2.is_some_and(|u| u.allow_localhost),
            },
        },
        "allow_launch_services": {
            "profile1": p1.allow_launch_services,
            "profile2": p2.allow_launch_services,
            "changed": p1.allow_launch_services != p2.allow_launch_services,
        },
        "allow_gpu": {
            "profile1": p1.allow_gpu,
            "profile2": p2.allow_gpu,
            "changed": p1.allow_gpu != p2.allow_gpu,
        },
    })
}

fn diff_fs_json(
    fs1: &profile::FilesystemConfig,
    fs2: &profile::FilesystemConfig,
) -> serde_json::Value {
    let diff_vec = |v1: &[String], v2: &[String]| -> serde_json::Value {
        let s1: BTreeSet<&str> = v1.iter().map(|s| s.as_str()).collect();
        let s2: BTreeSet<&str> = v2.iter().map(|s| s.as_str()).collect();
        let added: Vec<&str> = s2.difference(&s1).copied().collect();
        let removed: Vec<&str> = s1.difference(&s2).copied().collect();
        serde_json::json!({ "added": added, "removed": removed })
    };

    serde_json::json!({
        "allow": diff_vec(&fs1.allow, &fs2.allow),
        "read": diff_vec(&fs1.read, &fs2.read),
        "write": diff_vec(&fs1.write, &fs2.write),
        "allow_file": diff_vec(&fs1.allow_file, &fs2.allow_file),
        "read_file": diff_vec(&fs1.read_file, &fs2.read_file),
        "write_file": diff_vec(&fs1.write_file, &fs2.write_file),
    })
}

fn diff_hooks_json(
    h1: &std::collections::HashMap<String, profile::HookConfig>,
    h2: &std::collections::HashMap<String, profile::HookConfig>,
) -> serde_json::Value {
    let added: Vec<&String> = h2.keys().filter(|k| !h1.contains_key(*k)).collect();
    let removed: Vec<&String> = h1.keys().filter(|k| !h2.contains_key(*k)).collect();
    let changed: Vec<&String> = h1
        .keys()
        .filter(|k| {
            h2.get(*k).is_some_and(|v2| {
                let v1 = &h1[*k];
                v1.event != v2.event || v1.matcher != v2.matcher || v1.script != v2.script
            })
        })
        .collect();

    let mut changed_details = serde_json::Map::new();
    for k in &changed {
        let old = &h1[*k];
        let new = &h2[*k];
        let mut detail = serde_json::Map::new();
        if old.event != new.event {
            detail.insert(
                "event".into(),
                serde_json::json!({"profile1": old.event, "profile2": new.event}),
            );
        }
        if old.matcher != new.matcher {
            detail.insert(
                "matcher".into(),
                serde_json::json!({"profile1": old.matcher, "profile2": new.matcher}),
            );
        }
        if old.script != new.script {
            detail.insert(
                "script".into(),
                serde_json::json!({"profile1": old.script, "profile2": new.script}),
            );
        }
        changed_details.insert((*k).clone(), serde_json::Value::Object(detail));
    }

    serde_json::json!({
        "added": added,
        "removed": removed,
        "changed": changed_details,
    })
}

fn diff_custom_credentials_json(
    cc1: &std::collections::HashMap<String, profile::CustomCredentialDef>,
    cc2: &std::collections::HashMap<String, profile::CustomCredentialDef>,
) -> serde_json::Value {
    let added: Vec<&String> = cc2.keys().filter(|k| !cc1.contains_key(*k)).collect();
    let removed: Vec<&String> = cc1.keys().filter(|k| !cc2.contains_key(*k)).collect();
    let changed: Vec<&String> = cc1
        .keys()
        .filter(|k| cc2.get(*k).is_some_and(|v2| cc1[*k] != *v2))
        .collect();

    let mut changed_details = serde_json::Map::new();
    for k in &changed {
        let old = &cc1[*k];
        let new = &cc2[*k];
        let mut detail = serde_json::Map::new();
        if old.upstream != new.upstream {
            detail.insert(
                "upstream".into(),
                serde_json::json!({"profile1": old.upstream, "profile2": new.upstream}),
            );
        }
        if old.credential_key != new.credential_key {
            detail.insert(
                "credential_key".into(),
                serde_json::json!({"profile1": old.credential_key, "profile2": new.credential_key}),
            );
        }
        if old.inject_mode != new.inject_mode {
            detail.insert(
                "inject_mode".into(),
                serde_json::json!({"profile1": format!("{:?}", old.inject_mode), "profile2": format!("{:?}", new.inject_mode)}),
            );
        }
        if old.inject_header != new.inject_header {
            detail.insert(
                "inject_header".into(),
                serde_json::json!({"profile1": old.inject_header, "profile2": new.inject_header}),
            );
        }
        if old.credential_format != new.credential_format {
            detail.insert(
                "credential_format".into(),
                serde_json::json!({"profile1": old.credential_format, "profile2": new.credential_format}),
            );
        }
        if old.path_pattern != new.path_pattern {
            detail.insert(
                "path_pattern".into(),
                serde_json::json!({"profile1": old.path_pattern, "profile2": new.path_pattern}),
            );
        }
        if old.path_replacement != new.path_replacement {
            detail.insert(
                "path_replacement".into(),
                serde_json::json!({"profile1": old.path_replacement, "profile2": new.path_replacement}),
            );
        }
        if old.query_param_name != new.query_param_name {
            detail.insert(
                "query_param_name".into(),
                serde_json::json!({"profile1": old.query_param_name, "profile2": new.query_param_name}),
            );
        }
        if old.env_var != new.env_var {
            detail.insert(
                "env_var".into(),
                serde_json::json!({"profile1": old.env_var, "profile2": new.env_var}),
            );
        }
        changed_details.insert((*k).clone(), serde_json::Value::Object(detail));
    }

    serde_json::json!({
        "added": added,
        "removed": removed,
        "changed": changed_details,
    })
}

// ---------------------------------------------------------------------------
// nono profile validate
// ---------------------------------------------------------------------------

fn classify_profile_error(e: &NonoError) -> &'static str {
    match e {
        NonoError::ProfileParse(msg)
            if msg.starts_with("expected")
                || msg.contains("line ")
                || msg.contains("column ")
                || msg.contains("EOF") =>
        {
            "JSON syntax error"
        }
        NonoError::ProfileParse(_) => "Profile error",
        NonoError::ProfileRead { .. } => "File read error",
        NonoError::ProfileInheritance(_) => "Inheritance error",
        NonoError::ProfileNotFound(_) => "Profile not found",
        _ => "Error",
    }
}

/// Resolve a `nono profile validate` target into a filesystem path.
///
/// Clap parses the positional argument as a `PathBuf`, so a user who
/// types `nono profile validate claude-docs` arrives here with the bare
/// name. We mirror the same precedence as `--profile`: the literal path
/// wins if it exists, otherwise look up the user profile dir, then the
/// installed pack store, then the `.json` form of the bare name. If
/// nothing matches, return the original input so the existing
/// not-found error path produces a readable message.
fn resolve_validate_target(input: &std::path::Path) -> std::path::PathBuf {
    if input.exists() {
        return input.to_path_buf();
    }
    let Some(name) = input.to_str() else {
        return input.to_path_buf();
    };
    if name.contains('/') || name.ends_with(".json") {
        return input.to_path_buf();
    }
    if let Ok(p) = profile::get_user_profile_path(name) {
        if p.exists() {
            return p;
        }
    }
    if let Some(p) = profile::find_pack_store_profile(name) {
        return p;
    }
    input.to_path_buf()
}

pub(crate) fn cmd_validate(args: ProfileValidateArgs) -> Result<()> {
    let pol = policy::load_embedded_policy()?;
    let mut errors: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    // Resolve the input. Clap parses any bare token as a `PathBuf`, so a
    // user typing `nono profile validate claude-docs` lands here with
    // `args.file = PathBuf::from("claude-docs")`. If that doesn't exist as
    // a file, treat it as a profile name and look it up the same way
    // `--profile` does.
    let target_path = resolve_validate_target(&args.file);

    // Step 1: Load profile (parse JSON + resolve inheritance)
    let profile = match profile::load_profile_from_path(&target_path) {
        Ok(p) => Some(p),
        Err(e) => {
            let label = classify_profile_error(&e);
            errors.push(format!("{}: {}", label, e));
            None
        }
    };

    if let Some(ref profile) = profile {
        // Step 2: Check group references
        for group_name in &profile.security.groups {
            if !pol.groups.contains_key(group_name) {
                errors.push(format!("Group '{}' not found in policy.json", group_name));
            }
        }

        // Step 3: Check exclude_groups
        for excl in &profile.policy.exclude_groups {
            if let Some(group) = pol.groups.get(excl) {
                if group.required {
                    errors.push(format!("Cannot exclude required group '{}'", excl));
                }
            } else {
                warnings.push(format!(
                    "Excluded group '{}' not found in policy.json",
                    excl
                ));
            }
        }

        // Step 5: Check for empty paths
        let check_paths = |paths: &[String], label: &str, w: &mut Vec<String>| {
            for p in paths {
                if p.trim().is_empty() {
                    w.push(format!("Empty path in {}", label));
                }
            }
        };
        check_paths(&profile.filesystem.allow, "filesystem.allow", &mut warnings);
        check_paths(&profile.filesystem.read, "filesystem.read", &mut warnings);
        check_paths(&profile.filesystem.write, "filesystem.write", &mut warnings);
    }

    if args.quiet {
        // Short-circuit before any output. The errors-present
        // condition determines the exit code; warnings don't
        // influence validity (they're advisory).
        std::process::exit(if errors.is_empty() { 0 } else { 1 });
    }

    if args.json {
        let val = serde_json::json!({
            "file": target_path.display().to_string(),
            "valid": errors.is_empty(),
            "errors": errors,
            "warnings": warnings,
        });
        if let Some(ref field) = args.field {
            // Same shell-friendly extraction as `profile show --field`.
            // Common scripted usage: `--field valid` returns "true" /
            // "false" as a bare bool literal — perfect for shell
            // string comparisons.
            let extracted = crate::field_extract::extract_field_output(&val, field, args.compact)?;
            println!("{extracted}");
            if !errors.is_empty() {
                return Err(NonoError::ProfileParse("validation failed".into()));
            }
            return Ok(());
        }
        let rendered = if args.compact {
            to_json_compact(&val)?
        } else {
            to_json(&val)?
        };
        println!("{rendered}");
        if !errors.is_empty() {
            return Err(NonoError::ProfileParse("validation failed".into()));
        }
        return Ok(());
    }

    let t = theme::current();
    println!(
        "{}: validating {}",
        prefix(),
        theme::fg(&target_path.display().to_string(), t.text)
    );
    println!();

    if profile.is_some() {
        println!("  {}  JSON syntax valid", theme::fg("[ok]", t.green));
    }

    if let Some(ref profile) = profile {
        let valid_groups = profile
            .security
            .groups
            .iter()
            .filter(|g| pol.groups.contains_key(g.as_str()))
            .count();
        let total_groups = profile.security.groups.len();
        if valid_groups == total_groups && total_groups > 0 {
            println!(
                "  {}  All {} group references valid",
                theme::fg("[ok]", t.green),
                total_groups
            );
        }
    }

    for w in &warnings {
        println!(
            "  {} {}",
            theme::fg("[warn]", t.yellow),
            theme::fg(w, t.yellow)
        );
    }

    for e in &errors {
        println!("  {}  {}", theme::fg("[err]", t.red), theme::fg(e, t.red));
    }

    println!();
    if errors.is_empty() {
        let suffix = if warnings.is_empty() {
            String::new()
        } else {
            format!(
                " ({} warning{})",
                warnings.len(),
                if warnings.len() == 1 { "" } else { "s" }
            )
        };
        println!(
            "  Result: {}{}",
            theme::fg("valid", t.green).bold(),
            theme::fg(&suffix, t.yellow)
        );
        Ok(())
    } else {
        println!(
            "  Result: {} ({} error{})",
            theme::fg("invalid", t.red).bold(),
            errors.len(),
            if errors.len() == 1 { "" } else { "s" }
        );
        Err(NonoError::ProfileParse("validation failed".into()))
    }
}

// ---------------------------------------------------------------------------
// Profile → Manifest compilation
// ---------------------------------------------------------------------------

/// Compile a resolved profile into a capability manifest.
///
/// This produces a fully-resolved, portable manifest with absolute paths.
/// Environment variables (`~`, `$HOME`, `$TMPDIR`, etc.) are expanded.
fn resolve_to_manifest(
    prof: &Profile,
    workdir: &std::path::Path,
) -> Result<nono::manifest::CapabilityManifest> {
    use nono::manifest;

    // Helper: expand a path template and convert to string for the manifest
    let expand = |tmpl: &str| -> Result<String> {
        let expanded = profile::expand_vars(tmpl, workdir)?;
        Ok(expanded.to_string_lossy().into_owned())
    };

    // Filesystem
    let mut grants = Vec::new();
    let mut deny = Vec::new();

    let fs_sources: &[(&[String], manifest::AccessMode, bool)] = &[
        (
            &prof.filesystem.allow,
            manifest::AccessMode::Readwrite,
            false,
        ),
        (&prof.filesystem.read, manifest::AccessMode::Read, false),
        (&prof.filesystem.write, manifest::AccessMode::Write, false),
        (
            &prof.filesystem.allow_file,
            manifest::AccessMode::Readwrite,
            true,
        ),
        (&prof.filesystem.read_file, manifest::AccessMode::Read, true),
        (
            &prof.filesystem.write_file,
            manifest::AccessMode::Write,
            true,
        ),
        (
            &prof.policy.add_allow_read,
            manifest::AccessMode::Read,
            false,
        ),
        (
            &prof.policy.add_allow_write,
            manifest::AccessMode::Write,
            false,
        ),
        (
            &prof.policy.add_allow_readwrite,
            manifest::AccessMode::Readwrite,
            false,
        ),
    ];

    for (paths, access, is_file) in fs_sources {
        for p in *paths {
            grants.push(make_fs_grant(&expand(p)?, *access, *is_file)?);
        }
    }
    // Deny paths from policy patches
    for p in &prof.policy.add_deny_access {
        let expanded = expand(p)?;
        deny.push(manifest::FsDeny {
            path: expanded
                .parse()
                .map_err(|e| NonoError::ConfigParse(format!("invalid deny path: {e}")))?,
        });
    }

    // Resolve security.groups → filesystem grants, deny paths, and blocked commands.
    // Groups are the primary source of system read paths, deny rules, and dangerous
    // command blocks. Without this, the exported manifest is weaker than the profile.
    let loaded_policy = policy::load_embedded_policy()?;
    let mut scratch_caps = nono::CapabilitySet::new();
    let resolved_groups =
        policy::resolve_groups(&loaded_policy, &prof.security.groups, &mut scratch_caps)?;

    // Add filesystem grants from resolved groups
    for cap in scratch_caps.fs_capabilities() {
        let access = match cap.access {
            nono::AccessMode::Read => manifest::AccessMode::Read,
            nono::AccessMode::Write => manifest::AccessMode::Write,
            nono::AccessMode::ReadWrite => manifest::AccessMode::Readwrite,
        };
        let path_str = cap.resolved.to_string_lossy().into_owned();
        grants.push(make_fs_grant(&path_str, access, cap.is_file)?);
    }

    // Expand override_deny paths so we can filter them out of the deny list.
    // The manifest is the fully-resolved output — overridden denies must not
    // appear, otherwise the manifest re-applies restrictions the profile relaxed.
    let override_deny_expanded: Vec<std::path::PathBuf> = prof
        .policy
        .override_deny
        .iter()
        .filter_map(|tmpl| profile::expand_vars(tmpl, workdir).ok())
        .map(|p| {
            if p.exists() {
                p.canonicalize().unwrap_or(p)
            } else {
                p
            }
        })
        .collect();

    // Add deny paths from resolved groups, filtering out overridden paths.
    for deny_path in resolved_groups
        .deny_paths
        .iter()
        .filter(|dp| !override_deny_expanded.iter().any(|ovr| dp.starts_with(ovr)))
    {
        let path_str = deny_path.to_string_lossy().into_owned();
        deny.push(manifest::FsDeny {
            path: path_str
                .parse()
                .map_err(|e| NonoError::ConfigParse(format!("invalid deny path: {e}")))?,
        });
    }

    // Add blocked commands from resolved groups
    let group_blocked_commands: Vec<String> = scratch_caps.blocked_commands().to_vec();

    // Add workdir access as a filesystem grant
    let workdir_str = workdir.to_string_lossy().into_owned();
    match prof.workdir.access {
        WorkdirAccess::ReadWrite => {
            grants.push(make_fs_grant(
                &workdir_str,
                manifest::AccessMode::Readwrite,
                false,
            )?);
        }
        WorkdirAccess::Read => {
            grants.push(make_fs_grant(
                &workdir_str,
                manifest::AccessMode::Read,
                false,
            )?);
        }
        WorkdirAccess::Write => {
            grants.push(make_fs_grant(
                &workdir_str,
                manifest::AccessMode::Write,
                false,
            )?);
        }
        WorkdirAccess::None => {} // no grant
    }

    // Deduplicate grants: if the same path appears from both filesystem.allow
    // and workdir (or groups), keep the highest-access-mode entry.
    grants.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    grants.dedup_by(|a, b| {
        if a.path.as_str() == b.path.as_str() && a.type_ == b.type_ {
            // Keep the broader access mode in `b` (the survivor of dedup_by)
            b.access = wider_access(a.access, b.access);
            true
        } else {
            false
        }
    });

    // Deduplicate deny entries by path
    deny.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
    deny.dedup_by(|a, b| a.path.as_str() == b.path.as_str());

    let filesystem = if grants.is_empty() && deny.is_empty() {
        None
    } else {
        Some(manifest::Filesystem { grants, deny })
    };

    // Network
    let network_mode = if prof.network.block {
        manifest::NetworkMode::Blocked
    } else if prof.network.resolved_network_profile().is_some()
        || !prof.network.allow_domain.is_empty()
        || !prof.network.resolved_credentials().is_empty()
        || !prof.network.custom_credentials.is_empty()
    {
        manifest::NetworkMode::Proxy
    } else {
        manifest::NetworkMode::Unrestricted
    };

    let network = Some(manifest::Network {
        mode: network_mode,
        allow_domains: prof.network.allow_domain.clone(),
        endpoints: Vec::new(),
        dns: true,
        ports: if prof.network.listen_port.is_empty() && prof.network.open_port.is_empty() {
            None
        } else {
            Some(manifest::PortConfig {
                connect: Vec::new(),
                bind: prof
                    .network
                    .listen_port
                    .iter()
                    .filter_map(|p| std::num::NonZeroU64::new(u64::from(*p)))
                    .collect(),
                localhost: prof
                    .network
                    .open_port
                    .iter()
                    .filter_map(|p| std::num::NonZeroU64::new(u64::from(*p)))
                    .collect(),
            })
        },
    });

    // Process
    let signal_mode = match prof.security.signal_mode {
        Some(profile::ProfileSignalMode::Isolated) | None => manifest::SignalMode::Isolated,
        Some(profile::ProfileSignalMode::AllowSameSandbox) => {
            manifest::SignalMode::AllowSameSandbox
        }
        Some(profile::ProfileSignalMode::AllowAll) => manifest::SignalMode::AllowAll,
    };
    let process_info_mode = match prof.security.process_info_mode {
        Some(profile::ProfileProcessInfoMode::Isolated) | None => {
            manifest::ProcessInfoMode::Isolated
        }
        Some(profile::ProfileProcessInfoMode::AllowSameSandbox) => {
            manifest::ProcessInfoMode::AllowSameSandbox
        }
        Some(profile::ProfileProcessInfoMode::AllowAll) => manifest::ProcessInfoMode::AllowAll,
    };
    let ipc_mode = match prof.security.ipc_mode {
        Some(profile::ProfileIpcMode::SharedMemoryOnly) | None => {
            manifest::IpcMode::SharedMemoryOnly
        }
        Some(profile::ProfileIpcMode::Full) => manifest::IpcMode::Full,
    };

    let process = Some(manifest::Process {
        allowed_commands: prof.security.allowed_commands.clone(),
        blocked_commands: {
            let mut cmds = group_blocked_commands;
            cmds.extend(prof.policy.add_deny_commands.clone());
            cmds.sort();
            cmds.dedup();
            cmds
        },
        exec_strategy: if !prof.rollback.exclude_patterns.is_empty()
            || !prof.rollback.exclude_globs.is_empty()
        {
            manifest::ExecStrategy::Supervised
        } else {
            manifest::ExecStrategy::Monitor
        },
        signal_mode,
        process_info_mode,
        ipc_mode,
    });

    // Rollback
    let rollback =
        if prof.rollback.exclude_patterns.is_empty() && prof.rollback.exclude_globs.is_empty() {
            None
        } else {
            Some(manifest::Rollback {
                enabled: false,
                exclude_patterns: prof.rollback.exclude_patterns.clone(),
                exclude_globs: prof.rollback.exclude_globs.clone(),
            })
        };

    // Credentials (custom_credentials from profile → manifest credentials)
    // OAuth2 credentials (auth field) are not yet representable in the manifest
    // schema, so only static-key credentials are exported.
    let mut credentials = Vec::new();
    for (name, cred) in &prof.network.custom_credentials {
        let inject_mode = match cred.inject_mode {
            profile::InjectMode::Header => manifest::InjectMode::Header,
            profile::InjectMode::UrlPath => manifest::InjectMode::UrlPath,
            profile::InjectMode::QueryParam => manifest::InjectMode::QueryParam,
            profile::InjectMode::BasicAuth => manifest::InjectMode::BasicAuth,
        };

        let endpoint_rules: Vec<manifest::EndpointRule> = cred
            .endpoint_rules
            .iter()
            .map(|r| {
                let method = r.method.parse().map_err(|e| {
                    NonoError::ConfigParse(format!(
                        "invalid endpoint rule method '{}': {e}",
                        r.method
                    ))
                })?;
                let path = r.path.parse().map_err(|e| {
                    NonoError::ConfigParse(format!("invalid endpoint rule path '{}': {e}", r.path))
                })?;
                Ok(manifest::EndpointRule { method, path })
            })
            .collect::<Result<Vec<_>>>()?;

        credentials.push(manifest::Credential {
            name: name
                .parse()
                .map_err(|e| NonoError::ConfigParse(format!("invalid credential name: {e}")))?,
            upstream: cred
                .upstream
                .parse()
                .map_err(|e| NonoError::ConfigParse(format!("invalid credential upstream: {e}")))?,
            source: match cred.credential_key.as_ref() {
                Some(key) => key.parse().map_err(|e| {
                    NonoError::ConfigParse(format!("invalid credential source: {e}"))
                })?,
                None => continue,
            },
            inject: Some(manifest::CredentialInject {
                mode: inject_mode,
                header: cred.inject_header.clone(),
                format: cred.credential_format.clone(),
                path_pattern: cred.path_pattern.clone(),
                path_replacement: cred.path_replacement.clone(),
                query_param_name: cred.query_param_name.clone(),
            }),
            env_var: cred
                .env_var
                .as_ref()
                .map(|v| {
                    v.parse()
                        .map_err(|e| NonoError::ConfigParse(format!("invalid env_var: {e}")))
                })
                .transpose()?,
            endpoint_rules,
        });
    }

    let version = "0.1.0"
        .parse()
        .map_err(|e| NonoError::ConfigParse(format!("version parse error: {e}")))?;

    Ok(manifest::CapabilityManifest {
        version,
        schema: Some("https://nono.dev/schemas/capability-manifest.schema.json".to_string()),
        filesystem,
        network,
        process,
        rollback,
        credentials,
    })
}

/// Return the broader of two access modes (Read + Write → Readwrite).
fn wider_access(
    a: nono::manifest::AccessMode,
    b: nono::manifest::AccessMode,
) -> nono::manifest::AccessMode {
    use nono::manifest::AccessMode::{Read, Readwrite, Write};
    match (a, b) {
        (Readwrite, _) | (_, Readwrite) => Readwrite,
        (Read, Write) | (Write, Read) => Readwrite,
        (Read, Read) => Read,
        (Write, Write) => Write,
    }
}

/// Helper to construct an `FsGrant` from an expanded path string.
fn make_fs_grant(
    path: &str,
    access: nono::manifest::AccessMode,
    is_file: bool,
) -> Result<nono::manifest::FsGrant> {
    Ok(nono::manifest::FsGrant {
        path: path
            .parse()
            .map_err(|e| NonoError::ConfigParse(format!("invalid grant path: {e}")))?,
        access,
        type_: if is_file {
            nono::manifest::FsEntryType::File
        } else {
            nono::manifest::FsEntryType::Directory
        },
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    use std::path::PathBuf;

    /// The profile authoring guide is compiled into the binary and surfaced
    /// via `nono profile guide`. It must not instruct users to run the
    /// deprecated `nono policy <sub>` commands.
    #[test]
    fn embedded_guide_contains_no_nono_policy_references() {
        let text = crate::config::embedded::embedded_profile_guide();
        assert!(
            !text.contains("nono policy "),
            "profile-authoring-guide.md references deprecated 'nono policy ' commands — update to 'nono profile '",
        );
    }

    #[test]
    fn test_minimal_skeleton_is_valid_profile() {
        let args = ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        let json = serde_json::to_string(&skeleton).expect("serialize");
        let profile: Profile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(profile.meta.name, "test-profile");
    }

    #[test]
    fn test_full_skeleton_is_valid_profile() {
        let args = ProfileInitArgs {
            name: "full-test".to_string(),
            extends: Some("default".to_string()),
            groups: vec![],
            description: Some("A full test profile".to_string()),
            full: true,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        let json = serde_json::to_string(&skeleton).expect("serialize");
        let profile: Profile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(profile.meta.name, "full-test");
        assert_eq!(profile.extends, Some(vec!["default".to_string()]));
        assert_eq!(
            profile.meta.description,
            Some("A full test profile".to_string())
        );
    }

    #[test]
    fn test_skeleton_with_groups() {
        let args = ProfileInitArgs {
            name: "grouped".to_string(),
            extends: None,
            groups: vec!["deny_credentials".to_string()],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        let groups = skeleton["security"]["groups"].as_array().expect("array");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0], "deny_credentials");
    }

    #[test]
    fn test_skeleton_omits_schema_url() {
        let args = ProfileInitArgs {
            name: "schema-test".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let skeleton = build_skeleton(&args);
        // $schema is not emitted because the URL is not hosted;
        // users export the schema locally via `nono profile schema`
        assert!(skeleton.get("$schema").is_none());
    }

    #[test]
    fn test_invalid_profile_name() {
        let result = cmd_init(ProfileInitArgs {
            name: "-bad-name-".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(PathBuf::from("/tmp/nono-test-bad.json")),
            force: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(err.to_string().contains("Invalid profile name"));
    }

    #[test]
    fn test_invalid_group_name() {
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec!["nonexistent_group_xyz".to_string()],
            description: None,
            full: false,
            output: Some(PathBuf::from("/tmp/nono-test-badgroup.json")),
            force: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(err.to_string().contains("Unknown security group"));
    }

    #[test]
    fn test_invalid_extends_target() {
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: Some("nonexistent-base-profile-xyz".to_string()),
            groups: vec![],
            description: None,
            full: false,
            output: Some(PathBuf::from("/tmp/nono-test-badextends.json")),
            force: false,
        });
        assert!(result.is_err());
        let err = result.expect_err("error");
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn test_force_overwrite() {
        use std::io::Write;

        let tmp = std::env::temp_dir().join("nono-test-force-overwrite.json");
        // Create existing file
        let mut f = fs::File::create(&tmp).expect("create");
        f.write_all(b"{}").expect("write");
        drop(f);

        // Without force: should fail
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(tmp.clone()),
            force: false,
        });
        assert!(result.is_err());

        // With force: should succeed
        let result = cmd_init(ProfileInitArgs {
            name: "test-profile".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: Some(tmp.clone()),
            force: true,
        });
        assert!(result.is_ok());

        // Verify file was written with correct content
        let content = fs::read_to_string(&tmp).expect("read");
        let profile: Profile = serde_json::from_str(&content).expect("parse");
        assert_eq!(profile.meta.name, "test-profile");

        // Cleanup
        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn test_full_vs_minimal_differences() {
        let minimal_args = ProfileInitArgs {
            name: "minimal".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: false,
            output: None,
            force: false,
        };
        let full_args = ProfileInitArgs {
            name: "full".to_string(),
            extends: None,
            groups: vec![],
            description: None,
            full: true,
            output: None,
            force: false,
        };
        let minimal = build_skeleton(&minimal_args);
        let full = build_skeleton(&full_args);

        let minimal_obj = minimal.as_object().expect("object");
        let full_obj = full.as_object().expect("object");

        // Full has more keys than minimal
        assert!(full_obj.len() > minimal_obj.len());

        // Full has sections that minimal does not
        assert!(full_obj.contains_key("policy"));
        assert!(full_obj.contains_key("network"));
        assert!(full_obj.contains_key("env_credentials"));
        assert!(full_obj.contains_key("hooks"));
        assert!(full_obj.contains_key("rollback"));

        // open_urls, allow_launch_services, and allow_gpu are intentionally
        // omitted to avoid silently overriding inherited values from base profiles
        assert!(!full_obj.contains_key("open_urls"));
        assert!(!full_obj.contains_key("allow_launch_services"));
        assert!(!full_obj.contains_key("allow_gpu"));

        assert!(!minimal_obj.contains_key("policy"));
        assert!(!minimal_obj.contains_key("network"));
        assert!(!minimal_obj.contains_key("hooks"));

        // Full filesystem has all fields
        let full_fs = full_obj["filesystem"].as_object().expect("fs object");
        assert!(full_fs.contains_key("write"));
        assert!(full_fs.contains_key("allow_file"));
        assert!(full_fs.contains_key("read_file"));
        assert!(full_fs.contains_key("write_file"));

        // Minimal filesystem has only allow + read
        let min_fs = minimal_obj["filesystem"].as_object().expect("fs object");
        assert!(!min_fs.contains_key("write"));
        assert!(!min_fs.contains_key("allow_file"));

        // Full policy has add_deny_access
        let full_pol = full_obj["policy"].as_object().expect("policy object");
        assert!(full_pol.contains_key("add_deny_access"));

        // Full network has all fields
        let full_net = full_obj["network"].as_object().expect("network object");
        assert!(full_net.contains_key("allow_domain"));
        assert!(full_net.contains_key("credentials"));
        assert!(full_net.contains_key("open_port"));
        assert!(full_net.contains_key("listen_port"));
        assert!(full_net.contains_key("custom_credentials"));
    }

    #[test]
    fn test_groups_lists_all() {
        let pol = policy::load_embedded_policy().expect("should load policy");
        assert!(
            pol.groups.len() > 10,
            "expected many groups, got {}",
            pol.groups.len()
        );
        assert!(
            pol.groups.contains_key("deny_credentials"),
            "expected deny_credentials group"
        );
    }

    #[test]
    fn test_groups_specific_known() {
        let pol = policy::load_embedded_policy().expect("should load policy");
        let group = pol
            .groups
            .get("deny_credentials")
            .expect("deny_credentials should exist");
        assert!(!group.description.is_empty());
        assert!(group.required);
        if let Some(ref deny) = group.deny {
            let all_paths = deny.access.join(" ");
            assert!(all_paths.contains(".ssh"), "expected .ssh in deny paths");
            assert!(all_paths.contains(".aws"), "expected .aws in deny paths");
        } else {
            panic!("deny_credentials should have deny rules");
        }
    }

    #[test]
    fn test_groups_unknown_errors() {
        let pol = policy::load_embedded_policy().expect("should load policy");
        let result = cmd_groups_detail(&pol, "nonexistent_group_xyz", false, false, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_profiles_includes_builtins() {
        let profiles = profile::list_profiles();
        assert!(
            profiles.contains(&"default".to_string()),
            "expected 'default' in profiles"
        );
        assert!(
            profiles.contains(&"opencode".to_string()),
            "expected 'codex' in profiles"
        );
    }

    #[test]
    fn test_show_resolves_inheritance() {
        let profile = profile::load_profile("opencode").expect("opencode profile should load");
        assert!(
            !profile.security.groups.is_empty(),
            "codex should have security groups"
        );
        // codex extends default, so it should have default's base groups
        let has_deny = profile.security.groups.iter().any(|g| g.contains("deny"));
        assert!(has_deny, "codex should inherit deny groups");
    }

    #[test]
    fn test_diff_shows_differences() {
        let p1 = profile::load_profile("default").expect("default should load");
        let p2 = profile::load_profile("opencode").expect("opencode should load");

        let g1: BTreeSet<&str> = p1.security.groups.iter().map(|s| s.as_str()).collect();
        let g2: BTreeSet<&str> = p2.security.groups.iter().map(|s| s.as_str()).collect();

        let added: BTreeSet<&&str> = g2.difference(&g1).collect();
        assert!(
            !added.is_empty(),
            "codex should have additional groups over default"
        );
    }

    #[test]
    fn test_validate_valid_profile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test-profile.json");
        std::fs::write(
            &path,
            r#"{
                "meta": { "name": "test", "description": "test profile" },
                "security": { "groups": ["deny_credentials"] },
                "workdir": { "access": "readwrite" }
            }"#,
        )
        .expect("write");

        let args = ProfileValidateArgs {
            file: path,
            json: false,
            compact: false,
            field: None,
            quiet: false,
        };
        let result = cmd_validate(args);
        assert!(result.is_ok(), "valid profile should pass validation");
    }

    #[test]
    fn test_validate_invalid_group() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad-profile.json");
        std::fs::write(
            &path,
            r#"{
                "meta": { "name": "test" },
                "security": { "groups": ["nonexistent_group_xyz"] }
            }"#,
        )
        .expect("write");

        let args = ProfileValidateArgs {
            file: path,
            json: false,
            compact: false,
            field: None,
            quiet: false,
        };
        let result = cmd_validate(args);
        assert!(result.is_err(), "invalid group should fail validation");
    }

    #[test]
    fn test_validate_exclude_required() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad-exclude.json");
        std::fs::write(
            &path,
            r#"{
                "meta": { "name": "test" },
                "security": { "groups": [] },
                "policy": { "exclude_groups": ["deny_credentials"] }
            }"#,
        )
        .expect("write");

        let args = ProfileValidateArgs {
            file: path,
            json: false,
            compact: false,
            field: None,
            quiet: false,
        };
        let result = cmd_validate(args);
        assert!(
            result.is_err(),
            "excluding required group should fail validation"
        );
    }

    // `extract_field_output` unit tests live in `crate::field_extract`
    // alongside the function itself. Profile-specific wiring is
    // covered by the clap-parse tests in `cli.rs`.

    #[test]
    fn parse_guide_sections_splits_on_h2_headings_and_drops_preamble() {
        let guide = "\
# Top Title

Some preamble text that should be discarded.

## 1. First Section

First body line one.
First body line two.

## 2. Second Section

Second body.
";
        let sections = parse_guide_sections(guide);
        assert_eq!(sections.len(), 2, "exactly two H2 sections");
        assert_eq!(sections[0].0, "1. First Section");
        assert!(sections[0].1.contains("First body line one"));
        assert!(sections[0].1.contains("First body line two"));
        assert!(
            !sections[0].1.contains("Some preamble"),
            "preamble must not bleed into the first section"
        );
        assert!(
            !sections[0].1.contains("Second body"),
            "first section must not bleed into the second"
        );
        assert_eq!(sections[1].0, "2. Second Section");
    }

    #[test]
    fn parse_guide_sections_treats_h3_as_body_not_delimiter() {
        // Deeper headings (### or more) must stay inside their
        // enclosing H2 section. Otherwise `--section` would split
        // on every heading depth which is not the intent.
        let guide = "## A\n\nintro\n\n### A.1\n\ndetail\n\n## B\n\n";
        let sections = parse_guide_sections(guide);
        assert_eq!(sections.len(), 2);
        assert!(sections[0].1.contains("### A.1"));
        assert!(sections[0].1.contains("detail"));
    }

    #[test]
    fn search_guide_sections_groups_hits_by_section_with_relative_line_nums() {
        // Two-section guide; needle hits in both bodies (case-
        // insensitive). Line numbers must be 1-based and reset
        // per section, so the user reads the position cue in the
        // local-to-section frame they see in the terminal.
        let sections = vec![
            (
                "Networking".to_string(),
                "TCP ports go here\nUDP not yet\nmore tcp talk\n".to_string(),
            ),
            ("Filesystem".to_string(), "no match here\n".to_string()),
            ("Other".to_string(), "tcp again\n".to_string()),
        ];
        let hits = search_guide_sections(&sections, "tcp");
        assert_eq!(
            hits.len(),
            2,
            "Filesystem section had no hit, must be skipped"
        );
        // First section: lines 1 and 3 contain 'tcp' (line 2 'UDP'
        // does not).
        assert_eq!(hits[0].0, "Networking");
        assert_eq!(hits[0].1.len(), 2);
        assert_eq!(hits[0].1[0].0, 1);
        assert!(hits[0].1[0].1.contains("TCP"));
        assert_eq!(hits[0].1[1].0, 3);
        assert!(hits[0].1[1].1.contains("tcp"));
        // Third section: single hit on line 1 (relative).
        assert_eq!(hits[1].0, "Other");
        assert_eq!(hits[1].1.len(), 1);
        assert_eq!(hits[1].1[0].0, 1);
    }

    #[test]
    fn search_guide_sections_returns_empty_when_no_section_matches() {
        let sections = vec![
            ("A".to_string(), "alpha\nbeta\n".to_string()),
            ("B".to_string(), "gamma\n".to_string()),
        ];
        // Caller (cmd_guide) translates empty into a `ProfileParse`
        // error with a `--list-sections` hint.
        assert!(search_guide_sections(&sections, "delta").is_empty());
    }

    #[test]
    fn search_guide_sections_does_not_search_titles() {
        // Title-based lookup is what `--section` already does.
        // `--search` is body-only so the two flags don't double-
        // count or collide.
        let sections = vec![("validation".to_string(), "body has no hit\n".to_string())];
        assert!(search_guide_sections(&sections, "validation").is_empty());
    }

    #[test]
    fn find_guide_section_matches_case_insensitive_substring() {
        let sections = vec![
            ("1. Profile File Location".to_string(), "body1".to_string()),
            ("5. Validation".to_string(), "body5".to_string()),
        ];
        // Exact title (case-insensitive).
        assert!(find_guide_section(&sections, "validation").is_some());
        assert!(find_guide_section(&sections, "VALIDATION").is_some());
        // Substring (numeric prefix or suffix).
        assert!(find_guide_section(&sections, "valid").is_some());
        assert!(find_guide_section(&sections, "1.").is_some());
        // Miss returns None so the caller can surface a hint.
        assert!(find_guide_section(&sections, "nonexistent").is_none());
    }

    fn make_group(
        description: &str,
        platform: Option<&str>,
        allow_read: Vec<&str>,
        deny_commands: Vec<&str>,
    ) -> Group {
        Group {
            description: description.to_string(),
            platform: platform.map(|s| s.to_string()),
            required: false,
            allow: Some(AllowOps {
                read: allow_read.into_iter().map(|s| s.to_string()).collect(),
                write: Vec::new(),
                readwrite: Vec::new(),
            }),
            deny: Some(DenyOps {
                access: Vec::new(),
                unlink: false,
                unlink_override_for_user_writable: false,
                commands: deny_commands.into_iter().map(|s| s.to_string()).collect(),
            }),
            symlink_pairs: None,
        }
    }

    #[test]
    fn search_groups_matches_across_name_description_paths_and_commands() {
        // Each group hits a different field — the test verifies
        // every documented match path actually wires up.
        let g_name = make_group("desc", None, vec![], vec![]);
        let g_desc = make_group("touches /etc paths", None, vec![], vec![]);
        let g_path = make_group("desc", None, vec!["/etc/hosts"], vec![]);
        let g_cmd = make_group("desc", None, vec![], vec!["fetch-etc"]);
        let names = [
            "etc_in_name".to_string(),
            "g_desc".to_string(),
            "g_path".to_string(),
            "g_cmd".to_string(),
        ];
        let groups: Vec<(&String, &Group)> = vec![
            (&names[0], &g_name),
            (&names[1], &g_desc),
            (&names[2], &g_path),
            (&names[3], &g_cmd),
        ];
        let hits = search_groups(&groups, "etc");
        assert_eq!(hits.len(), 4);
        let by_name: std::collections::HashMap<&str, &Vec<&'static str>> =
            hits.iter().map(|(n, _, w)| (n.as_str(), w)).collect();
        assert_eq!(by_name["etc_in_name"], &vec!["name"]);
        assert_eq!(by_name["g_desc"], &vec!["description"]);
        assert_eq!(by_name["g_path"], &vec!["allow.read"]);
        assert_eq!(by_name["g_cmd"], &vec!["deny.commands"]);
    }

    #[test]
    fn search_groups_is_case_insensitive_and_returns_empty_on_miss() {
        let g = make_group("HTTPS endpoints", None, vec!["/Users/Foo"], vec![]);
        let name = "ssl_group".to_string();
        let groups: Vec<(&String, &Group)> = vec![(&name, &g)];
        // Mixed-case needle hits both lowercase and uppercase data.
        assert_eq!(search_groups(&groups, "https").len(), 1);
        assert_eq!(search_groups(&groups, "users/foo").len(), 1);
        // Genuine miss returns empty so the caller surfaces a hint.
        assert!(search_groups(&groups, "nonexistent_xyz").is_empty());
    }

    #[test]
    fn search_groups_records_every_matching_field_for_one_group() {
        // A single group with the needle landing in name, description,
        // and a path must report all three labels in deterministic
        // order (name → description → allow.read).
        let g = make_group("etc reference", None, vec!["/etc/passwd"], vec![]);
        let name = "etc_group".to_string();
        let groups: Vec<(&String, &Group)> = vec![(&name, &g)];
        let hits = search_groups(&groups, "etc");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].2, vec!["name", "description", "allow.read"]);
    }

    #[test]
    fn match_profile_fields_hits_every_field_independently() {
        // Each call lands in a different field — verifies every
        // documented match path actually wires up.
        let extends = vec!["base".to_string(), "default".to_string()];

        // name only
        assert_eq!(
            match_profile_fields("rust-dev", None, &[], "", None, "rust"),
            vec!["name"]
        );
        // description only (case-insensitive)
        assert_eq!(
            match_profile_fields("p", Some("Rust SDK profile"), &[], "", None, "sdk"),
            vec!["description"]
        );
        // extends only (substring against any chain entry)
        assert_eq!(
            match_profile_fields("p", None, &extends, "", None, "default"),
            vec!["extends"]
        );
        // source only
        assert_eq!(
            match_profile_fields("p", None, &[], "user (overrides built-in)", None, "user"),
            vec!["source"]
        );
        // pack only
        assert_eq!(
            match_profile_fields("p", None, &[], "", Some("always-further/example"), "always"),
            vec!["pack"]
        );
    }

    #[test]
    fn match_profile_fields_orders_labels_deterministically() {
        // Multiple hits in one entry must come out in the documented
        // fixed order: name → description → extends → source → pack.
        // Tests rely on this for stable assertions and the rendered
        // `[matched in: …]` line should be predictable for users.
        let extends = vec!["foo".to_string()];
        let labels = match_profile_fields(
            "foo-profile",
            Some("foo description"),
            &extends,
            "foo/source",
            Some("foo/pack"),
            "foo",
        );
        assert_eq!(
            labels,
            vec!["name", "description", "extends", "source", "pack"]
        );
    }

    #[test]
    fn match_profile_fields_returns_empty_on_miss() {
        assert!(match_profile_fields(
            "p",
            Some("desc"),
            &["base".to_string()],
            "src",
            Some("pack"),
            "no_such_thing"
        )
        .is_empty());
    }
}
