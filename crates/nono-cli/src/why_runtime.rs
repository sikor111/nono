use crate::capability_ext::CapabilitySetExt;
use crate::cli::{SandboxArgs, WhyArgs, WhyOp};
use crate::{policy, profile, query_ext, sandbox_state};
use nono::{AccessMode, CapabilitySet, NonoError, Result};

pub(crate) fn run_why(args: WhyArgs) -> Result<()> {
    use query_ext::{print_result, query_network, query_path, QueryResult};
    use sandbox_state::load_sandbox_state;

    let (caps, overridden_paths): (CapabilitySet, Vec<std::path::PathBuf>) = if args.self_query {
        match load_sandbox_state() {
            Some(state) => {
                let paths = state.override_deny_as_paths();
                (state.to_caps()?, paths)
            }
            None => {
                let result = QueryResult::NotSandboxed {
                    message: "Not running inside a nono sandbox".to_string(),
                };
                if args.json {
                    let json = if args.compact {
                        serde_json::to_string(&result)
                    } else {
                        serde_json::to_string_pretty(&result)
                    }
                    .map_err(|e| {
                        NonoError::ConfigParse(format!("JSON serialization failed: {}", e))
                    })?;
                    println!("{}", json);
                } else {
                    print_result(&result);
                }
                return Ok(());
            }
        }
    } else if let Some(ref profile_name) = args.profile {
        let profile = profile::load_profile(profile_name)?;
        let workdir = args
            .workdir
            .clone()
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| std::path::PathBuf::from("."));

        let sandbox_args = SandboxArgs {
            allow: args.allow.clone(),
            read: args.read.clone(),
            write: args.write.clone(),
            allow_file: args.allow_file.clone(),
            read_file: args.read_file.clone(),
            write_file: args.write_file.clone(),
            block_net: args.block_net,
            workdir: args.workdir.clone(),
            allow_command: args.allow_command.clone(),
            block_command: args.block_command.clone(),
            ..SandboxArgs::default()
        };

        let mut override_paths = Vec::new();
        for tmpl in &profile.policy.override_deny {
            let expanded = profile::expand_vars(tmpl, &workdir)?;
            if expanded.exists() {
                if let Ok(canonical) = expanded.canonicalize() {
                    override_paths.push(canonical);
                }
            } else {
                override_paths.push(expanded);
            }
        }

        let (mut caps, needs_unlink) =
            CapabilitySet::from_profile(&profile, &workdir, &sandbox_args)?;
        if needs_unlink {
            policy::apply_unlink_overrides(&mut caps);
        }
        (caps, override_paths)
    } else {
        let sandbox_args = SandboxArgs {
            allow: args.allow.clone(),
            read: args.read.clone(),
            write: args.write.clone(),
            allow_file: args.allow_file.clone(),
            read_file: args.read_file.clone(),
            write_file: args.write_file.clone(),
            block_net: args.block_net,
            workdir: args.workdir.clone(),
            allow_command: args.allow_command.clone(),
            block_command: args.block_command.clone(),
            ..SandboxArgs::default()
        };

        let (mut caps, needs_unlink) = CapabilitySet::from_args(&sandbox_args)?;
        if needs_unlink {
            policy::apply_unlink_overrides(&mut caps);
        }
        (caps, vec![])
    };

    // `--print-policy` short-circuits the query path and just dumps the
    // resolved CapabilitySet. Conflicts with the query flags at the
    // clap layer, so reaching here means the user opted in explicitly.
    if args.print_policy {
        if args.json {
            // Reuse the same JSON shape as `--dry-run-json` (minus the
            // command + secrets), so consumers writing tooling around
            // policy snapshots see a familiar layout.
            // Manually construct extras since `DryRunJsonExtras::empty`
            // is `#[cfg(test)]`-gated (intentionally — production
            // dry-run callers always populate this from
            // `PreparedSandbox`). For `nono why --print-policy` the
            // proxy / launch-services / GPU bits aren't relevant to
            // a query, so inert defaults are correct here.
            let extras = crate::output::DryRunJsonExtras {
                allowed_env_vars: None,
                override_deny_paths: &overridden_paths,
                network_profile: None,
                allow_domain: &[],
                listen_ports: &[],
                capability_elevation: false,
                allow_launch_services_active: false,
                allow_gpu_active: false,
            };
            let value = crate::output::capabilities_to_json(
                &caps,
                std::ffi::OsStr::new("(why)"),
                &[],
                0,
                &extras,
            );
            let json = if args.compact {
                serde_json::to_string(&value)
            } else {
                serde_json::to_string_pretty(&value)
            }
            .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
            println!("{}", json);
        } else {
            // verbose=1 surfaces every cap (otherwise system grants get
            // collapsed into "+ N system/group paths" since the user
            // explicitly asked to see the full picture).
            crate::output::print_capabilities(&caps, 1, false);
        }
        return Ok(());
    }

    // The `--explain` rider returns a match list alongside the verdict.
    // Match shape varies by query kind (paths report capabilities,
    // commands report rule entries, ports report allowlist entries)
    // so we keep them in separate optional state vars; only one
    // will ever be Some at a time.
    let mut explained_path: Option<Vec<query_ext::ExplainedMatch>> = None;
    let mut explained_command: Option<Vec<query_ext::ExplainedCommandMatch>> = None;
    let mut explained_port: Option<Vec<query_ext::ExplainedPortMatch>> = None;
    let result = if let Some(ref path) = args.path {
        let op = match args.op {
            Some(WhyOp::Read) => AccessMode::Read,
            Some(WhyOp::Write) => AccessMode::Write,
            Some(WhyOp::ReadWrite) => AccessMode::ReadWrite,
            None => AccessMode::Read,
        };
        if args.explain {
            let (verdict, matches) =
                query_ext::query_path_explained(path, op, &caps, &overridden_paths)?;
            explained_path = Some(matches);
            verdict
        } else {
            query_path(path, op, &caps, &overridden_paths)?
        }
    } else if let Some(ref net) = args.net {
        let (host, port) = query_ext::parse_host_port(net, args.port)?;
        query_network(&host, port, &caps)
    } else if let Some(ref host) = args.host {
        query_network(host, args.port, &caps)
    } else if let Some(port) = args.tcp {
        if args.explain {
            let (verdict, matches) = query_ext::query_tcp_port_explained(port, &caps);
            explained_port = Some(matches);
            verdict
        } else {
            query_ext::query_tcp_port(port, &caps)
        }
    } else if let Some(port) = args.tcp_bind {
        if args.explain {
            let (verdict, matches) = query_ext::query_tcp_bind_port_explained(port, &caps);
            explained_port = Some(matches);
            verdict
        } else {
            query_ext::query_tcp_bind_port(port, &caps)
        }
    } else if let Some(ref command) = args.command_name {
        if args.explain {
            let (verdict, matches) = query_ext::query_command_explained(command, &caps)?;
            explained_command = Some(matches);
            verdict
        } else {
            query_ext::query_command(command, &caps)?
        }
    } else {
        return Err(NonoError::ConfigParse(
            "--path, --host, --net, --tcp, --tcp-bind or --command is required".to_string(),
        ));
    };

    if args.json {
        // When `--explain` is set alongside `--json`, wrap the document
        // so consumers get both the verdict and the full match list.
        // Without `--explain`, the document stays as the bare verdict
        // for backwards compatibility with existing tooling.
        let value: serde_json::Value = if let Some(matches) = &explained_path {
            serde_json::json!({"result": result, "matches": matches})
        } else if let Some(matches) = &explained_command {
            serde_json::json!({"result": result, "matches": matches})
        } else if let Some(matches) = &explained_port {
            serde_json::json!({"result": result, "matches": matches})
        } else {
            serde_json::to_value(&result)
                .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?
        };
        let json = if args.compact {
            serde_json::to_string(&value)
        } else {
            serde_json::to_string_pretty(&value)
        }
        .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {}", e)))?;
        println!("{}", json);
    } else {
        print_result(&result);
        if let Some(matches) = &explained_path {
            println!();
            print_explained_matches(matches);
        } else if let Some(matches) = &explained_command {
            println!();
            print_explained_command_matches(matches);
        } else if let Some(matches) = &explained_port {
            println!();
            print_explained_port_matches(matches);
        }
    }

    Ok(())
}

/// Render the `--explain` match list as a small table appended after
/// the regular verdict. Empty list means "the verdict was not driven
/// by a covering capability" (e.g. sensitive_path / network query) —
/// surface that explicitly so the user knows the explainer ran.
fn print_explained_matches(matches: &[query_ext::ExplainedMatch]) {
    println!("All matching capabilities:");
    if matches.is_empty() {
        println!("  (no fs capability covers this path)");
        return;
    }
    println!(
        "  {:<48}  {:<10}  {:<24}  SUFFICIENT?",
        "PATH", "ACCESS", "SOURCE"
    );
    for m in matches {
        let path = if m.path.len() > 48 {
            format!("…{}", &m.path[m.path.len() - 47..])
        } else {
            m.path.clone()
        };
        println!(
            "  {:<48}  {:<10}  {:<24}  {}",
            path,
            m.access,
            m.source,
            if m.sufficient { "yes" } else { "no" },
        );
    }
}

/// Render `--tcp[-bind] --explain` port rows. Empty list means the
/// policy configures no per-port allowlist (default-allow when
/// network is open, default-deny when blocked) — surface that
/// explicitly so the user knows the explainer ran.
fn print_explained_port_matches(matches: &[query_ext::ExplainedPortMatch]) {
    println!("All matching port rules:");
    if matches.is_empty() {
        println!(
            "  (policy configures no localhost_ports, tcp_connect_ports, \
             or tcp_bind_ports)"
        );
        return;
    }
    println!("  {:<8}  {:<22}  MATCHES?", "PORT", "LIST");
    for m in matches {
        println!(
            "  {:<8}  {:<22}  {}",
            m.port,
            m.list,
            if m.matches { "yes" } else { "no" }
        );
    }
}

/// Render `--command --explain` rule rows. Empty list means the policy
/// configures neither an allow nor a block list — surface that
/// explicitly so the user knows the explainer ran (an empty table
/// would otherwise look like a parsing bug).
fn print_explained_command_matches(matches: &[query_ext::ExplainedCommandMatch]) {
    println!("All matching command rules:");
    if matches.is_empty() {
        println!("  (policy configures no allowed_commands or blocked_commands)");
        return;
    }
    println!("  {:<32}  {:<20}  MATCHES?", "RULE", "LIST");
    for m in matches {
        // Rule names cap at 32 chars to keep the column aligned. Long
        // entries (rare — these are usually short binary names) get
        // an ellipsis prefix mirroring the path renderer.
        let rule = if m.rule.len() > 32 {
            format!("…{}", &m.rule[m.rule.len() - 31..])
        } else {
            m.rule.clone()
        };
        println!(
            "  {:<32}  {:<20}  {}",
            rule,
            m.list,
            if m.matches { "yes" } else { "no" }
        );
    }
}
