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

    // For `--path --explain` we need the full match list alongside the
    // verdict; non-path queries fall back to the regular `query_path`/
    // `query_network`/etc. paths since the explainer is path-specific.
    let mut explained_matches: Option<Vec<query_ext::ExplainedMatch>> = None;
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
            explained_matches = Some(matches);
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
        query_ext::query_tcp_port(port, &caps)
    } else if let Some(ref command) = args.command_name {
        query_ext::query_command(command, &caps)?
    } else {
        return Err(NonoError::ConfigParse(
            "--path, --host, --net, --tcp or --command is required".to_string(),
        ));
    };

    if args.json {
        // When `--explain` is set alongside `--json`, wrap the document
        // so consumers get both the verdict and the full match list.
        // Without `--explain`, the document stays as the bare verdict
        // for backwards compatibility with existing tooling.
        let value = match &explained_matches {
            None => serde_json::to_value(&result),
            Some(matches) => Ok(serde_json::json!({
                "result": result,
                "matches": matches,
            })),
        }
        .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        let json = if args.compact {
            serde_json::to_string(&value)
        } else {
            serde_json::to_string_pretty(&value)
        }
        .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {}", e)))?;
        println!("{}", json);
    } else {
        print_result(&result);
        if let Some(matches) = &explained_matches {
            println!();
            print_explained_matches(matches);
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
