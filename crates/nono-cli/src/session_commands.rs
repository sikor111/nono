//! Session management command implementations.
//!
//! Handles `nono ps`, `nono stop`, `nono detach`, `nono attach`, `nono logs`,
//! `nono inspect`, and `nono prune`.

use crate::cli::{
    AttachArgs, DetachArgs, InspectArgs, LogsArgs, PruneArgs, PsArgs, PsSortBy, PsStatusFilter,
    StopArgs,
};
use crate::command_display::{format_command_line, truncate_command};
use crate::session::{self, SessionAttachment, SessionRecord, SessionStatus};
use colored::Colorize;
use nono::{NonoError, Result};
use std::collections::VecDeque;
use std::io::{BufRead, Seek, SeekFrom};
use std::path::Path;
use tracing::debug;

/// Refuse to run if we're inside a nono sandbox.
///
/// Commands that send signals or delete files (stop, prune) must not run
/// inside a sandbox — a sandboxed agent could use them to kill other
/// supervisors or tamper with session state.
fn reject_if_sandboxed(command: &str) -> Result<()> {
    if std::env::var_os("NONO_CAP_FILE").is_some() {
        return Err(NonoError::ConfigParse(format!(
            "`nono {}` cannot be used inside a sandbox.",
            command
        )));
    }
    Ok(())
}

/// Dispatch `nono ps`.
pub fn run_ps(args: &PsArgs) -> Result<()> {
    let sessions = session::list_sessions()?;
    let mut filtered: Vec<&SessionRecord> =
        sessions.iter().filter(|s| ps_matches(s, args)).collect();

    // Apply explicit --sort if provided; otherwise keep list_sessions'
    // newest-first ordering. --reverse always flips whatever order ends
    // up being shown so users can pair it with the default sort too.
    if let Some(key) = args.sort {
        filtered.sort_by(|a, b| cmp_ps(a, b, key));
    }
    if args.reverse {
        filtered.reverse();
    }

    if args.json {
        let json = serde_json::to_string_pretty(&filtered)
            .map_err(|e| nono::NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
        return Ok(());
    }

    if filtered.is_empty() {
        eprintln!("{}", empty_filter_message(args));
        return Ok(());
    }

    if args.short {
        println!("{:<16} {:<12} {:<12} COMMAND", "SESSION", "NAME", "STATUS");
        for session in &filtered {
            println!("{}", format_ps_short_row(session, 60));
        }
        return Ok(());
    }

    // Table header
    println!(
        "{:<16} {:<12} {:<12} {:<12} {:<8} {:<10} {:<14} COMMAND",
        "SESSION", "NAME", "STATUS", "ATTACH", "PID", "UPTIME", "PROFILE"
    );

    for session in &filtered {
        let name = session.name.as_deref().unwrap_or("-");
        let col_width = 12;
        let exit_code = session.exit_code.unwrap_or(-1);
        let status_text = match session.status {
            SessionStatus::Running => "running".to_string(),
            SessionStatus::Paused => "paused".to_string(),
            SessionStatus::Exited => format!("exited({exit_code})"),
        };
        let status_padded = format!("{status_text:<col_width$}");
        let status = match session.status {
            SessionStatus::Running => status_padded.green().to_string(),
            SessionStatus::Paused => status_padded.yellow().to_string(),
            SessionStatus::Exited if exit_code != 0 => status_padded.red().to_string(),
            _ => status_padded,
        };

        let attach_text = match session.status {
            SessionStatus::Exited => "-".to_string(),
            _ => match session.attachment {
                SessionAttachment::Attached => "attached".to_string(),
                SessionAttachment::Detached => "detached".to_string(),
            },
        };
        let attach_padded = format!("{attach_text:<col_width$}");
        let attach = match (&session.status, &session.attachment) {
            (SessionStatus::Exited, _) => attach_padded,
            (_, SessionAttachment::Attached) => attach_padded.green().to_string(),
            (_, SessionAttachment::Detached) => attach_padded.yellow().to_string(),
        };
        let pid = session.child_pid;
        let uptime = format_uptime(&session.started);
        let profile = session.profile.as_deref().unwrap_or("-");
        let command = truncate_command(&session.command, 40);

        println!(
            "{:<16} {:<12} {} {} {:<8} {:<10} {:<14} {}",
            session.session_id, name, status, attach, pid, uptime, profile, command
        );
    }

    Ok(())
}

/// Decide whether a session passes the active `nono ps` filters.
///
/// Filters compose as AND: a session must satisfy every flag the user
/// supplied. The status decision is layered:
///
/// 1. If `--status` is set, only sessions with that status pass.
/// 2. Else if `--all` is set, every status passes.
/// 3. Otherwise the legacy default applies — exited sessions are hidden.
///
/// On top of that, `--name` and `--profile` apply if set.
fn ps_matches(s: &SessionRecord, args: &PsArgs) -> bool {
    let status_ok = match args.status {
        Some(PsStatusFilter::Running) => s.status == SessionStatus::Running,
        Some(PsStatusFilter::Paused) => s.status == SessionStatus::Paused,
        Some(PsStatusFilter::Exited) => s.status == SessionStatus::Exited,
        None => args.all || s.status != SessionStatus::Exited,
    };
    if !status_ok {
        return false;
    }

    if let Some(pat) = args.name.as_deref() {
        let needle = pat.to_lowercase();
        match s.name.as_deref() {
            Some(name) if name.to_lowercase().contains(&needle) => {}
            _ => return false,
        }
    }

    if let Some(profile) = args.profile.as_deref() {
        if s.profile.as_deref() != Some(profile) {
            return false;
        }
    }

    true
}

/// Render a single session as a compact, color-free row for `nono ps --short`.
///
/// Drops the columns least relevant to "which session is which?" (PID,
/// UPTIME, PROFILE, ATTACH) and skips ANSI color codes so the output
/// pipes cleanly into `awk`/`cut`/`column`. Status text keeps the
/// `exited(<code>)` suffix because the exit code is the single most
/// useful piece of information for a finished session.
fn format_ps_short_row(record: &SessionRecord, max_command_len: usize) -> String {
    let name = record.name.as_deref().unwrap_or("-");
    let exit_code = record.exit_code.unwrap_or(-1);
    let status = match record.status {
        SessionStatus::Running => "running".to_string(),
        SessionStatus::Paused => "paused".to_string(),
        SessionStatus::Exited => format!("exited({exit_code})"),
    };
    let command = truncate_command(&record.command, max_command_len);
    format!(
        "{:<16} {:<12} {:<12} {}",
        record.session_id, name, status, command
    )
}

/// Numeric rank for `SessionStatus` so `--sort status` gives the most
/// useful ordering: live work first (running ▶ paused), exited last.
fn status_rank(status: &SessionStatus) -> u8 {
    match status {
        SessionStatus::Running => 0,
        SessionStatus::Paused => 1,
        SessionStatus::Exited => 2,
    }
}

/// Compare two session records under the requested `nono ps --sort` key.
///
/// Each key has a "natural" order users typically expect; `--reverse`
/// flips whichever ordering ends up being applied. Optional fields
/// (`name`, `profile`) are ranked AFTER any populated value because
/// "no name" is rarely what you're looking for in a sorted listing.
fn cmp_ps(a: &SessionRecord, b: &SessionRecord, key: PsSortBy) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match key {
        // Default user-facing newest-first: bigger epoch ⇒ earlier in the
        // list, matching `list_sessions`. Tiebreak by session_id so the
        // sort is stable across equal timestamps.
        PsSortBy::Started => b
            .started_epoch
            .cmp(&a.started_epoch)
            .then_with(|| a.session_id.cmp(&b.session_id)),
        PsSortBy::Name => match (a.name.as_deref(), b.name.as_deref()) {
            (Some(x), Some(y)) => x.cmp(y).then_with(|| a.session_id.cmp(&b.session_id)),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => a.session_id.cmp(&b.session_id),
        },
        PsSortBy::Status => status_rank(&a.status)
            .cmp(&status_rank(&b.status))
            .then_with(|| b.started_epoch.cmp(&a.started_epoch))
            .then_with(|| a.session_id.cmp(&b.session_id)),
        PsSortBy::Profile => match (a.profile.as_deref(), b.profile.as_deref()) {
            (Some(x), Some(y)) => x.cmp(y).then_with(|| a.session_id.cmp(&b.session_id)),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => a.session_id.cmp(&b.session_id),
        },
    }
}

/// Build the user-facing "no sessions" message that mirrors the active
/// filter set, so the user understands *why* the table is empty.
fn empty_filter_message(args: &PsArgs) -> &'static str {
    if args.name.is_some() || args.profile.is_some() || args.status.is_some() {
        "No sessions match the requested filters."
    } else if args.all {
        "No sessions found."
    } else {
        "No running or detached sessions. Use --all to include exited sessions."
    }
}

/// Format uptime from an ISO 8601 start time string.
fn format_uptime(started: &str) -> String {
    let Ok(start) = chrono::DateTime::parse_from_rfc3339(started) else {
        return "-".to_string();
    };
    let now = chrono::Local::now();
    let duration = now.signed_duration_since(start);

    if duration.num_days() > 0 {
        format!("{}d", duration.num_days())
    } else if duration.num_hours() > 0 {
        format!("{}h", duration.num_hours())
    } else if duration.num_minutes() > 0 {
        format!("{}m", duration.num_minutes())
    } else {
        format!("{}s", duration.num_seconds().max(0))
    }
}

/// Dispatch `nono stop`.
pub fn run_stop(args: &StopArgs) -> Result<()> {
    reject_if_sandboxed("stop")?;
    let record = session::load_session(&args.session)?;

    if record.status == SessionStatus::Exited {
        return Err(NonoError::ConfigParse(format!(
            "Session {} is already exited",
            record.session_id
        )));
    }

    if !session::is_process_alive(record.supervisor_pid, record.started_epoch) {
        return Err(NonoError::ConfigParse(format!(
            "Session {} supervisor (PID {}) is no longer running",
            record.session_id, record.supervisor_pid
        )));
    }

    let pid = nix::unistd::Pid::from_raw(record.supervisor_pid as i32);

    if args.force {
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL)
            .map_err(|e| NonoError::ConfigParse(format!("Failed to send SIGKILL: {}", e)))?;
        eprintln!("Stopped session {}.", record.session_id);
    } else {
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM)
            .map_err(|e| NonoError::ConfigParse(format!("Failed to send SIGTERM: {}", e)))?;

        // Wait for the process to exit with a timeout
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(args.timeout);
        loop {
            if !session::is_process_alive(record.supervisor_pid, record.started_epoch) {
                eprintln!("Stopped session {}.", record.session_id);
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL);
                eprintln!("Stopped session {} (forced).", record.session_id);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    }

    Ok(())
}

/// Dispatch `nono detach`.
pub fn run_detach(args: &DetachArgs) -> Result<()> {
    reject_if_sandboxed("detach")?;
    let record = session::load_session(&args.session)?;

    if record.attachment == SessionAttachment::Detached {
        eprintln!("Session {} is already detached.", record.session_id);
        return Ok(());
    }

    if record.status != SessionStatus::Running {
        return Err(NonoError::ConfigParse(format!(
            "Session {} is not running (status: {:?})",
            record.session_id, record.status
        )));
    }

    if !session::is_process_alive(record.supervisor_pid, record.started_epoch) {
        return Err(NonoError::ConfigParse(format!(
            "Session {} supervisor (PID {}) is no longer running",
            record.session_id, record.supervisor_pid
        )));
    }

    crate::pty_proxy::request_session_detach(&record.session_id)?;

    eprintln!("Detached session {}.", record.session_id);
    Ok(())
}

/// Dispatch `nono attach`.
pub fn run_attach(args: &AttachArgs) -> Result<()> {
    reject_if_sandboxed("attach")?;
    let record = session::load_session(&args.session)?;

    if record.status == SessionStatus::Exited {
        match record.exit_code {
            Some(code) => {
                eprintln!(
                    "[nono] Session {} has already exited (exit code {}).",
                    record.session_id, code
                );
            }
            None => {
                eprintln!("[nono] Session {} has already exited.", record.session_id);
            }
        }
        return Ok(());
    }

    if !session::is_process_alive(record.supervisor_pid, record.started_epoch) {
        return Err(NonoError::ConfigParse(format!(
            "Session {} supervisor (PID {}) is no longer running",
            record.session_id, record.supervisor_pid
        )));
    }

    eprintln!("[nono] Attaching to session {}...", record.session_id);

    if record.status == SessionStatus::Paused {
        return Err(NonoError::ConfigParse(format!(
            "Session {} is paused/stopped and cannot accept attach",
            record.session_id
        )));
    }

    match crate::pty_proxy::attach_to_session(&record.session_id) {
        Err(NonoError::AttachBusy) => {
            eprintln!(
                "[nono] Session {} already has an active attached client.",
                record.session_id
            );
            Ok(())
        }
        Err(NonoError::SessionGone) => {
            eprintln!(
                "[nono] Session {} exited before attach could complete.",
                record.session_id
            );
            Ok(())
        }
        other => other,
    }
}

/// Dispatch `nono logs` — placeholder for Step 3.
pub fn run_logs(args: &LogsArgs) -> Result<()> {
    let record = session::load_session(&args.session)?;
    let events_path = session::session_events_path(&record.session_id)?;

    if !events_path.exists() {
        eprintln!("No event log recorded for session {}.", record.session_id);
        return Ok(());
    }

    if args.follow {
        follow_event_log(&events_path, args.tail, args.json)
    } else {
        let lines = read_event_log_lines(&events_path, args.tail)?;
        print_event_log_lines(&lines, args.json)
    }
}

/// Dispatch `nono inspect`.
pub fn run_inspect(args: &InspectArgs) -> Result<()> {
    let record = session::load_session(&args.session)?;

    // When --events is set, eagerly read the event log so both human and
    // JSON modes can use the same data. A missing log is not an error
    // (the session may have exited before any events were written) — we
    // surface an empty list instead of failing.
    let event_lines: Option<Vec<String>> = if args.events {
        let events_path = session::session_events_path(&record.session_id)?;
        if events_path.exists() {
            Some(read_event_log_lines(&events_path, args.logs_tail)?)
        } else {
            Some(Vec::new())
        }
    } else {
        None
    };

    if args.json {
        let value = match &event_lines {
            None => serde_json::to_value(&record)
                .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?,
            Some(lines) => {
                // Each ndjson line is itself a JSON document; preserve that
                // structure so consumers don't have to re-parse strings.
                let events: Vec<serde_json::Value> = lines
                    .iter()
                    .map(|line| {
                        serde_json::from_str::<serde_json::Value>(line)
                            .unwrap_or_else(|_| serde_json::Value::String(line.clone()))
                    })
                    .collect();
                serde_json::json!({
                    "session": record,
                    "events": events,
                })
            }
        };
        let json = serde_json::to_string_pretty(&value)
            .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
        return Ok(());
    }

    println!("Session:    {}", record.session_id);
    if let Some(ref name) = record.name {
        println!("Name:       {}", name);
    }
    println!("Status:     {:?}", record.status);
    println!("Attached:   {:?}", record.attachment);
    println!(
        "PID:        {} (supervisor: {})",
        record.child_pid, record.supervisor_pid
    );
    println!("Started:    {}", record.started);
    if let Some(code) = record.exit_code {
        println!("Exit code:  {}", code);
    }
    println!("Command:    {}", format_command_line(&record.command));
    if let Some(ref profile) = record.profile {
        println!("Profile:    {}", profile);
    }
    println!("Workdir:    {}", record.workdir.display());
    println!("Network:    {}", record.network);
    if let Some(ref rollback) = record.rollback_session {
        println!("Rollback:   {}", rollback);
    }

    if let Some(lines) = event_lines {
        let header = match args.logs_tail {
            Some(n) => format!("\nEVENTS (last {n}):"),
            None => "\nEVENTS:".to_string(),
        };
        println!("{header}");
        if lines.is_empty() {
            println!("  (no events recorded)");
        } else {
            for line in &lines {
                println!("{line}");
            }
        }
    }

    Ok(())
}

/// Dispatch `nono prune`.
pub fn run_prune(args: &PruneArgs) -> Result<()> {
    reject_if_sandboxed("prune")?;
    let sessions = session::list_sessions()?;

    let now = chrono::Utc::now();
    let mut to_remove: Vec<&SessionRecord> = Vec::new();

    for s in &sessions {
        // Skip running sessions
        if s.status == SessionStatus::Running {
            continue;
        }

        let should_remove = if let Some(days) = args.older_than {
            if let Ok(started) = chrono::DateTime::parse_from_rfc3339(&s.started) {
                let age = now.signed_duration_since(started);
                age.num_days() >= days as i64
            } else {
                false
            }
        } else {
            true // No age filter: all exited sessions are candidates
        };

        if should_remove {
            to_remove.push(s);
        }
    }

    // Apply --keep: keep the N most recent, remove the rest
    if let Some(keep) = args.keep {
        // to_remove is sorted newest-first (from list_sessions), so skip the first `keep`
        if to_remove.len() > keep {
            to_remove = to_remove[keep..].to_vec();
        } else {
            to_remove.clear();
        }
    }

    if to_remove.is_empty() {
        eprintln!("Nothing to prune.");
        return Ok(());
    }

    let dir = session::sessions_dir()?;

    for s in &to_remove {
        let session_file = dir.join(format!("{}.json", s.session_id));
        let events_file = dir.join(format!("{}.events.ndjson", s.session_id));

        if args.dry_run {
            eprintln!("Would remove: {} (started {})", s.session_id, s.started);
        } else {
            if let Err(e) = std::fs::remove_file(&session_file) {
                debug!(
                    "Failed to remove session file {}: {}",
                    session_file.display(),
                    e
                );
            }
            if events_file.exists() {
                if let Err(e) = std::fs::remove_file(&events_file) {
                    debug!(
                        "Failed to remove events file {}: {}",
                        events_file.display(),
                        e
                    );
                }
            }
            eprintln!("Removed: {} (started {})", s.session_id, s.started);
        }
    }

    eprintln!(
        "\n{} {} session(s).",
        if args.dry_run {
            "Would prune"
        } else {
            "Pruned"
        },
        to_remove.len()
    );

    Ok(())
}

fn read_event_log_lines(path: &Path, tail: Option<usize>) -> Result<Vec<String>> {
    let file = std::fs::File::open(path).map_err(|e| NonoError::ConfigRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    let reader = std::io::BufReader::new(file);

    if let Some(limit) = tail {
        let mut lines = VecDeque::with_capacity(limit.min(256));
        for line in reader.lines() {
            let line = line.map_err(|e| NonoError::ConfigRead {
                path: path.to_path_buf(),
                source: e,
            })?;
            if lines.len() == limit {
                let _ = lines.pop_front();
            }
            lines.push_back(line);
        }
        Ok(lines.into_iter().collect())
    } else {
        reader
            .lines()
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| NonoError::ConfigRead {
                path: path.to_path_buf(),
                source: e,
            })
    }
}

fn print_event_log_lines(lines: &[String], as_json: bool) -> Result<()> {
    if as_json {
        let values: Vec<serde_json::Value> = lines
            .iter()
            .map(|line| {
                serde_json::from_str::<serde_json::Value>(line)
                    .unwrap_or_else(|_| serde_json::Value::String(line.clone()))
            })
            .collect();
        let json = serde_json::to_string_pretty(&values)
            .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
    } else {
        for line in lines {
            println!("{line}");
        }
    }
    Ok(())
}

fn follow_event_log(path: &Path, tail: Option<usize>, as_json: bool) -> Result<()> {
    let initial_lines = read_event_log_lines(path, tail)?;
    if as_json {
        for line in &initial_lines {
            println!("{line}");
        }
    } else {
        print_event_log_lines(&initial_lines, false)?;
    }

    let mut file = std::fs::File::open(path).map_err(|e| NonoError::ConfigRead {
        path: path.to_path_buf(),
        source: e,
    })?;
    file.seek(SeekFrom::End(0))
        .map_err(|e| NonoError::ConfigRead {
            path: path.to_path_buf(),
            source: e,
        })?;
    let mut reader = std::io::BufReader::new(file);

    loop {
        let mut line = String::new();
        let bytes = reader
            .read_line(&mut line)
            .map_err(|e| NonoError::ConfigRead {
                path: path.to_path_buf(),
                source: e,
            })?;
        if bytes == 0 {
            std::thread::sleep(std::time::Duration::from_millis(250));
            continue;
        }
        print!("{}", line);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_uptime_seconds() {
        let now = chrono::Local::now();
        let started = (now - chrono::Duration::seconds(30)).to_rfc3339();
        let result = format_uptime(&started);
        assert!(result.ends_with('s'));
    }

    #[test]
    fn test_format_uptime_minutes() {
        let now = chrono::Local::now();
        let started = (now - chrono::Duration::minutes(5)).to_rfc3339();
        let result = format_uptime(&started);
        assert!(result.ends_with('m'));
    }

    fn make_record(
        id: &str,
        name: Option<&str>,
        profile: Option<&str>,
        status: SessionStatus,
    ) -> SessionRecord {
        SessionRecord {
            session_id: id.to_string(),
            name: name.map(str::to_string),
            supervisor_pid: 1,
            child_pid: 2,
            started: "2026-04-30T22:00:00+00:00".to_string(),
            started_epoch: 0,
            status,
            attachment: SessionAttachment::Detached,
            exit_code: None,
            command: vec!["echo".to_string()],
            profile: profile.map(str::to_string),
            workdir: std::path::PathBuf::from("/tmp"),
            network: "blocked".to_string(),
            rollback_session: None,
        }
    }

    fn ps_args() -> PsArgs {
        PsArgs {
            json: false,
            all: false,
            name: None,
            profile: None,
            status: None,
            sort: None,
            reverse: false,
            short: false,
        }
    }

    #[test]
    fn ps_filter_default_hides_exited_but_keeps_running() {
        let running = make_record("a", None, None, SessionStatus::Running);
        let exited = make_record("b", None, None, SessionStatus::Exited);
        let args = ps_args();
        assert!(ps_matches(&running, &args));
        assert!(!ps_matches(&exited, &args));
    }

    #[test]
    fn ps_filter_all_includes_exited() {
        let exited = make_record("b", None, None, SessionStatus::Exited);
        let args = PsArgs {
            all: true,
            ..ps_args()
        };
        assert!(ps_matches(&exited, &args));
    }

    #[test]
    fn ps_filter_status_overrides_default_and_pins_a_single_status() {
        let running = make_record("a", None, None, SessionStatus::Running);
        let exited = make_record("b", None, None, SessionStatus::Exited);
        let paused = make_record("c", None, None, SessionStatus::Paused);

        let args = PsArgs {
            status: Some(PsStatusFilter::Exited),
            ..ps_args()
        };
        // No --all needed: --status exited should let exited sessions through.
        assert!(ps_matches(&exited, &args));
        assert!(!ps_matches(&running, &args));
        assert!(!ps_matches(&paused, &args));
    }

    #[test]
    fn ps_filter_name_uses_case_insensitive_substring_and_skips_unnamed() {
        let claude = make_record("a", Some("Claude-1"), None, SessionStatus::Running);
        let codex = make_record("b", Some("codex"), None, SessionStatus::Running);
        let unnamed = make_record("c", None, None, SessionStatus::Running);
        let args = PsArgs {
            name: Some("CLAUDE".to_string()),
            ..ps_args()
        };
        assert!(ps_matches(&claude, &args), "case-insensitive substring");
        assert!(!ps_matches(&codex, &args));
        assert!(
            !ps_matches(&unnamed, &args),
            "sessions without a name are filtered out, not matched"
        );
    }

    #[test]
    fn ps_filter_profile_requires_exact_match_and_skips_unprofiled() {
        let claude = make_record("a", None, Some("claude-code"), SessionStatus::Running);
        let claude_stretch = make_record(
            "b",
            None,
            Some("claude-code-stretch"),
            SessionStatus::Running,
        );
        let no_profile = make_record("c", None, None, SessionStatus::Running);
        let args = PsArgs {
            profile: Some("claude-code".to_string()),
            ..ps_args()
        };
        assert!(ps_matches(&claude, &args));
        assert!(
            !ps_matches(&claude_stretch, &args),
            "exact match — substring of another profile must NOT pass"
        );
        assert!(!ps_matches(&no_profile, &args));
    }

    #[test]
    fn ps_filter_combines_filters_with_and() {
        let target = make_record(
            "a",
            Some("review-bot"),
            Some("default"),
            SessionStatus::Running,
        );
        let wrong_profile = make_record(
            "b",
            Some("review-bot"),
            Some("opencode"),
            SessionStatus::Running,
        );
        let wrong_name = make_record("c", Some("other"), Some("default"), SessionStatus::Running);
        let args = PsArgs {
            name: Some("review".to_string()),
            profile: Some("default".to_string()),
            ..ps_args()
        };
        assert!(ps_matches(&target, &args));
        assert!(!ps_matches(&wrong_profile, &args));
        assert!(!ps_matches(&wrong_name, &args));
    }

    fn sort_session_ids(records: &[SessionRecord], key: PsSortBy) -> Vec<&str> {
        let mut refs: Vec<&SessionRecord> = records.iter().collect();
        refs.sort_by(|a, b| cmp_ps(a, b, key));
        refs.iter().map(|r| r.session_id.as_str()).collect()
    }

    fn dated_record(id: &str, epoch: u64, status: SessionStatus) -> SessionRecord {
        SessionRecord {
            started_epoch: epoch,
            ..make_record(id, None, None, status)
        }
    }

    #[test]
    fn ps_sort_started_puts_newest_first() {
        let records = vec![
            dated_record("old", 100, SessionStatus::Running),
            dated_record("new", 300, SessionStatus::Running),
            dated_record("mid", 200, SessionStatus::Running),
        ];
        assert_eq!(
            sort_session_ids(&records, PsSortBy::Started),
            vec!["new", "mid", "old"],
            "newer started_epoch must come first under --sort started"
        );
    }

    #[test]
    fn ps_sort_status_orders_running_before_paused_before_exited() {
        let records = vec![
            dated_record("e", 100, SessionStatus::Exited),
            dated_record("r", 100, SessionStatus::Running),
            dated_record("p", 100, SessionStatus::Paused),
        ];
        assert_eq!(
            sort_session_ids(&records, PsSortBy::Status),
            vec!["r", "p", "e"],
            "active sessions surface before exited ones",
        );
    }

    #[test]
    fn ps_sort_name_is_alpha_with_unnamed_last() {
        let records = vec![
            make_record("a", None, None, SessionStatus::Running),
            make_record("b", Some("zeta"), None, SessionStatus::Running),
            make_record("c", Some("alpha"), None, SessionStatus::Running),
        ];
        assert_eq!(
            sort_session_ids(&records, PsSortBy::Name),
            vec!["c", "b", "a"],
            "named sessions sort alphabetically; unnamed go last",
        );
    }

    #[test]
    fn ps_sort_profile_is_alpha_with_unprofiled_last() {
        let records = vec![
            make_record("a", None, Some("rust-dev"), SessionStatus::Running),
            make_record("b", None, None, SessionStatus::Running),
            make_record("c", None, Some("default"), SessionStatus::Running),
        ];
        assert_eq!(
            sort_session_ids(&records, PsSortBy::Profile),
            vec!["c", "a", "b"],
            "profiled sessions sort alphabetically; unprofiled go last",
        );
    }

    #[test]
    fn ps_sort_started_is_stable_via_session_id_tiebreak() {
        // Identical epochs: tiebreak by session_id ascending so the order
        // is deterministic between runs.
        let records = vec![
            dated_record("zzz", 100, SessionStatus::Running),
            dated_record("aaa", 100, SessionStatus::Running),
            dated_record("mmm", 100, SessionStatus::Running),
        ];
        assert_eq!(
            sort_session_ids(&records, PsSortBy::Started),
            vec!["aaa", "mmm", "zzz"],
        );
    }

    fn full_record_for_short_row(
        id: &str,
        name: Option<&str>,
        status: SessionStatus,
        exit_code: Option<i32>,
        command: Vec<String>,
    ) -> SessionRecord {
        SessionRecord {
            exit_code,
            command,
            ..make_record(id, name, None, status)
        }
    }

    #[test]
    fn ps_short_row_omits_ansi_and_uses_named_status_for_running() {
        let rec = full_record_for_short_row(
            "abc12345",
            Some("claude-1"),
            SessionStatus::Running,
            None,
            vec!["echo".to_string(), "hi".to_string()],
        );
        let row = format_ps_short_row(&rec, 60);

        assert!(
            !row.contains('\x1b'),
            "short row must be plain text (no ANSI escapes): {row:?}"
        );
        assert!(row.contains("abc12345"));
        assert!(row.contains("claude-1"));
        assert!(row.contains("running"));
        assert!(row.contains("echo hi"));
    }

    #[test]
    fn ps_short_row_renders_exit_code_for_exited_status() {
        let rec = full_record_for_short_row(
            "deadbeef",
            None,
            SessionStatus::Exited,
            Some(127),
            vec!["bash".to_string(), "-c".to_string(), "false".to_string()],
        );
        let row = format_ps_short_row(&rec, 60);

        assert!(
            row.contains("exited(127)"),
            "exit code must be visible after the status word: {row:?}"
        );
        // Unnamed sessions render as `-` to keep column alignment stable.
        assert!(row.contains(" - "));
    }

    #[test]
    fn ps_short_row_truncates_command_to_max_len() {
        let long: String = "x".repeat(200);
        let rec = full_record_for_short_row("abc", None, SessionStatus::Running, None, vec![long]);
        let row = format_ps_short_row(&rec, 32);
        // The truncate helper uses an ellipsis; the visible command must
        // never exceed the cap (give a small fudge for trailing chars).
        let cmd_section = row.split_whitespace().last().unwrap_or("");
        assert!(
            cmd_section.chars().count() <= 35,
            "command got past max_command_len: {cmd_section:?}"
        );
    }

    #[test]
    fn empty_filter_message_reflects_active_flags() {
        let plain = ps_args();
        assert!(empty_filter_message(&plain).contains("Use --all"));

        let with_all = PsArgs {
            all: true,
            ..ps_args()
        };
        assert_eq!(empty_filter_message(&with_all), "No sessions found.");

        let with_filter = PsArgs {
            profile: Some("default".to_string()),
            ..ps_args()
        };
        assert!(empty_filter_message(&with_filter).contains("filters"));
    }
}
