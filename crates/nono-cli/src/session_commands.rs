//! Session management command implementations.
//!
//! Handles `nono ps`, `nono stop`, `nono detach`, `nono attach`, `nono logs`,
//! `nono inspect`, and `nono prune`.

use crate::cli::{
    AttachArgs, DetachArgs, InspectArgs, LogsArgs, PruneArgs, PsArgs, PsColumn, PsHeaderFormat,
    PsOutputFormat, PsSortBy, PsStatusFilter, StopArgs,
};
use crate::command_display::{format_command_line, truncate_command};
use crate::session::{self, SessionAttachment, SessionRecord, SessionStatus};
use colored::Colorize;
use nono::{NonoError, Result};
use std::collections::VecDeque;
use std::io::{BufRead, IsTerminal, Seek, SeekFrom};
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
    if let Some(spec) = args.watch.as_deref() {
        let interval = parse_duration_to_secs(spec)?;
        let dur = std::time::Duration::from_secs(interval);
        // `--max-iterations` bounds the loop. None = unlimited
        // (legacy behavior); Some(n) prints n frames and exits.
        // Sleep after the last frame is skipped so callers don't
        // wait an extra interval after the final render.
        let mut iterations_remaining: Option<u64> = args.max_iterations;
        loop {
            // ANSI clear-screen + home-cursor. Users wired up to a
            // non-ANSI terminal would see escape codes, but `--watch`
            // is opt-in interactive — they wouldn't ask for it from
            // a dumb pipe.
            print!("\x1b[2J\x1b[H");
            std::io::Write::flush(&mut std::io::stdout()).ok();
            // Print a refresh banner so the user can tell at a glance
            // whether the screen is alive and how often it ticks.
            // Going through chrono::Local so the time is in the user's
            // local zone rather than UTC.
            println!("{}", format_watch_banner(chrono::Local::now(), interval));
            println!();
            print_ps_table_once(args)?;

            if let Some(ref mut remaining) = iterations_remaining {
                *remaining = remaining.saturating_sub(1);
                if *remaining == 0 {
                    return Ok(());
                }
            }

            std::thread::sleep(dur);
        }
    }
    print_ps_table_once(args)
}

/// Format the `nono ps --watch` header line shown above each refresh.
///
/// Pure formatter so the header layout is unit-testable without
/// spawning the watch loop. Uses HH:MM:SS local time + the interval in
/// seconds — terminal-friendly width, no date (the watch loop survives
/// midnight rollover, but a human watching `top` doesn't need the date
/// every refresh).
fn format_watch_banner(now: chrono::DateTime<chrono::Local>, interval_secs: u64) -> String {
    format!(
        "nono ps  -  refreshed {}  (every {}s)",
        now.format("%H:%M:%S"),
        interval_secs,
    )
}

/// Divider width for the `--short` layout: 3 padded columns +
/// COMMAND. The default layout no longer has a constant — its width
/// is computed dynamically from the rendered header so `--columns`
/// subsets get the right divider length without per-layout constants.
const PS_SHORT_TABLE_WIDTH: usize = 16 + 1 + 12 + 1 + 12 + 1 + "COMMAND".len();

/// Render the table header — column titles followed by a divider —
/// per the user's chosen `PsHeaderFormat`. Returns `None` for `None`
/// so the caller can decide whether to print or skip both lines as a
/// unit (skipping the header without the divider would leave a stray
/// horizontal rule).
fn render_ps_header(
    fmt: PsHeaderFormat,
    header_line: &str,
    divider_width: usize,
) -> Option<String> {
    let divider_char = match fmt {
        PsHeaderFormat::Fancy => '─',
        PsHeaderFormat::Ascii => '-',
        PsHeaderFormat::None => return None,
    };
    let divider: String = std::iter::repeat(divider_char)
        .take(divider_width)
        .collect();
    Some(format!("{header_line}\n{divider}"))
}

/// Render the COMMAND column for a single ps row, honoring the
/// `--no-truncate` opt-in. Centralized so the default and `--short`
/// branches stay in lockstep — diverging behavior between the two
/// renderers (e.g. `--no-truncate` working in `--short` but not in
/// the default table) is the obvious latent bug.
fn render_ps_command(command: &[String], no_truncate: bool, max_len: usize) -> String {
    if no_truncate {
        format_command_line(command)
    } else {
        truncate_command(command, max_len)
    }
}

/// Canonical column order — what users get when they don't pass
/// `--columns`. Matches the `PsColumn` variant order exactly; bumping
/// either side without the other would silently reorder the default
/// table, which is the obvious user-visible regression.
const DEFAULT_PS_COLUMNS: &[PsColumn] = &[
    PsColumn::Session,
    PsColumn::Name,
    PsColumn::Status,
    PsColumn::Attach,
    PsColumn::Pid,
    PsColumn::Uptime,
    PsColumn::Profile,
    PsColumn::Command,
];

/// Header text + padded width for each column. The COMMAND column
/// has width 0 because its rendered cell is variable-length (driven
/// by `--no-truncate` and the 40-char cap); padding it would just
/// add trailing spaces with no benefit.
fn column_meta(col: PsColumn) -> (&'static str, usize) {
    match col {
        PsColumn::Session => ("SESSION", 16),
        PsColumn::Name => ("NAME", 12),
        PsColumn::Status => ("STATUS", 12),
        PsColumn::Attach => ("ATTACH", 12),
        PsColumn::Pid => ("PID", 8),
        PsColumn::Uptime => ("UPTIME", 10),
        PsColumn::Profile => ("PROFILE", 14),
        PsColumn::Command => ("COMMAND", 0),
    }
}

/// Render the column-title row for the selected columns. Joining with
/// a single space matches the row builder so header and cells align.
fn render_default_header_row(columns: &[PsColumn]) -> String {
    columns
        .iter()
        .map(|&col| {
            let (header, width) = column_meta(col);
            if width == 0 {
                header.to_string()
            } else {
                format!("{header:<width$}")
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render a single data row across the selected columns, joining
/// cells with one space. Per-cell rendering is delegated to
/// `render_default_cell` so the per-column logic (ANSI colors,
/// command truncation, status formatting) lives in one place.
fn render_default_data_row(
    session: &SessionRecord,
    columns: &[PsColumn],
    no_truncate: bool,
) -> String {
    columns
        .iter()
        .map(|&col| render_default_cell(col, session, no_truncate))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Render one cell for the default table. ANSI coloring on the
/// status / attach cells is preserved across re-orderings — splitting
/// the loop out shouldn't lose the color attribution that drove the
/// original verbose format string.
fn render_default_cell(col: PsColumn, session: &SessionRecord, no_truncate: bool) -> String {
    match col {
        PsColumn::Session => format!("{:<16}", session.session_id),
        PsColumn::Name => format!("{:<12}", session.name.as_deref().unwrap_or("-")),
        PsColumn::Status => render_status_cell(session, 12),
        PsColumn::Attach => render_attach_cell(session, 12),
        PsColumn::Pid => format!("{:<8}", session.child_pid),
        PsColumn::Uptime => format!("{:<10}", format_uptime(&session.started)),
        PsColumn::Profile => format!("{:<14}", session.profile.as_deref().unwrap_or("-")),
        PsColumn::Command => render_ps_command(&session.command, no_truncate, 40),
    }
}

/// Render the STATUS cell with status-specific ANSI coloring
/// (green = running, yellow = paused, red = exited with non-zero).
fn render_status_cell(session: &SessionRecord, width: usize) -> String {
    let exit_code = session.exit_code.unwrap_or(-1);
    let status_text = match session.status {
        SessionStatus::Running => "running".to_string(),
        SessionStatus::Paused => "paused".to_string(),
        SessionStatus::Exited => format!("exited({exit_code})"),
    };
    let padded = format!("{status_text:<width$}");
    match session.status {
        SessionStatus::Running => padded.green().to_string(),
        SessionStatus::Paused => padded.yellow().to_string(),
        SessionStatus::Exited if exit_code != 0 => padded.red().to_string(),
        _ => padded,
    }
}

/// Render the ATTACH cell with attachment-specific coloring.
/// Exited sessions render `-` (no color) since attachment is moot.
fn render_attach_cell(session: &SessionRecord, width: usize) -> String {
    let attach_text = match session.status {
        SessionStatus::Exited => "-".to_string(),
        _ => match session.attachment {
            SessionAttachment::Attached => "attached".to_string(),
            SessionAttachment::Detached => "detached".to_string(),
        },
    };
    let padded = format!("{attach_text:<width$}");
    match (&session.status, &session.attachment) {
        (SessionStatus::Exited, _) => padded,
        (_, SessionAttachment::Attached) => padded.green().to_string(),
        (_, SessionAttachment::Detached) => padded.yellow().to_string(),
    }
}

fn print_ps_table_once(args: &PsArgs) -> Result<()> {
    let sessions = session::list_sessions()?;
    // Translate `--since 1h` into an epoch threshold once so the filter
    // closure stays pure and testable.
    let since_threshold: Option<u64> = match args.since.as_deref() {
        None => None,
        Some(input) => {
            let dur = parse_duration_to_secs(input)?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| NonoError::ConfigParse(format!("system time before UNIX epoch: {e}")))?
                .as_secs();
            Some(now.saturating_sub(dur))
        }
    };
    let mut filtered: Vec<&SessionRecord> = sessions
        .iter()
        .filter(|s| ps_matches(s, args, since_threshold))
        .collect();

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
        if let Some(ref field) = args.field {
            // `--field` short-circuits the full-document render. The
            // session list is an array, so JSON Pointer paths like
            // `/0/name` reach individual entries (and `/0` returns
            // the first entry as JSON). Same shell-friendly
            // semantics as the other --field surfaces.
            let value = serde_json::to_value(&filtered).map_err(|e| {
                nono::NonoError::ConfigParse(format!("JSON serialization failed: {e}"))
            })?;
            let extracted =
                crate::field_extract::extract_field_output(&value, field, args.compact)?;
            println!("{extracted}");
            return Ok(());
        }
        let json = if args.compact {
            serde_json::to_string(&filtered)
        } else {
            serde_json::to_string_pretty(&filtered)
        }
        .map_err(|e| nono::NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
        return Ok(());
    }

    if let Some(fmt) = args.output {
        // Tabular text formats always emit the header so consumers can
        // detect column count without separately checking the row count.
        print!("{}", format_ps_tabular(&filtered, fmt));
        return Ok(());
    }

    if filtered.is_empty() {
        eprintln!("{}", empty_filter_message(args));
        return Ok(());
    }

    if args.short {
        let header = format!("{:<16} {:<12} {:<12} COMMAND", "SESSION", "NAME", "STATUS");
        if let Some(rendered) = render_ps_header(args.header_format, &header, PS_SHORT_TABLE_WIDTH)
        {
            println!("{rendered}");
        }
        for session in &filtered {
            println!("{}", format_ps_short_row(session, 60, args.no_truncate));
        }
        return Ok(());
    }

    // `--columns` overrides the default canonical order; an empty
    // Vec from clap means the user didn't pass the flag, so fall
    // back to the full set. Storing the resolved view in a local
    // makes both header and body iterate over the same Vec — a
    // mismatched order between the two would silently misalign
    // every row, which is the obvious latent bug.
    let columns: Vec<PsColumn> = if args.columns.is_empty() {
        DEFAULT_PS_COLUMNS.to_vec()
    } else {
        args.columns.clone()
    };

    let header = render_default_header_row(&columns);
    // Divider matches the rendered header's character width — works
    // uniformly across `--columns` subsets without needing a separate
    // width constant per layout.
    let divider_width = header.chars().count();
    if let Some(rendered) = render_ps_header(args.header_format, &header, divider_width) {
        println!("{rendered}");
    }

    for session in &filtered {
        println!(
            "{}",
            render_default_data_row(session, &columns, args.no_truncate)
        );
    }

    Ok(())
}

/// Parse a relative-duration shorthand into seconds.
///
/// Accepts `<N><unit>` where unit is one of:
///   - `s` — seconds
///   - `m` — minutes
///   - `h` — hours
///   - `d` — days
///   - `w` — weeks (7 days)
///
/// Examples: `30s`, `15m`, `2h`, `7d`, `1w`. Compound forms (`1h30m`)
/// and bare numbers (`30`) are rejected so the unit is unambiguous.
pub(crate) fn parse_duration_to_secs(input: &str) -> Result<u64> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(NonoError::ConfigParse(
            "duration must not be empty".to_string(),
        ));
    }
    let bytes = trimmed.as_bytes();
    let last = *bytes
        .last()
        .ok_or_else(|| NonoError::ConfigParse("duration must not be empty".to_string()))?;
    if !last.is_ascii_alphabetic() {
        return Err(NonoError::ConfigParse(format!(
            "duration `{trimmed}` is missing a unit suffix (s/m/h/d/w)"
        )));
    }
    let multiplier: u64 = match last.to_ascii_lowercase() {
        b's' => 1,
        b'm' => 60,
        b'h' => 60 * 60,
        b'd' => 60 * 60 * 24,
        b'w' => 60 * 60 * 24 * 7,
        _ => {
            return Err(NonoError::ConfigParse(format!(
                "duration `{trimmed}` has unknown unit `{}` (expected s/m/h/d/w)",
                last as char,
            )))
        }
    };
    let number_part = &trimmed[..trimmed.len() - 1];
    if number_part.is_empty() {
        return Err(NonoError::ConfigParse(format!(
            "duration `{trimmed}` is missing a numeric prefix",
        )));
    }
    let n: u64 = number_part.parse().map_err(|_| {
        NonoError::ConfigParse(format!("duration `{trimmed}` has non-numeric prefix"))
    })?;
    if n == 0 {
        return Err(NonoError::ConfigParse(
            "duration must be greater than zero".to_string(),
        ));
    }
    n.checked_mul(multiplier).ok_or_else(|| {
        NonoError::ConfigParse(format!("duration `{trimmed}` overflows u64 seconds"))
    })
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
fn ps_matches(s: &SessionRecord, args: &PsArgs, since_threshold: Option<u64>) -> bool {
    // `--exit-code` only makes sense for exited sessions; if the user
    // asked for a specific code, force-narrow to Exited regardless of
    // --all / --status defaults so `nono ps --exit-code 0` doesn't have
    // to be paired with `--all` to be useful.
    if let Some(target) = args.exit_code {
        if s.status != SessionStatus::Exited {
            return false;
        }
        if s.exit_code != Some(target) {
            return false;
        }
    } else {
        let status_ok = match args.status {
            Some(PsStatusFilter::Running) => s.status == SessionStatus::Running,
            Some(PsStatusFilter::Paused) => s.status == SessionStatus::Paused,
            Some(PsStatusFilter::Exited) => s.status == SessionStatus::Exited,
            None => args.all || s.status != SessionStatus::Exited,
        };
        if !status_ok {
            return false;
        }
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

    if let Some(threshold) = since_threshold {
        if s.started_epoch < threshold {
            return false;
        }
    }

    true
}

/// CSV-escape a field per RFC 4180: wrap in `"`s if the value contains a
/// comma, quote, or newline; double any embedded `"`.
fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') || value.contains('\r') {
        let escaped = value.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        value.to_string()
    }
}

/// TSV-escape a field: TSV has no quoting rule, so the only safe option
/// is to backslash-escape characters that would break the line shape
/// (tab as the delimiter, newlines that would split the row).
fn tsv_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out
}

/// Render the session list as CSV, TSV, or NDJSON. CSV/TSV emit a
/// header row even for empty input so consumers can detect the column
/// shape. NDJSON has no header row by design — one JSON object per line.
///
/// CSV/TSV columns mirror the human-readable table minus colors /
/// per-row padding: session_id, name, status, exit_code, attach, pid,
/// uptime, started, profile, network, command. NDJSON serializes the
/// full SessionRecord (same shape as `--json`) so it's a strict
/// superset of the CSV columns.
fn format_ps_tabular(records: &[&SessionRecord], fmt: PsOutputFormat) -> String {
    if matches!(fmt, PsOutputFormat::Ndjson) {
        let mut out = String::new();
        for record in records {
            // serde_json::to_string emits compact JSON (no whitespace) —
            // perfect for line-delimited consumers. Failure is treated
            // as a skipped row rather than aborting the whole render
            // because each record is independent.
            if let Ok(line) = serde_json::to_string(record) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        return out;
    }

    let header = [
        "session_id",
        "name",
        "status",
        "exit_code",
        "attach",
        "pid",
        "uptime",
        "started",
        "profile",
        "network",
        "command",
    ];
    let (sep, escape): (&str, fn(&str) -> String) = match fmt {
        PsOutputFormat::Csv => (",", csv_escape),
        PsOutputFormat::Tsv => ("\t", tsv_escape),
        PsOutputFormat::Ndjson => unreachable!("ndjson handled above"),
    };

    let mut out = String::new();
    out.push_str(
        &header
            .iter()
            .map(|h| escape(h))
            .collect::<Vec<_>>()
            .join(sep),
    );
    out.push('\n');

    for record in records {
        let exit_code = record.exit_code.map(|c| c.to_string()).unwrap_or_default();
        let attach = match (&record.status, &record.attachment) {
            (SessionStatus::Exited, _) => "-".to_string(),
            (_, SessionAttachment::Attached) => "attached".to_string(),
            (_, SessionAttachment::Detached) => "detached".to_string(),
        };
        let status = match record.status {
            SessionStatus::Running => "running",
            SessionStatus::Paused => "paused",
            SessionStatus::Exited => "exited",
        };
        let row = [
            record.session_id.as_str(),
            record.name.as_deref().unwrap_or(""),
            status,
            exit_code.as_str(),
            attach.as_str(),
            &record.child_pid.to_string(),
            &format_uptime(&record.started),
            record.started.as_str(),
            record.profile.as_deref().unwrap_or(""),
            record.network.as_str(),
            &format_command_line(&record.command),
        ];
        out.push_str(&row.iter().map(|f| escape(f)).collect::<Vec<_>>().join(sep));
        out.push('\n');
    }
    out
}

/// Render a single session as a compact, color-free row for `nono ps --short`.
///
/// Drops the columns least relevant to "which session is which?" (PID,
/// UPTIME, PROFILE, ATTACH) and skips ANSI color codes so the output
/// pipes cleanly into `awk`/`cut`/`column`. Status text keeps the
/// `exited(<code>)` suffix because the exit code is the single most
/// useful piece of information for a finished session.
fn format_ps_short_row(
    record: &SessionRecord,
    max_command_len: usize,
    no_truncate: bool,
) -> String {
    let name = record.name.as_deref().unwrap_or("-");
    let exit_code = record.exit_code.unwrap_or(-1);
    let status = match record.status {
        SessionStatus::Running => "running".to_string(),
        SessionStatus::Paused => "paused".to_string(),
        SessionStatus::Exited => format!("exited({exit_code})"),
    };
    let command = render_ps_command(&record.command, no_truncate, max_command_len);
    format!(
        "{:<16} {:<12} {:<12} {}",
        record.session_id, name, status, command
    )
}

/// Decide whether a line of stdin counts as an affirmative confirmation.
///
/// Defaults to "no" — `[y/N]` style — so the user has to actively confirm
/// destructive operations. Accepts case-insensitive `y` or `yes` after
/// trimming surrounding whitespace; everything else (including empty
/// input from a bare Enter) is a refusal.
fn is_yes_response(input: &str) -> bool {
    let trimmed = input.trim().to_ascii_lowercase();
    trimmed == "y" || trimmed == "yes"
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
    if args.name.is_some()
        || args.profile.is_some()
        || args.status.is_some()
        || args.exit_code.is_some()
        || args.since.is_some()
    {
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

    // Resolve the on-disk path of the session record once. Surfacing it
    // alongside the JSON makes "where can I `cat` this?" answerable
    // without the user re-deriving the path from the session_id.
    let session_file = session::session_file_path(&record.session_id)?;

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
        let session_file_str = session_file.display().to_string();
        let value = match &event_lines {
            None => {
                // Without --events the document remains bare-record shape
                // for backwards compatibility with existing
                // `nono inspect --json` consumers — we just inject one
                // additional `session_file` key alongside the existing
                // fields. Adding (not removing/renaming) is safe under
                // the consumers we know.
                let mut value = serde_json::to_value(&record).map_err(|e| {
                    NonoError::ConfigParse(format!("JSON serialization failed: {e}"))
                })?;
                if let Some(obj) = value.as_object_mut() {
                    obj.insert(
                        "session_file".to_string(),
                        serde_json::Value::String(session_file_str),
                    );
                }
                value
            }
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
                    "session_file": session_file_str,
                    "events": events,
                })
            }
        };
        if let Some(ref field) = args.field {
            // Field extraction short-circuits the full-document render.
            // Same shell-friendly semantics as `profile show --field`
            // (jq-r-lite: primitives raw, composites JSON honoring
            // --compact, missing fields error rather than empty).
            let extracted =
                crate::field_extract::extract_field_output(&value, field, args.compact)?;
            println!("{extracted}");
            return Ok(());
        }
        let json = if args.compact {
            serde_json::to_string(&value)
        } else {
            serde_json::to_string_pretty(&value)
        }
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
    println!("File:       {}", session_file.display());

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

    // Resolve the age filter once. `--age <duration>` (1h/7d/2w/...) and
    // `--older-than <days>` are mutually exclusive at clap; here we
    // collapse both into the same "minimum age in seconds" so the loop
    // logic stays uniform.
    let age_floor_secs: Option<u64> = match (args.age.as_deref(), args.older_than) {
        (Some(spec), None) => Some(parse_duration_to_secs(spec)?),
        (None, Some(days)) => Some(days.saturating_mul(60 * 60 * 24)),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("clap conflicts_with prevents this combination"),
    };

    let now = chrono::Utc::now();
    let mut to_remove: Vec<&SessionRecord> = Vec::new();

    for s in &sessions {
        // Skip running sessions
        if s.status == SessionStatus::Running {
            continue;
        }

        let should_remove = if let Some(min_secs) = age_floor_secs {
            if let Ok(started) = chrono::DateTime::parse_from_rfc3339(&s.started) {
                let age = now.signed_duration_since(started);
                age.num_seconds() >= min_secs as i64
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
        if args.json {
            // Empty doc with the same shape as the populated case
            // so downstream consumers don't have to special-case
            // "nothing to prune".
            let action = if args.dry_run {
                "would-remove"
            } else {
                "removed"
            };
            let value = serde_json::json!({
                "action": action,
                "count": 0,
                "sessions": [],
            });
            let json = if args.compact {
                serde_json::to_string(&value)
            } else {
                serde_json::to_string_pretty(&value)
            }
            .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
            println!("{json}");
        } else {
            eprintln!("Nothing to prune.");
        }
        return Ok(());
    }

    if args.interactive {
        if !std::io::stdin().is_terminal() {
            return Err(NonoError::ConfigParse(
                "--interactive requires a TTY on stdin (no one to answer the prompt). \
                 Use --dry-run to preview without confirmation."
                    .to_string(),
            ));
        }
        eprintln!(
            "The following {} session(s) will be removed:",
            to_remove.len()
        );
        for s in &to_remove {
            eprintln!("  {} (started {})", s.session_id, s.started);
        }
        eprintln!();
        let mut input = String::new();
        eprint!("Proceed? [y/N] ");
        std::io::Write::flush(&mut std::io::stderr())
            .map_err(|e| NonoError::ConfigParse(format!("Failed to flush prompt: {e}")))?;
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| NonoError::ConfigParse(format!("Failed to read confirmation: {e}")))?;
        if !is_yes_response(&input) {
            eprintln!("Aborted; nothing removed.");
            return Ok(());
        }
    }

    let dir = session::sessions_dir()?;

    for s in &to_remove {
        let session_file = dir.join(format!("{}.json", s.session_id));
        let events_file = dir.join(format!("{}.events.ndjson", s.session_id));

        if args.dry_run {
            if !args.json {
                eprintln!("Would remove: {} (started {})", s.session_id, s.started);
            }
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
            if !args.json {
                eprintln!("Removed: {} (started {})", s.session_id, s.started);
            }
        }
    }

    if args.json {
        // Same shape as the empty-list branch: action / count /
        // sessions. Each entry carries session_id + started so
        // downstream tooling can correlate with previous `nono ps`
        // snapshots without re-parsing.
        let action = if args.dry_run {
            "would-remove"
        } else {
            "removed"
        };
        let entries: Vec<serde_json::Value> = to_remove
            .iter()
            .map(|s| {
                serde_json::json!({
                    "session_id": s.session_id,
                    "started": s.started,
                })
            })
            .collect();
        let value = serde_json::json!({
            "action": action,
            "count": to_remove.len(),
            "sessions": entries,
        });
        let json = if args.compact {
            serde_json::to_string(&value)
        } else {
            serde_json::to_string_pretty(&value)
        }
        .map_err(|e| NonoError::ConfigParse(format!("JSON serialization failed: {e}")))?;
        println!("{json}");
    } else {
        eprintln!(
            "\n{} {} session(s).",
            if args.dry_run {
                "Would prune"
            } else {
                "Pruned"
            },
            to_remove.len()
        );
    }

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
            exit_code: None,
            since: None,
            sort: None,
            reverse: false,
            short: false,
            output: None,
            watch: None,
            compact: false,
            header_format: PsHeaderFormat::Fancy,
            no_truncate: false,
            columns: Vec::new(),
            field: None,
            max_iterations: None,
        }
    }

    #[test]
    fn ps_filter_default_hides_exited_but_keeps_running() {
        let running = make_record("a", None, None, SessionStatus::Running);
        let exited = make_record("b", None, None, SessionStatus::Exited);
        let args = ps_args();
        assert!(ps_matches(&running, &args, None));
        assert!(!ps_matches(&exited, &args, None));
    }

    #[test]
    fn ps_filter_all_includes_exited() {
        let exited = make_record("b", None, None, SessionStatus::Exited);
        let args = PsArgs {
            all: true,
            ..ps_args()
        };
        assert!(ps_matches(&exited, &args, None));
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
        assert!(ps_matches(&exited, &args, None));
        assert!(!ps_matches(&running, &args, None));
        assert!(!ps_matches(&paused, &args, None));
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
        assert!(
            ps_matches(&claude, &args, None),
            "case-insensitive substring"
        );
        assert!(!ps_matches(&codex, &args, None));
        assert!(
            !ps_matches(&unnamed, &args, None),
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
        assert!(ps_matches(&claude, &args, None));
        assert!(
            !ps_matches(&claude_stretch, &args, None),
            "exact match — substring of another profile must NOT pass"
        );
        assert!(!ps_matches(&no_profile, &args, None));
    }

    fn exited_with_code(id: &str, code: i32) -> SessionRecord {
        SessionRecord {
            exit_code: Some(code),
            ..make_record(id, None, None, SessionStatus::Exited)
        }
    }

    #[test]
    fn ps_filter_exit_code_zero_finds_only_successful_exits() {
        let success = exited_with_code("a", 0);
        let failed = exited_with_code("b", 137);
        let still_running = make_record("c", None, None, SessionStatus::Running);
        let args = PsArgs {
            exit_code: Some(0),
            ..ps_args()
        };
        assert!(ps_matches(&success, &args, None));
        assert!(!ps_matches(&failed, &args, None));
        assert!(
            !ps_matches(&still_running, &args, None),
            "running sessions have no exit code yet — must be excluded"
        );
    }

    #[test]
    fn ps_filter_exit_code_specific_value() {
        let oom = exited_with_code("a", 137);
        let other = exited_with_code("b", 1);
        let args = PsArgs {
            exit_code: Some(137),
            ..ps_args()
        };
        assert!(ps_matches(&oom, &args, None));
        assert!(!ps_matches(&other, &args, None));
    }

    #[test]
    fn ps_filter_exit_code_implicitly_includes_exited_without_all() {
        // Default behavior hides exited sessions; --exit-code should
        // override that so users don't need to also pass --all.
        let success = exited_with_code("a", 0);
        let args = PsArgs {
            exit_code: Some(0),
            all: false,
            ..ps_args()
        };
        assert!(
            ps_matches(&success, &args, None),
            "--exit-code must auto-include exited sessions even without --all"
        );
    }

    #[test]
    fn ps_filter_exit_code_composes_with_other_filters() {
        let target = SessionRecord {
            exit_code: Some(0),
            ..make_record(
                "a",
                Some("review-bot"),
                Some("default"),
                SessionStatus::Exited,
            )
        };
        let wrong_name = SessionRecord {
            exit_code: Some(0),
            ..make_record("b", Some("other"), Some("default"), SessionStatus::Exited)
        };
        let args = PsArgs {
            exit_code: Some(0),
            name: Some("review".to_string()),
            ..ps_args()
        };
        assert!(ps_matches(&target, &args, None));
        assert!(!ps_matches(&wrong_name, &args, None));
    }

    #[test]
    fn format_watch_banner_uses_hhmmss_and_interval() {
        // Anchor time so the assertion is deterministic across test
        // hosts / time zones — chrono::Local::with_ymd_and_hms returns
        // a LocalResult, so unwrap a known-valid 2026-05-01 14:23:05.
        use chrono::TimeZone;
        let when = chrono::Local
            .with_ymd_and_hms(2026, 5, 1, 14, 23, 5)
            .single()
            .expect("valid local time");
        let banner = format_watch_banner(when, 5);
        assert_eq!(
            banner, "nono ps  -  refreshed 14:23:05  (every 5s)",
            "watch banner format must be stable: HH:MM:SS local time + interval"
        );
    }

    #[test]
    fn format_watch_banner_handles_minute_or_longer_intervals() {
        // `parse_duration_to_secs` happily accepts `1m` / `1h`; the
        // banner just shows the resolved seconds count for honesty
        // (so users know what's *actually* in flight if they typed
        // `--watch 1m`).
        use chrono::TimeZone;
        let when = chrono::Local
            .with_ymd_and_hms(2026, 5, 1, 0, 0, 0)
            .single()
            .expect("valid local time");
        assert!(format_watch_banner(when, 60).contains("(every 60s)"));
        assert!(format_watch_banner(when, 3600).contains("(every 3600s)"));
    }

    #[test]
    fn render_ps_header_fancy_emits_unicode_divider() {
        let header = "SESSION   NAME   STATUS";
        let rendered = render_ps_header(PsHeaderFormat::Fancy, header, 24)
            .expect("fancy must render a header");
        let mut lines = rendered.lines();
        assert_eq!(lines.next(), Some("SESSION   NAME   STATUS"));
        let divider = lines.next().expect("divider line follows header");
        assert_eq!(divider.chars().count(), 24, "divider width matches request");
        assert!(
            divider.chars().all(|c| c == '─'),
            "fancy divider must use the unicode box-drawing horizontal: {divider:?}"
        );
        assert_eq!(lines.next(), None, "exactly two lines: header + divider");
    }

    #[test]
    fn render_ps_header_ascii_emits_dash_divider() {
        let header = "SESSION   NAME   STATUS";
        let rendered = render_ps_header(PsHeaderFormat::Ascii, header, 24)
            .expect("ascii must render a header");
        let mut lines = rendered.lines();
        assert_eq!(lines.next(), Some("SESSION   NAME   STATUS"));
        let divider = lines.next().expect("divider line follows header");
        assert_eq!(divider, "-".repeat(24), "ASCII divider is plain dashes");
        assert_eq!(lines.next(), None);
    }

    #[test]
    fn render_ps_header_none_returns_none() {
        // The "none" branch must skip BOTH the header line AND the
        // divider — printing only the divider would leave a stray
        // horizontal rule above the data rows.
        assert!(render_ps_header(PsHeaderFormat::None, "SESSION", 16).is_none());
    }

    #[test]
    fn render_ps_header_default_is_fancy() {
        // Backwards-compat guarantee: existing `nono ps` invocations
        // (no --header-format flag) get the unicode-divider rendering.
        let default_fmt = PsHeaderFormat::default();
        assert_eq!(default_fmt, PsHeaderFormat::Fancy);
    }

    #[test]
    fn parse_duration_accepts_each_unit_suffix() {
        assert_eq!(parse_duration_to_secs("30s").expect("30s"), 30);
        assert_eq!(parse_duration_to_secs("5m").expect("5m"), 5 * 60);
        assert_eq!(parse_duration_to_secs("2h").expect("2h"), 2 * 60 * 60);
        assert_eq!(parse_duration_to_secs("7d").expect("7d"), 7 * 60 * 60 * 24);
        assert_eq!(parse_duration_to_secs("1w").expect("1w"), 60 * 60 * 24 * 7);
        // case-insensitive on the unit letter
        assert_eq!(parse_duration_to_secs("2H").expect("2H"), 2 * 60 * 60);
    }

    #[test]
    fn parse_duration_rejects_malformed_input() {
        // Empty / whitespace-only
        assert!(parse_duration_to_secs("").is_err());
        assert!(parse_duration_to_secs("  ").is_err());
        // Bare number — no unit
        assert!(parse_duration_to_secs("30").is_err());
        // Unknown unit
        assert!(parse_duration_to_secs("5y").is_err());
        // Missing numeric prefix
        assert!(parse_duration_to_secs("h").is_err());
        // Non-numeric prefix
        assert!(parse_duration_to_secs("abch").is_err());
        // Zero is rejected (would otherwise mean "all sessions")
        assert!(parse_duration_to_secs("0s").is_err());
        assert!(parse_duration_to_secs("0d").is_err());
    }

    #[test]
    fn ps_filter_since_threshold_excludes_older_sessions() {
        let recent = SessionRecord {
            started_epoch: 200,
            ..make_record("a", None, None, SessionStatus::Running)
        };
        let stale = SessionRecord {
            started_epoch: 50,
            ..make_record("b", None, None, SessionStatus::Running)
        };
        let args = ps_args();
        // threshold 100 — only sessions started at or after 100 pass
        assert!(ps_matches(&recent, &args, Some(100)));
        assert!(
            !ps_matches(&stale, &args, Some(100)),
            "started_epoch < threshold must be excluded"
        );
    }

    #[test]
    fn ps_filter_since_with_no_threshold_is_a_passthrough() {
        let stale = SessionRecord {
            started_epoch: 0,
            ..make_record("a", None, None, SessionStatus::Running)
        };
        // None threshold preserves all the other filter semantics
        assert!(ps_matches(&stale, &ps_args(), None));
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
        assert!(ps_matches(&target, &args, None));
        assert!(!ps_matches(&wrong_profile, &args, None));
        assert!(!ps_matches(&wrong_name, &args, None));
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
        let row = format_ps_short_row(&rec, 60, false);

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
        let row = format_ps_short_row(&rec, 60, false);

        assert!(
            row.contains("exited(127)"),
            "exit code must be visible after the status word: {row:?}"
        );
        // Unnamed sessions render as `-` to keep column alignment stable.
        assert!(row.contains(" - "));
    }

    #[test]
    fn csv_escape_quotes_only_when_needed() {
        assert_eq!(
            csv_escape("simple"),
            "simple",
            "no special chars ⇒ unchanged"
        );
        assert_eq!(csv_escape("a,b"), "\"a,b\"", "comma forces quoting");
        assert_eq!(
            csv_escape("a\"b"),
            "\"a\"\"b\"",
            "embedded quotes are doubled, then wrapped"
        );
        assert_eq!(
            csv_escape("line1\nline2"),
            "\"line1\nline2\"",
            "embedded newlines force quoting"
        );
    }

    #[test]
    fn tsv_escape_preserves_field_shape() {
        assert_eq!(tsv_escape("plain"), "plain");
        assert_eq!(tsv_escape("a\tb"), "a\\tb", "tabs become \\t");
        assert_eq!(tsv_escape("a\nb"), "a\\nb", "newlines become \\n");
        assert_eq!(
            tsv_escape("a\\b"),
            "a\\\\b",
            "literal backslash is escaped first to keep round-trip semantics"
        );
    }

    #[test]
    fn format_ps_tabular_csv_header_present_for_empty_input() {
        let out = format_ps_tabular(&[], PsOutputFormat::Csv);
        assert!(
            out.starts_with("session_id,name,status,exit_code,"),
            "header must be present even for empty session list: {out}"
        );
        assert_eq!(
            out.lines().count(),
            1,
            "empty input ⇒ header only, no record rows"
        );
    }

    #[test]
    fn format_ps_tabular_csv_quotes_command_with_comma() {
        let rec = make_record("abc", Some("test"), None, SessionStatus::Running);
        let rec = SessionRecord {
            command: vec![
                "bash".to_string(),
                "-c".to_string(),
                "echo a, b".to_string(),
            ],
            ..rec
        };
        let out = format_ps_tabular(&[&rec], PsOutputFormat::Csv);
        let row = out.lines().nth(1).expect("data row");
        // The command field had a `,` so it must be wrapped in double quotes
        // (RFC 4180). Sanity-check by counting the quoted run.
        assert!(
            row.contains("\"bash -c 'echo a, b'\"")
                || row.contains("\"bash -c \"\"echo a, b\"\"\""),
            "command with comma must be CSV-quoted: {row}"
        );
    }

    #[test]
    fn format_ps_tabular_ndjson_one_record_per_line_no_header() {
        let rec_a = make_record("a", Some("first"), None, SessionStatus::Running);
        let rec_b = make_record("b", None, Some("default"), SessionStatus::Exited);
        let out = format_ps_tabular(&[&rec_a, &rec_b], PsOutputFormat::Ndjson);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "exactly one line per record, no header");
        for line in &lines {
            // Each line must round-trip as JSON — that's the whole
            // contract of NDJSON.
            let value: serde_json::Value =
                serde_json::from_str(line).expect("each line must be valid JSON");
            assert!(value.is_object(), "line must be a JSON object: {line}");
        }
    }

    #[test]
    fn format_ps_tabular_ndjson_empty_input_produces_no_lines() {
        // NDJSON has no header concept, so empty input ⇒ empty output.
        // Distinguishes it from CSV/TSV which emit a header anyway.
        let out = format_ps_tabular(&[], PsOutputFormat::Ndjson);
        assert!(
            out.is_empty(),
            "empty NDJSON must be the empty string, got {out:?}"
        );
    }

    #[test]
    fn format_ps_tabular_tsv_uses_tabs_and_escapes_newlines() {
        let rec = make_record("xyz", None, Some("default"), SessionStatus::Exited);
        let out = format_ps_tabular(&[&rec], PsOutputFormat::Tsv);
        let row = out.lines().nth(1).expect("data row");
        assert!(
            row.contains("\txyz\t") || row.starts_with("xyz\t"),
            "tab-separated: {row}"
        );
        assert!(!row.contains('\n'));
    }

    #[test]
    fn ps_short_row_truncates_command_to_max_len() {
        let long: String = "x".repeat(200);
        let rec = full_record_for_short_row("abc", None, SessionStatus::Running, None, vec![long]);
        let row = format_ps_short_row(&rec, 32, false);
        // The truncate helper uses an ellipsis; the visible command must
        // never exceed the cap (give a small fudge for trailing chars).
        let cmd_section = row.split_whitespace().last().unwrap_or("");
        assert!(
            cmd_section.chars().count() <= 35,
            "command got past max_command_len: {cmd_section:?}"
        );
    }

    #[test]
    fn is_yes_response_only_accepts_y_or_yes_case_insensitive() {
        for ok in ["y", "Y", "yes", "Yes", "YES", "  y  ", "yes\n"] {
            assert!(
                is_yes_response(ok),
                "{ok:?} must count as confirmation (case-insensitive, trimmed)"
            );
        }
        for nope in ["", "\n", "n", "no", "  ", "yep", "yeah", "1", "true"] {
            assert!(
                !is_yes_response(nope),
                "{nope:?} must NOT count as confirmation — only literal y/yes"
            );
        }
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

    #[test]
    fn render_ps_command_truncates_when_flag_off() {
        // Default behavior: shave to max_len with a 3-char "..." suffix
        // so wide commands don't blow up the column alignment.
        let cmd: Vec<String> = vec!["a".repeat(80)];
        let rendered = render_ps_command(&cmd, false, 40);
        assert!(rendered.ends_with("..."));
        assert!(rendered.chars().count() <= 40);
    }

    #[test]
    fn render_ps_command_skips_truncate_with_flag() {
        // The whole point of --no-truncate is letting users see the
        // full argv. The result must NOT end in `...` even when the
        // input is far longer than the would-be cap.
        let long_arg = "a".repeat(200);
        let cmd: Vec<String> = vec!["sh".to_string(), "-c".to_string(), long_arg.clone()];
        let rendered = render_ps_command(&cmd, true, 40);
        assert!(
            !rendered.ends_with("..."),
            "no_truncate must not end with the truncation ellipsis"
        );
        assert!(
            rendered.contains(&long_arg),
            "no_truncate must include the full long argument verbatim"
        );
    }

    #[test]
    fn default_ps_columns_match_pscolumn_variant_order() {
        // Backwards-compat guard: the canonical default render order
        // must equal the variant declaration order. Anyone reordering
        // PsColumn variants without updating DEFAULT_PS_COLUMNS would
        // silently rearrange every existing user's `nono ps` output.
        assert_eq!(
            DEFAULT_PS_COLUMNS,
            &[
                PsColumn::Session,
                PsColumn::Name,
                PsColumn::Status,
                PsColumn::Attach,
                PsColumn::Pid,
                PsColumn::Uptime,
                PsColumn::Profile,
                PsColumn::Command,
            ]
        );
    }

    #[test]
    fn render_default_header_row_lays_out_all_columns_with_widths() {
        let header = render_default_header_row(DEFAULT_PS_COLUMNS);
        // Each header word still appears (regression guard for typos
        // or column-removal during refactors).
        for needle in [
            "SESSION", "NAME", "STATUS", "ATTACH", "PID", "UPTIME", "PROFILE", "COMMAND",
        ] {
            assert!(
                header.contains(needle),
                "default header missing {needle}: {header:?}"
            );
        }
        // Column widths from `column_meta` should sum (with separator
        // spaces and the unpadded COMMAND label) to the total length.
        let expected_len =
            16 + 1 + 12 + 1 + 12 + 1 + 12 + 1 + 8 + 1 + 10 + 1 + 14 + 1 + "COMMAND".len();
        assert_eq!(header.chars().count(), expected_len);
    }

    #[test]
    fn render_default_header_row_subset_drops_unselected_columns() {
        let header = render_default_header_row(&[PsColumn::Session, PsColumn::Command]);
        assert!(header.contains("SESSION"));
        assert!(header.contains("COMMAND"));
        assert!(
            !header.contains("STATUS"),
            "subset must not leak columns: {header:?}"
        );
        assert!(!header.contains("ATTACH"));
    }

    #[test]
    fn render_default_data_row_drops_unselected_cells() {
        // Triage subset: just session + status + command — what a
        // user investigating a failing run would actually want.
        let rec = full_record_for_short_row(
            "abc12345",
            Some("triage-1"),
            SessionStatus::Exited,
            Some(127),
            vec!["bash".to_string(), "-lc".to_string(), "boom".to_string()],
        );
        let row = render_default_data_row(
            &rec,
            &[PsColumn::Session, PsColumn::Status, PsColumn::Command],
            false,
        );
        assert!(row.contains("abc12345"));
        assert!(row.contains("exited(127)"));
        assert!(row.contains("bash"));
        // Unselected columns should not appear; "triage-1" (the name)
        // is the cleanest probe — every other column has its own
        // value space that overlaps with status/session text.
        assert!(
            !row.contains("triage-1"),
            "name column must be omitted when not selected: {row:?}"
        );
    }

    #[test]
    fn ps_short_row_with_no_truncate_emits_full_command() {
        // End-to-end via format_ps_short_row: the no_truncate boolean
        // must reach the rendered row, not just the helper. Regression
        // guard for the (easy) bug where a new flag is plumbed through
        // PsArgs but only one of the two render branches gets updated.
        let long: String = "x".repeat(200);
        let rec = full_record_for_short_row("abc", None, SessionStatus::Running, None, vec![long]);
        let row = format_ps_short_row(&rec, 32, true);
        // Count xs anywhere in the row — must hit 200.
        let xs = row.chars().filter(|c| *c == 'x').count();
        assert_eq!(xs, 200, "full 200-char command should reach the row");
        assert!(!row.contains("..."), "no truncation ellipsis: {row:?}");
    }
}
