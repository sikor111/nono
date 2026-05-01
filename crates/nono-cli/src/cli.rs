//! CLI argument definitions for nono
//!
//! Uses clap for argument parsing. This module defines all subcommands
//! and their options.

use clap::builder::styling::{Style, Styles};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

const STYLES: Styles = Styles::plain().header(Style::new().bold());

/// nono - The opposite of YOLO
///
/// A capability-based shell for running untrusted AI agents and processes
/// with OS-enforced filesystem and network isolation.
#[derive(Parser, Debug)]
#[command(name = "nono")]
#[command(author, version, about, long_about = None)]
#[command(styles = STYLES, next_help_heading = "OPTIONS")]
#[command(subcommand_help_heading = "")]
#[command(help_template = "\
{about-with-newline}
\x1b[1mUSAGE\x1b[0m
  nono <command> [flags]

\x1b[1mGETTING STARTED\x1b[0m
  setup      Set up nono on this system

\x1b[1mCORE USAGE\x1b[0m
  run        Run a command inside the sandbox
  shell      Start an interactive shell inside the sandbox
  wrap       Apply sandbox and exec into command (nono disappears)

\x1b[1mEXPLORATION & DEBUGGING\x1b[0m
  learn      Trace a command to discover required filesystem paths
  why        Check why a path or network operation would be allowed or denied

\x1b[1mSESSION MANAGEMENT\x1b[0m
  ps         List running or detached sandbox sessions
  stop       Stop a running sandbox session
  detach     Detach from an interactive runtime session
  attach     Attach to a detached runtime session
  logs       View runtime session event logs
  inspect    Show detailed runtime session state
  session    Manage runtime session storage
  rollback   Manage rollback sessions (browse, restore, cleanup)
  audit      View audit trail of sandboxed commands
  trust      Manage file trust and attestation

\x1b[1mPACKS\x1b[0m
  pull       Install a signed nono pack from the registry
  remove     Remove an installed nono pack
  update     Update installed nono packs
  search     Search the registry for nono packs
  list       List installed nono packs

\x1b[1mPOLICY & PROFILES\x1b[0m
  policy     [deprecated] Use 'nono profile' instead
  profile    Create, inspect, and compare nono profiles

\x1b[1mTOOLING\x1b[0m
  dry-run-schema  Print the JSON Schema for `--dry-run-json` output

\x1b[1mOPTIONS\x1b[0m
{options}

\x1b[1mLEARN MORE\x1b[0m
  Use `nono <command> --help` for more information about a command.
  Read the docs at https://nono.sh/docs
")]
pub struct Cli {
    /// Silent mode - suppress all nono output (banner, summary, status)
    #[arg(long, short = 's', global = true, help_heading = "OPTIONS")]
    pub silent: bool,

    /// Color theme for output (mocha, latte, frappe, macchiato, tokyo-night, minimal)
    #[arg(
        long,
        global = true,
        env = "NONO_THEME",
        value_name = "THEME",
        help_heading = "OPTIONS"
    )]
    pub theme: Option<String>,

    /// Write logs to a file instead of stderr
    #[arg(
        long,
        global = true,
        env = "NONO_LOG_FILE",
        value_name = "PATH",
        help_heading = "OPTIONS"
    )]
    pub log_file: Option<PathBuf>,

    /// Disable colored output. The `colored` crate already honors the
    /// well-known `NO_COLOR` env var; this flag is the explicit CLI
    /// override for tools / pipelines that want a deterministic
    /// no-color output without touching the environment.
    #[arg(long, global = true, help_heading = "OPTIONS")]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    // ── Getting started ─────────────────────────────────────────────────
    /// Set up nono on this system
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono setup [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono setup --profiles                        # Full setup with profile generation
  nono setup --check-only                      # Verify installation and sandbox support
  nono setup --profiles --shell-integration    # Setup with shell integration help
  nono setup -v --profiles                     # Verbose setup
")]
    Setup(SetupArgs),

    // ── Core usage ──────────────────────────────────────────────────────
    /// Run a command inside the sandbox
    #[command(trailing_var_arg = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono run [flags] <program>...

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono run --allow . claude                    # Read/write current dir, run claude
  nono run --profile claude-code claude        # Use a built-in profile
  nono run --profile claude-code --allow-domain api.openai.com claude
                                               # Restrict outbound access to listed domains
  nono run --read ./src --write ./output cargo build
                                               # Separate read/write permissions
  nono run --allow . --block-net cargo build   # Block network access
  nono run --allow . --env-credential openai_api_key,anthropic_api_key -- claude
                                               # Load secrets from system keystore
")]
    Run(Box<RunArgs>),

    /// Start an interactive shell inside the sandbox
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono shell [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono shell --allow .                         # Shell with read/write to current dir
  nono shell --profile claude-code             # Use a named profile
  nono shell --allow . --shell /bin/zsh        # Override shell binary
")]
    Shell(Box<ShellArgs>),

    /// Apply sandbox and exec into command (nono disappears).
    /// For scripts, piping, and embedding where no parent process is wanted.
    #[command(trailing_var_arg = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono wrap [flags] <program>...

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono wrap --allow . -- cargo build           # Sandbox and exec into cargo build
  nono wrap --profile developer -- cargo test  # Use a named profile
")]
    Wrap(Box<WrapArgs>),

    // ── Exploration & debugging ─────────────────────────────────────────
    /// Trace a command to discover required filesystem paths
    #[command(trailing_var_arg = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono learn [flags] <program>...

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono learn -- my-app                         # Discover paths needed by a command
  nono learn --profile my-profile -- my-app    # Compare against an existing profile
  nono learn --json -- node server.js          # Output as JSON for profile
  nono learn --timeout 30 -- my-app            # Limit trace duration

\x1b[1mPLATFORM NOTES\x1b[0m
  Linux   Uses strace (install with: apt install strace)
  macOS   Uses fs_usage (requires sudo)
")]
    Learn(Box<LearnArgs>),

    /// Check why a path or network operation would be allowed or denied
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono why [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono why --path ~/.ssh --op read             # Check if ~/.ssh is readable
  nono why --path ./src --op write --allow .   # Check with capability context
  nono why --json --path ~/.aws --op read      # JSON output for agents
  nono why --host api.openai.com --port 443    # Query network access
  nono why --self --path /tmp --op write       # Inside sandbox, query own capabilities
")]
    Why(Box<WhyArgs>),

    // ── Session management ───────────────────────────────────────────────
    /// Manage rollback sessions (browse, restore, cleanup)
    #[command(subcommand_help_heading = "COMMANDS", disable_help_subcommand = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono rollback <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono rollback list                           # List rollback sessions
  nono rollback show <id> --diff               # Show changes with diff
  nono rollback restore <id>                   # Restore files from a session
  nono rollback restore <id> --dry-run         # Preview what would change
  nono rollback verify <id>                    # Verify session integrity
  nono rollback cleanup --dry-run              # Preview cleanup
")]
    Rollback(RollbackArgs),

    /// View audit trail of sandboxed commands
    #[command(subcommand_help_heading = "COMMANDS", disable_help_subcommand = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono audit <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono audit list                              # List all sessions
  nono audit list --today                      # List sessions from today
  nono audit list --command claude             # Filter by command
  nono audit show <id> --json                  # Export as JSON
")]
    Audit(AuditArgs),

    /// Manage file trust and attestation
    #[command(subcommand_help_heading = "COMMANDS", disable_help_subcommand = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono trust <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono trust sign SKILLS.md                    # Sign with default keystore key
  nono trust sign SKILLS.md --key my-key       # Sign with a specific key ID
  nono trust sign-policy                       # Sign project trust policy
  nono trust sign-policy --user                # Sign user-level trust policy
  nono trust verify SKILLS.md                  # Verify a file
  nono trust verify --all                      # Verify all files matching policy
  nono trust list                              # List files and verification status
  nono trust keygen                            # Generate a new signing key pair
")]
    Trust(TrustArgs),

    /// List running sandboxed sessions
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono ps [flags]

{all-args}
{after-help}")]
    #[command(after_help = "EXAMPLES:
    # Show running sessions
    nono ps

    # Show all sessions (including exited)
    nono ps --all

    # JSON output
    nono ps --json
")]
    Ps(PsArgs),

    /// Stop a running sandboxed session
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono stop [flags] <session>

{all-args}
{after-help}")]
    #[command(after_help = "EXAMPLES:
    # Stop a session by ID (prefix match)
    nono stop a3f7c2

    # Force stop (SIGKILL)
    nono stop --force a3f7c2
")]
    Stop(StopArgs),

    /// Detach from a running sandboxed session and return to the shell
    #[command(
        help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono detach <session>

{all-args}
{after-help}",
        alias = "pause",
        after_help = "EXAMPLES:
    # Detach by session ID
    nono detach a3f7c2

    # Detach by name
    nono detach calm-gate

IN-BAND DETACH:
    By default, press Ctrl-] then d to detach without opening a second terminal.
    This can be changed in ~/.config/nono/config.toml:
      [ui]
      detach_sequence = \"ctrl-] d\"
"
    )]
    Detach(DetachArgs),

    /// Attach to a detached or running session from another terminal
    #[command(
        help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono attach <session>

{all-args}
{after-help}",
        alias = "resume",
        after_help = "EXAMPLES:
    # Attach by session ID
    nono attach a3f7c2

    # Attach by name
    nono attach calm-gate

IN-BAND DETACH:
    By default, press Ctrl-] then d to detach from the session.
    This can be changed in ~/.config/nono/config.toml:
      [ui]
      detach_sequence = \"ctrl-] d\"
"
    )]
    Attach(AttachArgs),

    /// View event log for a session
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono logs [flags] <session>

{all-args}
{after-help}")]
    #[command(after_help = "EXAMPLES:
    # View recent events
    nono logs a3f7c2

    # Follow events in real-time
    nono logs -f a3f7c2

    # Show last 20 events
    nono logs --tail 20 a3f7c2

    # JSON output
    nono logs --json a3f7c2
")]
    Logs(LogsArgs),

    /// Show detailed information about a session
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono inspect [flags] <session>

{all-args}
{after-help}")]
    #[command(after_help = "EXAMPLES:
    # Inspect a session
    nono inspect a3f7c2

    # Include event log
    nono inspect --events a3f7c2

    # JSON output
    nono inspect --json a3f7c2
")]
    Inspect(InspectArgs),

    /// Clean up old session files
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono prune [flags]

{all-args}
{after-help}")]
    #[command(after_help = "EXAMPLES:
    # Preview what would be cleaned
    nono prune --dry-run

    # Remove sessions older than 7 days
    nono prune --older-than 7

    # Keep only 10 most recent sessions
    nono prune --keep 10
")]
    #[command(hide = true)]
    Prune(PruneArgs),

    /// Manage runtime session storage
    #[command(subcommand_help_heading = "COMMANDS")]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono session <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono session cleanup --dry-run              # Preview old runtime sessions
  nono session cleanup --older-than 7         # Remove sessions older than 7 days
  nono session cleanup --keep 10              # Keep only 10 recent sessions
")]
    Session(SessionArgs),

    // ── Policy & profiles ────────────────────────────────────────────────
    /// [deprecated] Use 'nono profile' instead
    #[command(subcommand_help_heading = "COMMANDS")]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono policy <command>

\x1b[1mNOTE\x1b[0m
  These commands are deprecated. Use the corresponding 'nono profile'
  form; every invocation of 'nono policy <sub>' prints a deprecation
  warning to stderr.

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono policy groups        # deprecated -> use 'nono profile groups'
  nono policy profiles      # deprecated -> use 'nono profile list'
  nono policy show <name>   # deprecated -> use 'nono profile show <name>'
  nono policy diff a b      # deprecated -> use 'nono profile diff a b'
  nono policy validate <f>  # deprecated -> use 'nono profile validate <f>'
")]
    Policy(crate::deprecated_policy::PolicyArgs),

    /// Create, inspect, and compare nono profiles
    #[command(subcommand_help_heading = "COMMANDS")]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono profile <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono profile init my-agent                   # Create a new profile with defaults
  nono profile init my-agent --extends default --groups deny_credentials
                                               # Extend an existing profile
  nono profile init my-agent --full            # Generate a full skeleton
  nono profile list                            # List all profiles (built-in and user)
  nono profile show claude-code                # Show a fully resolved profile
  nono profile diff default claude-code        # Compare two profiles
  nono profile validate ~/my-profile.json      # Validate a user profile file
  nono profile groups                          # List all policy groups
  nono profile groups deny_credentials         # Show details for a specific group
  nono profile schema                          # Print JSON Schema for editor validation
  nono profile guide                           # Print profile authoring guide
")]
    Profile(ProfileCmdArgs),

    /// Print the JSON Schema describing `--dry-run-json` output. Useful
    /// for wiring `nono run --dry-run-json` consumers into editor
    /// integrations or CI policy linters that validate against a
    /// schema document.
    #[command(name = "dry-run-schema")]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono dry-run-schema [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  # Print the schema to stdout
  nono dry-run-schema

  # Write the schema to a file (e.g. for editor JSON-Schema mappings)
  nono dry-run-schema -o nono-dry-run.schema.json
")]
    DryRunSchema(DryRunSchemaArgs),

    /// Install a signed nono pack from the registry
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono pull <namespace>/<name>[@<version>] [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono pull nono-project/claude-code
  nono pull nono-project/claude-code@1.2.0 --registry http://localhost:3000
  nono pull nono-project/claude-code --init
")]
    Pull(PullArgs),

    /// Remove an installed nono pack
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono remove <namespace>/<name>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono remove nono-project/claude-code
")]
    Remove(RemoveArgs),

    /// Update installed nono packs
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono update [<namespace>/<name>] [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono update
  nono update nono-project/claude-code
")]
    Update(UpdateArgs),

    /// Search the registry for nono packs
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono search <query> [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono search claude
  nono search sandbox --json
")]
    Search(SearchArgs),

    /// List installed nono packs
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono list --installed [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono list --installed
  nono list --installed --json
")]
    List(ListArgs),

    /// Internal: open a URL via supervisor IPC
    #[command(hide = true)]
    OpenUrlHelper(OpenUrlHelperArgs),
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct PullArgs {
    /// Package reference (<namespace>/<name>[@<version>])
    pub package_ref: String,

    /// Registry base URL
    #[arg(
        long,
        env = "NONO_REGISTRY",
        value_name = "URL",
        help_heading = "OPTIONS"
    )]
    pub registry: Option<String>,

    /// Overwrite conflicts and accept signer changes
    #[arg(long, help_heading = "OPTIONS")]
    pub force: bool,

    /// Copy project instructions into the current directory
    #[arg(long, help_heading = "OPTIONS")]
    pub init: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RemoveArgs {
    /// Installed package reference (<namespace>/<name>)
    pub package_ref: String,

    /// Continue removal even if some wiring directives fail to reverse.
    /// Without this flag, partial reversal failures keep the lockfile
    /// entry intact so the user can retry, since silently forgetting a
    /// half-removed pack would orphan agent wiring (e.g. a hook entry
    /// in `~/.codex/hooks.json` left active with no record of who put
    /// it there).
    #[arg(long, default_value_t = false)]
    pub force: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct UpdateArgs {
    /// Optional package reference (<namespace>/<name>)
    pub package_ref: Option<String>,

    /// Registry base URL
    #[arg(
        long,
        env = "NONO_REGISTRY",
        value_name = "URL",
        help_heading = "OPTIONS"
    )]
    pub registry: Option<String>,

    /// Accept signer changes
    #[arg(long, help_heading = "OPTIONS")]
    pub force: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct SearchArgs {
    /// Search query
    pub query: String,

    /// Registry base URL
    #[arg(
        long,
        env = "NONO_REGISTRY",
        value_name = "URL",
        help_heading = "OPTIONS"
    )]
    pub registry: Option<String>,

    /// Output as JSON
    #[arg(long, help_heading = "OPTIONS")]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct ListArgs {
    /// Show installed nono packs
    #[arg(long, help_heading = "OPTIONS")]
    pub installed: bool,

    /// Output as JSON
    #[arg(long, help_heading = "OPTIONS")]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

/// Arguments for the hidden open-url-helper subcommand.
///
/// Invoked as `BROWSER=nono open-url-helper` on Linux, or via the `open`
/// PATH shim on macOS. Reads `NONO_SUPERVISOR_FD` from the environment,
/// sends an `OpenUrl` IPC message to the unsandboxed supervisor, and
/// waits for a response.
#[derive(Parser, Debug, Clone)]
pub struct OpenUrlHelperArgs {
    /// The URL to open
    pub url: String,
}

// NOTE: `PolicyArgs`, `PolicyCommands`, and `Policy*Args` types that
// backed `nono policy <sub>` now live in `crate::deprecated_policy`. They
// share their inner arg shapes with `ProfileGroupsArgs` / `ProfileListArgs`
// / `ProfileShowArgs` / `ProfileDiffArgs` / `ProfileValidateArgs` via
// `pub use` aliases so there is no parallel set of types to keep in sync.

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct ProfileCmdArgs {
    #[command(subcommand)]
    pub command: ProfileCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum ProfileCommands {
    /// Generate a skeleton profile JSON file
    Init(ProfileInitArgs),
    /// List all available profiles (built-in and user)
    List(ProfileListArgs),
    /// Show a fully resolved profile
    Show(ProfileShowArgs),
    /// Diff two profiles
    Diff(ProfileDiffArgs),
    /// Validate a profile JSON file
    Validate(ProfileValidateArgs),
    /// List policy groups or show details for a specific group
    Groups(ProfileGroupsArgs),
    /// Output the JSON Schema for profile files
    Schema(ProfileSchemaArgs),
    /// Print the profile authoring guide
    Guide(ProfileGuideArgs),
}

#[derive(Parser, Debug)]
pub struct ProfileInitArgs {
    /// Profile name (alphanumeric + hyphens)
    pub name: String,
    /// Base profile to extend
    #[arg(long)]
    pub extends: Option<String>,
    /// Security groups to include (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub groups: Vec<String>,
    /// Profile description
    #[arg(long)]
    pub description: Option<String>,
    /// Generate a full skeleton with all sections
    #[arg(long)]
    pub full: bool,
    /// Output file path (default: ~/.config/nono/profiles/<name>.json)
    #[arg(long, short)]
    pub output: Option<PathBuf>,
    /// Overwrite existing file
    #[arg(long)]
    pub force: bool,
}

#[derive(Parser, Debug)]
pub struct ProfileSchemaArgs {
    /// Write schema to a file instead of stdout
    #[arg(long, short)]
    pub output: Option<PathBuf>,

    /// Extract a single field from the schema document instead of
    /// emitting the whole thing — same `jq -r`-lite semantics as
    /// the other `--field` surfaces. Common use:
    /// `nono profile schema --field /properties/security/type`
    /// reads one piece of the schema without parsing it in shell.
    /// Conflicts with `--output` (the latter writes the full doc
    /// to a file).
    #[arg(long, value_name = "PATH", conflicts_with = "output")]
    pub field: Option<String>,

    /// Emit composite extracted values as compact JSON. Has no
    /// effect on primitive --field results (always raw) and no
    /// effect when --field is unset (the schema is always emitted
    /// pretty by the embedded source).
    #[arg(long, requires = "field")]
    pub compact: bool,
}

#[derive(Parser, Debug)]
pub struct ProfileGuideArgs {
    /// Print only the named guide section (case-insensitive
    /// substring match against the `## ` headings). Useful for
    /// targeted reads — `nono profile guide --section validation`
    /// gets just the validation rules without scrolling through
    /// everything else. Conflicts with `--list-sections`.
    #[arg(long, value_name = "NAME", conflicts_with = "list_sections")]
    pub section: Option<String>,

    /// List the section titles (one per line) without their bodies.
    /// Pair with `--section` afterwards to drill into a specific
    /// one. Useful for shell-tab-completion-like discovery.
    #[arg(long)]
    pub list_sections: bool,

    /// Search the guide for a keyword (case-insensitive substring
    /// matched against section bodies). Output is grep-like: every
    /// section with a hit emits its `## ` heading followed by each
    /// matching line prefixed with the 1-based line number within
    /// that section. Useful for discovery — `nono profile guide
    /// --search tcp` surfaces every section that mentions TCP
    /// without you having to grep through the rendered document.
    /// Exits non-zero with a `--list-sections` hint if no section
    /// matches. Conflicts with `--section` / `--list-sections`
    /// (different display modes).
    #[arg(
        long,
        value_name = "KEYWORD",
        conflicts_with_all = &["section", "list_sections"],
    )]
    pub search: Option<String>,
}

#[derive(Parser, Debug)]
pub struct ProfileListArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Emit compact JSON (no whitespace / indentation). Has no effect
    /// without `--json`. Mirrors `profile show --compact` etc.
    #[arg(long, requires = "json")]
    pub compact: bool,
    /// Extract a single field from the JSON array instead of emitting
    /// the whole document — same `jq -r`-lite semantics as
    /// `nono profile show --field`. The list output is an array, so
    /// JSON Pointer paths reach individual entries (e.g. `/0/name`,
    /// `/0/source`). Requires `--json`.
    #[arg(long, value_name = "PATH", requires = "json")]
    pub field: Option<String>,

    /// Emit only the profile names, one per line. Friendlier than
    /// `--field /N/name` (which only gets a single index) for
    /// shell loops: `for p in $(nono profile list --names-only);
    /// do …; done`. Conflicts with `--json` / `--compact` /
    /// `--field` (different output shape).
    #[arg(long, conflicts_with_all = &["json", "compact", "field"])]
    pub names_only: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct ProfileShowArgs {
    /// Profile name or path
    pub profile: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Emit compact JSON (no whitespace / indentation) instead of the
    /// default pretty-printed form. Useful for streaming into `jq -c`
    /// or pinning a profile snapshot in an audit log. Has no effect
    /// without `--json`.
    #[arg(long, requires = "json")]
    pub compact: bool,
    /// Show raw paths before expansion (e.g., $HOME instead of /Users/luke)
    #[arg(long)]
    pub raw: bool,
    /// Output format: 'profile' (default) or 'manifest' (capability manifest JSON)
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub format: Option<ProfileShowFormat>,
    /// Extract a single field from the JSON profile output instead of
    /// emitting the whole document — `jq -r`-lite for shell scripts.
    /// Accepts a top-level key (`network`) or a JSON Pointer path
    /// (`/security/groups/0`). String / number / bool / null primitives
    /// are emitted raw (no surrounding quotes); objects / arrays still
    /// render as JSON, honoring `--compact`. Requires `--json` and is
    /// not honored when `--format manifest` is set.
    #[arg(long, value_name = "PATH", requires = "json")]
    pub field: Option<String>,
    /// Refresh the profile output every DURATION (e.g. `2s`,
    /// `5s`, `1m`) — top-like polling. Useful when editing a
    /// profile JSON file and watching it re-resolve as the
    /// inheritance chain changes. Exit with Ctrl-C. Conflicts
    /// with the single-shot structured-output modes (`--json` /
    /// `--compact` / `--field`).
    #[arg(
        long,
        value_name = "DURATION",
        conflicts_with_all = &["json", "compact", "field"],
    )]
    pub watch: Option<String>,
    /// Cap `--watch` at N frames before exiting. Symmetric to
    /// `nono inspect --max-iterations`. Requires `--watch`; has
    /// no effect on a single-shot show.
    #[arg(long, value_name = "N", requires = "watch")]
    pub max_iterations: Option<u64>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ProfileShowFormat {
    Profile,
    Manifest,
}

#[derive(Parser, Debug, Clone)]
pub struct ProfileDiffArgs {
    /// First profile name or path
    pub profile1: String,
    /// Second profile name or path
    pub profile2: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Emit compact JSON (no whitespace / indentation). Has no effect
    /// without `--json`.
    #[arg(long, requires = "json")]
    pub compact: bool,
    /// Extract a single field from the diff JSON output instead of
    /// emitting the whole document — symmetric to
    /// `nono profile show --field`. Useful for `if [ "$(nono profile
    /// diff a b --json --field /security/groups/added | jq length)" -gt 0 ]`
    /// style guards. Accepts a top-level key or a JSON Pointer path.
    /// Requires `--json`.
    #[arg(long, value_name = "PATH", requires = "json")]
    pub field: Option<String>,
    /// Suppress all stdout and signal "are these profiles different?"
    /// via exit code: 0 = identical, 1 = differ. Useful for CI
    /// gates: `if ! nono profile diff a b --quiet; then echo
    /// "drift detected"; fi`. Conflicts with output-emitting flags
    /// (`--json` / `--compact` / `--field`).
    #[arg(long, conflicts_with_all = &["json", "compact", "field"])]
    pub quiet: bool,
    /// Refresh the diff every DURATION (e.g. `2s`, `5s`, `1m`) —
    /// top-like polling. Useful for live drift detection while
    /// editing one of the two profiles. Each tick re-reads both
    /// profiles from disk via `load_profile_no_migrate`. Conflicts
    /// with the structured-output / single-shot modes (`--json`
    /// / `--compact` / `--field` / `--quiet`).
    #[arg(
        long,
        value_name = "DURATION",
        conflicts_with_all = &["json", "compact", "field", "quiet"],
    )]
    pub watch: Option<String>,
    /// Cap `--watch` at N frames before exiting. Symmetric to
    /// `nono inspect --max-iterations`. Requires `--watch`; has
    /// no effect on a single-shot diff.
    #[arg(long, value_name = "N", requires = "watch")]
    pub max_iterations: Option<u64>,
}

#[derive(Parser, Debug)]
pub struct ProfileValidateArgs {
    /// Profile JSON file to validate
    pub file: PathBuf,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Emit compact JSON (no whitespace / indentation). Has no effect
    /// without `--json`.
    #[arg(long, requires = "json")]
    pub compact: bool,
    /// Extract a single field from the JSON output instead of emitting
    /// the whole document — same `jq -r`-lite semantics as
    /// `nono profile show --field`. Useful for scripting:
    /// `if [ "$(nono profile validate <file> --json --field valid)" =
    /// "true" ]; then …`. Top-level keys are `file`, `valid`,
    /// `errors`, `warnings`. Requires `--json`.
    #[arg(long, value_name = "PATH", requires = "json")]
    pub field: Option<String>,
    /// Suppress all stdout and signal validity via exit code:
    /// `0` valid, `1` invalid (errors present). Cleaner than the
    /// `--field valid` form when shell scripts only need the
    /// branch — `nono profile validate p.json --quiet && deploy`.
    /// Conflicts with output-emitting flags (`--json` /
    /// `--compact` / `--field`).
    #[arg(long, conflicts_with_all = &["json", "compact", "field"])]
    pub quiet: bool,
}

#[derive(Parser, Debug)]
pub struct ProfileGroupsArgs {
    /// Group name to show details for (omit to list all)
    pub name: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Emit compact JSON (no whitespace / indentation). Has no effect
    /// without `--json`.
    #[arg(long, requires = "json")]
    pub compact: bool,
    /// Show all platforms (not just current)
    #[arg(long)]
    pub all_platforms: bool,
    /// Extract a single field from the JSON output instead of
    /// emitting the whole document — same `jq -r`-lite semantics as
    /// `nono profile show --field`. Top-level keys for the detail
    /// view (`description`, `platform`); JSON Pointer paths into
    /// the array (e.g. `/0/name`) for the list view. Requires
    /// `--json`.
    #[arg(long, value_name = "PATH", requires = "json")]
    pub field: Option<String>,

    /// Emit only the group names, one per line — symmetric to
    /// `nono profile list --names-only`. Useful for shell loops
    /// over policy groups: `for g in $(nono profile groups
    /// --names-only); do nono profile groups "$g"; done`. Only
    /// honored in list mode (no group name argument). Conflicts
    /// with output-emitting flags (`--json` / `--compact` /
    /// `--field`).
    #[arg(long, conflicts_with_all = &["json", "compact", "field"])]
    pub names_only: bool,

    /// Filter the group list to those that match a keyword as a
    /// case-insensitive substring against name, description, and
    /// every path / command in `allow.{read,write,readwrite}`,
    /// `deny.access`, and `deny.commands`. Each surviving group
    /// is annotated with `[matched in: <fields>]` so it is clear
    /// which field carried the hit. Symmetric to `profile guide
    /// --search`. Combines naturally with `--names-only` for
    /// shell-loop ergonomics: `for g in $(nono profile groups
    /// --search etc --names-only); do …; done`. Only honored in
    /// list mode (the per-group detail view is already a single
    /// document — drop the group-name argument to use it).
    /// Conflicts with output-emitting flags (`--json` /
    /// `--compact` / `--field`) — same convention as `guide
    /// --search`.
    #[arg(
        long,
        value_name = "KEYWORD",
        conflicts_with_all = &["json", "compact", "field"],
    )]
    pub search: Option<String>,
}

#[derive(Parser, Debug, Clone, Default)]
pub struct SandboxArgs {
    // ── Filesystem ───────────────────────────────────────────────────────
    /// Allow read+write access to a directory (recursive)
    #[arg(
        long,
        short = 'a',
        value_name = "DIR",
        env = "NONO_ALLOW",
        value_delimiter = ',',
        help_heading = "FILESYSTEM"
    )]
    pub allow: Vec<PathBuf>,

    /// Allow read-only access to a directory (recursive)
    #[arg(long, short = 'r', value_name = "DIR", help_heading = "FILESYSTEM")]
    pub read: Vec<PathBuf>,

    /// Allow write-only access to a directory (recursive). Directory deletion NOT included
    #[arg(long, short = 'w', value_name = "DIR", help_heading = "FILESYSTEM")]
    pub write: Vec<PathBuf>,

    /// Allow read+write access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub allow_file: Vec<PathBuf>,

    /// Allow read-only access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub read_file: Vec<PathBuf>,

    /// Allow write-only access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub write_file: Vec<PathBuf>,

    /// Allow connect() to an AF_UNIX socket at this path (implies --read-file)
    #[arg(long, value_name = "SOCKET", help_heading = "FILESYSTEM")]
    pub allow_unix_socket: Vec<PathBuf>,

    /// Allow connect() and bind() on an AF_UNIX socket at this path.
    /// If the path exists, implies --allow-file on the socket. If it
    /// does not yet exist (the typical bind(2) case), implies --allow
    /// on the parent directory so the kernel can create the socket
    /// file. Prefer --allow-unix-socket-dir-bind for runtime-generated
    /// filenames.
    #[arg(long, value_name = "SOCKET", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_bind: Vec<PathBuf>,

    /// Allow connect() to any AF_UNIX socket directly within this directory
    /// (non-recursive; implies --read)
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_dir: Vec<PathBuf>,

    /// Allow connect() and bind() on any AF_UNIX socket directly within this
    /// directory (non-recursive; implies --allow). Use for runtime-generated
    /// socket filenames (PID-derived paths, etc.).
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_dir_bind: Vec<PathBuf>,

    /// Override a deny rule for a path. Pair with --allow/--read/--write grant
    #[arg(long, value_name = "PATH", help_heading = "FILESYSTEM")]
    pub override_deny: Vec<PathBuf>,

    /// Allow CWD access without prompting (level set by profile, defaults to read-only)
    #[arg(long, help_heading = "FILESYSTEM")]
    pub allow_cwd: bool,

    /// Working directory for $WORKDIR expansion in profiles
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub workdir: Option<PathBuf>,

    // ── Network ──────────────────────────────────────────────────────────
    /// Block outbound network access (allowed by default)
    #[arg(
        long = "block-net",
        alias = "net-block",
        conflicts_with = "allow_net",
        env = "NONO_BLOCK_NET",
        value_parser = clap::builder::BoolishValueParser::new(),
        action = clap::ArgAction::SetTrue,
        help_heading = "NETWORK"
    )]
    pub block_net: bool,

    /// Deprecated compatibility flag. Network is unrestricted by default.
    #[arg(
        long = "allow-net",
        alias = "net-allow",
        env = "NONO_ALLOW_NET",
        value_parser = clap::builder::BoolishValueParser::new(),
        action = clap::ArgAction::SetTrue,
        conflicts_with_all = [
            "block_net",
            "network_profile",
            "allow_proxy",
            "proxy_credential",
            "external_proxy",
            "external_proxy_bypass",
            "proxy_port"
        ],
        hide = true,
        help_heading = "NETWORK"
    )]
    pub allow_net: bool,

    /// Enable proxy filtering with a named network profile
    #[arg(
        long,
        value_name = "PROFILE",
        env = "NONO_NETWORK_PROFILE",
        help_heading = "NETWORK"
    )]
    pub network_profile: Option<String>,

    /// Add a domain to the proxy allowlist (repeatable)
    #[arg(
        long = "allow-domain",
        alias = "allow-proxy",
        alias = "proxy-allow",
        env = "NONO_ALLOW_DOMAIN",
        value_name = "DOMAIN",
        help_heading = "NETWORK"
    )]
    pub allow_proxy: Vec<String>,

    /// Allow the sandboxed child to listen on a TCP port (repeatable)
    #[arg(
        long = "listen-port",
        alias = "allow-bind",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_bind: Vec<u16>,

    /// Allow bidirectional localhost TCP on a port: connect + listen (repeatable)
    #[arg(
        long = "open-port",
        alias = "allow-port",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_port: Vec<u16>,

    /// Allow outbound TCP connect to a specific port (repeatable; Linux Landlock V4+ only)
    #[arg(
        long = "allow-connect-port",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_connect_port: Vec<u16>,

    /// Chain outbound traffic through an upstream proxy (host:port)
    #[arg(
        long = "upstream-proxy",
        alias = "external-proxy",
        value_name = "HOST:PORT",
        env = "NONO_UPSTREAM_PROXY",
        help_heading = "NETWORK"
    )]
    pub external_proxy: Option<String>,

    /// Route these domains direct instead of through the upstream proxy
    #[arg(
        long = "upstream-bypass",
        alias = "external-proxy-bypass",
        value_name = "DOMAIN",
        env = "NONO_UPSTREAM_BYPASS",
        value_delimiter = ',',
        help_heading = "NETWORK"
    )]
    pub external_proxy_bypass: Vec<String>,

    /// Fixed port for the credential proxy (default: OS-assigned)
    #[arg(long, value_name = "PORT", help_heading = "NETWORK")]
    pub proxy_port: Option<u16>,

    // ── Credentials ──────────────────────────────────────────────────────
    /// Inject credentials via reverse proxy for a service (repeatable)
    #[arg(
        long = "credential",
        alias = "proxy-credential",
        env = "NONO_CREDENTIAL",
        value_name = "SERVICE",
        help_heading = "CREDENTIALS"
    )]
    pub proxy_credential: Vec<String>,

    /// Restrict a credential service to specific HTTP method+path patterns (repeatable).
    /// Format: "SERVICE:METHOD:/path/pattern" (e.g., "github:GET:/repos/*/issues")
    /// Use "*" for any method: "github:*:/repos/*/issues"
    /// Patterns: "*" matches one path segment, "**" matches zero or more.
    #[arg(
        long = "allow-endpoint",
        value_name = "SERVICE:METHOD:PATH",
        help_heading = "CREDENTIALS"
    )]
    pub allow_endpoint: Vec<String>,

    /// Load credentials as env vars. For network API keys, prefer --credential
    #[arg(
        long,
        value_name = "CREDENTIALS",
        env = "NONO_ENV_CREDENTIAL",
        help_heading = "CREDENTIALS"
    )]
    pub env_credential: Option<String>,

    /// Map a credential reference to an environment variable (repeatable)
    #[arg(
        long,
        value_names = ["CREDENTIAL_REF", "ENV_VAR"],
        num_args = 2,
        action = clap::ArgAction::Append,
        help_heading = "CREDENTIALS"
    )]
    pub env_credential_map: Vec<String>,

    // ── Commands ─────────────────────────────────────────────────────────
    /// Deprecated startup-only command allowlist override (not child-process enforced)
    #[arg(long, value_name = "CMD", help_heading = "COMMANDS")]
    pub allow_command: Vec<String>,

    /// Deprecated startup-only command denylist extension (not child-process enforced)
    #[arg(long, value_name = "CMD", help_heading = "COMMANDS")]
    pub block_command: Vec<String>,

    // ── General ──────────────────────────────────────────────────────────
    /// Use a profile by name or file path
    #[arg(
        long,
        short = 'p',
        value_name = "NAME_OR_PATH",
        env = "NONO_PROFILE",
        help_heading = "OPTIONS"
    )]
    pub profile: Option<String>,

    /// Allow direct LaunchServices opens on macOS (temporary login/setup flows)
    #[arg(long, help_heading = "OPTIONS")]
    pub allow_launch_services: bool,

    /// Allow GPU access (Metal/IOKit on Apple Silicon macOS, render nodes on Linux)
    #[arg(long, help_heading = "OPTIONS")]
    pub allow_gpu: bool,

    /// Capability manifest file (JSON). A fully-resolved sandbox specification —
    /// mutually exclusive with all other sandbox configuration flags.
    #[arg(
        long,
        short = 'c',
        value_name = "FILE",
        conflicts_with_all = &[
            "allow", "read", "write", "allow_file", "read_file", "write_file",
            "allow_unix_socket", "allow_unix_socket_bind",
            "allow_unix_socket_dir", "allow_unix_socket_dir_bind",
            "profile", "override_deny", "allow_cwd",
            "block_net", "allow_net", "network_profile", "allow_proxy",
            "allow_bind", "allow_port", "allow_connect_port", "external_proxy", "proxy_port",
            "proxy_credential", "allow_endpoint", "env_credential", "env_credential_map",
            "allow_command", "block_command", "allow_launch_services", "allow_gpu",
        ],
        help_heading = "OPTIONS"
    )]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    /// Show what would be sandboxed without executing
    #[arg(long, help_heading = "OPTIONS")]
    pub dry_run: bool,

    /// Like --dry-run, but emit a structured JSON snapshot of the resolved
    /// capabilities and planned command to stdout (one JSON document per
    /// invocation). Intended for tooling integration. Currently honored by
    /// `nono run` only; other subcommands ignore this flag (MVP).
    #[arg(long, help_heading = "OPTIONS", conflicts_with = "dry_run")]
    pub dry_run_json: bool,
}

impl SandboxArgs {
    /// Whether any CLI flag requires proxy mode activation.
    pub fn has_proxy_flags(&self) -> bool {
        self.network_profile.is_some()
            || !self.allow_proxy.is_empty()
            || !self.proxy_credential.is_empty()
            || self.external_proxy.is_some()
    }
}

#[derive(Parser, Debug, Clone, Default)]
pub struct WrapSandboxArgs {
    // ── Filesystem ───────────────────────────────────────────────────────
    /// Allow read+write access to a directory (recursive)
    #[arg(
        long,
        short = 'a',
        value_name = "DIR",
        env = "NONO_ALLOW",
        value_delimiter = ',',
        help_heading = "FILESYSTEM"
    )]
    pub allow: Vec<PathBuf>,

    /// Allow read-only access to a directory (recursive)
    #[arg(long, short = 'r', value_name = "DIR", help_heading = "FILESYSTEM")]
    pub read: Vec<PathBuf>,

    /// Allow write-only access to a directory (recursive). Directory deletion NOT included
    #[arg(long, short = 'w', value_name = "DIR", help_heading = "FILESYSTEM")]
    pub write: Vec<PathBuf>,

    /// Allow read+write access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub allow_file: Vec<PathBuf>,

    /// Allow read-only access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub read_file: Vec<PathBuf>,

    /// Allow write-only access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub write_file: Vec<PathBuf>,

    /// Allow connect() to an AF_UNIX socket at this path (implies --read-file)
    #[arg(long, value_name = "SOCKET", help_heading = "FILESYSTEM")]
    pub allow_unix_socket: Vec<PathBuf>,

    /// Allow connect() and bind() on an AF_UNIX socket at this path.
    /// If the path exists, implies --allow-file on the socket. If it
    /// does not yet exist (the typical bind(2) case), implies --allow
    /// on the parent directory so the kernel can create the socket
    /// file. Prefer --allow-unix-socket-dir-bind for runtime-generated
    /// filenames.
    #[arg(long, value_name = "SOCKET", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_bind: Vec<PathBuf>,

    /// Allow connect() to any AF_UNIX socket directly within this directory
    /// (non-recursive; implies --read)
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_dir: Vec<PathBuf>,

    /// Allow connect() and bind() on any AF_UNIX socket directly within this
    /// directory (non-recursive; implies --allow). Use for runtime-generated
    /// socket filenames (PID-derived paths, etc.).
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_dir_bind: Vec<PathBuf>,

    /// Override a deny rule for a path. Pair with --allow/--read/--write grant
    #[arg(long, value_name = "PATH", help_heading = "FILESYSTEM")]
    pub override_deny: Vec<PathBuf>,

    /// Allow CWD access without prompting (level set by profile, defaults to read-only)
    #[arg(long, help_heading = "FILESYSTEM")]
    pub allow_cwd: bool,

    /// Working directory for $WORKDIR expansion in profiles
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub workdir: Option<PathBuf>,

    // ── Network ──────────────────────────────────────────────────────────
    /// Block outbound network access (allowed by default)
    #[arg(
        long = "block-net",
        alias = "net-block",
        env = "NONO_BLOCK_NET",
        value_parser = clap::builder::BoolishValueParser::new(),
        action = clap::ArgAction::SetTrue,
        help_heading = "NETWORK"
    )]
    pub block_net: bool,

    /// Allow the sandboxed child to listen on a TCP port (repeatable)
    #[arg(
        long = "listen-port",
        alias = "allow-bind",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_bind: Vec<u16>,

    /// Allow bidirectional localhost TCP on a port: connect + listen (repeatable)
    #[arg(
        long = "open-port",
        alias = "allow-port",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_port: Vec<u16>,

    /// Allow outbound TCP connect to a specific port (repeatable; Linux Landlock V4+ only)
    #[arg(
        long = "allow-connect-port",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_connect_port: Vec<u16>,

    // ── Credentials ──────────────────────────────────────────────────────
    /// Load credentials as env vars
    #[arg(
        long,
        value_name = "CREDENTIALS",
        env = "NONO_ENV_CREDENTIAL",
        help_heading = "CREDENTIALS"
    )]
    pub env_credential: Option<String>,

    /// Map a credential reference to an environment variable (repeatable)
    #[arg(
        long,
        value_names = ["CREDENTIAL_REF", "ENV_VAR"],
        num_args = 2,
        action = clap::ArgAction::Append,
        help_heading = "CREDENTIALS"
    )]
    pub env_credential_map: Vec<String>,

    // ── Commands ─────────────────────────────────────────────────────────
    /// Deprecated startup-only command allowlist override (not child-process enforced)
    #[arg(long, value_name = "CMD", help_heading = "COMMANDS")]
    pub allow_command: Vec<String>,

    /// Deprecated startup-only command denylist extension (not child-process enforced)
    #[arg(long, value_name = "CMD", help_heading = "COMMANDS")]
    pub block_command: Vec<String>,

    // ── General ──────────────────────────────────────────────────────────
    /// Use a profile by name or file path
    #[arg(
        long,
        short = 'p',
        value_name = "NAME_OR_PATH",
        env = "NONO_PROFILE",
        help_heading = "OPTIONS"
    )]
    pub profile: Option<String>,

    /// Allow direct LaunchServices opens on macOS (temporary login/setup flows)
    #[arg(long, help_heading = "OPTIONS")]
    pub allow_launch_services: bool,

    /// Allow GPU access (Metal/IOKit on Apple Silicon macOS, render nodes on Linux)
    #[arg(long, help_heading = "OPTIONS")]
    pub allow_gpu: bool,

    /// Capability manifest file (JSON). A fully-resolved sandbox specification —
    /// mutually exclusive with all other sandbox configuration flags.
    #[arg(
        long,
        short = 'c',
        value_name = "FILE",
        conflicts_with_all = &[
            "allow", "read", "write", "allow_file", "read_file", "write_file",
            "allow_unix_socket", "allow_unix_socket_bind",
            "allow_unix_socket_dir", "allow_unix_socket_dir_bind",
            "profile", "override_deny", "allow_cwd",
            "block_net", "allow_bind", "allow_port", "allow_connect_port",
            "env_credential", "env_credential_map",
            "allow_command", "block_command", "allow_launch_services", "allow_gpu",
        ],
        help_heading = "OPTIONS"
    )]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    /// Show what would be sandboxed without executing
    #[arg(long, help_heading = "OPTIONS")]
    pub dry_run: bool,

    /// Like --dry-run, but emit a structured JSON snapshot of the resolved
    /// capabilities and planned command to stdout. Honored by `nono wrap`
    /// (mirrors the same flag on `nono run` / `nono shell`).
    #[arg(long, help_heading = "OPTIONS", conflicts_with = "dry_run")]
    pub dry_run_json: bool,
}

impl From<WrapSandboxArgs> for SandboxArgs {
    fn from(args: WrapSandboxArgs) -> Self {
        Self {
            allow: args.allow,
            read: args.read,
            write: args.write,
            allow_file: args.allow_file,
            read_file: args.read_file,
            write_file: args.write_file,
            allow_unix_socket: args.allow_unix_socket,
            allow_unix_socket_bind: args.allow_unix_socket_bind,
            allow_unix_socket_dir: args.allow_unix_socket_dir,
            allow_unix_socket_dir_bind: args.allow_unix_socket_dir_bind,
            override_deny: args.override_deny,
            allow_cwd: args.allow_cwd,
            workdir: args.workdir,
            block_net: args.block_net,
            allow_net: false,
            network_profile: None,
            allow_proxy: Vec::new(),
            allow_bind: args.allow_bind,
            allow_port: args.allow_port,
            allow_connect_port: args.allow_connect_port,
            external_proxy: None,
            external_proxy_bypass: Vec::new(),
            proxy_port: None,
            proxy_credential: Vec::new(),
            allow_endpoint: Vec::new(),
            env_credential: args.env_credential,
            env_credential_map: args.env_credential_map,
            allow_command: args.allow_command,
            block_command: args.block_command,
            profile: args.profile,
            allow_launch_services: args.allow_launch_services,
            allow_gpu: args.allow_gpu,
            config: args.config,
            verbose: args.verbose,
            dry_run: args.dry_run,
            dry_run_json: args.dry_run_json,
        }
    }
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RunArgs {
    #[command(flatten)]
    pub sandbox: SandboxArgs,

    /// Start the session without attaching the current terminal.
    /// The supervisor keeps the sandboxed process running in the background;
    /// use `nono attach <session>` later to inspect or interact with it.
    #[arg(long, help_heading = "OPTIONS")]
    pub detached: bool,

    // ── Rollback ──────────────────────────────────────────────────────
    /// Enable atomic rollback snapshots for the session
    #[arg(long, conflicts_with = "no_rollback", help_heading = "ROLLBACK")]
    pub rollback: bool,

    /// Skip the post-exit rollback review prompt
    #[arg(long, help_heading = "ROLLBACK")]
    pub no_rollback_prompt: bool,

    /// Disable rollback entirely (no snapshots taken)
    #[arg(long, conflicts_with = "rollback", help_heading = "ROLLBACK")]
    pub no_rollback: bool,

    /// Exclude from snapshots. Globs match filenames; plain names match path components
    #[arg(long, value_name = "PATTERN", help_heading = "ROLLBACK")]
    pub rollback_exclude: Vec<String>,

    /// Force-include an auto-excluded directory (name only, not full path)
    #[arg(long, value_name = "DIR_NAME", help_heading = "ROLLBACK")]
    pub rollback_include: Vec<String>,

    /// Include all directories in snapshots. VCS dirs (.git) always excluded
    #[arg(long, conflicts_with = "rollback_include", help_heading = "ROLLBACK")]
    pub rollback_all: bool,

    /// Skip large directory trees during trust scanning and rollback preflight.
    /// Matched as an exact path component name. Repeatable.
    #[arg(long, value_name = "DIR_NAME", help_heading = "OPTIONS")]
    pub skip_dir: Vec<String>,

    /// Override the rollback snapshot destination directory.
    /// By default, snapshots are stored in ~/.nono/rollbacks/.
    /// The destination must be within a path already granted write access
    /// by --allow (or profile); nono will fail with a clear error if not.
    /// Useful for Docker volume mounts or shared storage paths.
    #[arg(
        long,
        value_name = "PATH",
        requires = "rollback",
        help_heading = "ROLLBACK"
    )]
    pub rollback_dest: Option<std::path::PathBuf>,

    // ── Options ────────────────────────────────────────────────────────
    /// Suppress diagnostic footer on command failure
    #[arg(long, help_heading = "OPTIONS")]
    pub no_diagnostics: bool,

    /// Disable the audit trail for this session
    #[arg(
        long,
        conflicts_with_all = ["audit_integrity", "no_audit_integrity", "rollback"],
        help_heading = "OPTIONS"
    )]
    pub no_audit: bool,

    /// Disable the default Merkleized append-only audit log
    #[arg(long, conflicts_with_all = ["audit_integrity", "rollback"], help_heading = "OPTIONS")]
    pub no_audit_integrity: bool,

    /// Add filesystem-state hashing over in-scope writable paths
    #[arg(long, help_heading = "OPTIONS")]
    pub audit_integrity: bool,

    /// Sign the audit Merkle root with a keyed signing key loaded from the given secret reference.
    /// Accepts bare trust-key IDs, keystore:// names, file:// paths, op:// URIs, apple-password:// URIs, keyring:// URIs, or env:// URIs.
    #[arg(
        long,
        value_name = "SECRET_REF",
        conflicts_with_all = ["no_audit", "no_audit_integrity"],
        help_heading = "OPTIONS"
    )]
    pub audit_sign_key: Option<String>,

    /// Disable trust verification (not recommended for production)
    #[arg(long, help_heading = "OPTIONS")]
    pub trust_override: bool,

    /// Name for this session (shown in `nono ps`)
    #[arg(long, value_name = "NAME", help_heading = "OPTIONS")]
    pub name: Option<String>,

    /// Enable runtime capability elevation (seccomp-notify + approval prompts).
    /// Overrides the profile's capability_elevation setting.
    /// When enabled, the supervisor can grant access to paths not in the
    /// initial capability set via interactive prompts.
    #[arg(long, env = "NONO_CAPABILITY_ELEVATION", help_heading = "OPTIONS")]
    pub capability_elevation: bool,

    /// Command to run inside the sandbox
    #[arg(required = true, hide = true)]
    pub command: Vec<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct ShellArgs {
    #[command(flatten)]
    pub sandbox: SandboxArgs,

    /// Shell to execute (defaults to $SHELL or /bin/sh)
    #[arg(long, value_name = "SHELL", help_heading = "OPTIONS")]
    pub shell: Option<PathBuf>,

    /// Name for this session (shown in `nono ps`)
    #[arg(long, value_name = "NAME", help_heading = "OPTIONS")]
    pub name: Option<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct WrapArgs {
    #[command(flatten)]
    pub sandbox: WrapSandboxArgs,

    /// Suppress diagnostic footer on command failure
    #[arg(long, help_heading = "OPTIONS")]
    pub no_diagnostics: bool,

    /// Command to run inside the sandbox
    #[arg(required = true, hide = true)]
    pub command: Vec<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct SetupArgs {
    /// Only verify installation and sandbox support, don't create files
    #[arg(long, help_heading = "OPTIONS")]
    pub check_only: bool,

    /// Generate example user profiles in ~/.config/nono/profiles/
    #[arg(long, help_heading = "OPTIONS")]
    pub profiles: bool,

    /// Show shell integration instructions
    #[arg(long, help_heading = "OPTIONS")]
    pub shell_integration: bool,

    /// Print the filesystem paths nono uses (config, profiles, sessions,
    /// trusted keys, executable) and exit. Useful for debugging "where
    /// does nono look for X?" without strace or reading the source.
    #[arg(long, help_heading = "OPTIONS")]
    pub print_paths: bool,

    /// Show detailed information during setup
    #[arg(short, long, action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug, Clone)]
#[command(disable_help_flag = true)]
pub struct WhyArgs {
    /// Path to check
    #[arg(long, help_heading = "QUERY")]
    pub path: Option<PathBuf>,

    /// Operation to check: read, write, or readwrite
    #[arg(long, value_enum, help_heading = "QUERY")]
    pub op: Option<WhyOp>,

    /// Network host to check
    #[arg(long, help_heading = "QUERY")]
    pub host: Option<String>,

    /// Network port (default 443)
    #[arg(long, default_value = "443", help_heading = "QUERY")]
    pub port: u16,

    /// Combined `host:port` shorthand for network queries (alternative to
    /// `--host` + `--port`). Useful when the address comes from a URL or
    /// config file that already has `host:port` formatted, e.g.
    /// `nono why --net api.openai.com:443 --profile claude-code`.
    #[arg(long, value_name = "HOST:PORT", help_heading = "QUERY",
          conflicts_with_all = &["host", "port", "path", "command_name"])]
    pub net: Option<String>,

    /// Check whether a single TCP port is allowed under the resolved
    /// per-port allowlist (Linux Landlock V4+ filters by port; macOS
    /// Seatbelt tracks the same allowlists for parity). Reports which
    /// list — `tcp_connect_ports`, `tcp_bind_ports`, or `localhost_ports`
    /// — covers the port, or denies if network is blocked overall.
    #[arg(long, value_name = "PORT", help_heading = "QUERY",
          conflicts_with_all = &["host", "port", "path", "command_name", "net", "tcp_bind"])]
    pub tcp: Option<u16>,

    /// Check whether a single TCP port is bind-allowed (listen / bind)
    /// — narrower than `--tcp` since `tcp_connect_ports` is intentionally
    /// ignored. Useful when verifying that `--allow-port <PORT>` (which
    /// only authorizes inbound bind) actually covers a server-side port,
    /// without being misled by an unrelated outbound `--allow-connect-port`
    /// grant on the same number. Resolution: `localhost_ports` then
    /// `tcp_bind_ports`, falling back to the resolved network mode.
    #[arg(long = "tcp-bind", value_name = "PORT", help_heading = "QUERY",
          conflicts_with_all = &["host", "port", "path", "command_name", "net", "tcp"])]
    pub tcp_bind: Option<u16>,

    /// Command name to check against the resolved policy's blocklist /
    /// allowlist (e.g. `nono why --command rm --profile claude`).
    #[arg(long = "command", value_name = "NAME", help_heading = "QUERY",
          conflicts_with_all = &["path", "host", "net"])]
    pub command_name: Option<String>,

    /// Output JSON instead of human-readable format
    #[arg(long, help_heading = "OPTIONS")]
    pub json: bool,

    /// Emit compact JSON (no whitespace / indentation) instead of the
    /// default pretty-printed form. Useful for streaming into `jq -c`.
    /// Has no effect without `--json`.
    #[arg(long, requires = "json", help_heading = "OPTIONS")]
    pub compact: bool,

    /// In addition to the verdict, list every rule that touches the
    /// query: capabilities (with a `sufficient?` column) for `--path`,
    /// every entry in `allowed_commands` / `blocked_commands` (with
    /// a `matches?` column) for `--command`, and every per-port
    /// allowlist entry for `--tcp` / `--tcp-bind`. Useful for
    /// debugging complex profiles where the best-match verdict alone
    /// doesn't capture the full picture.
    #[arg(long, help_heading = "OPTIONS")]
    pub explain: bool,

    /// Don't run any query — instead print the resolved capability set
    /// that *would* be used as the query context. Useful for
    /// understanding what `--profile NAME` grants in aggregate before
    /// poking individual paths / hosts / commands. Mutually exclusive
    /// with the query flags (`--path`, `--host`, `--net`, `--tcp`,
    /// `--tcp-bind`, `--command`).
    #[arg(
        long,
        help_heading = "OPTIONS",
        conflicts_with_all = &["path", "host", "net", "tcp", "tcp_bind", "command_name"],
    )]
    pub print_policy: bool,

    /// Extract a single field from the JSON output instead of emitting
    /// the whole document — same `jq -r`-lite semantics as
    /// `nono profile show --field` / `nono inspect --field`. Accepts
    /// a top-level key (`reason`, `status`) or a JSON Pointer path
    /// (`/matches/0/list` when `--explain` is set). Requires `--json`.
    #[arg(long, value_name = "PATH", help_heading = "OPTIONS", requires = "json")]
    pub field: Option<String>,

    /// Suppress all stdout output and signal the verdict via exit
    /// code: 0 = allowed, 2 = denied, 3 = not running inside a
    /// sandbox (only reachable with `--self`). Useful for shell
    /// branching: `if nono why --command rm --profile X --quiet;
    /// then echo allowed; fi`. Conflicts with `--json` / `--compact`
    /// / `--field` (those modes ask for output) and `--print-policy`
    /// (the policy dump has no verdict).
    #[arg(
        long,
        help_heading = "OPTIONS",
        conflicts_with_all = &["json", "compact", "field", "print_policy"],
    )]
    pub quiet: bool,

    /// Refresh the verdict every DURATION (e.g. `2s`, `5s`,
    /// `1m`) — top-like polling. Useful when editing a profile
    /// and watching how the resolution affects a specific path
    /// / command / port query in real time. Each tick re-loads
    /// the profile and re-runs the query. Conflicts with the
    /// structured-output / single-shot modes (`--json` /
    /// `--compact` / `--field` / `--quiet`).
    #[arg(
        long,
        help_heading = "OPTIONS",
        value_name = "DURATION",
        conflicts_with_all = &["json", "compact", "field", "quiet"],
    )]
    pub watch: Option<String>,

    /// Cap `--watch` at N frames before exiting. Symmetric to
    /// `nono inspect --max-iterations`. Requires `--watch`; has
    /// no effect on a single-shot query.
    #[arg(long, help_heading = "OPTIONS", value_name = "N", requires = "watch")]
    pub max_iterations: Option<u64>,

    /// Query current sandbox state (use inside a sandboxed process)
    #[arg(long = "self", help_heading = "OPTIONS")]
    pub self_query: bool,

    // ── Capability context ─────────────────────────────────────────────
    /// Directories to allow read+write access (for query context)
    #[arg(long, short = 'a', value_name = "DIR", help_heading = "CONTEXT")]
    pub allow: Vec<PathBuf>,

    /// Directories to allow read-only access (for query context)
    #[arg(long, short = 'r', value_name = "DIR", help_heading = "CONTEXT")]
    pub read: Vec<PathBuf>,

    /// Directories to allow write-only access (for query context)
    #[arg(long, short = 'w', value_name = "DIR", help_heading = "CONTEXT")]
    pub write: Vec<PathBuf>,

    /// Single files to allow read+write access (for query context)
    #[arg(long, value_name = "FILE", help_heading = "CONTEXT")]
    pub allow_file: Vec<PathBuf>,

    /// Single files to allow read-only access (for query context)
    #[arg(long, value_name = "FILE", help_heading = "CONTEXT")]
    pub read_file: Vec<PathBuf>,

    /// Single files to allow write-only access (for query context)
    #[arg(long, value_name = "FILE", help_heading = "CONTEXT")]
    pub write_file: Vec<PathBuf>,

    /// Block network access (for query context)
    #[arg(long = "block-net", alias = "net-block", help_heading = "CONTEXT")]
    pub block_net: bool,

    /// Add a command to the allow-list for this query (overrides blocklist).
    /// Mirrors `nono run --allow-command` so `nono why --command rm
    /// --allow-command rm` answers the same way as the runtime would.
    #[arg(long, value_name = "CMD", help_heading = "CONTEXT")]
    pub allow_command: Vec<String>,

    /// Add a command to the block-list for this query. Lets users probe
    /// command policy without authoring a profile first
    /// (e.g. `nono why --command dd --block-command dd`).
    #[arg(long, value_name = "CMD", help_heading = "CONTEXT")]
    pub block_command: Vec<String>,

    /// Use a named profile for query context
    #[arg(long, short = 'p', value_name = "NAME", help_heading = "CONTEXT")]
    pub profile: Option<String>,

    /// Working directory for $WORKDIR expansion in profiles
    #[arg(long, value_name = "DIR", help_heading = "CONTEXT")]
    pub workdir: Option<PathBuf>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct LearnArgs {
    /// Use a named profile to compare against (shows only missing paths)
    #[arg(long, short = 'p', value_name = "NAME", help_heading = "OPTIONS")]
    pub profile: Option<String>,

    /// Output discovered paths as JSON fragment for profile
    #[arg(long, help_heading = "OPTIONS")]
    pub json: bool,

    /// Timeout in seconds (default: run until command exits)
    #[arg(long, value_name = "SECS", help_heading = "OPTIONS")]
    pub timeout: Option<u64>,

    /// Show all accessed paths, not just those that would be blocked
    #[arg(long, help_heading = "OPTIONS")]
    pub all: bool,

    /// Skip reverse DNS lookups for discovered IPs
    #[arg(long, help_heading = "OPTIONS")]
    pub no_rdns: bool,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    /// Command to trace
    #[arg(required = true, hide = true)]
    pub command: Vec<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

/// Operation type for why command
#[derive(Clone, Debug, ValueEnum)]
pub enum WhyOp {
    /// Read-only access
    Read,
    /// Write-only access
    Write,
    /// Read and write access
    #[value(name = "readwrite")]
    ReadWrite,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RollbackArgs {
    #[command(subcommand)]
    pub command: RollbackCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum RollbackCommands {
    /// List rollback sessions
    List(RollbackListArgs),
    /// Show changes in a session
    Show(RollbackShowArgs),
    /// Restore files from a past session
    Restore(RollbackRestoreArgs),
    /// Verify session integrity
    Verify(RollbackVerifyArgs),
    /// Clean up old sessions
    Cleanup(RollbackCleanupArgs),
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RollbackListArgs {
    /// Show only the N most recent sessions
    #[arg(long, value_name = "N")]
    pub recent: Option<usize>,

    /// Filter sessions by tracked path (matches if session tracked this path or a parent/child)
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Compatibility flag; rollback sessions are shown by default
    #[arg(long)]
    pub all: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RollbackShowArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Show unified diff (git diff style)
    #[arg(long)]
    pub diff: bool,

    /// Show side-by-side diff
    #[arg(long)]
    pub side_by_side: bool,

    /// Show full file content from snapshot
    #[arg(long)]
    pub full: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RollbackRestoreArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Snapshot number to restore to (default: last snapshot)
    #[arg(long)]
    pub snapshot: Option<u32>,

    /// Show what would change without modifying files
    #[arg(long)]
    pub dry_run: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RollbackVerifyArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RollbackCleanupArgs {
    /// Retain N newest sessions (default: from config, usually 10)
    #[arg(long, value_name = "N")]
    pub keep: Option<usize>,

    /// Remove sessions older than N days
    #[arg(long, value_name = "DAYS")]
    pub older_than: Option<u64>,

    /// Show what would be removed without deleting
    #[arg(long)]
    pub dry_run: bool,

    /// Remove all sessions (requires confirmation)
    #[arg(long)]
    pub all: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

// ---------------------------------------------------------------------------
// Audit command args
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum AuditCommands {
    /// List all sandboxed sessions
    List(AuditListArgs),
    /// Show audit details for a session
    Show(AuditShowArgs),
    /// Verify audit integrity by recomputing hashes from the event log
    Verify(AuditVerifyArgs),
    /// Remove old audit sessions
    Cleanup(AuditCleanupArgs),
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct AuditListArgs {
    /// Show only sessions from today
    #[arg(long)]
    pub today: bool,

    /// Show sessions since date (YYYY-MM-DD)
    #[arg(long, value_name = "DATE")]
    pub since: Option<String>,

    /// Show sessions until date (YYYY-MM-DD)
    #[arg(long, value_name = "DATE")]
    pub until: Option<String>,

    /// Filter by command name (e.g., claude, cat)
    #[arg(long, value_name = "CMD")]
    pub command: Option<String>,

    /// Filter by tracked path
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Show only the N most recent sessions
    #[arg(long, value_name = "N")]
    pub recent: Option<usize>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct AuditShowArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct AuditVerifyArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Public key file to match against the attested signer key (PEM or base64 DER)
    #[arg(long, value_name = "FILE")]
    pub public_key_file: Option<PathBuf>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct AuditCleanupArgs {
    /// Retain N newest audit sessions
    #[arg(long, value_name = "N")]
    pub keep: Option<usize>,

    /// Remove sessions older than N days
    #[arg(long, value_name = "DAYS")]
    pub older_than: Option<u64>,

    /// Show what would be removed without deleting
    #[arg(long)]
    pub dry_run: bool,

    /// Remove all audit sessions (skips active sessions)
    #[arg(long)]
    pub all: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub command: SessionCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum SessionCommands {
    /// Remove old runtime sessions
    Cleanup(PruneArgs),
}

/// Status filter accepted by `nono ps --status`.
///
/// Setting any status overrides the default "exclude exited" behavior of
/// `--all` so users can ask for *only* exited sessions without having to
/// add `--all` separately.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[clap(rename_all = "lowercase")]
pub enum PsStatusFilter {
    Running,
    Paused,
    Exited,
}

/// Sort key for `nono ps --sort`.
///
/// Each variant has a "natural" order users typically expect:
/// `Started` newest-first, `Name`/`Profile` alphabetical ascending,
/// `Status` running > paused > exited (most-active first). `--reverse`
/// flips whichever order is active.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[clap(rename_all = "lowercase")]
pub enum PsSortBy {
    Started,
    Name,
    Status,
    Profile,
}

/// Tabular output format for `nono ps --output`.
///
/// `Csv` and `Tsv` emit a header row followed by one record per line,
/// with proper escaping of separator/quote characters in command
/// arguments. `Csv` uses RFC 4180 quoting; `Tsv` encodes newlines, tabs,
/// and carriage returns using backslash escapes so each record stays on
/// a single line. `Ndjson` emits one compact JSON object per line —
/// the line-oriented counterpart to `--json`'s pretty array, suitable
/// for streaming through `jq -c` / fluentd / log aggregators.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[clap(rename_all = "lowercase")]
pub enum PsOutputFormat {
    Csv,
    Tsv,
    Ndjson,
}

/// Selectable columns for the human-readable `nono ps` table. The
/// canonical render in the default table (and the order users get
/// when they don't pass `--columns`) is exactly the variant order
/// declared here. JSON / CSV / TSV / NDJSON outputs always emit the
/// full set and ignore this knob — those formats have to keep a
/// stable schema for downstream tooling.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[clap(rename_all = "lowercase")]
pub enum PsColumn {
    Session,
    Name,
    Status,
    Attach,
    Pid,
    Uptime,
    Profile,
    Command,
}

/// Header style for the human-readable `nono ps` table.
///
/// Only applies to the default and `--short` table renders — the
/// machine-friendly `--output csv|tsv|ndjson` and `--json` paths follow
/// their own conventions and ignore this knob.
#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[clap(rename_all = "lowercase")]
pub enum PsHeaderFormat {
    /// Print column titles with a unicode box-drawing divider beneath
    /// (`─` repeated to the table width). Default for interactive use.
    #[default]
    Fancy,
    /// Same column titles, but the divider falls back to ASCII dashes
    /// (`-`). Pick this when piping through tools or terminals that
    /// mangle non-ASCII characters.
    Ascii,
    /// Skip the header (and divider) entirely — emits only data rows,
    /// so `awk`/`cut`/`column` consumers don't have to `tail -n +2`.
    None,
}

#[derive(Parser, Debug)]
pub struct PsArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Include exited sessions
    #[arg(long)]
    pub all: bool,

    /// Filter by session name — case-insensitive substring match.
    /// Sessions without a name are excluded.
    #[arg(long, value_name = "PATTERN")]
    pub name: Option<String>,

    /// Filter by profile — exact match. Sessions launched without a profile
    /// are excluded when this flag is set.
    #[arg(long, value_name = "NAME")]
    pub profile: Option<String>,

    /// Filter by lifecycle status (overrides `--all`'s exited behavior).
    #[arg(long, value_enum, value_name = "STATUS")]
    pub status: Option<PsStatusFilter>,

    /// Filter by exit code. Implicitly restricts to exited sessions
    /// (`--all` is forced on for the lookup since running sessions have
    /// no exit code yet). Useful for triaging — e.g. `--exit-code 0`
    /// finds successful runs, `--exit-code 137` finds OOM kills.
    #[arg(long, value_name = "CODE")]
    pub exit_code: Option<i32>,

    /// Show only sessions started within the given duration window
    /// (e.g. `--since 30m`, `--since 1h`, `--since 7d`). Accepts
    /// suffixes `s`/`m`/`h`/`d`/`w`. Combine with `--all` if you also
    /// want recent exited sessions.
    #[arg(long, value_name = "DURATION")]
    pub since: Option<String>,

    /// Sort the table by started time, name, status, or profile.
    /// Default sort is `started` (newest first), matching prior behavior.
    #[arg(long, value_enum, value_name = "KEY")]
    pub sort: Option<PsSortBy>,

    /// Reverse the active sort order. Combine with `--sort` to flip the
    /// natural order (e.g. `--sort started --reverse` lists oldest first).
    #[arg(long)]
    pub reverse: bool,

    /// Compact mode for narrow terminals — drops PID, UPTIME, PROFILE,
    /// and ATTACH columns and writes plain text (no ANSI colors) so the
    /// output pipes cleanly into tools like `column`, `cut`, or `awk`.
    #[arg(long)]
    pub short: bool,

    /// Tabular output format for piping into data tools (`csv`, `tsv`).
    /// Conflicts with `--json` because both ask for a non-table view.
    #[arg(long, value_enum, value_name = "FMT", conflicts_with = "json")]
    pub output: Option<PsOutputFormat>,

    /// Refresh the session table every DURATION (e.g. `2s`, `5s`, `1m`)
    /// — top-like polling mode. Conflicts with `--json` and `--output`
    /// because both intend a single batch render. Exit with Ctrl-C.
    #[arg(
        long,
        value_name = "DURATION",
        conflicts_with_all = &["json", "output"],
    )]
    pub watch: Option<String>,

    /// Cap `--watch` at N frames before exiting. Useful in CI smoke
    /// tests of watch mode (don't hang forever) and for capturing a
    /// fixed-size sample without manual Ctrl-C. Requires `--watch`;
    /// has no effect on a single-shot `ps`. Default (unset) means the
    /// loop runs until the user interrupts it.
    #[arg(long, value_name = "N", requires = "watch")]
    pub max_iterations: Option<u64>,

    /// Emit compact JSON (no whitespace / indentation) instead of the
    /// default pretty-printed array. Useful for streaming the session
    /// list into `jq -c`. Has no effect without `--json` — use
    /// `--output ndjson` if you want one record per line.
    #[arg(long, requires = "json")]
    pub compact: bool,

    /// Header style for the human-readable table (`fancy`, `ascii`,
    /// `none`). Defaults to `fancy` (unicode divider). Use `ascii` for
    /// legacy terminals / CI logs and `none` to drop the header
    /// entirely so `awk`/`cut` consumers don't need a `tail -n +2`.
    /// Has no effect on `--json` or `--output csv|tsv|ndjson`.
    #[arg(long, value_enum, value_name = "STYLE", default_value_t = PsHeaderFormat::Fancy)]
    pub header_format: PsHeaderFormat,

    /// Disable command-line truncation in the COMMAND column. Default
    /// caps the rendered argv at 40 chars (60 in `--short`) so wide
    /// terminals stay aligned; pass this when investigating a session
    /// whose argv is hidden behind `…`. The CSV / TSV / NDJSON / JSON
    /// outputs already emit the full command and ignore this flag.
    #[arg(long)]
    pub no_truncate: bool,

    /// Comma-separated list of columns to render in the default
    /// human-readable table — `session,name,status,attach,pid,uptime,
    /// profile,command`. Pass any subset to narrow the output (e.g.
    /// `--columns session,status,command` for triage). Empty / unset
    /// means the canonical full set in the order above. Conflicts
    /// with `--short` (which has its own fixed 4-column subset). The
    /// machine-readable outputs (`--json`, `--output csv|tsv|ndjson`)
    /// always emit the full schema and ignore this knob.
    #[arg(
        long,
        value_enum,
        value_delimiter = ',',
        value_name = "LIST",
        conflicts_with = "short"
    )]
    pub columns: Vec<PsColumn>,

    /// Extract a single field from the JSON output instead of emitting
    /// the whole array — same `jq -r`-lite semantics as other
    /// `--field` surfaces. The session list is an array, so JSON
    /// Pointer paths like `/0/name`, `/0/session_id`, or `/0/profile`
    /// reach individual entries; `0` returns the first entry as JSON.
    /// Requires `--json`; has no effect on `--output csv|tsv|ndjson`.
    #[arg(long, value_name = "PATH", requires = "json")]
    pub field: Option<String>,

    /// Suppress all stdout and signal "any sessions match?" via exit
    /// code (grep-like): 0 = at least one session matches the
    /// resolved filters, 1 = none. Lets CI / shell scripts branch
    /// without parsing tabular output: `if nono ps --status running
    /// --quiet; then echo "have running sessions"; fi`. Conflicts
    /// with output-emitting flags (`--json` / `--compact` /
    /// `--output` / `--field`) and with `--watch` (which is an
    /// interactive loop, not a single check).
    #[arg(
        long,
        conflicts_with_all = &["json", "compact", "output", "field", "watch"],
    )]
    pub quiet: bool,

    /// Emit just the session_id values, one per line, after the
    /// resolved filter / sort / reverse pipeline. Friendlier than
    /// `--field /N/session_id` for shell loops over matches:
    /// `for sid in $(nono ps --status exited --ids-only); do
    /// nono inspect "$sid" --quiet; done`. Conflicts with
    /// output-emitting flags (`--json` / `--compact` / `--output`
    /// / `--field`) and with `--watch` / `--quiet` (different
    /// output modes).
    #[arg(
        long,
        conflicts_with_all = &["json", "compact", "output", "field", "watch", "quiet"],
    )]
    pub ids_only: bool,
}

#[derive(Parser, Debug)]
pub struct StopArgs {
    /// Session ID (or prefix)
    pub session: String,

    /// Force stop (SIGKILL instead of SIGTERM)
    #[arg(long)]
    pub force: bool,

    /// Grace period in seconds before SIGKILL (default: 10)
    #[arg(long, default_value = "10")]
    pub timeout: u64,
}

#[derive(Parser, Debug)]
pub struct DetachArgs {
    /// Session ID, prefix, or name
    pub session: String,
}

#[derive(Parser, Debug)]
pub struct AttachArgs {
    /// Session ID, prefix, or name
    pub session: String,
}

#[derive(Parser, Debug)]
pub struct LogsArgs {
    /// Session ID (or prefix)
    pub session: String,

    /// Follow events in real-time
    #[arg(long, short = 'f')]
    pub follow: bool,

    /// Show last N events
    #[arg(long, value_name = "N")]
    pub tail: Option<usize>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct DryRunSchemaArgs {
    /// Write the schema to FILE instead of stdout. Useful for
    /// dropping it into editor configs (e.g. `.vscode/settings.json`
    /// schema mappings) without manual redirection.
    #[arg(long, short = 'o', value_name = "FILE")]
    pub output: Option<std::path::PathBuf>,

    /// Extract a single field from the schema document instead of
    /// emitting the whole thing — same `jq -r`-lite semantics as
    /// the other `--field` surfaces. Common use:
    /// `nono dry-run-schema --field /properties/schema_version/const`
    /// asserts the runtime schema version without parsing the doc
    /// in shell. Conflicts with `--output` (the latter writes the
    /// full doc to a file).
    #[arg(long, value_name = "PATH", conflicts_with = "output")]
    pub field: Option<String>,

    /// Emit composite extracted values as compact JSON. Has no
    /// effect on primitive --field results (always raw) and no
    /// effect when --field is unset (the schema is always emitted
    /// pretty, since the raw literal is multi-line).
    #[arg(long, requires = "field")]
    pub compact: bool,
}

#[derive(Parser, Debug)]
pub struct InspectArgs {
    /// Session ID (or prefix)
    pub session: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Emit compact JSON (no whitespace / indentation) instead of the
    /// default pretty-printed form. Useful for streaming or piping into
    /// `jq -c`. Has no effect without `--json`.
    #[arg(long, requires = "json")]
    pub compact: bool,

    /// Include the event log alongside the session metadata.
    /// In human-readable mode an `EVENTS` section is appended;
    /// in `--json` mode the document becomes
    /// `{"session": <record>, "events": [...]}` instead of the bare record.
    #[arg(long)]
    pub events: bool,

    /// When `--events` is set, only show the last N event log entries
    /// (default: all entries). Has no effect without `--events`.
    #[arg(long, value_name = "N", requires = "events")]
    pub logs_tail: Option<usize>,

    /// Include file changes
    #[arg(long)]
    pub changes: bool,

    /// Extract a single field from the JSON output instead of emitting
    /// the whole record — same `jq -r`-lite semantics as
    /// `nono profile show --field`. Accepts a top-level key
    /// (`status`) or a JSON Pointer (`/events/0/timestamp` when
    /// `--events` is also set). Requires `--json`.
    #[arg(long, value_name = "PATH", requires = "json")]
    pub field: Option<String>,

    /// Suppress all stdout and signal "does this session exist?"
    /// via exit code: `0` if the session loaded successfully,
    /// non-zero (the existing missing-session error path) if not.
    /// Useful for CI guards: `if nono inspect <id> --quiet; then …`.
    /// Conflicts with output-emitting flags (`--json` / `--compact`
    /// / `--field` / `--events`).
    #[arg(long, conflicts_with_all = &["json", "compact", "field", "events"])]
    pub quiet: bool,

    /// Emit the raw on-disk session JSON without going through
    /// nono's parse + reserialize step. Useful for diagnosing
    /// schema-evolution issues — preserves any unknown fields
    /// that the strict deserializer would reject. Conflicts with
    /// the structured output flags (`--json` / `--compact` /
    /// `--field` / `--events` / `--quiet`).
    #[arg(long, conflicts_with_all = &["json", "compact", "field", "events", "quiet"])]
    pub raw: bool,

    /// Refresh the inspect output every DURATION (e.g. `2s`,
    /// `5s`, `1m`) — top-like polling for a single session.
    /// Useful for tracking a still-running session in real time
    /// without re-running the command. Pairs with `--events` to
    /// also refresh the event log. Exit with Ctrl-C. Conflicts
    /// with the single-shot structured-output modes (`--json` /
    /// `--compact` / `--field` / `--quiet` / `--raw`).
    #[arg(
        long,
        value_name = "DURATION",
        conflicts_with_all = &["json", "compact", "field", "quiet", "raw"],
    )]
    pub watch: Option<String>,

    /// Cap `--watch` at N frames before exiting. Symmetric to
    /// `nono ps --max-iterations`: useful for CI smoke tests of
    /// watch mode (don't hang forever) and for capturing fixed-
    /// size samples without manual Ctrl-C. Requires `--watch`;
    /// has no effect on a single-shot inspect.
    #[arg(long, value_name = "N", requires = "watch")]
    pub max_iterations: Option<u64>,
}

#[derive(Parser, Debug)]
pub struct PruneArgs {
    /// Show what would be removed without deleting
    #[arg(long)]
    pub dry_run: bool,

    /// List the sessions that would be removed and ask for `y/N`
    /// confirmation before deleting any of them. Conflicts with
    /// `--dry-run` (preview-only) since both modes opt out of immediate
    /// deletion. Refuses to run when stdin is not a TTY — there's no one
    /// to answer the prompt, so silently treating that as "no" would be
    /// surprising.
    #[arg(long, conflicts_with = "dry_run")]
    pub interactive: bool,

    /// Remove sessions older than N days
    #[arg(long, value_name = "DAYS")]
    pub older_than: Option<u64>,

    /// Remove sessions older than the given duration. Accepts the same
    /// shorthand as `nono ps --since` (e.g. `1h`, `7d`, `2w`). Conflicts
    /// with `--older-than` (the legacy days-only form). Use `--age` for
    /// finer-grained windows like `48h` or `12h`.
    #[arg(long, value_name = "DURATION", conflicts_with = "older_than")]
    pub age: Option<String>,

    /// Keep only the N most recent sessions
    #[arg(long, value_name = "N")]
    pub keep: Option<usize>,

    /// Emit a machine-readable JSON summary instead of the
    /// human-readable progress lines. The document is
    /// `{"action": "would-remove" | "removed", "count": N,
    /// "sessions": [{"session_id", "started"}, ...]}`. Useful for
    /// scripting cleanup workflows. Conflicts with `--interactive`
    /// (no place to prompt in JSON mode).
    #[arg(long, conflicts_with = "interactive")]
    pub json: bool,

    /// Emit compact JSON (no whitespace / indentation). Has no
    /// effect without `--json`.
    #[arg(long, requires = "json")]
    pub compact: bool,

    /// Extract a single field from the JSON output instead of
    /// emitting the whole document — same `jq -r`-lite semantics
    /// as the other `--field` surfaces. Top-level keys for the
    /// summary view (`action`, `count`); JSON Pointer paths into
    /// the sessions array (e.g. `/sessions/0/session_id`) for
    /// individual entries. Common shell-friendly use:
    /// `count=$(nono prune --dry-run --json --field count)`.
    /// Requires `--json`.
    #[arg(long, value_name = "PATH", requires = "json")]
    pub field: Option<String>,

    /// Suppress all stdout / stderr and signal "did anything get
    /// pruned?" via exit code: 0 = at least one session was
    /// matched (and removed, unless `--dry-run`), 1 = nothing
    /// matched. Useful for CI gates that conditionally clean up:
    /// `if nono prune --age 7d --dry-run --quiet; then nono prune
    /// --age 7d; fi`. Conflicts with output-emitting flags
    /// (`--json` / `--compact` / `--field`) and with
    /// `--interactive` (the prompt would defeat the suppress-
    /// stdout intent).
    #[arg(long, conflicts_with_all = &["json", "compact", "field", "interactive"])]
    pub quiet: bool,
}

// ---------------------------------------------------------------------------
// Trust command args
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub command: TrustCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum TrustCommands {
    /// Create a trust-policy.json in the current directory
    Init(TrustInitArgs),
    /// Sign a file, producing a .bundle alongside it
    Sign(TrustSignArgs),
    /// Sign a trust policy file, producing a .bundle alongside it
    SignPolicy(TrustSignPolicyArgs),
    /// Verify a file's bundle against the trust policy
    Verify(TrustVerifyArgs),
    /// List files and their verification status
    List(TrustListArgs),
    /// Generate a new ECDSA P-256 signing key pair
    Keygen(TrustKeygenArgs),
    /// Export the public key for a signing key (base64 DER)
    ExportKey(TrustExportKeyArgs),
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustSignArgs {
    /// Instruction file(s) to sign
    #[arg(required_unless_present = "all")]
    pub files: Vec<PathBuf>,

    /// Sign all files matching trust policy patterns in CWD
    #[arg(long)]
    pub all: bool,

    /// Key ID to use from the system keystore (default: "default")
    #[arg(long, value_name = "KEY_ID", conflicts_with_all = ["keyless", "keyref"])]
    pub key: Option<String>,

    /// Key reference URI (keystore://name or file:///path/to/key.pem)
    #[arg(long, value_name = "URI", conflicts_with_all = ["key", "keyless"])]
    pub keyref: Option<String>,

    /// Use Sigstore keyless signing (Fulcio + Rekor via ambient OIDC)
    #[arg(long, conflicts_with = "keyref")]
    pub keyless: bool,

    /// Produce a single .nono-trust.bundle containing all subjects instead of per-file bundles
    #[arg(long)]
    pub multi_subject: bool,

    /// Trust policy file (default: auto-discover)
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustSignPolicyArgs {
    /// Trust policy file to sign (default: trust-policy.json in CWD)
    #[arg(conflicts_with = "user")]
    pub file: Option<PathBuf>,

    /// Key ID to use from the system keystore (default: "default")
    #[arg(long, value_name = "KEY_ID", conflicts_with = "keyref")]
    pub key: Option<String>,

    /// Key reference URI (keystore://name or file:///path/to/key.pem)
    #[arg(long, value_name = "URI", conflicts_with = "key")]
    pub keyref: Option<String>,

    /// Sign the user-level trust policy at ~/.config/nono/trust-policy.json
    #[arg(long)]
    pub user: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustVerifyArgs {
    /// Instruction file(s) to verify
    #[arg(required_unless_present = "all")]
    pub files: Vec<PathBuf>,

    /// Verify all files matching trust policy patterns in CWD
    #[arg(long)]
    pub all: bool,

    /// Trust policy file (default: auto-discover)
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustInitArgs {
    /// Glob patterns for files to include in the trust policy (e.g., "*.md", "*.py", "SKILLS.md")
    #[arg(long, value_name = "PATTERN", num_args = 1..)]
    pub include: Vec<String>,

    /// Key ID to include as a publisher (default: "default")
    #[arg(long, value_name = "KEY_ID", conflicts_with = "keyref")]
    pub key: Option<String>,

    /// Key reference URI (keystore://name or file:///path/to/key.pem)
    #[arg(long, value_name = "URI", conflicts_with = "key")]
    pub keyref: Option<String>,

    /// Create a user-level policy at ~/.config/nono/ instead of the current directory
    #[arg(long)]
    pub user: bool,

    /// Overwrite existing trust-policy.json
    #[arg(long)]
    pub force: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustListArgs {
    /// Trust policy file (default: auto-discover)
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustKeygenArgs {
    /// Key identifier (stored in system keystore under this name)
    #[arg(
        long,
        value_name = "NAME",
        default_value = "default",
        conflicts_with = "keyref"
    )]
    pub id: String,

    /// Key reference URI (keystore://name or file:///path/to/key.pem)
    #[arg(long, value_name = "URI", conflicts_with = "id")]
    pub keyref: Option<String>,

    /// Overwrite existing key with the same ID
    #[arg(long)]
    pub force: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustExportKeyArgs {
    /// Key identifier to export (default: "default")
    #[arg(
        long,
        value_name = "NAME",
        default_value = "default",
        conflicts_with = "keyref"
    )]
    pub id: String,

    /// Key reference URI (keystore://name or file:///path/to/key.pem)
    #[arg(long, value_name = "URI", conflicts_with = "id")]
    pub keyref: Option<String>,

    /// Output as PEM instead of base64 DER
    #[arg(long)]
    pub pem: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_run_basic() {
        let cli = Cli::parse_from(["nono", "run", "--allow", ".", "echo", "hello"]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow.len(), 1);
                assert_eq!(args.command, vec!["echo", "hello"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_with_separator() {
        let cli = Cli::parse_from(["nono", "run", "--allow", ".", "--", "echo", "hello"]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow.len(), 1);
                assert_eq!(args.command, vec!["echo", "hello"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_multiple_paths() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            "./src",
            "--allow",
            "./docs",
            "--read",
            "/usr/share",
            "ls",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow.len(), 2);
                assert_eq!(args.sandbox.read.len(), 1);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_wrap_basic() {
        let cli = Cli::parse_from(["nono", "wrap", "--allow", ".", "--", "cargo", "build"]);
        match cli.command {
            Commands::Wrap(args) => {
                assert_eq!(args.command, vec!["cargo", "build"]);
                assert_eq!(args.sandbox.allow.len(), 1);
                assert!(!args.no_diagnostics);
            }
            _ => panic!("Expected Wrap command"),
        }
    }

    #[test]
    fn test_wrap_supports_direct_network_flags_only() {
        let cli = Cli::parse_from([
            "nono",
            "wrap",
            "--block-net",
            "--listen-port",
            "3000",
            "--open-port",
            "5432",
            "--allow",
            ".",
            "--",
            "cargo",
            "build",
        ]);
        match cli.command {
            Commands::Wrap(args) => {
                assert!(args.sandbox.block_net);
                assert_eq!(args.sandbox.allow_bind, vec![3000]);
                assert_eq!(args.sandbox.allow_port, vec![5432]);
            }
            _ => panic!("Expected Wrap command"),
        }
    }

    #[test]
    fn test_wrap_rejects_proxy_flags_at_parse_time() {
        let result = Cli::try_parse_from([
            "nono",
            "wrap",
            "--allow-domain",
            "api.openai.com",
            "--",
            "echo",
        ]);
        assert!(
            result.is_err(),
            "wrap should not accept proxy filtering flags"
        );
    }

    #[test]
    fn test_wrap_help_hides_proxy_flags() {
        let mut cmd = Cli::command();
        let wrap = cmd
            .find_subcommand_mut("wrap")
            .expect("wrap subcommand should exist");

        let mut buf = Vec::new();
        wrap.write_long_help(&mut buf)
            .expect("failed to write wrap help");
        let help = String::from_utf8(buf).expect("help is not utf-8");

        assert!(help.contains("--block-net"));
        assert!(help.contains("--listen-port"));
        assert!(help.contains("--open-port"));
        assert!(!help.contains("--allow-domain"));
        assert!(!help.contains("--credential"));
        assert!(!help.contains("--network-profile"));
        assert!(!help.contains("--upstream-proxy"));
        assert!(!help.contains("--upstream-bypass"));
        assert!(!help.contains("--proxy-port"));
        assert!(!help.contains("--allow-net"));
    }

    #[test]
    fn inspect_compact_requires_json_flag() {
        // `--compact` only makes sense for the JSON output path —
        // there's no "compact" form for the human-readable text. clap
        // should reject the flag without `--json` so the dependency is
        // surfaced at parse time.
        let bare = Cli::try_parse_from(["nono", "inspect", "abc", "--compact"]);
        assert!(bare.is_err(), "--compact without --json must fail to parse");

        let with_json =
            Cli::try_parse_from(["nono", "inspect", "abc", "--json", "--compact"]).expect("parse");
        if let Commands::Inspect(args) = with_json.command {
            assert!(args.json);
            assert!(args.compact);
        } else {
            panic!("expected Inspect");
        }
    }

    #[test]
    fn inspect_logs_tail_requires_events_flag() {
        // `--logs-tail N` is meaningful only alongside `--events`. Without
        // it, clap should reject the invocation so users discover the
        // dependency at parse time, not silently ignore the limit.
        let bare = Cli::try_parse_from(["nono", "inspect", "abc123", "--logs-tail", "10"]);
        assert!(
            bare.is_err(),
            "--logs-tail without --events should fail at parse time"
        );

        let with_events =
            Cli::try_parse_from(["nono", "inspect", "abc123", "--events", "--logs-tail", "10"]);
        assert!(
            with_events.is_ok(),
            "--logs-tail with --events should be accepted: {:?}",
            with_events.err()
        );
        if let Ok(cli) = with_events {
            if let Commands::Inspect(args) = cli.command {
                assert!(args.events);
                assert_eq!(args.logs_tail, Some(10));
            } else {
                panic!("expected Inspect command");
            }
        }
    }

    #[test]
    fn inspect_events_alone_implies_no_tail_limit() {
        let cli =
            Cli::try_parse_from(["nono", "inspect", "abc123", "--events"]).expect("should parse");
        if let Commands::Inspect(args) = cli.command {
            assert!(args.events);
            assert_eq!(args.logs_tail, None);
        } else {
            panic!("expected Inspect command");
        }
    }

    #[test]
    fn profile_validate_compact_requires_json_flag() {
        let bare = Cli::try_parse_from(["nono", "profile", "validate", "/tmp/p.json", "--compact"]);
        assert!(bare.is_err(), "--compact without --json must be rejected");
        let with_json = Cli::try_parse_from([
            "nono",
            "profile",
            "validate",
            "/tmp/p.json",
            "--json",
            "--compact",
        ]);
        assert!(with_json.is_ok(), "--json --compact must parse");
    }

    #[test]
    fn profile_list_diff_groups_compact_require_json() {
        // Closure: each profile subcommand that already had `--json`
        // now also accepts `--compact` under the same `requires`
        // constraint. Negative tests use the `--compact` flag without
        // `--json`; clap should reject all three.
        for invocation in [
            vec!["nono", "profile", "list", "--compact"],
            vec!["nono", "profile", "diff", "a", "b", "--compact"],
            vec!["nono", "profile", "groups", "--compact"],
        ] {
            let result = Cli::try_parse_from(&invocation);
            assert!(
                result.is_err(),
                "{:?}: --compact without --json must be rejected",
                invocation
            );
        }

        // Positive: each accepts `--json --compact` together.
        for invocation in [
            vec!["nono", "profile", "list", "--json", "--compact"],
            vec!["nono", "profile", "diff", "a", "b", "--json", "--compact"],
            vec!["nono", "profile", "groups", "--json", "--compact"],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_ok(),
                "{:?}: --json --compact must parse",
                invocation
            );
        }
    }

    #[test]
    fn profile_show_compact_requires_json_flag() {
        // Same ergonomics as iter 32-34: compact has no meaning for the
        // human-readable text output (which is colored / multi-section
        // by design), so `--compact` without `--json` is rejected at
        // parse time.
        let bare = Cli::try_parse_from(["nono", "profile", "show", "default", "--compact"]);
        assert!(bare.is_err(), "--compact without --json must fail to parse");

        let with_json =
            Cli::try_parse_from(["nono", "profile", "show", "default", "--json", "--compact"])
                .expect("parse");
        if let Commands::Profile(args) = with_json.command {
            if let crate::cli::ProfileCommands::Show(show) = args.command {
                assert!(show.json);
                assert!(show.compact);
            } else {
                panic!("expected Profile::Show");
            }
        } else {
            panic!("expected Profile");
        }
    }

    #[test]
    fn why_watch_parses_and_conflicts_with_single_shot_modes() {
        // --watch refreshes the verdict on a fixed cadence;
        // structured-output / quiet flags expect a single-shot
        // render so combining them must be rejected. Same
        // conflict shape as the four other --watch surfaces.
        let bare = Cli::try_parse_from(["nono", "why", "--path", "/tmp", "--watch", "2s"])
            .expect("--watch alone parses");
        if let Commands::Why(args) = bare.command {
            assert_eq!(args.watch.as_deref(), Some("2s"));
            assert!(args.max_iterations.is_none());
        } else {
            panic!("expected Why");
        }

        let capped = Cli::try_parse_from([
            "nono",
            "why",
            "--path",
            "/tmp",
            "--watch",
            "1s",
            "--max-iterations",
            "3",
        ])
        .expect("--watch + --max-iterations parses");
        if let Commands::Why(args) = capped.command {
            assert_eq!(args.watch.as_deref(), Some("1s"));
            assert_eq!(args.max_iterations, Some(3));
        } else {
            panic!("expected Why");
        }

        // --max-iterations is meaningless without --watch; clap's
        // `requires` keeps the surface honest.
        assert!(
            Cli::try_parse_from(["nono", "why", "--path", "/tmp", "--max-iterations", "3"])
                .is_err(),
            "--max-iterations without --watch must fail to parse"
        );

        for invocation in [
            vec!["nono", "why", "--path", "/tmp", "--watch", "2s", "--json"],
            vec!["nono", "why", "--path", "/tmp", "--watch", "2s", "--quiet"],
            vec![
                "nono",
                "why",
                "--path",
                "/tmp",
                "--watch",
                "2s",
                "--json",
                "--compact",
            ],
            vec![
                "nono", "why", "--path", "/tmp", "--watch", "2s", "--json", "--field", "reason",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{invocation:?}: --watch + structured/quiet flag must be rejected"
            );
        }
    }

    #[test]
    fn why_quiet_parses_and_conflicts_with_output_modes() {
        // --quiet is exit-code-only; combining with output-emitting
        // flags would be contradictory.
        let bare = Cli::try_parse_from(["nono", "why", "--path", "/tmp", "--quiet"])
            .expect("--quiet alone parses");
        if let Commands::Why(args) = bare.command {
            assert!(args.quiet);
        } else {
            panic!("expected Why");
        }

        for invocation in [
            vec!["nono", "why", "--path", "/tmp", "--quiet", "--json"],
            vec![
                "nono",
                "why",
                "--path",
                "/tmp",
                "--quiet",
                "--json",
                "--compact",
            ],
            vec![
                "nono", "why", "--path", "/tmp", "--quiet", "--json", "--field", "reason",
            ],
            vec!["nono", "why", "--quiet", "--print-policy"],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --quiet + output flag must be rejected",
                invocation
            );
        }
    }

    #[test]
    fn why_field_requires_json_and_parses_path_forms() {
        // Same shell-friendly extraction as inspect / profile show.
        // The human-readable why output has no document to navigate,
        // so `--field` without `--json` must fail at parse time.
        let bare = Cli::try_parse_from(["nono", "why", "--path", "/tmp", "--field", "reason"]);
        assert!(bare.is_err(), "--field without --json must fail to parse");

        let with_json = Cli::try_parse_from([
            "nono",
            "why",
            "--path",
            "/tmp",
            "--json",
            "--field",
            "/result/reason",
        ])
        .expect("pointer path parses");
        if let Commands::Why(args) = with_json.command {
            assert_eq!(args.field.as_deref(), Some("/result/reason"));
        } else {
            panic!("expected Why");
        }
    }

    #[test]
    fn inspect_watch_parses_and_conflicts_with_structured_output_modes() {
        let bare = Cli::try_parse_from(["nono", "inspect", "abc123", "--watch", "5s"])
            .expect("--watch parses");
        if let Commands::Inspect(args) = bare.command {
            assert_eq!(args.watch.as_deref(), Some("5s"));
            assert!(args.max_iterations.is_none());
        } else {
            panic!("expected Inspect");
        }

        let with_cap = Cli::try_parse_from([
            "nono",
            "inspect",
            "abc123",
            "--watch",
            "1s",
            "--max-iterations",
            "3",
        ])
        .expect("--watch + --max-iterations parses");
        if let Commands::Inspect(args) = with_cap.command {
            assert_eq!(args.max_iterations, Some(3));
        } else {
            panic!("expected Inspect");
        }

        // --max-iterations without --watch is meaningless (single-
        // shot inspect doesn't loop) — clap rejects.
        let bare_max = Cli::try_parse_from(["nono", "inspect", "abc123", "--max-iterations", "5"]);
        assert!(bare_max.is_err(), "--max-iterations requires --watch");

        for invocation in [
            vec!["nono", "inspect", "abc123", "--watch", "1s", "--json"],
            vec![
                "nono",
                "inspect",
                "abc123",
                "--watch",
                "1s",
                "--json",
                "--compact",
            ],
            vec![
                "nono", "inspect", "abc123", "--watch", "1s", "--json", "--field", "status",
            ],
            vec!["nono", "inspect", "abc123", "--watch", "1s", "--quiet"],
            vec!["nono", "inspect", "abc123", "--watch", "1s", "--raw"],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --watch + structured-output flag must be rejected",
                invocation
            );
        }
    }

    #[test]
    fn inspect_raw_parses_and_conflicts_with_structured_output_modes() {
        let bare = Cli::try_parse_from(["nono", "inspect", "abc123", "--raw"])
            .expect("--raw alone parses");
        if let Commands::Inspect(args) = bare.command {
            assert!(args.raw);
        } else {
            panic!("expected Inspect");
        }

        for invocation in [
            vec!["nono", "inspect", "abc123", "--raw", "--json"],
            vec!["nono", "inspect", "abc123", "--raw", "--json", "--compact"],
            vec![
                "nono", "inspect", "abc123", "--raw", "--json", "--field", "status",
            ],
            vec!["nono", "inspect", "abc123", "--raw", "--events"],
            vec!["nono", "inspect", "abc123", "--raw", "--quiet"],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --raw + structured-output flag must be rejected",
                invocation
            );
        }
    }

    #[test]
    fn inspect_quiet_parses_and_conflicts_with_output_modes() {
        let bare = Cli::try_parse_from(["nono", "inspect", "abc123", "--quiet"])
            .expect("--quiet alone parses");
        if let Commands::Inspect(args) = bare.command {
            assert!(args.quiet);
        } else {
            panic!("expected Inspect");
        }

        for invocation in [
            vec!["nono", "inspect", "abc123", "--quiet", "--json"],
            vec![
                "nono",
                "inspect",
                "abc123",
                "--quiet",
                "--json",
                "--compact",
            ],
            vec![
                "nono", "inspect", "abc123", "--quiet", "--json", "--field", "status",
            ],
            vec!["nono", "inspect", "abc123", "--quiet", "--events"],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --quiet + output flag must be rejected",
                invocation
            );
        }
    }

    #[test]
    fn inspect_field_requires_json_and_parses_path_forms() {
        // Symmetric with profile show/diff `--field`: --field needs
        // --json since the human-readable inspect view has no JSON
        // document to navigate.
        let bare = Cli::try_parse_from(["nono", "inspect", "abc123", "--field", "status"]);
        assert!(bare.is_err(), "--field without --json must fail to parse");

        let with_json = Cli::try_parse_from([
            "nono",
            "inspect",
            "abc123",
            "--json",
            "--field",
            "/session/name",
        ])
        .expect("pointer path parses");
        if let Commands::Inspect(args) = with_json.command {
            assert_eq!(args.field.as_deref(), Some("/session/name"));
        } else {
            panic!("expected Inspect");
        }
    }

    #[test]
    fn profile_validate_quiet_parses_and_conflicts_with_output_modes() {
        let bare = Cli::try_parse_from(["nono", "profile", "validate", "/tmp/foo.json", "--quiet"])
            .expect("--quiet alone parses");
        if let Commands::Profile(args) = bare.command {
            if let crate::cli::ProfileCommands::Validate(v) = args.command {
                assert!(v.quiet);
            } else {
                panic!("expected Profile::Validate");
            }
        } else {
            panic!("expected Profile");
        }

        for invocation in [
            vec![
                "nono",
                "profile",
                "validate",
                "/tmp/foo.json",
                "--quiet",
                "--json",
            ],
            vec![
                "nono",
                "profile",
                "validate",
                "/tmp/foo.json",
                "--quiet",
                "--json",
                "--compact",
            ],
            vec![
                "nono",
                "profile",
                "validate",
                "/tmp/foo.json",
                "--quiet",
                "--json",
                "--field",
                "valid",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --quiet + output flag must be rejected",
                invocation
            );
        }
    }

    #[test]
    fn profile_validate_field_requires_json_and_parses_path_forms() {
        let bare = Cli::try_parse_from([
            "nono",
            "profile",
            "validate",
            "/tmp/foo.json",
            "--field",
            "valid",
        ]);
        assert!(bare.is_err(), "--field without --json must fail to parse");

        let with_json = Cli::try_parse_from([
            "nono",
            "profile",
            "validate",
            "/tmp/foo.json",
            "--json",
            "--field",
            "valid",
        ])
        .expect("parses");
        if let Commands::Profile(args) = with_json.command {
            if let crate::cli::ProfileCommands::Validate(v) = args.command {
                assert_eq!(v.field.as_deref(), Some("valid"));
            } else {
                panic!("expected Profile::Validate");
            }
        } else {
            panic!("expected Profile");
        }
    }

    #[test]
    fn profile_list_names_only_parses_and_conflicts_with_output_modes() {
        let bare = Cli::try_parse_from(["nono", "profile", "list", "--names-only"])
            .expect("--names-only alone parses");
        if let Commands::Profile(args) = bare.command {
            if let crate::cli::ProfileCommands::List(l) = args.command {
                assert!(l.names_only);
                assert!(!l.json);
            } else {
                panic!("expected Profile::List");
            }
        } else {
            panic!("expected Profile");
        }

        for invocation in [
            vec!["nono", "profile", "list", "--names-only", "--json"],
            vec![
                "nono",
                "profile",
                "list",
                "--names-only",
                "--json",
                "--compact",
            ],
            vec![
                "nono",
                "profile",
                "list",
                "--names-only",
                "--json",
                "--field",
                "/0/name",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --names-only + output flag must be rejected",
                invocation
            );
        }
    }

    #[test]
    fn profile_list_field_requires_json_and_parses_path_forms() {
        let bare = Cli::try_parse_from(["nono", "profile", "list", "--field", "name"]);
        assert!(bare.is_err(), "--field without --json must fail to parse");

        let with_json =
            Cli::try_parse_from(["nono", "profile", "list", "--json", "--field", "/0/name"])
                .expect("pointer path parses");
        if let Commands::Profile(args) = with_json.command {
            if let crate::cli::ProfileCommands::List(l) = args.command {
                assert_eq!(l.field.as_deref(), Some("/0/name"));
            } else {
                panic!("expected Profile::List");
            }
        } else {
            panic!("expected Profile");
        }
    }

    #[test]
    fn profile_groups_names_only_parses_and_conflicts_with_output_modes() {
        let bare =
            Cli::try_parse_from(["nono", "profile", "groups", "--names-only"]).expect("parses");
        if let Commands::Profile(args) = bare.command {
            if let crate::cli::ProfileCommands::Groups(g) = args.command {
                assert!(g.names_only);
                assert!(g.name.is_none());
            } else {
                panic!("expected Profile::Groups");
            }
        } else {
            panic!("expected Profile");
        }

        for invocation in [
            vec!["nono", "profile", "groups", "--names-only", "--json"],
            vec![
                "nono",
                "profile",
                "groups",
                "--names-only",
                "--json",
                "--compact",
            ],
            vec![
                "nono",
                "profile",
                "groups",
                "--names-only",
                "--json",
                "--field",
                "/0/name",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --names-only + output flag must be rejected",
                invocation
            );
        }

        // --names-only + group name positional parses (clap-level
        // — runtime rejects in cmd_groups since detail mode
        // semantics don't fit). Just verify the parse succeeds
        // here so we don't accidentally tighten too much.
        let with_name = Cli::try_parse_from([
            "nono",
            "profile",
            "groups",
            "deny_credentials",
            "--names-only",
        ])
        .expect("clap-level parse succeeds; runtime rejects");
        if let Commands::Profile(args) = with_name.command {
            if let crate::cli::ProfileCommands::Groups(g) = args.command {
                assert!(g.names_only);
                assert_eq!(g.name.as_deref(), Some("deny_credentials"));
            } else {
                panic!("expected Profile::Groups");
            }
        } else {
            panic!("expected Profile");
        }
    }

    #[test]
    fn profile_groups_field_requires_json_and_parses_path_forms() {
        let bare = Cli::try_parse_from(["nono", "profile", "groups", "--field", "name"]);
        assert!(bare.is_err(), "--field without --json must fail to parse");

        let with_json =
            Cli::try_parse_from(["nono", "profile", "groups", "--json", "--field", "/0/name"])
                .expect("pointer path parses");
        if let Commands::Profile(args) = with_json.command {
            if let crate::cli::ProfileCommands::Groups(g) = args.command {
                assert_eq!(g.field.as_deref(), Some("/0/name"));
            } else {
                panic!("expected Profile::Groups");
            }
        } else {
            panic!("expected Profile");
        }
    }

    #[test]
    fn profile_diff_watch_parses_and_conflicts_with_structured_output_modes() {
        let bare = Cli::try_parse_from(["nono", "profile", "diff", "a", "b", "--watch", "5s"])
            .expect("--watch parses");
        if let Commands::Profile(args) = bare.command {
            if let crate::cli::ProfileCommands::Diff(d) = args.command {
                assert_eq!(d.watch.as_deref(), Some("5s"));
                assert!(d.max_iterations.is_none());
            } else {
                panic!("expected Profile::Diff");
            }
        } else {
            panic!("expected Profile");
        }

        let with_cap = Cli::try_parse_from([
            "nono",
            "profile",
            "diff",
            "a",
            "b",
            "--watch",
            "1s",
            "--max-iterations",
            "3",
        ])
        .expect("watch + max-iterations parses");
        if let Commands::Profile(args) = with_cap.command {
            if let crate::cli::ProfileCommands::Diff(d) = args.command {
                assert_eq!(d.max_iterations, Some(3));
            } else {
                panic!("expected Profile::Diff");
            }
        } else {
            panic!("expected Profile");
        }

        // --max-iterations alone fails.
        let bare_max =
            Cli::try_parse_from(["nono", "profile", "diff", "a", "b", "--max-iterations", "5"]);
        assert!(bare_max.is_err(), "--max-iterations requires --watch");

        for invocation in [
            vec![
                "nono", "profile", "diff", "a", "b", "--watch", "1s", "--json",
            ],
            vec![
                "nono",
                "profile",
                "diff",
                "a",
                "b",
                "--watch",
                "1s",
                "--json",
                "--compact",
            ],
            vec![
                "nono", "profile", "diff", "a", "b", "--watch", "1s", "--json", "--field", "groups",
            ],
            vec![
                "nono", "profile", "diff", "a", "b", "--watch", "1s", "--quiet",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --watch + structured-output flag must be rejected",
                invocation
            );
        }
    }

    #[test]
    fn profile_diff_quiet_parses_and_conflicts_with_output_modes() {
        let bare =
            Cli::try_parse_from(["nono", "profile", "diff", "a", "b", "--quiet"]).expect("parses");
        if let Commands::Profile(args) = bare.command {
            if let crate::cli::ProfileCommands::Diff(d) = args.command {
                assert!(d.quiet);
            } else {
                panic!("expected Profile::Diff");
            }
        } else {
            panic!("expected Profile");
        }

        for invocation in [
            vec!["nono", "profile", "diff", "a", "b", "--quiet", "--json"],
            vec![
                "nono",
                "profile",
                "diff",
                "a",
                "b",
                "--quiet",
                "--json",
                "--compact",
            ],
            vec![
                "nono", "profile", "diff", "a", "b", "--quiet", "--json", "--field", "groups",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --quiet + output flag must be rejected",
                invocation
            );
        }
    }

    #[test]
    fn profile_diff_field_requires_json_and_parses_path_forms() {
        // Symmetric guard with `show --field`: clap rejects the
        // human-readable form because there's no JSON document to
        // navigate.
        let bare = Cli::try_parse_from([
            "nono",
            "profile",
            "diff",
            "default",
            "claude-code",
            "--field",
            "groups",
        ]);
        assert!(bare.is_err(), "--field without --json must fail to parse");

        let with_json = Cli::try_parse_from([
            "nono",
            "profile",
            "diff",
            "default",
            "claude-code",
            "--json",
            "--field",
            "/groups/added",
        ])
        .expect("pointer path parses");
        if let Commands::Profile(args) = with_json.command {
            if let crate::cli::ProfileCommands::Diff(diff) = args.command {
                assert_eq!(diff.field.as_deref(), Some("/groups/added"));
            } else {
                panic!("expected Profile::Diff");
            }
        } else {
            panic!("expected Profile");
        }
    }

    #[test]
    fn profile_show_watch_parses_and_conflicts_with_structured_output_modes() {
        let bare = Cli::try_parse_from(["nono", "profile", "show", "default", "--watch", "5s"])
            .expect("--watch parses");
        if let Commands::Profile(args) = bare.command {
            if let crate::cli::ProfileCommands::Show(show) = args.command {
                assert_eq!(show.watch.as_deref(), Some("5s"));
                assert!(show.max_iterations.is_none());
            } else {
                panic!("expected Profile::Show");
            }
        } else {
            panic!("expected Profile");
        }

        let with_cap = Cli::try_parse_from([
            "nono",
            "profile",
            "show",
            "default",
            "--watch",
            "1s",
            "--max-iterations",
            "3",
        ])
        .expect("watch + max-iterations parses");
        if let Commands::Profile(args) = with_cap.command {
            if let crate::cli::ProfileCommands::Show(show) = args.command {
                assert_eq!(show.max_iterations, Some(3));
            } else {
                panic!("expected Profile::Show");
            }
        } else {
            panic!("expected Profile");
        }

        // --max-iterations without --watch must fail.
        let bare_max = Cli::try_parse_from([
            "nono",
            "profile",
            "show",
            "default",
            "--max-iterations",
            "5",
        ]);
        assert!(bare_max.is_err(), "--max-iterations requires --watch");

        for invocation in [
            vec![
                "nono", "profile", "show", "default", "--watch", "1s", "--json",
            ],
            vec![
                "nono",
                "profile",
                "show",
                "default",
                "--watch",
                "1s",
                "--json",
                "--compact",
            ],
            vec![
                "nono", "profile", "show", "default", "--watch", "1s", "--json", "--field", "name",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --watch + structured-output flag must be rejected",
                invocation
            );
        }
    }

    #[test]
    fn profile_show_field_requires_json_and_parses_path_forms() {
        // `--field` without `--json` is meaningless (the human-readable
        // form has no JSON document to navigate), so clap should reject
        // it. Same pattern as `--compact requires json`.
        let bare = Cli::try_parse_from(["nono", "profile", "show", "default", "--field", "name"]);
        assert!(bare.is_err(), "--field without --json must fail to parse");

        // Top-level key form: `--field name`.
        let with_key = Cli::try_parse_from([
            "nono", "profile", "show", "default", "--json", "--field", "name",
        ])
        .expect("top-level key parses");
        if let Commands::Profile(args) = with_key.command {
            if let crate::cli::ProfileCommands::Show(show) = args.command {
                assert_eq!(show.field.as_deref(), Some("name"));
            } else {
                panic!("expected Profile::Show");
            }
        } else {
            panic!("expected Profile");
        }

        // Pointer-path form: `--field /security/groups/0`. clap doesn't
        // need to validate the path syntax — that's the helper's job.
        let with_ptr = Cli::try_parse_from([
            "nono",
            "profile",
            "show",
            "default",
            "--json",
            "--field",
            "/security/groups/0",
        ])
        .expect("pointer path parses");
        if let Commands::Profile(args) = with_ptr.command {
            if let crate::cli::ProfileCommands::Show(show) = args.command {
                assert_eq!(show.field.as_deref(), Some("/security/groups/0"));
            } else {
                panic!("expected Profile::Show");
            }
        } else {
            panic!("expected Profile");
        }
    }

    #[test]
    fn why_print_policy_conflicts_with_query_flags() {
        // --print-policy is a different mode (dump caps, no query).
        // Combining with any query flag would be ambiguous; clap should
        // reject all such combinations at parse time.
        for invocation in [
            vec!["nono", "why", "--print-policy", "--path", "/tmp"],
            vec!["nono", "why", "--print-policy", "--host", "example.com"],
            vec!["nono", "why", "--print-policy", "--net", "example.com:443"],
            vec!["nono", "why", "--print-policy", "--tcp", "443"],
            vec!["nono", "why", "--print-policy", "--tcp-bind", "8080"],
            vec!["nono", "why", "--print-policy", "--command", "rm"],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --print-policy + query flag must be rejected",
                invocation
            );
        }

        // Standalone parses fine — emits the policy snapshot.
        let solo = Cli::try_parse_from(["nono", "why", "--print-policy"]).expect("parse");
        if let Commands::Why(args) = solo.command {
            assert!(args.print_policy);
        } else {
            panic!("expected Why");
        }
    }

    #[test]
    fn why_tcp_bind_parses_and_conflicts_with_tcp_and_other_query_selectors() {
        // Standalone parse populates the right field.
        let parsed =
            Cli::try_parse_from(["nono", "why", "--tcp-bind", "8080"]).expect("standalone parse");
        if let Commands::Why(args) = parsed.command {
            assert_eq!(args.tcp_bind, Some(8080));
            assert!(args.tcp.is_none());
        } else {
            panic!("expected Why");
        }

        // Mutually exclusive with --tcp (the broader query) and with the
        // path/host/net/command selectors. Pairing them would make the
        // verdict ambiguous (which question are you actually asking?).
        for invocation in [
            vec!["nono", "why", "--tcp", "443", "--tcp-bind", "8080"],
            vec!["nono", "why", "--tcp-bind", "8080", "--path", "/tmp"],
            vec!["nono", "why", "--tcp-bind", "8080", "--host", "example.com"],
            vec![
                "nono",
                "why",
                "--tcp-bind",
                "8080",
                "--net",
                "example.com:443",
            ],
            vec!["nono", "why", "--tcp-bind", "8080", "--command", "rm"],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --tcp-bind + other query flag must be rejected",
                invocation
            );
        }
    }

    #[test]
    fn why_compact_requires_json_flag() {
        // Same ergonomics as `nono inspect --compact` and
        // `nono ps --compact`: pure-text output has no compact form,
        // so `--compact` without `--json` should fail at parse time.
        let bare = Cli::try_parse_from(["nono", "why", "--path", "/tmp", "--compact"]);
        assert!(bare.is_err(), "--compact without --json must fail to parse");

        let with_json =
            Cli::try_parse_from(["nono", "why", "--path", "/tmp", "--json", "--compact"])
                .expect("parse");
        if let Commands::Why(args) = with_json.command {
            assert!(args.json);
            assert!(args.compact);
        } else {
            panic!("expected Why");
        }
    }

    #[test]
    fn ps_compact_requires_json_flag() {
        // Mirror of inspect's `--compact` ergonomics: no `--json`,
        // no `--compact` — the human table doesn't have a "compact"
        // form (that's what `--short` is). Letting `--compact` parse
        // without `--json` would silently ignore it.
        let bare = Cli::try_parse_from(["nono", "ps", "--compact"]);
        assert!(bare.is_err(), "--compact without --json must fail to parse");

        let with_json = Cli::try_parse_from(["nono", "ps", "--json", "--compact"]).expect("parse");
        if let Commands::Ps(args) = with_json.command {
            assert!(args.json);
            assert!(args.compact);
        } else {
            panic!("expected Ps");
        }
    }

    #[test]
    fn ps_watch_is_mutually_exclusive_with_batch_outputs() {
        // --watch is interactive (top-like polling). Combining it with
        // --json or --output would mean rendering a non-interactive
        // payload over and over, which is pointless and confusing.
        let alone = Cli::try_parse_from(["nono", "ps", "--watch", "5s"]).expect("--watch alone");
        if let Commands::Ps(args) = alone.command {
            assert_eq!(args.watch.as_deref(), Some("5s"));
        } else {
            panic!("expected Ps");
        }
        let with_json = Cli::try_parse_from(["nono", "ps", "--watch", "5s", "--json"]);
        assert!(with_json.is_err(), "--watch + --json must conflict");
        let with_output = Cli::try_parse_from(["nono", "ps", "--watch", "5s", "--output", "csv"]);
        assert!(
            with_output.is_err(),
            "--watch + --output must conflict — interactive mode vs batch render"
        );
    }

    #[test]
    fn profile_guide_section_and_list_are_mutually_exclusive() {
        // --section narrows; --list-sections gives an index. Both
        // selecting the same render is a contradiction, so clap
        // rejects.
        let bare = Cli::try_parse_from(["nono", "profile", "guide"]).expect("bare parses");
        if let Commands::Profile(args) = bare.command {
            if let crate::cli::ProfileCommands::Guide(g) = args.command {
                assert!(g.section.is_none() && !g.list_sections);
            } else {
                panic!("expected Profile::Guide");
            }
        } else {
            panic!("expected Profile");
        }

        let with_section =
            Cli::try_parse_from(["nono", "profile", "guide", "--section", "validation"])
                .expect("--section parses");
        if let Commands::Profile(args) = with_section.command {
            if let crate::cli::ProfileCommands::Guide(g) = args.command {
                assert_eq!(g.section.as_deref(), Some("validation"));
            } else {
                panic!("expected Profile::Guide");
            }
        } else {
            panic!("expected Profile");
        }

        let conflict = Cli::try_parse_from([
            "nono",
            "profile",
            "guide",
            "--section",
            "validation",
            "--list-sections",
        ]);
        assert!(
            conflict.is_err(),
            "--section + --list-sections must conflict"
        );
    }

    #[test]
    fn profile_guide_search_parses_and_conflicts_with_other_modes() {
        // --search is grep over bodies; pairing with --section or
        // --list-sections would mean two display modes asking for
        // different output, so clap rejects.
        let bare = Cli::try_parse_from(["nono", "profile", "guide", "--search", "tcp"])
            .expect("--search parses");
        if let Commands::Profile(args) = bare.command {
            if let crate::cli::ProfileCommands::Guide(g) = args.command {
                assert_eq!(g.search.as_deref(), Some("tcp"));
                assert!(g.section.is_none() && !g.list_sections);
            } else {
                panic!("expected Profile::Guide");
            }
        } else {
            panic!("expected Profile");
        }

        for invocation in [
            vec![
                "nono",
                "profile",
                "guide",
                "--search",
                "tcp",
                "--section",
                "validation",
            ],
            vec![
                "nono",
                "profile",
                "guide",
                "--search",
                "tcp",
                "--list-sections",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{invocation:?}: --search + display-mode flag must be rejected"
            );
        }
    }

    #[test]
    fn profile_groups_search_parses_and_conflicts_with_output_modes() {
        // --search filters the group list and emits a human-only
        // render with `[matched in: …]` annotations. Combining it
        // with structured-output flags would be contradictory so
        // clap rejects.
        let bare = Cli::try_parse_from(["nono", "profile", "groups", "--search", "etc"])
            .expect("--search parses");
        if let Commands::Profile(args) = bare.command {
            if let crate::cli::ProfileCommands::Groups(g) = args.command {
                assert_eq!(g.search.as_deref(), Some("etc"));
                assert!(!g.names_only);
                assert!(g.name.is_none());
            } else {
                panic!("expected Profile::Groups");
            }
        } else {
            panic!("expected Profile");
        }

        // --search must compose with --names-only — that's the
        // shell-loop ergonomic ("filter then names").
        let combo = Cli::try_parse_from([
            "nono",
            "profile",
            "groups",
            "--search",
            "etc",
            "--names-only",
        ])
        .expect("--search + --names-only must compose");
        if let Commands::Profile(args) = combo.command {
            if let crate::cli::ProfileCommands::Groups(g) = args.command {
                assert_eq!(g.search.as_deref(), Some("etc"));
                assert!(g.names_only);
            } else {
                panic!("expected Profile::Groups");
            }
        } else {
            panic!("expected Profile");
        }

        for invocation in [
            vec!["nono", "profile", "groups", "--search", "etc", "--json"],
            vec![
                "nono",
                "profile",
                "groups",
                "--search",
                "etc",
                "--json",
                "--compact",
            ],
            vec![
                "nono", "profile", "groups", "--search", "etc", "--json", "--field", "/0/name",
            ],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{invocation:?}: --search + structured-output flag must be rejected"
            );
        }
    }

    #[test]
    fn profile_schema_field_parses_and_conflicts_with_output() {
        // --field parses by itself.
        let with_field = Cli::try_parse_from([
            "nono",
            "profile",
            "schema",
            "--field",
            "/properties/security/type",
        ])
        .expect("--field parses");
        if let Commands::Profile(args) = with_field.command {
            if let crate::cli::ProfileCommands::Schema(s) = args.command {
                assert_eq!(s.field.as_deref(), Some("/properties/security/type"));
            } else {
                panic!("expected Profile::Schema");
            }
        } else {
            panic!("expected Profile");
        }

        // --compact requires --field.
        let bare_compact = Cli::try_parse_from(["nono", "profile", "schema", "--compact"]);
        assert!(bare_compact.is_err(), "--compact requires --field");

        // --field + --output mutually exclusive — same rationale as
        // dry-run-schema (file vs sub-value rendering modes).
        let with_both = Cli::try_parse_from([
            "nono",
            "profile",
            "schema",
            "--field",
            "title",
            "--output",
            "/tmp/foo.json",
        ]);
        assert!(with_both.is_err(), "--field + --output must conflict");
    }

    #[test]
    fn dry_run_schema_parses_with_and_without_output() {
        let bare = Cli::try_parse_from(["nono", "dry-run-schema"]).expect("bare parse");
        if let Commands::DryRunSchema(args) = bare.command {
            assert!(args.output.is_none(), "default writes to stdout");
            assert!(args.field.is_none());
            assert!(!args.compact);
        } else {
            panic!("expected DryRunSchema");
        }

        let with_output = Cli::try_parse_from(["nono", "dry-run-schema", "-o", "/tmp/schema.json"])
            .expect("--output parses");
        if let Commands::DryRunSchema(args) = with_output.command {
            assert_eq!(
                args.output.as_deref().map(|p| p.to_str().unwrap_or("")),
                Some("/tmp/schema.json"),
            );
        } else {
            panic!("expected DryRunSchema");
        }

        // --field parses by itself.
        let with_field = Cli::try_parse_from([
            "nono",
            "dry-run-schema",
            "--field",
            "/properties/schema_version/const",
        ])
        .expect("--field parses");
        if let Commands::DryRunSchema(args) = with_field.command {
            assert_eq!(
                args.field.as_deref(),
                Some("/properties/schema_version/const")
            );
        } else {
            panic!("expected DryRunSchema");
        }

        // --compact requires --field (no point pretty-vs-compact
        // when we're just emitting the static schema literal).
        let bare_compact = Cli::try_parse_from(["nono", "dry-run-schema", "--compact"]);
        assert!(bare_compact.is_err(), "--compact requires --field");

        // --field + --output are mutually exclusive: the latter
        // writes the full doc to a file, the former extracts a
        // sub-value to stdout. Combining them is ambiguous.
        let with_both = Cli::try_parse_from([
            "nono",
            "dry-run-schema",
            "--field",
            "title",
            "--output",
            "/tmp/foo.json",
        ]);
        assert!(with_both.is_err(), "--field + --output must conflict");
    }

    #[test]
    fn ps_ids_only_parses_and_conflicts_with_output_modes() {
        let bare = Cli::try_parse_from(["nono", "ps", "--ids-only"]).expect("parses");
        if let Commands::Ps(args) = bare.command {
            assert!(args.ids_only);
        } else {
            panic!("expected Ps");
        }

        for invocation in [
            vec!["nono", "ps", "--ids-only", "--json"],
            vec!["nono", "ps", "--ids-only", "--json", "--compact"],
            vec!["nono", "ps", "--ids-only", "--output", "csv"],
            vec!["nono", "ps", "--ids-only", "--json", "--field", "/0/name"],
            vec!["nono", "ps", "--ids-only", "--watch", "1s"],
            vec!["nono", "ps", "--ids-only", "--quiet"],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --ids-only + output flag must be rejected",
                invocation
            );
        }
    }

    #[test]
    fn ps_quiet_parses_and_conflicts_with_output_modes() {
        // Standalone parse: bare ps + --quiet → just sets the
        // flag, no output flags interfere.
        let bare = Cli::try_parse_from(["nono", "ps", "--quiet"]).expect("--quiet alone parses");
        if let Commands::Ps(args) = bare.command {
            assert!(args.quiet);
        } else {
            panic!("expected Ps");
        }

        // All output-emitting flags + --watch are mutually
        // exclusive with --quiet (rejecting at parse time is
        // clearer than letting one mode silently win).
        for invocation in [
            vec!["nono", "ps", "--quiet", "--json"],
            vec!["nono", "ps", "--quiet", "--json", "--compact"],
            vec!["nono", "ps", "--quiet", "--output", "csv"],
            vec!["nono", "ps", "--quiet", "--json", "--field", "/0/name"],
            vec!["nono", "ps", "--quiet", "--watch", "1s"],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --quiet + output flag must be rejected",
                invocation
            );
        }
    }

    #[test]
    fn ps_max_iterations_requires_watch_and_parses_count() {
        // Without --watch the flag is meaningless (single-shot ps
        // doesn't loop), so clap rejects up front.
        let bare = Cli::try_parse_from(["nono", "ps", "--max-iterations", "5"]);
        assert!(bare.is_err(), "--max-iterations without --watch must fail");

        let with_watch =
            Cli::try_parse_from(["nono", "ps", "--watch", "1s", "--max-iterations", "3"])
                .expect("watch + max-iterations parses");
        if let Commands::Ps(args) = with_watch.command {
            assert_eq!(args.max_iterations, Some(3));
            assert_eq!(args.watch.as_deref(), Some("1s"));
        } else {
            panic!("expected Ps");
        }
    }

    #[test]
    fn ps_field_requires_json_and_parses_path_forms() {
        // Same shell-friendly extraction as profile / inspect / why
        // --field. Without --json there's no JSON document to
        // navigate, so clap rejects.
        let bare = Cli::try_parse_from(["nono", "ps", "--field", "/0/name"]);
        assert!(bare.is_err(), "--field without --json must fail to parse");

        let with_json = Cli::try_parse_from(["nono", "ps", "--json", "--field", "/0/session_id"])
            .expect("pointer path parses");
        if let Commands::Ps(args) = with_json.command {
            assert_eq!(args.field.as_deref(), Some("/0/session_id"));
        } else {
            panic!("expected Ps");
        }
    }

    #[test]
    fn ps_columns_parses_comma_list_and_conflicts_with_short() {
        // Empty default — clap leaves the Vec untouched when the
        // flag isn't passed. The runtime treats empty as "all".
        let bare = Cli::try_parse_from(["nono", "ps"]).expect("bare ps parses");
        if let Commands::Ps(args) = bare.command {
            assert!(args.columns.is_empty());
        } else {
            panic!("expected Ps");
        }

        // Comma-delimited list parses into the right enum variants
        // in the user-supplied order. Order matters — iter 56's
        // contract is that --columns drives both the column SET
        // and the column ORDER.
        let parsed = Cli::try_parse_from(["nono", "ps", "--columns", "command,session,status"])
            .expect("comma list parses");
        if let Commands::Ps(args) = parsed.command {
            assert_eq!(
                args.columns,
                vec![PsColumn::Command, PsColumn::Session, PsColumn::Status]
            );
        } else {
            panic!("expected Ps");
        }

        // Invalid value — clap rejects at parse, no silent fallback.
        assert!(Cli::try_parse_from(["nono", "ps", "--columns", "session,bogus"]).is_err());

        // Conflict with --short. Both control which columns get
        // rendered; combining them would force one to win silently,
        // so clap rejects up front.
        let conflict = Cli::try_parse_from(["nono", "ps", "--columns", "session", "--short"]);
        assert!(conflict.is_err(), "--columns + --short must conflict");
    }

    #[test]
    fn ps_no_truncate_parses_and_defaults_to_false() {
        let bare = Cli::try_parse_from(["nono", "ps"]).expect("bare ps parses");
        if let Commands::Ps(args) = bare.command {
            assert!(!args.no_truncate, "default must be off (truncated)");
        } else {
            panic!("expected Ps");
        }

        let opted_in =
            Cli::try_parse_from(["nono", "ps", "--no-truncate"]).expect("flag parses standalone");
        if let Commands::Ps(args) = opted_in.command {
            assert!(args.no_truncate);
        } else {
            panic!("expected Ps");
        }
    }

    #[test]
    fn ps_header_format_parses_each_value_and_defaults_to_fancy() {
        // Default: no flag means Fancy, matching the prior behavior of
        // emitting the column header (now plus a unicode divider).
        let bare = Cli::try_parse_from(["nono", "ps"]).expect("bare ps parses");
        if let Commands::Ps(args) = bare.command {
            assert_eq!(args.header_format, PsHeaderFormat::Fancy);
        } else {
            panic!("expected Ps");
        }

        for (input, expected) in [
            ("fancy", PsHeaderFormat::Fancy),
            ("ascii", PsHeaderFormat::Ascii),
            ("none", PsHeaderFormat::None),
        ] {
            let parsed = Cli::try_parse_from(["nono", "ps", "--header-format", input])
                .unwrap_or_else(|e| panic!("parse {input:?}: {e}"));
            if let Commands::Ps(args) = parsed.command {
                assert_eq!(args.header_format, expected, "input was {input:?}");
            } else {
                panic!("expected Ps");
            }
        }

        // Invalid value: clap's value_enum rejects at parse time, no
        // chance for a typo to silently fall back to a default.
        assert!(Cli::try_parse_from(["nono", "ps", "--header-format", "bogus"]).is_err());
    }

    #[test]
    fn prune_field_requires_json_and_parses_path_forms() {
        // Same shell-friendly extraction as the other --field
        // surfaces. --field needs --json since the human-readable
        // progress lines have no JSON document to navigate.
        let bare = Cli::try_parse_from(["nono", "prune", "--field", "count"]);
        assert!(bare.is_err(), "--field without --json must fail to parse");

        let with_json = Cli::try_parse_from([
            "nono",
            "prune",
            "--json",
            "--field",
            "/sessions/0/session_id",
        ])
        .expect("pointer path parses");
        if let Commands::Prune(args) = with_json.command {
            assert_eq!(args.field.as_deref(), Some("/sessions/0/session_id"));
        } else {
            panic!("expected Prune");
        }
    }

    #[test]
    fn prune_quiet_parses_and_conflicts_with_output_modes() {
        // Standalone parse: bare prune + --quiet → just sets the
        // flag.
        let bare = Cli::try_parse_from(["nono", "prune", "--quiet"]).expect("--quiet alone parses");
        if let Commands::Prune(args) = bare.command {
            assert!(args.quiet);
        } else {
            panic!("expected Prune");
        }

        for invocation in [
            vec!["nono", "prune", "--quiet", "--json"],
            vec!["nono", "prune", "--quiet", "--json", "--compact"],
            vec!["nono", "prune", "--quiet", "--json", "--field", "count"],
            vec!["nono", "prune", "--quiet", "--interactive"],
        ] {
            assert!(
                Cli::try_parse_from(&invocation).is_err(),
                "{:?}: --quiet + output flag must be rejected",
                invocation
            );
        }
    }

    #[test]
    fn prune_json_parses_and_conflicts_with_interactive() {
        // --json is the machine-readable counterpart to the human
        // progress lines. --interactive prompts on stderr, which
        // would mix output streams in scripted JSON consumers, so
        // the two are mutually exclusive at the clap layer.
        let bare = Cli::try_parse_from(["nono", "prune", "--json"]).expect("--json alone");
        if let Commands::Prune(args) = bare.command {
            assert!(args.json);
            assert!(!args.compact, "--compact stays off without explicit opt-in");
        } else {
            panic!("expected Prune");
        }

        let with_compact = Cli::try_parse_from(["nono", "prune", "--json", "--compact"])
            .expect("--json + --compact");
        if let Commands::Prune(args) = with_compact.command {
            assert!(args.json && args.compact);
        } else {
            panic!("expected Prune");
        }

        // --compact alone (no --json) is meaningless; rejected.
        assert!(
            Cli::try_parse_from(["nono", "prune", "--compact"]).is_err(),
            "--compact requires --json"
        );

        // --json + --interactive: clap rejects (no place to prompt).
        assert!(
            Cli::try_parse_from(["nono", "prune", "--json", "--interactive"]).is_err(),
            "--json + --interactive must conflict"
        );
    }

    #[test]
    fn prune_age_and_older_than_are_mutually_exclusive() {
        // Both flags express the same intent (minimum session age) so
        // clap should reject combining them — otherwise we'd have to
        // pick a precedence rule and surprise the user.
        let bare =
            Cli::try_parse_from(["nono", "prune", "--age", "7d"]).expect("--age alone is fine");
        if let Commands::Prune(args) = bare.command {
            assert_eq!(args.age.as_deref(), Some("7d"));
            assert!(args.older_than.is_none());
        } else {
            panic!("expected Prune");
        }

        let combined = Cli::try_parse_from(["nono", "prune", "--age", "7d", "--older-than", "30"]);
        assert!(
            combined.is_err(),
            "--age + --older-than must be rejected at parse time"
        );
    }

    #[test]
    fn no_color_is_global_and_defaults_to_false() {
        let cli = Cli::try_parse_from(["nono", "ps"]).expect("parse");
        assert!(!cli.no_color, "default is colors enabled (or auto-detect)");

        // Flag should work both before AND after the subcommand because
        // it is `global = true`. Verify the `after subcommand` form which
        // is the more common shell muscle memory.
        let cli = Cli::try_parse_from(["nono", "ps", "--no-color"]).expect("parse");
        assert!(cli.no_color, "--no-color must propagate from subcommand");

        // And before the subcommand (clap's "global=true" lets it travel
        // either direction).
        let cli = Cli::try_parse_from(["nono", "--no-color", "ps"]).expect("parse");
        assert!(cli.no_color);
    }

    #[test]
    fn why_accepts_command_overrides_without_a_profile() {
        // Adding allow/block command flags on `nono why` lets the user
        // probe command policy ad-hoc without authoring a profile first.
        let cli = Cli::try_parse_from([
            "nono",
            "why",
            "--command",
            "rm",
            "--block-command",
            "rm",
            "--allow-command",
            "echo",
        ])
        .expect("should parse");
        if let Commands::Why(args) = cli.command {
            assert_eq!(args.command_name.as_deref(), Some("rm"));
            assert_eq!(args.block_command, vec!["rm".to_string()]);
            assert_eq!(args.allow_command, vec!["echo".to_string()]);
        } else {
            panic!("expected Why command");
        }
    }

    #[test]
    fn test_shell_basic() {
        let cli = Cli::parse_from(["nono", "shell", "--allow", "."]);
        match cli.command {
            Commands::Shell(args) => {
                assert_eq!(args.sandbox.allow.len(), 1);
                assert!(args.shell.is_none());
            }
            _ => panic!("Expected Shell command"),
        }
    }

    #[test]
    fn test_rollback_list() {
        let cli = Cli::parse_from(["nono", "rollback", "list"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::List(list_args) => {
                    assert!(list_args.recent.is_none());
                    assert!(list_args.path.is_none());
                    assert!(!list_args.json);
                }
                _ => panic!("Expected List subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_list_recent_json() {
        let cli = Cli::parse_from(["nono", "rollback", "list", "--recent", "5", "--json"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::List(list_args) => {
                    assert_eq!(list_args.recent, Some(5));
                    assert!(list_args.json);
                }
                _ => panic!("Expected List subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_show() {
        let cli = Cli::parse_from(["nono", "rollback", "show", "20260214-143022-12345"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Show(show_args) => {
                    assert_eq!(show_args.session_id, "20260214-143022-12345");
                    assert!(!show_args.json);
                }
                _ => panic!("Expected Show subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_restore_defaults() {
        let cli = Cli::parse_from(["nono", "rollback", "restore", "20260214-143022-12345"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Restore(restore_args) => {
                    assert_eq!(restore_args.session_id, "20260214-143022-12345");
                    assert_eq!(restore_args.snapshot, None); // Default to last snapshot
                    assert!(!restore_args.dry_run);
                }
                _ => panic!("Expected Restore subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_restore_with_options() {
        let cli = Cli::parse_from([
            "nono",
            "rollback",
            "restore",
            "20260214-143022-12345",
            "--snapshot",
            "3",
            "--dry-run",
        ]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Restore(restore_args) => {
                    assert_eq!(restore_args.snapshot, Some(3));
                    assert!(restore_args.dry_run);
                }
                _ => panic!("Expected Restore subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_audit_list() {
        let cli = Cli::parse_from(["nono", "audit", "list", "--today"]);
        match cli.command {
            Commands::Audit(args) => match args.command {
                AuditCommands::List(list_args) => {
                    assert!(list_args.today);
                    assert!(!list_args.json);
                }
                _ => panic!("Expected List subcommand"),
            },
            _ => panic!("Expected Audit command"),
        }
    }

    #[test]
    fn test_audit_show() {
        let cli = Cli::parse_from(["nono", "audit", "show", "20260214-143022-12345", "--json"]);
        match cli.command {
            Commands::Audit(args) => match args.command {
                AuditCommands::Show(show_args) => {
                    assert_eq!(show_args.session_id, "20260214-143022-12345");
                    assert!(show_args.json);
                }
                _ => panic!("Expected Show subcommand"),
            },
            _ => panic!("Expected Audit command"),
        }
    }

    #[test]
    fn test_audit_verify() {
        let cli = Cli::parse_from(["nono", "audit", "verify", "20260214-143022-12345", "--json"]);
        match cli.command {
            Commands::Audit(args) => match args.command {
                AuditCommands::Verify(verify_args) => {
                    assert_eq!(verify_args.session_id, "20260214-143022-12345");
                    assert!(verify_args.json);
                }
                _ => panic!("Expected Verify subcommand"),
            },
            _ => panic!("Expected Audit command"),
        }
    }

    #[test]
    fn test_audit_cleanup() {
        let cli = Cli::parse_from(["nono", "audit", "cleanup", "--keep", "5", "--dry-run"]);
        match cli.command {
            Commands::Audit(args) => match args.command {
                AuditCommands::Cleanup(cleanup_args) => {
                    assert_eq!(cleanup_args.keep, Some(5));
                    assert!(cleanup_args.dry_run);
                    assert!(!cleanup_args.all);
                }
                _ => panic!("Expected Cleanup subcommand"),
            },
            _ => panic!("Expected Audit command"),
        }
    }

    #[test]
    fn test_session_cleanup() {
        let cli = Cli::parse_from(["nono", "session", "cleanup", "--older-than", "7"]);
        match cli.command {
            Commands::Session(args) => match args.command {
                SessionCommands::Cleanup(cleanup_args) => {
                    assert_eq!(cleanup_args.older_than, Some(7));
                    assert!(!cleanup_args.dry_run);
                }
            },
            _ => panic!("Expected Session command"),
        }
    }

    #[test]
    fn test_prune_still_parses_as_hidden_compat_command() {
        let cli = Cli::parse_from(["nono", "prune", "--dry-run"]);
        match cli.command {
            Commands::Prune(args) => assert!(args.dry_run),
            _ => panic!("Expected hidden Prune command"),
        }
    }

    #[test]
    fn test_rollback_verify() {
        let cli = Cli::parse_from(["nono", "rollback", "verify", "20260214-143022-12345"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Verify(verify_args) => {
                    assert_eq!(verify_args.session_id, "20260214-143022-12345");
                }
                _ => panic!("Expected Verify subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_cleanup_defaults() {
        let cli = Cli::parse_from(["nono", "rollback", "cleanup"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Cleanup(cleanup_args) => {
                    assert!(cleanup_args.keep.is_none());
                    assert!(cleanup_args.older_than.is_none());
                    assert!(!cleanup_args.dry_run);
                    assert!(!cleanup_args.all);
                }
                _ => panic!("Expected Cleanup subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_cleanup_with_options() {
        let cli = Cli::parse_from([
            "nono",
            "rollback",
            "cleanup",
            "--keep",
            "5",
            "--older-than",
            "30",
            "--dry-run",
        ]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Cleanup(cleanup_args) => {
                    assert_eq!(cleanup_args.keep, Some(5));
                    assert_eq!(cleanup_args.older_than, Some(30));
                    assert!(cleanup_args.dry_run);
                    assert!(!cleanup_args.all);
                }
                _ => panic!("Expected Cleanup subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_trust_init_defaults() {
        let cli = Cli::parse_from(["nono", "trust", "init"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Init(init_args) => {
                    assert!(!init_args.force);
                    assert!(init_args.key.is_none());
                    assert!(init_args.include.is_empty());
                }
                _ => panic!("Expected Init subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_init_with_includes() {
        let cli = Cli::parse_from([
            "nono",
            "trust",
            "init",
            "--include",
            "*.md",
            "*.py",
            "--force",
        ]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Init(init_args) => {
                    assert!(init_args.force);
                    assert_eq!(init_args.include, vec!["*.md", "*.py"]);
                }
                _ => panic!("Expected Init subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_sign() {
        let cli = Cli::parse_from(["nono", "trust", "sign", "SKILLS.md"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Sign(sign_args) => {
                    assert_eq!(sign_args.files, vec![PathBuf::from("SKILLS.md")]);
                    assert!(!sign_args.all);
                    assert!(sign_args.key.is_none());
                }
                _ => panic!("Expected Sign subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_sign_with_key() {
        let cli = Cli::parse_from(["nono", "trust", "sign", "SKILLS.md", "--key", "my-key"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Sign(sign_args) => {
                    assert_eq!(sign_args.key, Some("my-key".to_string()));
                }
                _ => panic!("Expected Sign subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_sign_all() {
        let cli = Cli::parse_from(["nono", "trust", "sign", "--all"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Sign(sign_args) => {
                    assert!(sign_args.all);
                    assert!(sign_args.files.is_empty());
                    assert!(!sign_args.multi_subject);
                }
                _ => panic!("Expected Sign subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_sign_multi_subject() {
        let cli = Cli::parse_from(["nono", "trust", "sign", "--all", "--multi-subject"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Sign(sign_args) => {
                    assert!(sign_args.all);
                    assert!(sign_args.multi_subject);
                }
                _ => panic!("Expected Sign subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_verify() {
        let cli = Cli::parse_from(["nono", "trust", "verify", "SKILLS.md"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Verify(verify_args) => {
                    assert_eq!(verify_args.files, vec![PathBuf::from("SKILLS.md")]);
                    assert!(!verify_args.all);
                }
                _ => panic!("Expected Verify subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_list() {
        let cli = Cli::parse_from(["nono", "trust", "list"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::List(list_args) => {
                    assert!(!list_args.json);
                }
                _ => panic!("Expected List subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_keygen() {
        let cli = Cli::parse_from(["nono", "trust", "keygen"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Keygen(keygen_args) => {
                    assert_eq!(keygen_args.id, "default");
                    assert!(!keygen_args.force);
                }
                _ => panic!("Expected Keygen subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_keygen_with_id() {
        let cli = Cli::parse_from(["nono", "trust", "keygen", "--id", "my-key", "--force"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Keygen(keygen_args) => {
                    assert_eq!(keygen_args.id, "my-key");
                    assert!(keygen_args.force);
                }
                _ => panic!("Expected Keygen subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_export_key_defaults() {
        let cli = Cli::parse_from(["nono", "trust", "export-key"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::ExportKey(export_args) => {
                    assert_eq!(export_args.id, "default");
                    assert!(!export_args.pem);
                }
                _ => panic!("Expected ExportKey subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_export_key_with_options() {
        let cli = Cli::parse_from(["nono", "trust", "export-key", "--id", "my-key", "--pem"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::ExportKey(export_args) => {
                    assert_eq!(export_args.id, "my-key");
                    assert!(export_args.pem);
                }
                _ => panic!("Expected ExportKey subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_rollback_flags_with_no_rollback() {
        // --no-rollback alongside rollback customization flags should parse
        // (the warning is emitted at runtime, not parse time)
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--no-rollback",
            "--rollback-exclude",
            "target",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.no_rollback);
                assert_eq!(args.rollback_exclude, vec!["target"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_no_audit_integrity_flag_parses() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--no-audit-integrity",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.no_audit_integrity);
                assert!(!args.audit_integrity);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_rollback_all_conflicts_with_include() {
        // --rollback-all conflicts with --rollback-include (clap enforced)
        let result = Cli::try_parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--rollback-all",
            "--rollback-include",
            "target",
            "echo",
            "hello",
        ]);
        assert!(
            result.is_err(),
            "--rollback-all and --rollback-include should conflict"
        );
    }

    #[test]
    fn test_allow_net_parsing() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-net",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.sandbox.allow_net);
                assert!(!args.sandbox.block_net);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_allow_net_conflicts_with_block_net() {
        let result = Cli::try_parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-net",
            "--block-net",
            "echo",
        ]);
        assert!(
            result.is_err(),
            "--allow-net and --block-net should conflict"
        );
    }

    #[test]
    fn test_allow_net_conflicts_with_network_profile() {
        let result = Cli::try_parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-net",
            "--network-profile",
            "developer",
            "echo",
        ]);
        assert!(
            result.is_err(),
            "--allow-net and --network-profile should conflict"
        );
    }

    #[test]
    fn test_allow_net_conflicts_with_allow_domain() {
        let result = Cli::try_parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-net",
            "--allow-domain",
            "api.openai.com",
            "echo",
        ]);
        assert!(
            result.is_err(),
            "--allow-net and --allow-domain should conflict"
        );
    }

    #[test]
    fn test_network_flag_aliases_still_parse() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-domain",
            "api.openai.com",
            "--credential",
            "openai",
            "--listen-port",
            "3000",
            "--open-port",
            "5432",
            "--upstream-proxy",
            "squid.corp:3128",
            "--upstream-bypass",
            "internal.corp",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow_proxy, vec!["api.openai.com"]);
                assert_eq!(args.sandbox.proxy_credential, vec!["openai"]);
                assert_eq!(args.sandbox.allow_bind, vec![3000]);
                assert_eq!(args.sandbox.allow_port, vec![5432]);
                assert_eq!(
                    args.sandbox.external_proxy.as_deref(),
                    Some("squid.corp:3128")
                );
                assert_eq!(args.sandbox.external_proxy_bypass, vec!["internal.corp"]);
            }
            _ => panic!("Expected Run command"),
        }

        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--net-allow",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.sandbox.allow_net);
            }
            _ => panic!("Expected Run command"),
        }

        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--proxy-allow",
            "api.openai.com",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow_proxy, vec!["api.openai.com"]);
            }
            _ => panic!("Expected Run command"),
        }

        let cli = Cli::parse_from(["nono", "why", "--host", "example.com", "--net-block"]);
        match cli.command {
            Commands::Why(args) => {
                assert!(args.block_net);
            }
            _ => panic!("Expected Why command"),
        }
    }

    #[test]
    fn test_allow_endpoint_flag_parses() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--credential",
            "github",
            "--allow-endpoint",
            "github:GET:/repos/*/issues",
            "--allow-endpoint",
            "github:POST:/repos/*/issues/*/comments",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow_endpoint.len(), 2);
                assert_eq!(args.sandbox.allow_endpoint[0], "github:GET:/repos/*/issues");
                assert_eq!(
                    args.sandbox.allow_endpoint[1],
                    "github:POST:/repos/*/issues/*/comments"
                );
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_override_deny_single() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--override-deny",
            "/tmp/test",
            "--allow",
            "/tmp/test",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.override_deny.len(), 1);
                assert_eq!(args.sandbox.override_deny[0], PathBuf::from("/tmp/test"));
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_override_deny_multiple() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--override-deny",
            "/tmp/a",
            "--override-deny",
            "/tmp/b",
            "--allow",
            ".",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.override_deny.len(), 2);
                assert_eq!(args.sandbox.override_deny[0], PathBuf::from("/tmp/a"));
                assert_eq!(args.sandbox.override_deny[1], PathBuf::from("/tmp/b"));
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_env_credential_map_repeatable_parses_pairs() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--env-credential-map",
            "op://vault/item/field",
            "OPENAI_API_KEY",
            "--env-credential-map",
            "apple-password://github.com/user=name",
            "GITHUB_PASSWORD",
            "echo",
            "ok",
        ]);

        match cli.command {
            Commands::Run(args) => {
                assert_eq!(
                    args.sandbox.env_credential_map,
                    vec![
                        "op://vault/item/field".to_string(),
                        "OPENAI_API_KEY".to_string(),
                        "apple-password://github.com/user=name".to_string(),
                        "GITHUB_PASSWORD".to_string()
                    ]
                );
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_allow_port_parsing() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--open-port",
            "3000",
            "--open-port",
            "5000",
            "--allow",
            ".",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow_port, vec![3000, 5000]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_profile_init_basic() {
        let cli = Cli::parse_from(["nono", "profile", "init", "my-agent"]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Init(init) => {
                    assert_eq!(init.name, "my-agent");
                    assert!(init.extends.is_none());
                    assert!(init.groups.is_empty());
                    assert!(init.description.is_none());
                    assert!(!init.full);
                    assert!(init.output.is_none());
                    assert!(!init.force);
                }
                _ => panic!("Expected Init subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_init_all_flags() {
        let cli = Cli::parse_from([
            "nono",
            "profile",
            "init",
            "my-agent",
            "--extends",
            "default",
            "--groups",
            "deny_credentials,node_runtime",
            "--description",
            "My agent profile",
            "--full",
            "--output",
            "/tmp/out.json",
            "--force",
        ]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Init(init) => {
                    assert_eq!(init.name, "my-agent");
                    assert_eq!(init.extends, Some("default".to_string()));
                    assert_eq!(init.groups, vec!["deny_credentials", "node_runtime"]);
                    assert_eq!(init.description, Some("My agent profile".to_string()));
                    assert!(init.full);
                    assert_eq!(init.output, Some(std::path::PathBuf::from("/tmp/out.json")));
                    assert!(init.force);
                }
                _ => panic!("Expected Init subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_schema_default() {
        let cli = Cli::parse_from(["nono", "profile", "schema"]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Schema(schema) => {
                    assert!(schema.output.is_none());
                }
                _ => panic!("Expected Schema subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_schema_with_output() {
        let cli = Cli::parse_from(["nono", "profile", "schema", "-o", "/tmp/schema.json"]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Schema(schema) => {
                    assert_eq!(
                        schema.output,
                        Some(std::path::PathBuf::from("/tmp/schema.json"))
                    );
                }
                _ => panic!("Expected Schema subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_guide() {
        let cli = Cli::parse_from(["nono", "profile", "guide"]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Guide(_) => {}
                _ => panic!("Expected Guide subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_init_missing_name() {
        let result = Cli::try_parse_from(["nono", "profile", "init"]);
        assert!(result.is_err(), "init without name should fail");
    }

    #[test]
    fn test_profile_no_subcommand() {
        let result = Cli::try_parse_from(["nono", "profile"]);
        assert!(result.is_err(), "profile without subcommand should fail");
    }

    #[test]
    fn test_profile_list_parses() {
        let cli = Cli::try_parse_from(["nono", "profile", "list", "--json"])
            .expect("profile list --json must parse");
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::List(a) => assert!(a.json, "--json flag not set"),
                _ => panic!("expected ProfileCommands::List"),
            },
            _ => panic!("expected Commands::Profile"),
        }
    }

    #[test]
    fn test_profile_show_parses_with_format_manifest() {
        let cli =
            Cli::try_parse_from(["nono", "profile", "show", "default", "--format", "manifest"])
                .expect("profile show --format manifest must parse");
        if let Commands::Profile(args) = cli.command {
            if let ProfileCommands::Show(a) = args.command {
                assert_eq!(a.profile, "default");
                assert!(matches!(a.format, Some(ProfileShowFormat::Manifest)));
                return;
            }
        }
        panic!("expected Commands::Profile(Show(..))");
    }

    #[test]
    fn test_profile_show_parses_with_json_and_raw() {
        let cli = Cli::try_parse_from(["nono", "profile", "show", "default", "--json", "--raw"])
            .expect("profile show --json --raw must parse");
        if let Commands::Profile(args) = cli.command {
            if let ProfileCommands::Show(a) = args.command {
                assert!(a.json);
                assert!(a.raw);
                return;
            }
        }
        panic!("expected Commands::Profile(Show(..))");
    }

    #[test]
    fn test_profile_groups_parses() {
        let cli = Cli::try_parse_from(["nono", "profile", "groups", "--json", "--all-platforms"])
            .expect("profile groups --json --all-platforms must parse");
        if let Commands::Profile(args) = cli.command {
            if let ProfileCommands::Groups(a) = args.command {
                assert!(a.json);
                assert!(a.all_platforms);
                return;
            }
        }
        panic!("expected Commands::Profile(Groups(..))");
    }

    #[test]
    fn test_profile_groups_with_name() {
        let cli = Cli::try_parse_from(["nono", "profile", "groups", "deny_credentials"])
            .expect("profile groups <name> must parse");
        if let Commands::Profile(args) = cli.command {
            if let ProfileCommands::Groups(a) = args.command {
                assert_eq!(a.name.as_deref(), Some("deny_credentials"));
                return;
            }
        }
        panic!("expected Commands::Profile(Groups(..))");
    }

    #[test]
    fn test_profile_diff_parses() {
        let cli = Cli::try_parse_from(["nono", "profile", "diff", "a", "b"])
            .expect("profile diff must parse");
        if let Commands::Profile(args) = cli.command {
            if let ProfileCommands::Diff(a) = args.command {
                assert_eq!(a.profile1, "a");
                assert_eq!(a.profile2, "b");
                return;
            }
        }
        panic!("expected Commands::Profile(Diff(..))");
    }

    #[test]
    fn test_profile_validate_parses() {
        let cli = Cli::try_parse_from(["nono", "profile", "validate", "/tmp/p.json"])
            .expect("profile validate must parse");
        if let Commands::Profile(args) = cli.command {
            if let ProfileCommands::Validate(a) = args.command {
                assert_eq!(a.file.to_string_lossy(), "/tmp/p.json");
                return;
            }
        }
        panic!("expected Commands::Profile(Validate(..))");
    }

    /// All subcommand names that must appear in the root help template.
    /// If you add a new command to the `Commands` enum, add it here too.
    const ALL_SUBCOMMANDS: &[&str] = &[
        "setup",
        "run",
        "shell",
        "wrap",
        "learn",
        "why",
        "ps",
        "stop",
        "detach",
        "attach",
        "logs",
        "inspect",
        "session",
        "rollback",
        "audit",
        "trust",
        "policy",
        "profile",
        "dry-run-schema",
        "pull",
        "remove",
        "update",
        "search",
        "list",
    ];

    #[test]
    fn test_root_help_lists_all_commands() {
        // The root help template is hardcoded — verify every subcommand appears in it.
        let cmd = Cli::command();
        let mut buf = Vec::new();
        cmd.clone()
            .write_help(&mut buf)
            .expect("failed to write help");
        let help = String::from_utf8(buf).expect("help is not utf-8");

        for name in ALL_SUBCOMMANDS {
            assert!(
                help.contains(&format!("  {name}")),
                "Root --help is missing subcommand `{name}`. \
                 Update the help_template on the Cli struct.",
            );
        }

        // Also verify we haven't forgotten to add a new variant to ALL_SUBCOMMANDS.
        for sub in cmd.get_subcommands() {
            let name = sub.get_name().to_string();
            if name == "help" || sub.is_hide_set() {
                continue; // clap auto-generates help; hidden commands are internal
            }
            assert!(
                ALL_SUBCOMMANDS.contains(&name.as_str()),
                "Commands enum has variant `{name}` not listed in ALL_SUBCOMMANDS. \
                 Add it to the constant and to the root help_template.",
            );
        }
    }

    #[test]
    fn test_root_help_shows_all_flags() {
        // Every non-hidden root-level flag must appear in the rendered help.
        // Catches flags missing a help_heading (which puts them in an unnamed
        // group that our custom template doesn't render).
        let cmd = Cli::command();
        let mut buf = Vec::new();
        cmd.clone()
            .write_help(&mut buf)
            .expect("failed to write help");
        let help = String::from_utf8(buf).expect("help is not utf-8");

        for arg in cmd.get_arguments() {
            if arg.is_hide_set() {
                continue;
            }
            if let Some(long) = arg.get_long() {
                assert!(
                    help.contains(&format!("--{long}")),
                    "Root --help is missing flag `--{long}`. \
                     Add `help_heading = \"OPTIONS\"` to its #[arg] attribute.",
                );
            }
        }
    }

    #[test]
    fn test_subcommand_help_structure() {
        let root = Cli::command();

        for sub in root.get_subcommands() {
            let name = sub.get_name().to_string();
            if name == "help" || sub.is_hide_set() {
                continue;
            }

            // Render the help text
            let mut buf = Vec::new();
            sub.clone()
                .write_help(&mut buf)
                .expect("failed to write help");
            let help = String::from_utf8(buf).expect("help is not utf-8");

            // Every subcommand must have a USAGE section
            assert!(
                help.contains("USAGE"),
                "`nono {name} --help` is missing a USAGE section",
            );

            // Every subcommand must have an EXAMPLES section
            assert!(
                help.contains("EXAMPLES"),
                "`nono {name} --help` is missing an EXAMPLES section",
            );

            // USAGE line should reference the correct command name
            assert!(
                help.contains(&format!("nono {name}")),
                "`nono {name} --help` USAGE line doesn't mention `nono {name}`",
            );

            // Collect all flags this subcommand actually accepts
            let known_flags: Vec<String> = sub
                .get_arguments()
                .filter_map(|a: &clap::Arg| a.get_long().map(|l| l.to_string()))
                .collect();

            // Also collect flags from nested subcommands (for rollback/audit/trust)
            let known_sub_flags: Vec<String> = sub
                .get_subcommands()
                .flat_map(|s: &clap::Command| s.get_arguments())
                .filter_map(|a: &clap::Arg| a.get_long().map(|l| l.to_string()))
                .collect();

            // Extract the EXAMPLES section and check flags referenced there
            if let Some(examples_start) = help.find("EXAMPLES") {
                let examples = &help[examples_start..];

                // Find all --flag patterns in examples
                for token in examples.split_whitespace() {
                    if let Some(flag) = token.strip_prefix("--") {
                        let flag =
                            flag.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
                        if flag.is_empty() || flag == "help" {
                            continue;
                        }
                        let valid = known_flags.iter().any(|f| f == flag)
                            || known_sub_flags.iter().any(|f| f == flag);
                        assert!(
                            valid,
                            "`nono {name} --help` EXAMPLES references --{flag} \
                             which is not a known flag on this subcommand",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_log_file_flag() {
        let cli = Cli::parse_from([
            "nono",
            "--log-file",
            "/tmp/nono.log",
            "run",
            "--allow",
            ".",
            "echo",
            "hi",
        ]);
        assert_eq!(cli.log_file, Some(PathBuf::from("/tmp/nono.log")));
    }

    #[test]
    fn test_log_file_flag_absent() {
        let cli = Cli::parse_from(["nono", "run", "--allow", ".", "echo", "hi"]);
        assert!(cli.log_file.is_none());
    }
}
