use std::path::PathBuf;

use capture_updater::BUILD_ID;
use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "capture",
    about = "Inspect and operate Exalto Capture from the command line.",
    version,
    long_version = format!("{} ({BUILD_ID})", env!("CARGO_PKG_VERSION")),
    arg_required_else_help = true
)]
pub(super) struct Cli {
    #[arg(long, global = true)]
    pub(super) json: bool,
    #[arg(long, global = true)]
    pub(super) config: Option<PathBuf>,
    #[arg(long, global = true, value_name = "PATH")]
    pub(super) admin_password_file: Option<PathBuf>,
    #[command(subcommand)]
    pub(super) command: CliCommand,
}

#[derive(Subcommand, Debug)]
pub(super) enum CliCommand {
    Version,
    Update(UpdateArgs),
    #[command(name = "__apply-update", hide = true)]
    ApplyUpdate(ApplyUpdateArgs),
    Skill {
        #[command(subcommand)]
        command: SkillCommand,
    },
    Status,
    /// Show or set how provider requests are captured.
    Mode(ModeArgs),
    Traces {
        #[command(subcommand)]
        command: TracesCommand,
    },
    Activity(ActivityListArgs),
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    Notaries {
        #[command(subcommand)]
        command: NotariesCommand,
    },
}

#[derive(Args, Debug)]
pub(super) struct ModeArgs {
    /// The mode to set. Omit it to show the current mode.
    pub(super) mode: Option<crate::client::CaptureMode>,
}

#[derive(Args, Debug)]
pub(super) struct UpdateArgs {
    #[arg(long)]
    pub(super) check: bool,
}

#[derive(Args, Debug)]
pub(super) struct ApplyUpdateArgs {
    #[arg(long)]
    pub(super) parent_pid: u32,
    #[arg(long)]
    pub(super) install_directory: PathBuf,
    #[arg(long)]
    pub(super) staging_directory: PathBuf,
    #[arg(long)]
    pub(super) build_id: String,
}

#[derive(Subcommand, Debug)]
pub(super) enum SkillCommand {
    Install(SkillInstallArgs),
}

#[derive(Args, Debug)]
pub(super) struct SkillInstallArgs {
    #[arg(
        long,
        value_enum,
        required_unless_present = "skills_dir",
        conflicts_with = "skills_dir"
    )]
    pub(super) target: Option<SkillTarget>,
    #[arg(long, value_name = "DIR", conflicts_with = "target")]
    pub(super) skills_dir: Option<PathBuf>,
    #[arg(long)]
    pub(super) force: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum SkillTarget {
    Codex,
    Claude,
    All,
}

#[derive(Subcommand, Debug)]
pub(super) enum TracesCommand {
    List(TraceListArgs),
    Show(IdArgs),
    #[command(name = "seal")]
    Notarize(NotarizeArgs),
    Export(TraceExportArgs),
    Verify(TraceVerifyArgs),
    Share(ShareArgs),
    StopSharing(IdArgs),
}

#[derive(Subcommand, Debug)]
pub(super) enum AccountCommand {
    Connect,
    Show,
    Disconnect,
}

#[derive(Args, Debug)]
pub(super) struct TraceVerifyArgs {
    pub(super) target: String,
    #[arg(long)]
    pub(super) trusted_notary_key: Option<String>,
}

#[derive(Subcommand, Debug)]
pub(super) enum NotariesCommand {
    List,
}

#[derive(Args, Debug)]
pub(super) struct IdArgs {
    pub(super) id: String,
}

#[derive(Args, Debug)]
pub(super) struct NotarizeArgs {
    pub(super) id: String,
    #[arg(long)]
    pub(super) wait: bool,
}

#[derive(Args, Debug)]
pub(super) struct TraceExportArgs {
    pub(super) id: String,
    #[arg(long, value_name = "PATH")]
    pub(super) output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(super) struct ShareArgs {
    pub(super) id: String,
    #[arg(long, value_enum, default_value_t = ShareVisibility::Unlisted)]
    pub(super) visibility: ShareVisibility,
    #[arg(long)]
    pub(super) force: bool,
    /// Explicitly restore public access to a previously stopped share.
    #[arg(long)]
    pub(super) reactivate: bool,
    #[arg(long, value_name = "PATH", conflicts_with = "remove_password")]
    pub(super) password_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "password_file")]
    pub(super) remove_password: bool,
    #[arg(long)]
    pub(super) expires_in_days: Option<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub(super) enum ShareVisibility {
    Unlisted,
    Listed,
}

impl ShareVisibility {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Unlisted => "unlisted",
            Self::Listed => "listed",
        }
    }
}

#[derive(Args, Debug, Default)]
pub(super) struct TraceListArgs {
    #[arg(long)]
    pub(super) query: Option<String>,
    #[arg(long)]
    pub(super) model: Option<String>,
    #[arg(long)]
    pub(super) provider: Option<String>,
    #[arg(long)]
    pub(super) state: Option<String>,
    #[arg(long)]
    pub(super) status: Option<String>,
    #[arg(long)]
    pub(super) limit: Option<usize>,
    #[arg(long)]
    pub(super) cursor: Option<String>,
    #[arg(long)]
    pub(super) all: bool,
    #[arg(long)]
    pub(super) metadata_only: bool,
}

#[derive(Args, Debug, Default)]
pub(super) struct ActivityListArgs {
    #[arg(long)]
    pub(super) cursor: Option<String>,
    #[arg(long)]
    pub(super) after: Option<String>,
    #[arg(long)]
    pub(super) severity: Option<String>,
    #[arg(long)]
    pub(super) event_type: Option<String>,
    #[arg(long)]
    pub(super) trace_id: Option<String>,
    #[arg(long)]
    pub(super) operation_id: Option<String>,
    #[arg(long)]
    pub(super) created_after_unix_ms: Option<u64>,
    #[arg(long)]
    pub(super) limit: Option<usize>,
    #[arg(long)]
    pub(super) all: bool,
}
