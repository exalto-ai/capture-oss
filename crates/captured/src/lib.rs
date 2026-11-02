//! The capture server: the provider proxy and administration API for a
//! replicated deployment on shared PostgreSQL metadata and S3 artifacts.
//! Local capture is the desktop app's.
//!
//! The hosted public origin remains a distribution default in this package.
//! Evidence formats and Proxy-TLS protocol behavior are provided by
//! `capture-core`.

use anyhow::Result;
use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub use capture_core::*;

pub use capture_engine::{
    artifact_store, config, metadata, metadata_store, sqlite_metadata, sqlite_metadata_store,
};

pub mod admin;
mod artifact_reconciliation;
mod cluster_runtime;
mod persistence;
mod postgres_metadata_store;
mod s3_artifact_store;
mod service;
pub use capture_updater as update;

#[derive(Parser, Debug)]
#[command(
    name = "captured",
    about = "Run an Exalto Capture server replica",
    version,
    long_version = format!(
        "{} ({})",
        env!("CARGO_PKG_VERSION"),
        capture_updater::BUILD_ID
    )
)]
struct DaemonCli {
    /// Versioned server configuration file. It must configure [cluster],
    /// PostgreSQL metadata and S3 storage.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<DaemonCommand>,
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    /// Apply the daemon-owned PostgreSQL metadata migrations and exit.
    Migrate,
    /// Report missing, corrupt, or unreferenced private artifacts without deleting anything.
    ReconcileArtifacts {
        /// Minimum age in days before an unreferenced object is reported.
        #[arg(long, default_value_t = 7)]
        orphan_grace_days: u64,
    },
    /// Initialize shared key material for a clustered deployment.
    Cluster {
        #[command(subcommand)]
        command: ClusterCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ClusterCommand {
    /// Create one private 32-byte vault key for all cluster replicas.
    Init {
        /// New key file. Existing files are never overwritten.
        #[arg(long)]
        vault_key: PathBuf,
    },
}

/// Runs the client command line using process arguments.
pub async fn run_daemon() -> Result<()> {
    let cli = DaemonCli::parse();
    match cli.command {
        Some(DaemonCommand::Migrate) => return run_daemon_migrator(cli.config).await,
        Some(DaemonCommand::ReconcileArtifacts { orphan_grace_days }) => {
            return run_artifact_reconciliation(cli.config, orphan_grace_days).await;
        }
        Some(DaemonCommand::Cluster {
            command: ClusterCommand::Init { vault_key },
        }) => {
            capture_core::vault::Vault::init_cluster_key(&vault_key)?;
            println!("Created shared cluster vault key: {}", vault_key.display());
            return Ok(());
        }
        None => {}
    }
    let _telemetry = telemetry::init("captured")?;
    service::proxy::run(service::proxy::ProxyArgs { config: cli.config }).await
}

/// Runs a bounded, report-only artifact reconciliation without initializing
/// the vault, providers, notary discovery, or listeners.
async fn run_artifact_reconciliation(
    config_path: Option<PathBuf>,
    orphan_grace_days: u64,
) -> Result<()> {
    const SECONDS_PER_DAY: u64 = 24 * 60 * 60;

    let orphan_grace_seconds = orphan_grace_days
        .checked_mul(SECONDS_PER_DAY)
        .ok_or_else(|| anyhow::anyhow!("artifact reconciliation grace period is too large"))?;
    let path = match config_path {
        Some(path) => path,
        None => config::default_config_path()?,
    };
    let config = config::CapturedConfig::load(&path)?;
    let persistence = persistence::Persistence::open(&config)
        .await
        .map_err(|_| anyhow::anyhow!("artifact reconciliation could not open persistence"))?;
    let report = artifact_reconciliation::reconcile_artifacts(&persistence, orphan_grace_seconds)
        .await
        .map_err(|_| anyhow::anyhow!("artifact reconciliation failed"))?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

/// Applies only the daemon-owned PostgreSQL metadata migrations.
async fn run_daemon_migrator(config_path: Option<PathBuf>) -> Result<()> {
    use std::time::Duration;

    let path = match config_path {
        Some(path) => path,
        None => config::default_config_path()?,
    };
    let config = config::CapturedConfig::load_for_metadata_migration(&path)?;
    let postgres = &config.metadata.postgres;
    let database_url = config.postgres_migration_url()?;
    println!("Applying local daemon PostgreSQL metadata migrations");
    postgres_metadata_store::migrate_database(
        database_url.expose(),
        postgres.ssl_mode,
        Duration::from_secs(postgres.connect_timeout_seconds),
        Duration::from_secs(postgres.migration_lock_timeout_seconds),
    )
    .await
    .map_err(|_| anyhow::anyhow!("local daemon PostgreSQL metadata migration failed"))?;
    if config.cluster.is_some() {
        let vault = capture_core::vault::Vault::open_cluster()?;
        let vault_identity = vault.cluster_identity_sha256()?;
        postgres_metadata_store::configure_cluster_compatibility(
            database_url.expose(),
            postgres.ssl_mode,
            Duration::from_secs(postgres.connect_timeout_seconds),
            &config.cluster_compatibility_sha256(&vault_identity)?,
        )
        .await
        .map_err(|_| anyhow::anyhow!("server compatibility configuration failed"))?;
    }
    println!("Local daemon PostgreSQL metadata migrations are current");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_accepts_only_configuration() {
        assert!(DaemonCli::try_parse_from(["captured"]).is_ok());
        assert!(DaemonCli::try_parse_from(["captured", "traces"]).is_err());
        assert!(DaemonCli::try_parse_from(["captured", "migrate", "traces"]).is_err());
        assert!(DaemonCli::try_parse_from(["captured", "migrate"]).is_ok());
        assert!(
            DaemonCli::try_parse_from(["captured", "--config", "agent.toml", "migrate"]).is_ok()
        );
        assert!(
            DaemonCli::try_parse_from(["captured", "migrate", "--config", "agent.toml"]).is_ok()
        );
        assert!(DaemonCli::try_parse_from(["captured", "reconcile-artifacts"]).is_ok());
        assert!(
            DaemonCli::try_parse_from([
                "captured",
                "cluster",
                "init",
                "--vault-key",
                "/run/secrets/cluster-vault.key",
            ])
            .is_ok()
        );
        assert!(
            DaemonCli::try_parse_from([
                "captured",
                "server",
                "init",
                "--vault-key",
                "/run/secrets/cluster-vault.key",
            ])
            .is_err()
        );
        assert!(
            DaemonCli::try_parse_from([
                "captured",
                "--config",
                "agent.toml",
                "reconcile-artifacts",
                "--orphan-grace-days",
                "1",
            ])
            .is_ok()
        );
    }

    #[test]
    fn version_flag_reports_the_exact_build_identity() {
        let error = DaemonCli::try_parse_from(["captured", "--version"]).unwrap_err();

        assert_eq!(error.kind(), clap::error::ErrorKind::DisplayVersion);
        assert!(error.to_string().contains(&format!(
            "{} ({})",
            env!("CARGO_PKG_VERSION"),
            capture_updater::BUILD_ID
        )));
    }
}
