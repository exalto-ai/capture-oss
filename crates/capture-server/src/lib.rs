//! The capture server: the provider proxy and administration API for a
//! replicated deployment on shared PostgreSQL metadata and S3 artifacts.
//!
//! The hosted public origin remains a distribution default in this package.
//! Evidence formats and Proxy-TLS protocol behavior are provided by
//! `capture-core`.

use anyhow::{Context as _, Result};
use std::path::PathBuf;

use clap::{Parser, Subcommand};

pub use capture_core::*;

pub use capture_engine::{artifact_store, config, metadata, metadata_store, organization};

pub mod admin;
mod cluster_runtime;
mod customer_api;
mod persistence;
mod postgres_metadata_store;
mod s3_artifact_store;
mod service;

#[derive(Parser, Debug)]
#[command(
    name = "capture-server",
    about = "Run an Exalto Capture server replica",
    version
)]
struct DaemonCli {
    /// Versioned server configuration file (required). It must configure
    /// [cluster], PostgreSQL metadata and S3 storage.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<DaemonCommand>,
}

#[derive(Debug, Subcommand)]
enum DaemonCommand {
    /// Apply the daemon-owned PostgreSQL metadata migrations and exit.
    Migrate,
}

/// Runs the client command line using process arguments.
pub async fn run_daemon() -> Result<()> {
    let cli = DaemonCli::parse();
    // Clap cannot require a global argument.
    let config = cli.config.context("--config is required")?;
    if let Some(DaemonCommand::Migrate) = cli.command {
        return run_daemon_migrator(config).await;
    }
    let _telemetry = telemetry::init("capture-server")?;
    service::proxy::run(service::proxy::ProxyArgs { config }).await
}

/// Applies the daemon-owned PostgreSQL metadata migrations and pins the
/// cluster vault key.
async fn run_daemon_migrator(path: PathBuf) -> Result<()> {
    use std::time::Duration;

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
    let vault = capture_core::vault::Vault::open_cluster()?;
    postgres_metadata_store::configure_cluster_compatibility(
        database_url.expose(),
        postgres.ssl_mode,
        Duration::from_secs(postgres.connect_timeout_seconds),
        &vault.cluster_identity_sha256()?,
    )
    .await
    .map_err(|_| anyhow::anyhow!("server compatibility configuration failed"))?;
    println!("Local daemon PostgreSQL metadata migrations are current");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_accepts_only_configuration() {
        assert!(DaemonCli::try_parse_from(["capture-server", "--config", "agent.toml"]).is_ok());
        assert!(
            DaemonCli::try_parse_from(["capture-server", "--config", "agent.toml", "traces"])
                .is_err()
        );
        assert!(
            DaemonCli::try_parse_from(["capture-server", "--config", "agent.toml", "migrate"])
                .is_ok()
        );
        assert!(
            DaemonCli::try_parse_from(["capture-server", "migrate", "--config", "agent.toml"])
                .is_ok()
        );
    }
}
