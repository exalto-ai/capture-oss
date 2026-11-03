//! The server's shared PostgreSQL metadata and S3 artifact stores.

use std::{sync::Arc, time::Duration};

use anyhow::{Context as _, Result};
use capture_engine::storage::Storage;

use crate::{
    cluster_runtime::ClusterRuntime,
    config::CapturedConfig,
    metadata_store::{MetadataStore, ReplicaIdentity, ServerMetadataStore},
    organization::OrganizationId,
    postgres_metadata_store::PostgresMetadataStore,
    s3_artifact_store::{S3ArtifactStore, S3ArtifactStoreCredentials},
    service::proxy::require_server_configuration,
};

/// The organization every request is served as until requests are
/// authenticated as a specific organization.
pub(crate) fn default_organization() -> OrganizationId {
    OrganizationId::parse("default").expect("the default organization identifier is valid")
}

/// The metadata and byte stores shared by every replica.
#[derive(Clone)]
pub(crate) struct Persistence {
    /// The [`default_organization`]'s view of the shared metadata.
    pub(crate) metadata: Arc<dyn MetadataStore>,
    /// The whole managed bucket prefix. Artifacts are read and written only
    /// through [`S3ArtifactStore::for_organization`].
    pub(crate) artifacts: Arc<S3ArtifactStore>,
}

impl Persistence {
    /// Opens the shared stores for an offline maintenance command, without
    /// joining the replica set.
    pub(crate) async fn open(config: &CapturedConfig) -> Result<Self> {
        Ok(Self::open_stores(config).await?.0)
    }

    /// Opens persistence for a replica. The shared server metadata store is
    /// handed to the returned runtime, which records claimed work.
    pub(crate) async fn open_cluster(
        config: &CapturedConfig,
        identity: ReplicaIdentity,
    ) -> Result<(Self, ClusterRuntime)> {
        let (persistence, server_metadata) = Self::open_stores(config).await?;
        Ok((persistence, ClusterRuntime::new(identity, server_metadata)))
    }

    async fn open_stores(config: &CapturedConfig) -> Result<(Self, Arc<dyn ServerMetadataStore>)> {
        // `[cluster]` validation already requires PostgreSQL and S3.
        require_server_configuration(config)?;
        let postgres = &config.metadata.postgres;
        let database_url = config.postgres_runtime_url()?;
        let store = Arc::new(
            PostgresMetadataStore::connect_server(
                database_url.expose(),
                postgres.max_connections,
                Duration::from_secs(postgres.connect_timeout_seconds),
                Duration::from_secs(postgres.acquire_timeout_seconds),
                postgres.ssl_mode,
                config.metadata.full_text_search,
            )
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "PostgreSQL metadata database is unavailable or its daemon schema is not current; run `capture-server migrate --config <path>`"
                )
            })?,
        );
        let s3 = config
            .storage
            .s3
            .as_ref()
            .context("server mode requires storage.s3")?;
        let credentials = config.s3_credentials()?;
        let artifacts = S3ArtifactStore::new(
            s3.artifact_store_config()?,
            S3ArtifactStoreCredentials::new(
                credentials.access_key_id(),
                credentials.secret_access_key(),
                credentials.session_token().map(str::to_owned),
            ),
        )
        .map_err(|_| anyhow::anyhow!("S3 artifact storage configuration is invalid"))?;
        let server_metadata: Arc<dyn ServerMetadataStore> = store;
        Ok((
            Self {
                metadata: server_metadata.organization(&default_organization()),
                artifacts: Arc::new(artifacts),
            },
            server_metadata,
        ))
    }

    /// The [`default_organization`]'s stores as the engine's storage handle.
    pub(crate) fn storage(&self) -> Storage {
        Storage::new(
            self.metadata.clone(),
            Arc::new(self.artifacts.for_organization(&default_organization())),
        )
    }
}
