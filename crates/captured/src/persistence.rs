//! Composition of the daemon's configured metadata and artifact stores.

use std::sync::Arc;

use anyhow::Result;
use capture_engine::storage::Storage;

use crate::{
    artifact_router::RoutedArtifactStore,
    artifact_store::FileSystemArtifactStore,
    cluster_runtime::ClusterRuntime,
    config::{CapturedConfig, MetadataBackend},
    metadata_store::{MetadataStore, ReplicaIdentity, ServerMetadataStore},
    postgres_metadata_store::PostgresMetadataStore,
    s3_artifact_store::{S3ArtifactStore, S3ArtifactStoreCredentials},
    sqlite_metadata_store::SqliteMetadataStore,
};

/// The metadata and byte stores used by one daemon process.
#[derive(Clone)]
pub struct Persistence {
    pub metadata: Arc<dyn MetadataStore>,
    pub artifacts: Arc<RoutedArtifactStore>,
}

impl Persistence {
    /// Opens the default SQLite and filesystem adapters from the unchanged
    /// desktop configuration shape.
    pub async fn open(config: &CapturedConfig) -> Result<Self> {
        Ok(Self::open_stores(config).await?.0)
    }

    /// Opens persistence for a cluster replica. The shared server metadata
    /// store is handed to the returned runtime rather than kept beside the
    /// local-mode stores, so claimed work cannot be recorded outside cluster
    /// mode.
    pub(crate) async fn open_cluster(
        config: &CapturedConfig,
        identity: ReplicaIdentity,
    ) -> Result<(Self, ClusterRuntime)> {
        let (persistence, server_metadata) = Self::open_stores(config).await?;
        let server_metadata = server_metadata.ok_or_else(|| {
            anyhow::anyhow!("cluster mode requires metadata.backend = \"postgres\"")
        })?;
        Ok((persistence, ClusterRuntime::new(identity, server_metadata)))
    }

    async fn open_stores(
        config: &CapturedConfig,
    ) -> Result<(Self, Option<Arc<dyn ServerMetadataStore>>)> {
        let (metadata, cluster_metadata): (
            Arc<dyn MetadataStore>,
            Option<Arc<dyn ServerMetadataStore>>,
        ) = match config.metadata.backend {
            MetadataBackend::Sqlite => (
                Arc::new(
                    SqliteMetadataStore::open(
                        config.metadata.path.clone(),
                        config.metadata.full_text_search,
                    )
                    .await?,
                ),
                None,
            ),
            MetadataBackend::Postgres => {
                let postgres = &config.metadata.postgres;
                let database_url = config.postgres_runtime_url()?;
                let store = Arc::new(
                    if config.cluster.is_some() {
                        PostgresMetadataStore::connect_server(
                            database_url.expose(),
                            postgres.max_connections,
                            std::time::Duration::from_secs(postgres.connect_timeout_seconds),
                            std::time::Duration::from_secs(postgres.acquire_timeout_seconds),
                            postgres.ssl_mode,
                            config.metadata.full_text_search,
                        )
                        .await
                    } else {
                        PostgresMetadataStore::connect(
                        database_url.expose(),
                        postgres.max_connections,
                        std::time::Duration::from_secs(postgres.connect_timeout_seconds),
                        std::time::Duration::from_secs(postgres.acquire_timeout_seconds),
                        postgres.ssl_mode,
                        config.metadata.full_text_search,
                        )
                        .await
                    }
                    .map_err(|_| {
                        anyhow::anyhow!(
                            "PostgreSQL metadata database is unavailable or its daemon schema is not current; run `captured migrate --config <path>`"
                        )
                    })?,
                );
                let cluster_metadata = config.cluster.is_some().then(|| {
                    let cluster_metadata: Arc<dyn ServerMetadataStore> = store.clone();
                    cluster_metadata
                });
                (store, cluster_metadata)
            }
        };
        let filesystem = FileSystemArtifactStore::new(
            config.storage.checkpoint_dir.clone(),
            config.storage.package_dir.clone(),
        );
        let s3 = if let Some(s3) = &config.storage.s3 {
            let credentials = config.s3_credentials()?;
            Some(
                S3ArtifactStore::new(
                    s3.artifact_store_config()?,
                    S3ArtifactStoreCredentials::new(
                        credentials.access_key_id(),
                        credentials.secret_access_key(),
                        credentials.session_token().map(str::to_owned),
                    ),
                )
                .map_err(|_| anyhow::anyhow!("S3 artifact storage configuration is invalid"))?,
            )
        } else {
            None
        };
        let artifacts = RoutedArtifactStore::new(config.storage.backend, filesystem, s3)
            .map_err(|_| anyhow::anyhow!("selected artifact storage backend is not configured"))?;
        Ok((
            Self {
                metadata,
                artifacts: Arc::new(artifacts),
            },
            cluster_metadata,
        ))
    }

    /// The stores as the engine's storage handle.
    pub fn storage(&self) -> Storage {
        Storage::new(self.metadata.clone(), self.artifacts.clone())
    }
}
