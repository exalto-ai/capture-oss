//! SQLx PostgreSQL implementation of the local daemon metadata contract.
//!
//! Runtime construction is deliberately read-only with respect to schema.
//! Operators apply the daemon-owned migration journal through
//! [`migrate_database`] before starting a daemon that uses this adapter.
//!
//! Every organization's metadata shares one database. Isolation is enforced
//! here, not by row-level security: every query that reads or writes a Trace,
//! operation, event or capture setting names the organization explicitly, and
//! child rows (artifacts, attempts, search documents, shares) are reached only
//! through a parent row of that organization in the same statement.

use std::{sync::Arc, time::Duration};

use anyhow::{Context as _, anyhow, ensure};
use async_trait::async_trait;
use sha2::{Digest as _, Sha256};
use sqlx::{
    Connection as _, PgConnection, PgPool, Postgres, QueryBuilder, Row,
    postgres::{PgConnectOptions, PgPoolOptions, PgRow},
};

use crate::{
    NotarizationPhase, NotarizationProofProgress,
    artifact_store::{ArtifactKey, ArtifactKind, ArtifactLocator, ArtifactRecord},
    config::PostgresSslMode,
    metadata::{
        CaptureCompletion, CaptureMode, Event, EventFilters, EventSnapshot, IncompleteCapture,
        MetadataCounts, NewTrace, Operation, OperationAttempt, OperationFilters, RegistrySnapshot,
        TerminalOperationResult, TraceFilters, TraceShareRecord, TraceSummary, trace_search_parts,
    },
    metadata_store::{
        CaptureClaim, CaptureRecoveryClaim, MetadataResult, MetadataStore, MetadataStoreError,
        NotarizationClaim, ReplicaIdentity, TraceDeletionOutcome, TraceDeletionPreparation,
        validate_operation_id, validate_trace_id,
    },
    organization::OrganizationId,
    registry::Registry,
};

const JOURNAL: &str = "captured.schema_migrations";
const MIGRATION_LOCK_NAMESPACE: &str = "ecp/captured-postgres-migrations/v1";
const LATEST_SCHEMA_VERSION: i64 = 4;
const INITIAL_MIGRATION: &str = include_str!("../migrations-postgres-daemon/0001_initial.sql");
const CAPTURE_MODES_MIGRATION: &str =
    include_str!("../migrations-postgres-daemon/0002_capture_modes.sql");
const ORGANIZATIONS_MIGRATION: &str =
    include_str!("../migrations-postgres-daemon/0003_organizations.sql");
const VAULT_PIN_MIGRATION: &str = include_str!("../migrations-postgres-daemon/0004_vault_pin.sql");
const MIGRATIONS: [(i64, &str, &str); 4] = [
    (1, "initial captured metadata schema", INITIAL_MIGRATION),
    (
        2,
        "capture modes and evidence kinds",
        CAPTURE_MODES_MIGRATION,
    ),
    (3, "organizations", ORGANIZATIONS_MIGRATION),
    (4, "pin only the vault key", VAULT_PIN_MIGRATION),
];

/// A pooled PostgreSQL metadata backend whose schema has already been migrated.
///
/// This is the cluster's view: replica coordination, claims that span
/// organizations, dashboard sessions and the Registry. Everything else goes
/// through [`PostgresOrganizationStore`].
#[derive(Clone)]
pub(crate) struct PostgresMetadataStore {
    pool: PgPool,
    full_text_search: bool,
}

/// One organization's view of the shared metadata. Every read and write is
/// limited to `organization`.
#[derive(Clone)]
pub(crate) struct PostgresOrganizationStore {
    store: PostgresMetadataStore,
    organization: OrganizationId,
}

impl PostgresMetadataStore {
    /// One organization's view of this store, sharing its pool.
    pub(crate) fn organization_store(
        &self,
        organization: &OrganizationId,
    ) -> PostgresOrganizationStore {
        PostgresOrganizationStore {
            store: self.clone(),
            organization: organization.clone(),
        }
    }

    /// Opens a runtime pool and verifies, without mutating, the exact daemon
    /// schema version.
    pub(crate) async fn connect_server(
        database_url: &str,
        max_connections: u32,
        connect_timeout: Duration,
        acquire_timeout: Duration,
        ssl_mode: PostgresSslMode,
        full_text_search: bool,
    ) -> MetadataResult<Self> {
        let options = database_url
            .parse::<PgConnectOptions>()
            .map_err(|error| db(anyhow!(error).context("parsing daemon PostgreSQL URL")))?
            .ssl_mode(pg_ssl_mode(ssl_mode));
        tokio::time::timeout(connect_timeout, async move {
            let pool = PgPoolOptions::new()
                .max_connections(max_connections)
                .acquire_timeout(acquire_timeout)
                .connect_with(options)
                .await
                .map_err(|error| db(anyhow!(error).context("opening daemon PostgreSQL pool")))?;
            Self::from_pool(pool, full_text_search).await
        })
        .await
        .map_err(|_| {
            db(anyhow!(
                "opening and validating daemon PostgreSQL timed out"
            ))
        })?
    }

    /// A server store whose pool never reaches a database, for tests that
    /// must not touch one: every query fails.
    #[cfg(test)]
    pub(crate) fn unreachable() -> Self {
        let refused = std::net::TcpListener::bind("127.0.0.1:0")
            .and_then(|listener| listener.local_addr())
            .expect("reserve a local port");
        Self {
            pool: PgPoolOptions::new()
                .max_connections(1)
                .acquire_timeout(Duration::from_millis(200))
                .connect_lazy_with(
                    PgConnectOptions::new()
                        .host("127.0.0.1")
                        .port(refused.port())
                        .ssl_mode(pg_ssl_mode(PostgresSslMode::Disable)),
                ),
            full_text_search: true,
        }
    }

    /// Wraps an existing pool after verifying the daemon-owned migration journal.
    async fn from_pool(pool: PgPool, full_text_search: bool) -> MetadataResult<Self> {
        require_migrated_schema(&pool).await?;
        Ok(Self {
            pool,
            full_text_search,
        })
    }
}

/// Applies daemon PostgreSQL migrations with a dedicated schema, journal, and advisory lock.
///
/// This one-shot API expects a direct connection URL and is never called by runtime
/// construction. The lock timeout bounds coordination with another daemon migrator.
pub(crate) async fn migrate_database(
    database_url: &str,
    ssl_mode: PostgresSslMode,
    connect_timeout: Duration,
    lock_timeout: Duration,
) -> anyhow::Result<()> {
    migrate_database_through(
        database_url,
        ssl_mode,
        connect_timeout,
        lock_timeout,
        &MIGRATIONS,
    )
    .await
}

/// Applies `migrations`, a prefix of [`MIGRATIONS`]. Tests use a shorter
/// prefix to build a database at an earlier schema version.
async fn migrate_database_through(
    database_url: &str,
    ssl_mode: PostgresSslMode,
    connect_timeout: Duration,
    lock_timeout: Duration,
    migrations: &[(i64, &str, &str)],
) -> anyhow::Result<()> {
    ensure!(
        !connect_timeout.is_zero(),
        "daemon migration connect timeout must be non-zero"
    );
    ensure!(
        !lock_timeout.is_zero(),
        "daemon migration lock timeout must be non-zero"
    );
    ensure!(
        lock_timeout.as_millis() <= i64::MAX as u128,
        "daemon migration lock timeout is out of range"
    );
    let options = database_url
        .parse::<PgConnectOptions>()
        .context("daemon migration URL must be PostgreSQL")?
        .ssl_mode(pg_ssl_mode(ssl_mode));
    let mut connection =
        tokio::time::timeout(connect_timeout, PgConnection::connect_with(&options))
            .await
            .context("opening direct daemon migration connection timed out")?
            .context("opening direct daemon migration connection")?;
    let timeout_ms = lock_timeout.as_millis().to_string();
    sqlx::query("SELECT set_config('lock_timeout', $1, false)")
        .bind(format!("{timeout_ms}ms"))
        .execute(&mut connection)
        .await
        .context("setting daemon migration lock timeout")?;

    sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
        .bind(MIGRATION_LOCK_NAMESPACE)
        .execute(&mut connection)
        .await
        .context("acquiring daemon migration advisory lock")?;
    let mut transaction = connection
        .begin()
        .await
        .context("starting daemon migration transaction")?;
    sqlx::query("CREATE SCHEMA IF NOT EXISTS captured")
        .execute(&mut *transaction)
        .await
        .context("creating daemon metadata schema")?;
    sqlx::query("REVOKE ALL ON SCHEMA captured FROM PUBLIC")
        .execute(&mut *transaction)
        .await
        .context("restricting daemon metadata schema")?;
    sqlx::raw_sql(&format!(
        "CREATE TABLE IF NOT EXISTS {JOURNAL} (
            version BIGINT PRIMARY KEY,
            description TEXT NOT NULL,
            checksum TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
        );"
    ))
    .execute(&mut *transaction)
    .await
    .context("creating daemon migration journal")?;

    let rows = sqlx::query(&format!(
        "SELECT version, description, checksum FROM {JOURNAL} ORDER BY version"
    ))
    .fetch_all(&mut *transaction)
    .await
    .context("reading daemon migration journal")?;
    // A journal ahead of this binary is a newer release's, which keeps its
    // migrations compatible with this one: there is nothing to apply.
    for (index, (version, description, migration)) in migrations.iter().enumerate() {
        let checksum = hex::encode(Sha256::digest(migration.as_bytes()));
        if let Some(row) = rows.get(index) {
            ensure!(
                row.try_get::<i64, _>("version")? == *version,
                "daemon migration journal has a gap"
            );
            ensure!(
                row.try_get::<String, _>("description")? == *description
                    && row.try_get::<String, _>("checksum")? == checksum,
                "daemon migration {version} differs from the installed migration"
            );
            continue;
        }
        sqlx::raw_sql(migration)
            .execute(&mut *transaction)
            .await
            .with_context(|| format!("applying daemon PostgreSQL migration {version}"))?;
        sqlx::query(&format!(
            "INSERT INTO {JOURNAL} (version, description, checksum) VALUES ($1, $2, $3)"
        ))
        .bind(version)
        .bind(description)
        .bind(&checksum)
        .execute(&mut *transaction)
        .await
        .with_context(|| format!("recording daemon PostgreSQL migration {version}"))?;
    }
    transaction
        .commit()
        .await
        .context("committing daemon PostgreSQL migrations")?;
    let unlocked: bool = sqlx::query_scalar("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
        .bind(MIGRATION_LOCK_NAMESPACE)
        .fetch_one(&mut connection)
        .await
        .context("releasing daemon migration advisory lock")?;
    ensure!(unlocked, "daemon migration advisory lock was not held");
    Ok(())
}

/// Pins the identity of the shared vault key after migrations. A replica with
/// another key would write checkpoints no other replica can decrypt, so a
/// different key never replaces the pinned one; configuration is not pinned.
pub(crate) async fn configure_cluster_compatibility(
    database_url: &str,
    ssl_mode: PostgresSslMode,
    connect_timeout: Duration,
    compatibility_sha256: &str,
) -> anyhow::Result<()> {
    ensure!(
        compatibility_sha256.len() == 64
            && compatibility_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "server compatibility identity is invalid"
    );
    let options = database_url
        .parse::<PgConnectOptions>()
        .context("daemon migration URL must be PostgreSQL")?
        .ssl_mode(pg_ssl_mode(ssl_mode));
    let mut connection =
        tokio::time::timeout(connect_timeout, PgConnection::connect_with(&options))
            .await
            .context("opening server compatibility connection timed out")?
            .context("opening server compatibility connection")?;
    sqlx::query(
        "UPDATE captured.settings
         SET compatibility_sha256 = COALESCE(compatibility_sha256, $1),
             configured_at = clock_timestamp()
         WHERE singleton = TRUE",
    )
    .bind(compatibility_sha256)
    .execute(&mut connection)
    .await
    .context("pinning server compatibility identity")?;
    let configured: String = sqlx::query_scalar(
        "SELECT compatibility_sha256
         FROM captured.settings
         WHERE singleton = TRUE",
    )
    .fetch_one(&mut connection)
    .await
    .context("reading server compatibility identity")?;
    ensure!(
        configured == compatibility_sha256,
        "server compatibility identity differs from the installed profile"
    );
    Ok(())
}

fn pg_ssl_mode(mode: PostgresSslMode) -> sqlx::postgres::PgSslMode {
    match mode {
        PostgresSslMode::Disable => sqlx::postgres::PgSslMode::Disable,
        PostgresSslMode::Require => sqlx::postgres::PgSslMode::Require,
        PostgresSslMode::VerifyFull => sqlx::postgres::PgSslMode::VerifyFull,
    }
}

/// Refuses to start before `capture-server migrate` has applied every
/// migration this binary knows. A newer release's migrations stay compatible
/// with it, so a journal ahead of this binary is fine.
async fn require_migrated_schema(pool: &PgPool) -> MetadataResult<()> {
    let journal_exists: bool =
        sqlx::query_scalar(&format!("SELECT to_regclass('{JOURNAL}') IS NOT NULL"))
            .fetch_one(pool)
            .await
            .map_err(|error| db(anyhow!(error).context("checking daemon migration journal")))?;
    let applied: Option<i64> = if journal_exists {
        sqlx::query_scalar(&format!("SELECT MAX(version) FROM {JOURNAL}"))
            .fetch_one(pool)
            .await
            .map_err(|error| db(anyhow!(error).context("reading daemon schema version")))?
    } else {
        None
    };
    if applied.unwrap_or(0) < LATEST_SCHEMA_VERSION {
        return Err(db(anyhow!(
            "daemon PostgreSQL schema is older than version {LATEST_SCHEMA_VERSION}; run capture-server migrate"
        )));
    }
    Ok(())
}

fn db(error: anyhow::Error) -> MetadataStoreError {
    MetadataStoreError::Backend(error)
}

/// Rolls back a transaction that returns without committing. Dropping a sqlx
/// transaction only queues its ROLLBACK, which a background task sends when it
/// returns the connection to the pool. Until then the transaction keeps its row
/// locks, and a concurrent `FOR UPDATE SKIP LOCKED` claim skips the locked rows,
/// so a queued notarization can briefly look unclaimable. A failed rollback
/// means the connection is gone, which releases the locks too, so the caller's
/// result stands either way.
async fn release<T>(transaction: sqlx::Transaction<'_, Postgres>, value: T) -> MetadataResult<T> {
    let _ = transaction.rollback().await;
    Ok(value)
}

fn invalid_i64(value: u64, code: &'static str) -> MetadataResult<i64> {
    i64::try_from(value).map_err(|_| MetadataStoreError::InvalidInput(code))
}

fn validate_limit(limit: usize) -> MetadataResult<i64> {
    if !(1..=201).contains(&limit) {
        return Err(MetadataStoreError::InvalidInput("invalid_page_limit"));
    }
    i64::try_from(limit).map_err(|_| MetadataStoreError::InvalidInput("invalid_page_limit"))
}

fn validate_completion(completion: &CaptureCompletion) -> MetadataResult<()> {
    validate_trace_id(&completion.trace_id)?;
    invalid_i64(
        completion.completed_at_unix_ms,
        "capture_completed_at_out_of_range",
    )?;
    invalid_i64(completion.duration_ms, "duration_out_of_range")?;
    invalid_i64(completion.response_bytes, "response_bytes_out_of_range")?;
    invalid_i64(
        completion.expected_artifact_size_bytes,
        "artifact_size_out_of_range",
    )?;
    if completion.expected_artifact_sha256.len() != 64
        || !completion
            .expected_artifact_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MetadataStoreError::InvalidInput(
            "invalid_expected_artifact_sha256",
        ));
    }
    Ok(())
}

fn validate_artifact(artifact: &ArtifactRecord) -> MetadataResult<()> {
    artifact
        .validate()
        .map_err(|_| MetadataStoreError::InvalidInput("invalid_artifact_record"))?;
    invalid_i64(artifact.size_bytes, "artifact_size_out_of_range")?;
    Ok(())
}

fn validate_proof(progress: NotarizationProofProgress) -> MetadataResult<()> {
    for value in [
        progress.bytes_completed,
        progress.bytes_total,
        progress.commitments_completed,
        progress.commitments_total,
    ] {
        invalid_i64(value, "proof_progress_out_of_range")?;
    }
    if progress.bytes_completed > progress.bytes_total
        || progress.commitments_completed > progress.commitments_total
    {
        return Err(MetadataStoreError::InvalidInput("invalid_proof_progress"));
    }
    Ok(())
}

fn require_artifact(
    artifact: &ArtifactRecord,
    trace_id: &str,
    kind: ArtifactKind,
) -> MetadataResult<()> {
    if artifact.key.trace_id() != trace_id || artifact.key.kind() != kind {
        return Err(db(anyhow!("artifact does not match metadata transition")));
    }
    Ok(())
}

fn row_u64(row: &PgRow, name: &str) -> anyhow::Result<u64> {
    Ok(row.try_get::<i64, _>(name)?.try_into()?)
}

fn row_optional_u64(row: &PgRow, name: &str) -> anyhow::Result<Option<u64>> {
    row.try_get::<Option<i64>, _>(name)?
        .map(TryInto::try_into)
        .transpose()
        .map_err(Into::into)
}

fn trace_from_row(row: &PgRow) -> anyhow::Result<TraceSummary> {
    Ok(TraceSummary {
        trace_id: row.try_get("trace_id")?,
        created_at_unix_ms: row_u64(row, "created_at_unix_ms")?,
        completed_at_unix_ms: row_optional_u64(row, "completed_at_unix_ms")?,
        provider: row.try_get("provider")?,
        operation: row.try_get("operation")?,
        requested_model: row.try_get("requested_model")?,
        response_model: row.try_get("response_model")?,
        http_status: row
            .try_get::<Option<i32>, _>("http_status")?
            .map(TryInto::try_into)
            .transpose()?,
        streaming: row.try_get("streaming")?,
        request_bytes: row_u64(row, "request_bytes")?,
        response_bytes: row_optional_u64(row, "response_bytes")?,
        duration_ms: row_optional_u64(row, "duration_ms")?,
        capture_status: row.try_get("capture_status")?,
        notarization_status: row.try_get("notarization_status")?,
        prompt_preview: row.try_get("prompt_preview")?,
        prompt_preview_truncated: row.try_get("prompt_preview_truncated")?,
        output_preview: row.try_get("output_preview")?,
        output_preview_truncated: row.try_get("output_preview_truncated")?,
        expected_artifact_size_bytes: row_optional_u64(row, "expected_artifact_size_bytes")?,
        expected_artifact_sha256: row.try_get("expected_artifact_sha256")?,
        failure_code: row.try_get("failure_code")?,
        evidence_kind: stored_evidence_kind(row)?,
    })
}

fn stored_evidence_kind(row: &PgRow) -> anyhow::Result<crate::metadata::EvidenceKind> {
    let value: String = row.try_get("evidence_kind")?;
    crate::metadata::parse_evidence_kind(&value).context("stored evidence kind is unknown")
}

fn operation_from_row(row: &PgRow) -> anyhow::Result<Operation> {
    Ok(Operation {
        operation_id: row.try_get("operation_id")?,
        kind: row.try_get("kind")?,
        trace_id: row.try_get("trace_id")?,
        state: row.try_get("state")?,
        attempt: row.try_get::<i32, _>("attempt")?.try_into()?,
        created_at_unix_ms: row_u64(row, "created_at_unix_ms")?,
        started_at_unix_ms: row_optional_u64(row, "started_at_unix_ms")?,
        completed_at_unix_ms: row_optional_u64(row, "completed_at_unix_ms")?,
        failure_code: row.try_get("failure_code")?,
        progress_phase: row.try_get("progress_phase")?,
        progress_updated_at_unix_ms: row_u64(row, "progress_updated_at_unix_ms")?,
        proof_bytes_completed: row_u64(row, "proof_bytes_completed")?,
        proof_bytes_total: row_u64(row, "proof_bytes_total")?,
        proof_commitments_completed: row_u64(row, "proof_commitments_completed")?,
        proof_commitments_total: row_u64(row, "proof_commitments_total")?,
    })
}

fn attempt_from_row(row: &PgRow) -> anyhow::Result<OperationAttempt> {
    Ok(OperationAttempt {
        attempt: row.try_get::<i32, _>("attempt")?.try_into()?,
        state: row.try_get("state")?,
        started_at_unix_ms: row_u64(row, "started_at_unix_ms")?,
        completed_at_unix_ms: row_optional_u64(row, "completed_at_unix_ms")?,
        failure_code: row.try_get("failure_code")?,
    })
}

fn event_from_row(row: &PgRow) -> anyhow::Result<Event> {
    Ok(Event {
        event_id: row_u64(row, "event_id")?,
        created_at_unix_ms: row_u64(row, "created_at_unix_ms")?,
        event_type: row.try_get("event_type")?,
        trace_id: row.try_get("trace_id")?,
        operation_id: row.try_get("operation_id")?,
        severity: row.try_get("severity")?,
        message: row.try_get("message")?,
    })
}

fn trace_share_from_row(row: &PgRow) -> anyhow::Result<TraceShareRecord> {
    Ok(TraceShareRecord {
        trace_id: row.try_get("trace_id")?,
        hosted_trace_id: row.try_get("hosted_trace_id")?,
        progress: row.try_get("progress")?,
        visibility: row.try_get("visibility")?,
        access_enabled: row.try_get("access_enabled")?,
        password_protected: row.try_get("password_protected")?,
        expires_at_unix_ms: row_optional_u64(row, "expires_at_unix_ms")?,
        failure_code: row.try_get("failure_code")?,
        share_url: row.try_get("share_url")?,
        package_url: row.try_get("package_url")?,
        updated_at_unix_ms: row_u64(row, "updated_at_unix_ms")?,
    })
}

/// Records one activity event for `organization`, the organization of the
/// Trace, operation or setting the event describes.
#[allow(clippy::too_many_arguments)]
async fn insert_event(
    connection: &mut PgConnection,
    organization: &OrganizationId,
    now: i64,
    event_type: &str,
    trace_id: Option<&str>,
    operation_id: Option<&str>,
    severity: &str,
    message: &str,
) -> MetadataResult<()> {
    sqlx::query(
        "INSERT INTO captured.events
         (organization_id, created_at_unix_ms, event_type, trace_id, operation_id, severity, message)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(organization.as_str())
    .bind(now)
    .bind(event_type)
    .bind(trace_id)
    .bind(operation_id)
    .bind(severity)
    .bind(message)
    .execute(connection)
    .await
    .map_err(|error| db(anyhow!(error).context("inserting daemon event")))?;
    Ok(())
}

async fn artifact_exists_exact(
    connection: &mut PgConnection,
    organization: &OrganizationId,
    artifact: &ArtifactRecord,
) -> MetadataResult<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM captured.artifacts a
            JOIN captured.traces t ON t.trace_id = a.trace_id
            WHERE a.trace_id = $1 AND a.kind = $2 AND a.locator = $3
              AND a.size_bytes = $4 AND a.sha256 = $5 AND a.state = 'available'
              AND t.organization_id = $6
         )",
    )
    .bind(artifact.key.trace_id())
    .bind(artifact.key.kind().as_str())
    .bind(artifact.locator.as_stored())
    .bind(invalid_i64(
        artifact.size_bytes,
        "artifact_size_out_of_range",
    )?)
    .bind(&artifact.sha256)
    .bind(organization.as_str())
    .fetch_one(connection)
    .await
    .map_err(|error| db(anyhow!(error).context("checking immutable artifact metadata")))
}

/// Records an artifact of one of `organization`'s Traces. Nothing is
/// inserted for a Trace of another organization.
async fn insert_artifact(
    connection: &mut PgConnection,
    organization: &OrganizationId,
    artifact: &ArtifactRecord,
) -> MetadataResult<()> {
    let changed = sqlx::query(
        "INSERT INTO captured.artifacts
         (trace_id, kind, locator, size_bytes, sha256, state)
         SELECT trace_id, $2, $3, $4, $5, 'available'
         FROM captured.traces WHERE trace_id = $1 AND organization_id = $6
         ON CONFLICT (trace_id, kind) DO NOTHING",
    )
    .bind(artifact.key.trace_id())
    .bind(artifact.key.kind().as_str())
    .bind(artifact.locator.as_stored())
    .bind(invalid_i64(
        artifact.size_bytes,
        "artifact_size_out_of_range",
    )?)
    .bind(&artifact.sha256)
    .bind(organization.as_str())
    .execute(&mut *connection)
    .await
    .map_err(|error| db(anyhow!(error).context("inserting artifact metadata")))?
    .rows_affected();
    if changed != 1 && !artifact_exists_exact(connection, organization, artifact).await? {
        return Err(db(anyhow!(
            "artifact metadata conflicts with an immutable record"
        )));
    }
    Ok(())
}

/// Indexes one of `organization`'s Traces for preview search.
async fn index_trace_search(
    connection: &mut PgConnection,
    organization: &OrganizationId,
    trace_id: &str,
) -> MetadataResult<()> {
    sqlx::query(
        "INSERT INTO captured.trace_search
            (trace_id, prompt_document, output_document)
         SELECT trace_id, to_tsvector('simple', prompt_preview),
            to_tsvector('simple', output_preview)
         FROM captured.traces WHERE trace_id = $1 AND organization_id = $2
         ON CONFLICT (trace_id) DO UPDATE SET
            prompt_document = excluded.prompt_document,
            output_document = excluded.output_document",
    )
    .bind(trace_id)
    .bind(organization.as_str())
    .execute(connection)
    .await
    .map_err(|error| db(anyhow!(error).context("indexing capture preview")))?;
    Ok(())
}

/// Stamps the claim's commit on one of `organization`'s artifacts.
async fn set_artifact_commit(
    connection: &mut PgConnection,
    organization: &OrganizationId,
    trace_id: &str,
    kind: ArtifactKind,
    commit_id: &str,
) -> MetadataResult<()> {
    sqlx::query(
        "UPDATE captured.artifacts a SET commit_id = $3::uuid
         FROM captured.traces t
         WHERE a.trace_id = $1 AND a.kind = $2
           AND t.trace_id = a.trace_id AND t.organization_id = $4",
    )
    .bind(trace_id)
    .bind(kind.as_str())
    .bind(commit_id)
    .bind(organization.as_str())
    .execute(connection)
    .await
    .map_err(|error| db(anyhow!(error).context("recording artifact commit")))?;
    Ok(())
}

async fn completion_matches(
    connection: &mut PgConnection,
    organization: &OrganizationId,
    completion: &CaptureCompletion,
) -> MetadataResult<bool> {
    sqlx::query_scalar(
        "SELECT EXISTS(
            SELECT 1 FROM captured.traces
            WHERE trace_id = $1 AND completed_at_unix_ms = $2 AND duration_ms = $3
              AND http_status = $4 AND response_bytes = $5
              AND response_model IS NOT DISTINCT FROM $6
              AND output_preview = $7 AND output_preview_truncated = $8
              AND expected_artifact_size_bytes = $9 AND expected_artifact_sha256 = $10
              AND evidence_kind = $11 AND organization_id = $12
         )",
    )
    .bind(&completion.trace_id)
    .bind(invalid_i64(
        completion.completed_at_unix_ms,
        "capture_completed_at_out_of_range",
    )?)
    .bind(invalid_i64(
        completion.duration_ms,
        "duration_out_of_range",
    )?)
    .bind(i32::from(completion.http_status))
    .bind(invalid_i64(
        completion.response_bytes,
        "response_bytes_out_of_range",
    )?)
    .bind(&completion.response_model)
    .bind(&completion.output_preview)
    .bind(completion.output_preview_truncated)
    .bind(invalid_i64(
        completion.expected_artifact_size_bytes,
        "artifact_size_out_of_range",
    )?)
    .bind(&completion.expected_artifact_sha256)
    .bind(completion.evidence_kind.as_str())
    .bind(organization.as_str())
    .fetch_one(connection)
    .await
    .map_err(|error| db(anyhow!(error).context("checking capture completion metadata")))
}

/// The capture mode an organization without a stored setting uses.
const DEFAULT_CAPTURE_MODE: CaptureMode = CaptureMode::Notarized;
/// Whether auto-seal is on for an organization without a stored setting.
const DEFAULT_AUTO_SEAL_ENABLED: bool = false;

impl PostgresOrganizationStore {
    fn pool(&self) -> &PgPool {
        &self.store.pool
    }

    /// The organization's stored capture settings, or the defaults when it
    /// has never stored any.
    async fn settings(&self) -> MetadataResult<(CaptureMode, bool)> {
        let row = sqlx::query(
            "SELECT capture_mode, auto_seal_enabled FROM captured.organization_settings
             WHERE organization_id = $1",
        )
        .bind(self.organization.as_str())
        .fetch_optional(self.pool())
        .await
        .map_err(|error| db(anyhow!(error).context("reading organization settings")))?;
        let Some(row) = row else {
            return Ok((DEFAULT_CAPTURE_MODE, DEFAULT_AUTO_SEAL_ENABLED));
        };
        settings_from_row(&row)
    }

    /// Locks the organization's settings row for update, creating it with
    /// the defaults first so concurrent writers serialize on one row.
    async fn lock_settings(
        &self,
        transaction: &mut sqlx::Transaction<'_, Postgres>,
    ) -> MetadataResult<(CaptureMode, bool)> {
        sqlx::query(
            "INSERT INTO captured.organization_settings
                (organization_id, capture_mode, auto_seal_enabled)
             VALUES ($1, $2, $3)
             ON CONFLICT (organization_id) DO NOTHING",
        )
        .bind(self.organization.as_str())
        .bind(DEFAULT_CAPTURE_MODE.as_str())
        .bind(DEFAULT_AUTO_SEAL_ENABLED)
        .execute(&mut **transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("creating organization settings")))?;
        let row = sqlx::query(
            "SELECT capture_mode, auto_seal_enabled FROM captured.organization_settings
             WHERE organization_id = $1 FOR UPDATE",
        )
        .bind(self.organization.as_str())
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("locking organization settings")))?;
        settings_from_row(&row)
    }
}

fn settings_from_row(row: &PgRow) -> MetadataResult<(CaptureMode, bool)> {
    let capture_mode: String = row
        .try_get("capture_mode")
        .map_err(|error| db(anyhow!(error)))?;
    let auto_seal_enabled: bool = row
        .try_get("auto_seal_enabled")
        .map_err(|error| db(anyhow!(error)))?;
    let capture_mode = CaptureMode::parse(&capture_mode)
        .ok_or_else(|| db(anyhow!("stored capture mode is unknown")))?;
    Ok((capture_mode, auto_seal_enabled))
}

/// A server records captures and notarizations only through a replica's
/// claimed writes, and the cluster manages auto-seal, Trace deletion and
/// sharing, so the organization view refuses those local mutations.
fn server_requires_claim() -> MetadataStoreError {
    MetadataStoreError::InvalidInput("server_requires_claim")
}

#[async_trait]
impl MetadataStore for PostgresOrganizationStore {
    fn backend_name(&self) -> &'static str {
        "postgres"
    }

    async fn readiness(&self) -> MetadataResult<()> {
        sqlx::query("SELECT 1")
            .execute(self.pool())
            .await
            .map_err(|error| db(anyhow!(error).context("probing daemon PostgreSQL")))?;
        Ok(())
    }

    async fn capture_mode(&self) -> MetadataResult<CaptureMode> {
        Ok(self.settings().await?.0)
    }

    async fn set_capture_mode(
        &self,
        mode: CaptureMode,
        now_unix_ms: u64,
    ) -> MetadataResult<CaptureMode> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        let mut transaction = self
            .pool()
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting capture_mode transaction")))?;
        let (current, _) = self.lock_settings(&mut transaction).await?;
        if current != mode {
            sqlx::query(
                "UPDATE captured.organization_settings
                 SET capture_mode = $2, updated_at = clock_timestamp()
                 WHERE organization_id = $1",
            )
            .bind(self.organization.as_str())
            .bind(mode.as_str())
            .execute(&mut *transaction)
            .await
            .map_err(|error| db(anyhow!(error).context("storing capture_mode")))?;
            let (event_type, message) = mode.event();
            insert_event(
                &mut transaction,
                &self.organization,
                now,
                event_type,
                None,
                None,
                "info",
                message,
            )
            .await?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing capture_mode")))?;
        Ok(mode)
    }

    async fn auto_seal_enabled(&self) -> MetadataResult<bool> {
        Ok(self.settings().await?.1)
    }

    async fn set_auto_seal_enabled(
        &self,
        _enabled: bool,
        _now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        Err(server_requires_claim())
    }

    async fn begin_capture(&self, _capture: NewTrace) -> MetadataResult<()> {
        Err(server_requires_claim())
    }

    async fn mark_capture_failed(
        &self,
        _trace_id: &str,
        _failure_code: &str,
    ) -> MetadataResult<()> {
        Err(server_requires_claim())
    }

    async fn prepare_capture_completion(
        &self,
        _completion: CaptureCompletion,
    ) -> MetadataResult<()> {
        Err(server_requires_claim())
    }

    async fn complete_capture(
        &self,
        _completion: CaptureCompletion,
        _artifact: ArtifactRecord,
    ) -> MetadataResult<()> {
        Err(server_requires_claim())
    }

    async fn incomplete_captures(&self) -> MetadataResult<Vec<IncompleteCapture>> {
        Err(server_requires_claim())
    }

    async fn traces(&self, filters: TraceFilters) -> MetadataResult<Vec<TraceSummary>> {
        let limit = validate_limit(filters.limit)?;
        if let Some(value) = filters.created_after_unix_ms {
            invalid_i64(value, "created_after_out_of_range")?;
        }
        if let Some(value) = filters.created_before_unix_ms {
            invalid_i64(value, "created_before_out_of_range")?;
        }
        if let Some(cursor) = &filters.cursor {
            invalid_i64(cursor.created_at_unix_ms, "cursor_out_of_range")?;
        }
        let search = filters
            .query
            .as_deref()
            .filter(|query| !query.is_empty())
            .map(|query| {
                if !self.store.full_text_search {
                    return Err(MetadataStoreError::InvalidInput("preview_search_disabled"));
                }
                Ok(trace_search_parts(query))
            })
            .transpose()?
            .flatten();
        if filters.query.is_some() && search.is_none() {
            return Ok(Vec::new());
        }

        let mut query = QueryBuilder::<Postgres>::new("SELECT c.* FROM captured.traces c ");
        if search.is_some() {
            query.push("JOIN captured.trace_search search ON search.trace_id = c.trace_id ");
        }
        query
            .push("WHERE c.organization_id = ")
            .push_bind(self.organization.as_str());
        if let Some(parts) = search.as_deref() {
            for part in parts {
                let expression = part.expression();
                query
                    .push(" AND (search.prompt_document @@ websearch_to_tsquery('simple', ")
                    .push_bind(expression.clone())
                    .push(") OR search.output_document @@ websearch_to_tsquery('simple', ")
                    .push_bind(expression)
                    .push("))");
            }
        }
        for (column, value) in [
            ("requested_model", filters.model.as_deref()),
            ("provider", filters.provider.as_deref()),
            ("capture_status", filters.capture_status.as_deref()),
            (
                "notarization_status",
                filters.notarization_status.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                query
                    .push(" AND c.")
                    .push(column)
                    .push(" = ")
                    .push_bind(value);
            }
        }
        match filters.state.as_deref() {
            Some("captured") => query.push(
                " AND c.capture_status = 'captured' AND c.notarization_status != 'succeeded'",
            ),
            Some("notarized") => query
                .push(" AND c.capture_status = 'captured' AND c.notarization_status = 'succeeded'"),
            Some(_) => return Ok(Vec::new()),
            None => &mut query,
        };
        match filters.status.as_deref() {
            Some("capturing") => query.push(" AND c.capture_status = 'capturing'"),
            Some("capture_failed") => query.push(" AND c.capture_status = 'failed'"),
            Some("needs_attention") => query.push(
                " AND (c.capture_status = 'failed' OR (c.capture_status = 'captured' AND c.notarization_status IN ('failed', 'interrupted')))",
            ),
            Some("notarizing") => query.push(
                " AND c.capture_status = 'captured' AND c.notarization_status IN ('queued', 'running')",
            ),
            Some("notarization_failed") => query.push(
                " AND c.capture_status = 'captured' AND c.notarization_status = 'failed'",
            ),
            Some("notarization_interrupted") => query.push(
                " AND c.capture_status = 'captured' AND c.notarization_status = 'interrupted'",
            ),
            Some(_) => return Ok(Vec::new()),
            None => &mut query,
        };
        if let Some(streaming) = filters.streaming {
            query.push(" AND c.streaming = ").push_bind(streaming);
        }
        if let Some(created_after) = filters.created_after_unix_ms {
            query
                .push(" AND c.created_at_unix_ms >= ")
                .push_bind(i64::try_from(created_after).expect("validated timestamp"));
        }
        if let Some(created_before) = filters.created_before_unix_ms {
            query
                .push(" AND c.created_at_unix_ms <= ")
                .push_bind(i64::try_from(created_before).expect("validated timestamp"));
        }
        if let Some(cursor) = &filters.cursor {
            let created = i64::try_from(cursor.created_at_unix_ms).expect("validated cursor");
            query
                .push(" AND (c.created_at_unix_ms < ")
                .push_bind(created)
                .push(" OR (c.created_at_unix_ms = ")
                .push_bind(created)
                .push(" AND c.trace_id < ")
                .push_bind(&cursor.trace_id)
                .push("))");
        }
        query
            .push(" ORDER BY c.created_at_unix_ms DESC, c.trace_id DESC LIMIT ")
            .push_bind(limit);
        query
            .build()
            .fetch_all(self.pool())
            .await
            .map_err(|error| db(anyhow!(error).context("querying traces")))?
            .iter()
            .map(trace_from_row)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(db)
    }

    async fn trace(&self, trace_id: &str) -> MetadataResult<Option<TraceSummary>> {
        validate_trace_id(trace_id)?;
        sqlx::query("SELECT * FROM captured.traces WHERE trace_id = $1 AND organization_id = $2")
            .bind(trace_id)
            .bind(self.organization.as_str())
            .fetch_optional(self.pool())
            .await
            .map_err(|error| db(anyhow!(error).context("querying capture")))?
            .as_ref()
            .map(trace_from_row)
            .transpose()
            .map_err(db)
    }

    async fn artifacts(&self, trace_id: &str) -> MetadataResult<Vec<ArtifactRecord>> {
        validate_trace_id(trace_id)?;
        let rows = sqlx::query(
            "SELECT a.trace_id, a.kind, a.locator, a.size_bytes, a.sha256,
                    a.commit_id::text AS commit_id
             FROM captured.artifacts a
             JOIN captured.traces t ON t.trace_id = a.trace_id
             WHERE a.trace_id = $1 AND a.state = 'available' AND t.organization_id = $2
             ORDER BY a.kind",
        )
        .bind(trace_id)
        .bind(self.organization.as_str())
        .fetch_all(self.pool())
        .await
        .map_err(|error| db(anyhow!(error).context("querying artifact metadata")))?;
        rows.iter()
            .map(|row| -> anyhow::Result<_> {
                let trace_id: String = row.try_get("trace_id")?;
                let kind: String = row.try_get("kind")?;
                let locator: String = row.try_get("locator")?;
                let size_bytes: i64 = row.try_get("size_bytes")?;
                let sha256: String = row.try_get("sha256")?;
                let record = ArtifactRecord::new(
                    ArtifactKey::new(&trace_id, ArtifactKind::try_from(kind.as_str())?)?,
                    ArtifactLocator::from_stored(locator)?,
                    size_bytes.try_into()?,
                    sha256,
                )?;
                match row.try_get::<Option<String>, _>("commit_id")? {
                    Some(commit_id) => record.with_commit_id(commit_id),
                    None => Ok(record),
                }
            })
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(db)
    }

    async fn prepare_trace_deletion(
        &self,
        _trace_id: &str,
    ) -> MetadataResult<TraceDeletionPreparation> {
        Err(server_requires_claim())
    }

    async fn delete_trace(&self, _trace_id: &str) -> MetadataResult<TraceDeletionOutcome> {
        Err(server_requires_claim())
    }

    async fn counts(&self) -> MetadataResult<MetadataCounts> {
        let row = sqlx::query(
            "SELECT
                COUNT(*) FILTER (WHERE capture_status = 'captured'
                    AND notarization_status != 'succeeded') AS captured,
                COUNT(*) FILTER (WHERE capture_status = 'captured'
                    AND notarization_status IN ('queued', 'running')) AS notarizing,
                COUNT(*) FILTER (WHERE capture_status = 'captured'
                    AND notarization_status = 'succeeded') AS notarized,
                COUNT(*) FILTER (WHERE capture_status = 'failed'
                    OR notarization_status IN ('failed', 'interrupted')) AS needs_attention,
                COUNT(*) FILTER (WHERE capture_status = 'capturing') AS capturing,
                COUNT(*) FILTER (WHERE capture_status = 'failed') AS capture_failed
             FROM captured.traces WHERE organization_id = $1",
        )
        .bind(self.organization.as_str())
        .fetch_one(self.pool())
        .await
        .map_err(|error| db(anyhow!(error).context("counting daemon metadata")))?;
        let value = |name| -> anyhow::Result<u64> { Ok(row.try_get::<i64, _>(name)?.try_into()?) };
        Ok(MetadataCounts {
            captured: value("captured").map_err(db)?,
            notarizing: value("notarizing").map_err(db)?,
            notarized: value("notarized").map_err(db)?,
            needs_attention: value("needs_attention").map_err(db)?,
            capturing: value("capturing").map_err(db)?,
            capture_failed: value("capture_failed").map_err(db)?,
        })
    }

    async fn trace_share(&self, trace_id: &str) -> MetadataResult<Option<TraceShareRecord>> {
        validate_trace_id(trace_id)?;
        sqlx::query(
            "SELECT s.trace_id, s.hosted_trace_id, s.progress, s.visibility, s.access_enabled,
                    s.password_protected, s.expires_at_unix_ms, s.failure_code,
                    s.share_url, s.package_url, s.updated_at_unix_ms
             FROM captured.trace_shares s
             JOIN captured.traces t ON t.trace_id = s.trace_id
             WHERE s.trace_id = $1 AND t.organization_id = $2",
        )
        .bind(trace_id)
        .bind(self.organization.as_str())
        .fetch_optional(self.pool())
        .await
        .map_err(|error| db(anyhow!(error).context("querying trace share")))?
        .as_ref()
        .map(trace_share_from_row)
        .transpose()
        .map_err(db)
    }

    async fn put_trace_share(&self, _share: TraceShareRecord) -> MetadataResult<()> {
        Err(server_requires_claim())
    }

    async fn delete_trace_share(&self, _trace_id: &str) -> MetadataResult<bool> {
        Err(server_requires_claim())
    }

    async fn enqueue_notarization(
        &self,
        trace_id: &str,
        now_unix_ms: u64,
    ) -> MetadataResult<Option<(Operation, bool)>> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        validate_trace_id(trace_id)?;
        let mut transaction = self
            .pool()
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting notarization enqueue")))?;
        let eligible: bool = sqlx::query_scalar(
            "SELECT EXISTS(
                SELECT 1 FROM captured.traces
                WHERE trace_id = $1 AND organization_id = $2 AND capture_status = 'captured'
                  AND http_status BETWEEN 200 AND 299 AND evidence_kind = 'notarized'
                FOR UPDATE
             )",
        )
        .bind(trace_id)
        .bind(self.organization.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("locking capture for notarization")))?;
        if !eligible {
            return release(transaction, None).await;
        }
        if let Some(row) = sqlx::query(
            "SELECT * FROM captured.operations
             WHERE trace_id = $1 AND organization_id = $2 AND kind = 'notarization'",
        )
        .bind(trace_id)
        .bind(self.organization.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("checking existing notarization")))?
        {
            let operation = operation_from_row(&row).map_err(db)?;
            if matches!(operation.state.as_str(), "failed" | "interrupted") {
                let row = sqlx::query(
                    "UPDATE captured.operations SET
                        state = 'queued', started_at_unix_ms = NULL,
                        completed_at_unix_ms = NULL, failure_code = NULL,
                        progress_phase = 'queued', progress_updated_at_unix_ms = $2,
                        proof_bytes_completed = 0, proof_bytes_total = 0,
                        proof_commitments_completed = 0, proof_commitments_total = 0
                     WHERE operation_id = $1 AND organization_id = $3
                       AND state IN ('failed', 'interrupted')
                     RETURNING *",
                )
                .bind(&operation.operation_id)
                .bind(now)
                .bind(self.organization.as_str())
                .fetch_one(&mut *transaction)
                .await
                .map_err(|error| db(anyhow!(error).context("requeueing notarization")))?;
                sqlx::query(
                    "UPDATE captured.traces SET notarization_status = 'queued'
                     WHERE trace_id = $1 AND organization_id = $2",
                )
                .bind(trace_id)
                .bind(self.organization.as_str())
                .execute(&mut *transaction)
                .await
                .map_err(|error| db(anyhow!(error).context("requeueing trace notarization")))?;
                insert_event(
                    &mut transaction,
                    &self.organization,
                    now,
                    "notarization_queued",
                    Some(trace_id),
                    Some(&operation.operation_id),
                    "info",
                    "Notarization retry queued",
                )
                .await?;
                let operation = operation_from_row(&row).map_err(db)?;
                transaction
                    .commit()
                    .await
                    .map_err(|error| db(anyhow!(error).context("committing notarization retry")))?;
                return Ok(Some((operation, false)));
            }
            return Ok(Some((operation, true)));
        }
        let operation_id = format!("op-{}", uuid::Uuid::new_v4().simple());
        let row = sqlx::query(
            "INSERT INTO captured.operations (
                operation_id, kind, trace_id, state, attempt,
                created_at_unix_ms, progress_phase, progress_updated_at_unix_ms,
                organization_id
             ) VALUES ($1, 'notarization', $2, 'queued', 0, $3, 'queued', $3, $4)
             RETURNING *",
        )
        .bind(&operation_id)
        .bind(trace_id)
        .bind(now)
        .bind(self.organization.as_str())
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("inserting notarization operation")))?;
        sqlx::query(
            "UPDATE captured.traces SET notarization_status = 'queued'
             WHERE trace_id = $1 AND organization_id = $2",
        )
        .bind(trace_id)
        .bind(self.organization.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("queuing capture notarization")))?;
        insert_event(
            &mut transaction,
            &self.organization,
            now,
            "notarization_queued",
            Some(trace_id),
            Some(&operation_id),
            "info",
            "Notarization queued",
        )
        .await?;
        let operation = operation_from_row(&row).map_err(db)?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing notarization enqueue")))?;
        Ok(Some((operation, false)))
    }

    async fn claim_next_notarization(
        &self,
        _now_unix_ms: u64,
    ) -> MetadataResult<Option<Operation>> {
        Err(server_requires_claim())
    }

    async fn update_operation_progress(
        &self,
        _operation_id: &str,
        _phase: NotarizationPhase,
        _now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        Err(server_requires_claim())
    }

    async fn update_operation_proof_progress(
        &self,
        _operation_id: &str,
        _progress: NotarizationProofProgress,
        _now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        Err(server_requires_claim())
    }

    async fn complete_notarization(
        &self,
        _operation_id: &str,
        _artifact: ArtifactRecord,
        _now_unix_ms: u64,
    ) -> MetadataResult<TerminalOperationResult> {
        Err(server_requires_claim())
    }

    async fn fail_operation(
        &self,
        _operation_id: &str,
        _now_unix_ms: u64,
        _failure_code: &str,
    ) -> MetadataResult<TerminalOperationResult> {
        Err(server_requires_claim())
    }

    async fn interrupt_running_operations(&self, _now_unix_ms: u64) -> MetadataResult<usize> {
        Err(server_requires_claim())
    }

    async fn operation(&self, operation_id: &str) -> MetadataResult<Option<Operation>> {
        validate_operation_id(operation_id)?;
        sqlx::query(
            "SELECT * FROM captured.operations WHERE operation_id = $1 AND organization_id = $2",
        )
        .bind(operation_id)
        .bind(self.organization.as_str())
        .fetch_optional(self.pool())
        .await
        .map_err(|error| db(anyhow!(error).context("querying operation")))?
        .as_ref()
        .map(operation_from_row)
        .transpose()
        .map_err(db)
    }

    async fn operations(&self, filters: OperationFilters) -> MetadataResult<Vec<Operation>> {
        let limit = validate_limit(filters.limit)?;
        if let Some(trace_id) = &filters.trace_id {
            validate_trace_id(trace_id)?;
        }
        if let Some(cursor) = &filters.cursor {
            invalid_i64(cursor.created_at_unix_ms, "cursor_out_of_range")?;
        }
        let mut query = QueryBuilder::<Postgres>::new(
            "SELECT * FROM captured.operations WHERE organization_id = ",
        );
        query.push_bind(self.organization.as_str());
        for (column, value) in [
            ("state", filters.state.as_deref()),
            ("kind", filters.kind.as_deref()),
            ("trace_id", filters.trace_id.as_deref()),
        ] {
            if let Some(value) = value {
                query
                    .push(" AND ")
                    .push(column)
                    .push(" = ")
                    .push_bind(value);
            }
        }
        if let Some(cursor) = &filters.cursor {
            let created = i64::try_from(cursor.created_at_unix_ms).expect("validated cursor");
            query
                .push(" AND (created_at_unix_ms < ")
                .push_bind(created)
                .push(" OR (created_at_unix_ms = ")
                .push_bind(created)
                .push(" AND operation_id < ")
                .push_bind(&cursor.operation_id)
                .push("))");
        }
        query
            .push(" ORDER BY created_at_unix_ms DESC, operation_id DESC LIMIT ")
            .push_bind(limit);
        query
            .build()
            .fetch_all(self.pool())
            .await
            .map_err(|error| db(anyhow!(error).context("querying operations")))?
            .iter()
            .map(operation_from_row)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(db)
    }

    async fn operation_attempts(
        &self,
        operation_id: &str,
    ) -> MetadataResult<Vec<OperationAttempt>> {
        validate_operation_id(operation_id)?;
        sqlx::query(
            "SELECT a.attempt, a.state, a.started_at_unix_ms, a.completed_at_unix_ms,
                    a.failure_code
             FROM captured.operation_attempts a
             JOIN captured.operations o ON o.operation_id = a.operation_id
             WHERE a.operation_id = $1 AND o.organization_id = $2
             ORDER BY a.attempt DESC",
        )
        .bind(operation_id)
        .bind(self.organization.as_str())
        .fetch_all(self.pool())
        .await
        .map_err(|error| db(anyhow!(error).context("querying operation attempts")))?
        .iter()
        .map(attempt_from_row)
        .collect::<anyhow::Result<Vec<_>>>()
        .map_err(db)
    }

    async fn events_snapshot(&self, filters: EventFilters) -> MetadataResult<EventSnapshot> {
        let limit = validate_limit(filters.limit)?;
        if filters.before.is_some() && filters.after.is_some() {
            return Err(MetadataStoreError::InvalidInput(
                "conflicting_event_positions",
            ));
        }
        for value in [filters.before, filters.after, filters.created_after_unix_ms]
            .into_iter()
            .flatten()
        {
            invalid_i64(value, "event_position_out_of_range")?;
        }
        let mut transaction = self
            .pool()
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting event snapshot")))?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await
            .map_err(|error| db(anyhow!(error).context("configuring event snapshot")))?;

        let mut page =
            QueryBuilder::<Postgres>::new("SELECT * FROM captured.events WHERE organization_id = ");
        page.push_bind(self.organization.as_str());
        if let Some(before) = filters.before {
            page.push(" AND event_id < ")
                .push_bind(i64::try_from(before).expect("validated event position"));
        }
        if let Some(after) = filters.after {
            page.push(" AND event_id > ")
                .push_bind(i64::try_from(after).expect("validated event position"));
        }
        push_event_filters(&mut page, &filters);
        if filters.after.is_some() {
            page.push(" ORDER BY event_id ASC LIMIT ").push_bind(limit);
        } else {
            page.push(" ORDER BY event_id DESC LIMIT ").push_bind(limit);
        }
        let events = page
            .build()
            .fetch_all(&mut *transaction)
            .await
            .map_err(|error| db(anyhow!(error).context("querying event page")))?
            .iter()
            .map(event_from_row)
            .collect::<anyhow::Result<Vec<_>>>()
            .map_err(db)?;

        let mut high_water = QueryBuilder::<Postgres>::new(
            "SELECT MAX(event_id) AS high_water FROM captured.events WHERE organization_id = ",
        );
        high_water.push_bind(self.organization.as_str());
        push_event_filters(&mut high_water, &filters);
        let row = high_water
            .build()
            .fetch_one(&mut *transaction)
            .await
            .map_err(|error| db(anyhow!(error).context("querying event high-water")))?;
        let high_water = row_optional_u64(&row, "high_water").map_err(db)?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing event snapshot")))?;
        Ok(EventSnapshot { events, high_water })
    }
}

/// Coordination for the multi-replica server: replica leases, claims that
/// span organizations and carry the organization of the work they claim,
/// dashboard sessions and the Registry. Everything else goes through
/// [`Self::organization`], whose every read and write is limited to one
/// organization.
impl PostgresMetadataStore {
    pub(crate) fn organization(&self, organization: &OrganizationId) -> Arc<dyn MetadataStore> {
        Arc::new(self.organization_store(organization))
    }

    pub(crate) async fn register_replica(
        &self,
        identity: &ReplicaIdentity,
        compatibility_sha256: &str,
        lease_seconds: u64,
    ) -> MetadataResult<()> {
        let configured = sqlx::query_scalar::<_, String>(
            "SELECT compatibility_sha256
             FROM captured.settings
             WHERE singleton = TRUE",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("checking server compatibility")))?;
        if configured.as_deref() != Some(compatibility_sha256) {
            return Err(MetadataStoreError::InvalidInput(
                "server_compatibility_mismatch",
            ));
        }
        let lease = lease_i32(lease_seconds)?;
        let row = sqlx::query_scalar::<_, String>(
            "INSERT INTO captured.replicas
                (instance_id, incarnation_id, heartbeat_at, lease_expires_at)
             VALUES ($1, $2::uuid, clock_timestamp(),
                     clock_timestamp() + make_interval(secs => $3))
             ON CONFLICT (instance_id) DO UPDATE SET
                incarnation_id = excluded.incarnation_id,
                heartbeat_at = excluded.heartbeat_at,
                lease_expires_at = excluded.lease_expires_at
             WHERE captured.replicas.lease_expires_at <= clock_timestamp()
                OR captured.replicas.incarnation_id = excluded.incarnation_id
             RETURNING instance_id",
        )
        .bind(identity.instance_id())
        .bind(identity.incarnation_id())
        .bind(lease)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("registering cluster replica")))?;
        if row.is_none() {
            return Err(MetadataStoreError::InvalidInput(
                "live_instance_id_collision",
            ));
        }
        Ok(())
    }

    pub(crate) async fn heartbeat_replica(
        &self,
        identity: &ReplicaIdentity,
        lease_seconds: u64,
    ) -> MetadataResult<()> {
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        let changed = sqlx::query(
            "UPDATE captured.replicas SET
                heartbeat_at = clock_timestamp(),
                lease_expires_at = clock_timestamp() + make_interval(secs => $3)
             WHERE instance_id = $1 AND incarnation_id = $2::uuid
               AND lease_expires_at > clock_timestamp()",
        )
        .bind(identity.instance_id())
        .bind(identity.incarnation_id())
        .bind(lease)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("heartbeating cluster replica")))?
        .rows_affected();
        if changed != 1 {
            return Err(MetadataStoreError::Fenced);
        }
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing replica heartbeat")))
    }

    pub(crate) async fn replica_ready(&self, identity: &ReplicaIdentity) -> MetadataResult<bool> {
        sqlx::query_scalar(
            "SELECT EXISTS(
                 SELECT 1 FROM captured.replicas
                 WHERE instance_id=$1 AND incarnation_id=$2::uuid
                   AND lease_expires_at>clock_timestamp()
             )",
        )
        .bind(identity.instance_id())
        .bind(identity.incarnation_id())
        .fetch_one(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("checking replica lease readiness")))
    }

    pub(crate) async fn release_replica(&self, identity: &ReplicaIdentity) -> MetadataResult<()> {
        sqlx::query(
            "DELETE FROM captured.replicas
             WHERE instance_id = $1 AND incarnation_id = $2::uuid",
        )
        .bind(identity.instance_id())
        .bind(identity.incarnation_id())
        .execute(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("releasing cluster replica")))?;
        Ok(())
    }

    pub(crate) async fn begin_capture_claimed(
        &self,
        capture: NewTrace,
        claim: &CaptureClaim,
        lease_seconds: u64,
    ) -> MetadataResult<()> {
        if capture.trace_id != claim.trace_id {
            return Err(MetadataStoreError::InvalidInput("capture_claim_mismatch"));
        }
        let created_at = invalid_i64(
            capture.created_at_unix_ms,
            "capture_created_at_out_of_range",
        )?;
        let request_bytes = i64::try_from(capture.request_bytes)
            .map_err(|_| MetadataStoreError::InvalidInput("request_bytes_out_of_range"))?;
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        sqlx::query(
            "INSERT INTO captured.traces (
                trace_id, created_at_unix_ms, provider, operation, requested_model,
                streaming, request_bytes, prompt_preview, prompt_preview_truncated,
                config_fingerprint, capture_status, notarization_status,
                owner_instance_id, owner_incarnation_id, capture_fence,
                artifact_commit_id, claim_lease_expires_at, evidence_kind, organization_id
             ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'capturing','not_requested',
                       $11,$12::uuid,$13::uuid,$14::uuid,
                       clock_timestamp() + make_interval(secs => $15), $16, $17)",
        )
        .bind(capture.trace_id)
        .bind(created_at)
        .bind(capture.provider)
        .bind(capture.operation)
        .bind(capture.requested_model)
        .bind(capture.streaming)
        .bind(request_bytes)
        .bind(capture.prompt_preview)
        .bind(capture.prompt_preview_truncated)
        .bind(capture.config_fingerprint)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.claim_fence)
        .bind(&claim.commit_id)
        .bind(lease)
        .bind(capture.evidence_kind.as_str())
        .bind(claim.organization.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("beginning claimed capture")))?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing claimed capture")))
    }

    pub(crate) async fn renew_capture_claim(
        &self,
        claim: &CaptureClaim,
        lease_seconds: u64,
    ) -> MetadataResult<()> {
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let changed = sqlx::query(
            "UPDATE captured.traces SET
                claim_lease_expires_at = clock_timestamp() + make_interval(secs => $6)
             WHERE trace_id = $1 AND capture_status = 'capturing'
               AND owner_instance_id = $2 AND owner_incarnation_id = $3::uuid
               AND capture_fence = $4::uuid AND artifact_commit_id = $5::uuid
               AND claim_lease_expires_at > clock_timestamp() AND organization_id = $7",
        )
        .bind(&claim.trace_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.claim_fence)
        .bind(&claim.commit_id)
        .bind(lease)
        .bind(claim.organization.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("renewing capture claim")))?
        .rows_affected();
        if changed == 1 {
            transaction
                .commit()
                .await
                .map_err(|error| db(anyhow!(error).context("committing capture renewal")))
        } else {
            Err(MetadataStoreError::Fenced)
        }
    }

    pub(crate) async fn prepare_capture_completion_claimed(
        &self,
        completion: CaptureCompletion,
        claim: &CaptureClaim,
        lease_seconds: u64,
    ) -> MetadataResult<()> {
        validate_completion(&completion)?;
        if completion.trace_id != claim.trace_id {
            return Err(MetadataStoreError::InvalidInput("capture_claim_mismatch"));
        }
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let prepared: Option<bool> = sqlx::query_scalar(
            "SELECT expected_artifact_size_bytes IS NOT NULL
             FROM captured.traces
             WHERE trace_id=$1 AND capture_status='capturing'
               AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid
               AND capture_fence=$4::uuid AND artifact_commit_id=$5::uuid
               AND claim_lease_expires_at>clock_timestamp() AND organization_id=$6
             FOR UPDATE",
        )
        .bind(&claim.trace_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.claim_fence)
        .bind(&claim.commit_id)
        .bind(claim.organization.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("checking claimed capture preparation")))?;
        let Some(prepared) = prepared else {
            return Err(MetadataStoreError::Fenced);
        };
        if prepared
            && !completion_matches(&mut transaction, &claim.organization, &completion).await?
        {
            return Err(MetadataStoreError::InvalidInput(
                "capture_completion_conflict",
            ));
        }
        let changed = sqlx::query(
            "UPDATE captured.traces SET
                completed_at_unix_ms=$6,duration_ms=$7,http_status=$8,response_bytes=$9,
                response_model=$10,output_preview=$11,output_preview_truncated=$12,
                expected_artifact_size_bytes=$13,expected_artifact_sha256=$14,
                claim_lease_expires_at=clock_timestamp()+make_interval(secs => $15)
             WHERE trace_id=$1 AND capture_status='capturing'
               AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid
               AND capture_fence=$4::uuid AND artifact_commit_id=$5::uuid
               AND claim_lease_expires_at > clock_timestamp() AND evidence_kind=$16
               AND organization_id=$17",
        )
        .bind(&claim.trace_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.claim_fence)
        .bind(&claim.commit_id)
        .bind(invalid_i64(
            completion.completed_at_unix_ms,
            "capture_completed_at_out_of_range",
        )?)
        .bind(invalid_i64(
            completion.duration_ms,
            "duration_out_of_range",
        )?)
        .bind(i32::from(completion.http_status))
        .bind(invalid_i64(
            completion.response_bytes,
            "response_bytes_out_of_range",
        )?)
        .bind(&completion.response_model)
        .bind(&completion.output_preview)
        .bind(completion.output_preview_truncated)
        .bind(invalid_i64(
            completion.expected_artifact_size_bytes,
            "artifact_size_out_of_range",
        )?)
        .bind(&completion.expected_artifact_sha256)
        .bind(lease)
        .bind(completion.evidence_kind.as_str())
        .bind(claim.organization.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("preparing claimed capture")))?
        .rows_affected();
        if changed == 1 {
            transaction.commit().await.map_err(|error| {
                db(anyhow!(error).context("committing claimed capture preparation"))
            })
        } else {
            Err(MetadataStoreError::Fenced)
        }
    }

    pub(crate) async fn complete_capture_claimed(
        &self,
        completion: CaptureCompletion,
        artifact: ArtifactRecord,
        claim: &CaptureClaim,
    ) -> MetadataResult<()> {
        validate_completion(&completion)?;
        validate_artifact(&artifact)?;
        require_artifact(&artifact, &claim.trace_id, completion.artifact_kind())?;
        if artifact.commit_id() != Some(claim.commit_id.as_str()) {
            return Err(MetadataStoreError::InvalidInput("artifact_commit_mismatch"));
        }
        if artifact.size_bytes != completion.expected_artifact_size_bytes
            || artifact.sha256 != completion.expected_artifact_sha256
        {
            return Err(MetadataStoreError::InvalidInput(
                "capture_artifact_mismatch",
            ));
        }
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let changed = sqlx::query(
            "UPDATE captured.traces SET capture_status='captured', failure_code=NULL,
                notarization_status = CASE evidence_kind
                    WHEN 'witnessed' THEN 'succeeded' ELSE notarization_status END
             WHERE trace_id=$1 AND capture_status='capturing'
               AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid
               AND capture_fence=$4::uuid AND artifact_commit_id=$5::uuid
               AND claim_lease_expires_at > clock_timestamp()
               AND expected_artifact_size_bytes=$6 AND expected_artifact_sha256=$7
               AND evidence_kind=$8 AND organization_id=$9",
        )
        .bind(&claim.trace_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.claim_fence)
        .bind(&claim.commit_id)
        .bind(invalid_i64(
            artifact.size_bytes,
            "artifact_size_out_of_range",
        )?)
        .bind(&artifact.sha256)
        .bind(completion.evidence_kind.as_str())
        .bind(claim.organization.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error)))?
        .rows_affected();
        if changed != 1 {
            return Err(MetadataStoreError::Fenced);
        }
        insert_artifact(&mut transaction, &claim.organization, &artifact).await?;
        set_artifact_commit(
            &mut transaction,
            &claim.organization,
            &claim.trace_id,
            completion.artifact_kind(),
            &claim.commit_id,
        )
        .await?;
        index_trace_search(&mut transaction, &claim.organization, &claim.trace_id).await?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error)))
    }

    pub(crate) async fn fail_capture_claimed(
        &self,
        claim: &CaptureClaim,
        failure_code: &str,
    ) -> MetadataResult<()> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let changed = sqlx::query(
            "UPDATE captured.traces SET capture_status='failed',failure_code=$6
             WHERE trace_id=$1 AND capture_status='capturing'
               AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid
               AND capture_fence=$4::uuid AND artifact_commit_id=$5::uuid
               AND claim_lease_expires_at > clock_timestamp() AND organization_id=$7",
        )
        .bind(&claim.trace_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.claim_fence)
        .bind(&claim.commit_id)
        .bind(failure_code)
        .bind(claim.organization.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error)))?
        .rows_affected();
        if changed == 1 {
            transaction
                .commit()
                .await
                .map_err(|error| db(anyhow!(error).context("committing claimed capture failure")))
        } else {
            Err(MetadataStoreError::Fenced)
        }
    }

    pub(crate) async fn claim_next_stale_capture(
        &self,
        identity: &ReplicaIdentity,
        claim_fence: &str,
        lease_seconds: u64,
    ) -> MetadataResult<Option<CaptureRecoveryClaim>> {
        let lease = lease_i32(lease_seconds)?;
        let row = sqlx::query(
            "WITH live_owner AS (
                SELECT instance_id FROM captured.replicas
                WHERE instance_id=$1 AND incarnation_id=$2::uuid
                  AND lease_expires_at>clock_timestamp() FOR UPDATE),
             candidate AS (
                SELECT c.trace_id FROM captured.traces c
                WHERE c.capture_status='capturing' AND c.claim_lease_expires_at <= clock_timestamp()
                ORDER BY c.claim_lease_expires_at,c.trace_id FOR UPDATE SKIP LOCKED LIMIT 1)
             UPDATE captured.traces c SET owner_instance_id=$1,
                owner_incarnation_id=$2::uuid,capture_fence=$3::uuid,
                claim_lease_expires_at=clock_timestamp()+make_interval(secs => $4)
             FROM candidate,live_owner WHERE c.trace_id=candidate.trace_id
             RETURNING c.*,c.artifact_commit_id::text AS commit_id",
        )
        .bind(identity.instance_id())
        .bind(identity.incarnation_id())
        .bind(claim_fence)
        .bind(lease)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("claiming stale capture")))?;
        let Some(row) = row else {
            return Ok(None);
        };
        let trace_id: String = row.try_get("trace_id").map_err(|e| db(e.into()))?;
        let commit_id: String = row.try_get("commit_id").map_err(|e| db(e.into()))?;
        let organization = organization_from_row(&row)?;
        let completion = completion_from_row(&row).map_err(db)?;
        Ok(Some(CaptureRecoveryClaim {
            claim: CaptureClaim {
                organization,
                trace_id,
                owner: identity.clone(),
                claim_fence: claim_fence.to_owned(),
                commit_id,
            },
            completion,
        }))
    }

    pub(crate) async fn claim_next_notarization_claimed(
        &self,
        identity: &ReplicaIdentity,
        claim_fence: &str,
        lease_seconds: u64,
    ) -> MetadataResult<Option<NotarizationClaim>> {
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, identity).await?;
        let row = sqlx::query(
            "WITH moment AS (
                SELECT clock_timestamp() AS ts,
                       floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS unix_ms),
             candidate AS (
                SELECT operation_id FROM captured.operations
                WHERE kind='notarization' AND state='queued'
                ORDER BY created_at_unix_ms,operation_id FOR UPDATE SKIP LOCKED LIMIT 1)
             UPDATE captured.operations o SET state='running',attempt=attempt+1,
                started_at_unix_ms=moment.unix_ms,completed_at_unix_ms=NULL,failure_code=NULL,
                progress_phase='preparing',progress_updated_at_unix_ms=moment.unix_ms,
                proof_bytes_completed=0,proof_bytes_total=0,
                proof_commitments_completed=0,proof_commitments_total=0,
                owner_instance_id=$1,owner_incarnation_id=$2::uuid,claim_fence=$3::uuid,
                artifact_commit_id=$3::uuid,
                claim_lease_expires_at=moment.ts+make_interval(secs => $4)
             FROM candidate,moment WHERE o.operation_id=candidate.operation_id RETURNING o.*",
        )
        .bind(identity.instance_id())
        .bind(identity.incarnation_id())
        .bind(claim_fence)
        .bind(lease)
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("claiming server notarization")))?;
        let Some(row) = row else {
            return release(transaction, None).await;
        };
        let operation = operation_from_row(&row).map_err(db)?;
        let organization = organization_from_row(&row)?;
        let trace_id = &operation.trace_id;
        sqlx::query(
            "UPDATE captured.traces SET notarization_status='running'
             WHERE trace_id=$1 AND organization_id=$2",
        )
        .bind(trace_id)
        .bind(organization.as_str())
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error)))?;
        sqlx::query(
            "INSERT INTO captured.operation_attempts
                (operation_id,attempt,state,started_at_unix_ms,owner_instance_id,owner_incarnation_id,claim_fence)
             VALUES($1,$2,'running',$3,$4,$5::uuid,$6::uuid)",
        ).bind(&operation.operation_id).bind(i32::try_from(operation.attempt).map_err(|e| db(e.into()))?)
          .bind(invalid_i64(operation.started_at_unix_ms.unwrap_or(0), "timestamp_out_of_range")?)
          .bind(identity.instance_id()).bind(identity.incarnation_id()).bind(claim_fence)
          .execute(&mut *transaction).await.map_err(|error| db(anyhow!(error)))?;
        insert_event(
            &mut transaction,
            &organization,
            invalid_i64(
                operation.started_at_unix_ms.unwrap_or(0),
                "timestamp_out_of_range",
            )?,
            "notarization_started",
            Some(trace_id),
            Some(&operation.operation_id),
            "info",
            "Notarization started",
        )
        .await?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        Ok(Some(NotarizationClaim {
            organization,
            operation,
            owner: identity.clone(),
            claim_fence: claim_fence.to_owned(),
            commit_id: claim_fence.to_owned(),
        }))
    }

    pub(crate) async fn renew_notarization_claim(
        &self,
        claim: &NotarizationClaim,
        lease_seconds: u64,
    ) -> MetadataResult<()> {
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let changed = sqlx::query(
            "UPDATE captured.operations SET claim_lease_expires_at=clock_timestamp()+make_interval(secs => $6)
             WHERE operation_id=$1 AND state='running' AND owner_instance_id=$2
               AND owner_incarnation_id=$3::uuid AND claim_fence=$4::uuid
               AND artifact_commit_id=$5::uuid AND claim_lease_expires_at>clock_timestamp()
               AND organization_id=$7",
        ).bind(&claim.operation.operation_id).bind(claim.owner.instance_id()).bind(claim.owner.incarnation_id())
          .bind(&claim.claim_fence).bind(&claim.commit_id).bind(lease).bind(claim.organization.as_str())
          .execute(&mut *transaction).await.map_err(|error| db(anyhow!(error).context("renewing notarization claim")))?.rows_affected();
        if changed == 1 {
            transaction
                .commit()
                .await
                .map_err(|error| db(anyhow!(error).context("committing notarization renewal")))
        } else {
            Err(MetadataStoreError::Fenced)
        }
    }

    pub(crate) async fn update_operation_progress_claimed(
        &self,
        claim: &NotarizationClaim,
        phase: NotarizationPhase,
        now_unix_ms: u64,
        lease_seconds: u64,
    ) -> MetadataResult<bool> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let previous: Option<String> = sqlx::query_scalar(
            "SELECT progress_phase FROM captured.operations WHERE operation_id=$1
               AND state='running' AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid
               AND claim_fence=$4::uuid AND claim_lease_expires_at>clock_timestamp()
               AND organization_id=$5 FOR UPDATE",
        )
        .bind(&claim.operation.operation_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.claim_fence)
        .bind(claim.organization.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error)))?;
        let Some(previous) = previous else {
            return Err(MetadataStoreError::Fenced);
        };
        let changed = previous != phase.as_str();
        sqlx::query("UPDATE captured.operations SET progress_phase=$2,progress_updated_at_unix_ms=$3,claim_lease_expires_at=clock_timestamp()+make_interval(secs => $4) WHERE operation_id=$1 AND organization_id=$5")
            .bind(&claim.operation.operation_id).bind(phase.as_str()).bind(now).bind(lease).bind(claim.organization.as_str())
            .execute(&mut *transaction).await.map_err(|error| db(anyhow!(error)))?;
        if changed {
            let message = match phase.as_str() {
                "proving" => "Generating private proof",
                "signing" => "Requesting notary signature",
                "packaging" => "Building verified package",
                _ => "Notarization advanced",
            };
            insert_event(
                &mut transaction,
                &claim.organization,
                now,
                "notarization_progress",
                Some(&claim.operation.trace_id),
                Some(&claim.operation.operation_id),
                "info",
                message,
            )
            .await?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        Ok(changed)
    }

    pub(crate) async fn update_operation_proof_progress_claimed(
        &self,
        claim: &NotarizationClaim,
        progress: NotarizationProofProgress,
        now_unix_ms: u64,
        lease_seconds: u64,
    ) -> MetadataResult<bool> {
        validate_proof(progress)?;
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        let lease = lease_i32(lease_seconds)?;
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut transaction, &claim.owner).await?;
        let row = sqlx::query(
            "SELECT progress_phase,proof_bytes_completed,proof_bytes_total,
                    proof_commitments_completed,proof_commitments_total
             FROM captured.operations WHERE operation_id=$1 AND state='running'
               AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid
               AND claim_fence=$4::uuid AND claim_lease_expires_at>clock_timestamp()
               AND organization_id=$5 FOR UPDATE",
        )
        .bind(&claim.operation.operation_id)
        .bind(claim.owner.instance_id())
        .bind(claim.owner.incarnation_id())
        .bind(&claim.claim_fence)
        .bind(claim.organization.as_str())
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error)))?;
        let Some(row) = row else {
            return Err(MetadataStoreError::Fenced);
        };
        let old_phase: String = row.try_get("progress_phase").map_err(|e| db(e.into()))?;
        let old_bc = row_u64(&row, "proof_bytes_completed").map_err(db)?;
        let old_bt = row_u64(&row, "proof_bytes_total").map_err(db)?;
        let old_cc = row_u64(&row, "proof_commitments_completed").map_err(db)?;
        let old_ct = row_u64(&row, "proof_commitments_total").map_err(db)?;
        if progress.bytes_completed < old_bc
            || progress.commitments_completed < old_cc
            || (old_bt != 0 && progress.bytes_total != old_bt)
            || (old_ct != 0 && progress.commitments_total != old_ct)
        {
            return Err(MetadataStoreError::InvalidInput("invalid_proof_progress"));
        }
        let changed = old_phase != "proving"
            || old_bc != progress.bytes_completed
            || old_bt != progress.bytes_total
            || old_cc != progress.commitments_completed
            || old_ct != progress.commitments_total;
        sqlx::query("UPDATE captured.operations SET progress_phase='proving',progress_updated_at_unix_ms=$2,proof_bytes_completed=$3,proof_bytes_total=$4,proof_commitments_completed=$5,proof_commitments_total=$6,claim_lease_expires_at=clock_timestamp()+make_interval(secs => $7) WHERE operation_id=$1 AND organization_id=$8")
            .bind(&claim.operation.operation_id).bind(now)
            .bind(i64::try_from(progress.bytes_completed).expect("validated")).bind(i64::try_from(progress.bytes_total).expect("validated"))
            .bind(i64::try_from(progress.commitments_completed).expect("validated")).bind(i64::try_from(progress.commitments_total).expect("validated")).bind(lease).bind(claim.organization.as_str())
            .execute(&mut *transaction).await.map_err(|error| db(anyhow!(error)))?;
        if old_phase != "proving" {
            insert_event(
                &mut transaction,
                &claim.organization,
                now,
                "notarization_progress",
                Some(&claim.operation.trace_id),
                Some(&claim.operation.operation_id),
                "info",
                "Generating private proof",
            )
            .await?;
        }
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        Ok(changed)
    }

    pub(crate) async fn complete_notarization_claimed(
        &self,
        claim: &NotarizationClaim,
        artifact: ArtifactRecord,
        now_unix_ms: u64,
    ) -> MetadataResult<TerminalOperationResult> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        validate_artifact(&artifact)?;
        let trace_id = &claim.operation.trace_id;
        require_artifact(&artifact, trace_id, ArtifactKind::TracePackage)?;
        if artifact.commit_id() != Some(claim.commit_id.as_str()) {
            return Err(MetadataStoreError::InvalidInput("artifact_commit_mismatch"));
        }
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut tx, &claim.owner).await?;
        let row=sqlx::query("SELECT state,claim_fence::text AS claim_fence FROM captured.operations WHERE operation_id=$1 AND organization_id=$2 FOR UPDATE")
            .bind(&claim.operation.operation_id).bind(claim.organization.as_str()).fetch_optional(&mut *tx).await.map_err(|error| db(anyhow!(error)))?;
        let Some(row) = row else {
            return release(tx, TerminalOperationResult::NotFound).await;
        };
        let state: String = row.try_get("state").map_err(|e| db(e.into()))?;
        let stored_fence: Option<String> = row.try_get("claim_fence").map_err(|e| db(e.into()))?;
        if stored_fence.as_deref() != Some(&claim.claim_fence) {
            return Err(MetadataStoreError::Fenced);
        }
        if state == "succeeded" {
            return if artifact_exists_exact(&mut tx, &claim.organization, &artifact).await? {
                Ok(TerminalOperationResult::AlreadyApplied)
            } else {
                Err(MetadataStoreError::Fenced)
            };
        }
        if state != "running" {
            return Err(MetadataStoreError::Fenced);
        }
        let changed=sqlx::query("UPDATE captured.operations SET state='succeeded',completed_at_unix_ms=$5,failure_code=NULL,progress_phase='complete',progress_updated_at_unix_ms=$5 WHERE operation_id=$1 AND state='running' AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid AND claim_fence=$4::uuid AND claim_lease_expires_at>clock_timestamp() AND organization_id=$6")
            .bind(&claim.operation.operation_id).bind(claim.owner.instance_id()).bind(claim.owner.incarnation_id()).bind(&claim.claim_fence).bind(now).bind(claim.organization.as_str())
            .execute(&mut *tx).await.map_err(|error| db(anyhow!(error)))?.rows_affected();
        if changed != 1 {
            return Err(MetadataStoreError::Fenced);
        }
        insert_artifact(&mut tx, &claim.organization, &artifact).await?;
        set_artifact_commit(
            &mut tx,
            &claim.organization,
            trace_id,
            ArtifactKind::TracePackage,
            &claim.commit_id,
        )
        .await?;
        let attempt_changed=sqlx::query("UPDATE captured.operation_attempts a SET state='succeeded',completed_at_unix_ms=$5,failure_code=NULL FROM captured.operations o WHERE a.operation_id=$1 AND a.attempt=$2 AND a.owner_instance_id=$3 AND a.claim_fence=$4::uuid AND o.operation_id=a.operation_id AND o.organization_id=$6")
            .bind(&claim.operation.operation_id).bind(i32::try_from(claim.operation.attempt).map_err(|e| db(e.into()))?).bind(claim.owner.instance_id()).bind(&claim.claim_fence).bind(now).bind(claim.organization.as_str())
            .execute(&mut *tx).await.map_err(|error| db(anyhow!(error)))?.rows_affected();
        if attempt_changed != 1 {
            return Err(db(anyhow!("claimed attempt missing")));
        }
        sqlx::query("UPDATE captured.traces SET notarization_status='succeeded' WHERE trace_id=$1 AND organization_id=$2")
            .bind(trace_id)
            .bind(claim.organization.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|error| db(anyhow!(error)))?;
        insert_event(
            &mut tx,
            &claim.organization,
            now,
            "notarization_completed",
            Some(trace_id),
            Some(&claim.operation.operation_id),
            "success",
            "Notarization completed",
        )
        .await?;
        tx.commit().await.map_err(|error| db(anyhow!(error)))?;
        Ok(TerminalOperationResult::Applied)
    }

    pub(crate) async fn fail_operation_claimed(
        &self,
        claim: &NotarizationClaim,
        now_unix_ms: u64,
        failure_code: &str,
    ) -> MetadataResult<TerminalOperationResult> {
        let now = invalid_i64(now_unix_ms, "timestamp_out_of_range")?;
        let trace_id = &claim.operation.trace_id;
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        lock_live_replica(&mut tx, &claim.owner).await?;
        let changed=sqlx::query("UPDATE captured.operations SET state='failed',completed_at_unix_ms=$5,failure_code=$6 WHERE operation_id=$1 AND state='running' AND owner_instance_id=$2 AND owner_incarnation_id=$3::uuid AND claim_fence=$4::uuid AND claim_lease_expires_at>clock_timestamp() AND organization_id=$7")
            .bind(&claim.operation.operation_id).bind(claim.owner.instance_id()).bind(claim.owner.incarnation_id()).bind(&claim.claim_fence).bind(now).bind(failure_code).bind(claim.organization.as_str())
            .execute(&mut *tx).await.map_err(|error| db(anyhow!(error)))?.rows_affected();
        if changed != 1 {
            return Err(MetadataStoreError::Fenced);
        }
        let attempt_changed=sqlx::query("UPDATE captured.operation_attempts a SET state='failed',completed_at_unix_ms=$5,failure_code=$6 FROM captured.operations o WHERE a.operation_id=$1 AND a.attempt=$2 AND a.owner_instance_id=$3 AND a.claim_fence=$4::uuid AND o.operation_id=a.operation_id AND o.organization_id=$7")
            .bind(&claim.operation.operation_id).bind(i32::try_from(claim.operation.attempt).map_err(|e| db(e.into()))?).bind(claim.owner.instance_id()).bind(&claim.claim_fence).bind(now).bind(failure_code).bind(claim.organization.as_str())
            .execute(&mut *tx).await.map_err(|error| db(anyhow!(error)))?.rows_affected();
        if attempt_changed != 1 {
            return Err(db(anyhow!("claimed attempt missing")));
        }
        sqlx::query("UPDATE captured.traces SET notarization_status='failed' WHERE trace_id=$1 AND organization_id=$2")
            .bind(trace_id)
            .bind(claim.organization.as_str())
            .execute(&mut *tx)
            .await
            .map_err(|error| db(anyhow!(error)))?;
        insert_event(
            &mut tx,
            &claim.organization,
            now,
            "notarization_failed",
            Some(trace_id),
            Some(&claim.operation.operation_id),
            "error",
            "Notarization failed",
        )
        .await?;
        tx.commit().await.map_err(|error| db(anyhow!(error)))?;
        Ok(TerminalOperationResult::Applied)
    }

    pub(crate) async fn interrupt_next_expired_notarization(
        &self,
    ) -> MetadataResult<Option<String>> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error)))?;
        let row=sqlx::query(
            "WITH moment AS (SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS unix_ms),
             candidate AS (SELECT o.operation_id FROM captured.operations o
                WHERE o.state='running' AND o.claim_lease_expires_at<=clock_timestamp()
                ORDER BY o.claim_lease_expires_at,o.operation_id FOR UPDATE SKIP LOCKED LIMIT 1)
             UPDATE captured.operations o SET state='interrupted',completed_at_unix_ms=moment.unix_ms,failure_code='claim_expired'
             FROM candidate,moment WHERE o.operation_id=candidate.operation_id RETURNING o.operation_id,o.trace_id,o.attempt,o.completed_at_unix_ms,o.organization_id",
        ).fetch_optional(&mut *tx).await.map_err(|error| db(anyhow!(error)))?;
        let Some(row) = row else {
            return release(tx, None).await;
        };
        let operation_id: String = row.try_get("operation_id").map_err(|e| db(e.into()))?;
        let trace_id: String = row.try_get("trace_id").map_err(|e| db(e.into()))?;
        let organization = organization_from_row(&row)?;
        let attempt: i32 = row.try_get("attempt").map_err(|e| db(e.into()))?;
        let now: i64 = row
            .try_get("completed_at_unix_ms")
            .map_err(|e| db(e.into()))?;
        sqlx::query("UPDATE captured.operation_attempts SET state='interrupted',completed_at_unix_ms=$3,failure_code='claim_expired' WHERE operation_id=$1 AND attempt=$2 AND state='running'")
            .bind(&operation_id).bind(attempt).bind(now).execute(&mut *tx).await.map_err(|error| db(anyhow!(error)))?;
        sqlx::query(
            "UPDATE captured.traces SET notarization_status='interrupted'
             WHERE trace_id=$1 AND organization_id=$2",
        )
        .bind(&trace_id)
        .bind(organization.as_str())
        .execute(&mut *tx)
        .await
        .map_err(|error| db(anyhow!(error)))?;
        insert_event(
            &mut tx,
            &organization,
            now,
            "notarization_interrupted",
            Some(&trace_id),
            Some(&operation_id),
            "warning",
            "Notarization claim expired",
        )
        .await?;
        tx.commit().await.map_err(|error| db(anyhow!(error)))?;
        Ok(Some(operation_id))
    }

    pub(crate) async fn create_dashboard_session(
        &self,
        token_hash: &[u8; 32],
        created_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> MetadataResult<()> {
        let created = invalid_i64(created_at_unix_ms, "timestamp_out_of_range")?;
        let expires = invalid_i64(expires_at_unix_ms, "timestamp_out_of_range")?;
        let ttl = expires
            .checked_sub(created)
            .ok_or(MetadataStoreError::InvalidInput("invalid_session_expiry"))?;
        if !(1..=86_400_000).contains(&ttl) {
            return Err(MetadataStoreError::InvalidInput("invalid_session_expiry"));
        }
        sqlx::query("WITH moment AS (SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS unix_ms)
             INSERT INTO captured.sessions(token_hash,created_at_unix_ms,expires_at_unix_ms)
             SELECT $1,moment.unix_ms,moment.unix_ms+$2 FROM moment")
            .bind(token_hash.as_slice()).bind(ttl).execute(&self.pool).await
            .map_err(|error| db(anyhow!(error).context("creating dashboard session")))?;
        Ok(())
    }

    pub(crate) async fn dashboard_session_valid(
        &self,
        token_hash: &[u8; 32],
        _now_unix_ms: u64,
    ) -> MetadataResult<bool> {
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM captured.sessions WHERE token_hash=$1 AND to_timestamp(expires_at_unix_ms::double precision/1000.0) > clock_timestamp())")
            .bind(token_hash.as_slice()).fetch_one(&self.pool).await
            .map_err(|error| db(anyhow!(error).context("checking dashboard session")))
    }

    pub(crate) async fn revoke_dashboard_session(
        &self,
        token_hash: &[u8; 32],
    ) -> MetadataResult<()> {
        sqlx::query("DELETE FROM captured.sessions WHERE token_hash=$1")
            .bind(token_hash.as_slice())
            .execute(&self.pool)
            .await
            .map_err(|error| db(anyhow!(error).context("revoking dashboard session")))?;
        Ok(())
    }

    pub(crate) async fn prune_dashboard_sessions(
        &self,
        _now_unix_ms: u64,
        limit: usize,
    ) -> MetadataResult<usize> {
        let limit =
            i64::try_from(limit).map_err(|_| MetadataStoreError::InvalidInput("invalid_limit"))?;
        let affected = sqlx::query("DELETE FROM captured.sessions WHERE token_hash IN (SELECT token_hash FROM captured.sessions WHERE to_timestamp(expires_at_unix_ms::double precision/1000.0) <= clock_timestamp() ORDER BY expires_at_unix_ms LIMIT $1)")
            .bind(limit).execute(&self.pool).await.map_err(|error| db(anyhow!(error).context("pruning dashboard sessions")))?.rows_affected();
        usize::try_from(affected).map_err(|error| db(error.into()))
    }

    pub(crate) async fn pin_registry(
        &self,
        registry: Registry,
        registry_source: &str,
    ) -> MetadataResult<RegistrySnapshot> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| db(anyhow!(error).context("starting Registry transaction")))?;
        let current = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT registry_json FROM captured.registry
             WHERE singleton = TRUE FOR UPDATE",
        )
        .fetch_optional(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("locking shared Registry snapshot")))?
        .map(|bytes| {
            serde_json::from_slice::<RegistrySnapshot>(&bytes)
                .context("parsing shared Registry snapshot")
                .map_err(db)
        })
        .transpose()?;
        let snapshot =
            crate::service::registry::merge_registry_snapshot(current, registry, registry_source)
                .map_err(|error| db(error.context("merging shared Registry snapshot")))?;
        let generation = i64::try_from(snapshot.generation)
            .map_err(|_| MetadataStoreError::InvalidInput("notary_generation_out_of_range"))?;
        let registry_json = serde_json::to_vec(&snapshot)
            .map_err(|error| db(anyhow!(error).context("encoding shared Registry snapshot")))?;
        if registry_json.len() > 1_048_576 {
            return Err(MetadataStoreError::InvalidInput("registry_too_large"));
        }
        sqlx::query(
            "INSERT INTO captured.registry(
                 singleton,generation,registry_sha256,registry_source,active_key_id,registry_json,updated_at)
             VALUES(TRUE,$1,$2,$3,$4,$5,clock_timestamp())
             ON CONFLICT(singleton) DO UPDATE SET
                 generation=excluded.generation,
                 registry_sha256=excluded.registry_sha256,
                 registry_source=excluded.registry_source,
                 active_key_id=excluded.active_key_id,
                 registry_json=excluded.registry_json,
                 updated_at=clock_timestamp()",
        )
        .bind(generation)
        .bind(&snapshot.registry_sha256)
        .bind(&snapshot.registry_source)
        .bind(&snapshot.active_key_id)
        .bind(&registry_json)
        .execute(&mut *transaction)
        .await
        .map_err(|error| db(anyhow!(error).context("storing shared Registry snapshot")))?;
        transaction
            .commit()
            .await
            .map_err(|error| db(anyhow!(error).context("committing shared Registry snapshot")))?;
        Ok(snapshot)
    }

    pub(crate) async fn registry_snapshot(&self) -> MetadataResult<Option<RegistrySnapshot>> {
        let value = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT registry_json FROM captured.registry WHERE singleton = TRUE",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| db(anyhow!(error).context("reading shared Registry snapshot")))?
        .map(|bytes| {
            serde_json::from_slice::<RegistrySnapshot>(&bytes)
                .context("parsing shared Registry snapshot")
                .and_then(|snapshot| {
                    crate::service::registry::validate_registry_snapshot(&snapshot)?;
                    Ok(snapshot)
                })
                .map_err(db)
        })
        .transpose()?;
        Ok(value)
    }
}

fn push_event_filters<'a>(query: &mut QueryBuilder<'a, Postgres>, filters: &'a EventFilters) {
    for (column, value) in [
        ("severity", filters.severity.as_deref()),
        ("event_type", filters.event_type.as_deref()),
        ("trace_id", filters.trace_id.as_deref()),
        ("operation_id", filters.operation_id.as_deref()),
    ] {
        if let Some(value) = value {
            query
                .push(" AND ")
                .push(column)
                .push(" = ")
                .push_bind(value);
        }
    }
    if let Some(created_after) = filters.created_after_unix_ms {
        query
            .push(" AND created_at_unix_ms >= ")
            .push_bind(i64::try_from(created_after).expect("validated event position"));
    }
}

fn lease_i32(value: u64) -> MetadataResult<i32> {
    if !(1..=300).contains(&value) {
        return Err(MetadataStoreError::InvalidInput("invalid_server_lease"));
    }
    i32::try_from(value).map_err(|_| MetadataStoreError::InvalidInput("invalid_server_lease"))
}

async fn lock_live_replica(
    transaction: &mut sqlx::Transaction<'_, Postgres>,
    identity: &ReplicaIdentity,
) -> MetadataResult<()> {
    let live = sqlx::query_scalar::<_, String>(
        "SELECT instance_id FROM captured.replicas
         WHERE instance_id=$1 AND incarnation_id=$2::uuid
           AND lease_expires_at>clock_timestamp()
         FOR UPDATE",
    )
    .bind(identity.instance_id())
    .bind(identity.incarnation_id())
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| db(anyhow!(error).context("locking live cluster replica")))?;
    if live.is_some() {
        Ok(())
    } else {
        Err(MetadataStoreError::Fenced)
    }
}

/// The organization of a claimed Trace or operation row.
fn organization_from_row(row: &PgRow) -> MetadataResult<OrganizationId> {
    let organization: String = row
        .try_get("organization_id")
        .map_err(|error| db(anyhow!(error)))?;
    OrganizationId::parse(organization)
        .map_err(|_| db(anyhow!("stored organization identifier is invalid")))
}

fn completion_from_row(row: &PgRow) -> anyhow::Result<Option<CaptureCompletion>> {
    let Some(completed_at_unix_ms) = row_optional_u64(row, "completed_at_unix_ms")? else {
        return Ok(None);
    };
    let (
        Some(duration_ms),
        Some(http_status),
        Some(response_bytes),
        Some(expected_size),
        Some(expected_sha),
    ) = (
        row_optional_u64(row, "duration_ms")?,
        row.try_get::<Option<i32>, _>("http_status")?,
        row_optional_u64(row, "response_bytes")?,
        row_optional_u64(row, "expected_artifact_size_bytes")?,
        row.try_get::<Option<String>, _>("expected_artifact_sha256")?,
    )
    else {
        return Ok(None);
    };
    Ok(Some(CaptureCompletion {
        trace_id: row.try_get("trace_id")?,
        completed_at_unix_ms,
        duration_ms,
        http_status: u16::try_from(http_status)?,
        response_bytes,
        response_model: row.try_get("response_model")?,
        output_preview: row.try_get("output_preview")?,
        output_preview_truncated: row.try_get("output_preview_truncated")?,
        expected_artifact_size_bytes: expected_size,
        expected_artifact_sha256: expected_sha,
        evidence_kind: stored_evidence_kind(row)?,
    }))
}

/// Disposable PostgreSQL for tests that need a server-mode store.
#[cfg(test)]
pub(crate) mod test_postgres {
    use std::{sync::Arc, time::Duration};

    use sqlx::{PgPool, postgres::PgPoolOptions};
    use testcontainers_modules::{
        postgres::Postgres,
        testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner},
    };

    use super::{PostgresMetadataStore, configure_cluster_compatibility, migrate_database};
    use crate::config::PostgresSslMode;

    pub(crate) struct TestPostgres {
        pub(crate) admin: PgPool,
        pub(crate) base_url: String,
        _server: Arc<ContainerAsync<Postgres>>,
    }

    impl TestPostgres {
        pub(crate) async fn start() -> Self {
            let server = Arc::new(
                Postgres::default()
                    .with_tag("17.7-alpine")
                    .start()
                    .await
                    .expect("start PostgreSQL 17 test container"),
            );
            let host = server.get_host().await.expect("PostgreSQL test host");
            let port = server
                .get_host_port_ipv4(5432)
                .await
                .expect("PostgreSQL test port");
            let base_url = format!("postgres://postgres:postgres@{host}:{port}");
            let admin = PgPoolOptions::new()
                .max_connections(10)
                .connect(&format!("{base_url}/postgres"))
                .await
                .expect("connect to PostgreSQL test server");
            Self {
                admin,
                base_url,
                _server: server,
            }
        }

        pub(crate) async fn create_database(&self, name: &str) -> String {
            assert!(
                name.chars()
                    .all(|character| character.is_ascii_alphanumeric() || character == '_')
            );
            sqlx::query(&format!("CREATE DATABASE {name}"))
                .execute(&self.admin)
                .await
                .expect("create isolated daemon test database");
            format!("{}/{name}", self.base_url)
        }
    }

    /// A migrated database for replicas with `compatibility`, opened in
    /// server mode.
    pub(crate) async fn server_store(
        server: &TestPostgres,
        name: &str,
        compatibility: &str,
    ) -> PostgresMetadataStore {
        let url = server.create_database(name).await;
        migrate_database(
            &url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .expect("migrate server test database");
        configure_cluster_compatibility(
            &url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            compatibility,
        )
        .await
        .expect("configure server test compatibility");
        PostgresMetadataStore::connect_server(
            &url,
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
            PostgresSslMode::Disable,
            true,
        )
        .await
        .expect("open server test store")
    }
}

#[cfg(test)]
mod tests {
    const TEST_SERVER_COMPATIBILITY: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    use std::{sync::Arc, time::Duration};

    use sqlx::{Connection as _, PgConnection, postgres::PgPoolOptions};
    use tokio::sync::Barrier;

    use crate::{
        NotarizationPhase,
        artifact_store::{ArtifactKind, ArtifactLocator},
        config::PostgresSslMode,
        metadata::{CaptureMode, EventFilters},
        metadata::{NewTrace, TerminalOperationResult, TraceFilters},
        metadata_store::{
            CaptureClaim, MetadataStore, MetadataStoreError, ReplicaIdentity, conformance,
        },
        organization::OrganizationId,
        registry::{
            NotaryKeyStatus, NotaryTransport, REGISTRY_FORMAT, Registry, RegistryRecord, key_id,
        },
    };

    use super::{
        MIGRATION_LOCK_NAMESPACE, MIGRATIONS, PostgresMetadataStore,
        configure_cluster_compatibility, migrate_database, migrate_database_through,
        test_postgres::TestPostgres,
    };

    fn organization(value: &str) -> OrganizationId {
        OrganizationId::parse(value).unwrap()
    }

    /// A replica registered on a store configured with
    /// `TEST_SERVER_COMPATIBILITY`.
    async fn live_replica(store: &PostgresMetadataStore, name: &str) -> ReplicaIdentity {
        let replica = ReplicaIdentity::new(name).unwrap();
        store
            .register_replica(&replica, TEST_SERVER_COMPATIBILITY, 30)
            .await
            .unwrap();
        replica
    }

    /// Records one completed capture for `organization` through `replica`'s
    /// claimed writes, as a server replica does.
    async fn completed_capture(
        store: &PostgresMetadataStore,
        replica: &ReplicaIdentity,
        organization: &OrganizationId,
        trace_id: &str,
        created_at_unix_ms: u64,
    ) {
        let claim = CaptureClaim::new(organization.clone(), trace_id, replica.clone());
        store
            .begin_capture_claimed(
                conformance::new_capture(trace_id, created_at_unix_ms),
                &claim,
                30,
            )
            .await
            .unwrap();
        let mut checkpoint = conformance::artifact(trace_id, ArtifactKind::CaptureCheckpoint, 1);
        checkpoint.locator = ArtifactLocator::from_stored("artifact/v1/s3/Y2hlY2twb2ludA").unwrap();
        let checkpoint = checkpoint.with_commit_id(&claim.commit_id).unwrap();
        let mut completion = conformance::completion(trace_id, created_at_unix_ms + 1, 200);
        completion.expected_artifact_size_bytes = checkpoint.size_bytes;
        completion.expected_artifact_sha256 = checkpoint.sha256.clone();
        store
            .prepare_capture_completion_claimed(completion.clone(), &claim, 30)
            .await
            .unwrap();
        store
            .complete_capture_claimed(completion, checkpoint, &claim)
            .await
            .unwrap();
    }

    /// Everything one organization can read back from its metadata view.
    async fn snapshot(
        store: &dyn MetadataStore,
    ) -> (
        Vec<crate::metadata::TraceSummary>,
        Vec<crate::metadata::Operation>,
        crate::metadata::EventSnapshot,
        crate::metadata::MetadataCounts,
        CaptureMode,
    ) {
        let traces = store
            .traces(TraceFilters {
                limit: 201,
                ..TraceFilters::default()
            })
            .await
            .unwrap();
        let operations = store
            .operations(crate::metadata::OperationFilters {
                limit: 201,
                ..Default::default()
            })
            .await
            .unwrap();
        let events = store
            .events_snapshot(EventFilters {
                limit: 201,
                ..EventFilters::default()
            })
            .await
            .unwrap();
        (
            traces,
            operations,
            events,
            store.counts().await.unwrap(),
            store.capture_mode().await.unwrap(),
        )
    }

    /// One organization can neither see nor change another's metadata, with
    /// every row written through a replica's claimed writes.
    async fn organizations_are_isolated(store: &PostgresMetadataStore, full_text_search: bool) {
        let replica = live_replica(store, "isolation-replica").await;
        let first_org = organization("acct-first");
        let first = store.organization(&first_org);
        let second = store.organization(&organization("acct-second"));

        // The first organization has a failed, a running and a queued
        // notarization, an active capture and its own capture mode.
        let (failed, running, queued, active) = (
            "trc-org-first-failed",
            "trc-org-first-running",
            "trc-org-first-queued",
            "trc-org-first-active",
        );
        for (index, id) in [failed, running, queued].into_iter().enumerate() {
            completed_capture(store, &replica, &first_org, id, index as u64 * 2 + 1).await;
        }
        let active_claim = CaptureClaim::new(first_org.clone(), active, replica.clone());
        store
            .begin_capture_claimed(conformance::new_capture(active, 7), &active_claim, 30)
            .await
            .unwrap();
        let claim_next = async |id: &str, now: u64| {
            first.enqueue_notarization(id, now).await.unwrap().unwrap();
            let claim = store
                .claim_next_notarization_claimed(&replica, &uuid::Uuid::new_v4().to_string(), 30)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(claim.operation.trace_id, id);
            assert_eq!(claim.organization, first_org);
            claim
        };
        let failed_claim = claim_next(failed, 8).await;
        store
            .fail_operation_claimed(&failed_claim, 9, "fixture_failure")
            .await
            .unwrap();
        let running_claim = claim_next(running, 10).await;
        let queued_operation = first
            .enqueue_notarization(queued, 11)
            .await
            .unwrap()
            .unwrap()
            .0;
        first.set_capture_mode(CaptureMode::Off, 12).await.unwrap();
        let before = snapshot(first.as_ref()).await;
        assert_eq!(before.0.len(), 4);
        assert_eq!(before.1.len(), 3);
        assert!(!before.2.events.is_empty());
        if full_text_search {
            let found = first
                .traces(TraceFilters {
                    query: Some("quarterly".to_owned()),
                    limit: 20,
                    ..TraceFilters::default()
                })
                .await
                .unwrap();
            assert_eq!(found.len(), 3, "completed captures are searchable");
        }

        // The second organization sees none of it, with default settings.
        let (traces, operations, events, counts, mode) = snapshot(second.as_ref()).await;
        assert!(traces.is_empty() && operations.is_empty() && events.events.is_empty());
        assert_eq!(events.high_water, None);
        assert_eq!(counts, crate::metadata::MetadataCounts::default());
        assert_eq!(mode, CaptureMode::Notarized);
        for id in [failed, running, queued, active] {
            assert!(second.trace(id).await.unwrap().is_none());
            assert!(second.artifacts(id).await.unwrap().is_empty());
            assert!(second.trace_share(id).await.unwrap().is_none());
        }
        for operation in [
            &failed_claim.operation,
            &running_claim.operation,
            &queued_operation,
        ] {
            assert!(
                second
                    .operation(&operation.operation_id)
                    .await
                    .unwrap()
                    .is_none()
            );
            assert!(
                second
                    .operation_attempts(&operation.operation_id)
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        if full_text_search {
            assert!(
                second
                    .traces(TraceFilters {
                        query: Some("quarterly".to_owned()),
                        limit: 20,
                        ..TraceFilters::default()
                    })
                    .await
                    .unwrap()
                    .is_empty()
            );
        }

        // Nor can the second organization change any of it.
        for id in [failed, queued] {
            assert!(second.enqueue_notarization(id, 13).await.unwrap().is_none());
        }
        second
            .set_capture_mode(CaptureMode::Witnessed, 14)
            .await
            .unwrap();
        assert_eq!(snapshot(first.as_ref()).await, before);

        // The second organization's own work stays its own.
        let second_org = organization("acct-second");
        let own = "trc-org-second";
        completed_capture(store, &replica, &second_org, own, 30).await;
        let own_operation = second
            .enqueue_notarization(own, 32)
            .await
            .unwrap()
            .unwrap()
            .0;
        let (traces, operations, events, counts, mode) = snapshot(second.as_ref()).await;
        assert_eq!(traces.len(), 1);
        assert_eq!(traces[0].trace_id, own);
        assert_eq!(operations, vec![own_operation.clone()]);
        assert_eq!(mode, CaptureMode::Witnessed);
        assert_eq!(counts.captured, 1);
        assert_eq!(counts.notarizing, 1);
        let first_event_ids = before
            .2
            .events
            .iter()
            .map(|event| event.event_id)
            .collect::<std::collections::HashSet<_>>();
        assert!(events.events.iter().all(|event| {
            event.trace_id.as_deref().is_none_or(|trace| trace == own)
                && !first_event_ids.contains(&event.event_id)
        }));
        assert!(first.trace(own).await.unwrap().is_none());
        assert!(
            first
                .operation(&own_operation.operation_id)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(snapshot(first.as_ref()).await, before);
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL 17 container"]
    async fn organizations_are_isolated_with_search_enabled_and_disabled() {
        let server = TestPostgres::start().await;
        for (name, full_text_search) in [("daemon_orgs_fts", true), ("daemon_orgs_plain", false)] {
            let store =
                super::test_postgres::server_store(&server, name, TEST_SERVER_COMPATIBILITY).await;
            let store = PostgresMetadataStore::from_pool(store.pool.clone(), full_text_search)
                .await
                .unwrap();
            organizations_are_isolated(&store, full_text_search).await;
        }
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL 17 container"]
    async fn server_replica_fencing_and_hashed_sessions() {
        let server = TestPostgres::start().await;
        let url = server.create_database("daemon_server").await;
        migrate_database(
            &url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        configure_cluster_compatibility(
            &url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            TEST_SERVER_COMPATIBILITY,
        )
        .await
        .unwrap();
        let store = PostgresMetadataStore::connect_server(
            &url,
            8,
            Duration::from_secs(5),
            Duration::from_secs(5),
            PostgresSslMode::Disable,
            true,
        )
        .await
        .unwrap();
        let first = ReplicaIdentity::new("daemon-a").unwrap();
        let collision = ReplicaIdentity::new("daemon-a").unwrap();
        store
            .register_replica(&first, TEST_SERVER_COMPATIBILITY, 20)
            .await
            .unwrap();
        let incompatible = ReplicaIdentity::new("daemon-incompatible").unwrap();
        assert!(matches!(
            store
                .register_replica(&incompatible, &"1".repeat(64), 20)
                .await,
            Err(MetadataStoreError::InvalidInput(
                "server_compatibility_mismatch"
            ))
        ));
        assert!(matches!(
            store
                .register_replica(&collision, TEST_SERVER_COMPATIBILITY, 20)
                .await,
            Err(MetadataStoreError::InvalidInput(
                "live_instance_id_collision"
            ))
        ));

        // Claims span organizations and each reports its own.
        let org = organization("acct-fencing");
        let other_org = organization("acct-other");
        let org_store = store.organization_store(&org);
        let other_store = store.organization_store(&other_org);
        let trace_id = "trc-server-fencing";
        let other_trace_id = "trc-server-other";
        let original = CaptureClaim::new(org.clone(), trace_id, first.clone());
        store
            .begin_capture_claimed(
                NewTrace {
                    evidence_kind: crate::metadata::EvidenceKind::Notarized,
                    trace_id: trace_id.into(),
                    created_at_unix_ms: 1,
                    provider: "openai".into(),
                    operation: "/v1/responses".into(),
                    requested_model: Some("gpt-test".into()),
                    streaming: false,
                    request_bytes: 1,
                    prompt_preview: "safe".into(),
                    prompt_preview_truncated: false,
                    config_fingerprint: "sha256:test".into(),
                },
                &original,
                20,
            )
            .await
            .unwrap();
        let other_original = CaptureClaim::new(other_org.clone(), other_trace_id, first.clone());
        store
            .begin_capture_claimed(
                conformance::new_capture(other_trace_id, 2),
                &other_original,
                20,
            )
            .await
            .unwrap();
        assert!(org_store.trace(other_trace_id).await.unwrap().is_none());
        assert!(other_store.trace(trace_id).await.unwrap().is_none());
        let foreign_capture = CaptureClaim {
            organization: other_org.clone(),
            ..original.clone()
        };
        assert!(matches!(
            store.renew_capture_claim(&foreign_capture, 20).await,
            Err(MetadataStoreError::Fenced)
        ));
        assert!(matches!(
            store
                .fail_capture_claimed(&foreign_capture, "foreign_owner")
                .await,
            Err(MetadataStoreError::Fenced)
        ));
        sqlx::query("UPDATE captured.traces SET claim_lease_expires_at=clock_timestamp()-interval '1 second' WHERE trace_id IN ($1, $2)")
            .bind(trace_id).bind(other_trace_id).execute(&store.pool).await.unwrap();
        sqlx::query("UPDATE captured.replicas SET lease_expires_at=clock_timestamp()-interval '1 second' WHERE instance_id=$1")
            .bind(first.instance_id()).execute(&store.pool).await.unwrap();
        store
            .register_replica(&collision, TEST_SERVER_COMPATIBILITY, 20)
            .await
            .unwrap();
        let mut recoveries = Vec::new();
        for _ in 0..2 {
            recoveries.push(
                store
                    .claim_next_stale_capture(&collision, &uuid::Uuid::new_v4().to_string(), 20)
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        assert!(
            store
                .claim_next_stale_capture(&collision, &uuid::Uuid::new_v4().to_string(), 20)
                .await
                .unwrap()
                .is_none()
        );
        recoveries.sort_by(|left, right| left.claim.trace_id.cmp(&right.claim.trace_id));
        let other_recovered = recoveries.pop().unwrap();
        let recovered = recoveries.pop().unwrap();
        assert_eq!(recovered.claim.trace_id, trace_id);
        assert_eq!(recovered.claim.organization, org);
        assert_eq!(recovered.claim.commit_id, original.commit_id);
        assert_eq!(other_recovered.claim.trace_id, other_trace_id);
        assert_eq!(other_recovered.claim.organization, other_org);
        store
            .fail_capture_claimed(&other_recovered.claim, "claim_expired")
            .await
            .unwrap();
        assert_eq!(
            other_store
                .trace(other_trace_id)
                .await
                .unwrap()
                .unwrap()
                .capture_status,
            "failed"
        );
        assert!(matches!(
            store.renew_capture_claim(&original, 20).await,
            Err(MetadataStoreError::Fenced)
        ));

        let mut checkpoint = conformance::artifact(trace_id, ArtifactKind::CaptureCheckpoint, 2);
        checkpoint.locator = ArtifactLocator::from_stored(
            "artifact/v1/s3/Y2x1c3Rlci1jYXB0dXJlLWRlZmVycmVkLWJ1bmRsZQ",
        )
        .unwrap();
        let checkpoint = checkpoint
            .with_commit_id(&recovered.claim.commit_id)
            .unwrap();
        let mut completion = conformance::completion(trace_id, 9, 200);
        completion.expected_artifact_size_bytes = checkpoint.size_bytes;
        completion.expected_artifact_sha256 = checkpoint.sha256.clone();
        assert!(matches!(
            store
                .prepare_capture_completion_claimed(completion.clone(), &original, 20)
                .await,
            Err(MetadataStoreError::Fenced)
        ));
        assert!(matches!(
            store
                .complete_capture_claimed(completion.clone(), checkpoint.clone(), &original)
                .await,
            Err(MetadataStoreError::Fenced)
        ));
        assert!(matches!(
            store.fail_capture_claimed(&original, "stale_owner").await,
            Err(MetadataStoreError::Fenced)
        ));
        store
            .prepare_capture_completion_claimed(completion.clone(), &recovered.claim, 20)
            .await
            .unwrap();
        store
            .complete_capture_claimed(completion, checkpoint, &recovered.claim)
            .await
            .unwrap();

        assert_eq!(
            org_store
                .trace(trace_id)
                .await
                .unwrap()
                .unwrap()
                .capture_status,
            "captured"
        );
        assert_eq!(org_store.artifacts(trace_id).await.unwrap().len(), 1);
        let (operation, _) = org_store
            .enqueue_notarization(trace_id, 10)
            .await
            .unwrap()
            .unwrap();
        let second = ReplicaIdentity::new("daemon-b").unwrap();
        store
            .register_replica(&second, TEST_SERVER_COMPATIBILITY, 20)
            .await
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let first_contender = {
            let store = store.clone();
            let identity = collision.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .claim_next_notarization_claimed(
                        &identity,
                        &uuid::Uuid::new_v4().to_string(),
                        20,
                    )
                    .await
            })
        };
        let second_contender = {
            let store = store.clone();
            let identity = second.clone();
            let barrier = barrier.clone();
            tokio::spawn(async move {
                barrier.wait().await;
                store
                    .claim_next_notarization_claimed(
                        &identity,
                        &uuid::Uuid::new_v4().to_string(),
                        20,
                    )
                    .await
            })
        };
        let first_claim = first_contender.await.unwrap().unwrap();
        let second_claim = second_contender.await.unwrap().unwrap();
        assert_eq!(
            usize::from(first_claim.is_some()) + usize::from(second_claim.is_some()),
            1
        );
        let old_notarization = first_claim.or(second_claim).unwrap();
        assert_eq!(
            old_notarization.operation.operation_id,
            operation.operation_id
        );
        assert_eq!(old_notarization.organization, org);
        let foreign_notarization = crate::metadata_store::NotarizationClaim {
            organization: other_org.clone(),
            ..old_notarization.clone()
        };
        assert!(matches!(
            store
                .update_operation_progress_claimed(
                    &foreign_notarization,
                    NotarizationPhase::Proving,
                    11,
                    20,
                )
                .await,
            Err(MetadataStoreError::Fenced)
        ));
        assert!(matches!(
            store
                .renew_notarization_claim(&foreign_notarization, 20)
                .await,
            Err(MetadataStoreError::Fenced)
        ));
        assert!(
            store
                .update_operation_progress_claimed(
                    &old_notarization,
                    NotarizationPhase::Signing,
                    11,
                    20,
                )
                .await
                .unwrap()
        );
        sqlx::query("UPDATE captured.operations SET claim_lease_expires_at=clock_timestamp()-interval '1 second' WHERE operation_id=$1")
            .bind(&operation.operation_id).execute(&store.pool).await.unwrap();
        assert_eq!(
            store.interrupt_next_expired_notarization().await.unwrap(),
            Some(operation.operation_id.clone())
        );
        assert!(
            store
                .interrupt_next_expired_notarization()
                .await
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            store
                .update_operation_progress_claimed(
                    &old_notarization,
                    NotarizationPhase::Packaging,
                    12,
                    20,
                )
                .await,
            Err(MetadataStoreError::Fenced)
        ));
        let mut stale_package = conformance::artifact(trace_id, ArtifactKind::TracePackage, 3);
        stale_package.locator = ArtifactLocator::from_stored(
            "artifact/v1/s3/Y2x1c3Rlci1jYXB0dXJlLWZpbmFsaXplZC1wYWNrYWdl",
        )
        .unwrap();
        let stale_package = stale_package
            .with_commit_id(&old_notarization.commit_id)
            .unwrap();
        assert!(matches!(
            store
                .complete_notarization_claimed(&old_notarization, stale_package, 13)
                .await,
            Err(MetadataStoreError::Fenced)
        ));
        assert!(matches!(
            store
                .fail_operation_claimed(&old_notarization, 13, "stale_failure")
                .await,
            Err(MetadataStoreError::Fenced)
        ));
        assert!(
            other_store
                .enqueue_notarization(&operation.trace_id, 13)
                .await
                .unwrap()
                .is_none()
        );
        org_store
            .enqueue_notarization(&operation.trace_id, 13)
            .await
            .unwrap()
            .unwrap();
        let retry_owner = if old_notarization.owner == collision {
            second.clone()
        } else {
            collision.clone()
        };
        let winner = store
            .claim_next_notarization_claimed(&retry_owner, &uuid::Uuid::new_v4().to_string(), 20)
            .await
            .unwrap()
            .unwrap();
        assert_ne!(winner.claim_fence, old_notarization.claim_fence);
        assert_eq!(winner.organization, org);
        assert_eq!(
            store
                .fail_operation_claimed(&winner, 14, "test_failure")
                .await
                .unwrap(),
            TerminalOperationResult::Applied
        );
        // Every event a claimed transition wrote belongs to the claim's
        // organization.
        let all_events = EventFilters {
            limit: 201,
            ..EventFilters::default()
        };
        let org_events = org_store
            .events_snapshot(all_events.clone())
            .await
            .unwrap()
            .events;
        for event_type in [
            "notarization_queued",
            "notarization_started",
            "notarization_progress",
            "notarization_interrupted",
            "notarization_failed",
        ] {
            assert!(
                org_events
                    .iter()
                    .any(|event| event.event_type == event_type),
                "{event_type}"
            );
        }
        assert!(
            org_events
                .iter()
                .all(|event| event.trace_id.as_deref() == Some(trace_id))
        );
        for organization in [&other_org, &crate::persistence::default_organization()] {
            assert!(
                store
                    .organization_store(organization)
                    .events_snapshot(all_events.clone())
                    .await
                    .unwrap()
                    .events
                    .is_empty()
            );
        }

        let token_hash = [7_u8; 32];
        store
            .create_dashboard_session(&token_hash, 1, 60_001)
            .await
            .unwrap();
        assert!(store.dashboard_session_valid(&token_hash, 0).await.unwrap());
        let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM captured.sessions")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(stored, token_hash);

        let expired_token_hash = [8_u8; 32];
        store
            .create_dashboard_session(&expired_token_hash, 0, 1_000)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE captured.sessions SET created_at_unix_ms=0, expires_at_unix_ms=1 WHERE token_hash=$1",
        )
        .bind(expired_token_hash.as_slice())
        .execute(&store.pool)
        .await
        .unwrap();
        assert!(
            !store
                .dashboard_session_valid(&expired_token_hash, 0)
                .await
                .unwrap()
        );
        assert_eq!(store.prune_dashboard_sessions(0, 10).await.unwrap(), 1);
        let expired_stored: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM captured.sessions WHERE token_hash=$1)",
        )
        .bind(expired_token_hash.as_slice())
        .fetch_one(&store.pool)
        .await
        .unwrap();
        assert!(!expired_stored);
        assert!(store.dashboard_session_valid(&token_hash, 0).await.unwrap());
        store.revoke_dashboard_session(&token_hash).await.unwrap();
        assert!(!store.dashboard_session_valid(&token_hash, 0).await.unwrap());

        let registry_record = |seed: u8| {
            let signing = k256::ecdsa::SigningKey::from_slice(&[seed; 32]).unwrap();
            let public_key = signing.verifying_key().to_sec1_bytes().to_vec();
            RegistryRecord {
                name: format!("Notary {seed}"),
                operator: "Test operator".to_owned(),
                host: "notary.example".into(),
                port: 7047,
                transport: NotaryTransport::Tcp,
                key_id: key_id(&public_key),
                public_key: hex::encode(public_key),
                status: NotaryKeyStatus::Active,
                valid_from_unix_ms: 0,
                valid_until_unix_ms: None,
                notarize_until_unix_ms: None,
            }
        };
        let old = registry_record(9);
        let new = registry_record(10);
        let source = "https://api.example/api/registry";
        let first_registry = Registry {
            format: REGISTRY_FORMAT.into(),
            generation: 1,
            active_key_id: old.key_id.clone(),
            notaries: vec![old.clone()],
        };
        store
            .pin_registry(first_registry.clone(), source)
            .await
            .unwrap();
        let second_registry = Registry {
            format: REGISTRY_FORMAT.into(),
            generation: 2,
            active_key_id: new.key_id.clone(),
            notaries: vec![new.clone()],
        };
        let updated = store
            .pin_registry(second_registry.clone(), source)
            .await
            .unwrap();
        assert_eq!(updated.generation, 2);
        assert_eq!(
            updated
                .records
                .iter()
                .find(|record| record.key_id == old.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Retired
        );

        let replayed = store
            .pin_registry(second_registry.clone(), source)
            .await
            .unwrap();
        assert_eq!(replayed.generation, updated.generation);
        assert_eq!(replayed.registry_sha256, updated.registry_sha256);
        assert_eq!(replayed.registry_source, updated.registry_source);
        assert_eq!(
            replayed
                .records
                .iter()
                .find(|record| record.key_id == old.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Retired
        );

        let mirror_source = "https://mirror.example/api/registry";
        assert!(
            store
                .pin_registry(second_registry.clone(), mirror_source)
                .await
                .is_err()
        );
        let source_unchanged = store.registry_snapshot().await.unwrap().unwrap();
        assert_eq!(source_unchanged.generation, updated.generation);
        assert_eq!(source_unchanged.registry_sha256, updated.registry_sha256);
        assert_eq!(source_unchanged.registry_source, source);
        assert_eq!(
            source_unchanged
                .records
                .iter()
                .find(|record| record.key_id == old.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Retired
        );

        let mut conflicting_new = new.clone();
        conflicting_new.host = "conflict.example".into();
        assert!(
            store
                .pin_registry(
                    Registry {
                        format: REGISTRY_FORMAT.into(),
                        generation: 2,
                        active_key_id: conflicting_new.key_id.clone(),
                        notaries: vec![conflicting_new],
                    },
                    source,
                )
                .await
                .is_err()
        );
        assert!(store.pin_registry(first_registry, source).await.is_err());

        let mut revoked_old = old.clone();
        revoked_old.status = NotaryKeyStatus::Revoked;
        let revoked = store
            .pin_registry(
                Registry {
                    format: REGISTRY_FORMAT.into(),
                    generation: 3,
                    active_key_id: new.key_id.clone(),
                    notaries: vec![new.clone(), revoked_old],
                },
                source,
            )
            .await
            .unwrap();
        assert_eq!(
            revoked
                .records
                .iter()
                .find(|record| record.key_id == old.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Revoked
        );
        let mut attempted_restore = old.clone();
        attempted_restore.status = NotaryKeyStatus::Retired;
        let non_resurrected = store
            .pin_registry(
                Registry {
                    format: REGISTRY_FORMAT.into(),
                    generation: 4,
                    active_key_id: new.key_id.clone(),
                    notaries: vec![new, attempted_restore],
                },
                source,
            )
            .await
            .unwrap();
        assert_eq!(
            non_resurrected
                .records
                .iter()
                .find(|record| record.key_id == old.key_id)
                .unwrap()
                .status,
            NotaryKeyStatus::Revoked
        );
        assert_eq!(
            store.registry_snapshot().await.unwrap().unwrap().generation,
            4
        );
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL 17 container"]
    async fn migration_is_explicit_isolated_idempotent_and_lock_bounded() {
        let server = TestPostgres::start().await;
        let blank_url = server.create_database("daemon_blank").await;
        assert!(
            PostgresMetadataStore::connect_server(
                &blank_url,
                2,
                Duration::from_secs(5),
                Duration::from_secs(5),
                PostgresSslMode::Disable,
                true,
            )
            .await
            .is_err(),
            "runtime construction must not auto-migrate"
        );
        assert!(
            migrate_database(
                &blank_url,
                PostgresSslMode::Disable,
                Duration::from_secs(5),
                Duration::ZERO,
            )
            .await
            .is_err()
        );
        assert!(
            migrate_database(
                &blank_url,
                PostgresSslMode::Disable,
                Duration::ZERO,
                Duration::from_secs(5),
            )
            .await
            .is_err()
        );

        migrate_database(
            &blank_url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .expect("apply isolated daemon migration");
        migrate_database(
            &blank_url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .expect("daemon migration is idempotent");
        let pool = PgPoolOptions::new()
            .connect(&blank_url)
            .await
            .expect("open migrated test database");
        let daemon_journal: bool =
            sqlx::query_scalar("SELECT to_regclass('captured.schema_migrations') IS NOT NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        let hosted_journal: bool =
            sqlx::query_scalar("SELECT to_regclass('public._sqlx_migrations') IS NOT NULL")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert!(daemon_journal);
        assert!(!hosted_journal);

        sqlx::query("CREATE ROLE daemon_runtime LOGIN PASSWORD 'runtime-test-password'")
            .execute(&server.admin)
            .await
            .unwrap();
        sqlx::raw_sql(
            "GRANT CONNECT ON DATABASE daemon_blank TO daemon_runtime;
             GRANT USAGE ON SCHEMA captured TO daemon_runtime;
             GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES
                IN SCHEMA captured TO daemon_runtime;
             GRANT USAGE, SELECT, UPDATE ON ALL SEQUENCES
                IN SCHEMA captured TO daemon_runtime;",
        )
        .execute(&pool)
        .await
        .unwrap();
        let runtime_url = blank_url.replacen(
            "postgres://postgres:postgres@",
            "postgres://daemon_runtime:runtime-test-password@",
            1,
        );
        let runtime = PostgresMetadataStore::connect_server(
            &runtime_url,
            2,
            Duration::from_secs(5),
            Duration::from_secs(5),
            PostgresSslMode::Disable,
            true,
        )
        .await
        .unwrap();
        let default_org = crate::persistence::default_organization();
        runtime
            .organization_store(&default_org)
            .readiness()
            .await
            .unwrap();
        assert!(
            sqlx::query("CREATE TABLE captured.runtime_must_not_ddl (id bigint)")
                .execute(&runtime.pool)
                .await
                .is_err(),
            "the runtime role must not own DDL privileges"
        );

        let exhausted_pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(100))
            .connect(&runtime_url)
            .await
            .unwrap();
        let exhausted_store = PostgresMetadataStore::from_pool(exhausted_pool.clone(), true)
            .await
            .unwrap();
        let held_connection = exhausted_pool.acquire().await.unwrap();
        let exhausted = tokio::time::timeout(
            Duration::from_secs(1),
            exhausted_store.organization_store(&default_org).readiness(),
        )
        .await
        .expect("the pool acquire timeout must bound readiness");
        assert!(exhausted.is_err(), "pool exhaustion must fail readiness");
        drop(held_connection);

        configure_cluster_compatibility(
            &blank_url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            TEST_SERVER_COMPATIBILITY,
        )
        .await
        .unwrap();
        let search_disabled = PostgresMetadataStore::from_pool(pool.clone(), false)
            .await
            .unwrap();
        let replica = live_replica(&search_disabled, "search-toggle-replica").await;
        completed_capture(
            &search_disabled,
            &replica,
            &default_org,
            "trc-search-toggle",
            1,
        )
        .await;
        let search_enabled = PostgresMetadataStore::from_pool(pool.clone(), true)
            .await
            .unwrap()
            .organization_store(&default_org);
        assert_eq!(
            search_enabled
                .traces(TraceFilters {
                    query: Some("quarterly".to_owned()),
                    limit: 20,
                    ..TraceFilters::default()
                })
                .await
                .unwrap()
                .len(),
            1,
            "traces written while search is disabled must be indexed for a later enable"
        );

        let mut lock = PgConnection::connect(&blank_url).await.unwrap();
        sqlx::query("SELECT pg_advisory_lock(hashtextextended($1, 0))")
            .bind(MIGRATION_LOCK_NAMESPACE)
            .execute(&mut lock)
            .await
            .unwrap();
        let blocked = tokio::time::timeout(
            Duration::from_secs(2),
            migrate_database(
                &blank_url,
                PostgresSslMode::Disable,
                Duration::from_secs(5),
                Duration::from_millis(100),
            ),
        )
        .await
        .expect("migration lock timeout must bound the wait");
        assert!(blocked.is_err());
        let unlocked: bool =
            sqlx::query_scalar("SELECT pg_advisory_unlock(hashtextextended($1, 0))")
                .bind(MIGRATION_LOCK_NAMESPACE)
                .fetch_one(&mut lock)
                .await
                .unwrap();
        assert!(unlocked);
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL 17 container"]
    async fn migrating_version_2_assigns_existing_metadata_to_the_default_organization() {
        let server = TestPostgres::start().await;
        let url = server.create_database("daemon_version_2").await;
        migrate_database_through(
            &url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            Duration::from_secs(5),
            &MIGRATIONS[..2],
        )
        .await
        .expect("apply version 2");
        let pool = PgPoolOptions::new().connect(&url).await.unwrap();
        sqlx::raw_sql(
            "INSERT INTO captured.traces (
                trace_id, created_at_unix_ms, completed_at_unix_ms, provider, operation,
                streaming, request_bytes, prompt_preview, prompt_preview_truncated,
                config_fingerprint, capture_status, notarization_status, http_status
             ) VALUES (
                'trc-legacy', 1, 2, 'openai', 'responses', FALSE, 12,
                'Explain quarterly pricing', FALSE, 'sha256:test', 'captured', 'failed', 200
             );
             INSERT INTO captured.trace_search (trace_id, prompt_document, output_document)
             VALUES ('trc-legacy', to_tsvector('simple', 'Explain quarterly pricing'),
                     to_tsvector('simple', ''));
             INSERT INTO captured.artifacts (trace_id, kind, locator, size_bytes, sha256, state)
             VALUES ('trc-legacy', 'capture_checkpoint',
                     'fixture://trc-legacy/capture_checkpoint', 11, repeat('0', 63) || '1',
                     'available');
             INSERT INTO captured.operations (
                operation_id, kind, trace_id, state, attempt, created_at_unix_ms, failure_code
             ) VALUES ('op-legacy', 'notarization', 'trc-legacy', 'failed', 1, 3, 'notary_error');
             INSERT INTO captured.operation_attempts (
                operation_id, attempt, state, started_at_unix_ms, completed_at_unix_ms,
                failure_code
             ) VALUES ('op-legacy', 1, 'failed', 3, 4, 'notary_error');
             INSERT INTO captured.events (
                created_at_unix_ms, event_type, trace_id, operation_id, severity, message
             ) VALUES
                (3, 'notarization_failed', 'trc-legacy', 'op-legacy', 'error',
                 'Notarization failed'),
                (5, 'capture_disabled', NULL, NULL, 'info', 'Capture disabled');
             UPDATE captured.settings SET capture_mode = 'off', auto_seal_enabled = TRUE;",
        )
        .execute(&pool)
        .await
        .expect("write version 2 metadata");

        migrate_database(
            &url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .expect("migrate version 2 to the latest version");
        let versions: Vec<i64> =
            sqlx::query_scalar("SELECT version FROM captured.schema_migrations ORDER BY version")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(versions, [1, 2, 3, 4]);
        for table in ["traces", "operations", "events"] {
            let organizations: Vec<String> = sqlx::query_scalar(&format!(
                "SELECT DISTINCT organization_id FROM captured.{table}"
            ))
            .fetch_all(&pool)
            .await
            .unwrap();
            assert_eq!(organizations, ["default"], "{table}");
        }
        let settings_columns: Vec<String> = sqlx::query_scalar(
            "SELECT column_name::text FROM information_schema.columns
             WHERE table_schema = 'captured' AND table_name = 'settings'
             ORDER BY column_name",
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            settings_columns,
            ["compatibility_sha256", "configured_at", "singleton"],
            "capture settings moved to organization_settings"
        );

        let store = PostgresMetadataStore::connect_server(
            &url,
            2,
            Duration::from_secs(5),
            Duration::from_secs(5),
            PostgresSslMode::Disable,
            true,
        )
        .await
        .unwrap();
        let all_events = EventFilters {
            limit: 201,
            ..EventFilters::default()
        };
        let default_store = store.organization(&crate::persistence::default_organization());
        assert_eq!(
            default_store.capture_mode().await.unwrap(),
            CaptureMode::Off
        );
        assert!(default_store.auto_seal_enabled().await.unwrap());
        assert!(default_store.trace("trc-legacy").await.unwrap().is_some());
        assert_eq!(
            default_store.artifacts("trc-legacy").await.unwrap().len(),
            1
        );
        assert_eq!(
            default_store
                .operation_attempts("op-legacy")
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            default_store
                .events_snapshot(all_events.clone())
                .await
                .unwrap()
                .events
                .len(),
            2
        );
        assert_eq!(
            default_store
                .traces(TraceFilters {
                    query: Some("quarterly".to_owned()),
                    limit: 20,
                    ..TraceFilters::default()
                })
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            default_store
                .enqueue_notarization("trc-legacy", 10)
                .await
                .unwrap()
                .is_some()
        );

        let newcomer = store.organization(&organization("acct-new"));
        assert!(newcomer.trace("trc-legacy").await.unwrap().is_none());
        assert!(newcomer.operation("op-legacy").await.unwrap().is_none());
        assert_eq!(
            newcomer.capture_mode().await.unwrap(),
            CaptureMode::Notarized
        );
        assert!(!newcomer.auto_seal_enabled().await.unwrap());
        assert!(
            newcomer
                .events_snapshot(all_events)
                .await
                .unwrap()
                .events
                .is_empty()
        );
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL 17 container"]
    async fn an_older_release_runs_against_a_newer_schema() {
        let server = TestPostgres::start().await;
        let url = server.create_database("daemon_newer").await;
        let migrate = || {
            migrate_database(
                &url,
                PostgresSslMode::Disable,
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
        };
        migrate().await.expect("migrate");
        // A newer release has applied a migration this binary does not know,
        // as a rollback after a deploy finds it.
        let pool = PgPoolOptions::new().connect(&url).await.unwrap();
        sqlx::query(
            "INSERT INTO captured.schema_migrations (version, description, checksum)
             VALUES ($1, 'from a newer release', 'unknown')",
        )
        .bind(super::LATEST_SCHEMA_VERSION + 1)
        .execute(&pool)
        .await
        .unwrap();
        migrate()
            .await
            .expect("an older migrator has nothing to apply");
        let store = PostgresMetadataStore::connect_server(
            &url,
            2,
            Duration::from_secs(5),
            Duration::from_secs(5),
            PostgresSslMode::Disable,
            true,
        )
        .await
        .expect("an older replica starts");
        store
            .organization_store(&crate::persistence::default_organization())
            .readiness()
            .await
            .expect("and is ready");

        // A database this binary's migrations have not reached is refused.
        let blank = server.create_database("daemon_unmigrated").await;
        let refused = PostgresMetadataStore::connect_server(
            &blank,
            2,
            Duration::from_secs(5),
            Duration::from_secs(5),
            PostgresSslMode::Disable,
            true,
        )
        .await;
        assert!(refused.is_err(), "a replica must not start before migrate");
    }

    #[tokio::test]
    #[ignore = "requires Docker and a disposable PostgreSQL 17 container"]
    async fn migrating_version_3_replaces_the_configuration_pin_with_the_vault_key() {
        let server = TestPostgres::start().await;
        let url = server.create_database("daemon_version_3").await;
        migrate_database_through(
            &url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            Duration::from_secs(5),
            &MIGRATIONS[..3],
        )
        .await
        .expect("apply version 3");
        let configure = |identity: String| {
            let url = url.clone();
            async move {
                configure_cluster_compatibility(
                    &url,
                    PostgresSslMode::Disable,
                    Duration::from_secs(5),
                    &identity,
                )
                .await
            }
        };
        // A version 3 pin covers the configuration too, so it matches nothing
        // a replica computes now.
        configure("1".repeat(64)).await.expect("pin version 3");
        let vault = "2".repeat(64);
        assert!(configure(vault.clone()).await.is_err());

        migrate_database(
            &url,
            PostgresSslMode::Disable,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .expect("migrate version 3 to the latest version");
        configure(vault.clone()).await.expect("pin the vault key");
        // The vault key stays pinned: another key never replaces it.
        configure(vault.clone()).await.expect("replay the same pin");
        assert!(configure("3".repeat(64)).await.is_err());
        let store = PostgresMetadataStore::connect_server(
            &url,
            2,
            Duration::from_secs(5),
            Duration::from_secs(5),
            PostgresSslMode::Disable,
            true,
        )
        .await
        .unwrap();
        let replica = ReplicaIdentity::new("replica-a").unwrap();
        store.register_replica(&replica, &vault, 20).await.unwrap();
    }
}
