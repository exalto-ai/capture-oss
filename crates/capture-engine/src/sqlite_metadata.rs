//! Synchronous SQLite metadata implementation and schema migrations.

use std::{
    fs,
    path::Path,
    sync::{Mutex, MutexGuard},
};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

use crate::artifact_store::{ArtifactKey, ArtifactKind, ArtifactLocator, ArtifactRecord};
use crate::metadata::{
    CaptureCompletion, CaptureMode, Event, EventFilters, IncompleteCapture, MetadataCounts,
    NewTrace, Operation, OperationAttempt, OperationFilters, TerminalOperationResult, TraceFilters,
    TraceShareRecord, TraceSummary, trace_search_expression,
};
use crate::metadata_store::{TraceDeletionOutcome, TraceDeletionPreparation};

const METADATA_SCHEMA_VERSION: i64 = 2;

/// A single-process SQLite capture inventory.
pub struct SqliteMetadata {
    connection: Mutex<Connection>,
    full_text_search: bool,
}

impl SqliteMetadata {
    /// Opens and migrates a local SQLite metadata.
    pub fn open(path: &Path, full_text_search: bool) -> Result<Self> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
        }
        let mut connection = Connection::open(path)
            .with_context(|| format!("opening capture metadata {}", path.display()))?;
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .context("enabling SQLite foreign keys")?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .context("enabling SQLite WAL mode")?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .context("configuring SQLite durability")?;
        migrate(&mut connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
            full_text_search,
        })
    }

    /// Locks the connection, failing closed when a previous holder panicked.
    ///
    /// A panic while the guard is held can leave the connection mid-transaction
    /// or mid-statement, so the state is not known to be consistent. Recovering
    /// the guard with `PoisonError::into_inner` could commit or build on that
    /// partial state; returning an error instead turns every later metadata
    /// call into a backend failure (and failed readiness) rather than a
    /// cascading panic, and the daemon must be restarted to reopen the store.
    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("SQLite metadata connection is unavailable after a panic"))
    }

    pub fn readiness(&self) -> Result<()> {
        let connection = self.connection()?;
        let (count, version): (i64, Option<i64>) = connection.query_row(
            "SELECT COUNT(*), MAX(version) FROM schema_migrations",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        anyhow::ensure!(
            count == METADATA_SCHEMA_VERSION && version == Some(METADATA_SCHEMA_VERSION),
            "SQLite metadata schema journal does not exactly match version {METADATA_SCHEMA_VERSION}"
        );
        connection.query_row("SELECT COUNT(*) FROM traces", [], |row| {
            row.get::<_, i64>(0).map(|_| ())
        })?;
        Ok(())
    }

    pub fn capture_mode(&self) -> Result<CaptureMode> {
        let connection = self.connection()?;
        let stored: String = connection
            .query_row(
                "SELECT capture_mode FROM settings WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .context("reading capture_mode")?;
        CaptureMode::parse(&stored).context("stored capture mode is unknown")
    }

    pub fn set_capture_mode(&self, mode: CaptureMode, now_unix_ms: u64) -> Result<CaptureMode> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let current: String = transaction.query_row(
            "SELECT capture_mode FROM settings WHERE singleton = 1",
            [],
            |row| row.get(0),
        )?;
        if current != mode.as_str() {
            transaction.execute(
                "UPDATE settings SET capture_mode = ? WHERE singleton = 1",
                [mode.as_str()],
            )?;
            let (event_type, message) = mode.event();
            insert_event(
                &transaction,
                now_unix_ms,
                event_type,
                None,
                None,
                "info",
                message,
            )?;
        }
        transaction.commit()?;
        Ok(mode)
    }

    pub fn auto_seal_enabled(&self) -> Result<bool> {
        self.setting(&AUTO_SEAL_SETTING)
    }

    pub fn set_auto_seal_enabled(&self, enabled: bool, now_unix_ms: u64) -> Result<bool> {
        self.set_setting(&AUTO_SEAL_SETTING, enabled, now_unix_ms)
    }

    fn setting(&self, setting: &Setting) -> Result<bool> {
        let connection = self.connection()?;
        connection
            .query_row(
                &format!(
                    "SELECT {} FROM settings WHERE singleton = 1",
                    setting.column
                ),
                [],
                |row| row.get(0),
            )
            .with_context(|| format!("reading {}", setting.column))
    }

    fn set_setting(&self, setting: &Setting, enabled: bool, now_unix_ms: u64) -> Result<bool> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let current: bool = transaction.query_row(
            &format!(
                "SELECT {} FROM settings WHERE singleton = 1",
                setting.column
            ),
            [],
            |row| row.get(0),
        )?;
        if current != enabled {
            transaction.execute(
                &format!(
                    "UPDATE settings SET {} = ? WHERE singleton = 1",
                    setting.column
                ),
                [enabled],
            )?;
            let (event_type, message) = setting.event(enabled);
            insert_event(
                &transaction,
                now_unix_ms,
                event_type,
                None,
                None,
                "info",
                message,
            )?;
        }
        transaction.commit()?;
        Ok(enabled)
    }

    /// Records the start of a capture before the notary connection begins.
    pub fn begin_capture(&self, capture: &NewTrace) -> Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO traces (
                trace_id, created_at_unix_ms, provider, operation, requested_model,
                streaming, request_bytes, prompt_preview, prompt_preview_truncated,
                config_fingerprint, evidence_kind, capture_status, notarization_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'capturing', 'not_requested')",
            params![
                capture.trace_id,
                i64::try_from(capture.created_at_unix_ms)?,
                capture.provider,
                capture.operation,
                capture.requested_model,
                capture.streaming,
                i64::try_from(capture.request_bytes)?,
                capture.prompt_preview,
                capture.prompt_preview_truncated,
                capture.config_fingerprint,
                capture.evidence_kind.as_str(),
            ],
        )?;
        Ok(())
    }

    /// Marks a capture unavailable without persisting error strings that could
    /// contain provider or credential material.
    pub fn mark_capture_failed(&self, trace_id: &str, failure_code: &str) -> Result<()> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        let current = transaction
            .query_row(
                "SELECT capture_status, failure_code FROM traces WHERE trace_id = ?",
                params![trace_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("capture does not exist"))?;
        if current.0 == "failed" && current.1.as_deref() == Some(failure_code) {
            return Ok(());
        }
        anyhow::ensure!(current.0 == "capturing", "capture is not active");
        let changed = transaction.execute(
            "UPDATE traces
             SET capture_status = 'failed', failure_code = ?
             WHERE trace_id = ? AND capture_status = 'capturing'",
            params![failure_code, trace_id],
        )?;
        anyhow::ensure!(changed == 1, "active capture transition was lost");
        transaction.commit()?;
        Ok(())
    }

    /// Stages completion fields without advertising an artifact as available.
    pub fn prepare_capture_completion(&self, completion: &CaptureCompletion) -> Result<()> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        let current = transaction
            .query_row(
                "SELECT capture_status, completed_at_unix_ms IS NOT NULL
                 FROM traces WHERE trace_id = ?",
                params![completion.trace_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("capture does not exist"))?;
        anyhow::ensure!(
            current.0 == "capturing" || current.0 == "captured",
            "capture cannot accept completion metadata"
        );
        if current.1 {
            anyhow::ensure!(
                capture_completion_matches(&transaction, completion)?,
                "capture completion conflicts with persisted metadata"
            );
            return Ok(());
        }
        anyhow::ensure!(current.0 == "capturing", "capture is not active");
        let changed = transaction.execute(
            "UPDATE traces SET
                completed_at_unix_ms = ?, duration_ms = ?, http_status = ?, response_bytes = ?,
                response_model = ?, output_preview = ?, output_preview_truncated = ?,
                expected_artifact_size_bytes = ?, expected_artifact_sha256 = ?
             WHERE trace_id = ? AND capture_status = 'capturing'
               AND completed_at_unix_ms IS NULL AND evidence_kind = ?",
            params![
                i64::try_from(completion.completed_at_unix_ms)?,
                i64::try_from(completion.duration_ms)?,
                i64::from(completion.http_status),
                i64::try_from(completion.response_bytes)?,
                completion.response_model.as_deref(),
                completion.output_preview.as_str(),
                completion.output_preview_truncated,
                i64::try_from(completion.expected_artifact_size_bytes)?,
                completion.expected_artifact_sha256.as_str(),
                completion.trace_id,
                completion.evidence_kind.as_str(),
            ],
        )?;
        anyhow::ensure!(changed == 1, "capture completion staging was lost");
        transaction.commit()?;
        Ok(())
    }

    /// Commits capture completion and a previously stored artifact atomically.
    pub fn complete_capture_record(
        &self,
        completion: &CaptureCompletion,
        artifact: &ArtifactRecord,
    ) -> Result<()> {
        require_artifact(artifact, &completion.trace_id, completion.artifact_kind())?;
        anyhow::ensure!(
            artifact.size_bytes == completion.expected_artifact_size_bytes
                && artifact.sha256 == completion.expected_artifact_sha256,
            "artifact does not match the staged capture commit"
        );
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        let (current_state, completion_prepared) = transaction
            .query_row(
                "SELECT capture_status, completed_at_unix_ms IS NOT NULL
                 FROM traces WHERE trace_id = ?",
                params![completion.trace_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?
            .ok_or_else(|| anyhow::anyhow!("capture does not exist"))?;
        if current_state == "captured" {
            anyhow::ensure!(
                capture_completion_matches(&transaction, completion)?
                    && artifact_exists_exact(&transaction, artifact)?,
                "capture completion conflicts with persisted metadata"
            );
            return Ok(());
        }
        anyhow::ensure!(current_state == "capturing", "capture is not active");
        if completion_prepared {
            anyhow::ensure!(
                capture_completion_matches(&transaction, completion)?,
                "capture completion conflicts with staged metadata"
            );
        }
        let changed = transaction.execute(
            "UPDATE traces SET
                completed_at_unix_ms = ?, duration_ms = ?, http_status = ?, response_bytes = ?,
                response_model = ?, output_preview = ?, output_preview_truncated = ?,
                expected_artifact_size_bytes = ?, expected_artifact_sha256 = ?,
                capture_status = 'captured', failure_code = NULL,
                notarization_status = CASE evidence_kind
                    WHEN 'witnessed' THEN 'succeeded' ELSE notarization_status END
             WHERE trace_id = ? AND capture_status = 'capturing' AND evidence_kind = ?",
            params![
                i64::try_from(completion.completed_at_unix_ms)?,
                i64::try_from(completion.duration_ms)?,
                i64::from(completion.http_status),
                i64::try_from(completion.response_bytes)?,
                completion.response_model.as_deref(),
                completion.output_preview.as_str(),
                completion.output_preview_truncated,
                i64::try_from(completion.expected_artifact_size_bytes)?,
                completion.expected_artifact_sha256.as_str(),
                completion.trace_id,
                completion.evidence_kind.as_str(),
            ],
        )?;
        if changed != 1 {
            anyhow::bail!("active capture transition was lost");
        }
        insert_artifact(&transaction, artifact)?;
        if self.full_text_search {
            transaction.execute(
                "DELETE FROM trace_search WHERE trace_id = ?",
                params![completion.trace_id],
            )?;
            transaction.execute(
                "INSERT INTO trace_search(trace_id, prompt_preview, output_preview)
                 VALUES (?, (SELECT prompt_preview FROM traces WHERE trace_id = ?), ?)",
                params![
                    completion.trace_id,
                    completion.trace_id,
                    completion.output_preview.as_str()
                ],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Returns traces left active when a single-daemon process stopped.
    pub fn incomplete_captures(&self) -> Result<Vec<IncompleteCapture>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT trace_id, completed_at_unix_ms, duration_ms, http_status,
                    response_bytes, response_model, output_preview,
                    output_preview_truncated, expected_artifact_size_bytes,
                    expected_artifact_sha256, evidence_kind
             FROM traces WHERE capture_status = 'capturing'",
        )?;
        let mut rows = statement.query([])?;
        let mut traces = Vec::new();
        while let Some(row) = rows.next()? {
            let trace_id = row.get::<_, String>(0)?;
            let completed_at = row.get::<_, Option<i64>>(1)?;
            let duration = row.get::<_, Option<i64>>(2)?;
            let http_status = row.get::<_, Option<i64>>(3)?;
            let response_bytes = row.get::<_, Option<i64>>(4)?;
            let expected_size = row.get::<_, Option<i64>>(8)?;
            let expected_sha256 = row.get::<_, Option<String>>(9)?;
            let completion = match (
                completed_at,
                duration,
                http_status,
                response_bytes,
                expected_size,
                expected_sha256,
            ) {
                (
                    Some(completed_at),
                    Some(duration),
                    Some(http_status),
                    Some(response_bytes),
                    Some(expected_size),
                    Some(expected_sha256),
                ) => Some(CaptureCompletion {
                    trace_id: trace_id.clone(),
                    completed_at_unix_ms: completed_at.try_into()?,
                    duration_ms: duration.try_into()?,
                    http_status: http_status.try_into()?,
                    response_bytes: response_bytes.try_into()?,
                    response_model: row.get(5)?,
                    output_preview: row.get(6)?,
                    output_preview_truncated: row.get(7)?,
                    expected_artifact_size_bytes: expected_size.try_into()?,
                    expected_artifact_sha256: expected_sha256,
                    evidence_kind: stored_evidence_kind(&row.get::<_, String>(10)?)?,
                }),
                _ => None,
            };
            traces.push(IncompleteCapture {
                trace_id,
                completion,
            });
        }
        Ok(traces)
    }

    /// Lists traces using the complete REST filter set. Filter values are
    /// bound parameters, and the result is always bounded.
    pub fn filtered_traces(&self, filters: &TraceFilters) -> Result<Vec<TraceSummary>> {
        if filters.query.is_some() && !self.full_text_search {
            anyhow::bail!("full-text preview search is disabled in this captured configuration");
        }
        let search_query = filters.query.as_deref().and_then(trace_search_expression);
        if filters.query.is_some() && search_query.is_none() {
            return Ok(Vec::new());
        }
        let limit = filters.limit.clamp(1, 201);
        let connection = self.connection()?;
        let mut sql = if search_query.is_some() {
            "SELECT c.* FROM traces c JOIN trace_search search ON search.trace_id = c.trace_id WHERE trace_search MATCH ?".to_owned()
        } else {
            "SELECT c.* FROM traces c WHERE 1 = 1".to_owned()
        };
        let mut values = Vec::<rusqlite::types::Value>::new();
        if let Some(query) = search_query {
            values.push(query.into());
        }
        for (column, value) in [
            ("c.requested_model", filters.model.as_deref()),
            ("c.provider", filters.provider.as_deref()),
            ("c.capture_status", filters.capture_status.as_deref()),
            (
                "c.notarization_status",
                filters.notarization_status.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                sql.push_str(" AND ");
                sql.push_str(column);
                sql.push_str(" = ?");
                values.push(value.to_owned().into());
            }
        }
        match filters.state.as_deref() {
            Some("captured") => sql.push_str(
                " AND c.capture_status = 'captured' AND c.notarization_status != 'succeeded'",
            ),
            Some("notarized") => sql.push_str(
                " AND c.capture_status = 'captured' AND c.notarization_status = 'succeeded'",
            ),
            Some(_) => return Ok(Vec::new()),
            None => {}
        }
        match filters.status.as_deref() {
            Some("capturing") => sql.push_str(" AND c.capture_status = 'capturing'"),
            Some("capture_failed") => sql.push_str(" AND c.capture_status = 'failed'"),
            Some("needs_attention") => sql.push_str(
                " AND (c.capture_status = 'failed' OR (c.capture_status = 'captured' AND c.notarization_status IN ('failed', 'interrupted')))",
            ),
            Some("notarizing") => sql.push_str(
                " AND c.capture_status = 'captured' AND c.notarization_status IN ('queued', 'running')",
            ),
            Some("notarization_failed") => sql.push_str(
                " AND c.capture_status = 'captured' AND c.notarization_status = 'failed'",
            ),
            Some("notarization_interrupted") => sql.push_str(
                " AND c.capture_status = 'captured' AND c.notarization_status = 'interrupted'",
            ),
            Some(_) => return Ok(Vec::new()),
            None => {}
        }
        if let Some(streaming) = filters.streaming {
            sql.push_str(" AND c.streaming = ?");
            values.push(streaming.into());
        }
        if let Some(created_after) = filters.created_after_unix_ms {
            sql.push_str(" AND c.created_at_unix_ms >= ?");
            values.push(i64::try_from(created_after)?.into());
        }
        if let Some(created_before) = filters.created_before_unix_ms {
            sql.push_str(" AND c.created_at_unix_ms <= ?");
            values.push(i64::try_from(created_before)?.into());
        }
        if let Some(cursor) = &filters.cursor {
            sql.push_str(
                " AND (c.created_at_unix_ms < ? OR (c.created_at_unix_ms = ? AND c.trace_id < ?))",
            );
            let created_at = i64::try_from(cursor.created_at_unix_ms)?;
            values.push(created_at.into());
            values.push(created_at.into());
            values.push(cursor.trace_id.clone().into());
        }
        sql.push_str(" ORDER BY c.created_at_unix_ms DESC, c.trace_id DESC LIMIT ?");
        values.push(i64::try_from(limit)?.into());
        let mut statement = connection.prepare(&sql)?;
        let mut rows = statement.query(rusqlite::params_from_iter(values))?;
        let mut traces = Vec::new();
        while let Some(row) = rows.next()? {
            traces.push(trace_from_row(row)?);
        }
        Ok(traces)
    }

    pub fn trace(&self, trace_id: &str) -> Result<Option<TraceSummary>> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT * FROM traces WHERE trace_id = ?",
                params![trace_id],
                trace_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    /// Returns backend-neutral artifact records from the canonical locator column.
    pub fn artifact_records(&self, trace_id: &str) -> Result<Vec<ArtifactRecord>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT trace_id, kind, locator, size_bytes, sha256
             FROM artifacts
             WHERE trace_id = ? AND state = 'available'
             ORDER BY kind",
        )?;
        let rows = statement
            .query_map(params![trace_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|(trace_id, kind, locator, size_bytes, sha256)| {
                ArtifactRecord::new(
                    ArtifactKey::new(trace_id, ArtifactKind::try_from(kind.as_str())?)?,
                    ArtifactLocator::from_stored(locator)?,
                    size_bytes.try_into()?,
                    sha256,
                )
            })
            .collect()
    }

    pub fn prepare_trace_deletion(&self, trace_id: &str) -> Result<TraceDeletionPreparation> {
        let connection = self.connection()?;
        let Some((capture_status, notarization_status)) = connection
            .query_row(
                "SELECT capture_status, notarization_status FROM traces WHERE trace_id = ?",
                params![trace_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        else {
            return Ok(TraceDeletionPreparation::NotFound);
        };
        if capture_status == "capturing" {
            return Ok(TraceDeletionPreparation::CaptureActive);
        }
        let active_operation = connection.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM operations
                WHERE trace_id = ? AND state IN ('queued', 'running')
             )",
            params![trace_id],
            |row| row.get::<_, bool>(0),
        )?;
        if matches!(notarization_status.as_str(), "queued" | "running") || active_operation {
            return Ok(TraceDeletionPreparation::NotarizationActive);
        }
        let active_share = connection
            .query_row(
                "SELECT progress, access_enabled FROM trace_shares WHERE trace_id = ?",
                params![trace_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?
            .is_some_and(|(progress, access_enabled)| progress == "verifying" || access_enabled);
        if active_share {
            return Ok(TraceDeletionPreparation::ShareActive);
        }
        Ok(TraceDeletionPreparation::Ready)
    }

    /// Atomically removes one terminal Trace and every metadata row it owns.
    pub fn delete_trace(&self, trace_id: &str) -> Result<TraceDeletionOutcome> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let Some((capture_status, notarization_status)) = transaction
            .query_row(
                "SELECT capture_status, notarization_status FROM traces WHERE trace_id = ?",
                params![trace_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        else {
            return Ok(TraceDeletionOutcome::NotFound);
        };
        if capture_status == "capturing" {
            return Ok(TraceDeletionOutcome::CaptureActive);
        }
        let active_operation = transaction.query_row(
            "SELECT EXISTS(
                SELECT 1 FROM operations
                WHERE trace_id = ? AND state IN ('queued', 'running')
             )",
            params![trace_id],
            |row| row.get::<_, bool>(0),
        )?;
        if matches!(notarization_status.as_str(), "queued" | "running") || active_operation {
            return Ok(TraceDeletionOutcome::NotarizationActive);
        }
        let active_share = transaction
            .query_row(
                "SELECT progress, access_enabled FROM trace_shares WHERE trace_id = ?",
                params![trace_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, bool>(1)?)),
            )
            .optional()?
            .is_some_and(|(progress, access_enabled)| progress == "verifying" || access_enabled);
        if active_share {
            return Ok(TraceDeletionOutcome::ShareActive);
        }

        // Delete references in dependency order. Activity belongs to the
        // private local Trace, so it must not retain identifiers after removal.
        transaction.execute(
            "DELETE FROM events
             WHERE trace_id = ? OR operation_id IN (
                 SELECT operation_id FROM operations WHERE trace_id = ?
             )",
            params![trace_id, trace_id],
        )?;
        transaction.execute(
            "DELETE FROM operation_attempts
             WHERE operation_id IN (
                 SELECT operation_id FROM operations WHERE trace_id = ?
             )",
            params![trace_id],
        )?;
        transaction.execute(
            "DELETE FROM operations WHERE trace_id = ?",
            params![trace_id],
        )?;
        transaction.execute(
            "DELETE FROM artifacts WHERE trace_id = ?",
            params![trace_id],
        )?;
        transaction.execute(
            "DELETE FROM trace_shares WHERE trace_id = ?",
            params![trace_id],
        )?;
        transaction.execute(
            "DELETE FROM trace_search WHERE trace_id = ?",
            params![trace_id],
        )?;
        let changed =
            transaction.execute("DELETE FROM traces WHERE trace_id = ?", params![trace_id])?;
        anyhow::ensure!(changed == 1, "Trace deletion lost its metadata row");
        transaction.commit()?;
        Ok(TraceDeletionOutcome::Deleted)
    }

    pub fn counts(&self) -> Result<MetadataCounts> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT
                    SUM(capture_status = 'captured' AND notarization_status != 'succeeded'),
                    SUM(capture_status = 'captured' AND notarization_status IN ('queued', 'running')),
                    SUM(capture_status = 'captured' AND notarization_status = 'succeeded'),
                    SUM(capture_status = 'failed' OR notarization_status IN ('failed', 'interrupted')),
                    SUM(capture_status = 'capturing'),
                    SUM(capture_status = 'failed')
                 FROM traces",
                [],
                |row| {
                    Ok(MetadataCounts {
                        captured: row
                            .get::<_, Option<i64>>(0)?
                            .unwrap_or(0)
                            .try_into()
                            .unwrap_or(0),
                        notarizing: row
                            .get::<_, Option<i64>>(1)?
                            .unwrap_or(0)
                            .try_into()
                            .unwrap_or(0),
                        notarized: row
                            .get::<_, Option<i64>>(2)?
                            .unwrap_or(0)
                            .try_into()
                            .unwrap_or(0),
                        needs_attention: row
                            .get::<_, Option<i64>>(3)?
                            .unwrap_or(0)
                            .try_into()
                            .unwrap_or(0),
                        capturing: row
                            .get::<_, Option<i64>>(4)?
                            .unwrap_or(0)
                            .try_into()
                            .unwrap_or(0),
                        capture_failed: row
                            .get::<_, Option<i64>>(5)?
                            .unwrap_or(0)
                            .try_into()
                            .unwrap_or(0),
                    })
                },
            )
            .map_err(Into::into)
    }

    pub fn trace_share(&self, trace_id: &str) -> Result<Option<TraceShareRecord>> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT trace_id, hosted_trace_id, progress, visibility, access_enabled,
                        password_protected, expires_at_unix_ms, failure_code,
                        share_url, package_url, updated_at_unix_ms
                 FROM trace_shares WHERE trace_id = ?",
                params![trace_id],
                trace_share_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn put_trace_share(&self, share: &TraceShareRecord) -> Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO trace_shares (
                trace_id, hosted_trace_id, progress, visibility, access_enabled, password_protected,
                expires_at_unix_ms, failure_code, share_url, package_url, updated_at_unix_ms
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(trace_id) DO UPDATE SET
                hosted_trace_id = excluded.hosted_trace_id, progress = excluded.progress,
                visibility = excluded.visibility, access_enabled = excluded.access_enabled,
                password_protected = excluded.password_protected,
                expires_at_unix_ms = excluded.expires_at_unix_ms,
                failure_code = excluded.failure_code, share_url = excluded.share_url,
                package_url = excluded.package_url,
                updated_at_unix_ms = excluded.updated_at_unix_ms",
            params![
                share.trace_id,
                share.hosted_trace_id,
                share.progress,
                share.visibility,
                share.access_enabled,
                share.password_protected,
                share.expires_at_unix_ms.map(i64::try_from).transpose()?,
                share.failure_code,
                share.share_url,
                share.package_url,
                i64::try_from(share.updated_at_unix_ms)?,
            ],
        )?;
        Ok(())
    }

    pub fn delete_trace_share(&self, trace_id: &str) -> Result<bool> {
        let connection = self.connection()?;
        Ok(connection.execute(
            "DELETE FROM trace_shares WHERE trace_id = ?",
            params![trace_id],
        )? > 0)
    }

    /// Queues, resumes, or returns the one durable notarization operation for
    /// a trace. Retries keep the operation identity and attempt history.
    pub fn enqueue_notarization(
        &self,
        trace_id: &str,
        now: u64,
    ) -> Result<Option<(Operation, bool)>> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        let exists = transaction
            .query_row(
                "SELECT 1 FROM traces
                 WHERE trace_id = ? AND capture_status = 'captured'
                   AND http_status BETWEEN 200 AND 299 AND evidence_kind = 'notarized'",
                params![trace_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !exists {
            return Ok(None);
        }
        if let Some(mut operation) = transaction
            .query_row(
                "SELECT * FROM operations WHERE trace_id = ? AND kind = 'notarization' ORDER BY created_at_unix_ms DESC LIMIT 1",
                params![trace_id],
                operation_from_row,
            )
            .optional()?
        {
            if matches!(operation.state.as_str(), "failed" | "interrupted") {
                transaction.execute(
                    "UPDATE operations
                     SET state = 'queued', started_at_unix_ms = NULL,
                         completed_at_unix_ms = NULL, failure_code = NULL,
                         progress_phase = 'queued', progress_updated_at_unix_ms = ?,
                         proof_bytes_completed = 0, proof_bytes_total = 0,
                         proof_commitments_completed = 0, proof_commitments_total = 0
                     WHERE operation_id = ? AND state IN ('failed', 'interrupted')",
                    params![i64::try_from(now)?, operation.operation_id],
                )?;
                transaction.execute(
                    "UPDATE traces SET notarization_status = 'queued' WHERE trace_id = ?",
                    params![trace_id],
                )?;
                insert_event(
                    &transaction,
                    now,
                    "notarization_queued",
                    Some(trace_id),
                    Some(&operation.operation_id),
                    "info",
                    "Notarization retry queued",
                )?;
                operation = transaction.query_row(
                    "SELECT * FROM operations WHERE operation_id = ?",
                    params![operation.operation_id],
                    operation_from_row,
                )?;
                transaction.commit()?;
                return Ok(Some((operation, false)));
            }
            return Ok(Some((operation, true)));
        }
        let operation_id = format!("op-{}", uuid::Uuid::new_v4().simple());
        transaction.execute(
            "INSERT INTO operations (
                operation_id, kind, trace_id, state, attempt,
                created_at_unix_ms, progress_phase, progress_updated_at_unix_ms
             ) VALUES (?, 'notarization', ?, 'queued', 0, ?, 'queued', ?)",
            params![
                operation_id,
                trace_id,
                i64::try_from(now)?,
                i64::try_from(now)?
            ],
        )?;
        transaction.execute(
            "UPDATE traces SET notarization_status = 'queued' WHERE trace_id = ?",
            params![trace_id],
        )?;
        insert_event(
            &transaction,
            now,
            "notarization_queued",
            Some(trace_id),
            Some(&operation_id),
            "info",
            "Notarization queued",
        )?;
        let operation = transaction.query_row(
            "SELECT * FROM operations WHERE operation_id = ?",
            params![operation_id],
            operation_from_row,
        )?;
        transaction.commit()?;
        Ok(Some((operation, false)))
    }

    pub fn claim_next_notarization(&self, now: u64) -> Result<Option<Operation>> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        let operation_id = transaction
            .query_row(
                "SELECT operation_id FROM operations WHERE kind = 'notarization' AND state = 'queued' ORDER BY created_at_unix_ms LIMIT 1",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        let Some(operation_id) = operation_id else {
            return Ok(None);
        };
        transaction.execute(
            "UPDATE operations
             SET state = 'running', attempt = attempt + 1,
                 started_at_unix_ms = ?, completed_at_unix_ms = NULL,
                 failure_code = NULL, progress_phase = 'preparing',
                 progress_updated_at_unix_ms = ?, proof_bytes_completed = 0,
                 proof_bytes_total = 0, proof_commitments_completed = 0,
                 proof_commitments_total = 0
             WHERE operation_id = ? AND state = 'queued'",
            params![i64::try_from(now)?, i64::try_from(now)?, operation_id],
        )?;
        transaction.execute(
            "UPDATE traces SET notarization_status = 'running' WHERE trace_id = (SELECT trace_id FROM operations WHERE operation_id = ?)",
            params![operation_id],
        )?;
        let operation = transaction.query_row(
            "SELECT * FROM operations WHERE operation_id = ?",
            params![operation_id],
            operation_from_row,
        )?;
        transaction.execute(
            "INSERT INTO operation_attempts (operation_id, attempt, state, started_at_unix_ms) VALUES (?, ?, 'running', ?)",
            params![operation.operation_id, operation.attempt, i64::try_from(now)?],
        )?;
        insert_event(
            &transaction,
            now,
            "notarization_started",
            Some(&operation.trace_id),
            Some(&operation.operation_id),
            "info",
            "Notarization started",
        )?;
        transaction.commit()?;
        Ok(Some(operation))
    }

    /// Records one stable notarization milestone. The update is ignored if the
    /// operation is no longer running, which keeps a late callback from
    /// changing terminal state after interruption or failure.
    pub fn update_operation_progress(
        &self,
        operation_id: &str,
        phase: capture_core::NotarizationPhase,
        now: u64,
    ) -> Result<bool> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        let phase = phase.as_str();
        let changed = transaction.execute(
            "UPDATE operations
             SET progress_phase = ?, progress_updated_at_unix_ms = ?
             WHERE operation_id = ? AND state = 'running' AND progress_phase <> ?",
            params![phase, i64::try_from(now)?, operation_id, phase],
        )?;
        if changed == 0 {
            return Ok(false);
        }
        let trace_id: String = transaction.query_row(
            "SELECT trace_id FROM operations WHERE operation_id = ?",
            params![operation_id],
            |row| row.get(0),
        )?;
        let message = match phase {
            "proving" => "Generating private proof",
            "signing" => "Requesting notary signature",
            "packaging" => "Building verified package",
            _ => "Notarization advanced",
        };
        insert_event(
            &transaction,
            now,
            "notarization_progress",
            Some(&trace_id),
            Some(operation_id),
            "info",
            message,
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Persists throttled proof-work counters without emitting one activity
    /// event per batch. The first update also records entry into the proving
    /// phase for the activity feed.
    pub fn update_operation_proof_progress(
        &self,
        operation_id: &str,
        progress: capture_core::NotarizationProofProgress,
        now: u64,
    ) -> Result<bool> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        let previous = transaction
            .query_row(
                "SELECT progress_phase, proof_bytes_completed, proof_bytes_total,
                        proof_commitments_completed, proof_commitments_total
                 FROM operations
                 WHERE operation_id = ? AND state = 'running'",
                params![operation_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                },
            )
            .optional()?;
        let Some((
            previous_phase,
            bytes_completed,
            bytes_total,
            commitments_completed,
            commitments_total,
        )) = previous
        else {
            return Ok(false);
        };
        let bytes_completed = u64::try_from(bytes_completed)?;
        let bytes_total = u64::try_from(bytes_total)?;
        let commitments_completed = u64::try_from(commitments_completed)?;
        let commitments_total = u64::try_from(commitments_total)?;
        if previous_phase == "proving"
            && bytes_completed == progress.bytes_completed
            && bytes_total == progress.bytes_total
            && commitments_completed == progress.commitments_completed
            && commitments_total == progress.commitments_total
        {
            return Ok(false);
        }
        anyhow::ensure!(
            progress.bytes_completed >= bytes_completed
                && progress.commitments_completed >= commitments_completed,
            "proof progress cannot decrease"
        );
        anyhow::ensure!(
            bytes_total == 0 || progress.bytes_total == bytes_total,
            "proof byte total cannot change after it is established"
        );
        anyhow::ensure!(
            commitments_total == 0 || progress.commitments_total == commitments_total,
            "proof commitment total cannot change after it is established"
        );
        transaction.execute(
            "UPDATE operations
             SET progress_phase = 'proving', progress_updated_at_unix_ms = ?,
                 proof_bytes_completed = ?, proof_bytes_total = ?,
                 proof_commitments_completed = ?, proof_commitments_total = ?
             WHERE operation_id = ? AND state = 'running'",
            params![
                i64::try_from(now)?,
                i64::try_from(progress.bytes_completed)?,
                i64::try_from(progress.bytes_total)?,
                i64::try_from(progress.commitments_completed)?,
                i64::try_from(progress.commitments_total)?,
                operation_id,
            ],
        )?;
        if previous_phase != "proving" {
            let trace_id: String = transaction.query_row(
                "SELECT trace_id FROM operations WHERE operation_id = ?",
                params![operation_id],
                |row| row.get(0),
            )?;
            insert_event(
                &transaction,
                now,
                "notarization_progress",
                Some(&trace_id),
                Some(operation_id),
                "info",
                "Generating private proof",
            )?;
        }
        transaction.commit()?;
        Ok(true)
    }

    pub fn complete_notarization(
        &self,
        operation_id: &str,
        artifact: &ArtifactRecord,
        now: u64,
    ) -> Result<TerminalOperationResult> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        let Some((current_state, trace_id)) = transaction
            .query_row(
                "SELECT state, trace_id FROM operations WHERE operation_id = ?",
                params![operation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?
        else {
            return Ok(TerminalOperationResult::NotFound);
        };
        validate_persisted_operation_state(&current_state)?;
        require_artifact(artifact, &trace_id, ArtifactKind::TracePackage)?;
        if current_state == "succeeded" {
            anyhow::ensure!(
                artifact_exists_exact(&transaction, artifact)?,
                "trace package artifact does not match persisted metadata"
            );
            return Ok(TerminalOperationResult::AlreadyApplied);
        }
        if current_state != "running" {
            return Ok(TerminalOperationResult::Conflict { current_state });
        }

        insert_artifact(&transaction, artifact)?;
        let changed = transaction.execute(
            "UPDATE operations
             SET state = 'succeeded', completed_at_unix_ms = ?, failure_code = NULL,
                 progress_phase = 'complete', progress_updated_at_unix_ms = ?
             WHERE operation_id = ? AND state = 'running'",
            params![i64::try_from(now)?, i64::try_from(now)?, operation_id],
        )?;
        anyhow::ensure!(changed == 1, "running operation transition was lost");
        let changed = transaction.execute(
            "UPDATE operation_attempts SET state = 'succeeded', completed_at_unix_ms = ?, failure_code = NULL WHERE operation_id = ? AND attempt = (SELECT attempt FROM operations WHERE operation_id = ?)",
            params![i64::try_from(now)?, operation_id, operation_id],
        )?;
        anyhow::ensure!(changed == 1, "running operation has no current attempt");
        let changed = transaction.execute(
            "UPDATE traces SET notarization_status = 'succeeded' WHERE trace_id = (SELECT trace_id FROM operations WHERE operation_id = ?)",
            params![operation_id],
        )?;
        anyhow::ensure!(changed == 1, "notarization operation has no capture");
        insert_event(
            &transaction,
            now,
            "notarization_completed",
            Some(&trace_id),
            Some(operation_id),
            "success",
            "Notarization completed",
        )?;
        transaction.commit()?;
        Ok(TerminalOperationResult::Applied)
    }

    pub fn fail_operation(
        &self,
        operation_id: &str,
        now: u64,
        failure_code: &str,
    ) -> Result<TerminalOperationResult> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        let Some((current_state, current_failure_code)) = transaction
            .query_row(
                "SELECT state, failure_code FROM operations WHERE operation_id = ?",
                params![operation_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
        else {
            return Ok(TerminalOperationResult::NotFound);
        };
        validate_persisted_operation_state(&current_state)?;
        if current_state == "failed" && current_failure_code.as_deref() == Some(failure_code) {
            return Ok(TerminalOperationResult::AlreadyApplied);
        }
        if current_state != "running" {
            return Ok(TerminalOperationResult::Conflict { current_state });
        }

        let changed = transaction.execute(
            "UPDATE operations SET state = 'failed', completed_at_unix_ms = ?, failure_code = ? WHERE operation_id = ? AND state = 'running'",
            params![i64::try_from(now)?, failure_code, operation_id],
        )?;
        anyhow::ensure!(changed == 1, "running operation transition was lost");
        let changed = transaction.execute(
            "UPDATE operation_attempts SET state = 'failed', completed_at_unix_ms = ?, failure_code = ? WHERE operation_id = ? AND attempt = (SELECT attempt FROM operations WHERE operation_id = ?)",
            params![i64::try_from(now)?, failure_code, operation_id, operation_id],
        )?;
        anyhow::ensure!(changed == 1, "running operation has no current attempt");
        let changed = transaction.execute(
            "UPDATE traces SET notarization_status = 'failed' WHERE trace_id = (SELECT trace_id FROM operations WHERE operation_id = ?)",
            params![operation_id],
        )?;
        anyhow::ensure!(changed == 1, "notarization operation has no capture");
        let trace_id: String = transaction.query_row(
            "SELECT trace_id FROM operations WHERE operation_id = ?",
            params![operation_id],
            |row| row.get(0),
        )?;
        insert_event(
            &transaction,
            now,
            "notarization_failed",
            Some(&trace_id),
            Some(operation_id),
            "error",
            "Notarization failed",
        )?;
        transaction.commit()?;
        Ok(TerminalOperationResult::Applied)
    }

    pub fn recover_operations(&self, now: u64) -> Result<usize> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        let mut statement = transaction
            .prepare("SELECT operation_id, trace_id FROM operations WHERE state = 'running'")?;
        let interrupted = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        for (operation_id, trace_id) in &interrupted {
            transaction.execute("UPDATE operations SET state = 'interrupted', completed_at_unix_ms = ?, failure_code = 'service_restarted' WHERE operation_id = ?", params![i64::try_from(now)?, operation_id])?;
            transaction.execute("UPDATE operation_attempts SET state = 'interrupted', completed_at_unix_ms = ?, failure_code = 'service_restarted' WHERE operation_id = ? AND attempt = (SELECT attempt FROM operations WHERE operation_id = ?)", params![i64::try_from(now)?, operation_id, operation_id])?;
            transaction.execute(
                "UPDATE traces SET notarization_status = 'interrupted' WHERE trace_id = ?",
                params![trace_id],
            )?;
            insert_event(
                &transaction,
                now,
                "notarization_interrupted",
                Some(trace_id),
                Some(operation_id),
                "warning",
                "Notarization interrupted by service restart",
            )?;
        }
        transaction.commit()?;
        Ok(interrupted.len())
    }

    pub fn retry_operation(&self, operation_id: &str, now: u64) -> Result<Option<Operation>> {
        let connection = self.connection()?;
        let transaction = connection.unchecked_transaction()?;
        let changed = transaction.execute(
            "UPDATE operations
             SET state = 'queued', started_at_unix_ms = NULL,
                 completed_at_unix_ms = NULL, failure_code = NULL,
                 progress_phase = 'queued', progress_updated_at_unix_ms = ?,
                 proof_bytes_completed = 0, proof_bytes_total = 0,
                 proof_commitments_completed = 0, proof_commitments_total = 0
             WHERE operation_id = ? AND state IN ('failed', 'interrupted')
               AND EXISTS (
                   SELECT 1 FROM traces
                   WHERE traces.trace_id = operations.trace_id
                     AND traces.http_status BETWEEN 200 AND 299
               )",
            params![i64::try_from(now)?, operation_id],
        )?;
        if changed == 0 {
            return Ok(None);
        }
        transaction.execute("UPDATE traces SET notarization_status = 'queued' WHERE trace_id = (SELECT trace_id FROM operations WHERE operation_id = ?)", params![operation_id])?;
        let operation = transaction.query_row(
            "SELECT * FROM operations WHERE operation_id = ?",
            params![operation_id],
            operation_from_row,
        )?;
        insert_event(
            &transaction,
            now,
            "notarization_retried",
            Some(&operation.trace_id),
            Some(operation_id),
            "info",
            "Notarization queued for retry",
        )?;
        transaction.commit()?;
        Ok(Some(operation))
    }

    pub fn operation(&self, operation_id: &str) -> Result<Option<Operation>> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT * FROM operations WHERE operation_id = ?",
                params![operation_id],
                operation_from_row,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn filtered_operations(&self, filters: &OperationFilters) -> Result<Vec<Operation>> {
        let connection = self.connection()?;
        let mut sql = "SELECT * FROM operations WHERE 1 = 1".to_owned();
        let mut values = Vec::<rusqlite::types::Value>::new();
        for (column, value) in [
            ("state", filters.state.as_deref()),
            ("kind", filters.kind.as_deref()),
            ("trace_id", filters.trace_id.as_deref()),
        ] {
            if let Some(value) = value {
                sql.push_str(" AND ");
                sql.push_str(column);
                sql.push_str(" = ?");
                values.push(value.to_owned().into());
            }
        }
        if let Some(cursor) = &filters.cursor {
            sql.push_str(
                " AND (created_at_unix_ms < ? OR (created_at_unix_ms = ? AND operation_id < ?))",
            );
            let created_at = i64::try_from(cursor.created_at_unix_ms)?;
            values.push(created_at.into());
            values.push(created_at.into());
            values.push(cursor.operation_id.clone().into());
        }
        sql.push_str(" ORDER BY created_at_unix_ms DESC, operation_id DESC LIMIT ?");
        values.push(i64::try_from(filters.limit.clamp(1, 201))?.into());
        let mut statement = connection.prepare(&sql)?;
        let mut rows = statement.query(rusqlite::params_from_iter(values))?;
        let mut operations = Vec::new();
        while let Some(row) = rows.next()? {
            operations.push(operation_from_row(row)?);
        }
        Ok(operations)
    }

    pub fn operation_attempts(&self, operation_id: &str) -> Result<Vec<OperationAttempt>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT attempt, state, started_at_unix_ms, completed_at_unix_ms, failure_code
             FROM operation_attempts WHERE operation_id = ? ORDER BY attempt DESC",
        )?;
        let rows = statement.query_map(params![operation_id], operation_attempt_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Reads the displayed page and its follow watermark from one SQLite
    /// snapshot so an event committed between the two reads cannot be skipped.
    pub fn filtered_events_with_high_water(
        &self,
        filters: &EventFilters,
    ) -> Result<(Vec<Event>, Option<u64>)> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let events = filtered_events(&transaction, filters)?;
        let high_water = event_high_water(&transaction, filters)?;
        transaction.commit()?;
        Ok((events, high_water))
    }
}

fn filtered_events(connection: &Connection, filters: &EventFilters) -> Result<Vec<Event>> {
    if filters.before.is_some() && filters.after.is_some() {
        anyhow::bail!("event history and follow positions are mutually exclusive");
    }
    let mut sql = "SELECT * FROM events WHERE 1 = 1".to_owned();
    let mut values = Vec::<rusqlite::types::Value>::new();
    if let Some(before) = filters.before {
        sql.push_str(" AND event_id < ?");
        values.push(i64::try_from(before)?.into());
    }
    if let Some(after) = filters.after {
        sql.push_str(" AND event_id > ?");
        values.push(i64::try_from(after)?.into());
    }
    for (column, value) in [
        ("severity", filters.severity.as_deref()),
        ("event_type", filters.event_type.as_deref()),
        ("trace_id", filters.trace_id.as_deref()),
        ("operation_id", filters.operation_id.as_deref()),
    ] {
        if let Some(value) = value {
            sql.push_str(" AND ");
            sql.push_str(column);
            sql.push_str(" = ?");
            values.push(value.to_owned().into());
        }
    }
    if let Some(created_after) = filters.created_after_unix_ms {
        sql.push_str(" AND created_at_unix_ms >= ?");
        values.push(i64::try_from(created_after)?.into());
    }
    if filters.after.is_some() {
        sql.push_str(" ORDER BY event_id ASC LIMIT ?");
    } else {
        sql.push_str(" ORDER BY event_id DESC LIMIT ?");
    }
    values.push(i64::try_from(filters.limit.clamp(1, 201))?.into());
    let mut statement = connection.prepare(&sql)?;
    let mut rows = statement.query(rusqlite::params_from_iter(values))?;
    let mut events = Vec::new();
    while let Some(row) = rows.next()? {
        events.push(event_from_row(row)?);
    }
    Ok(events)
}

fn event_high_water(connection: &Connection, filters: &EventFilters) -> Result<Option<u64>> {
    let mut sql = "SELECT MAX(event_id) FROM events WHERE 1 = 1".to_owned();
    let mut values = Vec::<rusqlite::types::Value>::new();
    for (column, value) in [
        ("severity", filters.severity.as_deref()),
        ("event_type", filters.event_type.as_deref()),
        ("trace_id", filters.trace_id.as_deref()),
        ("operation_id", filters.operation_id.as_deref()),
    ] {
        if let Some(value) = value {
            sql.push_str(" AND ");
            sql.push_str(column);
            sql.push_str(" = ?");
            values.push(value.to_owned().into());
        }
    }
    if let Some(created_after) = filters.created_after_unix_ms {
        sql.push_str(" AND created_at_unix_ms >= ?");
        values.push(i64::try_from(created_after)?.into());
    }
    connection
        .query_row(&sql, rusqlite::params_from_iter(values), |row| {
            row.get::<_, Option<i64>>(0)
        })?
        .map(TryInto::try_into)
        .transpose()
        .map_err(Into::into)
}

fn validate_persisted_operation_state(state: &str) -> Result<()> {
    anyhow::ensure!(
        matches!(
            state,
            "queued" | "running" | "interrupted" | "failed" | "succeeded"
        ),
        "operation has an invalid persisted state"
    );
    Ok(())
}

fn migrate(connection: &mut Connection) -> Result<()> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
            version INTEGER PRIMARY KEY
        );",
    )?;
    let (migration_count, version) = connection.query_row(
        "SELECT COUNT(*), MAX(version) FROM schema_migrations",
        [],
        |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Option<i64>>(1)?)),
    )?;
    anyhow::ensure!(
        matches!(
            (migration_count, version),
            (0, None) | (1, Some(1)) | (2, Some(2))
        ),
        "SQLite metadata uses an unsupported schema"
    );

    if migration_count == 0 {
        let transaction = connection.transaction()?;
        apply_initial_migration(&transaction)?;
        transaction.execute("INSERT INTO schema_migrations(version) VALUES (1)", [])?;
        transaction.commit()?;
    }
    if migration_count < 2 {
        let transaction = connection.transaction()?;
        apply_capture_mode_migration(&transaction)?;
        transaction.execute("INSERT INTO schema_migrations(version) VALUES (2)", [])?;
        transaction.commit()?;
    }
    Ok(())
}

fn apply_initial_migration(transaction: &rusqlite::Transaction<'_>) -> Result<()> {
    transaction.execute_batch(
        "CREATE TABLE traces (
                trace_id TEXT PRIMARY KEY CHECK (
                    length(trace_id) BETWEEN 5 AND 128
                    AND substr(trace_id, 1, 4) = 'trc-'
                    AND trace_id NOT GLOB '*[^A-Za-z0-9._-]*'
                ),
                created_at_unix_ms INTEGER NOT NULL,
                completed_at_unix_ms INTEGER,
                provider TEXT NOT NULL,
                operation TEXT NOT NULL,
                requested_model TEXT,
                response_model TEXT,
                http_status INTEGER,
                streaming INTEGER NOT NULL,
                request_bytes INTEGER NOT NULL,
                response_bytes INTEGER,
                duration_ms INTEGER,
                prompt_preview TEXT NOT NULL,
                prompt_preview_truncated INTEGER NOT NULL,
                output_preview TEXT NOT NULL DEFAULT '',
                output_preview_truncated INTEGER NOT NULL DEFAULT 0,
                config_fingerprint TEXT NOT NULL,
                capture_status TEXT NOT NULL CHECK (
                    capture_status IN ('capturing', 'captured', 'failed')
                ),
                notarization_status TEXT NOT NULL CHECK (
                    notarization_status IN (
                        'not_requested', 'queued', 'running', 'interrupted', 'failed', 'succeeded'
                    )
                ),
                failure_code TEXT,
                expected_artifact_size_bytes INTEGER,
                expected_artifact_sha256 TEXT,
                CHECK (
                    (expected_artifact_size_bytes IS NULL) =
                    (expected_artifact_sha256 IS NULL)
                )
            );
            CREATE TABLE artifacts (
                trace_id TEXT NOT NULL REFERENCES traces(trace_id),
                kind TEXT NOT NULL CHECK (kind IN ('capture_checkpoint', 'trace_package')),
                locator TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('available', 'missing')),
                PRIMARY KEY(trace_id, kind)
            );
            CREATE INDEX traces_created_page_idx
                ON traces(created_at_unix_ms DESC, trace_id DESC);
            CREATE INDEX traces_model_idx ON traces(requested_model);
            CREATE VIRTUAL TABLE trace_search USING fts5(
                trace_id UNINDEXED,
                prompt_preview,
                output_preview
            );
            CREATE TABLE operations (
                operation_id TEXT PRIMARY KEY CHECK (
                    length(operation_id) BETWEEN 4 AND 128
                    AND substr(operation_id, 1, 3) = 'op-'
                    AND operation_id NOT GLOB '*[^A-Za-z0-9._-]*'
                ),
                kind TEXT NOT NULL CHECK (kind = 'notarization'),
                trace_id TEXT NOT NULL REFERENCES traces(trace_id),
                state TEXT NOT NULL CHECK (
                    state IN ('queued', 'running', 'interrupted', 'failed', 'succeeded')
                ),
                attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
                created_at_unix_ms INTEGER NOT NULL,
                started_at_unix_ms INTEGER,
                completed_at_unix_ms INTEGER,
                failure_code TEXT,
                progress_phase TEXT NOT NULL DEFAULT 'queued',
                progress_updated_at_unix_ms INTEGER NOT NULL DEFAULT 0,
                proof_bytes_completed INTEGER NOT NULL DEFAULT 0,
                proof_bytes_total INTEGER NOT NULL DEFAULT 0,
                proof_commitments_completed INTEGER NOT NULL DEFAULT 0,
                proof_commitments_total INTEGER NOT NULL DEFAULT 0,
                CHECK (proof_bytes_completed <= proof_bytes_total),
                CHECK (proof_commitments_completed <= proof_commitments_total)
            );
            CREATE UNIQUE INDEX one_notarization_per_trace
                ON operations(trace_id, kind);
            CREATE INDEX operations_created_page_idx
                ON operations(created_at_unix_ms DESC, operation_id DESC);
            CREATE TABLE operation_attempts (
                operation_id TEXT NOT NULL REFERENCES operations(operation_id),
                attempt INTEGER NOT NULL CHECK (attempt > 0),
                state TEXT NOT NULL CHECK (
                    state IN ('running', 'interrupted', 'failed', 'succeeded')
                ),
                started_at_unix_ms INTEGER NOT NULL,
                completed_at_unix_ms INTEGER,
                failure_code TEXT,
                PRIMARY KEY(operation_id, attempt)
            );
            CREATE INDEX operation_attempts_started_idx
                ON operation_attempts(started_at_unix_ms DESC);
            CREATE TABLE events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at_unix_ms INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                trace_id TEXT REFERENCES traces(trace_id),
                operation_id TEXT REFERENCES operations(operation_id),
                severity TEXT NOT NULL,
                message TEXT NOT NULL
            );
            CREATE INDEX events_created_idx ON events(created_at_unix_ms DESC);
            CREATE TABLE trace_shares (
                trace_id TEXT PRIMARY KEY REFERENCES traces(trace_id) ON DELETE CASCADE,
                hosted_trace_id TEXT NOT NULL UNIQUE CHECK (length(hosted_trace_id) BETWEEN 1 AND 256),
                progress TEXT NOT NULL CHECK (
                    progress IN ('verifying', 'shared', 'stopped', 'rejected', 'failed')
                ),
                visibility TEXT NOT NULL CHECK (visibility IN ('listed', 'unlisted')),
                access_enabled INTEGER NOT NULL CHECK (access_enabled IN (0, 1)),
                password_protected INTEGER NOT NULL CHECK (password_protected IN (0, 1)),
                expires_at_unix_ms INTEGER,
                failure_code TEXT,
                share_url TEXT,
                package_url TEXT,
                updated_at_unix_ms INTEGER NOT NULL
            );
            CREATE TABLE settings (
                singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                capture_enabled INTEGER NOT NULL CHECK (capture_enabled IN (0, 1)),
                auto_seal_enabled INTEGER NOT NULL DEFAULT 0 CHECK (auto_seal_enabled IN (0, 1))
            );
            INSERT INTO settings (singleton, capture_enabled) VALUES (1, 1);",
    )?;
    Ok(())
}

/// Replaces the boolean capture setting with the three capture modes and
/// records each trace's evidence kind. Existing captures were all made with
/// Proxy-TLS, so they become Notarized; an enabled setting becomes
/// Notarized and a disabled one Off. The boolean column is removed so there
/// is one source of truth.
fn apply_capture_mode_migration(transaction: &rusqlite::Transaction<'_>) -> Result<()> {
    transaction.execute_batch(
        "ALTER TABLE settings ADD COLUMN capture_mode TEXT NOT NULL DEFAULT 'notarized'
             CHECK (capture_mode IN ('off', 'witnessed', 'notarized'));
         UPDATE settings
             SET capture_mode = CASE capture_enabled WHEN 1 THEN 'notarized' ELSE 'off' END;
         ALTER TABLE settings DROP COLUMN capture_enabled;
         ALTER TABLE traces ADD COLUMN evidence_kind TEXT NOT NULL DEFAULT 'notarized'
             CHECK (evidence_kind IN ('notarized', 'witnessed'));",
    )?;
    Ok(())
}

fn require_artifact(artifact: &ArtifactRecord, trace_id: &str, kind: ArtifactKind) -> Result<()> {
    if artifact.key.trace_id() != trace_id {
        anyhow::bail!("artifact capture does not match metadata transition");
    }
    if artifact.key.kind() != kind {
        anyhow::bail!("artifact kind does not match metadata transition");
    }
    Ok(())
}

fn insert_artifact(
    transaction: &rusqlite::Transaction<'_>,
    artifact: &ArtifactRecord,
) -> Result<()> {
    let changed = transaction.execute(
        "INSERT INTO artifacts (trace_id, kind, locator, size_bytes, sha256, state)
         VALUES (?, ?, ?, ?, ?, 'available')
         ON CONFLICT(trace_id, kind) DO NOTHING",
        params![
            artifact.key.trace_id(),
            artifact.key.kind().as_str(),
            artifact.locator.as_stored(),
            i64::try_from(artifact.size_bytes)?,
            artifact.sha256.as_str(),
        ],
    )?;
    anyhow::ensure!(
        changed == 1 || artifact_exists_exact(transaction, artifact)?,
        "artifact metadata conflicts with an existing immutable record"
    );
    Ok(())
}

fn artifact_exists_exact(
    transaction: &rusqlite::Transaction<'_>,
    artifact: &ArtifactRecord,
) -> Result<bool> {
    transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM artifacts
                WHERE trace_id = ? AND kind = ? AND locator = ?
                  AND size_bytes = ? AND sha256 = ? AND state = 'available'
             )",
            params![
                artifact.key.trace_id(),
                artifact.key.kind().as_str(),
                artifact.locator.as_stored(),
                i64::try_from(artifact.size_bytes)?,
                artifact.sha256.as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn capture_completion_matches(
    transaction: &rusqlite::Transaction<'_>,
    completion: &CaptureCompletion,
) -> Result<bool> {
    transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM traces
                WHERE trace_id = ?
                  AND completed_at_unix_ms = ? AND duration_ms = ? AND http_status = ?
                  AND response_bytes = ? AND response_model IS ?
                  AND output_preview = ? AND output_preview_truncated = ?
                  AND expected_artifact_size_bytes = ? AND expected_artifact_sha256 = ?
                  AND evidence_kind = ?
             )",
            params![
                completion.trace_id,
                i64::try_from(completion.completed_at_unix_ms)?,
                i64::try_from(completion.duration_ms)?,
                i64::from(completion.http_status),
                i64::try_from(completion.response_bytes)?,
                completion.response_model.as_deref(),
                completion.output_preview,
                completion.output_preview_truncated,
                i64::try_from(completion.expected_artifact_size_bytes)?,
                completion.expected_artifact_sha256,
                completion.evidence_kind.as_str(),
            ],
            |row| row.get(0),
        )
        .map_err(Into::into)
}

fn stored_evidence_kind(value: &str) -> Result<crate::metadata::EvidenceKind> {
    crate::metadata::parse_evidence_kind(value).context("stored evidence kind is unknown")
}

fn trace_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TraceSummary> {
    let evidence_kind = row.get::<_, String>("evidence_kind")?;
    let evidence_kind = crate::metadata::parse_evidence_kind(&evidence_kind).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Text,
            "stored evidence kind is unknown".into(),
        )
    })?;
    Ok(TraceSummary {
        evidence_kind,
        trace_id: row.get("trace_id")?,
        created_at_unix_ms: row
            .get::<_, i64>("created_at_unix_ms")?
            .try_into()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        completed_at_unix_ms: row
            .get::<_, Option<i64>>("completed_at_unix_ms")?
            .map(TryInto::try_into)
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        provider: row.get("provider")?,
        operation: row.get("operation")?,
        requested_model: row.get("requested_model")?,
        response_model: row.get("response_model")?,
        http_status: row
            .get::<_, Option<i64>>("http_status")?
            .map(TryInto::try_into)
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    7,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        streaming: row.get("streaming")?,
        request_bytes: row
            .get::<_, i64>("request_bytes")?
            .try_into()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    9,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        response_bytes: row
            .get::<_, Option<i64>>("response_bytes")?
            .map(TryInto::try_into)
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    10,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        duration_ms: row
            .get::<_, Option<i64>>("duration_ms")?
            .map(TryInto::try_into)
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    11,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        capture_status: row.get("capture_status")?,
        notarization_status: row.get("notarization_status")?,
        prompt_preview: row.get("prompt_preview")?,
        prompt_preview_truncated: row.get("prompt_preview_truncated")?,
        output_preview: row.get("output_preview")?,
        output_preview_truncated: row.get("output_preview_truncated")?,
        expected_artifact_size_bytes: row
            .get::<_, Option<i64>>("expected_artifact_size_bytes")?
            .map(TryInto::try_into)
            .transpose()
            .map_err(|error| {
                rusqlite::Error::FromSqlConversionFailure(
                    21,
                    rusqlite::types::Type::Integer,
                    Box::new(error),
                )
            })?,
        expected_artifact_sha256: row.get("expected_artifact_sha256")?,
        failure_code: row.get("failure_code")?,
    })
}

fn operation_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Operation> {
    Ok(Operation {
        operation_id: row.get("operation_id")?,
        kind: row.get("kind")?,
        trace_id: row.get("trace_id")?,
        state: row.get("state")?,
        attempt: row.get::<_, i64>("attempt")?.try_into().unwrap_or(0),
        created_at_unix_ms: row
            .get::<_, i64>("created_at_unix_ms")?
            .try_into()
            .unwrap_or(0),
        started_at_unix_ms: row
            .get::<_, Option<i64>>("started_at_unix_ms")?
            .and_then(|value| value.try_into().ok()),
        completed_at_unix_ms: row
            .get::<_, Option<i64>>("completed_at_unix_ms")?
            .and_then(|value| value.try_into().ok()),
        failure_code: row.get("failure_code")?,
        progress_phase: row.get("progress_phase")?,
        progress_updated_at_unix_ms: row
            .get::<_, i64>("progress_updated_at_unix_ms")?
            .try_into()
            .unwrap_or(0),
        proof_bytes_completed: row
            .get::<_, i64>("proof_bytes_completed")?
            .try_into()
            .unwrap_or(0),
        proof_bytes_total: row
            .get::<_, i64>("proof_bytes_total")?
            .try_into()
            .unwrap_or(0),
        proof_commitments_completed: row
            .get::<_, i64>("proof_commitments_completed")?
            .try_into()
            .unwrap_or(0),
        proof_commitments_total: row
            .get::<_, i64>("proof_commitments_total")?
            .try_into()
            .unwrap_or(0),
    })
}

fn operation_attempt_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationAttempt> {
    Ok(OperationAttempt {
        attempt: row.get::<_, i64>("attempt")?.try_into().unwrap_or(0),
        state: row.get("state")?,
        started_at_unix_ms: row
            .get::<_, i64>("started_at_unix_ms")?
            .try_into()
            .unwrap_or(0),
        completed_at_unix_ms: row
            .get::<_, Option<i64>>("completed_at_unix_ms")?
            .and_then(|value| value.try_into().ok()),
        failure_code: row.get("failure_code")?,
    })
}

fn event_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Event> {
    Ok(Event {
        event_id: row.get::<_, i64>("event_id")?.try_into().unwrap_or(0),
        created_at_unix_ms: row
            .get::<_, i64>("created_at_unix_ms")?
            .try_into()
            .unwrap_or(0),
        event_type: row.get("event_type")?,
        trace_id: row.get("trace_id")?,
        operation_id: row.get("operation_id")?,
        severity: row.get("severity")?,
        message: row.get("message")?,
    })
}

fn trace_share_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<TraceShareRecord> {
    let expires_at_unix_ms = row
        .get::<_, Option<i64>>("expires_at_unix_ms")?
        .map(TryInto::try_into)
        .transpose()
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                6,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?;
    let updated_at_unix_ms = row
        .get::<_, i64>("updated_at_unix_ms")?
        .try_into()
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                10,
                rusqlite::types::Type::Integer,
                Box::new(error),
            )
        })?;
    Ok(TraceShareRecord {
        trace_id: row.get("trace_id")?,
        hosted_trace_id: row.get("hosted_trace_id")?,
        progress: row.get("progress")?,
        visibility: row.get("visibility")?,
        access_enabled: row.get("access_enabled")?,
        password_protected: row.get("password_protected")?,
        expires_at_unix_ms,
        failure_code: row.get("failure_code")?,
        share_url: row.get("share_url")?,
        package_url: row.get("package_url")?,
        updated_at_unix_ms,
    })
}

/// A boolean column of the singleton settings row and its activity events.
struct Setting {
    column: &'static str,
    enabled: (&'static str, &'static str),
    disabled: (&'static str, &'static str),
}

impl Setting {
    fn event(&self, enabled: bool) -> (&'static str, &'static str) {
        if enabled { self.enabled } else { self.disabled }
    }
}

const AUTO_SEAL_SETTING: Setting = Setting {
    column: "auto_seal_enabled",
    enabled: ("auto_seal_enabled", "Auto-seal enabled"),
    disabled: ("auto_seal_disabled", "Auto-seal disabled"),
};

fn insert_event(
    transaction: &rusqlite::Transaction<'_>,
    now: u64,
    event_type: &str,
    trace_id: Option<&str>,
    operation_id: Option<&str>,
    severity: &str,
    message: &str,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO events (created_at_unix_ms, event_type, trace_id, operation_id, severity, message) VALUES (?, ?, ?, ?, ?, ?)",
        params![i64::try_from(now)?, event_type, trace_id, operation_id, severity, message],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_an_unknown_migration_journal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("metadata.db");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);
                 INSERT INTO schema_migrations(version) VALUES (1), (2), (3);",
            )
            .unwrap();
        drop(connection);

        let error = match SqliteMetadata::open(&path, true) {
            Ok(_) => panic!("an unknown schema was accepted"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unsupported schema"));
    }

    #[test]
    fn version_one_metadata_upgrades_to_capture_modes() {
        for (enabled, expected) in [(0, CaptureMode::Off), (1, CaptureMode::Notarized)] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("metadata.db");
            let mut connection = Connection::open(&path).unwrap();
            connection
                .execute_batch("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY);")
                .unwrap();
            let transaction = connection.transaction().unwrap();
            apply_initial_migration(&transaction).unwrap();
            transaction
                .execute("INSERT INTO schema_migrations(version) VALUES (1)", [])
                .unwrap();
            transaction
                .execute("UPDATE settings SET capture_enabled = ?", [enabled])
                .unwrap();
            transaction
                .execute(
                    "INSERT INTO traces (
                        trace_id, created_at_unix_ms, provider, operation, streaming,
                        request_bytes, prompt_preview, prompt_preview_truncated,
                        config_fingerprint, capture_status, notarization_status
                     ) VALUES ('trc-old', 1, 'openai', '/v1/responses', 0, 1, '', 0,
                               'fingerprint', 'failed', 'not_requested')",
                    [],
                )
                .unwrap();
            transaction.commit().unwrap();
            drop(connection);

            let metadata = SqliteMetadata::open(&path, true).unwrap();
            metadata.readiness().unwrap();
            assert_eq!(metadata.capture_mode().unwrap(), expected);
            assert_eq!(
                metadata.trace("trc-old").unwrap().unwrap().evidence_kind,
                crate::metadata::EvidenceKind::Notarized
            );
        }
    }

    #[test]
    fn poisoned_connection_returns_errors_instead_of_panicking() {
        let directory = tempfile::tempdir().unwrap();
        let metadata = SqliteMetadata::open(&directory.path().join("metadata.db"), true).unwrap();
        metadata.readiness().unwrap();

        let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _connection = metadata.connection().unwrap();
            panic!("simulated panic while holding the metadata connection");
        }));
        assert!(panicked.is_err());
        assert!(metadata.connection.is_poisoned());

        let error = metadata.readiness().unwrap_err();
        assert!(error.to_string().contains("unavailable after a panic"));
        assert!(metadata.capture_mode().is_err());
        assert!(metadata.counts().is_err());
    }
}
