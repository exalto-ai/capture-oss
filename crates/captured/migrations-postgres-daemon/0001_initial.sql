CREATE TABLE captured.traces (
    trace_id TEXT PRIMARY KEY CHECK (
        length(trace_id) BETWEEN 5 AND 128
        AND trace_id ~ '^trc-[A-Za-z0-9._-]+$'
    ),
    created_at_unix_ms BIGINT NOT NULL CHECK (created_at_unix_ms >= 0),
    completed_at_unix_ms BIGINT CHECK (completed_at_unix_ms >= 0),
    provider TEXT NOT NULL,
    operation TEXT NOT NULL,
    requested_model TEXT,
    response_model TEXT,
    http_status INTEGER CHECK (http_status BETWEEN 0 AND 65535),
    streaming BOOLEAN NOT NULL,
    request_bytes BIGINT NOT NULL CHECK (request_bytes >= 0),
    response_bytes BIGINT CHECK (response_bytes >= 0),
    duration_ms BIGINT CHECK (duration_ms >= 0),
    prompt_preview TEXT NOT NULL,
    prompt_preview_truncated BOOLEAN NOT NULL,
    output_preview TEXT NOT NULL DEFAULT '',
    output_preview_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    config_fingerprint TEXT NOT NULL,
    capture_status TEXT NOT NULL CHECK (capture_status IN ('capturing', 'captured', 'failed')),
    notarization_status TEXT NOT NULL CHECK (
        notarization_status IN ('not_requested', 'queued', 'running', 'interrupted', 'failed', 'succeeded')
    ),
    failure_code TEXT
);

CREATE INDEX traces_created_page_idx
    ON captured.traces(created_at_unix_ms DESC, trace_id DESC);
CREATE INDEX traces_model_idx
    ON captured.traces(requested_model);

CREATE TABLE captured.trace_search (
    trace_id TEXT PRIMARY KEY REFERENCES captured.traces(trace_id) ON DELETE CASCADE,
    prompt_document TSVECTOR NOT NULL,
    output_document TSVECTOR NOT NULL
);
CREATE INDEX trace_search_prompt_document_idx
    ON captured.trace_search USING GIN(prompt_document);
CREATE INDEX trace_search_output_document_idx
    ON captured.trace_search USING GIN(output_document);

CREATE TABLE captured.artifacts (
    trace_id TEXT NOT NULL REFERENCES captured.traces(trace_id),
    kind TEXT NOT NULL CHECK (kind IN ('capture_checkpoint', 'trace_package')),
    locator TEXT NOT NULL,
    size_bytes BIGINT NOT NULL CHECK (size_bytes >= 0),
    sha256 TEXT NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    state TEXT NOT NULL CHECK (state IN ('available', 'missing')),
    PRIMARY KEY(trace_id, kind)
);

CREATE TABLE captured.operations (
    operation_id TEXT PRIMARY KEY CHECK (
        length(operation_id) BETWEEN 4 AND 128
        AND operation_id ~ '^op-[A-Za-z0-9._-]+$'
    ),
    kind TEXT NOT NULL CHECK (kind = 'notarization'),
    trace_id TEXT NOT NULL REFERENCES captured.traces(trace_id),
    state TEXT NOT NULL CHECK (state IN ('queued', 'running', 'interrupted', 'failed', 'succeeded')),
    attempt INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    created_at_unix_ms BIGINT NOT NULL CHECK (created_at_unix_ms >= 0),
    started_at_unix_ms BIGINT CHECK (started_at_unix_ms >= 0),
    completed_at_unix_ms BIGINT CHECK (completed_at_unix_ms >= 0),
    failure_code TEXT,
    progress_phase TEXT NOT NULL DEFAULT 'queued',
    progress_updated_at_unix_ms BIGINT NOT NULL DEFAULT 0 CHECK (progress_updated_at_unix_ms >= 0),
    proof_bytes_completed BIGINT NOT NULL DEFAULT 0 CHECK (proof_bytes_completed >= 0),
    proof_bytes_total BIGINT NOT NULL DEFAULT 0 CHECK (proof_bytes_total >= 0),
    proof_commitments_completed BIGINT NOT NULL DEFAULT 0 CHECK (proof_commitments_completed >= 0),
    proof_commitments_total BIGINT NOT NULL DEFAULT 0 CHECK (proof_commitments_total >= 0),
    CHECK (proof_bytes_completed <= proof_bytes_total),
    CHECK (proof_commitments_completed <= proof_commitments_total)
);
CREATE UNIQUE INDEX one_notarization_per_trace
    ON captured.operations(trace_id, kind);
CREATE INDEX operations_created_page_idx
    ON captured.operations(created_at_unix_ms DESC, operation_id DESC);

CREATE TABLE captured.operation_attempts (
    operation_id TEXT NOT NULL REFERENCES captured.operations(operation_id),
    attempt INTEGER NOT NULL CHECK (attempt > 0),
    state TEXT NOT NULL CHECK (state IN ('running', 'interrupted', 'failed', 'succeeded')),
    started_at_unix_ms BIGINT NOT NULL CHECK (started_at_unix_ms >= 0),
    completed_at_unix_ms BIGINT CHECK (completed_at_unix_ms >= 0),
    failure_code TEXT,
    PRIMARY KEY(operation_id, attempt)
);
CREATE INDEX operation_attempts_started_idx
    ON captured.operation_attempts(started_at_unix_ms DESC);

CREATE TABLE captured.events (
    event_id BIGSERIAL PRIMARY KEY,
    created_at_unix_ms BIGINT NOT NULL CHECK (created_at_unix_ms >= 0),
    event_type TEXT NOT NULL,
    trace_id TEXT REFERENCES captured.traces(trace_id),
    operation_id TEXT REFERENCES captured.operations(operation_id),
    severity TEXT NOT NULL,
    message TEXT NOT NULL
);
CREATE INDEX events_created_idx
    ON captured.events(created_at_unix_ms DESC);

CREATE TABLE captured.trace_shares (
    trace_id TEXT PRIMARY KEY REFERENCES captured.traces(trace_id) ON DELETE CASCADE,
    hosted_trace_id TEXT NOT NULL UNIQUE CHECK (length(hosted_trace_id) BETWEEN 1 AND 256),
    progress TEXT NOT NULL CHECK (
        progress IN ('verifying', 'shared', 'stopped', 'rejected', 'failed')
    ),
    visibility TEXT NOT NULL CHECK (visibility IN ('listed', 'unlisted')),
    access_enabled BOOLEAN NOT NULL,
    password_protected BOOLEAN NOT NULL,
    expires_at_unix_ms BIGINT CHECK (expires_at_unix_ms >= 0),
    failure_code TEXT,
    share_url TEXT,
    package_url TEXT,
    updated_at_unix_ms BIGINT NOT NULL CHECK (updated_at_unix_ms >= 0)
);

ALTER TABLE captured.traces
    ADD COLUMN expected_artifact_size_bytes BIGINT CHECK (expected_artifact_size_bytes >= 0),
    ADD COLUMN expected_artifact_sha256 TEXT CHECK (
        expected_artifact_sha256 ~ '^[0-9a-f]{64}$'
    ),
    ADD COLUMN owner_instance_id TEXT,
    ADD COLUMN owner_incarnation_id UUID,
    ADD COLUMN capture_fence UUID,
    ADD COLUMN artifact_commit_id UUID,
    ADD COLUMN claim_lease_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT capture_artifact_expectation_complete CHECK (
        (expected_artifact_size_bytes IS NULL) = (expected_artifact_sha256 IS NULL)
    ),
    ADD CONSTRAINT traces_claim_all_or_none CHECK (
        (owner_instance_id IS NULL AND owner_incarnation_id IS NULL AND capture_fence IS NULL
         AND artifact_commit_id IS NULL AND claim_lease_expires_at IS NULL)
        OR
        (owner_instance_id IS NOT NULL AND owner_incarnation_id IS NOT NULL AND capture_fence IS NOT NULL
         AND artifact_commit_id IS NOT NULL AND claim_lease_expires_at IS NOT NULL)
    );
CREATE INDEX traces_expired_claim_idx
    ON captured.traces(claim_lease_expires_at, trace_id)
    WHERE capture_status = 'capturing';

ALTER TABLE captured.operations
    ADD COLUMN owner_instance_id TEXT,
    ADD COLUMN owner_incarnation_id UUID,
    ADD COLUMN claim_fence UUID,
    ADD COLUMN artifact_commit_id UUID,
    ADD COLUMN claim_lease_expires_at TIMESTAMPTZ,
    ADD CONSTRAINT operations_claim_all_or_none CHECK (
        (owner_instance_id IS NULL AND owner_incarnation_id IS NULL AND claim_fence IS NULL
         AND artifact_commit_id IS NULL AND claim_lease_expires_at IS NULL)
        OR
        (owner_instance_id IS NOT NULL AND owner_incarnation_id IS NOT NULL AND claim_fence IS NOT NULL
         AND artifact_commit_id IS NOT NULL AND claim_lease_expires_at IS NOT NULL)
    );
CREATE INDEX operations_server_queue_idx
    ON captured.operations(created_at_unix_ms, operation_id)
    WHERE kind = 'notarization' AND state = 'queued';
CREATE INDEX operations_expired_claim_idx
    ON captured.operations(claim_lease_expires_at, operation_id)
    WHERE kind = 'notarization' AND state = 'running';

ALTER TABLE captured.operation_attempts
    ADD COLUMN owner_instance_id TEXT,
    ADD COLUMN owner_incarnation_id UUID,
    ADD COLUMN claim_fence UUID;

ALTER TABLE captured.artifacts
    ADD COLUMN commit_id UUID;

CREATE TABLE captured.replicas (
    instance_id TEXT PRIMARY KEY,
    incarnation_id UUID NOT NULL,
    heartbeat_at TIMESTAMPTZ NOT NULL,
    lease_expires_at TIMESTAMPTZ NOT NULL,
    CHECK (length(instance_id) BETWEEN 1 AND 64)
);

CREATE TABLE captured.sessions (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    created_at_unix_ms BIGINT NOT NULL CHECK (created_at_unix_ms >= 0),
    expires_at_unix_ms BIGINT NOT NULL CHECK (expires_at_unix_ms > created_at_unix_ms)
);
CREATE INDEX sessions_expiry_idx ON captured.sessions(expires_at_unix_ms);

CREATE TABLE captured.settings (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    capture_enabled BOOLEAN NOT NULL,
    auto_seal_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    compatibility_sha256 TEXT CHECK (compatibility_sha256 ~ '^[0-9a-f]{64}$'),
    configured_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO captured.settings (singleton, capture_enabled) VALUES (TRUE, TRUE);

CREATE TABLE captured.registry (
    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
    generation BIGINT NOT NULL CHECK (generation >= 0),
    registry_sha256 TEXT NOT NULL CHECK (registry_sha256 ~ '^[0-9a-f]{64}$'),
    registry_source TEXT NOT NULL CHECK (length(registry_source) BETWEEN 1 AND 2048),
    active_key_id TEXT NOT NULL CHECK (length(active_key_id) BETWEEN 1 AND 128),
    registry_json BYTEA NOT NULL CHECK (octet_length(registry_json) BETWEEN 1 AND 1048576),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
