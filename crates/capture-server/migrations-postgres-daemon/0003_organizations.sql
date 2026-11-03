-- Organizations share one capture server and never see each other's data.
-- Every Trace, operation and event belongs to an organization, and capture
-- settings are per organization. Rows written before this migration belong
-- to the server's default organization. Child rows (artifacts, attempts,
-- search documents, shares) belong to their Trace's or operation's
-- organization, and every query reaches them through it.

ALTER TABLE captured.traces
    ADD COLUMN organization_id TEXT NOT NULL DEFAULT 'default' CHECK (
        length(organization_id) BETWEEN 1 AND 128
        AND organization_id ~ '^[A-Za-z0-9_-][A-Za-z0-9._-]*$'
    );
ALTER TABLE captured.traces ALTER COLUMN organization_id DROP DEFAULT;
ALTER TABLE captured.traces ADD UNIQUE (organization_id, trace_id);

DROP INDEX captured.traces_created_page_idx;
CREATE INDEX traces_created_page_idx
    ON captured.traces(organization_id, created_at_unix_ms DESC, trace_id DESC);
DROP INDEX captured.traces_model_idx;
CREATE INDEX traces_model_idx
    ON captured.traces(organization_id, requested_model);

-- An operation names its Trace together with the Trace's organization, so
-- the database refuses an operation on another organization's Trace.
ALTER TABLE captured.operations
    ADD COLUMN organization_id TEXT;
UPDATE captured.operations AS operations
SET organization_id = traces.organization_id
FROM captured.traces
WHERE traces.trace_id = operations.trace_id;
ALTER TABLE captured.operations
    ALTER COLUMN organization_id SET NOT NULL,
    ADD FOREIGN KEY (organization_id, trace_id)
        REFERENCES captured.traces(organization_id, trace_id);

DROP INDEX captured.operations_created_page_idx;
CREATE INDEX operations_created_page_idx
    ON captured.operations(organization_id, created_at_unix_ms DESC, operation_id DESC);

ALTER TABLE captured.events
    ADD COLUMN organization_id TEXT;
UPDATE captured.events SET organization_id = 'default';
ALTER TABLE captured.events
    ALTER COLUMN organization_id SET NOT NULL,
    ADD CHECK (
        length(organization_id) BETWEEN 1 AND 128
        AND organization_id ~ '^[A-Za-z0-9_-][A-Za-z0-9._-]*$'
    );

DROP INDEX captured.events_created_idx;
CREATE INDEX events_created_idx
    ON captured.events(organization_id, created_at_unix_ms DESC);
CREATE INDEX events_page_idx
    ON captured.events(organization_id, event_id);

-- Capture mode and auto-seal are each organization's own. An organization
-- with no row uses the defaults: Notarized capture, auto-seal off.
CREATE TABLE captured.organization_settings (
    organization_id TEXT PRIMARY KEY CHECK (
        length(organization_id) BETWEEN 1 AND 128
        AND organization_id ~ '^[A-Za-z0-9_-][A-Za-z0-9._-]*$'
    ),
    capture_mode TEXT NOT NULL CHECK (capture_mode IN ('off', 'witnessed', 'notarized')),
    auto_seal_enabled BOOLEAN NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);
INSERT INTO captured.organization_settings (organization_id, capture_mode, auto_seal_enabled)
SELECT 'default', capture_mode, auto_seal_enabled FROM captured.settings;

-- What remains in settings is the cluster's own configuration fingerprint.
ALTER TABLE captured.settings
    DROP COLUMN capture_mode,
    DROP COLUMN auto_seal_enabled;
