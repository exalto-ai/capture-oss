-- Replace the boolean capture setting with the three capture modes and record
-- each trace's evidence kind. Existing captures were all made with Proxy-TLS,
-- so they are Notarized; an enabled setting becomes Notarized and a disabled
-- one Off. The boolean column is removed so there is one source of truth.
ALTER TABLE captured.settings
    ADD COLUMN capture_mode TEXT NOT NULL DEFAULT 'notarized'
    CHECK (capture_mode IN ('off', 'witnessed', 'notarized'));
UPDATE captured.settings
    SET capture_mode = CASE WHEN capture_enabled THEN 'notarized' ELSE 'off' END;
ALTER TABLE captured.settings DROP COLUMN capture_enabled;
ALTER TABLE captured.traces
    ADD COLUMN evidence_kind TEXT NOT NULL DEFAULT 'notarized'
    CHECK (evidence_kind IN ('notarized', 'witnessed'));
