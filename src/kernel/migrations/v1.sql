-- ReliAgent audit log schema — version 1 (formato final de v0.0.3).
-- Todas las columnas obligatorias son NOT NULL. Los campos del HMAC se
-- almacenan como hex ASCII (lowercase); las longitudes no se enforzan aquí
-- sino en el código (kernel::audit::HMAC_KEY_LEN y derivados).

BEGIN;

CREATE TABLE IF NOT EXISTS audit_entries (
    sequence_no         INTEGER PRIMARY KEY,
    timestamp           TEXT    NOT NULL,
    tool                TEXT    NOT NULL,
    args_hash           TEXT    NOT NULL,
    status_kind         TEXT    NOT NULL CHECK (status_kind IN ('ok','rejected')),
    status_reason       TEXT,
    prev_hmac           TEXT    NOT NULL,
    hmac                TEXT    NOT NULL UNIQUE,
    hash_format_version INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_entries_tool
    ON audit_entries (tool);

CREATE INDEX IF NOT EXISTS idx_audit_entries_timestamp
    ON audit_entries (timestamp);

INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '1');

COMMIT;
