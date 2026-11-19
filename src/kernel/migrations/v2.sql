-- ReliAgent audit log schema — version 2 (hash_format_version 2).
-- Cada acción se registra en dos filas: `pending` antes de ejecutarse y su
-- resolución (`ok` / `error` / `rejected`) con `resolves_seq` apuntando al
-- `pending`. SQLite no permite cambiar un CHECK con ALTER TABLE, así que se
-- recrea la tabla conservando todas las filas v1 tal cual (sus HMAC no
-- cambian: `resolves_seq` es NULL y no forma parte de sus bytes firmados).

BEGIN;

CREATE TABLE audit_entries_v2 (
    sequence_no         INTEGER PRIMARY KEY,
    timestamp           TEXT    NOT NULL,
    tool                TEXT    NOT NULL,
    args_hash           TEXT    NOT NULL,
    status_kind         TEXT    NOT NULL
                        CHECK (status_kind IN ('pending','ok','error','rejected')),
    status_reason       TEXT,
    resolves_seq        INTEGER,
    prev_hmac           TEXT    NOT NULL,
    hmac                TEXT    NOT NULL UNIQUE,
    hash_format_version INTEGER NOT NULL
);

INSERT INTO audit_entries_v2 (
    sequence_no, timestamp, tool, args_hash, status_kind, status_reason,
    resolves_seq, prev_hmac, hmac, hash_format_version
)
SELECT sequence_no, timestamp, tool, args_hash, status_kind, status_reason,
       NULL, prev_hmac, hmac, hash_format_version
  FROM audit_entries;

DROP TABLE audit_entries;
ALTER TABLE audit_entries_v2 RENAME TO audit_entries;

CREATE INDEX idx_audit_entries_tool ON audit_entries (tool);
CREATE INDEX idx_audit_entries_timestamp ON audit_entries (timestamp);
-- Un `pending` se resuelve como mucho una vez (NULL no cuenta como duplicado).
CREATE UNIQUE INDEX idx_audit_entries_resolves ON audit_entries (resolves_seq);

INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('schema_version', '2');

COMMIT;
