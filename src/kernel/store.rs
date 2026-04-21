use rusqlite::{Connection, OptionalExtension, params};
use serde::Serialize;
use std::path::{Path, PathBuf};

use super::anchor::{AnchorLog, DEFAULT_ANCHOR_ROTATE_LINES};
use super::audit::{
    AuditEntry, AuditLog, AuditStatus, HASH_FORMAT_VERSION, HMAC_KEY_LEN, SignedEntry,
};
use super::{KernelError, KernelResult};

const SCHEMA_V1_SQL: &str = include_str!("migrations/v1.sql");
const CURRENT_SCHEMA_VERSION: &str = "1";
const SCHEMA_META_BOOTSTRAP: &str = r#"
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
"#;

pub struct AuditStore {
    conn: Connection,
    log: AuditLog,
    anchor: AnchorLog,
    db_path: PathBuf,
}

impl AuditStore {
    pub fn open(db_path: &Path, anchor_dir: &Path, key: Vec<u8>) -> KernelResult<Self> {
        if key.len() != HMAC_KEY_LEN {
            return Err(KernelError::Audit(format!(
                "HMAC key length {} != expected {}",
                key.len(),
                HMAC_KEY_LEN
            )));
        }

        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let conn = Connection::open(db_path)
            .map_err(|e| KernelError::Audit(format!("open sqlite: {e}")))?;
        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| KernelError::Audit(format!("set WAL: {e}")))?;
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| KernelError::Audit(format!("set synchronous: {e}")))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| KernelError::Audit(format!("set FK: {e}")))?;

        apply_migrations(&conn)?;

        let persisted = load_all_entries(&conn)?;
        let log = AuditLog::from_persisted(persisted, key)?;
        let anchor = AnchorLog::open(anchor_dir, DEFAULT_ANCHOR_ROTATE_LINES)?;

        let store = Self {
            conn,
            log,
            anchor,
            db_path: db_path.to_path_buf(),
        };
        store.verify()?;
        Ok(store)
    }

    pub fn record<T: Serialize>(
        &mut self,
        tool: &str,
        args: &T,
        status: AuditStatus,
    ) -> KernelResult<SignedEntry> {
        let signed = self.log.record(tool, args, status)?.clone();
        if let Err(e) = insert_entry(&self.conn, &signed) {
            let _ = self.log.rollback_last();
            return Err(e);
        }
        if let Err(e) = self.anchor.append_entry(&signed) {
            eprintln!("[reli] warn: anchor append failed: {e}");
        }
        Ok(signed)
    }

    pub fn verify(&self) -> KernelResult<()> {
        self.log.verify()?;
        if let Some(latest) = self.anchor.latest()? {
            match self.log.entry_hmac_at(latest.sequence_no) {
                Some(hmac) => {
                    if hmac != latest.hmac {
                        return Err(KernelError::AuditCorrupted {
                            sequence_no: latest.sequence_no,
                            reason: "anchor hmac does not match DB hmac".into(),
                        });
                    }
                }
                None => {
                    return Err(KernelError::AuditCorrupted {
                        sequence_no: latest.sequence_no,
                        reason: "anchor references a sequence_no missing from DB (truncation?)"
                            .into(),
                    });
                }
            }
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.log.len()
    }

    pub fn last_hmac(&self) -> Option<&str> {
        self.log.last_hmac()
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    #[cfg(test)]
    pub(super) fn connection(&self) -> &Connection {
        &self.conn
    }
}

fn apply_migrations(conn: &Connection) -> KernelResult<()> {
    conn.execute_batch(SCHEMA_META_BOOTSTRAP)
        .map_err(|e| KernelError::Audit(format!("bootstrap schema_meta: {e}")))?;

    let version: Option<String> = conn
        .query_row(
            "SELECT value FROM schema_meta WHERE key = 'schema_version'",
            [],
            |row| row.get::<_, String>(0),
        )
        .optional()
        .map_err(|e| KernelError::Audit(format!("read schema_version: {e}")))?;

    match version.as_deref() {
        None => {
            conn.execute_batch(SCHEMA_V1_SQL)
                .map_err(|e| KernelError::Audit(format!("apply migration v1: {e}")))?;
            Ok(())
        }
        Some(v) if v == CURRENT_SCHEMA_VERSION => Ok(()),
        Some(other) => Err(KernelError::Audit(format!(
            "unsupported schema version {other} (expected {CURRENT_SCHEMA_VERSION})"
        ))),
    }
}

fn insert_entry(conn: &Connection, signed: &SignedEntry) -> KernelResult<()> {
    let (status_kind, status_reason): (&str, Option<&str>) = match &signed.entry.status {
        AuditStatus::Ok => ("ok", None),
        AuditStatus::Rejected { reason } => ("rejected", Some(reason.as_str())),
    };
    let seq_i64: i64 = signed
        .entry
        .sequence_no
        .try_into()
        .map_err(|_| KernelError::Audit("sequence_no overflows i64".into()))?;
    conn.execute(
        "INSERT INTO audit_entries (
            sequence_no, timestamp, tool, args_hash,
            status_kind, status_reason, prev_hmac, hmac, hash_format_version
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            seq_i64,
            signed.entry.timestamp,
            signed.entry.tool,
            signed.entry.args_hash,
            status_kind,
            status_reason,
            signed.entry.prev_hmac,
            signed.hmac,
            signed.entry.hash_format_version as i64,
        ],
    )
    .map_err(|e| KernelError::Audit(format!("insert audit entry: {e}")))?;
    Ok(())
}

fn load_all_entries(conn: &Connection) -> KernelResult<Vec<SignedEntry>> {
    let mut stmt = conn
        .prepare(
            "SELECT sequence_no, timestamp, tool, args_hash,
                    status_kind, status_reason, prev_hmac, hmac, hash_format_version
             FROM audit_entries ORDER BY sequence_no ASC",
        )
        .map_err(|e| KernelError::Audit(format!("prepare load: {e}")))?;

    let rows = stmt
        .query_map([], |row| {
            let seq: i64 = row.get(0)?;
            let timestamp: String = row.get(1)?;
            let tool: String = row.get(2)?;
            let args_hash: String = row.get(3)?;
            let status_kind: String = row.get(4)?;
            let status_reason: Option<String> = row.get(5)?;
            let prev_hmac: String = row.get(6)?;
            let hmac: String = row.get(7)?;
            let hfv: i64 = row.get(8)?;

            let status = match status_kind.as_str() {
                "ok" => AuditStatus::Ok,
                "rejected" => AuditStatus::Rejected {
                    reason: status_reason.unwrap_or_default(),
                },
                other => {
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Text,
                        format!("unknown status_kind: {other}").into(),
                    ));
                }
            };

            let seq_u64: u64 = seq
                .try_into()
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, seq))?;
            let hfv_u32: u32 = hfv
                .try_into()
                .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(8, hfv))?;

            let entry = AuditEntry {
                sequence_no: seq_u64,
                timestamp,
                tool,
                args_hash,
                status,
                prev_hmac,
                hash_format_version: hfv_u32,
            };
            Ok(SignedEntry { entry, hmac })
        })
        .map_err(|e| KernelError::Audit(format!("query entries: {e}")))?;

    let mut out = Vec::new();
    for r in rows {
        let row = r.map_err(|e| KernelError::Audit(format!("read row: {e}")))?;
        if row.entry.hash_format_version != HASH_FORMAT_VERSION {
            return Err(KernelError::Audit(format!(
                "unsupported hash_format_version {} in row {}",
                row.entry.hash_format_version, row.entry.sequence_no
            )));
        }
        out.push(row);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use tempfile::TempDir;

    const TEST_KEY: [u8; HMAC_KEY_LEN] = [0x5a; HMAC_KEY_LEN];

    #[derive(Serialize)]
    struct WriteArgs<'a> {
        path: &'a str,
        bytes: usize,
    }

    fn fresh_store() -> (TempDir, AuditStore) {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        let store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
        (tmp, store)
    }

    #[test]
    fn fresh_store_is_empty_and_verifies() {
        let (_tmp, store) = fresh_store();
        assert_eq!(store.len(), 0);
        assert!(store.last_hmac().is_none());
        store.verify().unwrap();
    }

    #[test]
    fn append_persists_and_verifies_across_reopen() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");

        let hmac_after_record = {
            let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
            let s1 = store
                .record(
                    "write_file",
                    &WriteArgs {
                        path: "a.txt",
                        bytes: 4,
                    },
                    AuditStatus::Ok,
                )
                .unwrap();
            let _s2 = store
                .record(
                    "write_file",
                    &WriteArgs {
                        path: "b.txt",
                        bytes: 1,
                    },
                    AuditStatus::Ok,
                )
                .unwrap();
            let s3 = store
                .record(
                    "write_file",
                    &WriteArgs {
                        path: "../x",
                        bytes: 0,
                    },
                    AuditStatus::Rejected {
                        reason: "PathOutsideSandbox".into(),
                    },
                )
                .unwrap();
            assert_eq!(s1.entry.sequence_no, 0);
            assert_eq!(s3.entry.sequence_no, 2);
            store.verify().unwrap();
            store.last_hmac().unwrap().to_string()
        };

        let reopened = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
        assert_eq!(reopened.len(), 3);
        assert_eq!(reopened.last_hmac().unwrap(), hmac_after_record);
        reopened.verify().unwrap();
    }

    #[test]
    fn reopen_with_wrong_key_fails_verification() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        {
            let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
            store
                .record(
                    "write_file",
                    &WriteArgs {
                        path: "a.txt",
                        bytes: 4,
                    },
                    AuditStatus::Ok,
                )
                .unwrap();
        }
        let wrong_key = vec![0xff; HMAC_KEY_LEN];
        let res = AuditStore::open(&db, &anchor, wrong_key);
        assert!(matches!(res, Err(KernelError::AuditCorrupted { .. })));
    }

    #[test]
    fn tampered_hmac_in_db_is_detected_on_reopen() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        {
            let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
            store
                .record(
                    "write_file",
                    &WriteArgs {
                        path: "a.txt",
                        bytes: 4,
                    },
                    AuditStatus::Ok,
                )
                .unwrap();
        }
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute(
                "UPDATE audit_entries SET hmac = ? WHERE sequence_no = 0",
                params!["00".repeat(32)],
            )
            .unwrap();
        }
        let res = AuditStore::open(&db, &anchor, TEST_KEY.to_vec());
        assert!(matches!(res, Err(KernelError::AuditCorrupted { .. })));
    }

    #[test]
    fn tampered_tool_field_is_detected_on_reopen() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        {
            let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
            store
                .record(
                    "write_file",
                    &WriteArgs {
                        path: "a.txt",
                        bytes: 4,
                    },
                    AuditStatus::Ok,
                )
                .unwrap();
        }
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute(
                "UPDATE audit_entries SET tool = 'read_file' WHERE sequence_no = 0",
                [],
            )
            .unwrap();
        }
        let res = AuditStore::open(&db, &anchor, TEST_KEY.to_vec());
        assert!(matches!(res, Err(KernelError::AuditCorrupted { .. })));
    }

    #[test]
    fn truncation_is_detected_via_anchor() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        {
            let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
            for i in 0..4 {
                store
                    .record(
                        "write_file",
                        &WriteArgs {
                            path: "a.txt",
                            bytes: i,
                        },
                        AuditStatus::Ok,
                    )
                    .unwrap();
            }
            store.verify().unwrap();
        }
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute("DELETE FROM audit_entries WHERE sequence_no >= 2", [])
                .unwrap();
        }
        let res = AuditStore::open(&db, &anchor, TEST_KEY.to_vec());
        assert!(matches!(res, Err(KernelError::AuditCorrupted { .. })));
    }

    #[test]
    fn migrations_are_idempotent() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        let _ = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
        let store2 = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
        let version: String = store2
            .connection()
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(version, "1");
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(SCHEMA_META_BOOTSTRAP).unwrap();
            conn.execute(
                "INSERT INTO schema_meta (key, value) VALUES ('schema_version', '9999')",
                [],
            )
            .unwrap();
        }
        let res = AuditStore::open(&db, &anchor, TEST_KEY.to_vec());
        assert!(matches!(res, Err(KernelError::Audit(_))));
    }

    #[test]
    fn rejects_wrong_key_length() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        let res = AuditStore::open(&db, &anchor, vec![0u8; 16]);
        assert!(matches!(res, Err(KernelError::Audit(_))));
    }

    #[test]
    fn anchor_consistency_after_many_appends_triggers_rotation() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
        // Con DEFAULT_ANCHOR_ROTATE_LINES = 100, 250 entradas producen al menos 2 rotaciones.
        for i in 0..250 {
            store
                .record(
                    "write_file",
                    &WriteArgs {
                        path: "x.txt",
                        bytes: i,
                    },
                    AuditStatus::Ok,
                )
                .unwrap();
        }
        store.verify().unwrap();
        assert_eq!(store.len(), 250);
    }
}
