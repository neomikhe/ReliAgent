use rusqlite::config::DbConfig;
use rusqlite::limits::Limit;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use serde::Serialize;
use std::path::{Path, PathBuf};

use super::anchor::{AnchorLog, DEFAULT_ANCHOR_ROTATE_LINES};
use super::audit::{AuditEntry, AuditLog, AuditStatus, HMAC_KEY_LEN, SignedEntry};
use super::head::{Head, HeadWitness};
use super::{KernelError, KernelResult};

const SCHEMA_V1_SQL: &str = include_str!("migrations/v1.sql");
const SCHEMA_V2_SQL: &str = include_str!("migrations/v2.sql");
const CURRENT_SCHEMA_VERSION: &str = "2";

/// Motivo con el que se cierra un `pending` que quedó sin resolución porque
/// el proceso terminó antes (crash, corte, Ctrl+C). Es `error`, no
/// `rejected`: no se sabe si la acción llegó a ejecutarse.
pub const ABANDONED_REASON: &str =
    "abandoned: the process ended before recording the outcome; the action may or may not have run";
const SCHEMA_META_BOOTSTRAP: &str = r#"
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID;
"#;

/// Nombre del estado tal como se guarda en `status_kind`.
fn status_label(status: &AuditStatus) -> &'static str {
    match status {
        AuditStatus::Pending => "pending",
        AuditStatus::Ok => "ok",
        AuditStatus::Error { .. } => "error",
        AuditStatus::Rejected { .. } => "rejected",
    }
}

/// Si un fallo al escribir los testigos (anchor y cabeza) impide continuar.
#[derive(Clone, Copy)]
enum WitnessPolicy {
    /// Fila `pending`: sin testigos fuera de la BD no se actúa.
    Required,
    /// Resoluciones: la acción ya ocurrió; se avisa y se sigue.
    BestEffort,
}

pub struct AuditStore {
    conn: Connection,
    log: AuditLog,
    anchor: AnchorLog,
    head: Option<Box<dyn HeadWitness>>,
    db_path: PathBuf,
}

impl AuditStore {
    /// Abre el log sin testigo de cabeza (pruebas y herramientas). La CLI
    /// usa `open_with_head` con el llavero del SO.
    pub fn open(db_path: &Path, anchor_dir: &Path, key: Vec<u8>) -> KernelResult<Self> {
        Self::open_impl(db_path, anchor_dir, key, None)
    }

    /// Abre el log comprobando que no es más corto que su testigo de cabeza
    /// (ver `head`). Si el log aún no tenía testigo, lo inicializa.
    pub fn open_with_head(
        db_path: &Path,
        anchor_dir: &Path,
        key: Vec<u8>,
        head: Box<dyn HeadWitness>,
    ) -> KernelResult<Self> {
        let mut store = Self::open_impl(db_path, anchor_dir, key, Some(head))?;
        store.adopt_head_if_missing()?;
        Ok(store)
    }

    fn open_impl(
        db_path: &Path,
        anchor_dir: &Path,
        key: Vec<u8>,
        head: Option<Box<dyn HeadWitness>>,
    ) -> KernelResult<Self> {
        if key.len() != HMAC_KEY_LEN {
            return Err(KernelError::Audit(format!(
                "HMAC key length {} != expected {}",
                key.len(),
                HMAC_KEY_LEN
            )));
        }

        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                super::create_private_dir_all(parent)?;
            }
        }

        let conn = Connection::open(db_path)
            .map_err(|e| KernelError::Audit(format!("open sqlite: {e}")))?;
        configure_connection(&conn)?;
        check_schema(&conn)?;
        apply_migrations(&conn, db_path)?;

        let persisted = load_all_entries(&conn)?;
        let log = AuditLog::from_persisted(persisted, key)?;
        let anchor = AnchorLog::open(anchor_dir, DEFAULT_ANCHOR_ROTATE_LINES)?;

        let store = Self {
            conn,
            log,
            anchor,
            head,
            db_path: db_path.to_path_buf(),
        };
        store.verify()?;
        Ok(store)
    }

    /// Logs creados antes del testigo (o tras perderlo): se adopta la cabeza
    /// actual, ya verificada, para no esperar a la próxima acción.
    fn adopt_head_if_missing(&mut self) -> KernelResult<()> {
        let Some(witness) = self.head.as_mut() else {
            return Ok(());
        };
        if witness.load()?.is_some() {
            return Ok(());
        }
        if let Some(last) = self.log.entries().last() {
            witness.store(&Head {
                sequence_no: last.entry.sequence_no,
                hmac: last.hmac.clone(),
            })?;
        }
        Ok(())
    }

    /// Ejecuta una acción auditada. Orden garantizado:
    ///
    /// 1. Cierra como `abandoned` los `pending` de sesiones anteriores.
    /// 2. Registra y persiste (`synchronous=FULL`) la fila `pending` y su
    ///    línea en el anchor.
    /// 3. Solo si (2) tuvo éxito, ejecuta `act`, que devuelve su resultado y
    ///    el estado con el que debe quedar registrado (`ok`/`error`/`rejected`).
    /// 4. Registra la resolución.
    ///
    /// Si (2) falla, `act` no se ejecuta. Si (4) falla, la acción ya ocurrió
    /// pero su `pending` queda en el log y la siguiente sesión lo cierra
    /// como `abandoned`. Devuelve el resultado de `act` y la fila de resolución.
    pub fn run_audited<T, A: Serialize>(
        &mut self,
        tool: &str,
        args: &A,
        act: impl FnOnce() -> (T, AuditStatus),
    ) -> KernelResult<(T, SignedEntry)> {
        self.resolve_orphans()?;
        self.log.record_pending(tool, args)?;
        let pending = self.persist_last(WitnessPolicy::Required)?;
        let (value, status) = act();
        // Si no se puede registrar, al menos que el error diga qué pasó: la
        // próxima sesión solo podrá anotar `abandoned`.
        let outcome = status_label(&status);
        let lost = |e: KernelError| {
            KernelError::Audit(format!(
                "the action ran with outcome `{outcome}` but that outcome could not be \
                 recorded (seq {} stays pending): {e}",
                pending.entry.sequence_no
            ))
        };
        self.log
            .record_resolution(pending.entry.sequence_no, status)
            .map_err(lost)?;
        let resolution = self.persist_last(WitnessPolicy::BestEffort).map_err(lost)?;
        Ok((value, resolution))
    }

    /// Cierra como `error` (`ABANDONED_REASON`) cada `pending` sin resolución.
    /// Seguro porque el log está abierto en exclusiva: ningún otro proceso
    /// puede tener una acción en curso. Devuelve las filas `pending` que
    /// cerró, para que la CLI pueda mostrarlas.
    pub fn resolve_orphans(&mut self) -> KernelResult<Vec<AuditEntry>> {
        let mut closed = Vec::new();
        for seq in self.log.unresolved_pending() {
            closed.push(self.log.entries()[seq as usize].entry.clone());
            self.log.record_resolution(
                seq,
                AuditStatus::Error {
                    reason: ABANDONED_REASON.into(),
                },
            )?;
            self.persist_last(WitnessPolicy::BestEffort)?;
        }
        Ok(closed)
    }

    pub fn unresolved_pending(&self) -> Vec<u64> {
        self.log.unresolved_pending()
    }

    pub fn entries(&self) -> &[SignedEntry] {
        self.log.entries()
    }

    /// Persiste la última fila del log en memoria; si SQLite falla, la
    /// deshace también en memoria para que ambos sigan coincidiendo. Con
    /// `WitnessPolicy::Required`, un fallo del anchor es un error (la fila ya
    /// está en SQLite y no se deshace: quedará como huérfana honesta).
    fn persist_last(&mut self, policy: WitnessPolicy) -> KernelResult<SignedEntry> {
        let signed = self
            .log
            .entries()
            .last()
            .cloned()
            .ok_or_else(|| KernelError::Audit("nothing to persist".into()))?;
        // Fuera de una transacción, cada INSERT se confirma (y sincroniza)
        // al volver; si hubiera una abierta, el `pending` no sería durable.
        debug_assert!(self.conn.is_autocommit());
        if let Err(e) = insert_entry(&self.conn, &signed) {
            let _ = self.log.rollback_last();
            return Err(e);
        }
        let seq = signed.entry.sequence_no;
        let anchored = self
            .anchor
            .append_entry(&signed)
            .map_err(|e| format!("anchor append failed for seq {seq}: {e}"));
        let headed = match self.head.as_mut() {
            Some(w) => w
                .store(&Head {
                    sequence_no: seq,
                    hmac: signed.hmac.clone(),
                })
                .map_err(|e| format!("head witness update failed for seq {seq}: {e}")),
            None => Ok(()),
        };
        for failure in [anchored, headed].into_iter().filter_map(Result::err) {
            match policy {
                WitnessPolicy::Required => return Err(KernelError::Audit(failure)),
                WitnessPolicy::BestEffort => eprintln!("[reli] warn: {failure}"),
            }
        }
        Ok(signed)
    }

    pub fn verify(&self) -> KernelResult<()> {
        verify_parts(&self.log, Some(&self.anchor), self.head.as_deref())
    }

    pub fn len(&self) -> usize {
        self.log.len()
    }

    pub fn is_empty(&self) -> bool {
        self.log.len() == 0
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

/// Cuánto espera `open` si otro proceso tiene el log bloqueado.
const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

/// Pragmas de la conexión. Orden importante: el modo de bloqueo exclusivo se
/// fija primero y el lock se toma de inmediato, antes de leer o migrar.
fn configure_connection(conn: &Connection) -> KernelResult<()> {
    harden_connection(conn)?;
    let in_use = busy_or;
    // SQLite devuelve el modo efectivo sin error si no puede cambiarlo: se
    // comprueba en vez de asumir.
    let set_mode = |pragma: &str, value: &str, expected: &str| -> KernelResult<()> {
        let actual: String = conn
            .pragma_update_and_check(None, pragma, value, |r| r.get(0))
            .map_err(|e| in_use(pragma, e))?;
        if actual.eq_ignore_ascii_case(expected) {
            Ok(())
        } else {
            Err(KernelError::Audit(format!(
                "{pragma} is {actual:?}, expected {expected:?}"
            )))
        }
    };
    // Explícito: no depender del valor por defecto de rusqlite (5 s).
    conn.busy_timeout(LOCK_WAIT)
        .map_err(|e| KernelError::Audit(format!("set busy_timeout: {e}")))?;
    // Un único proceso usa el log: así un `pending` abierto al arrancar es
    // siempre huérfano y nunca la acción en curso de otro proceso. El
    // bloqueo es de archivo (comprobado entre procesos en Windows): las
    // conexiones WAL normales de otras herramientas también lo respetan.
    set_mode("locking_mode", "EXCLUSIVE", "exclusive")?;
    set_mode("journal_mode", "WAL", "wal")?;
    // FULL: el `pending` tiene que sobrevivir a un corte de luz antes de
    // ejecutar la acción que describe. En macOS, fsync no vacía la caché
    // del disco: hace falta F_FULLFSYNC.
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(|e| in_use("set synchronous", e))?;
    #[cfg(target_os = "macos")]
    {
        conn.pragma_update(None, "fullfsync", "ON")
            .map_err(|e| in_use("set fullfsync", e))?;
        conn.pragma_update(None, "checkpoint_fullfsync", "ON")
            .map_err(|e| in_use("set checkpoint_fullfsync", e))?;
    }
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| in_use("set FK", e))?;
    conn.execute_batch("BEGIN EXCLUSIVE; COMMIT;")
        .map_err(|e| in_use("acquire exclusive lock", e))?;
    Ok(())
}

/// Bloqueo exclusivo del log sin cargarlo ni verificarlo. Lo usa
/// `reli reset` para no borrar nada mientras otro proceso está en mitad de
/// una acción (también funciona con un log corrupto). Se libera al soltarlo.
pub struct LogLock {
    _conn: Connection,
}

impl LogLock {
    pub fn acquire(db_path: &Path) -> KernelResult<Self> {
        let conn = Connection::open(db_path)
            .map_err(|e| KernelError::Audit(format!("open sqlite: {e}")))?;
        configure_connection(&conn)?;
        Ok(Self { _conn: conn })
    }
}

/// Verificación completa: cadena HMAC, testigo de cabeza y último anchor.
/// La comparten `AuditStore::verify` y `LogReader::verify`.
fn verify_parts(
    log: &AuditLog,
    anchor: Option<&AnchorLog>,
    head: Option<&dyn HeadWitness>,
) -> KernelResult<()> {
    log.verify()?;
    if let Some(witness) = head {
        check_head(log, witness)?;
    }
    if let Some(anchor) = anchor {
        check_anchor(log, anchor)?;
    }
    Ok(())
}

/// El log no puede ser más corto que su testigo, y la fila del testigo
/// tiene que ser la misma. Más filas que el testigo sí (crash entre el
/// commit y la escritura del testigo).
fn check_head(log: &AuditLog, witness: &dyn HeadWitness) -> KernelResult<()> {
    let Some(head) = witness.load()? else {
        return Ok(());
    };
    match log.entry_hmac_at(head.sequence_no) {
        Some(hmac) if hmac == head.hmac => Ok(()),
        Some(_) => Err(KernelError::AuditCorrupted {
            sequence_no: head.sequence_no,
            reason: "row does not match the head witness kept in the OS keyring".into(),
        }),
        None => Err(KernelError::AuditCorrupted {
            sequence_no: head.sequence_no,
            reason: "log is shorter than the head witness kept in the OS keyring \
                     (tail truncated, or audit.db deleted or replaced)"
                .into(),
        }),
    }
}

/// La última línea del anchor tiene que existir en la BD con la misma HMAC.
fn check_anchor(log: &AuditLog, anchor: &AnchorLog) -> KernelResult<()> {
    let Some(latest) = anchor.latest()? else {
        return Ok(());
    };
    match log.entry_hmac_at(latest.sequence_no) {
        Some(hmac) if hmac == latest.hmac => Ok(()),
        Some(_) => Err(KernelError::AuditCorrupted {
            sequence_no: latest.sequence_no,
            reason: "anchor hmac does not match DB hmac".into(),
        }),
        None => Err(KernelError::AuditCorrupted {
            sequence_no: latest.sequence_no,
            reason: "anchor references a sequence_no missing from DB (truncation?)".into(),
        }),
    }
}

/// Lectura del log sin modificar nada: el modo solo lectura que queda cuando
/// la verificación falla (`reli log`). Conexión de solo lectura y sin
/// checkpoint al cerrar: no crea el archivo, no migra, no cierra huérfanas,
/// no escribe anchors ni testigo, no aplica journals ni vacía el -wal.
/// Exportar y verificar leen la misma instantánea. Respeta el bloqueo de un
/// `reli` en marcha (`AuditBusy`).
pub struct LogReader {
    conn: Connection,
}

/// Una fila de `audit_entries` con las columnas firmadas (las de v2).
pub type RawRow = serde_json::Map<String, serde_json::Value>;

impl LogReader {
    pub fn open(db_path: &Path) -> KernelResult<Self> {
        refuse_pending_recovery(db_path)?;
        // Sin CREATE: un log que no existe no se crea.
        let flags = OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(db_path, flags)
            .map_err(|e| KernelError::Audit(format!("open sqlite: {e}")))?;
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
            .map_err(|e| KernelError::Audit(format!("disable checkpoint on close: {e}")))?;
        harden_connection(&conn)?;
        conn.busy_timeout(LOCK_WAIT)
            .map_err(|e| KernelError::Audit(format!("set busy_timeout: {e}")))?;
        conn.pragma_update(None, "query_only", "ON")
            .map_err(|e| busy_or("set query_only", e))?;
        // Una sola instantánea para exportar y verificar (se cierra al soltar).
        conn.execute_batch("BEGIN DEFERRED")
            .map_err(|e| busy_or("begin read", e))?;
        Ok(Self { conn })
    }

    /// Versión del esquema, tras la allow-list (`check_schema`). Nada se
    /// consulta en `audit_entries` antes de esto: con un esquema ajeno (una
    /// vista, un trigger, columnas sin firmar) no se exporta nada.
    fn checked_schema_version(&self) -> KernelResult<u32> {
        let by_columns = check_schema(&self.conn)?;
        match (read_schema_version(&self.conn)?.as_deref(), by_columns) {
            (Some("1"), Some(1)) => Ok(1),
            (Some("2"), Some(2)) => Ok(2),
            (meta, columns) => Err(foreign_schema(format!(
                "schema_version {:?} with {} audit_entries columns",
                meta.map(|v| v.chars().take(32).collect::<String>()),
                columns.map_or("no".into(), |v| format!("v{v}"))
            ))),
        }
    }

    /// Llama a `f` con cada fila, en orden de `sequence_no`, sin
    /// interpretarla: una fila manipulada también se exporta tal cual. Solo
    /// las columnas firmadas, con nombres fijos (`resolves_seq` es null en un
    /// log v1). Si `f` devuelve un error, la lectura se detiene y lo devuelve.
    pub fn for_each_row(&self, mut f: impl FnMut(RawRow) -> KernelResult<()>) -> KernelResult<()> {
        // Constantes, no datos del archivo: sin riesgo de inyección.
        let resolves = match self.checked_schema_version()? {
            1 => "NULL",
            _ => "resolves_seq",
        };
        let sql = format!(
            "SELECT sequence_no, timestamp, tool, args_hash, status_kind, status_reason,
                    {resolves}, prev_hmac, hmac, hash_format_version
             FROM audit_entries ORDER BY sequence_no"
        );
        let read = |e| busy_or("read audit_entries", e);
        let mut stmt = self.conn.prepare(&sql).map_err(read)?;
        let mut rows = stmt.query([]).map_err(read)?;
        while let Some(row) = rows.next().map_err(read)? {
            let mut raw = RawRow::new();
            for (i, name) in V2_COLUMNS.iter().enumerate() {
                raw.insert(
                    (*name).to_string(),
                    sql_to_json(row.get_ref(i).map_err(read)?),
                );
            }
            f(raw)?;
        }
        Ok(())
    }

    /// Verifica como `reli verify` (cadena HMAC, testigo de cabeza, anchors)
    /// sin escribir nada. Devuelve el número de filas.
    pub fn verify(
        &self,
        anchor_dir: &Path,
        key: Vec<u8>,
        head: Option<&dyn HeadWitness>,
    ) -> KernelResult<usize> {
        if self.checked_schema_version()? == 1 {
            // Migrar escribe (y es sin vuelta atrás): no se hace aquí.
            return Err(KernelError::Audit(
                "audit.db still uses schema version 1 and is only verified after migrating: \
                 copy the directory first; any other reli command (e.g. `reli verify`) \
                 migrates it one-way and keeps audit.db.schema1.bak"
                    .into(),
            ));
        }
        let log = AuditLog::from_persisted(load_all_entries(&self.conn)?, key)?;
        let anchor = existing_anchor_log(anchor_dir)?;
        verify_parts(&log, anchor.as_ref(), head)?;
        Ok(log.len())
    }

    #[cfg(test)]
    fn rows(&self) -> KernelResult<Vec<RawRow>> {
        let mut out = Vec::new();
        self.for_each_row(|r| {
            out.push(r);
            Ok(())
        })?;
        Ok(out)
    }

    #[cfg(test)]
    fn connection_is_query_only(&self) -> bool {
        self.conn
            .query_row("PRAGMA query_only", [], |r| r.get::<_, i64>(0))
            .unwrap()
            == 1
    }
}

/// Valor SQLite → JSON sin perder información: lo que reli nunca escribe
/// (BLOB, texto que no es UTF-8, reales no finitos) sale etiquetado en vez
/// de parecerse a un valor normal.
fn sql_to_json(value: rusqlite::types::ValueRef<'_>) -> serde_json::Value {
    use rusqlite::types::ValueRef;
    use serde_json::{Value, json};
    match value {
        ValueRef::Null => Value::Null,
        ValueRef::Integer(i) => i.into(),
        ValueRef::Real(f) => serde_json::Number::from_f64(f)
            .map(Value::Number)
            .unwrap_or_else(|| json!({ "real": f.to_string() })),
        ValueRef::Text(t) => match std::str::from_utf8(t) {
            Ok(s) => s.into(),
            Err(_) => json!({ "text_hex": hex::encode(t) }),
        },
        ValueRef::Blob(b) => json!({ "blob_hex": hex::encode(b) }),
    }
}

/// SQLite reescribe el archivo al abrirlo, incluso en solo lectura, si hay
/// un journal pendiente (lo aplica sobre audit.db) o un -wal junto a una BD
/// vacía (lo borra). `reli` nunca deja ninguno de los dos: se pide analizar
/// una copia en vez de tocar el original.
fn refuse_pending_recovery(db_path: &Path) -> KernelResult<()> {
    let sibling = |suffix: &str| {
        let mut name = db_path.as_os_str().to_owned();
        name.push(suffix);
        PathBuf::from(name)
    };
    let present = |p: &Path| std::fs::symlink_metadata(p).is_ok();
    let reason = if present(&sibling("-journal")) {
        "a rollback journal (audit.db-journal) is pending"
    } else if std::fs::metadata(db_path)?.len() < 512 && present(&sibling("-wal")) {
        "audit.db is empty but audit.db-wal exists"
    } else {
        return Ok(());
    };
    Err(KernelError::Audit(format!(
        "{reason}: SQLite would rewrite these files even to read them; copy the whole \
         directory and analyse the copy (e.g. with sqlite3)"
    )))
}

/// Anchors de un log que se inspecciona. Sin directorio no hay nada que
/// contrastar (al abrir, `AuditStore` lo crearía vacío); una ruta que existe
/// pero no es un directorio solo puede ser una manipulación.
fn existing_anchor_log(dir: &Path) -> KernelResult<Option<AnchorLog>> {
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(KernelError::Io(e)),
        Ok(m) if m.is_dir() => AnchorLog::open(dir, DEFAULT_ANCHOR_ROTATE_LINES).map(Some),
        Ok(_) => Err(KernelError::AuditCorrupted {
            sequence_no: 0,
            reason: "the anchors path exists but is not a directory".into(),
        }),
    }
}

/// Error de SQLite; "base de datos ocupada/bloqueada" es `AuditBusy`.
fn busy_or(what: &str, e: rusqlite::Error) -> KernelError {
    if matches!(
        e.sqlite_error_code(),
        Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
    ) {
        KernelError::AuditBusy
    } else {
        KernelError::Audit(format!("{what}: {e}"))
    }
}

/// `schema_version` de `schema_meta`, si la tabla y la clave existen.
fn read_schema_version(conn: &Connection) -> KernelResult<Option<String>> {
    conn.query_row(
        "SELECT value FROM schema_meta WHERE key = 'schema_version'",
        [],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(|e| busy_or("read schema_version", e))
}

/// Tablas que crea `reli`.
const KNOWN_TABLES: [&[u8]; 2] = [b"audit_entries", b"schema_meta"];
/// Columnas de `audit_entries`, en el orden en que las crean v1.sql y v2.sql.
const V1_COLUMNS: [&str; 9] = [
    "sequence_no",
    "timestamp",
    "tool",
    "args_hash",
    "status_kind",
    "status_reason",
    "prev_hmac",
    "hmac",
    "hash_format_version",
];
const V2_COLUMNS: [&str; 10] = [
    "sequence_no",
    "timestamp",
    "tool",
    "args_hash",
    "status_kind",
    "status_reason",
    "resolves_seq",
    "prev_hmac",
    "hmac",
    "hash_format_version",
];
/// Ningún valor del log puede pasar de esto (los de reli no llegan a 1 KiB).
const MAX_VALUE_BYTES: i32 = 1024 * 1024;

/// Allow-list del esquema: solo las tablas e índices que crea `reli`, y en
/// `audit_entries` exactamente las columnas de v1 o v2. Cualquier otra cosa
/// (un trigger con `RAISE(IGNORE)`, una vista, una tabla virtual, una columna
/// sin firmar) solo puede venir de una manipulación. La comparación es
/// binaria a propósito: SQLite decide qué es un objeto por su `sql` y
/// compara `type` sin distinguir mayúsculas y hasta el primer NUL, así que
/// prohibir 'trigger' y 'view' se esquivaba. Devuelve la versión que indican
/// las columnas (None si la tabla aún no existe).
fn check_schema(conn: &Connection) -> KernelResult<Option<u32>> {
    let mut stmt = conn
        .prepare(
            "SELECT CAST(type AS BLOB), CAST(name AS BLOB), CAST(tbl_name AS BLOB),
                    CAST(sql AS BLOB)
             FROM sqlite_master",
        )
        .map_err(|e| busy_or("inspect schema", e))?;
    let objects: Vec<SchemaObject> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .and_then(|rows| rows.collect())
        .map_err(|e| busy_or("inspect schema", e))?;
    for (kind, name, table, sql) in &objects {
        if !schema_object_allowed(kind, name, table, sql) {
            return Err(foreign_schema(format!(
                "a {} named {}",
                shown_bytes(kind),
                shown_bytes(name)
            )));
        }
    }
    entry_columns_version(conn)
}

/// (type, name, tbl_name, sql) de `sqlite_master`, como bytes: los escribe
/// quien escriba el archivo y pueden no ser UTF-8.
type SchemaObject = (
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
    Option<Vec<u8>>,
);

fn schema_object_allowed(
    kind: &Option<Vec<u8>>,
    name: &Option<Vec<u8>>,
    table: &Option<Vec<u8>>,
    sql: &Option<Vec<u8>>,
) -> bool {
    let known = |n: &Option<Vec<u8>>| n.as_deref().is_some_and(|n| KNOWN_TABLES.contains(&n));
    let sql_starts = |prefix: &[u8]| sql.as_deref().is_some_and(|s| s.starts_with(prefix));
    match kind.as_deref() {
        Some(b"table") => known(name) && name == table && sql_starts(b"CREATE TABLE "),
        // Sin `sql`: índices automáticos (UNIQUE, PRIMARY KEY).
        Some(b"index") => {
            known(table)
                && (sql.is_none()
                    || sql_starts(b"CREATE INDEX ")
                    || sql_starts(b"CREATE UNIQUE INDEX "))
        }
        _ => false,
    }
}

/// Las columnas de `audit_entries` son exactamente las de v1 o las de v2, sin
/// ocultas ni generadas: una columna más no está firmada y se leería como
/// parte del log (por ejemplo, una ruta en claro).
fn entry_columns_version(conn: &Connection) -> KernelResult<Option<u32>> {
    let mut stmt = conn
        .prepare("SELECT CAST(name AS BLOB), hidden FROM pragma_table_xinfo('audit_entries')")
        .map_err(|e| busy_or("inspect columns", e))?;
    let columns: Vec<(Option<Vec<u8>>, i64)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .and_then(|rows| rows.collect())
        .map_err(|e| busy_or("inspect columns", e))?;
    if columns.is_empty() {
        return Ok(None);
    }
    let matches = |expected: &[&str]| {
        columns.len() == expected.len()
            && columns.iter().zip(expected).all(|((name, hidden), want)| {
                *hidden == 0 && name.as_deref() == Some(want.as_bytes())
            })
    };
    match (matches(&V1_COLUMNS), matches(&V2_COLUMNS)) {
        (true, _) => Ok(Some(1)),
        (_, true) => Ok(Some(2)),
        _ => Err(foreign_schema("columns in audit_entries".into())),
    }
}

fn foreign_schema(what: String) -> KernelError {
    KernelError::AuditCorrupted {
        sequence_no: 0,
        reason: format!("schema check: audit.db contains {what} that reli never creates"),
    }
}

/// Bytes del archivo para un mensaje: recortados y con escapes.
fn shown_bytes(bytes: &Option<Vec<u8>>) -> String {
    match bytes {
        None => "NULL".into(),
        Some(b) => format!(
            "{:?}",
            String::from_utf8_lossy(b)
                .chars()
                .take(40)
                .collect::<String>()
        ),
    }
}

/// Defensas de SQLite para un archivo que puede estar manipulado: el
/// esquema no puede llamar a funciones con efectos (`trusted_schema`), no se
/// puede corromper el archivo desde SQL (DEFENSIVE), se comprueban las
/// celdas al leer y ningún valor pasa de `MAX_VALUE_BYTES`.
fn harden_connection(conn: &Connection) -> KernelResult<()> {
    conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)
        .map_err(|e| busy_or("set defensive", e))?;
    conn.pragma_update(None, "trusted_schema", "OFF")
        .map_err(|e| busy_or("set trusted_schema", e))?;
    conn.pragma_update(None, "cell_size_check", "ON")
        .map_err(|e| busy_or("set cell_size_check", e))?;
    conn.set_limit(Limit::SQLITE_LIMIT_LENGTH, MAX_VALUE_BYTES);
    conn.set_limit(Limit::SQLITE_LIMIT_COLUMN, 64);
    Ok(())
}

fn table_has_column(conn: &Connection, table: &str, column: &str) -> KernelResult<bool> {
    let mut stmt = conn
        .prepare("SELECT 1 FROM pragma_table_info(?1) WHERE name = ?2")
        .map_err(|e| KernelError::Audit(format!("inspect table: {e}")))?;
    stmt.exists(params![table, column])
        .map_err(|e| KernelError::Audit(format!("inspect table: {e}")))
}

/// Copia de seguridad consistente (incluye lo que esté en el WAL) antes de
/// una migración sin vuelta atrás. Nunca sobrescribe una copia existente.
fn backup_before_migration(conn: &Connection, db_path: &Path) -> KernelResult<()> {
    let mut name = db_path.as_os_str().to_owned();
    name.push(".schema1.bak");
    let backup = PathBuf::from(name);
    if backup.exists() {
        return Ok(());
    }
    let target = backup
        .to_str()
        .ok_or_else(|| KernelError::Audit("backup path is not valid UTF-8".into()))?;
    conn.execute("VACUUM INTO ?1", params![target])
        .map_err(|e| KernelError::Audit(format!("backup before migration: {e}")))?;
    Ok(())
}

fn apply_migrations(conn: &Connection, db_path: &Path) -> KernelResult<()> {
    conn.execute_batch(SCHEMA_META_BOOTSTRAP)
        .map_err(|e| KernelError::Audit(format!("bootstrap schema_meta: {e}")))?;

    let version = read_schema_version(conn)?;

    let migrate = |sql: &str, name: &str| {
        conn.execute_batch(sql)
            .map_err(|e| KernelError::Audit(format!("apply migration {name}: {e}")))
    };
    match version.as_deref() {
        None => {
            migrate(SCHEMA_V1_SQL, "v1")?;
            migrate(SCHEMA_V2_SQL, "v2")
        }
        Some("1") => {
            // v2.sql reconstruye la tabla con resolves_seq = NULL. Si la
            // tabla ya es v2, `schema_version` fue manipulado y migrar
            // destruiría evidencia firmada.
            if table_has_column(conn, "audit_entries", "resolves_seq")? {
                return Err(KernelError::AuditCorrupted {
                    sequence_no: 0,
                    reason: "schema check: schema_version says 1 but the table is already \
                             version 2; refusing to migrate"
                        .into(),
                });
            }
            backup_before_migration(conn, db_path)?;
            migrate(SCHEMA_V2_SQL, "v2")
        }
        Some(v) if v == CURRENT_SCHEMA_VERSION => Ok(()),
        // Valor controlado por quien escriba el archivo: se muestra con
        // escapes y recortado.
        Some(other) => Err(KernelError::Audit(format!(
            "unsupported schema version {:?} (expected {CURRENT_SCHEMA_VERSION})",
            other.chars().take(32).collect::<String>()
        ))),
    }
}

fn insert_entry(conn: &Connection, signed: &SignedEntry) -> KernelResult<()> {
    let status_kind = status_label(&signed.entry.status);
    let status_reason: Option<&str> = match &signed.entry.status {
        AuditStatus::Pending | AuditStatus::Ok => None,
        AuditStatus::Error { reason } | AuditStatus::Rejected { reason } => Some(reason),
    };
    let to_i64 = |v: u64, what: &str| -> KernelResult<i64> {
        v.try_into()
            .map_err(|_| KernelError::Audit(format!("{what} overflows i64")))
    };
    let seq_i64 = to_i64(signed.entry.sequence_no, "sequence_no")?;
    let resolves_i64 = signed
        .entry
        .resolves
        .map(|r| to_i64(r, "resolves"))
        .transpose()?;
    let inserted = conn
        .execute(
            "INSERT INTO audit_entries (
            sequence_no, timestamp, tool, args_hash, status_kind, status_reason,
            resolves_seq, prev_hmac, hmac, hash_format_version
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                seq_i64,
                signed.entry.timestamp,
                signed.entry.tool,
                signed.entry.args_hash,
                status_kind,
                status_reason,
                resolves_i64,
                signed.entry.prev_hmac,
                signed.hmac,
                signed.entry.hash_format_version as i64,
            ],
        )
        .map_err(|e| KernelError::Audit(format!("insert audit entry: {e}")))?;
    // Un trigger con RAISE(IGNORE) hace que el INSERT "tenga éxito" sin
    // escribir nada; registrar antes de actuar exige comprobarlo.
    if inserted != 1 {
        return Err(KernelError::Audit(format!(
            "insert audit entry: {inserted} rows written instead of 1"
        )));
    }
    Ok(())
}

/// Carga todas las filas. No valida versiones ni semántica: eso lo hace
/// `AuditLog::verify`, que `open` llama a continuación.
fn load_all_entries(conn: &Connection) -> KernelResult<Vec<SignedEntry>> {
    let mut stmt = conn
        .prepare(
            "SELECT sequence_no, timestamp, tool, args_hash, status_kind, status_reason,
                    resolves_seq, prev_hmac, hmac, hash_format_version
             FROM audit_entries ORDER BY sequence_no ASC",
        )
        .map_err(|e| KernelError::Audit(format!("prepare load: {e}")))?;

    let rows = stmt
        .query_map([], |row| {
            let seq: i64 = row.get(0)?;
            let status_kind: String = row.get(4)?;
            let status_reason: Option<String> = row.get(5)?;
            let resolves: Option<i64> = row.get(6)?;
            let hfv: i64 = row.get(9)?;

            // `status_reason` solo está firmado (dentro de `status`) para
            // `error`/`rejected`. Texto en `ok`/`pending`, o NULL en
            // `error`/`rejected`, sería una columna no firmada que alguien
            // con acceso al archivo puede rellenar a su gusto.
            let status = match (status_kind.as_str(), status_reason) {
                ("pending", None) => AuditStatus::Pending,
                ("ok", None) => AuditStatus::Ok,
                ("error", Some(reason)) => AuditStatus::Error { reason },
                ("rejected", Some(reason)) => AuditStatus::Rejected { reason },
                _ => {
                    return Err(rusqlite::Error::FromSqlConversionFailure(
                        4,
                        rusqlite::types::Type::Text,
                        format!(
                            "row {seq}: status_kind/status_reason combination is not one reli writes"
                        )
                        .into(),
                    ));
                }
            };

            let entry = AuditEntry {
                sequence_no: seq
                    .try_into()
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(0, seq))?,
                timestamp: row.get(1)?,
                tool: row.get(2)?,
                args_hash: row.get(3)?,
                status,
                resolves: resolves
                    .map(|r| {
                        r.try_into()
                            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(6, r))
                    })
                    .transpose()?,
                prev_hmac: row.get(7)?,
                hash_format_version: hfv
                    .try_into()
                    .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(9, hfv))?,
            };
            Ok(SignedEntry {
                entry,
                hmac: row.get(8)?,
            })
        })
        .map_err(|e| KernelError::Audit(format!("query entries: {e}")))?;

    rows.map(|r| {
        r.map_err(|e| match e {
            // Fila que no casa con lo que reli escribe: manipulación.
            rusqlite::Error::FromSqlConversionFailure(_, _, reason) => {
                KernelError::AuditCorrupted {
                    sequence_no: 0,
                    reason: format!("schema check: {reason}"),
                }
            }
            other => KernelError::Audit(format!("read row: {other}")),
        })
    })
    .collect()
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

    #[cfg(unix)]
    #[test]
    fn directories_it_creates_are_private_on_unix() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let audit_dir = tmp.path().join("new").join("reliagent");
        let _store = AuditStore::open(
            &audit_dir.join("audit.db"),
            &audit_dir.join("anchors"),
            TEST_KEY.to_vec(),
        )
        .unwrap();
        for dir in [
            tmp.path().join("new"),
            audit_dir.clone(),
            audit_dir.join("anchors"),
        ] {
            let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", dir.display());
        }
    }

    /// Acción completa (pending + resolución). Devuelve la fila de resolución.
    fn audited(
        store: &mut AuditStore,
        path: &str,
        bytes: usize,
        status: AuditStatus,
    ) -> SignedEntry {
        store
            .run_audited("write_file", &WriteArgs { path, bytes }, || ((), status))
            .unwrap()
            .1
    }

    fn statuses(store: &AuditStore) -> Vec<(AuditStatus, Option<u64>)> {
        store
            .entries()
            .iter()
            .map(|s| (s.entry.status.clone(), s.entry.resolves))
            .collect()
    }

    // --- Registrar antes de actuar -----------------------------------------

    #[test]
    fn run_audited_records_pending_then_resolution() {
        let (_tmp, mut store) = fresh_store();
        let (value, resolution) = store
            .run_audited(
                "write_file",
                &WriteArgs {
                    path: "a.txt",
                    bytes: 4,
                },
                || (42, AuditStatus::Ok),
            )
            .unwrap();
        assert_eq!(value, 42);
        assert_eq!(resolution.entry.sequence_no, 1);
        assert_eq!(
            statuses(&store),
            vec![(AuditStatus::Pending, None), (AuditStatus::Ok, Some(0))]
        );
        store.verify().unwrap();
    }

    #[test]
    fn action_is_not_executed_when_pending_cannot_be_persisted() {
        let (_tmp, mut store) = fresh_store();
        store
            .connection()
            .execute_batch("DROP TABLE audit_entries;")
            .unwrap();
        let mut executed = false;
        let res = store.run_audited(
            "write_file",
            &WriteArgs {
                path: "a.txt",
                bytes: 4,
            },
            || {
                executed = true;
                ((), AuditStatus::Ok)
            },
        );
        assert!(res.is_err());
        assert!(!executed, "the action ran without a persisted pending row");
        assert_eq!(store.len(), 0, "in-memory chain must be rolled back");
    }

    #[test]
    fn failed_resolution_leaves_orphan_that_next_session_abandons() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        {
            let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
            // Simula un fallo (o un corte) justo después de ejecutar.
            store
                .connection()
                .execute_batch(
                    "CREATE TRIGGER fail_resolution BEFORE INSERT ON audit_entries
                     WHEN NEW.status_kind != 'pending'
                     BEGIN SELECT RAISE(ABORT, 'simulated failure'); END;",
                )
                .unwrap();
            let mut executed = false;
            let res = store.run_audited(
                "write_file",
                &WriteArgs {
                    path: "a.txt",
                    bytes: 4,
                },
                || {
                    executed = true;
                    ((), AuditStatus::Ok)
                },
            );
            assert!(res.is_err());
            assert!(executed);
            assert_eq!(store.len(), 1, "only the pending row is persisted");
            store
                .connection()
                .execute_batch("DROP TRIGGER fail_resolution;")
                .unwrap();
        }

        let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
        assert_eq!(store.unresolved_pending(), vec![0]);
        assert_eq!(store.resolve_orphans().unwrap().len(), 1);
        audited(&mut store, "b.txt", 1, AuditStatus::Ok);
        assert_eq!(
            statuses(&store),
            vec![
                (AuditStatus::Pending, None),
                (
                    AuditStatus::Error {
                        reason: ABANDONED_REASON.into()
                    },
                    Some(0)
                ),
                (AuditStatus::Pending, None),
                (AuditStatus::Ok, Some(2)),
            ]
        );
        store.verify().unwrap();
        drop(store);
        AuditStore::open(&db, &anchor, TEST_KEY.to_vec())
            .unwrap()
            .verify()
            .unwrap();
    }

    #[test]
    fn run_audited_resolves_orphans_by_itself() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        {
            let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
            store
                .connection()
                .execute_batch(
                    "CREATE TRIGGER fail_resolution BEFORE INSERT ON audit_entries
                     WHEN NEW.status_kind != 'pending'
                     BEGIN SELECT RAISE(ABORT, 'simulated failure'); END;",
                )
                .unwrap();
            let _ = store.run_audited(
                "write_file",
                &WriteArgs {
                    path: "a",
                    bytes: 1,
                },
                || ((), AuditStatus::Ok),
            );
            store
                .connection()
                .execute_batch("DROP TRIGGER fail_resolution;")
                .unwrap();
        }
        let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
        audited(&mut store, "b.txt", 1, AuditStatus::Ok);
        assert!(store.unresolved_pending().is_empty());
        assert_eq!(store.len(), 4);
        store.verify().unwrap();
    }

    #[test]
    fn resolves_seq_is_persisted() {
        let (_tmp, mut store) = fresh_store();
        audited(&mut store, "a.txt", 1, AuditStatus::Ok);
        let resolves: Option<i64> = store
            .connection()
            .query_row(
                "SELECT resolves_seq FROM audit_entries WHERE sequence_no = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(resolves, Some(0));
    }

    #[test]
    fn database_refuses_a_second_resolution_of_the_same_pending() {
        let (_tmp, mut store) = fresh_store();
        audited(&mut store, "a.txt", 1, AuditStatus::Ok);
        let res = store.connection().execute(
            "INSERT INTO audit_entries (sequence_no, timestamp, tool, args_hash, status_kind,
                 status_reason, resolves_seq, prev_hmac, hmac, hash_format_version)
             VALUES (2, 't', 'write_file', 'x', 'ok', NULL, 0, 'p', 'h2', 2)",
            [],
        );
        assert!(res.is_err(), "UNIQUE(resolves_seq) must reject it");
    }

    #[test]
    fn writes_are_fully_synchronous() {
        let (_tmp, store) = fresh_store();
        let sync: i64 = store
            .connection()
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            sync, 2,
            "synchronous=FULL: a pending row must survive power loss"
        );
    }

    #[test]
    fn second_process_cannot_open_the_log_while_in_use() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        let first = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
        let second = AuditStore::open(&db, &anchor, TEST_KEY.to_vec());
        // Error propio: "ocupado" no es "corrupto" (códigos de salida distintos).
        assert!(
            matches!(second, Err(KernelError::AuditBusy)),
            "{:?}",
            second.err()
        );
        drop(first);
        AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
    }

    #[test]
    fn log_lock_blocks_stores_and_is_blocked_by_them() {
        // `reli reset` toma este lock antes de borrar nada.
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        let store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
        assert!(matches!(LogLock::acquire(&db), Err(KernelError::AuditBusy)));
        drop(store);
        let lock = LogLock::acquire(&db).unwrap();
        assert!(matches!(
            AuditStore::open(&db, &anchor, TEST_KEY.to_vec()),
            Err(KernelError::AuditBusy)
        ));
        drop(lock);
    }

    #[test]
    fn connection_really_runs_in_wal_and_exclusive_mode() {
        let (_tmp, store) = fresh_store();
        let journal: String = store
            .connection()
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        let locking: String = store
            .connection()
            .query_row("PRAGMA locking_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!((journal.as_str(), locking.as_str()), ("wal", "exclusive"));
    }

    #[test]
    fn failed_resolution_reports_the_outcome_that_was_lost() {
        let (_tmp, mut store) = fresh_store();
        store
            .connection()
            .execute_batch(
                "CREATE TRIGGER fail_resolution BEFORE INSERT ON audit_entries
                 WHEN NEW.status_kind != 'pending'
                 BEGIN SELECT RAISE(ABORT, 'disk full'); END;",
            )
            .unwrap();
        let err = store
            .run_audited(
                "write_file",
                &WriteArgs {
                    path: "a.txt",
                    bytes: 1,
                },
                || ((), AuditStatus::Ok),
            )
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ran") && msg.contains("ok"), "{msg}");
    }

    // --- Testigo de cabeza fuera del disco (hallazgo A2) -------------------

    use crate::kernel::head::{Head, memory::MemoryHead};

    fn open_with(tmp: &TempDir, head: &MemoryHead) -> KernelResult<AuditStore> {
        AuditStore::open_with_head(
            &tmp.path().join("audit.db"),
            &tmp.path().join("anchors"),
            TEST_KEY.to_vec(),
            Box::new(head.clone()),
        )
    }

    /// Recorta la última fila de la BD y la última línea del anchor, como
    /// haría un atacante con acceso al disco.
    fn truncate_db_and_anchor_tail(tmp: &TempDir) {
        let conn = Connection::open(tmp.path().join("audit.db")).unwrap();
        conn.execute(
            "DELETE FROM audit_entries WHERE sequence_no = (SELECT MAX(sequence_no) FROM audit_entries)",
            [],
        )
        .unwrap();
        drop(conn);
        let anchor = tmp.path().join("anchors").join("anchor.log");
        let text = std::fs::read_to_string(&anchor).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.pop();
        std::fs::write(&anchor, lines.join("\n") + "\n").unwrap();
    }

    #[test]
    fn head_witness_follows_every_row() {
        let tmp = TempDir::new().unwrap();
        let head = MemoryHead::default();
        let mut store = open_with(&tmp, &head).unwrap();
        let resolution = audited(&mut store, "a.txt", 1, AuditStatus::Ok);
        assert_eq!(
            head.state.borrow().clone(),
            Some(Head {
                sequence_no: resolution.entry.sequence_no,
                hmac: resolution.hmac
            })
        );
    }

    #[test]
    fn coordinated_tail_truncation_is_caught_only_with_the_witness() {
        let tmp = TempDir::new().unwrap();
        let head = MemoryHead::default();
        {
            let mut store = open_with(&tmp, &head).unwrap();
            audited(&mut store, "a.txt", 1, AuditStatus::Ok);
            audited(&mut store, "b.txt", 1, AuditStatus::Ok);
        }
        truncate_db_and_anchor_tail(&tmp);
        // Sin testigo, el recorte coordinado pasa desapercibido (la
        // limitación que motiva el testigo).
        AuditStore::open(
            &tmp.path().join("audit.db"),
            &tmp.path().join("anchors"),
            TEST_KEY.to_vec(),
        )
        .unwrap();
        let res = open_with(&tmp, &head);
        assert!(
            matches!(res, Err(KernelError::AuditCorrupted { sequence_no: 3, .. })),
            "{:?}",
            res.err()
        );
    }

    #[test]
    fn deleted_log_with_an_existing_witness_is_tampering() {
        let tmp = TempDir::new().unwrap();
        let head = MemoryHead::default();
        {
            let mut store = open_with(&tmp, &head).unwrap();
            audited(&mut store, "a.txt", 1, AuditStatus::Ok);
        }
        std::fs::remove_file(tmp.path().join("audit.db")).unwrap();
        std::fs::remove_dir_all(tmp.path().join("anchors")).unwrap();
        assert!(matches!(
            open_with(&tmp, &head),
            Err(KernelError::AuditCorrupted { .. })
        ));
    }

    #[test]
    fn witness_pointing_to_a_different_row_is_tampering() {
        let tmp = TempDir::new().unwrap();
        let head = MemoryHead::default();
        {
            let mut store = open_with(&tmp, &head).unwrap();
            audited(&mut store, "a.txt", 1, AuditStatus::Ok);
        }
        head.state.borrow_mut().as_mut().unwrap().hmac = "0".repeat(64);
        assert!(matches!(
            open_with(&tmp, &head),
            Err(KernelError::AuditCorrupted { .. })
        ));
    }

    #[test]
    fn rows_beyond_the_witness_are_accepted() {
        // Crash entre el commit en SQLite y la escritura del testigo.
        let tmp = TempDir::new().unwrap();
        let head = MemoryHead::default();
        {
            let mut store = open_with(&tmp, &head).unwrap();
            audited(&mut store, "a.txt", 1, AuditStatus::Ok);
            audited(&mut store, "b.txt", 1, AuditStatus::Ok);
        }
        let first = {
            let store = open_with(&tmp, &head).unwrap();
            store.entries()[1].clone()
        };
        *head.state.borrow_mut() = Some(Head {
            sequence_no: 1,
            hmac: first.hmac,
        });
        open_with(&tmp, &head).unwrap().verify().unwrap();
    }

    #[test]
    fn pending_is_not_acted_on_if_the_witness_cannot_be_updated() {
        let tmp = TempDir::new().unwrap();
        let head = MemoryHead::default();
        let mut store = open_with(&tmp, &head).unwrap();
        *head.fail_writes.borrow_mut() = true;
        let mut executed = false;
        let res = store.run_audited(
            "write_file",
            &WriteArgs {
                path: "a.txt",
                bytes: 1,
            },
            || {
                executed = true;
                ((), AuditStatus::Ok)
            },
        );
        assert!(res.is_err());
        assert!(!executed);
    }

    #[test]
    fn first_open_without_witness_initialises_it() {
        // Logs anteriores a esta versión no tienen testigo: se adopta.
        let tmp = TempDir::new().unwrap();
        {
            let mut store = AuditStore::open(
                &tmp.path().join("audit.db"),
                &tmp.path().join("anchors"),
                TEST_KEY.to_vec(),
            )
            .unwrap();
            audited(&mut store, "a.txt", 1, AuditStatus::Ok);
        }
        let head = MemoryHead::default();
        let store = open_with(&tmp, &head).unwrap();
        assert_eq!(
            head.state.borrow().as_ref().map(|h| h.sequence_no),
            Some(1),
            "the witness must not stay empty until the next action"
        );
        drop(store);
    }

    // --- Base de datos manipulada en disco (actor 3) -----------------------

    const SWALLOW_INSERTS: &str = "CREATE TRIGGER swallow BEFORE INSERT ON audit_entries
         BEGIN SELECT RAISE(IGNORE); END;";

    #[test]
    fn insert_swallowed_by_a_trigger_is_an_error_and_the_action_does_not_run() {
        let (_tmp, mut store) = fresh_store();
        store.connection().execute_batch(SWALLOW_INSERTS).unwrap();
        let mut executed = false;
        let res = store.run_audited(
            "write_file",
            &WriteArgs {
                path: "a.txt",
                bytes: 1,
            },
            || {
                executed = true;
                ((), AuditStatus::Ok)
            },
        );
        assert!(res.is_err());
        assert!(
            !executed,
            "RAISE(IGNORE) made the pending insert a silent no-op"
        );
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn database_with_planted_trigger_is_refused_on_open() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        {
            let store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
            store.connection().execute_batch(SWALLOW_INSERTS).unwrap();
        }
        let res = AuditStore::open(&db, &anchor, TEST_KEY.to_vec());
        assert!(
            matches!(res, Err(KernelError::AuditCorrupted { .. })),
            "a trigger in audit.db must be treated as tampering"
        );
    }

    #[test]
    fn database_with_planted_view_is_refused_on_open() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        {
            let store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
            store
                .connection()
                .execute_batch("CREATE VIEW v AS SELECT * FROM audit_entries;")
                .unwrap();
        }
        let res = AuditStore::open(&db, &anchor, TEST_KEY.to_vec());
        assert!(matches!(res, Err(KernelError::AuditCorrupted { .. })));
    }

    /// Ejecuta SQL arbitrario sobre el archivo, como un atacante con acceso
    /// al disco (incluido `writable_schema`, que reli nunca activa).
    fn tamper(db: &Path, sql: &str) {
        let conn = Connection::open(db).unwrap();
        conn.execute_batch(sql).unwrap();
    }

    /// AuditStore (y LogReader) rechazan el archivo como manipulado.
    fn assert_refused_as_tampering(db: &Path, anchor: &Path) {
        let res = AuditStore::open(db, anchor, TEST_KEY.to_vec());
        assert!(
            matches!(res, Err(KernelError::AuditCorrupted { .. })),
            "AuditStore: {:?}",
            res.err()
        );
        let reader = LogReader::open(db).unwrap();
        let export = reader.rows();
        assert!(
            matches!(export, Err(KernelError::AuditCorrupted { .. })),
            "export must not run on a foreign schema: {:?}",
            export.map(|r| r.len())
        );
        assert!(matches!(
            reader.verify(anchor, TEST_KEY.to_vec(), None),
            Err(KernelError::AuditCorrupted { .. })
        ));
    }

    #[test]
    fn trigger_or_view_disguised_by_the_type_column_is_refused() {
        // SQLite decide si un objeto es trigger o vista por su `sql`; `type`
        // se compara sin distinguir mayúsculas y hasta el primer NUL.
        for disguise in ["'TRIGGER'", "'Trigger'", "'trigger' || char(0)"] {
            let (_tmp, db, anchor, _head) = log_with_two_actions();
            tamper(&db, SWALLOW_INSERTS);
            tamper(
                &db,
                &format!(
                    "PRAGMA writable_schema = ON;
                     UPDATE sqlite_master SET type = {disguise} WHERE name = 'swallow';"
                ),
            );
            assert_refused_as_tampering(&db, &anchor);
        }
        let (_tmp, db, anchor, _head) = log_with_two_actions();
        tamper(
            &db,
            "CREATE VIEW v AS SELECT * FROM audit_entries;
             PRAGMA writable_schema = ON;
             UPDATE sqlite_master SET type = 'VIEW' WHERE name = 'v';",
        );
        assert_refused_as_tampering(&db, &anchor);
    }

    #[test]
    fn oversized_value_is_refused_instead_of_loaded() {
        let (_tmp, db, anchor, _head) = log_with_two_actions();
        tamper(
            &db,
            "UPDATE audit_entries SET tool = printf('%.*c', 2000000, 'x') WHERE sequence_no = 0;",
        );
        assert!(AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).is_err());
        assert!(LogReader::open(&db).unwrap().rows().is_err());
    }

    #[test]
    fn unknown_table_is_refused() {
        let (_tmp, db, anchor, _head) = log_with_two_actions();
        tamper(&db, "CREATE TABLE notes (x TEXT);");
        assert_refused_as_tampering(&db, &anchor);
    }

    #[test]
    fn unsigned_extra_column_is_refused() {
        // Una columna que no está firmada parecería parte del log.
        let (_tmp, db, anchor, _head) = log_with_two_actions();
        tamper(
            &db,
            "ALTER TABLE audit_entries ADD COLUMN path TEXT DEFAULT 'notes/todo.txt';",
        );
        assert_refused_as_tampering(&db, &anchor);
    }

    #[test]
    fn column_name_that_is_not_utf8_is_refused_without_panicking() {
        let (_tmp, db, anchor, _head) = log_with_two_actions();
        tamper(
            &db,
            "PRAGMA writable_schema = ON;
             UPDATE sqlite_master
                SET sql = replace(sql, 'hash_format_version INTEGER NOT NULL',
                    'hash_format_version INTEGER NOT NULL, \"' || CAST(X'FF' AS TEXT) || '\" TEXT')
              WHERE name = 'audit_entries';",
        );
        assert_refused_as_tampering(&db, &anchor);
    }

    #[test]
    fn pending_is_not_acted_on_if_its_anchor_cannot_be_written() {
        let (tmp, mut store) = fresh_store();
        audited(&mut store, "a.txt", 1, AuditStatus::Ok);
        let anchor_file = tmp.path().join("anchors").join("anchor.log");
        let mut perms = std::fs::metadata(&anchor_file).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&anchor_file, perms.clone()).unwrap();

        let mut executed = false;
        let res = store.run_audited(
            "write_file",
            &WriteArgs {
                path: "b.txt",
                bytes: 1,
            },
            || {
                executed = true;
                ((), AuditStatus::Ok)
            },
        );

        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        std::fs::set_permissions(&anchor_file, perms).unwrap();
        assert!(res.is_err());
        assert!(
            !executed,
            "the witness of the pending row is part of logging before acting"
        );
    }

    #[test]
    fn reason_text_on_ok_rows_is_treated_as_tampering() {
        // status_reason no está firmado para `ok`/`pending`: no puede tener texto.
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        {
            let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
            audited(&mut store, "a.txt", 1, AuditStatus::Ok);
            store
                .connection()
                .execute(
                    "UPDATE audit_entries SET status_reason = 'user_denied' WHERE sequence_no = 1",
                    [],
                )
                .unwrap();
        }
        let res = AuditStore::open(&db, &anchor, TEST_KEY.to_vec());
        assert!(matches!(res, Err(KernelError::AuditCorrupted { .. })));
    }

    #[test]
    fn missing_reason_on_rejected_rows_is_treated_as_tampering() {
        // NULL y '' no pueden ser equivalentes para `error`/`rejected`.
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        {
            let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
            audited(
                &mut store,
                "a.txt",
                1,
                AuditStatus::Rejected {
                    reason: String::new(),
                },
            );
            store
                .connection()
                .execute(
                    "UPDATE audit_entries SET status_reason = NULL WHERE sequence_no = 1",
                    [],
                )
                .unwrap();
        }
        let res = AuditStore::open(&db, &anchor, TEST_KEY.to_vec());
        assert!(matches!(res, Err(KernelError::AuditCorrupted { .. })));
    }

    #[test]
    fn tampered_schema_version_cannot_rerun_the_destructive_migration() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        {
            let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
            audited(&mut store, "a.txt", 1, AuditStatus::Ok);
            store
                .connection()
                .execute(
                    "UPDATE schema_meta SET value = '1' WHERE key = 'schema_version'",
                    [],
                )
                .unwrap();
        }
        assert!(AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).is_err());
        // La evidencia firmada sigue intacta: resolves_seq no se ha borrado.
        let conn = Connection::open(&db).unwrap();
        let resolves: Option<i64> = conn
            .query_row(
                "SELECT resolves_seq FROM audit_entries WHERE sequence_no = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(resolves, Some(0));
    }

    #[test]
    fn migration_from_v1_keeps_a_backup_of_the_original_database() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(SCHEMA_META_BOOTSTRAP).unwrap();
            conn.execute_batch(SCHEMA_V1_SQL).unwrap();
        }
        AuditStore::open(&db, &tmp.path().join("anchors"), TEST_KEY.to_vec()).unwrap();
        let backup = tmp.path().join("audit.db.schema1.bak");
        assert!(backup.exists(), "expected {}", backup.display());
        let conn = Connection::open(&backup).unwrap();
        let version: String = conn
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, "1");
    }

    // --- Migración desde el formato v1 -------------------------------------

    #[test]
    fn v1_database_is_migrated_and_still_verifies() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        {
            // Base de datos tal como la dejaba el código v1.
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(SCHEMA_META_BOOTSTRAP).unwrap();
            conn.execute_batch(SCHEMA_V1_SQL).unwrap();
            let signer = AuditLog::with_key(TEST_KEY.to_vec()).unwrap();
            let mut prev = super::super::audit::GENESIS_PREV.to_string();
            for (seq, (kind, reason)) in [("ok", None), ("rejected", Some("PathOutsideSandbox"))]
                .into_iter()
                .enumerate()
            {
                let status = match reason {
                    None => AuditStatus::Ok,
                    Some(r) => AuditStatus::Rejected { reason: r.into() },
                };
                let signed = signer.sign_for_test(AuditEntry {
                    sequence_no: seq as u64,
                    timestamp: "2026-04-21T00:00:00Z".into(),
                    tool: "write_file".into(),
                    args_hash: "ab".repeat(32),
                    status,
                    resolves: None,
                    prev_hmac: prev.clone(),
                    hash_format_version: 1,
                });
                conn.execute(
                    "INSERT INTO audit_entries (sequence_no, timestamp, tool, args_hash,
                         status_kind, status_reason, prev_hmac, hmac, hash_format_version)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1)",
                    params![
                        seq as i64,
                        signed.entry.timestamp,
                        signed.entry.tool,
                        signed.entry.args_hash,
                        kind,
                        reason,
                        signed.entry.prev_hmac,
                        signed.hmac
                    ],
                )
                .unwrap();
                prev = signed.hmac;
            }
        }

        let mut store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
        assert_eq!(store.len(), 2);
        let version: String = store
            .connection()
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, "2");
        audited(&mut store, "c.txt", 1, AuditStatus::Ok);
        store.verify().unwrap();
        drop(store);
        let reopened = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
        assert_eq!(reopened.len(), 4);
        reopened.verify().unwrap();
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
            let s1 = audited(&mut store, "a.txt", 4, AuditStatus::Ok);
            audited(&mut store, "b.txt", 1, AuditStatus::Ok);
            let s3 = audited(
                &mut store,
                "../x",
                0,
                AuditStatus::Rejected {
                    reason: "PathOutsideSandbox".into(),
                },
            );
            assert_eq!(s1.entry.sequence_no, 1);
            assert_eq!(s3.entry.sequence_no, 5);
            store.verify().unwrap();
            store.last_hmac().unwrap().to_string()
        };

        let reopened = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
        assert_eq!(reopened.len(), 6);
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
            audited(&mut store, "a.txt", 4, AuditStatus::Ok);
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
            audited(&mut store, "a.txt", 4, AuditStatus::Ok);
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
            audited(&mut store, "a.txt", 4, AuditStatus::Ok);
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
                audited(&mut store, "a.txt", i, AuditStatus::Ok);
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
        assert_eq!(version, "2");
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
        // Con DEFAULT_ANCHOR_ROTATE_LINES = 100, 250 acciones (500 filas) producen varias rotaciones.
        for i in 0..250 {
            audited(&mut store, "x.txt", i, AuditStatus::Ok);
        }
        store.verify().unwrap();
        assert_eq!(store.len(), 500);
    }

    // --- Modo solo lectura (`reli log`) --------------------------------------

    /// Log con dos acciones completas (4 filas) y su testigo de cabeza.
    fn log_with_two_actions() -> (TempDir, PathBuf, PathBuf, MemoryHead) {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        let anchor = tmp.path().join("anchors");
        let head = MemoryHead::default();
        {
            let mut store =
                AuditStore::open_with_head(&db, &anchor, TEST_KEY.to_vec(), Box::new(head.clone()))
                    .unwrap();
            audited(&mut store, "a.txt", 1, AuditStatus::Ok);
            audited(&mut store, "b.txt", 2, AuditStatus::Ok);
        }
        (tmp, db, anchor, head)
    }

    fn sha256_file(path: &Path) -> String {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(std::fs::read(path).unwrap()))
    }

    #[test]
    fn log_reader_lists_rows_and_verifies_a_healthy_log() {
        let (_tmp, db, anchor, head) = log_with_two_actions();
        let reader = LogReader::open(&db).unwrap();
        let rows = reader.rows().unwrap();
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0]["sequence_no"], serde_json::json!(0));
        assert_eq!(rows[0]["status_kind"], serde_json::json!("pending"));
        assert_eq!(rows[1]["resolves_seq"], serde_json::json!(0));
        assert_eq!(
            reader
                .verify(&anchor, TEST_KEY.to_vec(), Some(&head))
                .unwrap(),
            4
        );
    }

    #[test]
    fn log_reader_still_shows_a_tampered_log_and_names_the_bad_row() {
        let (_tmp, db, anchor, head) = log_with_two_actions();
        Connection::open(&db)
            .unwrap()
            .execute(
                "UPDATE audit_entries SET tool = 'evil' WHERE sequence_no = 2",
                [],
            )
            .unwrap();
        let reader = LogReader::open(&db).unwrap();
        let rows = reader.rows().unwrap();
        assert_eq!(rows.len(), 4, "every row is still exported");
        assert_eq!(rows[2]["tool"], serde_json::json!("evil"));
        match reader.verify(&anchor, TEST_KEY.to_vec(), Some(&head)) {
            Err(KernelError::AuditCorrupted { sequence_no: 2, .. }) => {}
            other => panic!("expected corruption at seq 2, got {other:?}"),
        }
    }

    #[test]
    fn log_reader_detects_truncation_through_the_head_witness() {
        let (_tmp, db, anchor, head) = log_with_two_actions();
        Connection::open(&db)
            .unwrap()
            .execute("DELETE FROM audit_entries WHERE sequence_no = 3", [])
            .unwrap();
        let reader = LogReader::open(&db).unwrap();
        assert_eq!(reader.rows().unwrap().len(), 3);
        assert!(matches!(
            reader.verify(&anchor, TEST_KEY.to_vec(), Some(&head)),
            Err(KernelError::AuditCorrupted { .. })
        ));
    }

    #[test]
    fn log_reader_never_writes_not_even_a_migration() {
        let (_tmp, db, anchor, head) = log_with_two_actions();
        // Deja una huérfana: abrir con AuditStore + actuar la cerraría.
        Connection::open(&db)
            .unwrap()
            .execute("DELETE FROM audit_entries WHERE sequence_no = 3", [])
            .unwrap();
        let before = sha256_file(&db);
        let anchors_before = std::fs::read_dir(&anchor).unwrap().count();
        let reader = LogReader::open(&db).unwrap();
        let _ = reader.rows().unwrap();
        let _ = reader.verify(&anchor, TEST_KEY.to_vec(), Some(&head));
        assert!(reader.connection_is_query_only());
        drop(reader);
        assert_eq!(sha256_file(&db), before);
        assert_eq!(std::fs::read_dir(&anchor).unwrap().count(), anchors_before);
        assert_eq!(
            head.load().unwrap().unwrap().sequence_no,
            3,
            "witness untouched"
        );
    }

    /// SHA-256 de cada archivo del directorio, por nombre.
    fn hash_files(dir: &Path) -> std::collections::BTreeMap<String, String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.is_file())
            .map(|p| {
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    sha256_file(&p),
                )
            })
            .collect()
    }

    /// Estado tras un corte: la segunda acción solo está en el -wal (el
    /// checkpoint ocurre al cerrar). Se copia con el log todavía abierto.
    fn crashed_log_with_rows_only_in_the_wal() -> (TempDir, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let live = tmp.path().join("live");
        let crashed = tmp.path().join("crashed");
        std::fs::create_dir_all(&crashed).unwrap();
        let open = || {
            AuditStore::open(
                &live.join("audit.db"),
                &live.join("anchors"),
                TEST_KEY.to_vec(),
            )
        };
        audited(&mut open().unwrap(), "a.txt", 1, AuditStatus::Ok);
        let mut store = open().unwrap();
        audited(&mut store, "b.txt", 2, AuditStatus::Ok);
        for name in ["audit.db", "audit.db-wal"] {
            std::fs::copy(live.join(name), crashed.join(name)).unwrap();
        }
        drop(store);
        (tmp, crashed)
    }

    #[test]
    fn log_reader_reads_rows_left_in_the_wal_without_changing_any_file() {
        let (_tmp, dir) = crashed_log_with_rows_only_in_the_wal();
        let before = hash_files(&dir);
        let reader = LogReader::open(&dir.join("audit.db")).unwrap();
        assert_eq!(
            reader.rows().unwrap().len(),
            4,
            "rows in the WAL are exported too"
        );
        drop(reader);
        let after = hash_files(&dir);
        for (name, hash) in &before {
            assert_eq!(
                after.get(name),
                Some(hash),
                "{name} was modified or deleted"
            );
        }
        for name in after.keys().filter(|n| !before.contains_key(*n)) {
            assert!(name.ends_with("-shm"), "unexpected new file {name}");
        }
    }

    #[test]
    fn log_reader_refuses_files_sqlite_would_rewrite_even_when_reading() {
        // Journal pendiente: SQLite lo aplicaría sobre audit.db.
        let (_tmp, db, _anchor, _head) = log_with_two_actions();
        let journal = db.with_file_name("audit.db-journal");
        std::fs::write(&journal, b"junk").unwrap();
        let before = sha256_file(&db);
        assert!(LogReader::open(&db).is_err());
        assert_eq!(std::fs::read(&journal).unwrap(), b"junk");
        assert_eq!(sha256_file(&db), before);
        // BD vacía junto a un -wal: SQLite borraría el -wal.
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        std::fs::write(&db, b"").unwrap();
        std::fs::write(tmp.path().join("audit.db-wal"), b"wal").unwrap();
        assert!(LogReader::open(&db).is_err());
        assert_eq!(
            std::fs::read(tmp.path().join("audit.db-wal")).unwrap(),
            b"wal"
        );
    }

    #[test]
    fn log_reader_does_not_create_a_missing_log() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("missing").join("audit.db");
        assert!(LogReader::open(&db).is_err());
        assert!(!db.exists());
        assert!(!db.parent().unwrap().exists());
    }

    #[test]
    fn log_reader_reports_busy_while_reli_holds_the_log() {
        let (_tmp, db, anchor, _head) = log_with_two_actions();
        let _store = AuditStore::open(&db, &anchor, TEST_KEY.to_vec()).unwrap();
        let res = LogReader::open(&db).and_then(|r| r.rows());
        assert!(
            matches!(res, Err(KernelError::AuditBusy)),
            "{:?}",
            res.err()
        );
    }

    #[test]
    fn log_reader_refuses_to_verify_an_unmigrated_v1_log_without_migrating_it() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("audit.db");
        {
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(SCHEMA_META_BOOTSTRAP).unwrap();
            conn.execute_batch(SCHEMA_V1_SQL).unwrap();
        }
        let reader = LogReader::open(&db).unwrap();
        assert_eq!(reader.rows().unwrap().len(), 0);
        let err = reader
            .verify(&tmp.path().join("anchors"), TEST_KEY.to_vec(), None)
            .unwrap_err();
        assert!(format!("{err}").contains("schema version"), "{err}");
        drop(reader);
        let version: String = Connection::open(&db)
            .unwrap()
            .query_row(
                "SELECT value FROM schema_meta WHERE key = 'schema_version'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(version, "1");
    }
}
