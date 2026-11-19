use std::collections::BTreeSet;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{KernelError, KernelResult};

type HmacSha256 = Hmac<Sha256>;

/// Formato que escribe este código: cada acción son dos filas, `pending`
/// (antes de ejecutar) y su resolución (`ok` / `error` / `rejected`, con
/// `resolves` apuntando al `pending`). Ver docs/HASH_FORMAT.md §2.
pub const HASH_FORMAT_VERSION: u32 = 2;
/// Formato anterior (una fila por acción, solo `ok` / `rejected`). Se sigue
/// verificando, pero ya no se escribe.
pub const HASH_FORMAT_V1: u32 = 1;
pub const GENESIS_PREV: &str = "GENESIS";
pub const HMAC_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditStatus {
    /// Acción propuesta, registrada antes de ejecutarse (solo v2).
    Pending,
    Ok,
    /// La acción se intentó y falló (p. ej. E/S), o su resultado es
    /// desconocido (`abandoned`). Solo v2.
    Error {
        reason: String,
    },
    Rejected {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub sequence_no: u64,
    pub timestamp: String,
    pub tool: String,
    pub args_hash: String,
    pub status: AuditStatus,
    /// `sequence_no` del `pending` que esta fila resuelve. Se omite al
    /// serializar cuando es `None`, así los bytes firmados de v1 no cambian.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolves: Option<u64>,
    pub prev_hmac: String,
    pub hash_format_version: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedEntry {
    pub entry: AuditEntry,
    pub hmac: String,
}

pub struct AuditLog {
    entries: Vec<SignedEntry>,
    key: Vec<u8>,
}

impl AuditLog {
    #[allow(dead_code)]
    pub fn with_key(key: Vec<u8>) -> KernelResult<Self> {
        if key.len() != HMAC_KEY_LEN {
            return Err(KernelError::Audit(format!(
                "HMAC key length {} != expected {}",
                key.len(),
                HMAC_KEY_LEN
            )));
        }
        Ok(Self {
            entries: Vec::new(),
            key,
        })
    }

    /// Registra una acción propuesta, antes de ejecutarla. Falla si hay otra
    /// acción abierta: primero hay que resolverla (o cerrarla como huérfana).
    pub fn record_pending<T: Serialize>(
        &mut self,
        tool: &str,
        args: &T,
    ) -> KernelResult<&SignedEntry> {
        if let Some(open) = self.unresolved_pending().first() {
            return Err(KernelError::Audit(format!(
                "seq {open} is still pending; resolve it before recording another action"
            )));
        }
        let args_bytes = serde_json::to_vec(args)
            .map_err(|e| KernelError::Audit(format!("serialize args: {e}")))?;
        let args_hash = hex::encode(Sha256::digest(&args_bytes));
        self.append(tool.to_string(), args_hash, AuditStatus::Pending, None)
    }

    /// Registra el resultado de un `pending` todavía abierto. Copia su
    /// `tool` y `args_hash`: la resolución no puede describir otra acción.
    pub fn record_resolution(
        &mut self,
        pending_seq: u64,
        status: AuditStatus,
    ) -> KernelResult<&SignedEntry> {
        if status == AuditStatus::Pending {
            return Err(KernelError::Audit(
                "a resolution cannot have status pending".into(),
            ));
        }
        if !self.unresolved_pending().contains(&pending_seq) {
            return Err(KernelError::Audit(format!(
                "seq {pending_seq} is not an open pending action"
            )));
        }
        // `from_persisted` no verifica: no se asume que índice == seq.
        let pending = usize::try_from(pending_seq)
            .ok()
            .and_then(|i| self.entries.get(i))
            .map(|s| &s.entry)
            .filter(|e| e.sequence_no == pending_seq)
            .ok_or_else(|| {
                KernelError::Audit(format!(
                    "seq {pending_seq} is not at its position in the log"
                ))
            })?;
        let (tool, args_hash) = (pending.tool.clone(), pending.args_hash.clone());
        self.append(tool, args_hash, status, Some(pending_seq))
    }

    /// `sequence_no` de las filas `pending` (v2) que aún no tienen resolución,
    /// en orden ascendente.
    pub fn unresolved_pending(&self) -> Vec<u64> {
        let mut open = BTreeSet::new();
        for signed in &self.entries {
            let e = &signed.entry;
            if e.hash_format_version != HASH_FORMAT_VERSION {
                continue;
            }
            match (&e.status, e.resolves) {
                (AuditStatus::Pending, _) => {
                    open.insert(e.sequence_no);
                }
                (_, Some(p)) => {
                    open.remove(&p);
                }
                _ => {}
            }
        }
        open.into_iter().collect()
    }

    fn append(
        &mut self,
        tool: String,
        args_hash: String,
        status: AuditStatus,
        resolves: Option<u64>,
    ) -> KernelResult<&SignedEntry> {
        let prev_hmac = self
            .entries
            .last()
            .map(|s| s.hmac.clone())
            .unwrap_or_else(|| GENESIS_PREV.to_string());

        let sequence_no = self.entries.len() as u64;
        let timestamp = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .map_err(|e| KernelError::Audit(format!("format timestamp: {e}")))?;

        let entry = AuditEntry {
            sequence_no,
            timestamp,
            tool,
            args_hash,
            status,
            resolves,
            prev_hmac,
            hash_format_version: HASH_FORMAT_VERSION,
        };
        let hmac = self.compute_hmac(&entry)?;
        self.entries.push(SignedEntry { entry, hmac });
        Ok(self.entries.last().expect("just pushed"))
    }

    fn compute_hmac(&self, entry: &AuditEntry) -> KernelResult<String> {
        let canonical = serde_json::to_vec(entry)
            .map_err(|e| KernelError::Audit(format!("serialize entry: {e}")))?;
        let mut mac = HmacSha256::new_from_slice(&self.key)
            .map_err(|e| KernelError::Audit(format!("hmac init: {e}")))?;
        mac.update(&canonical);
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    pub fn verify(&self) -> KernelResult<()> {
        let mut expected_prev = GENESIS_PREV.to_string();
        let mut seen_v2 = false;
        let mut open_pending = BTreeSet::new();
        for (i, signed) in self.entries.iter().enumerate() {
            let seq = i as u64;
            let e = &signed.entry;
            let corrupted = |reason: String| KernelError::AuditCorrupted {
                sequence_no: seq,
                reason,
            };
            if e.sequence_no != seq {
                return Err(corrupted(format!(
                    "sequence_no mismatch: expected {seq}, got {}",
                    e.sequence_no
                )));
            }
            if e.hash_format_version != HASH_FORMAT_V1
                && e.hash_format_version != HASH_FORMAT_VERSION
            {
                return Err(corrupted(format!(
                    "unsupported hash_format_version {}",
                    e.hash_format_version
                )));
            }
            if e.prev_hmac != expected_prev {
                return Err(corrupted("prev_hmac does not match prior entry".into()));
            }
            if self.compute_hmac(e)? != signed.hmac {
                return Err(corrupted("HMAC mismatch (entry or hmac tampered)".into()));
            }
            // A partir de aquí la fila está bien firmada; se comprueba que
            // además sea coherente (protege de bugs y de quien tenga la clave).
            if e.hash_format_version == HASH_FORMAT_V1 {
                check_v1_row(e, seen_v2).map_err(corrupted)?;
            } else {
                seen_v2 = true;
                self.check_v2_row(e, &mut open_pending).map_err(corrupted)?;
            }
            expected_prev = signed.hmac.clone();
        }
        Ok(())
    }

    fn check_v2_row(&self, e: &AuditEntry, open_pending: &mut BTreeSet<u64>) -> Result<(), String> {
        match (&e.status, e.resolves) {
            (AuditStatus::Pending, None) => {
                // Acciones estrictamente secuenciales: un `pending` solo puede
                // abrirse cuando el anterior ya tiene resolución.
                if let Some(open) = open_pending.first() {
                    return Err(format!("pending while seq {open} is still open"));
                }
                open_pending.insert(e.sequence_no);
                Ok(())
            }
            (AuditStatus::Pending, Some(_)) => Err("pending row must not resolve another".into()),
            (_, None) => Err("resolution row without `resolves`".into()),
            (_, Some(p)) => {
                if !open_pending.remove(&p) {
                    return Err(format!("resolves seq {p}, which is not an open pending"));
                }
                let pending = &self.entries[p as usize].entry;
                if pending.tool != e.tool || pending.args_hash != e.args_hash {
                    return Err(format!(
                        "resolution does not match the action pending at seq {p}"
                    ));
                }
                Ok(())
            }
        }
    }

    #[allow(dead_code)]
    pub fn entries(&self) -> &[SignedEntry] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn last_hmac(&self) -> Option<&str> {
        self.entries.last().map(|s| s.hmac.as_str())
    }

    pub fn entry_hmac_at(&self, sequence_no: u64) -> Option<&str> {
        let idx: usize = sequence_no.try_into().ok()?;
        self.entries.get(idx).map(|s| s.hmac.as_str())
    }

    /// Construye un log a partir de entradas ya persistidas. No recomputa HMACs:
    /// el llamador debe llamar a `verify()` inmediatamente después para validar.
    pub fn from_persisted(entries: Vec<SignedEntry>, key: Vec<u8>) -> KernelResult<Self> {
        if key.len() != HMAC_KEY_LEN {
            return Err(KernelError::Audit(format!(
                "HMAC key length {} != expected {}",
                key.len(),
                HMAC_KEY_LEN
            )));
        }
        Ok(Self { entries, key })
    }

    /// Elimina la última entrada del log. Usado por el store para rollback si
    /// el INSERT en SQLite falla después de `record`.
    pub(super) fn rollback_last(&mut self) -> KernelResult<SignedEntry> {
        self.entries
            .pop()
            .ok_or_else(|| KernelError::Audit("rollback on empty log".into()))
    }

    #[cfg(test)]
    pub(super) fn entries_mut(&mut self) -> &mut Vec<SignedEntry> {
        &mut self.entries
    }

    #[cfg(test)]
    pub(super) fn with_state_for_test(entries: Vec<SignedEntry>, key: Vec<u8>) -> Self {
        Self { entries, key }
    }

    /// Firma una entrada arbitraria con la clave del log (pruebas de filas
    /// v1 heredadas o de filas incoherentes bien firmadas).
    #[cfg(test)]
    pub(super) fn sign_for_test(&self, entry: AuditEntry) -> SignedEntry {
        let hmac = self.compute_hmac(&entry).expect("hmac");
        SignedEntry { entry, hmac }
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn last_entry(&self) -> Option<&SignedEntry> {
        self.entries.last()
    }
}

/// Las filas v1 solo pueden ser `ok`/`rejected` sin `resolves`, y nunca
/// aparecer después de una fila v2 (el código actual ya no escribe v1).
fn check_v1_row(e: &AuditEntry, seen_v2: bool) -> Result<(), String> {
    if seen_v2 {
        return Err("hash_format_version 1 row after version 2 rows".into());
    }
    let status_ok = matches!(e.status, AuditStatus::Ok | AuditStatus::Rejected { .. });
    if !status_ok || e.resolves.is_some() {
        return Err("hash_format_version 1 row with a version 2 status".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    const TEST_KEY_A: [u8; HMAC_KEY_LEN] = [0xaa; HMAC_KEY_LEN];
    const TEST_KEY_B: [u8; HMAC_KEY_LEN] = [0xbb; HMAC_KEY_LEN];

    #[derive(Serialize)]
    struct WriteArgs<'a> {
        path: &'a str,
        bytes: usize,
    }

    /// Una acción completa: fila `pending` + su resolución.
    fn record_action(log: &mut AuditLog, path: &str, bytes: usize, status: AuditStatus) {
        let pending = log
            .record_pending("write_file", &WriteArgs { path, bytes })
            .unwrap()
            .entry
            .sequence_no;
        log.record_resolution(pending, status).unwrap();
    }

    /// Tres acciones = seis filas: (0 pending, 1 ok) (2 pending, 3 ok)
    /// (4 pending, 5 rejected).
    fn make_log_with_three_actions() -> AuditLog {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        record_action(&mut log, "a.txt", 4, AuditStatus::Ok);
        record_action(&mut log, "b.txt", 1, AuditStatus::Ok);
        record_action(
            &mut log,
            "../x",
            0,
            AuditStatus::Rejected {
                reason: "PathOutsideSandbox".into(),
            },
        );
        log
    }

    /// Firma una entrada arbitraria con la clave del log (para simular filas
    /// escritas por alguien que tiene la clave, o por código antiguo v1).
    fn push_signed(log: &mut AuditLog, mut entry: AuditEntry) {
        entry.sequence_no = log.len() as u64;
        entry.prev_hmac = log
            .last_hmac()
            .map(str::to_string)
            .unwrap_or_else(|| GENESIS_PREV.to_string());
        let signed = log.sign_for_test(entry);
        log.entries_mut().push(signed);
    }

    fn entry(status: AuditStatus, resolves: Option<u64>, version: u32) -> AuditEntry {
        AuditEntry {
            sequence_no: 0,
            timestamp: "2026-11-18T00:00:00Z".into(),
            tool: "write_file".into(),
            args_hash: "ab".repeat(32),
            status,
            resolves,
            prev_hmac: String::new(),
            hash_format_version: version,
        }
    }

    #[test]
    fn empty_log_verifies_ok() {
        let log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        log.verify().unwrap();
        assert!(log.is_empty());
    }

    #[test]
    fn baseline_three_actions_verify_ok() {
        let log = make_log_with_three_actions();
        log.verify().unwrap();
        assert_eq!(log.len(), 6);
    }

    // --- Flujo pending → resolución (formato v2) ---------------------------

    #[test]
    fn pending_row_is_written_before_any_resolution() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        let pending = log
            .record_pending(
                "write_file",
                &WriteArgs {
                    path: "a.txt",
                    bytes: 4,
                },
            )
            .unwrap()
            .clone();
        assert_eq!(pending.entry.status, AuditStatus::Pending);
        assert_eq!(pending.entry.resolves, None);
        assert_eq!(pending.entry.hash_format_version, HASH_FORMAT_VERSION);
        assert_eq!(HASH_FORMAT_VERSION, 2);
        assert_eq!(log.unresolved_pending(), vec![0]);
        log.verify().unwrap();
    }

    #[test]
    fn resolution_points_to_pending_and_copies_its_tool_and_args() {
        let log = make_log_with_three_actions();
        let e = log.entries();
        assert_eq!(e[1].entry.status, AuditStatus::Ok);
        assert_eq!(e[1].entry.resolves, Some(0));
        assert_eq!(e[1].entry.tool, e[0].entry.tool);
        assert_eq!(e[1].entry.args_hash, e[0].entry.args_hash);
        assert_eq!(e[5].entry.resolves, Some(4));
        assert!(log.unresolved_pending().is_empty());
    }

    #[test]
    fn resolving_unknown_sequence_fails() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        assert!(log.record_resolution(7, AuditStatus::Ok).is_err());
        assert!(log.is_empty());
    }

    #[test]
    fn resolving_twice_fails() {
        let mut log = make_log_with_three_actions();
        assert!(log.record_resolution(0, AuditStatus::Ok).is_err());
        assert_eq!(log.len(), 6);
    }

    #[test]
    fn resolving_a_resolution_row_fails() {
        let mut log = make_log_with_three_actions();
        assert!(log.record_resolution(1, AuditStatus::Ok).is_err());
    }

    #[test]
    fn resolution_cannot_be_pending() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        log.record_pending(
            "write_file",
            &WriteArgs {
                path: "a",
                bytes: 1,
            },
        )
        .unwrap();
        assert!(log.record_resolution(0, AuditStatus::Pending).is_err());
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn error_status_is_recorded_and_verifies() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        record_action(
            &mut log,
            "a.txt",
            1,
            AuditStatus::Error {
                reason: "disk full".into(),
            },
        );
        log.verify().unwrap();
    }

    #[test]
    fn orphan_pending_still_verifies_and_is_reported() {
        let mut log = make_log_with_three_actions();
        log.record_pending(
            "write_file",
            &WriteArgs {
                path: "c.txt",
                bytes: 2,
            },
        )
        .unwrap();
        log.verify().unwrap();
        assert_eq!(log.unresolved_pending(), vec![6]);
    }

    // --- Bytes firmados (contrato de HASH_FORMAT.md) -----------------------

    #[test]
    fn v1_payload_bytes_are_unchanged() {
        let mut e = entry(AuditStatus::Ok, None, 1);
        e.prev_hmac = GENESIS_PREV.into();
        let json = String::from_utf8(serde_json::to_vec(&e).unwrap()).unwrap();
        assert_eq!(
            json,
            format!(
                r#"{{"sequence_no":0,"timestamp":"2026-11-18T00:00:00Z","tool":"write_file","args_hash":"{}","status":{{"kind":"ok"}},"prev_hmac":"GENESIS","hash_format_version":1}}"#,
                "ab".repeat(32)
            )
        );
    }

    #[test]
    fn v2_resolution_payload_includes_resolves_after_status() {
        let mut e = entry(AuditStatus::Error { reason: "x".into() }, Some(3), 2);
        e.sequence_no = 4;
        e.prev_hmac = "cd".repeat(32);
        let json = String::from_utf8(serde_json::to_vec(&e).unwrap()).unwrap();
        assert!(
            json.contains(r#""status":{"kind":"error","reason":"x"},"resolves":3,"prev_hmac":"#),
            "{json}"
        );
        let mut p = entry(AuditStatus::Pending, None, 2);
        p.prev_hmac = GENESIS_PREV.into();
        let json = String::from_utf8(serde_json::to_vec(&p).unwrap()).unwrap();
        assert!(
            json.contains(r#""status":{"kind":"pending"},"prev_hmac":"#),
            "{json}"
        );
    }

    // --- Compatibilidad con filas v1 ---------------------------------------

    #[test]
    fn legacy_v1_rows_followed_by_v2_actions_verify() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        push_signed(&mut log, entry(AuditStatus::Ok, None, 1));
        push_signed(
            &mut log,
            entry(
                AuditStatus::Rejected {
                    reason: "PathOutsideSandbox".into(),
                },
                None,
                1,
            ),
        );
        log.verify().unwrap();
        record_action(&mut log, "a.txt", 1, AuditStatus::Ok);
        log.verify().unwrap();
        assert_eq!(log.len(), 4);
    }

    #[test]
    fn v1_row_after_v2_rows_is_rejected() {
        let mut log = make_log_with_three_actions();
        push_signed(&mut log, entry(AuditStatus::Ok, None, 1));
        let err = log.verify().unwrap_err();
        assert!(
            matches!(err, KernelError::AuditCorrupted { sequence_no: 6, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn v1_row_with_v2_only_status_is_rejected() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        push_signed(&mut log, entry(AuditStatus::Pending, None, 1));
        assert!(log.verify().is_err());
    }

    // --- Semántica v2 que la HMAC sola no garantiza ------------------------
    // (filas bien firmadas pero incoherentes: bug o alguien con la clave)

    #[test]
    fn v2_resolution_without_resolves_is_rejected() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        push_signed(&mut log, entry(AuditStatus::Ok, None, 2));
        assert!(log.verify().is_err());
    }

    #[test]
    fn v2_pending_with_resolves_is_rejected() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        push_signed(&mut log, entry(AuditStatus::Pending, None, 2));
        push_signed(&mut log, entry(AuditStatus::Pending, Some(0), 2));
        assert!(log.verify().is_err());
    }

    #[test]
    fn v2_resolution_of_non_pending_is_rejected() {
        let mut log = make_log_with_three_actions();
        // Fila 6 dice resolver la fila 1, que es una resolución.
        push_signed(&mut log, entry(AuditStatus::Ok, Some(1), 2));
        assert!(log.verify().is_err());
    }

    #[test]
    fn v2_second_resolution_of_same_pending_is_rejected() {
        let mut log = make_log_with_three_actions();
        let mut dup = log.entries()[1].entry.clone();
        dup.resolves = Some(0);
        push_signed(&mut log, dup);
        assert!(log.verify().is_err());
    }

    #[test]
    fn v2_resolution_with_different_args_is_rejected() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        push_signed(&mut log, entry(AuditStatus::Pending, None, 2));
        let mut res = entry(AuditStatus::Ok, Some(0), 2);
        res.args_hash = "ff".repeat(32);
        push_signed(&mut log, res);
        assert!(log.verify().is_err());
    }

    #[test]
    fn v2_resolution_with_different_tool_is_rejected() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        push_signed(&mut log, entry(AuditStatus::Pending, None, 2));
        let mut res = entry(AuditStatus::Ok, Some(0), 2);
        res.tool = "read_file".into();
        push_signed(&mut log, res);
        assert!(log.verify().is_err());
    }

    #[test]
    fn v2_pending_while_another_is_open_is_rejected() {
        // `run_audited` cierra las huérfanas antes de cada `pending`: nunca
        // hay dos abiertos a la vez ni uno abierto en mitad del log.
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        push_signed(&mut log, entry(AuditStatus::Pending, None, 2));
        push_signed(&mut log, entry(AuditStatus::Pending, None, 2));
        push_signed(&mut log, entry(AuditStatus::Ok, Some(1), 2));
        let err = log.verify().unwrap_err();
        assert!(
            matches!(err, KernelError::AuditCorrupted { sequence_no: 1, .. }),
            "{err:?}"
        );
    }

    #[test]
    fn recording_a_pending_while_another_is_open_fails() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        let args = WriteArgs {
            path: "a",
            bytes: 1,
        };
        log.record_pending("write_file", &args).unwrap();
        assert!(log.record_pending("write_file", &args).is_err());
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn resolving_with_mismatched_sequence_numbers_fails_without_panicking() {
        // from_persisted no verifica: con huecos, el índice no es el seq.
        let source = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        let mut p = entry(AuditStatus::Pending, None, 2);
        p.sequence_no = 5;
        let signed = source.sign_for_test(p);
        let mut log = AuditLog::from_persisted(vec![signed], TEST_KEY_A.to_vec()).unwrap();
        assert!(log.record_resolution(5, AuditStatus::Ok).is_err());
    }

    #[test]
    fn detects_resolves_tamper() {
        let mut log = make_log_with_three_actions();
        log.entries_mut()[3].entry.resolves = Some(0);
        assert!(log.verify().is_err());
    }

    #[test]
    fn rejects_short_key() {
        let res = AuditLog::with_key(vec![0u8; 16]);
        assert!(matches!(res, Err(KernelError::Audit(_))));
    }

    #[test]
    fn rejects_long_key() {
        let res = AuditLog::with_key(vec![0u8; 64]);
        assert!(matches!(res, Err(KernelError::Audit(_))));
    }

    #[test]
    fn prev_hmac_chains_to_prior_hmac() {
        let log = make_log_with_three_actions();
        for i in 1..log.entries().len() {
            assert_eq!(log.entries()[i].entry.prev_hmac, log.entries()[i - 1].hmac);
        }
        assert_eq!(log.entries()[0].entry.prev_hmac, GENESIS_PREV);
    }

    #[test]
    fn sequence_nos_are_contiguous() {
        let log = make_log_with_three_actions();
        for (i, signed) in log.entries().iter().enumerate() {
            assert_eq!(signed.entry.sequence_no, i as u64);
        }
    }

    #[test]
    fn detects_any_byte_flip_in_stored_hmac() {
        for entry_idx in 0..3 {
            let mut log = make_log_with_three_actions();
            let original_hex = log.entries()[entry_idx].hmac.clone();
            let original_bytes = hex::decode(&original_hex).unwrap();
            assert_eq!(original_bytes.len(), 32);
            for byte_idx in 0..original_bytes.len() {
                let mut tampered = original_bytes.clone();
                tampered[byte_idx] ^= 0x01;
                log.entries_mut()[entry_idx].hmac = hex::encode(&tampered);
                let err = log.verify().unwrap_err();
                assert!(
                    matches!(err, KernelError::AuditCorrupted { .. }),
                    "entry {entry_idx} byte {byte_idx}: expected AuditCorrupted, got {err:?}"
                );
                log.entries_mut()[entry_idx].hmac = original_hex.clone();
            }
        }
    }

    #[test]
    fn detects_any_byte_flip_in_args_hash() {
        for entry_idx in 0..3 {
            let mut log = make_log_with_three_actions();
            let original_hex = log.entries()[entry_idx].entry.args_hash.clone();
            let original_bytes = hex::decode(&original_hex).unwrap();
            for byte_idx in 0..original_bytes.len() {
                let mut tampered = original_bytes.clone();
                tampered[byte_idx] ^= 0x01;
                log.entries_mut()[entry_idx].entry.args_hash = hex::encode(&tampered);
                assert!(
                    log.verify().is_err(),
                    "entry {entry_idx} byte {byte_idx}: tampering should be detected"
                );
                log.entries_mut()[entry_idx].entry.args_hash = original_hex.clone();
            }
        }
    }

    #[test]
    fn detects_tool_name_tamper() {
        let mut log = make_log_with_three_actions();
        log.entries_mut()[1].entry.tool = "read_file".into();
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_timestamp_tamper() {
        let mut log = make_log_with_three_actions();
        log.entries_mut()[0].entry.timestamp = "1999-01-01T00:00:00Z".into();
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_status_ok_to_rejected_tamper() {
        let mut log = make_log_with_three_actions();
        log.entries_mut()[1].entry.status = AuditStatus::Rejected {
            reason: "forged".into(),
        };
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_status_rejected_to_ok_tamper() {
        let mut log = make_log_with_three_actions();
        log.entries_mut()[5].entry.status = AuditStatus::Ok;
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_pending_to_ok_tamper() {
        let mut log = make_log_with_three_actions();
        log.entries_mut()[0].entry.status = AuditStatus::Ok;
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_sequence_no_tamper() {
        let mut log = make_log_with_three_actions();
        log.entries_mut()[1].entry.sequence_no = 99;
        let err = log.verify().unwrap_err();
        assert!(matches!(err, KernelError::AuditCorrupted { .. }));
    }

    #[test]
    fn detects_hash_format_version_tamper() {
        let mut log = make_log_with_three_actions();
        log.entries_mut()[0].entry.hash_format_version = 999;
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_broken_prev_hmac_link() {
        let mut log = make_log_with_three_actions();
        log.entries_mut()[1].entry.prev_hmac = "deadbeef".repeat(8);
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_genesis_entry_wrong_prev() {
        let mut log = make_log_with_three_actions();
        log.entries_mut()[0].entry.prev_hmac = "NOT_GENESIS".into();
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_swapped_entries() {
        let mut log = make_log_with_three_actions();
        log.entries_mut().swap(0, 1);
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_duplicated_entry() {
        let mut log = make_log_with_three_actions();
        let dup = log.entries()[1].clone();
        log.entries_mut().insert(2, dup);
        assert!(log.verify().is_err());
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let original = make_log_with_three_actions();
        let wrong_key_log =
            AuditLog::with_state_for_test(original.entries().to_vec(), TEST_KEY_B.to_vec());
        let err = wrong_key_log.verify().unwrap_err();
        assert!(matches!(err, KernelError::AuditCorrupted { .. }));
    }

    #[test]
    fn verify_with_same_key_different_instance_succeeds() {
        // Prueba de determinismo: la misma clave en otra instancia debe verificar
        // las entradas producidas por la primera sin modificaciones.
        let original = make_log_with_three_actions();
        let reopened =
            AuditLog::with_state_for_test(original.entries().to_vec(), TEST_KEY_A.to_vec());
        reopened.verify().unwrap();
    }

    #[test]
    fn truncation_of_tail_is_not_detected_without_anchor() {
        // Limitación conocida de v0.0.2: sin anclaje externo, eliminar la última
        // entrada deja una cadena internamente consistente. El fix llega en v0.1
        // con anchor.log + rolling anchor.
        let mut log = make_log_with_three_actions();
        log.entries_mut().pop();
        assert_eq!(log.len(), 5);
        log.verify()
            .expect("v0.0.2 no detecta truncamiento de cola — limitación documentada");
    }

    #[test]
    fn identical_args_produce_identical_args_hash() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        record_action(&mut log, "same.txt", 7, AuditStatus::Ok);
        record_action(&mut log, "same.txt", 7, AuditStatus::Ok);
        let h1 = log.entries()[0].entry.args_hash.clone();
        let h2 = log.entries()[2].entry.args_hash.clone();
        assert_eq!(h1, h2);
        assert_ne!(log.entries()[0].hmac, log.entries()[2].hmac);
    }

    #[test]
    fn rejected_status_produces_valid_chain() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        record_action(
            &mut log,
            "../x",
            0,
            AuditStatus::Rejected {
                reason: "PathOutsideSandbox".into(),
            },
        );
        log.verify().unwrap();
    }
}
