use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::{KernelError, KernelResult};

type HmacSha256 = Hmac<Sha256>;

pub const HASH_FORMAT_VERSION: u32 = 1;
pub const GENESIS_PREV: &str = "GENESIS";
pub const HMAC_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuditStatus {
    Ok,
    Rejected { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub sequence_no: u64,
    pub timestamp: String,
    pub tool: String,
    pub args_hash: String,
    pub status: AuditStatus,
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

    pub fn record<T: Serialize>(
        &mut self,
        tool: &str,
        args: &T,
        status: AuditStatus,
    ) -> KernelResult<&SignedEntry> {
        let args_bytes = serde_json::to_vec(args)
            .map_err(|e| KernelError::Audit(format!("serialize args: {e}")))?;
        let args_hash = hex::encode(Sha256::digest(&args_bytes));

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
            tool: tool.to_string(),
            args_hash,
            status,
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
        for (i, signed) in self.entries.iter().enumerate() {
            let seq = i as u64;
            if signed.entry.sequence_no != seq {
                return Err(KernelError::AuditCorrupted {
                    sequence_no: seq,
                    reason: format!(
                        "sequence_no mismatch: expected {}, got {}",
                        seq, signed.entry.sequence_no
                    ),
                });
            }
            if signed.entry.hash_format_version != HASH_FORMAT_VERSION {
                return Err(KernelError::AuditCorrupted {
                    sequence_no: seq,
                    reason: format!(
                        "unsupported hash_format_version {}",
                        signed.entry.hash_format_version
                    ),
                });
            }
            if signed.entry.prev_hmac != expected_prev {
                return Err(KernelError::AuditCorrupted {
                    sequence_no: seq,
                    reason: "prev_hmac does not match prior entry".into(),
                });
            }
            let recomputed = self.compute_hmac(&signed.entry)?;
            if recomputed != signed.hmac {
                return Err(KernelError::AuditCorrupted {
                    sequence_no: seq,
                    reason: "HMAC mismatch (entry or hmac tampered)".into(),
                });
            }
            expected_prev = signed.hmac.clone();
        }
        Ok(())
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

    #[cfg(test)]
    #[allow(dead_code)]
    pub(super) fn last_entry(&self) -> Option<&SignedEntry> {
        self.entries.last()
    }
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

    fn make_log_with_three_entries() -> AuditLog {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        log.record(
            "write_file",
            &WriteArgs {
                path: "a.txt",
                bytes: 4,
            },
            AuditStatus::Ok,
        )
        .unwrap();
        log.record(
            "write_file",
            &WriteArgs {
                path: "b.txt",
                bytes: 1,
            },
            AuditStatus::Ok,
        )
        .unwrap();
        log.record(
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
        log
    }

    #[test]
    fn empty_log_verifies_ok() {
        let log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        log.verify().unwrap();
        assert!(log.is_empty());
    }

    #[test]
    fn baseline_three_entries_verifies_ok() {
        let log = make_log_with_three_entries();
        log.verify().unwrap();
        assert_eq!(log.len(), 3);
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
        let log = make_log_with_three_entries();
        for i in 1..log.entries().len() {
            assert_eq!(log.entries()[i].entry.prev_hmac, log.entries()[i - 1].hmac);
        }
        assert_eq!(log.entries()[0].entry.prev_hmac, GENESIS_PREV);
    }

    #[test]
    fn sequence_nos_are_contiguous() {
        let log = make_log_with_three_entries();
        for (i, signed) in log.entries().iter().enumerate() {
            assert_eq!(signed.entry.sequence_no, i as u64);
        }
    }

    #[test]
    fn detects_any_byte_flip_in_stored_hmac() {
        for entry_idx in 0..3 {
            let mut log = make_log_with_three_entries();
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
            let mut log = make_log_with_three_entries();
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
        let mut log = make_log_with_three_entries();
        log.entries_mut()[1].entry.tool = "read_file".into();
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_timestamp_tamper() {
        let mut log = make_log_with_three_entries();
        log.entries_mut()[0].entry.timestamp = "1999-01-01T00:00:00Z".into();
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_status_ok_to_rejected_tamper() {
        let mut log = make_log_with_three_entries();
        log.entries_mut()[0].entry.status = AuditStatus::Rejected {
            reason: "forged".into(),
        };
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_status_rejected_to_ok_tamper() {
        let mut log = make_log_with_three_entries();
        log.entries_mut()[2].entry.status = AuditStatus::Ok;
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_sequence_no_tamper() {
        let mut log = make_log_with_three_entries();
        log.entries_mut()[1].entry.sequence_no = 99;
        let err = log.verify().unwrap_err();
        assert!(matches!(err, KernelError::AuditCorrupted { .. }));
    }

    #[test]
    fn detects_hash_format_version_tamper() {
        let mut log = make_log_with_three_entries();
        log.entries_mut()[0].entry.hash_format_version = 999;
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_broken_prev_hmac_link() {
        let mut log = make_log_with_three_entries();
        log.entries_mut()[1].entry.prev_hmac = "deadbeef".repeat(8);
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_genesis_entry_wrong_prev() {
        let mut log = make_log_with_three_entries();
        log.entries_mut()[0].entry.prev_hmac = "NOT_GENESIS".into();
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_swapped_entries() {
        let mut log = make_log_with_three_entries();
        log.entries_mut().swap(0, 1);
        assert!(log.verify().is_err());
    }

    #[test]
    fn detects_duplicated_entry() {
        let mut log = make_log_with_three_entries();
        let dup = log.entries()[1].clone();
        log.entries_mut().insert(2, dup);
        assert!(log.verify().is_err());
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let original = make_log_with_three_entries();
        let wrong_key_log =
            AuditLog::with_state_for_test(original.entries().to_vec(), TEST_KEY_B.to_vec());
        let err = wrong_key_log.verify().unwrap_err();
        assert!(matches!(err, KernelError::AuditCorrupted { .. }));
    }

    #[test]
    fn verify_with_same_key_different_instance_succeeds() {
        // Prueba de determinismo: la misma clave en otra instancia debe verificar
        // las entradas producidas por la primera sin modificaciones.
        let original = make_log_with_three_entries();
        let reopened =
            AuditLog::with_state_for_test(original.entries().to_vec(), TEST_KEY_A.to_vec());
        reopened.verify().unwrap();
    }

    #[test]
    fn truncation_of_tail_is_not_detected_without_anchor() {
        // Limitación conocida de v0.0.2: sin anclaje externo, eliminar la última
        // entrada deja una cadena internamente consistente. El fix llega en v0.1
        // con anchor.log + rolling anchor.
        let mut log = make_log_with_three_entries();
        log.entries_mut().pop();
        assert_eq!(log.len(), 2);
        log.verify()
            .expect("v0.0.2 no detecta truncamiento de cola — limitación documentada");
    }

    #[test]
    fn identical_args_produce_identical_args_hash() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        log.record(
            "write_file",
            &WriteArgs {
                path: "same.txt",
                bytes: 7,
            },
            AuditStatus::Ok,
        )
        .unwrap();
        let h1 = log.entries()[0].entry.args_hash.clone();
        log.record(
            "write_file",
            &WriteArgs {
                path: "same.txt",
                bytes: 7,
            },
            AuditStatus::Ok,
        )
        .unwrap();
        let h2 = log.entries()[1].entry.args_hash.clone();
        assert_eq!(h1, h2);
        assert_ne!(log.entries()[0].hmac, log.entries()[1].hmac);
    }

    #[test]
    fn rejected_status_produces_valid_chain() {
        let mut log = AuditLog::with_key(TEST_KEY_A.to_vec()).unwrap();
        log.record(
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
        log.verify().unwrap();
    }
}
