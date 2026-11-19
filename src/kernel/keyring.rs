use std::path::Path;

use sha2::{Digest, Sha256};

use super::audit::HMAC_KEY_LEN;
use super::head::{Head, HeadWitness};
use super::{KernelError, KernelResult};

const SERVICE: &str = "reliagent";
const ACCOUNT: &str = "audit-hmac-v1";
const HEAD_ACCOUNT_PREFIX: &str = "audit-head-v1:";

/// Cuenta del llavero donde vive el testigo de cabeza de un log concreto
/// (`--audit-dir` distintos no comparten testigo). Crea el directorio del log
/// si falta, para que la ruta canónica, y con ella la cuenta, no cambie
/// entre la primera ejecución y las siguientes.
pub fn head_account(db_path: &Path) -> KernelResult<String> {
    let dir = match db_path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = db_path
        .file_name()
        .ok_or_else(|| KernelError::Audit("audit db path has no file name".into()))?;
    std::fs::create_dir_all(dir)?;
    let canonical = std::fs::canonicalize(dir)?.join(name);
    let digest = Sha256::digest(canonical.to_string_lossy().as_bytes());
    Ok(format!(
        "{HEAD_ACCOUNT_PREFIX}{}",
        &hex::encode(digest)[..16]
    ))
}

/// Testigo de cabeza guardado en el llavero del SO, fuera del alcance de
/// quien solo puede modificar archivos (ver `kernel::head`).
pub struct KeyringHead {
    entry: keyring::Entry,
}

impl KeyringHead {
    pub fn for_log(db_path: &Path) -> KernelResult<Self> {
        let entry = keyring::Entry::new(SERVICE, &head_account(db_path)?)
            .map_err(|e| KernelError::Keyring(format!("open head entry: {e}")))?;
        Ok(Self { entry })
    }
}

impl HeadWitness for KeyringHead {
    fn load(&self) -> KernelResult<Option<Head>> {
        match self.entry.get_password() {
            Ok(raw) => Head::decode(&raw).map(Some),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(KernelError::Keyring(format!("read head witness: {e}"))),
        }
    }

    fn store(&mut self, head: &Head) -> KernelResult<()> {
        self.entry
            .set_password(&head.encode())
            .map_err(|e| KernelError::Keyring(format!("store head witness: {e}")))
    }
}

/// Borra el testigo de cabeza de un log (`reli reset`). Ok(false) si no
/// había ninguno.
pub fn delete_head(db_path: &Path) -> KernelResult<bool> {
    let entry = keyring::Entry::new(SERVICE, &head_account(db_path)?)
        .map_err(|e| KernelError::Keyring(format!("open head entry: {e}")))?;
    match entry.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(KernelError::Keyring(format!("delete head witness: {e}"))),
    }
}

pub fn head_label(db_path: &Path) -> String {
    match head_account(db_path) {
        Ok(account) => format!("{SERVICE}/{account}"),
        Err(_) => format!("{SERVICE}/{HEAD_ACCOUNT_PREFIX}<?>"),
    }
}

pub fn load_or_create_audit_key() -> KernelResult<(Vec<u8>, bool)> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|e| KernelError::Keyring(format!("open entry: {e}")))?;

    match entry.get_password() {
        Ok(hex_key) => {
            let key = hex::decode(hex_key.trim())
                .map_err(|e| KernelError::Keyring(format!("decode stored key: {e}")))?;
            if key.len() != HMAC_KEY_LEN {
                return Err(KernelError::Keyring(format!(
                    "stored key length {} != expected {}",
                    key.len(),
                    HMAC_KEY_LEN
                )));
            }
            Ok((key, false))
        }
        Err(keyring::Error::NoEntry) => {
            let mut key = vec![0u8; HMAC_KEY_LEN];
            getrandom::getrandom(&mut key)
                .map_err(|e| KernelError::Keyring(format!("generate random key: {e}")))?;
            entry
                .set_password(&hex::encode(&key))
                .map_err(|e| KernelError::Keyring(format!("store new key: {e}")))?;
            Ok((key, true))
        }
        Err(e) => Err(KernelError::Keyring(format!("read keyring: {e}"))),
    }
}

pub fn account_label() -> String {
    format!("{SERVICE}/{ACCOUNT}")
}

/// Remove the stored HMAC key, if any. Returns Ok(true) if an entry was
/// deleted, Ok(false) if there was nothing to delete. Used by
/// `reli reset --wipe-everything`.
pub fn delete_audit_key() -> KernelResult<bool> {
    let entry = keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|e| KernelError::Keyring(format!("open entry: {e}")))?;
    match entry.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring::Error::NoEntry) => Ok(false),
        Err(e) => Err(KernelError::Keyring(format!("delete keyring entry: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn head_account_is_stable_per_log_and_distinct_between_logs() {
        let tmp = TempDir::new().unwrap();
        let a = tmp.path().join("a").join("audit.db");
        let b = tmp.path().join("b").join("audit.db");
        let first = head_account(&a).unwrap();
        assert!(first.starts_with("audit-head-v1:"), "{first}");
        assert_eq!(first, head_account(&a).unwrap());
        assert_ne!(first, head_account(&b).unwrap());
        // La misma carpeta escrita de otra forma es el mismo log.
        let roundabout = tmp.path().join("a").join("..").join("a").join("audit.db");
        assert_eq!(first, head_account(&roundabout).unwrap());
    }

    #[test]
    fn head_account_does_not_depend_on_the_directory_existing_beforehand() {
        // La primera ejecución crea el directorio; la segunda no debe
        // derivar otra cuenta (perdería el testigo).
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("new").join("audit.db");
        let before = head_account(&db).unwrap();
        assert!(db.parent().unwrap().exists());
        assert_eq!(before, head_account(&db).unwrap());
    }
}
