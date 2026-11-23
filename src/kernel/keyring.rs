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
    let (dir, name) = split_db_path(db_path)?;
    super::create_private_dir_all(dir)?;
    Ok(account_for(&std::fs::canonicalize(dir)?.join(name)))
}

/// Como `head_account`, pero sin crear nada (`reli log` sobre un log cuyo
/// directorio ya no existe): se canonicaliza el antepasado más cercano que
/// exista y se le añaden los componentes que faltan. Es la misma cuenta
/// salvo que esos componentes fueran enlaces simbólicos.
pub fn head_account_without_creating(db_path: &Path) -> KernelResult<String> {
    let (dir, name) = split_db_path(db_path)?;
    let absolute = std::path::absolute(dir)?;
    let mut existing = absolute.as_path();
    let mut missing = Vec::new();
    while !existing.try_exists()? {
        let (Some(part), Some(parent)) = (existing.file_name(), existing.parent()) else {
            return Err(KernelError::Audit(
                "cannot derive the head witness of a log whose directory does not exist".into(),
            ));
        };
        missing.push(part);
        existing = parent;
    }
    let mut canonical = std::fs::canonicalize(existing)?;
    canonical.extend(missing.iter().rev());
    Ok(account_for(&canonical.join(name)))
}

/// (directorio, nombre de archivo) de la ruta de un `audit.db`.
fn split_db_path(db_path: &Path) -> KernelResult<(&Path, &std::ffi::OsStr)> {
    let dir = match db_path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d,
        _ => Path::new("."),
    };
    let name = db_path
        .file_name()
        .ok_or_else(|| KernelError::Audit("audit db path has no file name".into()))?;
    Ok((dir, name))
}

fn account_for(canonical_db_path: &Path) -> String {
    let digest = Sha256::digest(canonical_db_path.to_string_lossy().as_bytes());
    format!("{HEAD_ACCOUNT_PREFIX}{}", &hex::encode(digest)[..16])
}

/// Testigo de cabeza guardado en el llavero del SO, fuera del alcance de
/// quien solo puede modificar archivos (ver `kernel::head`).
pub struct KeyringHead {
    entry: keyring::Entry,
}

impl KeyringHead {
    pub fn for_log(db_path: &Path) -> KernelResult<Self> {
        Self::for_account(&head_account(db_path)?)
    }

    /// Mismo testigo que `for_log`, sin crear el directorio del log.
    pub fn for_log_without_creating(db_path: &Path) -> KernelResult<Self> {
        Self::for_account(&head_account_without_creating(db_path)?)
    }

    fn for_account(account: &str) -> KernelResult<Self> {
        let entry = keyring::Entry::new(SERVICE, account)
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

fn audit_key_entry() -> KernelResult<keyring::Entry> {
    keyring::Entry::new(SERVICE, ACCOUNT)
        .map_err(|e| KernelError::Keyring(format!("open entry: {e}")))
}

/// Clave guardada en hex → bytes, comprobando la longitud.
fn decode_audit_key(hex_key: &str) -> KernelResult<Vec<u8>> {
    let key = hex::decode(hex_key.trim())
        .map_err(|e| KernelError::Keyring(format!("decode stored key: {e}")))?;
    if key.len() != HMAC_KEY_LEN {
        return Err(KernelError::Keyring(format!(
            "stored key length {} != expected {}",
            key.len(),
            HMAC_KEY_LEN
        )));
    }
    Ok(key)
}

/// Lee la clave HMAC sin crearla: `reli log` no debe dejar una clave nueva
/// en el llavero solo por inspeccionar un log. `None` si no hay ninguna.
pub fn load_audit_key() -> KernelResult<Option<Vec<u8>>> {
    match audit_key_entry()?.get_password() {
        Ok(hex_key) => decode_audit_key(&hex_key).map(Some),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(KernelError::Keyring(format!("read keyring: {e}"))),
    }
}

pub fn load_or_create_audit_key() -> KernelResult<(Vec<u8>, bool)> {
    if let Some(key) = load_audit_key()? {
        return Ok((key, false));
    }
    let mut key = vec![0u8; HMAC_KEY_LEN];
    getrandom::getrandom(&mut key)
        .map_err(|e| KernelError::Keyring(format!("generate random key: {e}")))?;
    audit_key_entry()?
        .set_password(&hex::encode(&key))
        .map_err(|e| KernelError::Keyring(format!("store new key: {e}")))?;
    Ok((key, true))
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
    fn account_without_creating_matches_and_creates_nothing() {
        let tmp = TempDir::new().unwrap();
        let db = tmp.path().join("gone").join("deeper").join("audit.db");
        let derived = head_account_without_creating(&db).unwrap();
        assert!(!tmp.path().join("gone").exists(), "nothing may be created");
        // Cuando el directorio existe, `head_account` da la misma cuenta.
        assert_eq!(head_account(&db).unwrap(), derived);
        assert_eq!(head_account_without_creating(&db).unwrap(), derived);
    }

    #[test]
    fn stored_key_must_be_hex_of_the_right_length() {
        let good = "ab".repeat(HMAC_KEY_LEN);
        assert_eq!(decode_audit_key(&good).unwrap(), vec![0xab; HMAC_KEY_LEN]);
        assert_eq!(
            decode_audit_key(&format!(" {good}\n")).unwrap().len(),
            HMAC_KEY_LEN
        );
        assert!(decode_audit_key("abcd").is_err(), "too short");
        assert!(
            decode_audit_key(&"zz".repeat(HMAC_KEY_LEN)).is_err(),
            "not hex"
        );
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
