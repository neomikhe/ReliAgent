use super::audit::HMAC_KEY_LEN;
use super::{KernelError, KernelResult};

const SERVICE: &str = "reliagent";
const ACCOUNT: &str = "audit-hmac-v1";

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
