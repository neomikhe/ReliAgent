//! Testigo de la cabeza del log fuera de `audit.db`.
//!
//! `anchor.log` vive en el mismo disco y no lleva clave: quien pueda
//! modificar archivos puede recortar a la vez la cola de la BD y la del
//! anchor. El testigo guarda la última fila (`seq` + `hmac`) donde ese
//! atacante no llega — en producción, el llavero del SO
//! (`keyring::KeyringHead`). Al abrir, un log más corto que su testigo es
//! manipulación. Filas por delante del testigo se aceptan: es la ventana de
//! un crash entre el commit en SQLite y la escritura del testigo.

use super::{KernelError, KernelResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub sequence_no: u64,
    pub hmac: String,
}

impl Head {
    /// Formato almacenado: `<seq>:<hmac hex>`.
    pub fn encode(&self) -> String {
        format!("{}:{}", self.sequence_no, self.hmac)
    }

    pub fn decode(raw: &str) -> KernelResult<Self> {
        let bad = || KernelError::Audit("malformed head witness".into());
        let (seq, hmac) = raw.trim().split_once(':').ok_or_else(bad)?;
        let sequence_no = seq.parse().map_err(|_| bad())?;
        let valid_hmac = hmac.len() == 64
            && hmac
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        if !valid_hmac {
            return Err(bad());
        }
        Ok(Self {
            sequence_no,
            hmac: hmac.to_string(),
        })
    }
}

pub trait HeadWitness {
    fn load(&self) -> KernelResult<Option<Head>>;
    fn store(&mut self, head: &Head) -> KernelResult<()>;
}

#[cfg(test)]
pub(crate) mod memory {
    //! Testigo en memoria para pruebas. El estado se comparte entre clones
    //! para poder "reabrir" un log con el mismo testigo.
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    #[derive(Clone, Default)]
    pub(crate) struct MemoryHead {
        pub(crate) state: Rc<RefCell<Option<Head>>>,
        pub(crate) fail_writes: Rc<RefCell<bool>>,
    }

    impl HeadWitness for MemoryHead {
        fn load(&self) -> KernelResult<Option<Head>> {
            Ok(self.state.borrow().clone())
        }

        fn store(&mut self, head: &Head) -> KernelResult<()> {
            if *self.fail_writes.borrow() {
                return Err(KernelError::Keyring("simulated keyring failure".into()));
            }
            *self.state.borrow_mut() = Some(head.clone());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_round_trips_through_its_stored_form() {
        let head = Head {
            sequence_no: 41,
            hmac: "ab".repeat(32),
        };
        assert_eq!(Head::decode(&head.encode()).unwrap(), head);
    }

    #[test]
    fn malformed_witness_is_an_error() {
        for raw in [
            "",
            "41",
            "x:".to_string().as_str(),
            "41:zz",
            "41:ABAB",
            "-1:ab",
        ] {
            assert!(Head::decode(raw).is_err(), "{raw:?}");
        }
        assert!(Head::decode(&format!("7:{}", "AB".repeat(32))).is_err());
    }
}
