use crate::types::Rail;

pub struct Adapter;

impl Adapter {
    pub fn settle(&self, _amount_usd: f64, entity_did: &str) -> Result<String, String> {
        let proof = crate::crypto::sha256_hex(format!("lightning_settle_{}_{}", entity_did, crate::crypto::now()).as_bytes());
        Ok(format!("proof_{}", &proof[..16]))
    }
}

pub fn adapter_for(_rail: &Rail) -> Adapter {
    Adapter
}
