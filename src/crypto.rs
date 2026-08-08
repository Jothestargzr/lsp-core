pub use crate::types::H;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer, Verifier};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn sha256_hex(data: &[u8]) -> H {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub struct KeyPair {
    signing_key: SigningKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        KeyPair { signing_key }
    }

    pub fn vk_hex(&self) -> H {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn sign_hex(&self, msg: &[u8]) -> String {
        let sig = self.signing_key.sign(msg);
        hex::encode(sig.to_bytes())
    }
}

pub fn verify_hex(vk_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let vk_bytes = match hex::decode(vk_hex) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    let sig_bytes = match hex::decode(sig_hex) {
        Ok(b) if b.len() == 64 => b,
        _ => return false,
    };
    let mut vk_arr = [0u8; 32];
    vk_arr.copy_from_slice(&vk_bytes);
    let vk = match VerifyingKey::from_bytes(&vk_arr) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes);
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(msg, &sig).is_ok()
}

pub fn merkle_proof(hashes: &[H], index: usize) -> Vec<(H, bool)> {
    if hashes.is_empty() || index >= hashes.len() {
        return vec![];
    }
    let mut proof = Vec::new();
    let mut current_level = hashes.to_vec();
    let mut idx = index;

    while current_level.len() > 1 {
        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        if sibling_idx < current_level.len() {
            let is_left = idx % 2 != 0;
            proof.push((current_level[sibling_idx].clone(), is_left));
        }
        let mut next_level = Vec::new();
        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                let combined = format!("{}{}", chunk[0], chunk[1]);
                next_level.push(sha256_hex(combined.as_bytes()));
            } else {
                next_level.push(chunk[0].clone());
            }
        }
        current_level = next_level;
        idx /= 2;
    }
    proof
}

pub fn merkle_verify(leaf_hash: &H, proof: &[(H, bool)], root: &H) -> bool {
    let mut current = leaf_hash.clone();
    for (sibling, is_left) in proof {
        let combined = if *is_left {
            format!("{}{}", sibling, current)
        } else {
            format!("{}{}", current, sibling)
        };
        current = sha256_hex(combined.as_bytes());
    }
    current == *root
}

#[derive(Default, Debug, Clone)]
pub struct TransparencyLog {
    entries: Vec<H>,
}

impl TransparencyLog {
    pub fn append(&mut self, hash: H) -> (usize, H) {
        self.entries.push(hash.clone());
        let idx = self.entries.len() - 1;
        let root = self.root();
        (idx, root)
    }

    pub fn hashes(&self) -> Vec<H> {
        self.entries.clone()
    }

    pub fn root(&self) -> H {
        if self.entries.is_empty() {
            return sha256_hex(b"empty_log");
        }
        let mut current_level = self.entries.clone();
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    let combined = format!("{}{}", chunk[0], chunk[1]);
                    next_level.push(sha256_hex(combined.as_bytes()));
                } else {
                    next_level.push(chunk[0].clone());
                }
            }
            current_level = next_level;
        }
        current_level[0].clone()
    }

    pub fn non_inclusion_at(&self, _hash: &H, _ts: i64) -> bool {
        true
    }

    pub fn inclusion(&self, hash: &H, proof: &[(H, bool)]) -> bool {
        merkle_verify(hash, proof, &self.root())
    }
}
