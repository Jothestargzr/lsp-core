use crate::crypto::{self, TransparencyLog, H};
use crate::types::*;

pub struct LawRegistry {
    pub regulator_vk: H,
    pub laws: Vec<LawObject>,
    pub log: TransparencyLog,
}

impl LawRegistry {
    pub fn verify_law(&self, p: &LegalPacket) -> bool {
        match self.laws.iter().find(|l| l.content_hash == p.law_hash) {
            Some(l) => l.effective_from <= p.ts
                && crypto::verify_hex(&self.regulator_vk, l.content_hash.as_bytes(), &l.regulator_sig)
                && self.log.inclusion(&p.law_hash, &p.law_inclusion_proof),
            None => false,
        }
    }
}

pub struct ConsentRegistry {
    pub consents: Vec<Consent>,
    pub rev_log: TransparencyLog,
}

impl ConsentRegistry {
    pub fn verify(&self, id: &str, entity: &Did, ts: i64) -> bool {
        match self.consents.iter().find(|c| c.id == id && &c.entity == entity) {
            Some(c) => c.active && c.expires_at > ts
                && self.rev_log.non_inclusion_at(&crypto::sha256_hex(id.as_bytes()), ts),
            None => false,
        }
    }
}

/// registry → entity root → officer → action, anchored to the trusted registry key.
pub fn verify_authority_chain(entity: &Entity, p: &LegalPacket, trusted_registry_vk: &H) -> bool {
    let chain = &p.authority_chain;
    if chain.len() < 2 { return false; }
    if chain[0].issuer_vk != *trusted_registry_vk { return false; }

    for (i, link) in chain.iter().enumerate() {
        if link.expires_at <= p.ts { return false; }
        if !crypto::verify_hex(&link.issuer_vk, &link.msg(), &link.sig) { return false; }
        if i > 0 && link.issuer_vk != chain[i - 1].bound_vk { return false; }
    }
    if chain[0].subject_did != entity.did || chain[0].bound_vk != entity.root_vk { return false; }

    let officer_vk = chain.last().unwrap().bound_vk.clone();
    let officer = match entity.officers.iter().find(|o| o.did == p.actor_did && o.signing_authority) {
        Some(o) => o, None => return false,
    };
    if officer.vk != officer_vk || chain.last().unwrap().subject_did != officer.did { return false; }

    p.sigs.iter().any(|(did, sig)| did == &p.actor_did
        && crypto::verify_hex(&officer_vk, p.packet_hash.as_bytes(), sig))
}

pub fn verify_contract_multisig<F>(p: &LegalPacket, resolve: F) -> bool
where F: Fn(&Did) -> Option<H> {
    p.sigs.iter().filter(|(did, sig)| {
        did != &p.actor_did
            && resolve(did).map(|vk| crypto::verify_hex(&vk, p.contract_hash.as_bytes(), sig)).unwrap_or(false)
    }).count() >= 1
}

#[allow(clippy::too_many_arguments)]
pub fn verify_legal_proof<F>(
    entity: &Entity, p: &LegalPacket,
    law: &LawRegistry, consents: &ConsentRegistry,
    trusted_registry_vk: &H, resolve_vk: F,
    audit_root: &H, audit_proof: &[(H, bool)],
) -> ProofReceipt
where F: Fn(&Did) -> Option<H> {
    let checks = vec![
        CheckResult { name: "law_pinned_signed_logged".into(),   pass: law.verify_law(p) },
        CheckResult { name: "authority_chain_unbroken".into(),   pass: verify_authority_chain(entity, p, trusted_registry_vk) },
        CheckResult { name: "consent_active_in_scope".into(),    pass: consents.verify(&p.consent_id, &entity.did, p.ts) },
        CheckResult { name: "contract_multisig_complete".into(), pass: verify_contract_multisig(p, resolve_vk) },
        CheckResult { name: "audit_inclusion".into(),            pass: crypto::merkle_verify(&p.packet_hash, audit_proof, audit_root) },
    ];
    let receipt_hash = crypto::sha256_hex(serde_json::to_string(&checks).unwrap().as_bytes());
    ProofReceipt { checks, receipt_hash, verified_at: crypto::now() }
}
