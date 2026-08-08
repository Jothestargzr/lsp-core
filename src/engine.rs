use crate::crypto::{self, KeyPair, TransparencyLog, H};
use crate::law::{ConsentRegistry, LawRegistry, verify_legal_proof};
use crate::pricing;
use crate::risk;
use crate::settle;
use crate::store::{MemoryStore, TerminusStore};
use crate::types::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

pub struct Engine {
    pub store: MemoryStore,
    pub law: LawRegistry,
    pub consents: ConsentRegistry,
    pub audit: Mutex<TransparencyLog>,
    pub events: broadcast::Sender<serde_json::Value>,
    pub terminus: Option<TerminusStore>,
    pub registry_vk: H,
    pub key_registry: HashMap<Did, H>,
    pub registry_kp: KeyPair, pub regulator_kp: KeyPair,
    pub root_kp: KeyPair, pub officer_kp: KeyPair, pub investor_kp: KeyPair,
}

fn terminus_from_env() -> Option<TerminusStore> {
    std::env::var("TDB_SERVER").ok().map(|base| TerminusStore {
        base,
        user: std::env::var("TDB_USER").unwrap_or_else(|_| "admin".into()),
        key:  std::env::var("TDB_KEY").unwrap_or_else(|_| "root".into()),
        org:  std::env::var("TDB_ORG").unwrap_or_else(|_| "lsp".into()),
        db:   "sumsum".into(),
    })
}

impl Engine {
    pub async fn genesis() -> Arc<Self> {
        let (events, _) = broadcast::channel(256);
        let registry_kp = KeyPair::generate();
        let regulator_kp = KeyPair::generate();
        let root_kp = KeyPair::generate();
        let officer_kp = KeyPair::generate();
        let investor_kp = KeyPair::generate();

        let law_hash = crypto::sha256_hex(b"KE|v1|e_sig=advanced|rbf=permitted|crypto_rail=permitted_at_ramps");
        let law = LawObject { jurisdiction: "KE".into(), version: 1, content_hash: law_hash.clone(),
            regulator_sig: regulator_kp.sign_hex(law_hash.as_bytes()), effective_from: 0 };
        let mut law_log = TransparencyLog::default();
        law_log.append(law_hash.clone());

        let mut key_registry = HashMap::new();
        key_registry.insert("did:lsp:off_1".into(), officer_kp.vk_hex());
        key_registry.insert("did:lsp:inv_1".into(), investor_kp.vk_hex());

        let eng = Arc::new(Engine {
            store: MemoryStore::default(),
            law: LawRegistry { regulator_vk: regulator_kp.vk_hex(), laws: vec![law], log: law_log },
            consents: ConsentRegistry {
                consents: vec![Consent { id: "consent_1".into(), entity: "did:lsp:ent_8891".into(),
                    scopes: vec!["ReadTransactions".into(), "ShareVerifiedState".into(), "SettlementAuthorization".into()],
                    expires_at: crypto::now() + 365 * 86400, active: true }],
                rev_log: TransparencyLog::default() },
            audit: Mutex::new(TransparencyLog::default()),
            events, terminus: terminus_from_env(),
            registry_vk: registry_kp.vk_hex(), key_registry,
            registry_kp, regulator_kp, root_kp, officer_kp, investor_kp,
        });

        let entity = Entity {
            did: "did:lsp:ent_8891".into(), legal_name: "Nairobi Fresh Foods Ltd".into(),
            jurisdiction: "KE".into(), registration_number: "REG-8891".into(),
            root_vk: eng.root_kp.vk_hex(), verification_tier: 4,
            officers: vec![Officer { did: "did:lsp:off_1".into(), name: "Jane Doe".into(),
                role: "CEO".into(), vk: eng.officer_kp.vk_hex(), signing_authority: true }],
        };
        {
            let mut db = eng.store.db.write().await;
            db.pools.push(Pool { pool_id: "POOL-KE-TECH-01".into(), jurisdiction: "KE".into(),
                min_tier: Tier::A, tvl_usd: 4_200_000.0, utilized_usd: 3_444_000.0, base_apy: 11.5 });
        }
        eng.store.put_entity(entity).await;
        eng
    }

    pub fn build_packet(&self, entity: &Entity, action: &str) -> LegalPacket {
        let ts = crypto::now();
        let far = ts + 365 * 86400;
        let mk = |issuer: &KeyPair, subject: Did, bound: H| -> ChainLink {
            let l = ChainLink { issuer_vk: issuer.vk_hex(), subject_did: subject, bound_vk: bound,
                sig: String::new(), expires_at: far };
            ChainLink { sig: issuer.sign_hex(&l.msg()), ..l }
        };
        let link0 = mk(&self.registry_kp, entity.did.clone(), entity.root_vk.clone());
        let link1 = mk(&self.root_kp, entity.officers[0].did.clone(), entity.officers[0].vk.clone());

        let law = &self.law.laws[0];
        let law_proof = self.law.log.merkle_proof_for(&law.content_hash);
        let contract_hash = crypto::sha256_hex(b"RBF|10pct_of_daily_rev|ke_law_v1");
        let packet_hash = crypto::sha256_hex(format!("{}|{}|{}|{}|{}|{}",
            action, entity.officers[0].did, entity.did, law.content_hash, contract_hash, ts).as_bytes());

        LegalPacket {
            action: action.into(), actor_did: entity.officers[0].did.clone(), entity_did: entity.did.clone(),
            law_hash: law.content_hash.clone(), law_inclusion_proof: law_proof, contract_hash: contract_hash.clone(),
            sigs: vec![
                (entity.officers[0].did.clone(), self.officer_kp.sign_hex(packet_hash.as_bytes())),
                ("did:lsp:inv_1".into(), self.investor_kp.sign_hex(contract_hash.as_bytes())),
            ],
            consent_id: "consent_1".into(), authority_chain: vec![link0, link1], ts, packet_hash,
        }
    }

    pub async fn verify_entity(&self, entity_did: &str, sources: Vec<SourceSample>,
                               tre: TreasuryState) -> Result<RiskState, String> {
        self.store.entity(entity_did).await.ok_or("entity not found")?;
        let (mrr, recon) = risk::reconcile(&sources);
        let rev = RevenueState { entity: entity_did.into(), epoch: 1, verified_mrr_usd: mrr,
            volatility: 0.18, concentration: 0.18, recon, sources,
            attestation: crypto::sha256_hex(b"oracle_consensus") };
        let (score, tier) = risk::score(&rev, &tre);
        let rs = RiskState { entity: entity_did.into(), epoch: 1, score, tier, revenue: rev,
            treasury: tre, expires_at: crypto::now() + 86400,
            engine_sig: crypto::sha256_hex(format!("{}|{}", entity_did, score).as_bytes()) };
        self.store.put_risk(rs.clone()).await;
        Ok(rs)
    }

    pub async fn draw(&self, req: DrawRequest) -> Result<Settlement, String> {
        let entity = self.store.entity(&req.entity).await.ok_or("entity not found")?;
        let risk_state = self.store.risk(&req.entity).await.ok_or("no risk state")?;

        if risk_state.revenue.recon != Recon::MultiSourceAgreed {
            return Err("PRIME DIRECTIVE: MultiSourceAgreed required".into());
        }
        if risk_state.expires_at < crypto::now() { return Err("risk state expired".into()); }

        let packet = self.build_packet(&entity, "capital_draw");

        // commit intent first: append → root/proof → verify (ordering fix)
        let log_index = { let mut a = self.audit.lock().unwrap(); a.append(packet.packet_hash.clone()).0 };
        let (root, proof) = {
            let a = self.audit.lock().unwrap();
            (a.root(), a.merkle_proof_for(&packet.packet_hash))
        };

        let receipt = verify_legal_proof(&entity, &packet, &self.law, &self.consents,
            &self.registry_vk, |did| self.key_registry.get(did).cloned(), &root, &proof);
        if !receipt.all_pass() {
            return Err(format!("legal proof failed: {:?}",
                receipt.checks.iter().filter(|c| !c.pass).map(|c| &c.name).collect::<Vec<_>>()));
        }

        let pool = self.store.pools().await.into_iter()
            .find(|p| p.pool_id == req.pool_id).ok_or("pool not found")?;
        if risk_state.tier.rank() < pool.min_tier.rank() { return Err("risk tier below pool minimum".into()); }

        let q = pricing::quote(&risk_state.tier, &risk_state.revenue, &risk_state.treasury, true);

        if !self.store.reserve(&req.pool_id, req.amount_usd).await {
            return Err("pool capacity exceeded".into());
        }
        let finality = match settle::adapter_for(&req.rail).settle(req.amount_usd, &entity.did) {
            Ok(f) => f,
            Err(e) => { self.store.rollback(&req.pool_id, req.amount_usd).await; return Err(e); }
        };

        let mut s = Settlement {
            id: uuid::Uuid::new_v4().to_string(), entity: req.entity.clone(),
            pool_id: req.pool_id.clone(), rail: req.rail.clone(), amount_usd: req.amount_usd,
            final_rate: q.final_rate, finality_proof: finality,
            packet_hash: packet.packet_hash.clone(), merkle_anchor: String::new(),
            settled_at: crypto::now(), legal_proof: receipt,
        };
        s.merkle_anchor = { let a = self.audit.lock().unwrap(); a.root() };

        self.store.put_settlement(s.clone()).await;
        self.store.put_receipt(&req.entity, s.legal_proof.clone()).await;

        if let Some(t) = &self.terminus {
            let (t, doc) = (t.clone(), serde_json::to_value(&s).unwrap());
            tokio::spawn(async move { let _ = t.publish(&doc).await; });
        }
        let _ = self.events.send(serde_json::json!({
            "event": "settlement.committed", "id": s.id, "rail": s.rail,
            "amount": s.amount_usd, "rate": s.final_rate,
            "anchor": s.merkle_anchor, "log_index": log_index }));
        Ok(s)
    }
}

impl TransparencyLog {
    pub fn merkle_proof_for(&self, hash: &H) -> Vec<(H, bool)> {
        match self.hashes().iter().position(|h| h == hash) {
            Some(i) => crypto::merkle_proof(&self.hashes(), i),
            None => vec![],
        }
    }
}
