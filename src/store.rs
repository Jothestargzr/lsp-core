use crate::types::*;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Default)]
pub struct StateDB {
    pub entities: HashMap<String, Entity>,
    pub risk: HashMap<String, RiskState>,
    pub settlements: Vec<Settlement>,
    pub receipts: HashMap<String, ProofReceipt>,
    pub pools: Vec<Pool>,
}

#[derive(Clone, Default)]
pub struct MemoryStore { pub db: Arc<RwLock<StateDB>> }

impl MemoryStore {
    pub async fn put_entity(&self, e: Entity) { self.db.write().await.entities.insert(e.did.clone(), e); }
    pub async fn put_risk(&self, r: RiskState) { self.db.write().await.risk.insert(r.entity.clone(), r); }
    pub async fn put_settlement(&self, s: Settlement) { self.db.write().await.settlements.push(s); }
    pub async fn put_receipt(&self, entity: &str, r: ProofReceipt) { self.db.write().await.receipts.insert(entity.into(), r); }
    pub async fn entity(&self, did: &str) -> Option<Entity> { self.db.read().await.entities.get(did).cloned() }
    pub async fn risk(&self, did: &str) -> Option<RiskState> { self.db.read().await.risk.get(did).cloned() }
    pub async fn pools(&self) -> Vec<Pool> { self.db.read().await.pools.clone() }
    pub async fn settlements(&self) -> Vec<Settlement> { self.db.read().await.settlements.clone() }
    pub async fn reserve(&self, pool_id: &str, amt: f64) -> bool {
        let mut db = self.db.write().await;
        match db.pools.iter_mut().find(|p| p.pool_id == pool_id) {
            Some(p) if p.utilized_usd + amt <= p.tvl_usd => { p.utilized_usd += amt; true }
            _ => false,
        }
    }
    pub async fn rollback(&self, pool_id: &str, amt: f64) {
        if let Some(p) = self.db.write().await.pools.iter_mut().find(|p| p.pool_id == pool_id) {
            p.utilized_usd -= amt;
        }
    }
}

#[derive(Clone)]
pub struct TerminusStore { pub base: String, pub user: String, pub key: String, pub org: String, pub db: String }

impl TerminusStore {
    pub async fn publish(&self, doc: &serde_json::Value) -> Result<(), String> {
        reqwest::Client::new()
            .post(format!("{}/api/document/{}/{}", self.base, self.org, self.db))
            .basic_auth(&self.user, Some(&self.key))
            .header("Content-Type", "application/json")
            .json(doc)
            .send().await.map_err(|e| e.to_string())?;
        Ok(())
    }
    #[allow(dead_code)]
    pub async fn create_branch(&self, name: &str) -> Result<(), String> {
        reqwest::Client::new()
            .post(format!("{}/api/branch/{}/{}/branch/{}", self.base, self.org, self.db, name))
            .basic_auth(&self.user, Some(&self.key))
            .send().await.map_err(|e| e.to_string())?;
        Ok(())
    }
}
