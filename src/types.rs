use serde::{Deserialize, Serialize};

pub type Did = String;
pub type H = String;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChainLink {
    pub issuer_vk: H,
    pub subject_did: Did,
    pub bound_vk: H,
    pub sig: String,
    pub expires_at: i64,
}

impl ChainLink {
    pub fn msg(&self) -> Vec<u8> {
        format!("{}|{}|{}|{}", self.issuer_vk, self.subject_did, self.bound_vk, self.expires_at).into_bytes()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LegalPacket {
    pub action: String,
    pub actor_did: Did,
    pub entity_did: Did,
    pub law_hash: H,
    pub law_inclusion_proof: Vec<(H, bool)>,
    pub contract_hash: H,
    pub sigs: Vec<(Did, String)>,
    pub consent_id: String,
    pub authority_chain: Vec<ChainLink>,
    pub ts: i64,
    pub packet_hash: H,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LawObject {
    pub jurisdiction: String,
    pub version: u32,
    pub content_hash: H,
    pub regulator_sig: String,
    pub effective_from: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Consent {
    pub id: String,
    pub entity: Did,
    pub scopes: Vec<String>,
    pub expires_at: i64,
    pub active: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Officer {
    pub did: Did,
    pub name: String,
    pub role: String,
    pub vk: H,
    pub signing_authority: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Entity {
    pub did: Did,
    pub legal_name: String,
    pub jurisdiction: String,
    pub registration_number: String,
    pub root_vk: H,
    pub verification_tier: u32,
    pub officers: Vec<Officer>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CheckResult {
    pub name: String,
    pub pass: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ProofReceipt {
    pub checks: Vec<CheckResult>,
    pub receipt_hash: H,
    pub verified_at: i64,
}

impl ProofReceipt {
    pub fn all_pass(&self) -> bool {
        self.checks.iter().all(|c| c.pass)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    AAA,
    AA,
    A,
    BBB,
    BB,
    B,
    Unrated,
}

impl Tier {
    pub fn rank(&self) -> u32 {
        match self {
            Tier::AAA => 7,
            Tier::AA => 6,
            Tier::A => 5,
            Tier::BBB => 4,
            Tier::BB => 3,
            Tier::B => 2,
            Tier::Unrated => 1,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Pool {
    pub pool_id: String,
    pub jurisdiction: String,
    pub min_tier: Tier,
    pub tvl_usd: f64,
    pub utilized_usd: f64,
    pub base_apy: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SourceSample {
    pub source: String,
    pub net_revenue_usd: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Recon {
    MultiSourceAgreed,
    DiscrepancyFound,
    SingleSourceOnly,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RevenueState {
    pub entity: Did,
    pub epoch: u64,
    pub verified_mrr_usd: f64,
    pub volatility: f64,
    pub concentration: f64,
    pub recon: Recon,
    pub sources: Vec<SourceSample>,
    pub attestation: H,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TreasuryState {
    pub entity: Did,
    pub epoch: u64,
    pub liquid_cash_usd: f64,
    pub total_debt_usd: f64,
    pub dscr: f64,
    pub runway_months: f64,
    pub currency_mismatch_pct: f64,
    pub attestation: H,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RiskState {
    pub entity: Did,
    pub epoch: u64,
    pub score: u32,
    pub tier: Tier,
    pub revenue: RevenueState,
    pub treasury: TreasuryState,
    pub expires_at: i64,
    pub engine_sig: H,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Rail {
    Lightning,
    PAPSS,
    BankWire,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DrawRequest {
    pub entity: Did,
    pub pool_id: String,
    pub amount_usd: f64,
    pub rail: Rail,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Settlement {
    pub id: String,
    pub entity: Did,
    pub pool_id: String,
    pub rail: Rail,
    pub amount_usd: f64,
    pub final_rate: f64,
    pub finality_proof: String,
    pub packet_hash: H,
    pub merkle_anchor: H,
    pub settled_at: i64,
    pub legal_proof: ProofReceipt,
}

pub struct Quote {
    pub final_rate: f64,
}
