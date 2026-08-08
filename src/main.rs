mod api; mod crypto; mod engine; mod law; mod pricing; mod risk; mod settle; mod store; mod types;

use engine::Engine;
use types::*;

#[tokio::main]
async fn main() {
    let eng = Engine::genesis().await;

    let tre = TreasuryState { entity: "did:lsp:ent_8891".into(), epoch: 1,
        liquid_cash_usd: 184_000.0, total_debt_usd: 62_000.0, dscr: 1.8,
        runway_months: 7.2, currency_mismatch_pct: 12.0,
        attestation: crypto::sha256_hex(b"treasury_attestation") };
    let sources = vec![
        SourceSample { source: "bank_api".into(), net_revenue_usd: 42_100.0 },
        SourceSample { source: "psp_paystack".into(), net_revenue_usd: 41_800.0 },
        SourceSample { source: "lightning_receipts".into(), net_revenue_usd: 42_400.0 },
    ];
    let rs = eng.verify_entity("did:lsp:ent_8891", sources, tre).await.unwrap();
    println!("[GENESIS] score={} tier={:?} recon={:?}", rs.score, rs.tier, rs.revenue.recon);

    // Genesis settlement so the terminal renders live state on first open
    let s = eng.draw(DrawRequest { entity: "did:lsp:ent_8891".into(),
        pool_id: "POOL-KE-TECH-01".into(), amount_usd: 50_000.0, rail: Rail::Lightning }).await.unwrap();
    println!("[GENESIS-SETTLE] id={} rate={}% anchor={}", &s.id[..8], s.final_rate, &s.merkle_anchor[..16]);

    if std::env::var("LSP_DEMO").is_ok() {
        for c in &s.legal_proof.checks { println!("  [{}] {}", if c.pass { "PASS" } else { "FAIL" }, c.name); }
        return;
    }

    println!("[LSP-CORE] serving :3001 — law is code, code is law");
    axum::serve(tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap(), api::router(eng)).await.unwrap();
}
