use crate::types::*;

pub fn reconcile(sources: &[SourceSample]) -> (f64, Recon) {
    if sources.is_empty() {
        return (0.0, Recon::SingleSourceOnly);
    }
    let avg = sources.iter().map(|s| s.net_revenue_usd).sum::<f64>() / sources.len() as f64;
    let recon = if sources.len() > 1 {
        let max_diff = sources.iter().map(|s| (s.net_revenue_usd - avg).abs()).fold(0.0, f64::max);
        if max_diff / avg < 0.05 {
            Recon::MultiSourceAgreed
        } else {
            Recon::DiscrepancyFound
        }
    } else {
        Recon::SingleSourceOnly
    };
    (avg, recon)
}

pub fn score(rev: &RevenueState, _tre: &TreasuryState) -> (u32, Tier) {
    if rev.recon == Recon::MultiSourceAgreed {
        (1000, Tier::AAA)
    } else {
        (750, Tier::BBB)
    }
}
