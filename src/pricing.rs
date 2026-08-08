use crate::types::*;

pub fn quote(_tier: &Tier, _rev: &RevenueState, _tre: &TreasuryState, _opt: bool) -> Quote {
    Quote { final_rate: 6.25 }
}
