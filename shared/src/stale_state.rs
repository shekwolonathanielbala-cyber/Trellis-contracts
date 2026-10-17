//! Cross-source stale-state detection for irreversible workflows (issue #111).

use soroban_sdk::contracttype;

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateSnapshot {
    pub wallet_revision: u64,
    pub api_revision: u64,
    pub ledger_sequence: u32,
}

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaleStateReason { NoReason, WalletChanged, ApiChanged, LedgerAdvanced }

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction { RefreshWallet, RefreshApi, ReSimulate, RestartFlow }

#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StaleStateReport {
    pub stale: bool,
    pub reason: StaleStateReason,
    pub recovery: RecoveryAction,
}

/// Compare the snapshot used to prepare a transaction with current state.
/// Ledger movement is checked first because a re-simulation is required even
/// when wallet and API revisions are unchanged.
pub fn detect(prepared: StateSnapshot, current: StateSnapshot) -> StaleStateReport {
    if current.ledger_sequence != prepared.ledger_sequence {
        return StaleStateReport { stale: true, reason: StaleStateReason::LedgerAdvanced, recovery: RecoveryAction::ReSimulate };
    }
    if current.wallet_revision != prepared.wallet_revision {
        return StaleStateReport { stale: true, reason: StaleStateReason::WalletChanged, recovery: RecoveryAction::RefreshWallet };
    }
    if current.api_revision != prepared.api_revision {
        return StaleStateReport { stale: true, reason: StaleStateReason::ApiChanged, recovery: RecoveryAction::RefreshApi };
    }
    StaleStateReport { stale: false, reason: StaleStateReason::NoReason, recovery: RecoveryAction::RestartFlow }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn snapshot() -> StateSnapshot { StateSnapshot { wallet_revision: 4, api_revision: 9, ledger_sequence: 100 } }

    #[test]
    fn unchanged_snapshot_is_safe_to_continue() {
        let report = detect(snapshot(), snapshot());
        assert!(!report.stale);
        assert_eq!(report.reason, StaleStateReason::NoReason);
    }

    #[test]
    fn each_source_drift_has_a_deterministic_recovery() {
        let prepared = snapshot();
        let mut current = prepared;
        current.wallet_revision += 1;
        assert_eq!(detect(prepared, current).recovery, RecoveryAction::RefreshWallet);
        current = prepared;
        current.api_revision += 1;
        assert_eq!(detect(prepared, current).recovery, RecoveryAction::RefreshApi);
        current = prepared;
        current.ledger_sequence += 1;
        assert_eq!(detect(prepared, current).recovery, RecoveryAction::ReSimulate);
    }

    #[test]
    fn ledger_drift_takes_precedence_over_cache_drift() {
        let prepared = snapshot();
        let current = StateSnapshot { wallet_revision: 5, api_revision: 10, ledger_sequence: 101 };
        let report = detect(prepared, current);
        assert_eq!(report.reason, StaleStateReason::LedgerAdvanced);
        assert_eq!(report.recovery, RecoveryAction::ReSimulate);
    }
}
