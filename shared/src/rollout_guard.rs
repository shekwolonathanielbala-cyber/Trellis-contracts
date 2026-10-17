//! Feature-flag rollout guard with automatic rollback verification (Issue #239).
//!
//! Across Soroban contracts — Treasury, Aid, Referral, Governance, Oracle, and
//! Marketplace — risky changes (v2 paths, algorithm updates, batch logic, fee
//! alterations) must be safely introduced behind staged rollout guards.
//!
//! When an anomaly, error spike, or invariant breach occurs in production, the guard
//! automatically trips an emergency rollback and verifies that no corrupted, partial,
//! or inconsistent state remains behind.
//!
//! ## Core Architecture
//!
//! 1. **Scoped Rollout Guard (`RolloutGuardConfig`)**:
//!    - Target scoping by module ([`RolloutModule`]) or typed flag ([`FeatureFlag`]).
//!    - Staged canary progression: [`RolloutStage::Canary`] -> [`RolloutStage::Partial`] ->
//!      [`RolloutStage::Majority`] -> [`RolloutStage::Full`].
//!    - Deterministic per-caller bucketing (`0..10_000` bps) using stable caller seeds.
//!
//! 2. **Telemetry & Health Monitoring (`RolloutHealthMetrics`)**:
//!    - Tracks total invocations, successful executions, consecutive failures, and error rates.
//!    - Evaluates health states: `Healthy` -> `Warning` -> `Degraded` -> `RolledBack`.
//!    - Provides pre-execution guard decisions ([`GuardDecision::ProceedNew`] vs
//!      [`GuardDecision::FallbackLegacy`]).
//!
//! 3. **Automatic Rollback Trigger (`trigger_auto_rollback`)**:
//!    - Automatically trips when consecutive failures exceed `max_consecutive_failures`,
//!      when error rate exceeds `max_error_rate_bps` over a sample window, or when an
//!      invariant post-check fails.
//!    - Immediately switches the flag off (`enabled = false`, `rollout_bps = 0`), sets
//!      the stage to `RolledBack`, records an immutable audit record, and publishes an event.
//!
//! 4. **Automatic Rollback Verification (`verify_rollback`)**:
//!    - Verifies that the flag is disabled and rollout weight is zeroed.
//!    - Confirms that execution routing strictly falls back to the safe legacy path for all callers.
//!    - Verifies module-specific state consistency invariants (solvency/reserves, no orphaned
//!      records, sequence monotonicity).
//!    - Generates an auditable [`RollbackVerificationReceipt`].
//!    - Enforces that rolled-back features cannot be re-enabled until clean rollback verification
//!      has succeeded ([`rearm_after_verified_rollback`]).

use soroban_sdk::{contracttype, symbol_short, Env, Symbol};

use crate::feature_flags::{
    emergency_disable, get_flag, FeatureFlag, FeatureFlagError, FULL_ROLLOUT_BPS,
};
use crate::storage::{instance_get, instance_set};

// ---------------------------------------------------------------------------
// Modules & Scoping
// ---------------------------------------------------------------------------

/// The six core contract modules generating operational activity in Trellis.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RolloutModule {
    Treasury,
    Aid,
    Referral,
    Governance,
    Oracle,
    Marketplace,
}

impl RolloutModule {
    pub fn as_symbol(self) -> Symbol {
        match self {
            RolloutModule::Treasury => symbol_short!("treasury"),
            RolloutModule::Aid => symbol_short!("aid"),
            RolloutModule::Referral => symbol_short!("referral"),
            RolloutModule::Governance => symbol_short!("gov"),
            RolloutModule::Oracle => symbol_short!("oracle"),
            RolloutModule::Marketplace => symbol_short!("market"),
        }
    }
}

/// Rollout target: either a broad module scope or a specific typed feature flag.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RolloutTarget {
    Module(RolloutModule),
    Flag(FeatureFlag),
}

/// Rollout stage progression for canaried deployments.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RolloutStage {
    /// Completely disabled (0 bps weight).
    Disabled,
    /// Canary stage: limited subset of callers (e.g. 500 bps = 5%).
    Canary,
    /// Partial rollout (e.g. 2 500 bps = 25%).
    Partial,
    /// Majority rollout (e.g. 7 500 bps = 75%).
    Majority,
    /// Full production rollout (10 000 bps = 100%).
    Full,
    /// Rolled back to safe legacy path due to failures or manual intervention.
    RolledBack,
}

/// Operational health of a guarded rollout.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardHealthStatus {
    /// Operating nominally within error limits.
    Healthy,
    /// Intermittent errors observed, within tolerance.
    Warning,
    /// Elevated failure rate approaching auto-rollback threshold.
    Degraded,
    /// Rollback triggered; guard routes all traffic to legacy path.
    RolledBack,
}

/// Root cause recorded when an emergency or automatic rollback is tripped.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackReason {
    /// Manually requested by maintainer/administrator.
    ManualTrigger,
    /// Consecutive failures exceeded maximum configured tolerance.
    ConsecutiveFailuresExceeded,
    /// Failure percentage exceeded maximum allowed threshold over sample window.
    ErrorRateBreached,
    /// State invariant or asset conservation post-check failed.
    InvariantViolation,
    /// Inconsistent state detected during verification.
    StateInconsistency,
}

/// Specific anomaly detected during rollback state consistency verification.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateAnomalyKind {
    /// Master switch remained active after rollback.
    FlagStillEnabled,
    /// Rollout basis points was not zeroed after rollback.
    RolloutBpsNotZeroed,
    /// Stage was not marked as RolledBack.
    StageNotRolledBack,
    /// Rollout guard failed to route callers to legacy fallback.
    LegacyFallbackBypassed,
    /// Physical reserves do not balance tracked liabilities.
    SolvencyDiscrepancy,
    /// Dangling or partial operational records detected.
    OrphanedPartialRecord,
    /// Governance vote tally does not match ballot records.
    TallyMismatch,
    /// Oracle price feed or quorum is stale/skewed.
    StalePriceOrQuorumDeficit,
    /// Listing escrow balance does not match active inventory.
    EscrowMismatch,
    /// Verification passed; no anomaly detected.
    NoAnomaly,
}

// ---------------------------------------------------------------------------
// Guard Configuration & Telemetry
// ---------------------------------------------------------------------------

/// Stored configuration for a feature rollout guard.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RolloutGuardConfig {
    /// Master switch for the rollout guard.
    pub enabled: bool,
    /// Current staged rollout phase.
    pub stage: RolloutStage,
    /// Effective traffic weight in basis points (0–10 000).
    pub rollout_bps: u32,
    /// Maximum consecutive errors allowed before tripping auto-rollback.
    pub max_consecutive_failures: u32,
    /// Maximum error rate in basis points (e.g. 1 000 = 10%) tolerated over `min_sample_size`.
    pub max_error_rate_bps: u32,
    /// Minimum invocations before error rate percentage is evaluated.
    pub min_sample_size: u32,
    /// When true, reaching failure thresholds immediately triggers automatic rollback.
    pub auto_rollback_enabled: bool,
    /// Ledger sequence when this config was updated.
    pub updated_at: u32,
}

/// Runtime telemetry metrics for a guarded rollout target.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RolloutHealthMetrics {
    /// Total invocations processed by the guard.
    pub total_invocations: u32,
    /// Successful invocations.
    pub successful_invocations: u32,
    /// Failed invocations.
    pub failed_invocations: u32,
    /// Current consecutive failures count (resets to 0 on success).
    pub consecutive_failures: u32,
    /// Error code of the most recent failure.
    pub last_error_code: u32,
    /// Ledger sequence when the last failure occurred.
    pub last_failure_ledger: u32,
    /// Effective health assessment.
    pub health_status: GuardHealthStatus,
}

/// Routing decision returned by the guard before taking a gated code branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardDecision {
    /// Safe to execute the new canaried feature path.
    ProceedNew,
    /// Safely route to legacy baseline path (missing config, disabled, outside canary, or rolled back).
    FallbackLegacy,
    /// Guard blocked the invocation due to critical failure.
    Blocked(FeatureFlagError),
}

/// Immutable audit record stored upon triggering an automatic or manual rollback.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackAuditRecord {
    pub target: RolloutTarget,
    pub reason: RollbackReason,
    pub triggered_ledger: u32,
    pub failing_error_code: u32,
    pub consecutive_failures_at_rb: u32,
    pub total_invocations_at_rollback: u32,
    pub failed_invocations_at_rollback: u32,
}

/// Verification receipt generated after inspecting post-rollback state consistency.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RollbackVerificationReceipt {
    /// True if all consistency checks passed without finding any inconsistent state.
    pub verified_clean: bool,
    /// Ledger sequence when verification ran.
    pub verified_ledger: u32,
    /// The target that was rolled back and verified.
    pub target: RolloutTarget,
    /// The rollback reason recorded.
    pub rollback_reason: RollbackReason,
    /// Number of distinct checks evaluated.
    pub checks_evaluated: u32,
    /// Number of checks passed.
    pub checks_passed: u32,
    /// First detected anomaly, if verification failed.
    pub anomaly: StateAnomalyKind,
}

/// Verification snapshot supplied to verify module-specific state invariants.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModuleConsistencySnapshot {
    pub module: RolloutModule,
    /// Assets/liabilities match reserves (e.g. Treasury, Marketplace escrow).
    pub reserves_solvent: bool,
    /// No half-committed or dangling records (e.g. Aid, Referral).
    pub records_consistent: bool,
    /// Invariant tallies or monotonic sequences are intact (e.g. Governance, Oracle).
    pub invariants_intact: bool,
}

impl ModuleConsistencySnapshot {
    pub fn treasury(reserves_solvent: bool, records_consistent: bool, invariants_intact: bool) -> Self {
        Self {
            module: RolloutModule::Treasury,
            reserves_solvent,
            records_consistent,
            invariants_intact,
        }
    }

    pub fn aid(reserves_solvent: bool, records_consistent: bool, invariants_intact: bool) -> Self {
        Self {
            module: RolloutModule::Aid,
            reserves_solvent,
            records_consistent,
            invariants_intact,
        }
    }

    pub fn referral(reserves_solvent: bool, records_consistent: bool, invariants_intact: bool) -> Self {
        Self {
            module: RolloutModule::Referral,
            reserves_solvent,
            records_consistent,
            invariants_intact,
        }
    }

    pub fn governance(reserves_solvent: bool, records_consistent: bool, invariants_intact: bool) -> Self {
        Self {
            module: RolloutModule::Governance,
            reserves_solvent,
            records_consistent,
            invariants_intact,
        }
    }

    pub fn oracle(reserves_solvent: bool, records_consistent: bool, invariants_intact: bool) -> Self {
        Self {
            module: RolloutModule::Oracle,
            reserves_solvent,
            records_consistent,
            invariants_intact,
        }
    }

    pub fn marketplace(reserves_solvent: bool, records_consistent: bool, invariants_intact: bool) -> Self {
        Self {
            module: RolloutModule::Marketplace,
            reserves_solvent,
            records_consistent,
            invariants_intact,
        }
    }

    pub fn clean(module: RolloutModule) -> Self {
        Self {
            module,
            reserves_solvent: true,
            records_consistent: true,
            invariants_intact: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum GuardStorageKey {
    Config(RolloutTarget),
    Metrics(RolloutTarget),
    Audit(RolloutTarget),
    Receipt(RolloutTarget),
}

fn target_symbol(target: RolloutTarget) -> Symbol {
    match target {
        RolloutTarget::Module(m) => m.as_symbol(),
        RolloutTarget::Flag(f) => match f {
            FeatureFlag::BatchExecutor => symbol_short!("batch_ex"),
            FeatureFlag::QuotaBypass => symbol_short!("q_bypass"),
            FeatureFlag::EscrowReleaseV2 => symbol_short!("escrow_v2"),
            FeatureFlag::ReferralPayoutV2 => symbol_short!("ref_v2"),
            FeatureFlag::TreasurySweepV2 => symbol_short!("trs_v2"),
            FeatureFlag::AidDisbursementV2 => symbol_short!("aid_v2"),
            FeatureFlag::GovernanceVotingV2 => symbol_short!("gov_v2"),
            FeatureFlag::OracleMedianizerV2 => symbol_short!("oracle_v2"),
            FeatureFlag::MarketplaceAuctionV2 => symbol_short!("mkt_v2"),
        },
    }
}

// ---------------------------------------------------------------------------
// Guard Configuration & Evaluation
// ---------------------------------------------------------------------------

/// Safe default configuration: disabled, 0 bps, fallback to legacy path.
pub fn default_guard_config(env: &Env) -> RolloutGuardConfig {
    RolloutGuardConfig {
        enabled: false,
        stage: RolloutStage::Disabled,
        rollout_bps: 0,
        max_consecutive_failures: 3,
        max_error_rate_bps: 1_000, // 10%
        min_sample_size: 10,
        auto_rollback_enabled: true,
        updated_at: env.ledger().sequence(),
    }
}

/// Safe default health telemetry.
pub fn default_health_metrics() -> RolloutHealthMetrics {
    RolloutHealthMetrics {
        total_invocations: 0,
        successful_invocations: 0,
        failed_invocations: 0,
        consecutive_failures: 0,
        last_error_code: 0,
        last_failure_ledger: 0,
        health_status: GuardHealthStatus::Healthy,
    }
}

/// Read the guard configuration for a rollout target.
pub fn get_guard_config(env: &Env, target: RolloutTarget) -> RolloutGuardConfig {
    instance_get(env, &GuardStorageKey::Config(target)).unwrap_or_else(|| default_guard_config(env))
}

/// Read runtime telemetry metrics for a rollout target.
pub fn get_health_metrics(env: &Env, target: RolloutTarget) -> RolloutHealthMetrics {
    instance_get(env, &GuardStorageKey::Metrics(target)).unwrap_or_else(default_health_metrics)
}

/// Initialize or update a rollout guard configuration.
pub fn init_or_update_guard(
    env: &Env,
    target: RolloutTarget,
    config: &RolloutGuardConfig,
) -> Result<(), FeatureFlagError> {
    if config.rollout_bps > FULL_ROLLOUT_BPS {
        return Err(FeatureFlagError::InvalidRollout);
    }
    if config.max_error_rate_bps > FULL_ROLLOUT_BPS || config.max_consecutive_failures == 0 {
        return Err(FeatureFlagError::InvalidGuardConfig);
    }

    // If currently rolled back and trying to enable, verify that clean rollback verification passed
    let existing = get_guard_config(env, target);
    if existing.stage == RolloutStage::RolledBack
        && config.enabled
        && !is_rollback_verified(env, target)
    {
        return Err(FeatureFlagError::UnverifiedRollbackReenableForbidden);
    }

    instance_set(env, &GuardStorageKey::Config(target), config);

    // Synchronize underlying feature flag if targeted
    if let RolloutTarget::Flag(flag) = target {
        let _ = crate::feature_flags::set_flag(
            env,
            &flag,
            config.enabled && config.stage != RolloutStage::RolledBack,
            config.rollout_bps,
        )?;
    }

    Ok(())
}

/// Evaluate whether an execution path should proceed with the new behavior or fall back to legacy.
pub fn evaluate_rollout_guard(env: &Env, target: RolloutTarget, caller_seed: u32) -> GuardDecision {
    let config = get_guard_config(env, target);

    // If disabled or rolled back, immediately route to safe legacy path
    if !config.enabled || config.stage == RolloutStage::Disabled || config.stage == RolloutStage::RolledBack {
        return GuardDecision::FallbackLegacy;
    }

    // Check health metrics
    let metrics = get_health_metrics(env, target);
    if metrics.health_status == GuardHealthStatus::RolledBack
        || metrics.health_status == GuardHealthStatus::Degraded
    {
        return GuardDecision::FallbackLegacy;
    }

    // Staged canary bucketing (0..10_000 bps)
    let bucket = caller_seed % FULL_ROLLOUT_BPS;
    if bucket < config.rollout_bps.min(FULL_ROLLOUT_BPS) {
        GuardDecision::ProceedNew
    } else {
        GuardDecision::FallbackLegacy
    }
}

// ---------------------------------------------------------------------------
// Telemetry & Automatic Rollback Trigger
// ---------------------------------------------------------------------------

/// Record execution outcome from a guarded path. Automatically triggers rollback if thresholds breached.
pub fn record_execution_outcome(
    env: &Env,
    target: RolloutTarget,
    success: bool,
    error_code: u32,
    invariant_passed: bool,
) -> Result<GuardHealthStatus, FeatureFlagError> {
    let config = get_guard_config(env, target);

    // If already rolled back, remain in rolled-back state
    if config.stage == RolloutStage::RolledBack {
        return Ok(GuardHealthStatus::RolledBack);
    }

    let mut metrics = get_health_metrics(env, target);
    metrics.total_invocations += 1;

    let mut auto_rollback_reason: Option<RollbackReason> = None;

    if success && invariant_passed {
        metrics.successful_invocations += 1;
        metrics.consecutive_failures = 0;
        metrics.health_status = GuardHealthStatus::Healthy;
    } else {
        metrics.failed_invocations += 1;
        metrics.consecutive_failures += 1;
        metrics.last_error_code = error_code;
        metrics.last_failure_ledger = env.ledger().sequence();

        // 1. Critical trigger: invariant failure
        if !invariant_passed {
            auto_rollback_reason = Some(RollbackReason::InvariantViolation);
        }
        // 2. Consecutive failure threshold
        else if metrics.consecutive_failures >= config.max_consecutive_failures {
            auto_rollback_reason = Some(RollbackReason::ConsecutiveFailuresExceeded);
        }
        // 3. Error rate threshold over sample size
        else if metrics.total_invocations >= config.min_sample_size {
            let error_rate_bps = (metrics.failed_invocations * FULL_ROLLOUT_BPS) / metrics.total_invocations;
            if error_rate_bps > config.max_error_rate_bps {
                auto_rollback_reason = Some(RollbackReason::ErrorRateBreached);
            } else {
                metrics.health_status = GuardHealthStatus::Warning;
            }
        } else {
            metrics.health_status = GuardHealthStatus::Warning;
        }
    }

    // Execute automatic rollback if condition triggered and enabled
    if let Some(reason) = auto_rollback_reason {
        if config.auto_rollback_enabled {
            trigger_auto_rollback(env, target, reason, error_code);
            metrics.health_status = GuardHealthStatus::RolledBack;
        } else {
            metrics.health_status = GuardHealthStatus::Degraded;
        }
    }

    instance_set(env, &GuardStorageKey::Metrics(target), &metrics);
    Ok(metrics.health_status)
}

/// Trip an emergency or automatic rollback for the target.
pub fn trigger_auto_rollback(
    env: &Env,
    target: RolloutTarget,
    reason: RollbackReason,
    failing_error_code: u32,
) -> RollbackAuditRecord {
    // 1. Disable guard and update stage to RolledBack
    let mut config = get_guard_config(env, target);
    config.enabled = false;
    config.rollout_bps = 0;
    config.stage = RolloutStage::RolledBack;
    config.updated_at = env.ledger().sequence();
    instance_set(env, &GuardStorageKey::Config(target), &config);

    // 2. Disable underlying feature flag if targeted
    if let RolloutTarget::Flag(flag) = target {
        emergency_disable(env, &flag);
    }

    // 3. Update health metrics
    let mut metrics = get_health_metrics(env, target);
    metrics.health_status = GuardHealthStatus::RolledBack;
    instance_set(env, &GuardStorageKey::Metrics(target), &metrics);

    // 4. Record audit entry
    let audit = RollbackAuditRecord {
        target,
        reason,
        triggered_ledger: env.ledger().sequence(),
        failing_error_code,
        consecutive_failures_at_rb: metrics.consecutive_failures,
        total_invocations_at_rollback: metrics.total_invocations,
        failed_invocations_at_rollback: metrics.failed_invocations,
    };
    instance_set(env, &GuardStorageKey::Audit(target), &audit);

    // 5. Emit rollback event
    env.events().publish(
        (symbol_short!("rollout"), symbol_short!("rollback")),
        (target_symbol(target), reason as u32, failing_error_code),
    );

    audit
}

// ---------------------------------------------------------------------------
// Automatic Rollback Verification
// ---------------------------------------------------------------------------

/// Retrieve the last recorded rollback audit record, if any.
pub fn get_last_rollback_audit(env: &Env, target: RolloutTarget) -> Option<RollbackAuditRecord> {
    instance_get(env, &GuardStorageKey::Audit(target))
}

/// Retrieve the last rollback verification receipt, if any.
pub fn get_last_verification_receipt(
    env: &Env,
    target: RolloutTarget,
) -> Option<RollbackVerificationReceipt> {
    instance_get(env, &GuardStorageKey::Receipt(target))
}

/// Whether a clean rollback has been verified for this target.
pub fn is_rollback_verified(env: &Env, target: RolloutTarget) -> bool {
    get_last_verification_receipt(env, target).map_or(false, |r| r.verified_clean)
}

/// Perform automatic rollback verification to prove no inconsistent state remains.
pub fn verify_rollback(
    env: &Env,
    target: RolloutTarget,
    snapshot: &ModuleConsistencySnapshot,
) -> RollbackVerificationReceipt {
    let mut checks_evaluated = 0u32;
    let mut checks_passed = 0u32;
    let mut detected_anomaly: StateAnomalyKind = StateAnomalyKind::NoAnomaly;

    // Check 1: Guard configuration disabled
    checks_evaluated += 1;
    let config = get_guard_config(env, target);
    if config.enabled {
        if detected_anomaly == StateAnomalyKind::NoAnomaly {
            detected_anomaly = StateAnomalyKind::FlagStillEnabled;
        }
    } else {
        checks_passed += 1;
    }

    // Check 2: Rollout weight zeroed
    checks_evaluated += 1;
    if config.rollout_bps != 0 {
        if detected_anomaly == StateAnomalyKind::NoAnomaly {
            detected_anomaly = StateAnomalyKind::RolloutBpsNotZeroed;
        }
    } else {
        checks_passed += 1;
    }

    // Check 3: Stage is marked as RolledBack
    checks_evaluated += 1;
    if config.stage != RolloutStage::RolledBack {
        if detected_anomaly == StateAnomalyKind::NoAnomaly {
            detected_anomaly = StateAnomalyKind::StageNotRolledBack;
        }
    } else {
        checks_passed += 1;
    }

    // Check 4: If targeting a feature flag, confirm flag config is disabled and zeroed
    if let RolloutTarget::Flag(flag) = target {
        checks_evaluated += 1;
        let flag_cfg = get_flag(env, &flag);
        if flag_cfg.enabled || flag_cfg.rollout_bps != 0 {
            if detected_anomaly == StateAnomalyKind::NoAnomaly {
                detected_anomaly = StateAnomalyKind::FlagStillEnabled;
            }
        } else {
            checks_passed += 1;
        }
    }

    // Check 5: Deterministic fallback routing for all caller seeds
    checks_evaluated += 1;
    let seeds = [0u32, 100u32, 2_500u32, 5_000u32, 7_500u32, 9_999u32];
    let mut routing_ok = true;
    for &seed in seeds.iter() {
        if evaluate_rollout_guard(env, target, seed) != GuardDecision::FallbackLegacy {
            routing_ok = false;
            break;
        }
    }
    if !routing_ok {
        if detected_anomaly == StateAnomalyKind::NoAnomaly {
            detected_anomaly = StateAnomalyKind::LegacyFallbackBypassed;
        }
    } else {
        checks_passed += 1;
    }

    // Check 6: Solvency & reserve backing
    checks_evaluated += 1;
    if !snapshot.reserves_solvent {
        if detected_anomaly == StateAnomalyKind::NoAnomaly {
            detected_anomaly = StateAnomalyKind::SolvencyDiscrepancy;
        }
    } else {
        checks_passed += 1;
    }

    // Check 7: No orphaned or half-committed records
    checks_evaluated += 1;
    if !snapshot.records_consistent {
        if detected_anomaly == StateAnomalyKind::NoAnomaly {
            detected_anomaly = StateAnomalyKind::OrphanedPartialRecord;
        }
    } else {
        checks_passed += 1;
    }

    // Check 8: Module-specific state invariant integrity
    checks_evaluated += 1;
    if !snapshot.invariants_intact {
        if detected_anomaly == StateAnomalyKind::NoAnomaly {
            detected_anomaly = match snapshot.module {
                RolloutModule::Governance => StateAnomalyKind::TallyMismatch,
                RolloutModule::Oracle => StateAnomalyKind::StalePriceOrQuorumDeficit,
                RolloutModule::Marketplace => StateAnomalyKind::EscrowMismatch,
                _ => StateAnomalyKind::SolvencyDiscrepancy,
            };
        }
    } else {
        checks_passed += 1;
    }

    let verified_clean = detected_anomaly == StateAnomalyKind::NoAnomaly && (checks_passed == checks_evaluated);
    let audit = get_last_rollback_audit(env, target);
    let rollback_reason = audit.map_or(RollbackReason::ManualTrigger, |a| a.reason);

    let receipt = RollbackVerificationReceipt {
        verified_clean,
        verified_ledger: env.ledger().sequence(),
        target,
        rollback_reason,
        checks_evaluated,
        checks_passed,
        anomaly: detected_anomaly,
    };

    instance_set(env, &GuardStorageKey::Receipt(target), &receipt);

    // Emit verification event
    env.events().publish(
        (symbol_short!("rollout"), symbol_short!("verified")),
        (target_symbol(target), verified_clean, checks_passed),
    );

    receipt
}

/// Safely re-arm a rolled-back feature only if clean rollback verification has passed.
pub fn rearm_after_verified_rollback(
    env: &Env,
    target: RolloutTarget,
    new_stage: RolloutStage,
    rollout_bps: u32,
) -> Result<RolloutGuardConfig, FeatureFlagError> {
    if !is_rollback_verified(env, target) {
        return Err(FeatureFlagError::UnverifiedRollbackReenableForbidden);
    }
    if rollout_bps > FULL_ROLLOUT_BPS {
        return Err(FeatureFlagError::InvalidRollout);
    }

    let mut config = get_guard_config(env, target);
    config.enabled = true;
    config.stage = new_stage;
    config.rollout_bps = rollout_bps;
    config.updated_at = env.ledger().sequence();

    init_or_update_guard(env, target, &config)?;

    // Reset health telemetry for fresh canary run
    let mut metrics = get_health_metrics(env, target);
    metrics.consecutive_failures = 0;
    metrics.health_status = GuardHealthStatus::Healthy;
    instance_set(env, &GuardStorageKey::Metrics(target), &metrics);

    Ok(config)
}

// ---------------------------------------------------------------------------
// Unit & Integration Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl};

    #[contract]
    pub struct RolloutGuardHarness;

    #[contractimpl]
    impl RolloutGuardHarness {
        pub fn noop(_env: Env) {}
    }

    fn with_storage<T>(env: &Env, f: impl FnOnce() -> T) -> T {
        let id = env.register_contract(None, RolloutGuardHarness);
        env.as_contract(&id, f)
    }

    #[test]
    fn default_guard_falls_back_to_legacy() {
        let env = Env::default();
        with_storage(&env, || {
            let target = RolloutTarget::Module(RolloutModule::Treasury);
            let config = get_guard_config(&env, target);
            assert!(!config.enabled);
            assert_eq!(config.rollout_bps, 0);
            assert_eq!(config.stage, RolloutStage::Disabled);

            // Any caller seed routes to legacy
            assert_eq!(
                evaluate_rollout_guard(&env, target, 0),
                GuardDecision::FallbackLegacy
            );
            assert_eq!(
                evaluate_rollout_guard(&env, target, 500),
                GuardDecision::FallbackLegacy
            );
        });
    }

    #[test]
    fn canary_rollout_scopes_callers_deterministically() {
        let env = Env::default();
        with_storage(&env, || {
            let target = RolloutTarget::Flag(FeatureFlag::EscrowReleaseV2);
            let mut config = default_guard_config(&env);
            config.enabled = true;
            config.stage = RolloutStage::Canary;
            config.rollout_bps = 500; // 5% canary
            init_or_update_guard(&env, target, &config).unwrap();

            // Inside canary window: seed < 500
            assert_eq!(
                evaluate_rollout_guard(&env, target, 0),
                GuardDecision::ProceedNew
            );
            assert_eq!(
                evaluate_rollout_guard(&env, target, 499),
                GuardDecision::ProceedNew
            );

            // Outside canary window: seed >= 500
            assert_eq!(
                evaluate_rollout_guard(&env, target, 500),
                GuardDecision::FallbackLegacy
            );
            assert_eq!(
                evaluate_rollout_guard(&env, target, 9_999),
                GuardDecision::FallbackLegacy
            );
        });
    }

    #[test]
    fn stage_promotions_expand_rollout() {
        let env = Env::default();
        with_storage(&env, || {
            let target = RolloutTarget::Module(RolloutModule::Aid);
            let mut config = default_guard_config(&env);
            config.enabled = true;

            // Partial stage: 25%
            config.stage = RolloutStage::Partial;
            config.rollout_bps = 2_500;
            init_or_update_guard(&env, target, &config).unwrap();
            assert_eq!(
                evaluate_rollout_guard(&env, target, 2_499),
                GuardDecision::ProceedNew
            );
            assert_eq!(
                evaluate_rollout_guard(&env, target, 2_500),
                GuardDecision::FallbackLegacy
            );

            // Full stage: 100%
            config.stage = RolloutStage::Full;
            config.rollout_bps = FULL_ROLLOUT_BPS;
            init_or_update_guard(&env, target, &config).unwrap();
            assert_eq!(
                evaluate_rollout_guard(&env, target, 9_999),
                GuardDecision::ProceedNew
            );
        });
    }

    #[test]
    fn consecutive_failures_trigger_automatic_rollback() {
        let env = Env::default();
        with_storage(&env, || {
            let target = RolloutTarget::Flag(FeatureFlag::ReferralPayoutV2);
            let mut config = default_guard_config(&env);
            config.enabled = true;
            config.stage = RolloutStage::Canary;
            config.rollout_bps = 1_000;
            config.max_consecutive_failures = 3;
            config.auto_rollback_enabled = true;
            init_or_update_guard(&env, target, &config).unwrap();

            // First failure -> Warning
            let status1 = record_execution_outcome(&env, target, false, 701, true).unwrap();
            assert_eq!(status1, GuardHealthStatus::Warning);
            assert_eq!(
                evaluate_rollout_guard(&env, target, 0),
                GuardDecision::ProceedNew
            );

            // Second failure -> Warning
            let status2 = record_execution_outcome(&env, target, false, 701, true).unwrap();
            assert_eq!(status2, GuardHealthStatus::Warning);

            // Third failure -> Trips Auto-Rollback!
            let status3 = record_execution_outcome(&env, target, false, 701, true).unwrap();
            assert_eq!(status3, GuardHealthStatus::RolledBack);

            // Confirm post-rollback state: disabled and 0 bps
            let updated_cfg = get_guard_config(&env, target);
            assert!(!updated_cfg.enabled);
            assert_eq!(updated_cfg.rollout_bps, 0);
            assert_eq!(updated_cfg.stage, RolloutStage::RolledBack);

            // Callers immediately fall back to legacy
            assert_eq!(
                evaluate_rollout_guard(&env, target, 0),
                GuardDecision::FallbackLegacy
            );

            // Audit record exists
            let audit = get_last_rollback_audit(&env, target).unwrap();
            assert_eq!(audit.reason, RollbackReason::ConsecutiveFailuresExceeded);
            assert_eq!(audit.failing_error_code, 701);
            assert_eq!(audit.consecutive_failures_at_rb, 3);
        });
    }

    #[test]
    fn error_rate_threshold_triggers_automatic_rollback() {
        let env = Env::default();
        with_storage(&env, || {
            let target = RolloutTarget::Module(RolloutModule::Oracle);
            let mut config = default_guard_config(&env);
            config.enabled = true;
            config.stage = RolloutStage::Partial;
            config.rollout_bps = 5_000;
            config.max_consecutive_failures = 10; // high consecutive threshold
            config.max_error_rate_bps = 2_000;    // 20% max error rate
            config.min_sample_size = 5;           // sample size of 5
            config.auto_rollback_enabled = true;
            init_or_update_guard(&env, target, &config).unwrap();

            // 3 successes
            record_execution_outcome(&env, target, true, 0, true).unwrap();
            record_execution_outcome(&env, target, true, 0, true).unwrap();
            record_execution_outcome(&env, target, true, 0, true).unwrap();

            // 1 failure (total 4) -> under min sample size
            record_execution_outcome(&env, target, false, 501, true).unwrap();

            // 1 more failure (total 5: 2 failures / 5 = 40% > 20% limit) -> Trips Auto-Rollback!
            let status = record_execution_outcome(&env, target, false, 501, true).unwrap();
            assert_eq!(status, GuardHealthStatus::RolledBack);

            let audit = get_last_rollback_audit(&env, target).unwrap();
            assert_eq!(audit.reason, RollbackReason::ErrorRateBreached);
        });
    }

    #[test]
    fn invariant_violation_trips_immediate_rollback() {
        let env = Env::default();
        with_storage(&env, || {
            let target = RolloutTarget::Module(RolloutModule::Treasury);
            let mut config = default_guard_config(&env);
            config.enabled = true;
            config.stage = RolloutStage::Full;
            config.rollout_bps = FULL_ROLLOUT_BPS;
            init_or_update_guard(&env, target, &config).unwrap();

            // Even on the very first execution, invariant failure triggers auto-rollback
            let status = record_execution_outcome(&env, target, true, 0, false).unwrap();
            assert_eq!(status, GuardHealthStatus::RolledBack);

            let audit = get_last_rollback_audit(&env, target).unwrap();
            assert_eq!(audit.reason, RollbackReason::InvariantViolation);
        });
    }

    #[test]
    fn automatic_rollback_verification_confirms_clean_state() {
        let env = Env::default();
        with_storage(&env, || {
            let target = RolloutTarget::Flag(FeatureFlag::TreasurySweepV2);
            let mut config = default_guard_config(&env);
            config.enabled = true;
            config.stage = RolloutStage::Canary;
            config.rollout_bps = 500;
            init_or_update_guard(&env, target, &config).unwrap();

            // Trigger rollback
            trigger_auto_rollback(&env, target, RollbackReason::ManualTrigger, 0);

            // Verify clean state
            let snapshot = ModuleConsistencySnapshot::clean(RolloutModule::Treasury);
            let receipt = verify_rollback(&env, target, &snapshot);

            assert!(receipt.verified_clean);
            assert_eq!(receipt.checks_passed, receipt.checks_evaluated);
            assert_eq!(receipt.anomaly, StateAnomalyKind::NoAnomaly);
            assert!(is_rollback_verified(&env, target));
        });
    }

    #[test]
    fn automatic_rollback_verification_detects_inconsistent_state() {
        let env = Env::default();
        with_storage(&env, || {
            let target = RolloutTarget::Module(RolloutModule::Marketplace);
            let mut config = default_guard_config(&env);
            config.enabled = true;
            config.stage = RolloutStage::Canary;
            config.rollout_bps = 500;
            init_or_update_guard(&env, target, &config).unwrap();

            trigger_auto_rollback(&env, target, RollbackReason::AnomalyDetected, 1001);

            // Dirty state snapshot: escrow mismatch
            let dirty_snapshot = ModuleConsistencySnapshot::marketplace(
                false, // reserves solvent failed!
                true,
                true,
            );

            let receipt = verify_rollback(&env, target, &dirty_snapshot);
            assert!(!receipt.verified_clean);
            assert_eq!(receipt.anomaly, StateAnomalyKind::SolvencyDiscrepancy);
            assert!(!is_rollback_verified(&env, target));
        });
    }

    #[test]
    fn unverified_rollback_cannot_be_rearmed() {
        let env = Env::default();
        with_storage(&env, || {
            let target = RolloutTarget::Flag(FeatureFlag::GovernanceVotingV2);
            let mut config = default_guard_config(&env);
            config.enabled = true;
            config.stage = RolloutStage::Canary;
            config.rollout_bps = 1_000;
            init_or_update_guard(&env, target, &config).unwrap();

            trigger_auto_rollback(&env, target, RollbackReason::ConsecutiveFailuresExceeded, 901);

            // Attempting to rearm without verification fails
            let rearm_result = rearm_after_verified_rollback(&env, target, RolloutStage::Canary, 500);
            assert_eq!(
                rearm_result,
                Err(FeatureFlagError::UnverifiedRollbackReenableForbidden)
            );

            // Verify rollback cleanly
            let clean = ModuleConsistencySnapshot::governance(true, true, true);
            let receipt = verify_rollback(&env, target, &clean);
            assert!(receipt.verified_clean);

            // Now rearming succeeds
            let rearmed = rearm_after_verified_rollback(&env, target, RolloutStage::Canary, 500).unwrap();
            assert!(rearmed.enabled);
            assert_eq!(rearmed.stage, RolloutStage::Canary);
            assert_eq!(rearmed.rollout_bps, 500);
            assert_eq!(
                evaluate_rollout_guard(&env, target, 0),
                GuardDecision::ProceedNew
            );
        });
    }

    #[test]
    fn vertical_slice_across_all_six_modules() {
        let env = Env::default();
        with_storage(&env, || {
            let modules = [
                RolloutModule::Treasury,
                RolloutModule::Aid,
                RolloutModule::Referral,
                RolloutModule::Governance,
                RolloutModule::Oracle,
                RolloutModule::Marketplace,
            ];

            for module in modules.iter() {
                let target = RolloutTarget::Module(*module);

                // 1. Initial configuration
                let mut config = default_guard_config(&env);
                config.enabled = true;
                config.stage = RolloutStage::Canary;
                config.rollout_bps = 1_000;
                config.max_consecutive_failures = 2;
                init_or_update_guard(&env, target, &config).unwrap();

                // 2. Telemetry execution
                record_execution_outcome(&env, target, true, 0, true).unwrap();
                let status = record_execution_outcome(&env, target, false, 999, false).unwrap();
                assert_eq!(status, GuardHealthStatus::RolledBack);

                // 3. Fallback verified
                assert_eq!(
                    evaluate_rollout_guard(&env, target, 0),
                    GuardDecision::FallbackLegacy
                );

                // 4. Verification executed
                let clean = ModuleConsistencySnapshot::clean(*module);
                let receipt = verify_rollback(&env, target, &clean);
                assert!(receipt.verified_clean);
                assert!(is_rollback_verified(&env, target));
            }
        });
    }
}
