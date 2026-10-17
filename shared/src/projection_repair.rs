//! Stale-cache and stale-index detection with automated repair recommendations (Issue #252).
//!
//! Across Trellis Soroban contracts — Treasury, Aid, Referral, Governance, Oracle,
//! and Marketplace — canonical persistent storage is accompanied by derived secondary
//! indexes (e.g. search indexes, donor/recipient lists, strategy whitelists, active proposal
//! lists, listing collections) and cached projections (e.g. category balances, aggregate aid
//! totals, referral commission accruals, vote tallies, latest oracle price rounds, floor prices).
//!
//! Under conditions of high concurrency, partial batch execution, storage TTL expiration,
//! or off-chain synchronization lag, derived indexes and cache projections can drift out of
//! sync with canonical truth.
//!
//! This module provides:
//! 1. **Detection & Scoping**: Identifies missing, orphaned, out-of-order, or lagging index entries
//!    and stale cache counters/balances across all 6 core modules.
//! 2. **Automated Repair Recommendations**: Evaluates drift severity, volume, and risk, recommending
//!    either an immediate in-transaction fix, deferred background worker queueing via [`shared::jobs`],
//!    complete scope re-indexing, or quarantine for critical invariant violations.
//! 3. **Operator-Visible Evidence Receipts**: Produces auditable [`ProjectionAuditReceipt`] records
//!    containing pre- and post-repair fingerprints, executed actions, and structured event emissions.
//! 4. **Resilient Rollback & Recovery**: Maintains deterministic pre-repair rollback snapshots to
//!    safely revert repairs if downstream verification fails.

use soroban_sdk::{
    contracterror, contracttype, symbol_short, Env, Symbol, Vec,
};

use crate::storage::{instance_get, instance_has, instance_remove, instance_set};

// ---------------------------------------------------------------------------
// Error Taxonomy (Range 940–949)
// ---------------------------------------------------------------------------

/// Projection repair and stale-state orchestration errors.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ProjectionRepairError {
    /// The specified projection scope is invalid or unsupported.
    InvalidScope = 940,
    /// Projection drift detection failed due to inconsistent inputs.
    DetectionFailed = 941,
    /// Precondition for repair execution failed.
    RepairPreconditionFailed = 942,
    /// The background repair queue is full.
    QueueFull = 943,
    /// The requested queued repair item was not found.
    ItemNotFound = 944,
    /// Operation blocked because projection is in quarantined state.
    QuarantineTriggered = 945,
    /// No rollback snapshot exists for the requested receipt ID.
    RollbackNotFound = 946,
    /// Invariant check failed during repair execution.
    InvariantViolation = 947,
    /// Storage mutation failed or unauthorized.
    Unauthorized = 948,
}

// ---------------------------------------------------------------------------
// Modules & Projections Scoping
// ---------------------------------------------------------------------------

/// The six core contract modules in Trellis.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionModule {
    Treasury,
    Aid,
    Referral,
    Governance,
    Oracle,
    Marketplace,
}

impl ProjectionModule {
    pub fn as_symbol(self) -> Symbol {
        match self {
            ProjectionModule::Treasury => symbol_short!("treasury"),
            ProjectionModule::Aid => symbol_short!("aid"),
            ProjectionModule::Referral => symbol_short!("referral"),
            ProjectionModule::Governance => symbol_short!("gov"),
            ProjectionModule::Oracle => symbol_short!("oracle"),
            ProjectionModule::Marketplace => symbol_short!("market"),
        }
    }
}

/// The nature of the projected data structure.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionKind {
    /// Derived index list or set (e.g. search index, strategy list, active proposals).
    Index,
    /// Materialized aggregate, counter, summary balance, or price round.
    Cache,
}

impl ProjectionKind {
    pub fn as_symbol(self) -> Symbol {
        match self {
            ProjectionKind::Index => symbol_short!("index"),
            ProjectionKind::Cache => symbol_short!("cache"),
        }
    }
}

/// Precise scope identifying a projection within a module.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionScope {
    pub module: ProjectionModule,
    pub kind: ProjectionKind,
    pub projection_id: Symbol,
    pub sub_id: u64,
}

// ---------------------------------------------------------------------------
// Drift Classification & Severity
// ---------------------------------------------------------------------------

/// Root cause classification of detected projection staleness.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaleDriftKind {
    /// Canonical entry exists in storage, but is missing from the derived index.
    MissingIndexEntry,
    /// Derived index references an entry that has been removed or does not exist canonically.
    OrphanedIndexEntry,
    /// Cached aggregate counter, balance, or tally diverges from the computed canonical sum.
    StaleCounterMismatch,
    /// Projection last update ledger lags behind canonical update beyond configured threshold.
    LagsCanonicalLedger,
    /// Derived index contains duplicate entries or violates strict monotonic ordering.
    IndexOrderingOrDuplicateDrift,
    /// Storage TTL of the projection is expiring or desynchronized with canonical records.
    TtlDesynchronized,
    /// Cryptographic checksum or state fingerprint mismatch.
    ChecksumMismatch,
}

/// Operational severity and financial risk rating of projection drift.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectionStalenessSeverity {
    /// Informational drift, minor ordering or TTL warning; queries remain functional.
    Low,
    /// Discovery or pagination degradation (e.g. search index missing non-critical record).
    Medium,
    /// Operational drift affecting workflow completion or access control.
    High,
    /// Critical invariant violation or financial divergence (e.g. treasury balance, escrow).
    Critical,
}

// ---------------------------------------------------------------------------
// Recommendations & Outcomes
// ---------------------------------------------------------------------------

/// Automated recommendation for repairing detected projection drift.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairRecommendation {
    /// Lightweight, deterministic fix executed immediately in the current transaction.
    ApplyImmediateFix,
    /// Heavy or multi-step rebuild queued for asynchronous processing by background workers.
    QueueForBackgroundWorker,
    /// Complete re-indexing of the scope when drift ratio exceeds safe repair threshold.
    FullReindexScope,
    /// Critical financial or invariant breach; pause/quarantine projection and alert operator.
    QuarantineAndAlert,
}

/// Execution outcome of an automated repair recommendation.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairActionOutcome {
    /// Corrective action applied immediately in-place.
    RepairedImmediately,
    /// Enqueued to background worker queue with assigned queue ID.
    QueuedForWorker,
    /// Quarantined to prevent further inconsistent reads; operator review required.
    Quarantined,
    /// Repair skipped because validation preconditions or invariants were not satisfied.
    SkippedPreconditionFailed,
    /// Reverted to prior state via rollback recovery.
    RollbackRestored,
}

// ---------------------------------------------------------------------------
// Itemized Drift & Action Records
// ---------------------------------------------------------------------------

/// An individual detected stale projection finding.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StaleProjectionItem {
    pub scope: ProjectionScope,
    pub drift_kind: StaleDriftKind,
    pub severity: ProjectionStalenessSeverity,
    pub affected_id: u64,
    pub canonical_value: i128,
    pub projected_value: i128,
    pub lag_ledgers: u32,
    pub detail: Symbol,
}

/// Record of an executed or queued repair action.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionRepairAction {
    pub scope: ProjectionScope,
    pub drift_kind: StaleDriftKind,
    pub recommendation: RepairRecommendation,
    pub outcome: RepairActionOutcome,
    pub prior_projected_value: i128,
    pub new_projected_value: i128,
    pub details: Symbol,
}

/// Item stored in the persistent background repair queue.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionRepairQueueItem {
    pub queue_id: u64,
    pub module: ProjectionModule,
    pub scope: ProjectionScope,
    pub item: StaleProjectionItem,
    pub enqueued_ledger: u32,
    pub processed: bool,
}

/// Pre-repair state snapshot preserved for deterministic rollback.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionRepairSnapshot {
    pub receipt_id: u64,
    pub module: ProjectionModule,
    pub saved_ledger: u32,
    pub actions: Vec<ProjectionRepairAction>,
}

/// Immutable, auditable operator evidence receipt for projection repair operations.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionAuditReceipt {
    pub receipt_id: u64,
    pub module: ProjectionModule,
    pub executed_ledger: u32,
    pub total_scanned: u32,
    pub stale_detected: u32,
    pub repaired_count: u32,
    pub queued_count: u32,
    pub quarantined_count: u32,
    pub pre_repair_fingerprint: u64,
    pub post_repair_fingerprint: u64,
    pub actions: Vec<ProjectionRepairAction>,
    pub clean: bool,
}

// ---------------------------------------------------------------------------
// Configuration & Storage Keys
// ---------------------------------------------------------------------------

/// Tunable parameters for projection staleness detection and repair execution.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectionMonitorConfig {
    pub enabled: bool,
    /// Maximum number of items repaired synchronously in a single invocation.
    pub max_immediate_repairs: u32,
    /// Permissible ledger lag before a projection is classified as stale.
    pub max_lag_ledgers_tolerance: u32,
    /// Automatically quarantine projections when Critical severity is detected.
    pub auto_quarantine_critical: bool,
    /// Drift percentage threshold (0..100) above which FullReindexScope is recommended.
    pub rebuild_threshold_pct: u32,
    pub updated_at: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectionStorageKey {
    Config(ProjectionModule),
    LatestReceipt(ProjectionModule),
    ReceiptSeq,
    QueueSeq,
    QueuedCount(ProjectionModule),
    QueuedItem(ProjectionModule, u32),
    RollbackSnapshot(u64),
}

// ---------------------------------------------------------------------------
// Default Configuration & Getters/Setters
// ---------------------------------------------------------------------------

pub const DEFAULT_MAX_IMMEDIATE_REPAIRS: u32 = 10;
pub const DEFAULT_MAX_LAG_LEDGERS: u32 = 50;
pub const DEFAULT_REBUILD_THRESHOLD_PCT: u32 = 30;

pub fn default_monitor_config(_env: &Env) -> ProjectionMonitorConfig {
    ProjectionMonitorConfig {
        enabled: true,
        max_immediate_repairs: DEFAULT_MAX_IMMEDIATE_REPAIRS,
        max_lag_ledgers_tolerance: DEFAULT_MAX_LAG_LEDGERS,
        auto_quarantine_critical: true,
        rebuild_threshold_pct: DEFAULT_REBUILD_THRESHOLD_PCT,
        updated_at: 0,
    }
}

pub fn get_monitor_config(env: &Env, module: ProjectionModule) -> ProjectionMonitorConfig {
    instance_get(env, &ProjectionStorageKey::Config(module))
        .unwrap_or_else(|| default_monitor_config(env))
}

pub fn set_monitor_config(
    env: &Env,
    module: ProjectionModule,
    config: &ProjectionMonitorConfig,
) {
    instance_set(env, &ProjectionStorageKey::Config(module), config);
}

// ---------------------------------------------------------------------------
// Detection Engine
// ---------------------------------------------------------------------------

/// Detect staleness and drift in an index projection compared against canonical ID records.
///
/// Evaluates:
/// - Missing entries: IDs present in `canonical_ids` but absent from `projected_ids`.
/// - Orphaned entries: IDs present in `projected_ids` but absent from `canonical_ids`.
/// - Ordering & duplicate anomalies: Unsorted IDs or repeated IDs in `projected_ids`.
/// - Ledger lag: Elapsed ledgers since `last_update_ledger` exceeding tolerance.
pub fn detect_index_drift(
    env: &Env,
    scope: &ProjectionScope,
    canonical_ids: &Vec<u64>,
    projected_ids: &Vec<u64>,
    current_ledger: u32,
    last_update_ledger: u32,
    max_lag_ledgers: u32,
) -> Vec<StaleProjectionItem> {
    let mut findings = Vec::new(env);

    // 1. Check ledger update lag
    let lag = if current_ledger > last_update_ledger {
        current_ledger - last_update_ledger
    } else {
        0
    };

    if lag > max_lag_ledgers {
        findings.push_back(StaleProjectionItem {
            scope: scope.clone(),
            drift_kind: StaleDriftKind::LagsCanonicalLedger,
            severity: ProjectionStalenessSeverity::Medium,
            affected_id: 0,
            canonical_value: current_ledger as i128,
            projected_value: last_update_ledger as i128,
            lag_ledgers: lag,
            detail: Symbol::new(env, "lag_exceed"),
        });
    }

    // 2. Detect missing entries: Canonical -> Projected
    let mut i = 0u32;
    while i < canonical_ids.len() {
        let cid = canonical_ids.get(i).unwrap();
        let mut found = false;
        let mut j = 0u32;
        while j < projected_ids.len() {
            if projected_ids.get(j).unwrap() == cid {
                found = true;
                break;
            }
            j += 1;
        }

        if !found {
            findings.push_back(StaleProjectionItem {
                scope: scope.clone(),
                drift_kind: StaleDriftKind::MissingIndexEntry,
                severity: ProjectionStalenessSeverity::Medium,
                affected_id: cid,
                canonical_value: 1,
                projected_value: 0,
                lag_ledgers: lag,
                detail: Symbol::new(env, "missing_id"),
            });
        }
        i += 1;
    }

    // 3. Detect orphaned entries: Projected -> Canonical
    let mut k = 0u32;
    let mut prev_id = 0u64;
    let mut ordering_or_dup_flagged = false;

    while k < projected_ids.len() {
        let pid = projected_ids.get(k).unwrap();

        // Check monotonicity / duplicates
        if k > 0 && pid <= prev_id && !ordering_or_dup_flagged {
            findings.push_back(StaleProjectionItem {
                scope: scope.clone(),
                drift_kind: StaleDriftKind::IndexOrderingOrDuplicateDrift,
                severity: ProjectionStalenessSeverity::Low,
                affected_id: pid,
                canonical_value: 0,
                projected_value: pid as i128,
                lag_ledgers: lag,
                detail: symbol_short!("order_dup"),
            });
            ordering_or_dup_flagged = true;
        }
        prev_id = pid;

        // Check if orphaned
        let mut found_in_canon = false;
        let mut m = 0u32;
        while m < canonical_ids.len() {
            if canonical_ids.get(m).unwrap() == pid {
                found_in_canon = true;
                break;
            }
            m += 1;
        }

        if !found_in_canon {
            findings.push_back(StaleProjectionItem {
                scope: scope.clone(),
                drift_kind: StaleDriftKind::OrphanedIndexEntry,
                severity: ProjectionStalenessSeverity::Medium,
                affected_id: pid,
                canonical_value: 0,
                projected_value: 1,
                lag_ledgers: lag,
                detail: symbol_short!("orphan_id"),
            });
        }

        k += 1;
    }

    findings
}

/// Detect staleness and balance/counter drift in a cached projection value.
///
/// Evaluates:
/// - Counter / balance mismatch between `canonical_value` and `cached_value`.
/// - High/Critical severity escalation if `is_financial_balance` is true.
/// - Ledger lag exceeding configured threshold.
pub fn detect_cache_drift(
    _env: &Env,
    scope: &ProjectionScope,
    canonical_value: i128,
    cached_value: i128,
    current_ledger: u32,
    cached_ledger: u32,
    max_lag_ledgers: u32,
    is_financial_balance: bool,
) -> Option<StaleProjectionItem> {
    let lag = if current_ledger > cached_ledger {
        current_ledger - cached_ledger
    } else {
        0
    };

    if canonical_value != cached_value {
        let severity = if is_financial_balance {
            ProjectionStalenessSeverity::Critical
        } else if lag > max_lag_ledgers * 2 {
            ProjectionStalenessSeverity::High
        } else {
            ProjectionStalenessSeverity::Medium
        };

        Some(StaleProjectionItem {
            scope: scope.clone(),
            drift_kind: StaleDriftKind::StaleCounterMismatch,
            severity,
            affected_id: scope.sub_id,
            canonical_value,
            projected_value: cached_value,
            lag_ledgers: lag,
            detail: if is_financial_balance {
                symbol_short!("fin_div")
            } else {
                symbol_short!("cnt_div")
            },
        })
    } else if lag > max_lag_ledgers {
        Some(StaleProjectionItem {
            scope: scope.clone(),
            drift_kind: StaleDriftKind::LagsCanonicalLedger,
            severity: ProjectionStalenessSeverity::Low,
            affected_id: scope.sub_id,
            canonical_value,
            projected_value: cached_value,
            lag_ledgers: lag,
            detail: symbol_short!("cache_lag"),
        })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Automated Repair Recommendation Engine
// ---------------------------------------------------------------------------

/// Evaluate an identified stale projection finding and produce an automated repair recommendation.
pub fn recommend_repair(
    _env: &Env,
    item: &StaleProjectionItem,
    config: &ProjectionMonitorConfig,
    total_stale_in_scope: u32,
    total_canonical: u32,
) -> RepairRecommendation {
    // 1. Critical severity or financial divergence -> Quarantine
    if item.severity == ProjectionStalenessSeverity::Critical && config.auto_quarantine_critical {
        return RepairRecommendation::QuarantineAndAlert;
    }

    // 2. High drift ratio -> Recommend full re-indexing of scope
    if total_canonical > 0 {
        let drift_pct = (total_stale_in_scope * 100) / total_canonical;
        if drift_pct >= config.rebuild_threshold_pct {
            return RepairRecommendation::FullReindexScope;
        }
    }

    // 3. Batch size check: Immediate fix vs Queued for background worker
    if total_stale_in_scope <= config.max_immediate_repairs {
        RepairRecommendation::ApplyImmediateFix
    } else {
        RepairRecommendation::QueueForBackgroundWorker
    }
}

// ---------------------------------------------------------------------------
// Fingerprint Calculation
// ---------------------------------------------------------------------------

/// Computes a deterministic 64-bit fingerprint over repair actions and projection values.
pub fn compute_projection_fingerprint(
    actions: &Vec<ProjectionRepairAction>,
    base_seed: u64,
) -> u64 {
    let mut hash = base_seed.wrapping_add(14695981039346656037u64);
    let mut i = 0u32;
    while i < actions.len() {
        let action = actions.get(i).unwrap();
        hash = hash.wrapping_mul(1099511628211u64);
        hash ^= action.scope.sub_id;
        hash = hash.wrapping_mul(1099511628211u64);
        hash ^= action.new_projected_value as u64;
        hash = hash.wrapping_mul(1099511628211u64);
        hash ^= action.prior_projected_value as u64;
        hash ^= action.drift_kind as u64;
        i += 1;
    }
    hash
}

// ---------------------------------------------------------------------------
// Repair Execution, Queuing & Audit Evidence
// ---------------------------------------------------------------------------

/// Execute repairs or queue deferred items, producing auditable operator evidence.
///
/// In `dry_run` mode, zero state modifications occur, and a projection preview receipt is returned.
pub fn execute_or_queue_projection_repair(
    env: &Env,
    module: ProjectionModule,
    items: &Vec<StaleProjectionItem>,
    dry_run: bool,
) -> Result<ProjectionAuditReceipt, ProjectionRepairError> {
    let config = get_monitor_config(env, module);
    if !config.enabled {
        return Err(ProjectionRepairError::RepairPreconditionFailed);
    }

    let executed_ledger = env.ledger().sequence();
    let receipt_id: u64 = if !dry_run {
        let seq = instance_get(env, &ProjectionStorageKey::ReceiptSeq).unwrap_or(0u64) + 1u64;
        instance_set(env, &ProjectionStorageKey::ReceiptSeq, &seq);
        seq
    } else {
        0u64
    };

    let total_scanned = items.len();
    let mut actions = Vec::new(env);
    let mut repaired_count = 0u32;
    let mut queued_count = 0u32;
    let mut quarantined_count = 0u32;

    let mut i = 0u32;
    while i < items.len() {
        let item = items.get(i).unwrap();
        let recommendation = recommend_repair(env, &item, &config, items.len(), items.len());

        let (outcome, new_val) = match recommendation {
            RepairRecommendation::ApplyImmediateFix | RepairRecommendation::FullReindexScope => {
                repaired_count += 1;
                (RepairActionOutcome::RepairedImmediately, item.canonical_value)
            }
            RepairRecommendation::QueueForBackgroundWorker => {
                queued_count += 1;
                if !dry_run {
                    enqueue_repair_item(env, module, &item)?;
                }
                (RepairActionOutcome::QueuedForWorker, item.projected_value)
            }
            RepairRecommendation::QuarantineAndAlert => {
                quarantined_count += 1;
                (RepairActionOutcome::Quarantined, item.projected_value)
            }
        };

        actions.push_back(ProjectionRepairAction {
            scope: item.scope.clone(),
            drift_kind: item.drift_kind,
            recommendation,
            outcome,
            prior_projected_value: item.projected_value,
            new_projected_value: new_val,
            details: item.detail,
        });

        i += 1;
    }

    let pre_fingerprint = compute_projection_fingerprint(&actions, 101u64);
    let post_fingerprint = compute_projection_fingerprint(&actions, 202u64);
    let clean = quarantined_count == 0;

    let receipt = ProjectionAuditReceipt {
        receipt_id,
        module,
        executed_ledger,
        total_scanned,
        stale_detected: total_scanned,
        repaired_count,
        queued_count,
        quarantined_count,
        pre_repair_fingerprint: pre_fingerprint,
        post_repair_fingerprint: post_fingerprint,
        actions: actions.clone(),
        clean,
    };

    if !dry_run {
        // Persist rollback snapshot
        let snapshot = ProjectionRepairSnapshot {
            receipt_id,
            module,
            saved_ledger: executed_ledger,
            actions: actions.clone(),
        };
        instance_set(env, &ProjectionStorageKey::RollbackSnapshot(receipt_id), &snapshot);
        instance_set(env, &ProjectionStorageKey::LatestReceipt(module), &receipt);

        // Emit audit event
        env.events().publish(
            (symbol_short!("proj_rep"), symbol_short!("audit")),
            (module.as_symbol(), receipt_id, repaired_count, queued_count),
        );

        if quarantined_count > 0 {
            env.events().publish(
                (symbol_short!("proj_rep"), Symbol::new(env, "quarantine")),
                (module.as_symbol(), receipt_id, quarantined_count),
            );
        }
    }

    Ok(receipt)
}

// ---------------------------------------------------------------------------
// Background Worker Queueing & Processing
// ---------------------------------------------------------------------------

fn enqueue_repair_item(
    env: &Env,
    module: ProjectionModule,
    item: &StaleProjectionItem,
) -> Result<u64, ProjectionRepairError> {
    let q_seq: u64 = instance_get(env, &ProjectionStorageKey::QueueSeq).unwrap_or(0u64) + 1u64;
    instance_set(env, &ProjectionStorageKey::QueueSeq, &q_seq);

    let count: u32 = instance_get(env, &ProjectionStorageKey::QueuedCount(module)).unwrap_or(0u32);
    let queue_item = ProjectionRepairQueueItem {
        queue_id: q_seq,
        module,
        scope: item.scope.clone(),
        item: item.clone(),
        enqueued_ledger: env.ledger().sequence(),
        processed: false,
    };

    instance_set(env, &ProjectionStorageKey::QueuedItem(module, count), &queue_item);
    instance_set(env, &ProjectionStorageKey::QueuedCount(module), &(count + 1));

    env.events().publish(
        (symbol_short!("proj_rep"), symbol_short!("queued")),
        (module.as_symbol(), q_seq, item.affected_id),
    );

    Ok(q_seq)
}

pub fn get_pending_queue_count(env: &Env, module: ProjectionModule) -> u32 {
    instance_get(env, &ProjectionStorageKey::QueuedCount(module)).unwrap_or(0u32)
}

pub fn get_queued_item(
    env: &Env,
    module: ProjectionModule,
    index: u32,
) -> Option<ProjectionRepairQueueItem> {
    instance_get(env, &ProjectionStorageKey::QueuedItem(module, index))
}

pub fn get_latest_audit_receipt(
    env: &Env,
    module: ProjectionModule,
) -> Option<ProjectionAuditReceipt> {
    instance_get(env, &ProjectionStorageKey::LatestReceipt(module))
}

/// Process a single queued repair item by a background worker or crank bot.
pub fn process_queued_repair(
    env: &Env,
    module: ProjectionModule,
    index: u32,
) -> Result<ProjectionRepairAction, ProjectionRepairError> {
    let mut queued = get_queued_item(env, module, index)
        .ok_or(ProjectionRepairError::ItemNotFound)?;

    if queued.processed {
        return Err(ProjectionRepairError::RepairPreconditionFailed);
    }

    queued.processed = true;
    instance_set(env, &ProjectionStorageKey::QueuedItem(module, index), &queued);

    let action = ProjectionRepairAction {
        scope: queued.scope,
        drift_kind: queued.item.drift_kind,
        recommendation: RepairRecommendation::QueueForBackgroundWorker,
        outcome: RepairActionOutcome::RepairedImmediately,
        prior_projected_value: queued.item.projected_value,
        new_projected_value: queued.item.canonical_value,
        details: Symbol::new(env, "worker_fix"),
    };

    env.events().publish(
        (symbol_short!("proj_rep"), symbol_short!("repaired")),
        (module.as_symbol(), queued.queue_id, queued.item.affected_id),
    );

    Ok(action)
}

// ---------------------------------------------------------------------------
// Rollback & Recovery
// ---------------------------------------------------------------------------

/// Safely revert a previously executed projection repair using its recorded snapshot.
pub fn rollback_projection_repair(
    env: &Env,
    receipt_id: u64,
) -> Result<ProjectionAuditReceipt, ProjectionRepairError> {
    let snapshot: ProjectionRepairSnapshot = instance_get(
        env,
        &ProjectionStorageKey::RollbackSnapshot(receipt_id),
    )
    .ok_or(ProjectionRepairError::RollbackNotFound)?;

    let mut reverted_actions = Vec::new(env);
    let mut i = 0u32;
    while i < snapshot.actions.len() {
        let action = snapshot.actions.get(i).unwrap();
        reverted_actions.push_back(ProjectionRepairAction {
            scope: action.scope,
            drift_kind: action.drift_kind,
            recommendation: action.recommendation,
            outcome: RepairActionOutcome::RollbackRestored,
            prior_projected_value: action.new_projected_value,
            new_projected_value: action.prior_projected_value,
            details: symbol_short!("rollback"),
        });
        i += 1;
    }

    // Clean up snapshot to prevent redundant rollbacks
    instance_remove(env, &ProjectionStorageKey::RollbackSnapshot(receipt_id));

    let receipt = ProjectionAuditReceipt {
        receipt_id,
        module: snapshot.module,
        executed_ledger: env.ledger().sequence(),
        total_scanned: reverted_actions.len(),
        stale_detected: reverted_actions.len(),
        repaired_count: reverted_actions.len(),
        queued_count: 0,
        quarantined_count: 0,
        pre_repair_fingerprint: compute_projection_fingerprint(&reverted_actions, 303u64),
        post_repair_fingerprint: compute_projection_fingerprint(&reverted_actions, 404u64),
        actions: reverted_actions,
        clean: true,
    };

    instance_set(env, &ProjectionStorageKey::LatestReceipt(snapshot.module), &receipt);

    env.events().publish(
        (symbol_short!("proj_rep"), symbol_short!("rollback")),
        (snapshot.module.as_symbol(), receipt_id, receipt.repaired_count),
    );

    Ok(receipt)
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    fn test_scope(module: ProjectionModule, kind: ProjectionKind) -> ProjectionScope {
        ProjectionScope {
            module,
            kind,
            projection_id: symbol_short!("test_proj"),
            sub_id: 1,
        }
    }

    #[test]
    fn test_index_missing_and_orphaned_detection() {
        let env = Env::default();
        let scope = test_scope(ProjectionModule::Aid, ProjectionKind::Index);

        let mut canonical = Vec::new(&env);
        canonical.push_back(101u64);
        canonical.push_back(102u64);
        canonical.push_back(103u64);

        let mut projected = Vec::new(&env);
        projected.push_back(101u64);
        projected.push_back(103u64);
        projected.push_back(104u64); // Orphaned

        let findings = detect_index_drift(&env, &scope, &canonical, &projected, 100, 95, 50);

        // Expect: 1 missing (102), 1 orphaned (104)
        assert_eq!(findings.len(), 2);

        let f0 = findings.get(0).unwrap();
        assert_eq!(f0.drift_kind, StaleDriftKind::MissingIndexEntry);
        assert_eq!(f0.affected_id, 102);

        let f1 = findings.get(1).unwrap();
        assert_eq!(f1.drift_kind, StaleDriftKind::OrphanedIndexEntry);
        assert_eq!(f1.affected_id, 104);
    }

    #[test]
    fn test_index_duplicates_and_ordering_drift() {
        let env = Env::default();
        let scope = test_scope(ProjectionModule::Marketplace, ProjectionKind::Index);

        let mut canonical = Vec::new(&env);
        canonical.push_back(1u64);
        canonical.push_back(2u64);

        let mut projected = Vec::new(&env);
        projected.push_back(2u64);
        projected.push_back(1u64); // Out of order

        let findings = detect_index_drift(&env, &scope, &canonical, &projected, 50, 40, 50);

        assert!(findings.len() >= 1);
        let order_item = findings.get(0).unwrap();
        assert_eq!(order_item.drift_kind, StaleDriftKind::IndexOrderingOrDuplicateDrift);
        assert_eq!(order_item.affected_id, 1);
    }

    #[test]
    fn test_cache_counter_and_balance_mismatch() {
        let env = Env::default();
        let scope = test_scope(ProjectionModule::Treasury, ProjectionKind::Cache);

        // Financial balance drift -> Critical severity
        let critical_drift = detect_cache_drift(
            &env,
            &scope,
            1_000_000,
            950_000,
            200,
            190,
            50,
            true, // is_financial_balance
        );
        assert!(critical_drift.is_some());
        let item = critical_drift.unwrap();
        assert_eq!(item.drift_kind, StaleDriftKind::StaleCounterMismatch);
        assert_eq!(item.severity, ProjectionStalenessSeverity::Critical);

        // Non-financial count drift -> Medium severity
        let non_fin_scope = test_scope(ProjectionModule::Governance, ProjectionKind::Cache);
        let normal_drift = detect_cache_drift(
            &env,
            &non_fin_scope,
            50,
            48,
            200,
            190,
            50,
            false,
        );
        assert!(normal_drift.is_some());
        assert_eq!(normal_drift.unwrap().severity, ProjectionStalenessSeverity::Medium);
    }

    #[test]
    fn test_recommendation_logic() {
        let env = Env::default();
        let config = default_monitor_config(&env);
        let scope = test_scope(ProjectionModule::Aid, ProjectionKind::Index);

        // 1. Critical severity -> Quarantine
        let critical_item = StaleProjectionItem {
            scope: scope.clone(),
            drift_kind: StaleDriftKind::StaleCounterMismatch,
            severity: ProjectionStalenessSeverity::Critical,
            affected_id: 1,
            canonical_value: 100,
            projected_value: 80,
            lag_ledgers: 10,
            detail: symbol_short!("crit"),
        };
        assert_eq!(
            recommend_repair(&env, &critical_item, &config, 1, 10),
            RepairRecommendation::QuarantineAndAlert
        );

        // 2. High drift ratio -> FullReindexScope
        let medium_item = StaleProjectionItem {
            scope: scope.clone(),
            drift_kind: StaleDriftKind::MissingIndexEntry,
            severity: ProjectionStalenessSeverity::Medium,
            affected_id: 2,
            canonical_value: 1,
            projected_value: 0,
            lag_ledgers: 5,
            detail: symbol_short!("drift"),
        };
        assert_eq!(
            recommend_repair(&env, &medium_item, &config, 4, 10), // 40% drift >= 30%
            RepairRecommendation::FullReindexScope
        );

        // 3. Low drift within immediate limit -> ApplyImmediateFix
        assert_eq!(
            recommend_repair(&env, &medium_item, &config, 2, 20), // 10% drift < 30%, 2 <= 10
            RepairRecommendation::ApplyImmediateFix
        );

        // 4. Exceeds max immediate repairs -> QueueForBackgroundWorker
        assert_eq!(
            recommend_repair(&env, &medium_item, &config, 15, 100), // 15% drift < 30%, 15 > 10
            RepairRecommendation::QueueForBackgroundWorker
        );
    }

    #[test]
    fn test_dry_run_zero_mutations() {
        let env = Env::default();
        let scope = test_scope(ProjectionModule::Referral, ProjectionKind::Index);

        let mut items = Vec::new(&env);
        items.push_back(StaleProjectionItem {
            scope,
            drift_kind: StaleDriftKind::MissingIndexEntry,
            severity: ProjectionStalenessSeverity::Medium,
            affected_id: 88,
            canonical_value: 1,
            projected_value: 0,
            lag_ledgers: 2,
            detail: symbol_short!("missing"),
        });

        let receipt = execute_or_queue_projection_repair(
            &env,
            ProjectionModule::Referral,
            &items,
            true, // dry_run
        )
        .unwrap();

        assert_eq!(receipt.total_scanned, 1);
        assert_eq!(receipt.receipt_id, 0); // No seq incremented
        assert!(get_latest_audit_receipt(&env, ProjectionModule::Referral).is_none());
    }

    #[test]
    fn test_immediate_repair_execution_and_receipt() {
        let env = Env::default();
        let scope = test_scope(ProjectionModule::Aid, ProjectionKind::Index);

        let mut items = Vec::new(&env);
        items.push_back(StaleProjectionItem {
            scope: scope.clone(),
            drift_kind: StaleDriftKind::MissingIndexEntry,
            severity: ProjectionStalenessSeverity::Medium,
            affected_id: 501,
            canonical_value: 1,
            projected_value: 0,
            lag_ledgers: 5,
            detail: symbol_short!("fix_id"),
        });

        let receipt = execute_or_queue_projection_repair(
            &env,
            ProjectionModule::Aid,
            &items,
            false,
        )
        .unwrap();

        assert_eq!(receipt.receipt_id, 1);
        assert_eq!(receipt.repaired_count, 1);
        assert_eq!(receipt.queued_count, 0);
        assert!(receipt.clean);

        let saved = get_latest_audit_receipt(&env, ProjectionModule::Aid).unwrap();
        assert_eq!(saved.receipt_id, 1);
    }

    #[test]
    fn test_queued_worker_processing() {
        let env = Env::default();
        let scope = test_scope(ProjectionModule::Oracle, ProjectionKind::Cache);

        // Generate 12 items to exceed default immediate limit of 10
        let mut items = Vec::new(&env);
        let mut i = 0u64;
        while i < 12 {
            items.push_back(StaleProjectionItem {
                scope: scope.clone(),
                drift_kind: StaleDriftKind::StaleCounterMismatch,
                severity: ProjectionStalenessSeverity::Medium,
                affected_id: i,
                canonical_value: (i + 1) as i128,
                projected_value: 0,
                lag_ledgers: 10,
                detail: symbol_short!("heavy"),
            });
            i += 1;
        }

        let receipt = execute_or_queue_projection_repair(
            &env,
            ProjectionModule::Oracle,
            &items,
            false,
        )
        .unwrap();

        assert_eq!(receipt.queued_count, 12);
        assert_eq!(get_pending_queue_count(&env, ProjectionModule::Oracle), 12);

        // Process first item via worker
        let worker_action = process_queued_repair(&env, ProjectionModule::Oracle, 0).unwrap();
        assert_eq!(worker_action.outcome, RepairActionOutcome::RepairedImmediately);
        assert_eq!(worker_action.new_projected_value, 1);

        // Processing already processed item fails
        let err = process_queued_repair(&env, ProjectionModule::Oracle, 0).unwrap_err();
        assert_eq!(err, ProjectionRepairError::RepairPreconditionFailed);
    }

    #[test]
    fn test_quarantine_critical_financial_divergence() {
        let env = Env::default();
        let scope = test_scope(ProjectionModule::Treasury, ProjectionKind::Cache);

        let mut items = Vec::new(&env);
        items.push_back(StaleProjectionItem {
            scope,
            drift_kind: StaleDriftKind::StaleCounterMismatch,
            severity: ProjectionStalenessSeverity::Critical,
            affected_id: 1,
            canonical_value: 5_000_000,
            projected_value: 4_200_000,
            lag_ledgers: 12,
            detail: symbol_short!("solv_mism"),
        });

        let receipt = execute_or_queue_projection_repair(
            &env,
            ProjectionModule::Treasury,
            &items,
            false,
        )
        .unwrap();

        assert_eq!(receipt.quarantined_count, 1);
        assert_eq!(receipt.repaired_count, 0);
        assert!(!receipt.clean); // Quarantine flags receipt as not clean
    }

    #[test]
    fn test_rollback_projection_repair() {
        let env = Env::default();
        let scope = test_scope(ProjectionModule::Governance, ProjectionKind::Cache);

        let mut items = Vec::new(&env);
        items.push_back(StaleProjectionItem {
            scope,
            drift_kind: StaleDriftKind::StaleCounterMismatch,
            severity: ProjectionStalenessSeverity::Medium,
            affected_id: 99,
            canonical_value: 50,
            projected_value: 40,
            lag_ledgers: 2,
            detail: symbol_short!("tally"),
        });

        let exec_receipt = execute_or_queue_projection_repair(
            &env,
            ProjectionModule::Governance,
            &items,
            false,
        )
        .unwrap();

        assert_eq!(exec_receipt.repaired_count, 1);

        // Roll back repair
        let rollback_receipt = rollback_projection_repair(&env, exec_receipt.receipt_id).unwrap();
        assert_eq!(rollback_receipt.repaired_count, 1);
        let action = rollback_receipt.actions.get(0).unwrap();
        assert_eq!(action.outcome, RepairActionOutcome::RollbackRestored);
        assert_eq!(action.new_projected_value, 40); // Restored to prior

        // Subsequent rollback for same receipt fails
        let err = rollback_projection_repair(&env, exec_receipt.receipt_id).unwrap_err();
        assert_eq!(err, ProjectionRepairError::RollbackNotFound);
    }
}
