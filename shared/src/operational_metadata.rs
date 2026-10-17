//! Data minimization review and retention enforcement for operational metadata (Issue #229).
//!
//! Across Soroban contracts — Treasury, Aid, Referral, Governance, Oracle, and
//! Marketplace — operational metadata accumulates during execution, audits,
//! diagnostic tracing, and administrative actions.
//!
//! This module provides:
//! 1. **Data Classification**: Classifies operational metadata by module, data class,
//!    and field sensitivity (Essential, OptionalContext, Redundant, Prohibited).
//! 2. **Data Minimization Review**: Inspects raw operational metadata, stripping
//!    unnecessary redundant fields and strictly removing prohibited sensitive data
//!    before persisting.
//! 3. **Retention Enforcement**: Binds metadata to retention windows, honors active
//!    holds and frozen classes, and enforces module-specific retention policies.
//! 4. **Testable, Safe Deletion**: Two-phase cleanup (dry-run plan -> confirmed execution)
//!    with re-evaluated protection guarantees at execution time.
//! 5. **Migration Compatibility**: Adapters to review and minimize legacy operational records
//!    without breaking public APIs.

use soroban_sdk::{contracttype, symbol_short, Env, Symbol, Vec};

use crate::errors::Error;
use crate::retention::{
    days_to_ledgers, HoldReason, HOLD_INDEFINITE, LEDGERS_PER_DAY, MAX_RETAIN_LEDGERS,
};
use crate::storage::{
    instance_get, instance_set, persistent_get, persistent_has, persistent_remove, persistent_set,
};

// ---------------------------------------------------------------------------
// Modules & Classification
// ---------------------------------------------------------------------------

/// The six core contract modules generating operational metadata.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationalModule {
    Treasury,
    Aid,
    Referral,
    Governance,
    Oracle,
    Marketplace,
}

impl OperationalModule {
    pub fn as_symbol(self) -> Symbol {
        match self {
            OperationalModule::Treasury => symbol_short!("treasury"),
            OperationalModule::Aid => symbol_short!("aid"),
            OperationalModule::Referral => symbol_short!("referral"),
            OperationalModule::Governance => symbol_short!("gov"),
            OperationalModule::Oracle => symbol_short!("oracle"),
            OperationalModule::Marketplace => symbol_short!("market"),
        }
    }
}

/// Operational data classes governed by retention windows.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataClass {
    /// Privileged/administrative audit trails.
    Audit,
    /// Runtime diagnostics, metrics, and health samples.
    Telemetry,
    /// Operational execution logs and checkpoints.
    Execution,
    /// Support and verification evidence.
    SupportEvidence,
    /// Financial obligations, fee settlements, and escrow records.
    FinancialSettlement,
    /// Contested records or active disputes.
    Dispute,
}

impl MetadataClass {
    pub fn as_symbol(self) -> Symbol {
        match self {
            MetadataClass::Audit => symbol_short!("audit"),
            MetadataClass::Telemetry => symbol_short!("telemetry"),
            MetadataClass::Execution => symbol_short!("exec"),
            MetadataClass::SupportEvidence => symbol_short!("support"),
            MetadataClass::FinancialSettlement => symbol_short!("settle"),
            MetadataClass::Dispute => symbol_short!("dispute"),
        }
    }
}

/// Field classification according to data minimization principles.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldSensitivity {
    /// Crucial for state verification, cryptographic proof, or invariant checking.
    Essential,
    /// Useful operational context that is non-redundant and non-sensitive.
    OptionalContext,
    /// Duplicated or superfluous information that must be pruned.
    Redundant,
    /// Sensitive PII, secrets, or unbounded stack traces that must be rejected/purged.
    Prohibited,
}

// ---------------------------------------------------------------------------
// Records & Field Structures
// ---------------------------------------------------------------------------

/// A candidate metadata field prior to minimization review.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawMetadataField {
    pub key: Symbol,
    pub value: Symbol,
    pub sensitivity: FieldSensitivity,
}

/// A sanitized, minimized metadata key-value field approved for persistence.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinimizedField {
    pub key: Symbol,
    pub value: Symbol,
}

/// Report summarizing the data minimization review.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MinimizationReviewResult {
    pub module: OperationalModule,
    pub class: MetadataClass,
    pub original_field_count: u32,
    pub minimized_field_count: u32,
    pub stripped_fields: Vec<Symbol>,
    pub passed: bool,
}

/// Minimized operational metadata record stored persistently on-chain.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredOperationalMetadata {
    pub id: Symbol,
    pub module: OperationalModule,
    pub class: MetadataClass,
    pub created_ledger: u32,
    pub expires_ledger: u32,
    pub fields: Vec<MinimizedField>,
    pub footprint_bytes: u32,
    pub is_held: bool,
    pub is_frozen: bool,
}

/// Operational hold preventing premature deletion of metadata.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalHold {
    pub id: Symbol,
    pub reason: HoldReason,
    pub placed_ledger: u32,
    pub until_ledger: u32,
}

/// Retention policy for operational metadata.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalRetentionPolicy {
    pub retain_ledgers: u32,
    pub honor_holds: bool,
    pub deletion_frozen: bool,
}

impl OperationalRetentionPolicy {
    pub fn validate(&self) -> Result<(), Error> {
        if self.retain_ledgers == 0 || self.retain_ledgers > MAX_RETAIN_LEDGERS {
            return Err(Error::ConfigInvalid);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Storage Keys
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum OpMetaStorageKey {
    Record(Symbol),
    Hold(Symbol),
    Policy(OperationalModule, MetadataClass),
}

// ---------------------------------------------------------------------------
// Data Minimization Review Engine
// ---------------------------------------------------------------------------

/// Classifies an operational field key based on module context and known taxonomy.
pub fn classify_field(module: OperationalModule, key: &Symbol) -> FieldSensitivity {
    // Globally prohibited fields: credentials, PII, raw secrets, stack traces
    if key == &symbol_short!("priv_key")
        || key == &symbol_short!("secret")
        || key == &symbol_short!("token_sec")
        || key == &symbol_short!("api_token")
        || key == &symbol_short!("user_pii")
        || key == &symbol_short!("ip_addr")
        || key == &symbol_short!("raw_memo")
        || key == &symbol_short!("card_no")
        || key == &symbol_short!("email")
        || key == &symbol_short!("phone")
        || key == &symbol_short!("dbg_trace")
    {
        return FieldSensitivity::Prohibited;
    }

    // Globally redundant fields: duplicate wall-clock time, duplicate client info
    if key == &symbol_short!("wall_time")
        || key == &symbol_short!("client_ts")
        || key == &symbol_short!("ui_theme")
        || key == &symbol_short!("cli_ver")
        || key == &symbol_short!("peer_list")
        || key == &symbol_short!("dup_tag")
    {
        return FieldSensitivity::Redundant;
    }

    // Module-specific field classification
    match module {
        OperationalModule::Treasury => {
            if key == &symbol_short!("actor")
                || key == &symbol_short!("action")
                || key == &symbol_short!("token")
                || key == &symbol_short!("amount")
                || key == &symbol_short!("category")
                || key == &symbol_short!("seq")
            {
                FieldSensitivity::Essential
            } else if key == &symbol_short!("tok_name") || key == &symbol_short!("memo_str") {
                FieldSensitivity::Redundant
            } else {
                FieldSensitivity::OptionalContext
            }
        }
        OperationalModule::Aid => {
            if key == &symbol_short!("aid_id")
                || key == &symbol_short!("donor")
                || key == &symbol_short!("claimant")
                || key == &symbol_short!("amount")
                || key == &symbol_short!("status")
            {
                FieldSensitivity::Essential
            } else if key == &symbol_short!("disp_name") || key == &symbol_short!("org_title") {
                FieldSensitivity::Redundant
            } else if key == &symbol_short!("biometric") || key == &symbol_short!("gps_loc") {
                FieldSensitivity::Prohibited
            } else {
                FieldSensitivity::OptionalContext
            }
        }
        OperationalModule::Referral => {
            if key == &symbol_short!("ref_code")
                || key == &symbol_short!("referrer")
                || key == &symbol_short!("referee")
                || key == &symbol_short!("tier")
                || key == &symbol_short!("commiss")
            {
                FieldSensitivity::Essential
            } else if key == &symbol_short!("campaign") || key == &symbol_short!("van_dup") {
                FieldSensitivity::Redundant
            } else {
                FieldSensitivity::OptionalContext
            }
        }
        OperationalModule::Governance => {
            if key == &symbol_short!("prop_id")
                || key == &symbol_short!("action")
                || key == &symbol_short!("proposer")
                || key == &symbol_short!("approver")
                || key == &symbol_short!("quorum")
            {
                FieldSensitivity::Essential
            } else if key == &symbol_short!("prose_dsc") || key == &symbol_short!("client_id") {
                FieldSensitivity::Redundant
            } else if key == &symbol_short!("ballot_sc") {
                FieldSensitivity::Prohibited
            } else {
                FieldSensitivity::OptionalContext
            }
        }
        OperationalModule::Oracle => {
            if key == &symbol_short!("feed_id")
                || key == &symbol_short!("submitter")
                || key == &symbol_short!("price")
                || key == &symbol_short!("round")
                || key == &symbol_short!("tx_hash")
            {
                FieldSensitivity::Essential
            } else if key == &symbol_short!("prov_tag") || key == &symbol_short!("raw_resp") {
                FieldSensitivity::Redundant
            } else {
                FieldSensitivity::OptionalContext
            }
        }
        OperationalModule::Marketplace => {
            if key == &symbol_short!("item_id")
                || key == &symbol_short!("seller")
                || key == &symbol_short!("bidder")
                || key == &symbol_short!("price")
                || key == &symbol_short!("royalty")
            {
                FieldSensitivity::Essential
            } else if key == &symbol_short!("item_desc") || key == &symbol_short!("view_mode") {
                FieldSensitivity::Redundant
            } else {
                FieldSensitivity::OptionalContext
            }
        }
    }
}

/// Performs data minimization review: strips redundant and prohibited fields,
/// preserving only essential and safe optional operational context.
pub fn review_and_minimize(
    env: &Env,
    id: &Symbol,
    module: OperationalModule,
    class: MetadataClass,
    raw_fields: &Vec<RawMetadataField>,
    created_ledger: u32,
) -> Result<(MinimizationReviewResult, StoredOperationalMetadata), Error> {
    if created_ledger == 0 {
        return Err(Error::InvalidArgument);
    }

    let policy = get_effective_operational_policy(env, module, class);
    let expires_ledger = created_ledger.saturating_add(policy.retain_ledgers);

    let mut stripped_fields = Vec::new(env);
    let mut minimized_fields = Vec::new(env);
    let mut footprint_bytes: u32 = 48; // Base record metadata overhead

    let original_count = raw_fields.len();
    for i in 0..original_count {
        let Some(field) = raw_fields.get(i) else {
            continue;
        };

        // Determine effective sensitivity: prohibited always takes precedence
        let sensitivity = match field.sensitivity {
            FieldSensitivity::Prohibited => FieldSensitivity::Prohibited,
            FieldSensitivity::Redundant => FieldSensitivity::Redundant,
            FieldSensitivity::Essential => {
                if classify_field(module, &field.key) == FieldSensitivity::Prohibited {
                    FieldSensitivity::Prohibited
                } else {
                    FieldSensitivity::Essential
                }
            }
            FieldSensitivity::OptionalContext => classify_field(module, &field.key),
        };

        match sensitivity {
            FieldSensitivity::Prohibited | FieldSensitivity::Redundant => {
                stripped_fields.push_back(field.key.clone());
            }
            FieldSensitivity::Essential | FieldSensitivity::OptionalContext => {
                minimized_fields.push_back(MinimizedField {
                    key: field.key.clone(),
                    value: field.value.clone(),
                });
                footprint_bytes = footprint_bytes.saturating_add(24);
            }
        }
    }

    let minimized_count = minimized_fields.len();
    let review_result = MinimizationReviewResult {
        module,
        class,
        original_field_count: original_count,
        minimized_field_count: minimized_count,
        stripped_fields,
        passed: true,
    };

    let stored_record = StoredOperationalMetadata {
        id: id.clone(),
        module,
        class,
        created_ledger,
        expires_ledger,
        fields: minimized_fields,
        footprint_bytes,
        is_held: false,
        is_frozen: policy.deletion_frozen,
    };

    Ok((review_result, stored_record))
}

// ---------------------------------------------------------------------------
// Retention Policies & Windows
// ---------------------------------------------------------------------------

/// Returns the compile-time default retention policy for a module and class.
pub fn default_operational_policy(
    module: OperationalModule,
    class: MetadataClass,
) -> OperationalRetentionPolicy {
    match class {
        MetadataClass::Audit => OperationalRetentionPolicy {
            retain_ledgers: days_to_ledgers(365),
            honor_holds: true,
            deletion_frozen: false,
        },
        MetadataClass::Telemetry => {
            let days = match module {
                OperationalModule::Oracle => 14,
                _ => 30,
            };
            OperationalRetentionPolicy {
                retain_ledgers: days_to_ledgers(days),
                honor_holds: true,
                deletion_frozen: false,
            }
        }
        MetadataClass::Execution => OperationalRetentionPolicy {
            retain_ledgers: days_to_ledgers(90),
            honor_holds: true,
            deletion_frozen: false,
        },
        MetadataClass::SupportEvidence => OperationalRetentionPolicy {
            retain_ledgers: days_to_ledgers(180),
            honor_holds: true,
            deletion_frozen: false,
        },
        MetadataClass::FinancialSettlement => OperationalRetentionPolicy {
            retain_ledgers: days_to_ledgers(2_555), // ~7 years
            honor_holds: true,
            deletion_frozen: true,
        },
        MetadataClass::Dispute => OperationalRetentionPolicy {
            retain_ledgers: days_to_ledgers(365),
            honor_holds: true,
            deletion_frozen: true,
        },
    }
}

/// Stores an administrative retention policy override for a module and class.
pub fn set_operational_retention_policy(
    env: &Env,
    module: OperationalModule,
    class: MetadataClass,
    policy: &OperationalRetentionPolicy,
) -> Result<(), Error> {
    policy.validate()?;
    instance_set(env, &OpMetaStorageKey::Policy(module, class), policy);
    Ok(())
}

/// Retrieves stored retention policy override if configured.
pub fn get_operational_retention_policy(
    env: &Env,
    module: OperationalModule,
    class: MetadataClass,
) -> Option<OperationalRetentionPolicy> {
    instance_get(env, &OpMetaStorageKey::Policy(module, class))
}

/// Retrieves the effective retention policy (stored override or compile-time default).
pub fn get_effective_operational_policy(
    env: &Env,
    module: OperationalModule,
    class: MetadataClass,
) -> OperationalRetentionPolicy {
    get_operational_retention_policy(env, module, class)
        .unwrap_or_else(|| default_operational_policy(module, class))
}

// ---------------------------------------------------------------------------
// Storage & Hold Management
// ---------------------------------------------------------------------------

/// Persists a minimized operational metadata record into storage.
pub fn store_operational_metadata(
    env: &Env,
    record: &StoredOperationalMetadata,
) -> Result<(), Error> {
    if record.created_ledger == 0 {
        return Err(Error::InvalidArgument);
    }
    persistent_set(env, &OpMetaStorageKey::Record(record.id.clone()), record);
    Ok(())
}

/// Loads a stored operational metadata record by ID.
pub fn get_operational_metadata(
    env: &Env,
    id: &Symbol,
) -> Option<StoredOperationalMetadata> {
    persistent_get(env, &OpMetaStorageKey::Record(id.clone()))
}

/// Checks if an operational metadata record exists in storage.
pub fn has_operational_metadata(env: &Env, id: &Symbol) -> bool {
    persistent_has(env, &OpMetaStorageKey::Record(id.clone()))
}

/// Places a retention hold on an operational metadata record.
pub fn place_operational_hold(
    env: &Env,
    id: &Symbol,
    reason: HoldReason,
    until_ledger: u32,
) -> Result<OperationalHold, Error> {
    let now = env.ledger().sequence();
    if until_ledger != HOLD_INDEFINITE && until_ledger <= now {
        return Err(Error::ConfigInvalid);
    }
    let hold = OperationalHold {
        id: id.clone(),
        reason,
        placed_ledger: now,
        until_ledger,
    };
    persistent_set(env, &OpMetaStorageKey::Hold(id.clone()), &hold);

    if let Some(mut rec) = get_operational_metadata(env, id) {
        rec.is_held = true;
        persistent_set(env, &OpMetaStorageKey::Record(id.clone()), &rec);
    }

    Ok(hold)
}

/// Releases a retention hold.
pub fn release_operational_hold(env: &Env, id: &Symbol) -> Result<(), Error> {
    if !persistent_has(env, &OpMetaStorageKey::Hold(id.clone())) {
        return Err(Error::NotFound);
    }
    persistent_remove(env, &OpMetaStorageKey::Hold(id.clone()));

    if let Some(mut rec) = get_operational_metadata(env, id) {
        rec.is_held = false;
        persistent_set(env, &OpMetaStorageKey::Record(id.clone()), &rec);
    }

    Ok(())
}

/// Retrieves the stored hold for a record.
pub fn get_operational_hold(env: &Env, id: &Symbol) -> Option<OperationalHold> {
    persistent_get(env, &OpMetaStorageKey::Hold(id.clone()))
}

/// Returns the active hold protecting a record at `now_ledger`, if valid.
pub fn active_operational_hold(
    env: &Env,
    id: &Symbol,
    now_ledger: u32,
) -> Option<OperationalHold> {
    match get_operational_hold(env, id) {
        Some(hold) if hold.until_ledger == HOLD_INDEFINITE || hold.until_ledger > now_ledger => {
            Some(hold)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Two-Phase Cleanup Planning & Execution
// ---------------------------------------------------------------------------

/// Non-destructive plan describing the outcome of a cleanup run.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalCleanupPlan {
    pub dry_run: bool,
    pub evaluated_ledger: u32,
    pub eligible: Vec<Symbol>,
    pub protected_held: Vec<Symbol>,
    pub protected_frozen: Vec<Symbol>,
    pub retained_active: Vec<Symbol>,
    pub bytes_reclaimable: u32,
    pub bytes_protected: u32,
}

/// Execution report of an applied cleanup operation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationalCleanupReport {
    pub evaluated_ledger: u32,
    pub deleted: Vec<Symbol>,
    pub skipped_protected: Vec<Symbol>,
    pub bytes_reclaimed: u32,
    pub destructive: bool,
}

/// Generates a cleanup plan evaluated at an explicit ledger sequence.
pub fn plan_operational_cleanup_at(
    env: &Env,
    records: &Vec<StoredOperationalMetadata>,
    evaluated_ledger: u32,
) -> OperationalCleanupPlan {
    let mut eligible = Vec::new(env);
    let mut protected_held = Vec::new(env);
    let mut protected_frozen = Vec::new(env);
    let mut retained_active = Vec::new(env);
    let mut bytes_reclaimable: u32 = 0;
    let mut bytes_protected: u32 = 0;

    for i in 0..records.len() {
        let Some(rec) = records.get(i) else {
            continue;
        };
        let policy = get_effective_operational_policy(env, rec.module, rec.class);

        // Deletion frozen classes cannot be deleted
        if policy.deletion_frozen || rec.is_frozen {
            protected_frozen.push_back(rec.id.clone());
            bytes_protected = bytes_protected.saturating_add(rec.footprint_bytes);
            continue;
        }

        // Active records within retention window
        if evaluated_ledger < rec.expires_ledger {
            retained_active.push_back(rec.id.clone());
            continue;
        }

        // Expired but protected by active hold
        if policy.honor_holds && active_operational_hold(env, &rec.id, evaluated_ledger).is_some() {
            protected_held.push_back(rec.id.clone());
            bytes_protected = bytes_protected.saturating_add(rec.footprint_bytes);
            continue;
        }

        // Eligible for safe deletion
        eligible.push_back(rec.id.clone());
        bytes_reclaimable = bytes_reclaimable.saturating_add(rec.footprint_bytes);
    }

    OperationalCleanupPlan {
        dry_run: true,
        evaluated_ledger,
        eligible,
        protected_held,
        protected_frozen,
        retained_active,
        bytes_reclaimable,
        bytes_protected,
    }
}

/// Generates a cleanup plan evaluated at the current ledger sequence.
pub fn plan_operational_cleanup(
    env: &Env,
    records: &Vec<StoredOperationalMetadata>,
) -> OperationalCleanupPlan {
    plan_operational_cleanup_at(env, records, env.ledger().sequence())
}

/// Executes an approved cleanup plan.
///
/// Guarantees:
/// - A dry-run plan is guaranteed non-destructive.
/// - Requires explicit `confirm == true` to perform deletions.
/// - Protection is re-checked at execution time so late holds win.
/// - Deletion physically cleans up storage without orphaned keys.
pub fn apply_operational_cleanup(
    env: &Env,
    plan: &OperationalCleanupPlan,
    confirm: bool,
) -> Result<OperationalCleanupReport, Error> {
    if plan.dry_run {
        return Ok(OperationalCleanupReport {
            evaluated_ledger: plan.evaluated_ledger,
            deleted: Vec::new(env),
            skipped_protected: Vec::new(env),
            bytes_reclaimed: 0,
            destructive: false,
        });
    }

    if !confirm {
        return Err(Error::InvalidArgument);
    }

    let now = env.ledger().sequence();
    let mut deleted = Vec::new(env);
    let mut skipped_protected = Vec::new(env);
    let mut bytes_reclaimed: u32 = 0;

    for i in 0..plan.protected_frozen.len() {
        if let Some(id) = plan.protected_frozen.get(i) {
            skipped_protected.push_back(id);
        }
    }
    for i in 0..plan.protected_held.len() {
        if let Some(id) = plan.protected_held.get(i) {
            skipped_protected.push_back(id);
        }
    }

    for i in 0..plan.eligible.len() {
        let Some(id) = plan.eligible.get(i) else {
            continue;
        };

        let Some(rec) = get_operational_metadata(env, &id) else {
            continue;
        };

        let policy = get_effective_operational_policy(env, rec.module, rec.class);

        // Re-check protection at execution time
        if policy.deletion_frozen
            || rec.is_frozen
            || (policy.honor_holds && active_operational_hold(env, &id, now).is_some())
        {
            skipped_protected.push_back(id);
            continue;
        }

        persistent_remove(env, &OpMetaStorageKey::Record(id.clone()));
        persistent_remove(env, &OpMetaStorageKey::Hold(id.clone()));
        bytes_reclaimed = bytes_reclaimed.saturating_add(rec.footprint_bytes);
        deleted.push_back(id);
    }

    env.events().publish(
        (symbol_short!("op_meta"), symbol_short!("cleanup")),
        (plan.evaluated_ledger, deleted.len() as u32, bytes_reclaimed),
    );

    Ok(OperationalCleanupReport {
        evaluated_ledger: plan.evaluated_ledger,
        deleted,
        skipped_protected,
        bytes_reclaimed,
        destructive: true,
    })
}

// ---------------------------------------------------------------------------
// Migration & Compatibility Adapters
// ---------------------------------------------------------------------------

/// Adapter function to review, minimize, and convert legacy operational metadata.
pub fn minimize_legacy_metadata(
    env: &Env,
    id: &Symbol,
    module: OperationalModule,
    class: MetadataClass,
    raw_keys: &Vec<Symbol>,
    raw_values: &Vec<Symbol>,
    created_ledger: u32,
) -> Result<StoredOperationalMetadata, Error> {
    if raw_keys.len() != raw_values.len() {
        return Err(Error::InvalidArgument);
    }
    let mut raw_fields = Vec::new(env);
    for i in 0..raw_keys.len() {
        if let (Some(k), Some(v)) = (raw_keys.get(i), raw_values.get(i)) {
            let sens = classify_field(module, &k);
            raw_fields.push_back(RawMetadataField {
                key: k,
                value: v,
                sensitivity: sens,
            });
        }
    }
    let (_, stored) = review_and_minimize(env, id, module, class, &raw_fields, created_ledger)?;
    Ok(stored)
}

/// Converts a StoredOperationalMetadata into a shared::retention::RetentionRecord.
pub fn to_shared_retention_record(
    rec: &StoredOperationalMetadata,
) -> crate::retention::RetentionRecord {
    let shared_class = match rec.class {
        MetadataClass::Audit => crate::retention::DataClass::Audit,
        MetadataClass::Telemetry => crate::retention::DataClass::Telemetry,
        MetadataClass::Execution => crate::retention::DataClass::Export,
        MetadataClass::SupportEvidence => crate::retention::DataClass::SupportEvidence,
        MetadataClass::FinancialSettlement => crate::retention::DataClass::FinancialSettlement,
        MetadataClass::Dispute => crate::retention::DataClass::Dispute,
    };
    crate::retention::RetentionRecord {
        id: rec.id.clone(),
        class: shared_class,
        created_ledger: rec.created_ledger,
        bytes: rec.footprint_bytes,
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{contract, contractimpl, testutils::Ledger};

    #[contract]
    pub struct OperationalMetadataHarness;

    #[contractimpl]
    impl OperationalMetadataHarness {
        pub fn noop(_env: Env) {}
    }

    fn with_storage<T>(env: &Env, f: impl FnOnce() -> T) -> T {
        let id = env.register_contract(None, OperationalMetadataHarness);
        env.as_contract(&id, f)
    }

    #[test]
    fn classify_fields_across_all_six_modules() {
        // Treasury
        assert_eq!(
            classify_field(OperationalModule::Treasury, &symbol_short!("actor")),
            FieldSensitivity::Essential
        );
        assert_eq!(
            classify_field(OperationalModule::Treasury, &symbol_short!("wall_time")),
            FieldSensitivity::Redundant
        );
        assert_eq!(
            classify_field(OperationalModule::Treasury, &symbol_short!("secret")),
            FieldSensitivity::Prohibited
        );

        // Aid
        assert_eq!(
            classify_field(OperationalModule::Aid, &symbol_short!("aid_id")),
            FieldSensitivity::Essential
        );
        assert_eq!(
            classify_field(OperationalModule::Aid, &symbol_short!("disp_name")),
            FieldSensitivity::Redundant
        );
        assert_eq!(
            classify_field(OperationalModule::Aid, &symbol_short!("biometric")),
            FieldSensitivity::Prohibited
        );

        // Referral
        assert_eq!(
            classify_field(OperationalModule::Referral, &symbol_short!("ref_code")),
            FieldSensitivity::Essential
        );
        assert_eq!(
            classify_field(OperationalModule::Referral, &symbol_short!("campaign")),
            FieldSensitivity::Redundant
        );

        // Governance
        assert_eq!(
            classify_field(OperationalModule::Governance, &symbol_short!("prop_id")),
            FieldSensitivity::Essential
        );
        assert_eq!(
            classify_field(OperationalModule::Governance, &symbol_short!("prose_dsc")),
            FieldSensitivity::Redundant
        );
        assert_eq!(
            classify_field(OperationalModule::Governance, &symbol_short!("ballot_sc")),
            FieldSensitivity::Prohibited
        );

        // Oracle
        assert_eq!(
            classify_field(OperationalModule::Oracle, &symbol_short!("feed_id")),
            FieldSensitivity::Essential
        );
        assert_eq!(
            classify_field(OperationalModule::Oracle, &symbol_short!("raw_resp")),
            FieldSensitivity::Redundant
        );

        // Marketplace
        assert_eq!(
            classify_field(OperationalModule::Marketplace, &symbol_short!("item_id")),
            FieldSensitivity::Essential
        );
        assert_eq!(
            classify_field(OperationalModule::Marketplace, &symbol_short!("card_no")),
            FieldSensitivity::Prohibited
        );
    }

    #[test]
    fn data_minimization_review_strips_redundant_and_prohibited_fields() {
        let env = Env::default();
        with_storage(&env, || {
            let mut raw_fields = Vec::new(&env);
            // Essential
            raw_fields.push_back(RawMetadataField {
                key: symbol_short!("actor"),
                value: symbol_short!("admin_1"),
                sensitivity: FieldSensitivity::Essential,
            });
            // Redundant: wall_time
            raw_fields.push_back(RawMetadataField {
                key: symbol_short!("wall_time"),
                value: symbol_short!("1234567"),
                sensitivity: FieldSensitivity::Redundant,
            });
            // Prohibited: secret
            raw_fields.push_back(RawMetadataField {
                key: symbol_short!("secret"),
                value: symbol_short!("bad_data"),
                sensitivity: FieldSensitivity::Prohibited,
            });
            // Optional context
            raw_fields.push_back(RawMetadataField {
                key: symbol_short!("category"),
                value: symbol_short!("reserve"),
                sensitivity: FieldSensitivity::OptionalContext,
            });

            let id = symbol_short!("meta_test");
            let (review, stored) = review_and_minimize(
                &env,
                &id,
                OperationalModule::Treasury,
                MetadataClass::Audit,
                &raw_fields,
                100,
            )
            .unwrap();

            assert_eq!(review.original_field_count, 4);
            assert_eq!(review.minimized_field_count, 2);
            assert_eq!(review.stripped_fields.len(), 2);
            assert!(review.passed);

            assert_eq!(stored.fields.len(), 2);
            assert_eq!(stored.fields.get(0).unwrap().key, symbol_short!("actor"));
            assert_eq!(stored.fields.get(1).unwrap().key, symbol_short!("category"));
            assert_eq!(stored.created_ledger, 100);
            assert_eq!(stored.expires_ledger, 100 + days_to_ledgers(365));
        });
    }

    #[test]
    fn default_and_override_retention_policies() {
        let env = Env::default();
        with_storage(&env, || {
            // Default policies
            let def_settle = default_operational_policy(
                OperationalModule::Treasury,
                MetadataClass::FinancialSettlement,
            );
            assert!(def_settle.deletion_frozen);
            assert_eq!(def_settle.retain_ledgers, days_to_ledgers(2_555));

            let def_telemetry = default_operational_policy(
                OperationalModule::Treasury,
                MetadataClass::Telemetry,
            );
            assert!(!def_telemetry.deletion_frozen);
            assert_eq!(def_telemetry.retain_ledgers, days_to_ledgers(30));

            // Custom override
            let custom = OperationalRetentionPolicy {
                retain_ledgers: 500,
                honor_holds: true,
                deletion_frozen: false,
            };
            set_operational_retention_policy(
                &env,
                OperationalModule::Treasury,
                MetadataClass::Telemetry,
                &custom,
            )
            .unwrap();

            let effective = get_effective_operational_policy(
                &env,
                OperationalModule::Treasury,
                MetadataClass::Telemetry,
            );
            assert_eq!(effective, custom);

            // Invalid policy rejected
            let invalid = OperationalRetentionPolicy {
                retain_ledgers: 0,
                honor_holds: true,
                deletion_frozen: false,
            };
            assert_eq!(
                set_operational_retention_policy(
                    &env,
                    OperationalModule::Treasury,
                    MetadataClass::Telemetry,
                    &invalid
                ),
                Err(Error::ConfigInvalid)
            );
        });
    }

    #[test]
    fn metadata_persistence_and_retrieval() {
        let env = Env::default();
        with_storage(&env, || {
            let id = symbol_short!("rec_1");
            let mut fields = Vec::new(&env);
            fields.push_back(MinimizedField {
                key: symbol_short!("aid_id"),
                value: symbol_short!("aid_42"),
            });

            let record = StoredOperationalMetadata {
                id: id.clone(),
                module: OperationalModule::Aid,
                class: MetadataClass::Execution,
                created_ledger: 50,
                expires_ledger: 50 + days_to_ledgers(90),
                fields,
                footprint_bytes: 72,
                is_held: false,
                is_frozen: false,
            };

            store_operational_metadata(&env, &record).unwrap();
            assert!(has_operational_metadata(&env, &id));

            let loaded = get_operational_metadata(&env, &id).unwrap();
            assert_eq!(loaded, record);
        });
    }

    #[test]
    fn cleanup_plan_is_dry_run_and_apply_deletes_when_confirmed() {
        let env = Env::default();
        with_storage(&env, || {
            let now = 1_000_000;
            env.ledger().set_sequence_number(now);

            // Record 1: Expired Telemetry
            let id1 = symbol_short!("tel_old");
            let rec1 = StoredOperationalMetadata {
                id: id1.clone(),
                module: OperationalModule::Oracle,
                class: MetadataClass::Telemetry,
                created_ledger: 10,
                expires_ledger: 10 + days_to_ledgers(14),
                fields: Vec::new(&env),
                footprint_bytes: 100,
                is_held: false,
                is_frozen: false,
            };
            store_operational_metadata(&env, &rec1).unwrap();

            // Record 2: Active Telemetry (not expired)
            let id2 = symbol_short!("tel_act");
            let rec2 = StoredOperationalMetadata {
                id: id2.clone(),
                module: OperationalModule::Oracle,
                class: MetadataClass::Telemetry,
                created_ledger: now - 100,
                expires_ledger: now + 500,
                fields: Vec::new(&env),
                footprint_bytes: 100,
                is_held: false,
                is_frozen: false,
            };
            store_operational_metadata(&env, &rec2).unwrap();

            let mut records = Vec::new(&env);
            records.push_back(rec1);
            records.push_back(rec2);

            let plan = plan_operational_cleanup(&env, &records);
            assert!(plan.dry_run);
            assert_eq!(plan.eligible.len(), 1);
            assert_eq!(plan.eligible.get(0).unwrap(), id1);
            assert_eq!(plan.retained_active.len(), 1);
            assert_eq!(plan.retained_active.get(0).unwrap(), id2);
            assert_eq!(plan.bytes_reclaimable, 100);

            // Dry-run execution deletes nothing
            let dry_rep = apply_operational_cleanup(&env, &plan, false).unwrap();
            assert!(!dry_rep.destructive);
            assert!(has_operational_metadata(&env, &id1));

            // Unconfirmed real run fails
            let mut live_plan = plan.clone();
            live_plan.dry_run = false;
            assert_eq!(
                apply_operational_cleanup(&env, &live_plan, false),
                Err(Error::InvalidArgument)
            );
            assert!(has_operational_metadata(&env, &id1));

            // Confirmed execution deletes eligible record
            let report = apply_operational_cleanup(&env, &live_plan, true).unwrap();
            assert!(report.destructive);
            assert_eq!(report.deleted.len(), 1);
            assert_eq!(report.deleted.get(0).unwrap(), id1);
            assert_eq!(report.bytes_reclaimed, 100);
            assert!(!has_operational_metadata(&env, &id1));
            assert!(has_operational_metadata(&env, &id2));
        });
    }

    #[test]
    fn retention_holds_protect_expired_operational_metadata() {
        let env = Env::default();
        with_storage(&env, || {
            let now = 2_000_000;
            env.ledger().set_sequence_number(now);

            let id = symbol_short!("gov_audit");
            let rec = StoredOperationalMetadata {
                id: id.clone(),
                module: OperationalModule::Governance,
                class: MetadataClass::Audit,
                created_ledger: 100,
                expires_ledger: 100 + days_to_ledgers(365),
                fields: Vec::new(&env),
                footprint_bytes: 256,
                is_held: false,
                is_frozen: false,
            };
            store_operational_metadata(&env, &rec).unwrap();

            // Place an indefinite legal hold
            place_operational_hold(&env, &id, HoldReason::Legal, HOLD_INDEFINITE).unwrap();
            assert!(active_operational_hold(&env, &id, now).is_some());

            let mut records = Vec::new(&env);
            records.push_back(rec);
            let mut plan = plan_operational_cleanup(&env, &records);

            assert_eq!(plan.eligible.len(), 0);
            assert_eq!(plan.protected_held.len(), 1);
            assert_eq!(plan.protected_held.get(0).unwrap(), id);
            assert_eq!(plan.bytes_protected, 256);

            plan.dry_run = false;
            let report = apply_operational_cleanup(&env, &plan, true).unwrap();
            assert_eq!(report.deleted.len(), 0);
            assert_eq!(report.skipped_protected.len(), 1);
            assert!(has_operational_metadata(&env, &id));

            // Release hold and re-plan
            release_operational_hold(&env, &id).unwrap();
            assert!(active_operational_hold(&env, &id, now).is_none());

            let fresh_rec = get_operational_metadata(&env, &id).unwrap();
            let mut records2 = Vec::new(&env);
            records2.push_back(fresh_rec);

            let mut plan2 = plan_operational_cleanup(&env, &records2);
            assert_eq!(plan2.eligible.len(), 1);
            plan2.dry_run = false;

            let report2 = apply_operational_cleanup(&env, &plan2, true).unwrap();
            assert_eq!(report2.deleted.len(), 1);
            assert!(!has_operational_metadata(&env, &id));
        });
    }

    #[test]
    fn late_hold_placed_after_planning_wins() {
        let env = Env::default();
        with_storage(&env, || {
            let now = 1_000_000;
            env.ledger().set_sequence_number(now);

            let id = symbol_short!("late_rec");
            let rec = StoredOperationalMetadata {
                id: id.clone(),
                module: OperationalModule::Marketplace,
                class: MetadataClass::Execution,
                created_ledger: 10,
                expires_ledger: 10 + days_to_ledgers(90),
                fields: Vec::new(&env),
                footprint_bytes: 120,
                is_held: false,
                is_frozen: false,
            };
            store_operational_metadata(&env, &rec).unwrap();

            let mut records = Vec::new(&env);
            records.push_back(rec);
            let mut plan = plan_operational_cleanup(&env, &records);
            assert_eq!(plan.eligible.len(), 1);

            // A dispute hold is placed after plan generation
            place_operational_hold(&env, &id, HoldReason::Dispute, HOLD_INDEFINITE).unwrap();

            plan.dry_run = false;
            let report = apply_operational_cleanup(&env, &plan, true).unwrap();
            assert_eq!(report.deleted.len(), 0);
            assert_eq!(report.skipped_protected.len(), 1);
            assert!(has_operational_metadata(&env, &id));
        });
    }

    #[test]
    fn frozen_classes_cannot_be_deleted() {
        let env = Env::default();
        with_storage(&env, || {
            let now = 50_000_000;
            env.ledger().set_sequence_number(now);

            let id = Symbol::new(env, "settle_rec");
            let rec = StoredOperationalMetadata {
                id: id.clone(),
                module: OperationalModule::Treasury,
                class: MetadataClass::FinancialSettlement,
                created_ledger: 1,
                expires_ledger: 1 + days_to_ledgers(2_555),
                fields: Vec::new(&env),
                footprint_bytes: 500,
                is_held: false,
                is_frozen: true,
            };
            store_operational_metadata(&env, &rec).unwrap();

            let mut records = Vec::new(&env);
            records.push_back(rec);
            let plan = plan_operational_cleanup(&env, &records);
            assert_eq!(plan.eligible.len(), 0);
            assert_eq!(plan.protected_frozen.len(), 1);

            // Even if hand-forged into eligible, execution protects frozen records
            let mut forged = plan.clone();
            forged.dry_run = false;
            forged.eligible.push_back(id.clone());
            let report = apply_operational_cleanup(&env, &forged, true).unwrap();
            assert_eq!(report.deleted.len(), 0);
            assert_eq!(report.skipped_protected.len(), 2); // 1 from plan.protected_frozen + 1 from re-check
            assert!(has_operational_metadata(&env, &id));
        });
    }

    #[test]
    fn legacy_metadata_minimization_adapter() {
        let env = Env::default();
        with_storage(&env, || {
            let id = symbol_short!("leg_aid");
            let mut raw_keys = Vec::new(&env);
            let mut raw_vals = Vec::new(&env);

            raw_keys.push_back(symbol_short!("aid_id"));
            raw_vals.push_back(symbol_short!("1001"));

            raw_keys.push_back(symbol_short!("disp_name"));
            raw_vals.push_back(symbol_short!("redundant"));

            raw_keys.push_back(symbol_short!("biometric"));
            raw_vals.push_back(symbol_short!("prohibit"));

            let stored = minimize_legacy_metadata(
                &env,
                &id,
                OperationalModule::Aid,
                MetadataClass::Audit,
                &raw_keys,
                &raw_vals,
                50,
            )
            .unwrap();

            assert_eq!(stored.id, id);
            assert_eq!(stored.fields.len(), 1);
            assert_eq!(stored.fields.get(0).unwrap().key, symbol_short!("aid_id"));
        });
    }
}
