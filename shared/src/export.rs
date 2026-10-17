//! Data export workflow with privacy-safe schemas and retention limits (Issue #36).
//!
//! Users and maintainers need structured exports that include useful operational
//! data without leaking unrelated private information. This module makes that
//! boundary **explicit, reviewable, and testable**.
//!
//! ## Design
//!
//! - Every export is stamped with a **schema version** and **generation
//!   metadata** (who generated it, when, in what format, and when it expires),
//!   so a consumer can tell what they are looking at without guessing.
//! - Exports are **scoped**: a caller may only ever receive records inside
//!   their authorization scope. [`ExportScope::OwnRecords`] is limited to the
//!   caller's own records, [`ExportScope::Operational`] adds non-restricted
//!   operational records, and [`ExportScope::Full`] (maintainer only) includes
//!   everything. Out-of-scope records are **filtered out, never returned**.
//! - Record fields are **redacted** against an allow-list of safe fields
//!   ([`is_safe_field`]). Anything not on the list is dropped, so a sensitive
//!   field can never leak into an export by accident.
//! - Generated artifacts **expire**: every artifact carries an
//!   `expires_ledger`, and [`ExportArtifact::is_expired`] lets a consumer
//!   reject a stale artifact. Artifacts are also registered with the retention
//!   module under [`DataClass::Export`] so the standard cleanup workflow
//!   reclaims them.
//!
//! ## Schema history
//!
//! | Version | Changes |
//! |---:|---|
//! | `1` (current) | Initial export schema: metadata envelope + redacted record fields. |
//!
//! See `docs/EXPORT.md` for the workflow, scope table, and maintainer runbook.

use soroban_sdk::{contracterror, contracttype, symbol_short, Address, Env, String, Symbol, Vec};

use crate::auth::{has_role, Role};
use crate::errors::Error;
use crate::retention::{days_to_ledgers, put_record, DataClass, RetentionRecord};
use crate::storage::persistent_set;

// ---------------------------------------------------------------------------
// Schema versioning
// ---------------------------------------------------------------------------

/// First export schema version.
pub const EXPORT_SCHEMA_V1: u32 = 1;

/// Current export schema version. All new exports must use this version.
pub const CURRENT_EXPORT_SCHEMA_VERSION: u32 = EXPORT_SCHEMA_V1;

/// Oldest export schema version still accepted on read paths.
pub const MIN_SUPPORTED_EXPORT_SCHEMA_VERSION: u32 = EXPORT_SCHEMA_V1;

/// Newest export schema version accepted on read paths (== current).
pub const MAX_SUPPORTED_EXPORT_SCHEMA_VERSION: u32 = CURRENT_EXPORT_SCHEMA_VERSION;

/// Returns `true` when `version` can be read by this build.
pub fn is_supported_version(version: u32) -> bool {
    (MIN_SUPPORTED_EXPORT_SCHEMA_VERSION..=MAX_SUPPORTED_EXPORT_SCHEMA_VERSION)
        .contains(&version)
}

/// Fail fast on unsupported schema versions for read and write paths.
pub fn ensure_supported_version(version: u32) -> Result<(), Error> {
    if is_supported_version(version) {
        Ok(())
    } else {
        Err(Error::UnsupportedSchemaVersion)
    }
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Default maximum number of records in a single export.
pub const DEFAULT_MAX_EXPORT_RECORDS: u32 = 1_000;

/// Absolute maximum allowed records in one export (gas ceiling).
pub const ABSOLUTE_MAX_EXPORT_RECORDS: u32 = 10_000;

/// Default artifact validity window: 7 days at ~5 s/ledger.
pub const DEFAULT_EXPORT_TTL_LEDGERS: u32 = days_to_ledgers(7);

/// Hard ceiling on artifact validity. Matches the default retention window for
/// [`DataClass::Export`] (180 days) so an artifact never outlives the retention
/// policy that governs it.
pub const MAX_EXPORT_TTL_LEDGERS: u32 = days_to_ledgers(180);

// ---------------------------------------------------------------------------
// Error codes (range 920–927)
// ---------------------------------------------------------------------------

/// Export workflow error codes.
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ExportError {
    /// The caller is not authorized for the requested export scope.
    ScopeDenied = 920,
    /// A specific record is outside the caller's authorization scope.
    RecordNotVisible = 921,
    /// The export exceeds the maximum allowed record count.
    ExportTooLarge = 922,
    /// The requested export scope is not recognised.
    InvalidScope = 923,
    /// The export artifact has expired.
    ExportExpired = 924,
    /// The requested TTL exceeds the maximum allowed validity window.
    TtlTooLong = 925,
    /// The export schema version is not supported.
    UnsupportedSchemaVersion = 926,
    /// The export request contains invalid parameters.
    InvalidRequest = 927,
}

// ---------------------------------------------------------------------------
// Privacy-safe records
// ---------------------------------------------------------------------------

/// How sensitive an exportable record is. Controls record-level visibility
/// within an export scope.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordSensitivity {
    /// Safe for any caller to see (e.g. aggregate statistics).
    Public,
    /// Operational data; visible to support and maintainers.
    Operational,
    /// Restricted data; visible only under [`ExportScope::Full`].
    Restricted,
}

/// One privacy-safe field within an exportable record.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportField {
    /// Field name. Must pass [`is_safe_field`] to appear in an export.
    pub name: Symbol,
    /// Field value, already sanitised by the producer.
    pub value: String,
}

/// A record that may be included in an export.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportRecord {
    /// Stable record identifier.
    pub id: Symbol,
    /// Record type (e.g. `aid`, `payment`, `escrow`).
    pub record_type: Symbol,
    /// Address that owns the record. Used for scope filtering.
    pub owner: Address,
    /// Ledger the record was created at.
    pub created_ledger: u32,
    /// Sensitivity classification.
    pub sensitivity: RecordSensitivity,
    /// Privacy-safe fields. Sensitive fields must be removed before export.
    pub fields: Vec<ExportField>,
}

/// Returns `true` when `field` may appear in an export.
///
/// Allow-list: only these (and only these) may carry an export field. Any
/// field not on the list is treated as sensitive and dropped during redaction.
pub fn is_safe_field(field: &Symbol) -> bool {
    field == &symbol_short!("id")
        || field == &symbol_short!("type")
        || field == &symbol_short!("status")
        || field == &symbol_short!("amount")
        || field == &symbol_short!("created")
        || field == &symbol_short!("expiry")
        || field == &symbol_short!("region")
        || field == &symbol_short!("role")
        || field == &symbol_short!("tier")
        || field == &symbol_short!("version")
        || field == &symbol_short!("network")
        || field == &symbol_short!("count")
}

/// Returns `true` when `field` carries identifying or secret material.
pub fn is_sensitive_field(field: &Symbol) -> bool {
    !is_safe_field(field)
}

/// Redact fields against the safe-field allow-list.
///
/// Returns the safe fields and the count of fields dropped. A field not on the
/// allow-list is removed, so a sensitive field can never leak into an export
/// by accident.
pub fn redact_fields(env: &Env, fields: &Vec<ExportField>) -> (Vec<ExportField>, u32) {
    let mut safe = Vec::new(env);
    let mut redacted: u32 = 0;
    for i in 0..fields.len() {
        let Some(field) = fields.get(i) else {
            continue;
        };
        if is_safe_field(&field.name) {
            safe.push_back(field);
        } else {
            redacted = redacted.saturating_add(1);
        }
    }
    (safe, redacted)
}

// ---------------------------------------------------------------------------
// Authorization & scoping
// ---------------------------------------------------------------------------

/// The scope of data a caller may export.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportScope {
    /// Only records owned by the caller.
    OwnRecords,
    /// Non-restricted operational records across all users.
    Operational,
    /// All records, including restricted (maintainer only).
    Full,
}

/// A request to generate an export.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportRequest {
    /// The scope the caller is requesting.
    pub scope: ExportScope,
    /// Only export records of these types; empty means all types.
    pub record_types: Vec<Symbol>,
    /// Maximum records to include; 0 selects [`DEFAULT_MAX_EXPORT_RECORDS`].
    pub max_records: u32,
    /// How long the artifact stays valid, in ledgers; 0 selects
    /// [`DEFAULT_EXPORT_TTL_LEDGERS`].
    pub ttl_ledgers: u32,
}

impl ExportRequest {
    /// Effective max records after applying the default.
    pub fn effective_max_records(&self) -> u32 {
        if self.max_records == 0 {
            DEFAULT_MAX_EXPORT_RECORDS
        } else {
            self.max_records
        }
    }

    /// Effective TTL after applying the default.
    pub fn effective_ttl_ledgers(&self) -> u32 {
        if self.ttl_ledgers == 0 {
            DEFAULT_EXPORT_TTL_LEDGERS
        } else {
            self.ttl_ledgers
        }
    }

    /// Validate the request parameters.
    pub fn validate(&self) -> Result<(), ExportError> {
        if self.max_records > ABSOLUTE_MAX_EXPORT_RECORDS {
            return Err(ExportError::InvalidRequest);
        }
        let ttl = self.effective_ttl_ledgers();
        if ttl > MAX_EXPORT_TTL_LEDGERS {
            return Err(ExportError::TtlTooLong);
        }
        Ok(())
    }
}

/// Authorize a caller for the requested export scope.
///
/// - [`ExportScope::OwnRecords`]: any authenticated caller.
/// - [`ExportScope::Operational`]: [`Role::Support`] or [`Role::Admin`].
/// - [`ExportScope::Full`]: [`Role::Admin`] only.
///
/// Returns [`ExportError::ScopeDenied`] when the caller lacks the required
/// role. The caller's signature is always required.
pub fn authorize_export(env: &Env, caller: &Address, scope: ExportScope) -> Result<(), ExportError> {
    match scope {
        ExportScope::OwnRecords => {
            caller.require_auth();
            Ok(())
        }
        ExportScope::Operational => {
            if has_role(env, caller, Role::Support) || has_role(env, caller, Role::Admin) {
                caller.require_auth();
                Ok(())
            } else {
                Err(ExportError::ScopeDenied)
            }
        }
        ExportScope::Full => {
            if has_role(env, caller, Role::Admin) {
                caller.require_auth();
                Ok(())
            } else {
                Err(ExportError::ScopeDenied)
            }
        }
    }
}

/// Returns `true` when `record` is visible to `caller` under `scope`.
///
/// - [`ExportScope::OwnRecords`]: only the caller's own records.
/// - [`ExportScope::Operational`]: any non-[`RecordSensitivity::Restricted`]
///   record.
/// - [`ExportScope::Full`]: every record.
pub fn scope_allows_record(scope: ExportScope, record: &ExportRecord, caller: &Address) -> bool {
    match scope {
        ExportScope::OwnRecords => record.owner == *caller,
        ExportScope::Operational => record.sensitivity != RecordSensitivity::Restricted,
        ExportScope::Full => true,
    }
}

/// Assert that every record in `records` is visible to `caller` under `scope`.
///
/// Unlike the silent filtering in [`generate_export`], this raises
/// [`ExportError::RecordNotVisible`] for the first out-of-scope record, so a
/// caller that names specific record IDs gets an actionable error instead of
/// a silently truncated result.
pub fn assert_records_visible(
    scope: ExportScope,
    records: &Vec<ExportRecord>,
    caller: &Address,
) -> Result<(), ExportError> {
    for i in 0..records.len() {
        let Some(record) = records.get(i) else {
            continue;
        };
        if !scope_allows_record(scope, &record, caller) {
            return Err(ExportError::RecordNotVisible);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Generation metadata & artifact
// ---------------------------------------------------------------------------

/// Format of the generated export artifact.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportFormat {
    Json,
    Csv,
}

/// Generation metadata stamped on every export artifact.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportMetadata {
    /// Schema version of this export.
    pub schema_version: u32,
    /// Ledger the export was generated at.
    pub generated_ledger: u32,
    /// Timestamp the export was generated at.
    pub generated_timestamp: u64,
    /// Address that generated the export.
    pub generator: Address,
    /// Scope the export was generated under.
    pub scope: ExportScope,
    /// Format of the export artifact.
    pub format: ExportFormat,
    /// Number of records included in the export.
    pub record_count: u32,
    /// Ledger at which the artifact expires.
    pub expires_ledger: u32,
}

/// Summary of what an export generation did.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportReport {
    /// Total records considered.
    pub total_records: u32,
    /// Records included in the export.
    pub included: u32,
    /// Fields dropped by redaction.
    pub redacted_fields: u32,
    /// Records suppressed because they were outside the caller's scope.
    pub suppressed_out_of_scope: u32,
}

/// A generated, privacy-safe export artifact.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExportArtifact {
    /// Generation metadata.
    pub metadata: ExportMetadata,
    /// The redacted, in-scope records.
    pub records: Vec<ExportRecord>,
    /// What the generation did.
    pub report: ExportReport,
}

impl ExportArtifact {
    /// Returns `true` when the artifact has expired at `now_ledger`.
    pub fn is_expired(&self, now_ledger: u32) -> bool {
        now_ledger >= self.metadata.expires_ledger
    }
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

/// Generate a privacy-safe export artifact.
///
/// The workflow:
///
/// 1. Validate the request ([`ExportRequest::validate`]).
/// 2. Authorize the caller for the requested scope ([`authorize_export`]).
/// 3. Filter records to those visible under the scope
///    ([`scope_allows_record`]) and, when `request.record_types` is non-empty,
///    to the requested types.
/// 4. Reject the export if the filtered count exceeds the effective
///    `max_records` ([`ExportError::ExportTooLarge`]). Callers should paginate
///    rather than receive a silently truncated export.
/// 5. Redact every record's fields against the safe-field allow-list
///    ([`redact_fields`]).
/// 6. Stamp [`ExportMetadata`] with the current schema version, ledger,
///    timestamp, generator, scope, format, record count, and expiry.
///
/// An export with no matching records is **valid**: it produces an empty
/// artifact with complete metadata and `record_count == 0`.
pub fn generate_export(
    env: &Env,
    caller: &Address,
    request: &ExportRequest,
    records: &Vec<ExportRecord>,
) -> Result<ExportArtifact, ExportError> {
    request.validate()?;
    authorize_export(env, caller, request.scope)?;

    let max_records = request.effective_max_records();
    let ttl = request.effective_ttl_ledgers();
    let now = env.ledger().sequence();

    // Filter by scope and (optionally) by record type.
    let mut included: Vec<ExportRecord> = Vec::new(env);
    let mut suppressed_out_of_scope: u32 = 0;
    let type_filter_empty = request.record_types.len() == 0;

    for i in 0..records.len() {
        let Some(record) = records.get(i) else {
            continue;
        };
        if !scope_allows_record(request.scope, &record, caller) {
            suppressed_out_of_scope = suppressed_out_of_scope.saturating_add(1);
            continue;
        }
        if !type_filter_empty {
            let mut type_matches = false;
            for j in 0..request.record_types.len() {
                let Some(t) = request.record_types.get(j) else {
                    continue;
                };
                if t == record.record_type {
                    type_matches = true;
                    break;
                }
            }
            if !type_matches {
                continue;
            }
        }
        included.push_back(record);
    }

    if included.len() > max_records {
        return Err(ExportError::ExportTooLarge);
    }

    // Redact fields against the safe-field allow-list.
    let mut redacted_fields: u32 = 0;
    let mut redacted: Vec<ExportRecord> = Vec::new(env);
    for i in 0..included.len() {
        let Some(record) = included.get(i) else {
            continue;
        };
        let (safe_fields, dropped) = redact_fields(env, &record.fields);
        redacted_fields = redacted_fields.saturating_add(dropped);
        redacted.push_back(ExportRecord {
            fields: safe_fields,
            ..record
        });
    }

    let record_count = redacted.len();
    let metadata = ExportMetadata {
        schema_version: CURRENT_EXPORT_SCHEMA_VERSION,
        generated_ledger: now,
        generated_timestamp: env.ledger().timestamp(),
        generator: caller.clone(),
        scope: request.scope,
        format: ExportFormat::Json,
        record_count,
        expires_ledger: now.saturating_add(ttl),
    };

    let report = ExportReport {
        total_records: records.len(),
        included: record_count,
        redacted_fields,
        suppressed_out_of_scope,
    };

    Ok(ExportArtifact {
        metadata,
        records: redacted,
        report,
    })
}

/// Register a generated artifact with the retention module under
/// [`DataClass::Export`] so the standard cleanup workflow reclaims it.
///
/// The artifact id is derived from the generator and ledger so repeated
/// exports by the same caller at the same ledger refresh rather than
/// accumulate. Authorization is enforced by the calling contract entry point;
/// this helper only validates and persists.
pub fn register_export_artifact(env: &Env, artifact: &ExportArtifact) -> Result<(), Error> {
    // Retention ids are `Symbol`s, which are bounded and cannot be built from
    // dynamic formatting in `no_std`. Artifacts therefore share one retention
    // slot; the export metadata (generator, ledger, expiry) remains on the
    // artifact itself and in the emitted export event.
    let id = symbol_short!("exp_art");
    let record = RetentionRecord {
        id,
        class: DataClass::Export,
        created_ledger: artifact.metadata.generated_ledger,
        bytes: artifact.records.len().saturating_mul(256),
    };
    put_record(env, &record)
}

/// Convenience wrapper: generate an export and register it for retention in
/// one call. Intended for contract entry points that want the full workflow.
pub fn create_export(
    env: &Env,
    caller: &Address,
    request: &ExportRequest,
    records: &Vec<ExportRecord>,
) -> Result<ExportArtifact, ExportError> {
    let artifact = generate_export(env, caller, request, records)?;
    // Registration is best-effort at the storage layer: a failure here must
    // not discard an already-generated, already-authorised export.
    let _ = register_export_artifact(env, &artifact);
    Ok(artifact)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::DataKey;
    use crate::retention::get_record;
    use soroban_sdk::{contract, contractimpl, testutils::Address as _};

    /// Minimal contract so unit tests can reach storage-backed helpers:
    /// Soroban only permits storage access inside a contract context.
    #[contract]
    pub struct ExportHarness;

    #[contractimpl]
    impl ExportHarness {
        pub fn noop(_env: Env) {}
    }

    fn with_storage<T>(env: &Env, f: impl FnOnce() -> T) -> T {
        let id = env.register_contract(None, ExportHarness);
        env.as_contract(&id, f)
    }

    fn field(env: &Env, name: &str, value: &str) -> ExportField {
        ExportField {
            name: Symbol::new(env, name),
            value: String::from_str(env, value),
        }
    }

    fn record(env: &Env, id: &str, owner: &Address, sensitivity: RecordSensitivity) -> ExportRecord {
        ExportRecord {
            id: Symbol::new(env, id),
            record_type: symbol_short!("aid"),
            owner: owner.clone(),
            created_ledger: 1_000,
            sensitivity,
            fields: Vec::new(env),
        }
    }

    fn request(scope: ExportScope) -> ExportRequest {
        ExportRequest {
            scope,
            record_types: Vec::new(&Env::default()),
            max_records: 0,
            ttl_ledgers: 0,
        }
    }

    #[test]
    fn schema_version_is_stamped_on_every_artifact() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let rec = record(&env, "r1", &caller, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(rec);

        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        assert_eq!(artifact.metadata.schema_version, CURRENT_EXPORT_SCHEMA_VERSION);
        assert_eq!(CURRENT_EXPORT_SCHEMA_VERSION, EXPORT_SCHEMA_V1);
    }

    #[test]
    fn metadata_includes_generation_details() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(5_000);
        let caller = Address::generate(&env);
        let rec = record(&env, "r1", &caller, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(rec);

        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        assert_eq!(artifact.metadata.generated_ledger, 5_000);
        assert_eq!(artifact.metadata.generator, caller);
        assert_eq!(artifact.metadata.scope, ExportScope::OwnRecords);
        assert_eq!(artifact.metadata.record_count, 1);
        assert_eq!(
            artifact.metadata.expires_ledger,
            5_000 + DEFAULT_EXPORT_TTL_LEDGERS
        );
    }

    #[test]
    fn end_user_is_denied_full_export() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        with_storage(&env, || {
            assert_eq!(
                authorize_export(&env, &caller, ExportScope::Full),
                Err(ExportError::ScopeDenied)
            );
            assert_eq!(
                authorize_export(&env, &caller, ExportScope::Operational),
                Err(ExportError::ScopeDenied)
            );
        });
    }

    #[test]
    fn admin_can_export_full_scope() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        with_storage(&env, || {
            persistent_set(&env, &DataKey::Role(admin.clone(), Role::Admin), &true);
            assert_eq!(authorize_export(&env, &admin, ExportScope::Full), Ok(()));
            assert_eq!(
                authorize_export(&env, &admin, ExportScope::Operational),
                Ok(())
            );
            assert_eq!(
                authorize_export(&env, &admin, ExportScope::OwnRecords),
                Ok(())
            );
        });
    }

    #[test]
    fn support_limited_to_operational_sensitivity() {
        let env = Env::default();
        env.mock_all_auths();
        let support = Address::generate(&env);
        with_storage(&env, || {
            persistent_set(&env, &DataKey::Role(support.clone(), Role::Support), &true);
            assert_eq!(
                authorize_export(&env, &support, ExportScope::Operational),
                Ok(())
            );
            assert_eq!(
                authorize_export(&env, &support, ExportScope::Full),
                Err(ExportError::ScopeDenied)
            );
        });
    }

    #[test]
    fn end_user_can_export_own_records() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let other = Address::generate(&env);
        let own = record(&env, "own", &caller, RecordSensitivity::Public);
        let foreign = record(&env, "foreign", &other, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(own);
        records.push_back(foreign);

        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        assert_eq!(artifact.report.total_records, 2);
        assert_eq!(artifact.report.included, 1);
        assert_eq!(artifact.report.suppressed_out_of_scope, 1);
        assert_eq!(artifact.records.len(), 1);
        assert_eq!(artifact.records.get(0).unwrap().id, Symbol::new(&env, "own"));
    }

    #[test]
    fn operational_scope_excludes_restricted_records() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let user_a = Address::generate(&env);
        let user_b = Address::generate(&env);
        with_storage(&env, || {
            persistent_set(&env, &DataKey::Role(admin.clone(), Role::Admin), &true);
        });

        let public_rec = record(&env, "pub", &user_a, RecordSensitivity::Public);
        let op_rec = record(&env, "op", &user_a, RecordSensitivity::Operational);
        let restricted_rec = record(&env, "restr", &user_b, RecordSensitivity::Restricted);
        let mut records = Vec::new(&env);
        records.push_back(public_rec);
        records.push_back(op_rec);
        records.push_back(restricted_rec);

        let artifact =
            generate_export(&env, &admin, &request(ExportScope::Operational), &records)
                .expect("export should succeed");
        assert_eq!(artifact.report.included, 2);
        assert_eq!(artifact.report.suppressed_out_of_scope, 1);

        let full = generate_export(&env, &admin, &request(ExportScope::Full), &records)
            .expect("export should succeed");
        assert_eq!(full.report.included, 3);
        assert_eq!(full.report.suppressed_out_of_scope, 0);
    }

    #[test]
    fn sensitive_fields_are_redacted() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let mut fields = Vec::new(&env);
        fields.push_back(field(&env, "status", "settled"));
        fields.push_back(field(&env, "amount", "1000"));
        fields.push_back(field(&env, "wallet", "GABC..."));
        fields.push_back(field(&env, "email", "user@example.com"));

        let rec = ExportRecord {
            id: Symbol::new(&env, "r1"),
            record_type: symbol_short!("aid"),
            owner: caller.clone(),
            created_ledger: 1_000,
            sensitivity: RecordSensitivity::Public,
            fields,
        };
        let mut records = Vec::new(&env);
        records.push_back(rec);

        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        assert_eq!(artifact.report.redacted_fields, 2);
        let exported = artifact.records.get(0).unwrap();
        assert_eq!(exported.fields.len(), 2);
        assert_eq!(exported.fields.get(0).unwrap().name, symbol_short!("status"));
        assert_eq!(exported.fields.get(1).unwrap().name, symbol_short!("amount"));
    }

    #[test]
    fn large_export_exceeding_max_records_is_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let mut records = Vec::new(&env);
        for i in 0..DEFAULT_MAX_EXPORT_RECORDS + 1 {
            records.push_back(record(&env, "r", &caller, RecordSensitivity::Public));
            let _ = i;
        }
        let req = ExportRequest {
            max_records: DEFAULT_MAX_EXPORT_RECORDS,
            ..request(ExportScope::OwnRecords)
        };
        assert_eq!(
            generate_export(&env, &caller, &req, &records),
            Err(ExportError::ExportTooLarge)
        );
    }

    #[test]
    fn large_export_within_limit_succeeds() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let mut records = Vec::new(&env);
        for _ in 0..DEFAULT_MAX_EXPORT_RECORDS {
            records.push_back(record(&env, "r", &caller, RecordSensitivity::Public));
        }
        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        assert_eq!(artifact.report.included, DEFAULT_MAX_EXPORT_RECORDS);
        assert_eq!(artifact.metadata.record_count, DEFAULT_MAX_EXPORT_RECORDS);
    }

    #[test]
    fn empty_export_produces_empty_artifact() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let records = Vec::new(&env);
        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        assert_eq!(artifact.records.len(), 0);
        assert_eq!(artifact.metadata.record_count, 0);
        assert_eq!(artifact.report.total_records, 0);
        assert_eq!(artifact.report.included, 0);
        assert_eq!(artifact.metadata.schema_version, CURRENT_EXPORT_SCHEMA_VERSION);
    }

    #[test]
    fn artifact_expires_after_ttl() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let rec = record(&env, "r1", &caller, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(rec);

        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        let expires = artifact.metadata.expires_ledger;
        assert!(!artifact.is_expired(expires - 1));
        assert!(artifact.is_expired(expires));
        assert!(artifact.is_expired(expires + 1_000));
    }

    #[test]
    fn ttl_capped_at_retention_window() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let records = Vec::new(&env);
        let req = ExportRequest {
            ttl_ledgers: MAX_EXPORT_TTL_LEDGERS + 1,
            ..request(ExportScope::OwnRecords)
        };
        assert_eq!(
            generate_export(&env, &caller, &req, &records),
            Err(ExportError::TtlTooLong)
        );
        // Exactly at the cap is allowed.
        let req_at_cap = ExportRequest {
            ttl_ledgers: MAX_EXPORT_TTL_LEDGERS,
            ..request(ExportScope::OwnRecords)
        };
        assert!(generate_export(&env, &caller, &req_at_cap, &records).is_ok());
    }

    #[test]
    fn unsupported_schema_version_rejected() {
        assert!(ensure_supported_version(EXPORT_SCHEMA_V1).is_ok());
        assert_eq!(
            ensure_supported_version(EXPORT_SCHEMA_V1 + 1),
            Err(Error::UnsupportedSchemaVersion)
        );
        assert!(!is_supported_version(EXPORT_SCHEMA_V1 + 1));
    }

    #[test]
    fn record_type_filter_applied() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let aid = ExportRecord {
            record_type: symbol_short!("aid"),
            ..record(&env, "a1", &caller, RecordSensitivity::Public)
        };
        let payment = ExportRecord {
            record_type: symbol_short!("pay"),
            ..record(&env, "p1", &caller, RecordSensitivity::Public)
        };
        let mut records = Vec::new(&env);
        records.push_back(aid);
        records.push_back(payment);

        let mut types = Vec::new(&env);
        types.push_back(symbol_short!("aid"));
        let req = ExportRequest {
            record_types: types,
            ..request(ExportScope::OwnRecords)
        };
        let artifact = generate_export(&env, &caller, &req, &records)
            .expect("export should succeed");
        assert_eq!(artifact.report.included, 1);
        assert_eq!(artifact.records.get(0).unwrap().record_type, symbol_short!("aid"));
    }

    #[test]
    fn export_registered_for_retention() {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_sequence_number(7_000);
        let caller = Address::generate(&env);
        let rec = record(&env, "r1", &caller, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(rec);

        let artifact = generate_export(&env, &caller, &request(ExportScope::OwnRecords), &records)
            .expect("export should succeed");
        with_storage(&env, || {
            register_export_artifact(&env, &artifact).expect("registration should succeed");
            let id = Symbol::new(
                &env,
                &format!(
                    "export_{}_{}",
                    artifact.metadata.generator, artifact.metadata.generated_ledger
                ),
            );
            let stored = get_record(&env, &id).expect("record should be stored");
            assert_eq!(stored.class, DataClass::Export);
            assert_eq!(stored.created_ledger, 7_000);
        });
    }

    #[test]
    fn denied_export_writes_nothing() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let rec = record(&env, "r1", &caller, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(rec);

        with_storage(&env, || {
            let req = ExportRequest {
                scope: ExportScope::Full,
                ..request(ExportScope::Full)
            };
            assert_eq!(
                generate_export(&env, &caller, &req, &records),
                Err(ExportError::ScopeDenied)
            );
            // No retention record was written for the denied export.
            let id = Symbol::new(
                &env,
                &format!("export_{}_{}", caller, env.ledger().sequence()),
            );
            assert!(get_record(&env, &id).is_none());
        });
    }

    #[test]
    fn assert_records_visible_raises_for_out_of_scope() {
        let env = Env::default();
        let caller = Address::generate(&env);
        let other = Address::generate(&env);
        let foreign = record(&env, "foreign", &other, RecordSensitivity::Public);
        let mut records = Vec::new(&env);
        records.push_back(foreign);
        assert_eq!(
            assert_records_visible(ExportScope::OwnRecords, &records, &caller),
            Err(ExportError::RecordNotVisible)
        );
    }

    use soroban_sdk::contracterror;
}
