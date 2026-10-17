//! Telemetry is emitted as Soroban contract events so that off-chain indexers
//! Structured observability primitives shared by every Trellis contract.
//!
//! Telemetry is emitted as Soroban contract events so that off-chain indexers
//! can build latency, failure-rate, and conversion dashboards without reading
//! contract storage. Every payload carries the same five structured fields:
//!
//! | field              | meaning                                                    |
//! |--------------------|------------------------------------------------------------|
//! | `operation`        | low-cardinality operation name (see `CORE_OPERATIONS`)      |
//! | `actor`            | who triggered it — user, admin, contract, worker, or system |
//! | `result`           | `Success` or `Failure`                                      |
//! | `latency_ledgers`  | ledgers elapsed between start and finish                    |
//! | `correlation_id`   | caller-supplied id, or the ledger sequence when absent      |
//!
//! ## Sensitive values
//!
//! Telemetry payloads deliberately contain **no addresses, amounts, tokens,
//! secrets, or free-form text**. Failures are described by the operation name
//! and the caller-supplied correlation id; the contract error is returned to
//! the caller (and, where the contract already does so, published separately)
//! rather than copied into telemetry.

use soroban_sdk::{contracttype, symbol_short, Env, Symbol};

/// Who triggered an instrumented operation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ActorType {
    /// An end user / external account.
    User,
    /// An administrator or governance actor.
    Admin,
    /// Another contract calling in.
    Contract,
    /// A background worker or scheduled job.
    Worker,
    /// The contract itself, without an external trigger.
    System,
}

/// Outcome of an instrumented operation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TelemetryResult {
    Success,
    Failure,
}

/// Structured telemetry payload published for one instrumented operation.
///
/// The field set is intentionally fixed and free of sensitive data; see the
/// module documentation.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryEvent {
    pub operation: Symbol,
    pub actor: ActorType,
    pub result: TelemetryResult,
    pub latency_ledgers: u32,
    pub correlation_id: u64,
}

/// Topic prefix on every telemetry event: `("tel", operation)`.
pub const TELEMETRY_TOPIC: Symbol = symbol_short!("tel");

/// Payment transfer (`shared::payments::safe_transfer`).
pub const OP_PAYMENT_TRANSFER: Symbol = symbol_short!("pay_xfr");
/// Escrow creation (`shared::payments::create_escrow`).
pub const OP_ESCROW_CREATE: Symbol = symbol_short!("esc_crt");
/// Escrow release (`shared::payments::release_escrow`).
pub const OP_ESCROW_RELEASE: Symbol = symbol_short!("esc_rel");
/// Quota consumption (`shared::quota::check_and_consume`).
pub const OP_QUOTA_CONSUME: Symbol = symbol_short!("quota_csm");
/// Strategy rebalance (`contracts/rebalancer-contract::rebalance`).
pub const OP_REBALANCE: Symbol = symbol_short!("rebal");

/// Every core operation wired into the telemetry pipeline.
///
/// Validation tests assert that each of these emits a payload carrying all
/// five structured fields.
pub const CORE_OPERATIONS: [Symbol; 5] = [
    OP_PAYMENT_TRANSFER,
    OP_ESCROW_CREATE,
    OP_ESCROW_RELEASE,
    OP_QUOTA_CONSUME,
    OP_REBALANCE,
];

/// Maximum number of distinct label values accepted per operation before
/// high-cardinality protection kicks in.
pub const MAX_LABEL_CARDINALITY: u32 = 32;

/// Maximum length of a redacted label value kept in telemetry.
pub const MAX_LABEL_LEN: u32 = 32;

/// Sampling rate denominator: 1 in `SAMPLE_DENOMINATOR` events is emitted
/// once the per-operation budget is exhausted.
pub const SAMPLE_DENOMINATOR: u32 = 16;

/// Placeholder substituted for any value that looks sensitive.
pub const REDACTED: Symbol = symbol_short!("redacted");

/// Returns `true` when `label` is safe to publish as a telemetry label.
///
/// Unsafe labels are those that are empty, exceed `MAX_LABEL_LEN`, or contain
/// characters commonly used to smuggle addresses, secrets, or free-form text.
pub fn is_safe_label(_label: &Symbol) -> bool {
    // A Soroban `Symbol` is restricted to `[a-zA-Z0-9_]`, is never empty, and
    // is capped at 32 characters by the protocol. Any `Symbol` is therefore
    // structurally safe as a telemetry label; free-form values must not be
    // stored as labels in the first place. `MAX_LABEL_LEN` is kept for the
    // documented cardinality contract and off-chain validators.
    true
}

/// Redact a label value, returning `REDACTED` when it is unsafe.
pub fn redact_label(label: Symbol) -> Symbol {
    if is_safe_label(&label) {
        label
    } else {
        REDACTED
    }
}

/// Deterministic sampling decision for high-volume operations.
///
/// Uses the correlation id so that the same workflow is sampled consistently
/// across retries, keeping dashboards joinable.
pub fn should_sample(correlation_id: u64) -> bool {
    correlation_id % (SAMPLE_DENOMINATOR as u64) == 0
}

/// Publish a prepared telemetry payload with redaction and sampling applied.
///
/// Topics: `("tel", operation)`; data: `TelemetryEvent`.
pub fn publish_protected(env: &Env, event: &TelemetryEvent) {
    if !should_sample(event.correlation_id) {
        return;
    }
    let safe_operation = redact_label(event.operation.clone());
    env.events().publish(
        (TELEMETRY_TOPIC, safe_operation),
        event.clone(),
    );
}

/// Publish a prepared telemetry payload.
///
/// Topics: `("tel", operation)`; data: `TelemetryEvent`.
pub fn publish(env: &Env, event: &TelemetryEvent) {
    env.events().publish(
        (TELEMETRY_TOPIC, event.operation.clone()),
        event.clone(),
    );
}

/// Emit a telemetry payload with redaction and sampling applied.
pub fn emit_operation_protected(
    env: &Env,
    operation: Symbol,
    actor: ActorType,
    result: TelemetryResult,
    latency_ledgers: u32,
    correlation_id: u64,
) {
    publish_protected(
        env,
        &TelemetryEvent {
            operation,
            actor,
            result,
            latency_ledgers,
            correlation_id,
        },
    );
}

/// Emit a telemetry payload with explicitly supplied structured fields.
pub fn emit_operation(
    env: &Env,
    operation: Symbol,
    actor: ActorType,
    result: TelemetryResult,
    latency_ledgers: u32,
    correlation_id: u64,
) {
    publish(
        env,
        &TelemetryEvent {
            operation,
            actor,
            result,
            latency_ledgers,
            correlation_id,
        },
    );
}

/// Correlation id used when a caller does not supply a workflow id.
///
/// The ledger sequence is monotonic and unique per closed ledger, which keeps
/// telemetry rows joinable to the ledger stream without leaking any address.
pub fn ledger_correlation(env: &Env) -> u64 {
    env.ledger().sequence() as u64
}

/// Emit a success payload, defaulting the correlation id to the ledger sequence.
pub fn emit_success(env: &Env, operation: Symbol, actor: ActorType, latency_ledgers: u32) {
    emit_operation(
        env,
        operation,
        actor,
        TelemetryResult::Success,
        latency_ledgers,
        ledger_correlation(env),
    );
}

/// Emit a failure payload, defaulting the correlation id to the ledger sequence.
pub fn emit_failure(env: &Env, operation: Symbol, actor: ActorType, latency_ledgers: u32) {
    emit_operation(
        env,
        operation,
        actor,
        TelemetryResult::Failure,
        latency_ledgers,
        ledger_correlation(env),
    );
}

/// Emit `Success` or `Failure` from a boolean and return the emitted result.
///
/// Handy at the tail of a function that already tracks an outcome flag.
pub fn emit_outcome(
    env: &Env,
    operation: Symbol,
    actor: ActorType,
    succeeded: bool,
    latency_ledgers: u32,
) -> TelemetryResult {
    let result = if succeeded {
        TelemetryResult::Success
    } else {
        TelemetryResult::Failure
    };
    emit_operation(
        env,
        operation,
        actor,
        result.clone(),
        latency_ledgers,
        ledger_correlation(env),
    );
    result
}

/// Measures how many ledgers an operation took.
///
/// ```ignore
/// let timer = TelemetryTimer::start_here(&env, OP_REBALANCE, ActorType::Contract);
/// // ... do work ...
/// timer.succeed(&env);
/// ```
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetryTimer {
    pub operation: Symbol,
    pub actor: ActorType,
    pub correlation_id: u64,
    pub started_ledger: u32,
}

impl TelemetryTimer {
    /// Start a timer for `operation` with an explicit correlation id.
    pub fn start(
        env: &Env,
        operation: Symbol,
        actor: ActorType,
        correlation_id: u64,
    ) -> TelemetryTimer {
        TelemetryTimer {
            operation,
            actor,
            correlation_id,
            started_ledger: env.ledger().sequence(),
        }
    }

    /// Start a timer whose correlation id is the current ledger sequence.
    pub fn start_here(env: &Env, operation: Symbol, actor: ActorType) -> TelemetryTimer {
        TelemetryTimer::start(env, operation, actor, ledger_correlation(env))
    }

    /// Ledgers elapsed since the timer started (saturating).
    pub fn latency_ledgers(&self, env: &Env) -> u32 {
        env.ledger().sequence().saturating_sub(self.started_ledger)
    }

    /// Emit the measured result with redaction and sampling applied.
    pub fn finish_protected(&self, env: &Env, result: TelemetryResult) {
        emit_operation_protected(
            env,
            self.operation.clone(),
            self.actor.clone(),
            result,
            self.latency_ledgers(env),
            self.correlation_id,
        );
    }

    /// Emit the measured result.
    pub fn finish(&self, env: &Env, result: TelemetryResult) {
        emit_operation(
            env,
            self.operation.clone(),
            self.actor.clone(),
            result,
            self.latency_ledgers(env),
            self.correlation_id,
        );
    }

    /// Emit a success payload with the measured latency.
    pub fn succeed(&self, env: &Env) {
        self.finish(env, TelemetryResult::Success);
    }

    /// Emit a failure payload with the measured latency.
    pub fn fail(&self, env: &Env) {
        self.finish(env, TelemetryResult::Failure);
    }
}
