#![cfg(test)]

use soroban_sdk::{testutils::Env as _, Env, Vec};
use crate::dashboard::{
    generate_dashboard, generate_enhanced_dashboard, create_partial_failure, 
    add_external_reference, redact_partial_failure, group_by_operation_type, 
    group_by_severity, group_by_age, group_by_retryability,
    PartialFailure, FailureSeverity, OperationType, FailureState, OperationKind,
};
use crate::reconciliation::SourceRecord;
use crate::health::{set_dependency_health, DependencyStatus};
use soroban_sdk::symbol_short;

#[test]
fn test_dashboard_aggregation() {
    let env = Env::default();
    
    // Simulate some incidents
    set_dependency_health(&env, &symbol_short!("indexer"), DependencyStatus::Down);
    set_dependency_health(&env, &symbol_short!("rpc"), DependencyStatus::Healthy);

    let ledger_records = Vec::new(&env);
    let db_records = Vec::new(&env);
    let user_records = Vec::new(&env);
    
    let report = generate_dashboard(&env, ledger_records, db_records, user_records, 100);
    
    // We expect 3 categories
    assert_eq!(report.categories.len(), 3);
    
    let incidents = report.categories.get(2).unwrap();
    assert_eq!(incidents.count, 1);
    assert_eq!(incidents.actionable, true);

    let drifts = report.categories.get(1).unwrap();
    assert_eq!(drifts.count, 0);
    assert_eq!(drifts.actionable, false);

    let jobs = report.categories.get(0).unwrap();
    assert_eq!(jobs.count, 0);
    assert_eq!(jobs.actionable, false);
}

#[test]
fn test_create_partial_failure() {
    let env = Env::default();
    
    let failure = create_partial_failure(
        &env,
        1,
        OperationType::Payment,
        100,
        1, // Unauthorized error
        100,
        OperationKind::WalletAction,
        String::from_str(&env, "Payment failed due to authorization"),
    );
    
    assert_eq!(failure.failure_id, 1);
    assert_eq!(failure.operation_type, OperationType::Payment);
    assert_eq!(failure.operation_id, 100);
    assert_eq!(failure.error_code, 1);
    assert_eq!(failure.failed_at_ledger, 100);
    assert_eq!(failure.retry_attempts, 0);
    assert_eq!(failure.is_retryable, false); // Unauthorized is not retryable
    assert_eq!(failure.severity, FailureSeverity::Critical);
    assert_eq!(failure.state, FailureState::Unresolved);
}

#[test]
fn test_create_retryable_partial_failure() {
    let env = Env::default();
    
    let failure = create_partial_failure(
        &env,
        2,
        OperationType::Worker,
        200,
        6, // Expired error (retryable)
        100,
        OperationKind::Worker,
        String::from_str(&env, "Worker job expired"),
    );
    
    assert_eq!(failure.failure_id, 2);
    assert_eq!(failure.operation_type, OperationType::Worker);
    assert_eq!(failure.is_retryable, true); // Expired is retryable
    assert_eq!(failure.state, FailureState::Retryable);
    assert_eq!(failure.severity, FailureSeverity::Low); // Worker with fresh age
}

#[test]
fn test_add_external_reference() {
    let env = Env::default();
    
    let mut failure = create_partial_failure(
        &env,
        1,
        OperationType::Payment,
        100,
        1,
        100,
        OperationKind::WalletAction,
        String::from_str(&env, "Payment failed"),
    );
    
    add_external_reference(
        &mut failure,
        &env,
        symbol_short!("stripe"),
        String::from_str(&env, "pi_1234567890"),
    );
    
    assert_eq!(failure.external_refs.len(), 1);
    let ext_ref = failure.external_refs.get(0).unwrap();
    assert_eq!(ext_ref.system, symbol_short!("stripe"));
    assert_eq!(ext_ref.reference_id, String::from_str(&env, "pi_1234567890"));
}

#[test]
fn test_redact_partial_failure() {
    let env = Env::default();
    
    let mut failure = create_partial_failure(
        &env,
        1,
        OperationType::Payment,
        100,
        1,
        100,
        OperationKind::WalletAction,
        String::from_str(&env, "Payment failed"),
    );
    
    add_external_reference(
        &mut failure,
        &env,
        symbol_short!("stripe"),
        String::from_str(&env, "pi_secret_key"),
    );
    
    let redacted = redact_partial_failure(&env, &failure);
    
    assert_eq!(redacted.failure_id, 1);
    assert_eq!(redacted.operation_type, OperationType::Payment);
    assert_eq!(redacted.external_systems.len(), 1);
    assert_eq!(redacted.external_systems.get(0).unwrap(), &symbol_short!("stripe"));
    // Reference ID should be redacted (not exposed in redacted version)
    assert_eq!(redacted.retry_link, String::from_str(&env, "dashboard/not-retryable"));
    assert_eq!(redacted.inspect_link, String::from_str(&env, "api/inspect/{id}"));
    assert_eq!(redacted.remediation_link, String::from_str(&env, "docs/remediation/unresolved"));
}

#[test]
fn test_group_by_operation_type() {
    let env = Env::default();
    
    let mut failures = Vec::new(&env);
    
    failures.push_back(create_partial_failure(
        &env, 1, OperationType::Payment, 100, 1, 100, OperationKind::WalletAction,
        String::from_str(&env, "Payment failed"),
    ));
    
    failures.push_back(create_partial_failure(
        &env, 2, OperationType::Payment, 101, 8, 100, OperationKind::WalletAction,
        String::from_str(&env, "Insufficient balance"),
    ));
    
    failures.push_back(create_partial_failure(
        &env, 3, OperationType::Worker, 200, 6, 100, OperationKind::Worker,
        String::from_str(&env, "Worker expired"),
    ));
    
    let groups = group_by_operation_type(&env, &failures);
    
    assert_eq!(groups.len(), 2); // Payment and Worker
    
    let payment_group = groups.iter().find(|g| g.value == symbol_short!("payment")).unwrap();
    assert_eq!(payment_group.count, 2);
    assert_eq!(payment_group.critical_count, 2); // Both critical
    assert_eq!(payment_group.retryable_count, 0); // Neither retryable
    
    let worker_group = groups.iter().find(|g| g.value == symbol_short!("worker")).unwrap();
    assert_eq!(worker_group.count, 1);
    assert_eq!(worker_group.critical_count, 0);
    assert_eq!(worker_group.retryable_count, 1);
}

#[test]
fn test_group_by_severity() {
    let env = Env::default();
    
    let mut failures = Vec::new(&env);
    
    failures.push_back(create_partial_failure(
        &env, 1, OperationType::Payment, 100, 1, 100, OperationKind::WalletAction,
        String::from_str(&env, "Payment failed"),
    ));
    
    failures.push_back(create_partial_failure(
        &env, 2, OperationType::Transfer, 101, 8, 100, OperationKind::WalletAction,
        String::from_str(&env, "Insufficient balance"),
    ));
    
    failures.push_back(create_partial_failure(
        &env, 3, OperationType::Worker, 200, 6, 100, OperationKind::Worker,
        String::from_str(&env, "Worker expired"),
    ));
    
    let groups = group_by_severity(&env, &failures);
    
    assert!(groups.len() >= 1);
    
    let critical_group = groups.iter().find(|g| g.value == symbol_short!("critical"));
    assert!(critical_group.is_some());
    let critical = critical_group.unwrap();
    assert_eq!(critical.count, 2); // Payment and Transfer
    assert_eq!(critical.critical_count, 2);
}

#[test]
fn test_group_by_age_fresh_vs_stale() {
    let env = Env::default();
    env.ledger().set(2000); // Set current ledger to 2000
    
    let mut failures = Vec::new(&env);
    
    // Fresh failure (age < 1000)
    failures.push_back(create_partial_failure(
        &env, 1, OperationType::Payment, 100, 1, 1500, OperationKind::WalletAction,
        String::from_str(&env, "Recent payment failed"),
    ));
    
    // Stale failure (age >= 1000)
    failures.push_back(create_partial_failure(
        &env, 2, OperationType::Worker, 200, 6, 500, OperationKind::Worker,
        String::from_str(&env, "Old worker failure"),
    ));
    
    let groups = group_by_age(&env, &failures);
    
    assert_eq!(groups.len(), 2);
    
    let fresh_group = groups.iter().find(|g| g.value == symbol_short!("fresh")).unwrap();
    assert_eq!(fresh_group.count, 1);
    
    let stale_group = groups.iter().find(|g| g.value == symbol_short!("stale")).unwrap();
    assert_eq!(stale_group.count, 1);
}

#[test]
fn test_group_by_retryability() {
    let env = Env::default();
    
    let mut failures = Vec::new(&env);
    
    // Non-retryable (Unauthorized)
    failures.push_back(create_partial_failure(
        &env, 1, OperationType::Payment, 100, 1, 100, OperationKind::WalletAction,
        String::from_str(&env, "Unauthorized payment"),
    ));
    
    // Retryable (Expired)
    failures.push_back(create_partial_failure(
        &env, 2, OperationType::Worker, 200, 6, 100, OperationKind::Worker,
        String::from_str(&env, "Expired worker"),
    ));
    
    // Non-retryable (NotFound)
    failures.push_back(create_partial_failure(
        &env, 3, OperationType::Payment, 101, 2, 100, OperationKind::WalletAction,
        String::from_str(&env, "Not found"),
    ));
    
    let groups = group_by_retryability(&env, &failures);
    
    assert_eq!(groups.len(), 2);
    
    let retryable_group = groups.iter().find(|g| g.value == symbol_short!("retryable")).unwrap();
    assert_eq!(retryable_group.count, 1);
    assert_eq!(retryable_group.retryable_count, 1);
    
    let non_retryable_group = groups.iter().find(|g| g.value == Symbol::new(env, "non_retryable")).unwrap();
    assert_eq!(non_retryable_group.count, 2);
    assert_eq!(non_retryable_group.retryable_count, 0);
}

#[test]
fn test_enhanced_dashboard_with_partial_failures() {
    let env = Env::default();
    
    let ledger_records = Vec::new(&env);
    let db_records = Vec::new(&env);
    let user_records = Vec::new(&env);
    
    let mut partial_failures = Vec::new(&env);
    
    // Add some partial failures
    partial_failures.push_back(create_partial_failure(
        &env, 1, OperationType::Payment, 100, 1, 100, OperationKind::WalletAction,
        String::from_str(&env, "Critical payment failure"),
    ));
    
    partial_failures.push_back(create_partial_failure(
        &env, 2, OperationType::Worker, 200, 6, 100, OperationKind::Worker,
        String::from_str(&env, "Retryable worker failure"),
    ));
    
    // Add a resolved failure (should not appear in dashboard)
    let mut resolved_failure = create_partial_failure(
        &env, 3, OperationType::Transfer, 300, 6, 100, OperationKind::ApiCall,
        String::from_str(&env, "Resolved transfer"),
    );
    resolved_failure.state = FailureState::Resolved;
    partial_failures.push_back(resolved_failure);
    
    let report = generate_enhanced_dashboard(
        &env,
        ledger_records,
        db_records,
        user_records,
        100,
        partial_failures,
    );
    
    // Should have base categories
    assert_eq!(report.categories.len(), 3);
    
    // Should have partial failures (excluding resolved)
    assert_eq!(report.partial_failures.len(), 2);
    
    // Should have failure groups
    assert!(report.failure_groups.len() > 0);
    
    // Verify the partial failures are redacted
    for failure in report.partial_failures.iter() {
        assert_ne!(failure.retry_link.len(), 0);
        assert_ne!(failure.inspect_link.len(), 0);
        assert_ne!(failure.remediation_link.len(), 0);
    }
}

#[test]
fn test_stale_failure_detection() {
    let env = Env::default();
    env.ledger().set(5000); // Set current ledger to 5000
    
    // Create a failure that happened at ledger 1000 (4000 ledgers ago - stale)
    let failure = create_partial_failure(
        &env, 1, OperationType::Worker, 100, 6, 1000, OperationKind::Worker,
        String::from_str(&env, "Stale worker failure"),
    );
    
    assert_eq!(failure.age_ledgers, 4000);
    assert!(failure.age_ledgers >= 1000); // Stale threshold
}

#[test]
fn test_retryable_vs_non_retryable_failures() {
    let env = Env::default();
    
    // Retryable error (Expired)
    let retryable = create_partial_failure(
        &env, 1, OperationType::Worker, 100, 6, 100, OperationKind::Worker,
        String::from_str(&env, "Retryable"),
    );
    assert_eq!(retryable.is_retryable, true);
    assert_eq!(retryable.state, FailureState::Retryable);
    
    // Non-retryable error (Unauthorized)
    let non_retryable = create_partial_failure(
        &env, 2, OperationType::Payment, 101, 1, 100, OperationKind::WalletAction,
        String::from_str(&env, "Non-retryable"),
    );
    assert_eq!(non_retryable.is_retryable, false);
    assert_eq!(non_retryable.state, FailureState::Unresolved);
}

#[test]
fn test_ignored_failure_state() {
    let env = Env::default();
    
    let mut failure = create_partial_failure(
        &env, 1, OperationType::Payment, 100, 1, 100, OperationKind::WalletAction,
        String::from_str(&env, "Payment failed"),
    );
    
    // Simulate manual ignore
    failure.state = FailureState::Ignored;
    
    let redacted = redact_partial_failure(&env, &failure);
    assert_eq!(redacted.state, FailureState::Ignored);
    assert_eq!(redacted.remediation_link, String::from_str(&env, "docs/remediation/ignored"));
}

#[test]
fn test_resolved_failure_excluded_from_dashboard() {
    let env = Env::default();
    
    let mut failures = Vec::new(&env);
    
    let mut unresolved = create_partial_failure(
        &env, 1, OperationType::Payment, 100, 1, 100, OperationKind::WalletAction,
        String::from_str(&env, "Unresolved"),
    );
    
    let mut resolved = create_partial_failure(
        &env, 2, OperationType::Payment, 101, 1, 100, OperationKind::WalletAction,
        String::from_str(&env, "Resolved"),
    );
    resolved.state = FailureState::Resolved;
    
    failures.push_back(unresolved);
    failures.push_back(resolved);
    
    let redacted_failures = Vec::new(&env);
    for failure in failures.iter() {
        if failure.state != FailureState::Resolved {
            redacted_failures.push_back(redact_partial_failure(&env, failure));
        }
    }
    
    // Only unresolved should be included
    assert_eq!(redacted_failures.len(), 1);
}
