#![cfg(test)]

use soroban_sdk::{
    contract, contractimpl, symbol_short,
    testutils::{Address as _, Events as _},
    Address, Bytes, BytesN, Env, FromVal, Symbol,
};

use shared::audit_ledger::{
    anchor_count, entry_hash, export, get_anchor, get_entry, head, seal, verify_anchors,
    verify_range, AuditLedgerEntry, AuditLedgerKey, AuditTamperReason, MAX_AUDIT_EXPORT_ENTRIES,
};
use shared::auth::{grant_role, set_admin, Role};
use shared::errors::Error;
use shared::timeline::{
    record_action_audit_event, ResourceLink, TimelineEventType, DEFAULT_PAGE_SIZE,
};

#[contract]
pub struct DummyAuditContract;

#[contractimpl]
impl DummyAuditContract {
    pub fn noop(_env: Env) {}
}

struct Ctx {
    env: Env,
    id: Address,
    admin: Address,
    stranger: Address,
}

impl Ctx {
    /// Runs `f` in the registered contract's storage frame, which is where the
    /// ledger stores its entries. Production callers always run here.
    fn run<T>(&self, f: impl FnOnce() -> T) -> T {
        self.env.as_contract(&self.id, f)
    }
}

fn setup() -> Ctx {
    let env = Env::default();
    env.mock_all_auths_allowing_non_root_auth();
    let admin = Address::generate(&env);
    let stranger = Address::generate(&env);
    let id = env.register_contract(None, DummyAuditContract);
    env.as_contract(&id, || {
        set_admin(&env, &admin);
        grant_role(&env, &admin, &admin, Role::Admin).unwrap();
    });
    Ctx {
        env,
        id,
        admin,
        stranger,
    }
}

fn treasury_link(env: &Env) -> ResourceLink {
    ResourceLink {
        kind: Bytes::from_slice(env, b"treasury"),
        id: 0,
        revision: 0,
    }
}

fn deposit(ctx: &Ctx, before: i128, after: i128) -> AuditLedgerEntry {
    ctx.run(|| {
        record_action_audit_event(
            &ctx.env,
            &ctx.admin,
            TimelineEventType::RecordUpdated,
            treasury_link(&ctx.env),
            symbol_short!("treasury"),
            symbol_short!("deposit"),
            symbol_short!("funds_in"),
            None,
            Some(symbol_short!("reserve")),
            Some(before),
            Some(after),
        )
        .unwrap();
        let current = head(&ctx.env);
        get_entry(&ctx.env, current.count - 1).unwrap()
    })
}

fn withdraw(ctx: &Ctx, before: i128, after: i128) -> AuditLedgerEntry {
    ctx.run(|| {
        record_action_audit_event(
            &ctx.env,
            &ctx.admin,
            TimelineEventType::PaymentSent,
            treasury_link(&ctx.env),
            symbol_short!("treasury"),
            symbol_short!("withdraw"),
            symbol_short!("funds_out"),
            None,
            Some(symbol_short!("reserve")),
            Some(before),
            Some(after),
        )
        .unwrap();
        let current = head(&ctx.env);
        get_entry(&ctx.env, current.count - 1).unwrap()
    })
}

/// Overwrites a stored entry, simulating storage corruption or a malicious
/// migration with write access to the audit key space.
fn overwrite_entry(ctx: &Ctx, seq: u64, entry: &AuditLedgerEntry) {
    ctx.run(|| {
        ctx.env
            .storage()
            .persistent()
            .set(&AuditLedgerKey::Entry(seq), entry);
    });
}

fn remove_entry(ctx: &Ctx, seq: u64) {
    ctx.run(|| {
        ctx.env
            .storage()
            .persistent()
            .remove(&AuditLedgerKey::Entry(seq));
    });
}

fn overwrite_head(ctx: &Ctx, count: u64, hash: BytesN<32>) {
    ctx.run(|| {
        ctx.env.storage().persistent().set(
            &AuditLedgerKey::Head,
            &shared::audit_ledger::AuditLedgerHead {
                version: 1,
                count,
                head_hash: hash,
            },
        );
    });
}

fn zero_hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

// ---------------------------------------------------------------------------
// Chain construction
// ---------------------------------------------------------------------------

#[test]
fn empty_ledger_starts_at_genesis_and_verifies() {
    let ctx = setup();
    let current = ctx.run(|| head(&ctx.env));
    assert_eq!(current.version, 1);
    assert_eq!(current.count, 0);
    assert_eq!(current.head_hash, zero_hash(&ctx.env));

    let verification = ctx.run(|| verify_range(&ctx.env, 0, 10).unwrap());
    assert!(verification.ok);
    assert!(verification.complete);
    assert_eq!(verification.checked, 0);
    assert_eq!(verification.reason, AuditTamperReason::ChainIntact);

    let result = ctx.run(|| seal(&ctx.env));
    assert_eq!(result, Err(Error::NotFound));
}

#[test]
fn entries_are_hash_linked_and_advance_the_head() {
    let ctx = setup();
    let first = deposit(&ctx, 0, 100);
    let second = withdraw(&ctx, 100, 40);

    assert_eq!(first.seq, 0);
    assert_eq!(first.prev_hash, zero_hash(&ctx.env));
    assert_eq!(second.seq, 1);
    assert_eq!(second.prev_hash, first.hash);
    assert_ne!(first.hash, second.hash);

    let current = ctx.run(|| head(&ctx.env));
    assert_eq!(current.count, 2);
    assert_eq!(current.head_hash, second.hash);

    let verification = ctx.run(|| verify_range(&ctx.env, 0, 10).unwrap());
    assert!(verification.ok);
    assert!(verification.complete);
    assert_eq!(verification.checked, 2);
    assert_eq!(verification.head_hash, second.hash);
}

#[test]
fn action_audit_entries_are_recorded_with_full_context() {
    let ctx = setup();
    let entry = withdraw(&ctx, 500, 200);

    assert_eq!(entry.event_type, TimelineEventType::PaymentSent);
    assert_eq!(entry.actor, ctx.admin);
    assert_eq!(entry.scope, symbol_short!("treasury"));
    assert_eq!(entry.action, symbol_short!("withdraw"));
    assert_eq!(entry.reason, symbol_short!("funds_out"));
    assert_eq!(entry.attribute, Some(symbol_short!("reserve")));
    assert_eq!(entry.before, Some(500));
    assert_eq!(entry.after, Some(200));
    assert_eq!(entry.ledger, ctx.env.ledger().sequence());
    assert_eq!(entry.timestamp, ctx.env.ledger().timestamp());
}

#[test]
fn every_entry_publishes_external_seal_evidence() {
    let ctx = setup();
    let before = ctx.env.events().all().len();
    let entry = deposit(&ctx, 0, 25);
    let events = ctx.env.events().all();
    assert!(events.len() > before);

    let (_contract, topics, data) = events.get(events.len() - 3).unwrap();
    let topic: Symbol = FromVal::from_val(&ctx.env, &topics.get(1).unwrap());
    assert_eq!(topic, shared::audit_ledger::AUDIT_LEDGER_EVENT);

    let payload: (u64, BytesN<32>, BytesN<32>, u32) = FromVal::from_val(&ctx.env, &data);
    assert_eq!(payload.0, entry.seq);
    assert_eq!(payload.1, entry.hash);
    assert_eq!(payload.2, entry.prev_hash);
    assert_eq!(payload.3, entry.ledger);
}

// ---------------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------------

#[test]
fn editing_a_stored_field_is_detected() {
    let ctx = setup();
    deposit(&ctx, 0, 100);
    deposit(&ctx, 100, 250);
    let third = deposit(&ctx, 250, 400);

    let mut tampered = third;
    tampered.after = Some(4_000_000);
    overwrite_entry(&ctx, 2, &tampered);

    let verification = ctx.run(|| verify_range(&ctx.env, 0, 10).unwrap());
    assert!(!verification.ok);
    assert_eq!(verification.reason, AuditTamperReason::EntryHashMismatch);
    assert_eq!(verification.first_bad_seq, Some(2));
}

#[test]
fn deleting_a_middle_entry_is_detected() {
    let ctx = setup();
    deposit(&ctx, 0, 1);
    deposit(&ctx, 1, 2);
    deposit(&ctx, 2, 3);

    remove_entry(&ctx, 1);

    let verification = ctx.run(|| verify_range(&ctx.env, 0, 10).unwrap());
    assert!(!verification.ok);
    assert_eq!(verification.reason, AuditTamperReason::MissingEntry);
    assert_eq!(verification.first_bad_seq, Some(1));
}

#[test]
fn reordering_entries_is_detected() {
    let ctx = setup();
    deposit(&ctx, 0, 1);
    deposit(&ctx, 1, 2);
    let third = deposit(&ctx, 2, 3);

    // Move entry 2 into slot 1 and recompute its hash so the attacker's copy is
    // internally consistent. The prev_hash link still points at entry 1, which
    // is no longer the predecessor at that position.
    let mut moved = third;
    moved.seq = 1;
    moved.hash = ctx.run(|| entry_hash(&ctx.env, &moved));
    overwrite_entry(&ctx, 1, &moved);

    let verification = ctx.run(|| verify_range(&ctx.env, 0, 10).unwrap());
    assert!(!verification.ok);
    assert_eq!(verification.reason, AuditTamperReason::PrevHashMismatch);
    assert_eq!(verification.first_bad_seq, Some(1));
}

#[test]
fn tampering_with_the_sequence_number_is_detected() {
    let ctx = setup();
    deposit(&ctx, 0, 1);
    let mut second = deposit(&ctx, 1, 2);
    second.seq = 9;
    second.hash = ctx.run(|| entry_hash(&ctx.env, &second));
    overwrite_entry(&ctx, 1, &second);

    let verification = ctx.run(|| verify_range(&ctx.env, 0, 10).unwrap());
    assert!(!verification.ok);
    assert_eq!(verification.reason, AuditTamperReason::UnexpectedSequence);
    assert_eq!(verification.first_bad_seq, Some(1));
}

#[test]
fn unsupported_entry_version_is_rejected() {
    let ctx = setup();
    deposit(&ctx, 0, 1);
    let mut second = deposit(&ctx, 1, 2);
    second.version = 2;
    second.hash = ctx.run(|| entry_hash(&ctx.env, &second));
    overwrite_entry(&ctx, 1, &second);

    let verification = ctx.run(|| verify_range(&ctx.env, 0, 10).unwrap());
    assert!(!verification.ok);
    assert_eq!(verification.reason, AuditTamperReason::UnsupportedVersion);
    assert_eq!(verification.first_bad_seq, Some(1));
}

#[test]
fn truncating_the_tail_is_detected() {
    let ctx = setup();
    deposit(&ctx, 0, 1);
    deposit(&ctx, 1, 2);
    deposit(&ctx, 2, 3);

    // A rollback that drops the last entry without touching the head leaves a
    // gap the range scan must report.
    remove_entry(&ctx, 2);

    let verification = ctx.run(|| verify_range(&ctx.env, 0, 10).unwrap());
    assert!(!verification.ok);
    assert_eq!(verification.reason, AuditTamperReason::MissingEntry);
    assert_eq!(verification.first_bad_seq, Some(2));
}

#[test]
fn consistent_tail_truncation_is_detected_by_an_anchor() {
    let ctx = setup();
    deposit(&ctx, 0, 1);
    deposit(&ctx, 1, 2);
    let third = deposit(&ctx, 2, 3);

    let anchor = ctx.run(|| seal(&ctx.env).unwrap());
    assert_eq!(anchor.seq, 3);
    assert_eq!(anchor.hash, third.hash);

    // Attacker removes the tail *and* rewrites the head so the remaining chain
    // is internally consistent. The anchor still remembers three entries.
    remove_entry(&ctx, 2);
    let second = ctx.run(|| get_entry(&ctx.env, 1).unwrap());
    overwrite_head(&ctx, 2, second.hash.clone());

    let chain = ctx.run(|| verify_range(&ctx.env, 0, 10).unwrap());
    assert!(chain.ok, "a truncated chain can look internally consistent");

    let anchors = ctx.run(|| verify_anchors(&ctx.env, 0, 10).unwrap());
    assert!(!anchors.ok);
    assert_eq!(anchors.reason, AuditTamperReason::AnchorMismatch);
    assert_eq!(anchors.first_bad_id, Some(0));
}

#[test]
fn edited_anchor_is_detected() {
    let ctx = setup();
    deposit(&ctx, 0, 1);
    deposit(&ctx, 1, 2);
    let anchor = ctx.run(|| seal(&ctx.env).unwrap());
    assert_eq!(ctx.run(|| anchor_count(&ctx.env)), 1);

    let mut tampered = anchor;
    tampered.hash = zero_hash(&ctx.env);
    ctx.run(|| {
        ctx.env
            .storage()
            .persistent()
            .set(&AuditLedgerKey::Anchor(0), &tampered);
    });

    let anchors = ctx.run(|| verify_anchors(&ctx.env, 0, 10).unwrap());
    assert!(!anchors.ok);
    assert_eq!(anchors.reason, AuditTamperReason::AnchorMismatch);
    assert_eq!(anchors.first_bad_id, Some(0));

    let stored = ctx.run(|| get_anchor(&ctx.env, 0).unwrap());
    assert_eq!(stored.hash, zero_hash(&ctx.env));
}

// ---------------------------------------------------------------------------
// Hash coverage
// ---------------------------------------------------------------------------

#[test]
fn hash_is_position_dependent_and_covers_optional_fields() {
    let ctx = setup();
    let base = deposit(&ctx, 1, 2);

    let base_hash = ctx.run(|| entry_hash(&ctx.env, &base));

    let mut swapped = base.clone();
    swapped.before = Some(2);
    swapped.after = Some(1);
    assert_ne!(ctx.run(|| entry_hash(&ctx.env, &swapped)), base_hash);

    let mut scope_swapped = base.clone();
    scope_swapped.scope = base.action.clone();
    scope_swapped.action = base.scope.clone();
    assert_ne!(ctx.run(|| entry_hash(&ctx.env, &scope_swapped)), base_hash);

    let mut no_attribute = base.clone();
    no_attribute.attribute = None;
    assert_ne!(ctx.run(|| entry_hash(&ctx.env, &no_attribute)), base_hash);

    let mut no_resource = base.clone();
    no_resource.resource = Some(Address::generate(&ctx.env));
    assert_ne!(ctx.run(|| entry_hash(&ctx.env, &no_resource)), base_hash);

    let mut next_ledger = base.clone();
    next_ledger.ledger = base.ledger + 1;
    assert_ne!(ctx.run(|| entry_hash(&ctx.env, &next_ledger)), base_hash);

    let mut other_prev = base.clone();
    other_prev.prev_hash = BytesN::from_array(&ctx.env, &[9u8; 32]);
    assert_ne!(ctx.run(|| entry_hash(&ctx.env, &other_prev)), base_hash);
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

#[test]
fn export_is_paged_and_off_chain_verifiable() {
    let ctx = setup();
    for i in 0..5 {
        deposit(&ctx, i, i + 1);
    }
    let current = ctx.run(|| head(&ctx.env));

    let mut collected: soroban_sdk::Vec<AuditLedgerEntry> = soroban_sdk::Vec::new(&ctx.env);
    let mut cursor = None;
    loop {
        let page = ctx.run(|| export(&ctx.env, &ctx.admin, cursor, 2).unwrap());
        assert_eq!(page.head_seq, current.count);
        assert_eq!(page.head_hash, current.head_hash);
        assert!(page.entries.len() <= 2);
        for entry in page.entries.iter() {
            collected.push_back(entry);
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    assert_eq!(collected.len(), 5);

    // Verify the export exactly as an off-chain consumer would: recompute each
    // hash, follow prev_hash, and compare the last hash with the head.
    let mut previous = zero_hash(&ctx.env);
    for i in 0..collected.len() {
        let entry = collected.get(i).unwrap();
        assert_eq!(entry.seq, i as u64);
        assert_eq!(entry.prev_hash, previous);
        assert_eq!(ctx.run(|| entry_hash(&ctx.env, &entry)), entry.hash);
        previous = entry.hash;
    }
    assert_eq!(previous, current.head_hash);
}

#[test]
fn export_requires_a_maintainer_and_bounds_the_page() {
    let ctx = setup();
    deposit(&ctx, 0, 1);

    let denied = ctx.run(|| export(&ctx.env, &ctx.stranger, None, DEFAULT_PAGE_SIZE));
    assert_eq!(denied, Err(Error::Unauthorized));

    let too_large = ctx.run(|| export(&ctx.env, &ctx.admin, None, MAX_AUDIT_EXPORT_ENTRIES + 1));
    assert_eq!(too_large, Err(Error::InvalidArgument));

    let beyond_head = ctx.run(|| export(&ctx.env, &ctx.admin, Some(5), 2));
    assert_eq!(beyond_head, Err(Error::InvalidArgument));
}

// ---------------------------------------------------------------------------
// Paged verification
// ---------------------------------------------------------------------------

#[test]
fn verification_can_resume_from_a_cursor() {
    let ctx = setup();
    for i in 0..6 {
        deposit(&ctx, i, i + 1);
    }

    let first = ctx.run(|| verify_range(&ctx.env, 0, 2).unwrap());
    assert!(!first.ok);
    assert!(!first.complete);
    assert_eq!(first.checked, 2);
    assert_eq!(first.resume_at, Some(2));

    let second = ctx.run(|| verify_range(&ctx.env, first.resume_at.unwrap(), 10).unwrap());
    assert!(second.ok);
    assert!(second.complete);
    assert_eq!(second.from_seq, 2);
    assert_eq!(second.checked, 4);
}
