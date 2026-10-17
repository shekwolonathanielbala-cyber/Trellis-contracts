//! End-to-end coverage for the treasury audit-ledger entrypoints.
//!
//! The ledger itself is unit-tested in `shared/tests/audit_ledger.rs`; this
//! test proves the real financial paths (deposit, withdraw, emergency
//! withdrawal, initialisation) are sealed into the chain and that the
//! exported/verifiable surface works through the deployed contract interface.

use shared::audit_ledger::{get_entry, AuditLedgerKey, AuditTamperReason, AUDIT_LEDGER_VERSION};
use soroban_sdk::{symbol_short, testutils::Address as _, token, Address, Env};
use treasury_contract::{TreasuryContract, TreasuryContractClient};

struct Ctx {
    env: Env,
    id: Address,
    admin: Address,
    token: Address,
    reserve: soroban_sdk::Symbol,
}

impl Ctx {
    fn client(&self) -> TreasuryContractClient<'_> {
        TreasuryContractClient::new(&self.env, &self.id)
    }
}

fn setup() -> Ctx {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.initialize(&admin, &1_000);

    let asset = env.register_stellar_asset_contract_v2(admin.clone());
    let token = asset.address();
    let asset_client = token::StellarAssetClient::new(&env, &token);
    asset_client.mint(&admin, &10_000);

    Ctx {
        env,
        id,
        admin,
        token,
        reserve: symbol_short!("reserve"),
    }
}

fn fund_and_spend(ctx: &Ctx) {
    ctx.client()
        .deposit(&ctx.admin, &ctx.token, &ctx.reserve, &500);
    ctx.client()
        .withdraw(&ctx.admin, &ctx.token, &ctx.admin, &100, &ctx.reserve);
}

#[test]
fn privileged_and_financial_actions_are_sealed_into_one_chain() {
    let ctx = setup();
    fund_and_spend(&ctx);
    ctx.env.as_contract(&ctx.id, || {
        shared::storage::set_paused(&ctx.env, true);
    });
    ctx.client()
        .emergency_withdraw(&ctx.admin, &ctx.token, &ctx.admin, &50);

    // Initialise, deposit, withdraw and emergency-withdraw each record one
    // structured action audit entry, and each of those is sealed.
    let head = ctx.client().audit_ledger_head();
    assert_eq!(head.version, AUDIT_LEDGER_VERSION);
    assert_eq!(head.count, 4);

    let verification = ctx.client().verify_audit_ledger(&0, &10);
    assert!(verification.ok);
    assert!(verification.complete);
    assert_eq!(verification.checked, 4);
    assert_eq!(verification.head_hash, head.head_hash);
    assert_eq!(verification.reason, AuditTamperReason::ChainIntact);

    let first = ctx
        .env
        .as_contract(&ctx.id, || get_entry(&ctx.env, 0).unwrap());
    let second = ctx
        .env
        .as_contract(&ctx.id, || get_entry(&ctx.env, 1).unwrap());
    assert_eq!(
        first.prev_hash,
        soroban_sdk::BytesN::from_array(&ctx.env, &[0; 32])
    );
    assert_eq!(second.prev_hash, first.hash);
    assert_eq!(first.scope, symbol_short!("treasury"));
    assert_eq!(second.action, symbol_short!("deposit"));
    assert_eq!(first.event_type, shared::TimelineEventType::ConfigChanged);
    assert_eq!(second.event_type, shared::TimelineEventType::RecordUpdated);
}

#[test]
fn maintainers_can_export_a_paged_chain_that_verifies_off_chain() {
    let ctx = setup();
    fund_and_spend(&ctx);

    let head = ctx.client().audit_ledger_head();
    let mut cursor: Option<u64> = None;
    let mut entries = soroban_sdk::Vec::new(&ctx.env);
    loop {
        let page = ctx.client().export_audit_ledger(&ctx.admin, &cursor, &2);
        assert_eq!(page.head_seq, head.count);
        assert_eq!(page.head_hash, head.head_hash);
        for entry in page.entries.iter() {
            entries.push_back(entry);
        }
        match page.next_cursor {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }

    assert_eq!(entries.len(), 3);
    let mut previous = soroban_sdk::BytesN::from_array(&ctx.env, &[0; 32]);
    for i in 0..entries.len() {
        let entry = entries.get(i).unwrap();
        assert_eq!(entry.seq, i as u64);
        assert_eq!(entry.prev_hash, previous);
        assert_eq!(
            shared::audit_ledger::entry_hash(&ctx.env, &entry),
            entry.hash
        );
        previous = entry.hash;
    }
    assert_eq!(previous, head.head_hash);
}

#[test]
fn seals_detect_a_consistent_tail_truncation() {
    let ctx = setup();
    fund_and_spend(&ctx);

    let anchor = ctx.client().seal_audit_ledger(&ctx.admin);
    assert_eq!(anchor.seq, 3);
    assert_eq!(ctx.client().verify_audit_ledger_anchors(&0, &10).ok, true);

    // Simulate a rollback that removes the newest entry *and* rewrites the head
    // so the surviving chain is internally consistent.
    ctx.env.as_contract(&ctx.id, || {
        let second = get_entry(&ctx.env, 1).unwrap();
        ctx.env
            .storage()
            .persistent()
            .remove(&AuditLedgerKey::Entry(2));
        ctx.env.storage().persistent().set(
            &AuditLedgerKey::Head,
            &shared::AuditLedgerHead {
                version: AUDIT_LEDGER_VERSION,
                count: 2,
                head_hash: second.hash,
            },
        );
    });

    let chain = ctx.client().verify_audit_ledger(&0, &10);
    assert!(chain.ok, "a truncated chain can look internally consistent");

    let anchors = ctx.client().verify_audit_ledger_anchors(&0, &10);
    assert!(!anchors.ok);
    assert_eq!(anchors.reason, AuditTamperReason::AnchorMismatch);
    assert_eq!(anchors.first_bad_id, Some(0));
}

#[test]
fn editing_a_sealed_treasury_entry_is_detected_through_the_contract() {
    let ctx = setup();
    fund_and_spend(&ctx);

    // Rewrite the amount on the deposit entry while keeping its old hash, the
    // exact shape of a storage-level tamper.
    ctx.env.as_contract(&ctx.id, || {
        let mut entry = get_entry(&ctx.env, 1).unwrap();
        entry.after = Some(9_999_999);
        ctx.env
            .storage()
            .persistent()
            .set(&AuditLedgerKey::Entry(1), &entry);
    });

    let verification = ctx.client().verify_audit_ledger(&0, &10);
    assert!(!verification.ok);
    assert_eq!(verification.reason, AuditTamperReason::EntryHashMismatch);
    assert_eq!(verification.first_bad_seq, Some(1));
}

#[test]
fn seal_is_admin_gated() {
    let ctx = setup();
    fund_and_spend(&ctx);
    let stranger = Address::generate(&ctx.env);

    let result = ctx.client().try_seal_audit_ledger(&stranger);
    assert!(result.is_err());
    assert_eq!(ctx.client().audit_ledger_head().count, 3);
}
