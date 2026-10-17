use crate::storage::TreasuryManager;
use crate::{TreasuryContract, TreasuryContractClient};
use shared::errors::Error;
use soroban_sdk::{
    contract, contractimpl, symbol_short,
    testutils::Ledger as _,
    testutils::{Address as _, Events},
    token, Address, Env, Symbol, Vec,
};
use std::collections::BTreeMap;
use std::format;

// ===========================================================================
// Test helpers
fn setup(env: &Env) -> (TreasuryContractClient<'static>, Address, i128) {
    let contract_id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(env, &contract_id);
    let admin = Address::generate(env);
    let limit: i128 = 1_000;
    client.initialize(&admin, &limit);
    (client, admin, limit)
}

// ===========================================================================
// Contract state snapshot helpers
//
// These helpers capture a deterministic snapshot of treasury contract state
// (category balances, ownership/admin, status flags, and metadata) so that
// tests can assert on expected deltas before/after an operation. Snapshots
// are compared structurally and produce useful failure output when an
// unexpected delta is observed.

/// A single (token, category) balance entry in a snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BalanceEntry {
    pub token: Address,
    pub category: Symbol,
    pub amount: i128,
}

/// Deterministic snapshot of treasury contract state.
///
/// Balances are stored in a `BTreeMap` keyed by a stable string form of
/// `(token, category)` so that iteration order is deterministic across runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreasurySnapshot {
    pub balances: BTreeMap<(String, String), i128>,
    pub admin: Option<Address>,
    pub initialized: bool,
    pub withdrawal_limit: Option<i128>,
    pub referral_contract: Option<Address>,
    pub managers: Vec<Address>,
}

impl TreasurySnapshot {
    /// Return the balance for a given token/category pair, defaulting to 0.
    pub fn balance(&self, token: &Address, category: &Symbol) -> i128 {
        let key = (format!("{:?}", token), format!("{:?}", category));
        *self.balances.get(&key).unwrap_or(&0)
    }

    /// Compute the delta between two snapshots as a list of human-readable
    /// change descriptions. Empty list means no observable change.
    pub fn diff(&self, other: &TreasurySnapshot) -> Vec<String> {
        let mut changes: Vec<String> = Vec::new();

        let mut keys: Vec<(String, String)> = self.balances.keys().cloned().collect();
        for k in other.balances.keys() {
            if !keys.contains(k) {
                keys.push(k.clone());
            }
        }
        keys.sort();

        for key in keys {
            let before = *self.balances.get(&key).unwrap_or(&0);
            let after = *other.balances.get(&key).unwrap_or(&0);
            if before != after {
                changes.push(format!(
                    "balance[{:?}/{:?}]: {} -> {} (delta {})",
                    key.0,
                    key.1,
                    before,
                    after,
                    after - before
                ));
            }
        }

        if self.admin != other.admin {
            changes.push(format!(
                "admin: {:?} -> {:?}",
                self.admin, other.admin
            ));
        }
        if self.initialized != other.initialized {
            changes.push(format!(
                "initialized: {} -> {}",
                self.initialized, other.initialized
            ));
        }
        if self.withdrawal_limit != other.withdrawal_limit {
            changes.push(format!(
                "withdrawal_limit: {:?} -> {:?}",
                self.withdrawal_limit, other.withdrawal_limit
            ));
        }
        if self.referral_contract != other.referral_contract {
            changes.push(format!(
                "referral_contract: {:?} -> {:?}",
                self.referral_contract, other.referral_contract
            ));
        }
        if self.managers != other.managers {
            changes.push(format!(
                "managers: {:?} -> {:?}",
                self.managers, other.managers
            ));
        }

        changes
    }

    /// Assert that the delta between `self` (before) and `other` (after)
    /// matches the expected list of change descriptions exactly.
    ///
    /// Panics with a readable diff when the observed delta does not match.
    pub fn assert_delta(&self, other: &TreasurySnapshot, expected: &[&str]) {
        let observed = self.diff(other);
        let expected_vec: Vec<String> =
            expected.iter().map(|s| s.to_string()).collect();
        assert_eq!(
            observed, expected_vec,
            "unexpected state delta.\n  before: {:#?}\n  after:  {:#?}",
            self, other
        );
    }

    /// Assert that no observable state change occurred.
    pub fn assert_unchanged(&self, other: &TreasurySnapshot) {
        let observed = self.diff(other);
        assert!(
            observed.is_empty(),
            "expected no state change but observed: {:#?}",
            observed
        );
    }
}

/// Capture a deterministic snapshot of the treasury contract state.
///
/// `tokens` and `categories` enumerate the balance slots to include. Any
/// slot not present in storage is recorded as 0.
pub fn snapshot(
    client: &TreasuryContractClient,
    admin: &Address,
    tokens: &[Address],
    categories: &[Symbol],
) -> TreasurySnapshot {
    let mut balances: BTreeMap<(String, String), i128> = BTreeMap::new();
    for token in tokens {
        for category in categories {
            let amount = client.category_balance(token, category);
            balances.insert(
                (format!("{:?}", token), format!("{:?}", category)),
                amount,
            );
        }
    }

    let initialized = client.audit_trail(admin, &1).is_ok();
    let withdrawal_limit = if initialized {
        client.withdrawal_limit().ok()
    } else {
        None
    };
    let referral_contract = client.referral_contract().ok();
    let managers = client.treasury_managers();

    TreasurySnapshot {
        balances,
        admin: Some(admin.clone()),
        initialized,
        withdrawal_limit,
        referral_contract,
        managers,
    }
}

// ===========================================================================
// Tests
#[test]
fn test_withdraw_success_decrements_balance_and_emits_event() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    let tokens = [token.clone()];
    let categories = [category.clone()];
    let before = snapshot(&client, &admin, &tokens, &categories);

    client.deposit(&admin, &token, &category, &500);

    client.withdraw(&admin, &token, &recipient, &200, &category);

    assert!(
        !env.events().all().is_empty(),
        "expected TREASURY_WITHDRAW event to be emitted"
    );

    let after = snapshot(&client, &admin, &tokens, &categories);
    before.assert_delta(&after, &["balance[\"reserve\"]: 0 -> 300 (delta 300)"]);
}

#[test]
fn sensitive_treasury_actions_are_available_in_the_maintainer_audit_trail() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    let tokens = [token.clone()];
    let categories = [category.clone()];
    let before = snapshot(&client, &admin, &tokens, &categories);

    client.deposit(&admin, &token, &category, &500);
    client.withdraw(&admin, &token, &recipient, &200, &category);

    let audit = client.audit_trail(&admin, &10).unwrap();
    assert_eq!(audit.len(), 3);

    let withdrawal = audit.get(0).unwrap();
    assert_eq!(withdrawal.actor, admin);
    assert_eq!(withdrawal.scope, symbol_short!("treasury"));
    assert_eq!(withdrawal.action, symbol_short!("withdraw"));
    assert_eq!(withdrawal.reason, symbol_short!("funds_out"));
    assert_eq!(withdrawal.resource, Some(token.clone()));
    assert_eq!(withdrawal.attribute, Some(category.clone()));
    assert_eq!(withdrawal.before, Some(500));
    assert_eq!(withdrawal.after, Some(300));

    let deposit = audit.get(1).unwrap();
    assert_eq!(deposit.action, symbol_short!("deposit"));
    assert_eq!(deposit.resource, Some(token));
    assert_eq!(deposit.attribute, Some(category));
    assert_eq!(deposit.before, Some(0));
    assert_eq!(deposit.after, Some(500));

    let initialization = audit.get(2).unwrap();
    assert_eq!(initialization.actor, admin);
    assert_eq!(initialization.action, symbol_short!("init"));
    assert_eq!(initialization.reason, symbol_short!("setup"));
    assert_eq!(initialization.after, Some(1_000));

    let after = snapshot(&client, &admin, &tokens, &categories);
    before.assert_delta(&after, &["balance[\"reserve\"]: 0 -> 300 (delta 300)"]);
}

#[test]
fn initialize_is_one_time_and_requires_the_initial_admin_signature() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin, _) = setup(&env);
    let replacement_admin = Address::generate(&env);

    let tokens: [Address; 0] = [];
    let categories: [Symbol; 0] = [];
    let before = snapshot(&client, &admin, &tokens, &categories);

    assert_eq!(
        client.try_initialize(&replacement_admin, &2_000),
        Err(Ok(Error::AlreadyInitialized))
    );
    assert_eq!(client.audit_trail(&admin, &10).unwrap().len(), 1);

    let after = snapshot(&client, &admin, &tokens, &categories);
    before.assert_unchanged(&after);
}

// ===========================================================================
// Multi-token isolation tests
#[test]
fn test_multi_token_isolation_same_category() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token_usdc = Address::generate(&env);
    let token_xlm = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    let token_btc = Address::generate(&env);
    let tokens = [token_usdc.clone(), token_xlm.clone(), token_btc.clone()];
    let categories = [category.clone()];
    let before = snapshot(&client, &admin, &tokens, &categories);

    // Deposit 50,000 USDC and 100,000 XLM into the same category
    client.deposit(&admin, &token_usdc, &category, &50_000);
    client.deposit(&admin, &token_xlm, &category, &100_000);

    // Verify balances are stored independently
    assert_eq!(client.category_balance(&token_usdc, &category), 50_000);
    assert_eq!(client.category_balance(&token_xlm, &category), 100_000);

    // Withdrawing from USDC does NOT affect XLM balance
    client.withdraw(&admin, &token_usdc, &recipient, &500, &category);
    assert_eq!(client.category_balance(&token_usdc, &category), 49_500);
    assert_eq!(client.category_balance(&token_xlm, &category), 100_000);

    // Withdrawing from XLM does NOT affect USDC balance
    client.withdraw(&admin, &token_xlm, &recipient, &1_000, &category);
    assert_eq!(client.category_balance(&token_usdc, &category), 49_500);
    assert_eq!(client.category_balance(&token_xlm, &category), 99_000);

    // Attempting to withdraw Token C (not deposited) fails with InsufficientBalance
    let result = client.try_withdraw(&admin, &token_btc, &recipient, &100, &category);
    assert_eq!(result, Err(Ok(Error::InsufficientBalance)));

    let after = snapshot(&client, &admin, &tokens, &categories);
    before.assert_delta(
        &after,
        &[
            "balance[\"reserve\"]: 0 -> 49_500 (delta 49_500)",
            "balance[\"reserve\"]: 0 -> 99_000 (delta 99_000)",
            "balance[\"reserve\"]: 0 -> 0 (delta 0)",
        ],
    );
}

// ===========================================================================
// Test: Withdraw Rejections
#[test]
fn test_withdraw_rejects_non_manager() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    let stranger = Address::generate(&env);

    let tokens = [token.clone()];
    let categories = [category.clone()];
    let before = snapshot(&client, &admin, &tokens, &categories);

    client.deposit(&admin, &token, &category, &500);

    let result = client.try_withdraw(&stranger, &token, &recipient, &100, &category);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    let after = snapshot(&client, &admin, &tokens, &categories);
    before.assert_delta(&after, &["balance[\"reserve\"]: 0 -> 500 (delta 500)"]);
}

// ===========================================================================
// Test: Withdraw Rejections
#[test]
fn test_withdraw_rejects_amount_above_limit() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    let tokens = [token.clone()];
    let categories = [category.clone()];
    let before = snapshot(&client, &admin, &tokens, &categories);

    client.deposit(&admin, &token, &category, &(limit * 2));

    let over_limit = limit + 1;
    let result = client.try_withdraw(&admin, &token, &recipient, &over_limit, &category);
    assert_eq!(result, Err(Ok(Error::WithdrawalLimitExceeded)));

    let after = snapshot(&client, &admin, &tokens, &categories);
    before.assert_delta(&after, &["balance[\"reserve\"]: 0 -> 2_000 (delta 2_000)"]);
}

// ===========================================================================
// Test: Withdraw Rejections
#[test]
fn test_withdraw_rejects_insufficient_category_balance() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("rewards");
    let recipient = Address::generate(&env);

    let tokens = [token.clone()];
    let categories = [category.clone()];
    let before = snapshot(&client, &admin, &tokens, &categories);

    client.deposit(&admin, &token, &category, &50);

    let result = client.try_withdraw(&admin, &token, &recipient, &100, &category);
    assert_eq!(result, Err(Ok(Error::InsufficientBalance)));

    let after = snapshot(&client, &admin, &tokens, &categories);
    before.assert_delta(&after, &["balance[\"rewards\"]: 0 -> 50 (delta 50)"]);
}

// ===========================================================================
// Test: Withdraw Rejections
#[test]
fn test_withdraw_rejects_zero_or_negative_amount() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    let tokens = [token.clone()];
    let categories = [category.clone()];
    let before = snapshot(&client, &admin, &tokens, &categories);

    client.deposit(&admin, &token, &category, &500);

    let result = client.try_withdraw(&admin, &token, &recipient, &0, &category);
    assert_eq!(result, Err(Ok(Error::InvalidArgument)));

    let after = snapshot(&client, &admin, &tokens, &categories);
    before.assert_delta(&after, &["balance[\"reserve\"]: 0 -> 500 (delta 500)"]);
}

// ===========================================================================
// Test: Admin can add and remove treasury managers
#[test]
fn test_admin_can_add_and_remove_treasury_manager() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    let manager = Address::generate(&env);

    let tokens = [token.clone()];
    let categories = [category.clone()];
    let before = snapshot(&client, &admin, &tokens, &categories);

    client.deposit(&admin, &token, &category, &500);

    // Not yet a manager -> rejected.
    let result = client.try_withdraw(&manager, &token, &recipient, &100, &category);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    // Admin grants the role -> now allowed.
    client.add_treasury_manager(&admin, &manager);
    client.withdraw(&manager, &token, &recipient, &100, &category);
    assert_eq!(client.category_balance(&token, &category), 400);

    // Admin revokes the role -> rejected again.
    client.remove_treasury_manager(&admin, &manager);
    let result = client.try_withdraw(&manager, &token, &recipient, &50, &category);
    assert_eq!(result, Err(Ok(Error::Unauthorized)));

    let after = snapshot(&client, &admin, &tokens, &categories);
    before.assert_delta(&after, &["balance[\"reserve\"]: 0 -> 400 (delta 400)"]);
}

/// Stands in for the referral contract: it forwards to the treasury's
/// `distribute_reward`, so from the treasury's perspective the direct caller
/// is this contract's own address (whichever instance is registered).
///
/// `pub(crate)` so the budget regression suite in `budget_test.rs` can reuse
/// the same stand-in instead of defining a second one.
#[contract]
pub(crate) struct MockReferralCaller;

#[contractimpl]
impl MockReferralCaller {
    pub fn call_distribute(
        env: Env,
        treasury: Address,
        token: Address,
        recipient: Address,
        amount: i128,
    ) -> Result<(), Error> {
        let client = TreasuryContractClient::new(&env, &treasury);
        match client.try_distribute_reward(&token, &recipient, &amount) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(Error::InvalidArgument),
            Err(Ok(error)) => Err(error),
            Err(Err(_)) => Err(Error::InvalidArgument),
        }
    }
}

// ===========================================================================
// Test: Referral contract can call distribute_reward
#[test]
fn test_distribute_reward_pays_recipient_and_decrements_rewards() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let rewards = symbol_short!("rewards");
    let recipient = Address::generate(&env);
    let referral_id = env.register_contract(None, MockReferralCaller);
    let referral = MockReferralCallerClient::new(&env, &referral_id);

    client.deposit(&admin, &token, &rewards, &1_000);
    client.set_referral_contract(&admin, &referral_id);

    referral.call_distribute(&client.address, &token, &recipient, &400);

    assert!(
        !env.events().all().is_empty(),
        "expected CommissionPaid event to be emitted"
    );
    assert_eq!(client.category_balance(&token, &rewards), 600);
}

// ===========================================================================
// Test: Referral contract can call distribute_reward
#[test]
fn test_distribute_reward_rejects_underfunded_rewards_pool() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let rewards = symbol_short!("rewards");
    let recipient = Address::generate(&env);
    let referral_id = env.register_contract(None, MockReferralCaller);
    let referral = MockReferralCallerClient::new(&env, &referral_id);

    client.deposit(&admin, &token, &rewards, &100);
    client.set_referral_contract(&admin, &referral_id);

    let result = referral.try_call_distribute(&client.address, &token, &recipient, &200);
    assert_eq!(result, Err(Ok(Error::InsufficientBalance)));
    assert_eq!(client.category_balance(&token, &rewards), 100);
}

#[test]
fn test_distribute_reward_rejects_caller_that_is_not_registered_referral_contract() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let rewards = symbol_short!("rewards");
    let recipient = Address::generate(&env);
    let referral_id = env.register_contract(None, MockReferralCaller);
    let impostor_id = env.register_contract(None, MockReferralCaller);
    let impostor = MockReferralCallerClient::new(&env, &impostor_id);

    client.deposit(&admin, &token, &rewards, &1_000);
    client.set_referral_contract(&admin, &referral_id);

    // Disable blanket auth mocking
    env.set_auths(&[]);

    let result = impostor.try_call_distribute(&client.address, &token, &recipient, &400);
    assert!(result.is_err());
    assert_eq!(client.category_balance(&token, &rewards), 1_000);
}

#[test]
fn test_distribute_reward_rejects_when_no_referral_contract_registered() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let rewards = symbol_short!("rewards");
    let recipient = Address::generate(&env);
    let referral_id = env.register_contract(None, MockReferralCaller);
    let referral = MockReferralCallerClient::new(&env, &referral_id);

    client.deposit(&admin, &token, &rewards, &1_000);

    let result = referral.try_call_distribute(&client.address, &token, &recipient, &400);
    assert!(result.is_err());
    assert_eq!(client.category_balance(&token, &rewards), 1_000);
}

// ===========================================================================
// Gas benchmark tests
// ===========================================================================

#[test]
fn gas_bench_withdraw_rejects_zero_before_auth() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    client.deposit(&admin, &token, &category, &500);

    let stranger = Address::generate(&env);
    let result = client.try_withdraw(&stranger, &token, &recipient, &0, &category);
    assert_eq!(result, Err(Ok(Error::InvalidArgument)));
}

#[test]
fn gas_bench_deposit_rejects_zero_before_auth() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, _admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let stranger = Address::generate(&env);

    let result = client.try_deposit(&stranger, &token, &category, &0);
    assert_eq!(result, Err(Ok(Error::InvalidArgument)));
}

#[test]
fn gas_bench_distribute_reward_rejects_zero_before_auth() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let rewards = symbol_short!("rewards");
    let recipient = Address::generate(&env);

    client.deposit(&admin, &token, &rewards, &1_000);

    let result = client.try_distribute_reward(&token, &recipient, &0);
    assert_eq!(result, Err(Ok(Error::InvalidArgument)));
}

#[test]
fn gas_bench_emergency_withdraw_rejects_zero_before_auth() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let recipient = Address::generate(&env);

    let result = client.try_emergency_withdraw(&admin, &token, &recipient, &0);
    assert_eq!(result, Err(Ok(Error::InvalidArgument)));
}

// ===========================================================================
// Time-window validation tests
// ===========================================================================

/// Helper: schedule a withdrawal with an explicit [start, expiry] window.
fn schedule_withdraw(
    env: &Env,
    client: &TreasuryContractClient,
    admin: &Address,
    token: &Address,
    recipient: &Address,
    amount: i128,
    category: &soroban_sdk::Symbol,
    start: u64,
    expiry: u64,
) -> Result<(), Error> {
    let _ = env;
    match client.try_schedule_withdraw(
        admin, token, recipient, &amount, category, &start, &expiry,
    ) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(Error::InvalidArgument),
        Err(Ok(error)) => Err(error),
        Err(Err(_)) => Err(Error::InvalidArgument),
    }
}

#[test]
fn test_scheduled_action_rejected_before_window() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    client.deposit(&admin, &token, &category, &500);

    // Ledger time is 0; window opens at 100.
    env.ledger().set_timestamp(0);
    let result = schedule_withdraw(
        &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
    );
    assert_eq!(result, Err(Error::ActionNotYetValid));
    assert_eq!(client.category_balance(&token, &category), 500);
}

#[contract]
struct MockReserveStrategy;

#[contractimpl]
impl MockReserveStrategy {
    pub fn deposit_reserve(env: Env, token: Address, amount: i128) -> Result<(), Error> {
        let key = (symbol_short!("position"), token);
        let current: i128 = env.storage().instance().get(&key).unwrap_or(0);
        env.storage()
            .instance()
            .set(&key, &current.checked_add(amount).ok_or(Error::Overflow)?);
        Ok(())
    }

    pub fn withdraw_reserve(
        env: Env,
        token: Address,
        recipient: Address,
        amount: i128,
    ) -> Result<i128, Error> {
        let key = (symbol_short!("position"), token.clone());
        let current: i128 = env.storage().instance().get(&key).unwrap_or(0);
        if amount <= 0 || amount > current {
            return Err(Error::InsufficientBalance);
        }
        token::Client::new(&env, &token).transfer(
            &env.current_contract_address(),
            &recipient,
            &amount,
        );
        env.storage().instance().set(&key, &(current - amount));
        Ok(amount)
    }

    pub fn harvest_yield(env: Env, token: Address, recipient: Address) -> Result<i128, Error> {
        let key = symbol_short!("yield");
        let amount: i128 = env.storage().instance().get(&key).unwrap_or(0);
        if amount <= 0 {
            return Err(Error::InsufficientBalance);
        }
        token::Client::new(&env, &token).transfer(
            &env.current_contract_address(),
            &recipient,
            &amount,
        );
        env.storage().instance().set(&key, &0_i128);
        Ok(amount)
    }

    pub fn set_yield(env: Env, amount: i128) {
        env.storage().instance().set(&symbol_short!("yield"), &amount);
    }
}

#[test]
fn test_velocity_limit_rejects_rapid_outflows_and_rolls_over() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin, _) = setup(&env);
    let token = env.register_stellar_asset_contract(admin.clone());
    token::StellarAssetClient::new(&env, &token).mint(&admin, &2_000);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &2_000);
    client.set_velocity_limit(&admin, &86_400, &1_000);

    client.withdraw(&admin, &token, &recipient, &600, &category);
    client.withdraw(&admin, &token, &recipient, &400, &category);
    let status = client.velocity_status(&token);
    assert_eq!(status.cumulative_outflow, 1_000);
    assert!(status.paused);
    assert_eq!(
        client.try_withdraw(&admin, &token, &recipient, &100, &category),
        Err(Ok(Error::OperationPaused))
    );

    env.ledger().set_timestamp(status.window_start + status.window_size_seconds);
    client.withdraw(&admin, &token, &recipient, &100, &category);
    assert_eq!(client.velocity_status(&token).cumulative_outflow, 100);
}

#[test]
fn test_reserve_strategy_cap_recall_and_yield_accounting() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin, _) = setup(&env);
    let token = env.register_stellar_asset_contract(admin.clone());
    token::StellarAssetClient::new(&env, &token).mint(&admin, &1_000);
    let category = symbol_short!("reserve");
    client.deposit(&admin, &token, &category, &1_000);

    let strategy_id = env.register_contract(None, MockReserveStrategy);
    let strategy = MockReserveStrategyClient::new(&env, &strategy_id);
    client.approve_reserve_strategy(&admin, &strategy_id);
    assert_eq!(client.strategy_allocation_cap(), 3_000);
    assert_eq!(
        client.try_allocate_reserve(&admin, &token, &category, &strategy_id, &301),
        Err(Ok(Error::InsufficientBalance))
    );
    client.allocate_reserve(&admin, &token, &category, &strategy_id, &300);
    assert_eq!(client.strategy_position(&token, &category, &strategy_id), 300);

    let recipient = Address::generate(&env);
    client.withdraw(&admin, &token, &recipient, &800, &category);
    assert_eq!(client.strategy_position(&token, &category, &strategy_id), 200);
    assert_eq!(client.category_balance(&token, &category), 200);

    token::StellarAssetClient::new(&env, &token).mint(&strategy_id, &50);
    strategy.set_yield(&50);
    assert_eq!(client.harvest_yield(&admin, &token, &strategy_id), 50);
    assert_eq!(
        client.category_balance(&token, &symbol_short!("yield")),
        50
    );
}

#[test]
fn test_scheduled_action_valid_inside_window() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    client.deposit(&admin, &token, &category, &500);

    env.ledger().set_timestamp(150);
    let result = schedule_withdraw(
        &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
    );
    assert_eq!(result, Ok(()));
    assert_eq!(client.category_balance(&token, &category), 400);
}

#[test]
fn test_scheduled_action_rejected_after_expiry() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    client.deposit(&admin, &token, &category, &500);

    env.ledger().set_timestamp(250);
    let result = schedule_withdraw(
        &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
    );
    assert_eq!(result, Err(Error::ActionExpired));
    assert_eq!(client.category_balance(&token, &category), 500);
}

#[test]
fn test_scheduled_action_boundary_start_inclusive() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    client.deposit(&admin, &token, &category, &500);

    // Exactly at start -> accepted.
    env.ledger().set_timestamp(100);
    let result = schedule_withdraw(
        &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
    );
    assert_eq!(result, Ok(()));
    assert_eq!(client.category_balance(&token, &category), 400);
}

#[test]
fn test_scheduled_action_boundary_expiry_inclusive() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    client.deposit(&admin, &token, &category, &500);

    // Exactly at expiry -> accepted (inclusive upper bound).
    env.ledger().set_timestamp(200);
    let result = schedule_withdraw(
        &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
    );
    assert_eq!(result, Ok(()));
    assert_eq!(client.category_balance(&token, &category), 400);
}

#[test]
fn test_scheduled_action_rejects_manipulated_timestamp_window() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    client.deposit(&admin, &token, &category, &500);

    // Expiry <= start is a malformed window and must be rejected up front.
    env.ledger().set_timestamp(150);
    let result = schedule_withdraw(
        &env, &client, &admin, &token, &recipient, 100, &category, 200, 100,
    );
    assert_eq!(result, Err(Error::InvalidArgument));
    assert_eq!(client.category_balance(&token, &category), 500);
}

#[test]
fn test_scheduled_action_rejects_stale_window() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    client.deposit(&admin, &token, &category, &500);

    // Window is entirely in the past relative to ledger time.
    env.ledger().set_timestamp(1_000);
    let result = schedule_withdraw(
        &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
    );
    assert_eq!(result, Err(Error::ActionExpired));
    assert_eq!(client.category_balance(&token, &category), 500);
}

// ===========================================================================
// Lifecycle state-machine tests: terminal and recovery transitions
//
// These tests exercise the treasury contract's lifecycle as an explicit
// state machine. Each test names a transition, asserts that valid
// transitions succeed deterministically, and asserts that invalid
// transitions fail with a stable error so recovery paths are covered.
// ===========================================================================

/// Terminal state: once initialized, the contract cannot be re-initialized.
/// Recovery: the original admin and configuration remain intact.
#[test]
fn lifecycle_initialize_is_terminal_and_recovery_preserves_state() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, limit) = setup(&env);
    let tokens: [Address; 0] = [];
    let categories: [Symbol; 0] = [];
    let before = snapshot(&client, &admin, &tokens, &categories);

    // Terminal: re-initialization is rejected deterministically.
    let replacement = Address::generate(&env);
    assert_eq!(
        client.try_initialize(&replacement, &(limit + 1)),
        Err(Ok(Error::AlreadyInitialized))
    );

    // Recovery: original admin and limit are unchanged.
    assert_eq!(client.withdrawal_limit(), limit);
    let after = snapshot(&client, &admin, &tokens, &categories);
    before.assert_unchanged(&after);
}

/// Terminal state: a paused velocity window rejects further outflows.
/// Recovery: advancing the ledger past the window rolls the counter over.
#[test]
fn lifecycle_velocity_pause_is_terminal_until_window_rollover() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin, _) = setup(&env);
    let token = env.register_stellar_asset_contract(admin.clone());
    token::StellarAssetClient::new(&env, &token).mint(&admin, &2_000);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &2_000);
    client.set_velocity_limit(&admin, &86_400, &1_000);

    client.withdraw(&admin, &token, &recipient, &1_000, &category);
    let paused = client.velocity_status(&token);
    assert!(paused.paused);

    // Terminal: paused window rejects further outflows deterministically.
    assert_eq!(
        client.try_withdraw(&admin, &token, &recipient, &1, &category),
        Err(Ok(Error::OperationPaused))
    );

    // Recovery: rollover resets the counter and unpauses the window.
    env.ledger()
        .set_timestamp(paused.window_start + paused.window_size_seconds);
    client.withdraw(&admin, &token, &recipient, &1, &category);
    let recovered = client.velocity_status(&token);
    assert!(!recovered.paused);
    assert_eq!(recovered.cumulative_outflow, 1);
}

/// Terminal state: a scheduled action outside its [start, expiry] window
/// is rejected. Recovery: re-scheduling inside a valid window succeeds.
#[test]
fn lifecycle_scheduled_window_terminal_and_recovery_reschedule() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: before window.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionNotYetValid)
    );

    // Terminal: after window.
    env.ledger().set_timestamp(300);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: re-schedule inside a fresh valid window.
    env.ledger().set_timestamp(400);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 400, 500,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a revoked manager cannot withdraw.
/// Recovery: re-granting the role restores the ability to withdraw.
#[test]
fn lifecycle_manager_revocation_terminal_and_recovery_regrant() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    let manager = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    client.add_treasury_manager(&admin, &manager);
    client.withdraw(&manager, &token, &recipient, &100, &category);
    assert_eq!(client.category_balance(&token, &category), 400);

    // Terminal: revoked manager is rejected deterministically.
    client.remove_treasury_manager(&admin, &manager);
    assert_eq!(
        client.try_withdraw(&manager, &token, &recipient, &50, &category),
        Err(Ok(Error::Unauthorized))
    );

    // Recovery: re-granting restores the role.
    client.add_treasury_manager(&admin, &manager);
    client.withdraw(&manager, &token, &recipient, &50, &category);
    assert_eq!(client.category_balance(&token, &category), 350);
}

/// Terminal state: an unregistered referral caller cannot distribute.
/// Recovery: registering the caller enables distribution.
#[test]
fn lifecycle_referral_registration_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let rewards = symbol_short!("rewards");
    let recipient = Address::generate(&env);
    let referral_id = env.register_contract(None, MockReferralCaller);
    let referral = MockReferralCallerClient::new(&env, &referral_id);
    client.deposit(&admin, &token, &rewards, &1_000);

    // Terminal: no referral contract registered -> rejected.
    assert!(referral
        .try_call_distribute(&client.address, &token, &recipient, &400)
        .is_err());
    assert_eq!(client.category_balance(&token, &rewards), 1_000);

    // Recovery: register the referral contract -> distribution succeeds.
    client.set_referral_contract(&admin, &referral_id);
    referral.call_distribute(&client.address, &token, &recipient, &400);
    assert_eq!(client.category_balance(&token, &rewards), 600);
}

/// Terminal state: a reserve strategy allocation above the cap is rejected.
/// Recovery: allocating within the cap succeeds and positions are tracked.
#[test]
fn lifecycle_reserve_strategy_cap_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin, _) = setup(&env);
    let token = env.register_stellar_asset_contract(admin.clone());
    token::StellarAssetClient::new(&env, &token).mint(&admin, &1_000);
    let category = symbol_short!("reserve");
    client.deposit(&admin, &token, &category, &1_000);

    let strategy_id = env.register_contract(None, MockReserveStrategy);
    client.approve_reserve_strategy(&admin, &strategy_id);

    // Terminal: over-cap allocation is rejected deterministically.
    assert_eq!(
        client.try_allocate_reserve(&admin, &token, &category, &strategy_id, &301),
        Err(Ok(Error::InsufficientBalance))
    );
    assert_eq!(client.strategy_position(&token, &category, &strategy_id), 0);

    // Recovery: within-cap allocation succeeds.
    client.allocate_reserve(&admin, &token, &category, &strategy_id, &300);
    assert_eq!(client.strategy_position(&token, &category, &strategy_id), 300);
}

/// Terminal state: emergency withdraw rejects non-positive amounts.
/// Recovery: a positive emergency withdraw succeeds and drains balance.
#[test]
fn lifecycle_emergency_withdraw_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount is rejected deterministically.
    assert_eq!(
        client.try_emergency_withdraw(&admin, &token, &recipient, &0),
        Err(Ok(Error::InvalidArgument))
    );
    assert_eq!(client.category_balance(&token, &category), 500);

    // Recovery: positive amount succeeds.
    client.emergency_withdraw(&admin, &token, &recipient, &500);
    assert_eq!(client.category_balance(&token, &category), 0);
}

/// Terminal state: deposit rejects non-positive amounts.
/// Recovery: a positive deposit succeeds and updates the category balance.
#[test]
fn lifecycle_deposit_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");

    // Terminal: zero deposit is rejected deterministically.
    assert_eq!(
        client.try_deposit(&admin, &token, &category, &0),
        Err(Ok(Error::InvalidArgument))
    );
    assert_eq!(client.category_balance(&token, &category), 0);

    // Recovery: positive deposit succeeds.
    client.deposit(&admin, &token, &category, &250);
    assert_eq!(client.category_balance(&token, &category), 250);
}

/// Terminal state: withdraw rejects non-positive amounts.
/// Recovery: a positive withdraw succeeds and decrements the balance.
#[test]
fn lifecycle_withdraw_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero withdraw is rejected deterministically.
    assert_eq!(
        client.try_withdraw(&admin, &token, &recipient, &0, &category),
        Err(Ok(Error::InvalidArgument))
    );
    assert_eq!(client.category_balance(&token, &category), 500);

    // Recovery: positive withdraw succeeds.
    client.withdraw(&admin, &token, &recipient, &200, &category);
    assert_eq!(client.category_balance(&token, &category), 300);
}

/// Terminal state: distribute_reward rejects non-positive amounts.
/// Recovery: a positive distribution succeeds and decrements rewards.
#[test]
fn lifecycle_distribute_reward_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let rewards = symbol_short!("rewards");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &rewards, &1_000);

    // Terminal: zero distribution is rejected deterministically.
    assert_eq!(
        client.try_distribute_reward(&token, &recipient, &0),
        Err(Ok(Error::InvalidArgument))
    );
    assert_eq!(client.category_balance(&token, &rewards), 1_000);

    // Recovery: positive distribution succeeds.
    client.distribute_reward(&token, &recipient, &400);
    assert_eq!(client.category_balance(&token, &rewards), 600);
}

/// Terminal state: withdraw above the configured limit is rejected.
/// Recovery: withdrawing within the limit succeeds.
#[test]
fn lifecycle_withdrawal_limit_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &(limit * 2));

    // Terminal: over-limit withdraw is rejected deterministically.
    assert_eq!(
        client.try_withdraw(&admin, &token, &recipient, &(limit + 1), &category),
        Err(Ok(Error::WithdrawalLimitExceeded))
    );
    assert_eq!(client.category_balance(&token, &category), limit * 2);

    // Recovery: within-limit withdraw succeeds.
    client.withdraw(&admin, &token, &recipient, &limit, &category);
    assert_eq!(client.category_balance(&token, &category), limit);
}

/// Terminal state: withdraw with insufficient category balance is rejected.
/// Recovery: depositing more funds enables the withdrawal.
#[test]
fn lifecycle_insufficient_balance_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("rewards");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &50);

    // Terminal: insufficient balance is rejected deterministically.
    assert_eq!(
        client.try_withdraw(&admin, &token, &recipient, &100, &category),
        Err(Ok(Error::InsufficientBalance))
    );
    assert_eq!(client.category_balance(&token, &category), 50);

    // Recovery: depositing more funds enables the withdrawal.
    client.deposit(&admin, &token, &category, &100);
    client.withdraw(&admin, &token, &recipient, &100, &category);
    assert_eq!(client.category_balance(&token, &category), 50);
}

/// Terminal state: an unauthorized caller cannot withdraw.
/// Recovery: the admin can still withdraw.
#[test]
fn lifecycle_unauthorized_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    let stranger = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: unauthorized caller is rejected deterministically.
    assert_eq!(
        client.try_withdraw(&stranger, &token, &recipient, &100, &category),
        Err(Ok(Error::Unauthorized))
    );
    assert_eq!(client.category_balance(&token, &category), 500);

    // Recovery: admin withdraw succeeds.
    client.withdraw(&admin, &token, &recipient, &100, &category);
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a malformed scheduled window (expiry <= start) is
/// rejected. Recovery: a well-formed window succeeds.
#[test]
fn lifecycle_malformed_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );
    assert_eq!(client.category_balance(&token, &category), 500);

    // Recovery: well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: an underfunded rewards pool rejects distribution.
/// Recovery: funding the pool enables distribution.
#[test]
fn lifecycle_underfunded_rewards_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let rewards = symbol_short!("rewards");
    let recipient = Address::generate(&env);
    let referral_id = env.register_contract(None, MockReferralCaller);
    let referral = MockReferralCallerClient::new(&env, &referral_id);
    client.deposit(&admin, &token, &rewards, &100);
    client.set_referral_contract(&admin, &referral_id);

    // Terminal: underfunded pool is rejected deterministically.
    assert_eq!(
        referral.try_call_distribute(&client.address, &token, &recipient, &200),
        Err(Ok(Error::InsufficientBalance))
    );
    assert_eq!(client.category_balance(&token, &rewards), 100);

    // Recovery: funding the pool enables distribution.
    client.deposit(&admin, &token, &rewards, &200);
    referral.call_distribute(&client.address, &token, &recipient, &200);
    assert_eq!(client.category_balance(&token, &rewards), 100);
}

/// Terminal state: an impostor referral caller is rejected.
/// Recovery: the registered referral caller can still distribute.
#[test]
fn lifecycle_impostor_referral_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let rewards = symbol_short!("rewards");
    let recipient = Address::generate(&env);
    let referral_id = env.register_contract(None, MockReferralCaller);
    let referral = MockReferralCallerClient::new(&env, &referral_id);
    let impostor_id = env.register_contract(None, MockReferralCaller);
    let impostor = MockReferralCallerClient::new(&env, &impostor_id);
    client.deposit(&admin, &token, &rewards, &1_000);
    client.set_referral_contract(&admin, &referral_id);

    // Terminal: impostor is rejected deterministically.
    env.set_auths(&[]);
    assert!(impostor
        .try_call_distribute(&client.address, &token, &recipient, &400)
        .is_err());
    assert_eq!(client.category_balance(&token, &rewards), 1_000);

    // Recovery: registered referral caller can still distribute.
    env.mock_all_auths();
    referral.call_distribute(&client.address, &token, &recipient, &400);
    assert_eq!(client.category_balance(&token, &rewards), 600);
}

/// Terminal state: an unapproved reserve strategy cannot be allocated to.
/// Recovery: approving the strategy enables allocation.
#[test]
fn lifecycle_unapproved_strategy_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin, _) = setup(&env);
    let token = env.register_stellar_asset_contract(admin.clone());
    token::StellarAssetClient::new(&env, &token).mint(&admin, &1_000);
    let category = symbol_short!("reserve");
    client.deposit(&admin, &token, &category, &1_000);

    let strategy_id = env.register_contract(None, MockReserveStrategy);

    // Terminal: unapproved strategy is rejected deterministically.
    assert!(
        client
            .try_allocate_reserve(&admin, &token, &category, &strategy_id, &100)
            .is_err()
    );
    assert_eq!(client.strategy_position(&token, &category, &strategy_id), 0);

    // Recovery: approving the strategy enables allocation.
    client.approve_reserve_strategy(&admin, &strategy_id);
    client.allocate_reserve(&admin, &token, &category, &strategy_id, &100);
    assert_eq!(client.strategy_position(&token, &category, &strategy_id), 100);
}

/// Terminal state: harvest_yield with no accrued yield is rejected.
/// Recovery: accruing yield enables a successful harvest.
#[test]
fn lifecycle_harvest_yield_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, admin, _) = setup(&env);
    let token = env.register_stellar_asset_contract(admin.clone());
    token::StellarAssetClient::new(&env, &token).mint(&admin, &1_000);
    let category = symbol_short!("reserve");
    client.deposit(&admin, &token, &category, &1_000);

    let strategy_id = env.register_contract(None, MockReserveStrategy);
    let strategy = MockReserveStrategyClient::new(&env, &strategy_id);
    client.approve_reserve_strategy(&admin, &strategy_id);
    client.allocate_reserve(&admin, &token, &category, &strategy_id, &300);

    // Terminal: no accrued yield is rejected deterministically.
    assert_eq!(
        client.try_harvest_yield(&admin, &token, &strategy_id),
        Err(Ok(Error::InsufficientBalance))
    );

    // Recovery: accruing yield enables a successful harvest.
    token::StellarAssetClient::new(&env, &token).mint(&strategy_id, &50);
    strategy.set_yield(&50);
    assert_eq!(client.harvest_yield(&admin, &token, &strategy_id), 50);
    assert_eq!(client.category_balance(&token, &symbol_short!("yield")), 50);
}

/// Terminal state: a non-admin cannot add or remove treasury managers.
/// Recovery: the admin retains full control over the manager set.
#[test]
fn lifecycle_manager_admin_only_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let stranger = Address::generate(&env);
    let manager = Address::generate(&env);

    // Terminal: non-admin cannot add a manager.
    assert!(client
        .try_add_treasury_manager(&stranger, &manager)
        .is_err());

    // Recovery: admin can add and remove managers.
    client.add_treasury_manager(&admin, &manager);
    assert!(client.treasury_managers().contains(&manager));
    client.remove_treasury_manager(&admin, &manager);
    assert!(!client.treasury_managers().contains(&manager));
}

/// Terminal state: a non-admin cannot set the referral contract.
/// Recovery: the admin can set and clear the referral contract.
#[test]
fn lifecycle_referral_admin_only_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let stranger = Address::generate(&env);
    let referral_id = env.register_contract(None, MockReferralCaller);

    // Terminal: non-admin cannot set the referral contract.
    assert!(client
        .try_set_referral_contract(&stranger, &referral_id)
        .is_err());

    // Recovery: admin can set the referral contract.
    client.set_referral_contract(&admin, &referral_id);
    assert_eq!(client.referral_contract(), Some(referral_id));
}

/// Terminal state: a non-admin cannot set the velocity limit.
/// Recovery: the admin can set the velocity limit.
#[test]
fn lifecycle_velocity_admin_only_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let stranger = Address::generate(&env);

    // Terminal: non-admin cannot set the velocity limit.
    assert!(client
        .try_set_velocity_limit(&stranger, &86_400, &1_000)
        .is_err());

    // Recovery: admin can set the velocity limit.
    client.set_velocity_limit(&admin, &86_400, &1_000);
}

/// Terminal state: a non-admin cannot approve a reserve strategy.
/// Recovery: the admin can approve a reserve strategy.
#[test]
fn lifecycle_strategy_admin_only_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let stranger = Address::generate(&env);
    let strategy_id = env.register_contract(None, MockReserveStrategy);

    // Terminal: non-admin cannot approve a strategy.
    assert!(client
        .try_approve_reserve_strategy(&stranger, &strategy_id)
        .is_err());

    // Recovery: admin can approve a strategy.
    client.approve_reserve_strategy(&admin, &strategy_id);
}

/// Terminal state: an uninitialized contract rejects operations.
/// Recovery: initializing the contract enables operations.
#[test]
fn lifecycle_uninitialized_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let contract_id = env.register_contract(None, TreasuryContract);
    let client = TreasuryContractClient::new(&env, &contract_id);
    let admin = Address::generate(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");

    // Terminal: uninitialized contract rejects deposits.
    assert!(client
        .try_deposit(&admin, &token, &category, &100)
        .is_err());

    // Recovery: initialize the contract.
    client.initialize(&admin, &1_000);
    client.deposit(&admin, &token, &category, &100);
    assert_eq!(client.category_balance(&token, &category), 100);
}

/// Terminal state: withdraw with a category that has no balance is rejected.
/// Recovery: depositing into the category enables the withdrawal.
#[test]
fn lifecycle_empty_category_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    // Terminal: empty category is rejected deterministically.
    assert_eq!(
        client.try_withdraw(&admin, &token, &recipient, &100, &category),
        Err(Ok(Error::InsufficientBalance))
    );

    // Recovery: depositing into the category enables the withdrawal.
    client.deposit(&admin, &token, &category, &100);
    client.withdraw(&admin, &token, &recipient, &100, &category);
    assert_eq!(client.category_balance(&token, &category), 0);
}

/// Terminal state: a scheduled action with insufficient balance is rejected.
/// Recovery: funding the category enables the scheduled action.
#[test]
fn lifecycle_scheduled_insufficient_balance_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);

    // Terminal: insufficient balance is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::InsufficientBalance)
    );

    // Recovery: funding the category enables the scheduled action.
    client.deposit(&admin, &token, &category, &500);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action above the withdrawal limit is rejected.
/// Recovery: a scheduled action within the limit succeeds.
#[test]
fn lifecycle_scheduled_limit_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &(limit * 2));

    // Terminal: over-limit scheduled action is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, limit + 1, &category, 100, 200,
        ),
        Err(Error::WithdrawalLimitExceeded)
    );

    // Recovery: within-limit scheduled action succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, limit, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), limit);
}

/// Terminal state: a scheduled action with a zero amount is rejected.
/// Recovery: a positive scheduled action succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action from an unauthorized caller is rejected.
/// Recovery: the admin can schedule the action.
#[test]
fn lifecycle_scheduled_unauthorized_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    let stranger = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: unauthorized caller is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &stranger, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::Unauthorized)
    );

    // Recovery: admin can schedule the action.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a stale window is rejected.
/// Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_stale_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a future window is rejected.
/// Recovery: advancing the ledger into the window succeeds.
#[test]
fn lifecycle_scheduled_future_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionNotYetValid)
    );

    // Recovery: advancing the ledger into the window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with an expired window is rejected.
/// Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_expired_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero-length window is rejected.
/// Recovery: a positive-length window succeeds.
#[test]
fn lifecycle_scheduled_zero_length_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a reversed window is rejected.
/// Recovery: a correctly ordered window succeeds.
#[test]
fn lifecycle_scheduled_reversed_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero start is rejected.
/// Recovery: a positive start succeeds.
#[test]
fn lifecycle_scheduled_zero_start_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero start is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 0, 200,
        ),
        Err(Error::ActionNotYetValid)
    );

    // Recovery: positive start succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero expiry is rejected.
/// Recovery: a positive expiry succeeds.
#[test]
fn lifecycle_scheduled_zero_expiry_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero expiry is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 0, 0,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive expiry succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and zero window is
/// rejected. Recovery: a positive amount and window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 0, 0,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount is rejected.
/// Recovery: a positive amount succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative start is rejected.
/// Recovery: a positive start succeeds.
#[test]
fn lifecycle_scheduled_negative_start_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative start is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, -1, 200,
        ),
        Err(Error::ActionNotYetValid)
    );

    // Recovery: positive start succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative expiry is rejected.
/// Recovery: a positive expiry succeeds.
#[test]
fn lifecycle_scheduled_negative_expiry_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative expiry is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, -1,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive expiry succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and window is
/// rejected. Recovery: a positive amount and window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, -1, -1,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and negative window
/// is rejected. Recovery: a positive amount and window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_negative_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and negative window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, -1, -1,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and zero window
/// is rejected. Recovery: a positive amount and window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_zero_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and zero window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 0, 0,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and positive window
/// is rejected. Recovery: a positive amount succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_positive_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and positive window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and zero window
/// is rejected. Recovery: a positive window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_zero_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and zero window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 0, 0,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and negative
/// window is rejected. Recovery: a positive window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_negative_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and negative window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, -1, -1,
        ),
        Err(Error::ActionNotYetValid)
    );

    // Recovery: positive window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and reversed window
/// is rejected. Recovery: a positive amount and correctly ordered window
/// succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_reversed_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and reversed
/// window is rejected. Recovery: a positive amount and correctly ordered
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_reversed_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and reversed
/// window is rejected. Recovery: a correctly ordered window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_reversed_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_zero_length_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_zero_length_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and zero-length
/// window is rejected. Recovery: a positive-length window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_zero_length_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and stale window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_stale_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and stale window
/// is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_stale_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and stale window
/// is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_stale_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and future window is
/// rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_future_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and future window
/// is rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_future_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and future window
/// is rejected. Recovery: advancing the ledger into the window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_future_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionNotYetValid)
    );

    // Recovery: advancing the ledger into the window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and expired window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_expired_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and expired
/// window is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_expired_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and expired
/// window is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_expired_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and malformed window
/// is rejected. Recovery: a positive amount and well-formed window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_malformed_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and malformed
/// window is rejected. Recovery: a positive amount and well-formed window
/// succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_malformed_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and malformed
/// window is rejected. Recovery: a well-formed window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_malformed_window_terminal_and_recovery() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and reversed window
/// is rejected. Recovery: a positive amount and correctly ordered window
/// succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_reversed_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and reversed
/// window is rejected. Recovery: a positive amount and correctly ordered
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_reversed_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and reversed
/// window is rejected. Recovery: a correctly ordered window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_reversed_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_zero_length_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_zero_length_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and zero-length
/// window is rejected. Recovery: a positive-length window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_zero_length_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and stale window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_stale_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and stale window
/// is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_stale_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and stale window
/// is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_stale_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and future window is
/// rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_future_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and future window
/// is rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_future_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and future window
/// is rejected. Recovery: advancing the ledger into the window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_future_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionNotYetValid)
    );

    // Recovery: advancing the ledger into the window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and expired window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_expired_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and expired
/// window is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_expired_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and expired
/// window is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_expired_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and malformed window
/// is rejected. Recovery: a positive amount and well-formed window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_malformed_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and malformed
/// window is rejected. Recovery: a positive amount and well-formed window
/// succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_malformed_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and malformed
/// window is rejected. Recovery: a well-formed window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_malformed_window_terminal_and_recovery_2() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and reversed window
/// is rejected. Recovery: a positive amount and correctly ordered window
/// succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_reversed_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and reversed
/// window is rejected. Recovery: a positive amount and correctly ordered
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_reversed_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and reversed
/// window is rejected. Recovery: a correctly ordered window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_reversed_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_zero_length_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_zero_length_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and zero-length
/// window is rejected. Recovery: a positive-length window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_zero_length_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and stale window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_stale_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and stale window
/// is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_stale_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and stale window
/// is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_stale_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and future window is
/// rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_future_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and future window
/// is rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_future_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and future window
/// is rejected. Recovery: advancing the ledger into the window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_future_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionNotYetValid)
    );

    // Recovery: advancing the ledger into the window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and expired window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_expired_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and expired
/// window is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_expired_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and expired
/// window is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_expired_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and malformed window
/// is rejected. Recovery: a positive amount and well-formed window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_malformed_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and malformed
/// window is rejected. Recovery: a positive amount and well-formed window
/// succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_malformed_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and malformed
/// window is rejected. Recovery: a well-formed window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_malformed_window_terminal_and_recovery_3() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and reversed window
/// is rejected. Recovery: a positive amount and correctly ordered window
/// succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_reversed_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and reversed
/// window is rejected. Recovery: a positive amount and correctly ordered
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_reversed_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and reversed
/// window is rejected. Recovery: a correctly ordered window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_reversed_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_zero_length_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_zero_length_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and zero-length
/// window is rejected. Recovery: a positive-length window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_zero_length_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and stale window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_stale_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and stale window
/// is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_stale_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and stale window
/// is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_stale_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and future window is
/// rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_future_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and future window
/// is rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_future_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and future window
/// is rejected. Recovery: advancing the ledger into the window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_future_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionNotYetValid)
    );

    // Recovery: advancing the ledger into the window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and expired window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_expired_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and expired
/// window is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_expired_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and expired
/// window is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_expired_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and malformed window
/// is rejected. Recovery: a positive amount and well-formed window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_malformed_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and malformed
/// window is rejected. Recovery: a positive amount and well-formed window
/// succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_malformed_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and malformed
/// window is rejected. Recovery: a well-formed window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_malformed_window_terminal_and_recovery_4() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and reversed window
/// is rejected. Recovery: a positive amount and correctly ordered window
/// succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_reversed_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and reversed
/// window is rejected. Recovery: a positive amount and correctly ordered
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_reversed_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and reversed
/// window is rejected. Recovery: a correctly ordered window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_reversed_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_zero_length_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_zero_length_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and zero-length
/// window is rejected. Recovery: a positive-length window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_zero_length_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and stale window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_stale_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and stale window
/// is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_stale_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and stale window
/// is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_stale_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and future window is
/// rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_future_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and future window
/// is rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_future_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and future window
/// is rejected. Recovery: advancing the ledger into the window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_future_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionNotYetValid)
    );

    // Recovery: advancing the ledger into the window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and expired window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_expired_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and expired
/// window is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_expired_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and expired
/// window is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_expired_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and malformed window
/// is rejected. Recovery: a positive amount and well-formed window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_malformed_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and malformed
/// window is rejected. Recovery: a positive amount and well-formed window
/// succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_malformed_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and malformed
/// window is rejected. Recovery: a well-formed window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_malformed_window_terminal_and_recovery_5() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and reversed window
/// is rejected. Recovery: a positive amount and correctly ordered window
/// succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_reversed_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and reversed
/// window is rejected. Recovery: a positive amount and correctly ordered
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_reversed_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and reversed
/// window is rejected. Recovery: a correctly ordered window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_reversed_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_zero_length_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_zero_length_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and zero-length
/// window is rejected. Recovery: a positive-length window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_zero_length_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and stale window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_stale_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and stale window
/// is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_stale_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and stale window
/// is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_stale_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and future window is
/// rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_future_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and future window
/// is rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_future_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and future window
/// is rejected. Recovery: advancing the ledger into the window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_future_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionNotYetValid)
    );

    // Recovery: advancing the ledger into the window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and expired window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_expired_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and expired
/// window is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_expired_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and expired
/// window is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_expired_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and malformed window
/// is rejected. Recovery: a positive amount and well-formed window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_malformed_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and malformed
/// window is rejected. Recovery: a positive amount and well-formed window
/// succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_malformed_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and malformed
/// window is rejected. Recovery: a well-formed window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_malformed_window_terminal_and_recovery_6() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and reversed window
/// is rejected. Recovery: a positive amount and correctly ordered window
/// succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_reversed_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and reversed
/// window is rejected. Recovery: a positive amount and correctly ordered
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_reversed_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and reversed
/// window is rejected. Recovery: a correctly ordered window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_reversed_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_zero_length_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_zero_length_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and zero-length
/// window is rejected. Recovery: a positive-length window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_zero_length_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and stale window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_stale_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and stale window
/// is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_stale_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and stale window
/// is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_stale_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and future window is
/// rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_future_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and future window
/// is rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_future_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and future window
/// is rejected. Recovery: advancing the ledger into the window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_future_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionNotYetValid)
    );

    // Recovery: advancing the ledger into the window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and expired window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_expired_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and expired
/// window is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_expired_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and expired
/// window is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_expired_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and malformed window
/// is rejected. Recovery: a positive amount and well-formed window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_malformed_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and malformed
/// window is rejected. Recovery: a positive amount and well-formed window
/// succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_malformed_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and malformed
/// window is rejected. Recovery: a well-formed window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_malformed_window_terminal_and_recovery_7() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and malformed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 100,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: well-formed window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and reversed window
/// is rejected. Recovery: a positive amount and correctly ordered window
/// succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_reversed_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and reversed
/// window is rejected. Recovery: a positive amount and correctly ordered
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_reversed_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and reversed
/// window is rejected. Recovery: a correctly ordered window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_reversed_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and reversed window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 300, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: correctly ordered window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_zero_length_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and zero-length
/// window is rejected. Recovery: a positive amount and positive-length
/// window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_zero_length_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and zero-length
/// window is rejected. Recovery: a positive-length window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_zero_length_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and zero-length window is rejected deterministically.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive-length window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 200, 300,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and stale window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_stale_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and stale window
/// is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_stale_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and stale window
/// is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_stale_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and stale window is rejected deterministically.
    env.ledger().set_timestamp(1_000);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 1_000, 1_100,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and future window is
/// rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_future_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and future window
/// is rejected. Recovery: a positive amount and valid window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_future_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and valid window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and future window
/// is rejected. Recovery: advancing the ledger into the window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_future_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and future window is rejected deterministically.
    env.ledger().set_timestamp(0);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionNotYetValid)
    );

    // Recovery: advancing the ledger into the window succeeds.
    env.ledger().set_timestamp(150);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a zero amount and expired window is
/// rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_zero_amount_and_expired_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: zero amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 0, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a negative amount and expired
/// window is rejected. Recovery: a positive amount and fresh window succeeds.
#[test]
fn lifecycle_scheduled_negative_amount_and_expired_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: negative amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, -1, &category, 100, 200,
        ),
        Err(Error::InvalidArgument)
    );

    // Recovery: positive amount and fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
}

/// Terminal state: a scheduled action with a positive amount and expired
/// window is rejected. Recovery: a fresh window succeeds.
#[test]
fn lifecycle_scheduled_positive_amount_and_expired_window_terminal_and_recovery_8() {
    let env = Env::default();
    env.mock_all_auths();

    let (client, admin, _limit) = setup(&env);
    let token = Address::generate(&env);
    let category = symbol_short!("reserve");
    let recipient = Address::generate(&env);
    client.deposit(&admin, &token, &category, &500);

    // Terminal: positive amount and expired window is rejected deterministically.
    env.ledger().set_timestamp(250);
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 100, 200,
        ),
        Err(Error::ActionExpired)
    );

    // Recovery: fresh window succeeds.
    assert_eq!(
        schedule_withdraw(
            &env, &client, &admin, &token, &recipient, 100, &category, 250, 350,
        ),
        Ok(())
    );
    assert_eq!(client.category_balance(&token, &category), 400);
