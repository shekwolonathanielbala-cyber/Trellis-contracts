#![no_std]
//! # Treasury Contract
//!
//! Protocol treasury management for Trellis humanitarian aid platform.
//!
//! ## Overview
//!
//! The Treasury Contract is the financial heart of Trellis, managing:
//! - **Multi-token per-category balances** (e.g., `reserve`, `rewards`) for fund segregation
//! - **Withdrawal limits** to prevent accidental large transfers
//! - **Role-based access control** via treasury managers and administrators
//! - **Referral reward distribution** through integration with the referral contract
//!
//! ## Categories
//!
//! The treasury organizes funds into categories per asset, each with its own balance:
//! - **`reserve`**: Protocol emergency funds
//! - **`rewards`**: Referral commission pool
//! - Custom categories as defined by administrators
//!
//! ## Roles
//!
//! - **Admin**: Full governance (set managers, configure limits, emergency withdraw)
//! - **Treasury Manager**: Operational access (deposit, withdraw, distribute rewards)
//!
//! ## Queries
//!
//! - [`TreasuryContract::category_balance`]: Check an asset category's current balance
//! - [`TreasuryContract::withdrawal_limit`]: View the max per-transaction limit
//! - [`TreasuryContract::referral_contract`]: See the registered referral contract

use soroban_sdk::{
    contract, contractclient, contractimpl, contracttype, symbol_short, token, Address, Bytes,
    BytesN, Env, IntoVal, Symbol, Vec,
};

use shared::auth::{self, Permission, Role};
use shared::errors::Error;
use shared::events::{
    self, emit_action_executed, emit_commission_paid, emit_module_initialized,
    emit_permission_changed, emit_treasury_deposit, emit_treasury_withdrawal,
};
use shared::storage::{instance_get, instance_set, persistent_set};
use shared::{record_action_audit_event, ResourceLink, TimelineEventType};

/// Storage key prefix for per-category multi-token balances; the full key is
/// `(BALANCE, token, category)`.
const BALANCE: Symbol = symbol_short!("cat_bal");
/// Storage key for the configurable max per-transaction withdrawal limit.
const MAX_WD: Symbol = symbol_short!("max_wd");
/// Category symbol for the emergency reserve (used by `emergency_withdraw`).
const RESERVE_CATEGORY: Symbol = symbol_short!("reserve");
/// Category symbol for the referral commission rewards pool (used by
/// `distribute_reward`).
const REWARDS_CATEGORY: Symbol = symbol_short!("rewards");
/// Storage key for the referral contract address authorised to call
/// `distribute_reward`.
const REFERRAL_CONTRACT: Symbol = symbol_short!("ref_ctr");
/// Storage key prefix for scheduled-action time windows; full key is
/// `(SCHEDULE, action_id)`.
const SCHEDULE: Symbol = symbol_short!("sched");
const VELOCITY_WINDOW: Symbol = symbol_short!("vel_wnd");
const VELOCITY_MAX: Symbol = symbol_short!("vel_max");
const VELOCITY_STATE: Symbol = symbol_short!("vel_state");
const STRATEGY_APPROVED: Symbol = symbol_short!("strat_ok");
const STRATEGY_LIST: Symbol = symbol_short!("strat_lst");
const STRATEGY_CAP: Symbol = symbol_short!("strat_cap");
const STRATEGY_POSITION: Symbol = symbol_short!("strat_pos");
const STRATEGY_TOTAL: Symbol = symbol_short!("strat_tot");
const STRATEGY_YIELD_CATEGORY: Symbol = symbol_short!("yield");
const MAX_STRATEGY_ALLOCATION_BPS: u32 = 3_000;

#[contractclient(name = "ReserveStrategyClient")]
pub trait ReserveStrategy {
    fn deposit_reserve(env: Env, token: Address, amount: i128) -> Result<(), Error>;
    fn withdraw_reserve(env: Env, token: Address, recipient: Address, amount: i128)
        -> Result<i128, Error>;
    fn harvest_yield(env: Env, token: Address, recipient: Address) -> Result<i128, Error>;
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VelocityStatus {
    pub window_start: u64,
    pub cumulative_outflow: i128,
    pub window_size_seconds: u64,
    pub max_window_outflow: i128,
    pub paused: bool,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
struct VelocityState {
    window_start: u64,
    cumulative_outflow: i128,
    active: bool,
}

/// A time window during which a scheduled action may execute.
///
/// `not_before` is the earliest ledger timestamp at which the action is valid;
/// `expires_at` is the exclusive upper bound (the action is stale at or after
/// this timestamp). Both are unix seconds sourced from `env.ledger().timestamp()`.
#[soroban_sdk::contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeWindow {
    pub not_before: u64,
    pub expires_at: u64,
}

impl TimeWindow {
    /// Validates `now` against this window, returning a typed error for the
    /// early / late / stale cases so callers can surface precise diagnostics.
    pub fn validate(&self, now: u64) -> Result<(), Error> {
        if self.expires_at <= self.not_before {
            return Err(Error::InvalidArgument);
        }
        if now < self.not_before {
            return Err(Error::ActionTooEarly);
        }
        if now >= self.expires_at {
            return Err(Error::ActionExpired);
        }
        Ok(())
    }
}

/// Validates `now` against a window and emits an audit event on failure so
/// rejected attempts are observable on-chain.
fn validate_window(
    env: &Env,
    actor: &Address,
    action: Symbol,
    window: &TimeWindow,
) -> Result<(), Error> {
    let now = env.ledger().timestamp();
    match window.validate(now) {
        Ok(()) => Ok(()),
        Err(err) => {
            let reason = match err {
                Error::ActionTooEarly => symbol_short!("early"),
                Error::ActionExpired => {
                    if now >= window.expires_at {
                        symbol_short!("stale")
                    } else {
                        symbol_short!("late")
                    }
                }
                _ => symbol_short!("invalid"),
            };
            record_treasury_audit(
                env,
                actor,
                TimelineEventType::ActionRejected,
                action,
                reason,
                None,
                None,
                Some(window.not_before as i128),
                Some(window.expires_at as i128),
            )?;
            Err(err)
        }
    }
}

fn record_treasury_audit(
    env: &Env,
    actor: &Address,
    event_type: TimelineEventType,
    action: Symbol,
    reason: Symbol,
    resource: Option<Address>,
    attribute: Option<Symbol>,
    before: Option<i128>,
    after: Option<i128>,
) -> Result<(), Error> {
    record_action_audit_event(
        env,
        actor,
        event_type,
        ResourceLink {
            kind: Bytes::from_slice(env, b"treasury"),
            id: 0,
            revision: 0,
        },
        symbol_short!("treasury"),
        action,
        reason,
        resource,
        attribute,
        before,
        after,
    )?;
    Ok(())
}

fn zero_correlation_id(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32])
}

#[contract]
pub struct TreasuryContract;

#[contractimpl]
impl TreasuryContract {
    /// Initialise the contract: sets the admin address, grants the admin
    /// the `TreasuryManager` role, and sets the initial max
    /// per-transaction withdrawal limit.
    pub fn initialize(env: Env, admin: Address, max_withdrawal_limit: i128) -> Result<(), Error> {
        if max_withdrawal_limit <= 0 {
            return Err(Error::InvalidArgument);
        }
        auth::initialize_admin(&env, &admin)?;
        persistent_set(
            &env,
            &shared::auth::DataKey::Role(admin.clone(), Role::TreasuryManager),
            &true,
        );
        instance_set(&env, &MAX_WD, &max_withdrawal_limit);
        instance_set(&env, &STRATEGY_CAP, &MAX_STRATEGY_ALLOCATION_BPS);
        record_treasury_audit(
            &env,
            &admin,
            TimelineEventType::ConfigChanged,
            symbol_short!("init"),
            symbol_short!("setup"),
            None,
            None,
            None,
            Some(max_withdrawal_limit),
        )?;
        emit_module_initialized(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            1,
            &admin,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Grants the `TreasuryManager` role to `who`. Admin only.
    pub fn add_treasury_manager(env: Env, caller: Address, who: Address) -> Result<(), Error> {
        let was_manager = auth::has_role(&env, &who, Role::TreasuryManager);
        auth::grant_role(&env, &caller, &who, Role::TreasuryManager)?;
        record_treasury_audit(
            &env,
            &caller,
            TimelineEventType::RoleChanged,
            symbol_short!("mgr_grnt"),
            symbol_short!("adm_grant"),
            Some(who.clone()),
            Some(symbol_short!("manager")),
            Some(if was_manager { 1 } else { 0 }),
            Some(1),
        )?;
        emit_permission_changed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            symbol_short!("manager"),
            &who,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Revokes the `TreasuryManager` role from `who`. Admin only.
    pub fn remove_treasury_manager(env: Env, caller: Address, who: Address) -> Result<(), Error> {
        let was_manager = auth::has_role(&env, &who, Role::TreasuryManager);
        auth::revoke_role(&env, &caller, &who, Role::TreasuryManager)?;
        record_treasury_audit(
            &env,
            &caller,
            TimelineEventType::RoleChanged,
            symbol_short!("mgr_rvok"),
            symbol_short!("adm_rvok"),
            Some(who.clone()),
            Some(symbol_short!("manager")),
            Some(if was_manager { 1 } else { 0 }),
            Some(0),
        )?;
        emit_permission_changed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            symbol_short!("manager"),
            &who,
            false,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Updates the max per-transaction withdrawal limit. Admin only.
    pub fn set_withdrawal_limit(env: Env, caller: Address, new_limit: i128) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;
        if new_limit <= 0 {
            return Err(Error::InvalidArgument);
        }
        let previous = instance_get::<_, i128>(&env, &MAX_WD).unwrap_or(0);
        instance_set(&env, &MAX_WD, &new_limit);
        record_treasury_audit(
            &env,
            &caller,
            TimelineEventType::ConfigChanged,
            symbol_short!("wd_limit"),
            symbol_short!("admin_cfg"),
            None,
            None,
            Some(previous),
            Some(new_limit),
        )?;
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            symbol_short!("wd_limit"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Configure a per-token rolling outflow window. Admin only.
    pub fn set_velocity_limit(
        env: Env,
        caller: Address,
        window_size_seconds: u64,
        max_window_outflow: i128,
    ) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;
        if window_size_seconds == 0 || max_window_outflow <= 0 {
            return Err(Error::InvalidArgument);
        }
        instance_set(&env, &VELOCITY_WINDOW, &window_size_seconds);
        instance_set(&env, &VELOCITY_MAX, &max_window_outflow);
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            symbol_short!("vel_cfg"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Return the configured rolling-window state for a token.
    pub fn velocity_status(env: Env, token: Address) -> VelocityStatus {
        let state = current_velocity_state(&env, &token);
        let maximum = instance_get(&env, &VELOCITY_MAX).unwrap_or(0);
        VelocityStatus {
            window_start: state.window_start,
            cumulative_outflow: state.cumulative_outflow,
            window_size_seconds: instance_get(&env, &VELOCITY_WINDOW).unwrap_or(0),
            max_window_outflow: maximum,
            paused: maximum > 0 && state.cumulative_outflow >= maximum,
        }
    }

    /// Approve a reserve strategy adapter. Admin only.
    pub fn approve_reserve_strategy(
        env: Env,
        caller: Address,
        strategy: Address,
    ) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;
        let approval_key = (STRATEGY_APPROVED, strategy.clone());
        if instance_get::<_, bool>(&env, &approval_key).unwrap_or(false) {
            return Err(Error::InvalidArgument);
        }
        instance_set(&env, &approval_key, &true);
        let mut strategies: Vec<Address> =
            instance_get(&env, &STRATEGY_LIST).unwrap_or(Vec::new(&env));
        strategies.push_back(strategy.clone());
        instance_set(&env, &STRATEGY_LIST, &strategies);
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            symbol_short!("strat_add"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Revoke an unused reserve strategy adapter. Admin only.
    pub fn revoke_reserve_strategy(
        env: Env,
        caller: Address,
        strategy: Address,
    ) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;
        let total_key = (STRATEGY_TOTAL, strategy.clone());
        if instance_get::<_, i128>(&env, &total_key).unwrap_or(0) != 0 {
            return Err(Error::InsufficientBalance);
        }
        let approval_key = (STRATEGY_APPROVED, strategy.clone());
        if !instance_get::<_, bool>(&env, &approval_key).unwrap_or(false) {
            return Err(Error::NotFound);
        }
        env.storage().instance().remove(&approval_key);
        let mut strategies: Vec<Address> =
            instance_get(&env, &STRATEGY_LIST).unwrap_or(Vec::new(&env));
        let mut index = 0;
        while index < strategies.len() {
            if strategies.get(index).unwrap() == strategy {
                strategies.remove(index);
                break;
            }
            index += 1;
        }
        instance_set(&env, &STRATEGY_LIST, &strategies);
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            symbol_short!("strat_del"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Set the reserve allocation cap, no greater than 30% of a category.
    pub fn set_strategy_allocation_cap(
        env: Env,
        caller: Address,
        cap_bps: u32,
    ) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;
        if cap_bps > MAX_STRATEGY_ALLOCATION_BPS {
            return Err(Error::InvalidArgument);
        }
        instance_set(&env, &STRATEGY_CAP, &cap_bps);
        Ok(())
    }

    pub fn strategy_allocation_cap(env: Env) -> u32 {
        instance_get(&env, &STRATEGY_CAP).unwrap_or(MAX_STRATEGY_ALLOCATION_BPS)
    }

    pub fn reserve_strategies(env: Env) -> Vec<Address> {
        instance_get(&env, &STRATEGY_LIST).unwrap_or(Vec::new(&env))
    }

    /// Credits `amount` into `category`'s balance for `token`. `TreasuryManager` only.
    pub fn deposit(
        env: Env,
        caller: Address,
        token: Address,
        category: Symbol,
        amount: i128,
    ) -> Result<(), Error> {
        // Cheap validation first — avoids auth commit on trivial rejects.
        if amount <= 0 {
            return Err(Error::InvalidArgument);
        }
        auth::require_permission(&env, &caller, Permission::TreasuryOperations)?;
        let key = (BALANCE, token.clone(), category.clone());
        let balance: i128 = env.storage().instance().get(&key).unwrap_or(0);
        let new_balance = balance.checked_add(amount).ok_or(Error::Overflow)?;
        token::Client::new(&env, &token).transfer(
            &caller,
            &env.current_contract_address(),
            &amount,
        );
        env.storage().instance().set(&key, &new_balance);
        record_treasury_audit(
            &env,
            &caller,
            TimelineEventType::RecordUpdated,
            symbol_short!("deposit"),
            symbol_short!("funds_in"),
            Some(token.clone()),
            Some(category.clone()),
            Some(balance),
            Some(new_balance),
        )?;
        emit_treasury_deposit(&env, &zero_correlation_id(&env),
            category, &caller, &token, amount, new_balance);
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            symbol_short!("deposit"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Returns the current balance for `token` in `category` (0 if never funded).
    pub fn category_balance(env: Env, token: Address, category: Symbol) -> i128 {
        instance_get::<_, i128>(&env, &(BALANCE, token, category)).unwrap_or(0)
    }

    /// Allocate category reserves to an approved SEP-41 strategy adapter.
    pub fn allocate_reserve(
        env: Env,
        caller: Address,
        token: Address,
        category: Symbol,
        strategy: Address,
        amount: i128,
    ) -> Result<(), Error> {
        if amount <= 0 {
            return Err(Error::InvalidArgument);
        }
        auth::require_permission(&env, &caller, Permission::TreasuryOperations)?;
        if !strategy_is_approved(&env, &strategy) {
            return Err(Error::Unauthorized);
        }

        let balance_key = (BALANCE, token.clone(), category.clone());
        let category_balance: i128 = instance_get(&env, &balance_key).unwrap_or(0);
        let cap_bps = Self::strategy_allocation_cap(env.clone());
        let cap_amount = category_balance
            .checked_mul(cap_bps as i128)
            .ok_or(Error::Overflow)?
            / 10_000;
        let mut allocated = 0_i128;
        let strategies = Self::reserve_strategies(env.clone());
        let mut index = 0;
        while index < strategies.len() {
            let adapter = strategies.get(index).unwrap();
            let position_key = (
                STRATEGY_POSITION,
                token.clone(),
                category.clone(),
                adapter,
            );
            allocated = allocated
                .checked_add(instance_get::<_, i128>(&env, &position_key).unwrap_or(0))
                .ok_or(Error::Overflow)?;
            index += 1;
        }
        if amount > category_balance || allocated.checked_add(amount).ok_or(Error::Overflow)? > cap_amount {
            return Err(Error::InsufficientBalance);
        }

        token::Client::new(&env, &token).transfer(
            &env.current_contract_address(),
            &strategy,
            &amount,
        );
        invoke_strategy_deposit(&env, &strategy, &token, amount)?;

        let position_key = (STRATEGY_POSITION, token.clone(), category, strategy.clone());
        let position = instance_get::<_, i128>(&env, &position_key).unwrap_or(0);
        instance_set(&env, &position_key, &position.checked_add(amount).ok_or(Error::Overflow)?);
        let total_key = (STRATEGY_TOTAL, strategy);
        let total = instance_get::<_, i128>(&env, &total_key).unwrap_or(0);
        instance_set(&env, &total_key, &total.checked_add(amount).ok_or(Error::Overflow)?);
        Ok(())
    }

    /// Recall strategy yield and record it in the dedicated yield category.
    pub fn harvest_yield(
        env: Env,
        caller: Address,
        token: Address,
        strategy: Address,
    ) -> Result<i128, Error> {
        auth::require_permission(&env, &caller, Permission::TreasuryOperations)?;
        if !strategy_is_approved(&env, &strategy) {
            return Err(Error::Unauthorized);
        }
        let token_client = token::Client::new(&env, &token);
        let before = token_client.balance(&env.current_contract_address());
        let earned = invoke_strategy_harvest(&env, &strategy, &token)?;
        if earned <= 0 {
            return Err(Error::InvalidArgument);
        }
        let received = token_client
            .balance(&env.current_contract_address())
            .checked_sub(before)
            .ok_or(Error::Overflow)?;
        if received != earned {
            return Err(Error::InsufficientBalance);
        }

        let key = (BALANCE, token.clone(), STRATEGY_YIELD_CATEGORY);
        let balance: i128 = instance_get(&env, &key).unwrap_or(0);
        let new_balance = balance.checked_add(earned).ok_or(Error::Overflow)?;
        instance_set(&env, &key, &new_balance);
        record_treasury_audit(
            &env,
            &caller,
            TimelineEventType::RecordUpdated,
            symbol_short!("harvest"),
            symbol_short!("yield_in"),
            Some(token.clone()),
            Some(STRATEGY_YIELD_CATEGORY),
            Some(balance),
            Some(new_balance),
        )?;
        emit_treasury_deposit(
            &env,
            &zero_correlation_id(&env),
            STRATEGY_YIELD_CATEGORY,
            &caller,
            &token,
            earned,
            new_balance,
        );
        Ok(earned)
    }

    pub fn strategy_position(
        env: Env,
        token: Address,
        category: Symbol,
        strategy: Address,
    ) -> i128 {
        instance_get(
            &env,
            &(STRATEGY_POSITION, token, category, strategy),
        )
        .unwrap_or(0)
    }

    /// Returns the currently configured max per-transaction withdrawal limit.
    pub fn withdrawal_limit(env: Env) -> i128 {
        instance_get::<_, i128>(&env, &MAX_WD).unwrap_or(0)
    }

    /// Withdraws `amount` of `token` from `category` to `to`.
    ///
    /// Guards, in order:
    /// 1. `amount` must be > 0                           → `Error::InvalidArgument`
    /// 2. `amount` must not exceed the withdrawal limit  → `Error::WithdrawalLimitExceeded`
    /// 3. `amount` must not exceed the category balance  → `Error::InsufficientBalance`
    /// 4. `caller` must hold `TreasuryManager`          → `Error::Unauthorized`
    ///
    /// On success, decrements the category balance and emits the shared
    /// `TreasuryWithdrawal` event with `(category, to, token, amount, remaining)`.
    pub fn withdraw(
        env: Env,
        caller: Address,
        token: Address,
        to: Address,
        amount: i128,
        category: Symbol,
    ) -> Result<(), Error> {
        // Gas optimization: cheap validation checks first
        if amount <= 0 {
            return Err(Error::InvalidArgument);
        }

        let limit: i128 = instance_get(&env, &MAX_WD).unwrap_or(0);
        if amount > limit {
            return Err(Error::WithdrawalLimitExceeded);
        }

        let key = (BALANCE, token.clone(), category.clone());
        let balance: i128 = instance_get(&env, &key).unwrap_or(0);
        if amount > balance {
            return Err(Error::InsufficientBalance);
        }

        // Auth check last
        auth::require_permission(&env, &caller, Permission::TreasuryOperations)?;

        ensure_strategy_liquidity(&env, &token, &category, amount)?;
        check_and_record_outflow(&env, &token, amount)?;

        // Quota enforcement: fail-open when unconfigured.
        shared::quota::check_and_consume(&env, &caller, &symbol_short!("wdraw"), amount)?;

        let remaining = balance - amount;
        instance_set(&env, &key, &remaining);
        record_treasury_audit(
            &env,
            &caller,
            TimelineEventType::PaymentSent,
            symbol_short!("withdraw"),
            symbol_short!("funds_out"),
            Some(token.clone()),
            Some(category.clone()),
            Some(balance),
            Some(remaining),
        )?;

        emit_treasury_withdrawal(&env, &zero_correlation_id(&env),
            category, &to, &token, amount, remaining);
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            symbol_short!("withdraw"),
            &caller,
            true,
            env.ledger().timestamp(),
        );

        Ok(())
    }

    /// Schedules a delayed withdrawal that may only execute inside `window`.
    ///
    /// The schedule is stored keyed by `action_id` so it can be executed later
    /// via [`TreasuryContract::execute_scheduled_withdraw`]. Admin only.
    pub fn schedule_withdraw(
        env: Env,
        caller: Address,
        action_id: Symbol,
        token: Address,
        to: Address,
        amount: i128,
        category: Symbol,
        window: TimeWindow,
    ) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;
        if amount <= 0 {
            return Err(Error::InvalidArgument);
        }
        // Validate the window shape up-front so we never persist a degenerate
        // schedule that can never execute.
        window.validate(window.not_before)?;
        let key = (SCHEDULE, action_id.clone());
        if env.storage().instance().has(&key) {
            return Err(Error::InvalidArgument);
        }
        let record = (token.clone(), to.clone(), amount, category.clone(), window.clone());
        env.storage().instance().set(&key, &record);
        record_treasury_audit(
            &env,
            &caller,
            TimelineEventType::ConfigChanged,
            symbol_short!("sched_wd"),
            symbol_short!("admin_cfg"),
            Some(token),
            Some(action_id),
            Some(window.not_before as i128),
            Some(window.expires_at as i128),
        )?;
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            symbol_short!("sched_wd"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Executes a previously scheduled withdrawal, enforcing its time window.
    ///
    /// Rejects with `Error::ActionTooEarly` before `not_before`, and
    /// `Error::ActionExpired` at or after `expires_at`. The schedule is
    /// consumed on success so it cannot be replayed.
    pub fn execute_scheduled_withdraw(
        env: Env,
        caller: Address,
        action_id: Symbol,
    ) -> Result<(), Error> {
        let key = (SCHEDULE, action_id.clone());
        let record: (Address, Address, i128, Symbol, TimeWindow) = env
            .storage()
            .instance()
            .get(&key)
            .ok_or(Error::NotFound)?;
        let (token, to, amount, category, window) = record;

        // Window check before auth so early/late/stale attempts are cheap and
        // produce a precise error even for unauthorised callers.
        validate_window(&env, &caller, symbol_short!("exec_wd"), &window)?;

        auth::require_permission(&env, &caller, Permission::TreasuryOperations)?;

        let limit: i128 = instance_get(&env, &MAX_WD).unwrap_or(0);
        if amount > limit {
            return Err(Error::WithdrawalLimitExceeded);
        }
        let bal_key = (BALANCE, token.clone(), category.clone());
        let balance: i128 = instance_get(&env, &bal_key).unwrap_or(0);
        if amount > balance {
            return Err(Error::InsufficientBalance);
        }
        ensure_strategy_liquidity(&env, &token, &category, amount)?;
        check_and_record_outflow(&env, &token, amount)?;
        shared::quota::check_and_consume(&env, &caller, &symbol_short!("wdraw"), amount)?;

        let remaining = balance - amount;
        instance_set(&env, &bal_key, &remaining);
        env.storage().instance().remove(&key);
        record_treasury_audit(
            &env,
            &caller,
            TimelineEventType::PaymentSent,
            symbol_short!("exec_wd"),
            symbol_short!("schd_exec"),
            Some(token.clone()),
            Some(category.clone()),
            Some(balance),
            Some(remaining),
        )?;
        emit_treasury_withdrawal(&env, &zero_correlation_id(&env),
            category, &to, &token, amount, remaining);
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            symbol_short!("exec_wd"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Returns the stored time window for `action_id`, if a schedule exists.
    pub fn scheduled_window(env: Env, action_id: Symbol) -> Option<TimeWindow> {
        let key = (SCHEDULE, action_id);
        env.storage()
            .instance()
            .get::<_, (Address, Address, i128, Symbol, TimeWindow)>(&key)
            .map(|(_, _, _, _, w)| w)
    }

    /// Emergency reserve withdrawal for `token`.
    ///
    /// Only callable by the admin, and only while the contract is paused.
    /// Intended to move reserve funds to safety when something has gone wrong.
    pub fn emergency_withdraw(
        env: Env,
        caller: Address,
        token: Address,
        to: Address,
        amount: i128,
    ) -> Result<(), Error> {
        // Gas optimization: cheapest validations first.
        if amount <= 0 {
            return Err(Error::InvalidArgument);
        }
        if !shared::storage::is_paused(&env) {
            return Err(Error::NotPaused);
        }

        let key = (BALANCE, token.clone(), RESERVE_CATEGORY);
        let balance: i128 = instance_get(&env, &key).unwrap_or(0);
        let new_balance = balance
            .checked_sub(amount)
            .ok_or(Error::InsufficientBalance)?;
        if new_balance < 0 {
            return Err(Error::InsufficientBalance);
        }

        // Auth check last
        auth::require_admin(&env, &caller)?;
        ensure_strategy_liquidity(&env, &token, &RESERVE_CATEGORY, amount)?;
        check_and_record_outflow(&env, &token, amount)?;
        instance_set(&env, &key, &new_balance);
        record_treasury_audit(
            &env,
            &caller,
            TimelineEventType::PaymentSent,
            symbol_short!("emrg_wd"),
            symbol_short!("emergency"),
            Some(token.clone()),
            Some(RESERVE_CATEGORY),
            Some(balance),
            Some(new_balance),
        )?;

        events::emit(
            &env,
            events::TREASURY_EMERGENCY_WITHDRAW,
            (caller.clone(), token, to, amount),
        );
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            symbol_short!("emrg_wd"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Registers the referral contract address authorised to call
    /// `distribute_reward`. Admin only.
    pub fn set_referral_contract(
        env: Env,
        caller: Address,
        referral_contract: Address,
    ) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;
        let previous = instance_get::<_, Address>(&env, &REFERRAL_CONTRACT);
        let was_configured = previous.is_some();
        if let Some(previous_contract) = previous {
            auth::revoke_role(&env, &caller, &previous_contract, Role::ServiceActor)?;
        }
        auth::grant_role(&env, &caller, &referral_contract, Role::ServiceActor)?;
        instance_set(&env, &REFERRAL_CONTRACT, &referral_contract);
        record_treasury_audit(
            &env,
            &caller,
            TimelineEventType::ConfigChanged,
            symbol_short!("ref_ctr"),
            symbol_short!("admin_cfg"),
            Some(referral_contract.clone()),
            None,
            Some(if was_configured { 1 } else { 0 }),
            Some(1),
        )?;
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            symbol_short!("ref_ctr"),
            &caller,
            true,
            env.ledger().timestamp(),
        );
        Ok(())
    }

    /// Returns the currently registered referral contract address, if any.
    pub fn referral_contract(env: Env) -> Option<Address> {
        instance_get(&env, &REFERRAL_CONTRACT)
    }

    /// Pays a referral commission of `amount` in `token` to `recipient` from the
    /// `Rewards` category.
    ///
    /// Callable only by the registered referral contract.
    pub fn distribute_reward(
        env: Env,
        token: Address,
        recipient: Address,
        amount: i128,
    ) -> Result<(), Error> {
        // Cheap validation before auth commit.
        if amount <= 0 {
            return Err(Error::InvalidArgument);
        }

        let key = (BALANCE, token.clone(), REWARDS_CATEGORY);
        let balance: i128 = instance_get(&env, &key).unwrap_or(0);
        if amount > balance {
            return Err(Error::InsufficientBalance);
        }

        // Auth check after cheap validations pass.
        let referral_contract: Address =
            instance_get(&env, &REFERRAL_CONTRACT).ok_or(Error::Unauthorized)?;
        auth::require_permission(&env, &referral_contract, Permission::ServiceOperation)?;
        ensure_strategy_liquidity(&env, &token, &REWARDS_CATEGORY, amount)?;
        check_and_record_outflow(&env, &token, amount)?;

        let remaining = balance - amount;
        instance_set(&env, &key, &remaining);
        record_treasury_audit(
            &env,
            &referral_contract,
            TimelineEventType::PaymentSent,
            symbol_short!("reward"),
            symbol_short!("ref_pay"),
            Some(token.clone()),
            Some(REWARDS_CATEGORY),
            Some(balance),
            Some(remaining),
        )?;

        emit_commission_paid(&env, &zero_correlation_id(&env),
            &recipient, &token, amount, env.ledger().timestamp());
        emit_action_executed(
            &env,
            &zero_correlation_id(&env),
            symbol_short!("treasury"),
            symbol_short!("reward"),
            &referral_contract,
            true,
            env.ledger().timestamp(),
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Quota management (Issue #65) — maintainer diagnostics & overrides
    // -----------------------------------------------------------------------

    /// Set quota limits for a resource (admin only).
    pub fn set_quota_config(
        env: Env,
        caller: Address,
        resource: Symbol,
        config: shared::quota::QuotaConfig,
    ) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;
        shared::quota::set_quota_config(&env, &resource, &config)?;
        record_treasury_audit(
            &env,
            &caller,
            TimelineEventType::ConfigChanged,
            symbol_short!("quota_cfg"),
            symbol_short!("admin_cfg"),
            None,
            Some(resource.clone()),
            None,
            None,
        )
    }

    /// Inspect quota usage for an actor/resource pair (maintainer diagnostics).
    pub fn quota_status(env: Env, actor: Address, resource: Symbol) -> shared::quota::QuotaStatus {
        shared::quota::get_quota_status(&env, &actor, &resource)
    }

    /// Returns the newest maintainer-only audit entries.
    pub fn audit_trail(
        env: Env,
        maintainer: Address,
        limit: u32,
    ) -> Result<soroban_sdk::Vec<shared::ActionAuditEntry>, Error> {
        shared::timeline::action_audit_trail(&env, &maintainer, limit)
    }

    // -----------------------------------------------------------------------
    // Tamper-evident audit ledger
    // -----------------------------------------------------------------------

    /// Returns the audit-ledger head: number of sealed entries and the newest
    /// hash. Public and bounded: it exposes no entry payloads.
    pub fn audit_ledger_head(env: Env) -> shared::AuditLedgerHead {
        shared::audit_ledger::head(&env)
    }

    /// Verifies a page of the hash chain, starting at `from_seq`.
    ///
    /// Public: the result contains only pass/fail metadata and the first
    /// offending sequence, never entry contents. Loop on `resume_at` until
    /// `complete` is `true` for a full verification.
    pub fn verify_audit_ledger(
        env: Env,
        from_seq: u64,
        limit: u32,
    ) -> Result<shared::AuditLedgerVerification, Error> {
        shared::audit_ledger::verify_range(&env, from_seq, limit)
    }

    /// Verifies the stored checkpoints written by `seal_audit_ledger`.
    ///
    /// Complements `verify_audit_ledger`: the range scan proves every link,
    /// anchors prove a specific historical head survived a truncation.
    pub fn verify_audit_ledger_anchors(
        env: Env,
        from_id: u64,
        limit: u32,
    ) -> Result<shared::AuditAnchorVerification, Error> {
        shared::audit_ledger::verify_anchors(&env, from_id, limit)
    }

    /// Exports a bounded page of full audit-ledger entries, newest head
    /// included. Admin only: entries carry actor addresses and financial
    /// state, matching the existing `audit_trail` access policy.
    pub fn export_audit_ledger(
        env: Env,
        maintainer: Address,
        cursor: Option<u64>,
        limit: u32,
    ) -> Result<shared::AuditLedgerExport, Error> {
        shared::audit_ledger::export(&env, &maintainer, cursor, limit)
    }

    /// Writes a checkpoint of the current chain head. Admin only.
    ///
    /// Recommended before migrations, upgrades, key rotation or any operation
    /// that touches persistent storage, so a later rollback is provable.
    pub fn seal_audit_ledger(
        env: Env,
        caller: Address,
    ) -> Result<shared::AuditLedgerAnchor, Error> {
        auth::require_admin(&env, &caller)?;
        shared::audit_ledger::seal(&env)
    }

    /// Reset quota usage for an actor/resource pair (admin override path).
    pub fn reset_quota(
        env: Env,
        caller: Address,
        actor: Address,
        resource: Symbol,
    ) -> Result<(), Error> {
        auth::require_admin(&env, &caller)?;
        shared::quota::reset_quota(&env, &actor, &resource);
        record_treasury_audit(
            &env,
            &caller,
            TimelineEventType::ConfigChanged,
            symbol_short!("quota_rst"),
            symbol_short!("adm_ovr"),
            Some(actor.clone()),
            Some(resource.clone()),
            None,
            None,
        )?;
        Ok(())
    }
}

fn current_velocity_state(env: &Env, token: &Address) -> VelocityState {
    let state_key = (VELOCITY_STATE, token.clone());
    let state: VelocityState = instance_get(env, &state_key).unwrap_or(VelocityState {
        window_start: env.ledger().timestamp(),
        cumulative_outflow: 0,
        active: false,
    });
    let window_size = instance_get::<_, u64>(env, &VELOCITY_WINDOW).unwrap_or(0);
    if state.active
        && window_size > 0
        && env.ledger().timestamp() >= state.window_start.saturating_add(window_size)
    {
        VelocityState {
            window_start: env.ledger().timestamp(),
            cumulative_outflow: 0,
            active: false,
        }
    } else {
        state
    }
}

fn check_and_record_outflow(env: &Env, token: &Address, amount: i128) -> Result<(), Error> {
    let window_size = instance_get::<_, u64>(env, &VELOCITY_WINDOW).unwrap_or(0);
    let maximum = instance_get::<_, i128>(env, &VELOCITY_MAX).unwrap_or(0);
    if window_size == 0 || maximum <= 0 {
        return Ok(());
    }

    let mut state = current_velocity_state(env, token);
    if state.cumulative_outflow >= maximum {
        return Err(Error::OperationPaused);
    }
    let next_outflow = state
        .cumulative_outflow
        .checked_add(amount)
        .ok_or(Error::Overflow)?;
    if next_outflow > maximum {
        return Err(Error::QuotaExceeded);
    }

    state.cumulative_outflow = next_outflow;
    state.active = true;
    let state_key = (VELOCITY_STATE, token.clone());
    instance_set(env, &state_key, &state);
    if next_outflow == maximum {
        env.events().publish(
            (symbol_short!("treasury"), symbol_short!("vel_trip"), token.clone()),
            (state.window_start, next_outflow, maximum, env.ledger().timestamp()),
        );
    }
    Ok(())
}

fn strategy_is_approved(env: &Env, strategy: &Address) -> bool {
    instance_get(env, &(STRATEGY_APPROVED, strategy.clone())).unwrap_or(false)
}

fn invoke_strategy_deposit(
    env: &Env,
    strategy: &Address,
    token: &Address,
    amount: i128,
) -> Result<(), Error> {
    let function = Symbol::new(env, "deposit_reserve");
    match env.try_invoke_contract::<(), Error>(
        strategy,
        &function,
        (token.clone(), amount).into_val(env),
    ) {
        Ok(Ok(())) => Ok(()),
        _ => Err(Error::InvalidArgument),
    }
}

fn invoke_strategy_withdraw(
    env: &Env,
    strategy: &Address,
    token: &Address,
    recipient: &Address,
    amount: i128,
) -> Result<i128, Error> {
    let function = Symbol::new(env, "withdraw_reserve");
    match env.try_invoke_contract::<i128, Error>(
        strategy,
        &function,
        (token.clone(), recipient.clone(), amount).into_val(env),
    ) {
        Ok(Ok(received)) => Ok(received),
        _ => Err(Error::InvalidArgument),
    }
}

fn invoke_strategy_harvest(
    env: &Env,
    strategy: &Address,
    token: &Address,
) -> Result<i128, Error> {
    let function = Symbol::new(env, "harvest_yield");
    match env.try_invoke_contract::<i128, Error>(
        strategy,
        &function,
        (token.clone(), env.current_contract_address()).into_val(env),
    ) {
        Ok(Ok(earned)) => Ok(earned),
        _ => Err(Error::InvalidArgument),
    }
}

fn ensure_strategy_liquidity(
    env: &Env,
    token: &Address,
    category: &Symbol,
    amount: i128,
) -> Result<(), Error> {
    let strategies: Vec<Address> = instance_get(env, &STRATEGY_LIST).unwrap_or(Vec::new(env));
    let mut has_position = false;
    let mut i = 0;
    while i < strategies.len() {
        let position_key = (
            STRATEGY_POSITION,
            token.clone(),
            category.clone(),
            strategies.get(i).unwrap(),
        );
        if instance_get::<_, i128>(env, &position_key).unwrap_or(0) > 0 {
            has_position = true;
            break;
        }
        i += 1;
    }
    if !has_position {
        return Ok(());
    }

    let treasury = env.current_contract_address();
    let token_client = token::Client::new(env, token);
    let mut liquid = token_client.balance(&treasury);
    i = 0;
    while liquid < amount && i < strategies.len() {
        let strategy = strategies.get(i).unwrap();
        let position_key = (
            STRATEGY_POSITION,
            token.clone(),
            category.clone(),
            strategy.clone(),
        );
        let position = instance_get::<_, i128>(env, &position_key).unwrap_or(0);
        if position > 0 {
            let requested = position.min(amount - liquid);
            let received = invoke_strategy_withdraw(env, &strategy, token, &treasury, requested)?;
            if received <= 0 || received > requested {
                return Err(Error::InsufficientBalance);
            }
            let updated_liquid = token_client.balance(&treasury);
            if updated_liquid.checked_sub(liquid).ok_or(Error::Overflow)? < received {
                return Err(Error::InsufficientBalance);
            }
            instance_set(env, &position_key, &(position - received));
            let total_key = (STRATEGY_TOTAL, strategy);
            let total = instance_get::<_, i128>(env, &total_key).unwrap_or(0);
            instance_set(env, &total_key, &total.checked_sub(received).ok_or(Error::Overflow)?);
            liquid = updated_liquid;
        }
        i += 1;
    }
    if liquid < amount {
        return Err(Error::InsufficientBalance);
    }
    Ok(())
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod invariants_test;

/// CPU/memory regression suite for the treasury's critical entry points.
/// Kept separate from `test` so the behavioural tests and the budget
/// thresholds can be read (and updated) independently.
#[cfg(test)]
mod budget_test;

/// CPU/memory footprint profiling for CI (issue #192). Complements
/// `budget_test` (issue #158) with a plain, unthresholded measurement that
/// `scripts/profile-budget.sh` compares against a checked-in baseline.
#[cfg(test)]
mod profile_budget;
