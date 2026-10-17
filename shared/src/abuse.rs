//! Abuse controls layered on top of quota checks.
///
/// Quotas limit repeated use of a resource. Abuse scoring records why an
/// operation was rejected so frontends and maintainers can distinguish normal
/// throttling from suspicious patterns.

use soroban_sdk::{contracttype, Address, Env, Symbol};

use crate::errors::Error;
use crate::storage::{persistent_get, persistent_set};

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbusePolicy {
    pub max_score: u32,
    pub decay_per_window: u32,
    pub window_ledgers: u32,
}

impl Default for AbusePolicy {
    fn default() -> Self {
        Self {
            max_score: 100,
            decay_per_window: 10,
            window_ledgers: 17_280,
        }
    }
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbuseState {
    pub score: u32,
    pub last_ledger: u32,
    pub strikes: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
enum AbuseKey {
    Policy(Symbol),
    State(Address, Symbol),
}

pub fn set_abuse_policy(env: &Env, resource: &Symbol, policy: &AbusePolicy) -> Result<(), Error> {
    if policy.max_score == 0 || policy.window_ledgers == 0 {
        return Err(Error::ConfigInvalid);
    }
    persistent_set(env, &AbuseKey::Policy(resource.clone()), policy);
    Ok(())
}

pub fn get_abuse_policy(env: &Env, resource: &Symbol) -> AbusePolicy {
    persistent_get(env, &AbuseKey::Policy(resource.clone())).unwrap_or_default()
}

pub fn get_abuse_state(env: &Env, actor: &Address, resource: &Symbol) -> AbuseState {
    persistent_get(env, &AbuseKey::State(actor.clone(), resource.clone())).unwrap_or(AbuseState {
        score: 0,
        last_ledger: env.ledger().sequence(),
        strikes: 0,
    })
}

pub fn record_abuse(
    env: &Env,
    actor: &Address,
    resource: &Symbol,
    weight: u32,
) -> Result<AbuseState, Error> {
    let policy = get_abuse_policy(env, resource);
    let mut state = get_abuse_state(env, actor, resource);
    let elapsed = env.ledger().sequence().saturating_sub(state.last_ledger);
    if elapsed >= policy.window_ledgers {
        let windows = elapsed / policy.window_ledgers;
        state.score = state
            .score
            .saturating_sub(policy.decay_per_window.saturating_mul(windows));
    }
    state.score = state.score.saturating_add(weight);
    state.strikes = state.strikes.saturating_add(1);
    state.last_ledger = env.ledger().sequence();
    persistent_set(
        env,
        &AbuseKey::State(actor.clone(), resource.clone()),
        &state,
    );
    if state.score > policy.max_score {
        return Err(Error::QuotaExceeded);
    }
    Ok(state)
}

/// Cross-boundary trust decision for abuse scoring.
///
/// The abuse module is the boundary between an untrusted actor and the
/// resource it is trying to consume. Before any operation is authorized,
/// the caller must check whether the actor's accumulated score exceeds the
/// policy maximum. This is the guard that makes the boundary decision
/// explicit rather than implicit in the caller.
///
/// Returns `true` when the actor is at or above the policy maximum and
/// the caller must reject the operation. Returns `false` when the actor
/// is within bounds.
pub fn is_abuse_blocked(env: &Env, actor: &Address, resource: &Symbol) -> bool {
    let policy = get_abuse_policy(env, resource);
    let state = get_abuse_state(env, actor, resource);
    state.score >= policy.max_score
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;

    fn setup() -> Env {
        Env::default()
    }

    #[test]
    fn record_abuse_accumulates_score_and_strikes() {
        let env = setup();
        let actor = Address::generate(&env);
        let resource = Symbol::new(&env, "invite");
        let state = record_abuse(&env, &actor, &resource, 5).unwrap();
        assert_eq!(state.score, 5);
        assert_eq!(state.strikes, 1);
    }

    #[test]
    fn record_abuse_rejects_when_max_score_exceeded() {
        let env = setup();
        let actor = Address::generate(&env);
        let resource = Symbol::new(&env, "invite");
        let policy = AbusePolicy {
            max_score: 10,
            decay_per_window: 1,
            window_ledgers: 10,
        };
        set_abuse_policy(&env, &resource, &policy).unwrap();
        let result = record_abuse(&env, &actor, &resource, 11);
        assert!(result.is_err());
    }

    #[test]
    fn is_abuse_blocked_respects_policy_max() {
        let env = setup();
        let actor = Address::generate(&env);
        let resource = Symbol::new(&env, "invite");
        let policy = AbusePolicy {
            max_score: 10,
            decay_per_window: 1,
            window_ledgers: 10,
        };
        set_abuse_policy(&env, &resource, &policy).unwrap();
        assert!(!is_abuse_blocked(&env, &actor, &resource));
        let _ = record_abuse(&env, &actor, &resource, 10);
        assert!(is_abuse_blocked(&env, &actor, &resource));
    }

    #[test]
    fn set_abuse_policy_rejects_zero_max_score() {
        let env = setup();
        let resource = Symbol::new(&env, "invite");
        let policy = AbusePolicy {
            max_score: 0,
            decay_per_window: 1,
            window_ledgers: 10,
        };
        assert_eq!(set_abuse_policy(&env, &resource, &policy), Err(Error::ConfigInvalid));
    }

    #[test]
    fn set_abuse_policy_rejects_zero_window() {
        let env = setup();
        let resource = Symbol::new(&env, "invite");
        let policy = AbusePolicy {
            max_score: 10,
            decay_per_window: 1,
            window_ledgers: 0,
        };
        assert_eq!(set_abuse_policy(&env, &resource, &policy), Err(Error::ConfigInvalid));
    }
}
