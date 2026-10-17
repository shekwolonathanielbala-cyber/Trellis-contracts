//! Versioned domain-event envelopes and producer/consumer validation.
//!
//! Events are part of the public contract surface.  This module keeps the
//! event name and schema version explicit and validates the field set before a
//! producer publishes an event.  Consumers can accept a preferred version and
//! fall back to an older compatible version without guessing from payload
//! shape.

use soroban_sdk::{contracttype, Env, Map, IntoVal, Symbol, Val, Vec};

/// A versioned event schema.  `required_fields` is the exact allow-list for a
/// payload, so producers cannot silently publish misspelled or undocumented
/// fields.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EventSchema {
    pub name: Symbol,
    pub version: u32,
    pub required_fields: Vec<Symbol>,
}

/// The value published to the ledger event stream.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DomainEvent {
    pub name: Symbol,
    pub version: u32,
    pub payload: Map<Symbol, Val>,
}

/// Validation failures are intentionally compact and contain no payload data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventValidationError {
    EmptyName,
    UnsupportedVersion,
    MissingRequiredField,
    UnknownField,
}

/// Validate an event against its producer-owned schema.
pub fn validate_event(
    schema: &EventSchema,
    payload: &Map<Symbol, Val>,
) -> Result<(), EventValidationError> {
    // `Symbol` cannot be empty (`Symbol::new` rejects the empty string), so
    // the former `is_empty` guard is unreachable. The `EmptyName` variant is
    // retained for API compatibility.
    if schema.version == 0 {
        return Err(EventValidationError::UnsupportedVersion);
    }

    for field in schema.required_fields.iter() {
        if !payload.contains_key(field.clone()) {
            return Err(EventValidationError::MissingRequiredField);
        }
    }
    for field in payload.keys() {
        if !schema.required_fields.iter().any(|required| required == field) {
            return Err(EventValidationError::UnknownField);
        }
    }
    Ok(())
}

/// Validate and publish a versioned event.  The event is not emitted when the
/// schema check fails.
pub fn publish_event(
    env: &Env,
    schema: &EventSchema,
    payload: Map<Symbol, Val>,
) -> Result<(), EventValidationError> {
    validate_event(schema, &payload)?;
    env.events().publish((schema.name.clone(), schema.version), DomainEvent {
        name: schema.name.clone(),
        version: schema.version,
        payload,
    });
    Ok(())
}

/// Return the newest supported schema version not newer than the producer.
/// This is the consumer fallback rule: a consumer can process its preferred
/// version, or an older version with a known decoder, but never an unknown
/// future version.
pub fn consumer_version(
    producer_version: u32,
    supported_versions: &Vec<u32>,
) -> Option<u32> {
    supported_versions
        .iter()
        .filter(|version| *version <= producer_version)
        .max()
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{symbol_short, Env};

    fn schema(env: &Env) -> EventSchema {
        let mut fields = Vec::new(env);
        fields.push_back(symbol_short!("amount"));
        fields.push_back(symbol_short!("actor"));
        EventSchema { name: symbol_short!("payment"), version: 1, required_fields: fields }
    }

    #[test]
    fn valid_event_is_accepted_and_version_is_explicit() {
        let env = Env::default();
        let schema = schema(&env);
        let mut payload = Map::new(&env);
        payload.set(symbol_short!("amount"), 10_i128.into_val(&env));
        payload.set(symbol_short!("actor"), 1_u32.into_val(&env));
        assert!(validate_event(&schema, &payload).is_ok());
        assert_eq!(consumer_version(2, &soroban_sdk::vec![&env, 1_u32]), Some(1));
    }

    #[test]
    fn missing_and_unknown_fields_are_rejected() {
        let env = Env::default();
        let schema = schema(&env);
        let mut missing = Map::new(&env);
        missing.set(symbol_short!("amount"), 10_i128.into_val(&env));
        assert_eq!(validate_event(&schema, &missing), Err(EventValidationError::MissingRequiredField));

        let mut unknown = Map::new(&env);
        unknown.set(symbol_short!("amount"), 10_i128.into_val(&env));
        unknown.set(symbol_short!("actor"), 1_u32.into_val(&env));
        unknown.set(symbol_short!("extra"), true.into_val(&env));
        assert_eq!(validate_event(&schema, &unknown), Err(EventValidationError::UnknownField));
    }

    #[test]
    fn unknown_versions_do_not_fallback_forward() {
        let env = Env::default();
        let supported = soroban_sdk::vec![&env, 1_u32, 2_u32];
        assert_eq!(consumer_version(0, &supported), None);
        assert_eq!(consumer_version(3, &supported), Some(2));
    }
}
