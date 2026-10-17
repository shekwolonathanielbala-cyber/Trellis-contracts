//! Tamper-evident, chronological ledger for privileged and financial events.
//!
//! ## Why this exists
//!
//! [`crate::timeline::record_action_audit_event`] records *what* a privileged
//! actor did, but each record is stored independently: someone able to rewrite
//! contract storage (or a migration that touches the audit key space) could
//! edit or remove a record without leaving a trace. This module turns that
//! append-only store into a **hash chain**:
//!
//! ```text
//! entry[n].prev_hash = entry[n-1].hash
//! entry[n].hash      = sha256(domain || canonical_fields(entry[n]))
//! ```
//!
//! The first entry chains to 32 zero bytes. Every entry's hash covers its
//! position (`seq`), full domain context, ledger stamp and the previous hash,
//! so changing any recorded field, reordering entries, inserting an entry, or
//! deleting one from the middle breaks every subsequent link.
//!
//! ## What is covered
//!
//! Every call to [`crate::timeline::record_action_audit_event`] — the shared
//! choke point used by treasury (deposits, withdrawals, emergency withdrawals,
//! fee/reward payments, role and config changes), aid, referral, oracle and
//! access-control — appends one ledger entry. Legacy
//! [`crate::timeline::record_audit_event`] records (used for redaction and
//! deletion bookkeeping) are *not* chained; their hash-linked replacement is
//! the ledger entry emitted by the redacting action itself.
//!
//! ## Verifiability and export
//!
//! - [`head`] returns the current chain head: the number of sealed entries and
//!   the newest hash.
//! - [`verify_range`] recomputes the chain from a cursor and reports the first
//!   entry that does not match. It is read-only and callable by anyone: it
//!   never returns entry payloads, only pass/fail plus the offending sequence.
//! - [`export`] (maintainer-gated) returns a bounded page of full entries,
//!   each carrying `prev_hash` and `hash`, plus the head they must chain to.
//!   An off-chain verifier can recompute every hash without trusting the
//!   contract that produced the page.
//! - [`seal`] writes a checkpoint (`count`, `head_hash`, ledger stamp) so a
//!   tail truncation that also rewrites the head still disagrees with an
//!   earlier, independently readable anchor. [`verify_anchors`] checks them.
//!
//! Every append also publishes the `(audit, aud_seal)` event with
//! `(seq, hash, prev_hash, ledger)`. Ledger events are the external,
//! append-only evidence: an off-chain indexer that records them can detect a
//! wholesale rewrite that also rewrites the stored anchors (see
//! `docs/AUDIT_LEDGER.md` for the full threat model).
//!
//! ## Failure modes (summary)
//!
//! | Situation | Result |
//! | --- | --- |
//! | A stored field was edited | [`AuditTamperReason::EntryHashMismatch`] |
//! | Entries reordered / an entry removed | [`AuditTamperReason::PrevHashMismatch`] or `MissingEntry` |
//! | `seq` was rewritten | [`AuditTamperReason::UnexpectedSequence`] |
//! | Head rolled back without anchors | `HeadMismatch` after a full range scan |
//! | Head rolled back *with* an earlier anchor | [`AuditTamperReason::AnchorMismatch`] |
//! | Unknown schema version | [`AuditTamperReason::UnsupportedVersion`] |
//!
//! A verifier that cannot reach the head must not report success: the
//! `complete` flag is `false` and the caller should continue from
//! `resume_at`. See `docs/AUDIT_LEDGER.md` for operational recovery.

use soroban_sdk::xdr::ToXdr;
use soroban_sdk::{contracttype, symbol_short, Address, Bytes, BytesN, Env, Symbol, Vec};

use crate::auth::{require_role, Role};
use crate::errors::Error;
use crate::storage::{persistent_get, persistent_set};
use crate::timeline::TimelineEventType;

/// Schema version stamped into every entry and covered by its hash.
///
/// Bump only for an incompatible change to the hashed field encoding or the
/// `event_type` tag table; verifiers reject entries written under a version
/// they do not understand ([`AuditTamperReason::UnsupportedVersion`]).
pub const AUDIT_LEDGER_VERSION: u32 = 1;

/// Domain separator mixed into every entry hash.
///
/// Prevents an audit hash from colliding with a hash of the same bytes
/// produced for another purpose (for example a canonical payload fingerprint
/// or a release-readiness receipt).
pub const AUDIT_LEDGER_DOMAIN: &[u8] = b"trellis.audit-ledger.v1";

/// Default and maximum number of entries returned by [`export`].
pub const MAX_AUDIT_EXPORT_ENTRIES: u32 = 50;

/// Maximum number of entries a single [`verify_range`] call examines.
///
/// Verification is paged so it can never become an unbounded read inside one
/// transaction. Callers loop until `complete` is `true`.
pub const MAX_AUDIT_VERIFY_ENTRIES: u32 = 100;

/// Emitted for every sealed entry: `(seq, hash, prev_hash, ledger)`.
pub const AUDIT_LEDGER_EVENT: Symbol = symbol_short!("aud_seal");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// One sealed audit entry.
///
/// `hash` is not part of its own pre-image; it commits to every other field,
/// including [`Self::prev_hash`] and the schema [`Self::version`].
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLedgerEntry {
    /// Schema version of the hashed encoding.
    pub version: u32,
    /// Zero-based position in the chain. Never reused.
    pub seq: u64,
    /// Timeline event classification (mapped to a stable tag in the hash).
    pub event_type: TimelineEventType,
    /// Authenticated actor that performed the action.
    pub actor: Address,
    /// Protocol area, e.g. `treasury`.
    pub scope: Symbol,
    /// Stable action label, e.g. `withdraw`.
    pub action: Symbol,
    /// Stable reason code supplied by the caller.
    pub reason: Symbol,
    /// Public resource address affected, when applicable.
    pub resource: Option<Address>,
    /// Stable attribute such as a category or role, when applicable.
    pub attribute: Option<Symbol>,
    /// Numeric state before the action, when relevant.
    pub before: Option<i128>,
    /// Numeric state after the action, when relevant.
    pub after: Option<i128>,
    /// Ledger sequence at which the entry was sealed.
    pub ledger: u32,
    /// Ledger timestamp at which the entry was sealed.
    pub timestamp: u64,
    /// Hash of the previous entry, or 32 zero bytes for the first entry.
    pub prev_hash: BytesN<32>,
    /// `sha256(AUDIT_LEDGER_DOMAIN || canonical_fields(self))`.
    pub hash: BytesN<32>,
}

/// Current chain head.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLedgerHead {
    /// Schema version of the entries in this chain.
    pub version: u32,
    /// Number of sealed entries; also the `seq` the next entry will use.
    pub count: u64,
    /// Hash of entry `count - 1`, or 32 zero bytes when the chain is empty.
    pub head_hash: BytesN<32>,
}

/// One checkpoint of the head, written by [`seal`].
///
/// Anchors are deliberately redundant with the head: they let a verifier
/// detect a head rollback (truncation) that leaves the remaining chain
/// internally consistent.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLedgerAnchor {
    /// Zero-based position in the anchor list.
    pub id: u64,
    /// Number of entries that existed when the anchor was written.
    pub seq: u64,
    /// Head hash at that moment.
    pub hash: BytesN<32>,
    /// Ledger sequence at which the anchor was written.
    pub ledger: u32,
    /// Ledger timestamp at which the anchor was written.
    pub timestamp: u64,
}

/// Why a chain verification failed.
#[contracttype]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditTamperReason {
    /// Every examined entry is authentic and links to the previous one.
    ChainIntact,
    /// A sequence number in the verified range has no stored entry.
    MissingEntry,
    /// A stored entry's `seq` field does not match the key it was read from.
    UnexpectedSequence,
    /// The entry was written under a schema this verifier does not support.
    UnsupportedVersion,
    /// `entry.prev_hash` does not equal the previous entry's `hash`.
    PrevHashMismatch,
    /// Recomputing the hash from the entry's fields does not match its `hash`.
    EntryHashMismatch,
    /// The chain does not end at the stored head hash.
    HeadMismatch,
    /// A stored anchor disagrees with the recomputed entry hash or the head.
    AnchorMismatch,
}

/// Result of verifying a range of the chain.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLedgerVerification {
    /// `true` only when the range reached the head with every link intact.
    pub ok: bool,
    /// Whether this call reached `head.count`. A partial scan that is intact
    /// returns `ok = false, complete = false` so callers cannot mistake it for
    /// a full verification.
    pub complete: bool,
    /// First sequence number examined.
    pub from_seq: u64,
    /// Number of entries examined.
    pub checked: u64,
    /// Head count observed when verification started.
    pub head_seq: u64,
    /// Head hash observed when verification started.
    pub head_hash: BytesN<32>,
    /// First offending sequence, when `ok` is `false`.
    pub first_bad_seq: Option<u64>,
    /// Machine-readable outcome.
    pub reason: AuditTamperReason,
    /// Sequence to resume from when `complete` is `false`; `None` at the head.
    pub resume_at: Option<u64>,
}

/// Result of verifying stored anchors.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditAnchorVerification {
    /// `true` when every examined anchor matches the chain.
    pub ok: bool,
    /// Number of anchors examined.
    pub checked: u64,
    /// First offending anchor id, when `ok` is `false`.
    pub first_bad_id: Option<u64>,
    /// Machine-readable outcome.
    pub reason: AuditTamperReason,
    /// Head count observed when verification started.
    pub head_seq: u64,
    /// Anchor id to resume from when the scan limit was reached.
    pub resume_at: Option<u64>,
}

/// A bounded, self-describing export page.
///
/// The page carries the head it was produced against, so an off-chain
/// verifier can confirm it saw a consistent snapshot: recompute each
/// `hash` from the exported fields, check each `prev_hash`, and compare the
/// last hash with `head_hash` when `next_cursor` is `None`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditLedgerExport {
    /// Schema version of the exported entries.
    pub version: u32,
    /// Number of sealed entries at export time.
    pub head_seq: u64,
    /// Head hash at export time.
    pub head_hash: BytesN<32>,
    /// Sequence number of the first returned entry.
    pub from_seq: u64,
    /// Entries in ascending `seq` order, including their hashes.
    pub entries: Vec<AuditLedgerEntry>,
    /// Pass back as `cursor` to continue; `None` when the head was reached.
    pub next_cursor: Option<u64>,
}

/// Storage keys owned by the audit ledger.
#[contracttype]
pub enum AuditLedgerKey {
    /// Current chain head.
    Head,
    /// Sealed entry by sequence number.
    Entry(u64),
    /// Number of checkpoints written by [`seal`].
    AnchorCount,
    /// Checkpoint by id.
    Anchor(u64),
}

// ---------------------------------------------------------------------------
// Read helpers
// ---------------------------------------------------------------------------

/// 32 zero bytes — the `prev_hash` of the first entry.
fn zero_hash(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0u8; 32])
}

/// Returns the current chain head (empty chain when nothing was sealed yet).
///
/// This is a cheap, public read: it exposes only a count and a hash, never
/// entry payloads.
pub fn head(env: &Env) -> AuditLedgerHead {
    persistent_get(env, &AuditLedgerKey::Head).unwrap_or(AuditLedgerHead {
        version: AUDIT_LEDGER_VERSION,
        count: 0,
        head_hash: zero_hash(env),
    })
}

/// Loads one sealed entry by sequence number.
pub fn get_entry(env: &Env, seq: u64) -> Option<AuditLedgerEntry> {
    persistent_get(env, &AuditLedgerKey::Entry(seq))
}

/// Number of checkpoints written by [`seal`].
pub fn anchor_count(env: &Env) -> u64 {
    persistent_get(env, &AuditLedgerKey::AnchorCount).unwrap_or(0)
}

/// Loads one checkpoint by id.
pub fn get_anchor(env: &Env, id: u64) -> Option<AuditLedgerAnchor> {
    persistent_get(env, &AuditLedgerKey::Anchor(id))
}

// ---------------------------------------------------------------------------
// Append
// ---------------------------------------------------------------------------

/// Appends one event to the hash chain.
///
/// Called by [`crate::timeline::record_action_audit_event`] after the action
/// has been authorised and its state change applied, so a rejected action never
/// produces a ledger entry. The append is atomic with that state change: if it
/// fails, the whole contract invocation reverts.
#[allow(clippy::too_many_arguments)]
pub fn append(
    env: &Env,
    event_type: TimelineEventType,
    actor: Address,
    scope: Symbol,
    action: Symbol,
    reason: Symbol,
    resource: Option<Address>,
    attribute: Option<Symbol>,
    before: Option<i128>,
    after: Option<i128>,
) -> Result<AuditLedgerEntry, Error> {
    let current = head(env);
    let mut entry = AuditLedgerEntry {
        version: AUDIT_LEDGER_VERSION,
        seq: current.count,
        event_type,
        actor,
        scope,
        action,
        reason,
        resource,
        attribute,
        before,
        after,
        ledger: env.ledger().sequence(),
        timestamp: env.ledger().timestamp(),
        prev_hash: current.head_hash.clone(),
        hash: zero_hash(env),
    };
    entry.hash = entry_hash(env, &entry);

    let next_count = current.count.checked_add(1).ok_or(Error::Overflow)?;
    persistent_set(env, &AuditLedgerKey::Entry(entry.seq), &entry);
    persistent_set(
        env,
        &AuditLedgerKey::Head,
        &AuditLedgerHead {
            version: AUDIT_LEDGER_VERSION,
            count: next_count,
            head_hash: entry.hash.clone(),
        },
    );

    // External, append-only evidence. Indexers keep these even if storage is
    // later rewritten; see the module threat model.
    env.events().publish(
        (symbol_short!("audit"), AUDIT_LEDGER_EVENT),
        (
            entry.seq,
            entry.hash.clone(),
            entry.prev_hash.clone(),
            entry.ledger,
        ),
    );
    Ok(entry)
}

// ---------------------------------------------------------------------------
// Hashing
// ---------------------------------------------------------------------------

/// Recomputes the hash of an entry from its fields.
///
/// Public so an off-chain verifier can mirror the exact encoding; the
/// contract uses the same function during [`verify_range`].
pub fn entry_hash(env: &Env, entry: &AuditLedgerEntry) -> BytesN<32> {
    env.crypto().sha256(&encode_entry(env, entry)).to_bytes()
}

fn push_bytes(out: &mut Bytes, env: &Env, value: &Bytes) {
    out.append(&Bytes::from_slice(env, &value.len().to_be_bytes()));
    out.append(value);
}

fn push_u16(out: &mut Bytes, env: &Env, value: u16) {
    out.append(&Bytes::from_slice(env, &value.to_be_bytes()));
}

fn push_u32(out: &mut Bytes, env: &Env, value: u32) {
    out.append(&Bytes::from_slice(env, &value.to_be_bytes()));
}

fn push_u64(out: &mut Bytes, env: &Env, value: u64) {
    out.append(&Bytes::from_slice(env, &value.to_be_bytes()));
}

fn push_i128(out: &mut Bytes, env: &Env, value: i128) {
    out.append(&Bytes::from_slice(env, &value.to_be_bytes()));
}

/// Stable tag table for [`TimelineEventType`].
///
/// Tags are part of the hash pre-image: never renumber an existing variant.
/// Adding a variant requires bumping [`AUDIT_LEDGER_VERSION`] and updating
/// this match (the compiler enforces the update).
fn event_type_tag(event_type: &TimelineEventType) -> u16 {
    match event_type {
        TimelineEventType::RecordCreated => 1,
        TimelineEventType::RecordUpdated => 2,
        TimelineEventType::RecordSettled => 3,
        TimelineEventType::RecordExpired => 4,
        TimelineEventType::RecordRestricted => 5,
        TimelineEventType::PaymentSent => 6,
        TimelineEventType::PaymentRefunded => 7,
        TimelineEventType::RoleChanged => 8,
        TimelineEventType::ConfigChanged => 9,
        TimelineEventType::ContractPaused => 10,
        TimelineEventType::ContractResumed => 11,
        TimelineEventType::ScheduledActionEarly => 12,
        TimelineEventType::ScheduledActionLate => 13,
        TimelineEventType::ActionRejected => 14,
    }
}

/// Length-delimited, position-dependent encoding of every hashed field.
///
/// Encoding is deliberately **not** sorted (unlike the unordered canonical
/// payload helper in [`crate::canonical`]): swapping `before` and `after`, or
/// `scope` and `action`, must change the hash. Each field is length-prefixed or
/// fixed-width, so concatenation cannot be ambiguous.
fn encode_entry(env: &Env, entry: &AuditLedgerEntry) -> Bytes {
    let mut out = Bytes::new(env);
    push_bytes(&mut out, env, &Bytes::from_slice(env, AUDIT_LEDGER_DOMAIN));
    push_u32(&mut out, env, entry.version);
    push_u64(&mut out, env, entry.seq);
    push_u16(&mut out, env, event_type_tag(&entry.event_type));
    push_bytes(&mut out, env, &entry.actor.clone().to_xdr(env));
    push_bytes(&mut out, env, &entry.scope.clone().to_xdr(env));
    push_bytes(&mut out, env, &entry.action.clone().to_xdr(env));
    push_bytes(&mut out, env, &entry.reason.clone().to_xdr(env));

    match &entry.resource {
        Some(resource) => {
            push_u16(&mut out, env, 1);
            push_bytes(&mut out, env, &resource.clone().to_xdr(env));
        }
        None => push_u16(&mut out, env, 0),
    }
    match &entry.attribute {
        Some(attribute) => {
            push_u16(&mut out, env, 1);
            push_bytes(&mut out, env, &attribute.clone().to_xdr(env));
        }
        None => push_u16(&mut out, env, 0),
    }
    match entry.before {
        Some(value) => {
            push_u16(&mut out, env, 1);
            push_i128(&mut out, env, value);
        }
        None => push_u16(&mut out, env, 0),
    }
    match entry.after {
        Some(value) => {
            push_u16(&mut out, env, 1);
            push_i128(&mut out, env, value);
        }
        None => push_u16(&mut out, env, 0),
    }

    push_u32(&mut out, env, entry.ledger);
    push_u64(&mut out, env, entry.timestamp);
    push_bytes(
        &mut out,
        env,
        &Bytes::from_slice(env, &entry.prev_hash.to_array()),
    );
    out
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

fn failure(
    current: &AuditLedgerHead,
    from_seq: u64,
    checked: u64,
    bad_seq: u64,
    reason: AuditTamperReason,
) -> AuditLedgerVerification {
    AuditLedgerVerification {
        ok: false,
        complete: false,
        from_seq,
        checked,
        head_seq: current.count,
        head_hash: current.head_hash.clone(),
        first_bad_seq: Some(bad_seq),
        reason,
        resume_at: None,
    }
}

/// Verifies up to [`MAX_AUDIT_VERIFY_ENTRIES`] entries starting at `from_seq`.
///
/// Pass `from_seq = 0` for a full scan. When the ledger is longer than the
/// limit the result has `complete = false` and `resume_at = Some(next)`; loop
/// until `complete` is `true`. The scan is read-only and does not require
/// authorisation, but it never returns entry contents.
pub fn verify_range(
    env: &Env,
    from_seq: u64,
    limit: u32,
) -> Result<AuditLedgerVerification, Error> {
    let current = head(env);
    if from_seq > current.count {
        return Err(Error::InvalidArgument);
    }
    let limit = if limit == 0 {
        MAX_AUDIT_VERIFY_ENTRIES
    } else {
        limit
    };
    if limit > MAX_AUDIT_VERIFY_ENTRIES {
        return Err(Error::InvalidArgument);
    }

    let mut expected_prev = if from_seq == 0 {
        zero_hash(env)
    } else {
        match get_entry(env, from_seq - 1) {
            Some(previous) => previous.hash,
            None => {
                return Ok(failure(
                    &current,
                    from_seq,
                    0,
                    from_seq - 1,
                    AuditTamperReason::MissingEntry,
                ))
            }
        }
    };

    let mut seq = from_seq;
    let mut checked: u64 = 0;
    while seq < current.count && checked < u64::from(limit) {
        let entry = match get_entry(env, seq) {
            Some(entry) => entry,
            None => {
                return Ok(failure(
                    &current,
                    from_seq,
                    checked,
                    seq,
                    AuditTamperReason::MissingEntry,
                ))
            }
        };
        if entry.seq != seq {
            return Ok(failure(
                &current,
                from_seq,
                checked,
                seq,
                AuditTamperReason::UnexpectedSequence,
            ));
        }
        if entry.version != AUDIT_LEDGER_VERSION {
            return Ok(failure(
                &current,
                from_seq,
                checked,
                seq,
                AuditTamperReason::UnsupportedVersion,
            ));
        }
        if entry.prev_hash != expected_prev {
            return Ok(failure(
                &current,
                from_seq,
                checked,
                seq,
                AuditTamperReason::PrevHashMismatch,
            ));
        }
        if entry_hash(env, &entry) != entry.hash {
            return Ok(failure(
                &current,
                from_seq,
                checked,
                seq,
                AuditTamperReason::EntryHashMismatch,
            ));
        }
        expected_prev = entry.hash;
        seq = seq.saturating_add(1);
        checked = checked.saturating_add(1);
    }

    let complete = seq == current.count;
    if complete && expected_prev != current.head_hash {
        return Ok(failure(
            &current,
            from_seq,
            checked,
            seq.saturating_sub(1),
            AuditTamperReason::HeadMismatch,
        ));
    }

    Ok(AuditLedgerVerification {
        ok: complete,
        complete,
        from_seq,
        checked,
        head_seq: current.count,
        head_hash: current.head_hash.clone(),
        first_bad_seq: None,
        reason: AuditTamperReason::ChainIntact,
        resume_at: if complete { None } else { Some(seq) },
    })
}

/// Writes a checkpoint of the current head and returns it.
///
/// Recommended before privileged maintenance (migration, upgrade, key
/// rotation) so a later rollback or truncation is provable even if the head is
/// rewritten. Fails with [`Error::NotFound`] on an empty chain: there is
/// nothing to anchor yet.
pub fn seal(env: &Env) -> Result<AuditLedgerAnchor, Error> {
    let current = head(env);
    if current.count == 0 {
        return Err(Error::NotFound);
    }
    let id = anchor_count(env);
    let anchor = AuditLedgerAnchor {
        id,
        seq: current.count,
        hash: current.head_hash,
        ledger: env.ledger().sequence(),
        timestamp: env.ledger().timestamp(),
    };
    persistent_set(env, &AuditLedgerKey::Anchor(id), &anchor);
    persistent_set(
        env,
        &AuditLedgerKey::AnchorCount,
        &id.checked_add(1).ok_or(Error::Overflow)?,
    );
    Ok(anchor)
}

/// Verifies stored checkpoints against the current chain.
///
/// Each anchor records a `(seq, hash)` pair. Verification recomputes the hash
/// of entry `seq - 1` and compares, so it detects:
///
/// - a truncated tail (the anchored entry is gone → `MissingEntry`);
/// - a rewritten entry at an anchored position (`AnchorMismatch`);
/// - an anchor rewritten without the corresponding entry (`AnchorMismatch`).
///
/// Run [`verify_range`] as well: anchors prove specific positions, while the
/// range scan proves every link between them.
pub fn verify_anchors(
    env: &Env,
    from_id: u64,
    limit: u32,
) -> Result<AuditAnchorVerification, Error> {
    let current = head(env);
    let total = anchor_count(env);
    if from_id > total {
        return Err(Error::InvalidArgument);
    }
    let limit = if limit == 0 {
        MAX_AUDIT_VERIFY_ENTRIES
    } else {
        limit
    };
    if limit > MAX_AUDIT_VERIFY_ENTRIES {
        return Err(Error::InvalidArgument);
    }

    let mut id = from_id;
    let mut checked: u64 = 0;
    while id < total && checked < u64::from(limit) {
        let anchor = get_anchor(env, id).ok_or(Error::NotFound)?;
        if anchor.seq == 0 || anchor.seq > current.count {
            return Ok(AuditAnchorVerification {
                ok: false,
                checked,
                first_bad_id: Some(id),
                reason: AuditTamperReason::AnchorMismatch,
                head_seq: current.count,
                resume_at: None,
            });
        }
        match get_entry(env, anchor.seq - 1) {
            Some(entry) if entry_hash(env, &entry) == anchor.hash => {}
            Some(_) => {
                return Ok(AuditAnchorVerification {
                    ok: false,
                    checked,
                    first_bad_id: Some(id),
                    reason: AuditTamperReason::AnchorMismatch,
                    head_seq: current.count,
                    resume_at: None,
                })
            }
            None => {
                return Ok(AuditAnchorVerification {
                    ok: false,
                    checked,
                    first_bad_id: Some(id),
                    reason: AuditTamperReason::MissingEntry,
                    head_seq: current.count,
                    resume_at: None,
                })
            }
        }
        id = id.saturating_add(1);
        checked = checked.saturating_add(1);
    }

    let complete = id == total;
    Ok(AuditAnchorVerification {
        ok: complete,
        checked,
        first_bad_id: None,
        reason: AuditTamperReason::ChainIntact,
        head_seq: current.count,
        resume_at: if complete { None } else { Some(id) },
    })
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// Exports a bounded page of the chain, newest head included.
///
/// Maintainer-gated for the same reason as
/// [`crate::timeline::action_audit_trail`]: entries contain actor addresses
/// and financial state. `cursor` is `None` for the first page, then the
/// `next_cursor` of the previous page. `limit = 0` selects
/// [`MAX_AUDIT_EXPORT_ENTRIES`].
///
/// The returned entries include `prev_hash` and `hash`, so an off-chain
/// verifier can recompute the chain and compare the last hash with
/// `head_hash` (when `next_cursor` is `None`).
pub fn export(
    env: &Env,
    maintainer: &Address,
    cursor: Option<u64>,
    limit: u32,
) -> Result<AuditLedgerExport, Error> {
    require_role(env, maintainer, Role::Admin)?;
    let limit = if limit == 0 {
        MAX_AUDIT_EXPORT_ENTRIES
    } else {
        limit
    };
    if limit > MAX_AUDIT_EXPORT_ENTRIES {
        return Err(Error::InvalidArgument);
    }

    let current = head(env);
    let from_seq = cursor.unwrap_or(0);
    if from_seq > current.count {
        return Err(Error::InvalidArgument);
    }

    let mut entries = Vec::new(env);
    let mut seq = from_seq;
    while seq < current.count && entries.len() < limit {
        entries.push_back(get_entry(env, seq).ok_or(Error::NotFound)?);
        seq = seq.saturating_add(1);
    }

    Ok(AuditLedgerExport {
        version: AUDIT_LEDGER_VERSION,
        head_seq: current.count,
        head_hash: current.head_hash,
        from_seq,
        entries,
        next_cursor: if seq < current.count { Some(seq) } else { None },
    })
}
