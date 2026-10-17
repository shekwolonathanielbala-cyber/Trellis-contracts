# Tamper-evident audit ledger

`shared::audit_ledger` turns the privileged and financial audit trail into a
hash chain, so an edit, reorder, insertion or deletion of a recorded action is
detectable — on-chain, by a verifier contract, and off-chain from an export.

The module is generic; the treasury contract is the first vertical slice wired
end to end (`contracts/treasury-contract/src/lib.rs`).

## Scope

Every call to [`shared::timeline::record_action_audit_event`](../shared/src/timeline.rs)
seals one ledger entry. That is the single choke point already used by:

| Module | Examples of what is sealed |
| --- | --- |
| Treasury | initialisation, deposit, withdraw, scheduled withdraw, emergency withdraw, fee/reward payment, role and config changes |
| Aid | create, claim, refund, settle, admin changes |
| Referral | registration, commission accruals, config changes |
| Oracle | feed registration, price submission/rejection, quorum/config changes |
| Access control | role grants/revocations, ownership transfer |

Legacy [`shared::timeline::record_audit_event`](../shared/src/timeline.rs)
records (used for redaction and deletion bookkeeping) are **not** chained: the
ledger already seals the structured action that triggered them, and extending
the chain to the legacy store would change its key space and read path. User
timeline entries are intentionally out of scope — they are not privileged or
financial records.

**Not yet covered:** governance, NFT marketplace, registry, payments and
rebalancer currently have no `record_action_audit_event` call site, so their
actions are not sealed. Adding one is additive — call
`record_action_audit_event` after authorization and validation succeed, mapping
its `shared::Error` into the module's own error type — and the choke point seals
it without any further change. This slice covers the treasury, aid, referral,
oracle and access-control paths first because that is where the audited
financial and privileged flows already live.

## Chain construction

```text
entry[0].prev_hash = 0x00…00
entry[n].prev_hash = entry[n-1].hash
entry[n].hash      = sha256(preimage(entry[n]))
```

`hash` is not part of its own pre-image. The pre-image is a position-dependent,
length-delimited encoding (deliberately **not** the order-insensitive
`shared::canonical` payload encoding, so swapping `before`/`after` or
`scope`/`action` changes the hash):

| Order | Field | Encoding |
| --- | --- | --- |
| 1 | domain separator | `u32` length + `trellis.audit-ledger.v1` |
| 2 | `version` | `u32` big-endian |
| 3 | `seq` | `u64` big-endian |
| 4 | `event_type` | `u16` tag (table below) |
| 5 | `actor` | `u32` length + ScVal XDR |
| 6 | `scope` | `u32` length + ScVal XDR |
| 7 | `action` | `u32` length + ScVal XDR |
| 8 | `reason` | `u32` length + ScVal XDR |
| 9 | `resource` | `u16` present flag, then `u32` length + ScVal XDR when present |
| 10 | `attribute` | `u16` present flag, then `u32` length + ScVal XDR when present |
| 11 | `before` | `u16` present flag, then `i128` big-endian when present |
| 12 | `after` | `u16` present flag, then `i128` big-endian when present |
| 13 | `ledger` | `u32` big-endian |
| 14 | `timestamp` | `u64` big-endian |
| 15 | `prev_hash` | `u32` length (32) + 32 bytes |

`event_type` tags (part of the pre-image; never renumber):

| Tag | Event type | Tag | Event type |
| --- | --- | --- | --- |
| 1 | `RecordCreated` | 8 | `RoleChanged` |
| 2 | `RecordUpdated` | 9 | `ConfigChanged` |
| 3 | `RecordSettled` | 10 | `ContractPaused` |
| 4 | `RecordExpired` | 11 | `ContractResumed` |
| 5 | `RecordRestricted` | 12 | `ScheduledActionEarly` |
| 6 | `PaymentSent` | 13 | `ScheduledActionLate` |
| 7 | `PaymentRefunded` | 14 | `ActionRejected` |

`shared::audit_ledger::entry_hash(env, &entry)` is the authoritative
implementation; an off-chain verifier reimplements the table above with a
standard SHA-256 and the ScVal XDR encoding of the Soroban SDK for its target
protocol version.

The schema version is the first hashed field, so a future incompatible encoding
change is explicit: verifiers reject unknown versions with
`AuditTamperReason::UnsupportedVersion` instead of silently recomputing with the
wrong rules.

## External evidence

Every append publishes:

```text
topics: ("audit", "aud_seal")
data:   (seq: u64, hash: BytesN<32>, prev_hash: BytesN<32>, ledger: u32)
```

Stellar ledger events live for the network's event-retention window and cannot
be rewritten by the contract. An indexer that stores these seals independently
of the contract's own storage is therefore the strongest available anchor: a
wholesale rewrite that also rewrites stored anchors is still inconsistent with
the recorded event history inside the retention window.

## Verification

| Call | Auth | Returns |
| --- | --- | --- |
| `shared::audit_ledger::head(env)` | none | `AuditLedgerHead { version, count, head_hash }` |
| `shared::audit_ledger::verify_range(env, from_seq, limit)` | none | `AuditLedgerVerification` (pass/fail only; never payloads) |
| `shared::audit_ledger::verify_anchors(env, from_id, limit)` | none | `AuditAnchorVerification` |
| `shared::audit_ledger::export(env, maintainer, cursor, limit)` | `Role::Admin` | `AuditLedgerExport` with full entries + hashes |
| `shared::audit_ledger::seal(env)` | caller-defined (treasury: `Role::Admin`) | `AuditLedgerAnchor` |

`verify_range` is paged: `MAX_AUDIT_VERIFY_ENTRIES = 100` per call. A call that
does not reach the head returns `ok = false, complete = false`, with
`resume_at` set to the next sequence. **A partial scan can never be reported as
success**; callers must loop until `complete` is `true`.

Treasury exposes the same surface as contract methods:

```text
audit_ledger_head() -> AuditLedgerHead
verify_audit_ledger(from_seq, limit) -> AuditLedgerVerification
verify_audit_ledger_anchors(from_id, limit) -> AuditAnchorVerification
export_audit_ledger(maintainer, cursor, limit) -> AuditLedgerExport   # Admin
seal_audit_ledger(caller) -> AuditLedgerAnchor                        # Admin
```

Other contracts can expose the same four-line wrappers; no contract needs to
change its existing entrypoints to benefit from chaining, because the
`record_action_audit_event` choke point does the work.

### Off-chain recipe

1. Page `export` with `cursor` until `next_cursor` is `None`.
2. For each entry, recompute the pre-image and hash; assert it equals
   `entry.hash`.
3. Assert `entry.prev_hash` equals the previous entry's `hash` (genesis: 32
   zero bytes).
4. Assert the last hash equals `head_hash` and the count equals `head_seq`.
5. Compare the retained `("audit", "aud_seal")` events with the exported chain.

Steps 2–5 are exactly what `shared/tests/audit_ledger.rs::export_is_paged_and_off_chain_verifiable`
does, and what `contracts/treasury-contract/tests/audit_ledger.rs` repeats
through the contract interface.

## Edge cases

| Case | Behaviour |
| --- | --- |
| Empty chain | `head` returns `count = 0`, zero hash; `verify_range(0, …)` returns `ok = true, checked = 0`; `seal()` returns `Error::NotFound`. |
| Two entries in one ledger | Allowed. `seq` is the ordering authority; `ledger`/`timestamp` may repeat. |
| Rejected action | No entry. Sealing happens only after the action's authorization and validation succeed, and the append is atomic with the state change. |
| Reverted transaction | The entry, the head and the emitted event are rolled back together — no partial chain. |
| Same action recorded twice | Two distinct entries; callers that need deduplication must pass an idempotency key through `action`/`reason`/`correlation`, as they already do. |
| `export` cursor past the head | `Error::InvalidArgument`. |
| `export`/`verify` limit above the cap | `Error::InvalidArgument`. |
| Entry written by a newer schema | `UnsupportedVersion` — upgrade the verifier, never reinterpret the entry. |
| Long ledger | Verification must be paged; a single call that cannot reach the head reports `complete = false`. |

## Failure modes

| Detection result | Meaning | Likely cause |
| --- | --- | --- |
| `EntryHashMismatch` at `n` | Entry `n`'s stored fields do not match its hash | Direct storage edit, buggy migration, corrupted restore |
| `PrevHashMismatch` at `n` | `n` does not follow its predecessor | Entry inserted/removed/reordered, or `n-1` rewritten |
| `UnexpectedSequence` at `n` | Stored `seq` field differs from its storage key | Re-keyed entry, faulty restore |
| `MissingEntry` at `n` | No entry under `seq = n` while the head claims more | Deletion, truncation, partial restore |
| `HeadMismatch` | Full scan ended on a hash different from the head | Head edited, or tail truncated **and** head rewritten |
| `AnchorMismatch` | A checkpoint disagrees with the chain | Tail truncation with a rewritten head, or a rewritten anchor |
| `UnsupportedVersion` | Verifier and entries disagree on encoding | Verifier not upgraded with the contract |

A chain that fails verification proves *some* write happened outside the
append path. It does not by itself identify the writer: on-chain, only code
inside the contract can write contract storage, so the candidates are a buggy
or malicious migration/upgrade path, or a restore from a snapshot that did not
replay appends.

## Rollback and recovery

The ledger deliberately exposes **no API to rewrite, delete or rewind an
entry**, and no API to set the head. Recovery is therefore evidence-driven:

1. **Detect.** Run `verify_audit_ledger(0, limit)` paging to the head, then
   `verify_audit_ledger_anchors(0, limit)`. Record `first_bad_seq`/`first_bad_id`
   and the current head.
2. **Freeze.** Pause the affected module (the shared pause flag / treasury
   `NotPaused` guard) so no new financial action lands while the chain is in
   question.
3. **Preserve evidence.** Admin `export_audit_ledger` every page and retain the
   `("audit", "aud_seal")` events already observed by indexers. Do this before
   any migration or restore: the export captures hashes that later writes can
   no longer change.
4. **Seal.** If the chain still verifies, `seal_audit_ledger` creates a
   checkpoint of the current head before maintenance, so a later rollback is
   provable even if the head is rewritten.
5. **Diagnose.**
   - `MissingEntry`/`PrevHashMismatch` confined to the newly restored range →
     restore from a snapshot and replay the missing appends; do not patch
     individual entries.
   - `EntryHashMismatch` on an old entry → the writing path was modified (a
     migration or upgrade). Roll the contract WASM back (see
     `docs/UPGRADEABILITY.md`), re-apply only verified state migrations, and
     treat the affected range as compromised.
   - `HeadMismatch`/`AnchorMismatch` with an intact range scan → the tail was
     truncated or the head rewritten. Rebuild the tail from the off-chain event
     history and compare hashes, then re-append the missing actions from the
     source-of-truth records.
6. **Re-verify and resume.** After recovery, the full scan plus anchor scan
   must both report intact before unpausing. If they cannot, keep the module
   paused and escalate per `docs/RUNBOOK.md`; do **not** rewrite entries to make
   verification pass.
7. **Record.** Add a maintenance note (reason, affected range, head hashes
   before/after) to the incident record. If the incident involved a storage
   layout change, the migration plan must include a `seal` before and a
   verification step after (`docs/MIGRATION_SAFETY.md`).

## Threat model and limits

- **In scope:** an actor with write access to contract storage (malicious
  migration, upgrade hook, compromised deployment pipeline) editing, reordering
  or removing sealed entries; a restore that silently drops appends; a
  truncated tail presented as the whole chain.
- **Detected by:** range verification (any link), anchor verification
  (truncation with a rewritten head), and off-chain comparison with retained
  `aud_seal` events (wholesale rewrite of storage plus anchors).
- **Not detected on-chain alone:** a rewrite that consistently recomputes every
  entry hash, the head, *and* every anchor. Detecting that requires the
  off-chain event history or an external checkpoint. Treat stored anchors as
  evidence, not as an external trust root.
- **Not covered:** legacy `record_audit_event` records and user timeline
  entries; confidential payloads (the ledger only ever contains the same
  stable symbols and numeric context the audit trail already stores, so no new
  data class is introduced).
- **Gas and storage:** each sealed action adds one persistent entry plus one
  head write and one event. Entries are bumped to the standard persistent TTL
  via `shared::storage`. `MAX_AUDIT_EXPORT_ENTRIES = 50` and
  `MAX_AUDIT_VERIFY_ENTRIES = 100` bound the read side.
- **Unbounded growth:** the chain grows with the number of privileged and
  financial actions. Operational retention/freeze tooling
  (`shared::retention`, `shared::operational_metadata`) governs other data
  classes; audit entries are deliberately exempt and must be exported before
  any storage-reducing migration.
- **Event retention:** `aud_seal` events age out of the network's event window.
  Indexers that need permanent evidence must persist them.

## Compatibility

- Purely additive to existing APIs: `record_action_audit_event` keeps its
  signature and return type; contracts keep their existing entrypoints.
- New public items: `shared::audit_ledger` (plus root re-exports), and the
  treasury methods listed above.
- New storage key space (`shared::AuditLedgerKey`), so no existing record
  layout changes.
- New event topic `("audit", "aud_seal")`; existing consumers that filter by
  topic are unaffected.
- Cost: one extra persistent write path per privileged/financial action and a
  small gas increase on those paths.

## Tests

| Test | Covers |
| --- | --- |
| `shared/tests/audit_ledger.rs` (16 tests) | genesis/head, linking, event evidence, edited field, deleted middle entry, reorder, sequence edit, tail truncation (plain and head-rewritten), edited anchor, hash position-dependence, paged export + off-chain verification, admin gating and bounds, resumable verification |
| `contracts/treasury-contract/tests/audit_ledger.rs` (5 tests) | real deposit/withdraw/emergency-withdraw/initialise sealed into one chain, paged export verified off-chain, consistent tail truncation caught by an anchor, storage edit caught through the contract, admin-gated seal |
