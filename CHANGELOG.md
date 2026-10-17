# Changelog

All notable changes to the Trellis Contracts repository are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added
- `shared::audit_ledger`: a hash-chained, tamper-evident ledger for privileged and financial events. Every `record_action_audit_event` call — the choke point used by treasury, aid, referral, oracle and access control — seals one entry, and treasury exposes `audit_ledger_head`, `verify_audit_ledger`, `verify_audit_ledger_anchors`, `export_audit_ledger` and `seal_audit_ledger` entrypoints (#233); see `docs/AUDIT_LEDGER.md`
- `shared::operational_metadata`: Data minimization review and retention enforcement for operational metadata across Treasury, Aid, Referral, Governance, Oracle, and Marketplace modules with classification, redundant field pruning, two-phase testable deletion, hold management, and migration adapters (#229); see `docs/OPERATIONAL_METADATA_RETENTION.md`
- Two-step ownership transfer with pending acceptance and expiry in `shared::auth` and `contracts/access-control`, requiring explicit cryptographic acceptance by the target owner, supporting automatic expiry rejection, and allowing cancellation before acceptance (#150); see `docs/ACCESS_CONTROL.md`
- `shared::lifecycle_events`: a canonical, versioned event envelope (`("lifecycle", resource, transition)` with schema version, resource ID, from/to state, actor, and timestamp) for every lifecycle transition, plus an ordered-sequence assertion harness (`testing::lifecycle_events`) that fails tests when an expected event is missing or reordered (#144); see `docs/LIFECYCLE_EVENTS.md`
- `shared::disclosure`: progressive disclosure of transaction detail fields, where a `Critical`-severity field can never end up reachable only through the advanced/expanded view (#125)
- Machine-readable changelog (`changelog/entries.json` + `changelog/schema.json`) for protocol-facing changes, validated in CI (#126); see `docs/CHANGELOG_SCHEMA.md`
- Fault-injection test suite (`testing/src/fault_injection.rs`) exercising the sandbox's fake oracle/token/RPC adapters for hard failures, staleness, insufficient balance, and submission timeouts, proving each fails actionably with no partial state (#127)
- PR checklist enforcement (`scripts/check-pr-checklist.cjs`, new `release-readiness.yml` workflow) so an incomplete `.github/PULL_REQUEST_TEMPLATE.md` checklist fails CI instead of only reviewer attention; documented in `docs/RELEASE_READINESS.md` (#128)
- Cross-contract integration test suite covering full aid lifecycle, expiry flows, authorization boundaries, partial failure recovery, and referral commission distribution
- WASM size budget check in CI with per-contract limits and PR comments showing size deltas
- Automated API documentation publishing to GitHub Pages on every merge to main
- Improved crate-level rustdoc for all core contracts (aid, treasury, referral, oracle, registry)
- Landing page for API documentation explaining contract relationships and navigation

### Changed
- Enhanced rustdoc crate-level documentation with usage examples and cross-references
- Updated CI workflow to include WASM size measurement step

### Fixed
- `shared`'s `health`, `reconciliation`, and `telemetry` modules were re-exported (`pub use health::{...}` etc.) without a matching `mod` declaration in `shared/src/lib.rs` — an unresolved-module compile error for the whole workspace. Added the three missing `pub mod` declarations.
- Repaired the remaining pre-existing compilation breakage required to build and test the audit ledger: `shared/src/lib.rs` was truncated and carried corrupted tokens (`#`!no_std]`, `pubmod`, `pub use x:{`, a stray `.`, references to non-existent `golden` modules, duplicate root re-exports); `shared` used `symbol_short!` literals longer than the 9-character limit; `Option<Enum>` fields in `#[contracttype]` structs are unsupported by SDK spec generation, so `RollbackVerificationReceipt.anomaly` and `StaleStateReport.reason` use explicit `NoAnomaly`/`NoReason` variants; `RollbackVerificationReceipt.consecutive_failures_at_rollback` was renamed to `consecutive_failures_at_rb` to satisfy the 30-character contracttype field limit; `treasury-contract`'s strategy-invocation error arms did not type-check against `try_invoke_contract`, and its unit-test file was truncated mid-function.

---

## [0.1.0] - 2024-09-24

### Added
- **Initial Release**: Complete Soroban smart contract suite for humanitarian aid distribution
- **Core Contracts**:
  - `aid-contract`: Direct aid settlement, escrow, and claim management
  - `treasury-contract`: Protocol treasury management with per-category balances and withdrawal limits
  - `referral-contract`: Multi-tier referral network with commission accrual and distribution
  - `governance-contract`: Multi-signature governance for role management and protocol upgrades
  - `oracle-contract`: Off-chain data integration and verification bridge
  - `registry-contract`: Central contract discovery and version tracking
  - `payments-contract`: Token transfer and payment settlement layer
  - `rebalancer-contract`: Liquidity rebalancing and reserve management
  - `nft-marketplace`: NFT minting, trading, and marketplace functionality
  - `access-control`: Role-based access control primitives
  - `upgradeability`: Centralized upgrade registry and coordinator

- **Shared Library**:
  - Error codes and event schemas
  - Storage helpers and authorization patterns
  - Batch transfer primitives for atomic multi-recipient payments
  - Persistent storage optimization (`persistent_read` for TTL-free reads)

- **Testing Infrastructure**:
  - Comprehensive test harness with mocks and helpers
  - Gas optimization benchmarking suite
  - Fuzzing harnesses for critical modules
  - Simulation tools for multi-user protocol activity

- **CI/CD**:
  - GitHub Actions workflows for build, clippy, test, and format checks
  - Automated test execution on push and pull requests

- **Documentation**:
  - GAS_OPTIMIZATION.md: Complete gas optimization guide with identified hotspots and benchmarks
  - UPGRADEABILITY.md: System-wide upgrade registry and coordinator documentation
  - Per-contract README files explaining module responsibilities and interfaces
  - CODE_OF_CONDUCT.md and contribution guidelines

- **Deployment Scripts**:
  - `scripts/deploy.sh`: Multi-contract deployment to testnet/mainnet
  - `scripts/initialize.sh`: Contract initialization utilities
  - `scripts/upgrade.sh`: Upgrade execution and management
  - `scripts/verify.sh`: Deployment verification tools
  - `scripts/register_upgradeable.sh`: Contract registration for upgrade system

### Key Features
- **Security**: Reentrancy protection, signature verification, overflow-safe arithmetic, access control, replay protection
- **Efficiency**: Gas optimizations for storage reads, validation ordering, event batching
- **Auditability**: Transparent transaction records, immutable event logs, comprehensive state tracking
- **Upgradeability**: Centralized upgrade registry with version tracking and history
- **Modularity**: Independent contracts with clear interfaces and cross-contract integration
- **Production Ready**: Comprehensive error handling, edge case coverage, extensive testing

### Architecture
- Modular contract design with separation of concerns
- Shared library for common patterns and utilities
- Central registry for contract discovery and upgrade management
- Multi-signature governance for protocol changes
- Role-based access control across all contracts

### Testing Coverage
- Unit tests for all contract functions
- Integration tests for cross-contract flows
- Gas benchmarking tests for optimization verification
- Fuzzing tests for critical security-sensitive operations
- Simulation harnesses for multi-user scenarios

---

## Versioning Strategy

The Trellis Contracts project uses a hybrid versioning approach:

### Repository Version
- Follows Semantic Versioning (MAJOR.MINOR.PATCH)
- Incremented when contract suite interfaces or behaviors change significantly
- Used for releases and documentation

### Individual Contract Versions
- Each contract tracks its own version in the upgradeability registry
- Allows independent contract updates without forcing suite-wide version bumps
- Critical for the on-chain upgrade system where contract identity is preserved across versions

See [UPGRADEABILITY.md](./UPGRADEABILITY.md) for details on the on-chain upgrade registry and version tracking.

---

## How to Contribute

When adding changes, update this CHANGELOG by:
1. Adding entries to the `[Unreleased]` section
2. Following the existing format (Added, Changed, Deprecated, Removed, Fixed, Security)
3. Keeping entries concise and user-focused
4. When preparing a release, rename `[Unreleased]` to a dated version section

See [CONTRIBUTING.md](./CONTRIBUTING.md) for full contribution guidelines.
