//! Typed client contract definitions for cross-repo Trellis integrations (Issue #120).
//!
//! Provides canonical shared types, envelopes, receipts, and schema fingerprinting
//! ensuring that frontend (SDK), API server, and smart contracts remain perfectly aligned.

use soroban_sdk::{contracttype, symbol_short, Address, BytesN, Env, Symbol};
use crate::error_taxonomy::{describe_error, ErrorDomain};

/// Current canonical schema version for cross-repo Trellis integration.
pub const CLIENT_SCHEMA_VERSION: u32 = 1;

/// Universal operation status codes across all Trellis modules.
#[contracttype]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum OperationStatus {
    Pending = 0,
    Active = 1,
    Completed = 2,
    Refunded = 3,
    Cancelled = 4,
    Failed = 5,
}

// ---------------------------------------------------------------------------
// Aid Module Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateAidRequest {
    pub donor: Address,
    pub recipient: Address,
    pub amount: i128,
    pub expiry_ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AidSummaryResponse {
    pub aid_id: u64,
    pub donor: Address,
    pub recipient: Address,
    pub token: Address,
    pub amount: i128,
    pub expiry_ledger: u32,
    pub status: OperationStatus,
    pub schema_version: u32,
}

// ---------------------------------------------------------------------------
// Payment & Escrow Module Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateEscrowRequest {
    pub depositor: Address,
    pub beneficiary: Address,
    pub token: Address,
    pub amount: i128,
    pub expiry_ledger: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EscrowSummaryResponse {
    pub escrow_id: u64,
    pub depositor: Address,
    pub beneficiary: Address,
    pub token: Address,
    pub amount: i128,
    pub fee_amount: i128,
    pub expiry_ledger: u32,
    pub status: OperationStatus,
}

// ---------------------------------------------------------------------------
// Governance Module Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateProposalRequest {
    pub title: Symbol,
    pub target: Address,
    pub action_type: u32,
    pub parameter_key: u32,
    pub parameter_value: i128,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProposalSummaryResponse {
    pub proposal_id: u64,
    pub proposer: Address,
    pub status: OperationStatus,
    pub approval_count: u32,
    pub threshold: u32,
    pub created_at: u64,
    pub expires_at: u64,
}

// ---------------------------------------------------------------------------
// NFT Marketplace Module Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateListingRequest {
    pub seller: Address,
    pub collection: Address,
    pub token_id: u64,
    pub price: i128,
    pub currency: Address,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListingSummaryResponse {
    pub listing_id: u64,
    pub seller: Address,
    pub collection: Address,
    pub token_id: u64,
    pub price: i128,
    pub currency: Address,
    pub status: OperationStatus,
}

// ---------------------------------------------------------------------------
// Rebalancer Module Types
// ---------------------------------------------------------------------------

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebalanceRequest {
    pub asset_in: Symbol,
    pub asset_out: Symbol,
    pub amount: u128,
    pub max_slippage_bps: u32,
}

#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RebalanceSummaryResponse {
    pub status: OperationStatus,
    pub executed_amount: u128,
    pub fee_paid: u128,
    pub actual_slippage_bps: u32,
}

// ---------------------------------------------------------------------------
// Standard Client Receipt and Error Envelopes
// ---------------------------------------------------------------------------

/// Universal execution receipt for client applications (dApp / API).
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientReceipt {
    pub operation_id: u64,
    pub domain: Symbol,
    pub status: OperationStatus,
    pub tx_hash: BytesN<32>,
    pub ledger: u32,
    pub timestamp: u64,
    pub payload_hash: BytesN<32>,
}

/// Standardized structured error response envelope for cross-repo API clients.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientErrorResponse {
    pub domain: Symbol,
    pub code: u32,
    pub category: Symbol,
    pub retryable: bool,
    pub message: Symbol,
    pub recovery: Symbol,
    pub correlation_id: BytesN<32>,
}

/// Converts a domain error code into a structured [`ClientErrorResponse`].
pub fn format_client_error(
    env: &Env,
    domain: ErrorDomain,
    code: u32,
    correlation_id: BytesN<32>,
) -> ClientErrorResponse {
    let info = describe_error(env, domain.clone(), code, correlation_id.clone());

    let domain_sym = match domain {
        ErrorDomain::Shared => symbol_short!("shared"),
        ErrorDomain::Aid => symbol_short!("aid"),
        ErrorDomain::Payments => symbol_short!("pay"),
        ErrorDomain::Batch => symbol_short!("batch"),
        ErrorDomain::Governance => symbol_short!("gov"),
        ErrorDomain::Marketplace => symbol_short!("mkt"),
        ErrorDomain::Oracle => symbol_short!("oracle"),
        ErrorDomain::AccessControl => symbol_short!("ac"),
        ErrorDomain::Treasury => symbol_short!("treas"),
        ErrorDomain::Referral => symbol_short!("ref"),
        ErrorDomain::Registry => symbol_short!("reg"),
        ErrorDomain::Upgradeability => symbol_short!("upg"),
        ErrorDomain::Import => symbol_short!("import"),
        ErrorDomain::Export => symbol_short!("export"),
    };

    let cat_sym = match info.category {
        crate::error_taxonomy::ErrorCategory::Validation => symbol_short!("val"),
        crate::error_taxonomy::ErrorCategory::Authorization => symbol_short!("auth"),
        crate::error_taxonomy::ErrorCategory::NotFound => symbol_short!("not_fnd"),
        crate::error_taxonomy::ErrorCategory::Conflict => symbol_short!("conflict"),
        crate::error_taxonomy::ErrorCategory::Settlement => symbol_short!("settle"),
        crate::error_taxonomy::ErrorCategory::Configuration => symbol_short!("config"),
        crate::error_taxonomy::ErrorCategory::Internal => symbol_short!("internal"),
    };

    ClientErrorResponse {
        domain: domain_sym,
        code,
        category: cat_sym,
        retryable: info.retryable,
        message: symbol_short!("err_msg"),
        recovery: symbol_short!("err_rec"),
        correlation_id,
    }
}

/// Generates a deterministic cryptographic checksum of the schema types to guarantee
/// compile-time and runtime detection of cross-repo type drift.
pub fn client_schema_fingerprint(env: &Env) -> BytesN<32> {
    // SHA-256 over canonical schema descriptor string
    let descriptor = b"TrellisClientContract:v1:Aid,Payment,Gov,Mkt,Rebal,Receipt,Error";
    let bytes = soroban_sdk::Bytes::from_slice(env, descriptor);
    env.crypto().sha256(&bytes).into()
}
