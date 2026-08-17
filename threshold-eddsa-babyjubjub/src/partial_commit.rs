//! Distributed Partial Commitments for Threshold `EdDSA`
//!
//! This module defines the `PartialEdDSACommitments` struct.
//! Each participating party generates commitment shares that
//! are then aggregated to produce a non-interactive challenge hash for the `EdDSA` signature, without.
//!
//! The primitives defined here are agnostic to the underlying threshold sharing scheme and are used by both
//! additive and Shamir variants, which are implemented in their respective submodules `additive` and `shamir`.
//!
//! This module provides:
//! - Per-party commitment structures for partial commitment (nonce splits).
//!
//! Secret randomness is never clonable, and session types deliberately do not implement `Debug` to avoid accidental leakage.

use crate::Affine;
use ark_serde_compat::babyjubjub;
use serde::{Deserialize, Serialize};

/// Per-party commitments to the distributed `EdDSA` signature protocol.
///
/// Each party sends these commitments, which consist of a split of the actual response and nonce splits, for aggregation and creation of the global challenge hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialEdDSACommitments {
    #[serde(with = "babyjubjub::affine")]
    /// The share of G*d, the first part of the two-nonce commitment to the randomness r = d + e*b
    pub(crate) d: Affine,
    #[serde(with = "babyjubjub::affine")]
    /// The share of G*e, the second part of the two-nonce commitment to the randomness r = d + e*b
    pub(crate) e: Affine,
}
