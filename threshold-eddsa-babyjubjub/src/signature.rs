//! Signature Shares for Threshold `EdDSA`
//!
//! This module defines the `EdDSASigShare` struct, a single party's share of the response `s` of
//! the final `EdDSA` signature.
//!
//! The primitives defined here are agnostic to the underlying threshold sharing scheme and are used by both
//! additive and Shamir variants, which are implemented in their respective submodules `additive` and `shamir`.

use crate::ScalarField;
use serde::{Deserialize, Serialize};

/// Individual party's proof share for the `EdDSA` protocol.
/// Carries a response share for the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EdDSASigShare(
    pub(crate) u16,
    // The share of the response s.
    #[serde(with = "ark_serde_compat::field")] pub(crate) ScalarField,
);
