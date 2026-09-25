//! Signature Shares for Threshold `EdDSA`
//!
//! This module defines the `EdDSASigShare` struct, a single party's share of the response `s` of
//! the final `EdDSA` signature.
//!
//! The primitives defined here are agnostic to the underlying threshold sharing scheme and are used by
//! the Shamir variant, which is implemented in the submodule `shamir`.

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
