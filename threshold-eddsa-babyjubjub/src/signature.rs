//! Signature Shares for Threshold `EdDSA`
//!
//! This module defines the `EdDSASigShare` struct, one party's Lagrange-weighted share of the
//! response `s` of the final `EdDSA` signature.

use crate::ScalarField;
use serde::{Deserialize, Serialize};
use std::num::NonZeroU16;

/// Individual party's signature share for the `EdDSA` signature protocol.
/// Carries a response share for the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdDSASigShare(
    pub(crate) NonZeroU16,
    // The share of the response s.
    #[serde(with = "ark_serde_compat::field")] pub(crate) ScalarField,
);

impl EdDSASigShare {
    /// Return the party ID bound into this signature share.
    #[must_use]
    pub fn party_id(&self) -> NonZeroU16 {
        self.0
    }
}
