//! Additive shares of the `EdDSA` signing key.
//!
//! This module defines the `DLogShareAdditive` struct, one party's additive share of the discrete
//! logarithm of the public key. All `n` shares sum to the signing key.

use crate::ScalarField;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Additive Secret-share of an `EdDSA` signing secret.
///
/// Serializable so it can be persisted via a secret manager.
/// Not `Debug`/`Display` to avoid accidental leaks.
///
#[derive(Serialize, Deserialize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize)]
pub struct DLogShareAdditive {
    #[serde(with = "ark_serde_compat::field")]
    pub(crate) value: ScalarField,
    pub(crate) party_id: u16,
    pub(crate) number_of_parties: u16,
}

impl DLogShareAdditive {
    /// Bind an additive scalar share to its identity and complete party count.
    ///
    /// # Errors
    /// Returns an error unless `1 <= party_id <= number_of_parties`.
    pub fn new(value: ScalarField, party_id: u16, number_of_parties: u16) -> eyre::Result<Self> {
        if party_id == 0 || number_of_parties == 0 || party_id > number_of_parties {
            eyre::bail!("party ID must lie in the non-empty additive party set");
        }
        Ok(Self {
            value,
            party_id,
            number_of_parties,
        })
    }

    /// Return the identity bound to this share.
    #[must_use]
    pub fn party_id(&self) -> u16 {
        self.party_id
    }
}
