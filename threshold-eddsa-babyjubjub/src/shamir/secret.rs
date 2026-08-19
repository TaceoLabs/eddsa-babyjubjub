//! Shamir shares of the `EdDSA` signing key.
//!
//! This module defines the `DLogShareShamir` struct, one party's Shamir share of the discrete
//! logarithm of the public key, i.e., the evaluation of the sharing polynomial at the party's
//! index.

use crate::ScalarField;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Shamir Secret-share of an `EdDSA` signing secret.
///
/// Serializable so it can be persisted via a secret manager.
/// Not `Debug`/`Display` to avoid accidental leaks.
///
#[derive(Serialize, Deserialize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize)]
pub struct DLogShareShamir {
    #[serde(with = "ark_serde_compat::field")]
    pub(crate) value: ScalarField,
    pub(crate) party_id: u16,
    pub(crate) number_of_parties: u16,
    pub(crate) threshold: u16,
}

impl DLogShareShamir {
    /// Bind a scalar share to its party identity and Shamir committee parameters.
    ///
    /// # Errors
    /// Returns an error unless the metadata satisfies
    /// `1 <= party_id <= number_of_parties` and
    /// `1 <= threshold <= number_of_parties`.
    pub fn new(
        value: ScalarField,
        party_id: u16,
        number_of_parties: u16,
        threshold: u16,
    ) -> eyre::Result<Self> {
        if party_id == 0 || number_of_parties == 0 || party_id > number_of_parties {
            eyre::bail!("party ID must lie in the non-empty Shamir party set");
        }
        if threshold == 0 || threshold > number_of_parties {
            eyre::bail!("invalid Shamir threshold");
        }
        Ok(Self {
            value,
            party_id,
            number_of_parties,
            threshold,
        })
    }

    /// Return the identity bound to this share.
    #[must_use]
    pub fn party_id(&self) -> u16 {
        self.party_id
    }
}
