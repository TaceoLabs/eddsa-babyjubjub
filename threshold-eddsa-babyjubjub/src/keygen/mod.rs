//! Distributed Key Generation for Threshold `EdDSA`
//!
//! This module implements the distributed key generation (DKG) protocol that produces the
//! Shamir shares of the signing key, without any party ever learning the key itself.

pub mod finished;
pub mod round1;
pub mod round2;
pub mod schnorr;
#[cfg(test)]
pub mod test;

use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

pub(crate) struct SecretScalars<F: PrimeField>(pub(crate) Vec<F>);

impl<F: PrimeField> Deref for SecretScalars<F> {
    type Target = [F];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: PrimeField> DerefMut for SecretScalars<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<F: PrimeField> Drop for SecretScalars<F> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The parameters of a DKG protocol run, which must be the same for all participating parties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Parameters {
    pub(crate) number_of_parties: u16,
    pub(crate) threshold: u16,
}

impl Parameters {
    /// Create the parameters for a protocol run with `number_of_parties` parties, where
    /// `threshold` parties are required to reconstruct the key.
    ///
    /// # Panics
    /// Panics unless `1 <= threshold <= number_of_parties`.
    #[must_use]
    pub fn new(number_of_parties: u16, threshold: u16) -> Self {
        assert!(number_of_parties > 0, "Number of parties must be non-zero");
        assert!(threshold > 0, "Threshold must be non-zero");
        assert!(
            threshold <= number_of_parties,
            "Threshold must not be larger than the number of parties"
        );
        Self {
            number_of_parties,
            threshold,
        }
    }

    /// Returns the degree of the polynomials the parties share their contribution with, i.e., one
    /// less than the threshold.
    #[must_use]
    pub fn degree(&self) -> u16 {
        self.threshold - 1
    }
}

/// The error returned by a round of the DKG protocol if a party contributed a malformed message.
///
/// Carries the ID of the party identified as cheating.
#[derive(Debug, thiserror::Error)]
#[error("Malicious parties detected")]
pub struct MaliciousPartyError(usize);

impl MaliciousPartyError {
    /// Consumes the error and returns the ID of the parties identified as cheating.
    #[must_use]
    pub fn into_inner(self) -> usize {
        self.0
    }

    /// Creates the error carrying the ID of the party identified as cheating.
    #[must_use]
    pub fn new(party_id: usize) -> Self {
        Self(party_id)
    }
}

/// The error returned by the first round of the DKG protocol if two parties broadcast the same
/// commitment to the constant term of their polynomial.
///
/// Carries the IDs of both parties involved.
#[derive(Debug, thiserror::Error)]
#[error("Duplicate commitments detected")]
pub struct DuplicateCommitmentsError((usize, usize));

impl DuplicateCommitmentsError {
    /// Consumes the error and returns the ID of the parties identified as cheating.
    #[must_use]
    pub fn into_inner(self) -> (usize, usize) {
        self.0
    }

    /// Creates the error carrying the IDs of the two parties that committed to the same value.
    #[must_use]
    pub fn new(party_id1: usize, party_id2: usize) -> Self {
        Self((party_id1, party_id2))
    }
}
