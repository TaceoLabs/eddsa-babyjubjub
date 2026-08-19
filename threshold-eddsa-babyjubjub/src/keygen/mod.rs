//! Distributed Key Generation for Threshold `EdDSA`
//!
//! This module implements the distributed key generation (DKG) protocol that produces the
//! Shamir shares of the signing key, without any party ever learning the key itself.

pub mod blame;
pub mod finished;
pub mod round1;
pub mod round2;
pub mod schnorr;
#[cfg(test)]
pub mod test;

use ark_ff::PrimeField;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use std::{
    collections::HashMap,
    ops::{Deref, DerefMut},
};
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

pub(crate) struct SecretScalarMap<F: PrimeField>(pub(crate) HashMap<u16, F>);

impl<F: PrimeField> Deref for SecretScalarMap<F> {
    type Target = HashMap<u16, F>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<F: PrimeField> DerefMut for SecretScalarMap<F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<F: PrimeField> Drop for SecretScalarMap<F> {
    #[allow(
        clippy::iter_over_hash_type,
        reason = "zeroization order has no semantic effect"
    )]
    fn drop(&mut self) {
        for value in self.0.values_mut() {
            value.zeroize();
        }
    }
}

/// The parameters of a DKG protocol run, which must be the same for all participating parties.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Parameters {
    pub(crate) number_of_parties: u16,
    pub(crate) threshold: u16,
}

impl<'de> Deserialize<'de> for Parameters {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Repr {
            number_of_parties: u16,
            threshold: u16,
        }

        let repr = Repr::deserialize(deserializer)?;
        if repr.number_of_parties == 0 {
            return Err(D::Error::custom("number of parties must be non-zero"));
        }
        if repr.threshold == 0 || repr.threshold > repr.number_of_parties {
            return Err(D::Error::custom(
                "threshold must be non-zero and not exceed the number of parties",
            ));
        }
        Ok(Self {
            number_of_parties: repr.number_of_parties,
            threshold: repr.threshold,
        })
    }
}

impl Parameters {
    /// Create the parameters for a protocol run with `number_of_parties` parties, where
    /// `threshold` parties are required to reconstruct the key.
    ///
    /// `threshold` is the number of shares that reconstruct, so the polynomial has degree
    /// `threshold - 1`. The `PedPoP` schemes in the [source
    /// documentation](https://github.com/TaceoLabs/oprf-service/tree/main/docs) use `t` for the
    /// polynomial *degree* instead, so passing that document's `t` here builds a `(t + 1)`-of-`n`
    /// key: a valid key that verifies, but a stricter policy than intended.
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

/// A party failed a cryptographic check and is provably at fault.
///
/// The ID is part of the `Display` output, so attribution survives being logged as a string.
#[derive(Debug, thiserror::Error)]
#[error("party {0} failed a cryptographic check and is provably at fault")]
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

/// Two parties broadcast the same commitment to the constant term of their polynomial.
///
/// Both IDs are in the `Display` output. Resolve by passing both to
/// [`disqualify_parties`](crate::keygen::round1::RoundOne::disqualify_parties) as one atomic set.
#[derive(Debug, thiserror::Error)]
#[error("parties {} and {} committed to the same constant term; both are at fault", .0.0, .0.1)]
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

/// A message does not fit the local protocol view, which does **not** prove the sender misbehaved.
///
/// The usual cause is a configuration mismatch: a node started with different [`Parameters`] derives
/// a different proof-of-possession context and expects a different commitment count, so every honest
/// peer looks wrong to it. A stale session ID behaves the same way. Check the local configuration
/// before excluding the named party.
#[derive(Debug, thiserror::Error)]
#[error(
    "message from party {party} does not fit the local protocol view ({reason}); this is usually a \
     local configuration mismatch and does not prove party {party} misbehaved"
)]
pub struct MalformedMessageError {
    party: usize,
    reason: &'static str,
}

impl MalformedMessageError {
    /// Creates the error naming the claimed sender and why its message did not fit.
    #[must_use]
    pub fn new(party: usize, reason: &'static str) -> Self {
        Self { party, reason }
    }

    /// The claimed sender. This party is *not* accused; see the type documentation.
    #[must_use]
    pub fn party_id(&self) -> usize {
        self.party
    }
}

/// Why a participant's protocol message was rejected.
///
/// Only [`MessageError::MaliciousParty`] and [`MessageError::DuplicateCommitments`] attribute blame.
/// [`MessageError::Malformed`] usually means the *local* node is misconfigured, and
/// [`MessageError::LocalFault`] means the caller misused the API, so no remote message was evaluated.
/// Use [`MessageError::attributable_parties`] to act on blame; every variant names the parties
/// involved in its `Display` output, so a log line is still useful.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MessageError {
    /// A cryptographic check failed, so the named sender is provably at fault.
    #[error(transparent)]
    MaliciousParty(#[from] MaliciousPartyError),
    /// Two named parties committed to the same constant term, so both are at fault.
    #[error(transparent)]
    DuplicateCommitments(#[from] DuplicateCommitmentsError),
    /// The message does not fit the local protocol view; blame is not attributable.
    #[error(transparent)]
    Malformed(#[from] MalformedMessageError),
    /// The local caller supplied invalid input, so no remote message was evaluated.
    #[error(transparent)]
    LocalFault(#[from] eyre::Report),
}

impl MessageError {
    /// Wraps a local-fault message.
    pub(crate) fn local(reason: String) -> Self {
        Self::LocalFault(eyre::eyre!(reason))
    }

    /// The parties this error proves are at fault, empty when it attributes no blame.
    #[must_use]
    pub fn attributable_parties(&self) -> Vec<usize> {
        match self {
            Self::MaliciousParty(error) => vec![error.0],
            Self::DuplicateCommitments(error) => vec![error.0.0, error.0.1],
            Self::Malformed(_) | Self::LocalFault(_) => Vec::new(),
        }
    }
}

/// A [`Result`] whose error separates attributable misbehaviour from a local fault.
pub type MessageResult<T> = Result<T, MessageError>;
