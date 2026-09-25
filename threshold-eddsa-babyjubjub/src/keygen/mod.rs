//! Distributed Key Generation for Threshold `EdDSA`
//!
//! This module implements the distributed key generation (DKG) protocol that produces the
//! Shamir shares of the signing key, without any party ever learning the key itself.
//!
//! Every configured participant must contribute a valid round-one broadcast and a valid private
//! round-two share. Abort the run if a contribution is invalid or missing; restart with fresh
//! polynomials and a fresh context after agreeing on any change to the participant set.
//! There is no public share-revelation or participant-exclusion recovery protocol.

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
    num::NonZeroU16,
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

pub(crate) struct SecretScalarMap<F: PrimeField>(pub(crate) HashMap<NonZeroU16, F>);

impl<F: PrimeField> Deref for SecretScalarMap<F> {
    type Target = HashMap<NonZeroU16, F>;

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
    pub(crate) number_of_parties: NonZeroU16,
    pub(crate) threshold: NonZeroU16,
}

impl<'de> Deserialize<'de> for Parameters {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Repr {
            number_of_parties: NonZeroU16,
            threshold: NonZeroU16,
        }

        let repr = Repr::deserialize(deserializer)?;
        if repr.threshold > repr.number_of_parties {
            return Err(D::Error::custom(
                "threshold must not exceed the number of parties",
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
    /// polynomial *degree* instead, so that document's `t` corresponds to a threshold of `t + 1`
    /// here.
    ///
    /// # Panics
    /// Panics unless `threshold <= number_of_parties`.
    #[must_use]
    pub fn new(number_of_parties: NonZeroU16, threshold: NonZeroU16) -> Self {
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
        self.threshold.get() - 1
    }

    /// Iterates over all party indices of a run, from one to `number_of_parties`.
    pub(crate) fn party_indices(self) -> impl Iterator<Item = NonZeroU16> {
        (1..=self.number_of_parties.get())
            .map(|index| NonZeroU16::new(index).expect("range starts at one"))
    }
}

/// A sender's contribution failed a cryptographic check.
///
/// Attribution assumes authenticated, session-bound delivery and agreed parameters and context.
/// This is a local error, not a publicly verifiable proof of what a private sender delivered.
/// The ID is part of the `Display` output, so attribution survives being logged as a string.
#[derive(Debug, thiserror::Error)]
#[error("party {0}'s contribution failed a cryptographic check")]
pub struct MaliciousPartyError(NonZeroU16);

impl MaliciousPartyError {
    /// Consumes the error and returns the ID of the parties identified as cheating.
    #[must_use]
    pub fn into_inner(self) -> NonZeroU16 {
        self.0
    }

    /// Creates the error carrying the ID of the party identified as cheating.
    #[must_use]
    pub fn new(party_id: NonZeroU16) -> Self {
        Self(party_id)
    }
}

/// A message does not fit the local protocol view, which does **not** prove the sender misbehaved.
///
/// The usual cause is a configuration mismatch: a node started with different [`Parameters`] expects
/// a different commitment count, so every honest peer looks wrong to it. Check the local
/// configuration before attributing fault to the named party. Note that a node started with a different
/// session *context* is not detected here: it derives a different proof-of-possession context, so
/// its messages fail cryptographic checks and are reported as attributable misbehaviour.
#[derive(Debug, thiserror::Error)]
#[error(
    "message from party {party} does not fit the local protocol view ({reason}); this is usually a \
     local configuration mismatch and does not prove party {party} misbehaved"
)]
pub struct MalformedMessageError {
    party: NonZeroU16,
    reason: &'static str,
}

impl MalformedMessageError {
    /// Creates the error naming the claimed sender and why its message did not fit.
    #[must_use]
    pub fn new(party: NonZeroU16, reason: &'static str) -> Self {
        Self { party, reason }
    }

    /// The claimed sender. This party is *not* accused; see the type documentation.
    #[must_use]
    pub fn party_id(&self) -> NonZeroU16 {
        self.party
    }
}

/// Why a participant's protocol message was rejected.
///
/// Only [`MessageError::MaliciousParty`] attributes blame, subject to the delivery and agreement
/// requirements documented on [`MaliciousPartyError`].
/// [`MessageError::Malformed`] usually means the *local* node is misconfigured, and
/// [`MessageError::LocalFault`] means the caller misused the API, so no remote message was evaluated.
/// Use [`MessageError::attributable_parties`] to act on blame; every variant names the parties
/// involved in its `Display` output, so a log line is still useful.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MessageError {
    /// The named sender's contribution failed a cryptographic check.
    #[error(transparent)]
    MaliciousParty(#[from] MaliciousPartyError),
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

    /// The parties this local error attributes fault to, empty when it attributes no blame.
    #[must_use]
    pub fn attributable_parties(&self) -> Vec<NonZeroU16> {
        match self {
            Self::MaliciousParty(error) => vec![error.0],
            Self::Malformed(_) | Self::LocalFault(_) => Vec::new(),
        }
    }
}

/// A [`Result`] whose error separates attributable misbehaviour from a local fault.
pub type MessageResult<T> = Result<T, MessageError>;
