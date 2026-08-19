//! Threshold `EdDSA` signatures over the Baby Jubjub curve based on Frost3, using Poseidon2 as the internal hash function for the Fiat-Shamir transform.

#[cfg(feature = "additive")]
pub mod additive;
pub mod commit;
pub mod keygen;
pub mod nonce;
pub mod partial_commit;
pub mod reshare;
mod serde_utils;
pub mod session;
pub mod shamir;
pub mod signature;

use ark_ec::{CurveGroup, PrimeGroup};

pub(crate) type Curve = ark_babyjubjub::EdwardsProjective;
pub(crate) type Affine = <Curve as CurveGroup>::Affine;
pub(crate) type BaseField = <Curve as CurveGroup>::BaseField;
pub(crate) type Projective = ark_babyjubjub::EdwardsProjective;
pub(crate) type ScalarField = <Curve as PrimeGroup>::ScalarField;

pub(crate) const FROST_3_NONCE_COMBINER_LABEL: &[u8] = b"FROST_3_NONCE_COMBINER";

/// The IDs of the parties that contributed a malformed signature share.
#[derive(Debug, thiserror::Error)]
#[error("Malicious parties detected: {0:?}")]
pub struct MaliciousPartiesError(Vec<usize>);

impl MaliciousPartiesError {
    /// Consumes the error and returns the IDs of the parties identified as cheating.
    #[must_use]
    pub fn into_inner(self) -> Vec<usize> {
        self.0
    }

    /// The IDs of the parties identified as cheating.
    #[must_use]
    pub fn party_ids(&self) -> &[usize] {
        &self.0
    }
}

/// The error returned by aggregation with identifiable abort.
///
/// The two variants are the two distinguishable outcomes, and the distinction matters: only
/// [`IdentifiableAbortError::MaliciousParties`] attributes blame. An
/// [`IdentifiableAbortError::InvalidInput`] means the aggregator's own inputs were inconsistent, so
/// no share was validated and no participant may be accused. Use
/// [`IdentifiableAbortError::malicious_parties`] rather than only logging the error, or the
/// attribution this API exists to produce is silently discarded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IdentifiableAbortError {
    /// At least one signature share failed its validation equation.
    #[error(transparent)]
    MaliciousParties(#[from] MaliciousPartiesError),
    /// The supplied aggregation inputs do not form a consistent set, so no share could be checked.
    #[error(transparent)]
    InvalidInput(#[from] eyre::Report),
}

impl IdentifiableAbortError {
    /// The IDs of the parties whose signature share failed validation, or `None` when the abort was
    /// caused by inconsistent aggregation input rather than by a malformed share.
    #[must_use]
    pub fn malicious_parties(&self) -> Option<&[usize]> {
        match self {
            Self::MaliciousParties(error) => Some(error.party_ids()),
            Self::InvalidInput(_) => None,
        }
    }

    /// Consumes the error and returns the IDs of the parties identified as cheating, or `None` when
    /// the abort was caused by inconsistent aggregation input.
    #[must_use]
    pub fn into_malicious_parties(self) -> Option<Vec<usize>> {
        match self {
            Self::MaliciousParties(error) => Some(error.into_inner()),
            Self::InvalidInput(_) => None,
        }
    }
}
