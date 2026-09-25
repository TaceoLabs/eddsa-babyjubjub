//! Error types for Threshold `EdDSA`
//!
//! This module defines the errors returned by the aggregation with identifiable abort, which
//! distinguish attributable cheating from inconsistent aggregation input.

use std::num::NonZeroU16;

/// The IDs of the parties that contributed a malformed signature share.
#[derive(Debug, thiserror::Error)]
#[error("Malicious parties detected: {0:?}")]
pub struct MaliciousPartiesError(pub(crate) Vec<NonZeroU16>);

impl MaliciousPartiesError {
    /// Consumes the error and returns the IDs of the parties identified as cheating.
    #[must_use]
    pub fn into_inner(self) -> Vec<NonZeroU16> {
        self.0
    }

    /// The IDs of the parties identified as cheating.
    #[must_use]
    pub fn party_ids(&self) -> &[NonZeroU16] {
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
    pub fn malicious_parties(&self) -> Option<&[NonZeroU16]> {
        match self {
            Self::MaliciousParties(error) => Some(error.party_ids()),
            Self::InvalidInput(_) => None,
        }
    }

    /// Consumes the error and returns the IDs of the parties identified as cheating, or `None` when
    /// the abort was caused by inconsistent aggregation input.
    #[must_use]
    pub fn into_malicious_parties(self) -> Option<Vec<NonZeroU16>> {
        match self {
            Self::MaliciousParties(error) => Some(error.into_inner()),
            Self::InvalidInput(_) => None,
        }
    }
}
