//! Threshold `EdDSA` signatures over the Baby Jubjub curve based on Frost3, using Poseidon2 as the internal hash function for the Fiat-Shamir transform.

#[cfg(feature = "additive")]
pub mod additive;
pub mod commit;
pub mod nonce;
pub mod partial_commit;
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

/// The error returned by the aggregation with identifiable abort.
///
/// Carries the IDs of the parties that contributed a malformed signature share.
#[derive(Debug, thiserror::Error)]
#[error("Cheating parties detected")]
pub struct CheatingPartiesError(Vec<usize>);

impl CheatingPartiesError {
    /// Consumes the error and returns the IDs of the parties identified as cheating.
    #[must_use]
    pub fn into_inner(self) -> Vec<usize> {
        self.0
    }
}
