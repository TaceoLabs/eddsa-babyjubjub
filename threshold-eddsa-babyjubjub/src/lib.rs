//! Threshold `EdDSA` signatures over the Baby Jubjub curve based on Frost3, using Poseidon2 as the internal hash function for the Fiat-Shamir transform.
//!
//! This crate implements the `t`-out-of-`n` variant of the protocol, where the signing key is
//! shared via a Shamir polynomial of degree `d`, so any `d + 1` parties can jointly produce a
//! signature by weighting their shares with the matching Lagrange coefficients.
//!
//! The protocol involves two roles, mirrored by the module layout:
//!
//! - Each **signer** ([`signer`]) holds a [`DLogShareShamir`] key share and runs
//!   [`EdDSASession::pre_round`] to produce a [`PartialEdDSACommitments`] message, then
//!   [`EdDSASession::sign_round`] to produce an [`EdDSASigShare`].
//! - The **aggregator** ([`aggregator`]) combines the partial commitments via
//!   [`EdDSACommitments::pre_agg`] into the challenge input sent back to the signers, and combines
//!   their signature shares into the final signature via [`EdDSACommitments::sign_agg`] or
//!   [`EdDSACommitments::sign_agg_with_identifiable_abort`].

pub mod aggregator;
pub mod error;
mod internal;
pub mod key_share;
pub mod keygen;
pub mod signer;
#[cfg(test)]
mod tests;

pub use aggregator::EdDSACommitments;
pub use error::{IdentifiableAbortError, MaliciousPartiesError};
pub use key_share::DLogShareShamir;
pub use signer::{EdDSASession, EdDSASigShare, PartialEdDSACommitments};

use ark_ec::{CurveGroup, PrimeGroup};

pub(crate) type Curve = ark_babyjubjub::EdwardsProjective;
pub(crate) type Affine = <Curve as CurveGroup>::Affine;
pub(crate) type BaseField = <Curve as CurveGroup>::BaseField;
pub(crate) type ScalarField = <Curve as PrimeGroup>::ScalarField;
