//! Per-Party Session State for Threshold `EdDSA`
//!
//! This module defines the `EdDSASession` struct, which holds the secret two-nonce randomness a
//! party samples in the pre-round and consumes again when producing its signature share.
//!
//! The primitives defined here are agnostic to the underlying threshold sharing scheme and are used by both
//! additive and Shamir variants, which are implemented in their respective submodules `additive` and `shamir`.
//!
//! Secret randomness is never clonable, and session types deliberately do not implement `Debug` to avoid accidental leakage.

use crate::{Affine, ScalarField, partial_commit::PartialEdDSACommitments};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use rand::{CryptoRng, Rng};
use zeroize::ZeroizeOnDrop;

/// The internal storage of a party in a distributed `EdDSA` protocol.
///
/// This is not `Clone` because it contains secret randomness that may only be used once. We also don't implement `Debug` so we do don't print it by accident.
/// The `challenge` method consumes the session.
#[derive(ZeroizeOnDrop)]
pub struct EdDSASession {
    pub(crate) party_id: u16,
    pub(crate) d: ScalarField,
    pub(crate) e: ScalarField,
}

impl EdDSASession {
    /// Computes commitments to two random values `d_share` and `e_share`, which will be the shares of the randomness used in the `EdDSA` signature.
    /// The result is meant to be sent to one accumulating party (i.e., the aggregator) who combines all the shares of all parties and creates the challenge hash.
    ///
    /// # Errors
    /// Returns an error if `party_id` is zero.
    pub fn pre_round(
        party_id: u16,
        rng: &mut (impl CryptoRng + Rng),
    ) -> eyre::Result<(Self, PartialEdDSACommitments)> {
        if party_id == 0 {
            eyre::bail!("party ID must be non-zero");
        }
        let d_share: ark_ff::Fp<ark_ff::MontBackend<ark_babyjubjub::FrConfig, 4>, 4> =
            ScalarField::rand(rng);
        let e_share = ScalarField::rand(rng);
        let d = (Affine::generator() * d_share).into_affine();
        let e = (Affine::generator() * e_share).into_affine();
        let comm = PartialEdDSACommitments { party_id, d, e };

        let session = EdDSASession {
            party_id,
            d: d_share,
            e: e_share,
        };

        Ok((session, comm))
    }
}
