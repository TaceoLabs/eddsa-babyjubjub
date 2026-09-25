//! Per-Party Session State for Threshold `EdDSA`
//!
//! This module defines the `EdDSASession` struct, which holds the secret two-nonce randomness a
//! party samples in the pre-round and consumes again when producing its signature share.
//!
//! Secret randomness is never clonable, and session types deliberately do not implement `Debug` to avoid accidental leakage.

use crate::{
    Affine, BaseField, ScalarField, commit::EdDSACommitments, nonce::CombineTwoNonceRandomnessArgs,
    partial_commit::PartialEdDSACommitments, secret::DLogShareShamir, signature::EdDSASigShare,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use rand::{CryptoRng, Rng};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

/// The internal storage of a party in a distributed `EdDSA` protocol.
///
/// Stores non-clonable, non-debug secret state for a threshold party during the `EdDSA` protocol,
/// used to generate the commitment share and construct the signature share.
///
/// This is not `Clone` because it contains secret randomness that may only be used once. We also don't implement `Debug` so we do don't print it by accident.
/// The `sign_round` method consumes the session.
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

    /// Finalizes a signature share for a given challenge hash and session.
    /// The session and information therein is consumed to prevent reuse of the randomness.
    ///
    /// The Lagrange coefficient and the public key are both derived from the identity-bound key
    /// share rather than taken as arguments, so the signer never signs against a committee or a key
    /// it cannot check.
    ///
    /// # Errors
    /// Returns an error if the key-share metadata is invalid, the signing set is non-canonical,
    /// outside the key's committee, or smaller than its threshold, or the nonce session, key share,
    /// and signing set do not identify the same party.
    pub fn sign_round(
        self,
        session_id: Uuid,
        x_share: &DLogShareShamir,
        message: BaseField,
        challenge_input: EdDSACommitments,
    ) -> eyre::Result<EdDSASigShare> {
        let EdDSACommitments {
            d,
            e,
            contributing_parties,
        } = challenge_input;
        let public_key = x_share.public_key();
        let parties = &contributing_parties;
        EdDSACommitments::validate_party_ids(parties)?;
        if x_share.party_id == 0
            || x_share.number_of_parties == 0
            || x_share.party_id > x_share.number_of_parties
            || x_share.threshold == 0
            || x_share.threshold > x_share.number_of_parties
        {
            eyre::bail!("invalid Shamir key-share metadata");
        }
        if parties.last().copied().unwrap_or_default() > x_share.number_of_parties {
            eyre::bail!("signing set contains a party outside the key's committee");
        }
        if parties.len() < usize::from(x_share.threshold) {
            eyre::bail!("signing set is smaller than the threshold bound to the key share");
        }
        if self.party_id != x_share.party_id {
            eyre::bail!("nonce session and key share belong to different parties");
        }
        if parties.binary_search(&x_share.party_id).is_err() {
            eyre::bail!("signing set does not contain this party");
        }
        let lagrange_coefficient =
            crate::utils::single_lagrange_from_coeff::<ScalarField, _>(x_share.party_id, parties);
        // Recombine the two-nonce randomness shares into the full randomness used in the challenge.
        let (r, b) = crate::nonce::combine_two_nonce_randomness(CombineTwoNonceRandomnessArgs {
            session_id,
            message,
            public_key: public_key.clone(),
            d,
            e,
            parties,
        });

        // Recompute the challenge hash to ensure the challenge is well-formed.
        let c = eddsa_babyjubjub::challenge_hash(message, r, public_key.pk);

        // The following modular reduction in convert_base_to_scalar is required in rust to perform the scalar multiplications. Using all 254 bits of the base field in a double/add ladder would apply this reduction implicitly. We show in the docs of convert_base_to_scalar why this does not introduce a bias when applied to a uniform element of the base field.
        let c_ = eddsa_babyjubjub::convert_base_to_scalar(c);
        Ok(EdDSASigShare(
            x_share.party_id,
            self.d + b * self.e + lagrange_coefficient * c_ * x_share.value,
        ))
    }
}
