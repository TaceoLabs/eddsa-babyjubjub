//! The Signing-Party Side of Threshold `EdDSA`
//!
//! This module defines the `EdDSASession` struct, which holds the secret two-nonce randomness a
//! party samples in the pre-round and consumes again when producing its signature share, together
//! with the two messages a signer emits: the `PartialEdDSACommitments` commitment share sent to
//! the aggregator in the pre-round, and the `EdDSASigShare` produced in the sign round.
//!
//! Secret randomness is never clonable, and the `Debug` implementation of session types redacts it to avoid accidental leakage.

use crate::{
    Affine, BaseField, ScalarField, aggregator::EdDSACommitments,
    internal::binding::CombineTwoNonceRandomnessArgs, key_share::DLogShareShamir,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use ark_serde_compat::babyjubjub;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::num::NonZeroU16;
use zeroize::ZeroizeOnDrop;

/// Per-party commitments to the distributed `EdDSA` signature protocol.
///
/// Each party sends these commitments, which consist of a split of the actual response and nonce splits, for aggregation and creation of the global challenge hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialEdDSACommitments {
    /// The claimed ID of the party that created this commitment.
    pub(crate) party_id: NonZeroU16,
    #[serde(with = "babyjubjub::affine")]
    /// The share of G*d, the first part of the two-nonce commitment to the randomness r = d + e*b
    pub(crate) d: Affine,
    #[serde(with = "babyjubjub::affine")]
    /// The share of G*e, the second part of the two-nonce commitment to the randomness r = d + e*b
    pub(crate) e: Affine,
}

impl PartialEdDSACommitments {
    /// Return the party ID carried by this commitment.
    #[must_use]
    pub fn party_id(&self) -> NonZeroU16 {
        self.party_id
    }
}

/// Individual party's signature share for the `EdDSA` signature protocol.
/// Carries a response share for the signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EdDSASigShare(
    pub(crate) NonZeroU16,
    // The share of the response s.
    #[serde(with = "ark_serde_compat::field")] pub(crate) ScalarField,
);

impl EdDSASigShare {
    /// Return the party ID bound into this signature share.
    #[must_use]
    pub fn party_id(&self) -> NonZeroU16 {
        self.0
    }
}

/// The internal storage of a party in a distributed `EdDSA` protocol.
///
/// Stores non-clonable secret state for a threshold party during the `EdDSA` protocol,
/// used to generate the commitment share and construct the signature share.
///
/// This is not `Clone` because it contains secret randomness that may only be used once. The
/// `Debug` implementation redacts the secret nonces so they are not printed by accident.
/// The `sign_round` method consumes the session.
#[derive(ZeroizeOnDrop)]
pub struct EdDSASession {
    // The party ID is public, only the two nonces are secrets.
    #[zeroize(skip)]
    pub(crate) party_id: NonZeroU16,
    pub(crate) d: ScalarField,
    pub(crate) e: ScalarField,
}

impl std::fmt::Debug for EdDSASession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EdDSASession")
            .field("party_id", &self.party_id)
            .field("d", &"<redacted>")
            .field("e", &"<redacted>")
            .finish()
    }
}

impl EdDSASession {
    /// Computes commitments to two random values `d_share` and `e_share`, which will be the shares of the randomness used in the `EdDSA` signature.
    /// The result is meant to be sent to one accumulating party (i.e., the aggregator) who combines all the shares of all parties and creates the challenge hash.
    pub fn pre_round(
        party_id: NonZeroU16,
        rng: &mut (impl CryptoRng + Rng),
    ) -> (Self, PartialEdDSACommitments) {
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

        (session, comm)
    }

    /// Finalizes a signature share for a given challenge hash and session.
    /// The session and information therein is consumed to prevent reuse of the randomness.
    ///
    /// The Lagrange coefficient and the public key are both derived from the identity-bound key
    /// share rather than taken as arguments, so the signer never signs against a committee or a key
    /// it cannot check.
    ///
    /// The opaque `context` is mixed into the nonce-binding hash and must be byte-identical across
    /// all signers and the aggregator of one session — a mismatched participant produces an invalid
    /// share and is blamed by [`EdDSACommitments::sign_agg_with_identifiable_abort`]. Use it to
    /// bind the session to application data such as a unique session identifier. It is *not*
    /// verifier-visible domain separation: the final signature is a plain `EdDSA` signature over
    /// the message and verifies regardless of the context it was produced under.
    ///
    /// # Errors
    /// Returns an error if the key-share metadata is invalid, the signing set is non-canonical,
    /// outside the key's committee, or smaller than its threshold, or the nonce session, key share,
    /// and signing set do not identify the same party.
    pub fn sign_round(
        self,
        context: &[u8],
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
        if x_share.party_id > x_share.number_of_parties
            || x_share.threshold.get() < 2
            || x_share.threshold > x_share.number_of_parties
        {
            eyre::bail!("invalid Shamir key-share metadata");
        }
        if parties
            .last()
            .is_some_and(|&largest| largest > x_share.number_of_parties)
        {
            eyre::bail!("signing set contains a party outside the key's committee");
        }
        if parties.len() < usize::from(x_share.threshold.get()) {
            eyre::bail!("signing set is smaller than the threshold bound to the key share");
        }
        if self.party_id != x_share.party_id {
            eyre::bail!("nonce session and key share belong to different parties");
        }
        if parties.binary_search(&x_share.party_id).is_err() {
            eyre::bail!("signing set does not contain this party");
        }
        let lagrange_coefficient =
            crate::internal::lagrange::single_lagrange_from_coeff::<ScalarField, _>(
                x_share.party_id.get(),
                parties.iter().map(|party| party.get()),
            );
        // Recombine the two-nonce randomness shares into the full randomness used in the challenge.
        let (r, b) =
            crate::internal::binding::combine_two_nonce_randomness(CombineTwoNonceRandomnessArgs {
                context,
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
