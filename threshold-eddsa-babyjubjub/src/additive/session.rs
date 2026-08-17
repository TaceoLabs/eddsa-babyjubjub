//! Per-party session state for the additive threshold `EdDSA` protocol.
//!
//! This module defines the `EdDSASessionAdditive` struct, which holds the secret two-nonce
//! randomness of one party between the pre-round and the signing round.
//!
//! Secret randomness is never clonable, and session types deliberately do not implement `Debug` to avoid accidental leakage.

use crate::{
    BaseField,
    additive::{
        commit::EdDSACommitmentsAdditive, partial_commit::PartialEdDSACommitmentsAdditive,
        secret::DLogShareAdditive, signature::EdDSASigShareAdditive,
    },
    nonce::CombineTwoNonceRandomnessArgs,
    session::EdDSASession,
    signature::EdDSASigShare,
};
use eddsa_babyjubjub::EdDSAPublicKey;
use rand::{CryptoRng, Rng};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

/// Wrapper for the internal `EdDSA` session state in the additive-sharing variant.
///
/// Stores non-clonable, non-debug secret state for a threshold party during the `EdDSA` protocol.
/// Used to generate the commitment shares and construct the signature share for Shamir secret sharing.
#[derive(ZeroizeOnDrop)]
pub struct EdDSASessionAdditive(EdDSASession);

impl EdDSASessionAdditive {
    /// Computes commitments to two random values `d_share` and `e_share`, which will be the shares of the randomness used in the `EdDSA` signature.
    /// The result is meant to be sent to one accumulating party (i.e., the aggregator) who combines all the shares of all parties and creates the challenge hash.
    pub fn pre_round(rng: &mut (impl CryptoRng + Rng)) -> (Self, PartialEdDSACommitmentsAdditive) {
        let (session, comm) = EdDSASession::pre_round(rng);
        (Self(session), PartialEdDSACommitmentsAdditive(comm))
    }

    /// Finalizes a signature share for a given challenge hash and session.
    /// The session and information therein is consumed to prevent reuse of the randomness.
    #[must_use]
    pub fn sign_round(
        self,
        session_id: Uuid,
        DLogShareAdditive(x_share): DLogShareAdditive,
        message: BaseField,
        public_key: &EdDSAPublicKey,
        EdDSACommitmentsAdditive(challenge_input): EdDSACommitmentsAdditive,
    ) -> EdDSASigShareAdditive {
        // Recombine the two-nonce randomness shares into the full randomness used in the challenge.
        let (r, b) = crate::nonce::combine_two_nonce_randomness(CombineTwoNonceRandomnessArgs {
            session_id,
            message,
            public_key: public_key.clone(),
            d: challenge_input.d,
            e: challenge_input.e,
            parties: &challenge_input.contributing_parties,
        });

        // Recompute the challenge hash to ensure the challenge is well-formed.
        let c = eddsa_babyjubjub::challenge_hash(message, r, public_key.pk);

        // The following modular reduction in convert_base_to_scalar is required in rust to perform the scalar multiplications. Using all 254 bits of the base field in a double/add ladder would apply this reduction implicitly. We show in the docs of convert_base_to_scalar why this does not introduce a bias when applied to a uniform element of the base field.
        let c_ = eddsa_babyjubjub::convert_base_to_scalar(c);
        let share = EdDSASigShare(self.0.d + b * self.0.e + c_ * x_share);
        EdDSASigShareAdditive(share)
    }
}
