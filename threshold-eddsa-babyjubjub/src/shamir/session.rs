//! Per-party session state for the Shamir threshold `EdDSA` protocol.
//!
//! This module defines the `EdDSASessionShamir` struct, which holds the secret two-nonce
//! randomness of one party between the pre-round and the signing round.
//!
//! Secret randomness is never clonable, and session types deliberately do not implement `Debug` to avoid accidental leakage.

use crate::{
    BaseField, ScalarField,
    nonce::CombineTwoNonceRandomnessArgs,
    session::EdDSASession,
    shamir::{
        commit::EdDSACommitmentsShamir, partial_commit::PartialEdDSACommitmentsShamir,
        secret::DLogShareShamir, signature::EdDSASigShareShamir,
    },
    signature::EdDSASigShare,
};
use rand::{CryptoRng, Rng};
use uuid::Uuid;
use zeroize::ZeroizeOnDrop;

/// Wrapper for the internal `EdDSA` session state in the Shamir-sharing variant.
///
/// Stores non-clonable, non-debug secret state for a threshold party during the `EdDSA` protocol.
/// Used to generate the commitment shares and construct the signature share for Shamir secret sharing.
#[derive(ZeroizeOnDrop)]
pub struct EdDSASessionShamir(EdDSASession);

impl EdDSASessionShamir {
    /// Computes commitments to two random values `d_share` and `e_share`, which will be the shares of the randomness used in the `EdDSA` signature.
    /// The result is meant to be sent to one accumulating party (i.e., the aggregator) who combines all the shares of all parties and creates the challenge hash.
    ///
    /// # Errors
    /// Returns an error if `party_id` is zero.
    pub fn pre_round(
        party_id: u16,
        rng: &mut (impl CryptoRng + Rng),
    ) -> eyre::Result<(Self, PartialEdDSACommitmentsShamir)> {
        let (session, comm) = EdDSASession::pre_round(party_id, rng)?;
        Ok((Self(session), PartialEdDSACommitmentsShamir(comm)))
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
        EdDSACommitmentsShamir(challenge_input): EdDSACommitmentsShamir,
    ) -> eyre::Result<EdDSASigShareShamir> {
        let public_key = x_share.public_key();
        let parties = &challenge_input.contributing_parties;
        crate::commit::EdDSACommitments::validate_party_ids(parties)?;
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
        if self.0.party_id != x_share.party_id {
            eyre::bail!("nonce session and key share belong to different parties");
        }
        if parties.binary_search(&x_share.party_id).is_err() {
            eyre::bail!("signing set does not contain this party");
        }
        let lagrange_coefficient = crate::shamir::utils::single_lagrange_from_coeff::<ScalarField, _>(
            x_share.party_id,
            parties,
        );
        // Recombine the two-nonce randomness shares into the full randomness used in the challenge.
        let (r, b) = crate::nonce::combine_two_nonce_randomness(CombineTwoNonceRandomnessArgs {
            session_id,
            message,
            public_key: public_key.clone(),
            d: challenge_input.d,
            e: challenge_input.e,
            parties,
        });

        // Recompute the challenge hash to ensure the challenge is well-formed.
        let c = eddsa_babyjubjub::challenge_hash(message, r, public_key.pk);

        // The following modular reduction in convert_base_to_scalar is required in rust to perform the scalar multiplications. Using all 254 bits of the base field in a double/add ladder would apply this reduction implicitly. We show in the docs of convert_base_to_scalar why this does not introduce a bias when applied to a uniform element of the base field.
        let c_ = eddsa_babyjubjub::convert_base_to_scalar(c);
        let share = EdDSASigShare(
            x_share.party_id,
            self.0.d + b * self.0.e + lagrange_coefficient * c_ * x_share.value,
        );
        Ok(EdDSASigShareShamir(share))
    }
}
