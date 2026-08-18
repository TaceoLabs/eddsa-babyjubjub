//! Aggregated commitments for the Shamir threshold `EdDSA` protocol.
//!
//! This module defines the `EdDSACommitmentsShamir` struct, which sums the per-party commitment
//! shares of the `d + 1` contributing parties and combines the received signature shares into the
//! final `EdDSA` signature. It also offers an aggregation with identifiable abort, which pinpoints
//! the parties that contributed a malformed share.

use crate::{
    Affine, BaseField, MaliciousPartiesError, Projective, ScalarField,
    commit::EdDSACommitments,
    nonce::CombineTwoNonceRandomnessArgs,
    shamir::{partial_commit::PartialEdDSACommitmentsShamir, signature::EdDSASigShareShamir},
};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use itertools::izip;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Commitment aggregation object for the Shamir `EdDSA` protocol.
///
/// This is a transparent wrapper around the core `EdDSACommitments` struct, grouping
/// together the aggregate commitments and participating party identifiers as reconstructed
/// via Shamir Lagrange interpolation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EdDSACommitmentsShamir(pub(crate) EdDSACommitments);

impl EdDSACommitmentsShamir {
    /// Create an aggregated commitment object from component affine points and party IDs.
    #[must_use]
    pub fn new(d: Affine, e: Affine, parties: Vec<u16>) -> Self {
        let commitments = EdDSACommitments {
            d,
            e,
            contributing_parties: parties,
        };
        Self(commitments)
    }

    /// Returns the parties that contributed to this commitment.
    #[must_use]
    pub fn get_contributing_parties(&self) -> &[u16] {
        &self.0.contributing_parties
    }

    /// Combine all parties' signature shares into a single `EdDSA` signature object.
    ///
    /// Must use the same order of contributing parties as in aggregation
    #[must_use]
    pub fn sign_agg(
        self,
        session_id: Uuid,
        shares: &[EdDSASigShareShamir],
        message: BaseField,
        public_key: EdDSAPublicKey,
    ) -> EdDSASignature {
        self.0
            .sign_agg(session_id, shares.iter().map(|x| &x.0), message, public_key)
    }

    /// Combine all parties' signature shares into a single `EdDSA` signature object, verifying
    /// each party's contribution individually so that malformed shares can be attributed.
    ///
    /// The order of `shares`, `commitments`, and `x_share_commitments` must match the order of the
    /// Lagrange coefficients.
    ///
    /// # Errors
    /// Returns a [`MaliciousPartiesError`] with the IDs of all parties whose signature share does
    /// not verify against their commitment and their Lagrange-weighted share of the public key.
    ///
    /// # Panics
    /// Panics if `shares`, `x_share_commitments`, `commitments` and `lagrange_coefficients` do not
    /// all have the same length. The call site is expected to enforce this.
    #[expect(
        clippy::too_many_arguments,
        reason = "Keeps consistency with the additive version of this function"
    )]
    pub fn sign_agg_with_identifiable_abort(
        self,
        session_id: Uuid,
        shares: &[EdDSASigShareShamir],
        message: BaseField,
        public_key: &EdDSAPublicKey,
        x_share_commitments: &[Affine],
        commitments: &[PartialEdDSACommitmentsShamir],
        lagrange_coefficients: &[ScalarField],
    ) -> Result<EdDSASignature, MaliciousPartiesError> {
        assert_eq!(
            shares.len(),
            x_share_commitments.len(),
            "Shares and commitments must match"
        );
        assert_eq!(
            shares.len(),
            commitments.len(),
            "Shares and commitments must match"
        );
        assert_eq!(
            shares.len(),
            lagrange_coefficients.len(),
            "Shares and lagrange coefficients must match"
        );

        let (r, b) = crate::nonce::combine_two_nonce_randomness(CombineTwoNonceRandomnessArgs {
            session_id,
            message,
            public_key: public_key.to_owned(),
            d: self.0.d,
            e: self.0.e,
            parties: &self.0.contributing_parties,
        });

        // Recompute the challenge hash to ensure the challenge is well-formed.
        let c = eddsa_babyjubjub::challenge_hash(message, r, public_key.pk);

        // The following modular reduction in convert_base_to_scalar is required in rust to perform the scalar multiplications. Using all 254 bits of the base field in a double/add ladder would apply this reduction implicitly. We show in the docs of convert_base_to_scalar why this does not introduce a bias when applied to a uniform element of the base field.
        let c_ = eddsa_babyjubjub::convert_base_to_scalar(c);

        // For identifiable abort, we check the contribution of all parties
        let mut cheating_parties = Vec::new();
        for (id, (share, x_share_commitment, commitment, lagrange)) in izip!(
            shares,
            x_share_commitments,
            commitments,
            lagrange_coefficients
        )
        .enumerate()
        {
            let s = share.0.0;
            let r = commitment.0.d + commitment.0.e * b;
            if !crate::commit::verify_for_identifiable_abort(
                x_share_commitment,
                r.into_affine(),
                s,
                c_ * lagrange,
            ) {
                cheating_parties.push(usize::from(self.0.contributing_parties[id]));
            }
        }

        if !cheating_parties.is_empty() {
            return Err(MaliciousPartiesError(cheating_parties));
        }

        // Finally assemble the signature
        let mut s = ScalarField::zero();
        for share in shares {
            s += share.0.0;
        }

        let sig = EdDSASignature { r, s };
        Ok(sig)
    }

    /// The accumulating party (i.e., the aggregatir) combines the shares of `d + 1` parties.
    ///
    /// # Panics
    /// Panics if the number of commitments does not match the number of contributing parties,
    /// i.e. `commitments.len() != contributing_parties.len()`.
    /// Additionally, panics if the contributing parties contain duplicate party IDs.
    /// The call site is expected to enforce these checks.
    #[must_use]
    pub fn pre_agg(
        commitments: &[PartialEdDSACommitmentsShamir],
        contributing_parties: Vec<u16>,
    ) -> Self {
        let mut contributing_parties_dedup = contributing_parties.clone();
        contributing_parties_dedup.sort_unstable();
        contributing_parties_dedup.dedup();
        assert_eq!(
            contributing_parties.len(),
            contributing_parties_dedup.len(),
            "Party IDs must be unique"
        );
        assert_eq!(
            contributing_parties.len(),
            commitments.len(),
            "Number of commitments must match number of contributing parties"
        );

        let mut d = Projective::zero();
        let mut e = Projective::zero();

        for PartialEdDSACommitmentsShamir(comm) in commitments {
            d += comm.d;
            e += comm.e;
        }

        let d = d.into_affine();
        let e = e.into_affine();

        let commitments = EdDSACommitments {
            d,
            e,
            contributing_parties,
        };

        EdDSACommitmentsShamir(commitments)
    }
}
