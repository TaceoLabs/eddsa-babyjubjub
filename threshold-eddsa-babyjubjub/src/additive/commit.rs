//! Aggregated commitments for the additive threshold `EdDSA` protocol.
//!
//! This module defines the `EdDSACommitmentsAdditive` struct, which sums the per-party commitment
//! shares of all `n` parties and combines the received signature shares into the final `EdDSA`
//! signature. It also offers an aggregation with identifiable abort, which pinpoints the parties
//! that contributed a malformed share.

use crate::{
    Affine, BaseField, IdentifiableAbortError, MaliciousPartiesError, Projective, ScalarField,
    additive::{partial_commit::PartialEdDSACommitmentsAdditive, signature::EdDSASigShareAdditive},
    commit::EdDSACommitments,
    nonce::CombineTwoNonceRandomnessArgs,
};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use ark_serialize::Valid;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use itertools::izip;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Commitment aggregation object for the additive `EdDSA` protocol.
///
/// Transparent wrapper for individual commitment shares produced by each participant in the additive
/// secret sharing case, ready for simple sum aggregation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EdDSACommitmentsAdditive(pub(crate) EdDSACommitments);

impl EdDSACommitmentsAdditive {
    /// Create an aggregated commitment object from component affine points and party IDs.
    ///
    /// # Errors
    /// Returns an error if a commitment is invalid, or if party IDs are empty, zero, duplicated,
    /// or not canonically ordered.
    pub fn new(d: Affine, e: Affine, parties: Vec<u16>) -> eyre::Result<Self> {
        if d.check().is_err() || e.check().is_err() {
            eyre::bail!("commitments must be valid subgroup points");
        }
        EdDSACommitments::validate_party_ids(&parties)?;
        let commitments = EdDSACommitments {
            d,
            e,
            contributing_parties: parties,
        };
        Ok(Self(commitments))
    }

    /// Returns the parties that contributed to this commitment.
    #[must_use]
    pub fn get_contributing_parties(&self) -> &[u16] {
        &self.0.contributing_parties
    }

    /// Combine all parties' signature shares into a single `EdDSA` signature object.
    ///
    /// Signature shares are matched to the contributing set by their embedded party IDs.
    ///
    /// # Errors
    /// Returns an error unless exactly one signature share is supplied for each contributing
    /// party.
    pub fn sign_agg(
        self,
        session_id: Uuid,
        shares: &[EdDSASigShareAdditive],
        message: BaseField,
        public_key: EdDSAPublicKey,
    ) -> eyre::Result<EdDSASignature> {
        let shares = self.ordered_shares(shares)?;
        Ok(self.0.sign_agg(
            session_id,
            shares.into_iter().map(|share| &share.0),
            message,
            public_key,
        ))
    }

    /// Combine all parties' signature shares into a single `EdDSA` signature object, verifying
    /// each party's contribution individually so that malformed shares can be attributed.
    ///
    /// Signature shares and nonce commitments carry party IDs. Public-key shares are keyed by ID.
    ///
    /// # Errors
    /// Returns [`IdentifiableAbortError::MaliciousParties`] with the IDs of all parties whose
    /// signature share does not verify against their commitment and their share of the public key.
    /// Returns [`IdentifiableAbortError::InvalidInput`] when the supplied shares, commitments, or
    /// public-key shares do not match the contributing party set, do not sum to the stored
    /// aggregate, or do not reconstruct the public key — in that case no share was validated and no
    /// participant may be accused.
    pub fn sign_agg_with_identifiable_abort(
        self,
        session_id: Uuid,
        shares: &[EdDSASigShareAdditive],
        message: BaseField,
        public_key: &EdDSAPublicKey,
        x_share_commitments: &BTreeMap<u16, Affine>,
        commitments: &[PartialEdDSACommitmentsAdditive],
    ) -> Result<EdDSASignature, IdentifiableAbortError> {
        EdDSACommitments::validate_party_ids(&self.0.contributing_parties)?;
        let shares = self.ordered_shares(shares)?;
        let commitment_by_party = commitments
            .iter()
            .map(|commitment| (commitment.party_id(), commitment))
            .collect::<BTreeMap<_, _>>();
        if commitment_by_party.len() != commitments.len()
            || commitment_by_party.keys().copied().collect::<Vec<_>>()
                != self.0.contributing_parties
        {
            return Err(eyre::eyre!("nonce commitments do not match the contributing party set").into());
        }
        if x_share_commitments.keys().copied().collect::<Vec<_>>() != self.0.contributing_parties {
            return Err(eyre::eyre!("public-key shares do not match the contributing party set").into());
        }
        let (individual_d, individual_e) = commitment_by_party.values().fold(
            (Projective::zero(), Projective::zero()),
            |(d, e), commitment| (d + commitment.0.d, e + commitment.0.e),
        );
        if individual_d.into_affine() != self.0.d || individual_e.into_affine() != self.0.e {
            return Err(eyre::eyre!("individual and aggregate nonce commitments differ").into());
        }
        let reconstructed_pk = x_share_commitments
            .values()
            .fold(Projective::zero(), |acc, point| acc + point);
        if reconstructed_pk.into_affine() != public_key.pk {
            return Err(eyre::eyre!("public-key shares do not reconstruct the public key").into());
        }

        let (r, b) = crate::nonce::combine_two_nonce_randomness(CombineTwoNonceRandomnessArgs {
            session_id,
            message,
            public_key: public_key.clone(),
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
        for (id, (share, x_share_commitment, commitment)) in izip!(
            &shares,
            x_share_commitments.values(),
            commitment_by_party.values()
        )
        .enumerate()
        {
            let s = share.0.1;
            let r = commitment.0.d + commitment.0.e * b;
            if !crate::commit::verify_for_identifiable_abort(
                x_share_commitment,
                r.into_affine(),
                s,
                c_,
            ) {
                cheating_parties.push(usize::from(self.0.contributing_parties[id]));
            }
        }

        if !cheating_parties.is_empty() {
            return Err(MaliciousPartiesError(cheating_parties).into());
        }

        // Finally assemble the signature
        let mut s = ScalarField::zero();
        for share in shares {
            s += share.0.1;
        }

        let sig = EdDSASignature { r, s };
        Ok(sig)
    }

    /// The accumulating party (i.e., the aggregatir) combines the shares of `n` parties.
    /// The returned points are the combined commitments C, R.
    ///
    /// # Errors
    /// Returns an error for an empty set or duplicate/invalid party IDs.
    pub fn pre_agg(commitments: &[PartialEdDSACommitmentsAdditive]) -> eyre::Result<Self> {
        let input_len = commitments.len();
        let commitments = commitments
            .iter()
            .map(|commitment| (commitment.party_id(), commitment))
            .collect::<BTreeMap<_, _>>();
        if commitments.len() != input_len {
            eyre::bail!("duplicate nonce commitment party ID");
        }
        let party_ids = commitments.keys().copied().collect::<Vec<_>>();
        EdDSACommitments::validate_party_ids(&party_ids)?;
        let mut d = Projective::zero();
        let mut e = Projective::zero();
        let mut contributing_parties = Vec::with_capacity(commitments.len());

        for (party_id, PartialEdDSACommitmentsAdditive(comm)) in commitments {
            d += comm.d;
            e += comm.e;
            contributing_parties.push(party_id);
        }

        let d = d.into_affine();
        let e = e.into_affine();

        let commitments = EdDSACommitments {
            d,
            e,
            contributing_parties,
        };
        Ok(EdDSACommitmentsAdditive(commitments))
    }

    fn ordered_shares<'a>(
        &self,
        shares: &'a [EdDSASigShareAdditive],
    ) -> eyre::Result<Vec<&'a EdDSASigShareAdditive>> {
        let shares = shares
            .iter()
            .map(|share| (share.party_id(), share))
            .collect::<BTreeMap<_, _>>();
        if shares.len() != self.0.contributing_parties.len()
            || shares.keys().copied().collect::<Vec<_>>() != self.0.contributing_parties
        {
            eyre::bail!("signature shares do not match the contributing party set");
        }
        Ok(shares.into_values().collect())
    }
}
