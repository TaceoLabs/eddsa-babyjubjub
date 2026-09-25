//! Aggregated Commitments for Threshold `EdDSA`
//!
//! This module defines the `EdDSACommitments` struct, which sums the per-party commitment shares
//! of the `d + 1` contributing parties and is used both as the challenge hash input and to combine
//! the received signature shares into the final `EdDSA` signature. It also offers an aggregation
//! with identifiable abort, which pinpoints the parties that contributed a malformed share.

use crate::{
    Affine, BaseField, IdentifiableAbortError, MaliciousPartiesError, Projective, ScalarField,
    nonce::CombineTwoNonceRandomnessArgs, partial_commit::PartialEdDSACommitments,
    signature::EdDSASigShare,
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{AdditiveGroup, PrimeField, Zero};
use ark_serde_compat::babyjubjub;
use ark_serialize::Valid;
use eddsa_babyjubjub::{EdDSAPublicKey, EdDSASignature};
use itertools::izip;
use num_bigint::BigUint;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use std::{collections::BTreeMap, num::NonZeroU16};
use uuid::Uuid;

/// Aggregated commitments for the distributed `EdDSA` protocol.
///
/// This struct groups the aggregate commitments, to be used as the challenge hash input, together
/// with the participating party identifiers whose shares are recombined via Shamir Lagrange
/// interpolation.
#[derive(Debug, Clone, Serialize)]
pub struct EdDSACommitments {
    #[serde(with = "babyjubjub::affine")]
    /// The aggregated G*d.
    pub(crate) d: Affine,
    #[serde(with = "babyjubjub::affine")]
    /// The aggregated G*e.
    pub(crate) e: Affine,
    /// The parties that contributed to this commitment.
    pub(crate) contributing_parties: Vec<NonZeroU16>,
}

impl EdDSACommitments {
    /// Create an aggregated commitment object from component affine points and party IDs.
    ///
    /// # Errors
    /// Returns an error if a commitment is invalid, or if party IDs are empty, duplicated, or not
    /// canonically ordered.
    pub fn new(d: Affine, e: Affine, parties: Vec<NonZeroU16>) -> eyre::Result<Self> {
        if d.check().is_err() || e.check().is_err() {
            eyre::bail!("commitments must be valid subgroup points");
        }
        Self::validate_party_ids(&parties)?;
        Ok(Self {
            d,
            e,
            contributing_parties: parties,
        })
    }

    /// Returns the parties that contributed to this commitment.
    #[must_use]
    pub fn get_contributing_parties(&self) -> &[NonZeroU16] {
        &self.contributing_parties
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
        shares: &[EdDSASigShare],
        message: BaseField,
        public_key: EdDSAPublicKey,
    ) -> eyre::Result<EdDSASignature> {
        let shares = self.ordered_shares(shares)?;
        let mut s = ScalarField::zero();
        for share in shares {
            s += share.1;
        }
        let (r, _) = crate::nonce::combine_two_nonce_randomness(CombineTwoNonceRandomnessArgs {
            session_id,
            message,
            public_key,
            d: self.d,
            e: self.e,
            parties: &self.contributing_parties,
        });

        Ok(EdDSASignature { r, s })
    }

    /// Combine all parties' signature shares into a single `EdDSA` signature object, verifying
    /// each party's contribution individually so that malformed shares can be attributed.
    ///
    /// Signature shares and nonce commitments carry party IDs. Public-key shares are keyed by ID.
    /// Lagrange coefficients are derived internally.
    ///
    /// # Errors
    /// Returns [`IdentifiableAbortError::MaliciousParties`] with the IDs of all parties whose
    /// signature share does not verify against their commitment and their Lagrange-weighted share of
    /// the public key. Returns [`IdentifiableAbortError::InvalidInput`] when the supplied shares,
    /// commitments, or public-key shares do not match the contributing party set, do not sum to the
    /// stored aggregate, or do not reconstruct the public key — in that case no share was validated
    /// and no participant may be accused.
    pub fn sign_agg_with_identifiable_abort(
        self,
        session_id: Uuid,
        shares: &[EdDSASigShare],
        message: BaseField,
        public_key: &EdDSAPublicKey,
        x_share_commitments: &BTreeMap<NonZeroU16, Affine>,
        commitments: &[PartialEdDSACommitments],
    ) -> Result<EdDSASignature, IdentifiableAbortError> {
        Self::validate_party_ids(&self.contributing_parties)?;
        let shares = self.ordered_shares(shares)?;
        let commitment_by_party = commitments
            .iter()
            .map(|commitment| (commitment.party_id(), commitment))
            .collect::<BTreeMap<_, _>>();
        if commitment_by_party.len() != commitments.len()
            || commitment_by_party.keys().copied().collect::<Vec<_>>() != self.contributing_parties
        {
            return Err(
                eyre::eyre!("nonce commitments do not match the contributing party set").into(),
            );
        }
        if x_share_commitments.keys().copied().collect::<Vec<_>>() != self.contributing_parties {
            return Err(
                eyre::eyre!("public-key shares do not match the contributing party set").into(),
            );
        }
        let lagrange_coefficients = self
            .contributing_parties
            .iter()
            .map(|party| {
                crate::utils::single_lagrange_from_coeff::<ScalarField, _>(
                    party.get(),
                    self.contributing_parties.iter().map(|party| party.get()),
                )
            })
            .collect::<Vec<_>>();
        let (individual_d, individual_e) = commitment_by_party.values().fold(
            (Projective::zero(), Projective::zero()),
            |(d, e), commitment| (d + commitment.d, e + commitment.e),
        );
        if individual_d.into_affine() != self.d || individual_e.into_affine() != self.e {
            return Err(eyre::eyre!("individual and aggregate nonce commitments differ").into());
        }
        let reconstructed_pk = x_share_commitments
            .values()
            .zip(&lagrange_coefficients)
            .fold(Projective::zero(), |acc, (point, lambda)| {
                acc + *point * lambda
            });
        if reconstructed_pk.into_affine() != public_key.pk {
            return Err(eyre::eyre!("public-key shares do not reconstruct the public key").into());
        }

        let (r, b) = crate::nonce::combine_two_nonce_randomness(CombineTwoNonceRandomnessArgs {
            session_id,
            message,
            public_key: public_key.to_owned(),
            d: self.d,
            e: self.e,
            parties: &self.contributing_parties,
        });

        // Recompute the challenge hash to ensure the challenge is well-formed.
        let c = eddsa_babyjubjub::challenge_hash(message, r, public_key.pk);

        // The following modular reduction in convert_base_to_scalar is required in rust to perform the scalar multiplications. Using all 254 bits of the base field in a double/add ladder would apply this reduction implicitly. We show in the docs of convert_base_to_scalar why this does not introduce a bias when applied to a uniform element of the base field.
        let c_ = eddsa_babyjubjub::convert_base_to_scalar(c);

        // For identifiable abort, we check the contribution of all parties
        let mut cheating_parties = Vec::new();
        for (id, (share, x_share_commitment, commitment, lagrange)) in izip!(
            &shares,
            x_share_commitments.values(),
            commitment_by_party.values(),
            &lagrange_coefficients
        )
        .enumerate()
        {
            let s = share.1;
            let r = commitment.d + commitment.e * b;
            if !verify_for_identifiable_abort(x_share_commitment, r.into_affine(), s, c_ * lagrange)
            {
                cheating_parties.push(usize::from(self.contributing_parties[id].get()));
            }
        }

        if !cheating_parties.is_empty() {
            return Err(MaliciousPartiesError(cheating_parties).into());
        }

        // Finally assemble the signature
        let mut s = ScalarField::zero();
        for share in shares {
            s += share.1;
        }

        let sig = EdDSASignature { r, s };
        Ok(sig)
    }

    /// The accumulating party combines a threshold-sized set of identity-bound commitments.
    ///
    /// Duplicate party IDs are rejected, but two distinct IDs presenting the same `(d, e)` pair are
    /// not. This follows Frost3, which drops the duplicate-presignature abort of Frost2-CKM on the
    /// grounds that authenticated, confidential signer-to-aggregator channels rule out copying.
    /// Unforgeability is unaffected — a copied commitment cannot yield a share that passes
    /// `sign_agg_with_identifiable_abort` — but a copy shows up as a failed share rather than as a
    /// duplicate.
    ///
    /// # Errors
    /// Returns an error for an empty set or duplicate/invalid party IDs.
    pub fn pre_agg(commitments: &[PartialEdDSACommitments]) -> eyre::Result<Self> {
        let input_len = commitments.len();
        let commitments = commitments
            .iter()
            .map(|commitment| (commitment.party_id(), commitment))
            .collect::<BTreeMap<_, _>>();
        let contributing_parties = commitments.keys().copied().collect::<Vec<_>>();
        if commitments.len() != input_len {
            eyre::bail!("duplicate nonce commitment party ID");
        }
        Self::validate_party_ids(&contributing_parties)?;

        let mut d = Projective::zero();
        let mut e = Projective::zero();

        for comm in commitments.values() {
            d += comm.d;
            e += comm.e;
        }

        let d = d.into_affine();
        let e = e.into_affine();

        Ok(EdDSACommitments {
            d,
            e,
            contributing_parties,
        })
    }

    fn ordered_shares<'a>(
        &self,
        shares: &'a [EdDSASigShare],
    ) -> eyre::Result<Vec<&'a EdDSASigShare>> {
        let shares = shares
            .iter()
            .map(|share| (share.party_id(), share))
            .collect::<BTreeMap<_, _>>();
        if shares.len() != self.contributing_parties.len()
            || shares.keys().copied().collect::<Vec<_>>() != self.contributing_parties
        {
            eyre::bail!("signature shares do not match the contributing party set");
        }
        Ok(shares.into_values().collect())
    }

    pub(crate) fn validate_party_ids(parties: &[NonZeroU16]) -> eyre::Result<()> {
        if parties.is_empty() {
            eyre::bail!("at least one contributing party is required");
        }
        if parties.windows(2).any(|ids| ids[0] >= ids[1]) {
            eyre::bail!("party IDs must be unique and canonically ordered");
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for EdDSACommitments {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Repr {
            #[serde(with = "babyjubjub::affine")]
            d: Affine,
            #[serde(with = "babyjubjub::affine")]
            e: Affine,
            #[serde(deserialize_with = "crate::serde_utils::deserialize_protocol_vec")]
            contributing_parties: Vec<NonZeroU16>,
        }

        let repr = Repr::deserialize(deserializer)?;
        Self::validate_party_ids(&repr.contributing_parties).map_err(D::Error::custom)?;
        Ok(Self {
            d: repr.d,
            e: repr.e,
            contributing_parties: repr.contributing_parties,
        })
    }
}

// This is modelled after the `verify` function in `eddsa-babyjubjub/src/lib.rs`, but it takes the challenge as input
pub(crate) fn verify_for_identifiable_abort(
    pk: &Affine,
    r: Affine,
    s: ScalarField,
    c: ScalarField,
) -> bool {
    let s_biguint: BigUint = s.into();
    if s_biguint >= ScalarField::MODULUS.into() {
        return false;
    }

    if pk.is_zero()
        || !pk.is_on_curve()
        || !pk.is_in_correct_subgroup_assuming_on_curve()
        || !r.is_on_curve()
    {
        return false;
    }

    let mut v = (Affine::generator() * s) - r - (*pk * c); // multiply by the cofactor 8
    v.double_in_place();
    v.double_in_place();
    v.double_in_place();
    v.is_zero()
}
