//! The final state of the DKG protocol.
//!
//! This module defines the `Finished` struct, which holds one party's share of the jointly
//! generated signing key together with the public information about all parties.

use ark_ec::CurveGroup;
use ark_serialize::CanonicalSerialize;
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::Zeroize;

const AGREEMENT_DIGEST_LABEL: &[u8] = b"TACEO_THRESHOLD_EDDSA_AGREEMENT_V1";

/// The state of the DKG protocol after it has finished, holding the results of the protocol.
///
/// Every field except [`Finished::my_idx`] and [`Finished::sk_share`] must be identical at every
/// honest participant; [`Finished::agreement_digest`] reduces those to one comparable value.
///
/// There is deliberately no conversion to [`DLogShareShamir`](crate::shamir::secret::DLogShareShamir),
/// because this type does not carry the [`Parameters`](crate::keygen::Parameters) of the run. The
/// caller must pass the party count and threshold itself, and a wrong-but-self-consistent value is
/// accepted silently: `sign_round` derives the Lagrange coefficient from the signer set, so a too
/// small threshold only loosens the minimum-signer-set check and a too large party count only
/// loosens the range check. Neither enables a forgery, but neither is caught either. After a reshare,
/// pass the *new* parameters.
#[expect(
    clippy::exhaustive_structs,
    reason = "Only carries the results of the protocol - not planned to add something"
)]
pub struct Finished<C: CurveGroup> {
    /// The index of this party in the set of parties participating in the protocol.
    pub my_idx: u16,
    /// The session id shared by all parties of this protocol run.
    pub session_id: Uuid,
    /// This party's Shamir share of the jointly generated signing key.
    pub sk_share: C::ScalarField,
    /// The public counterparts of the secret key shares of all parties, indexed by party index.
    pub pk_shares: HashMap<u16, C::Affine>,
    /// The public key belonging to the jointly generated signing key.
    pub pk: C::Affine,
    /// The parties whose polynomial contributions make up this output, ascending.
    ///
    /// For a DKG these are the qualified dealers, in the same index namespace as
    /// [`Finished::pk_shares`]. For a reshare these are the surviving *old* senders, so they are
    /// **old**-committee indices while `pk_shares` is keyed by new-party index.
    pub contributing_parties: Vec<u16>,
}

impl<C: CurveGroup> Finished<C> {
    /// A digest over everything in this output that all participants must agree on: the session id,
    /// [`Finished::contributing_parties`], [`Finished::pk`], and [`Finished::pk_shares`]. The
    /// per-party `my_idx` and `sk_share` are excluded, so an honest run yields the same digest
    /// everywhere.
    ///
    /// Comparing this is mandatory after a reshare. Resharing combines the surviving senders as
    /// `P_S(Z) = Σ_{i∈S} λ_i^S · f_i(Z)`, and every coefficient depends on `S` — but `P_S(0) = sk`
    /// for *every* valid `S`. Receivers that disagreed on `S` hold points on unrelated polynomials
    /// while both reconstruct the correct public key, so the public-key check in `finalize` reports
    /// nothing and the shares silently fail to interpolate. The DKG has no such blind spot: there a
    /// divergent dealer set changes `pk` itself. Compare digests before erasing the old shares.
    #[must_use]
    pub fn agreement_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(AGREEMENT_DIGEST_LABEL);
        hasher.update(self.session_id.as_bytes());

        // Both collections are variable-length, so length-prefix them to keep the preimage injective.
        hasher.update(&length_prefix(self.contributing_parties.len()));
        for party in &self.contributing_parties {
            hasher.update(&party.to_be_bytes());
        }

        let mut buf = Vec::new();
        absorb_point::<C>(&mut hasher, &mut buf, &self.pk);

        // `pk_shares` is a `HashMap`, so absorb a sorted index list: the digest must not depend on
        // hash order.
        let mut indices = self.pk_shares.keys().copied().collect::<Vec<_>>();
        indices.sort_unstable();
        hasher.update(&length_prefix(indices.len()));
        for index in indices {
            hasher.update(&index.to_be_bytes());
            absorb_point::<C>(&mut hasher, &mut buf, &self.pk_shares[&index]);
        }

        *hasher.finalize().as_bytes()
    }
}

fn absorb_point<C: CurveGroup>(hasher: &mut blake3::Hasher, buf: &mut Vec<u8>, point: &C::Affine) {
    point
        .serialize_compressed(&mut *buf)
        .expect("can serialize a curve point into a vec");
    hasher.update(buf);
    buf.clear();
}

fn length_prefix(length: usize) -> [u8; 8] {
    u64::try_from(length)
        .expect("participant-sized length fits into u64")
        .to_be_bytes()
}

impl<C: CurveGroup> Drop for Finished<C> {
    fn drop(&mut self) {
        self.sk_share.zeroize();
    }
}
