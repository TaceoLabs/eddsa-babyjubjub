//! Non-interactive proof of knowledge of a discrete logarithm.
//!
//! The parties use this Schnorr proof in the first round of the DKG protocol to show that they know
//! the constant term of their polynomial. This prevents a party from choosing its contribution to
//! the public key depending on the contributions of the other parties.

use crate::keygen::Parameters;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalSerialize, CompressedChecked, Valid};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
/// A non-interactive Schnorr proof of knowledge of the discrete logarithm of a curve point.
pub struct SchnorrZkProof<C: CurveGroup> {
    big_r: CompressedChecked<C::Affine>,
    #[serde(with = "ark_serde_compat::field")]
    z: C::ScalarField,
}

impl<C: CurveGroup> SchnorrZkProof<C> {
    const CONTEXT_DOMAIN: &'static [u8] = b"PEDPOP_SCHNORR_POP_V1";

    fn challenge_hash(
        context: &[u8],
        party_idx: u16,
        public: &C::Affine,
        big_r: &C::Affine,
        transcript_commitments: &[C::Affine],
    ) -> C::ScalarField {
        let mut random_oracle = blake3::Hasher::new();
        random_oracle.update(Self::CONTEXT_DOMAIN);
        random_oracle.update(
            &u64::try_from(context.len())
                .expect("context length fits into u64")
                .to_be_bytes(),
        );
        random_oracle.update(context);
        random_oracle.update(&party_idx.to_be_bytes());

        let mut buf = Vec::with_capacity(public.compressed_size());
        // serialize an Affine point in canonical compressed form
        let mut serialize_point = |point: &C::Affine| {
            point
                .serialize_compressed(&mut buf)
                .expect("can serialize point into a vec");
            random_oracle.update(&buf);
            buf.clear();
        };

        // first one is the message, second one the public key, to keep compatibility with standard Schnorr signatures according to CKM21 (https://eprint.iacr.org/2021/1375)
        serialize_point(public);
        serialize_point(big_r);
        for comm in transcript_commitments {
            serialize_point(comm);
        }

        let mut hash_output = random_oracle.finalize_xof();

        // We use 64 bytes to have enough statistical security against modulo bias
        let mut unreduced_b = [0u8; 64];
        hash_output.fill(&mut unreduced_b);

        C::ScalarField::from_le_bytes_mod_order(&unreduced_b)
    }

    /// Create a proof of knowledge of `secret`, the discrete logarithm of `public`.
    ///
    /// The index of the proving party is bound into the challenge hash, so that a proof cannot be
    /// replayed by another party.
    pub fn new<R: Rng + CryptoRng>(
        context: &[u8],
        party_idx: u16,
        secret: &C::ScalarField,
        public: &C::Affine,
        transcript_commitments: &[C::Affine],
        rng: &mut R,
    ) -> SchnorrZkProof<C> {
        let r = C::ScalarField::rand(rng);
        let big_r = C::generator() * r;
        let big_r = big_r.into_affine();

        let c = Self::challenge_hash(context, party_idx, public, &big_r, transcript_commitments);

        let z = r + c * secret;

        SchnorrZkProof {
            big_r: CompressedChecked(big_r),
            z,
        }
    }

    /// Verify the proof against the `public` point claimed by the party with index `party_idx`.
    pub fn verify(
        &self,
        context: &[u8],
        party_idx: u16,
        public: &C::Affine,
        transcript_commitments: &[C::Affine],
    ) -> bool {
        if public.is_zero() || public.check().is_err() || self.big_r.check().is_err() {
            return false;
        }

        let c = Self::challenge_hash(
            context,
            party_idx,
            public,
            &self.big_r,
            transcript_commitments,
        );

        let v = (C::generator() * self.z) - self.big_r.0 - (*public * c);
        let v = v.into_affine().clear_cofactor();
        v.is_zero()
    }
}

pub(crate) fn proof_context(domain: &[u8], session_id: Uuid, parameters: &[Parameters]) -> Vec<u8> {
    let session_id_bytes = session_id.as_bytes();
    let len = domain.len() + session_id_bytes.len() + parameters.len() * 4;
    let mut context = Vec::with_capacity(len);
    context.extend_from_slice(domain);
    context.extend_from_slice(session_id.as_bytes());
    for parameters in parameters {
        context.extend_from_slice(&parameters.number_of_parties.to_be_bytes());
        context.extend_from_slice(&parameters.threshold.to_be_bytes());
    }
    assert_eq!(context.len(), len, "context length matches expected length");
    context
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Affine, Curve, ScalarField};
    use ark_ec::PrimeGroup;
    use rand::thread_rng;

    #[test]
    fn basic_schnorr_nizk() {
        let mut rng = thread_rng();
        let idx = 1;
        let secret = ScalarField::rand(&mut rng);
        let public = (Affine::generator() * secret).into_affine();
        let nizk = SchnorrZkProof::<Curve>::new(b"test", idx, &secret, &public, &[], &mut rng);
        assert!(nizk.verify(b"test", idx, &public, &[]));
        assert!(!nizk.verify(b"other session", idx, &public, &[]));
    }

    #[test]
    fn basic_schnorr_nizk_invalid() {
        let mut rng = thread_rng();
        let idx = 1;
        let secret = ScalarField::rand(&mut rng);
        let public = (Affine::generator() * secret + Curve::generator()).into_affine();
        let nizk = SchnorrZkProof::<Curve>::new(b"test", idx, &secret, &public, &[], &mut rng);
        assert!(!nizk.verify(b"test", idx, &public, &[]));
    }
}
