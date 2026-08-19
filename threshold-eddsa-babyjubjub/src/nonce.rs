//! Two-Nonce Combination for Threshold `EdDSA`
//!
//! This module derives the full signing randomness `r = d + e*b` from the aggregated two-nonce
//! commitments, where the binding factor `b` is a hash over the session ID, the contributing
//! parties, the public key, both nonce commitments, and the message.
//!
//! The primitives defined here are agnostic to the underlying threshold sharing scheme and are used by both
//! additive and Shamir variants, which are implemented in their respective submodules `additive` and `shamir`.
//!
//! Binding the randomness to all of these inputs is what makes concurrent signing sessions safe,
//! as required by Frost3.

use crate::{Affine, BaseField, ScalarField};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use eddsa_babyjubjub::EdDSAPublicKey;
use uuid::Uuid;

pub(crate) struct CombineTwoNonceRandomnessArgs<'a> {
    pub(crate) session_id: Uuid,
    pub(crate) message: BaseField,
    pub(crate) public_key: EdDSAPublicKey,
    pub(crate) d: Affine,
    pub(crate) e: Affine,
    pub(crate) parties: &'a [u16],
}

/// Combines the two-nonce randomness shares into the full randomness used in the challenge.
/// Returns (r, b) where r = d + e*b
#[allow(
    clippy::needless_pass_by_value,
    reason = "This method should consume the args"
)]
pub(crate) fn combine_two_nonce_randomness(
    args: CombineTwoNonceRandomnessArgs<'_>,
) -> (Affine, ScalarField) {
    let CombineTwoNonceRandomnessArgs {
        session_id,
        message,
        public_key,
        d,
        e,
        parties,
    } = args;
    let mut hasher = blake3::Hasher::new();
    hasher.update(crate::FROST_3_NONCE_COMBINER_LABEL);
    hasher.update(session_id.as_bytes());
    // The signer set is the only variable-length field in the preimage, so it is length-prefixed:
    // without the prefix, injectivity would rely on every following field staying fixed-width.
    hasher.update(
        &u64::try_from(parties.len())
            .expect("signer set length fits into u64")
            .to_be_bytes(),
    );
    for party in parties {
        hasher.update(&party.to_be_bytes());
    }
    let mut buf = Vec::with_capacity(d.compressed_size());

    // serialize an Affine point in canonical compressed form
    let mut serialize_point = |point: &Affine| {
        point
            .serialize_compressed(&mut buf)
            .expect("can serialize point into a vec");
        hasher.update(&buf);
        buf.clear();
    };
    serialize_point(&public_key.pk);
    serialize_point(&d);
    serialize_point(&e);

    let mut buf = Vec::with_capacity(message.compressed_size());
    message
        .serialize_compressed(&mut buf)
        .expect("can serialize field into a vec");
    hasher.update(&buf);

    let mut hash_output = hasher.finalize_xof();

    // We use 64 bytes to have enough statistical security against modulo bias
    let mut unreduced_b = [0u8; 64];
    hash_output.fill(&mut unreduced_b);

    let b = ScalarField::from_le_bytes_mod_order(&unreduced_b);
    let r = d + e * b;
    (r.into_affine(), b)
}
