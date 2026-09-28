//! Two-Nonce Combination for Threshold `EdDSA`
//!
//! This module derives the full signing randomness `r = d + e*b` from the aggregated two-nonce
//! commitments, where the binding factor `b` is a hash over the caller-supplied context, the
//! contributing parties, the public key, both nonce commitments, and the message.
//!
//! Binding the randomness to all of these inputs is what makes concurrent signing sessions safe,
//! as required by Frost3. Frost3's security does not rely on the context: the fresh nonce
//! commitments already make the preimage unique per session. The context is an agreement check —
//! participants that disagree on it derive different binding factors, so the session aborts
//! instead of producing a signature.

use crate::{Affine, BaseField, ScalarField};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use eddsa_babyjubjub::EdDSAPublicKey;
use std::num::NonZeroU16;

pub(crate) const FROST_3_NONCE_COMBINER_LABEL: &[u8] = b"FROST_3_NONCE_COMBINER";

pub(crate) struct CombineTwoNonceRandomnessArgs<'a> {
    pub(crate) context: &'a [u8],
    pub(crate) message: BaseField,
    pub(crate) public_key: EdDSAPublicKey,
    pub(crate) d: Affine,
    pub(crate) e: Affine,
    pub(crate) parties: &'a [NonZeroU16],
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
        context,
        message,
        public_key,
        d,
        e,
        parties,
    } = args;
    let mut hasher = blake3::Hasher::new();
    hasher.update(FROST_3_NONCE_COMBINER_LABEL);
    // The context and the signer set are the variable-length fields in the preimage, so each is
    // length-prefixed: without the prefixes, injectivity would rely on every following field
    // staying fixed-width.
    hasher.update(
        &u64::try_from(context.len())
            .expect("context length fits into u64")
            .to_be_bytes(),
    );
    hasher.update(context);
    hasher.update(
        &u64::try_from(parties.len())
            .expect("signer set length fits into u64")
            .to_be_bytes(),
    );
    for party in parties {
        hasher.update(&party.get().to_be_bytes());
    }
    // serialize the Affine points and the message in canonical compressed form, writing
    // directly into the hasher
    public_key
        .pk
        .serialize_compressed(&mut hasher)
        .expect("can serialize point into the hasher");
    d.serialize_compressed(&mut hasher)
        .expect("can serialize point into the hasher");
    e.serialize_compressed(&mut hasher)
        .expect("can serialize point into the hasher");
    message
        .serialize_compressed(&mut hasher)
        .expect("can serialize field into the hasher");

    let mut hash_output = hasher.finalize_xof();

    // We use 64 bytes to have enough statistical security against modulo bias
    let mut unreduced_b = [0u8; 64];
    hash_output.fill(&mut unreduced_b);

    let b = ScalarField::from_le_bytes_mod_order(&unreduced_b);
    let r = d + e * b;
    (r.into_affine(), b)
}
