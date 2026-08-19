//! Shamir shares of the `EdDSA` signing key.
//!
//! This module defines the `DLogShareShamir` struct, one party's Shamir share of the discrete
//! logarithm of the public key, i.e., the evaluation of the sharing polynomial at the party's
//! index.

use crate::ScalarField;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Shamir Secret-share of an `EdDSA` signing secret.
///
/// Serializable so it can be persisted via a secret manager.
/// Not `Debug`/`Display` to avoid accidental leaks.
///
#[derive(Serialize, Deserialize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize)]
#[serde(transparent)]
pub struct DLogShareShamir(#[serde(with = "ark_serde_compat::field")] pub(crate) ScalarField);

impl From<ark_babyjubjub::Fr> for DLogShareShamir {
    fn from(value: ark_babyjubjub::Fr) -> Self {
        Self(value)
    }
}

impl From<DLogShareShamir> for ark_babyjubjub::Fr {
    fn from(value: DLogShareShamir) -> Self {
        value.0
    }
}
