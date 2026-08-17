//! Additive shares of the `EdDSA` signing key.
//!
//! This module defines the `DLogShareAdditive` struct, one party's additive share of the discrete
//! logarithm of the public key. All `n` shares sum to the signing key.

use crate::ScalarField;
use ark_serialize::CanonicalDeserialize;
use ark_serialize::CanonicalSerialize;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

/// Additive Secret-share of an `EdDSA` signing secret.
///
/// Serializable so it can be persisted via a secret manager.
/// Not `Debug`/`Display` to avoid accidental leaks.
///
#[derive(
    Clone, Serialize, Deserialize, ZeroizeOnDrop, CanonicalSerialize, CanonicalDeserialize,
)]
#[serde(transparent)]
pub struct DLogShareAdditive(#[serde(with = "ark_serde_compat::field")] pub(crate) ScalarField);

impl From<ark_babyjubjub::Fr> for DLogShareAdditive {
    fn from(value: ark_babyjubjub::Fr) -> Self {
        Self(value)
    }
}

impl From<DLogShareAdditive> for ark_babyjubjub::Fr {
    fn from(value: DLogShareAdditive) -> Self {
        value.0
    }
}
