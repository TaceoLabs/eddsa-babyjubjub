//! Aggregated Commitments for Threshold `EdDSA`
//!
//! This module defines the `EdDSACommitments` struct, which holds the sum of the per-party
//! commitment shares and is used both as the challenge hash input and to combine the received
//! signature shares into the final `EdDSA` signature.
//!
//! The primitives defined here are agnostic to the underlying threshold sharing scheme and are used by
//! the Shamir variant, which is implemented in the submodule `shamir`.
//!
//! This module provides:
//! - The aggregated two-nonce commitment (`d`, `e`) together with the set of contributing parties.
//! - Combination of the signature shares, and the challenge-based verification used for identifiable abort.

use crate::Affine;
use ark_serde_compat::babyjubjub;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

/// Aggregated commitments for the distributed `EdDSA` protocol.
///
/// This struct aggregates the per-party commitment shares, to be used as the challenge hash input, and to verify against the full proof after all shares are combined.
#[derive(Debug, Clone, Serialize)]
pub struct EdDSACommitments {
    #[serde(with = "babyjubjub::affine")]
    /// The aggregated G*d.
    pub(crate) d: Affine,
    #[serde(with = "babyjubjub::affine")]
    /// The aggregated G*e.
    pub(crate) e: Affine,
    /// The parties that contributed to this commitment.
    pub(crate) contributing_parties: Vec<u16>,
}

impl EdDSACommitments {
    pub(crate) fn validate_party_ids(parties: &[u16]) -> eyre::Result<()> {
        if parties.is_empty() {
            eyre::bail!("at least one contributing party is required");
        }
        if parties[0] == 0 {
            eyre::bail!("party IDs must be non-zero");
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
            contributing_parties: Vec<u16>,
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
