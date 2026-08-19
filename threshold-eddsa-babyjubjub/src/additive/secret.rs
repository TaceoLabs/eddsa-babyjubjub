//! Additive shares of the `EdDSA` signing key.
//!
//! This module defines the `DLogShareAdditive` struct, one party's additive share of the discrete
//! logarithm of the public key. All `n` shares sum to the signing key.

use crate::{Affine, ScalarField};
use ark_ec::AffineRepr;
use ark_serde_compat::babyjubjub;
use ark_serialize::Valid;
use eddsa_babyjubjub::EdDSAPublicKey;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use zeroize::ZeroizeOnDrop;

/// Additive Secret-share of an `EdDSA` signing secret.
///
/// The scalar is bound to the identity, party count, and public key it belongs to, so
/// [`sign_round`](crate::additive::session::EdDSASessionAdditive::sign_round) can check every one of
/// them instead of trusting a caller-supplied argument. Deserialization enforces the same invariants
/// as [`DLogShareAdditive::new`].
///
/// Serializable so it can be persisted via a secret manager.
/// Not `Debug`/`Display` to avoid accidental leaks.
#[derive(Serialize, ZeroizeOnDrop)]
pub struct DLogShareAdditive {
    #[serde(with = "ark_serde_compat::field")]
    pub(crate) value: ScalarField,
    #[serde(with = "babyjubjub::affine")]
    #[zeroize(skip)]
    pub(crate) public_key: Affine,
    pub(crate) party_id: u16,
    pub(crate) number_of_parties: u16,
}

impl DLogShareAdditive {
    /// Bind an additive scalar share to its identity, complete party count, and public key.
    ///
    /// # Errors
    /// Returns an error unless `1 <= party_id <= number_of_parties` and `public_key` is a non-zero
    /// point in the prime-order subgroup.
    pub fn new(
        value: ScalarField,
        public_key: &EdDSAPublicKey,
        party_id: u16,
        number_of_parties: u16,
    ) -> eyre::Result<Self> {
        Self::validate(&public_key.pk, party_id, number_of_parties)?;
        Ok(Self {
            value,
            public_key: public_key.pk,
            party_id,
            number_of_parties,
        })
    }

    fn validate(public_key: &Affine, party_id: u16, number_of_parties: u16) -> eyre::Result<()> {
        if party_id == 0 || number_of_parties == 0 || party_id > number_of_parties {
            eyre::bail!("party ID must lie in the non-empty additive party set");
        }
        if public_key.is_zero() || public_key.check().is_err() {
            eyre::bail!("public key must be a non-zero point in the prime-order subgroup");
        }
        Ok(())
    }

    /// Return the identity bound to this share.
    #[must_use]
    pub fn party_id(&self) -> u16 {
        self.party_id
    }

    /// Return the public key this share belongs to.
    #[must_use]
    pub fn public_key(&self) -> EdDSAPublicKey {
        EdDSAPublicKey {
            pk: self.public_key,
        }
    }
}

impl<'de> Deserialize<'de> for DLogShareAdditive {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Repr {
            #[serde(with = "ark_serde_compat::field")]
            value: ScalarField,
            #[serde(with = "babyjubjub::affine")]
            public_key: Affine,
            party_id: u16,
            number_of_parties: u16,
        }

        // The intermediate representation holds the secret scalar, so clear it rather than leaving a
        // copy in freed memory. Every field is `Copy`, so reading them out below still works.
        impl Drop for Repr {
            fn drop(&mut self) {
                use zeroize::Zeroize as _;
                self.value.zeroize();
            }
        }

        let repr = Repr::deserialize(deserializer)?;
        DLogShareAdditive::validate(&repr.public_key, repr.party_id, repr.number_of_parties)
            .map_err(D::Error::custom)?;
        Ok(Self {
            value: repr.value,
            public_key: repr.public_key,
            party_id: repr.party_id,
            number_of_parties: repr.number_of_parties,
        })
    }
}
