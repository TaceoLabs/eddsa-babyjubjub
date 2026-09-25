//! Shamir shares of the `EdDSA` signing key.
//!
//! This module defines the `DLogShareShamir` struct, one party's Shamir share of the discrete
//! logarithm of the public key, i.e., the evaluation of the sharing polynomial at the party's
//! index.

use crate::{Affine, ScalarField};
use ark_ec::AffineRepr;
use ark_ff::Zero;
use ark_serde_compat::babyjubjub;
use ark_serialize::Valid;
use eddsa_babyjubjub::EdDSAPublicKey;
use serde::{Deserialize, Deserializer, Serialize, de::Error as _};
use std::num::NonZeroU16;
use zeroize::ZeroizeOnDrop;

/// Shamir Secret-share of an `EdDSA` signing secret.
///
/// The scalar is bound to the identity, committee parameters, and public key it belongs to, so
/// [`sign_round`](crate::signer::EdDSASession::sign_round) can check every one of
/// them instead of trusting a caller-supplied argument. Deserialization enforces the same
/// invariants as [`DLogShareShamir::new`].
///
/// Serializable so it can be persisted via a secret manager.
/// The `Debug` implementation redacts the secret share; there is no `Display` to avoid accidental leaks.
#[derive(Serialize, ZeroizeOnDrop)]
pub struct DLogShareShamir {
    #[serde(with = "ark_serde_compat::field")]
    pub(crate) value: ScalarField,
    #[serde(with = "babyjubjub::affine")]
    #[zeroize(skip)]
    pub(crate) public_key: Affine,
    // The committee metadata is public, only `value` is a secret.
    #[zeroize(skip)]
    pub(crate) party_id: NonZeroU16,
    #[zeroize(skip)]
    pub(crate) number_of_parties: NonZeroU16,
    #[zeroize(skip)]
    pub(crate) threshold: NonZeroU16,
}

impl std::fmt::Debug for DLogShareShamir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DLogShareShamir")
            .field("value", &"<redacted>")
            .field("public_key", &self.public_key)
            .field("party_id", &self.party_id)
            .field("number_of_parties", &self.number_of_parties)
            .field("threshold", &self.threshold)
            .finish()
    }
}

impl DLogShareShamir {
    /// Bind a scalar share to its party identity, Shamir committee parameters, and public key.
    ///
    /// # Errors
    /// Returns an error unless `value` is non-zero, the metadata satisfies
    /// `party_id <= number_of_parties` and `2 <= threshold <= number_of_parties`, and `public_key`
    /// is a non-zero point in the prime-order subgroup.
    pub fn new(
        value: ScalarField,
        public_key: &EdDSAPublicKey,
        party_id: NonZeroU16,
        number_of_parties: NonZeroU16,
        threshold: NonZeroU16,
    ) -> eyre::Result<Self> {
        Self::validate(
            &value,
            &public_key.pk,
            party_id,
            number_of_parties,
            threshold,
        )?;
        Ok(Self {
            value,
            public_key: public_key.pk,
            party_id,
            number_of_parties,
            threshold,
        })
    }

    fn validate(
        value: &ScalarField,
        public_key: &Affine,
        party_id: NonZeroU16,
        number_of_parties: NonZeroU16,
        threshold: NonZeroU16,
    ) -> eyre::Result<()> {
        if value.is_zero() {
            eyre::bail!("secret share must be non-zero");
        }
        if party_id > number_of_parties {
            eyre::bail!("party ID must lie in the Shamir party set");
        }
        if threshold.get() < 2 || threshold > number_of_parties {
            eyre::bail!("invalid Shamir threshold");
        }
        if public_key.is_zero() || public_key.check().is_err() {
            eyre::bail!("public key must be a non-zero point in the prime-order subgroup");
        }
        Ok(())
    }

    /// Return the identity bound to this share.
    #[must_use]
    pub fn party_id(&self) -> NonZeroU16 {
        self.party_id
    }

    /// Return the public key this share belongs to.
    #[must_use]
    pub fn public_key(&self) -> EdDSAPublicKey {
        EdDSAPublicKey {
            pk: self.public_key,
        }
    }

    /// Return the threshold of the sharing this share belongs to.
    #[must_use]
    pub fn threshold(&self) -> NonZeroU16 {
        self.threshold
    }
}

impl<'de> Deserialize<'de> for DLogShareShamir {
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
            party_id: NonZeroU16,
            number_of_parties: NonZeroU16,
            threshold: NonZeroU16,
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
        DLogShareShamir::validate(
            &repr.value,
            &repr.public_key,
            repr.party_id,
            repr.number_of_parties,
            repr.threshold,
        )
        .map_err(D::Error::custom)?;
        Ok(Self {
            value: repr.value,
            public_key: repr.public_key,
            party_id: repr.party_id,
            number_of_parties: repr.number_of_parties,
            threshold: repr.threshold,
        })
    }
}
