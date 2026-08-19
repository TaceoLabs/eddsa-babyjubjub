//! The set of old parties handing a key over in the `ReShare` protocol.
//!
//! This module defines the `ReShareSenderSet` struct, which pins down the threshold sized subset of
//! the old parties taking part in the handover together with their shares of the public key, so that
//! the receivers can check the communication they get from them.

use crate::{keygen::Parameters, shamir::utils};
use ark_ec::CurveGroup;
use ark_serialize::Valid;
use std::collections::BTreeMap;

/// A struct representing the parties (and their public information) participating in a `ReShare` protocol run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReShareSenderSet<C: CurveGroup> {
    // BTreeMap to always have the same order when iterating
    // this holds pk_share points, already deserialized
    pub(crate) senders: BTreeMap<u16, C::Affine>,
    pub(crate) pk: C::Affine,
    pub(crate) old_parameters: Parameters,
    pub(crate) new_parameters: Parameters,
}

impl<C: CurveGroup> ReShareSenderSet<C> {
    /// Start the construction of a new [`ReShareSenderSet`].
    pub fn for_pk_and_parameters(
        pk: C::Affine,
        old_parameters: Parameters,
        new_parameters: Parameters,
    ) -> ReShareSenderSet<C> {
        ReShareSenderSet {
            senders: BTreeMap::default(),
            pk,
            old_parameters,
            new_parameters,
        }
    }

    /// Check if the set of parties is ready, i.e., if enough parties have been added to the set
    pub fn ready(&self) -> bool {
        self.senders.len() == usize::from(self.old_parameters.threshold)
    }

    /// Adds a party to the set of `ReShare` senders. A party's public information is made up of its share of the public key
    ///
    /// # Errors
    /// Returns an error if the set of senders is already complete, i.e., if [`ReShareSenderSet::ready`]
    /// returns true, or if a party with the same `id` has been added before.
    pub fn add_party(&mut self, id: u16, pk_share: C::Affine) -> eyre::Result<()> {
        if id == 0 || id > self.old_parameters.number_of_parties {
            return Err(eyre::eyre!("Party id {id} is outside the old party set"));
        }
        if pk_share.check().is_err() {
            return Err(eyre::eyre!("Public-key share for party {id} is invalid"));
        }
        if self.ready() {
            return Err(eyre::eyre!(
                "Cannot add party {} to ReShareSenderSet, already have enough parties",
                id
            ));
        }

        if self.senders.contains_key(&id) {
            return Err(eyre::eyre!("Duplicate party id: {}", id));
        }
        self.senders.insert(id, pk_share);
        Ok(())
    }

    /// Check if the set of parties is correct, i.e., if the shares can be recombined to the public key
    ///
    /// # Errors
    /// Returns an error if the set of senders is not complete yet, i.e., if
    /// [`ReShareSenderSet::ready`] returns false, or if the shares of the senders do not recombine to
    /// the public key of this set.
    pub fn correct(&self) -> eyre::Result<()> {
        if !self.ready() {
            eyre::bail!("Cannot check correctness of ReShareSenderSet, not enough parties");
        }

        let indices: Vec<_> = self.senders.keys().copied().collect();
        let recomb_pk = self.senders.iter().fold(C::zero(), |acc, (&idx, p)| {
            acc + *p * utils::single_lagrange_from_coeff::<C::ScalarField, u16>(idx, &indices)
        });

        if recomb_pk.into_affine() != self.pk {
            eyre::bail!(
                "ReShareSenderSet is not correct, recombined pk does not match: {:?} != {:?}",
                recomb_pk.into_affine(),
                self.pk
            );
        }
        Ok(())
    }
}
