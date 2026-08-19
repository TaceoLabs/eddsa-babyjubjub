//! The first round of the DKG protocol.
//!
//! In this round every party commits to the coefficients of its polynomial and broadcasts these
//! commitments, so that the parties can verify the secret shares they receive in the second round.

use crate::{
    keygen::{
        DuplicateCommitmentsError, MaliciousPartyError, Parameters, SecretScalars,
        round2::RoundTwo,
        schnorr::{self, SchnorrZkProof},
    },
    shamir::utils,
};
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_serialize::CompressedChecked;
use eyre::Result;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use uuid::Uuid;

/// The state of the DKG protocol in the first round.
///
/// In this round each party samples a random polynomial, publishes the commitments to its
/// coefficients together with a Schnorr proof of knowledge of the constant term, and collects the
/// same information from all other parties.
pub struct RoundOne<C: CurveGroup> {
    session_id: Uuid,
    coefficients: SecretScalars<C::ScalarField>,
    commitments: Vec<C::Affine>,
    nizk: SchnorrZkProof<C>,
    my_idx: u16,
    params: Parameters,
    received_party_messages: HashMap<u16, Vec<C::Affine>>,
}

/// Communication sent in the first round of the DKG protocol.
/// This is intended to be broadcast to all other participants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundOneBroadcast<C: CurveGroup> {
    pub(crate) session_id: Uuid,
    pub(crate) commitments: CompressedChecked<Vec<C::Affine>>,
    pub(crate) nizk: SchnorrZkProof<C>,
}

impl<C: CurveGroup> RoundOne<C> {
    const CONTEXT_DOMAIN: &'static [u8] = b"PEDPOP_DKG_V1";

    /// Begin a new instance of the distributed key generation protocol.
    /// The provided [`Parameters`] must be the same for all participating parties.
    /// Each party must have a distinct `party_index`, ranging from 1 to `params.number_of_parties`, inclusively.
    /// The provided session id must be the same for all participating parties.
    ///
    /// # Errors
    /// Returns an error if `party_index` is zero or larger than the number of parties allowed by
    /// the provided [`Parameters`].
    pub fn new<R: Rng + CryptoRng>(
        parameters: Parameters,
        party_index: u16,
        session_id: Uuid,
        rng: &mut R,
    ) -> Result<Self> {
        if party_index == 0 {
            eyre::bail!("party index must be non-zero",);
        }
        if party_index > parameters.number_of_parties {
            eyre::bail!("provided party index {party_index} is larger than parameters allow",);
        }

        let coefficients = SecretScalars(
            (0..=parameters.degree())
                .map(|_| C::ScalarField::rand(rng))
                .collect::<Vec<_>>(),
        );

        let commitments = coefficients
            .iter()
            .map(|a_k| (C::generator() * a_k).into_affine())
            .collect::<Vec<_>>();

        let context = schnorr::proof_context(Self::CONTEXT_DOMAIN, session_id, &[parameters]);
        let nizk = SchnorrZkProof::<C>::new(
            &context,
            party_index,
            &coefficients[0],
            &commitments[0],
            &commitments[1..],
            rng,
        );

        let num_parties = parameters.number_of_parties;

        Ok(RoundOne {
            coefficients,
            commitments,
            nizk,
            my_idx: party_index,
            params: parameters,
            session_id,
            received_party_messages: HashMap::with_capacity(num_parties as usize - 1),
        })
    }

    /// Returns the message that must be broadcast to all other participants in this round.
    pub fn get_broadcast_message(&self) -> RoundOneBroadcast<C> {
        RoundOneBroadcast {
            session_id: self.session_id,
            commitments: CompressedChecked(self.commitments.clone()),
            nizk: self.nizk.clone(),
        }
    }

    /// Add a [`RoundOneBroadcast`] received from a party, verifying that everything is in order.
    ///
    /// # Errors
    /// Returns a [`MaliciousPartyError`] identifying the offending party if its broadcast contains
    /// the wrong number of commitments, a different session id, or an invalid proof of knowledge.
    /// Returns a [`DuplicateCommitmentsError`] identifying both offending parties if this party
    /// committed to the same constant term as a party added earlier.
    /// All other errors indicate an invalid `from` index and are usually the fault of the local
    /// party.
    pub fn add_party_communication(&mut self, from: u16, comm: RoundOneBroadcast<C>) -> Result<()> {
        if from == 0 {
            eyre::bail!("party index must be non-zero",);
        }
        if from > self.params.number_of_parties {
            eyre::bail!("party index {from} invalid for parameters",);
        }
        if from == self.my_idx {
            eyre::bail!("do not add messages from own party {from}",);
        }

        if self.received_party_messages.contains_key(&from) {
            eyre::bail!("already added message for party {from}");
        }
        if comm.commitments.len() != usize::from(self.params.threshold) {
            eyre::bail!(MaliciousPartyError::new(from as usize));
        }

        if self.session_id != comm.session_id {
            eyre::bail!("session id mismatch for party {from}");
        }

        // verify ZK proof
        let context = schnorr::proof_context(Self::CONTEXT_DOMAIN, self.session_id, &[self.params]);
        if !comm
            .nizk
            .verify(&context, from, &comm.commitments[0], &comm.commitments[1..])
        {
            eyre::bail!(MaliciousPartyError::new(from as usize));
        }

        // the commitment to the constant term must be unique across parties, so a duplicate means
        // one party copied the other and both are reported as offending
        let share_commitment = &comm.commitments[0];
        for id in 1..=self.params.number_of_parties {
            let Some(commitment) = self.received_party_messages.get(&id) else {
                continue;
            };
            if share_commitment == &commitment[0] {
                eyre::bail!(DuplicateCommitmentsError::new(from as usize, id as usize));
            }
        }

        self.received_party_messages
            .insert(from, comm.commitments.0);

        Ok(())
    }

    /// Returns a list of party indices for which we have not yet received and added a [`RoundOneBroadcast`] message.
    pub fn get_missing_parties(&self) -> Vec<u16> {
        (1..=self.params.number_of_parties)
            .filter(|idx| *idx != self.my_idx)
            .filter(|idx| !self.received_party_messages.contains_key(idx))
            .collect()
    }

    /// Indicates if all required messages have been received and we can proceed to the next round.
    /// See [`RoundOne::get_missing_parties`] to retrieve a list of parties we are still waiting on.
    pub fn can_advance(&self) -> bool {
        self.received_party_messages.len() == usize::from(self.params.number_of_parties) - 1
    }

    /// Try to advance into the second round of the DKG protocol.
    ///
    /// # Errors
    /// Returns an error if not all [`RoundOneBroadcast`] messages have been added yet, i.e., if
    /// [`RoundOne::can_advance`] returns false.
    pub fn round2(self) -> Result<RoundTwo<C>> {
        if !self.can_advance() {
            eyre::bail!("cannot advance to round 2, not all messages received");
        }
        // at this point, we have already checked that the received values are ok

        // evaluate our polynomial to get the secret share of each party
        let secret_shares = (1..=self.params.number_of_parties)
            .map(|party_idx| {
                utils::evaluate_poly(&self.coefficients, C::ScalarField::from(party_idx))
            })
            .collect();

        let mut commitments = self.received_party_messages;
        // also insert ourself into commitments
        commitments.insert(self.my_idx, self.commitments);

        Ok(RoundTwo {
            session_id: self.session_id,
            received_party_messages: HashMap::with_capacity(commitments.len() - 1),
            failed_parties: BTreeSet::default(),
            commitments,
            secret_shares: SecretScalars(secret_shares),
            my_idx: self.my_idx,
            params: self.params,
        })
    }
}
