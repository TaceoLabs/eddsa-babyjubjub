//! The first round of the DKG protocol.
//!
//! In this round every party commits to the coefficients of its polynomial and broadcasts these
//! commitments, so that the parties can verify the secret shares they receive in the second round.

use crate::{
    internal::lagrange,
    keygen::{
        DuplicateCommitmentsError, MalformedMessageError, MaliciousPartyError, MessageError,
        MessageResult, Parameters, SecretScalarMap, SecretScalars,
        round2::RoundTwo,
        schnorr::{self, SchnorrZkProof},
    },
};
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use eyre::Result;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, HashMap},
    num::NonZeroU16,
};

/// The state of the DKG protocol in the first round.
///
/// In this round each party samples a random polynomial, publishes the commitments to its
/// coefficients together with a Schnorr proof of knowledge of the constant term, and collects the
/// same information from all other parties.
pub struct RoundOne<C: CurveGroup> {
    context: Vec<u8>,
    coefficients: SecretScalars<C::ScalarField>,
    commitments: Vec<C::Affine>,
    nizk: SchnorrZkProof<C>,
    my_idx: NonZeroU16,
    params: Parameters,
    received_party_messages: HashMap<NonZeroU16, Vec<C::Affine>>,
    disqualified_parties: BTreeSet<NonZeroU16>,
}

/// Communication sent in the first round of the DKG protocol.
/// This is intended to be broadcast to all other participants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct RoundOneBroadcast<C: CurveGroup> {
    #[serde(
        serialize_with = "crate::internal::serde::serialize_canonical_protocol_vec",
        deserialize_with = "crate::internal::serde::deserialize_canonical_protocol_vec"
    )]
    pub(crate) commitments: Vec<C::Affine>,
    pub(crate) nizk: SchnorrZkProof<C>,
}

impl<C: CurveGroup> RoundOne<C> {
    const CONTEXT_DOMAIN: &'static [u8] = b"PEDPOP_DKG_V1";

    /// Begin a new instance of the distributed key generation protocol.
    /// The provided [`Parameters`] must be the same for all participating parties.
    /// Each party must have a distinct `party_index`, ranging from 1 to `params.number_of_parties`, inclusively.
    /// The opaque `context` must be byte-identical for all participating parties, and must be
    /// globally unique per run: it is the only run-specific input to the proof-of-possession
    /// context, so reusing it with the same [`Parameters`] makes round-one broadcasts replayable. An
    /// adversary with network control can then suppress an honest party's fresh broadcast, inject
    /// its stale one, and have the honest party's fresh evaluations fail against the stale
    /// commitments — which gets it blamed. Use a fresh random value per run, never a context derived
    /// from configuration alone.
    ///
    /// The context is not carried in the protocol messages: a party running with a different
    /// context derives a different proof-of-possession context, so its broadcast fails proof
    /// verification at every peer and is reported as attributable misbehaviour, not as a mismatch.
    ///
    /// # Errors
    /// Returns an error if `party_index` is larger than the number of parties allowed by the
    /// provided [`Parameters`].
    pub fn new<R: Rng + CryptoRng>(
        parameters: Parameters,
        party_index: NonZeroU16,
        context: &[u8],
        rng: &mut R,
    ) -> Result<Self> {
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

        let proof_context = schnorr::proof_context(Self::CONTEXT_DOMAIN, context, &[parameters]);
        let nizk = SchnorrZkProof::<C>::new(
            &proof_context,
            party_index,
            &coefficients[0],
            &commitments[0],
            &commitments[1..],
            rng,
        );

        let num_parties = parameters.number_of_parties.get();

        Ok(RoundOne {
            context: context.to_vec(),
            coefficients,
            commitments,
            nizk,
            my_idx: party_index,
            params: parameters,
            received_party_messages: HashMap::with_capacity(usize::from(num_parties) - 1),
            disqualified_parties: BTreeSet::new(),
        })
    }

    /// Returns the message that must be broadcast to all other participants in this round.
    pub fn get_broadcast_message(&self) -> RoundOneBroadcast<C> {
        RoundOneBroadcast {
            commitments: self.commitments.clone(),
            nizk: self.nizk.clone(),
        }
    }

    /// Add a [`RoundOneBroadcast`] received from a party, verifying that everything is in order.
    ///
    /// # Errors
    /// Returns [`MessageError::MaliciousParty`] for an invalid proof of knowledge and
    /// [`MessageError::DuplicateCommitments`] if this broadcast repeats the constant-term commitment
    /// of the local party or of one added earlier; both attribute blame. Note that a sender running
    /// with a different session context also fails proof verification, so it is blamed too.
    /// [`MessageError::Malformed`] (wrong commitment count) does not attribute blame — it is usually
    /// a local configuration mismatch. [`MessageError::LocalFault`] means an invalid `from` index or
    /// a duplicate delivery.
    pub fn add_party_communication(
        &mut self,
        from: NonZeroU16,
        comm: RoundOneBroadcast<C>,
    ) -> MessageResult<()> {
        if from > self.params.number_of_parties {
            return Err(MessageError::local(format!(
                "party index {from} invalid for parameters"
            )));
        }
        if from == self.my_idx {
            return Err(MessageError::local(format!(
                "do not add messages from own party {from}"
            )));
        }

        if self.received_party_messages.contains_key(&from) {
            return Err(MessageError::local(format!(
                "already added message for party {from}"
            )));
        }
        if comm.commitments.len() != usize::from(self.params.threshold.get()) {
            return Err(MalformedMessageError::new(
                from,
                "commitment count does not match the local threshold",
            )
            .into());
        }

        // verify ZK proof
        let proof_context =
            schnorr::proof_context(Self::CONTEXT_DOMAIN, &self.context, &[self.params]);
        if !comm.nizk.verify(
            &proof_context,
            from,
            &comm.commitments[0],
            &comm.commitments[1..],
        ) {
            return Err(MaliciousPartyError::new(from).into());
        }

        // the commitment to the constant term must be unique across parties, so a duplicate means
        // one party copied the other and both are reported as offending
        let share_commitment = &comm.commitments[0];
        if share_commitment == &self.commitments[0] {
            return Err(DuplicateCommitmentsError::new(from, self.my_idx).into());
        }
        for id in self.params.party_indices() {
            let Some(commitment) = self.received_party_messages.get(&id) else {
                continue;
            };
            if share_commitment == &commitment[0] {
                return Err(DuplicateCommitmentsError::new(from, id).into());
            }
        }

        self.received_party_messages.insert(from, comm.commitments);

        Ok(())
    }

    /// Returns a list of party indices for which we have not yet received and added a [`RoundOneBroadcast`] message.
    pub fn get_missing_parties(&self) -> Vec<NonZeroU16> {
        self.params
            .party_indices()
            .filter(|idx| *idx != self.my_idx)
            .filter(|idx| !self.received_party_messages.contains_key(idx))
            .filter(|idx| !self.disqualified_parties.contains(idx))
            .collect()
    }

    /// Record an externally agreed disqualification for a missing or malformed round-one dealer.
    ///
    /// Every honest participant must apply the same decision, normally after reliable broadcast
    /// or a common timeout certificate.
    ///
    /// An accepted broadcast is removed so every honest participant can apply the same qualified
    /// set even if duplicate commitments were received in different orders. If `party` is the
    /// local party, this state becomes terminal and [`RoundOne::round2`] will reject it.
    ///
    /// # Errors
    /// Returns an error for an invalid or already-disqualified party.
    pub fn disqualify_party(&mut self, party: NonZeroU16) -> Result<()> {
        self.disqualify_parties(&BTreeSet::from([party]))
    }

    /// Atomically apply an externally agreed set of round-one disqualifications.
    ///
    /// This is the preferred API for resolving [`DuplicateCommitmentsError`], which identifies
    /// both dealers. Every honest participant must apply the same complete set.
    ///
    /// # Errors
    /// Returns an error without changing state if the set is empty, contains an invalid party, or
    /// contains a party that was already disqualified, or would leave fewer than the threshold
    /// number of qualified parties.
    pub fn disqualify_parties(&mut self, parties: &BTreeSet<NonZeroU16>) -> Result<()> {
        if parties.is_empty() {
            eyre::bail!("at least one round-one party must be disqualified");
        }
        for party in parties {
            if *party > self.params.number_of_parties {
                eyre::bail!("invalid round-one party to disqualify: {party}");
            }
            if self.disqualified_parties.contains(party) {
                eyre::bail!("party {party} was already disqualified");
            }
        }
        let remaining = usize::from(self.params.number_of_parties.get())
            - self.disqualified_parties.len()
            - parties.len();
        if remaining < usize::from(self.params.threshold.get()) {
            eyre::bail!("round-one disqualifications would leave fewer than the threshold parties");
        }
        for party in parties {
            self.received_party_messages.remove(party);
            self.disqualified_parties.insert(*party);
        }
        Ok(())
    }

    /// Indicates if all required messages have been received and we can proceed to the next round.
    /// See [`RoundOne::get_missing_parties`] to retrieve a list of parties we are still waiting on.
    pub fn can_advance(&self) -> bool {
        !self.disqualified_parties.contains(&self.my_idx)
            && self.received_party_messages.len() + self.disqualified_parties.len()
                == usize::from(self.params.number_of_parties.get()) - 1
    }

    /// Try to advance into the second round of the DKG protocol.
    ///
    /// # Errors
    /// Returns an error if not all [`RoundOneBroadcast`] messages have been added yet, i.e., if
    /// [`RoundOne::can_advance`] returns false, or if the local party was disqualified.
    pub fn round2(self) -> Result<RoundTwo<C>> {
        if self.disqualified_parties.contains(&self.my_idx) {
            eyre::bail!("local party was disqualified in round one");
        }
        if !self.can_advance() {
            eyre::bail!("cannot advance to round 2, not all messages received");
        }
        // at this point, we have already checked that the received values are ok

        // evaluate our polynomial to get the secret share of each party
        let secret_shares = self
            .params
            .party_indices()
            .map(|party_idx| {
                lagrange::evaluate_poly(&self.coefficients, C::ScalarField::from(party_idx.get()))
            })
            .collect();

        let mut commitments = self.received_party_messages;
        // also insert ourself into commitments
        commitments.insert(self.my_idx, self.commitments);

        Ok(RoundTwo {
            context: self.context,
            received_party_messages: SecretScalarMap(HashMap::with_capacity(commitments.len() - 1)),
            failed_parties: BTreeSet::default(),
            disqualified_parties: self.disqualified_parties,
            commitments,
            secret_shares: SecretScalars(secret_shares),
            my_idx: self.my_idx,
            params: self.params,
        })
    }
}
