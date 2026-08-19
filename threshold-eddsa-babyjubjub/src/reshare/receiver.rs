//! The receivers in the `ReShare` protocol.
//!
//! A receiver is a party in the new set of parties. It checks the shares it receives from the old
//! parties against their broadcast commitments and combines them, weighted with the Lagrange
//! coefficients of the senders, into its own share of the unchanged signing key.

use crate::{
    keygen::{
        MalformedMessageError, MaliciousPartyError, MessageError, MessageResult,
        finished::Finished, schnorr,
    },
    reshare::{
        BroadcastMessage, PartyMessage, blame::ReShareBlameRound, sender::ReShareProtocolSender,
        sender_set::ReShareSenderSet,
    },
    shamir::utils,
};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use eyre::Result;
use std::collections::{BTreeSet, HashMap};
use std::ops::{Deref, DerefMut};
use uuid::Uuid;

/// A receiver in the `ReShare` protocol is a party in the new set of parties.
pub struct ReShareProtocolReceiver<C: CurveGroup> {
    pub(crate) my_idx: u16,
    pub(crate) received_shares: ReceivedShares<C>,
    pub(crate) reshare_senders: ReShareSenderSet<C>,
    pub(crate) session_id: Uuid,
    pub(crate) failed_senders: BTreeSet<u16>,
    pub(crate) pre_disqualified_senders: BTreeSet<u16>,
}

pub(crate) struct ReceivedShares<C: CurveGroup>(
    pub(crate) HashMap<u16, (C::ScalarField, Vec<C::Affine>)>,
);

impl<C: CurveGroup> Deref for ReceivedShares<C> {
    type Target = HashMap<u16, (C::ScalarField, Vec<C::Affine>)>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<C: CurveGroup> DerefMut for ReceivedShares<C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<C: CurveGroup> Drop for ReceivedShares<C> {
    #[allow(
        clippy::iter_over_hash_type,
        reason = "zeroization order has no semantic effect"
    )]
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        for (share, _) in self.0.values_mut() {
            share.zeroize();
        }
    }
}

impl<C: CurveGroup> ReShareProtocolReceiver<C> {
    const CONTEXT_DOMAIN: &'static [u8] = ReShareProtocolSender::<C>::CONTEXT_DOMAIN;

    /// Construct a [`ReShareProtocolReceiver`] for a party in the new set of parties with new index `my_idx`.
    ///
    /// `session_id` must be the same for every participant *and* globally unique per run; see
    /// [`ReShareProtocolSender::new`] for why reuse lets an honest sender be framed.
    ///
    /// # Errors
    /// Returns an error if `my_idx` is zero or larger than the number of parties allowed by the new
    /// [`Parameters`](crate::keygen::Parameters).
    pub fn new(
        my_idx: u16,
        reshare_senders: ReShareSenderSet<C>,
        session_id: Uuid,
    ) -> Result<Self> {
        if my_idx == 0 {
            eyre::bail!("party index must be non-zero",);
        }
        if my_idx > reshare_senders.new_parameters.number_of_parties {
            eyre::bail!("provided party index {my_idx} is larger than new parameters allow",);
        }
        reshare_senders.correct()?;

        Ok(ReShareProtocolReceiver {
            my_idx,
            received_shares: ReceivedShares(HashMap::new()),
            reshare_senders,
            session_id,
            failed_senders: BTreeSet::new(),
            pre_disqualified_senders: BTreeSet::new(),
        })
    }

    /// Add communication received from a party in the old set of parties.
    ///
    /// The communication is split into two parts, a part that is broadcast to everyone and a part
    /// that is specific to each recipient party.
    /// This uses the information in the [`ReShareSenderSet`] to ensure the received communication is
    /// consistent with the share of the public key the sender was registered with.
    ///
    /// # Errors
    /// Returns [`MessageError::MaliciousParty`] if the proof of knowledge is invalid, the
    /// constant-term commitment does not match the sender's registered public-key share, or the
    /// secret share does not verify against the commitments; all three attribute blame.
    /// [`MessageError::Malformed`] (wrong commitment count or session id) does not — it is usually a
    /// local configuration mismatch. [`MessageError::LocalFault`] means an unselected sender or a
    /// duplicate delivery.
    pub fn add_old_party_communication(
        &mut self,
        from: u16,
        commitments: BroadcastMessage<C>,
        share: &PartyMessage<C>,
    ) -> MessageResult<()> {
        self.validate_broadcast(from, &commitments)?;
        self.validate_share_session(from, share)?;

        if !utils::verify_polynomial_evaluation::<C>(
            &commitments.commitments,
            self.my_idx,
            &share.secret_share,
        ) {
            return Err(MaliciousPartyError::new(from as usize).into());
        }

        self.received_shares
            .insert(from, (share.secret_share, commitments.commitments));

        Ok(())
    }

    /// Add old-party communication while retaining an invalid polynomial evaluation for the
    /// optional public blame round.
    ///
    /// All broadcast commitments and proofs must still be valid. Only a private share that fails
    /// its committed polynomial equation is converted into a complaint.
    ///
    /// # Errors
    /// As [`ReShareProtocolReceiver::add_old_party_communication`], except that a private evaluation
    /// failing its polynomial equation becomes a recorded complaint rather than
    /// [`MessageError::MaliciousParty`].
    pub fn add_old_party_communication_for_blame(
        &mut self,
        from: u16,
        commitments: BroadcastMessage<C>,
        share: &PartyMessage<C>,
    ) -> MessageResult<()> {
        self.validate_broadcast(from, &commitments)?;
        self.validate_share_session(from, share)?;

        if !utils::verify_polynomial_evaluation::<C>(
            &commitments.commitments,
            self.my_idx,
            &share.secret_share,
        ) {
            self.failed_senders.insert(from);
        }
        self.received_shares
            .insert(from, (share.secret_share, commitments.commitments));
        Ok(())
    }

    /// Returns a list of party indices for which we have not yet received and added their communication.
    pub fn get_missing_parties(&self) -> Vec<u16> {
        self.reshare_senders
            .senders
            .keys()
            .copied()
            .filter(|idx| !self.received_shares.contains_key(idx))
            .collect()
    }

    /// Register a valid sender broadcast but complain that its private evaluation was missing.
    ///
    /// This lets the protocol enter the public blame round, where the sender can reveal the
    /// committed evaluation or be disqualified after an externally agreed deadline.
    ///
    /// Use this when the sender's broadcast arrived and only its private evaluation is missing.
    /// Choosing between this and [`ReShareProtocolReceiver::disqualify_missing_sender`] changes the
    /// surviving sender set, so it must be an externally agreed decision — see that method.
    ///
    /// # Errors
    /// As [`ReShareProtocolReceiver::add_old_party_communication`], minus the private-share checks.
    pub fn complain_missing_share(
        &mut self,
        from: u16,
        commitments: BroadcastMessage<C>,
    ) -> MessageResult<()> {
        self.validate_broadcast(from, &commitments)?;
        self.failed_senders.insert(from);
        self.received_shares
            .insert(from, (C::ScalarField::zero(), commitments.commitments));
        Ok(())
    }

    /// Validates a sender's broadcast, shared by every intake path. The sender and framing checks
    /// attribute no blame; the two cryptographic checks bind the broadcast to the public-key share
    /// the sender was registered with and do.
    fn validate_broadcast(
        &self,
        from: u16,
        commitments: &BroadcastMessage<C>,
    ) -> MessageResult<()> {
        if from == 0 || from > self.reshare_senders.old_parameters.number_of_parties {
            return Err(MessageError::local(format!(
                "party index {from} invalid for old parameters"
            )));
        }
        if !self.reshare_senders.senders.contains_key(&from) {
            return Err(MessageError::local(format!(
                "party index {from} is not part of the set of ReShare senders"
            )));
        }
        if self.received_shares.contains_key(&from) {
            return Err(MessageError::local(format!(
                "already added communication for sender {from}"
            )));
        }
        if commitments.commitments.len()
            != usize::from(self.reshare_senders.new_parameters.threshold)
        {
            return Err(MalformedMessageError::new(
                from as usize,
                "commitment count does not match the local new threshold",
            )
            .into());
        }
        if commitments.session_id != self.session_id {
            return Err(MalformedMessageError::new(
                from as usize,
                "broadcast session id does not match the local session",
            )
            .into());
        }

        let context = schnorr::proof_context(
            Self::CONTEXT_DOMAIN,
            self.session_id,
            &[
                self.reshare_senders.old_parameters,
                self.reshare_senders.new_parameters,
            ],
        );
        if !commitments.nizk.verify(
            &context,
            from,
            &commitments.commitments[0],
            &commitments.commitments[1..],
            // Commitment must match the public key share of the sender
        ) || commitments.commitments[0] != self.reshare_senders.senders[&from]
        {
            return Err(MaliciousPartyError::new(from as usize).into());
        }
        Ok(())
    }

    fn validate_share_session(&self, from: u16, share: &PartyMessage<C>) -> MessageResult<()> {
        if share.session_id != self.session_id {
            return Err(MalformedMessageError::new(
                from as usize,
                "private evaluation session id does not match the local session",
            )
            .into());
        }
        Ok(())
    }

    /// Apply an externally agreed disqualification when a sender supplied no usable broadcast.
    ///
    /// This drops `from` from the sender set, which changes every remaining Lagrange coefficient and
    /// therefore the polynomial the new sharing lies on. Since every valid sender set reconstructs
    /// the same public key, a receiver that disqualifies a different set than its peers still passes
    /// [`ReShareProtocolReceiver::finalize`] — see
    /// [`Finished::agreement_digest`](crate::keygen::finished::Finished::agreement_digest). The
    /// overlap with [`ReShareProtocolReceiver::complain_missing_share`] is the trap: both are
    /// reachable whenever nothing was recorded for a sender, so derive the choice from an externally
    /// agreed decision, never from a local timeout.
    ///
    /// # Errors
    /// Returns an error if communication was already received, the sender was not selected, or
    /// removing it would leave an invalid sender set that no longer reconstructs the old key.
    pub fn disqualify_missing_sender(&mut self, from: u16) -> Result<()> {
        if self.received_shares.contains_key(&from) {
            eyre::bail!("sender {from}'s communication was already received");
        }
        let Some(removed_share) = self.reshare_senders.senders.remove(&from) else {
            eyre::bail!("party {from} is not a selected old sender");
        };
        if let Err(error) = self.reshare_senders.correct() {
            self.reshare_senders.senders.insert(from, removed_share);
            eyre::bail!("cannot disqualify sender while preserving the old key: {error}");
        }
        self.pre_disqualified_senders.insert(from);
        Ok(())
    }

    /// Indicates if the protocol is ready to advance into the next state.
    /// See [`ReShareProtocolReceiver::get_missing_parties`] for parties we are still missing information from.
    pub fn can_advance(&self) -> bool {
        self.received_shares.len() == self.reshare_senders.senders.len()
    }

    /// Try to finalize the `ReShare` protocol, putting it in a state where the results of the protocol
    /// can be obtained.
    ///
    /// The resulting [`Finished`] state holds this party's share of the unchanged signing key under
    /// the new [`Parameters`](crate::keygen::Parameters).
    ///
    /// The public-key check below catches a wrong sender *contribution* but is not an agreement
    /// check: every valid sender set reconstructs the same key, so receivers that used different sets
    /// both succeed here. Compare
    /// [`Finished::agreement_digest`](crate::keygen::finished::Finished::agreement_digest) across
    /// receivers before erasing the old shares.
    ///
    /// # Errors
    /// Returns an error if the communication of not all old parties has been added yet, i.e., if
    /// [`ReShareProtocolReceiver::can_advance`] returns false, or if the constant terms committed to
    /// by the senders do not recombine to the public key of the [`ReShareSenderSet`].
    pub fn finalize(self) -> Result<Finished<C>> {
        if !self.can_advance() {
            eyre::bail!("cannot finalize, not all messages received");
        }
        if !self.failed_senders.is_empty() {
            eyre::bail!("cannot finalize with unresolved complaints; enter the blame round");
        }

        // The Lagrange coefficients are relative to the set of parties that actually took part in
        // the handover, which is only a threshold sized subset of the old parties.
        let old_parties = self
            .reshare_senders
            .senders
            .keys()
            .copied()
            .collect::<Vec<_>>();
        let mut lagrange_coeffs = HashMap::with_capacity(old_parties.len());
        for party in &old_parties {
            let lambda =
                utils::single_lagrange_from_coeff::<C::ScalarField, _>(*party, &old_parties);
            lagrange_coeffs.insert(party, lambda);
        }

        let my_secret_key_share = self
            .received_shares
            .iter()
            .fold(C::ScalarField::zero(), |acc, (party, share)| {
                acc + lagrange_coeffs[party] * share.0
            });
        let my_public_key_share = (C::generator() * my_secret_key_share).into_affine();

        let mut public_key_shares = HashMap::new();
        public_key_shares.insert(self.my_idx, my_public_key_share);

        for party_idx in 1..=self.reshare_senders.new_parameters.number_of_parties {
            if party_idx == self.my_idx {
                continue;
            }
            let pk_share = self
                .received_shares
                .iter()
                .fold(C::zero(), |acc, (party, (_, com))| {
                    acc + utils::evaluate_polynomial_in_exponent::<C>(com, party_idx)
                        * lagrange_coeffs[party]
                });
            public_key_shares.insert(party_idx, pk_share.into_affine());
        }

        let public_key = self
            .received_shares
            .iter()
            .fold(C::zero(), |acc, (party, (_, com))| {
                acc + com[0] * lagrange_coeffs[party]
            });
        let public_key = public_key.into_affine();
        if public_key != self.reshare_senders.pk {
            eyre::bail!(
                "ReShare protocol failed, recombined pk does not match: {:?} != {:?}",
                public_key,
                self.reshare_senders.pk
            );
        }

        Ok(Finished {
            my_idx: self.my_idx,
            session_id: self.session_id,
            sk_share: my_secret_key_share,
            pk_shares: public_key_shares,
            pk: public_key,
            // Old-committee indices, ascending because `senders` is a `BTreeMap`.
            contributing_parties: old_parties,
        })
    }

    /// Enter the optional public blame round after collecting every selected sender's messages.
    ///
    /// # Errors
    /// Returns an error unless all selected sender communications have been collected.
    pub fn blame_round(self) -> Result<ReShareBlameRound<C>> {
        ReShareBlameRound::new(self)
    }
}
