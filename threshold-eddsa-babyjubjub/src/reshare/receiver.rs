//! The receivers in the `ReShare` protocol.
//!
//! A receiver is a party in the new set of parties. It checks the shares it receives from the old
//! parties against their broadcast commitments and combines them, weighted with the Lagrange
//! coefficients of the senders, into its own share of the unchanged signing key.

use crate::{
    keygen::{MaliciousPartyError, finished::Finished, schnorr},
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
use uuid::Uuid;

/// A receiver in the `ReShare` protocol is a party in the new set of parties.
pub struct ReShareProtocolReceiver<C: CurveGroup> {
    pub(crate) my_idx: u16,
    pub(crate) received_shares: HashMap<u16, (C::ScalarField, Vec<C::Affine>)>,
    pub(crate) reshare_senders: ReShareSenderSet<C>,
    pub(crate) session_id: Uuid,
    pub(crate) failed_senders: BTreeSet<u16>,
}

impl<C: CurveGroup> ReShareProtocolReceiver<C> {
    const CONTEXT_DOMAIN: &'static [u8] = ReShareProtocolSender::<C>::CONTEXT_DOMAIN;

    /// Construct a [`ReShareProtocolReceiver`] for a party in the new set of parties with new index `my_idx`.
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
            received_shares: HashMap::new(),
            reshare_senders,
            session_id,
            failed_senders: BTreeSet::new(),
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
    /// Returns a [`MaliciousPartyError`] identifying the offending party if its broadcast contains
    /// the wrong number of commitments, either message carries a different session id, the proof of
    /// knowledge is invalid, the commitment to the constant term does not match the sender's share
    /// of the public key, or the secret share does not verify against the commitments.
    /// All other errors indicate an invalid `from` index and are usually the fault of the local
    /// party.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Keeps consistency with the broadcast message, which is consumed"
    )]
    pub fn add_old_party_communication(
        &mut self,
        from: u16,
        commitments: BroadcastMessage<C>,
        share: PartyMessage<C>,
    ) -> Result<()> {
        if from == 0 {
            eyre::bail!("party index must be non-zero",);
        }
        if from > self.reshare_senders.old_parameters.number_of_parties {
            eyre::bail!("party index {from} invalid for old parameters",);
        }

        if !self.reshare_senders.senders.contains_key(&from) {
            eyre::bail!("party index {from} is not part of the set of ReShare senders");
        }
        if self.received_shares.contains_key(&from) {
            eyre::bail!("already added message for party {from}");
        }

        if commitments.commitments.len()
            != usize::from(self.reshare_senders.new_parameters.threshold)
        {
            eyre::bail!(MaliciousPartyError::new(from as usize));
        }

        if self.session_id != commitments.session_id || self.session_id != share.session_id {
            eyre::bail!("session id mismatch for party {from}");
        }

        let pk_share = self.reshare_senders.senders[&from];

        // verify ZK proof
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
        ) {
            eyre::bail!(MaliciousPartyError::new(from as usize));
        }

        // Commitment must match the public key share of the sender
        if commitments.commitments[0] != pk_share {
            eyre::bail!(MaliciousPartyError::new(from as usize));
        }

        if !utils::verify_polynomial_evaluation::<C>(
            &commitments.commitments.0,
            self.my_idx,
            &share.secret_share,
        ) {
            eyre::bail!(MaliciousPartyError::new(from as usize));
        }

        self.received_shares
            .insert(from, (share.secret_share, commitments.commitments.0));

        Ok(())
    }

    /// Add old-party communication while retaining an invalid polynomial evaluation for the
    /// optional public blame round.
    ///
    /// All broadcast commitments and proofs must still be valid. Only a private share that fails
    /// its committed polynomial equation is converted into a complaint.
    ///
    /// # Errors
    /// Returns an error for invalid sender metadata, commitments, proof of possession, or session.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Keeps consistency with add_old_party_communication"
    )]
    pub fn add_old_party_communication_for_blame(
        &mut self,
        from: u16,
        commitments: BroadcastMessage<C>,
        share: PartyMessage<C>,
    ) -> Result<()> {
        if from == 0 {
            eyre::bail!("party index must be non-zero",);
        }
        if from > self.reshare_senders.old_parameters.number_of_parties {
            eyre::bail!("party index {from} invalid for old parameters",);
        }

        if !self.reshare_senders.senders.contains_key(&from) {
            eyre::bail!("party index {from} is not part of the set of ReShare senders");
        }
        if self.received_shares.contains_key(&from) {
            eyre::bail!("already added message for party {from}");
        }

        if commitments.commitments.len()
            != usize::from(self.reshare_senders.new_parameters.threshold)
        {
            eyre::bail!(MaliciousPartyError::new(from as usize));
        }

        if self.session_id != commitments.session_id || self.session_id != share.session_id {
            eyre::bail!("session id mismatch for party {from}");
        }

        let pk_share = self.reshare_senders.senders[&from];

        // verify ZK proof
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
        ) {
            eyre::bail!(MaliciousPartyError::new(from as usize));
        }

        // Commitment must match the public key share of the sender
        if commitments.commitments[0] != pk_share {
            eyre::bail!(MaliciousPartyError::new(from as usize));
        }

        if !utils::verify_polynomial_evaluation::<C>(
            &commitments.commitments,
            self.my_idx,
            &share.secret_share,
        ) {
            self.failed_senders.insert(from);
        }
        self.received_shares
            .insert(from, (share.secret_share, commitments.commitments.0));
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
    /// # Errors
    /// Returns an error if the communication of not all old parties has been added yet, i.e., if
    /// [`ReShareProtocolReceiver::can_advance`] returns false, or if the constant terms committed to
    /// by the senders do not recombine to the public key of the [`ReShareSenderSet`].
    pub fn finalize(self) -> Result<Finished<C>> {
        if !self.can_advance() {
            eyre::bail!("cannot finalize, not all messages received");
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
