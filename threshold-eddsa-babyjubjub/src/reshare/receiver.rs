//! The receivers in the `ReShare` protocol.
//!
//! A receiver is a party in the new set of parties. It checks the shares it receives from the old
//! parties against their broadcast commitments and combines them, weighted with the Lagrange
//! coefficients of the senders, into its own share of the unchanged signing key.

use crate::{
    internal::lagrange,
    keygen::{
        MalformedMessageError, MaliciousPartyError, MessageError, MessageResult,
        finished::Finished, schnorr,
    },
    reshare::{
        BroadcastMessage, PartyMessage, sender::ReShareProtocolSender, sender_set::ReShareSenderSet,
    },
};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use eyre::Result;
use std::collections::HashMap;
use std::num::NonZeroU16;
use std::ops::{Deref, DerefMut};

/// A receiver in the `ReShare` protocol is a party in the new set of parties.
pub struct ReShareProtocolReceiver<C: CurveGroup> {
    my_idx: NonZeroU16,
    received_shares: ReceivedShares<C>,
    reshare_senders: ReShareSenderSet<C>,
    context: Vec<u8>,
}

struct ReceivedShares<C: CurveGroup>(HashMap<NonZeroU16, (C::ScalarField, Vec<C::Affine>)>);

impl<C: CurveGroup> Deref for ReceivedShares<C> {
    type Target = HashMap<NonZeroU16, (C::ScalarField, Vec<C::Affine>)>;

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
    /// The opaque `context` must be byte-identical for every participant *and* globally unique per
    /// run; see [`ReShareProtocolSender::new`] for why reuse lets an honest sender be framed.
    ///
    /// # Errors
    /// Returns an error if `my_idx` is larger than the number of parties allowed by the new
    /// [`Parameters`](crate::keygen::Parameters).
    pub fn new(
        my_idx: NonZeroU16,
        reshare_senders: ReShareSenderSet<C>,
        context: &[u8],
    ) -> Result<Self> {
        if my_idx > reshare_senders.new_parameters.number_of_parties {
            eyre::bail!("provided party index {my_idx} is larger than new parameters allow",);
        }
        reshare_senders.correct()?;

        Ok(ReShareProtocolReceiver {
            my_idx,
            received_shares: ReceivedShares(HashMap::new()),
            reshare_senders,
            context: context.to_vec(),
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
    /// secret share does not verify against the commitments; all three attribute blame. Note that a
    /// sender running with a different session context also fails proof verification, so it is
    /// blamed too. [`MessageError::Malformed`] (wrong commitment count) does not attribute blame —
    /// it is usually a local configuration mismatch. [`MessageError::LocalFault`] means an
    /// unselected sender or a duplicate delivery.
    pub fn add_old_party_communication(
        &mut self,
        from: NonZeroU16,
        commitments: BroadcastMessage<C>,
        share: &PartyMessage<C>,
    ) -> MessageResult<()> {
        self.validate_broadcast(from, &commitments)?;

        if !lagrange::verify_polynomial_evaluation::<C>(
            &commitments.commitments,
            self.my_idx,
            &share.secret_share,
        ) {
            return Err(MaliciousPartyError::new(from).into());
        }

        self.received_shares
            .insert(from, (share.secret_share, commitments.commitments));

        Ok(())
    }

    /// Returns a list of party indices for which we have not yet received and added their communication.
    pub fn get_missing_parties(&self) -> Vec<NonZeroU16> {
        self.reshare_senders
            .senders
            .keys()
            .copied()
            .filter(|idx| !self.received_shares.contains_key(idx))
            .collect()
    }

    /// Validates a sender's broadcast. The sender and framing checks
    /// attribute no blame; the two cryptographic checks bind the broadcast to the public-key share
    /// the sender was registered with and do.
    fn validate_broadcast(
        &self,
        from: NonZeroU16,
        commitments: &BroadcastMessage<C>,
    ) -> MessageResult<()> {
        if from > self.reshare_senders.old_parameters.number_of_parties {
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
            != usize::from(self.reshare_senders.new_parameters.threshold.get())
        {
            return Err(MalformedMessageError::new(
                from,
                "commitment count does not match the local new threshold",
            )
            .into());
        }

        let proof_context = schnorr::proof_context(
            Self::CONTEXT_DOMAIN,
            &self.context,
            &[
                self.reshare_senders.old_parameters,
                self.reshare_senders.new_parameters,
            ],
        );
        if !commitments.nizk.verify(
            &proof_context,
            from,
            &commitments.commitments[0],
            &commitments.commitments[1..],
            // Commitment must match the public key share of the sender
        ) || commitments.commitments[0] != self.reshare_senders.senders[&from]
        {
            return Err(MaliciousPartyError::new(from).into());
        }
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
            let lambda = lagrange::single_lagrange_from_coeff::<C::ScalarField, u16>(
                party.get(),
                old_parties.iter().map(|party| party.get()),
            );
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

        for party_idx in self.reshare_senders.new_parameters.party_indices() {
            if party_idx == self.my_idx {
                continue;
            }
            let pk_share = self
                .received_shares
                .iter()
                .fold(C::zero(), |acc, (party, (_, com))| {
                    acc + lagrange::evaluate_polynomial_in_exponent::<C>(com, party_idx)
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
            context: self.context,
            threshold: self.reshare_senders.new_parameters.threshold,
            sk_share: my_secret_key_share,
            pk_shares: public_key_shares,
            pk: public_key,
            // Old-committee indices, ascending because `senders` is a `BTreeMap`.
            contributing_parties: old_parties,
        })
    }
}
