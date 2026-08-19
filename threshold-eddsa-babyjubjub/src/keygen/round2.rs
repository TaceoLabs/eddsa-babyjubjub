//! The second round of the DKG protocol.
//!
//! In this round every party sends the evaluation of its polynomial to the respective party over a
//! private channel, which the receiving party verifies against the commitments from the first round.

use crate::{
    keygen::{
        MalformedMessageError, MaliciousPartyError, MessageError, MessageResult, Parameters,
        SecretScalarMap, SecretScalars, blame::BlameRound, finished::Finished,
    },
    shamir::utils,
};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use uuid::Uuid;

/// The state of the DKG protocol in the second round.
///
/// In this round each party sends the evaluation of its polynomial to the respective party over a
/// private channel, and checks the shares it receives against the commitments broadcast in the
/// first round.
pub struct RoundTwo<C: CurveGroup> {
    pub(crate) session_id: Uuid,
    pub(crate) commitments: HashMap<u16, Vec<C::Affine>>,
    pub(crate) secret_shares: SecretScalars<C::ScalarField>,
    pub(crate) my_idx: u16,
    pub(crate) params: Parameters,
    pub(crate) received_party_messages: SecretScalarMap<C::ScalarField>,
    pub(crate) failed_parties: BTreeSet<u16>,
    pub(crate) disqualified_parties: BTreeSet<u16>,
}

/// Communication in the second round of the DKG protocol.
/// This communication is intended to be sent *privately* to a specific other party.
#[derive(Serialize, Deserialize)]
pub struct RoundTwoCommunication<C: CurveGroup> {
    pub(crate) session_id: Uuid,
    #[serde(with = "ark_serde_compat::field")]
    pub(crate) secret_share: C::ScalarField,
}

impl<C: CurveGroup> Drop for RoundTwoCommunication<C> {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.secret_share.zeroize();
    }
}

impl<C: CurveGroup> RoundTwo<C> {
    /// Retrieve the communication for the second round to be sent *privately* to the party with index `for_party`.
    ///
    /// This has to be called for each other party participating in the protocol to retrieve the message intended for this party.
    /// The message has to be sent using a private communication channel, and should not be available to other parties.
    ///
    /// # Errors
    /// Returns an error if `for_party` is not a valid party index for the used [`Parameters`] or
    /// if that party was disqualified in round one.
    pub fn get_party_communication(&self, for_party: u16) -> Result<RoundTwoCommunication<C>> {
        if for_party == 0 {
            eyre::bail!("party index must be non-zero",);
        }
        if self.disqualified_parties.contains(&for_party) {
            eyre::bail!("party {for_party} was disqualified in round one");
        }
        let idx = usize::from(for_party) - 1;
        let secret_share = *self.secret_shares.get(idx).ok_or(eyre::eyre!(
            "party index {for_party} invalid for used parameters"
        ))?;

        Ok(RoundTwoCommunication {
            session_id: self.session_id,
            secret_share,
        })
    }

    /// Add a [`RoundTwoCommunication`] received from a party, verifying that everything is in order.
    ///
    /// # Errors
    /// Returns [`MessageError::MaliciousParty`] if the secret share does not verify against the
    /// commitments the sender broadcast in round one; this attributes blame.
    /// [`MessageError::Malformed`] (session id mismatch) and [`MessageError::LocalFault`] (invalid
    /// sender, unqualified dealer, duplicate delivery) do not.
    pub fn add_party_communication(
        &mut self,
        from: u16,
        comm: &RoundTwoCommunication<C>,
    ) -> MessageResult<()> {
        self.validate_message(from, comm)?;

        if !utils::verify_polynomial_evaluation::<C>(
            &self.commitments[&from],
            self.my_idx,
            &comm.secret_share,
        ) {
            return Err(MaliciousPartyError::new(from as usize).into());
        }
        self.received_party_messages.insert(from, comm.secret_share);
        Ok(())
    }

    /// Add a private share while retaining malformed shares for the optional public blame round.
    ///
    /// Unlike [`RoundTwo::add_party_communication`], a share that fails its polynomial equation is
    /// recorded as a complaint rather than returning [`MessageError::MaliciousParty`]. Structural
    /// errors, duplicate messages, and session mismatches still return an error.
    ///
    /// # Errors
    /// Returns [`MessageError::Malformed`] for a session mismatch and [`MessageError::LocalFault`]
    /// for an invalid sender or duplicate communication. Neither attributes blame.
    pub fn add_party_communication_for_blame(
        &mut self,
        from: u16,
        comm: &RoundTwoCommunication<C>,
    ) -> MessageResult<()> {
        self.validate_message(from, comm)?;

        if !utils::verify_polynomial_evaluation::<C>(
            &self.commitments[&from],
            self.my_idx,
            &comm.secret_share,
        ) {
            self.failed_parties.insert(from);
        }
        self.received_party_messages.insert(from, comm.secret_share);
        Ok(())
    }

    /// Checks shared by both intake paths: nothing here inspects the share itself, so no rejection
    /// attributes blame.
    fn validate_message(&self, from: u16, comm: &RoundTwoCommunication<C>) -> MessageResult<()> {
        if from == 0 {
            return Err(MessageError::local(
                "party index must be non-zero".to_owned(),
            ));
        }
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
        if !self.commitments.contains_key(&from) {
            return Err(MessageError::local(format!(
                "party {from} is not a qualified dealer"
            )));
        }
        if self.received_party_messages.contains_key(&from) {
            return Err(MessageError::local(format!(
                "already added message for party {from}"
            )));
        }
        if self.session_id != comm.session_id {
            return Err(MalformedMessageError::new(
                from as usize,
                "session id does not match the local session",
            )
            .into());
        }
        Ok(())
    }

    /// Returns a list of party indices for which we have not yet received and added a [`RoundTwoCommunication`] message.
    #[must_use]
    pub fn get_missing_parties(&self) -> Vec<u16> {
        self.commitments
            .keys()
            .filter(|idx| **idx != self.my_idx)
            .filter(|idx| !self.received_party_messages.contains_key(idx))
            .copied()
            .collect()
    }

    /// Turn an externally confirmed missing private share into a public complaint.
    ///
    /// The placeholder is never used as output: [`RoundTwo::finalize`] rejects unresolved
    /// complaints and the blame round either replaces it with a valid revelation or disqualifies
    /// the dealer.
    ///
    /// # Errors
    /// Returns an error for an invalid dealer or if that dealer's share was already received.
    pub fn complain_missing_party(&mut self, from: u16) -> Result<()> {
        if from == self.my_idx || !self.commitments.contains_key(&from) {
            eyre::bail!("invalid dealer for a missing-share complaint");
        }
        if self.received_party_messages.contains_key(&from) {
            eyre::bail!("dealer {from}'s private share was already received");
        }
        self.failed_parties.insert(from);
        self.received_party_messages
            .insert(from, C::ScalarField::zero());
        Ok(())
    }

    /// Indicates if the protocol is ready to advance into the next state.
    /// See [`RoundTwo::get_missing_parties`] for parties we are still missing information from.
    #[must_use]
    pub fn can_advance(&self) -> bool {
        self.received_party_messages.len() == self.commitments.len() - 1
    }

    /// Try to finalize the DKG protocol, putting it in a state where the results of the protocol can be obtained.
    ///
    /// # Errors
    /// Returns an error if not all [`RoundTwoCommunication`] messages have been added yet, i.e., if
    /// [`RoundTwo::can_advance`] returns false.
    pub fn finalize(self) -> Result<Finished<C>> {
        if !self.can_advance() {
            eyre::bail!("cannot finalize, not all messages received");
        }
        if !self.failed_parties.is_empty() {
            eyre::bail!("cannot finalize with unresolved complaints; enter the blame round");
        }

        let my_secret_key_share = self
            .received_party_messages
            .values()
            .fold(self.secret_shares[self.my_idx as usize - 1], |acc, x| {
                acc + x
            });
        let my_public_key_share = (C::generator() * my_secret_key_share).into_affine();

        let mut public_key_shares = HashMap::new();
        public_key_shares.insert(self.my_idx, my_public_key_share);

        for party_idx in (1..=self.params.number_of_parties)
            .filter(|party| !self.disqualified_parties.contains(party))
        {
            if party_idx == self.my_idx {
                continue;
            }
            let pk_share = self.commitments.values().fold(C::zero(), |acc, x| {
                acc + utils::evaluate_polynomial_in_exponent::<C>(x, party_idx)
            });
            public_key_shares.insert(party_idx, pk_share.into_affine());
        }

        let public_key = self
            .commitments
            .values()
            .fold(C::zero(), |acc, x| acc + x[0]);

        // `commitments` is a `HashMap`; sort so the reported set is comparable across parties.
        let mut contributing_parties = self.commitments.keys().copied().collect::<Vec<_>>();
        contributing_parties.sort_unstable();

        Ok(Finished {
            contributing_parties,
            my_idx: self.my_idx,
            session_id: self.session_id,
            sk_share: my_secret_key_share,
            pk_shares: public_key_shares,
            pk: public_key.into_affine(),
        })
    }

    /// Enter the optional public blame round after collecting every private share.
    ///
    /// # Errors
    /// Returns an error unless all round-two communications have been collected.
    pub fn blame_round(self) -> Result<BlameRound<C>> {
        BlameRound::new(self)
    }
}
