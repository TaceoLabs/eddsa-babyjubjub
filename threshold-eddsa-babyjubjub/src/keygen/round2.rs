//! The second round of the DKG protocol.
//!
//! In this round every party sends the evaluation of its polynomial to the respective party over a
//! private channel, which the receiving party verifies against the commitments from the first round.

use crate::keygen::{MaliciousPartyError, Parameters, finished::Finished};
use ark_ec::CurveGroup;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// The state of the DKG protocol in the second round.
///
/// In this round each party sends the evaluation of its polynomial to the respective party over a
/// private channel, and checks the shares it receives against the commitments broadcast in the
/// first round.
pub struct RoundTwo<C: CurveGroup> {
    pub(crate) session_id: Uuid,
    pub(crate) commitments: HashMap<u16, Vec<C::Affine>>,
    pub(crate) secret_shares: Vec<C::ScalarField>,
    pub(crate) my_idx: u16,
    pub(crate) params: Parameters,
    pub(crate) received_party_messages: HashMap<u16, C::ScalarField>,
}

/// Communication in the second round of the DKG protocol.
/// This communication is intended to be sent *privately* to a specific other party.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoundTwoCommunication<C: CurveGroup> {
    session_id: Uuid,
    #[serde(with = "ark_serde_compat::field")]
    secret_share: C::ScalarField,
}

impl<C: CurveGroup> RoundTwo<C> {
    fn evaluate_polynomial_in_exponent(coefficients: &[C::Affine], party_idx: u16) -> C {
        debug_assert!(party_idx > 0, "party index must be non-zero");
        // since the party index is non-zero, this is non zero
        let x = C::ScalarField::from(u64::from(party_idx));

        let mut result = C::zero();

        // evaluate the poly using Horner's algorithm
        for (idx, coeff) in coefficients.iter().rev().enumerate() {
            // skip first mult
            if idx != 0 {
                result *= &x;
            }
            result += coeff;
        }

        result
    }

    fn verify_polynomial_evaluation(
        commitments: &[C::Affine],
        party_idx: u16,
        share: &C::ScalarField,
    ) -> bool {
        let result = Self::evaluate_polynomial_in_exponent(commitments, party_idx);
        result == C::generator() * share
    }

    /// Retrieve the communication for the second round to be sent *privately* to the party with index `for_party`.
    ///
    /// This has to be called for each other party participating in the protocol to retrieve the message intended for this party.
    /// The message has to be sent using a private communication channel, and should not be available to other parties.
    ///
    /// # Errors
    /// Returns an error if `for_party` is not a valid party index for the used [`Parameters`].
    pub fn get_party_communication(&self, for_party: u16) -> Result<RoundTwoCommunication<C>> {
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
    /// Returns a [`MaliciousPartyError`] identifying the offending party if its message carries a
    /// different session id, or a secret share that does not verify against the commitments this
    /// party broadcast in the first round.
    /// All other errors indicate an invalid `from` index and are usually the fault of the local
    /// party.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "Keeps consistency with the first round, where the message is consumed"
    )]
    pub fn add_party_communication(
        &mut self,
        from: u16,
        comm: RoundTwoCommunication<C>,
    ) -> Result<()> {
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
            eyre::bail!("already added message for party {from}",);
        }

        if self.session_id != comm.session_id {
            eyre::bail!(MaliciousPartyError::new(from as usize));
        }

        if !Self::verify_polynomial_evaluation(
            &self.commitments[&from],
            self.my_idx,
            &comm.secret_share,
        ) {
            eyre::bail!(MaliciousPartyError::new(from as usize));
        }
        self.received_party_messages.insert(from, comm.secret_share);
        Ok(())
    }

    /// Returns a list of party indices for which we have not yet received and added a [`RoundTwoCommunication`] message.
    #[must_use]
    pub fn get_missing_parties(&self) -> Vec<u16> {
        (1..=self.params.number_of_parties)
            .filter(|idx| *idx != self.my_idx)
            .filter(|idx| !self.received_party_messages.contains_key(idx))
            .collect()
    }

    /// Indicates if the protocol is ready to advance into the next state.
    /// See [`RoundTwo::get_missing_parties`] for parties we are still missing information from.
    #[must_use]
    pub fn can_advance(&self) -> bool {
        self.received_party_messages.len() == usize::from(self.params.number_of_parties) - 1
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

        let my_secret_key_share = self
            .received_party_messages
            .values()
            .fold(self.secret_shares[self.my_idx as usize - 1], |acc, x| {
                acc + x
            });
        let my_public_key_share = (C::generator() * my_secret_key_share).into_affine();

        let mut public_key_shares = HashMap::new();
        public_key_shares.insert(self.my_idx, my_public_key_share);

        for party_idx in 1..=self.params.number_of_parties {
            if party_idx == self.my_idx {
                continue;
            }
            let pk_share = self.commitments.values().fold(C::zero(), |acc, x| {
                acc + Self::evaluate_polynomial_in_exponent(x, party_idx)
            });
            public_key_shares.insert(party_idx, pk_share.into_affine());
        }

        let public_key = self
            .commitments
            .values()
            .fold(C::zero(), |acc, x| acc + x[0]);

        Ok(Finished {
            session_id: self.session_id,
            sk_share: my_secret_key_share,
            pk_shares: public_key_shares,
            pk: public_key.into_affine(),
        })
    }
}
