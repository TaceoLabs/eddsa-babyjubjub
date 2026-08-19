//! Optional public complaint round for resharing.
//!
//! New parties first broadcast either `Ok` or the old senders whose private evaluations failed.
//! Every accused old sender then reveals the committed evaluation for each accuser.

use crate::{
    keygen::{
        Parameters,
        blame::{BlameResult, BlameRevelation, BlameVerdict},
        finished::Finished,
    },
    reshare::{receiver::ReShareProtocolReceiver, sender_set::ReShareSenderSet},
    shamir::utils,
};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use eyre::Result;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use uuid::Uuid;

/// Receiver-side state for the optional resharing blame round.
pub struct ReShareBlameRound<C: CurveGroup> {
    my_idx: u16,
    received_shares: HashMap<u16, (C::ScalarField, Vec<C::Affine>)>,
    reshare_senders: ReShareSenderSet<C>,
    session_id: Uuid,
    verdicts: BTreeMap<u16, BlameVerdict>,
    resolved_senders: BTreeSet<u16>,
    disqualified_senders: BTreeSet<u16>,
}

impl<C: CurveGroup> ReShareBlameRound<C> {
    pub(crate) fn new(receiver: ReShareProtocolReceiver<C>) -> Result<Self> {
        if !receiver.can_advance() {
            eyre::bail!("cannot enter reshare blame round before all sender messages arrive");
        }
        let own_verdict = BlameVerdict {
            session_id: receiver.session_id,
            blamed_parties: receiver.failed_senders,
        };
        let mut verdicts = BTreeMap::new();
        verdicts.insert(receiver.my_idx, own_verdict);

        Ok(Self {
            my_idx: receiver.my_idx,
            received_shares: receiver.received_shares,
            reshare_senders: receiver.reshare_senders,
            session_id: receiver.session_id,
            verdicts,
            resolved_senders: BTreeSet::new(),
            disqualified_senders: BTreeSet::new(),
        })
    }

    /// Return this new party's `Ok` or blame-set broadcast.
    #[must_use]
    pub fn verdict(&self) -> BlameVerdict {
        self.verdicts[&self.my_idx].clone()
    }

    /// Add another new party's verdict broadcast.
    ///
    /// # Errors
    /// Returns an error for invalid or duplicate senders, a wrong session, or a blamed ID outside
    /// the selected old-sender set.
    pub fn add_verdict(&mut self, from: u16, verdict: BlameVerdict) -> Result<()> {
        if from == 0 {
            eyre::bail!("party index must be non-zero",);
        }
        if from > self.reshare_senders.new_parameters.number_of_parties {
            eyre::bail!("party index {from} invalid for parameters",);
        }
        if from == self.my_idx {
            eyre::bail!("do not add own verdict");
        }
        if self.verdicts.contains_key(&from) {
            eyre::bail!("already added verdict from new party {from}");
        }
        if verdict.session_id != self.session_id {
            eyre::bail!("session id mismatch in verdict from new party {from}");
        }
        if verdict
            .blamed_parties
            .iter()
            .any(|sender| !self.reshare_senders.senders.contains_key(sender))
        {
            eyre::bail!("verdict from new party {from} blames an unselected old sender");
        }
        self.verdicts.insert(from, verdict);
        Ok(())
    }

    /// New parties whose verdict broadcasts are still missing.
    #[must_use]
    pub fn missing_verdicts(&self) -> Vec<u16> {
        (1..=self.reshare_senders.new_parameters.number_of_parties)
            .filter(|party| !self.verdicts.contains_key(party))
            .collect()
    }

    /// Whether every party's `Ok` or blame-set broadcast has been received.
    #[must_use]
    pub fn verdicts_complete(&self) -> bool {
        self.verdicts.len() == usize::from(self.reshare_senders.new_parameters.number_of_parties)
    }

    /// Map every accused old sender to the new parties accusing it.
    ///
    /// # Errors
    /// Returns an error until every new party's verdict has arrived.
    pub fn accusations(&self) -> Result<BTreeMap<u16, BTreeSet<u16>>> {
        if !self.verdicts_complete() {
            eyre::bail!("cannot determine accusations before all verdicts are received");
        }
        let mut accusations = BTreeMap::<u16, BTreeSet<u16>>::new();
        for (&receiver, verdict) in &self.verdicts {
            for &sender in &verdict.blamed_parties {
                accusations.entry(sender).or_default().insert(receiver);
            }
        }
        Ok(accusations)
    }

    /// Add and verify an accused old sender's public revelation.
    ///
    /// A valid revelation replaces this receiver's private value where applicable. A malformed
    /// broadcast or failed polynomial equation disqualifies the old sender.
    ///
    /// # Errors
    /// Returns an error for an unselected or unaccused sender or duplicate resolution.
    pub fn add_revelation(&mut self, from: u16, revelation: &BlameRevelation<C>) -> Result<()> {
        if !self.reshare_senders.senders.contains_key(&from) {
            eyre::bail!("old party {from} is not a selected sender");
        }
        let accusations = self.accusations()?;
        let Some(expected_receivers) = accusations.get(&from) else {
            eyre::bail!("old sender {from} was not accused");
        };
        if self.resolved_senders.contains(&from) {
            eyre::bail!("old sender {from}'s accusation was already resolved");
        }
        let receivers = revelation
            .shares
            .iter()
            .map(|share| share.receiver)
            .collect::<BTreeSet<_>>();
        let structurally_valid = revelation.session_id == self.session_id
            && receivers.len() == revelation.shares.len()
            && &receivers == expected_receivers;
        let equations_valid = structurally_valid
            && revelation.shares.iter().all(|share| {
                utils::verify_polynomial_evaluation::<C>(
                    &self.received_shares[&from].1,
                    share.receiver,
                    &share.share,
                )
            });
        if equations_valid {
            if let Some(share) = revelation
                .shares
                .iter()
                .find(|share| share.receiver == self.my_idx)
                && let Some(received) = self.received_shares.get_mut(&from)
            {
                received.0 = share.share;
            }
        } else {
            self.disqualified_senders.insert(from);
        }
        self.resolved_senders.insert(from);
        Ok(())
    }

    /// Disqualify an accused sender that missed an externally enforced revelation deadline.
    ///
    /// # Errors
    /// Returns an error for an unaccused sender or duplicate resolution.
    pub fn disqualify_missing_sender(&mut self, sender: u16) -> Result<()> {
        if !self.accusations()?.contains_key(&sender) {
            eyre::bail!("old sender {sender} was not accused");
        }
        if !self.resolved_senders.insert(sender) {
            eyre::bail!("old sender {sender}'s accusation was already resolved");
        }
        self.disqualified_senders.insert(sender);
        Ok(())
    }

    /// Accused old senders whose revelation or timeout resolution is still missing.
    ///
    /// # Errors
    /// Returns an error until all verdicts arrive.
    pub fn missing_revelations(&self) -> Result<Vec<u16>> {
        Ok(self
            .accusations()?
            .keys()
            .filter(|sender| !self.resolved_senders.contains(sender))
            .copied()
            .collect())
    }

    /// Finalize using the surviving old senders and freshly recomputed Lagrange coefficients.
    ///
    /// # Errors
    /// Returns an error while messages remain unresolved, if fewer than the old threshold senders
    /// survive, or if their constant commitments do not reconstruct the original public key.
    pub fn finalize(self) -> Result<BlameResult<C>> {
        if !self.verdicts_complete() {
            eyre::bail!("cannot finalize before all verdicts are received");
        }
        if !self.missing_revelations()?.is_empty() {
            eyre::bail!("cannot finalize before all accusations are resolved");
        }
        let qualified = self
            .reshare_senders
            .senders
            .keys()
            .filter(|sender| !self.disqualified_senders.contains(sender))
            .copied()
            .collect::<Vec<_>>();
        if qualified.len() < usize::from(self.reshare_senders.old_parameters.threshold) {
            eyre::bail!("not enough qualified old senders remain after blame round");
        }

        let lagrange = qualified
            .iter()
            .map(|sender| {
                (
                    *sender,
                    utils::single_lagrange_from_coeff::<C::ScalarField, _>(*sender, &qualified),
                )
            })
            .collect::<HashMap<_, _>>();

        let my_secret_key_share = qualified
            .iter()
            .fold(C::ScalarField::zero(), |acc, sender| {
                acc + lagrange[sender] * self.received_shares[sender].0
            });
        let public_key = qualified.iter().fold(C::zero(), |acc, sender| {
            acc + self.received_shares[sender].1[0] * lagrange[sender]
        });
        if public_key.into_affine() != self.reshare_senders.pk {
            eyre::bail!("qualified old senders do not reconstruct the original public key");
        }

        let public_key_shares = (1..=self.reshare_senders.new_parameters.number_of_parties)
            .map(|receiver| {
                let share = qualified.iter().fold(C::zero(), |acc, sender| {
                    acc + utils::evaluate_polynomial_in_exponent::<C>(
                        &self.received_shares[sender].1,
                        receiver,
                    ) * lagrange[sender]
                });
                (receiver, share.into_affine())
            })
            .collect();

        Ok(BlameResult {
            finished: Finished {
                my_idx: self.my_idx,
                session_id: self.session_id,
                sk_share: my_secret_key_share,
                pk_shares: public_key_shares,
                pk: self.reshare_senders.pk,
            },
            disqualified_parties: self.disqualified_senders.into_iter().collect(),
        })
    }

    /// Parameters of the old sharing.
    #[must_use]
    pub fn old_parameters(&self) -> Parameters {
        self.reshare_senders.old_parameters
    }
}
