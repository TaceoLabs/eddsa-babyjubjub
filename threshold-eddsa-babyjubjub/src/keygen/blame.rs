//! Optional public complaint and blame round for distributed key generation.
//!
//! Parties first broadcast either `Ok` or the set of dealers whose private shares failed
//! verification. Every accused dealer then broadcasts the committed share for each accuser. All
//! parties verify those revelations against the dealer's polynomial commitments.

use crate::{
    keygen::{Parameters, SecretScalarMap, SecretScalars, finished::Finished, round2::RoundTwo},
    shamir::utils,
};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use eyre::Result;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use uuid::Uuid;

/// A party's first broadcast in the blame round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlameVerdict {
    pub(crate) session_id: Uuid,
    #[serde(deserialize_with = "crate::serde_utils::deserialize_protocol_btree_set")]
    pub(crate) blamed_parties: BTreeSet<u16>,
}

impl BlameVerdict {
    /// Returns the parties accused by this verdict. An empty set represents `Ok`.
    #[must_use]
    pub fn blamed_parties(&self) -> &BTreeSet<u16> {
        &self.blamed_parties
    }

    /// Returns whether the sender reported that every private share was valid.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.blamed_parties.is_empty()
    }
}

/// One private polynomial evaluation made public in response to a complaint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealedShare<C: CurveGroup> {
    pub(crate) receiver: u16,
    #[serde(with = "ark_serde_compat::field")]
    pub(crate) share: C::ScalarField,
}

/// An accused dealer's share-revelation broadcast in the blame round.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlameRevelation<C: CurveGroup> {
    pub(crate) session_id: Uuid,
    #[serde(
        serialize_with = "crate::serde_utils::serialize_protocol_vec",
        deserialize_with = "crate::serde_utils::deserialize_protocol_vec"
    )]
    pub(crate) shares: Vec<RevealedShare<C>>,
}

/// Successful output of DKG or resharing that used the optional blame round.
#[non_exhaustive]
pub struct BlameResult<C: CurveGroup> {
    /// The ordinary finalized DKG output, computed without disqualified dealer contributions.
    pub finished: Finished<C>,
    /// DKG dealers or old reshare senders excluded for invalid or missing protocol messages.
    ///
    /// Their polynomial contribution is dropped from the output. A DKG dealer disqualified in the
    /// blame round nonetheless remains a shareholder and keeps a `pk_shares` entry, because it can
    /// compute its share of the surviving aggregate polynomial regardless; exclude it from future
    /// signing committees at the application layer if that is the intent.
    pub disqualified_parties: Vec<u16>,
    /// Verdict participants omitted after an externally agreed timeout.
    ///
    /// This is empty for DKG. During resharing these are new receivers whose missing verdict was
    /// ignored for liveness; it does not revoke any key share they may already hold.
    pub excluded_verdict_parties: Vec<u16>,
}

/// State for the optional public DKG complaint and blame workflow.
pub struct BlameRound<C: CurveGroup> {
    session_id: Uuid,
    commitments: HashMap<u16, Vec<C::Affine>>,
    secret_shares: SecretScalars<C::ScalarField>,
    my_idx: u16,
    params: Parameters,
    received_party_messages: SecretScalarMap<C::ScalarField>,
    verdicts: BTreeMap<u16, BlameVerdict>,
    resolved_dealers: BTreeSet<u16>,
    disqualified_dealers: BTreeSet<u16>,
}

impl<C: CurveGroup> BlameRound<C> {
    pub(crate) fn new(round_two: RoundTwo<C>) -> Result<Self> {
        if !round_two.can_advance() {
            eyre::bail!("cannot enter blame round, not all private shares were received");
        }

        let own_verdict = BlameVerdict {
            session_id: round_two.session_id,
            blamed_parties: round_two.failed_parties,
        };
        let mut verdicts = BTreeMap::new();
        verdicts.insert(round_two.my_idx, own_verdict);

        Ok(Self {
            session_id: round_two.session_id,
            commitments: round_two.commitments,
            secret_shares: round_two.secret_shares,
            my_idx: round_two.my_idx,
            params: round_two.params,
            received_party_messages: round_two.received_party_messages,
            verdicts,
            resolved_dealers: BTreeSet::new(),
            disqualified_dealers: round_two.disqualified_parties,
        })
    }

    /// Return this party's `Ok` or blame-set broadcast.
    #[must_use]
    pub fn verdict(&self) -> BlameVerdict {
        self.verdicts[&self.my_idx].clone()
    }

    /// Add another party's verdict broadcast.
    ///
    /// # Errors
    /// Returns an error for an invalid sender, duplicate verdict, wrong session, or invalid blamed
    /// party identifier.
    pub fn add_verdict(&mut self, from: u16, verdict: BlameVerdict) -> Result<()> {
        self.validate_other_party(from)?;
        if !self.commitments.contains_key(&from) {
            eyre::bail!("party {from} was disqualified before the blame round");
        }
        if self.disqualified_dealers.contains(&from) {
            eyre::bail!("party {from} was disqualified after missing its blame verdict");
        }
        if self.verdicts.contains_key(&from) {
            eyre::bail!("already added blame verdict for party {from}");
        }
        if verdict.session_id != self.session_id {
            eyre::bail!("session id mismatch in blame verdict from party {from}");
        }
        if verdict.blamed_parties.iter().any(|party| {
            *party == 0
                || *party > self.params.number_of_parties
                || *party == from
                || !self.commitments.contains_key(party)
        }) {
            eyre::bail!("invalid blamed party in verdict from party {from}");
        }
        self.verdicts.insert(from, verdict);
        Ok(())
    }

    /// Parties whose first blame-round broadcasts are still missing.
    #[must_use]
    pub fn missing_verdicts(&self) -> Vec<u16> {
        self.commitments
            .keys()
            .filter(|party| !self.verdicts.contains_key(party))
            .filter(|party| !self.disqualified_dealers.contains(party))
            .copied()
            .collect()
    }

    /// Whether every party's `Ok` or blame-set broadcast has been received.
    #[must_use]
    pub fn verdicts_complete(&self) -> bool {
        self.missing_verdicts().is_empty()
    }

    /// Disqualify a dealer whose blame verdict was missing or rejected.
    ///
    /// All honest parties must apply the same decision after an externally agreed deadline. The
    /// dealer's polynomial contribution is excluded from the final DKG output.
    ///
    /// # Errors
    /// Returns an error for an invalid, pre-disqualified, local, already-resolved party, or a party
    /// whose verdict was already accepted. It also returns an error if disqualification would leave
    /// fewer than the configured threshold parties.
    pub fn disqualify_missing_verdict(&mut self, party: u16) -> Result<()> {
        self.validate_other_party(party)?;
        if !self.commitments.contains_key(&party) {
            eyre::bail!("party {party} was disqualified before the blame round");
        }
        if self.verdicts.contains_key(&party) {
            eyre::bail!("party {party}'s blame verdict was already accepted");
        }
        if self.disqualified_dealers.contains(&party) {
            eyre::bail!("party {party} was already disqualified");
        }
        let remaining = self
            .commitments
            .keys()
            .filter(|dealer| !self.disqualified_dealers.contains(dealer))
            .filter(|dealer| **dealer != party)
            .count();
        if remaining < usize::from(self.params.threshold) {
            eyre::bail!("verdict disqualification would leave fewer than the threshold parties");
        }
        self.disqualified_dealers.insert(party);
        self.resolved_dealers.insert(party);
        Ok(())
    }

    /// Return the map from every accused dealer to its accusers.
    ///
    /// # Errors
    /// Returns an error until all verdict broadcasts have been collected.
    pub fn accusations(&self) -> Result<BTreeMap<u16, BTreeSet<u16>>> {
        if !self.verdicts_complete() {
            eyre::bail!("cannot determine accusations before all verdicts are received");
        }
        let mut accusations = BTreeMap::<u16, BTreeSet<u16>>::new();
        for (&accuser, verdict) in &self.verdicts {
            for &dealer in &verdict.blamed_parties {
                accusations.entry(dealer).or_default().insert(accuser);
            }
        }
        Ok(accusations)
    }

    /// Create this dealer's revelation broadcast if another party accused it.
    ///
    /// The accuser set is derived from the verdicts collected with
    /// [`BlameRound::add_verdict`] and is never supplied by the caller, so a party that did not
    /// broadcast a blaming verdict is never answered.
    ///
    /// This does *not* mark the local dealer as resolved. Feed the revelation back through
    /// [`BlameRound::add_revelation`] as the broadcast channel actually delivered it, exactly as
    /// every other party does. Otherwise a dealer whose broadcast was corrupted or truncated in
    /// transit would judge itself qualified while everyone else disqualified it, and would silently
    /// end up holding a share of a different key.
    ///
    /// # Errors
    /// Returns an error until all verdict broadcasts have been collected, or if answering the
    /// accusers would reveal enough evaluations to interpolate this dealer's polynomial. The latter
    /// cannot happen while at most `threshold - 1` parties are corrupted, because an honest dealer
    /// is never accused by an honest party.
    pub fn revelation(&mut self) -> Result<Option<BlameRevelation<C>>> {
        let accusations = self.accusations()?;
        let Some(accusers) = accusations.get(&self.my_idx) else {
            return Ok(None);
        };
        let threshold = usize::from(self.params.threshold);
        if accusers.len() >= threshold {
            eyre::bail!(
                "refusing to reveal {} evaluations of a degree-{} polynomial: at a threshold of \
                 {threshold} this would disclose party {}'s polynomial",
                accusers.len(),
                self.params.degree(),
                self.my_idx,
            );
        }
        let shares = accusers
            .iter()
            .map(|receiver| RevealedShare {
                receiver: *receiver,
                share: self.secret_shares[usize::from(*receiver) - 1],
            })
            .collect();
        Ok(Some(BlameRevelation {
            session_id: self.session_id,
            shares,
        }))
    }

    /// Add and publicly verify an accused dealer's revelation broadcast.
    ///
    /// A dealer is disqualified if the broadcast is malformed or any revealed share fails its
    /// polynomial equation. A valid revelation replaces the private value held by its receiver.
    ///
    /// `from` may be the local party: an accused dealer must judge its own broadcast as the channel
    /// delivered it, so that it reaches the same verdict about itself as everyone else and cannot
    /// finalize onto a key the other parties are not using.
    ///
    /// # Errors
    /// Returns an error for an invalid sender, duplicate resolution, or an unaccused sender.
    /// Invalid revelations are recorded as dealer disqualifications.
    pub fn add_revelation(&mut self, from: u16, revelation: &BlameRevelation<C>) -> Result<()> {
        if from == 0 {
            eyre::bail!("party index must be non-zero");
        }
        if from > self.params.number_of_parties {
            eyre::bail!("party index {from} invalid for parameters");
        }
        if !self.commitments.contains_key(&from) {
            eyre::bail!("party {from} was disqualified before the blame round");
        }
        let accusations = self.accusations()?;
        let Some(expected_receivers) = accusations.get(&from) else {
            eyre::bail!("party {from} was not accused");
        };
        if self.resolved_dealers.contains(&from) {
            eyre::bail!("party {from}'s accusation was already resolved");
        }

        let revealed_receivers = revelation
            .shares
            .iter()
            .map(|revealed| revealed.receiver)
            .collect::<BTreeSet<_>>();
        let duplicate_receiver = revealed_receivers.len() != revelation.shares.len();
        let structurally_valid = revelation.session_id == self.session_id
            && !duplicate_receiver
            && &revealed_receivers == expected_receivers;
        let equations_valid = structurally_valid
            && revelation.shares.iter().all(|revealed| {
                utils::verify_polynomial_evaluation::<C>(
                    &self.commitments[&from],
                    revealed.receiver,
                    &revealed.share,
                )
            });

        if equations_valid {
            if let Some(revealed) = revelation
                .shares
                .iter()
                .find(|revealed| revealed.receiver == self.my_idx)
            {
                use zeroize::Zeroize as _;
                if let Some(mut previous) =
                    self.received_party_messages.insert(from, revealed.share)
                {
                    previous.zeroize();
                }
            }
        } else {
            self.disqualified_dealers.insert(from);
        }
        self.resolved_dealers.insert(from);
        Ok(())
    }

    /// Disqualify an accused dealer that failed to broadcast its shares before an externally
    /// enforced timeout. All parties must apply the same timeout decision to retain agreement.
    ///
    /// # Errors
    /// Returns an error if verdict collection is incomplete, the dealer was not accused, or its
    /// accusation was already resolved.
    pub fn disqualify_missing_dealer(&mut self, dealer: u16) -> Result<()> {
        if !self.accusations()?.contains_key(&dealer) {
            eyre::bail!("party {dealer} was not accused");
        }
        if !self.resolved_dealers.insert(dealer) {
            eyre::bail!("party {dealer}'s accusation was already resolved");
        }
        self.disqualified_dealers.insert(dealer);
        Ok(())
    }

    /// Accused dealers whose revelation or timeout resolution is still missing.
    ///
    /// # Errors
    /// Returns an error until all verdict broadcasts have been collected.
    pub fn missing_revelations(&self) -> Result<Vec<u16>> {
        Ok(self
            .accusations()?
            .keys()
            .filter(|dealer| !self.resolved_dealers.contains(dealer))
            .copied()
            .collect())
    }

    /// Finalize the DKG from all non-disqualified dealer contributions.
    ///
    /// A dealer disqualified during this blame round has its *polynomial* dropped from the aggregate,
    /// as `PedPoP` prescribes, but remains a *shareholder*: it completed round two, so it received
    /// every qualified dealer's evaluation and can compute its own share of the aggregate polynomial
    /// whether or not the honest parties record one for it. Withholding its public-key share would
    /// therefore buy no security while desynchronizing the views and shrinking the shareholder set.
    /// Its ID is still reported in [`BlameResult::disqualified_parties`], so an integrator that does
    /// not want a proven cheater in future signing committees can exclude it at that layer.
    ///
    /// Parties disqualified back in round one are a different case and are *not* shareholders: they
    /// never reached round two, so they hold nothing to build a share from.
    ///
    /// # Errors
    /// Returns an error until every verdict and required revelation has been processed, or if fewer
    /// than the threshold number of dealer contributions survive.
    pub fn finalize(self) -> Result<BlameResult<C>> {
        if !self.verdicts_complete() {
            eyre::bail!("cannot finalize before all verdicts are received");
        }
        if !self.missing_revelations()?.is_empty() {
            eyre::bail!("cannot finalize before all accusations are resolved");
        }

        // Everyone that completed round two, blame-disqualified dealers included.
        let shareholders = self.commitments.keys().copied().collect::<Vec<_>>();
        // `commitments` is a `HashMap`; sort so the reported set is comparable across parties.
        let mut qualified_dealers = self
            .commitments
            .keys()
            .filter(|dealer| !self.disqualified_dealers.contains(dealer))
            .copied()
            .collect::<Vec<_>>();
        qualified_dealers.sort_unstable();
        if qualified_dealers.len() < usize::from(self.params.threshold) {
            eyre::bail!("cannot finalize with fewer than the threshold qualified parties");
        }

        let my_secret_key_share =
            qualified_dealers
                .iter()
                .fold(C::ScalarField::zero(), |acc, dealer| {
                    if *dealer == self.my_idx {
                        acc + self.secret_shares[usize::from(self.my_idx) - 1]
                    } else {
                        acc + self.received_party_messages[dealer]
                    }
                });
        let mut public_key_shares = HashMap::new();
        for party in shareholders {
            let share = qualified_dealers
                .iter()
                .fold(C::zero(), |acc, dealer| {
                    acc + utils::evaluate_polynomial_in_exponent::<C>(
                        &self.commitments[dealer],
                        party,
                    )
                })
                .into_affine();
            public_key_shares.insert(party, share);
        }
        let public_key = qualified_dealers
            .iter()
            .fold(C::zero(), |acc, dealer| acc + self.commitments[dealer][0]);

        Ok(BlameResult {
            finished: Finished {
                my_idx: self.my_idx,
                session_id: self.session_id,
                sk_share: my_secret_key_share,
                pk_shares: public_key_shares,
                pk: public_key.into_affine(),
                contributing_parties: qualified_dealers,
            },
            disqualified_parties: self.disqualified_dealers.into_iter().collect(),
            excluded_verdict_parties: Vec::new(),
        })
    }

    fn validate_other_party(&self, from: u16) -> Result<()> {
        if from == 0 {
            eyre::bail!("party index must be non-zero",);
        }
        if from > self.params.number_of_parties {
            eyre::bail!("party index {from} invalid for parameters",);
        }
        if from == self.my_idx {
            eyre::bail!("do not add own party {from}'s broadcast");
        }
        Ok(())
    }
}
