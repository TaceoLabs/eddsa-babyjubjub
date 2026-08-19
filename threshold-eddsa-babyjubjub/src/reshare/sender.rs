//! The senders in the `ReShare` protocol.
//!
//! A sender is one of the old parties handing the key over. It re-shares its own Shamir share of the
//! signing key with a fresh polynomial, broadcasts the commitments to that polynomial's
//! coefficients, and sends its evaluations to the parties in the new set.

use crate::{
    keygen::{
        SecretScalars,
        blame::{BlameRevelation, BlameVerdict, RevealedShare},
        schnorr::{self, SchnorrZkProof},
    },
    reshare::{BroadcastMessage, PartyMessage, sender_set::ReShareSenderSet},
    shamir::utils,
};
use ark_ec::CurveGroup;
use ark_ff::UniformRand;
use ark_serialize::CompressedChecked;
use eyre::Result;
use rand::{CryptoRng, Rng};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

/// The senders in the `ReShare` protocol are the "old" parties, i.e., the set of parties currently holding the shares.
///
/// The `ReShare` protocol lets the "old" parties re-share their secret key to a new set of parties (which may be overlapping the current set of parties.)
pub struct ReShareProtocolSender<C: CurveGroup> {
    session_id: Uuid,
    my_idx: u16,
    coefficients: SecretScalars<C::ScalarField>,
    commitments: Vec<C::Affine>,
    nizk: SchnorrZkProof<C>,
    reshare_set: ReShareSenderSet<C>,
    verdicts: BTreeMap<u16, BlameVerdict>,
    excluded_verdict_parties: BTreeSet<u16>,
}

impl<C: CurveGroup> ReShareProtocolSender<C> {
    pub(super) const CONTEXT_DOMAIN: &'static [u8] = b"PEDPOP_RESHARE_V1";

    /// Construct a new [`ReShareProtocolSender`] for the old party with index `party_index`.
    ///
    /// `my_share` is this party's Shamir share of the signing key as held under the old
    /// [`Parameters`](crate::keygen::Parameters). Both the old and the new parameters, as well as
    /// the set of old parties handing the key over, are taken from `reshare_set`.
    ///
    /// # Errors
    /// Returns an error if `party_index` is zero or larger than the number of parties allowed by the
    /// old [`Parameters`](crate::keygen::Parameters).
    pub fn new<R: Rng + CryptoRng>(
        party_index: u16,
        my_share: &C::ScalarField,
        reshare_set: ReShareSenderSet<C>,
        session_id: Uuid,
        rng: &mut R,
    ) -> Result<Self> {
        let old_params = reshare_set.old_parameters;
        let new_params = reshare_set.new_parameters;
        if party_index == 0 {
            eyre::bail!("party index must be non-zero",);
        }
        if party_index > old_params.number_of_parties {
            eyre::bail!("provided party index {party_index} is larger than old parameters allow",);
        }
        reshare_set.correct()?;
        let Some(expected_public_share) = reshare_set.senders.get(&party_index) else {
            eyre::bail!("party index {party_index} is not a selected reshare sender");
        };
        if (C::generator() * my_share).into_affine() != *expected_public_share {
            eyre::bail!("secret share does not match party {party_index}'s public share");
        }

        let coefficients = SecretScalars(
            std::iter::once(*my_share)
                .chain((1..=new_params.degree()).map(|_| C::ScalarField::rand(rng)))
                .collect::<Vec<_>>(),
        );

        let commitments = coefficients
            .iter()
            .map(|a_k| (C::generator() * a_k).into_affine())
            .collect::<Vec<_>>();

        let context =
            schnorr::proof_context(Self::CONTEXT_DOMAIN, session_id, &[old_params, new_params]);
        let nizk = SchnorrZkProof::<C>::new(
            &context,
            party_index,
            &coefficients[0],
            &commitments[0],
            &commitments[1..],
            rng,
        );

        Ok(ReShareProtocolSender {
            session_id,
            my_idx: party_index,
            coefficients,
            commitments,
            nizk,
            reshare_set,
            verdicts: BTreeMap::new(),
            excluded_verdict_parties: BTreeSet::new(),
        })
    }

    /// Returns the message that must be broadcast to all other participants in this round.
    pub fn get_broadcast_message(&self) -> BroadcastMessage<C> {
        BroadcastMessage {
            session_id: self.session_id,
            commitments: CompressedChecked(self.commitments.clone()),
            nizk: self.nizk.clone(),
        }
    }

    /// Retrieve the communication for the second round to be sent *privately* to the party with index `for_party` from the new set of parties.
    ///
    /// This has to be called for each other party participating in the protocol to retrieve the message intended for this party.
    /// The message has to be sent using a private communication channel, and should not be available to other parties.
    ///
    /// # Errors
    /// Returns an error if `for_party` is not a valid party index for the new
    /// [`Parameters`](crate::keygen::Parameters).
    pub fn get_party_communication(&self, for_party: u16) -> Result<PartyMessage<C>> {
        if for_party == 0 {
            eyre::bail!("party index must be non-zero",);
        }
        if for_party > self.reshare_set.new_parameters.number_of_parties {
            eyre::bail!("provided party index {for_party} is larger than new parameters allow",);
        }
        let secret_share =
            utils::evaluate_poly(&self.coefficients, C::ScalarField::from(for_party));

        Ok(PartyMessage {
            session_id: self.session_id,
            secret_share,
        })
    }

    /// Add a new party's blame verdict broadcast.
    ///
    /// The sender derives the set of accusers it must answer from these verdicts, so they require
    /// the same reliable broadcast and sender authentication as on the receiver side. Bind the
    /// externally authenticated identity to `from`.
    ///
    /// # Errors
    /// Returns an error for an invalid, duplicate, or already-excluded new party, a session
    /// mismatch, or a verdict blaming an old party outside the selected sender set.
    pub fn add_verdict(&mut self, from: u16, verdict: BlameVerdict) -> Result<()> {
        if from == 0 {
            eyre::bail!("party index must be non-zero",);
        }
        if from > self.reshare_set.new_parameters.number_of_parties {
            eyre::bail!("new party index {from} invalid for the new parameters");
        }
        if self.excluded_verdict_parties.contains(&from) {
            eyre::bail!("new party {from}'s verdict was already excluded");
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
            .any(|sender| !self.reshare_set.senders.contains_key(sender))
        {
            eyre::bail!("verdict from new party {from} blames an unselected old sender");
        }
        self.verdicts.insert(from, verdict);
        Ok(())
    }

    /// New parties whose verdict broadcast is still missing.
    #[must_use]
    pub fn missing_verdicts(&self) -> Vec<u16> {
        (1..=self.reshare_set.new_parameters.number_of_parties)
            .filter(|party| !self.verdicts.contains_key(party))
            .filter(|party| !self.excluded_verdict_parties.contains(party))
            .collect()
    }

    /// Whether every new party's verdict has been received or externally excluded.
    #[must_use]
    pub fn verdicts_complete(&self) -> bool {
        self.missing_verdicts().is_empty()
    }

    /// Ignore a new party that missed the externally agreed verdict deadline.
    ///
    /// Every honest participant must apply the identical exclusion set, matching
    /// [`ReShareBlameRound::disqualify_missing_verdict`](crate::reshare::blame::ReShareBlameRound::disqualify_missing_verdict).
    /// A sender that applies a different set derives a different accuser set and is disqualified by
    /// the receivers for an inconsistent revelation.
    ///
    /// # Errors
    /// Returns an error for an invalid new party, one whose verdict was already accepted or
    /// excluded, or if the exclusion would leave fewer than the new threshold of receivers.
    pub fn exclude_missing_verdict(&mut self, party: u16) -> Result<()> {
        if party == 0 || party > self.reshare_set.new_parameters.number_of_parties {
            eyre::bail!("new party index {party} invalid for the new parameters");
        }
        if self.verdicts.contains_key(&party) {
            eyre::bail!("new party {party}'s verdict was already accepted");
        }
        if self.excluded_verdict_parties.contains(&party) {
            eyre::bail!("new party {party}'s verdict was already excluded");
        }
        let remaining = usize::from(self.reshare_set.new_parameters.number_of_parties)
            - self.excluded_verdict_parties.len()
            - 1;
        if remaining < usize::from(self.reshare_set.new_parameters.threshold) {
            eyre::bail!("verdict exclusion would leave fewer than the threshold receivers");
        }
        self.excluded_verdict_parties.insert(party);
        Ok(())
    }

    /// Reveal the committed polynomial evaluation for every new party that accused this sender.
    ///
    /// The accuser set is derived from the verdicts collected with
    /// [`ReShareProtocolSender::add_verdict`] and is never supplied by the caller: an accuser that
    /// did not broadcast a blaming verdict is never answered. Returns `None` when no new party
    /// accused this sender.
    ///
    /// The constant term of the resharing polynomial is this sender's secret key share, so
    /// revealing `new_parameters.threshold` evaluations would let any observer interpolate it. At
    /// that point the sender refuses: either it really is malicious and being disqualified is the
    /// correct outcome, or the accusers form a threshold-sized coalition that can already
    /// reconstruct the key from their own new shares. Disqualification is never worse than
    /// disclosure.
    ///
    /// # Errors
    /// Returns an error until every new party's verdict has been received or externally excluded,
    /// or if answering the accusers would disclose the secret key share.
    pub fn get_blame_revelation(&self) -> Result<Option<BlameRevelation<C>>> {
        if !self.verdicts_complete() {
            eyre::bail!("cannot reveal before every new party's verdict is received or excluded");
        }
        let accusers = self
            .verdicts
            .iter()
            .filter(|(_, verdict)| verdict.blamed_parties.contains(&self.my_idx))
            .map(|(accuser, _)| *accuser)
            .collect::<BTreeSet<_>>();
        if accusers.is_empty() {
            return Ok(None);
        }
        let threshold = usize::from(self.reshare_set.new_parameters.threshold);
        if accusers.len() >= threshold {
            eyre::bail!(
                "refusing to reveal {} evaluations of a degree-{} polynomial: at the new threshold \
                 of {threshold} this would disclose party {}'s secret key share",
                accusers.len(),
                self.reshare_set.new_parameters.degree(),
                self.my_idx,
            );
        }
        let shares = accusers
            .iter()
            .map(|receiver| RevealedShare {
                receiver: *receiver,
                share: utils::evaluate_poly(&self.coefficients, C::ScalarField::from(*receiver)),
            })
            .collect();
        Ok(Some(BlameRevelation {
            session_id: self.session_id,
            shares,
        }))
    }
}
