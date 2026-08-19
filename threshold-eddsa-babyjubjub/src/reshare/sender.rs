//! The senders in the `ReShare` protocol.
//!
//! A sender is one of the old parties handing the key over. It re-shares its own Shamir share of the
//! signing key with a fresh polynomial, broadcasts the commitments to that polynomial's
//! coefficients, and sends its evaluations to the parties in the new set.

use crate::{
    keygen::{
        SecretScalars,
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
use uuid::Uuid;

/// The senders in the `ReShare` protocol are the "old" parties, i.e., the set of parties currently holding the shares.
///
/// The `ReShare` protocol lets the "old" parties re-share their secret key to a new set of parties (which may be overlapping the current set of parties.)
pub struct ReShareProtocolSender<C: CurveGroup> {
    session_id: Uuid,
    coefficients: SecretScalars<C::ScalarField>,
    commitments: Vec<C::Affine>,
    nizk: SchnorrZkProof<C>,
    reshare_set: ReShareSenderSet<C>,
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
            coefficients,
            commitments,
            nizk,
            reshare_set,
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
}
