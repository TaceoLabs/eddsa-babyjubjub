//! End-to-end tests for the `ReShare` protocol, covering the handover of a threshold key to a new
//! set of parties on its own, as well as signing with the resulting key shares.

use crate::{
    Affine, BaseField, Curve, ScalarField,
    key_share::DLogShareShamir,
    keygen::{Parameters, finished::Finished, test::run_keygen},
    reshare::{
        receiver::ReShareProtocolReceiver, sender::ReShareProtocolSender,
        sender_set::ReShareSenderSet,
    },
    tests::{
        nz, reconstruct, reconstruct_random_pointshares, reconstruct_random_shares,
        test_threshold_eddsa_inner,
    },
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, UniformRand};
use eddsa_babyjubjub::EdDSAPublicKey;
use rand::{CryptoRng, Rng, seq::IteratorRandom as _};
use std::num::NonZeroU16;

/// Runs the full `ReShare` protocol, handing the key held by `old_parties` over to a new set of
/// parties described by `new_params`, and returns the final state of every new party.
///
/// The set of senders is a random subset of the old parties of the size required by `old_params`.
fn run_reshare<R: Rng + CryptoRng>(
    old_parties: &[Finished<Curve>],
    old_params: Parameters,
    new_params: Parameters,
    context: &[u8],
    rng: &mut R,
) -> Vec<Finished<Curve>> {
    // 0) The parties agree on the set of old parties handing over the key
    let senders = (1..=old_params.number_of_parties.get())
        .map(nz)
        .choose_multiple(rng, usize::from(old_params.threshold.get()));

    let mut sender_set =
        ReShareSenderSet::<Curve>::for_pk_and_parameters(old_parties[0].pk, old_params, new_params);
    for &sender in &senders {
        assert!(
            !sender_set.ready(),
            "the set of senders is not complete yet"
        );
        sender_set
            .add_party(
                sender,
                old_parties[party_position(sender)].pk_shares[&sender],
            )
            .expect("public key share of an honest party is accepted");
    }
    assert!(sender_set.ready(), "the set of senders is complete");
    sender_set
        .correct()
        .expect("the public key shares of the senders recombine to the public key");

    // 1) Every sender re-shares its share of the key with a fresh polynomial and broadcasts the
    //    commitments to its coefficients
    let sender_states = senders
        .iter()
        .map(|&sender| {
            ReShareProtocolSender::<Curve>::new(
                sender,
                &old_parties[party_position(sender)].sk_share,
                sender_set.clone(),
                context,
                rng,
            )
            .expect("party index is valid for the old parameters")
        })
        .collect::<Vec<_>>();

    let broadcasts = sender_states
        .iter()
        .map(ReShareProtocolSender::get_broadcast_message)
        .collect::<Vec<_>>();

    // 2) Every sender sends the evaluation of its polynomial to the respective new party. This communication can happen in parallel with the broadcast of the commitments.
    let communications = sender_states
        .iter()
        .map(|sender| {
            (1..=new_params.number_of_parties.get())
                .map(|for_party| {
                    sender
                        .get_party_communication(nz(for_party))
                        .expect("party index is valid for the new parameters")
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    // 3) Every new party combines the received shares into its share of the unchanged key
    (1..=new_params.number_of_parties.get())
        .map(nz)
        .map(|my_idx| {
            let mut receiver =
                ReShareProtocolReceiver::<Curve>::new(my_idx, sender_set.clone(), context)
                    .expect("party index is valid for the new parameters");
            assert_eq!(
                receiver.get_missing_parties().len(),
                senders.len(),
                "no communication of the senders has been added yet"
            );

            for (position, &from) in senders.iter().enumerate() {
                receiver
                    .add_old_party_communication(
                        from,
                        broadcasts[position].clone(),
                        &communications[position][party_position(my_idx)],
                    )
                    .expect("secret share of an honest sender verifies against its commitments");
            }
            assert!(
                receiver.get_missing_parties().is_empty(),
                "the communication of all senders has been added"
            );
            assert!(receiver.can_advance(), "the ReShare protocol is complete");

            receiver
                .finalize()
                .expect("the ReShare protocol is complete")
        })
        .collect()
}

/// Translates the party index used by the protocol, which starts at one, into a position in the
/// vector of parties.
fn party_position(party_id: NonZeroU16) -> usize {
    usize::from(party_id.get()) - 1
}

/// Translates a position in the vector of parties into the party index used by the protocol, which
/// starts at one.
fn party_id(position: usize) -> NonZeroU16 {
    nz(u16::try_from(position + 1).expect("Fits into u16"))
}

/// Asserts that the parties hold a consistent Shamir sharing of `secret_key` for the given
/// parameters, and returns the public key they agree on.
fn assert_consistent_shares<R: Rng>(
    parties: &[Finished<Curve>],
    params: Parameters,
    context: &[u8],
    secret_key: ScalarField,
    rng: &mut R,
) -> Affine {
    let num_parties = params.number_of_parties.get();
    let degree = usize::from(params.degree());

    assert_eq!(
        parties.len(),
        usize::from(num_parties),
        "every party finished the protocol"
    );

    // All parties agree on the session, the public key and the public key shares
    let public_key = parties[0].pk;
    for party in parties {
        assert_eq!(party.context, context, "session context is preserved");
        assert_eq!(
            party.threshold, params.threshold,
            "output threshold matches the current sharing parameters"
        );
        assert_eq!(party.pk, public_key, "parties agree on the public key");
        assert_eq!(
            party.pk_shares.len(),
            usize::from(num_parties),
            "there is a public key share for every party"
        );
        for other_id in (1..=num_parties).map(nz) {
            assert_eq!(
                party.pk_shares[&other_id], parties[0].pk_shares[&other_id],
                "parties agree on the public key share of party {other_id}"
            );
        }
    }

    // The public key share of a party is the public counterpart of its secret key share
    for (position, party) in parties.iter().enumerate() {
        let my_id = party_id(position);
        assert_eq!(party.my_idx, my_id, "the party index is preserved");
        assert_eq!(
            party.pk_shares[&my_id],
            (Affine::generator() * party.sk_share).into_affine(),
            "public key share of party {my_id} matches its secret key share"
        );
    }

    // Any `threshold` of the secret key shares reconstruct the unchanged signing key
    let sk_shares = parties
        .iter()
        .map(|party| party.sk_share)
        .collect::<Vec<_>>();
    assert_eq!(
        reconstruct_random_shares(&sk_shares, degree, rng),
        secret_key,
        "the reconstructed secret key is unchanged"
    );

    // The same holds for the public key shares in the exponent
    let pk_shares = parties
        .iter()
        .enumerate()
        .map(|(position, party)| party.pk_shares[&party_id(position)].into_group())
        .collect::<Vec<_>>();
    assert_eq!(
        reconstruct_random_pointshares(&pk_shares, degree, rng).into_affine(),
        public_key,
        "reconstructed public key shares match the public key"
    );
    assert_eq!(
        (Affine::generator() * secret_key).into_affine(),
        public_key,
        "the public key belongs to the unchanged secret key"
    );

    public_key
}

/// Creates a key with the DKG protocol and reshares it to a new set of parties, asserting that the
/// key is preserved along the way. Returns the final state of every new party.
fn keygen_and_reshare<R: Rng + CryptoRng>(
    old_params: Parameters,
    new_params: Parameters,
    rng: &mut R,
) -> Vec<Finished<Curve>> {
    let keygen_context: &[u8] = b"reshare test: keygen session";
    let old_parties = run_keygen(
        old_params.number_of_parties.get(),
        old_params.threshold.get(),
        keygen_context,
        rng,
    );
    let sk_shares = old_parties
        .iter()
        .map(|party| party.sk_share)
        .collect::<Vec<_>>();
    let secret_key = reconstruct_random_shares(&sk_shares, usize::from(old_params.degree()), rng);
    let public_key =
        assert_consistent_shares(&old_parties, old_params, keygen_context, secret_key, rng);

    let reshare_context: &[u8] = b"reshare test: reshare session";
    let new_parties = run_reshare(&old_parties, old_params, new_params, reshare_context, rng);
    assert_eq!(
        public_key,
        assert_consistent_shares(&new_parties, new_params, reshare_context, secret_key, rng),
        "the public key survives the ReShare protocol"
    );

    new_parties
}

/// Creates a signature with the given parties, which hold a Shamir sharing of the signing key for
/// `params`. The parties at the given positions in the set of signers contribute a malformed
/// signature share and must be identified by the aggregation.
fn sign<R: Rng + CryptoRng>(
    parties: &[Finished<Curve>],
    params: Parameters,
    cheating_positions: &[usize],
    rng: &mut R,
) {
    let public_key = EdDSAPublicKey { pk: parties[0].pk };
    let message = BaseField::rand(rng);

    let x_shares = parties
        .iter()
        .enumerate()
        .map(|(position, party)| {
            DLogShareShamir::new(
                party.sk_share,
                &public_key,
                party_id(position),
                params.number_of_parties,
                params.threshold,
            )
            .expect("valid reshared signing share metadata")
        })
        .collect::<Vec<_>>();
    let public_key_shares = (1..=params.number_of_parties.get())
        .map(|party_id| parties[0].pk_shares[&nz(party_id)])
        .collect::<Vec<_>>();

    test_threshold_eddsa_inner(
        usize::from(params.number_of_parties.get()),
        usize::from(params.degree()),
        cheating_positions,
        message,
        &x_shares,
        &public_key,
        &public_key_shares,
        rng,
    );
}

fn test_reshare(old: (u16, u16), new: (u16, u16)) {
    let mut rng = rand::thread_rng();
    keygen_and_reshare(
        Parameters::new(nz(old.0), nz(old.1)),
        Parameters::new(nz(new.0), nz(new.1)),
        &mut rng,
    );
}

fn test_reshare_and_sign(old: (u16, u16), new: (u16, u16), cheating_positions: &[usize]) {
    let mut rng = rand::thread_rng();
    let new_params = Parameters::new(nz(new.0), nz(new.1));
    let new_parties =
        keygen_and_reshare(Parameters::new(nz(old.0), nz(old.1)), new_params, &mut rng);
    sign(&new_parties, new_params, cheating_positions, &mut rng);
}

/// Creates a key with the DKG protocol, reshares it along the whole chain of parameters and finally
/// signs with the key shares of the last set of parties.
fn test_repeated_reshare_and_sign(
    old: (u16, u16),
    chain: &[(u16, u16)],
    cheating_positions: &[usize],
) {
    let mut rng = rand::thread_rng();

    let mut params = Parameters::new(nz(old.0), nz(old.1));
    let new_params = Parameters::new(nz(chain[0].0), nz(chain[0].1));
    let mut parties = keygen_and_reshare(params, new_params, &mut rng);
    params = new_params;

    let sk_shares = parties
        .iter()
        .map(|party| party.sk_share)
        .collect::<Vec<_>>();
    let secret_key = reconstruct_random_shares(&sk_shares, usize::from(params.degree()), &mut rng);
    let public_key = parties[0].pk;

    for (step, &(num_parties, threshold)) in chain[1..].iter().enumerate() {
        let new_params = Parameters::new(nz(num_parties), nz(threshold));
        let context = format!("reshare test: chain step {step}");
        parties = run_reshare(&parties, params, new_params, context.as_bytes(), &mut rng);
        assert_eq!(
            public_key,
            assert_consistent_shares(
                &parties,
                new_params,
                context.as_bytes(),
                secret_key,
                &mut rng
            ),
            "the public key survives repeated runs of the ReShare protocol"
        );
        params = new_params;
    }

    sign(&parties, params, cheating_positions, &mut rng);
}

#[test]
fn test_reshare_to_smaller_set() {
    test_reshare((5, 3), (3, 2));
}

#[test]
fn test_reshare_to_bigger_set() {
    test_reshare((5, 3), (7, 4));
}

#[test]
fn test_reshare_to_same_size_set() {
    test_reshare((5, 3), (5, 3));
}

#[test]
fn test_reshare_and_sign_to_smaller_set() {
    test_reshare_and_sign((5, 3), (3, 2), &[]);
}

#[test]
fn test_reshare_and_sign_to_bigger_set() {
    test_reshare_and_sign((5, 3), (7, 4), &[]);
}

#[test]
fn test_reshare_and_sign_to_same_size_set() {
    test_reshare_and_sign((5, 3), (5, 3), &[]);
}

#[test]
fn test_repeated_reshare_and_sign_to_smaller_sets() {
    test_repeated_reshare_and_sign((7, 5), &[(6, 4), (5, 3), (3, 2)], &[]);
}

#[test]
fn test_repeated_reshare_and_sign_to_bigger_sets() {
    test_repeated_reshare_and_sign((3, 2), &[(5, 3), (6, 4), (7, 5)], &[]);
}

#[test]
fn test_repeated_reshare_and_sign_to_same_size_sets() {
    test_repeated_reshare_and_sign((5, 3), &[(5, 3), (5, 3), (5, 3)], &[]);
}

#[test]
fn test_repeated_reshare_and_sign_identifies_cheating_parties() {
    // The set of parties shrinks and grows again before signing with two cheating parties
    test_repeated_reshare_and_sign((5, 3), &[(3, 2), (7, 4), (7, 4)], &[0, 2]);
}

/// Sets up a 3-party old committee and the sender states of the selected old senders 1 and 2 for
/// the abort-model regression tests.
fn reshare_setup<R: Rng + CryptoRng>(
    context: &[u8],
    rng: &mut R,
) -> ([ReShareProtocolSender<Curve>; 2], ReShareSenderSet<Curve>) {
    let old_params = Parameters::new(nz(3), nz(2));
    let new_params = Parameters::new(nz(3), nz(2));
    let old_parties = run_keygen(3, 2, b"reshare abort test: keygen session", rng);
    let mut sender_set =
        ReShareSenderSet::<Curve>::for_pk_and_parameters(old_parties[0].pk, old_params, new_params);
    for id in [nz(1), nz(2)] {
        sender_set
            .add_party(id, old_parties[party_position(id)].pk_shares[&id])
            .expect("honest old public-key share");
    }
    sender_set
        .correct()
        .expect("the selected senders reconstruct the key");
    let senders = [nz(1), nz(2)].map(|id| {
        ReShareProtocolSender::<Curve>::new(
            id,
            &old_parties[party_position(id)].sk_share,
            sender_set.clone(),
            context,
            rng,
        )
        .expect("valid old sender")
    });
    (senders, sender_set)
}

#[test]
fn reshare_requires_every_selected_sender() {
    let mut rng = rand::thread_rng();
    let context: &[u8] = b"reshare abort test: missing sender";
    let (senders, sender_set) = reshare_setup(context, &mut rng);
    let mut receiver =
        ReShareProtocolReceiver::new(nz(1), sender_set, context).expect("valid new receiver");
    receiver
        .add_old_party_communication(
            nz(1),
            senders[0].get_broadcast_message(),
            &senders[0]
                .get_party_communication(nz(1))
                .expect("valid new receiver"),
        )
        .expect("valid sender communication");
    let error = receiver
        .add_old_party_communication(
            nz(1),
            senders[0].get_broadcast_message(),
            &senders[0]
                .get_party_communication(nz(1))
                .expect("valid new receiver"),
        )
        .expect_err("duplicate delivery cannot replace a missing sender");
    assert!(error.attributable_parties().is_empty());
    assert_eq!(receiver.get_missing_parties(), vec![nz(2)]);
    assert!(
        !receiver.can_advance(),
        "every selected sender must contribute"
    );
    let Err(_) = receiver.finalize() else {
        panic!("cannot finalize while a selected sender's contribution is missing");
    };
}

#[test]
fn invalid_reshare_evaluation_returns_culprit_and_prevents_finalization() {
    let mut rng = rand::thread_rng();
    let context: &[u8] = b"reshare abort test: invalid evaluation";
    let (senders, sender_set) = reshare_setup(context, &mut rng);
    let mut receiver =
        ReShareProtocolReceiver::new(nz(1), sender_set, context).expect("valid new receiver");
    receiver
        .add_old_party_communication(
            nz(1),
            senders[0].get_broadcast_message(),
            &senders[0]
                .get_party_communication(nz(1))
                .expect("valid new receiver"),
        )
        .expect("valid sender communication");
    let mut invalid = senders[1]
        .get_party_communication(nz(1))
        .expect("valid new receiver");
    invalid.secret_share += ScalarField::one();
    let error = receiver
        .add_old_party_communication(nz(2), senders[1].get_broadcast_message(), &invalid)
        .expect_err("an invalid evaluation must fail its committed polynomial equation");
    assert_eq!(error.attributable_parties(), vec![nz(2)]);
    assert!(matches!(
        error,
        crate::keygen::MessageError::MaliciousParty(_)
    ));
    assert_eq!(receiver.get_missing_parties(), vec![nz(2)]);
    assert!(!receiver.can_advance());
    let Err(_) = receiver.finalize() else {
        panic!("an invalid evaluation must never enter the aggregate");
    };
}

/// Two receivers that finish with different sender sets both pass the public-key check, so only the
/// agreement digest catches the divergence — and the resulting shares really are incompatible.
#[test]
fn divergent_sender_sets_are_caught_only_by_the_agreement_digest() {
    let mut rng = rand::thread_rng();
    // Four old parties for a threshold of three, so two different sender sets of three exist.
    let old_params = Parameters::new(nz(4), nz(3));
    let new_params = Parameters::new(nz(3), nz(2));
    let old_parties = run_keygen(4, 3, b"divergent test: keygen session", &mut rng);
    let sk_shares = old_parties.iter().map(|p| p.sk_share).collect::<Vec<_>>();
    let secret_key = reconstruct_random_shares(&sk_shares, 2, &mut rng);

    let context: &[u8] = b"divergent test: reshare session";
    // Receiver 1 was told senders {1, 2, 3} and receiver 2 senders {2, 3, 4}. Both sets are
    // individually valid: any three old shares reconstruct the key.
    let sender_sets = [[1u16, 2, 3], [2, 3, 4]].map(|ids| {
        let mut sender_set = ReShareSenderSet::<Curve>::for_pk_and_parameters(
            old_parties[0].pk,
            old_params,
            new_params,
        );
        for id in ids.map(nz) {
            sender_set
                .add_party(id, old_parties[party_position(id)].pk_shares[&id])
                .expect("honest old party");
        }
        sender_set.correct().expect("three senders recombine");
        sender_set
    });

    // Every honest sender has one polynomial and sends everyone the same messages; a sender is
    // constructed with a selection that contains it, but its messages do not depend on which one.
    let senders = (1..=4u16)
        .map(nz)
        .map(|id| {
            ReShareProtocolSender::new(
                id,
                &old_parties[party_position(id)].sk_share,
                sender_sets[usize::from(id.get() == 4)].clone(),
                context,
                &mut rng,
            )
            .expect("valid old sender")
        })
        .collect::<Vec<_>>();

    let finished = [nz(1), nz(2)]
        .into_iter()
        .zip(&sender_sets)
        .map(|(receiver, sender_set)| {
            let mut state = ReShareProtocolReceiver::new(receiver, sender_set.clone(), context)
                .expect("valid new receiver");
            for &sender in sender_set.senders.keys() {
                let position = party_position(sender);
                state
                    .add_old_party_communication(
                        sender,
                        senders[position].get_broadcast_message(),
                        &senders[position]
                            .get_party_communication(receiver)
                            .expect("valid new receiver"),
                    )
                    .expect("honest sender communication");
            }
            state.finalize().expect("both sender sets finalize")
        })
        .collect::<Vec<_>>();

    // Every check the protocol performs passes on both sides.
    assert_eq!(finished[0].pk, old_parties[0].pk);
    assert_eq!(finished[1].pk, old_parties[0].pk);
    assert_eq!(finished[0].contributing_parties, vec![nz(1), nz(2), nz(3)]);
    assert_eq!(finished[1].contributing_parties, vec![nz(2), nz(3), nz(4)]);

    assert_ne!(
        finished[0].agreement_digest(),
        finished[1].agreement_digest(),
        "divergent sender sets must yield different agreement digests"
    );

    // The shares lie on different polynomials, so they no longer interpolate to the signing key.
    let lagrange = crate::internal::lagrange::lagrange_from_coeff::<ScalarField, _>(&[1u16, 2u16]);
    assert_ne!(
        reconstruct(&[finished[0].sk_share, finished[1].sk_share], &lagrange),
        secret_key,
        "shares from divergent sender sets must not reconstruct the key"
    );
}

/// An honest run agrees on the digest at every receiver.
#[test]
fn matching_reshare_runs_agree_on_the_agreement_digest() {
    let mut rng = rand::thread_rng();
    let parties = keygen_and_reshare(
        Parameters::new(nz(3), nz(2)),
        Parameters::new(nz(4), nz(3)),
        &mut rng,
    );
    let digest = parties[0].agreement_digest();
    for party in &parties {
        assert_eq!(party.agreement_digest(), digest);
        assert_eq!(party.contributing_parties.len(), 2, "old threshold senders");
    }
}
