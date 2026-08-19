//! End-to-end tests for the `ReShare` protocol, covering the handover of a threshold key to a new
//! set of parties on its own, as well as signing with the resulting key shares.

use crate::{
    Affine, BaseField, Curve, ScalarField,
    keygen::{Parameters, finished::Finished, test::run_keygen},
    reshare::{
        receiver::ReShareProtocolReceiver, sender::ReShareProtocolSender,
        sender_set::ReShareSenderSet,
    },
    shamir::{secret::DLogShareShamir, test::test_threshold_eddsa_inner, utils::test_utils},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, UniformRand};
use eddsa_babyjubjub::EdDSAPublicKey;
use rand::{CryptoRng, Rng, seq::IteratorRandom as _};
use uuid::Uuid;

/// Runs the full `ReShare` protocol, handing the key held by `old_parties` over to a new set of
/// parties described by `new_params`, and returns the final state of every new party.
///
/// The set of senders is a random subset of the old parties of the size required by `old_params`.
fn run_reshare<R: Rng + CryptoRng>(
    old_parties: &[Finished<Curve>],
    old_params: Parameters,
    new_params: Parameters,
    session_id: Uuid,
    rng: &mut R,
) -> Vec<Finished<Curve>> {
    // 0) The parties agree on the set of old parties handing over the key
    let senders =
        (1..=old_params.number_of_parties).choose_multiple(rng, usize::from(old_params.threshold));

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
                session_id,
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
            (1..=new_params.number_of_parties)
                .map(|for_party| {
                    sender
                        .get_party_communication(for_party)
                        .expect("party index is valid for the new parameters")
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    // 3) Every new party combines the received shares into its share of the unchanged key
    (1..=new_params.number_of_parties)
        .map(|my_idx| {
            let mut receiver =
                ReShareProtocolReceiver::<Curve>::new(my_idx, sender_set.clone(), session_id)
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
fn party_position(party_id: u16) -> usize {
    usize::from(party_id) - 1
}

/// Translates a position in the vector of parties into the party index used by the protocol, which
/// starts at one.
fn party_id(position: usize) -> u16 {
    u16::try_from(position + 1).expect("Fits into u16")
}

/// Asserts that the parties hold a consistent Shamir sharing of `secret_key` for the given
/// parameters, and returns the public key they agree on.
fn assert_consistent_shares<R: Rng>(
    parties: &[Finished<Curve>],
    params: Parameters,
    session_id: Uuid,
    secret_key: ScalarField,
    rng: &mut R,
) -> Affine {
    let num_parties = params.number_of_parties;
    let degree = usize::from(params.degree());

    assert_eq!(
        parties.len(),
        usize::from(num_parties),
        "every party finished the protocol"
    );

    // All parties agree on the session, the public key and the public key shares
    let public_key = parties[0].pk;
    for party in parties {
        assert_eq!(party.session_id, session_id, "session id is preserved");
        assert_eq!(party.pk, public_key, "parties agree on the public key");
        assert_eq!(
            party.pk_shares.len(),
            usize::from(num_parties),
            "there is a public key share for every party"
        );
        for other_id in 1..=num_parties {
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
        test_utils::reconstruct_random_shares(&sk_shares, degree, rng),
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
        test_utils::reconstruct_random_pointshares(&pk_shares, degree, rng).into_affine(),
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
    let keygen_session_id = Uuid::new_v4();
    let old_parties = run_keygen(
        old_params.number_of_parties,
        old_params.threshold,
        keygen_session_id,
        rng,
    );
    let sk_shares = old_parties
        .iter()
        .map(|party| party.sk_share)
        .collect::<Vec<_>>();
    let secret_key =
        test_utils::reconstruct_random_shares(&sk_shares, usize::from(old_params.degree()), rng);
    let public_key =
        assert_consistent_shares(&old_parties, old_params, keygen_session_id, secret_key, rng);

    let reshare_session_id = Uuid::new_v4();
    let new_parties = run_reshare(
        &old_parties,
        old_params,
        new_params,
        reshare_session_id,
        rng,
    );
    assert_eq!(
        public_key,
        assert_consistent_shares(
            &new_parties,
            new_params,
            reshare_session_id,
            secret_key,
            rng
        ),
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
                party_id(position),
                params.number_of_parties,
                params.threshold,
            )
            .expect("valid reshared signing share metadata")
        })
        .collect::<Vec<_>>();
    let public_key_shares = (1..=params.number_of_parties)
        .map(|party_id| parties[0].pk_shares[&party_id])
        .collect::<Vec<_>>();

    test_threshold_eddsa_inner(
        usize::from(params.number_of_parties),
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
        Parameters::new(old.0, old.1),
        Parameters::new(new.0, new.1),
        &mut rng,
    );
}

fn test_reshare_and_sign(old: (u16, u16), new: (u16, u16), cheating_positions: &[usize]) {
    let mut rng = rand::thread_rng();
    let new_params = Parameters::new(new.0, new.1);
    let new_parties = keygen_and_reshare(Parameters::new(old.0, old.1), new_params, &mut rng);
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

    let mut params = Parameters::new(old.0, old.1);
    let new_params = Parameters::new(chain[0].0, chain[0].1);
    let mut parties = keygen_and_reshare(params, new_params, &mut rng);
    params = new_params;

    let sk_shares = parties
        .iter()
        .map(|party| party.sk_share)
        .collect::<Vec<_>>();
    let secret_key =
        test_utils::reconstruct_random_shares(&sk_shares, usize::from(params.degree()), &mut rng);
    let public_key = parties[0].pk;

    for &(num_parties, threshold) in &chain[1..] {
        let new_params = Parameters::new(num_parties, threshold);
        let session_id = Uuid::new_v4();
        parties = run_reshare(&parties, params, new_params, session_id, &mut rng);
        assert_eq!(
            public_key,
            assert_consistent_shares(&parties, new_params, session_id, secret_key, &mut rng),
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReShareBlameTestMode {
    Valid,
    Malformed,
    Missing,
    MissingPrivateMessage,
    MissingBroadcast,
    MissingVerdict,
}

#[allow(
    clippy::too_many_lines,
    reason = "Exercises the complete optional reshare blame workflow"
)]
fn run_reshare_blame_test(
    mode: ReShareBlameTestMode,
    old_params: Parameters,
    new_params: Parameters,
) {
    assert!(old_params.number_of_parties > old_params.threshold);
    let mut rng = rand::thread_rng();
    let old_parties = run_keygen(
        old_params.number_of_parties,
        old_params.threshold,
        Uuid::new_v4(),
        &mut rng,
    );
    let session_id = Uuid::new_v4();
    let mut sender_set =
        ReShareSenderSet::<Curve>::for_pk_and_parameters(old_parties[0].pk, old_params, new_params);
    for sender in 1..=old_params.number_of_parties {
        sender_set
            .add_party(
                sender,
                old_parties[party_position(sender)].pk_shares[&sender],
            )
            .expect("honest old public-key share");
    }
    sender_set
        .correct()
        .expect("all old shares reconstruct the key");

    let sender_states = (1..=old_params.number_of_parties)
        .map(|sender| {
            ReShareProtocolSender::<Curve>::new(
                sender,
                &old_parties[party_position(sender)].sk_share,
                sender_set.clone(),
                session_id,
                &mut rng,
            )
            .expect("valid old sender")
        })
        .collect::<Vec<_>>();
    let broadcasts = sender_states
        .iter()
        .map(ReShareProtocolSender::get_broadcast_message)
        .collect::<Vec<_>>();
    let mut private_shares = sender_states
        .iter()
        .map(|sender| {
            (1..=new_params.number_of_parties)
                .map(|receiver| {
                    sender
                        .get_party_communication(receiver)
                        .expect("valid new receiver")
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    // Dealer 1 equivocates only toward receiver 2, which will complain publicly.
    if !matches!(
        mode,
        ReShareBlameTestMode::MissingPrivateMessage | ReShareBlameTestMode::MissingBroadcast
    ) {
        private_shares[0][1].secret_share += ScalarField::one();
    }
    let mut receivers = (1..=new_params.number_of_parties)
        .map(|receiver| {
            let mut state = ReShareProtocolReceiver::new(receiver, sender_set.clone(), session_id)
                .expect("valid new receiver");
            for sender in 1..=old_params.number_of_parties {
                if mode == ReShareBlameTestMode::MissingBroadcast
                    && sender == old_params.number_of_parties
                {
                    state
                        .disqualify_missing_sender(sender)
                        .expect("common timeout disqualifies missing sender broadcast");
                } else if mode == ReShareBlameTestMode::MissingPrivateMessage
                    && receiver == 2
                    && sender == 1
                {
                    state
                        .complain_missing_share(1, broadcasts[0].clone())
                        .expect("missing private reshare evaluation becomes a complaint");
                } else {
                    state
                        .add_old_party_communication_for_blame(
                            sender,
                            broadcasts[party_position(sender)].clone(),
                            &private_shares[party_position(sender)][party_position(receiver)],
                        )
                        .expect("sender communication retained for blame");
                }
            }
            state.blame_round().expect("all sender messages received")
        })
        .collect::<Vec<_>>();
    let verdicts = receivers
        .iter()
        .map(crate::reshare::blame::ReShareBlameRound::verdict)
        .collect::<Vec<_>>();
    assert!(verdicts[0].is_ok());
    let expected_blame = if mode == ReShareBlameTestMode::MissingBroadcast {
        vec![]
    } else {
        vec![1]
    };
    assert_eq!(
        verdicts[1]
            .blamed_parties()
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        expected_blame,
    );
    let completing_receivers = if mode == ReShareBlameTestMode::MissingVerdict {
        receivers.len() - 1
    } else {
        receivers.len()
    };
    for (receiver, state) in receivers.iter_mut().take(completing_receivers).enumerate() {
        for (sender, verdict) in verdicts.iter().enumerate() {
            if receiver != sender
                && !(mode == ReShareBlameTestMode::MissingVerdict
                    && sender + 1 == usize::from(new_params.number_of_parties))
            {
                state
                    .add_verdict(party_id(sender), verdict.clone())
                    .expect("valid new-party verdict");
            }
        }
        if mode == ReShareBlameTestMode::MissingVerdict {
            state
                .exclude_missing_verdict(new_params.number_of_parties)
                .expect("common timeout excludes the missing receiver verdict");
        }
    }

    let accusers = receivers[0].accusations().expect("all verdicts received");
    let mut revelation = if matches!(
        mode,
        ReShareBlameTestMode::Missing | ReShareBlameTestMode::MissingBroadcast
    ) {
        None
    } else {
        Some(
            sender_states[0]
                .get_blame_revelation(&accusers[&1])
                .expect("accused sender reveals committed shares"),
        )
    };
    if mode == ReShareBlameTestMode::Malformed {
        revelation
            .as_mut()
            .expect("malformed mode has a revelation")
            .shares[0]
            .share += ScalarField::one();
    }
    for state in receivers.iter_mut().take(completing_receivers) {
        if let Some(revelation) = &revelation {
            state
                .add_revelation(1, revelation)
                .expect("old-sender revelation processed");
        } else if mode == ReShareBlameTestMode::Missing {
            state
                .disqualify_missing_sender(1)
                .expect("missing old sender disqualified");
        }
    }

    let results = receivers
        .into_iter()
        .take(completing_receivers)
        .map(|state| state.finalize().expect("enough qualified senders survive"))
        .collect::<Vec<_>>();
    let expected_disqualified = if mode == ReShareBlameTestMode::MissingBroadcast {
        vec![old_params.number_of_parties]
    } else if matches!(
        mode,
        ReShareBlameTestMode::Valid
            | ReShareBlameTestMode::MissingPrivateMessage
            | ReShareBlameTestMode::MissingVerdict
    ) {
        vec![]
    } else {
        vec![1]
    };
    for result in &results {
        assert_eq!(result.disqualified_parties, expected_disqualified);
        let expected_excluded = if mode == ReShareBlameTestMode::MissingVerdict {
            vec![new_params.number_of_parties]
        } else {
            vec![]
        };
        assert_eq!(result.excluded_verdict_parties, expected_excluded);
        assert_eq!(result.finished.pk, old_parties[0].pk);
        assert_eq!(result.finished.pk_shares, results[0].finished.pk_shares);
        assert_eq!(
            (Affine::generator() * result.finished.sk_share).into_affine(),
            result.finished.pk_shares[&result.finished.my_idx]
        );
    }
}

#[test]
fn reshare_blame_accepts_valid_sender_revelation() {
    run_reshare_blame_test(
        ReShareBlameTestMode::Valid,
        Parameters::new(4, 2),
        Parameters::new(3, 2),
    );
}

#[test]
fn reshare_blame_disqualifies_malformed_sender_revelation() {
    run_reshare_blame_test(
        ReShareBlameTestMode::Malformed,
        Parameters::new(4, 2),
        Parameters::new(3, 2),
    );
}

#[test]
fn reshare_blame_disqualifies_missing_sender_revelation() {
    run_reshare_blame_test(
        ReShareBlameTestMode::Missing,
        Parameters::new(4, 2),
        Parameters::new(3, 2),
    );
}

#[test]
fn reshare_blame_recovers_a_missing_private_message() {
    run_reshare_blame_test(
        ReShareBlameTestMode::MissingPrivateMessage,
        Parameters::new(4, 2),
        Parameters::new(3, 2),
    );
}

#[test]
fn reshare_continues_after_a_missing_sender_broadcast() {
    run_reshare_blame_test(
        ReShareBlameTestMode::MissingBroadcast,
        Parameters::new(4, 2),
        Parameters::new(3, 2),
    );
}

#[test]
fn reshare_blame_continues_after_a_missing_receiver_verdict() {
    run_reshare_blame_test(
        ReShareBlameTestMode::MissingVerdict,
        Parameters::new(4, 2),
        Parameters::new(3, 2),
    );
}
