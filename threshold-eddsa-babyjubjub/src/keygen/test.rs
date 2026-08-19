//! End-to-end tests for the distributed key generation protocol, covering the DKG on its own as
//! well as creating a signature with the resulting key shares.

use crate::{
    Affine, BaseField, Curve,
    keygen::{Parameters, finished::Finished, round1::RoundOne},
    shamir::{secret::DLogShareShamir, test::test_threshold_eddsa_inner, utils::test_utils},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, UniformRand};
use eddsa_babyjubjub::EdDSAPublicKey;
use rand::{CryptoRng, Rng};
use uuid::Uuid;

/// Runs the full DKG protocol for `num_parties` honest parties, where `threshold` parties are
/// required to reconstruct the key, and returns the final state of every party.
pub(crate) fn run_keygen<R: Rng + CryptoRng>(
    num_parties: u16,
    threshold: u16,
    session_id: Uuid,
    rng: &mut R,
) -> Vec<Finished<Curve>> {
    // 1) Every party samples a polynomial and broadcasts the commitments to its coefficients
    let mut round1 = (1..=num_parties)
        .map(|party_id| {
            RoundOne::<Curve>::new(
                Parameters::new(num_parties, threshold),
                party_id,
                session_id,
                rng,
            )
            .expect("party index is valid for the parameters")
        })
        .collect::<Vec<_>>();

    let broadcasts = round1
        .iter()
        .map(RoundOne::get_broadcast_message)
        .collect::<Vec<_>>();

    for (my_pos, party) in round1.iter_mut().enumerate() {
        for (from_pos, broadcast) in broadcasts.iter().enumerate() {
            if from_pos == my_pos {
                continue;
            }
            party
                .add_party_communication(party_id(from_pos), broadcast.clone())
                .expect("broadcast of an honest party is accepted");
        }
        assert!(
            party.get_missing_parties().is_empty(),
            "all round one broadcasts have been added"
        );
        assert!(party.can_advance(), "round one is complete");
    }

    // 2) Every party sends the evaluation of its polynomial to the respective party
    let mut round2 = round1
        .into_iter()
        .map(|party| party.round2().expect("round one is complete"))
        .collect::<Vec<_>>();

    let communications = round2
        .iter()
        .map(|party| {
            (1..=num_parties)
                .map(|for_party| {
                    party
                        .get_party_communication(for_party)
                        .expect("party index is valid for the parameters")
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    for (my_pos, party) in round2.iter_mut().enumerate() {
        for (from_pos, comms) in communications.iter().enumerate() {
            if from_pos == my_pos {
                continue;
            }
            party
                .add_party_communication(party_id(from_pos), comms[my_pos].clone())
                .expect("secret share of an honest party verifies against its commitments");
        }
        assert!(
            party.get_missing_parties().is_empty(),
            "all round two messages have been added"
        );
        assert!(party.can_advance(), "round two is complete");
    }

    round2
        .into_iter()
        .map(|party| party.finalize().expect("round two is complete"))
        .collect()
}

/// Translates a position in the vector of parties into the party index used by the protocol, which
/// starts at one.
fn party_id(position: usize) -> u16 {
    u16::try_from(position + 1).expect("Fits into u16")
}

fn test_keygen(num_parties: u16, threshold: u16) {
    let mut rng = rand::thread_rng();
    let degree = usize::from(threshold) - 1;

    let session_id = Uuid::new_v4();
    let parties = run_keygen(num_parties, threshold, session_id, &mut rng);
    assert_eq!(
        parties.len(),
        usize::from(num_parties),
        "every party finished the protocol"
    );

    // All parties agree on the session, the public key and the public key shares
    let public_key = parties[0].pk;
    for party in &parties {
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
        assert_eq!(
            party.pk_shares[&my_id],
            (Affine::generator() * party.sk_share).into_affine(),
            "public key share of party {my_id} matches its secret key share"
        );
    }

    // The secret key shares are a Shamir sharing of the discrete logarithm of the public key, so
    // any `threshold` of them reconstruct a secret matching the public key
    let sk_shares = parties
        .iter()
        .map(|party| party.sk_share)
        .collect::<Vec<_>>();
    let secret_key = test_utils::reconstruct_random_shares(&sk_shares, degree, &mut rng);
    assert_eq!(
        (Affine::generator() * secret_key).into_affine(),
        public_key,
        "reconstructed secret key matches the public key"
    );

    // The same holds for the public key shares in the exponent
    let pk_shares = parties
        .iter()
        .enumerate()
        .map(|(position, party)| party.pk_shares[&party_id(position)].into_group())
        .collect::<Vec<_>>();
    let public_key_ =
        test_utils::reconstruct_random_pointshares(&pk_shares, degree, &mut rng).into_affine();
    assert_eq!(
        public_key_, public_key,
        "reconstructed public key shares match the public key"
    );
}

fn test_keygen_and_sign(num_parties: u16, threshold: u16, cheating_positions: &[usize]) {
    let mut rng = rand::thread_rng();
    let degree = usize::from(threshold) - 1;

    // Create the signing key shares via the DKG protocol
    let parties = run_keygen(num_parties, threshold, Uuid::new_v4(), &mut rng);
    let public_key = EdDSAPublicKey { pk: parties[0].pk };

    let message = BaseField::rand(&mut rng);

    let x_shares = parties
        .iter()
        .map(|party| DLogShareShamir(party.sk_share))
        .collect::<Vec<_>>();

    let public_key_shares = (1..=num_parties)
        .map(|party_id| parties[0].pk_shares[&party_id])
        .collect::<Vec<_>>();

    test_threshold_eddsa_inner(
        usize::from(num_parties),
        degree,
        cheating_positions,
        message,
        &x_shares,
        &public_key,
        &public_key_shares,
        &mut rng,
    );
}

#[test]
fn test_keygen_3_2() {
    test_keygen(3, 2);
}

#[test]
fn test_keygen_7_4() {
    test_keygen(7, 4);
}

#[test]
fn test_keygen_and_sign_3_2() {
    test_keygen_and_sign(3, 2, &[]);
}

#[test]
fn test_keygen_and_sign_7_4() {
    test_keygen_and_sign(7, 4, &[]);
}

#[test]
fn test_keygen_and_sign_identifies_cheating_parties() {
    test_keygen_and_sign(7, 4, &[0, 2]);
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BlameTestMode {
    Valid,
    Malformed,
    Missing,
}

#[allow(
    clippy::too_many_lines,
    reason = "Exercises the complete optional two-broadcast workflow"
)]
fn run_optional_blame_round(mode: BlameTestMode, num_parties: u16, threshold: u16) {
    let mut rng = rand::thread_rng();
    assert!(
        num_parties >= 3,
        "blame test fixture requires at least three parties"
    );
    let parameters = Parameters::new(num_parties, threshold);
    let session_id = Uuid::new_v4();
    let mut round1 = (1..=num_parties)
        .map(|party| {
            RoundOne::<Curve>::new(parameters, party, session_id, &mut rng)
                .expect("valid DKG parameters")
        })
        .collect::<Vec<_>>();
    let round1_broadcasts = round1
        .iter()
        .map(RoundOne::get_broadcast_message)
        .collect::<Vec<_>>();
    for (receiver, state) in round1.iter_mut().enumerate() {
        for (dealer, broadcast) in round1_broadcasts.iter().enumerate() {
            if receiver != dealer {
                state
                    .add_party_communication(party_id(dealer), broadcast.clone())
                    .expect("honest round-one broadcast");
            }
        }
    }

    let mut round2 = round1
        .into_iter()
        .map(|state| state.round2().expect("round one complete"))
        .collect::<Vec<_>>();
    let mut private_shares = round2
        .iter()
        .map(|dealer| {
            (1..=num_parties)
                .map(|receiver| {
                    dealer
                        .get_party_communication(receiver)
                        .expect("valid receiver")
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();

    // Dealer 1 equivocates only toward receiver 2, which will complain publicly.
    private_shares[0][1].secret_share += crate::ScalarField::one();
    for (receiver, state) in round2.iter_mut().enumerate() {
        for (dealer, shares) in private_shares.iter().enumerate() {
            if receiver != dealer {
                state
                    .add_party_communication_for_blame(party_id(dealer), &shares[receiver])
                    .expect("well-formed private communication is retained for blame");
            }
        }
    }

    let mut blame_rounds = round2
        .into_iter()
        .map(|state| state.blame_round().expect("all private shares received"))
        .collect::<Vec<_>>();
    let verdicts = blame_rounds
        .iter()
        .map(crate::keygen::blame::BlameRound::verdict)
        .collect::<Vec<_>>();
    assert!(verdicts[0].is_ok());
    assert_eq!(
        verdicts[1]
            .blamed_parties()
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        vec![1]
    );
    assert!(verdicts[2].is_ok());
    for (receiver, state) in blame_rounds.iter_mut().enumerate() {
        for (sender, verdict) in verdicts.iter().enumerate() {
            if receiver != sender {
                state
                    .add_verdict(party_id(sender), verdict.clone())
                    .expect("valid verdict broadcast");
            }
        }
    }

    let mut revelations = blame_rounds
        .iter_mut()
        .enumerate()
        .map(|(dealer, state)| {
            if mode == BlameTestMode::Missing && dealer == 0 {
                None
            } else {
                state.revelation().expect("verdict exchange complete")
            }
        })
        .collect::<Vec<_>>();
    if mode == BlameTestMode::Malformed {
        revelations[0]
            .as_mut()
            .expect("dealer 1 was accused")
            .shares[0]
            .share += crate::ScalarField::one();
    }
    for (receiver, state) in blame_rounds.iter_mut().enumerate() {
        for (dealer, revelation) in revelations.iter().enumerate() {
            if receiver != dealer
                && let Some(revelation) = revelation
            {
                state
                    .add_revelation(party_id(dealer), revelation)
                    .expect("accused dealer's public revelation is processed");
            }
        }
    }
    if mode == BlameTestMode::Missing {
        for state in &mut blame_rounds {
            state
                .disqualify_missing_dealer(1)
                .expect("accused dealer can be disqualified after withholding its share");
        }
    }

    let results = blame_rounds
        .into_iter()
        .map(crate::keygen::blame::BlameRound::finalize)
        .collect::<Vec<_>>();
    let expected_disqualified = if mode == BlameTestMode::Valid {
        vec![]
    } else {
        vec![1]
    };
    if mode == BlameTestMode::Missing {
        for disqualified in &expected_disqualified {
            assert!(results[usize::from(*disqualified) - 1].is_err());
        }
    }
    let honest_results = results
        .iter()
        .enumerate()
        .filter(|(position, _)| !expected_disqualified.contains(&party_id(*position)))
        .filter_map(|(_, result)| result.as_ref().ok())
        .collect::<Vec<_>>();
    let expected = &honest_results[0].finished;
    for result in honest_results {
        assert_eq!(result.disqualified_parties, expected_disqualified);
        assert!(
            expected_disqualified
                .iter()
                .all(|party| !result.finished.pk_shares.contains_key(party)),
            "disqualified parties must not have public-key shares"
        );
        assert_eq!(
            result.finished.pk_shares.len(),
            usize::from(num_parties) - expected_disqualified.len()
        );
        assert_eq!(result.finished.pk, expected.pk);
        assert_eq!(result.finished.pk_shares, expected.pk_shares);
        assert_eq!(
            (Affine::generator() * result.finished.sk_share).into_affine(),
            result.finished.pk_shares[&result.finished.my_idx]
        );
    }
}

#[test]
fn optional_blame_round_accepts_valid_dealer_revelation() {
    run_optional_blame_round(BlameTestMode::Valid, 3, 2);
}

#[test]
fn optional_blame_round_disqualifies_malformed_dealer_revelation() {
    run_optional_blame_round(BlameTestMode::Malformed, 3, 2);
}

#[test]
fn optional_blame_round_disqualifies_missing_dealer_revelation() {
    run_optional_blame_round(BlameTestMode::Missing, 3, 2);
}
