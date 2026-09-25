//! End-to-end tests for the distributed key generation protocol, covering the DKG on its own as
//! well as creating a signature with the resulting key shares.

use crate::{
    Affine, BaseField, Curve,
    key_share::DLogShareShamir,
    keygen::{
        Parameters,
        finished::Finished,
        round1::{RoundOne, RoundOneBroadcast},
        round2::RoundTwo,
    },
    tests::{
        nz, reconstruct_random_pointshares, reconstruct_random_shares, test_threshold_eddsa_inner,
    },
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, UniformRand};
use eddsa_babyjubjub::EdDSAPublicKey;
use rand::{CryptoRng, Rng};
use std::num::NonZeroU16;

/// Runs the full DKG protocol for `num_parties` honest parties, where `threshold` parties are
/// required to reconstruct the key, and returns the final state of every party.
pub(crate) fn run_keygen<R: Rng + CryptoRng>(
    num_parties: u16,
    threshold: u16,
    context: &[u8],
    rng: &mut R,
) -> Vec<Finished<Curve>> {
    let mut round2 = run_round_one(num_parties, threshold, context, rng);

    let communications = round2
        .iter()
        .map(|party| {
            (1..=num_parties)
                .map(|for_party| {
                    party
                        .get_party_communication(nz(for_party))
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
                .add_party_communication(party_id(from_pos), &comms[my_pos])
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

fn run_round_one<R: Rng + CryptoRng>(
    num_parties: u16,
    threshold: u16,
    context: &[u8],
    rng: &mut R,
) -> Vec<RoundTwo<Curve>> {
    // 1) Every party samples a polynomial and broadcasts the commitments to its coefficients
    let mut round1 = (1..=num_parties)
        .map(|party_id| {
            RoundOne::<Curve>::new(
                Parameters::new(nz(num_parties), nz(threshold)),
                nz(party_id),
                context,
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
    round1
        .into_iter()
        .map(|party| party.round2().expect("round one is complete"))
        .collect()
}

/// Translates a position in the vector of parties into the party index used by the protocol, which
/// starts at one.
fn party_id(position: usize) -> NonZeroU16 {
    nz(u16::try_from(position + 1).expect("Fits into u16"))
}

fn test_keygen(num_parties: u16, threshold: u16) {
    let mut rng = rand::thread_rng();
    let degree = usize::from(threshold) - 1;

    let context: &[u8] = b"keygen test: unique session context";
    let parties = run_keygen(num_parties, threshold, context, &mut rng);
    assert_eq!(
        parties.len(),
        usize::from(num_parties),
        "every party finished the protocol"
    );

    // All parties agree on the session, the public key and the public key shares
    let public_key = parties[0].pk;
    for party in &parties {
        assert_eq!(party.context, context, "session context is preserved");
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
    let secret_key = reconstruct_random_shares(&sk_shares, degree, &mut rng);
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
    let public_key_ = reconstruct_random_pointshares(&pk_shares, degree, &mut rng).into_affine();
    assert_eq!(
        public_key_, public_key,
        "reconstructed public key shares match the public key"
    );
}

fn test_keygen_and_sign(num_parties: u16, threshold: u16, cheating_positions: &[usize]) {
    let mut rng = rand::thread_rng();
    let degree = usize::from(threshold) - 1;

    // Create the signing key shares via the DKG protocol
    let parties = run_keygen(
        num_parties,
        threshold,
        b"keygen test: DKG-then-sign session context",
        &mut rng,
    );
    let public_key = EdDSAPublicKey { pk: parties[0].pk };

    let message = BaseField::rand(&mut rng);

    let x_shares = parties
        .iter()
        .enumerate()
        .map(|(position, party)| {
            DLogShareShamir::new(
                party.sk_share,
                &public_key,
                party_id(position),
                nz(num_parties),
                nz(threshold),
            )
            .expect("valid DKG signing share metadata")
        })
        .collect::<Vec<_>>();

    let public_key_shares = (1..=num_parties)
        .map(|party_id| parties[0].pk_shares[&nz(party_id)])
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

#[test]
fn parameters_reject_invalid_deserialization() {
    let Err(_) = serde_json::from_str::<Parameters>(r#"{"number_of_parties":3,"threshold":0}"#)
    else {
        panic!("zero threshold must be rejected");
    };
    let Err(_) = serde_json::from_str::<Parameters>(r#"{"number_of_parties":2,"threshold":3}"#)
    else {
        panic!("threshold above the party count must be rejected");
    };
}

#[test]
fn round_one_broadcast_serde_round_trips() {
    let mut rng = rand::thread_rng();
    let params = Parameters::new(nz(3), nz(2));
    let context: &[u8] = b"keygen test: serde round trip";
    let dealer = RoundOne::<Curve>::new(params, nz(1), context, &mut rng).expect("valid DKG party");
    let mut receiver =
        RoundOne::<Curve>::new(params, nz(2), context, &mut rng).expect("valid DKG party");
    let encoded = serde_json::to_vec(&dealer.get_broadcast_message())
        .expect("round-one broadcast serializes");
    let decoded = serde_json::from_slice::<RoundOneBroadcast<Curve>>(&encoded)
        .expect("round-one broadcast deserializes");

    receiver
        .add_party_communication(nz(1), decoded)
        .expect("round-tripped broadcast verifies");
}

/// Blame attribution must survive being logged, and a local configuration mismatch must not be
/// reported as remote misbehaviour.
#[test]
fn round_one_errors_separate_attributable_blame_from_a_local_mismatch() {
    let mut rng = rand::thread_rng();
    let context: &[u8] = b"keygen test: blame attribution";
    let params = Parameters::new(nz(3), nz(2));
    let mut state =
        RoundOne::<Curve>::new(params, nz(1), context, &mut rng).expect("valid DKG party");

    // A proof of possession binds the prover's index, so replaying party 2's broadcast as party 3
    // fails cryptographically and is attributable.
    let broadcast = RoundOne::<Curve>::new(params, nz(2), context, &mut rng)
        .expect("valid DKG party")
        .get_broadcast_message();
    let error = state
        .add_party_communication(nz(3), broadcast)
        .expect_err("a replayed proof must not verify");
    assert_eq!(error.attributable_parties(), vec![nz(3)]);
    assert!(
        error.to_string().contains('3'),
        "the party ID must survive being logged: {error}"
    );

    // A peer configured with a different threshold looks wrong locally, but is not at fault.
    let mismatched =
        RoundOne::<Curve>::new(Parameters::new(nz(3), nz(3)), nz(2), context, &mut rng)
            .expect("valid DKG party")
            .get_broadcast_message();
    let error = state
        .add_party_communication(nz(2), mismatched)
        .expect_err("a commitment count mismatch must be rejected");
    assert!(
        error.attributable_parties().is_empty(),
        "a configuration mismatch must not accuse anyone: {error}"
    );
    assert!(matches!(error, crate::keygen::MessageError::Malformed(_)));
}

#[test]
fn round_one_requires_every_configured_participant() {
    let mut rng = rand::thread_rng();
    let params = Parameters::new(nz(3), nz(2));
    let context = b"keygen test: incomplete commitments";
    let mut receiver =
        RoundOne::<Curve>::new(params, nz(1), context, &mut rng).expect("valid DKG party");
    let broadcast = RoundOne::<Curve>::new(params, nz(2), context, &mut rng)
        .expect("valid DKG party")
        .get_broadcast_message();
    receiver
        .add_party_communication(nz(2), broadcast.clone())
        .expect("valid broadcast");
    let error = receiver
        .add_party_communication(nz(2), broadcast)
        .expect_err("duplicate delivery cannot replace a missing participant");
    assert!(error.attributable_parties().is_empty());
    assert_eq!(receiver.get_missing_parties(), vec![nz(3)]);
    assert!(
        !receiver.can_advance(),
        "a signing threshold is insufficient for DKG"
    );
    let Err(_) = receiver.round2() else {
        panic!("cannot advance while any participant's commitment is missing");
    };
}

#[test]
fn round_two_requires_every_configured_participant() {
    let mut rng = rand::thread_rng();
    let mut states = run_round_one(3, 2, b"keygen test: missing private share", &mut rng);
    let share = states[1]
        .get_party_communication(nz(1))
        .expect("share for participant one");
    let mut receiver = states.remove(0);
    receiver
        .add_party_communication(nz(2), &share)
        .expect("valid private share");
    let error = receiver
        .add_party_communication(nz(2), &share)
        .expect_err("duplicate delivery cannot replace a missing participant");
    assert!(error.attributable_parties().is_empty());
    assert_eq!(receiver.get_missing_parties(), vec![nz(3)]);
    assert!(
        !receiver.can_advance(),
        "all DKG participants must contribute"
    );
    let Err(_) = receiver.finalize() else {
        panic!("cannot finalize while any participant's private share is missing");
    };
}

#[test]
fn invalid_private_share_returns_culprit_and_prevents_finalization() {
    let mut rng = rand::thread_rng();
    let mut states = run_round_one(3, 2, b"keygen test: invalid private share", &mut rng);
    let mut invalid = states[1]
        .get_party_communication(nz(1))
        .expect("share for participant one");
    invalid.secret_share += crate::ScalarField::one();
    let valid = states[2]
        .get_party_communication(nz(1))
        .expect("share for participant one");
    let mut receiver = states.remove(0);
    receiver
        .add_party_communication(nz(3), &valid)
        .expect("valid private share");
    let error = receiver
        .add_party_communication(nz(2), &invalid)
        .expect_err("an invalid share must fail its Feldman equation");
    assert_eq!(error.attributable_parties(), vec![nz(2)]);
    assert!(matches!(
        error,
        crate::keygen::MessageError::MaliciousParty(_)
    ));
    assert_eq!(receiver.get_missing_parties(), vec![nz(2)]);
    assert!(!receiver.can_advance());
    let Err(_) = receiver.finalize() else {
        panic!("an invalid share must never enter the aggregate");
    };
}

#[test]
fn proof_binds_context_parameters_and_all_commitments() {
    let mut rng = rand::thread_rng();
    let params = Parameters::new(nz(3), nz(2));
    let context = b"keygen test: transcript binding";
    let honest = RoundOne::<Curve>::new(params, nz(2), context, &mut rng)
        .expect("valid DKG party")
        .get_broadcast_message();
    let mut changed_coefficient = honest;
    changed_coefficient.commitments[1] =
        (changed_coefficient.commitments[1] + Affine::generator()).into_affine();
    let other_context = RoundOne::<Curve>::new(params, nz(2), b"another session", &mut rng)
        .expect("valid DKG party")
        .get_broadcast_message();
    let other_count =
        RoundOne::<Curve>::new(Parameters::new(nz(4), nz(2)), nz(2), context, &mut rng)
            .expect("valid DKG party")
            .get_broadcast_message();

    for broadcast in [changed_coefficient, other_context, other_count] {
        let mut receiver =
            RoundOne::<Curve>::new(params, nz(1), context, &mut rng).expect("valid DKG party");
        let error = receiver
            .add_party_communication(nz(2), broadcast)
            .expect_err("a proof for a different transcript must fail");
        assert_eq!(error.attributable_parties(), vec![nz(2)]);
        assert_eq!(receiver.get_missing_parties(), vec![nz(2), nz(3)]);
        assert!(!receiver.can_advance());
    }
}

#[test]
fn equal_constant_commitments_require_independent_participant_proofs() {
    use crate::keygen::schnorr::{SchnorrZkProof, proof_context};

    let mut rng = rand::thread_rng();
    let params = Parameters::new(nz(3), nz(2));
    let context = b"keygen test: independently proven equal constants";
    let mut receiver =
        RoundOne::<Curve>::new(params, nz(1), context, &mut rng).expect("valid DKG party");
    let constant = crate::ScalarField::from(5_u64);
    let proof_context = proof_context(b"PEDPOP_DKG_V1", context, &[params]);
    for party in [nz(2), nz(3)] {
        let commitments = vec![
            (Affine::generator() * constant).into_affine(),
            (Affine::generator() * crate::ScalarField::from(party.get())).into_affine(),
        ];
        let nizk = SchnorrZkProof::new(
            &proof_context,
            party,
            &constant,
            &commitments[0],
            &commitments[1..],
            &mut rng,
        );
        receiver
            .add_party_communication(party, RoundOneBroadcast { commitments, nizk })
            .expect("each participant proves knowledge under its own ID");
    }
    assert!(receiver.can_advance());
}
