//! End-to-end tests for the distributed key generation protocol, covering the DKG on its own as
//! well as creating a signature with the resulting key shares.

use crate::{
    Affine, BaseField, Curve,
    keygen::{Parameters, finished::Finished, round1::RoundOne},
    shamir::{secret::DLogShareShamir, test::test_threshold_eddsa_inner, utils::test_utils},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use eddsa_babyjubjub::EdDSAPublicKey;
use rand::{CryptoRng, Rng};
use uuid::Uuid;

/// Runs the full DKG protocol for `num_parties` honest parties, where `threshold` parties are
/// required to reconstruct the key, and returns the final state of every party.
fn run_keygen<R: Rng + CryptoRng>(
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
