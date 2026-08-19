//! End-to-end tests for the additive threshold `EdDSA` protocol, covering both plain aggregation
//! and aggregation with identifiable abort.

use crate::{
    Affine, BaseField, Projective, ScalarField,
    additive::{
        commit::EdDSACommitmentsAdditive, secret::DLogShareAdditive, session::EdDSASessionAdditive,
    },
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{UniformRand, Zero};
use eddsa_babyjubjub::EdDSAPublicKey;
use uuid::Uuid;

fn test_distributed_eddsa(num_parties: usize, cheating_parties: &[usize]) {
    let mut rng = rand::thread_rng();

    let message = BaseField::rand(&mut rng);
    // Random x shares
    let x_shares = (0..num_parties)
        .map(|_| DLogShareAdditive(ScalarField::rand(&mut rng)))
        .collect::<Vec<_>>();

    // Combine x shares
    let x = x_shares
        .iter()
        .fold(ScalarField::zero(), |acc, x| acc + x.0);

    // Create public keys
    let public_key = (Affine::generator() * x).into_affine();
    let x_share_commitments = x_shares
        .iter()
        .map(|x| (Affine::generator() * x.0).into_affine())
        .collect::<Vec<_>>();
    let public_key_ = x_share_commitments
        .iter()
        .fold(Projective::zero(), |acc, x| acc + x)
        .into_affine();
    assert_eq!(public_key, public_key_);
    let public_key = EdDSAPublicKey { pk: public_key };

    // Crete session
    let session_id = Uuid::new_v4();

    // 1) Aggregator requests commitments from all servers
    let mut sessions = Vec::with_capacity(num_parties);
    let mut commitments = Vec::with_capacity(num_parties);
    for id in 0..num_parties {
        let (session, comm) = EdDSASessionAdditive::pre_round(&mut rng);
        sessions.push(session);
        commitments.push((u16::try_from(id + 1).expect("Can fit into u16"), comm));
    }

    // 2) Aggregator accumulates commitments and creates challenge
    let challenge = EdDSACommitmentsAdditive::pre_agg(&commitments);

    // 3) Aggregator challenges all servers
    let mut signatures = Vec::with_capacity(num_parties);
    for (session, x_) in sessions.into_iter().zip(x_shares.iter()) {
        let signature = session.sign_round(session_id, x_, message, &public_key, challenge.clone());
        signatures.push(signature);
    }

    for &party_id in cheating_parties {
        signatures[party_id - 1].0.0 += ScalarField::from(1_u64);
    }

    // 4) Aggregator combines received signature shares
    let partial_commitments = commitments
        .iter()
        .map(|(_, commitment)| commitment.clone())
        .collect::<Vec<_>>();

    // Without identifiable abort
    let signature_noabort =
        challenge
            .clone()
            .sign_agg(session_id, &signatures, message, public_key.clone());

    // With identifiable abort
    let result = challenge.sign_agg_with_identifiable_abort(
        session_id,
        &signatures,
        message,
        &public_key,
        &x_share_commitments,
        &partial_commitments,
    );

    if cheating_parties.is_empty() {
        let signature = result.expect("honest parties produce a signature");
        assert!(public_key.verify(message, &signature));
        assert!(public_key.verify(message, &signature_noabort));
    } else {
        match result {
            Err(error) => assert_eq!(error.into_inner(), cheating_parties),
            Ok(_) => panic!("cheating parties must be identified"),
        }
        assert!(!public_key.verify(message, &signature_noabort));
    }
}

#[test]
fn test_distributed_eddsa_3_parties() {
    test_distributed_eddsa(3, &[]);
}

#[test]
fn test_distributed_eddsa_30_parties() {
    test_distributed_eddsa(31, &[]);
}

#[test]
fn test_distributed_eddsa_identifies_cheating_parties() {
    test_distributed_eddsa(5, &[2, 4]);
}
