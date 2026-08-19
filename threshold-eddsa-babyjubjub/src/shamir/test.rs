//! End-to-end tests for the Shamir threshold `EdDSA` protocol, covering both plain aggregation
//! and aggregation with identifiable abort.

use crate::{
    Affine, BaseField, ScalarField,
    shamir::{
        commit::EdDSACommitmentsShamir,
        secret::DLogShareShamir,
        session::EdDSASessionShamir,
        utils::{self, evaluate_poly},
    },
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::UniformRand;
use eddsa_babyjubjub::EdDSAPublicKey;
use rand::{CryptoRng, Rng, seq::IteratorRandom};
use uuid::Uuid;

fn share<R: Rng>(
    secret: ScalarField,
    num_shares: usize,
    degree: usize,
    rng: &mut R,
) -> Vec<DLogShareShamir> {
    let mut shares: Vec<DLogShareShamir> = Vec::with_capacity(num_shares);
    let mut coeffs = Vec::with_capacity(degree + 1);
    coeffs.push(secret);
    for _ in 0..degree {
        coeffs.push(ScalarField::rand(rng));
    }
    for i in 1..=num_shares {
        let share = evaluate_poly(&coeffs, ScalarField::from(i as u64));
        shares.push(DLogShareShamir(share));
    }
    shares
}

#[expect(
    clippy::too_many_arguments,
    reason = "Shared test driver for the plain and the DKG-based signing flow"
)]
pub(crate) fn test_threshold_eddsa_inner<R: Rng + CryptoRng>(
    num_parties: usize,
    degree: usize,
    cheating_positions: &[usize],
    message: BaseField,
    x_shares: &[DLogShareShamir],
    public_key: &EdDSAPublicKey,
    public_key_shares: &[Affine],
    rng: &mut R,
) {
    // Crete session and choose the used set of parties
    let session_id = Uuid::new_v4();
    let used_parties =
        (1..=u16::try_from(num_parties).expect("Fits into u16")).choose_multiple(rng, degree + 1);

    // 1) Aggregator requests commitments from all servers
    let mut sessions = Vec::with_capacity(num_parties);
    let mut commitments = Vec::with_capacity(num_parties);
    for _ in 0..num_parties {
        let (session, comm) = EdDSASessionShamir::pre_round(rng);
        sessions.push(Some(session));
        commitments.push(comm);
    }

    // 2) Aggregator accumulates commitments and creates challenge
    // Choose the commitments of the used parties
    let used_commitments = used_parties
        .iter()
        .map(|&i| commitments[i as usize - 1].clone())
        .collect::<Vec<_>>();

    let challenge = EdDSACommitmentsShamir::pre_agg(&used_commitments, used_parties.clone());

    // 3) Aggregator challenges used used parties
    let mut used_sigs = Vec::with_capacity(num_parties);

    for server_idx in &used_parties {
        // we just use an option here in tests to be able to move out of the vector since the session is consumed
        let session = sessions[*server_idx as usize - 1]
            .take()
            .expect("have not used this session before");
        let x_ = &x_shares[*server_idx as usize - 1];
        let lagrange = utils::single_lagrange_from_coeff(*server_idx, &used_parties);
        let proof = session.sign_round(
            session_id,
            x_,
            message,
            public_key,
            challenge.clone(),
            lagrange,
        );
        used_sigs.push(proof);
    }

    for &position in cheating_positions {
        used_sigs[position].0.0 += ScalarField::from(1_u64);
    }

    // 4) Aggregator combines received signature shares
    let used_public_key_shares = used_parties
        .iter()
        .map(|&party_id| public_key_shares[usize::from(party_id) - 1])
        .collect::<Vec<_>>();

    // Without identifiable abort
    let signature_noabort =
        challenge
            .clone()
            .sign_agg(session_id, &used_sigs, message, public_key.clone());

    // With identifiable abort
    let result = challenge.sign_agg_with_identifiable_abort(
        session_id,
        &used_sigs,
        message,
        public_key,
        &used_public_key_shares,
        &used_commitments,
    );

    if cheating_positions.is_empty() {
        let signature = result.expect("honest parties produce a signature");
        assert!(public_key.verify(message, &signature));
        assert!(public_key.verify(message, &signature_noabort));
    } else {
        let expected = cheating_positions
            .iter()
            .map(|&position| usize::from(used_parties[position]))
            .collect::<Vec<_>>();
        match result {
            Err(error) => assert_eq!(error.into_inner(), expected),
            Ok(_) => panic!("cheating parties must be identified"),
        }
        assert!(!public_key.verify(message, &signature_noabort));
    }
}

fn test_threshold_eddsa(num_parties: usize, degree: usize, cheating_positions: &[usize]) {
    let mut rng = rand::thread_rng();

    let message = BaseField::rand(&mut rng);
    let x = ScalarField::rand(&mut rng);
    let x_shares = share(x, num_parties, degree, &mut rng);

    // Create public keys
    let public_key = (Affine::generator() * x).into_affine();
    let public_key_shares = x_shares
        .iter()
        .map(|x| Affine::generator() * x.0)
        .collect::<Vec<_>>();
    let public_key_ =
        utils::test_utils::reconstruct_random_pointshares(&public_key_shares, degree, &mut rng);
    assert_eq!(public_key, public_key_);
    let public_key = EdDSAPublicKey { pk: public_key };

    let public_key_shares = public_key_shares
        .iter()
        .map(|&pk_share| pk_share.into_affine())
        .collect::<Vec<_>>();

    test_threshold_eddsa_inner(
        num_parties,
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
fn test_threshold_eddsa_shamir_3_1() {
    test_threshold_eddsa(3, 1, &[]);
}

#[test]
fn test_threshold_eddsa_shamir_31_15() {
    test_threshold_eddsa(31, 15, &[]);
}

#[test]
fn test_threshold_eddsa_shamir_identifies_cheating_parties() {
    test_threshold_eddsa(7, 3, &[0, 2]);
}
