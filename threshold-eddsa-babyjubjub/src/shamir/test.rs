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
use std::collections::BTreeMap;
use uuid::Uuid;

fn share<R: Rng>(
    secret: ScalarField,
    public_key: &EdDSAPublicKey,
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
        shares.push(
            DLogShareShamir::new(
                share,
                public_key,
                u16::try_from(i).expect("party ID fits"),
                u16::try_from(num_shares).expect("party count fits"),
                u16::try_from(degree + 1).expect("threshold fits"),
            )
            .expect("valid share metadata"),
        );
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
    for party_id in 1..=u16::try_from(num_parties).expect("party count fits") {
        let (session, comm) = EdDSASessionShamir::pre_round(party_id, rng).expect("valid party ID");
        sessions.push(Some(session));
        commitments.push(comm);
    }

    // 2) Aggregator accumulates commitments and creates challenge
    // Choose the commitments of the used parties
    let used_commitments = used_parties
        .iter()
        .map(|&i| commitments[i as usize - 1].clone())
        .collect::<Vec<_>>();

    let challenge = EdDSACommitmentsShamir::pre_agg(&used_commitments)
        .expect("valid identity-bound commitments");

    // 3) Aggregator challenges used used parties
    let mut used_sigs = Vec::with_capacity(num_parties);

    for server_idx in &used_parties {
        // we just use an option here in tests to be able to move out of the vector since the session is consumed
        let session = sessions[*server_idx as usize - 1]
            .take()
            .expect("have not used this session before");
        let x_ = &x_shares[*server_idx as usize - 1];
        let proof = session
            .sign_round(session_id, x_, message, challenge.clone())
            .expect("valid signing package");
        used_sigs.push(proof);
    }

    for &position in cheating_positions {
        used_sigs[position].0.1 += ScalarField::from(1_u64);
    }

    // 4) Aggregator combines received signature shares
    let used_public_key_shares = used_parties
        .iter()
        .map(|&party_id| (party_id, public_key_shares[usize::from(party_id) - 1]))
        .collect::<BTreeMap<_, _>>();

    // Without identifiable abort
    let signature_noabort = challenge
        .clone()
        .sign_agg(session_id, &used_sigs, message, public_key.clone())
        .expect("signature shares match the signing set");

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
        let mut expected = cheating_positions
            .iter()
            .map(|&position| usize::from(used_parties[position]))
            .collect::<Vec<_>>();
        expected.sort_unstable();
        match result {
            Err(error) => assert_eq!(
                error
                    .into_malicious_parties()
                    .expect("the abort must attribute blame, not report bad input"),
                expected,
            ),
            Ok(_) => panic!("cheating parties must be identified"),
        }
        assert!(!public_key.verify(message, &signature_noabort));
    }
}

fn test_threshold_eddsa(num_parties: usize, degree: usize, cheating_positions: &[usize]) {
    let mut rng = rand::thread_rng();

    let message = BaseField::rand(&mut rng);
    let x = ScalarField::rand(&mut rng);
    let public_key = EdDSAPublicKey {
        pk: (Affine::generator() * x).into_affine(),
    };
    let x_shares = share(x, &public_key, num_parties, degree, &mut rng);

    let public_key_shares = x_shares
        .iter()
        .map(|x| Affine::generator() * x.value)
        .collect::<Vec<_>>();
    let public_key_ =
        utils::test_utils::reconstruct_random_pointshares(&public_key_shares, degree, &mut rng);
    assert_eq!(public_key.pk, public_key_);

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

#[test]
fn aggregate_commitment_deserialization_enforces_party_invariants() {
    let mut rng = rand::thread_rng();
    let (_, commitment) = EdDSASessionShamir::pre_round(1, &mut rng).expect("valid party ID");
    let aggregate =
        EdDSACommitmentsShamir::pre_agg(&[commitment]).expect("valid aggregate commitment");
    let mut encoded = serde_json::to_value(aggregate).expect("serialize aggregate commitment");
    encoded["contributing_parties"] = serde_json::json!([0]);
    let Err(_) = serde_json::from_value::<EdDSACommitmentsShamir>(encoded) else {
        panic!("non-canonical commitment parties must be rejected");
    };
}

#[test]
fn signer_rejects_mismatched_identity_and_insufficient_sets() {
    let mut rng = rand::thread_rng();
    let message = BaseField::rand(&mut rng);
    let public_key = EdDSAPublicKey {
        pk: (Affine::generator() * ScalarField::rand(&mut rng)).into_affine(),
    };

    let (session, commitment) = EdDSASessionShamir::pre_round(1, &mut rng).expect("valid party ID");
    let aggregate =
        EdDSACommitmentsShamir::pre_agg(&[commitment]).expect("valid single-party commitment set");
    let other_party_share = DLogShareShamir::new(ScalarField::rand(&mut rng), &public_key, 2, 2, 1)
        .expect("valid metadata for another party");
    let Err(_) = session.sign_round(Uuid::new_v4(), &other_party_share, message, aggregate) else {
        panic!("a nonce session must not sign for another key-share identity");
    };

    let (session, commitment) = EdDSASessionShamir::pre_round(1, &mut rng).expect("valid party ID");
    let aggregate =
        EdDSACommitmentsShamir::pre_agg(&[commitment]).expect("valid single-party commitment set");
    let two_party_threshold_share =
        DLogShareShamir::new(ScalarField::rand(&mut rng), &public_key, 1, 2, 2)
            .expect("valid two-party threshold metadata");
    let Err(_) = session.sign_round(
        Uuid::new_v4(),
        &two_party_threshold_share,
        message,
        aggregate,
    ) else {
        panic!("a signer must reject a set below its bound threshold");
    };
}

/// A key share is bound to the public key it belongs to, and deserialization enforces that binding
/// and the committee metadata rather than deferring it to the signing path.
#[test]
fn key_share_deserialization_enforces_its_binding() {
    let mut rng = rand::thread_rng();
    let public_key = EdDSAPublicKey {
        pk: (Affine::generator() * ScalarField::rand(&mut rng)).into_affine(),
    };
    let share = DLogShareShamir::new(ScalarField::rand(&mut rng), &public_key, 2, 3, 2)
        .expect("valid share metadata");
    let encoded = serde_json::to_value(&share).expect("share serializes");
    let round_tripped = serde_json::from_value::<DLogShareShamir>(encoded.clone())
        .expect("an honest share round-trips");
    assert_eq!(round_tripped.public_key, public_key.pk);
    assert_eq!(round_tripped.party_id(), 2);
    assert_eq!(round_tripped.threshold(), 2);

    let tamper = |field: &str, value: serde_json::Value| {
        let mut encoded = encoded.clone();
        encoded[field] = value;
        serde_json::from_value::<DLogShareShamir>(encoded)
    };
    let Err(_) = tamper("party_id", 0.into()) else {
        panic!("a zero party ID must be rejected");
    };
    let Err(_) = tamper("party_id", 4.into()) else {
        panic!("a party ID outside the committee must be rejected");
    };
    let Err(_) = tamper("threshold", 0.into()) else {
        panic!("a zero threshold must be rejected");
    };
    let Err(_) = tamper("threshold", 4.into()) else {
        panic!("a threshold above the party count must be rejected");
    };
    // The neutral element (0, 1) is on the curve and in the prime-order subgroup, so the subgroup
    // check alone accepts it; the explicit non-zero check is what rejects it.
    let identity = serde_json::json!(["0", "1"]);
    let Err(_) = tamper("public_key", identity) else {
        panic!("an identity public key must be rejected");
    };

    // The share carries the key, so the signer cannot be pointed at a different one.
    let Err(_) = DLogShareShamir::new(
        ScalarField::rand(&mut rng),
        &EdDSAPublicKey { pk: Affine::zero() },
        1,
        3,
        2,
    ) else {
        panic!("a share must not be bound to a small-order public key");
    };
}
