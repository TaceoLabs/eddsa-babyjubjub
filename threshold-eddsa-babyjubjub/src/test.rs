//! End-to-end tests for the Shamir threshold `EdDSA` protocol, covering both plain aggregation
//! and aggregation with identifiable abort.

use crate::{
    Affine, BaseField, ScalarField,
    commit::EdDSACommitments,
    secret::DLogShareShamir,
    session::EdDSASession,
    utils::{self, evaluate_poly},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{One, UniformRand, Zero};
use eddsa_babyjubjub::EdDSAPublicKey;
use rand::{CryptoRng, Rng, seq::IteratorRandom};
use std::{collections::BTreeMap, num::NonZeroU16};
use uuid::Uuid;

fn nz(id: u16) -> NonZeroU16 {
    NonZeroU16::new(id).expect("party ID must be non-zero")
}

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
                nz(u16::try_from(i).expect("party ID fits")),
                nz(u16::try_from(num_shares).expect("party count fits")),
                nz(u16::try_from(degree + 1).expect("threshold fits")),
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
    let used_parties = (1..=u16::try_from(num_parties).expect("Fits into u16"))
        .map(nz)
        .choose_multiple(rng, degree + 1);

    // 1) Aggregator requests commitments from all servers
    let mut sessions = Vec::with_capacity(num_parties);
    let mut commitments = Vec::with_capacity(num_parties);
    for party_id in 1..=u16::try_from(num_parties).expect("party count fits") {
        let (session, comm) = EdDSASession::pre_round(nz(party_id), rng);
        sessions.push(Some(session));
        commitments.push(comm);
    }

    // 2) Aggregator accumulates commitments and creates challenge
    // Choose the commitments of the used parties
    let used_commitments = used_parties
        .iter()
        .map(|&i| commitments[usize::from(i.get()) - 1].clone())
        .collect::<Vec<_>>();

    let challenge =
        EdDSACommitments::pre_agg(&used_commitments).expect("valid identity-bound commitments");

    // 3) Aggregator challenges used used parties
    let mut used_sigs = Vec::with_capacity(num_parties);

    for server_idx in &used_parties {
        // we just use an option here in tests to be able to move out of the vector since the session is consumed
        let session = sessions[usize::from(server_idx.get()) - 1]
            .take()
            .expect("have not used this session before");
        let x_ = &x_shares[usize::from(server_idx.get()) - 1];
        let proof = session
            .sign_round(session_id, x_, message, challenge.clone())
            .expect("valid signing package");
        used_sigs.push(proof);
    }

    for &position in cheating_positions {
        used_sigs[position].1 += ScalarField::from(1_u64);
    }

    // 4) Aggregator combines received signature shares
    let used_public_key_shares = used_parties
        .iter()
        .map(|&party_id| (party_id, public_key_shares[usize::from(party_id.get()) - 1]))
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
            .map(|&position| usize::from(used_parties[position].get()))
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

/// A duplicated signature-share party ID must be rejected as invalid input. Silently collapsing
/// duplicates (last one wins) would let a forged duplicate replace the honest share and get the
/// honest party blamed by the identifiable-abort path.
#[test]
fn aggregation_rejects_duplicate_signature_shares() {
    let mut rng = rand::thread_rng();
    let message = BaseField::rand(&mut rng);
    let x = ScalarField::rand(&mut rng);
    let public_key = EdDSAPublicKey {
        pk: (Affine::generator() * x).into_affine(),
    };
    let x_shares = share(x, &public_key, 3, 1, &mut rng);
    let session_id = Uuid::new_v4();

    let mut sessions = Vec::new();
    let mut commitments = Vec::new();
    for party_id in 1..=2 {
        let (session, comm) = EdDSASession::pre_round(nz(party_id), &mut rng);
        sessions.push(session);
        commitments.push(comm);
    }
    let challenge = EdDSACommitments::pre_agg(&commitments).expect("valid commitment set");

    let mut sig_shares = sessions
        .into_iter()
        .zip(&x_shares)
        .map(|(session, x_share)| {
            session
                .sign_round(session_id, x_share, message, challenge.clone())
                .expect("valid signing package")
        })
        .collect::<Vec<_>>();

    // A forged duplicate carrying honest party 2's ID.
    let mut forged = sig_shares[1].clone();
    forged.1 += ScalarField::from(1_u64);
    sig_shares.push(forged);

    let Err(_) = challenge
        .clone()
        .sign_agg(session_id, &sig_shares, message, public_key.clone())
    else {
        panic!("duplicate signature-share party IDs must be rejected");
    };

    let public_key_shares = x_shares[..2]
        .iter()
        .map(|x_share| {
            (
                x_share.party_id(),
                (Affine::generator() * x_share.value).into_affine(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    match challenge.sign_agg_with_identifiable_abort(
        session_id,
        &sig_shares,
        message,
        &public_key,
        &public_key_shares,
        &commitments,
    ) {
        Err(error) => assert!(
            error.malicious_parties().is_none(),
            "a duplicate share is inconsistent input, not proof that its author cheated"
        ),
        Ok(_) => panic!("duplicate signature-share party IDs must be rejected"),
    }
}

/// A malformed public-key share is inconsistent aggregation input and must be reported as
/// `InvalidInput`, never blamed on the party: the Lagrange reconstruction check cannot detect
/// torsion components that cancel under even coefficients, and without up-front validation the
/// per-share check would misattribute them as cheating.
#[test]
fn identifiable_abort_rejects_malformed_public_key_shares_as_invalid_input() {
    let mut rng = rand::thread_rng();
    let message = BaseField::rand(&mut rng);
    let x = ScalarField::rand(&mut rng);
    let public_key = EdDSAPublicKey {
        pk: (Affine::generator() * x).into_affine(),
    };
    let x_shares = share(x, &public_key, 2, 1, &mut rng);
    let session_id = Uuid::new_v4();

    let mut sessions = Vec::new();
    let mut commitments = Vec::new();
    for party_id in 1..=2 {
        let (session, comm) = EdDSASession::pre_round(nz(party_id), &mut rng);
        sessions.push(session);
        commitments.push(comm);
    }
    let challenge = EdDSACommitments::pre_agg(&commitments).expect("valid commitment set");
    let sig_shares = sessions
        .into_iter()
        .zip(&x_shares)
        .map(|(session, x_share)| {
            session
                .sign_round(session_id, x_share, message, challenge.clone())
                .expect("valid signing package")
        })
        .collect::<Vec<_>>();

    // Over the signing set {1, 2}, party 1's Lagrange coefficient is 2, so an order-2 torsion
    // component added to X_1 cancels out of the public-key reconstruction check.
    let torsion = Affine::new_unchecked(BaseField::zero(), -BaseField::one());
    let mut public_key_shares = x_shares
        .iter()
        .map(|x_share| {
            (
                x_share.party_id(),
                (Affine::generator() * x_share.value).into_affine(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let tampered = (public_key_shares[&nz(1)].into_group() + torsion).into_affine();
    public_key_shares.insert(nz(1), tampered);

    match challenge.sign_agg_with_identifiable_abort(
        session_id,
        &sig_shares,
        message,
        &public_key,
        &public_key_shares,
        &commitments,
    ) {
        Err(error) => assert!(
            error.malicious_parties().is_none(),
            "a malformed public-key share is inconsistent input, not proof that a party cheated"
        ),
        Ok(_) => panic!("a malformed public-key share must abort the aggregation"),
    }
}

#[test]
fn aggregate_commitment_deserialization_enforces_party_invariants() {
    let mut rng = rand::thread_rng();
    let (_, commitment) = EdDSASession::pre_round(nz(1), &mut rng);
    let aggregate = EdDSACommitments::pre_agg(&[commitment]).expect("valid aggregate commitment");
    let mut encoded = serde_json::to_value(aggregate).expect("serialize aggregate commitment");
    // A zero party ID is unrepresentable as a `NonZeroU16`, so Serde itself rejects it.
    encoded["contributing_parties"] = serde_json::json!([0]);
    let Err(_) = serde_json::from_value::<EdDSACommitments>(encoded.clone()) else {
        panic!("a zero commitment party ID must be rejected");
    };
    encoded["contributing_parties"] = serde_json::json!([2, 1]);
    let Err(_) = serde_json::from_value::<EdDSACommitments>(encoded) else {
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

    let (session, commitment) = EdDSASession::pre_round(nz(1), &mut rng);
    let aggregate =
        EdDSACommitments::pre_agg(&[commitment]).expect("valid single-party commitment set");
    let other_party_share = DLogShareShamir::new(
        ScalarField::rand(&mut rng),
        &public_key,
        nz(2),
        nz(2),
        nz(1),
    )
    .expect("valid metadata for another party");
    let Err(_) = session.sign_round(Uuid::new_v4(), &other_party_share, message, aggregate) else {
        panic!("a nonce session must not sign for another key-share identity");
    };

    let (session, commitment) = EdDSASession::pre_round(nz(1), &mut rng);
    let aggregate =
        EdDSACommitments::pre_agg(&[commitment]).expect("valid single-party commitment set");
    let two_party_threshold_share = DLogShareShamir::new(
        ScalarField::rand(&mut rng),
        &public_key,
        nz(1),
        nz(2),
        nz(2),
    )
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
    let share = DLogShareShamir::new(
        ScalarField::rand(&mut rng),
        &public_key,
        nz(2),
        nz(3),
        nz(2),
    )
    .expect("valid share metadata");
    let encoded = serde_json::to_value(&share).expect("share serializes");
    let round_tripped = serde_json::from_value::<DLogShareShamir>(encoded.clone())
        .expect("an honest share round-trips");
    assert_eq!(round_tripped.public_key, public_key.pk);
    assert_eq!(round_tripped.party_id(), nz(2));
    assert_eq!(round_tripped.threshold(), nz(2));

    let tamper = |field: &str, value: serde_json::Value| {
        let mut encoded = encoded.clone();
        encoded[field] = value;
        serde_json::from_value::<DLogShareShamir>(encoded)
    };
    // Zero is unrepresentable as a `NonZeroU16`, so Serde itself rejects it.
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
        nz(1),
        nz(3),
        nz(2),
    ) else {
        panic!("a share must not be bound to a small-order public key");
    };
}
