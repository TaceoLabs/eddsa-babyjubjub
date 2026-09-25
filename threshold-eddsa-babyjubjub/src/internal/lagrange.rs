//! Utilities for Lagrange interpolation and polynomial evaluation over finite fields.
//!
//! Provides functions to compute Lagrange coefficients, evaluate polynomials, and reconstruct secrets from shares.

use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use std::num::NonZeroU16;

/// Computes the Lagrange coefficients for the provided party indices.
///
/// # Arguments
///
/// * `coeffs` - Slice of party indices.
///
/// # Returns
///
/// Vector of Lagrange coefficients for each party.
#[cfg(test)]
pub fn lagrange_from_coeff<F: PrimeField + From<T>, T: Copy + Eq>(coeffs: &[T]) -> Vec<F> {
    let num = coeffs.len();
    let mut res = Vec::with_capacity(num);
    for i in coeffs {
        res.push(single_lagrange_from_coeff(*i, coeffs.iter().copied()));
    }
    res
}

/// Computes the Lagrange coefficient for a specific party identifier.
///
/// # Arguments
///
/// * `my_id` - Party identifier.
/// * `coeffs` - Iterator over the party indices.
///
/// # Returns
///
/// The Lagrange coefficient for `my_id`.
///
/// # Panics
/// Might panic if chosen `T` does not fit into `Primefield`.
pub fn single_lagrange_from_coeff<F: PrimeField + From<T>, T: Copy + Eq>(
    my_id: T,
    coeffs: impl IntoIterator<Item = T>,
) -> F {
    let mut num = F::one();
    let mut den = F::one();
    let i_ = F::from(my_id);
    for j in coeffs {
        if my_id != j {
            let j_ = F::from(j);
            num *= j_;
            den *= j_ - i_;
        }
    }
    num * den.inverse().expect("Has an inverse")
}

/// Evaluates a polynomial at the given point.
///
/// # Arguments
///
/// * `poly` - Coefficients of the polynomial, low to high degree.
/// * `x` - The point at which to evaluate.
///
/// # Returns
///
/// The polynomial evaluated at `x`.
///
/// # Panics
/// If the provided polynomial is empty.
pub fn evaluate_poly<F: PrimeField>(poly: &[F], x: F) -> F {
    assert!(!poly.is_empty(), "Poly must not be empty");
    let mut iter = poly.iter().rev();
    let mut eval = iter.next().expect("Checked that not empty").to_owned();
    for coeff in iter {
        eval *= x;
        eval += coeff;
    }
    eval
}

/// Evaluates a committed polynomial in the exponent at a party index.
///
/// The party index is a [`NonZeroU16`], so the evaluation can never silently return the
/// commitment to the constant term, which in the reshare protocol is the sender's secret key
/// share.
///
/// # Panics
/// Panics if `coefficients` is empty.
pub fn evaluate_polynomial_in_exponent<C: CurveGroup>(
    coefficients: &[C::Affine],
    party_idx: NonZeroU16,
) -> C {
    // since the party index is non-zero, this is non zero
    let x = C::ScalarField::from(party_idx.get());

    assert!(!coefficients.is_empty(), "Poly must not be empty");
    let mut iter = coefficients.iter().rev();
    let mut result = iter
        .next()
        .expect("Checked that not empty")
        .to_owned()
        .into_group();

    // evaluate the poly using Horner's algorithm
    for coeff in iter {
        result *= &x;
        result += coeff;
    }

    result
}

/// Checks a private polynomial evaluation against the public coefficient commitments.
///
/// An empty commitment vector is rejected rather than evaluated, and the non-zero party index
/// guarantees a share can never verify against the constant term alone.
pub fn verify_polynomial_evaluation<C: CurveGroup>(
    commitments: &[C::Affine],
    party_idx: NonZeroU16,
    share: &C::ScalarField,
) -> bool {
    if commitments.is_empty() {
        return false;
    }
    let result = evaluate_polynomial_in_exponent::<C>(commitments, party_idx);
    result == C::generator() * share
}
