use ark_ec::{
    AdditiveGroup,
    models::CurveConfig,
    twisted_edwards::{Affine, MontCurveConfig, Projective, TECurveConfig},
};
use ark_ff::{BigInt, Field, MontFp, Zero};

use crate::{Fq, Fr};

#[cfg(test)]
mod tests;

pub type EdwardsAffine = Affine<EdwardsConfig>;
pub type EdwardsProjective = Projective<EdwardsConfig>;

/// `Baby-JubJub` is a twisted Edwards curve. These curves have equations of the
/// form: ax² + y² = 1 + dx²y².
/// over some base finite field Fq.
///
/// Baby-JubJub's curve equation: 168700x² + y² = 1 + 168696x²y²
///
/// q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
#[derive(Clone, Default, PartialEq, Eq)]
pub struct EdwardsConfig;

impl CurveConfig for EdwardsConfig {
    type BaseField = Fq;
    type ScalarField = Fr;

    /// COFACTOR = 8
    const COFACTOR: &'static [u64] = &[8];

    /// COFACTOR^(-1) mod r =
    /// 2394026564107420727433200628387514462817212225638746351800188703329891451411
    const COFACTOR_INV: Fr =
        MontFp!("2394026564107420727433200628387514462817212225638746351800188703329891451411");
}

impl TECurveConfig for EdwardsConfig {
    /// COEFF_A = 168700
    const COEFF_A: Fq = MontFp!("168700");

    /// COEFF_D = 168696
    const COEFF_D: Fq = MontFp!("168696");

    /// AFFINE_GENERATOR_COEFFS = (GENERATOR_X, GENERATOR_Y)
    const GENERATOR: EdwardsAffine = EdwardsAffine::new_unchecked(GENERATOR_X, GENERATOR_Y);

    type MontCurveConfig = EdwardsConfig;

    /// We override this since the default implementation uses double-and-add and skips all leading zero bits of the scalar,
    /// which is not constant time. This implementation uses the same amount of instructions regardless of the scalar, at the cost of performance.
    fn mul_projective(base: &Projective<Self>, scalar: &[u64]) -> Projective<Self> {
        let mut r0 = Projective::<Self>::zero();
        let mut r1 = *base;
        let mut prev_bit = false;
        for b in ark_ff::BitIteratorBE::new(scalar) {
            let swap = prev_bit ^ b;
            prev_bit = b;
            conditional_swap(&mut r0, &mut r1, swap);
            r1 += r0;
            r0.double_in_place();
        }
        conditional_select(&mut r0, &r1, prev_bit);
        r0
    }

    /// Also override mul_affine to use our constant-time mul_projective.
    fn mul_affine(base: &Affine<Self>, scalar: &[u64]) -> Projective<Self> {
        let base = Projective::<Self>::from(*base);
        Self::mul_projective(&base, scalar)
    }
}

impl MontCurveConfig for EdwardsConfig {
    /// COEFF_A = 168698
    const COEFF_A: Fq = MontFp!("168698");
    /// COEFF_B = 1
    const COEFF_B: Fq = Fq::ONE;

    type TECurveConfig = EdwardsConfig;
}

/// GENERATOR_X =
/// 5299619240641551281634865583518297030282874472190772894086521144482721001553
pub const GENERATOR_X: Fq =
    MontFp!("5299619240641551281634865583518297030282874472190772894086521144482721001553");

/// GENERATOR_Y =
/// 16950150798460657717958625567821834550301663161624707787222815936182638968203
pub const GENERATOR_Y: Fq =
    MontFp!("16950150798460657717958625567821834550301663161624707787222815936182638968203");

// Helper functions for constant-time conditional swap and select, used in the montgomery ladder implementation.
#[inline(always)]
fn conditional_swap(a: &mut EdwardsProjective, b: &mut EdwardsProjective, c: bool) {
    let mask = (c as u64).wrapping_neg(); // all 1s if c is true, all 0s if c is false
    conditionally_swap_bigint(&mut a.x.0, &mut b.x.0, mask);
    conditionally_swap_bigint(&mut a.y.0, &mut b.y.0, mask);
    conditionally_swap_bigint(&mut a.z.0, &mut b.z.0, mask);
    conditionally_swap_bigint(&mut a.t.0, &mut b.t.0, mask);
}

#[inline(always)]
fn conditional_select(a: &mut EdwardsProjective, b: &EdwardsProjective, c: bool) {
    let mask = (c as u64).wrapping_neg(); // all 1s if c is true, all 0s if c is false
    conditionally_select_bigint(&mut a.x.0, b.x.0, mask);
    conditionally_select_bigint(&mut a.y.0, b.y.0, mask);
    conditionally_select_bigint(&mut a.z.0, b.z.0, mask);
    conditionally_select_bigint(&mut a.t.0, b.t.0, mask);
}

#[inline(always)]
fn conditionally_select_bigint<const N: usize>(a: &mut BigInt<N>, b: BigInt<N>, mask: u64) {
    // Since this is a compile-time constant N, the compiler should unroll this loop.
    for i in 0..N {
        a.0[i] ^= mask & (a.0[i] ^ b.0[i]);
    }
}

#[inline(always)]
fn conditionally_swap_bigint<const N: usize>(a: &mut BigInt<N>, b: &mut BigInt<N>, mask: u64) {
    // Since this is a compile-time constant N, the compiler should unroll this loop.
    for i in 0..N {
        let swap = mask & (a.0[i] ^ b.0[i]);
        a.0[i] ^= swap;
        b.0[i] ^= swap;
    }
}
