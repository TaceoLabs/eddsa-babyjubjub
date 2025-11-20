//! Poseidon2 permutation methods for the `bn254` field, based on [eprint.iacr.org/2023/323](https://eprint.iacr.org/2023/323).
//!
//! This module provides efficient, pure-Rust, minimal APIs to compute the Poseidon2 permutation (not hash) on all supported state sizes (`t2`, `t3`, `t4`, `t8`, `t12`, `t16`).
//!
//! As specified in the paper, the S-box for `bn254` is defined as:
//! $$ x^5 $$
//!
//! Parameters are compatible with the original Poseidon2 [parameter generation script](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage).
//!
//! # Examples
//!
//! ```ignore
//! let mut state = [...];
//! poseidon2::bn254::t4::permutation(&state);
//! poseidon2::bn254::t4::permutation_in_place(&mut state);
//! ```
//!
//! All permutations are feature-gated, so enable only the once you need.

#[cfg(feature = "t12")]
pub mod t12;
#[cfg(feature = "t16")]
pub mod t16;
#[cfg(feature = "t2")]
pub mod t2;
#[cfg(feature = "t3")]
pub mod t3;
#[cfg(feature = "t4")]
pub mod t4;
#[cfg(feature = "t8")]
pub mod t8;

#[cfg(any(
    feature = "t2",
    feature = "t3",
    feature = "t4",
    feature = "t8",
    feature = "t12",
    feature = "t16"
))]
#[cfg(test)]
mod test {

    use crate::perm::Poseidon2Permutation;

    use ark_ff::PrimeField;
    use ark_std::rand::thread_rng;

    pub(crate) const TESTRUNS: usize = 10;

    pub(crate) fn poseidon2_kat<
        F: PrimeField,
        const T: usize,
        const D: u64,
        const ROUNDS_F: usize,
        const ROUNDS_P: usize,
    >(
        poseidon2_perm: &'static Poseidon2Permutation<F, T, D, ROUNDS_F, ROUNDS_P>,
        input: &[F; T],
        expected: &[F; T],
    ) {
        let result = poseidon2_perm.permutation(input);
        assert_eq!(&result, expected);
    }

    pub(crate) fn poseidon2_consistent_perm<
        F: PrimeField,
        const T: usize,
        const D: u64,
        const ROUNDS_F: usize,
        const ROUNDS_P: usize,
    >(
        poseidon2_perm: &'static Poseidon2Permutation<F, T, D, ROUNDS_F, ROUNDS_P>,
    ) {
        let mut rng = &mut thread_rng();
        let input1: Vec<F> = (0..T).map(|_| F::rand(&mut rng)).collect();
        let mut input2 = input1.clone();
        input2.rotate_right(T / 2);

        let perm1 = poseidon2_perm.permutation(input1.as_slice().try_into().unwrap());
        let perm2 = poseidon2_perm.permutation(&input1.try_into().unwrap());
        let perm3 = poseidon2_perm.permutation(&input2.try_into().unwrap());

        assert_eq!(perm1, perm2);
        assert_ne!(perm1, perm3);
    }
}
