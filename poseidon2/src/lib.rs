#![deny(missing_docs, unsafe_code)]
//! Poseidon2 permutation methods for the `bn254` field, based on [eprint.iacr.org/2023/323](https://eprint.iacr.org/2023/323).
//!
//! This crate provides efficient, pure-Rust, minimal APIs to compute the Poseidon2 permutation (not hash) on all supported state sizes (`t2`, `t3`, `t4`, `t8`, `t12`, `t16`).
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
//! poseidon2::t4_permutation(&state);
//! poseidon2::t4_permutation_in_place(&mut state);
//! ```
//!
//! This crate is suitable for cryptographic circuits, SNARKs, and low-level integrations requiring only the permutation (not hashing).

mod perm;

pub use perm::bn254_t2::t2_permutation;
pub use perm::bn254_t2::t2_permutation_in_place;

pub use perm::bn254_t3::t3_permutation;
pub use perm::bn254_t3::t3_permutation_in_place;

pub use perm::bn254_t4::t4_permutation;
pub use perm::bn254_t4::t4_permutation_in_place;

pub use perm::bn254_t8::t8_permutation;
pub use perm::bn254_t8::t8_permutation_in_place;

pub use perm::bn254_t12::t12_permutation;
pub use perm::bn254_t12::t12_permutation_in_place;

pub use perm::bn254_t16::t16_permutation;
pub use perm::bn254_t16::t16_permutation_in_place;
