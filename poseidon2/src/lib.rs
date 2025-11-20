#![deny(missing_docs, unsafe_code)]
//! Poseidon2 permutation methods, based on [eprint.iacr.org/2023/323](https://eprint.iacr.org/2023/323).
//!
//! This crate provides efficient, pure-Rust, minimal APIs to compute the Poseidon2 permutation (not hash) on all supported state sizes (`t2`, `t3`, `t4`, `t8`, `t12`, `t16`).
//!
//! Currently, the only supported field is the scalar field of `bn254`.
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
//! This crate is suitable for cryptographic circuits, SNARKs, and low-level integrations requiring only the permutation (not hashing).

#[cfg(feature = "bn254")]
pub mod bn254;
mod perm;
