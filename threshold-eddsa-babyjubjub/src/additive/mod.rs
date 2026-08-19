//! Threshold `EdDSA` with additive secret sharing.
//!
//! This module implements the `n`-out-of-`n` variant of the protocol, where the signing key is
//! split into shares that sum to it, so every party has to contribute to a signature.
//!
//! The types defined in the submodules are thin wrappers around the scheme-agnostic primitives in
//! the crate root modules `commit`, `nonce`, `partial_commit`, `session` and `signature`.

pub mod commit;
pub mod partial_commit;
pub mod secret;
pub mod session;
pub mod signature;
#[cfg(test)]
pub mod test;
