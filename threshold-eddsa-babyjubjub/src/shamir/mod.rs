//! Threshold `EdDSA` with Shamir secret sharing.
//!
//! This module implements the `t`-out-of-`n` variant of the protocol, where the signing key is
//! shared via a polynomial of degree `d`, so any `d + 1` parties can jointly produce a signature
//! by weighting their shares with the matching Lagrange coefficients.
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
pub(crate) mod utils;
