//! Signature Shares for Threshold `EdDSA`
//!
//! This module defines the `EdDSASigShare` struct, a single party's share of the response `s` of
//! the final `EdDSA` signature.
//!
//! The primitives defined here are agnostic to the underlying threshold sharing scheme and are used by
//! the Shamir variant, which is implemented in the submodule `shamir`.
