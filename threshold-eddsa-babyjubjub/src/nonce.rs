//! Two-Nonce Combination for Threshold `EdDSA`
//!
//! This module derives the full signing randomness `r = d + e*b` from the aggregated two-nonce
//! commitments, where the binding factor `b` is a hash over the session ID, the contributing
//! parties, the public key, both nonce commitments, and the message.
//!
//! The primitives defined here are agnostic to the underlying threshold sharing scheme and are used by
//! the Shamir variant, which is implemented in the submodule `shamir`.
//!
//! Binding the randomness to all of these inputs is what makes concurrent signing sessions safe,
//! as required by Frost3.
