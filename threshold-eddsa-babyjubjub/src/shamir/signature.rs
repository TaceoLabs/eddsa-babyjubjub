//! Signature shares for the Shamir threshold `EdDSA` protocol.
//!
//! This module defines the `EdDSASigShareShamir` struct, one party's Lagrange-weighted share of
//! the response `s` of the final `EdDSA` signature.

use crate::signature::EdDSASigShare;
use serde::{Deserialize, Serialize};

/// Individual party's signature share for the Shamir `EdDSA` signature protocol.
///
/// Wraps the share of the challenge response for Shamir secret sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EdDSASigShareShamir(pub(crate) EdDSASigShare);
