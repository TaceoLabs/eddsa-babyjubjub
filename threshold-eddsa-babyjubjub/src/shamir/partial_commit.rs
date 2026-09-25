//! Per-party commitments for the Shamir threshold `EdDSA` protocol.
//!
//! This module defines the `PartialEdDSACommitmentsShamir` struct, the commitment share a single
//! party sends to the aggregator in the pre-round.

use crate::partial_commit::PartialEdDSACommitments;
use serde::{Deserialize, Serialize};

/// Per-party commitment shares for Shamir `EdDSA` protocol.
///
/// Wraps and serializes individual party commitments to the distributed `EdDSA` signature,
/// in the context of Shamir secret sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct PartialEdDSACommitmentsShamir(pub(crate) PartialEdDSACommitments);

impl PartialEdDSACommitmentsShamir {
    /// Return the party ID carried by this commitment.
    #[must_use]
    pub fn party_id(&self) -> u16 {
        self.0.party_id()
    }
}
