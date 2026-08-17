//! Per-party commitments for the additive threshold `EdDSA` protocol.
//!
//! This module defines the `PartialEdDSACommitmentsAdditive` struct, the commitment share a single
//! party sends to the aggregator in the pre-round.

use crate::partial_commit::PartialEdDSACommitments;
use serde::{Deserialize, Serialize};

/// Per-party commitment shares for the additive `EdDSA` protocol.
///
/// Wraps and serializes individual party commitments to the distributed `EdDSA` signature,
/// in the context of additive secret sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[repr(transparent)]
#[serde(transparent)]
pub struct PartialEdDSACommitmentsAdditive(pub(crate) PartialEdDSACommitments);
