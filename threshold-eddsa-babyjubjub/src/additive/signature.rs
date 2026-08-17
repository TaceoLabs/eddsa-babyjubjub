//! Signature shares for the additive threshold `EdDSA` protocol.
//!
//! This module defines the `EdDSASigShareAdditive` struct, one party's share of the response `s`
//! of the final `EdDSA` signature.

use crate::signature::EdDSASigShare;
use serde::{Deserialize, Serialize};

/// Individual party's signature share for the additive `EdDSA` signature protocol.
///
/// Wraps the share of the challenge response for additive secret sharing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EdDSASigShareAdditive(pub(crate) EdDSASigShare);
