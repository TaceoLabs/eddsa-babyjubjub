//! The final state of the DKG protocol.
//!
//! This module defines the `Finished` struct, which holds one party's share of the jointly
//! generated signing key together with the public information about all parties.

use ark_ec::CurveGroup;
use std::collections::HashMap;
use uuid::Uuid;
use zeroize::Zeroize;

/// The state of the DKG protocol after it has finished, holding the results of the protocol.
#[expect(
    clippy::exhaustive_structs,
    reason = "Only carries the results of the protocol - not planned to add something"
)]
pub struct Finished<C: CurveGroup> {
    /// The index of this party in the set of parties participating in the protocol.
    pub my_idx: u16,
    /// The session id shared by all parties of this protocol run.
    pub session_id: Uuid,
    /// This party's Shamir share of the jointly generated signing key.
    pub sk_share: C::ScalarField,
    /// The public counterparts of the secret key shares of all parties, indexed by party index.
    pub pk_shares: HashMap<u16, C::Affine>,
    /// The public key belonging to the jointly generated signing key.
    pub pk: C::Affine,
}

impl<C: CurveGroup> Drop for Finished<C> {
    fn drop(&mut self) {
        self.sk_share.zeroize();
    }
}
