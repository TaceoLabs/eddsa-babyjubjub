//! Re-sharing of a threshold `EdDSA` key to a new set of parties.
//!
//! This module implements the `ReShare` protocol, which lets a threshold sized subset of the parties
//! currently holding a key hand it over to a new, possibly differently sized, set of parties. The
//! signing key itself is unchanged, only the Shamir sharing of it is replaced.
//!
//! Every selected old sender must contribute a valid broadcast and a valid private evaluation to
//! every new party. Abort the run if a contribution is invalid or missing; restart with fresh
//! polynomials and a fresh context after agreeing on any change to the sender set. There is no
//! public share-revelation or participant-exclusion recovery protocol.

pub mod receiver;
pub mod sender;
pub mod sender_set;
#[cfg(test)]
pub mod test;

pub(crate) type BroadcastMessage<C> = crate::keygen::round1::RoundOneBroadcast<C>;
pub(crate) type PartyMessage<C> = crate::keygen::round2::RoundTwoCommunication<C>;
