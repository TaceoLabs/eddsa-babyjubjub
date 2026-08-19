//! Re-sharing of a threshold `EdDSA` key to a new set of parties.
//!
//! This module implements the `ReShare` protocol, which lets a threshold sized subset of the parties
//! currently holding a key hand it over to a new, possibly differently sized, set of parties. The
//! signing key itself is unchanged, only the Shamir sharing of it is replaced.

pub mod blame;
pub mod receiver;
pub mod sender;
pub mod sender_set;
#[cfg(test)]
pub mod test;

pub(crate) type BroadcastMessage<C> = crate::keygen::round1::RoundOneBroadcast<C>;
pub(crate) type PartyMessage<C> = crate::keygen::round2::RoundTwoCommunication<C>;
