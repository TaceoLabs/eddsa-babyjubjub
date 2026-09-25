# Threshold EdDSA over Baby Jubjub

Threshold signing for the Poseidon2-based Baby Jubjub EdDSA implementation in
[`taceo-eddsa-babyjubjub`](../eddsa-babyjubjub).

The signing protocol is an adaptation of **FROST3**, the semi-interactive
threshold Schnorr construction described in
[ROAST: Robust Asynchronous Schnorr Threshold Signatures](https://eprint.iacr.org/2022/550.pdf).
It produces an ordinary `EdDSASignature`, so the result is verified with the
existing single-party `EdDSAPublicKey::verify` API.

## Features

- `t`-out-of-`n` EdDSA signing with Shamir-shared keys.
- A FROST3 two-nonce preprocessing round that can run before the message is
  known, followed by one signing round.
- Binding of the signer set, session ID, aggregate nonce commitments, public
  key, and message into the BLAKE3 nonce-combining hash.
- Poseidon2 for the final EdDSA Fiat-Shamir challenge.
- Signature-share aggregation with optional identifiable abort.
- Serde support for protocol messages and zeroization of secret state on drop.

The package name is `taceo-threshold-eddsa-babyjubjub`. The crate currently
requires Rust 1.90 or newer.

```toml
[dependencies]
taceo-threshold-eddsa-babyjubjub = "0.1"
```

## Network requirements

The protocol APIs operate on already-delivered messages. Bind the externally
authenticated sender identity to the `from` argument; never trust an ID carried
only by an unauthenticated transport.

| Protocol step | Required channel | Why |
| --- | --- | --- |
| FROST3 preprocessing commitments and signature shares | **Authenticated signer-to-aggregator communication** | The aggregator must attribute each contribution to the correct signer. Reliable broadcast is not required for the signing flow implemented here. |

Protocol deserializers cap participant-sized collections at the largest count
representable by a `u16`. This is a defense-in-depth limit, not a network frame
limit: reject oversized byte frames before invoking Serde, because the input
format and individual field encodings may allocate while decoding.

## Threshold signing

The protocol proceeds as follows:

- `EdDSASession::pre_round` samples two secret, single-use nonces and
  returns their public, identity-bound `PartialEdDSACommitments`.
- The aggregator selects a signing set of at least the threshold size and calls
  `EdDSACommitments::pre_agg`; aggregation canonicalizes the party order
  and rejects empty or duplicate sets.
- Each selected party consumes its session with
  `EdDSASession::sign_round`. The signer validates its identity and
  committee metadata and derives both its Lagrange coefficient and the public key
  internally, from the `DLogShareShamir` it was given. `sign_round` takes no
  public key argument, so a signer cannot be pointed at a key it does not hold a
  share of.
- The aggregator calls `sign_agg` or, when public-key shares and individual
  commitments are available, `sign_agg_with_identifiable_abort`.

The high-level message flow is:

```text
signers                         aggregator
   |-- pre-round commitments ------>|
   |                                | select signer set T
   |<-- (session ID, T, aggregate commitments, public key, message)
   |-- signature shares ----------->|
   |                                | aggregate and verify
   |                                `--> ordinary EdDSA signature
```

Commitments and signature shares carry party IDs, and public-key shares used
for identifiable abort are supplied in a `BTreeMap<u16, Affine>`. The map must
come from an authenticated, immutable source; the type system cannot
authenticate application-provided public-key metadata. Prefer
`sign_agg_with_identifiable_abort` when an invalid share must be attributed;
plain `sign_agg` only combines shares and may therefore return a signature that
does not verify if a participant supplied a malformed share.

`sign_agg_with_identifiable_abort` fails with `IdentifiableAbortError`, which
separates the two outcomes that must not be conflated:
`MaliciousParties` names the parties whose share failed validation, while
`InvalidInput` means the aggregator's own inputs were inconsistent, so nothing
was validated and nobody may be accused. Read the attribution with
`IdentifiableAbortError::malicious_parties`; logging the error alone discards it.

A `DLogShareShamir` binds its scalar to a party ID, the committee size, the
threshold, and the public key. Build it with `DLogShareShamir::new`, which
rejects out-of-range metadata and a small-order public key; deserialization
enforces the same invariants, so a persisted share cannot be loaded with its
binding altered.

The final threshold signature is an
`eddsa_babyjubjub::EdDSASignature` and is verified exactly like a regular
signature:

```rust,ignore
let valid = public_key.verify(message, &signature);
```

### Nonce and session safety

`EdDSASession` deliberately cannot be cloned and `sign_round` consumes it.
Never reuse or restore its nonce state. Use a fresh, globally unique UUID for
each logical signing attempt, and ensure every participant agrees on the same
session ID, signer set, public key, and message. Secret-key shares must be
stored and transported as secrets.

### Side-channel limitations

The Baby Jubjub implementation uses arkworks curve and field arithmetic. The
arkworks 0.6 scalar-multiplication implementation is not guaranteed to be
constant-time and includes secret-dependent control flow. Consequently, this
crate must not be treated as resistant to local timing, cache, branch-trace,
power, or similar side-channel attackers. Deploy it only where that threat is
excluded or use a separately reviewed constant-time arithmetic backend.

## References

- Tim Ruffing et al., [ROAST: Robust Asynchronous Schnorr Threshold
  Signatures](https://eprint.iacr.org/2022/550.pdf), especially the FROST3
  signing algorithms and identifiable-abort construction.

## License

Licensed under either of Apache License, Version 2.0 or the MIT license, at your
option.
