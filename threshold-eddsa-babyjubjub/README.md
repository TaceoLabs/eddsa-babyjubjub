# Threshold EdDSA over Baby Jubjub

Threshold signing and distributed key generation for the
Poseidon2-based Baby Jubjub EdDSA implementation in
[`taceo-eddsa-babyjubjub`](../eddsa-babyjubjub).

The signing protocol is an adaptation of **FROST3**, the semi-interactive
threshold Schnorr construction described in
[ROAST: Robust Asynchronous Schnorr Threshold Signatures](https://eprint.iacr.org/2022/550.pdf).
It produces an ordinary `EdDSASignature`, so the result is verified with the
existing single-party `EdDSAPublicKey::verify` API. The distributed key
generation (DKG) protocol uses Feldman commitments and Schnorr proofs of
possession, following the abort-on-error model of
[`frost-core` key generation](https://docs.rs/frost-core/3.0.0/frost_core/keys/dkg/index.html).

> [!WARNING]
> **Key generation requires reliable broadcast for the messages
> marked “reliable broadcast” below.** Sending a message separately to every
> participant is not sufficient: a malicious sender must not be able to make
> two honest participants accept different messages for the same protocol step.
> The application must provide agreement, sender authentication, duplicate
> suppression, and coordination of aborted runs and restarts.
>
> This crate does not implement networking, reliable broadcast, participant
> authentication, persistence, or timeouts. Supplying these is the integrator's
> responsibility. A consensus-backed ledger, a smart contract, or a dedicated
> Byzantine reliable-broadcast protocol are possible implementations.

## Features

- `t`-out-of-`n` EdDSA signing with Shamir-shared keys.
- A FROST3 two-nonce preprocessing round that can run before the message is
  known, followed by one signing round.
- Binding of an opaque caller-supplied context, the signer set, aggregate nonce
  commitments, public key, and message into the BLAKE3 nonce-combining hash.
- Poseidon2 for the final EdDSA Fiat-Shamir challenge.
- Signature-share aggregation with optional identifiable abort.
- Dealerless DKG requiring valid contributions from every configured participant.
- Serde support for protocol messages and zeroization of secret state on drop.

The package name is `taceo-threshold-eddsa-babyjubjub`. The crate currently
requires Rust 1.90 or newer.

```toml
[dependencies]
taceo-threshold-eddsa-babyjubjub = "0.1"
```

## Network requirements

The protocol APIs operate on already-delivered messages and identify senders
only by the party ID embedded in each message. That ID is a self-claimed field:
before passing a commitment or signature share to the aggregation APIs, check
that its `party_id()` equals the identity the transport authenticated. Never
trust an ID carried only by an unauthenticated transport — a message accepted
under the wrong ID lets its sender speak, and be blamed, as someone else.

| Protocol step | Required channel | Why |
| --- | --- | --- |
| FROST3 preprocessing commitments and signature shares | **Authenticated signer-to-aggregator communication** | The aggregator must attribute each contribution to the correct signer. Reliable broadcast is not required for the signing flow implemented here. |
| Signing requests (context, signer set, aggregate commitments, message) | **Authenticated aggregator-to-signer communication** | Blame from `sign_agg_with_identifiable_abort` is sound only if every signer received exactly the inputs the aggregator later verifies against. A tampered request makes the honest recipient's share fail validation, so the honest signer is blamed. |
| DKG round-one polynomial commitments and proof of possession | **Reliable broadcast to every DKG party** | All honest parties must use the same commitments and derive the same public key and public-key shares. |
| DKG round-two polynomial evaluations | **Private, authenticated point-to-point channel** | Each evaluation is a secret intended only for its recipient. |
| DKG restarts | **Agreement on a fresh session and participant set** | Discard an aborted run and generate fresh polynomials before retrying. |

The authenticated channels must also be replay-protected and bind each message
to its protocol, session, sender, and recipient. DKG round-one proofs bind the
session context; private round-two messages carry only a scalar. A share replayed
from another session fails validation and can incorrectly implicate its honest
author. The same transport binding is required for signing messages.

Reliable broadcast means more than best-effort multicast. In particular, if one
honest participant accepts a broadcast from a sender, all honest participants
that complete the step must accept the same payload from that sender. Do not
advance merely because a local node has received enough mutually inconsistent
point-to-point copies.

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
   |<-- (context, T, aggregate commitments, public key, message)
   |-- signature shares ----------->|
   |                                | aggregate and verify
   |                                `--> ordinary EdDSA signature
```

Party IDs, the committee size, and the signing threshold are `NonZeroU16`
values, so a zero ID is unrepresentable and rejected already during
deserialization.

We recommend limiting the total committee size `n` to **128 participants**,
following the [FROST3 signing draft (BIP 445)](https://github.com/siv2r/bip-frost-signing#footnotes),
which adopts this bound to address adaptive-corruption concerns related to the
Low-Dimensional Vector Representation (LDVR) problem. This recommendation applies
to the full committee, including participants not selected for a particular
signing session, and is not enforced by the API. The draft's security rationale
is specific to secp256k1; establishing the corresponding adaptive-security
guarantees for Baby Jubjub requires a separate analysis.

Commitments and signature shares carry party IDs, and public-key shares used
for identifiable abort are supplied in a `BTreeMap<NonZeroU16, Affine>`. The map must
come from an authenticated, immutable source such as the DKG output; the type
system cannot
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
rejects zero secret shares, out-of-range metadata, and a small-order public key;
deserialization enforces the same invariants, so a persisted share cannot be
loaded with its binding altered.

The final threshold signature is an
`eddsa_babyjubjub::EdDSASignature` and is verified exactly like a regular
signature:

```rust,ignore
let valid = public_key.verify(message, &signature);
```

### Nonce and session safety

`EdDSASession` deliberately cannot be cloned and `sign_round` consumes it.
Never reuse or restore its nonce state. Secret-key shares and DKG polynomial
evaluations must be stored and transported as secrets.

`sign_round` and the aggregation APIs take an opaque `context: &[u8]` that is
mixed into the nonce-binding hash. Every participant of one session must use
byte-identical context bytes, alongside the same signer set, public key, and
message; a participant with a mismatched context produces an invalid share and
is blamed by `sign_agg_with_identifiable_abort`. Use the context to bind the
session to application data — a unique session identifier, an application
label, a key epoch. Unforgeability does not depend on it (the fresh nonce
commitments already make each session's binding factor unique), and it is not
verifier-visible domain separation: the final signature is a plain EdDSA
signature over the message and verifies regardless of the context it was
produced under. An empty context is therefore safe, but forgoes the early
abort on crossed sessions that a unique per-session context provides.

### Side-channel limitations

The Baby Jubjub implementation uses arkworks curve and field arithmetic. The
arkworks 0.6 scalar-multiplication implementation is not guaranteed to be
constant-time and includes secret-dependent control flow. Consequently, this
crate must not be treated as resistant to local timing, cache, branch-trace,
power, or similar side-channel attackers. Deploy it only where that threat is
excluded or use a separately reviewed constant-time arithmetic backend.

## Distributed key generation

`keygen::Parameters::new(n, t)` configures an `n`-party sharing whose polynomial
degree is `t - 1`; any `t` resulting shares can sign. Note that the source
protocol document uses `t` for the polynomial _degree_ instead, so its `t` maps
to `Parameters::new(n, t + 1)` here.

Key generation takes an opaque session context (`context: &[u8]`) that must be
globally unique per run, not merely agreed. The context is the only run-specific
input to the proof-of-possession context, so reusing it with the same parameters
makes round-one broadcasts replayable: an adversary with network control can
suppress an honest party's fresh broadcast, inject its stale one from the earlier
run, and have that party's fresh private evaluations fail against the stale
commitments — which incorrectly implicates an honest party and aborts the run. Use fresh
random bytes per run and never derive the context from configuration alone.
The context is not carried in the protocol
messages: a party running with a different context fails proof verification at
every peer and is reported as malicious, so establish agreement on the context
before starting the run.

1. Every party creates `keygen::round1::RoundOne` with identical parameters and
   session context. It reliably broadcasts `get_broadcast_message()`, containing
   coefficient commitments and a Schnorr proof of possession. Each recipient
   passes that broadcast and its authenticated sender ID to `add_party_communication`.
2. After every other participant's broadcast verifies, `round2()` creates the
   private polynomial evaluations. Deliver each `get_party_communication(recipient)`
   over a confidential, authenticated channel bound to this session and recipient,
   and process received shares with `add_party_communication`.
3. After every other participant's share verifies, `finalize()` returns
   `keygen::finished::Finished`, containing the local secret share, every
   public-key share, and the aggregate public key. Compare `agreement_digest()`
   across participants before using the key; this does not replace reliable broadcast.

All `n` participants must contribute even though only `t` resulting shares are
needed to sign. An invalid contribution aborts the run. A missing contribution
prevents advancement; abort if the application's delivery deadline expires.
There is no participant-exclusion, complaint, or public share-revelation API.
Never publish private evaluations to recover from a timeout: an honest
recipient's revealed evaluation, combined with evaluations already held by
corrupt participants, can disclose a dealer's entire polynomial.

To retry, discard the old state, agree on the new participant set and parameters,
and start a new run with fresh randomness and a fresh context. A failure
identifies a sender locally when a cryptographic check fails; it does not produce
a publicly verifiable proof of private delivery. A timeout alone is not proof
that its sender acted maliciously.

Like the ordinary FROST/Pedersen DKG, this protocol does **not** guarantee an
unbiased public key. A last broadcaster can try known secret contributions until
the resulting public key has a desired property, and abort/retry choices can
introduce further bias. Schnorr proofs prevent rogue-key attacks; they do not
force independently chosen contributions. Applications needing unbiased
randomness require a protocol designed for that guarantee.

## Outputs and interoperability

DKG returns `keygen::finished::Finished<C>`. For Baby Jubjub, use
`ark_babyjubjub::EdwardsProjective` as `C`. Its `sk_share` can be converted into
`key_share::DLogShareShamir` for signing by binding the share to its party
ID, total party count, and threshold; `pk` and `pk_shares` supply the public
values required for verification and identifiable abort.
`contributing_parties` names all participants in the run, and
`agreement_digest()` reduces every value that must agree across participants to
one comparable 32-byte hash.

There is deliberately no automatic conversion to `DLogShareShamir`, because
`Finished` does not carry the run's `Parameters`. Supply the party count and
threshold yourself, and take care: a wrong-but-self-consistent value is accepted
silently. `sign_round` derives the Lagrange coefficient from the signer set, so a
too-small threshold only loosens the minimum-signer-set check and a too-large
party count only loosens the range check. Neither enables a forgery, but neither
is caught either.

## Error attribution

The message-intake APIs — `RoundOne::add_party_communication` and
`RoundTwo::add_party_communication` — return `keygen::MessageError`, which
keeps three outcomes apart:

- `MaliciousParty` attributes a failed cryptographic check to the authenticated
  sender, assuming all parties agreed on parameters and context.
- `Malformed` does not. The message did not fit the local protocol view, most
  often because the _local_ node is misconfigured — a node started with different
  `Parameters` derives a different proof-of-possession context and expects a
  different commitment count, so every honest peer looks wrong to it.
  Disqualifying on this basis would remove an honest participant.
- `LocalFault` means the caller misused the API, so no remote message was
  evaluated.

Use `MessageError::attributable_parties()` to inspect local attribution. The
`Display` output retains the relevant party IDs. Abort after a rejected protocol
contribution and investigate its cause before deciding which participants to
include in a fresh run.

## References

- Tim Ruffing et al., [ROAST: Robust Asynchronous Schnorr Threshold
  Signatures](https://eprint.iacr.org/2022/550.pdf), especially the FROST3
  signing algorithms and identifiable-abort construction.
- Zcash Foundation, [`frost-core` DKG implementation](https://github.com/ZcashFoundation/frost/blob/frost-core/v3.0.0/frost-core/src/keys/dkg.rs).
- Chelsea Komlo and Ian Goldberg, [FROST: Flexible Round-Optimized Schnorr Threshold Signatures](https://eprint.iacr.org/2020/852), including the discussion of DKG bias in section 2.3.
- TACEO, [OPRF protocol documentation](https://github.com/TaceoLabs/oprf-service/tree/main/docs),
  section “Key Generation and Reshare” ([PDF](https://github.com/TaceoLabs/oprf-service/blob/main/docs/oprf.pdf),
  [Typst source](https://github.com/TaceoLabs/oprf-service/blob/main/docs/oprf.typst)).

## License

Licensed under either of Apache License, Version 2.0 or the MIT license, at your
option.
