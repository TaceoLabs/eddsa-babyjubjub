# Threshold EdDSA over Baby Jubjub

Threshold signing, distributed key generation, and key resharing for the
Poseidon2-based Baby Jubjub EdDSA implementation in
[`taceo-eddsa-babyjubjub`](../eddsa-babyjubjub).

The signing protocol is an adaptation of **FROST3**, the semi-interactive
threshold Schnorr construction described in
[ROAST: Robust Asynchronous Schnorr Threshold Signatures](https://eprint.iacr.org/2022/550.pdf).
It produces an ordinary `EdDSASignature`, so the result is verified with the
existing single-party `EdDSAPublicKey::verify` API. The distributed key
generation (DKG) and resharing protocols follow the PedPoP-based algorithms in
the [TACEO OPRF protocol documentation](https://github.com/TaceoLabs/oprf-service/tree/main/docs).

> [!WARNING]
> **Key generation and resharing require reliable broadcast for the messages
> marked “reliable broadcast” below.** Sending a message separately to every
> participant is not sufficient: a malicious sender must not be able to make
> two honest participants accept different messages for the same protocol step.
> The application must provide agreement, sender authentication, duplicate
> suppression, and consistent timeout/disqualification decisions.
>
> This crate does not implement networking, reliable broadcast, participant
> authentication, persistence, or timeouts. Supplying these is the integrator's
> responsibility. A consensus-backed ledger, a smart contract, or a dedicated
> Byzantine reliable-broadcast protocol are possible implementations.

## Features

- `t`-out-of-`n` EdDSA signing with Shamir-shared keys.
- A FROST3 two-nonce preprocessing round that can run before the message is
  known, followed by one signing round.
- Binding of the signer set, session ID, aggregate nonce commitments, public
  key, and message into the BLAKE3 nonce-combining hash.
- Poseidon2 for the final EdDSA Fiat-Shamir challenge.
- Signature-share aggregation with optional identifiable abort.
- PedPoP-style dealerless DKG, including an optional public complaint round.
- Resharing to a different party set and/or threshold without changing or
  reconstructing the signing key.
- Serde support for protocol messages and zeroization of secret state on drop.
- An `n`-out-of-`n` additive-sharing variant behind the `additive` feature.

The package name is `taceo-threshold-eddsa-babyjubjub`. The crate currently
requires Rust 1.90 or newer.

```toml
[dependencies]
taceo-threshold-eddsa-babyjubjub = "0.1"

# Also expose the n-out-of-n additive variant:
# taceo-threshold-eddsa-babyjubjub = { version = "0.1", features = ["additive"] }
```

## Network requirements

The protocol APIs operate on already-delivered messages. Bind the externally
authenticated sender identity to the `from` argument; never trust an ID carried
only by an unauthenticated transport.

| Protocol step | Required channel | Why |
| --- | --- | --- |
| FROST3 preprocessing commitments and signature shares | **Authenticated signer-to-aggregator communication** | The aggregator must attribute each contribution to the correct signer. Reliable broadcast is not required for the signing flow implemented here. |
| DKG round-one polynomial commitments and proof of possession | **Reliable broadcast to every DKG party** | All honest parties must use the same commitments and derive the same public key and public-key shares. |
| DKG round-two polynomial evaluations | **Private, authenticated point-to-point channel** | Each evaluation is a secret intended only for its recipient. |
| DKG complaint verdicts and dealer revelations | **Reliable broadcast to every DKG party** | All honest parties must see the same accusation set, revelations, and qualified dealer set. |
| Reshare sender set, old/new parameters, public key, public-key shares, and session ID | **Global agreement before starting** | Every old sender and new receiver must execute the same handover. |
| Reshare polynomial commitments and proof of possession | **Reliable broadcast from each selected old sender to every new party** | A sender must not equivocate about the polynomial against which private evaluations are checked. |
| Reshare polynomial evaluations | **Private, authenticated point-to-point channel** | Each new party receives a different secret evaluation. |
| Reshare complaint verdicts and old-sender revelations | **Reliable broadcast to every new party** | Every new party must derive the same surviving sender set and public output. |
| Missing-message, verdict, and revelation timeout decisions | **Externally coordinated agreement** | Every honest participant must apply the same disqualification or verdict-exclusion set. |

Reliable broadcast means more than best-effort multicast. In particular, if one
honest participant accepts a broadcast from a sender, all honest participants
that complete the step must accept the same payload from that sender. Do not
advance merely because a local node has received enough mutually inconsistent
point-to-point copies.

## Threshold signing

The primary API is in the `shamir` module:

- `EdDSASessionShamir::pre_round` samples two secret, single-use nonces and
  returns their public, identity-bound `PartialEdDSACommitmentsShamir`.
- The aggregator selects a signing set of at least the threshold size and calls
  `EdDSACommitmentsShamir::pre_agg`; aggregation canonicalizes the party order
  and rejects empty or duplicate sets.
- Each selected party consumes its session with
  `EdDSASessionShamir::sign_round`. The signer validates its identity and
  committee metadata and derives its Lagrange coefficient internally.
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
come from authenticated, immutable DKG or reshare output; the type system cannot
authenticate application-provided public-key metadata. Prefer
`sign_agg_with_identifiable_abort` when an invalid share must be attributed;
plain `sign_agg` only combines shares and may therefore return a signature that
does not verify if a participant supplied a malformed share.

### Nonce and session safety

`EdDSASessionShamir` deliberately cannot be cloned and `sign_round` consumes it.
Never reuse or restore its nonce state. Use a fresh, globally unique UUID for
each logical signing attempt, and ensure every participant agrees on the same
session ID, signer set, public key, and message. Secret-key shares and DKG or
reshare polynomial evaluations must be stored and transported as secrets.

## Distributed key generation

`keygen::Parameters::new(n, t)` configures an `n`-party sharing whose polynomial
degree is `t - 1`; any `t` resulting shares can sign.

1. Every party creates `keygen::round1::RoundOne` with identical parameters and
   session ID. It reliably broadcasts `get_broadcast_message()`, containing its
   coefficient commitments and Schnorr proof of possession. Every other party
   passes that same broadcast to `add_party_communication`. A missing or
   malformed round-one dealer can be excluded with `disqualify_party`, but only
   after all honest parties agree on that decision. For duplicate constant
   commitments, apply both reported IDs atomically with `disqualify_parties`;
   this removes broadcasts accepted before the duplicate was discovered.
2. After `can_advance()` succeeds, `round2()` creates one secret polynomial
   evaluation per recipient. Deliver each `get_party_communication(recipient)`
   privately and authentically, and process it with `add_party_communication`.
3. In the all-honest path, `finalize()` returns `keygen::finished::Finished`,
   containing the local secret share, every public-key share, and the aggregate
   public key.

For a complaint-capable run, receive round-two shares with
`add_party_communication_for_blame`, enter `blame_round()`, and reliably
broadcast every party's `verdict()`. Each accused dealer then reliably broadcasts
its `revelation()`. Missing revelations may be resolved with
`disqualify_missing_dealer`, but only after an externally agreed deadline that
all honest parties apply identically. `BlameRound::finalize` excludes
disqualified dealers and reports their IDs.

If a selected dealer's private round-two evaluation never arrives, call
`complain_missing_party` after an externally agreed delivery deadline, then
enter the blame round. The dealer can reveal the committed evaluation publicly
or be disqualified under the same coordinated rule.

If a qualified dealer withholds or sends an invalid blame verdict, the remaining
parties can apply `disqualify_missing_verdict` after a common timeout. Its
polynomial is removed from the DKG output. Disqualification fails—and the run
must abort—if fewer than the configured threshold parties would remain.

The direct `add_party_communication` path reports a malformed private share as
an error and is suitable when the caller will abort the whole run. Use the blame
path when the caller needs public resolution and a consistently qualified
dealer set.

## Resharing

Resharing replaces the Shamir sharing while preserving the secret key and
public key. It can change `n`, change `t`, rotate participants, or refresh shares
for the same configuration.

1. All participants first agree on identical old and new `Parameters`, the old
   public key, a fresh session ID, and a selected old-party sender set containing
   at least the old threshold. Build it with
   `ReShareSenderSet::for_pk_and_parameters`, `add_party`, and `correct`.
2. Each selected old party creates a `ReShareProtocolSender`. Its polynomial
   commitment from `get_broadcast_message()` requires reliable broadcast to all
   new parties. Its `get_party_communication(new_party)` result is delivered
   privately to that new party. These two deliveries may happen in parallel.
3. Each new party creates a `ReShareProtocolReceiver`, adds every selected old
   sender's broadcast and private message with
   `add_old_party_communication`, and calls `finalize()`.

For public complaint handling, use
`add_old_party_communication_for_blame`, then enter `blame_round()`. Verdicts
from the new parties and revelations from accused old senders both require
reliable broadcast. Apply `disqualify_missing_sender` only from a common timeout
decision. Finalization recomputes Lagrange coefficients over the surviving old
senders, requires at least the old threshold to remain, and checks that their
constant commitments still reconstruct the original public key.

When a valid sender broadcast arrives but its private evaluation does not, use
`complain_missing_share` to enter blame and request a public revelation. When
no usable broadcast arrives, `disqualify_missing_sender` may exclude that sender
before blame, provided the remaining selected senders still reconstruct the old
key.

If a new receiver withholds or sends an invalid blame verdict, the completing
receivers can apply `exclude_missing_verdict` after a common timeout. This only
removes the receiver from the blame barrier and does not revoke a secret share
it may already possess. At least the new threshold number of receivers must
remain. The exclusion is reported in `BlameResult::excluded_verdict_parties`.

Do not let each receiver choose its own sender set or independently decide which
senders timed out. Doing so can create divergent shares and public-key-share
metadata even when every local cryptographic check succeeds.

## Outputs and interoperability

DKG and reshare return `keygen::finished::Finished<C>`. For Baby Jubjub, use
`ark_babyjubjub::EdwardsProjective` as `C`. Its `sk_share` can be converted into
`shamir::secret::DLogShareShamir` for signing by binding the share to its party
ID, total party count, and threshold; `pk` and `pk_shares` supply the public
values required for verification and identifiable abort.

The final threshold signature is an
`eddsa_babyjubjub::EdDSASignature` and is verified exactly like a regular
signature:

```rust,ignore
let valid = public_key.verify(message, &signature);
```

## References

- Tim Ruffing et al., [ROAST: Robust Asynchronous Schnorr Threshold
  Signatures](https://eprint.iacr.org/2022/550.pdf), especially the FROST3
  signing algorithms and identifiable-abort construction.
- TACEO, [OPRF protocol documentation](https://github.com/TaceoLabs/oprf-service/tree/main/docs),
  section “Key Generation and Reshare” ([PDF](https://github.com/TaceoLabs/oprf-service/blob/main/docs/oprf.pdf),
  [Typst source](https://github.com/TaceoLabs/oprf-service/blob/main/docs/oprf.typst)).

## License

Licensed under either of Apache License, Version 2.0 or the MIT license, at your
option.
