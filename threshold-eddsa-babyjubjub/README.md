# Threshold EdDSA over Baby Jubjub

Threshold signing and distributed key generation for the
Poseidon2-based Baby Jubjub EdDSA implementation in
[`taceo-eddsa-babyjubjub`](../eddsa-babyjubjub).

The signing protocol is an adaptation of **FROST3**, the semi-interactive
threshold Schnorr construction described in
[ROAST: Robust Asynchronous Schnorr Threshold Signatures](https://eprint.iacr.org/2022/550.pdf).
It produces an ordinary `EdDSASignature`, so the result is verified with the
existing single-party `EdDSAPublicKey::verify` API. The distributed key
generation (DKG) protocol follows the PedPoP-based algorithm in
the [TACEO OPRF protocol documentation](https://github.com/TaceoLabs/oprf-service/tree/main/docs).

> [!WARNING]
> **Key generation requires reliable broadcast for the messages
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
- Binding of an opaque caller-supplied context, the signer set, aggregate nonce
  commitments, public key, and message into the BLAKE3 nonce-combining hash.
- Poseidon2 for the final EdDSA Fiat-Shamir challenge.
- Signature-share aggregation with optional identifiable abort.
- PedPoP-style dealerless DKG, including an optional public complaint round.
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
| DKG complaint verdicts and dealer revelations | **Reliable broadcast to every DKG party** | All honest parties must see the same accusation set, revelations, and qualified dealer set. |
| Missing-message, verdict, and revelation timeout decisions | **Externally coordinated agreement** | Every honest participant must apply the same disqualification or verdict-exclusion set. |

Neither commitments nor signature shares carry a session binding of their own,
so the authenticated channels must also be replay-protected and bound to the
signing session: a share replayed from another session fails validation and its
honest author is blamed.

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
commitments — which gets an honest party blamed and disqualified. Use fresh
random bytes per run and never derive the context from configuration alone.
The context is not carried in the protocol
messages: a party running with a different context fails proof verification at
every peer and is reported as malicious, so establish agreement on the context
before starting the run.

1. Every party creates `keygen::round1::RoundOne` with identical parameters and
   session context. It reliably broadcasts `get_broadcast_message()`, containing its
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

`revelation()` derives its accuser set from the collected verdicts rather than
from a caller-supplied list, so a dealer never answers a party that did not
complain. It also refuses once the accuser set reaches the threshold, since that
many evaluations determine the dealer's whole polynomial. Under the `t - 1`
corruption bound this cannot occur for an honest dealer, because an honest party
never accuses one.

An accused dealer must feed its own revelation back through `add_revelation`, as
the broadcast channel delivered it, just as every other party does. `revelation()
` does not mark the dealer resolved by itself. Otherwise a dealer whose broadcast
was corrupted or truncated in transit would judge itself qualified while everyone
else disqualified it, and would silently finalize onto a key nobody else uses.

Following PedPoP, a dealer disqualified in the blame round has its _contribution_
dropped from the aggregate but remains a shareholder: it completed round two, so
it holds every qualified dealer's evaluation and can derive its share of the
surviving polynomial regardless of what the honest parties record. It therefore
keeps a `pk_shares` entry and `finalize()` returns its share. Its ID is still
listed in `BlameResult::disqualified_parties`; exclude a proven cheater from
future signing committees at the application layer if that is the intent.
Round-one disqualifications are different: those parties never reached round two,
so they are not shareholders and hold nothing. `disqualify_parties` and
`disqualify_missing_verdict` refuse a decision that would leave fewer than `t`
parties. `disqualify_missing_dealer` and the implicit disqualification of an
invalid revelation do not: those are caught one step later, by `finalize`, which
refuses to produce a key from fewer than `t` qualified dealers. Either way a run
can never silently produce an unusable key, but check the count yourself if you
want the failure attributed to the decision that caused it.

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

## Outputs and interoperability

DKG returns `keygen::finished::Finished<C>`. For Baby Jubjub, use
`ark_babyjubjub::EdwardsProjective` as `C`. Its `sk_share` can be converted into
`key_share::DLogShareShamir` for signing by binding the share to its party
ID, total party count, and threshold; `pk` and `pk_shares` supply the public
values required for verification and identifiable abort.
`contributing_parties` names the qualified dealers, and
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

- `MaliciousParty` and `DuplicateCommitments` **attribute blame**: a
  cryptographic check failed and the named parties are provably at fault.
- `Malformed` does not. The message did not fit the local protocol view, most
  often because the _local_ node is misconfigured — a node started with different
  `Parameters` derives a different proof-of-possession context and expects a
  different commitment count, so every honest peer looks wrong to it.
  Disqualifying on this basis would remove an honest participant.
- `LocalFault` means the caller misused the API, so no remote message was
  evaluated.

Use `MessageError::attributable_parties()` to act on blame. Every variant names
the parties involved in its `Display` output, so logging the error no longer
discards the attribution — but only the first two justify a disqualification.

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
