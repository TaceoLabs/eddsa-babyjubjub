# Collection of crates for creating EdDSA signatures over BabyJubJub curve

This repository holds a few crates related to creating EdDSA signatures over the BabyJubJub elliptic curve.
These signatures are friendly to verify in SNARK systems working over the BN254 scalar field, this is also why the SNARK-friendly Poseidon2 hash function is used.

## Crates

* `ark-babyjubjub`: Arkworks implementation of the BabyJubJub curve.
* `ark-serde-compat`: A few helper functions for serializing arkworks types with serde.
* `eddsa-babyjubjub`: An implementation of EdDSA over the BabyJubJub curve.
* `poseidon2`: An implementation of the SNARK-friendly Poseidon2 hash function over the BN254 scalar field.

Since there is no namespace support on crates.io, the above crates are published with a `taceo-` prefix, to not add confusion whether these belong to the arkworks ecosystem or not (e.g., `taceo-ark-babyjubjub`).
This might change in the future, once namespaces are available.
