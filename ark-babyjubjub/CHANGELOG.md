# Changelog

## [Unreleased]

## [0.5.3](https://github.com/TaceoLabs/eddsa-babyjubjub/compare/taceo-ark-babyjubjub-v0.5.2...taceo-ark-babyjubjub-v0.5.3)

### 🚜 Refactor


- Simplify by making constant time function generic over N - ([1740f60](https://github.com/TaceoLabs/eddsa-babyjubjub/commit/1740f6039ce7a43a00748806d4ed232d70207c02))
- Even more conservative Montgomery ladder without branches - ([35582ee](https://github.com/TaceoLabs/eddsa-babyjubjub/commit/35582ee4440a5bbf46350cc6253241473ad1b681))
- Change internal scalar multiplication to use a basic - ([7673d78](https://github.com/TaceoLabs/eddsa-babyjubjub/commit/7673d7857ed344547c6e809987058311b51cd895))
- Remove mul_by_a since it is equivalent to the default impl - ([75ac407](https://github.com/TaceoLabs/eddsa-babyjubjub/commit/75ac4079aa6304ab449fa5e44c09c5baf1685a34))


## [0.5.2](https://github.com/TaceoLabs/eddsa-babyjubjub/compare/taceo-ark-babyjubjub-v0.5.1...taceo-ark-babyjubjub-v0.5.2)

### Build


- Removed ark-serde-compat crate - ([c0f306d](https://github.com/TaceoLabs/eddsa-babyjubjub/commit/c0f306df06d6809d209cb414b8beb1290334b98b))


## [0.5.1](https://github.com/TaceoLabs/eddsa-babyjubjub/compare/taceo-ark-babyjubjub-v0.5.0...taceo-ark-babyjubjub-v0.5.1)

### ⚙️ Miscellaneous Tasks


- Update cargo.tomls after poseidon2 rewrite - ([a67dd6e](https://github.com/TaceoLabs/eddsa-babyjubjub/commit/a67dd6e5adf5e651ecdcce6be9d0637ac622413d))


## [0.5.0]

### ⚙️ Miscellaneous Tasks


- Add workspace structure, add `taceo-` prefix and fix imports - ([3375507](https://github.com/taceolabs/eddsa-babyjubjub/commit/337550723435f4815cb9e1e0d011b93d06f1574a))

