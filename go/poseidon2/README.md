# poseidon2

Poseidon2 permutation for the BN254 scalar field, implemented in Go.

Based on [eprint.iacr.org/2023/323](https://eprint.iacr.org/2023/323). Parameters and behavior match the [HorizenLabs Poseidon2](https://github.com/HorizenLabs/poseidon2) parameter generation script and the Rust `poseidon2` crate in this repository.

## Field

Uses [Consensys gnark-crypto](https://github.com/consensys/gnark-crypto) `ecc/bn254/fr` for field arithmetic (BN254 scalar field).

## API

Fixed-size state arrays; one function pair per state size:

| State size | Permutation        | In-place              |
|-----------:|--------------------|------------------------|
| 2          | `Permutation2`     | `PermutationInPlace2`  |
| 3          | `Permutation3`     | `PermutationInPlace3`  |
| 4          | `Permutation4`     | `PermutationInPlace4`  |
| 8          | `Permutation8`     | `PermutationInPlace8`  |
| 12         | `Permutation12`    | `PermutationInPlace12` |
| 16         | `Permutation16`    | `PermutationInPlace16` |

Example:

```go
import (
    "poseidon2"
    "github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

var state [4]fr.Element
// set state[0..3] ...
out := poseidon2.Permutation4(&state)
// or mutate in place:
poseidon2.PermutationInPlace4(&state)
```

## Tests

KAT tests match the Rust crate test vectors for each state size. Run:

```bash
go test ./...
```

## License

Same as the repository.
