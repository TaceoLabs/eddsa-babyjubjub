// Package poseidon2 implements the Poseidon2 permutation for the BN254 scalar field,
// based on https://eprint.iacr.org/2023/323.
//
// This package provides the permutation only (not a hash), with state sizes
// t = 2, 3, 4, 8, 12, 16. Parameters are compatible with the original Poseidon2
// parameter generation script (https://github.com/HorizenLabs/poseidon2) and
// with the Rust crate in this repository (poseidon2/).
//
// Field arithmetic uses github.com/consensys/gnark-crypto/ecc/bn254/fr.
//
// Example:
//
//	import "poseidon2"
//	import "github.com/consensys/gnark-crypto/ecc/bn254/fr"
//
//	var state [4]fr.Element
//	// ... set state ...
//	out := poseidon2.Permutation4(&state)
//	// or in place:
//	poseidon2.PermutationInPlace4(&state)
package poseidon2
