package poseidon2

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func benchState2() [2]fr.Element {
	var s [2]fr.Element
	s[0].SetUint64(42)
	s[1].SetUint64(43)
	return s
}

func benchState3() [3]fr.Element {
	var s [3]fr.Element
	for i := range 3 {
		s[i].SetUint64(uint64(42 + i))
	}
	return s
}

func benchState4() [4]fr.Element {
	var s [4]fr.Element
	for i := range 4 {
		s[i].SetUint64(uint64(42 + i))
	}
	return s
}

func benchState8() [8]fr.Element {
	var s [8]fr.Element
	for i := range 8 {
		s[i].SetUint64(uint64(42 + i))
	}
	return s
}

func benchState12() [12]fr.Element {
	var s [12]fr.Element
	for i := range 12 {
		s[i].SetUint64(uint64(42 + i))
	}
	return s
}

func benchState16() [16]fr.Element {
	var s [16]fr.Element
	for i := range 16 {
		s[i].SetUint64(uint64(42 + i))
	}
	return s
}

func BenchmarkPermutation2(b *testing.B) {
	state := benchState2()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Permutation2(&state)
	}
}

func BenchmarkPermutationInPlace2(b *testing.B) {
	ref := benchState2()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := ref
		PermutationInPlace2(&state)
	}
}

func BenchmarkPermutation3(b *testing.B) {
	state := benchState3()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Permutation3(&state)
	}
}

func BenchmarkPermutationInPlace3(b *testing.B) {
	ref := benchState3()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := ref
		PermutationInPlace3(&state)
	}
}

func BenchmarkPermutation4(b *testing.B) {
	state := benchState4()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Permutation4(&state)
	}
}

func BenchmarkPermutationInPlace4(b *testing.B) {
	ref := benchState4()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := ref
		PermutationInPlace4(&state)
	}
}

func BenchmarkPermutation8(b *testing.B) {
	state := benchState8()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Permutation8(&state)
	}
}

func BenchmarkPermutationInPlace8(b *testing.B) {
	ref := benchState8()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := ref
		PermutationInPlace8(&state)
	}
}

func BenchmarkPermutation12(b *testing.B) {
	state := benchState12()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Permutation12(&state)
	}
}

func BenchmarkPermutationInPlace12(b *testing.B) {
	ref := benchState12()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := ref
		PermutationInPlace12(&state)
	}
}

func BenchmarkPermutation16(b *testing.B) {
	state := benchState16()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Permutation16(&state)
	}
}

func BenchmarkPermutationInPlace16(b *testing.B) {
	ref := benchState16()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		state := ref
		PermutationInPlace16(&state)
	}
}
