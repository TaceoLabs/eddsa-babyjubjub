package poseidon2

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestPermutation3KAT(t *testing.T) {
	var state [3]fr.Element
	state[0].SetUint64(0)
	state[1].SetUint64(1)
	state[2].SetUint64(2)

	got := Permutation3(&state)

	want := mustElements(
		"5297208644449048816064511434384511824916970985131888684874823260532015509555",
		"21816030159894113985964609355246484851575571273661473159848781012394295965040",
		"13940986381491601233448981668101586453321811870310341844570924906201623195336",
	)
	for i := range want {
		if !got[i].Equal(&want[i]) {
			t.Errorf("Permutation3([0,1,2])[%d] = %s; want %s", i, got[i].String(), want[i].String())
		}
	}
}
