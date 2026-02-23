package poseidon2

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestPermutation2KAT(t *testing.T) {
	var state [2]fr.Element
	state[0].SetUint64(0)
	state[1].SetUint64(1)

	got := Permutation2(&state)

	var want0, want1 fr.Element
	mustSetString(&want0, "13120422956170837922441672802975889424559262309139960702680326932494325745547")
	mustSetString(&want1, "5923567162677888564808904842769941181302763723060647224839027357562627386465")

	if !got[0].Equal(&want0) || !got[1].Equal(&want1) {
		t.Errorf("Permutation2([0,1]) = %s, %s; want %s, %s",
			got[0].String(), got[1].String(),
			want0.String(), want1.String())
	}
}

func TestPermutationInPlace2KAT(t *testing.T) {
	var state [2]fr.Element
	state[0].SetUint64(0)
	state[1].SetUint64(1)

	PermutationInPlace2(&state)

	var want0, want1 fr.Element
	mustSetString(&want0, "13120422956170837922441672802975889424559262309139960702680326932494325745547")
	mustSetString(&want1, "5923567162677888564808904842769941181302763723060647224839027357562627386465")

	if !state[0].Equal(&want0) || !state[1].Equal(&want1) {
		t.Errorf("PermutationInPlace2([0,1]) => %s, %s; want %s, %s",
			state[0].String(), state[1].String(),
			want0.String(), want1.String())
	}
}
