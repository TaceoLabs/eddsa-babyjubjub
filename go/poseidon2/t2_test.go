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

func TestPermutation2KATAllZeros(t *testing.T) {
	var state [2]fr.Element
	state[0].SetUint64(0)
	state[1].SetUint64(0)
	got := Permutation2(&state)
	want := mustElements(
		"15621590199821056450610068202457788725601603091791048810523422053872049975191",
		"2715232016971520363089762378513811845602449806589549663954401130147232822667",
	)
	for i := range want {
		if !got[i].Equal(&want[i]) {
			t.Errorf("Permutation2(all zeros)[%d] = %s; want %s", i, got[i].String(), want[i].String())
		}
	}
}

func TestPermutation2KATAllOnes(t *testing.T) {
	var state [2]fr.Element
	state[0].SetUint64(1)
	state[1].SetUint64(1)
	got := Permutation2(&state)
	want := mustElements(
		"9647731108978936185894927878221573490593429080082292366711128738986830308852",
		"12182851897054208611016549081956934341830770980605431520467368131931900307857",
	)
	for i := range want {
		if !got[i].Equal(&want[i]) {
			t.Errorf("Permutation2(all ones)[%d] = %s; want %s", i, got[i].String(), want[i].String())
		}
	}
}

func TestPermutation2KATRandom(t *testing.T) {
	state := mustElements(
		"21635575031573999400944812583635782970833961628163643769545570446330252768227",
		"491935893655450245496183576506348091012280194952030725661588550103340027820",
	)
	var st [2]fr.Element
	copy(st[:], state)
	got := Permutation2(&st)
	want := mustElements(
		"20809581131624131580198399772048464729664720986850575920123023746375414517759",
		"18384999161712470106767733232003932603774911696234786881514418962719492139465",
	)
	for i := range want {
		if !got[i].Equal(&want[i]) {
			t.Errorf("Permutation2(random)[%d] = %s; want %s", i, got[i].String(), want[i].String())
		}
	}
}
