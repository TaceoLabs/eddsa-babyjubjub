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

func TestPermutation3KATAllZeros(t *testing.T) {
	var state [3]fr.Element
	for i := range 3 {
		state[i].SetUint64(0)
	}
	got := Permutation3(&state)
	want := mustElements(
		"21177166670744647784289648293577786481357446166129397094207318338605633126018",
		"13629302801197998987814902320299027581009939610751955228105166233386644439248",
		"20016279581229773656890104823225294246488953781156758873918627636762146545760",
	)
	for i := range want {
		if !got[i].Equal(&want[i]) {
			t.Errorf("Permutation3(all zeros)[%d] = %s; want %s", i, got[i].String(), want[i].String())
		}
	}
}

func TestPermutation3KATAllOnes(t *testing.T) {
	var state [3]fr.Element
	for i := range 3 {
		state[i].SetUint64(1)
	}
	got := Permutation3(&state)
	want := mustElements(
		"19545711034863201779438231250511619110830456715851294365287615403948781151171",
		"16186740072674623501643500197747172382154156613583384947939053818096389590163",
		"4736000920724964460750118100687351457177765671034094484613783794229961824502",
	)
	for i := range want {
		if !got[i].Equal(&want[i]) {
			t.Errorf("Permutation3(all ones)[%d] = %s; want %s", i, got[i].String(), want[i].String())
		}
	}
}

func TestPermutation3KATRandom(t *testing.T) {
	state := mustElements(
		"21635575031573999400944812583635782970833961628163643769545570446330252768227",
		"491935893655450245496183576506348091012280194952030725661588550103340027820",
		"4030623037705026013308992148752804248465345346822988437246454317738635908347",
	)
	var st [3]fr.Element
	copy(st[:], state)
	got := Permutation3(&st)
	want := mustElements(
		"9491551076484951479338074880708472340700371967613607191889910599263460737291",
		"16540039425758680546398251594862408215442861897604522465527031743930526860917",
		"9150137625533241640793834795776253698901072014644658385664202025557655722329",
	)
	for i := range want {
		if !got[i].Equal(&want[i]) {
			t.Errorf("Permutation3(random)[%d] = %s; want %s", i, got[i].String(), want[i].String())
		}
	}
}
