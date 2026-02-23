package poseidon2

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// params holds round constants and internal matrix diagonal for one state size.
type params struct {
	matDiagM1    []fr.Element
	externalRC   [][]fr.Element // ROUNDS_F rows, each of length T
	internalRC   []fr.Element
	roundsF      int
	roundsP      int
}

// sbox5 applies x^5 S-box to el (in place). BN254 uses D=5.
func sbox5(el *fr.Element) {
	var t0, t1 fr.Element
	t0.Square(el)
	t1.Square(&t0)
	el.Mul(el, &t1)
}

// matmulM4 applies the 4x4 MDS from the Poseidon2 paper to input[0:4].
func matmulM4(input []fr.Element) {
	t0 := input[0]
	t0.Add(&t0, &input[1])
	t1 := input[2]
	t1.Add(&t1, &input[3])
	t2 := input[1]
	t2.Double(&t2).Add(&t2, &t1)
	t3 := input[3]
	t3.Double(&t3).Add(&t3, &input[0]).Add(&t3, &input[1])
	t4 := t1
	t4.Double(&t4).Double(&t4).Add(&t4, &t3)
	t5 := t0
	t5.Double(&t5).Double(&t5).Add(&t5, &t2)
	t6 := t3
	t6.Add(&t6, &t5)
	t7 := t2
	t7.Add(&t7, &t4)
	input[0] = t6
	input[1] = t5
	input[2] = t7
	input[3] = t4
}

// matmulExternal applies the external linear layer (depends on T).
func matmulExternal(state []fr.Element, t int) {
	switch t {
	case 2:
		var sum fr.Element
		sum.Add(&state[0], &state[1])
		state[0].Add(&state[0], &sum)
		state[1].Add(&state[1], &sum)
	case 3:
		var sum fr.Element
		sum.Add(&state[0], &state[1]).Add(&sum, &state[2])
		state[0].Add(&state[0], &sum)
		state[1].Add(&state[1], &sum)
		state[2].Add(&state[2], &sum)
	case 4:
		matmulM4(state)
	case 8, 12, 16:
		for i := 0; i < t; i += 4 {
			matmulM4(state[i : i+4])
		}
		var stored [4]fr.Element
		for l := 0; l < 4; l++ {
			stored[l] = state[l]
			for j := 1; j < t/4; j++ {
				stored[l].Add(&stored[l], &state[4*j+l])
			}
		}
		for i := 0; i < t; i++ {
			state[i].Add(&state[i], &stored[i%4])
		}
	default:
		panic("poseidon2: invalid state size")
	}
}

// matmulInternal applies the internal linear layer (uses matDiagM1).
func matmulInternal(state []fr.Element, matDiagM1 []fr.Element, t int) {
	switch t {
	case 2:
		var sum fr.Element
		sum.Add(&state[0], &state[1])
		state[0].Add(&state[0], &sum)
		state[1].Double(&state[1]).Add(&state[1], &sum)
	case 3:
		var sum fr.Element
		sum.Add(&state[0], &state[1]).Add(&sum, &state[2])
		state[0].Add(&state[0], &sum)
		state[1].Add(&state[1], &sum)
		state[2].Double(&state[2]).Add(&state[2], &sum)
	default:
		var sum fr.Element
		for i := range state {
			sum.Add(&sum, &state[i])
		}
		for i := range state {
			state[i].Mul(&state[i], &matDiagM1[i]).Add(&state[i], &sum)
		}
	}
}

// permutationInPlaceSlice runs the full Poseidon2 permutation in place on state.
// len(state) must equal len(p.matDiagM1) and match the parameter set.
func permutationInPlaceSlice(state []fr.Element, p *params) {
	t := len(state)
	matmulExternal(state, t)
	halfF := p.roundsF / 2
	for i := 0; i < halfF; i++ {
		for j := 0; j < t; j++ {
			state[j].Add(&state[j], &p.externalRC[i][j])
		}
		for j := 0; j < t; j++ {
			sbox5(&state[j])
		}
		matmulExternal(state, t)
	}
	for i := 0; i < p.roundsP; i++ {
		state[0].Add(&state[0], &p.internalRC[i])
		sbox5(&state[0])
		matmulInternal(state, p.matDiagM1, t)
	}
	for i := halfF; i < p.roundsF; i++ {
		for j := 0; j < t; j++ {
			state[j].Add(&state[j], &p.externalRC[i][j])
		}
		for j := 0; j < t; j++ {
			sbox5(&state[j])
		}
		matmulExternal(state, t)
	}
}
