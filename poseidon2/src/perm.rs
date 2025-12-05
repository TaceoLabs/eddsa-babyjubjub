#![allow(dead_code)]
use ark_ff::PrimeField;

/// A struct representing the Poseidon2 permutation.
pub(crate) struct Poseidon2Permutation<
    F: PrimeField,
    const T: usize,
    const D: u64,
    const ROUNDS_F: usize,
    const ROUNDS_P: usize,
> {
    /// The diagonal of t x t matrix of the internal permutation. Each element is taken minus 1 for more efficient implementations.
    mat_internal_diag_m_1: [F; T],
    /// The round constants of the external rounds.
    round_constants_external: [[F; T]; ROUNDS_F],
    /// The round constants of the internal rounds.
    round_constants_internal: [F; ROUNDS_P],
}

impl<F: PrimeField, const T: usize, const D: u64, const ROUNDS_F: usize, const ROUNDS_P: usize>
    Poseidon2Permutation<F, T, D, ROUNDS_F, ROUNDS_P>
{
    /// Creates a new instance of the Poseidon2 permutation with given parameters
    pub const fn new(
        mat_internal_diag_m_1: [F; T],
        round_constants_external: [[F; T]; ROUNDS_F],
        round_constants_internal: [F; ROUNDS_P],
    ) -> Self {
        const {
            assert!(T == 2 || T == 3 || ((T <= 24) && (T % 4 == 0)));
            assert!(D % 2 == 1);
            assert!(ROUNDS_F % 2 == 0);
        }

        Self {
            mat_internal_diag_m_1,
            round_constants_external,
            round_constants_internal,
        }
    }

    fn sbox(input: &mut [F; T]) {
        input.iter_mut().for_each(Self::single_sbox);
    }

    fn single_sbox(input: &mut F) {
        match D {
            3 => {
                let input2 = input.square();
                *input *= input2;
            }
            5 => {
                let input2 = input.square();
                let input4 = input2.square();
                *input *= input4;
            }
            7 => {
                let input2 = input.square();
                let input4 = input2.square();
                *input *= input4;
                *input *= input2;
            }
            _ => {
                *input = input.pow([D]);
            }
        }
    }

    /**
     * hardcoded algorithm that evaluates matrix multiplication using the following MDS matrix:
     * /         \
     * | 5 7 1 3 |
     * | 4 6 1 1 |
     * | 1 3 5 7 |
     * | 1 1 4 6 |
     * \         /
     *
     * Algorithm is taken directly from the Poseidon2 paper.
     */
    fn matmul_m4(input: &mut [F; 4]) {
        let t_0 = input[0] + input[1]; // A + B
        let t_1 = input[2] + input[3]; // C + D
        let t_2 = input[1].double() + t_1; // 2B + C + D
        let t_3 = input[3].double() + t_0; // A + B + 2D
        let t_4 = t_1.double().double() + t_3; // A + B + 4C + 6D
        let t_5 = t_0.double().double() + t_2; // 4A + 6B + C + D
        let t_6 = t_3 + t_5; // 5A + 7B + C + 3D
        let t_7 = t_2 + t_4; // A + 3B + 5C + 7D
        input[0] = t_6;
        input[1] = t_5;
        input[2] = t_7;
        input[3] = t_4;
    }

    /// The matrix multiplication in the external rounds of the Poseidon2 permutation.
    pub fn matmul_external(input: &mut [F; T]) {
        match T {
            2 => {
                // Matrix circ(2, 1)
                let sum = input[0] + input[1];
                input[0] += &sum;
                input[1] += sum;
            }
            3 => {
                // Matrix circ(2, 1, 1)
                let sum = input[0] + input[1] + input[2];
                input[0] += &sum;
                input[1] += &sum;
                input[2] += sum;
            }
            4 => {
                Self::matmul_m4(input.as_mut_slice().try_into().unwrap());
            }
            8 | 12 | 16 | 20 | 24 => {
                // Applying cheap 4x4 MDS matrix to each 4-element part of the state
                for state in input.chunks_exact_mut(4) {
                    Self::matmul_m4(state.try_into().unwrap());
                }

                // Applying second cheap matrix for t > 4
                let mut stored = [F::zero(); 4];
                for l in 0..4 {
                    stored[l] = input[l];
                    for j in 1..T / 4 {
                        stored[l] += input[4 * j + l];
                    }
                }
                for i in 0..T {
                    input[i] += stored[i % 4];
                }
            }
            _ => {
                panic!("Invalid state size");
            }
        }
    }

    /// The matrix multiplication in the internal rounds of the Poseidon2 permutation.
    pub fn matmul_internal(&self, input: &mut [F; T]) {
        match T {
            2 => {
                // Matrix [[2, 1], [1, 3]]
                debug_assert_eq!(self.mat_internal_diag_m_1[0], F::one());
                debug_assert_eq!(self.mat_internal_diag_m_1[1], F::from(2u64));
                let sum = input[0] + input[1];
                input[0] += &sum;
                input[1].double_in_place();
                input[1] += sum;
            }
            3 => {
                // Matrix [[2, 1, 1], [1, 2, 1], [1, 1, 3]]
                debug_assert_eq!(self.mat_internal_diag_m_1[0], F::one());
                debug_assert_eq!(self.mat_internal_diag_m_1[1], F::one());
                debug_assert_eq!(self.mat_internal_diag_m_1[2], F::from(2u64));
                let sum = input[0] + input[1] + input[2];
                input[0] += &sum;
                input[1] += &sum;
                input[2].double_in_place();
                input[2] += sum;
            }
            _ => {
                // Compute input sum
                let sum: F = input.iter().sum();
                // Add sum + diag entry * element to each element

                for (s, m) in input.iter_mut().zip(self.mat_internal_diag_m_1.iter()) {
                    *s *= m;
                    *s += sum;
                }
            }
        }
    }

    /// The round constant addition in the external rounds of the Poseidon2 permutation.
    pub fn add_rc_external(&self, input: &mut [F; T], rc_e: &[F; T]) {
        for (s, rc) in input.iter_mut().zip(rc_e.iter()) {
            *s += rc;
        }
    }

    /// One external round of the Poseidon2 permutation.
    pub fn external_round(&self, state: &mut [F; T], rc_e: &[F; T]) {
        self.add_rc_external(state, rc_e);
        Self::sbox(state);
        Self::matmul_external(state);
    }

    /// One internal round of the Poseidon2 permutation.
    pub fn internal_round(&self, state: &mut [F; T], rc_i: F) {
        // add internal round constant
        state[0] += rc_i;
        Self::single_sbox(&mut state[0]);
        self.matmul_internal(state);
    }

    /// Performs the Poseidon2 Permutation on the given state.
    pub fn permutation_in_place(&self, state: &mut [F; T]) {
        // Linear layer at beginning
        Self::matmul_external(state);
        let mut round_constants_external = self.round_constants_external.iter();

        // First set of external rounds
        for rc_e in round_constants_external.by_ref().take(ROUNDS_F / 2) {
            self.external_round(state, rc_e);
        }

        // Internal rounds
        for rc_i in self.round_constants_internal {
            self.internal_round(state, rc_i);
        }

        // Remaining external rounds
        for rc_e in round_constants_external {
            self.external_round(state, rc_e);
        }
    }

    /// Performs the Poseidon2 Permutation on the given state.
    pub fn permutation(&self, input: &[F; T]) -> [F; T] {
        let mut state = *input;
        self.permutation_in_place(&mut state);
        state
    }
}
