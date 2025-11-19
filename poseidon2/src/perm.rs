use ark_ff::PrimeField;

pub(super) mod bn254_t12;
pub(super) mod bn254_t16;
pub(super) mod bn254_t2;
pub(super) mod bn254_t3;
pub(super) mod bn254_t4;
pub(super) mod bn254_t8;

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
        assert!(T == 2 || T == 3 || ((T <= 24) && (T % 4 == 0)));
        assert!(D % 2 == 1);
        assert!(ROUNDS_F % 2 == 0);

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

#[cfg(test)]
mod test {
    use std::array;
    use std::str::FromStr;

    use crate::perm::{
        bn254_t2::POSEIDON2_BN254_T2_PARAMS, bn254_t3::POSEIDON2_BN254_T3_PARAMS,
        bn254_t4::POSEIDON2_BN254_T4_PARAMS, bn254_t8::POSEIDON2_BN254_T8_PARAMS,
        bn254_t12::POSEIDON2_BN254_T12_PARAMS, bn254_t16::POSEIDON2_BN254_T16_PARAMS,
    };

    use super::*;
    use ark_std::rand::thread_rng;

    const TESTRUNS: usize = 10;

    fn poseidon2_kat<
        F: PrimeField,
        const T: usize,
        const D: u64,
        const ROUNDS_F: usize,
        const ROUNDS_P: usize,
    >(
        poseidon2_perm: &'static Poseidon2Permutation<F, T, D, ROUNDS_F, ROUNDS_P>,
        input: &[F; T],
        expected: &[F; T],
    ) {
        let result = poseidon2_perm.permutation(input);
        assert_eq!(&result, expected);
    }

    fn poseidon2_consistent_perm<
        F: PrimeField,
        const T: usize,
        const D: u64,
        const ROUNDS_F: usize,
        const ROUNDS_P: usize,
    >(
        poseidon2_perm: &'static Poseidon2Permutation<F, T, D, ROUNDS_F, ROUNDS_P>,
    ) {
        let mut rng = &mut thread_rng();
        let input1: Vec<F> = (0..T).map(|_| F::rand(&mut rng)).collect();
        let mut input2 = input1.clone();
        input2.rotate_right(T / 2);

        let perm1 = poseidon2_perm.permutation(input1.as_slice().try_into().unwrap());
        let perm2 = poseidon2_perm.permutation(&input1.try_into().unwrap());
        let perm3 = poseidon2_perm.permutation(&input2.try_into().unwrap());

        assert_eq!(perm1, perm2);
        assert_ne!(perm1, perm3);
    }

    #[test]
    fn poseidon2_bn254_t4_consistent_perm() {
        for _ in 0..TESTRUNS {
            poseidon2_consistent_perm(&POSEIDON2_BN254_T4_PARAMS);
        }
    }

    #[test]
    fn poseidon2_bn254_t2_kat1() {
        let input = [ark_bn254::Fr::from(0u64), ark_bn254::Fr::from(1u64)];
        let expected = [
            ark_bn254::Fr::from_str(
                "13120422956170837922441672802975889424559262309139960702680326932494325745547",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "5923567162677888564808904842769941181302763723060647224839027357562627386465",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T2_PARAMS, &input, &expected);
    }

    #[test]
    fn poseidon2_bn254_t3_kat1() {
        // Parameters are compatible with the original Poseidon2 parameter generation script found at:
        // [https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)
        let input = [
            ark_bn254::Fr::from(0u64),
            ark_bn254::Fr::from(1u64),
            ark_bn254::Fr::from(2u64),
        ];
        let expected = [
            ark_bn254::Fr::from_str(
                "5297208644449048816064511434384511824916970985131888684874823260532015509555",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "21816030159894113985964609355246484851575571273661473159848781012394295965040",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "13940986381491601233448981668101586453321811870310341844570924906201623195336",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T3_PARAMS, &input, &expected);
    }

    #[test]
    fn poseidon2_bn254_t4_kat1() {
        // Parameters are compatible with the original Poseidon2 parameter generation script found at:
        // [https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)
        let input = [
            ark_bn254::Fr::from(0u64),
            ark_bn254::Fr::from(1u64),
            ark_bn254::Fr::from(2u64),
            ark_bn254::Fr::from(3u64),
        ];
        let expected = [
            ark_bn254::Fr::from_str(
                "786823568102245344938517132468097745676732687098822989626730198331658606391",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "16105493617470833344375945651585194737369509580406730765188791202038211593826",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "2169165722086073256768101917994796590773204847633762971322389403847680713675",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "20837792685223053096472825292260687493226094382304778455120670180090619921530",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T4_PARAMS, &input, &expected);
    }

    #[test]
    fn poseidon2_bn254_t4_kat2() {
        // Parameters are compatible with the original Poseidon2 parameter generation script found at:
        // [https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)
        let input = [
            ark_bn254::Fr::from_str(
                "69883186645750645681994932030385246708157590398620226325678277467989879383945",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "69883186645750645681994932030385246708157590398620226325678277467989879383945",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "69883186645750645681994932030385246708157590398620226325678277467989879383945",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "69883186645750645681994932030385246708157590398620226325678277467989879383945",
            )
            .unwrap(),
        ];
        let expected = [
            ark_bn254::Fr::from_str(
                "19876884339830114960362368309895990346608408251258324603720941116757387714453",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "5431247209421262354231150208254604337955649394486434112818062632325221806111",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "687894710690940102848643567468393776669463870896767752431820942566056771027",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "5764589378402668418492845603546890649188307247798553598873913830282103946561",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T4_PARAMS, &input, &expected);
    }

    #[test]
    fn poseidon2_bn254_t8_kat1() {
        // Parameters are compatible with the original Poseidon2 parameter generation script found at:
        // [https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)
        let input = array::from_fn(|i| ark_bn254::Fr::from(i as u64));
        let expected = [
            ark_bn254::Fr::from_str(
                "13163567864211573827878829467860137302577760599598440387954761704438999762399",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "20455256474176316209572707628365862887207812418465031548192789068192434065861",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "21622031586696647398529562584873094656572287904668581566093346191656615936784",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "18320622048765136384409419776996464874987888500923344182439589703061890523284",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "19915468795157938233689963601267136400922725821760118753901600546477081024243",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "12383970660639123649548441396659012498414420037083153473614822644813849243474",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "9133088157465982496917058916696585316057943251337470087079495488316110895778",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "5020935059501715015422969097649999023750915432550677386523662686145648636517",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T8_PARAMS, &input, &expected);
    }

    #[test]
    fn poseidon2_bn254_t12_kat1() {
        // Parameters are compatible with the original Poseidon2 parameter generation script found at:
        // [https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)
        let input = array::from_fn(|i| ark_bn254::Fr::from(i as u64));
        let expected = [
            ark_bn254::Fr::from_str(
                "21747906029444710619015915752138298720154944671203754489949869861753578346008",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "21513939049501079563576935737155721457540823975552714210005077333811928299954",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "20878374758297529903859235955630169324042890083998477622604596085833701396575",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "13305407019214443087878969363157154486205891028167855104279647302453885090170",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "16682997524380753461053737193932628645715072618825598039805329428502517736729",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "11014586020348730912470390146630484158055437849128185322266607138671384948760",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "2994526630703474400464067497664388590264808865382597731255193635407418251755",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "18211926869629584578138817320090692365663938300773975413887207856257516040147",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "6849612996087489069533591576260064469744251636332619304205225628198348842052",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "968962401542471672838330254238837400778821690766303842855005474297047085971",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "14385329809671587788248037486076267578972545577910278482783910245125370012450",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "4080137159225732886879922458777678533435313239919796733917069554543642876459",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T12_PARAMS, &input, &expected);
    }

    #[test]
    fn poseidon2_bn254_t16_kat1() {
        // Parameters are compatible with the original Poseidon2 parameter generation script found at:
        // [https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage](https://github.com/HorizenLabs/poseidon2/blob/main/poseidon2_rust_params.sage)
        let input = array::from_fn(|i| ark_bn254::Fr::from(i as u64));
        let expected = [
            ark_bn254::Fr::from_str(
                "7129053404014098913941583447102076532611276040718594073862066403012892177215",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "5458683216916715697310099658604278457911373519210593239261146303695981710820",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "11764907654416682971926471140388165312909351793032868507449176373009888376893",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "17363012907147515824232626923071954964539976031233523938322583063167173991942",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "16754602647566413012759386310550362661092317428428132757066277153406453157400",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "10442131742273378767812305849732860137449534508695657144865044457198204305243",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "13315916208806700309353847107954103794241355430909228633658159683794835480566",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "14675611827802190925530581036356245293764500457751312643178429199155385431971",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "3800671750689110886099899395588427301982955036566905831860793275457528754896",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "863058427093450397617252284543198432424871511785791089866952153042503171268",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "16110421480974327191214802248220528120081914075253666769021797524181818259452",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "3050248777345249982082587219460801555485024010345812479213241978893548171998",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "8005144369031495385854140476761376792991595443174132540148616210767138457404",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "193712991007063517677674367979478243863141973963118958643316643360558925992",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "6765341258738133397733055933640609905610288576122407133007925535267189590216",
            )
            .unwrap(),
            ark_bn254::Fr::from_str(
                "6411743912316957490668095751870764077217660758836562678571866082387292213586",
            )
            .unwrap(),
        ];

        poseidon2_kat(&POSEIDON2_BN254_T16_PARAMS, &input, &expected);
    }
}
