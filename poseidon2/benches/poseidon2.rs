use criterion::*;

fn poseidon2_bench(c: &mut Criterion) {
    c.bench_function("Poseidon2 Permutation (t=2)", |b| {
        let input = [ark_bn254::Fr::from(42u64), ark_bn254::Fr::from(43u64)];
        b.iter(|| std::hint::black_box(taceo_poseidon2::bn254::t2::permutation(&input)));
    });
    c.bench_function("Poseidon2 Permutation (t=3)", |b| {
        let input = [
            ark_bn254::Fr::from(42u64),
            ark_bn254::Fr::from(43u64),
            ark_bn254::Fr::from(44u64),
        ];
        b.iter(|| std::hint::black_box(taceo_poseidon2::bn254::t3::permutation(&input)));
    });
    c.bench_function("Poseidon2 Permutation (t=4)", |b| {
        let input = [
            ark_bn254::Fr::from(42u64),
            ark_bn254::Fr::from(43u64),
            ark_bn254::Fr::from(44u64),
            ark_bn254::Fr::from(45u64),
        ];
        b.iter(|| std::hint::black_box(taceo_poseidon2::bn254::t4::permutation(&input)));
    });
    c.bench_function("Poseidon2 Permutation (t=8)", |b| {
        let input = std::array::from_fn(|i| ark_bn254::Fr::from((42 + i) as u64));
        b.iter(|| std::hint::black_box(taceo_poseidon2::bn254::t8::permutation(&input)));
    });
    c.bench_function("Poseidon2 Permutation (t=12)", |b| {
        let input = std::array::from_fn(|i| ark_bn254::Fr::from((42 + i) as u64));
        b.iter(|| std::hint::black_box(taceo_poseidon2::bn254::t12::permutation(&input)));
    });
    c.bench_function("Poseidon2 Permutation (t=16)", |b| {
        let input = std::array::from_fn(|i| ark_bn254::Fr::from((42 + i) as u64));
        b.iter(|| std::hint::black_box(taceo_poseidon2::bn254::t16::permutation(&input)));
    });

    c.bench_function("Poseidon2 PermutationInPlace (t=2)", |b| {
        let input = [ark_bn254::Fr::from(42u64), ark_bn254::Fr::from(43u64)];
        b.iter(|| {
            let mut state = input;
            taceo_poseidon2::bn254::t2::permutation_in_place(&mut state);
            std::hint::black_box(state)
        });
    });
    c.bench_function("Poseidon2 PermutationInPlace (t=3)", |b| {
        let input = [
            ark_bn254::Fr::from(42u64),
            ark_bn254::Fr::from(43u64),
            ark_bn254::Fr::from(44u64),
        ];
        b.iter(|| {
            let mut state = input;
            taceo_poseidon2::bn254::t3::permutation_in_place(&mut state);
            std::hint::black_box(state)
        });
    });
    c.bench_function("Poseidon2 PermutationInPlace (t=4)", |b| {
        let input = [
            ark_bn254::Fr::from(42u64),
            ark_bn254::Fr::from(43u64),
            ark_bn254::Fr::from(44u64),
            ark_bn254::Fr::from(45u64),
        ];
        b.iter(|| {
            let mut state = input;
            taceo_poseidon2::bn254::t4::permutation_in_place(&mut state);
            std::hint::black_box(state)
        });
    });
    c.bench_function("Poseidon2 PermutationInPlace (t=8)", |b| {
        let input = std::array::from_fn(|i| ark_bn254::Fr::from((42 + i) as u64));
        b.iter(|| {
            let mut state = input;
            taceo_poseidon2::bn254::t8::permutation_in_place(&mut state);
            std::hint::black_box(state)
        });
    });
    c.bench_function("Poseidon2 PermutationInPlace (t=12)", |b| {
        let input = std::array::from_fn(|i| ark_bn254::Fr::from((42 + i) as u64));
        b.iter(|| {
            let mut state = input;
            taceo_poseidon2::bn254::t12::permutation_in_place(&mut state);
            std::hint::black_box(state)
        });
    });
    c.bench_function("Poseidon2 PermutationInPlace (t=16)", |b| {
        let input = std::array::from_fn(|i| ark_bn254::Fr::from((42 + i) as u64));
        b.iter(|| {
            let mut state = input;
            taceo_poseidon2::bn254::t16::permutation_in_place(&mut state);
            std::hint::black_box(state)
        });
    });
}

criterion_group!(benches, poseidon2_bench);
criterion_main!(benches);
