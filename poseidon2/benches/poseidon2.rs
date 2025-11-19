use criterion::*;

fn poseidon2_bench(c: &mut Criterion) {
    c.bench_function("Poseidon2 Permutation (t=3)", |b| {
        let input = [
            ark_bn254::Fr::from(42u64),
            ark_bn254::Fr::from(43u64),
            ark_bn254::Fr::from(44u64),
        ];

        b.iter(|| std::hint::black_box(taceo_poseidon2::t3_permutation(&input)));
    });
    c.bench_function("Poseidon2 Permutation (t=4)", |b| {
        let input = [
            ark_bn254::Fr::from(42u64),
            ark_bn254::Fr::from(43u64),
            ark_bn254::Fr::from(44u64),
            ark_bn254::Fr::from(45u64),
        ];

        b.iter(|| std::hint::black_box(taceo_poseidon2::t4_permutation(&input)));
    });
}

criterion_group!(benches, poseidon2_bench);
criterion_main!(benches);
