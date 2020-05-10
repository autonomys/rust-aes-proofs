/// Proof of time
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use rust_aes_proofs::aes_low_level::key_expansion;
use rust_aes_proofs::pot::aes_ni;

pub fn criterion_benchmark(c: &mut Criterion) {
    {
        let seed: [u8; 16] = [
            0xd6, 0x66, 0xcc, 0xd8, 0xd5, 0x93, 0xc2, 0x3d, 0xa8, 0xdb, 0x6b, 0x5b, 0x14, 0x13,
            0xb1, 0x3a,
        ];
        let id: [u8; 16] = [
            0x9a, 0x84, 0x94, 0x0f, 0xfe, 0xf5, 0xb0, 0xd7, 0x01, 0x99, 0xfc, 0x67, 0xf4, 0x6e,
            0xa2, 0x7a,
        ];
        let base_aes_iterations = 3_000_000;
        let prove_keys = key_expansion::expand_keys_aes_128_enc(&id);

        let mut group = c.benchmark_group("Proof-of-time");
        group.sample_size(10);

        let benchmark_parameters = [1_usize, 10, 100]
            .iter()
            .map(|&n| n * base_aes_iterations)
            .flat_map(|aes_iterations| {
                [4, 16, 64]
                    .iter()
                    .map(move |&verifier_parallelism| (aes_iterations, verifier_parallelism))
            });
        for (aes_iterations, verifier_parallelism) in benchmark_parameters {
            group.bench_function(
                format!(
                    "Prove-{}-iterations-{}-parallelism",
                    aes_iterations, verifier_parallelism
                ),
                |b| {
                    b.iter(|| {
                        criterion::black_box(aes_ni::prove(
                            &seed,
                            &prove_keys,
                            aes_iterations,
                            verifier_parallelism,
                        ))
                    })
                },
            );

            let proof = aes_ni::prove(&seed, &prove_keys, aes_iterations, verifier_parallelism);
            let verify_keys = key_expansion::expand_keys_aes_128_dec(&id);

            group.bench_function(
                format!(
                    "Verify-pipelined-{}-iterations-{}-parallelism",
                    aes_iterations, verifier_parallelism
                ),
                |b| {
                    b.iter(|| {
                        criterion::black_box(aes_ni::verify_pipelined_4x(
                            &proof,
                            &seed,
                            &verify_keys,
                            aes_iterations,
                        ))
                    })
                },
            );

            group.bench_function(
                format!(
                    "Verify-pipelined-parallel-{}-iterations-{}-parallelism",
                    aes_iterations, verifier_parallelism
                ),
                |b| {
                    b.iter(|| {
                        criterion::black_box(aes_ni::verify_pipelined_4x_parallel(
                            &proof,
                            &seed,
                            &verify_keys,
                            aes_iterations,
                        ))
                    })
                },
            );
        }

        group.finish();
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
