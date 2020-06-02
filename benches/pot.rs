use crate::test_data::ID;
use crate::test_data::SEED;
/// Proof of time
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::Criterion;
use rust_aes_proofs::pot::aes_ni::AesNi;
use rust_aes_proofs::pot::aes_ni::AesNiKeys;
use rust_aes_proofs::pot::vaes::VAes;
use rust_aes_proofs::pot::vaes::VAesKeys;
use rust_aes_proofs::utils;
use rust_aes_proofs::utils::AesImplementation;

pub fn criterion_benchmark(c: &mut Criterion) {
    {
        let keys = AesNiKeys::new(&ID);
        let pot = AesNi::new();

        let base_aes_iterations = 3_000_000;

        let mut group = c.benchmark_group("AES-NI");
        group.sample_size(10);

        let benchmark_parameters = [1_usize, 10, 100]
            .iter()
            .map(|&n| n * base_aes_iterations)
            .flat_map(|aes_iterations| {
                [4, 8, 12, 16]
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
                        pot.prove(&SEED, &keys, aes_iterations, verifier_parallelism);
                    })
                },
            );

            let proof = pot.prove(&SEED, &keys, aes_iterations, verifier_parallelism);

            group.bench_function(
                format!(
                    "Verify-pipelined-{}-iterations-{}-parallelism",
                    aes_iterations, verifier_parallelism
                ),
                |b| {
                    b.iter(|| {
                        pot.verify(&proof, &SEED, &keys, aes_iterations);
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
                        pot.verify_parallel(&proof, &SEED, &keys, aes_iterations);
                    })
                },
            );
        }

        group.finish();
    }
    if !utils::aes_implementations_available().contains(&AesImplementation::VAes) {
        println!("VAES support not available, skipping benchmarks");
    } else {
        let keys = VAesKeys::new(&ID);
        let pot = VAes::new();

        let base_aes_iterations = 3_000_000;

        let mut group = c.benchmark_group("VAES");
        group.sample_size(10);

        let benchmark_parameters = [1_usize, 10, 100]
            .iter()
            .map(|&n| n * base_aes_iterations)
            .flat_map(|aes_iterations| {
                [4, 8, 12, 16]
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
                        pot.prove(&SEED, &keys, aes_iterations, verifier_parallelism);
                    })
                },
            );

            let proof = pot.prove(&SEED, &keys, aes_iterations, verifier_parallelism);

            group.bench_function(
                format!(
                    "Verify-pipelined-{}-iterations-{}-parallelism",
                    aes_iterations, verifier_parallelism
                ),
                |b| {
                    b.iter(|| {
                        pot.verify(&proof, &SEED, &keys, aes_iterations);
                    })
                },
            );
        }

        group.finish();
    }
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);

mod test_data {
    use rust_aes_proofs::Block;

    pub const SEED: Block = [
        0xd6, 0x66, 0xcc, 0xd8, 0xd5, 0x93, 0xc2, 0x3d, 0xa8, 0xdb, 0x6b, 0x5b, 0x14, 0x13, 0xb1,
        0x3a,
    ];
    pub const ID: Block = [
        0x9a, 0x84, 0x94, 0x0f, 0xfe, 0xf5, 0xb0, 0xd7, 0x01, 0x99, 0xfc, 0x67, 0xf4, 0x6e, 0xa2,
        0x7a,
    ];
}
