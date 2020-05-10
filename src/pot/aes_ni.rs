use crate::aes128_load4;
use crate::aes128_load_keys;
use crate::aes_low_level::aes_ni;
use rayon::prelude::*;
use std::convert::TryInto;

pub const BLOCK_SIZE: usize = 16;

/// Arbitrary length proof-of-time
pub fn prove(
    seed: &[u8; BLOCK_SIZE],
    keys: &[[u8; BLOCK_SIZE]; 11],
    aes_iterations: usize,
    verifier_parallelism: usize,
) -> Vec<u8> {
    assert_eq!(aes_iterations % verifier_parallelism, 0);

    let inner_iterations = aes_iterations / verifier_parallelism;

    let mut result = Vec::<u8>::with_capacity(verifier_parallelism * BLOCK_SIZE);
    let mut block = *seed;

    for _ in 0..verifier_parallelism {
        block = unsafe {
            aes_benchmarks::encode_aes_ni_128(
                &keys,
                block[..].try_into().unwrap(),
                inner_iterations,
            )
        };
        result.extend_from_slice(&block);
    }

    result
}

/// Arbitrary length proof-of-time verification using pipelined AES-NI (proof must be a multiple of
/// 4 blocks)
pub fn verify_pipelined_4x(
    proof: &[u8],
    seed: &[u8; BLOCK_SIZE],
    keys: &[[u8; BLOCK_SIZE]; 11],
    aes_iterations: usize,
) -> bool {
    let pipelining_parallelism = 4;

    assert_eq!(proof.len() % BLOCK_SIZE, 0);
    let verifier_parallelism = proof.len() / BLOCK_SIZE;
    assert_eq!(verifier_parallelism % pipelining_parallelism, 0);
    assert_eq!(aes_iterations % verifier_parallelism, 0);

    let keys_reg = unsafe { aes128_load_keys!(keys) };
    let inner_iterations = aes_iterations / verifier_parallelism;

    let mut previous = seed.as_ref();

    proof
        .chunks_exact(BLOCK_SIZE * pipelining_parallelism)
        .map(|blocks| -> bool {
            let (block0, blocks) = blocks.split_at(BLOCK_SIZE);
            let (block1, blocks) = blocks.split_at(BLOCK_SIZE);
            let (block2, block3) = blocks.split_at(BLOCK_SIZE);

            let expected_reg = unsafe { aes128_load4!(previous, block0, block1, block2) };
            let blocks_reg = unsafe { aes128_load4!(block0, block1, block2, block3) };
            previous = block3;

            aes_ni::pot_verify_pipelined_x4(keys_reg, expected_reg, blocks_reg, inner_iterations)
        })
        .fold(true, |a, b| a && b)
}

/// Arbitrary length proof-of-time verification using pipelined AES-NI (proof must be a multiple of
/// 4 blocks)
pub fn verify_pipelined_4x_parallel(
    proof: &[u8],
    seed: &[u8; BLOCK_SIZE],
    keys: &[[u8; BLOCK_SIZE]; 11],
    aes_iterations: usize,
) -> bool {
    let pipelining_parallelism = 4;

    assert_eq!(proof.len() % BLOCK_SIZE, 0);
    let verifier_parallelism = proof.len() / BLOCK_SIZE;
    assert_eq!(verifier_parallelism % pipelining_parallelism, 0);
    assert_eq!(aes_iterations % verifier_parallelism, 0);

    let keys_reg = unsafe { aes128_load_keys!(keys) };
    let inner_iterations = aes_iterations / verifier_parallelism;

    // Seeds iterator
    [seed.as_ref()]
        .iter()
        .map(|seed| -> &[u8] { seed })
        .chain(
            proof
                .chunks_exact(BLOCK_SIZE)
                .skip(pipelining_parallelism - 1)
                .step_by(pipelining_parallelism),
        )
        // Seeds with blocks iterator
        .zip(proof.chunks_exact(pipelining_parallelism * BLOCK_SIZE))
        .par_bridge()
        .map(|(seed, blocks)| {
            let (block0, blocks) = blocks.split_at(BLOCK_SIZE);
            let (block1, blocks) = blocks.split_at(BLOCK_SIZE);
            let (block2, block3) = blocks.split_at(BLOCK_SIZE);

            let expected_reg = unsafe { aes128_load4!(seed, block0, block1, block2) };
            let blocks_reg = unsafe { aes128_load4!(block0, block1, block2, block3) };

            let result = aes_ni::pot_verify_pipelined_x4(
                keys_reg,
                expected_reg,
                blocks_reg,
                inner_iterations,
            );

            result
        })
        .reduce(|| true, |a, b| a && b)
}

#[cfg(test)]
mod tests {
    mod test_data {
        // Proof of time
        pub const SEED: [u8; 16] = [
            0xd6, 0x66, 0xcc, 0xd8, 0xd5, 0x93, 0xc2, 0x3d, 0xa8, 0xdb, 0x6b, 0x5b, 0x14, 0x13,
            0xb1, 0x3a,
        ];
        pub const ID: [u8; 16] = [
            0x9a, 0x84, 0x94, 0x0f, 0xfe, 0xf5, 0xb0, 0xd7, 0x01, 0x99, 0xfc, 0x67, 0xf4, 0x6e,
            0xa2, 0x7a,
        ];
        pub const CORRECT_PROOF: [u8; 256] = [
            0x8b, 0xba, 0xda, 0x79, 0x13, 0x37, 0xc9, 0xff, 0xde, 0xd9, 0x6f, 0xa0, 0x4a, 0xbb,
            0x88, 0x10, 0x87, 0xe9, 0x09, 0xe5, 0x5b, 0x5e, 0x81, 0xd8, 0xf0, 0x92, 0x5c, 0x77,
            0x28, 0x49, 0xb4, 0x15, 0x10, 0x4e, 0xd2, 0xb8, 0x18, 0x8b, 0x9f, 0xf1, 0x85, 0xfe,
            0x99, 0xa5, 0x0c, 0xdd, 0x9a, 0xd6, 0x4b, 0x88, 0xd3, 0xd0, 0x09, 0x80, 0xea, 0x6c,
            0x56, 0xc7, 0x4b, 0x0e, 0x90, 0x8b, 0x14, 0xc6, 0xe6, 0xc7, 0x64, 0x58, 0x12, 0xb5,
            0xbf, 0x2f, 0xba, 0x16, 0x93, 0xd3, 0xc8, 0xe5, 0xd7, 0xe3, 0x0a, 0xa6, 0x56, 0x94,
            0xeb, 0x61, 0xaa, 0x20, 0xa2, 0x98, 0x99, 0xbc, 0x8d, 0x9a, 0xd8, 0x18, 0x5b, 0x29,
            0xef, 0xd1, 0x25, 0xe8, 0x78, 0x53, 0xb3, 0x09, 0x2b, 0x16, 0xaa, 0x9a, 0xcd, 0x95,
            0x8c, 0xa3, 0x80, 0x2d, 0x69, 0x51, 0x81, 0x25, 0x87, 0xf6, 0x97, 0x3c, 0xbb, 0x92,
            0x17, 0x94, 0x17, 0xa4, 0x18, 0xf7, 0x95, 0x89, 0x2d, 0xa4, 0xcf, 0x20, 0x17, 0xec,
            0x07, 0xf2, 0x02, 0x54, 0x96, 0xea, 0x00, 0x5b, 0xc4, 0xa6, 0x69, 0x15, 0xa0, 0x1a,
            0xa3, 0x5e, 0x6c, 0x71, 0x91, 0xc5, 0x14, 0xd6, 0x0c, 0x7d, 0xfe, 0xbb, 0xa6, 0x2a,
            0x62, 0x30, 0x21, 0xe6, 0x6d, 0x94, 0x72, 0xd3, 0xa0, 0xda, 0x33, 0xb3, 0x4e, 0xab,
            0x58, 0x4a, 0x06, 0x0d, 0xcf, 0x80, 0xe6, 0x82, 0x2d, 0x72, 0xa6, 0x59, 0x8b, 0xe7,
            0x2e, 0xb9, 0xb7, 0x09, 0xc1, 0xbb, 0x15, 0x80, 0x17, 0x0d, 0xa8, 0x81, 0x9f, 0x6d,
            0x19, 0x61, 0x5b, 0xe7, 0x1e, 0x77, 0x00, 0x57, 0x64, 0x77, 0x7a, 0x2d, 0x72, 0x35,
            0x72, 0x6c, 0x11, 0xcf, 0x7d, 0xe0, 0xfe, 0x60, 0xb6, 0x4a, 0x3e, 0x92, 0xdd, 0xff,
            0x43, 0xb5, 0x3d, 0xc6, 0xd8, 0x19, 0xaf, 0x61, 0xeb, 0x34, 0xaa, 0x52, 0xb4, 0x5e,
            0x88, 0x2f, 0x6a, 0x20,
        ];
    }

    use super::*;
    use crate::aes_low_level::key_expansion;
    use test_data::CORRECT_PROOF;
    use test_data::ID;
    use test_data::SEED;

    #[test]
    fn test() {
        let aes_iterations = 256;
        let verifier_parallelism = 16;
        let keys = key_expansion::expand_keys_aes_128_enc(&ID);

        let proof = prove(&SEED, &keys, aes_iterations, verifier_parallelism);
        assert_eq!(proof.len(), verifier_parallelism * BLOCK_SIZE);
        assert_eq!(proof, CORRECT_PROOF.to_vec());

        let keys = key_expansion::expand_keys_aes_128_dec(&ID);

        assert!(verify_pipelined_4x(
            &CORRECT_PROOF,
            &SEED,
            &keys,
            aes_iterations
        ));

        assert!(!verify_pipelined_4x(
            &vec![42; verifier_parallelism * BLOCK_SIZE],
            &SEED,
            &keys,
            aes_iterations
        ));

        assert!(verify_pipelined_4x_parallel(
            &CORRECT_PROOF,
            &SEED,
            &keys,
            aes_iterations
        ));

        assert!(!verify_pipelined_4x_parallel(
            &vec![42; verifier_parallelism * BLOCK_SIZE],
            &SEED,
            &keys,
            aes_iterations
        ));
    }
}
