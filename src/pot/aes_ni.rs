use crate::aes128_load;
use crate::aes128_load4;
use crate::aes128_load_keys;
use crate::aes128_store;
use crate::aes_low_level::aes_ni;
use rayon::prelude::*;

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
    let keys_reg = unsafe { aes128_load_keys!(keys) };
    let mut block = *seed;
    let mut block_reg = unsafe { aes128_load!(block) };

    for _ in 0..verifier_parallelism {
        block_reg = aes_ni::pot_prove_low_level(keys_reg, block_reg, inner_iterations);
        unsafe {
            aes128_store!(block, block_reg);
        }
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

            aes_ni::pot_verify_pipelined_x4_low_level(
                keys_reg,
                expected_reg,
                blocks_reg,
                inner_iterations,
            )
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

            let result = aes_ni::pot_verify_pipelined_x4_low_level(
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
    use super::*;
    use crate::aes_low_level::key_expansion;
    use crate::pot::test_data::CORRECT_PROOF;
    use crate::pot::test_data::ID;
    use crate::pot::test_data::SEED;
    use rand::Rng;

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

    #[test]
    fn test_random() {
        let aes_iterations = 256;
        let verifier_parallelism = 16;

        let mut key = [0u8; 16];
        rand::thread_rng().fill(&mut key[..]);
        let keys = key_expansion::expand_keys_aes_128_enc(&key);

        let mut seed = [0u8; 16];
        rand::thread_rng().fill(&mut seed[..]);

        let proof = prove(&seed, &keys, aes_iterations, verifier_parallelism);
        assert_eq!(proof.len(), verifier_parallelism * BLOCK_SIZE);

        let keys = key_expansion::expand_keys_aes_128_dec(&key);

        assert!(verify_pipelined_4x(&proof, &seed, &keys, aes_iterations));

        assert!(verify_pipelined_4x_parallel(
            &proof,
            &seed,
            &keys,
            aes_iterations
        ));
    }
}
