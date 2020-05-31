use crate::aes128_load;
use crate::aes128_load4;
use crate::aes128_store;
use crate::aes_low_level::aes_ni;
use crate::aes_low_level::aes_ni::ExpandedKeys;
use crate::pot::MAX_VERIFIER_PARALLELISM;
use crate::pot::MIN_VERIFIER_PARALLELISM;
use crate::Block;
use crate::BLOCK_SIZE;
use rayon::prelude::*;

/// Arbitrary length proof-of-time
pub fn prove(
    seed: &Block,
    keys_reg: ExpandedKeys,
    aes_iterations: usize,
    verifier_parallelism: usize,
) -> Vec<u8> {
    assert!(aes_iterations % 12 == 0 && aes_iterations % MAX_VERIFIER_PARALLELISM == 0);
    assert!(
        verifier_parallelism == MIN_VERIFIER_PARALLELISM
            || verifier_parallelism == 8
            || verifier_parallelism == 12
            || verifier_parallelism == MAX_VERIFIER_PARALLELISM
    );

    let inner_iterations = aes_iterations / verifier_parallelism;

    let mut result = Vec::<u8>::with_capacity(verifier_parallelism * BLOCK_SIZE);
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

/// Arbitrary length proof-of-time verification using pipelined AES-NI
pub fn verify(proof: &[u8], seed: &Block, keys_reg: ExpandedKeys, aes_iterations: usize) -> bool {
    assert!(proof.len() % BLOCK_SIZE == 0);
    assert!(aes_iterations % 12 == 0 && aes_iterations % MAX_VERIFIER_PARALLELISM == 0);
    let verifier_parallelism = proof.len() / BLOCK_SIZE;
    assert!(
        verifier_parallelism == MIN_VERIFIER_PARALLELISM
            || verifier_parallelism == 8
            || verifier_parallelism == 12
            || verifier_parallelism == MAX_VERIFIER_PARALLELISM
    );

    let inner_iterations = aes_iterations / verifier_parallelism;

    let mut previous = seed.as_ref();

    proof
        .chunks_exact(BLOCK_SIZE * 4)
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

/// Arbitrary length proof-of-time verification using pipelined AES-NI in parallel
pub fn verify_parallel(
    proof: &[u8],
    seed: &Block,
    keys_reg: ExpandedKeys,
    aes_iterations: usize,
) -> bool {
    let pipelining_parallelism = 4;

    assert_eq!(proof.len() % BLOCK_SIZE, 0);
    let verifier_parallelism = proof.len() / BLOCK_SIZE;
    assert_eq!(verifier_parallelism % pipelining_parallelism, 0);
    assert_eq!(aes_iterations % verifier_parallelism, 0);

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
    use crate::aes_low_level::aes_ni;
    use crate::pot::test_data::CORRECT_PROOF_16;
    use crate::pot::test_data::ID;
    use crate::pot::test_data::SEED;
    use rand::Rng;

    #[test]
    fn test() {
        let aes_iterations = 288;
        let verifier_parallelism = 16;
        let (keys_enc, keys_dec) = aes_ni::expand(&ID);

        let proof = prove(&SEED, keys_enc, aes_iterations, verifier_parallelism);
        assert_eq!(proof.len(), verifier_parallelism * BLOCK_SIZE);
        assert_eq!(proof, CORRECT_PROOF_16.to_vec());

        assert!(verify(&CORRECT_PROOF_16, &SEED, keys_dec, aes_iterations));

        assert!(!verify(
            &vec![42; verifier_parallelism * BLOCK_SIZE],
            &SEED,
            keys_dec,
            aes_iterations
        ));

        assert!(verify_parallel(
            &CORRECT_PROOF_16,
            &SEED,
            keys_dec,
            aes_iterations
        ));

        assert!(!verify_parallel(
            &vec![42; verifier_parallelism * BLOCK_SIZE],
            &SEED,
            keys_dec,
            aes_iterations
        ));
    }

    #[test]
    fn test_random() {
        let aes_iterations = 288;
        let verifier_parallelism = 16;

        let mut key = [0u8; 16];
        rand::thread_rng().fill(&mut key[..]);
        let (keys_enc, keys_dec) = aes_ni::expand(&ID);

        let mut seed = [0u8; 16];
        rand::thread_rng().fill(&mut seed[..]);

        let proof = prove(&seed, keys_enc, aes_iterations, verifier_parallelism);
        assert_eq!(proof.len(), verifier_parallelism * BLOCK_SIZE);

        assert!(verify(&proof, &seed, keys_dec, aes_iterations));

        assert!(verify_parallel(&proof, &seed, keys_dec, aes_iterations));
    }
}
