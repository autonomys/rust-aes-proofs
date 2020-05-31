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

pub struct AesNiKeys {
    keys_enc: ExpandedKeys,
    // Exposing this field is a hack to avoid duplicated key derivation in VAES code
    pub(super) keys_dec: ExpandedKeys,
}

impl AesNiKeys {
    pub fn new(id: &Block) -> Self {
        let (keys_enc, keys_dec) = aes_ni::expand(id);
        Self { keys_enc, keys_dec }
    }
}

pub struct AesNi;

impl AesNi {
    pub fn new() -> Self {
        Self {}
    }
    /// Arbitrary length proof-of-time
    pub fn prove(
        &self,
        seed: &Block,
        keys: &AesNiKeys,
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
            block_reg = aes_ni::pot_prove_low_level(keys.keys_enc, block_reg, inner_iterations);
            unsafe {
                aes128_store!(block, block_reg);
            }
            result.extend_from_slice(&block);
        }

        result
    }

    /// Arbitrary length proof-of-time verification using pipelined AES-NI
    pub fn verify(
        &self,
        proof: &[u8],
        seed: &Block,
        keys: &AesNiKeys,
        aes_iterations: usize,
    ) -> bool {
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
                    keys.keys_dec,
                    expected_reg,
                    blocks_reg,
                    inner_iterations,
                )
            })
            .fold(true, |a, b| a && b)
    }

    /// Arbitrary length proof-of-time verification using pipelined AES-NI in parallel
    pub fn verify_parallel(
        &self,
        proof: &[u8],
        seed: &Block,
        keys: &AesNiKeys,
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
                    keys.keys_dec,
                    expected_reg,
                    blocks_reg,
                    inner_iterations,
                );

                result
            })
            .reduce(|| true, |a, b| a && b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pot::test_data::CORRECT_PROOF_16;
    use crate::pot::test_data::ID;
    use crate::pot::test_data::SEED;
    use rand::Rng;

    #[test]
    fn test() {
        let aes_iterations = 288;
        let verifier_parallelism = 16;

        let keys = AesNiKeys::new(&ID);
        let pot = AesNi::new();

        let proof = pot.prove(&SEED, &keys, aes_iterations, verifier_parallelism);
        assert_eq!(proof.len(), verifier_parallelism * BLOCK_SIZE);
        assert_eq!(proof, CORRECT_PROOF_16.to_vec());

        assert!(pot.verify(&CORRECT_PROOF_16, &SEED, &keys, aes_iterations));

        assert!(!pot.verify(
            &vec![42; verifier_parallelism * BLOCK_SIZE],
            &SEED,
            &keys,
            aes_iterations
        ));

        assert!(pot.verify_parallel(&CORRECT_PROOF_16, &SEED, &keys, aes_iterations));

        assert!(!pot.verify_parallel(
            &vec![42; verifier_parallelism * BLOCK_SIZE],
            &SEED,
            &keys,
            aes_iterations
        ));
    }

    #[test]
    fn test_random() {
        let aes_iterations = 288;
        let verifier_parallelism = 16;

        let mut key = [0u8; 16];
        rand::thread_rng().fill(&mut key[..]);

        let mut seed = [0u8; 16];
        rand::thread_rng().fill(&mut seed[..]);

        let keys = AesNiKeys::new(&key);
        let pot = AesNi::new();

        let proof = pot.prove(&seed, &keys, aes_iterations, verifier_parallelism);
        assert_eq!(proof.len(), verifier_parallelism * BLOCK_SIZE);

        assert!(pot.verify(&proof, &seed, &keys, aes_iterations));

        assert!(pot.verify_parallel(&proof, &seed, &keys, aes_iterations));
    }
}
