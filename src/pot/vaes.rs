use crate::aes_low_level::vaes;
use crate::pot::aes_ni::AesNi;
use crate::pot::aes_ni::AesNiKeys;
use crate::pot::MAX_VERIFIER_PARALLELISM;
use crate::pot::MIN_VERIFIER_PARALLELISM;
use crate::Block;
use crate::BLOCK_SIZE;

// TODO: This should use keys expanded using AES-NI
pub struct VAesKeys {
    aes_ni: AesNiKeys,
}

impl VAesKeys {
    pub fn new(id: &Block) -> Self {
        let aes_ni = AesNiKeys::new(id);
        Self { aes_ni }
    }
}

pub struct VAes {
    aes_ni: AesNi,
}

impl VAes {
    pub fn new() -> Self {
        let aes_ni = AesNi::new();
        Self { aes_ni }
    }

    pub fn prove(
        &self,
        seed: &Block,
        keys: &VAesKeys,
        aes_iterations: usize,
        verifier_parallelism: usize,
    ) -> Vec<u8> {
        self.aes_ni
            .prove(seed, &keys.aes_ni, aes_iterations, verifier_parallelism)
    }

    /// Arbitrary length proof-of-time verification using pipelined VAES (proof must be a multiple of
    /// 12 blocks)
    pub fn verify(
        &self,
        proof: &[u8],
        seed: &Block,
        keys: &VAesKeys,
        aes_iterations: usize,
    ) -> bool {
        let pipelining_parallelism = 12;

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

        let iterator = proof.chunks_exact(BLOCK_SIZE * pipelining_parallelism);
        let remainder = iterator.remainder();
        let result = iterator
            .map(|blocks| -> bool {
                let expected_first_block = previous;
                previous = &blocks[(blocks.len() - BLOCK_SIZE)..];

                vaes::pot_verify_pipelined_x12_low_level(
                    &keys.aes_ni.keys_dec,
                    expected_first_block,
                    blocks,
                    inner_iterations,
                )
            })
            .fold(true, |a, b| a && b);

        if !result || remainder.is_empty() {
            return result;
        }

        let iterator = remainder.chunks_exact(BLOCK_SIZE * 8);
        let remainder = iterator.remainder();
        let result = iterator
            .map(|blocks| {
                let expected_first_block = previous;
                previous = &blocks[(blocks.len() - BLOCK_SIZE)..];

                vaes::pot_verify_pipelined_x8_low_level(
                    &keys.aes_ni.keys_dec,
                    expected_first_block,
                    blocks,
                    inner_iterations,
                )
            })
            .fold(true, |a, b| a && b);

        if !result || remainder.is_empty() {
            return result;
        }

        remainder
            .chunks_exact(MIN_VERIFIER_PARALLELISM)
            .map(|blocks| {
                let expected_first_block = previous;
                previous = &blocks[(blocks.len() - BLOCK_SIZE)..];

                vaes::pot_verify_x4_low_level(
                    &keys.aes_ni.keys_dec,
                    expected_first_block,
                    blocks,
                    inner_iterations,
                )
            })
            .fold(true, |a, b| a && b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pot::test_data::CORRECT_PROOF_12;
    use crate::pot::test_data::ID;
    use crate::pot::test_data::SEED;
    use crate::utils;
    use crate::utils::AesImplementation;
    use rand::Rng;

    #[test]
    fn test() {
        if !utils::aes_implementations_available().contains(&AesImplementation::VAes) {
            println!("VAES support not available, skipping test");
            return;
        }
        let aes_iterations = 288;
        let verifier_parallelism = 12;

        let keys = VAesKeys::new(&ID);
        let pot = VAes::new();

        let proof = pot.prove(&SEED, &keys, aes_iterations, verifier_parallelism);
        assert_eq!(proof.len(), verifier_parallelism * BLOCK_SIZE);
        assert_eq!(proof, CORRECT_PROOF_12.to_vec());

        assert!(pot.verify(&CORRECT_PROOF_12, &SEED, &keys, aes_iterations));

        assert!(!pot.verify(
            &vec![42; verifier_parallelism * BLOCK_SIZE],
            &SEED,
            &keys,
            aes_iterations,
        ));
    }

    #[test]
    fn test_random() {
        if !utils::aes_implementations_available().contains(&AesImplementation::VAes) {
            println!("VAES support not available, skipping test");
            return;
        }
        let aes_iterations = 288;
        let verifier_parallelism = 12;

        let mut key = [0u8; 16];
        rand::thread_rng().fill(&mut key[..]);

        let mut seed = [0u8; 16];
        rand::thread_rng().fill(&mut seed[..]);

        let keys = VAesKeys::new(&key);
        let pot = VAes::new();

        let proof = pot.prove(&seed, &keys, aes_iterations, verifier_parallelism);
        assert_eq!(proof.len(), verifier_parallelism * BLOCK_SIZE);

        assert!(pot.verify(&proof, &seed, &keys, aes_iterations));
    }
}
