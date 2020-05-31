use crate::por::utils;
use crate::Block;
use crate::Piece;
use crate::BLOCK_SIZE;
use crate::PIECE_SIZE;
use aes_frast::aes_core;
use std::io::Write;

/// Proof of replication encoding purely in software (using look-up table approach)
pub fn encode(
    piece: &mut Piece,
    key: &Block,
    mut iv: Block,
    aes_iterations: usize,
    breadth_iterations: usize,
) {
    // TODO: This should probably be made external, otherwise using the same key for frequent calls
    //  will have severe performance hit
    let mut keys = [0u32; 44];
    aes_core::setkey_enc_k128(key, &mut keys);
    for _ in 0..breadth_iterations {
        iv = encode_internal(piece, &keys, iv, aes_iterations);
    }
}

/// Proof of replication decoding purely in software (using look-up table approach)
pub fn decode(
    piece: &mut Piece,
    key: &Block,
    iv: &Block,
    aes_iterations: usize,
    breadth_iterations: usize,
) {
    // TODO: This should probably be made external, otherwise using the same key for frequent calls
    //  will have severe performance hit
    let mut keys = [0u32; 44];
    aes_core::setkey_dec_k128(key, &mut keys);
    for _ in 1..breadth_iterations {
        decode_internal(piece, &keys, None, aes_iterations);
    }

    decode_internal(piece, &keys, Some(iv), aes_iterations);
}

fn encode_internal(
    piece: &mut Piece,
    keys: &[u32; 44],
    mut iv: Block,
    aes_iterations: usize,
) -> Block {
    piece.chunks_exact_mut(BLOCK_SIZE).for_each(|block| {
        block
            .iter_mut()
            .zip(&iv)
            .for_each(|(block_byte, feedback_byte)| {
                *block_byte ^= feedback_byte;
            });

        for _ in 0..aes_iterations {
            // TODO: This needs to be in-place in aes_frast crate
            aes_core::block_enc_k128(&block, &mut iv, keys);
            block.as_mut().write_all(&iv).unwrap();
        }
    });

    iv
}

fn decode_internal(piece: &mut Piece, keys: &[u32; 44], iv: Option<&Block>, aes_iterations: usize) {
    let mut tmp: Block = [0u8; 16];

    for i in (1..(PIECE_SIZE / BLOCK_SIZE)).rev() {
        let (block, feedback) = utils::piece_to_blocks_and_feedback(piece, i, 1);

        decode_block_internal(keys, block, feedback, aes_iterations, &mut tmp);
    }

    let (first_block, feedback) = utils::piece_to_first_blocks_and_feedback(piece, iv, 1);
    decode_block_internal(keys, first_block, &feedback, aes_iterations, &mut tmp);
}

fn decode_block_internal(
    keys: &[u32; 44],
    block: &mut [u8],
    feedback: &Block,
    aes_iterations: usize,
    tmp: &mut Block,
) {
    for _ in 0..aes_iterations {
        // TODO: This needs to be in-place in aes_frast crate
        aes_core::block_dec_k128(&block, tmp, keys);
        block.as_mut().write_all(tmp).unwrap();
    }

    block
        .iter_mut()
        .zip(feedback.iter())
        .for_each(|(block_byte, feedback_byte)| {
            *block_byte ^= feedback_byte;
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::por::test_data::CORRECT_ENCODING;
    use crate::por::test_data::CORRECT_ENCODING_BREADTH_10;
    use crate::por::test_data::ID;
    use crate::por::test_data::INPUT;
    use crate::por::test_data::IV;
    use crate::PIECE_SIZE;
    use rand::Rng;

    #[test]
    fn test() {
        let aes_iterations = 256;

        let mut encoding = INPUT;
        encode(&mut encoding, &ID, IV, aes_iterations, 1);

        assert_eq!(encoding.to_vec(), CORRECT_ENCODING.to_vec());

        let mut decoding = CORRECT_ENCODING;
        decode(&mut decoding, &ID, &IV, aes_iterations, 1);

        assert_eq!(decoding.to_vec(), INPUT.to_vec());
    }

    #[test]
    fn test_breadth_10() {
        let aes_iterations = 256;

        let mut encoding = INPUT;
        encode(&mut encoding, &ID, IV, aes_iterations, 10);

        assert_eq!(encoding.to_vec(), CORRECT_ENCODING_BREADTH_10.to_vec());

        let mut decoding = CORRECT_ENCODING_BREADTH_10;
        decode(&mut decoding, &ID, &IV, aes_iterations, 10);

        assert_eq!(decoding.to_vec(), INPUT.to_vec());
    }

    #[test]
    fn test_random() {
        let aes_iterations = 256;

        let mut id = [0u8; 16];
        rand::thread_rng().fill(&mut id[..]);

        let mut input = [0u8; PIECE_SIZE];
        rand::thread_rng().fill(&mut input[..]);

        let mut iv = [0u8; 16];
        rand::thread_rng().fill(&mut iv[..]);

        let mut encoding = input;
        encode(&mut encoding, &id, iv, aes_iterations, 1);

        let mut decoding = encoding;
        decode(&mut decoding, &id, &iv, aes_iterations, 1);

        assert_eq!(decoding.to_vec(), input.to_vec());
    }

    #[test]
    fn test_random_breadth_10() {
        let aes_iterations = 256;

        let mut id = [0u8; 16];
        rand::thread_rng().fill(&mut id[..]);

        let mut input = [0u8; PIECE_SIZE];
        rand::thread_rng().fill(&mut input[..]);

        let mut iv = [0u8; 16];
        rand::thread_rng().fill(&mut iv[..]);

        let mut encoding = input;
        encode(&mut encoding, &id, iv, aes_iterations, 10);

        let mut decoding = encoding;
        decode(&mut decoding, &id, &iv, aes_iterations, 10);

        assert_eq!(decoding.to_vec(), input.to_vec());
    }
}
