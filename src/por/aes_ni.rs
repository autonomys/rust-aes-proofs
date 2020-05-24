use crate::aes128_load4;
use crate::aes128_load_keys;
use crate::aes128_store4;
use crate::aes_low_level::aes_ni;
use crate::por::utils;
use crate::por::Block;
use crate::por::Piece;
use crate::por::BLOCK_SIZE;
use crate::por::PIECE_SIZE;
use core::arch::x86_64::*;

/// Pipelined proof of replication encoding with AES-NI
pub fn encode(
    pieces: &mut [Piece; 4],
    keys: &[Block; 11],
    mut ivs: [Block; 4],
    aes_iterations: usize,
    breadth_iterations: usize,
) {
    for _ in 0..breadth_iterations {
        ivs = encode_internal(pieces, keys, ivs, aes_iterations);
    }
}

/// Pipelined proof of replication decoding with AES-NI
pub fn decode(
    piece: &mut Piece,
    keys: &[Block; 11],
    iv: &Block,
    aes_iterations: usize,
    breadth_iterations: usize,
) {
    for _ in 1..breadth_iterations {
        decode_internal(piece, keys, None, aes_iterations);
    }

    decode_internal(piece, keys, Some(iv), aes_iterations);
}

/// Returns iv for the next round
fn encode_internal(
    pieces: &mut [Piece; 4],
    keys: &[Block; 11],
    mut ivs: [Block; 4],
    aes_iterations: usize,
) -> [Block; 4] {
    let [piece0, piece1, piece2, piece3] = pieces;

    let keys_reg = unsafe { aes128_load_keys!(keys) };

    piece0
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(piece1.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece2.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece3.chunks_exact_mut(BLOCK_SIZE))
        .map(|(((piece0, piece1), piece2), piece3)| [piece0, piece1, piece2, piece3])
        .for_each(|blocks| {
            let mut blocks_reg =
                unsafe { aes128_load4!(blocks[0], blocks[1], blocks[2], blocks[3]) };
            let feedbacks_reg = unsafe { aes128_load4!(ivs[0], ivs[1], ivs[2], ivs[3]) };

            aes_ni::por_encode_pipelined_x4_low_level(
                keys_reg,
                &mut blocks_reg,
                feedbacks_reg,
                aes_iterations,
            );

            unsafe {
                aes128_store4!(blocks, blocks_reg);
                aes128_store4!(ivs, blocks_reg);
            }
        });

    ivs
}

fn decode_internal(
    piece: &mut Piece,
    keys: &[Block; 11],
    iv: Option<&Block>,
    aes_iterations: usize,
) {
    let keys_reg = unsafe { aes128_load_keys!(keys) };

    for i in (1..(PIECE_SIZE / BLOCK_SIZE / 4)).rev() {
        let (blocks, feedback) = utils::piece_to_blocks_and_feedback(piece, i, 4);
        decode_4_blocks_internal(keys_reg, blocks, feedback, aes_iterations);
    }

    let (first_4_blocks, feedback) = utils::piece_to_first_blocks_and_feedback(piece, iv, 4);
    decode_4_blocks_internal(keys_reg, first_4_blocks, feedback, aes_iterations);
}

fn decode_4_blocks_internal(
    keys_reg: [__m128i; 11],
    blocks: &mut [u8],
    feedback: &Block,
    aes_iterations: usize,
) {
    let (mut block0, blocks) = blocks.split_at_mut(BLOCK_SIZE);
    let (mut block1, blocks) = blocks.split_at_mut(BLOCK_SIZE);
    let (mut block2, mut block3) = blocks.split_at_mut(BLOCK_SIZE);

    let mut blocks_reg = unsafe { aes128_load4!(block0, block1, block2, block3) };
    let feedbacks_reg = unsafe { aes128_load4!(feedback, block0, block1, block2) };

    aes_ni::por_decode_pipelined_x4_low_level(
        keys_reg,
        &mut blocks_reg,
        feedbacks_reg,
        aes_iterations,
    );

    unsafe {
        aes128_store4!(
            [&mut block0, &mut block1, &mut block2, &mut block3],
            blocks_reg
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes_low_level::key_expansion;
    use crate::por::test_data::CORRECT_ENCODING;
    use crate::por::test_data::CORRECT_ENCODING_BREADTH_10;
    use crate::por::test_data::ID;
    use crate::por::test_data::INPUT;
    use crate::por::test_data::IV;
    use crate::por::PIECE_SIZE;
    use rand::Rng;

    #[test]
    fn test() {
        let aes_iterations = 256;

        let keys = key_expansion::expand_keys_aes_128_enc(&ID);

        let mut encodings = [INPUT; 4];
        encode(&mut encodings, &keys, [IV; 4], aes_iterations, 1);

        for encoding in encodings.iter() {
            assert_eq!(encoding.to_vec(), CORRECT_ENCODING.to_vec());
        }

        let keys = key_expansion::expand_keys_aes_128_dec(&ID);

        let mut decoding = CORRECT_ENCODING;
        decode(&mut decoding, &keys, &IV, aes_iterations, 1);

        assert_eq!(decoding.to_vec(), INPUT.to_vec());
    }

    #[test]
    fn test_breadth_10() {
        let aes_iterations = 256;

        let keys = key_expansion::expand_keys_aes_128_enc(&ID);

        let mut encodings = [INPUT; 4];
        encode(&mut encodings, &keys, [IV; 4], aes_iterations, 10);

        for encoding in encodings.iter() {
            assert_eq!(encoding.to_vec(), CORRECT_ENCODING_BREADTH_10.to_vec());
        }

        let keys = key_expansion::expand_keys_aes_128_dec(&ID);

        let mut decoding = CORRECT_ENCODING_BREADTH_10;
        decode(&mut decoding, &keys, &IV, aes_iterations, 10);

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

        let keys = key_expansion::expand_keys_aes_128_enc(&id);

        let mut encodings = [input; 4];
        encode(&mut encodings, &keys, [iv; 4], aes_iterations, 1);

        let keys = key_expansion::expand_keys_aes_128_dec(&id);

        for encoding in encodings.iter() {
            let mut decoding = *encoding;
            decode(&mut decoding, &keys, &iv, aes_iterations, 1);

            assert_eq!(decoding.to_vec(), input.to_vec());
        }
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

        let keys = key_expansion::expand_keys_aes_128_enc(&id);

        let mut encodings = [input; 4];
        encode(&mut encodings, &keys, [iv; 4], aes_iterations, 10);

        let keys = key_expansion::expand_keys_aes_128_dec(&id);

        for encoding in encodings.iter() {
            let mut decoding = *encoding;
            decode(&mut decoding, &keys, &iv, aes_iterations, 10);

            assert_eq!(decoding.to_vec(), input.to_vec());
        }
    }
}
