use crate::aes128_load4;
use crate::aes128_load_keys;
use crate::aes128_store4;
use crate::aes_low_level::aes_ni;
use crate::por::Block;
use crate::por::Piece;
use crate::por::BLOCK_SIZE;
use std::convert::TryInto;
use std::io::Write;

/// Pipelined proof of replication encoding with AES-NI
pub fn encode(
    pieces: &mut [Piece; 4],
    keys: &[Block; 11],
    iv: [&Block; 4],
    aes_iterations: usize,
    breadth_iterations: usize,
) {
    for _ in 0..breadth_iterations {
        encode_internal(pieces, keys, iv, aes_iterations);
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
    for _ in 0..breadth_iterations {
        decode_internal(piece, keys, iv, aes_iterations);
    }
}

fn encode_internal(
    pieces: &mut [Piece; 4],
    keys: &[Block; 11],
    iv: [&Block; 4],
    aes_iterations: usize,
) {
    let [piece0, piece1, piece2, piece3] = pieces;

    let mut feedbacks = [*iv[0], *iv[1], *iv[2], *iv[3]];

    piece0
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(piece1.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece2.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece3.chunks_exact_mut(BLOCK_SIZE))
        .map(|(((piece0, piece1), piece2), piece3)| [piece0, piece1, piece2, piece3])
        .for_each(|mut blocks| {
            blocks
                .iter_mut()
                .zip(&feedbacks)
                .for_each(|(block, feedback)| {
                    block.iter_mut().zip(feedback.iter()).for_each(
                        |(block_byte, feedback_byte)| {
                            *block_byte ^= feedback_byte;
                        },
                    );
                });

            // Current encrypted block
            feedbacks = unsafe {
                aes_benchmarks::encode_aes_ni_128_pipelined_x4(
                    &keys,
                    &[
                        blocks[0][..].try_into().unwrap(),
                        blocks[1][..].try_into().unwrap(),
                        blocks[2][..].try_into().unwrap(),
                        blocks[3][..].try_into().unwrap(),
                    ],
                    aes_iterations,
                )
            };

            blocks
                .iter_mut()
                .zip(feedbacks.iter())
                .for_each(|(block, feedback)| {
                    block.write_all(feedback).unwrap();
                });
        });
}

fn decode_internal(piece: &mut Piece, keys: &[Block; 11], iv: &Block, aes_iterations: usize) {
    let keys_reg = unsafe { aes128_load_keys!(keys) };
    let mut feedback = *iv;

    piece.chunks_exact_mut(BLOCK_SIZE * 4).for_each(|blocks| {
        let (mut block0, blocks) = blocks.split_at_mut(BLOCK_SIZE);
        let (mut block1, blocks) = blocks.split_at_mut(BLOCK_SIZE);
        let (mut block2, mut block3) = blocks.split_at_mut(BLOCK_SIZE);

        let previous_feedback = feedback;
        feedback.as_mut().write_all(block3).unwrap();

        let mut blocks_reg = unsafe { aes128_load4!(block0, block1, block2, block3) };
        let feedbacks_reg = unsafe { aes128_load4!(previous_feedback, block0, block1, block2) };

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
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes_low_level::key_expansion;
    use crate::por::test_data::CORRECT_ENCODING;
    use crate::por::test_data::ID;
    use crate::por::test_data::INPUT;
    use crate::por::test_data::IV;

    #[test]
    fn test() {
        let aes_iterations = 256;

        let keys = key_expansion::expand_keys_aes_128_enc(&ID);

        let mut encodings = [INPUT; 4];
        encode(&mut encodings, &keys, [&IV; 4], aes_iterations, 1);

        for encoding in encodings.iter() {
            assert_eq!(encoding.to_vec(), CORRECT_ENCODING.to_vec());
        }

        let keys = key_expansion::expand_keys_aes_128_dec(&ID);

        let mut decoding = CORRECT_ENCODING;
        decode(&mut decoding, &keys, &IV, aes_iterations, 1);

        assert_eq!(decoding.to_vec(), INPUT.to_vec());
    }
}
