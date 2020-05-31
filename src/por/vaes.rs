use crate::aes_low_level::software;
use crate::aes_low_level::vaes;
use crate::por::utils;
use crate::Block;
use crate::Piece;
use crate::BLOCK_SIZE;
use crate::PIECE_SIZE;
use std::io::Write;

// TODO: This should use keys expanded using AES-NI
pub struct VAes {
    keys_enc: [Block; 11],
    keys_dec: [Block; 11],
}

impl VAes {
    pub fn new(id: &Block) -> Self {
        let keys_enc = software::expand_keys_aes_128_enc(&id);
        let keys_dec = software::expand_keys_aes_128_dec(&id);
        Self { keys_enc, keys_dec }
    }

    /// Pipelined proof of replication encoding with VAES
    pub fn encode(
        &self,
        pieces: &mut [Piece; 12],
        mut ivs: [Block; 12],
        aes_iterations: usize,
        breadth_iterations: usize,
    ) {
        for _ in 0..breadth_iterations {
            ivs = encode_internal(pieces, &self.keys_enc, ivs, aes_iterations);
        }
    }

    /// Pipelined proof of replication decoding with VAES
    pub fn decode(
        &self,
        piece: &mut Piece,
        iv: &Block,
        aes_iterations: usize,
        breadth_iterations: usize,
    ) {
        for _ in 1..breadth_iterations {
            decode_internal(piece, &self.keys_dec, None, aes_iterations);
        }

        decode_internal(piece, &self.keys_dec, Some(iv), aes_iterations);
    }
}

/// Returns iv for the next round
fn encode_internal(
    pieces: &mut [Piece; 12],
    keys: &[Block; 11],
    mut ivs: [Block; 12],
    aes_iterations: usize,
) -> [Block; 12] {
    let [piece0, piece1, piece2, piece3, piece4, piece5, piece6, piece7, piece8, piece9, piece10, piece11] =
        pieces;

    piece0
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(piece1.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece2.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece3.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece4.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece5.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece6.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece7.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece8.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece9.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece10.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece11.chunks_exact_mut(BLOCK_SIZE))
        .map(
            |(
                (
                    (
                        (
                            (
                                ((((((piece0, piece1), piece2), piece3), piece4), piece5), piece6),
                                piece7,
                            ),
                            piece8,
                        ),
                        piece9,
                    ),
                    piece10,
                ),
                piece11,
            )| {
                [
                    piece0, piece1, piece2, piece3, piece4, piece5, piece6, piece7, piece8, piece9,
                    piece10, piece11,
                ]
            },
        )
        .for_each(|mut blocks| {
            vaes::por_encode_pipelined_x12_low_level(keys, &mut blocks, &ivs, aes_iterations);

            ivs.iter_mut().zip(blocks.iter()).for_each(|(iv, block)| {
                iv.as_mut().write_all(block).unwrap();
            });
        });

    ivs
}

fn decode_internal(
    piece: &mut Piece,
    keys: &[Block; 11],
    iv: Option<&Block>,
    aes_iterations: usize,
) {
    // We have `4096 / 16 / 12 = 21` iterations and 4 blocks extra
    for i in (0..(PIECE_SIZE / BLOCK_SIZE / 4)).rev() {
        let (blocks, feedback) = utils::piece_to_blocks_and_feedback(piece, i, 12);
        decode_12_blocks_internal(keys, blocks, feedback, aes_iterations);
    }

    // Remaining 4 blocks
    let (first_4_blocks, feedback) = utils::piece_to_first_blocks_and_feedback(piece, iv, 4);
    decode_4_blocks_internal(keys, first_4_blocks, feedback, aes_iterations);
}

fn decode_12_blocks_internal(
    keys: &[Block; 11],
    blocks: &mut [u8],
    feedback: &Block,
    aes_iterations: usize,
) {
    let mut feedbacks = [0u8; BLOCK_SIZE * 12];
    feedbacks.as_mut().write_all(feedback).unwrap();
    feedbacks[BLOCK_SIZE..]
        .as_mut()
        .write_all(&blocks[..(blocks.len() - BLOCK_SIZE)])
        .unwrap();

    vaes::por_decode_pipelined_x12_low_level(keys, blocks, &feedbacks, aes_iterations);
}

fn decode_4_blocks_internal(
    keys: &[Block; 11],
    blocks: &mut [u8],
    feedback: &Block,
    aes_iterations: usize,
) {
    let mut feedbacks = [0u8; BLOCK_SIZE * 4];
    feedbacks.as_mut().write_all(feedback).unwrap();
    feedbacks[BLOCK_SIZE..]
        .as_mut()
        .write_all(&blocks[..(blocks.len() - BLOCK_SIZE)])
        .unwrap();

    vaes::por_decode_pipelined_x12_low_level(keys, blocks, &feedbacks, aes_iterations);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::por::test_data::CORRECT_ENCODING;
    use crate::por::test_data::CORRECT_ENCODING_BREADTH_10;
    use crate::por::test_data::ID;
    use crate::por::test_data::INPUT;
    use crate::por::test_data::IV;
    use crate::utils;
    use crate::utils::AesImplementation;
    use crate::PIECE_SIZE;
    use rand::Rng;

    #[test]
    fn test() {
        if !utils::aes_implementations_available().contains(&AesImplementation::VAes) {
            println!("VAES support not available, skipping test");
            return;
        }
        let aes_iterations = 256;

        let por = VAes::new(&ID);

        let mut encodings = [INPUT; 12];
        por.encode(&mut encodings, [IV; 12], aes_iterations, 1);

        for encoding in encodings.iter() {
            assert_eq!(encoding.to_vec(), CORRECT_ENCODING.to_vec());
        }

        let mut decoding = CORRECT_ENCODING;
        por.decode(&mut decoding, &IV, aes_iterations, 1);

        assert_eq!(decoding.to_vec(), INPUT.to_vec());
    }

    #[test]
    fn test_breadth_10() {
        if !utils::aes_implementations_available().contains(&AesImplementation::VAes) {
            println!("VAES support not available, skipping test");
            return;
        }
        let aes_iterations = 256;

        let por = VAes::new(&ID);

        let mut encodings = [INPUT; 12];
        por.encode(&mut encodings, [IV; 12], aes_iterations, 10);

        for encoding in encodings.iter() {
            assert_eq!(encoding.to_vec(), CORRECT_ENCODING_BREADTH_10.to_vec());
        }

        let mut decoding = CORRECT_ENCODING_BREADTH_10;
        por.decode(&mut decoding, &IV, aes_iterations, 10);

        assert_eq!(decoding.to_vec(), INPUT.to_vec());
    }

    #[test]
    fn test_random() {
        if !utils::aes_implementations_available().contains(&AesImplementation::VAes) {
            println!("VAES support not available, skipping test");
            return;
        }
        let aes_iterations = 256;

        let mut id = [0u8; 16];
        rand::thread_rng().fill(&mut id[..]);

        let mut input = [0u8; PIECE_SIZE];
        rand::thread_rng().fill(&mut input[..]);

        let mut iv = [0u8; 16];
        rand::thread_rng().fill(&mut iv[..]);

        let por = VAes::new(&id);

        let mut encodings = [input; 12];
        por.encode(&mut encodings, [iv; 12], aes_iterations, 1);

        for encoding in encodings.iter() {
            let mut decoding = *encoding;
            por.decode(&mut decoding, &iv, aes_iterations, 1);

            assert_eq!(decoding.to_vec(), input.to_vec());
        }
    }

    #[test]
    fn test_random_breadth_10() {
        if !utils::aes_implementations_available().contains(&AesImplementation::VAes) {
            println!("VAES support not available, skipping test");
            return;
        }
        let aes_iterations = 256;

        let mut id = [0u8; 16];
        rand::thread_rng().fill(&mut id[..]);

        let mut input = [0u8; PIECE_SIZE];
        rand::thread_rng().fill(&mut input[..]);

        let mut iv = [0u8; 16];
        rand::thread_rng().fill(&mut iv[..]);

        let por = VAes::new(&id);

        let mut encodings = [input; 12];
        por.encode(&mut encodings, [iv; 12], aes_iterations, 10);

        for encoding in encodings.iter() {
            let mut decoding = *encoding;
            por.decode(&mut decoding, &iv, aes_iterations, 10);

            assert_eq!(decoding.to_vec(), input.to_vec());
        }
    }
}
