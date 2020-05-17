use crate::por::{Block, Piece, BLOCK_SIZE};
use aes_soft::block_cipher_trait::generic_array::typenum::{U16, U8};
use aes_soft::block_cipher_trait::generic_array::GenericArray;
use aes_soft::block_cipher_trait::BlockCipher;
use aes_soft::Aes128;
use std::io::Write;
use std::mem;

pub type Block128x8 = GenericArray<GenericArray<u8, U16>, U8>;

/// Proof of replication encoding purely in software (using bit slicing approach)
pub fn encode(
    pieces: &mut [Piece; 8],
    key: &Block,
    ivs: [&Block; 8],
    aes_iterations: usize,
    breadth_iterations: usize,
) {
    // TODO: This should probably be made external, otherwise using the same key for frequent calls
    //  will have severe performance hit
    let cipher = Aes128::new(GenericArray::from_slice(key));
    for _ in 0..breadth_iterations {
        encode_internal(pieces, &cipher, ivs, aes_iterations);
    }
}

/// Proof of replication decoding purely in software (using bit slicing approach)
pub fn decode(
    pieces: &mut [Piece; 8],
    key: &Block,
    ivs: [&Block; 8],
    aes_iterations: usize,
    breadth_iterations: usize,
) {
    // TODO: This should probably be made external, otherwise using the same key for frequent calls
    //  will have severe performance hit
    let cipher = Aes128::new(GenericArray::from_slice(key));
    for _ in 0..breadth_iterations {
        decode_internal(pieces, &cipher, ivs, aes_iterations);
    }
}

fn encode_internal(
    pieces: &mut [Piece; 8],
    cipher: &Aes128,
    ivs: [&Block; 8],
    aes_iterations: usize,
) {
    let [piece0, piece1, piece2, piece3, piece4, piece5, piece6, piece7] = pieces;
    let mut feedbacks = [
        *ivs[0], *ivs[1], *ivs[2], *ivs[3], *ivs[4], *ivs[5], *ivs[6], *ivs[7],
    ];

    let mut blocks_generic_array = Block128x8::default();

    piece0
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(piece1.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece2.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece3.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece4.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece5.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece6.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece7.chunks_exact_mut(BLOCK_SIZE))
        .map(
            |(((((((piece0, piece1), piece2), piece3), piece4), piece5), piece6), piece7)| {
                [
                    piece0, piece1, piece2, piece3, piece4, piece5, piece6, piece7,
                ]
            },
        )
        .for_each(|mut blocks| {
            blocks
                .iter_mut()
                .zip(feedbacks.iter())
                .for_each(|(block, feedback)| {
                    block.iter_mut().zip(feedback.iter()).for_each(
                        |(block_byte, feedback_byte)| {
                            *block_byte ^= feedback_byte;
                        },
                    );
                });

            swap_blocks(&mut blocks_generic_array, &mut blocks);
            for _ in 0..aes_iterations {
                cipher.encrypt_blocks(&mut blocks_generic_array);
            }
            swap_blocks(&mut blocks_generic_array, &mut blocks);

            feedbacks
                .iter_mut()
                .zip(blocks.iter())
                .for_each(|(feedback, block)| {
                    feedback.as_mut().write_all(block).unwrap();
                });
        });
}

fn decode_internal(
    pieces: &mut [Piece; 8],
    cipher: &Aes128,
    ivs: [&Block; 8],
    aes_iterations: usize,
) {
    let [piece0, piece1, piece2, piece3, piece4, piece5, piece6, piece7] = pieces;
    let mut feedbacks = [
        *ivs[0], *ivs[1], *ivs[2], *ivs[3], *ivs[4], *ivs[5], *ivs[6], *ivs[7],
    ];

    let mut blocks_generic_array = Block128x8::default();

    piece0
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(piece1.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece2.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece3.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece4.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece5.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece6.chunks_exact_mut(BLOCK_SIZE))
        .zip(piece7.chunks_exact_mut(BLOCK_SIZE))
        .map(
            |(((((((piece0, piece1), piece2), piece3), piece4), piece5), piece6), piece7)| {
                [
                    piece0, piece1, piece2, piece3, piece4, piece5, piece6, piece7,
                ]
            },
        )
        .for_each(|mut blocks| {
            let previous_feedbacks = feedbacks;
            feedbacks
                .iter_mut()
                .zip(blocks.iter())
                .for_each(|(feedback, block)| {
                    feedback.as_mut().write_all(block).unwrap();
                });

            swap_blocks(&mut blocks_generic_array, &mut blocks);
            for _ in 0..aes_iterations {
                cipher.decrypt_blocks(&mut blocks_generic_array);
            }
            swap_blocks(&mut blocks_generic_array, &mut blocks);

            blocks
                .iter_mut()
                .zip(previous_feedbacks.iter())
                .for_each(|(block, feedback)| {
                    block.iter_mut().zip(feedback.iter()).for_each(
                        |(block_byte, feedback_byte)| {
                            *block_byte ^= feedback_byte;
                        },
                    );
                });
        });
}

fn swap_blocks(generic_blocks: &mut Block128x8, slice_blocks: &mut [&mut [u8]; 8]) {
    generic_blocks
        .iter_mut()
        .zip(slice_blocks.iter_mut())
        .for_each(|(x, y)| {
            let y = GenericArray::from_mut_slice(y);
            mem::swap(x, y);
        });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::por::test_data::CORRECT_ENCODING;
    use crate::por::test_data::ID;
    use crate::por::test_data::INPUT;
    use crate::por::test_data::IV;
    use crate::por::PIECE_SIZE;
    use rand::Rng;

    #[test]
    fn test() {
        let aes_iterations = 256;

        let mut encodings = [INPUT; 8];
        encode(&mut encodings, &ID, [&IV; 8], aes_iterations, 1);

        for encoding in encodings.iter() {
            assert_eq!(encoding.to_vec(), CORRECT_ENCODING.to_vec());
        }

        let mut decodings = [CORRECT_ENCODING; 8];
        decode(&mut decodings, &ID, [&IV; 8], aes_iterations, 1);

        for decoding in decodings.iter() {
            assert_eq!(decoding.to_vec(), INPUT.to_vec());
        }
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

        let mut encodings = [input; 8];
        encode(&mut encodings, &id, [&iv; 8], aes_iterations, 1);

        let mut decodings = encodings;
        decode(&mut decodings, &id, [&iv; 8], aes_iterations, 1);

        for decoding in decodings.iter() {
            assert_eq!(decoding.to_vec(), input.to_vec());
        }
    }
}
