use crate::por::utils;
use crate::Block;
use crate::Piece;
use crate::BLOCK_SIZE;
use crate::PIECE_SIZE;
use aes_soft::block_cipher_trait::generic_array::typenum::{U16, U8};
use aes_soft::block_cipher_trait::generic_array::GenericArray;
use aes_soft::block_cipher_trait::BlockCipher;
use aes_soft::Aes128;
use std::io::Write;
use std::mem;

pub type Block128x8 = GenericArray<GenericArray<u8, U16>, U8>;

pub struct SoftwareBitSlicingKeys {
    cipher: Aes128,
}

impl SoftwareBitSlicingKeys {
    pub fn new(id: &Block) -> Self {
        let cipher = Aes128::new(GenericArray::from_slice(id));
        Self { cipher }
    }
}

pub struct SoftwareBitSlicing;

impl SoftwareBitSlicing {
    pub fn new() -> Self {
        Self {}
    }

    /// Proof of replication encoding purely in software (using bit slicing approach)
    pub fn encode(
        &self,
        pieces: &mut [Piece; 8],
        keys: &SoftwareBitSlicingKeys,
        mut ivs: [Block; 8],
        aes_iterations: usize,
        breadth_iterations: usize,
    ) {
        for _ in 0..breadth_iterations {
            ivs = encode_internal(pieces, &keys.cipher, ivs, aes_iterations);
        }
    }

    /// Proof of replication decoding purely in software (using bit slicing approach)
    pub fn decode(
        &self,
        pieces: &mut [Piece; 8],
        keys: &SoftwareBitSlicingKeys,
        ivs: [&Block; 8],
        aes_iterations: usize,
        breadth_iterations: usize,
    ) {
        for _ in 1..breadth_iterations {
            decode_internal(pieces, &keys.cipher, None, aes_iterations);
        }

        decode_internal(pieces, &keys.cipher, Some(ivs), aes_iterations);
    }
}

fn encode_internal(
    pieces: &mut [Piece; 8],
    cipher: &Aes128,
    mut ivs: [Block; 8],
    aes_iterations: usize,
) -> [Block; 8] {
    let [piece0, piece1, piece2, piece3, piece4, piece5, piece6, piece7] = pieces;

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
                .zip(ivs.iter())
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

            ivs.iter_mut()
                .zip(blocks.iter())
                .for_each(|(feedback, block)| {
                    feedback.as_mut().write_all(block).unwrap();
                });
        });

    ivs
}

fn decode_internal(
    pieces: &mut [Piece; 8],
    cipher: &Aes128,
    ivs: Option<[&Block; 8]>,
    aes_iterations: usize,
) {
    let [piece0, piece1, piece2, piece3, piece4, piece5, piece6, piece7] = pieces;

    let mut blocks_generic_array = Block128x8::default();

    for i in (1..(PIECE_SIZE / BLOCK_SIZE)).rev() {
        let (block0, feedback0) = utils::piece_to_blocks_and_feedback(piece0, i, 1);
        let (block1, feedback1) = utils::piece_to_blocks_and_feedback(piece1, i, 1);
        let (block2, feedback2) = utils::piece_to_blocks_and_feedback(piece2, i, 1);
        let (block3, feedback3) = utils::piece_to_blocks_and_feedback(piece3, i, 1);
        let (block4, feedback4) = utils::piece_to_blocks_and_feedback(piece4, i, 1);
        let (block5, feedback5) = utils::piece_to_blocks_and_feedback(piece5, i, 1);
        let (block6, feedback6) = utils::piece_to_blocks_and_feedback(piece6, i, 1);
        let (block7, feedback7) = utils::piece_to_blocks_and_feedback(piece7, i, 1);

        decode_8_blocks_internal(
            cipher,
            [
                block0, block1, block2, block3, block4, block5, block6, block7,
            ],
            [
                feedback0, feedback1, feedback2, feedback3, feedback4, feedback5, feedback6,
                feedback7,
            ],
            aes_iterations,
            &mut blocks_generic_array,
        );
    }

    let ivs: [Option<&Block>; 8] = if let Some(ivs) = ivs {
        [
            Some(ivs[0]),
            Some(ivs[1]),
            Some(ivs[2]),
            Some(ivs[3]),
            Some(ivs[4]),
            Some(ivs[5]),
            Some(ivs[6]),
            Some(ivs[7]),
        ]
    } else {
        [None, None, None, None, None, None, None, None]
    };

    let (first_block0, feedback0) = utils::piece_to_first_blocks_and_feedback(piece0, ivs[0], 1);
    let (first_block1, feedback1) = utils::piece_to_first_blocks_and_feedback(piece1, ivs[1], 1);
    let (first_block2, feedback2) = utils::piece_to_first_blocks_and_feedback(piece2, ivs[2], 1);
    let (first_block3, feedback3) = utils::piece_to_first_blocks_and_feedback(piece3, ivs[3], 1);
    let (first_block4, feedback4) = utils::piece_to_first_blocks_and_feedback(piece4, ivs[4], 1);
    let (first_block5, feedback5) = utils::piece_to_first_blocks_and_feedback(piece5, ivs[5], 1);
    let (first_block6, feedback6) = utils::piece_to_first_blocks_and_feedback(piece6, ivs[6], 1);
    let (first_block7, feedback7) = utils::piece_to_first_blocks_and_feedback(piece7, ivs[7], 1);

    decode_8_blocks_internal(
        cipher,
        [
            first_block0,
            first_block1,
            first_block2,
            first_block3,
            first_block4,
            first_block5,
            first_block6,
            first_block7,
        ],
        [
            feedback0, feedback1, feedback2, feedback3, feedback4, feedback5, feedback6, feedback7,
        ],
        aes_iterations,
        &mut blocks_generic_array,
    );
}

fn decode_8_blocks_internal(
    cipher: &Aes128,
    mut blocks: [&mut [u8]; 8],
    feedbacks: [&Block; 8],
    aes_iterations: usize,
    blocks_generic_array: &mut GenericArray<GenericArray<u8, U16>, U8>,
) {
    swap_blocks(blocks_generic_array, &mut blocks);
    for _ in 0..aes_iterations {
        cipher.decrypt_blocks(blocks_generic_array);
    }
    swap_blocks(blocks_generic_array, &mut blocks);

    blocks
        .iter_mut()
        .zip(feedbacks.iter())
        .for_each(|(block, feedback)| {
            block
                .iter_mut()
                .zip(feedback.iter())
                .for_each(|(block_byte, feedback_byte)| {
                    *block_byte ^= feedback_byte;
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
    use crate::por::test_data::CORRECT_ENCODING_BREADTH_10;
    use crate::por::test_data::ID;
    use crate::por::test_data::INPUT;
    use crate::por::test_data::IV;
    use crate::PIECE_SIZE;
    use rand::Rng;

    #[test]
    fn test() {
        let aes_iterations = 256;

        let mut encodings = [INPUT; 8];

        let keys = SoftwareBitSlicingKeys::new(&ID);
        let por = SoftwareBitSlicing::new();

        por.encode(&mut encodings, &keys, [IV; 8], aes_iterations, 1);

        for encoding in encodings.iter() {
            assert_eq!(encoding.to_vec(), CORRECT_ENCODING.to_vec());
        }

        let mut decodings = [CORRECT_ENCODING; 8];
        por.decode(&mut decodings, &keys, [&IV; 8], aes_iterations, 1);

        for decoding in decodings.iter() {
            assert_eq!(decoding.to_vec(), INPUT.to_vec());
        }
    }

    #[test]
    fn test_breadth_10() {
        let aes_iterations = 256;

        let mut encodings = [INPUT; 8];
        let keys = SoftwareBitSlicingKeys::new(&ID);
        let por = SoftwareBitSlicing::new();

        por.encode(&mut encodings, &keys, [IV; 8], aes_iterations, 10);

        for encoding in encodings.iter() {
            assert_eq!(encoding.to_vec(), CORRECT_ENCODING_BREADTH_10.to_vec());
        }

        let mut decodings = [CORRECT_ENCODING_BREADTH_10; 8];
        por.decode(&mut decodings, &keys, [&IV; 8], aes_iterations, 10);

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

        let keys = SoftwareBitSlicingKeys::new(&id);
        let por = SoftwareBitSlicing::new();

        let mut encodings = [input; 8];
        por.encode(&mut encodings, &keys, [iv; 8], aes_iterations, 1);

        let mut decodings = encodings;
        por.decode(&mut decodings, &keys, [&iv; 8], aes_iterations, 1);

        for decoding in decodings.iter() {
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

        let keys = SoftwareBitSlicingKeys::new(&id);
        let por = SoftwareBitSlicing::new();

        let mut encodings = [input; 8];
        por.encode(&mut encodings, &keys, [iv; 8], aes_iterations, 10);

        let mut decodings = encodings;
        por.decode(&mut decodings, &keys, [&iv; 8], aes_iterations, 10);

        for decoding in decodings.iter() {
            assert_eq!(decoding.to_vec(), input.to_vec());
        }
    }
}
