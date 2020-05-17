use crate::por::{Block, Piece, BLOCK_SIZE};
use aes_soft::block_cipher_trait::generic_array::GenericArray;
use aes_soft::block_cipher_trait::BlockCipher;
use aes_soft::Aes128;
use std::io::Write;

/// Proof of replication encoding purely in software
pub fn encode(
    piece: &mut Piece,
    key: &Block,
    iv: &Block,
    aes_iterations: usize,
    breadth_iterations: usize,
) {
    // TODO: This should probably be made external, otherwise using the same key for frequent calls
    //  will have severe performance hit
    let cipher = Aes128::new(GenericArray::from_slice(key));
    for _ in 0..breadth_iterations {
        encode_internal(piece, &cipher, iv, aes_iterations);
    }
}

/// Pipelined proof of replication decoding with AES-NI
pub fn decode(
    piece: &mut Piece,
    key: &Block,
    iv: &Block,
    aes_iterations: usize,
    breadth_iterations: usize,
) {
    // TODO: This should probably be made external, otherwise using the same key for frequent calls
    //  will have severe performance hit
    let cipher = Aes128::new(GenericArray::from_slice(key));
    for _ in 0..breadth_iterations {
        decode_internal(piece, &cipher, iv, aes_iterations);
    }
}

fn encode_internal(piece: &mut Piece, cipher: &Aes128, iv: &Block, aes_iterations: usize) {
    let mut feedback = *iv;

    piece
        .chunks_exact_mut(BLOCK_SIZE)
        .map(GenericArray::from_mut_slice)
        .for_each(|block| {
            block
                .iter_mut()
                .zip(&feedback)
                .for_each(|(block_byte, feedback_byte)| {
                    *block_byte ^= feedback_byte;
                });

            for _ in 0..aes_iterations {
                cipher.encrypt_block(block);
            }

            feedback.as_mut().write_all(block).unwrap();
        });
}

fn decode_internal(piece: &mut Piece, cipher: &Aes128, iv: &Block, aes_iterations: usize) {
    let mut feedback = *iv;

    piece
        .chunks_exact_mut(BLOCK_SIZE)
        .map(GenericArray::from_mut_slice)
        .for_each(|block| {
            let previous_feedback = feedback;
            feedback.as_mut().write_all(block).unwrap();

            for _ in 0..aes_iterations {
                cipher.decrypt_block(block);
            }

            block
                .iter_mut()
                .zip(&previous_feedback)
                .for_each(|(block_byte, feedback_byte)| {
                    *block_byte ^= feedback_byte;
                });
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

        let mut encoding = INPUT;
        encode(&mut encoding, &ID, &IV, aes_iterations, 1);

        assert_eq!(encoding.to_vec(), CORRECT_ENCODING.to_vec());

        let mut decoding = CORRECT_ENCODING;
        decode(&mut decoding, &ID, &IV, aes_iterations, 1);

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
        encode(&mut encoding, &id, &iv, aes_iterations, 1);

        let mut decoding = encoding;
        decode(&mut decoding, &id, &iv, aes_iterations, 1);

        assert_eq!(decoding.to_vec(), input.to_vec());
    }
}
