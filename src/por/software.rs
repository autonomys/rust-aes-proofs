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
}
