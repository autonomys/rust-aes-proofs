use crate::por::Block;
use crate::por::BLOCK_SIZE;
use std::io::Write;

pub fn por_encode_pipelined_x12_low_level(
    keys: &[Block; 11],
    blocks: &mut [&mut [u8]; 12],
    feedbacks: &[Block; 12],
    aes_iterations: usize,
) {
    let mut keys_flat = [0u8; 176];
    keys_flat
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(keys.iter())
        .for_each(|(chunk, key)| {
            chunk.as_mut().write_all(key.as_ref()).unwrap();
        });

    let mut blocks_0 = [0u8; BLOCK_SIZE * 4];
    blocks_0
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(blocks[..4].iter())
        .for_each(|(chunk, block)| {
            chunk.as_mut().write_all(block.as_ref()).unwrap();
        });
    let mut blocks_1 = [0u8; BLOCK_SIZE * 4];
    blocks_1
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(blocks[4..8].iter())
        .for_each(|(chunk, block)| {
            chunk.as_mut().write_all(block.as_ref()).unwrap();
        });
    let mut blocks_2 = [0u8; BLOCK_SIZE * 4];
    blocks_2
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(blocks[8..].iter())
        .for_each(|(chunk, block)| {
            chunk.as_mut().write_all(block.as_ref()).unwrap();
        });

    let mut feedbacks_0 = [0u8; BLOCK_SIZE * 4];
    feedbacks_0
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(feedbacks[..4].iter())
        .for_each(|(chunk, feedback)| {
            chunk.as_mut().write_all(feedback.as_ref()).unwrap();
        });
    let mut feedbacks_1 = [0u8; BLOCK_SIZE * 4];
    feedbacks_1
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(feedbacks[4..8].iter())
        .for_each(|(chunk, feedback)| {
            chunk.as_mut().write_all(feedback.as_ref()).unwrap();
        });
    let mut feedbacks_2 = [0u8; BLOCK_SIZE * 4];
    feedbacks_2
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(feedbacks[8..].iter())
        .for_each(|(chunk, feedback)| {
            chunk.as_mut().write_all(feedback.as_ref()).unwrap();
        });

    unsafe {
        c_exports::por_encode_pipelined_x12_low_level(
            blocks_0.as_mut_ptr(),
            blocks_1.as_mut_ptr(),
            blocks_2.as_mut_ptr(),
            feedbacks_0.as_ptr(),
            feedbacks_1.as_ptr(),
            feedbacks_2.as_ptr(),
            keys_flat.as_ptr(),
            aes_iterations,
        );
    }

    blocks[..4]
        .iter_mut()
        .zip(blocks_0.chunks_exact(BLOCK_SIZE))
        .for_each(|(block, chunk)| {
            block.as_mut().write_all(&chunk).unwrap();
        });
    blocks[4..8]
        .iter_mut()
        .zip(blocks_1.chunks_exact(BLOCK_SIZE))
        .for_each(|(block, chunk)| {
            block.as_mut().write_all(&chunk).unwrap();
        });
    blocks[8..]
        .iter_mut()
        .zip(blocks_2.chunks_exact(BLOCK_SIZE))
        .for_each(|(block, chunk)| {
            block.as_mut().write_all(&chunk).unwrap();
        });
}

pub fn por_decode_pipelined_x12_low_level(
    keys: &[Block; 11],
    blocks: &mut [u8],
    feedbacks: &[u8],
    aes_iterations: usize,
) {
    let mut keys_flat = [0u8; 176];
    keys_flat
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(keys.iter())
        .for_each(|(chunk, key)| {
            chunk.as_mut().write_all(key.as_ref()).unwrap();
        });

    unsafe {
        c_exports::por_decode_pipelined_x12_low_level(
            blocks.as_mut_ptr(),
            feedbacks.as_ptr(),
            keys_flat.as_ptr(),
            aes_iterations,
        );
    }
}

pub fn por_decode_pipelined_x4_low_level(
    keys: &[Block; 11],
    blocks: &mut [u8],
    feedbacks: &[u8],
    aes_iterations: usize,
) {
    let mut keys_flat = [0u8; 176];
    keys_flat
        .chunks_exact_mut(BLOCK_SIZE)
        .zip(keys.iter())
        .for_each(|(chunk, key)| {
            chunk.as_mut().write_all(key.as_ref()).unwrap();
        });

    unsafe {
        c_exports::por_decode_pipelined_x4_low_level(
            blocks.as_mut_ptr(),
            feedbacks.as_ptr(),
            keys_flat.as_ptr(),
            aes_iterations,
        );
    }
}

// pub fn pot_prove_low_level(
//     keys_reg: [__m128i; 11],
//     mut block_reg: __m128i,
//     inner_iterations: usize,
// ) -> __m128i {
//     unsafe {
//         for _ in 0..inner_iterations {
//             block_reg = _mm_xor_si128(block_reg, keys_reg[0]);
//             block_reg = _mm_aesenc_si128(block_reg, keys_reg[1]);
//             block_reg = _mm_aesenc_si128(block_reg, keys_reg[2]);
//             block_reg = _mm_aesenc_si128(block_reg, keys_reg[3]);
//             block_reg = _mm_aesenc_si128(block_reg, keys_reg[4]);
//             block_reg = _mm_aesenc_si128(block_reg, keys_reg[5]);
//             block_reg = _mm_aesenc_si128(block_reg, keys_reg[6]);
//             block_reg = _mm_aesenc_si128(block_reg, keys_reg[7]);
//             block_reg = _mm_aesenc_si128(block_reg, keys_reg[8]);
//             block_reg = _mm_aesenc_si128(block_reg, keys_reg[9]);
//
//             block_reg = _mm_aesenclast_si128(block_reg, keys_reg[10]);
//         }
//     }
//
//     block_reg
// }
//
// pub fn pot_verify_pipelined_x4_low_level(
//     keys_reg: [__m128i; 11],
//     expected_reg: [__m128i; 4],
//     mut blocks_reg: [__m128i; 4],
//     aes_iterations: usize,
// ) -> bool {
//     unsafe {
//         for _ in 0..aes_iterations {
//             aes128_xor4!(blocks_reg, keys_reg[10]);
//
//             aes128_decode4!(blocks_reg, keys_reg[9]);
//             aes128_decode4!(blocks_reg, keys_reg[8]);
//             aes128_decode4!(blocks_reg, keys_reg[7]);
//             aes128_decode4!(blocks_reg, keys_reg[6]);
//             aes128_decode4!(blocks_reg, keys_reg[5]);
//             aes128_decode4!(blocks_reg, keys_reg[4]);
//             aes128_decode4!(blocks_reg, keys_reg[3]);
//             aes128_decode4!(blocks_reg, keys_reg[2]);
//             aes128_decode4!(blocks_reg, keys_reg[1]);
//
//             aes128_decode4_last!(blocks_reg, keys_reg[0]);
//         }
//
//         compare_eq4!(expected_reg, blocks_reg)
//     }
// }

mod c_exports {
    #[link(name = "vaes")]
    extern "C" {
        pub fn por_encode_pipelined_x12_low_level(
            blocks_0: *mut u8,
            blocks_1: *mut u8,
            blocks_2: *mut u8,
            feedbacks_0: *const u8,
            feedbacks_1: *const u8,
            feedbacks_2: *const u8,
            keys: *const u8,
            aes_iterations: usize,
        );

        pub fn por_decode_pipelined_x12_low_level(
            blocks: *mut u8,
            feedbacks: *const u8,
            keys: *const u8,
            aes_iterations: usize,
        );

        pub fn por_decode_pipelined_x4_low_level(
            blocks: *mut u8,
            feedbacks: *const u8,
            keys: *const u8,
            aes_iterations: usize,
        );
    }
}
