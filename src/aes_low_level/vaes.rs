use crate::aes_low_level::aes_ni::ExpandedKeys;
use crate::Block;
use crate::BLOCK_SIZE;
use std::io::Write;

pub fn por_encode_pipelined_x12_low_level(
    keys: &ExpandedKeys,
    blocks: &mut [&mut [u8]; 12],
    feedbacks: &[Block; 12],
    aes_iterations: usize,
) {
    for block in blocks.iter() {
        assert_eq!(
            block.len(),
            BLOCK_SIZE,
            "Block length must be {} bytes",
            BLOCK_SIZE,
        );
    }

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
            keys.as_ptr(),
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
    keys: &ExpandedKeys,
    blocks: &mut [u8],
    feedbacks: &[u8],
    aes_iterations: usize,
) {
    assert_eq!(
        blocks.len(),
        BLOCK_SIZE * 12,
        "Blocks length must be exactly 12 blocks",
    );
    assert_eq!(
        feedbacks.len(),
        BLOCK_SIZE * 12,
        "Feedbacks length must be exactly 12 blocks",
    );

    unsafe {
        c_exports::por_decode_pipelined_x12_low_level(
            blocks.as_mut_ptr(),
            feedbacks.as_ptr(),
            keys.as_ptr(),
            aes_iterations,
        );
    }
}

pub fn por_decode_x4_low_level(
    keys: &ExpandedKeys,
    blocks: &mut [u8],
    feedbacks: &[u8],
    aes_iterations: usize,
) {
    assert_eq!(
        blocks.len(),
        BLOCK_SIZE * 4,
        "Blocks length must be exactly 4 blocks",
    );
    assert_eq!(
        feedbacks.len(),
        BLOCK_SIZE * 4,
        "Feedbacks length must be exactly 4 blocks",
    );

    unsafe {
        c_exports::por_decode_x4_low_level(
            blocks.as_mut_ptr(),
            feedbacks.as_ptr(),
            keys.as_ptr(),
            aes_iterations,
        );
    }
}

pub fn pot_verify_pipelined_x12_low_level(
    keys: &ExpandedKeys,
    expected_first_block: &[u8],
    blocks: &[u8],
    aes_iterations: usize,
) -> bool {
    assert!(
        blocks.len() == BLOCK_SIZE * 12,
        "Blocks length must be exactly 12 blocks",
    );
    assert!(
        expected_first_block.len() == BLOCK_SIZE,
        "Expected first block length is incorrect",
    );

    let mut expected_first_4_blocks = [0u8; BLOCK_SIZE * 4];
    expected_first_4_blocks
        .as_mut()
        .write_all(expected_first_block)
        .unwrap();
    expected_first_4_blocks[BLOCK_SIZE..]
        .as_mut()
        .write_all(&blocks[..(blocks.len() - BLOCK_SIZE)])
        .unwrap();

    unsafe {
        c_exports::pot_verify_pipelined_x12_low_level(
            blocks.as_ptr(),
            expected_first_4_blocks.as_ptr(),
            keys.as_ptr(),
            aes_iterations,
        ) == u8::max_value()
    }
}

pub fn pot_verify_pipelined_x8_low_level(
    keys: &ExpandedKeys,
    expected_first_block: &[u8],
    blocks: &[u8],
    aes_iterations: usize,
) -> bool {
    assert!(
        blocks.len() == BLOCK_SIZE * 8,
        "Blocks length must be exactly 8 blocks",
    );
    assert!(
        expected_first_block.len() == BLOCK_SIZE,
        "Expected first block length is incorrect",
    );

    let mut expected_first_4_blocks = [0u8; BLOCK_SIZE * 4];
    expected_first_4_blocks
        .as_mut()
        .write_all(expected_first_block)
        .unwrap();
    expected_first_4_blocks[BLOCK_SIZE..]
        .as_mut()
        .write_all(&blocks[..(blocks.len() - BLOCK_SIZE)])
        .unwrap();

    unsafe {
        c_exports::pot_verify_pipelined_x8_low_level(
            blocks.as_ptr(),
            expected_first_4_blocks.as_ptr(),
            keys.as_ptr(),
            aes_iterations,
        ) == u8::max_value()
    }
}

pub fn pot_verify_x4_low_level(
    keys: &ExpandedKeys,
    expected_first_block: &[u8],
    blocks: &[u8],
    aes_iterations: usize,
) -> bool {
    assert!(
        blocks.len() == BLOCK_SIZE * 4,
        "Blocks length must be exactly 4 blocks",
    );
    assert!(
        expected_first_block.len() == BLOCK_SIZE,
        "Expected first block length is incorrect",
    );

    let mut expected_blocks = [0u8; BLOCK_SIZE * 4];
    expected_blocks
        .as_mut()
        .write_all(expected_first_block)
        .unwrap();
    expected_blocks[BLOCK_SIZE..]
        .as_mut()
        .write_all(&blocks[..(blocks.len() - BLOCK_SIZE)])
        .unwrap();

    unsafe {
        c_exports::pot_verify_x4_low_level(
            blocks.as_ptr(),
            expected_blocks.as_ptr(),
            keys.as_ptr(),
            aes_iterations,
        ) == u8::max_value()
    }
}

mod c_exports {
    use core::arch::x86_64::*;

    #[link(name = "vaes")]
    extern "C" {
        // TODO: Compiler complains about `__m128i` in below functions and probably rightfully so
        pub fn por_encode_pipelined_x12_low_level(
            blocks_0: *mut u8,
            blocks_1: *mut u8,
            blocks_2: *mut u8,
            feedbacks_0: *const u8,
            feedbacks_1: *const u8,
            feedbacks_2: *const u8,
            keys: *const __m128i,
            aes_iterations: usize,
        );

        pub fn por_decode_pipelined_x12_low_level(
            blocks: *mut u8,
            feedbacks: *const u8,
            keys: *const __m128i,
            aes_iterations: usize,
        );

        pub fn por_decode_x4_low_level(
            blocks: *mut u8,
            feedbacks: *const u8,
            keys: *const __m128i,
            aes_iterations: usize,
        );

        pub fn pot_verify_pipelined_x12_low_level(
            blocks: *const u8,
            expected_first_4_blocks: *const u8,
            keys: *const __m128i,
            aes_iterations: usize,
        ) -> u8;

        pub fn pot_verify_pipelined_x8_low_level(
            blocks: *const u8,
            expected_first_4_blocks: *const u8,
            keys: *const __m128i,
            aes_iterations: usize,
        ) -> u8;

        pub fn pot_verify_x4_low_level(
            blocks: *const u8,
            expected_blocks: *const u8,
            keys: *const __m128i,
            aes_iterations: usize,
        ) -> u8;
    }
}
