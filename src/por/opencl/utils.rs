use crate::Block;
use ocl::core::Uchar16;
use ocl::core::Uint;
use std::convert::TryInto;

pub fn inputs_to_uchar16_vec(input: &[u8]) -> Vec<Uchar16> {
    assert!(input.len() % 4 == 0);

    input
        .chunks_exact(16)
        .map(|chunk| chunk.try_into().unwrap())
        .map(|chunk: [u8; 16]| Uchar16::from(chunk))
        .collect()
}

pub fn ivs_to_uchar16_vec(ivs: &[Block]) -> Vec<Uchar16> {
    ivs.iter().map(|chunk| Uchar16::from(*chunk)).collect()
}

pub fn keys_to_uint_vec(input: &[Block; 11]) -> Vec<Uint> {
    input
        .iter()
        .flat_map(|block| {
            block
                .chunks_exact(4)
                .map(|chunk| chunk.try_into().unwrap())
                .map(u32::from_be_bytes)
        })
        .map(|u32| Uint::from(u32))
        .collect()
}
