use core::arch::x86_64::*;

#[macro_export]
macro_rules! aes128_store4 {
    ($to:expr, $from:expr) => {
        _mm_storeu_si128($to[0].as_mut_ptr() as *mut __m128i, $from[0]);
        _mm_storeu_si128($to[1].as_mut_ptr() as *mut __m128i, $from[1]);
        _mm_storeu_si128($to[2].as_mut_ptr() as *mut __m128i, $from[2]);
        _mm_storeu_si128($to[3].as_mut_ptr() as *mut __m128i, $from[3]);
    };
}

#[macro_export]
macro_rules! aes128_xor4 {
    ($what:expr, $with:expr) => {
        $what[0] = _mm_xor_si128($what[0], $with);
        $what[1] = _mm_xor_si128($what[1], $with);
        $what[2] = _mm_xor_si128($what[2], $with);
        $what[3] = _mm_xor_si128($what[3], $with);
    };
}

#[macro_export]
macro_rules! aes128_xor4x4 {
    ($what:expr, $with:expr) => {
        $what[0] = _mm_xor_si128($what[0], $with[0]);
        $what[1] = _mm_xor_si128($what[1], $with[1]);
        $what[2] = _mm_xor_si128($what[2], $with[2]);
        $what[3] = _mm_xor_si128($what[3], $with[3]);
    };
}

#[macro_export]
macro_rules! aes128_decode4 {
    ($target:expr, $key:expr) => {
        $target[0] = _mm_aesdec_si128($target[0], $key);
        $target[1] = _mm_aesdec_si128($target[1], $key);
        $target[2] = _mm_aesdec_si128($target[2], $key);
        $target[3] = _mm_aesdec_si128($target[3], $key);
    };
}

#[macro_export]
macro_rules! aes128_decode4_last {
    ($target:expr, $key:expr) => {
        $target[0] = _mm_aesdeclast_si128($target[0], $key);
        $target[1] = _mm_aesdeclast_si128($target[1], $key);
        $target[2] = _mm_aesdeclast_si128($target[2], $key);
        $target[3] = _mm_aesdeclast_si128($target[3], $key);
    };
}

#[macro_export]
macro_rules! aes128_load4 {
    ($var0:expr, $var1:expr, $var2:expr, $var3:expr) => {{
        use core::arch::x86_64::*;
        [
            _mm_loadu_si128($var0.as_ptr() as *const __m128i),
            _mm_loadu_si128($var1.as_ptr() as *const __m128i),
            _mm_loadu_si128($var2.as_ptr() as *const __m128i),
            _mm_loadu_si128($var3.as_ptr() as *const __m128i),
        ]
    }};
    ($var:expr) => {
        aes128_load4!($var[0], $var[1], $var[2], $var[3])
    };
}

#[macro_export]
macro_rules! aes128_load_keys {
    ($var:expr) => {{
        use core::arch::x86_64::*;
        [
            _mm_loadu_si128($var[0].as_ptr() as *const __m128i),
            _mm_loadu_si128($var[1].as_ptr() as *const __m128i),
            _mm_loadu_si128($var[2].as_ptr() as *const __m128i),
            _mm_loadu_si128($var[3].as_ptr() as *const __m128i),
            _mm_loadu_si128($var[4].as_ptr() as *const __m128i),
            _mm_loadu_si128($var[5].as_ptr() as *const __m128i),
            _mm_loadu_si128($var[6].as_ptr() as *const __m128i),
            _mm_loadu_si128($var[7].as_ptr() as *const __m128i),
            _mm_loadu_si128($var[8].as_ptr() as *const __m128i),
            _mm_loadu_si128($var[9].as_ptr() as *const __m128i),
            _mm_loadu_si128($var[10].as_ptr() as *const __m128i),
        ]
    }};
}

#[macro_export]
macro_rules! compare_eq4 {
    ($what:expr, $with:expr) => {{
        let mut value = [0u128];
        _mm_storeu_si128(
            value.as_mut_ptr() as *mut __m128i,
            _mm_and_si128(
                _mm_and_si128(
                    _mm_cmpeq_epi64($what[0], $with[0]),
                    _mm_cmpeq_epi64($what[1], $with[1]),
                ),
                _mm_and_si128(
                    _mm_cmpeq_epi64($what[2], $with[2]),
                    _mm_cmpeq_epi64($what[3], $with[3]),
                ),
            ),
        );
        value == [u128::max_value()]
    }};
}

// pub fn decode_aes_ni_128_pipelined_x4(
//     keys: &[[u8; 16]; 11],
//     blocks: [&mut [u8; 16]; 4],
//     feedbacks: &[[u8; 16]; 4],
//     rounds: usize,
// ) {
//     unsafe {
//         let mut blocks_reg = aes128_load4!(blocks);
//         let feedbacks_reg = aes128_load4!(feedbacks);
//
//         let keys_reg = aes128_load_keys!(keys);
//
//         for _ in 0..rounds {
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
//         aes128_xor4x4!(blocks_reg, feedbacks_reg);
//
//         aes128_store4!(blocks, blocks_reg);
//     }
// }
//
// pub fn por_decode_pipelined_x4_low_level(
//     keys_reg: [__m128i; 11],
//     blocks_reg: &mut [__m128i; 4],
//     feedbacks_reg: [__m128i; 4],
//     aes_iterations: usize,
// ) {
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
//         aes128_xor4x4!(blocks_reg, feedbacks_reg);
//     }
// }

pub fn pot_verify_pipelined_x4(
    keys_reg: [__m128i; 11],
    expected_reg: [__m128i; 4],
    mut blocks_reg: [__m128i; 4],
    aes_iterations: usize,
) -> bool {
    unsafe {
        for _ in 0..aes_iterations {
            aes128_xor4!(blocks_reg, keys_reg[10]);

            aes128_decode4!(blocks_reg, keys_reg[9]);
            aes128_decode4!(blocks_reg, keys_reg[8]);
            aes128_decode4!(blocks_reg, keys_reg[7]);
            aes128_decode4!(blocks_reg, keys_reg[6]);
            aes128_decode4!(blocks_reg, keys_reg[5]);
            aes128_decode4!(blocks_reg, keys_reg[4]);
            aes128_decode4!(blocks_reg, keys_reg[3]);
            aes128_decode4!(blocks_reg, keys_reg[2]);
            aes128_decode4!(blocks_reg, keys_reg[1]);

            aes128_decode4_last!(blocks_reg, keys_reg[0]);
        }

        compare_eq4!(expected_reg, blocks_reg)
    }
}
