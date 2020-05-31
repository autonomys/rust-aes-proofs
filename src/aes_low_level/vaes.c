#include <immintrin.h>

__attribute__((target("aes,avx512f,vaes")))
void por_encode_pipelined_x12_low_level(
  unsigned char* blocks_0,
  unsigned char* blocks_1,
  unsigned char* blocks_2,
  const unsigned char* feedbacks_0,
  const unsigned char* feedbacks_1,
  const unsigned char* feedbacks_2,
  const unsigned char* keys,
  size_t aes_iterations
) {
    __m512i blocks_0_reg = _mm512_loadu_si512((__m512i*)(&blocks_0));
    __m512i blocks_1_reg = _mm512_loadu_si512((__m512i*)(&blocks_1));
    __m512i blocks_2_reg = _mm512_loadu_si512((__m512i*)(&blocks_2));

    __m512i key_0_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 0])));
    __m512i key_1_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 1])));
    __m512i key_2_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 2])));
    __m512i key_3_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 3])));
    __m512i key_4_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 4])));
    __m512i key_5_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 5])));
    __m512i key_6_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 6])));
    __m512i key_7_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 7])));
    __m512i key_8_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 8])));
    __m512i key_9_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 9])));
    __m512i key_10_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 10])));

    {
        __m512i feedbacks_0_reg = _mm512_loadu_si512((__m512i*)(&feedbacks_0));
        __m512i feedbacks_1_reg = _mm512_loadu_si512((__m512i*)(&feedbacks_1));
        __m512i feedbacks_2_reg = _mm512_loadu_si512((__m512i*)(&feedbacks_2));

        blocks_0_reg = _mm512_xor_si512(blocks_0_reg, feedbacks_0_reg);
        blocks_1_reg = _mm512_xor_si512(blocks_1_reg, feedbacks_1_reg);
        blocks_2_reg = _mm512_xor_si512(blocks_2_reg, feedbacks_2_reg);
    }

    for (size_t i = 0; i < aes_iterations; ++i) {
        blocks_0_reg = _mm512_xor_si512(blocks_0_reg, key_0_reg);
        blocks_1_reg = _mm512_xor_si512(blocks_1_reg, key_0_reg);
        blocks_2_reg = _mm512_xor_si512(blocks_2_reg, key_0_reg);

        blocks_0_reg = _mm512_aesenc_epi128(blocks_0_reg, key_1_reg);
        blocks_1_reg = _mm512_aesenc_epi128(blocks_1_reg, key_1_reg);
        blocks_2_reg = _mm512_aesenc_epi128(blocks_2_reg, key_1_reg);

        blocks_0_reg = _mm512_aesenc_epi128(blocks_0_reg, key_2_reg);
        blocks_1_reg = _mm512_aesenc_epi128(blocks_1_reg, key_2_reg);
        blocks_2_reg = _mm512_aesenc_epi128(blocks_2_reg, key_2_reg);

        blocks_0_reg = _mm512_aesenc_epi128(blocks_0_reg, key_3_reg);
        blocks_1_reg = _mm512_aesenc_epi128(blocks_1_reg, key_3_reg);
        blocks_2_reg = _mm512_aesenc_epi128(blocks_2_reg, key_3_reg);

        blocks_0_reg = _mm512_aesenc_epi128(blocks_0_reg, key_4_reg);
        blocks_1_reg = _mm512_aesenc_epi128(blocks_1_reg, key_4_reg);
        blocks_2_reg = _mm512_aesenc_epi128(blocks_2_reg, key_4_reg);

        blocks_0_reg = _mm512_aesenc_epi128(blocks_0_reg, key_5_reg);
        blocks_1_reg = _mm512_aesenc_epi128(blocks_1_reg, key_5_reg);
        blocks_2_reg = _mm512_aesenc_epi128(blocks_2_reg, key_5_reg);

        blocks_0_reg = _mm512_aesenc_epi128(blocks_0_reg, key_6_reg);
        blocks_1_reg = _mm512_aesenc_epi128(blocks_1_reg, key_6_reg);
        blocks_2_reg = _mm512_aesenc_epi128(blocks_2_reg, key_6_reg);

        blocks_0_reg = _mm512_aesenc_epi128(blocks_0_reg, key_7_reg);
        blocks_1_reg = _mm512_aesenc_epi128(blocks_1_reg, key_7_reg);
        blocks_2_reg = _mm512_aesenc_epi128(blocks_2_reg, key_7_reg);

        blocks_0_reg = _mm512_aesenc_epi128(blocks_0_reg, key_8_reg);
        blocks_1_reg = _mm512_aesenc_epi128(blocks_1_reg, key_8_reg);
        blocks_2_reg = _mm512_aesenc_epi128(blocks_2_reg, key_8_reg);

        blocks_0_reg = _mm512_aesenc_epi128(blocks_0_reg, key_9_reg);
        blocks_1_reg = _mm512_aesenc_epi128(blocks_1_reg, key_9_reg);
        blocks_2_reg = _mm512_aesenc_epi128(blocks_2_reg, key_9_reg);

        blocks_0_reg = _mm512_aesenclast_epi128(blocks_0_reg, key_10_reg);
        blocks_1_reg = _mm512_aesenclast_epi128(blocks_1_reg, key_10_reg);
        blocks_2_reg = _mm512_aesenclast_epi128(blocks_2_reg, key_10_reg);
    }

    _mm512_storeu_si512(((__m512i*)blocks_0), blocks_0_reg);
    _mm512_storeu_si512(((__m512i*)blocks_1), blocks_1_reg);
    _mm512_storeu_si512(((__m512i*)blocks_2), blocks_2_reg);
}

__attribute__((target("aes,avx512f,vaes")))
void por_decode_pipelined_x12_low_level(
  unsigned char* blocks,
  const unsigned char* feedbacks,
  const unsigned char* keys,
  size_t aes_iterations
) {
    __m512i blocks_0_reg = _mm512_loadu_si512((__m512i*)(&blocks[16 * 4 * 0]));
    __m512i blocks_1_reg = _mm512_loadu_si512((__m512i*)(&blocks[16 * 4 * 1]));
    __m512i blocks_2_reg = _mm512_loadu_si512((__m512i*)(&blocks[16 * 4 * 2]));

    __m512i key_0_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 0])));
    __m512i key_1_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 1])));
    __m512i key_2_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 2])));
    __m512i key_3_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 3])));
    __m512i key_4_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 4])));
    __m512i key_5_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 5])));
    __m512i key_6_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 6])));
    __m512i key_7_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 7])));
    __m512i key_8_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 8])));
    __m512i key_9_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 9])));
    __m512i key_10_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 10])));

    for (size_t i = 0; i < aes_iterations; ++i) {
        blocks_0_reg = _mm512_xor_si512(blocks_0_reg, key_10_reg);
        blocks_1_reg = _mm512_xor_si512(blocks_1_reg, key_10_reg);
        blocks_2_reg = _mm512_xor_si512(blocks_2_reg, key_10_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_9_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_9_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_9_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_8_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_8_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_8_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_7_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_7_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_7_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_6_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_6_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_6_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_5_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_5_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_5_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_4_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_4_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_4_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_3_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_3_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_3_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_2_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_2_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_2_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_1_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_1_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_1_reg);

        blocks_0_reg = _mm512_aesdeclast_epi128(blocks_0_reg, key_0_reg);
        blocks_1_reg = _mm512_aesdeclast_epi128(blocks_1_reg, key_0_reg);
        blocks_2_reg = _mm512_aesdeclast_epi128(blocks_2_reg, key_0_reg);
    }

    {
        __m512i feedbacks_0_reg = _mm512_loadu_si512((__m512i*)(&feedbacks[16 * 4 * 0]));
        __m512i feedbacks_1_reg = _mm512_loadu_si512((__m512i*)(&feedbacks[16 * 4 * 1]));
        __m512i feedbacks_2_reg = _mm512_loadu_si512((__m512i*)(&feedbacks[16 * 4 * 2]));

        blocks_0_reg = _mm512_xor_si512(blocks_0_reg, feedbacks_0_reg);
        blocks_1_reg = _mm512_xor_si512(blocks_1_reg, feedbacks_1_reg);
        blocks_2_reg = _mm512_xor_si512(blocks_2_reg, feedbacks_2_reg);
    }

    _mm512_storeu_si512(((__m512i*)&blocks[16 * 4 * 0]), blocks_0_reg);
    _mm512_storeu_si512(((__m512i*)&blocks[16 * 4 * 1]), blocks_1_reg);
    _mm512_storeu_si512(((__m512i*)&blocks[16 * 4 * 2]), blocks_2_reg);
}

__attribute__((target("aes,avx512f,vaes")))
void por_decode_x4_low_level(
  unsigned char* blocks,
  const unsigned char* feedbacks,
  const unsigned char* keys,
  size_t aes_iterations
) {
    __m512i blocks_reg = _mm512_loadu_si512((__m512i*)blocks);

    __m512i key_0_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 0])));
    __m512i key_1_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 1])));
    __m512i key_2_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 2])));
    __m512i key_3_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 3])));
    __m512i key_4_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 4])));
    __m512i key_5_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 5])));
    __m512i key_6_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 6])));
    __m512i key_7_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 7])));
    __m512i key_8_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 8])));
    __m512i key_9_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 9])));
    __m512i key_10_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 10])));

    for (size_t i = 0; i < aes_iterations; ++i) {
        blocks_reg = _mm512_xor_si512(blocks_reg, key_10_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_9_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_8_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_7_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_6_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_5_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_4_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_3_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_2_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_1_reg);
        blocks_reg = _mm512_aesdeclast_epi128(blocks_reg, key_0_reg);
    }

    {
        __m512i feedbacks_reg = _mm512_loadu_si512((__m512i*)(&feedbacks));
        blocks_reg = _mm512_xor_si512(blocks_reg, feedbacks_reg);
    }

    _mm512_storeu_si512(((__m512i*)blocks), blocks_reg);
}

__attribute__((target("aes,avx512f,vaes")))
char pot_verify_pipelined_x12_low_level(
  unsigned char* blocks,
  const unsigned char* expected_first_4_blocks,
  const unsigned char* keys,
  size_t aes_iterations
) {
    __m512i expected_blocks_0_reg = _mm512_loadu_si512((__m512i*)expected_first_4_blocks);
    __m512i expected_blocks_1_reg = _mm512_loadu_si512((__m512i*)(&blocks[16 * 4 * 0]));
    __m512i expected_blocks_2_reg = _mm512_loadu_si512((__m512i*)(&blocks[16 * 4 * 1]));

    __m512i blocks_0_reg = _mm512_loadu_si512((__m512i*)(&blocks[16 * 4 * 0]));
    __m512i blocks_1_reg = _mm512_loadu_si512((__m512i*)(&blocks[16 * 4 * 1]));
    __m512i blocks_2_reg = _mm512_loadu_si512((__m512i*)(&blocks[16 * 4 * 2]));

    __m512i key_0_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 0])));
    __m512i key_1_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 1])));
    __m512i key_2_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 2])));
    __m512i key_3_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 3])));
    __m512i key_4_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 4])));
    __m512i key_5_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 5])));
    __m512i key_6_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 6])));
    __m512i key_7_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 7])));
    __m512i key_8_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 8])));
    __m512i key_9_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 9])));
    __m512i key_10_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 10])));

    for (size_t i = 0; i < aes_iterations; ++i) {
        blocks_0_reg = _mm512_xor_si512(blocks_0_reg, key_10_reg);
        blocks_1_reg = _mm512_xor_si512(blocks_1_reg, key_10_reg);
        blocks_2_reg = _mm512_xor_si512(blocks_2_reg, key_10_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_9_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_9_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_9_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_8_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_8_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_8_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_7_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_7_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_7_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_6_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_6_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_6_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_5_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_5_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_5_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_4_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_4_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_4_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_3_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_3_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_3_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_2_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_2_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_2_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_1_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_1_reg);
        blocks_2_reg = _mm512_aesdec_epi128(blocks_2_reg, key_1_reg);

        blocks_0_reg = _mm512_aesdeclast_epi128(blocks_0_reg, key_0_reg);
        blocks_1_reg = _mm512_aesdeclast_epi128(blocks_1_reg, key_0_reg);
        blocks_2_reg = _mm512_aesdeclast_epi128(blocks_2_reg, key_0_reg);
    }

    __mmask8 res0 = _mm512_cmpeq_epi64_mask(expected_blocks_0_reg, blocks_0_reg);
    __mmask8 res1 = _mm512_cmpeq_epi64_mask(expected_blocks_1_reg, blocks_1_reg);
    __mmask8 res2 = _mm512_cmpeq_epi64_mask(expected_blocks_2_reg, blocks_2_reg);

    if (res0 == 255 && res1 == 255 && res2 == 255) {
        return 255;
    } else {
        return 0;
    }
}

__attribute__((target("aes,avx512f,vaes")))
char pot_verify_pipelined_x8_low_level(
  unsigned char* blocks,
  const unsigned char* expected_first_4_blocks,
  const unsigned char* keys,
  size_t aes_iterations
) {
    __m512i expected_blocks_0_reg = _mm512_loadu_si512((__m512i*)expected_first_4_blocks);
    __m512i expected_blocks_1_reg = _mm512_loadu_si512((__m512i*)(&blocks[16 * 4 * 0]));

    __m512i blocks_0_reg = _mm512_loadu_si512((__m512i*)(&blocks[16 * 4 * 0]));
    __m512i blocks_1_reg = _mm512_loadu_si512((__m512i*)(&blocks[16 * 4 * 1]));

    __m512i key_0_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 0])));
    __m512i key_1_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 1])));
    __m512i key_2_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 2])));
    __m512i key_3_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 3])));
    __m512i key_4_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 4])));
    __m512i key_5_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 5])));
    __m512i key_6_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 6])));
    __m512i key_7_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 7])));
    __m512i key_8_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 8])));
    __m512i key_9_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 9])));
    __m512i key_10_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 10])));

    for (size_t i = 0; i < aes_iterations; ++i) {
        blocks_0_reg = _mm512_xor_si512(blocks_0_reg, key_10_reg);
        blocks_1_reg = _mm512_xor_si512(blocks_1_reg, key_10_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_9_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_9_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_8_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_8_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_7_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_7_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_6_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_6_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_5_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_5_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_4_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_4_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_3_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_3_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_2_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_2_reg);

        blocks_0_reg = _mm512_aesdec_epi128(blocks_0_reg, key_1_reg);
        blocks_1_reg = _mm512_aesdec_epi128(blocks_1_reg, key_1_reg);

        blocks_0_reg = _mm512_aesdeclast_epi128(blocks_0_reg, key_0_reg);
        blocks_1_reg = _mm512_aesdeclast_epi128(blocks_1_reg, key_0_reg);
    }

    __mmask8 res0 = _mm512_cmpeq_epi64_mask(expected_blocks_0_reg, blocks_0_reg);
    __mmask8 res1 = _mm512_cmpeq_epi64_mask(expected_blocks_1_reg, blocks_1_reg);

    if (res0 == 255 && res1 == 255) {
        return 255;
    } else {
        return 0;
    }
}

__attribute__((target("aes,avx512f,vaes")))
char pot_verify_x4_low_level(
  unsigned char* blocks,
  const unsigned char* expected_blocks,
  const unsigned char* keys,
  size_t aes_iterations
) {
    __m512i expected_blocks_reg = _mm512_loadu_si512((__m512i*)expected_blocks);

    __m512i blocks_reg = _mm512_loadu_si512((__m512i*)(&blocks[16 * 4 * 0]));

    __m512i key_0_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 0])));
    __m512i key_1_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 1])));
    __m512i key_2_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 2])));
    __m512i key_3_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 3])));
    __m512i key_4_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 4])));
    __m512i key_5_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 5])));
    __m512i key_6_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 6])));
    __m512i key_7_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 7])));
    __m512i key_8_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 8])));
    __m512i key_9_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 9])));
    __m512i key_10_reg = _mm512_broadcast_i32x4(_mm_loadu_si128((__m128i*)(&keys[16 * 10])));

    for (size_t i = 0; i < aes_iterations; ++i) {
        blocks_reg = _mm512_xor_si512(blocks_reg, key_10_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_9_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_8_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_7_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_6_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_5_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_4_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_3_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_2_reg);
        blocks_reg = _mm512_aesdec_epi128(blocks_reg, key_1_reg);
        blocks_reg = _mm512_aesdeclast_epi128(blocks_reg, key_0_reg);
    }

    return _mm512_cmpeq_epi64_mask(expected_blocks_reg, blocks_reg);
}
