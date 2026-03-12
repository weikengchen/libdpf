/* crypto/aes/aes.h -*- mode:C; c-file-style: "eay" -*- */
#ifndef LIBDPF_BLOCK_H
#define LIBDPF_BLOCK_H

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    /* x86/x64 platform - use SSE/AES-NI intrinsics */
    #include <wmmintrin.h>
    #include <emmintrin.h>
    #include <xmmintrin.h>

    typedef __m128i block;

    #define dpf_xor(x,y)     _mm_xor_si128(x,y)
    #define dpf_zero_block() _mm_setzero_si128()
    #define dpf_equal(x,y)   (_mm_movemask_epi8(_mm_cmpeq_epi8(x,y)) == 0xffff)
    #define dpf_unequal(x,y) (_mm_movemask_epi8(_mm_cmpeq_epi8(x,y)) != 0xffff)

    #define dpf_lsb(x) (*((char *) &x) & 1)
    #define dpf_make_block(X,Y) _mm_set_epi64((__m64)(X), (__m64)(Y))
    #define dpf_double(B) _mm_slli_epi64(B,1)

    #define dpf_left_shirt(v, n) \
    ({ \
        __m128i v1, v2; \
    \
        if ((n) >= 64) \
        { \
            v1 = _mm_slli_si128(v, 8); \
            v1 = _mm_slli_epi64(v1, (n) - 64); \
        } \
        else \
        { \
            v1 = _mm_slli_epi64(v, n); \
            v2 = _mm_slli_si128(v, 8); \
            v2 = _mm_srli_epi64(v2, 64 - (n)); \
            v1 = _mm_or_si128(v1, v2); \
        } \
        v1; \
    })

#elif defined(__aarch64__) || defined(_M_ARM64)
    /* ARM64 platform - use NEON intrinsics */
    #include <arm_neon.h>

    typedef uint8x16_t block;

    /* Basic XOR operation */
    #define dpf_xor(x,y)     veorq_u8(x,y)

    /* Zero block */
    #define dpf_zero_block() vdupq_n_u8(0)

    /* Block equality check - ARM doesn't have movemask, so we use a different approach */
    static inline int dpf_equal(block x, block y) {
        uint8x16_t cmp = vceqq_u8(x, y);
        /* Check if all bytes are equal (all 0xFF) */
        uint64x2_t cmp64 = vreinterpretq_u64_u8(cmp);
        return (vgetq_lane_u64(cmp64, 0) == UINT64_MAX) && 
               (vgetq_lane_u64(cmp64, 1) == UINT64_MAX);
    }

    static inline int dpf_unequal(block x, block y) {
        return !dpf_equal(x, y);
    }

    /* Get LSB of block */
    #define dpf_lsb(x) (vgetq_lane_u8(x, 0) & 1)

    /* Create block from two 64-bit integers */
    static inline block dpf_make_block(uint64_t hi, uint64_t lo) {
        uint64x2_t v = {lo, hi};
        return vreinterpretq_u8_u64(v);
    }

    /* Double operation (shift left by 1) */
    static inline block dpf_double(block b) {
        uint64x2_t v = vreinterpretq_u64_u8(b);
        v = vshlq_n_u64(v, 1);
        return vreinterpretq_u8_u64(v);
    }

    /* Left shift by n bits for 128-bit value */
    static inline block dpf_left_shirt(block v, int n) {
        uint64x2_t vec = vreinterpretq_u64_u8(v);
        uint64x2_t result;
        
        if (n >= 64) {
            /* Shift the lower 64 bits to upper position, then shift within upper */
            int64x2_t shift_amt = vdupq_n_s64(n - 64);
            result = vshlq_u64(vec, shift_amt);
            result = vextq_u64(vdupq_n_u64(0), result, 1);
        } else if (n > 0) {
            /* Shift both halves and combine */
            int64x2_t shift_left = vdupq_n_s64(n);
            int64x2_t shift_right = vdupq_n_s64(-(64 - n));
            uint64x2_t shifted = vshlq_u64(vec, shift_left);
            uint64x2_t carry = vshlq_u64(vec, shift_right);
            /* Move carry from lower to upper half */
            carry = vextq_u64(carry, vdupq_n_u64(0), 1);
            result = vorrq_u64(shifted, carry);
        } else {
            result = vec;
        }
        
        return vreinterpretq_u8_u64(result);
    }

#else
    #error "Unsupported platform. Only x86_64 and ARM64 are supported."
#endif

#include <stdio.h>

block
dpf_seed(block *seed);
block
dpf_random_block(void);
block *
dpf_allocate_blocks(size_t nblocks);

void
dpf_cb(block input);
void dpf_cbnotnewline(block input);

#endif