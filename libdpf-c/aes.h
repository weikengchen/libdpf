/* crypto/aes/aes.h -*- mode:C; c-file-style: "eay" -*- */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */


#ifndef LIBDPF_AES_H
#define LIBDPF_AES_H

#include "block.h"
#include <string.h>
    
typedef struct { block rd_key[11]; unsigned int rounds; } AES_KEY;

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
/* ============================================
 * x86/x64 platform - Use AES-NI instructions
 * ============================================ */

#define EXPAND_ASSIST(v1,v2,v3,v4,shuff_const,aes_const)                    \
    v2 = _mm_aeskeygenassist_si128(v4,aes_const);                           \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 16));        \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
                                         _mm_castsi128_ps(v1), 140));       \
    v1 = _mm_xor_si128(v1,v3);                                              \
    v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
    v1 = _mm_xor_si128(v1,v2)

static inline void
AES_set_encrypt_key(const block userkey, AES_KEY *restrict key)
{
    block x0, x1, x2;
    block *kp = key->rd_key;
    kp[0] = x0 = userkey;
    x2 = _mm_setzero_si128();
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 1);
    kp[1] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 2);
    kp[2] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 4);
    kp[3] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 8);
    kp[4] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 16);
    kp[5] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 32);
    kp[6] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 64);
    kp[7] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 128);
    kp[8] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 27);
    kp[9] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 54);
    kp[10] = x0;
    key->rounds = 10;
}

static inline void
AES_ecb_encrypt_blks(block *restrict blks, unsigned int nblks, const AES_KEY *restrict key)
{
    for (unsigned int i = 0; i < nblks; ++i)
        blks[i] = _mm_xor_si128(blks[i], key->rd_key[0]);
    for (unsigned int j = 1; j < key->rounds; ++j)
        for (unsigned int i = 0; i < nblks; ++i)
            blks[i] = _mm_aesenc_si128(blks[i], key->rd_key[j]);
    for (unsigned int i = 0; i < nblks; ++i)
        blks[i] = _mm_aesenclast_si128(blks[i], key->rd_key[key->rounds]);
}

static inline void
AES_set_decrypt_key_fast(AES_KEY *restrict dkey, const AES_KEY *restrict ekey)
{
    int j = 0;
    int i = ekey->rounds;
#if (OCB_KEY_LEN == 0)
    dkey->rounds = i;
#endif
    dkey->rd_key[i--] = ekey->rd_key[j++];
    while (i)
        dkey->rd_key[i--] = _mm_aesimc_si128(ekey->rd_key[j++]);
    dkey->rd_key[i] = ekey->rd_key[j];
}

static inline void
AES_set_decrypt_key(block userkey, AES_KEY *restrict key)
{
    AES_KEY temp_key;
    AES_set_encrypt_key(userkey, &temp_key);
    AES_set_decrypt_key_fast(key, &temp_key);
}

static inline void
AES_ecb_decrypt_blks(block *restrict blks, unsigned nblks, const AES_KEY *restrict key)
{
    unsigned i, j, rnds = key->rounds;
    for (i = 0; i < nblks; ++i)
        blks[i] = _mm_xor_si128(blks[i], key->rd_key[0]);
    for (j = 1; j < rnds; ++j)
        for (i = 0; i < nblks; ++i)
            blks[i] = _mm_aesdec_si128(blks[i], key->rd_key[j]);
    for (i = 0; i < nblks; ++i)
        blks[i] = _mm_aesdeclast_si128(blks[i], key->rd_key[j]);
}

#elif defined(__aarch64__) || defined(_M_ARM64)
/* ============================================
 * ARM64 platform - Use ARM NEON AES intrinsics
 * ============================================ */

/* ARM uses the ARMv8-A Cryptographic Extension for AES.
 * On Apple Silicon (M1, M2, M3, etc.), these instructions are fully supported.
 * 
 * Key expansion on ARM doesn't have a direct equivalent to _mm_aeskeygenassist_si128,
 * so we implement it using the standard AES key expansion algorithm with NEON.
 */

/* AES S-box for key expansion */
static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

/* Rcon values for key expansion */
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

/* SubWord: Apply S-box to each byte of a 4-byte word */
static inline uint32_t sub_word(uint32_t w) {
    return ((uint32_t)aes_sbox[(w >> 24) & 0xff] << 24) |
           ((uint32_t)aes_sbox[(w >> 16) & 0xff] << 16) |
           ((uint32_t)aes_sbox[(w >> 8) & 0xff] << 8) |
           ((uint32_t)aes_sbox[w & 0xff]);
}

/* RotWord: Rotate a 4-byte word left by 8 bits */
static inline uint32_t rot_word(uint32_t w) {
    return (w << 8) | (w >> 24);
}

static inline void
AES_set_encrypt_key(const block userkey, AES_KEY *restrict key)
{
    /* Extract the 4 32-bit words from the 128-bit key */
    uint32_t w[44];  /* Expanded key schedule for AES-128 */
    uint8_t key_bytes[16];
    
    /* Store block to byte array */
    vst1q_u8(key_bytes, userkey);
    
    /* Copy initial key words */
    for (int i = 0; i < 4; i++) {
        w[i] = ((uint32_t)key_bytes[4*i] << 24) |
               ((uint32_t)key_bytes[4*i+1] << 16) |
               ((uint32_t)key_bytes[4*i+2] << 8) |
               ((uint32_t)key_bytes[4*i+3]);
    }
    
    /* Expand key for AES-128 (10 rounds, so we need 44 words) */
    for (int i = 4; i < 44; i++) {
        uint32_t temp = w[i-1];
        if (i % 4 == 0) {
            temp = sub_word(rot_word(temp)) ^ ((uint32_t)rcon[i/4] << 24);
        }
        w[i] = w[i-4] ^ temp;
    }
    
    /* Pack words into blocks */
    for (int i = 0; i < 11; i++) {
        uint8_t rd_key_bytes[16];
        for (int j = 0; j < 4; j++) {
            rd_key_bytes[4*j] = (w[4*i+j] >> 24) & 0xff;
            rd_key_bytes[4*j+1] = (w[4*i+j] >> 16) & 0xff;
            rd_key_bytes[4*j+2] = (w[4*i+j] >> 8) & 0xff;
            rd_key_bytes[4*j+3] = w[4*i+j] & 0xff;
        }
        key->rd_key[i] = vld1q_u8(rd_key_bytes);
    }
    
    key->rounds = 10;
}

static inline void
AES_ecb_encrypt_blks(block *restrict blks, unsigned int nblks, const AES_KEY *restrict key)
{
    /* 
     * ARM AES encryption uses:
     * - vaeseq_u8: Performs the AES single round encryption (SubBytes, ShiftRows, MixColumns)
     * - vaesmcq_u8: Performs the AES MixColumns operation separately
     * - For the last round, we skip MixColumns
     */
    for (unsigned int i = 0; i < nblks; ++i) {
        /* XOR with round 0 key (AddRoundKey) */
        blks[i] = veorq_u8(blks[i], key->rd_key[0]);
        
        /* Rounds 1-9: SubBytes, ShiftRows, MixColumns, AddRoundKey */
        for (unsigned int j = 1; j < key->rounds; ++j) {
            blks[i] = vaeseq_u8(blks[i], vdupq_n_u8(0));  /* SubBytes + ShiftRows */
            blks[i] = vaesmcq_u8(blks[i]);                /* MixColumns */
            blks[i] = veorq_u8(blks[i], key->rd_key[j]);  /* AddRoundKey */
        }
        
        /* Last round (round 10): SubBytes, ShiftRows, AddRoundKey (no MixColumns) */
        blks[i] = vaeseq_u8(blks[i], vdupq_n_u8(0));       /* SubBytes + ShiftRows */
        blks[i] = veorq_u8(blks[i], key->rd_key[key->rounds]); /* AddRoundKey */
    }
}

static inline void
AES_set_decrypt_key_fast(AES_KEY *restrict dkey, const AES_KEY *restrict ekey)
{
    int j = 0;
    int i = ekey->rounds;
    
    dkey->rounds = i;
    
    /* Last round key stays the same */
    dkey->rd_key[i--] = ekey->rd_key[j++];
    
    /* Middle round keys need inverse MixColumns */
    while (i) {
        /* vaesimcq_u8 performs the AES inverse MixColumns operation */
        dkey->rd_key[i--] = vaesimcq_u8(ekey->rd_key[j++]);
    }
    
    /* First round key stays the same */
    dkey->rd_key[i] = ekey->rd_key[j];
}

static inline void
AES_set_decrypt_key(block userkey, AES_KEY *restrict key)
{
    AES_KEY temp_key;
    AES_set_encrypt_key(userkey, &temp_key);
    AES_set_decrypt_key_fast(key, &temp_key);
}

static inline void
AES_ecb_decrypt_blks(block *restrict blks, unsigned nblks, const AES_KEY *restrict key)
{
    /* 
     * ARM AES decryption uses:
     * - vaesdq_u8: Performs the AES single round decryption (InvSubBytes, InvShiftRows, InvMixColumns)
     * - vaesimcq_u8: Performs the AES inverse MixColumns operation separately
     * - For the last round, we skip InvMixColumns
     */
    for (unsigned i = 0; i < nblks; ++i) {
        /* XOR with round 0 key (AddRoundKey) */
        blks[i] = veorq_u8(blks[i], key->rd_key[0]);
        
        /* Rounds 1-9: InvSubBytes, InvShiftRows, InvMixColumns, AddRoundKey */
        for (unsigned j = 1; j < key->rounds; ++j) {
            blks[i] = vaesdq_u8(blks[i], vdupq_n_u8(0));  /* InvSubBytes + InvShiftRows */
            blks[i] = vaesimcq_u8(blks[i]);               /* InvMixColumns */
            blks[i] = veorq_u8(blks[i], key->rd_key[j]);  /* AddRoundKey */
        }
        
        /* Last round: InvSubBytes, InvShiftRows, AddRoundKey (no InvMixColumns) */
        blks[i] = vaesdq_u8(blks[i], vdupq_n_u8(0));       /* InvSubBytes + InvShiftRows */
        blks[i] = veorq_u8(blks[i], key->rd_key[key->rounds]); /* AddRoundKey */
    }
}

#else
#error "Unsupported platform. Only x86_64 and ARM64 are supported."
#endif

#endif