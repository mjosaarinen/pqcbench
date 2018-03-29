/*
 * Copyright (c) 2017 Koninklijke Philips N.V. All rights reserved. A
 * copyright license for redistribution and use in source and binary
 * forms, with or without modification, is hereby granted for
 * non-commercial, experimental, research, public review and
 * evaluation purposes, provided that the following conditions are
 * met:
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution. If you wish to use this software commercially,
 *   kindly contact info.licensing@philips.com to obtain a commercial
 *   license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @cond DEVELOP
 * @file
 * Implementation of the deterministic random bytes functions.
 *
 * The deterministic random number generator is based on the NIST seed expander
 * (from `rng.c`), but optimized/specialized for the specific Round2 case.
 * It uses AES in ECB mode with the seed as key and a counter as plaintext.
 *
 * @author Jose Luis Torre Arce, Hayo Baan
 * @endcond
 */

#include "drng.h"

#include <string.h>
#include <stdint.h>

#include <openssl/evp.h>

/*******************************************************************************
 * Private functions
 ******************************************************************************/

/**
 * Structure for holding the context (state) of the seed expander used for
 * generating the deterministic random numbers.
 */
typedef struct {
    unsigned char buffer[16]; /**< Buffer for the deterministical random bytes. */
    unsigned int buffer_pos; /**< Current position of used random bytes in the buffer. */
    unsigned char key[32]; /**< The key for AES ECB. */
    unsigned char ctr[16]; /**< The counter for AES ECB. */
} seed_expander_context;

/**
 * The context of the seed expander used for generating the deterministic
 * random numbers.
 */
static seed_expander_context seed_expander_ctx;

/**
 * The AES ECB context as used within in the seed expander.
 */
static EVP_CIPHER_CTX *aes_ctx;

/**
 * Runs AES in ECB mode on the given key and counter (=plaintext).
 * 
 * @param[out] buffer the buffer to place the AES ECB result in
 * @param[in]  key    the key to use (32 bytes)
 * @param[in]  ctr    the counter to use (16 bytes)
 */
static void aes_ecb(unsigned char *buffer, const unsigned char *key, const unsigned char *ctr) {
    int len;

    /* Initialize */
    if (!(aes_ctx = EVP_CIPHER_CTX_new()) || (EVP_EncryptInit_ex(aes_ctx, EVP_aes_256_ecb(), NULL, key, NULL) != 1)) {
        fprintf(stderr, "Failed to initialise encryption engine for DRNG\n");
        exit(EXIT_FAILURE);
    }

    /* Run AES ECB */
    if (EVP_EncryptUpdate(aes_ctx, buffer, &len, ctr, 16) != 1) {
        fprintf(stderr, "Failed to run encrypt for DRNG\n");
        exit(EXIT_FAILURE);
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(aes_ctx);
}

/**
 * Initialises the seed expander used within the DRNG.
 * 
 * @param[in] seed        the 32 byte seed
 * @return  __0__ on success
 */
static int seedexpander_init(const unsigned char *seed) {
    /* Set key to seed */
    memcpy(seed_expander_ctx.key, seed, 32);

    /* Set counter to 0xffffffffffffffffffffffff | 0x00000000 */
    memset(seed_expander_ctx.ctr, 0xff, 12);
    memset(seed_expander_ctx.ctr + 12, 0x00, 4);

    /* Initialise buffer */
    seed_expander_ctx.buffer_pos = 16;
    memset(seed_expander_ctx.buffer, 0x00, 16);

    return 0;
}

/**
 * Expands the seed using AES in ECB mode, generating the specified number of random bytes.
 * 
 * @param[out] x    the buffer in which to place the deterministic random bytes
 * @param[in]  xlen the number of random bytes to produce
 * @return __0__ upon success
 */
static int seedexpander(unsigned char *x, unsigned long xlen) {
    /*
     * Note: Since with Round2 only up to 2*d*d random bytes are ever requested
     * from the same seed, we do not need to check whether or not we have
     * actually exhausted the number of random bytes that can be produced
     * without having to re-seed;  2*d*d is guaranteed to be < 2^32 (the number
     * of random bytes that can be generated without requiring a re-seed).
     */
    unsigned long offset;
    int i;

    offset = 0;
    while (xlen > 0) {
        if (xlen <= (16U - seed_expander_ctx.buffer_pos)) { /* Buffer has what we need */
            memcpy(x + offset, seed_expander_ctx.buffer + seed_expander_ctx.buffer_pos, xlen);
            seed_expander_ctx.buffer_pos = (unsigned int) (seed_expander_ctx.buffer_pos + xlen);

            return 0;
        }

        /* Take what's in the buffer */
        memcpy(x + offset, seed_expander_ctx.buffer + seed_expander_ctx.buffer_pos, 16 - seed_expander_ctx.buffer_pos);
        xlen -= 16U - seed_expander_ctx.buffer_pos;
        offset += 16U - seed_expander_ctx.buffer_pos;

        /* Fill buffer with new values */
        aes_ecb(seed_expander_ctx.buffer, seed_expander_ctx.key, seed_expander_ctx.ctr);
        seed_expander_ctx.buffer_pos = 0;

        /* increment the counter */
        for (i = 15; i >= 12; i--) {
            if (seed_expander_ctx.ctr[i] == 0xff)
                seed_expander_ctx.ctr[i] = 0x00;
            else {
                ++seed_expander_ctx.ctr[i];
                break;
            }
        }

    }

    return 0;
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int init_drng(const unsigned char *seed, const uint8_t seed_size) {
    unsigned char seed_used[32];

    /* Seed expander always takes 32 byte seeds so we need to expand/shrink the input seed as necessary */
    const unsigned seed_size_used = seed_size > 32 ? 32 : seed_size;
    memcpy(seed_used, seed, seed_size_used);
    if (seed_size_used < 32) {
        memset(seed_used + seed_size_used, 0, 32 - seed_size_used);
    }
    seedexpander_init(seed_used);

    return 0;
}

/**
 * Generates a number of deterministic random bytes.
 * @param[out] x    the buffer in which to place the deterministic random bytes
 * @param[in]  xlen the number of random bytes to produce
 * @return __0__ upon success
 */
int drng(unsigned char *x, const unsigned long xlen) {
    seedexpander(x, (unsigned long) xlen);

    return 0;
}
