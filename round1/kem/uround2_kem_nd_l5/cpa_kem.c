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
 * Implementation of the CPA KEM functions.
 *
 * @author Jose Luis Torre Arce, Hayo Baan
 * @endcond
 */

#include "cpa_kem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pst_api.h"
#include "pst_core.h"
#include "pst_encrypt.h"
#include "pack.h"
#include "hash.h"
#include "misc.h"
#include "randombytes.h"
#include "drng.h"

/*******************************************************************************
 * Private functions & macros
 ******************************************************************************/

/**
 * Checks the API parameters for correctness for this algorithm. If the are
 * incorrect, a warning is printed on `stderr`.
 */
#define check_api_parameters() \
    if (CRYPTO_SECRETKEYBYTES != params.sk_size) \
        fprintf(stderr, \
            "WARNING: API Parameters are for ENCRYPT, not for KEM.\n* The size of the SECRET KEY is actually %u, not %u!\n* The size of the CIPHER TEXT is actually %u, not %u!\n", \
            params.sk_size, CRYPTO_SECRETKEYBYTES, \
            params.ct_size, CRYPTO_CIPHERTEXTBYTES)

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
    parameters params;
    if (set_parameters_from_api(&params)) {
        exit(EXIT_FAILURE);
    }
    check_api_parameters();
    return crypto_kem_keypair_p(pk, sk, &params, ROUND2_VARIANT_A);
}

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
    parameters params;
    if (set_parameters_from_api(&params)) {
        exit(EXIT_FAILURE);
    }
    check_api_parameters();
    return crypto_kem_enc_p(ct, ss, pk, &params);
}

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
    parameters params;
    if (set_parameters_from_api(&params)) {
        exit(EXIT_FAILURE);
    }
    check_api_parameters();
    return crypto_kem_dec_p(ss, ct, sk, &params);
}

int crypto_kem_keypair_p(unsigned char *pk, unsigned char *sk, const parameters *params, const uint8_t fn) {
    return generate_keypair(pk, sk, params, fn);
}

int crypto_kem_enc_p(unsigned char *c, unsigned char *K, const unsigned char *pk, const parameters *params) {
    unsigned char *hash_input;
    unsigned char *m;

    /* Allocate space */
    hash_input = checked_malloc((size_t) (params->ss_size + params->ct_size));
    m = checked_malloc(params->ss_size);

    /* Generate a random m */
    randombytes(m, params->ss_size);   

#if defined(ROUND2_INTERMEDIATE) || defined(DEBUG)
    print_hex("cpa_encrypt: m", m, params->ss_size, 1);
#endif

    /* Encrypt m */
    encrypt(c, m, pk, params);

    /* K = H(m, c) */
    memcpy(hash_input, m, params->ss_size);
    memcpy(hash_input + params->ss_size, c, params->ct_size);
    hash(K, hash_input, (size_t) (params->ss_size + params->ct_size), params->ss_size);

    free(hash_input);
    free(m);

    return 0;
}

int crypto_kem_dec_p(unsigned char *K, const unsigned char *c, const unsigned char *sk, const parameters *params) {
    unsigned char *hash_input;
    unsigned char *m;

    /* Allocate space */
    hash_input = checked_malloc((size_t) (params->ss_size + params->ct_size));
    m = checked_malloc(params->ss_size);

    /* Decrypt m */
    decrypt(m, c, sk, params);

#if defined(ROUND2_INTERMEDIATE) || defined(DEBUG)
    print_hex("cpa_decrypt: m", m, params->ss_size, 1);
#endif

    /* K = H(m, c) */
    memcpy(hash_input, m, params->ss_size);
    memcpy(hash_input + params->ss_size, c, params->ct_size);
    hash(K, hash_input, (size_t) (params->ss_size + params->ct_size), params->ss_size);

    free(hash_input);
    free(m);

    return 0;
}
