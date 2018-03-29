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

/**
 * @file
 * Implementation of the encrypt and decrypt functions based on the CCA KEM
 * algorithm.
 *
 * @author Hayo Baan
 */

#include "cca_encrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#include "pst_api.h"
#include "cca_kem.h"
#include "pst_dem.h"
#include "hash.h"
#include "misc.h"
#include "randombytes.h"

/*******************************************************************************
 * Private functions & macros
 ******************************************************************************/

/**
 * Checks the API parameters for correctness for this algorithm. If the are
 * incorrect, a warning is printed on `stderr`.
 */
#define check_api_parameters() \
    if (CRYPTO_SECRETKEYBYTES == params.sk_size || CRYPTO_CIPHERTEXTBYTES != 0) \
        fprintf(stderr, \
            "WARNING: API Parameters are for KEM, not for ENCRYPT.\n* The size of the SECRET KEY is actually %u, not %u!\n* The size of the MESSAGE OVERHEAD is actually %u, not %u!\n", \
            params.sk_size + params.ss_size + params.pk_size, CRYPTO_SECRETKEYBYTES, \
            params.ct_size + params.ss_size, CRYPTO_BYTES)

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int crypto_encrypt_keypair(unsigned char *pk, unsigned char *sk) {
    parameters params;
    if (set_parameters_from_api(&params)) {
        exit(EXIT_FAILURE);
    }
    check_api_parameters();
    return crypto_encrypt_keypair_p(pk, sk, &params, ROUND2_VARIANT_A);
}

int crypto_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, const unsigned long long mlen, const unsigned char *pk) {
    parameters params;
    if (set_parameters_from_api(&params)) {
        exit(EXIT_FAILURE);
    }
    check_api_parameters();
    return crypto_encrypt_p(c, clen, m, mlen, pk, &params);
}

int crypto_encrypt_open(unsigned char *m, unsigned long long *mlen, const unsigned char *c, unsigned long long clen, const unsigned char *sk) {
    parameters params;
    if (set_parameters_from_api(&params)) {
        exit(EXIT_FAILURE);
    }
    check_api_parameters();
    return crypto_encrypt_open_p(m, mlen, c, clen, sk, &params);
}

int crypto_encrypt_keypair_p(unsigned char *pk, unsigned char *sk, const parameters *params, const uint8_t fn) {
    return crypto_cca_kem_keypair_p(pk, sk, params, fn);
}

int crypto_encrypt_p(unsigned char *c, unsigned long long *c_len, const unsigned char *m, const unsigned long long m_len, const unsigned char *pk, const parameters *params) {
    int result = 1;
    const unsigned long long c1_len = (unsigned long long) (params->ct_size + params->ss_size);
    unsigned char *c1 = checked_malloc(c1_len);
    unsigned long long c2_len;
    unsigned char *K = checked_malloc(params->ss_size);

    /* Determine c1 and K */
    crypto_cca_kem_enc_p(c1, K, pk, params);

    /* Copy c1 into first part of c */
    memcpy(c, c1, c1_len);
    *c_len = c1_len;

    /* Apply DEM to get second part of c */
    if (round2_dem(c + c1_len, &c2_len, K, params->ss_size, m, m_len)) {
        fprintf(stderr, "Failed to apply DEM\n");
        goto done_encrypt;
    }
    *c_len += c2_len;

    /* All OK */
    result = 0;

done_encrypt:
    free(c1);
    free(K);

    return result;
}

int crypto_encrypt_open_p(unsigned char *m, unsigned long long *m_len, const unsigned char *c, unsigned long long c_len, const unsigned char *sk, const parameters *params) {
    int result = 1;
    unsigned char *K = checked_malloc(params->ss_size);
    const unsigned char * const c1 = c;
    const unsigned long long c1_len = (unsigned long long) (params->ct_size + params->ss_size);
    const unsigned char * const c2 = c + c1_len;
    const unsigned long c2_len = c_len - c1_len;

    /* Determine K */
    crypto_cca_kem_dec_p(K, c1, sk, params);

    /* Apply DEM-inverse to get m */
    if (round2_dem_inverse(m, m_len, K, params->ss_size, c2, c2_len)) {
        fprintf(stderr, "Failed to apply DEM-inverse\n");
        goto done_decrypt;
    }

    /* OK */
    result = 0;

done_decrypt:
    free(K);

    return result;
}
