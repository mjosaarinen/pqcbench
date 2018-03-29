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
 * Declaration of the DEM functions used by the Round2 CCA KEM-based encrypt algorithm.
 *
 * @author Hayo Baan
 */

#include "pst_dem.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#include "pst_api.h"
#include "cca_kem.h"
#include "hash.h"
#include "misc.h"
#include "randombytes.h"

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int round2_dem(unsigned char *c2, unsigned long long *c2_len, const unsigned char *key, const unsigned key_len, const unsigned char *m, const unsigned long long m_len) {
    static uint64_t iv_counter = 0;
    int i;
    int result = 1;
    int len;
    int c2length;
    EVP_CIPHER_CTX *ctx;
    unsigned char key_used[32];
    const unsigned key_used_size = key_len > 32U ? 32U : key_len;
    unsigned char final_key[32];
    unsigned char tag[16];
    unsigned char iv[12];
    uint64_t iv_tmp = ++iv_counter;

    /* Use 256 bits (32 bytes) of key as initial key, truncate/pad if necessary */
    memcpy(key_used, key, key_used_size);
    if (key_used_size < 32U) {
        memset(key_used + key_used_size, 0, 32U - key_used_size);
    }

    /* Hash key_used to obtain final key */
    hash(final_key, key_used, 32, 32);

    /* Set up IV */
    randombytes(iv, 4);
    for (i = 0; i < 8; ++i) {
        iv[i + 4] = (unsigned char) (iv_tmp & 0xff);
        iv_tmp >>= 8;
    }

    /* Initialise AES GCM */
    if (!(ctx = EVP_CIPHER_CTX_new()) || (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, final_key, iv) != 1)) {
        fprintf(stderr, "Failed to initialise encryption engine\n");
        goto done_dem;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0); /* Disable padding */

    /* Encrypt message into c */
    if (EVP_EncryptUpdate(ctx, c2, &len, m, (int) m_len) != 1) {
        fprintf(stderr, "Failed to encrypt\n");
        goto done_dem;
    }
    c2length = len;

    /* Finalise encrypt */
    if (EVP_EncryptFinal_ex(ctx, c2 + c2length, &len) != 1) {
        fprintf(stderr, "Failed to finalise encrypt\n");
        goto done_dem;
    }
    c2length += len;

    /* Get tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        fprintf(stderr, "Failed to get tag\n");
        goto done_dem;
    }

    /* Append tag and IV */
    memcpy(c2 + c2length, tag, 16);
    c2length += 16;
    memcpy(c2 + c2length, iv, 12);
    c2length += 12;

    /* Set total length */
    *c2_len = (unsigned long long) c2length;

    /* All OK */
    result = 0;

done_dem:
    EVP_CIPHER_CTX_free(ctx);

    return result;
}

int round2_dem_inverse(unsigned char *m, unsigned long long *m_len, const unsigned char *key, const unsigned key_len, const unsigned char *c2, unsigned long long c2_len) {
    int result = 1;
    int len;
    int mlength;
    EVP_CIPHER_CTX *ctx;
    unsigned char key_used[32];
    const unsigned key_used_size = key_len > 32U ? 32U : key_len;
    unsigned char final_key[32];
    unsigned char tag[16];
    const unsigned long long c2_len_no_tag_iv = c2_len - 16U - 12U;
    const unsigned char * const iv = c2 + c2_len - 12U;

    /* Use 256 bits (32 bytes) of K as initial key, truncate/pad if necessary */
    memcpy(key_used, key, key_used_size);
    if (key_used_size < 32U) {
        memset(key_used + key_used_size, 0, 32 - key_used_size);
    }

    /* Hash K_used to obtain final key */
    hash(final_key, key_used, 32, 32);

    /* Get tag */
    memcpy(tag, c2 + c2_len_no_tag_iv, 16);

    /* Initialise AES GCM */
    if (!(ctx = EVP_CIPHER_CTX_new()) || (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, final_key, iv) != 1)) {
        fprintf(stderr, "Failed to initialise encryption engine\n");
        goto done_decrypt;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0); /* Disable padding */

    /* Decrypt */
    if (EVP_DecryptUpdate(ctx, m, &len, c2, (int) c2_len_no_tag_iv) != 1) {
        fprintf(stderr, "Failed to decrypt\n");
        goto done_decrypt;
    }
    mlength = len;

    /* Set expected tag value  */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag)) {
        fprintf(stderr, "Failed to set expected tag\n");
        goto done_decrypt;
    }

    /* Finalise decrypt */
    int ret = EVP_DecryptFinal_ex(ctx, m + mlength, &len);
    if (ret < 0) {
        fprintf(stderr, "Failed to finalise decrypt: %d\n", ret);
        goto done_decrypt;
    }

    /* Set decrypted message length */
    *m_len = (unsigned long long) mlength;

    /* OK */
    result = 0;

done_decrypt:
    EVP_CIPHER_CTX_free(ctx);

    return result;
}
