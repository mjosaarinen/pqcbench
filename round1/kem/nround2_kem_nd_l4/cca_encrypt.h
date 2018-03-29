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
 * Declaration of the encrypt and decrypt functions based on the CCA KEM
 * algorithm.
 *
 * @author Hayo Baan
 */

#ifndef CCA_ENCRYPT_H
#define CCA_ENCRYPT_H

#include "parameters.h"

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Generates an ENCRYPT key pair. Uses the fixed parameter configuration from `api.h`.
     *
     * @param[out] pk public key
     * @param[out] sk secret key
     * @return __0__ in case of success
     */
    int crypto_encrypt_keypair(unsigned char *pk, unsigned char *sk);

    /**
     * Encrypts a message. Uses the fixed parameter configuration from `api.h`.
     *
     * @param[out] c    the encrypted message
     * @param[out] clen the length of the encrypted message (`CRYPTO_CIPHERTEXTBYTES` + `mlen`)
     * @param[in]  m    the message to encrypt
     * @param[in]  mlen the length of the message to encrypt
     * @param[in]  pk   the public key to use for the encryption
     * @return __0__ in case of success
     */
    int crypto_encrypt(unsigned char *c, unsigned long long *clen, const unsigned char *m, const unsigned long long mlen, const unsigned char *pk);

    /**
     * Decrypts a message. Uses the fixed parameter configuration from `api.h`.
     *
     * @param[out] m    the decrypted message
     * @param[out] mlen the length of the decrypted message (`clen` - `CRYPTO_CIPHERTEXTBYTES`)
     * @param[in]  c    the message to decrypt
     * @param[in]  clen the length of the message to decrypt
     * @param[in]  sk   the secret key to use for the decryption
     * @return __0__ in case of success
     */
    int crypto_encrypt_open(unsigned char *m, unsigned long long *mlen, const unsigned char *c, unsigned long long clen, const unsigned char *sk);

    /**
     * Generates an ENCRYPT key pair. Uses the parameters as specified.
     *
     * @param[out] pk     public key
     * @param[out] sk     secret key (<b>important:</b> the size of `sk` is `sk_size` + `ss_size` + `pk_size`!)
     * @param[in]  params the algorithm parameters to use
     * @param[in]  fn     the variant to use for the generation of A
     * @return __0__ in case of success
     */
    int crypto_encrypt_keypair_p(unsigned char *pk, unsigned char *sk, const parameters *params, const uint8_t fn);

    /**
     * Encrypts a message. Uses the parameters as specified.
     *
     * @param[out] c      the encrypted message
     * @param[out] c_len  the length of the encrypted message (`ct_size` + `ss_size` + `mlen` + 16 + 12)
     * @param[in]  m      the message to encrypt
     * @param[in]  m_len  the length of the message to encrypt
     * @param[in]  pk     the public key to use for the encryption
     * @param[in]  params the algorithm parameters to use (will get `fn` set from `pk`)
     * @return __0__ in case of success
     */
    int crypto_encrypt_p(unsigned char *c, unsigned long long *c_len, const unsigned char *m, const unsigned long long m_len, const unsigned char *pk, const parameters *params);

    /**
     * Decrypts a message. Uses the parameters as specified.
     *
     * @param[out] m       the decrypted message
     * @param[out] m_len   the length of the decrypted message (`c_len` - `ct_size` - `ss_size` - 16 - 12)
     * @param[in]  c       the message to decrypt
     * @param[in]  c_len   the length of the message to decrypt
     * @param[in]  sk      the secret key to use for the decryption
     * @param[in]  params  the algorithm parameters to use
     * @return __0__ in case of success
     */
    int crypto_encrypt_open_p(unsigned char *m, unsigned long long *m_len, const unsigned char *c, unsigned long long c_len, const unsigned char *sk, const parameters *params);

#ifdef __cplusplus
}
#endif

#endif /* CCA_ENCRYPT_H */
