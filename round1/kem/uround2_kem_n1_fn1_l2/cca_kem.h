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
 * Declaration of the CCA KEM functions.
 *
 * @author Jose Luis Torre Arce, Hayo Baan
 */
#ifndef CCA_KEM_H
#define CCA_KEM_H

#include "parameters.h"

#ifdef __cplusplus
extern "C" {
#endif

    /*******************************************************************************
     * Public functions
     ******************************************************************************/

    /**
     * Generates a CCA KEM key pair. Uses the fixed parameter configuration from `api.h`.
     *
     * @param[out] pk public key
     * @param[out] sk secret key
     * @return __0__ in case of success
     */
    int crypto_cca_kem_keypair(unsigned char *pk, unsigned char *sk);

    /**
     * CCA KEM encapsulate. Uses the fixed parameter configuration from `api.h`.
     *
     * @param[out] ct    key encapsulation message (ciphertext)
     * @param[out] ss    shared secret
     * @param[in]  pk    public key with which the message is encapsulated
     * @return __0__ in case of success
     */
    int crypto_cca_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

    /**
     * CCA KEM de-capsulate. Uses the fixed parameter configuration from `api.h`.
     *
     * @param[out] ss    shared secret
     * @param[in]  ct    key encapsulation message (ciphertext)
     * @param[in]  sk    secret key with which the message is to be de-capsulated
     * @return __0__ in case of success
     */
    int crypto_cca_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

    /**
     * Generates a CCA KEM key pair. Uses the parameters as specified.
     *
     * @param[out] pk     public key
     * @param[out] sk     secret key
     * @param[in]  params the algorithm parameters to use
     * @param[in]  fn     the variant to use for the generation of A
     * @return __0__ in case of success
     */
    int crypto_cca_kem_keypair_p(unsigned char *pk, unsigned char *sk, const parameters *params, const uint8_t fn);

    /**
     * CCA KEM encapsulate. Uses the parameters as specified.
     *
     * @param[out] c      key encapsulation message (<b>important:</b> the size of `c` is `ct_size` + `ss_size`!)
     * @param[out] K      shared secret
     * @param[in]  pk     public key with which the message is encapsulated
     * @param[in]  params the algorithm parameters to use
     * @return __0__ in case of success
     */
    int crypto_cca_kem_enc_p(unsigned char *c, unsigned char *K, const unsigned char *pk, const parameters *params);

    /**
     * CCA KEM de-capsulate. Uses the parameters as specified.
     *
     * @param[out] K      shared secret
     * @param[in]  c      key encapsulation message (<b>important:</b> the size of `c` is `ct_size` + `ss_size`!)
     * @param[in]  sk     secret key with which the message is to be de-capsulated (<b>important:</b> the size of `sk` is `sk_size` + `ss_size` + `pk_size`!)
     * @param[in]  params the algorithm parameters to use
     * @return __0__ in case of success
     */
    int crypto_cca_kem_dec_p(unsigned char *K, const unsigned char *c, const unsigned char *sk, const parameters *params);

#ifdef __cplusplus
}
#endif

#endif /* CCA_KEM_H */

