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
 * Declaration of the various pack and unpack functions.
 *
 * @author Jose Luis Torre Arce, Hayo Baan
 * @endcond
 */

#ifndef PACK_H
#define PACK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Packs a public key from its sigma and B components.
     *
     * @param[out] packed_pk the packed key
     * @param[in]  fn        fn
     * @param[in]  sigma     sigma
     * @param[in]  sigma_len length of sigma
     * @param[in]  B         B
     * @param[in]  elements  number of elements of B
     * @param[in]  nr_bits   number of significant bits per element
     * @return the length of packed pk in bytes
     */
    size_t pack_pk(unsigned char *packed_pk, const uint8_t fn, const unsigned char *sigma, size_t sigma_len, const uint16_t *B, size_t elements, uint8_t nr_bits);

    /**
     * Packs the given secret key
     *
     * @param[out] packed_sk the packed key
     * @param[in]  sk        key to pack
     * @param[in]  elements  number of elements of the key
     * @return the length of packed sk in bytes
     */
    size_t pack_sk(unsigned char *packed_sk, const int16_t *sk, size_t elements);

    /**
     * Packs the given ciphertext
     *
     * @param[out] packed_ct buffer for the packed ciphertext
     * @param[in]  U         matrix U
     * @param[in]  U_els     elements in U
     * @param[in]  U_bits    significant bits per element
     * @param[in]  v         vector v
     * @param[in]  v_els     elements in v
     * @param[in]  v_bits    significant bits per element
     * @return the length of packed ct in bytes
     */
    size_t pack_ct(unsigned char *packed_ct, const uint16_t *U, size_t U_els, uint8_t U_bits, const uint16_t *v, size_t v_els, uint8_t v_bits);

    /**
     * Unpacks a packed public key into its fn, sigma and B components.
     *
     * @param[out] fn        fn
     * @param[out] sigma     sigma
     * @param[out] B         B
     * @param[in]  packed_pk packed public key
     * @param[in]  sigma_len length of sigma
     * @param[in]  elements  the number of elements of B
     * @param[in]  nr_bits   the number of significant bits per element
     * @return total unpacked bytes
     */
    size_t unpack_pk(uint8_t *fn, unsigned char *sigma, uint16_t *B, const unsigned char *packed_pk, size_t sigma_len, size_t elements, uint8_t nr_bits);

    /**
     * Unpacks a secret key.
     *
     * @param[out] sk        unpacked secret key
     * @param[in]  packed_sk packed secret key
     * @param[in]  elements  number of elements of the key
     * @return total unpacked bytes
     */
    size_t unpack_sk(int16_t *sk, const unsigned char *packed_sk, size_t elements);

    /**
     * Unpacks the given ciphertext into its U and v components.
     *
     * @param[out] U         matrix U
     * @param[out] v         vector v
     * @param[in]  packed_ct packed ciphertext
     * @param[in]  U_els     elements in U
     * @param[in]  U_bits    significant bits per element
     * @param[in]  v_els     elements in v
     * @param[in]  v_bits    significant bits per element
     * @return total unpacked bytes
     */
    size_t unpack_ct(uint16_t *U, uint16_t *v, const unsigned char *packed_ct, const size_t U_els, const uint8_t U_bits, const size_t v_els, const uint8_t v_bits);

#ifdef __cplusplus
}
#endif

#endif /* PACK_H */
