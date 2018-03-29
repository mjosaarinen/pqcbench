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
 * Declaration of the core algorithm functions.
 *
 * @author Jose Luis Torre Arce, Hayo Baan
 * @endcond
 */


#ifndef PST_CORE_H
#define PST_CORE_H

#include <stddef.h>

#include "parameters.h"

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Creates __A__ from the given parameters and seed.
     *
     * @param[out] A_master       created A_master
     * @param[in]  A_permutation  permutation of A_master
     * @param[in]  fn             function used to generate A_master
     * @param[in]  sigma          seed
     * @param[in]  params         the algorithm parameters in use
     * @return __0__ in case of success
     */
    int create_A(uint16_t *A_master, uint32_t *A_permutation, uint8_t fn, const unsigned char *sigma, const parameters *params);

    /**
     * Creates random __S__ and __S_idx__ from the given parameters.
     *
     * __S__ has length _d * n_bar_.
     * __S_idx__ has length _h * n_bar_.
     *
     * @param[out] S        created S
     * @param[out] S_idx    created S in index form
     * @param[in]  params   the algorithm parameters in use
     * @return __0__ in case of success
     */
    int create_S(int16_t *S, uint16_t *S_idx, const parameters *params);

    /**
     * Creates __R_idx__ from the given parameters and seed rho.
     *
     * __R_idx__ has length _h * m_bar_.
     *
     * @param[out] R_idx    created _R_
     * @param[in]  rho      seed
     * @param[in]  params   the algorithm parameters in use
     * @return __0__ in case of success
     */
    int create_R(uint16_t *R_idx, const unsigned char *rho, const parameters *params);

    /**
     * Compress all coefficients in a matrix of polynomials from a bits to b bits
     * rounding them to the nearest value, where a and b are power of 2.
     * There is no rounding error in this case.
     *
     * @param[out] matrix matrix to compress and compressed matrix
     * @param[in]  len    size of the matrix (rows * columns)
     * @param[in]  els    number of coefficients per polynomial
     * @param[in]  a      original value range
     * @param[in]  b      compressed value range
     * @return __0__ in case of success
     */
    int compress_matrix(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b);

    /**
     * Decompress all coefficients in a matrix of polynomials from b bits to a bits
     * where a and b are power of 2.
     *
     * @param[out] matrix matrix to compress and compressed matrix
     * @param[in]  len    size of the matrix (rows * columns)
     * @param[in]  els    number of coefficients per polynomial
     * @param[in]  a      decompressed value range
     * @param[in]  b      compressed value range
     * @return __0__ in case of success
     */
    int decompress_matrix(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b);

    /**
     * Computes __B__ as __A__*__S__ using the index form of S
     *
     * @param[out] B                  _B_
     * @param[in]  A                  A_master
     * @param[in]  row_displacements  permutation used to get A
     * @param[in]  S_idx              _S_ in index form
     * @param[in]  params             the algorithm parameters in use
     * @return __0__ in case of success
     */
    int compute_B(uint16_t *B, const uint16_t *A, const uint32_t *row_displacements, const uint16_t *S_idx, const parameters *params);

    /**
     * Computes __U__ as __A_T__*__R__ using the index form of S
     *
     * @param[out] U                  _U_
     * @param[in]  A                  A_master
     * @param[in]  row_displacements  permutation used to get A
     * @param[in]  R_idx              _R_ in index form
     * @param[in]  params             the algorithm parameters in use
     * @return __0__ in case of success
     */
    int compute_U(uint16_t *U, const uint16_t *A, const uint32_t *row_displacements, const uint16_t *R_idx, const parameters *params);
    /**
     * Transforms a sparse ternary matrix into index form
     *
     * @param[out] idx_matrix         matrix in index form
     * @param[in]  spter_matrix       sparse ternary matrix
     * @param[in]  num_vec            number of vectors in the matrix
     * @param[in]  params             the algorithm parameters in use
     * @return __0__ in case of success
     */
    int transform_to_index(uint16_t *idx_matrix, const int16_t *spter_matrix, size_t num_vec, const parameters *params);

    /**
     * Computes mu values of X
     *
     * @param[out] X                  _X_
     * @param[in]  B                  _B_
     * @param[in]  R_idx              _R_ in index form
     * @param[in]  params             the algorithm parameters in use
     * @param[in]  mod_bits           number of bits of the coefficients
     * @param[in]  vectors_B          number of vectors in B
     * @param[in]  vectors_R          number of vectors in R
     * @return __0__ in case of success
     */
    int compute_X(uint16_t *X,  const uint16_t *B, const uint16_t *R_idx, const parameters *params, const uint16_t mod_bits, const uint16_t vectors_B, const uint16_t vectors_R);

    /**
     * Computes mu values of X
     *
     * @param[out] X                  _X_prime_
     * @param[in]  U                  _U_
     * @param[in]  S_idx              _S_ in index form
     * @param[in]  params             the algorithm parameters in use
     * @param[in]  mod_bits           number of bits of the coefficients
     * @param[in]  vectors_B          number of vectors in B
     * @param[in]  vectors_R          number of vectors in R
     * @return __0__ in case of success
     */
    int compute_X_prime(uint16_t *X,  const uint16_t *U, const uint16_t *S_idx, const parameters *params, const uint16_t mod_bits, const uint16_t vectors_B, const uint16_t vectors_R);

#ifdef __cplusplus
}
#endif

#endif /* PST_CORE_H */
