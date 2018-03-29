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
     * A_master has length _d/n * d/n * n_.
     *
     * @param[out] A      created A
     * @param[in]  fn     the variant to use for the generation of A
     * @param[in]  sigma  seed
     * @param[in]  params the algorithm parameters in use
     * @return __0__ in case of success
     */
    int create_A(uint16_t *A, const uint8_t fn, const unsigned char *sigma, const parameters *params);

    /**
     * Creates random __S<sup>T</sup>__ from the given parameters.
     *
     * __S<sup>T</sup>__ has length _d/n * n * n_bar_.
     *
     * @param[out] S_T     created _S<sup>T</sup>_
     * @param[in]  params  the algorithm parameters in use
     * @return __0__ in case of success
     */
    int create_S_T(int16_t *S_T, const parameters *params);

    /**
     * Creates __R<sup>T</sup>__ from the given parameters and seed rho.
     *
     * __R<sup>T</sup>__ has length _d/n * n * m_bar_.
     *
     * @param[out] R_T      created _R<sup>T</sup>_
     * @param[in]  rho      seed
     * @param[in]  params   the algorithm parameters in use
     * @return __0__ in case of success
     */
    int create_R_T(int16_t *R_T, const unsigned char *rho, const parameters *params);

    /**
     * Computes _result = left * right_
     * Where left and right are matrices of polynomials.
     * The result is reduced modulo _x^n - 1_ and the coefficients modulo mod.
     *
     * @param[out] result  result of the operation
     * @param[in]  left    left side matrix
     * @param[in]  l_rows  number of rows of the left matrix
     * @param[in]  l_cols  number of columns of the left matrix
     * @param[in]  right   right side matrix
     * @param[in]  r_rows  number of rows of the right matrix
     * @param[in]  r_cols  number of columns of the right matrix
     * @param[in]  els     number of coefficients per polynomial
     * @param[in]  mod     modulo of the coefficients
     * @return __0__ in case of success
     */
    int mult_matrix(uint16_t *result, const int16_t *left, const size_t l_rows, const size_t l_cols, const int16_t *right, const size_t r_rows, const size_t r_cols, const size_t els, const uint16_t mod);

    /**
     * Compress all coefficients in a matrix of polynomials from range a to
     * range b rounding them to the nearest value. Uses random noise for the
     * rounding errors.
     *
     * @param[out] matrix matrix to compress and compressed matrix
     * @param[in]  len    size of the matrix (rows * columns)
     * @param[in]  els    number of coefficients per polynomial
     * @param[in]  a      original value range
     * @param[in]  b      compressed value range (must be a power of 2!)
     * @param[in]  e_seed_size size of the seed for the noise
     * @return __0__ in case of success
     */
    int r_compress_matrix(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b, const uint8_t e_seed_size);

    /**
     * Compress all coefficients in a matrix of polynomials from range a to range b
     * rounding them to the nearest value. Uses the specified seed for generating
     * the noise used for the rounding errors.
     *
     * @param[out] matrix matrix to compress and compressed matrix
     * @param[in]  len         size of the matrix (rows * columns)
     * @param[in]  els         number of coefficients per polynomial
     * @param[in]  a           original value range
     * @param[in]  b           compressed value range (must be a power of 2!)
     * @param[in]  e_seed      seed for the noise
     * @param[in]  e_seed_size size of the seed for the noise
     * @return __0__ in case of success
     */
    int compress_matrix(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b, const unsigned char *e_seed, const uint8_t e_seed_size);

    /**
     * Compress all coefficients in a matrix of polynomials from a bits to b bits
     * rounding them to the nearest value.
     * There is no rounding error in this case.
     *
     * @param[out] matrix matrix to compress and compressed matrix
     * @param[in]  len    size of the matrix (rows * columns)
     * @param[in]  els    number of coefficients per polynomial
     * @param[in]  a      original value number of bits
     * @param[in]  b      compressed value range
     * @return __0__ in case of success
     */
    int r_compress_matrix_base2(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b);

    /**
     * Decompress all coefficients in a matrix of polynomials from range b to range a.
     *
     * @param[out] matrix matrix to compress and compressed matrix
     * @param[in]  len    size of the matrix (rows * columns)
     * @param[in]  els    number of coefficients per polynomial
     * @param[in]  a      decompressed value range
     * @param[in]  b      compressed value range (must be a power of 2!)
     * @return __0__ in case of success
     */
    int decompress_matrix(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b);

    /**
     * Decompress all coefficients in a matrix of polynomials from b bits to a bits.
     *
     * @param[out] matrix matrix to compress and compressed matrix
     * @param[in]  len    size of the matrix (rows * columns)
     * @param[in]  els    number of coefficients per polynomial
     * @param[in]  a      decompressed value number of bits
     * @param[in]  b      compressed value number of bits
     * @return __0__ in case of success
     */
    int decompress_matrix_base2(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b);

    /**
     * Transpose a matrix of polynomials and store it in matrix_t.
     *
     * @param[out] matrix_t transposed matrix
     * @param[in]  matrix   original matrix
     * @param[in]  rows     number of rows of the original matrix
     * @param[in]  cols     number of columns of the original matrix
     * @param[in]  els      number of coefficients per polynomial
     * @return __0__ in case of success
     */
    int transpose_matrix(uint16_t *matrix_t, const uint16_t *matrix, const size_t rows, const size_t cols, const size_t els);

#ifdef __cplusplus
}
#endif

#endif /* PST_CORE_H */
