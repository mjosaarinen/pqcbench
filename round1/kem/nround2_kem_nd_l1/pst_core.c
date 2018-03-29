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
 * Implementation of the core algorithm functions.
 *
 * @author Jose Luis Torre Arce, Hayo Baan
 * @endcond
 */

#include "pst_core.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "misc.h"
#include "randombytes.h"
#include "drng.h"
#include "hash.h"
#include "a_fixed.h"

/*******************************************************************************
 * Private functions
 ******************************************************************************/

/**
 * Sort an array of 32 bit unsigned integers in constant time.
 *
 * @param arr    pointer to the array to sort
 * @param len    length of the array
 * @return __0__ in case of success
 */
static int radix_sort(uint32_t *arr, size_t len) {
    uint32_t *bucket = checked_malloc(2 * len * sizeof (*bucket));
    uint32_t ptr[2];
    size_t i, j;

    for (i = 0; i < 32; ++i) {
        ptr[0] = 0;
        ptr[1] = 0;
        for (j = 0; j < len; ++j) {
            uint8_t digit = (arr[j] >> i) & 0x1;
            bucket[digit * len + ptr[digit]] = arr[j];
            ++ptr[digit];
        }
        memcpy(arr, bucket, ptr[0] * sizeof (*arr));
        memcpy(arr + ptr[0], bucket + len, ptr[1] * sizeof (*arr));
    }

    free(bucket);

    return 0;
}

/**
 * Computes a mod b using the C remainder operator (%).
 *
 * @param[in] a
 * @param[in] b
 * @return a mod b
 */
static uint16_t modulo(const int32_t a, const uint16_t b) {
    return (uint16_t) (((a % b) + b) % b);
}

/**
 * Create a sparse ternary vector of length len from a seed.
 *
 * @param[out] vector    the generated vector
 * @param[in]  len       the length of the ternary vector to create
 * @param[in]  h         the hamming weight (i.e. number of non-zero elements)
 * @param[in]  seed      the seed for the deterministic random number generator
 * @param[in]  seed_size the size of the seed
 * @return __0__ in case of success
 */
static int create_spter_vec(int16_t *vector, const size_t len, const uint16_t h, const unsigned char *seed, const uint8_t seed_size) {
    size_t i;
    uint32_t *rnd_arr;
    int16_t *h_arr;

    init_drng(seed, seed_size);

    rnd_arr = checked_malloc(len * sizeof (*rnd_arr));
    h_arr = checked_malloc(len * sizeof (*h_arr));

    drng((unsigned char *) rnd_arr, len * sizeof (*rnd_arr));

    for (i = 0; i < h; ++i) {
        h_arr[i] = (i % 2) ? 2 : 0;
    }
    for (i = h; i < len; ++i) {
        h_arr[i] = 1;
    }

    for (i = 0; i < len; ++i) {
        rnd_arr[i] = (rnd_arr[i] & (uint32_t) ~0x3) ^ (h_arr[i] & 0x3);
    }

    /* Constant-time sorting algorithm */
    radix_sort(rnd_arr, len);

    for (i = 0; i < len; ++i) {
        vector[i] = (int16_t) ((rnd_arr[i] & 0x3) - 1);
    }

    free(rnd_arr);
    free(h_arr);

    return 0;
}

/**
 * Multiply 2 polynomials in the NTRU ring with len number of coefficients in
 * Z_mod and reduces the result modulo x^len - 1.
 *
 * @param[out] result result
 * @param[in]  pol_a  first operand
 * @param[in]  pol_b  second operand
 * @param[in]  len    number of coefficients
 * @param[in]  mod    reduction moduli for the coefficients
 * @return __0__ in case of success
 */
static int mult_poly_mod_ntru(uint16_t *result, const int16_t *pol_a, const int16_t *pol_b, const size_t len, const uint16_t mod) {
    size_t i, j;

    for (i = 0; i < len; ++i) {
        result[i] = 0;
    }
    for (i = 0; i < len; ++i) {
        for (j = 0; j < len; j++) {
            size_t deg = (i + j) % len;
            int32_t tmp = (int32_t) (pol_a[(i)] * pol_b[j]);
            result[deg] = modulo((int32_t) (result[deg] + tmp), mod);
        }
    }

    return 0;
}

/**
 * Multiplies a polynomial in the cyclotomic ring times (X - 1), the result can
 * be taken to be in the NTRU ring X^(len+1) - 1.
 *
 * @param[out] ntru_pol  result
 * @param[in]  cyc_pol   polynomial in the cyclotomic ring
 * @param[in]  len       number of coefficients of the cyclotomic polynomial
 * @param[in]  mod       reduction moduli for the coefficients
 * @return __0__ in case of success
 */
static int lift_poly(uint16_t *ntru_pol, const int16_t *cyc_pol, const size_t len, const uint16_t mod) {
    size_t i;

    ntru_pol[0] = modulo((int16_t) (-cyc_pol[0]), mod);
    for (i = 1; i < len; ++i) {
        ntru_pol[i] = modulo((int16_t) (cyc_pol[i - 1] - cyc_pol[i]), mod);
    }
    ntru_pol[len] = modulo((int16_t) cyc_pol[len - 1], mod);

    return 0;
}

/**
 * Divides a polynomial in the NTRU ring by (X - 1), the result can
 * be taken to be in the cyclotomic ring.
 *
 * @param[out] cyc_pol   result
 * @param[in]  ntru_pol  polynomial in the NTRU ring
 * @param[in]  len       number of coefficients of the cyclotomic polynomial
 * @param[in]  mod       reduction moduli for the coefficients
 * @return __0__ in case of success
 */
static int unlift_poly(uint16_t *cyc_pol, const uint16_t *ntru_pol, size_t len, const uint16_t mod) {
    int i;

    cyc_pol[len - 1] = modulo((int16_t) ntru_pol[len], mod);
    for (i = (int) len - 2; i >= 0; --i) {
        cyc_pol[i] = modulo((int16_t) (ntru_pol[i + 1] + cyc_pol[i + 1]), mod);
    }

    return 0;
}

/**
 * Multiplies two polynomials in the cyclotomic ring.
 *
 * The multiplication is done by lifting one operand, multiplying it times
 * (X - 1), performing the operation in the NTRU ring and then unlifting the
 * result.
 *
 * @param[out] result result
 * @param[in]  pol_a  first operand
 * @param[in]  pol_b  second operand
 * @param[in]  len    number of coefficients of the polynomials
 * @param[in]  mod    reduction moduli for the coefficients
 * @return __0__ in case of success
 */
static int mult_poly(uint16_t *result, const int16_t *pol_a, const int16_t *pol_b, const size_t len, const uint16_t mod) {
    uint16_t *ntru_a;
    int16_t *ntru_b;
    uint16_t *ntru_res;
    size_t i;

    ntru_a = checked_malloc((len + 1) * sizeof (*ntru_a));
    ntru_b = checked_malloc((len + 1) * sizeof (*ntru_b));
    ntru_res = checked_malloc((len + 1) * sizeof (*ntru_res));

    lift_poly(ntru_a, pol_a, len, mod);

    for (i = 0; i < len; ++i) {
        ntru_b[i] = pol_b[i];
    }
    ntru_b[len] = 0;

    mult_poly_mod_ntru(ntru_res, (int16_t *) ntru_a, ntru_b, len + 1, mod);

    unlift_poly(result, ntru_res, len, mod);

    free(ntru_a);
    free(ntru_b);
    free(ntru_res);

    return 0;
}

/**
 * Add 2 polynomials with len number of coefficients in Z_mod and reduce the
 * result modulo x^len - 1.
 *
 * @param[out] result result
 * @param[in]  pol_a  first operand
 * @param[in]  pol_b  second operand
 * @param[in]  len    number of coefficients
 * @param[in]  mod    reduction modulus
 * @return __0__ in case of success
 */
static int add_poly(uint16_t *result, const uint16_t *pol_a, const uint16_t *pol_b, const size_t len, const uint16_t mod) {
    size_t i;

    for (i = 0; i < len; ++i) {
        result[i] = (uint16_t) (pol_a[i] + pol_b[i]);
        result[i] = modulo((int16_t) result[i], mod);
    }

    return 0;
}

/**
 * Compress a number from range a to range b rounding it to the nearest value
 * (using a deterministically random error).
 *
 * @param[out] x number to compress and compressed number
 * @param[in]  a original value range
 * @param[in]  b compressed value range (must be a power of 2)
 * @return __0__ in case of success
 */
static int compress(uint16_t *x, const uint16_t a, const uint16_t b) {
    double tmp;
    int16_t e;
    const uint16_t b_mask = (uint16_t) (b - 1);

    if (a & b_mask) {
        uint16_t rnd;
        drng((unsigned char *) &rnd, sizeof (rnd));
        rnd &= b_mask;
        e = (int16_t) (rnd - ((b >> 1) - 1)); /* e <-$ (-b/2, b/2] */
    } else {
        e = 0;
    }

    tmp = ((double) (b * (*x) + e)) / a;

    *x = (uint16_t) (ROUND(tmp) & b_mask);

    return 0;
}

/**
 * Decompress a number from b bits to a bits.
 *
 * @param[out] x number to compress and compressed number
 * @param[in]  a original value range
 * @param[in]  b compressed value range
 * @return __0__ in case of success
 */
static int decompress(uint16_t *x, const uint16_t a, const uint16_t b) {
    double tmp;
    tmp = (double) (a * (*x)) / b;

    *x = modulo((int16_t) ROUND(tmp), a);

    return 0;
}

/**
 * Compress and round a number from a to b bits where a and b are power of 2.
 *
 * @param[out] x  the value to round and compress
 * @param[in]  a  original bit size
 * @param[in]  b  compressed bit size
 * @return __0__ in case of success
 */
static int r_compress_base2(uint16_t *x, const uint16_t a, const uint16_t b) {
    const uint16_t shift = (uint16_t) (a - b);
    const uint16_t rounding_mask = (uint16_t) (1 << (shift - 1));
    const uint16_t rounding = (uint16_t) ((*x & rounding_mask) >> (shift - 1));
    const uint16_t mask_b = (uint16_t) (((uint16_t) 1 << b) - 1);

    *x = (uint16_t) (*x >> shift);
    *x = (uint16_t) (*x + rounding);

    *x &= mask_b;

    return 0;
}

/**
 * Decompress a number from b to a bits where a and b are power of 2.
 *
 * @param[out] x  the value to decompress
 * @param[in]  a  original bit size
 * @param[in]  b  compressed bit size
 * @return __0__ in case of success
 */
static int decompress_base2(uint16_t *x, const uint16_t a, const uint16_t b) {
    const uint16_t shift = (uint16_t) (a - b);
    const uint16_t mask_a = (uint16_t) (((uint16_t) 1 << a) - 1);

    *x = (uint16_t) (*x << shift);
    *x &= mask_a;

    return 0;
}

/**
 * Generates the row displacements for the A matrix creation variant fn=1.
 *
 * Note: assumes the drng has been initialised!
 *
 * @param[out] row_disp the row displacements
 * @param[in]  params   the algorithm parameters in use
 * @return __0__ on success
 */
static int compute_displacements_non_ring_1(uint32_t *row_disp, const parameters *params) {
    uint32_t i;
    uint16_t rnd;
    const uint16_t mask_ceil_log2d = (uint16_t) ((1U << ceil_log2(params->d)) - 1);

    for (i = 0; i < params->d; ++i) {
        do {
            drng((unsigned char *) &rnd, sizeof (rnd));
            rnd &= mask_ceil_log2d;
        } while (rnd >= params->d);
        row_disp[i] = i * params->d + rnd;
    }

    return 0;
}

/**
 * Generates the row displacements for the A matrix creation variant fn=2.
 *
 * Note: assumes the drng has been initialised!
 *
 * @param[out] row_disp the row displacements
 * @param[in]  params   the algorithm parameters in use
 * @return __0__ on success
 */
static int compute_displacements_non_ring_2(uint32_t *row_disp, const parameters *params) {
    uint32_t i;
    uint16_t rnd;
    const uint16_t mask_ceil_log2q = (uint16_t) ((1U << ceil_log2(params->q)) - 1);

    for (i = 0; i < params->k; ++i) {
        do {
            drng((unsigned char *) &rnd, sizeof (rnd));
            rnd &= mask_ceil_log2q;
        } while (rnd >= params->q);
        row_disp[i] = rnd;
    }

    return 0;
}

/**
 * Creates A random for the given seed and algorithm parameters.
 *
 * @param[out] A_random     the random A to create
 * @param[out] num_elements the number of elements in the random A
 * @param[in]  seed         the seed
 * @param[in]  seed_size    the size of the seed
 * @param[in]  params       the algorithm parameters in use
 * @return
 */
static int create_A_random(uint16_t *A_random, const uint32_t num_elements, const unsigned char *seed, const uint8_t seed_size, const parameters *params) {
    const uint16_t mask_ceil_log2q = (uint16_t) ((1U << ceil_log2(params->q)) - 1);
    uint32_t i;

    init_drng(seed, seed_size);
    for (i = 0; i < num_elements; ++i) {
        do {
            drng((unsigned char *) &A_random[i], sizeof (*A_random));
            A_random[i] &= mask_ceil_log2q;
        } while (A_random[i] >= params->q);
    }

    return 0;
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int create_A_fixed(const unsigned char *seed, const uint8_t seed_size, const parameters *params) {
    const uint32_t len_a_fixed = (uint32_t) (params->d * params->d);

    /* (Re)allocate space for A_fixed */
    A_fixed = realloc(A_fixed, len_a_fixed * sizeof (*A_fixed));

    /* Create A_fixed randomly */
    return create_A_random(A_fixed, len_a_fixed, seed, seed_size, params);
}

int create_A(uint16_t *A, const uint8_t fn, const unsigned char *sigma, const parameters *params) {
    uint32_t i;
    uint16_t *A_master;
    uint32_t * A_permutation;
    unsigned char *prefixed_sigma = checked_malloc(2U + params->ss_size);
    unsigned char *seed = checked_malloc(params->ss_size);
    const uint16_t els_row = (uint16_t) (params->k * params->n);

    /* Seed for generating A is hash(0x0000 | sigma) */
    prefixed_sigma[0] = 0;
    prefixed_sigma[1] = 0;
    memcpy(prefixed_sigma + 2, sigma, params->ss_size);
    hash(seed, prefixed_sigma, 2U + params->ss_size, params->ss_size);

    /* Create A/A_Master*/
    if (fn == 1) {
        if (A_fixed == NULL) {
            fprintf(stderr, "A_fixed has not been initialised, use create_A_fixed() to initialise it.\n");
        }
        A_master = A_fixed;
    } else {
        switch (fn) {
            case 0:
                create_A_random(A, (uint32_t) (params->d * params->d), seed,  params->ss_size, params);
                break;
            case 2:
                A_master = checked_malloc((size_t)(params->q + params->d) * sizeof (*A_master));
                create_A_random(A_master, params->q, seed, params->ss_size, params);
                memcpy(A_master + params->q, A_master, params->d * sizeof (*A_master));
                break;
            case 3:
                create_A_random(A, params->d, seed, params->ss_size, params);
                break;
            default:
                fprintf(stderr, "Error: Wrong fn value for creating A: %hhu.\n", fn);
                exit(EXIT_FAILURE);
        }
    }

    /* Compute and apply the permutation to get A */
    if (fn == 1 || fn == 2) {
        A_permutation = checked_malloc(params->k * sizeof (*A_permutation));

        /* Seed for permutation is hash(0x0001 | sigma) */
        prefixed_sigma[0] = 0;
        prefixed_sigma[1] = 1;
        memcpy(prefixed_sigma + 2, sigma, params->ss_size);
        hash(seed, prefixed_sigma, 2U + params->ss_size, params->ss_size);
        init_drng(seed, params->ss_size);

        /* Compute and apply permutation */
        if (fn == 1) {
            compute_displacements_non_ring_1(A_permutation, params);
            for (i = 0; i < params->k; ++i) {
                uint32_t mod_d = A_permutation[i] % params->d;
                if (mod_d == 0) {
                    memcpy(A + (i * els_row), A_master + A_permutation[i], els_row * sizeof (*A));
                } else {
                    memcpy(A + (i * els_row), A_master + A_permutation[i], (els_row - mod_d) * sizeof (*A));
                    memcpy(A + (i * els_row) + (els_row - mod_d), A_master + A_permutation[i] - mod_d, mod_d * sizeof (*A));
                }
            }
        } else if (fn == 2) {
            compute_displacements_non_ring_2(A_permutation, params);
            for (i = 0; i < params->k; ++i) {
                for (i = 0; i < params->k; ++i) {
                    memcpy(A + (i * els_row), A_master + A_permutation[i], els_row * sizeof (*A));
                }
            }
        }
    }

    /* Free allocated memory */
    if (fn == 1 || fn == 2) {
        if (fn == 2) {
            free(A_master);
        }
        free(A_permutation);
    }
    free(seed);
    free(prefixed_sigma);

    return 0;
}

int create_S_T(int16_t *S_T, const parameters *params) {
    size_t i;
    size_t len = (size_t) (params->k * params->n);
    unsigned char *seed;

    seed = checked_malloc(params->ss_size);

    for (i = 0; i < params->n_bar; ++i) {
        randombytes(seed, params->ss_size);
        create_spter_vec(&S_T[i * len], len, params->h, seed, params->ss_size);
    }

    free(seed);

    return 0;
}

int create_R_T(int16_t *R_T, const unsigned char *rho, const parameters *params) {
    size_t i;
    size_t len = (size_t) (params->k * params->n);
    unsigned char *seed;

    seed = checked_malloc(params->ss_size);
    init_drng(rho, params->ss_size);

    for (i = 0; i < params->m_bar; ++i) {
        drng(seed, params->ss_size);
        create_spter_vec(&R_T[i * len], len, params->h, seed, params->ss_size);
    }

    free(seed);

    return 0;
}

int mult_matrix(uint16_t *result, const int16_t *left, const size_t l_rows, const size_t l_cols, const int16_t *right, const size_t r_rows, const size_t r_cols, const size_t els, const uint16_t mod) {
    size_t i, j, k;
    uint16_t *temp_poly = checked_malloc(els * sizeof (*temp_poly));

    if (l_cols != r_rows) {
        fprintf(stderr, "Error: Inner matrix dimensions must match.\n");
        exit(EXIT_FAILURE);
    }

    /* Initialize result to zero */
    /* Note: this might not be constant-time */
    memset(result, 0, (size_t) (l_rows * r_cols * els * sizeof (*result)));

    for (i = 0; i < l_rows; ++i) {
        for (j = 0; j < r_cols; j++) {
            for (k = 0; k < l_cols; k++) {
                mult_poly(temp_poly, &left[i * (l_cols * els) + k * els], &right[k * (r_cols * els) + j * els], els, mod);
                add_poly(&result[i * (r_cols * els) + j * els], &result[i * (r_cols * els) + j * els], temp_poly, els, mod);
            }
        }
    }

    free(temp_poly);

    return 0;
}

int r_compress_matrix(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b, const uint8_t e_seed_size) {
    unsigned char *e_seed = malloc(e_seed_size);

    if (a & (b - 1)) {
        randombytes(e_seed, e_seed_size);
    }
    compress_matrix(matrix, len, els, a, b, e_seed, e_seed_size);

    free(e_seed);

    return 0;
}

int compress_matrix(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b, const unsigned char *e_seed, const uint8_t e_seed_size) {
    size_t i;

    if (a & (b - 1)) {
        init_drng(e_seed, e_seed_size);
    }
    for (i = 0; i < len * els; ++i) {
        compress(matrix + i, a, b);
    }

    return 0;
}

int r_compress_matrix_base2(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b) {
    size_t i;

    for (i = 0; i < len * els; ++i) {
        r_compress_base2(matrix + i, a, b);
    }

    return 0;
}

int decompress_matrix(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b) {
    size_t i;

    for (i = 0; i < len * els; ++i) {
        decompress(matrix + i, a, b);
    }

    return 0;
}

int decompress_matrix_base2(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b) {
    size_t i;

    for (i = 0; i < len * els; ++i) {
        decompress_base2(matrix + i, a, b);
    }

    return 0;
}

int transpose_matrix(uint16_t *matrix_t, const uint16_t *matrix, const size_t rows, const size_t cols, const size_t els) {
    size_t i, j, k;

    for (i = 0; i < rows; ++i) {
        for (j = 0; j < cols; ++j) {
            for (k = 0; k < els; ++k) {
                matrix_t[j * (rows * els) + (i * els) + k] = matrix[i * (cols * els) + (j * els) + k];
            }
        }
    }

    return 0;
}

