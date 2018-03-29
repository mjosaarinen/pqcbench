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
 * Transform a sparse ternary matrix into index form.
 *
 * @param[out] idx_matrix    index form matrix
 * @param[in]  spter_matrix  original sparse ternary matrix
 * @param[in]  num_vec       number of vectors in the original matrix
 * @param[in]  params        the algorithm parameters in use
 * @return __0__ in case of success
 */
int transform_to_index(uint16_t *idx_matrix, const int16_t *spter_matrix, size_t num_vec, const parameters *params) {
    const size_t len = (size_t) (params->d);

    uint16_t *zero_ids = checked_malloc((len - params->h) * sizeof (*zero_ids));
    uint16_t i, j;

    for (i = 0; i < num_vec; ++i) {
        int pos = 0;
        int neg = 0;
        int zero = 0;
        int pos_index = i * params->h;
        int neg_index = pos_index + params->h / 2;
        for (j = 0; j < len; ++j) {
            if (spter_matrix[i * len + j] == 1) {
                idx_matrix[pos_index + pos] = j;
                pos++;
            }
            if (spter_matrix[i * len + j] == -1) {
                idx_matrix[neg_index + neg] = j;
                neg++;
            }
            if (spter_matrix[i * len + j] == 0) {
                zero_ids[zero] = j;
                zero++;
            }
        }
    }
    free(zero_ids);
    return 0;
}

/**
 * Multiplies a polynomial in the cyclotomic ring times (X - 1), the result can
 * be taken to be in the NTRU ring X^(len+1) - 1.
 *
 * @param[out] ntru_pol  result
 * @param[in]  cyc_pol   polynomial in the cyclotomic ring
 * @param[in]  len       number of coefficients of the cyclotomic polynomial
 * @param[in]  mod_mask  reduction modulus bitmask for the coefficients
 * @return __0__ in case of success
 */
static int lift_poly_2(uint16_t *ntru_pol, const int16_t *cyc_pol, const size_t len, const uint16_t mod_mask) {
    size_t i;

    ntru_pol[0] = (uint16_t) ((-cyc_pol[0]) & mod_mask);

    for (i = 1; i < len; ++i) {
        ntru_pol[i] = (uint16_t) (cyc_pol[i - 1] - cyc_pol[i]) & mod_mask;
    }

    ntru_pol[len] = (uint16_t) cyc_pol[len - 1] & mod_mask;

    return 0;

}

/**
 * Divides a polynomial in the NTRU ring by (X - 1), the result can
 * be taken to be in the cyclotomic ring.
 *
 * @param[out] cyc_pol   result
 * @param[in]  ntru_pol  polynomial in the NTRU ring
 * @param[in]  len       number of coefficients of the cyclotomic polynomial
 * @param[in]  mod_mask  reduction modulus bitmask for the coefficients
 * @return __0__ in case of success
 */
static int unlift_poly(uint16_t *cyc_pol, const uint16_t *ntru_pol, size_t len, const uint16_t mod_mask) {
    int i;

    cyc_pol[len - 1] = ntru_pol[len] & mod_mask;

    for (i = (int) len - 2; i >= 0; --i) {
        cyc_pol[i] = (uint16_t) (ntru_pol[i + 1] + cyc_pol[i + 1]) & mod_mask;
    }

    return 0;

}

/**
 * Multiplies a polynomial in the cyclotomic ring times (X - 1), the result can
 * be taken to be in the NTRU ring X^(len+1) - 1.
 *
 * @param[out] poly      polynomial to lift
 * @param[in]  len       number of coefficients of the cyclotomic polynomial
 * @param[in]  mod_mask  reduction modulus bitmask for the coefficients
 * @return __0__ in case of success
 */
static int lift_poly(uint16_t *poly, const size_t len, const uint16_t mod_mask) {
    size_t i;
    uint16_t aux0, aux1;

    aux0 = poly[0];
    aux1 = poly[1];
    poly[0] = (uint16_t) ((-poly[0]) & mod_mask);

    for (i = 1; i < len; ++i) {
        poly[i] = (uint16_t) ((aux0 - aux1) & mod_mask); /*(mod_mask + 1 + cyc_pol[i - 1] - cyc_pol[i]) & mod_mask;*/
        aux0 = aux1;
        aux1 = poly[i + 1];
    }

    poly[len] = aux0 & mod_mask;

    return 0;

}

/**
 * Compress and round a number from a to b bits where a and b are power of 2.
 *
 * @param[out] x  the value to round and compress
 * @param[in]  a  bitlen before compression
 * @param[in]  b  bitlen after compression
 * @return __0__ in case of success
 */
static int compress(uint16_t *x, const uint16_t a, const uint16_t b) {
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
 * @param[in]  a  decompressed bitlen
 * @param[in]  b  compressed bitlen
 * @return __0__ in case of success
 */
static int decompress(uint16_t *x, const uint16_t a, const uint16_t b) {
    const uint16_t shift = (uint16_t) (a - b);
    const uint16_t mask_a = (uint16_t) (((uint16_t) 1 << a) - 1);

    *x = (uint16_t) (*x << shift);
    *x &= mask_a;

    return 0;
}

/**
 * Computes a coefficient of X
 *
 * @param[in] U
 * @param[in] S_idx
 * @param[in] i
 * @param[in] j
 * @param[in] l
 * @param[in] range_i
 * @param[in] row_displacements
 * @param[in] params
 * @param[in] bits
 * @return __X[i,j,l]__
 */
static uint16_t compute_X_idx(const uint16_t *U, const uint16_t *S_idx, uint32_t i,
        uint32_t j, uint32_t l, const uint32_t range_i, const uint32_t *row_displacements, const parameters *params, const uint16_t bits) {
    uint32_t k;
    size_t index;

    uint16_t U_val;
    uint16_t X_val = 0;
    uint16_t mod_bits_mask = (uint16_t) ((1U << bits) - 1);

    for (k = 0; k < params->h / 2; ++k) {
        index = (size_t) ((S_idx[i * params->h + k]));
        U_val = U[j + index * range_i + row_displacements[l] ];
        X_val = (uint16_t) (X_val + U_val);
    }


    for (k = params->h / 2; k < params->h; ++k) {
        index = (size_t) ((S_idx[i * params->h + k]));
        U_val = U[j + index * range_i + row_displacements[l] ];
        X_val = (uint16_t) (X_val - U_val);
    }

    X_val &= mod_bits_mask;

    return X_val;
}

/**
 * Generates the row displacements for the A matrix creation variant fn=0.
 * Note: This is the identity mapping!
 *
 * @param[out] row_disp the row displacements
 * @param[in]  params   the algorithm parameters in use
 * @return __0__ on success
 */
static int compute_displacements_non_ring_0(uint32_t *row_disp, const parameters *params) {
    uint32_t i;

    for (i = 0; i < params->d; ++i) {
        row_disp[i] = i * params->d;
    }

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
    const uint16_t d_bits = ceil_log2(params->d);
    const uint16_t mask_d = (uint16_t) ((1 << d_bits) - 1);
    uint16_t rnd = 0;
    uint32_t i;

    for (i = 0; i < params->d; ++i) {
        do {
            drng((unsigned char *) &rnd, sizeof (rnd));
            rnd &= mask_d;
        } while (rnd >= params->d);
        row_disp[i] = 2 * i * params->d + rnd;
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
    uint16_t mod_q = (uint16_t) ((1 << params->q_bits) - 1);

    for (i = 0; i < params->d; ++i) {
        drng((unsigned char *) &rnd, sizeof (rnd));
        row_disp[i] = rnd & mod_q;
    }

    return 0;
}

/**
 * Generates the row displacements for the A matrix creation variant fn=3.
 * This permutation creates a convolution matrix assuming the first row is the
 * polynomial ordered as a_0, a_(n-1), a_(n-2), ...
 *
 * @param[out] row_disp the row displacements
 * @param[in]  params   the algorithm parameters in use
 * @return __0__ on success
 */
static int compute_displacements_ring_3(uint32_t *row_disp, const parameters *params) {
    uint32_t i;
    uint32_t n_rows = (uint32_t) (params->d + 1);

    for (i = 0; i < n_rows; ++i) {
        row_disp[i] = (uint32_t) (params->d + 1) - i;
    }

    return 0;
}

/**
 * Generates A_master
 *
 * @param[out]  A_master
 * @param[in]   fn        function used to generate A_master
 * @param[in]   sigma     seed
 * @param[in]   params    the algoritm parameters in use
 * @return __0__ on success
 */
static int create_A_master(uint16_t *A_master, uint8_t fn, const unsigned char *sigma, const parameters *params) {
    size_t i;

    if (fn == 1) {
        if (A_fixed == NULL) {
            fprintf(stderr, "A_fixed has not been initialised, use create_A_fixed() to initialise it.\n");
        }
        /* A_master is a copy of A_fixed but now with all rows duplicated to prevent having to mod d the permutation later */
        for (i = 0; i < params->d; ++i) {
            /* Copy row */
            memcpy(A_master + 2 * i * params->d, A_fixed + i * params->d, params->d * sizeof (*A_fixed));
            memcpy(A_master + 2 * i * params->d + params->d, A_fixed + i * params->d, params->d * sizeof (*A_fixed));
        }
    } else {
        uint32_t num_elements;
        unsigned char *prefixed_sigma = checked_malloc(2U + params->ss_size);
        unsigned char *seed = checked_malloc(params->ss_size);

        const uint16_t mod_q = (uint16_t) ((1U << params->q_bits) - 1);
        switch (fn) {
            case 0:
                num_elements = (uint32_t) (params->d * params->d);
                break;
            case 2:
                num_elements = params->q;
                break;
            case 3:
                num_elements = params->d;
                break;
            default:
                fprintf(stderr, "Error: Wrong fn value for generating A_Master: %hhu.\n", fn);
                exit(EXIT_FAILURE);
        }
        
        /* Seed for generating A is hash(0x0000 | sigma) */
        prefixed_sigma[0] = 0;
        prefixed_sigma[1] = 0;
        memcpy(prefixed_sigma + 2, sigma, params->ss_size);
        hash(seed, prefixed_sigma, 2U + params->ss_size, params->ss_size);        
        init_drng(seed, params->ss_size);

        /* Create a random A_master */
        drng((unsigned char *) A_master, num_elements * sizeof (*A_master));
        /* Mask elements in A_master to be in Z_q */
        for (i = 0; i < num_elements; ++i) {
            A_master[i] &= mod_q;
        }

        if (fn == 2) {
            memcpy(A_master + num_elements, A_master, params->d * sizeof (*A_master));
        } else if (fn == 3) {
            uint16_t *aux = checked_malloc((size_t) (params->d + 1) * sizeof (*aux));
            lift_poly_2(aux, (int16_t*) A_master, params->d, (uint16_t) (params->q - 1));
            A_master[0] = aux[0];
            for (i = 1; i < (size_t) (params->d + 1); ++i) {
                A_master[i] = aux[(size_t) (params->d + 1) - i];
            }
            memcpy(A_master + (params->d + 1), A_master, (size_t) (params->d + 1) * sizeof (*A_master));
            free(aux);
        }

        free(seed);
        free(prefixed_sigma);
    }

    return 0;
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int create_A_fixed(const unsigned char *seed, const uint8_t seed_size, const parameters *params) {
    const size_t len_a_fixed = (size_t) (params->d * params->d);
    const uint16_t mod_q = (uint16_t) ((1U << params->q_bits) - 1);
    uint32_t i;

    /* (Re)allocate space for A_fixed */
    A_fixed = realloc(A_fixed, len_a_fixed * sizeof (*A_fixed));

    /* Create A_fixed randomly */
    init_drng(seed, seed_size);
    drng((unsigned char *) A_fixed, len_a_fixed * sizeof (*A_fixed));

    /* Mask elements in A_fixed to be in Z_q */
    for (i = 0; i < len_a_fixed; ++i) {
        A_fixed[i] &= mod_q;
    }

    return 0;
}

int create_A(uint16_t *A_master, uint32_t *A_permutation, const uint8_t fn, const unsigned char *sigma, const parameters *params) {
    unsigned char *prefixed_sigma = checked_malloc(2U + params->ss_size);
    unsigned char *seed = checked_malloc(params->ss_size);

    /* Create of A_master */
    create_A_master(A_master, fn, sigma, params);

    /* Seed for permutations is hash(0x0001 | sigma) */
    prefixed_sigma[0] = 0;
    prefixed_sigma[1] = 1;
    memcpy(prefixed_sigma + 2, sigma, params->ss_size);

    /* Compute the permutation */
    switch (fn) {
        case 0:
            compute_displacements_non_ring_0(A_permutation, params);
            break;
        case 1:
            hash(seed, prefixed_sigma, 2U + params->ss_size, params->ss_size);
            init_drng(seed, params->ss_size);
            compute_displacements_non_ring_1(A_permutation, params);
            break;
        case 2:
            hash(seed, prefixed_sigma, 2U + params->ss_size, params->ss_size);
            init_drng(seed, params->ss_size);
            compute_displacements_non_ring_2(A_permutation, params);
            break;
        case 3:
            compute_displacements_ring_3(A_permutation, params);
            break;
        default:
            fprintf(stderr, "Error: Wrong fn value for creating A: %hhu.\n", fn);
            exit(EXIT_FAILURE);
    }

    free(seed);

    return 0;
}

int create_S(int16_t *S, uint16_t *S_idx, const parameters *params) {
    size_t i;
    size_t len = (size_t) params->d;
    unsigned char *seed;

    seed = checked_malloc(params->ss_size);

    for (i = 0; i < params->n_bar; ++i) {
        randombytes(seed, params->ss_size);
        create_spter_vec(&S[i * len], len, params->h, seed, params->ss_size);
    }

    transform_to_index(S_idx, S, params->n_bar, params);

    free(seed);

    return 0;
}

int create_R(uint16_t *R_idx, const unsigned char *rho, const parameters *params) {
    size_t i;
    size_t len = (size_t) params->d;
    unsigned char *seed;
    int16_t *R = checked_malloc((size_t) (params->d * params->m_bar) * sizeof (*R));

    seed = checked_malloc(params->ss_size);
    init_drng(rho, params->ss_size);

    for (i = 0; i < params->m_bar; ++i) {
        drng(seed, params->ss_size);
        create_spter_vec(&R[i * len], len, params->h, seed, params->ss_size);
    }

    transform_to_index(R_idx, R, params->m_bar, params);

    free(seed);
    free(R);

    return 0;
}

int compute_B(uint16_t *B, const uint16_t *A, const uint32_t *row_displacements, const uint16_t *S_idx, const parameters *params) {
    int i, j, l;
    size_t len_b = 0;
    size_t idx = 0;
    uint16_t A_val;
    size_t index = 0;
    uint16_t mod_q_mask = (uint16_t) ((1U << params->q_bits) - 1);
    uint16_t *B_aux;
    uint16_t loops;

    if (params->n != 1) { /*in the ring case, we need to lift first and reserve a position of memory more.*/
        len_b = (size_t) ((params->d + 1) * params->n_bar);
        loops = (uint16_t) (params->d + 1);
    } else {
        len_b = (size_t) ((params->d) * params->n_bar);
        loops = params->d;
    }

    B_aux = checked_malloc((len_b) * sizeof (*B_aux));
    memset(B_aux, 0, len_b * sizeof (*B_aux));

    for (i = 0; i < loops; ++i) {
        for (j = 0; j < params->n_bar; ++j) {
            for (l = 0; l < params->h / 2; ++l) { /* Positions where S = 1 */
                index = (size_t) ((S_idx[j * params->h + l]));
                A_val = A[index + row_displacements[i]];
                B_aux[idx] = (uint16_t) (B_aux[idx] + A_val);
            }
            for (l = params->h / 2; l < params->h; ++l) { /* Positions where S = -1 */
                index = (size_t) ((S_idx[j * params->h + l]));
                A_val = A[index + row_displacements[i]];
                B_aux[idx] = (uint16_t) (B_aux[idx] - A_val);
            }
            B_aux[idx] &= mod_q_mask;
            ++idx;
        }
    }

    /*Unlift for the ring case.*/
    if (params->n != 1) {
        for (j = 0; j < params->n_bar; ++j) {
            unlift_poly(B, B_aux, params->n, mod_q_mask);
        }
    } else {
        memcpy(B, B_aux, (size_t) (params->d * params->n_bar) * sizeof (uint16_t));
    }

    free(B_aux);

    return 0;
}

int compute_U(uint16_t *U, const uint16_t *A, const uint32_t *row_displacements, const uint16_t *R_idx, const parameters *params) {
    int j, l;
    uint32_t i;
    size_t len_u = (size_t) (params->d * params->m_bar);

    size_t idx = 0;
    uint16_t A_val;
    size_t index = 0;
    uint16_t mod_q = (uint16_t) ((1U << params->q_bits) - 1);

    memset(U, 0, len_u * sizeof (*U));

    for (i = 0; i < params->d; ++i) {
        for (j = 0; j < params->m_bar; ++j) {
            for (l = 0; l < params->h / 2; ++l) {
                index = (size_t) ((R_idx[j * params->h + l]));
                A_val = A[i + row_displacements[index]];
                U[idx] = (uint16_t) (U[idx] + A_val);
            }
            for (l = params->h / 2; l < params->h; ++l) {
                index = (size_t) ((R_idx[j * params->h + l]));
                A_val = A[i + row_displacements[index]];
                U[idx] = (uint16_t) (U[idx] - A_val);
            }
            U[idx] &= mod_q;
            ++idx;
        }
    }

    return 0;
}

/*
   Computes X = B^t * R and U^T*S
 */


int compute_X(uint16_t *X, const uint16_t *B, const uint16_t *R_idx, const parameters *params, const uint16_t mod_bits, const uint16_t vectors_B, const uint16_t vectors_R) {
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t l = 0;
    uint32_t *row_displacements;
    uint16_t mod_mask = (uint16_t) ((1U << mod_bits) - 1);

    uint16_t *B_aux;
    uint16_t *auxx;

    size_t idx = 0;
    uint16_t mu = (uint16_t) (params->ss_size * 8 / params->B);
    uint16_t len = 0;
    uint16_t loop = 0;

    if (params->d != params->n) { /* Non-ring */
        len = params->d;
        loop = mu;

        /*Fake permutation for unity*/
        row_displacements = checked_malloc(len * sizeof (*row_displacements));
        for (i = 0; i < params->d; ++i) {
            row_displacements[i] = i;
        }

        /*Copy to auxiliary vector*/
        B_aux = checked_malloc((size_t) (len * vectors_B) * sizeof (*B));
        memcpy(B_aux, B, (size_t) (len * vectors_B) * sizeof (uint16_t));

    } else { /* Ring */
        loop = (uint16_t) (mu + 1);
        len = (uint16_t) (params->d + 1);

        B_aux = checked_malloc((size_t) (2 * len * vectors_B) * sizeof (*B));
        memcpy(B_aux, B, (size_t) ((len - 1) * vectors_B) * sizeof (uint16_t));

        /*Moved to NTRU ring*/
        lift_poly(B_aux, (size_t) (len - 1), mod_mask);

        /*Compute NTRU permutation adapted to compute the last mu elements of cyclotomic polynomial
          Otherwise, it should be row_displacements[i] = len - i;
         */
        row_displacements = checked_malloc(len * sizeof (*row_displacements));
        row_displacements[0] = (mu + 1U) % len;
        for (i = 1; i < loop; ++i) {
            row_displacements[i] = mu + 1U - i;
        }

        /*Rearrange elements*/
        auxx = checked_malloc((len) * sizeof (*auxx));
        memcpy(auxx, B_aux, (len) * sizeof (uint16_t));
        for (i = 1; i < len; ++i) {
            B_aux[i] = auxx[len - i];
        }
        free(auxx);

        /*Duplicate vector to remove need of module operation*/
        /*This code only works for n_bar = 1*/
        memcpy(B_aux + len, B_aux, len * sizeof (uint16_t));
    }

    /*Auxiliary variable to store the results.*/
    auxx = checked_malloc((loop) * sizeof (*auxx));
    memset(auxx, 0, (loop) * sizeof (*X));

    /*Main code to compute X and X'*/
    l = 0;
    i = (uint32_t) (vectors_B - 1);
    j = vectors_R;
    for (idx = 0; idx < loop; ++idx) {
        if (l == params->n) {
            l = 0;
            --j;
            if (j == 0) {
                j = vectors_R;
                --i;
            }
        }
        auxx[idx] = compute_X_idx(B_aux, R_idx, j - 1, i, l, (uint32_t) vectors_B, row_displacements, params, mod_bits);
        l++;
    }

    /* In case of the ring, convert to cyclotomic polynomial*/
    if (params->d == params->n) {
        unlift_poly(X, auxx, mu, mod_mask);
    } else {
        for (i = 0; i < mu; ++i) {
            X[i] = auxx[mu - 1U - i];
        }
    }

    free(row_displacements);
    free(B_aux);
    free(auxx);

    return 0;
}

int compute_X_prime(uint16_t *X, const uint16_t *U, const uint16_t *S_idx, const parameters *params, const uint16_t mod_bits, const uint16_t vectors_U, const uint16_t vectors_S) {
    uint32_t i = 0;
    uint32_t j = 0;
    uint32_t l = 0;
    uint32_t *row_displacements;
    uint16_t mod_mask = (uint16_t) ((1U << mod_bits) - 1);

    uint16_t *U_aux;
    uint16_t *auxx;

    size_t idx = 0;
    uint16_t mu = (uint16_t) (params->ss_size * 8 / params->B);
    uint16_t len = 0;
    uint16_t loop = 0;

    if (params->d != params->n) { /* Non-ring */
        len = params->d;
        loop = mu;

        /*Fake permutation for unity*/
        row_displacements = checked_malloc(len * sizeof (*row_displacements));
        for (i = 0; i < params->d; ++i) {
            row_displacements[i] = i;
        }

        /*Copy to auxiliary vector*/
        U_aux = checked_malloc((size_t) (len * vectors_U) * sizeof (*U));
        memcpy(U_aux, U, (size_t) (len * vectors_U) * sizeof (uint16_t));

    } else { /* Ring */
        loop = (uint16_t) (mu + 1);
        len = (uint16_t) (params->d + 1);

        U_aux = checked_malloc((size_t) (2 * len * vectors_U) * sizeof (*U));
        memcpy(U_aux, U, (size_t) ((len - 1) * vectors_U) * sizeof (uint16_t));

        /*Moved to NTRU ring*/
        lift_poly(U_aux, (size_t) (len - 1), mod_mask);

        /*Compute NTRU permutation adapted to compute the last mu elements of cyclotomic polynomial
          Otherwise, it should be row_displacements[i] = len - i;
         */
        row_displacements = checked_malloc(len * sizeof (*row_displacements));
        row_displacements[0] = (uint32_t) (mu + 1U) % len;
        for (i = 1; i < loop; ++i) {
            row_displacements[i] = mu + 1U - i;
        }

        /*Rearrange elements*/
        auxx = checked_malloc((len) * sizeof (*auxx));
        memcpy(auxx, U_aux, (len) * sizeof (uint16_t));
        for (i = 1; i < len; ++i) {
            U_aux[i] = auxx[len - i];
        }
        free(auxx);

        /*Duplicate vector to remove need of module operation*/
        /*This code only works for n_bar = 1*/
        memcpy(U_aux + len, U_aux, len * sizeof (uint16_t));

    }

    /*Auxiliary variable to store the results.*/
    auxx = checked_malloc((loop) * sizeof (*auxx));
    memset(auxx, 0, (loop) * sizeof (*X));

    /*Main code to compute X and X'*/
    l = 0;
    i = vectors_U;
    j = (uint32_t) (vectors_S - 1);
    for (idx = 0; idx < loop; ++idx) {
        if (l == params->n) {
            l = 0;
            --i;
            if (i == 0) {
                i = vectors_U;
                --j;
            }
        }
        auxx[idx] = compute_X_idx(U_aux, S_idx, j, i - 1, l, (uint32_t) vectors_U, row_displacements, params, mod_bits);
        l++;
    }

    /* In case of the ring, convert to cyclotomic polynomial*/
    if (params->d == params->n) {
        unlift_poly(X, auxx, mu, mod_mask);
    } else {
        for (i = 0; i < mu; ++i) {
            X[i] = auxx[mu - 1U - i];
        }
    }

    free(row_displacements);
    free(U_aux);
    free(auxx);

    return 0;
}

int compress_matrix(uint16_t *matrix, const size_t len, const size_t els, const uint16_t a, const uint16_t b) {
    size_t i;

    for (i = 0; i < len * els; ++i) {
        compress(matrix + i, a, b);
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

