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
 * Implementation of the encryption functions used within the implementation.
 *
 * @author Jose Luis Torre Arce, Hayo Baan
 * @endcond
 */

#include "pst_encrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "misc.h"
#include "pst_core.h"
#include "pack.h"
#include "randombytes.h"
#include "drng.h"
#include "hash.h"

/*******************************************************************************
 * Private functions
 ******************************************************************************/

/**
 * Add the value of the message to a matrix as described in the algorithm
 *
 * @param[out] result         result of the addition
 * @param[in]  len            length of the result
 * @param[in]  matrix         matrix to which add the message
 * @param[in]  m              message to add
 * @param[in]  bits_coeff     number of bits added in each coefficient
 * @param[in]  scaling_factor scaling factor applied
 * @return __0__ in case of success
 */
static int add_msg(uint16_t *result, const size_t len, const uint16_t *matrix, const unsigned char *m, const uint16_t bits_coeff, const uint8_t scaling_factor) {
    int i;
    uint16_t mask_bits = (uint16_t) ((1 << bits_coeff) - 1);
    int shift = scaling_factor - bits_coeff;

    for (i = 0; i < (int) len; ++i) {
        int idx_bit = bits_coeff * i;
        int shift_bits = idx_bit % 8;
        int idx_bytes = idx_bit / 8;
        uint16_t m_chunk = (uint16_t) ((m[idx_bytes] >> shift_bits) &
                mask_bits);

        result[i] = (uint16_t) (matrix[i] + (m_chunk << shift));
    }

    return 0;
}

/**
 * Compute the difference of the first len values matrix_a - matrix_b
 *
 * @param[out] result         difference
 * @param[in]  len            length of the result
 * @param[in]  matrix_a       first operand
 * @param[in]  matrix_b       second operand
 * @return __0__ in case of success
 */
static int diff_msg(uint16_t *result, const size_t len, const uint16_t *matrix_a, const uint16_t *matrix_b) {
    size_t i;

    for (i = 0; i < len; ++i) {
        result[i] = (uint16_t) (matrix_a[i] - matrix_b[i]);
    }

    return 0;
}

/**
 * Convert a message from Z^len_(2^bits_per_elemen) to a bitstring
 *
 * @param[out] m                message in bitstring format
 * @param[in]  msg_int          message in integer format
 * @param[in]  msg_int_len      length of the message in integer format
 * @param[in]  bits_per_element number of bits per symbol in integer format
 * @return number of bytes of the message in bitstring format
 */
static int msg_to_bitstring(unsigned char *m, const uint16_t *msg_int, const size_t msg_int_len, const int16_t bits_per_element) {
    int idx_bytes;
    size_t i;
    size_t msg_len = BITS_TO_BYTES(msg_int_len * (size_t) bits_per_element);

    memset(m, 0, msg_len * sizeof (*m));

    for (i = 0; i < msg_int_len; ++i) {
        int idx_bit = bits_per_element * (int) i;
        int shift = idx_bit % 8;
        idx_bytes = idx_bit / 8;

        m[idx_bytes] = (unsigned char) (m[idx_bytes] | (msg_int[i] << shift));
    }

    return ++idx_bytes;
}

/**
 * Compute the size of A from the value of fn.
 *
 * @param[in] fn     value of fn
 * @param[in] params algorithm parameters in use
 * @return number of elements in A
 */
static size_t compute_len_a(uint8_t fn, const parameters *params) {
    size_t len_a;
    switch (fn) {
        case 0:
            len_a = (size_t) (params->d * params->d);
            break;
        case 1:
            len_a = 2 * (size_t) (params->d * params->d);
            break;
        case 2:
            len_a = (size_t) (params->q + params->d);
            break;
        case 3:
            len_a = 2 * (size_t) (params->d + 1);
            break;
        default:
            fprintf(stderr, "Error: Wrong fn value.\n");
            exit(EXIT_FAILURE);
    }

    return len_a;
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int generate_keypair(unsigned char *pk, unsigned char *sk, const parameters *params, uint8_t fn) {
    unsigned char *sigma;
    uint16_t *A;
    uint32_t *A_permutation;
    uint16_t *S_idx;
    int16_t *S_T;
    uint16_t *B;
    size_t len_a;
    size_t len_s_idx;
    size_t len_s;
    size_t len_b;

    fn = (params->d == params->n) ? 3 : fn;
    /* Calculate sizes */
    /* Size of A depends on fn */
    len_a = compute_len_a(fn, params);
    len_s_idx = (size_t) (params->h * params->n_bar);
    len_s = (size_t) (params->k * params->n_bar * params->n);
    len_b = (size_t) (params->k * params->n_bar * params->n);

    /* Allocate space */
    sigma = checked_malloc(params->ss_size);
    A = checked_malloc(len_a * sizeof (*A));
    A_permutation = checked_malloc((size_t) (params->d + 1) * sizeof (*A_permutation));
    S_idx = checked_malloc(len_s_idx * sizeof (*S_idx));
    S_T = checked_malloc(len_s * sizeof (*S_T));
    B = checked_malloc(len_b * sizeof (*B));

    /* Generate seed sigma */
    randombytes(sigma, params->ss_size);

    /* Create A from sigma */
    create_A(A, A_permutation, fn, sigma, params);

    /* Randomly generate S_T */
    create_S(S_T, S_idx, params);

    compute_B(B, A, A_permutation, S_idx, params);

    /* Compress B q_bits -> p_bits */
    compress_matrix(B, (size_t) (params->k * params->n_bar), params->n, params->q_bits, params->p_bits);

    /* Serializing and packing */
    pack_pk(pk, fn, sigma, params->ss_size, B, len_b, params->p_bits);
    pack_sk(sk, S_T, len_s);

#if defined(ROUND2_INTERMEDIATE) || defined(DEBUG)
    print_hex("generate_keypair: sigma", sigma, params->ss_size, 1);
#ifdef DEBUG
    printf("generate_keypair: fn=%hhu\n", fn);
    print_sage_u_vector_matrix("generate_keypair: A", A, params->k, params->k, params->n);
    print_sage_u_vector_matrix("generate_keypair: B", B, params->k, params->n_bar, params->n);
    print_sage_s_vector_matrix("generate_keypair: S_T", S_T, params->n_bar, params->k, params->n);
#endif
#endif

    free(sigma);
    free(A);
    free(A_permutation);
    free(S_idx);
    free(S_T);
    free(B);

    return 0;
}

int encrypt(unsigned char *c, const unsigned char *m, const unsigned char *pk, const parameters *params) {
    unsigned char *rho = checked_malloc(params->ss_size);

    /* Randomly generate rho */
    randombytes(rho, params->ss_size);

    encrypt_rho(c, m, rho, pk, params);

    return 0;
}

int encrypt_rho(unsigned char *c, const unsigned char *m, const unsigned char *rho, const unsigned char *pk, const parameters *params) {
    /* Seeds */
    unsigned char *sigma;

    /* Matrices */
    uint16_t *A;
    uint32_t *A_permutation;
    uint16_t *R_idx;
    uint16_t *U;
    uint16_t *B;
    uint16_t *X;
    uint16_t *v;

    /* Length of matrices */
    size_t len_a;
    size_t len_r_idx;
    size_t len_u;
    size_t len_b;
    size_t len_x;
    size_t len_v;
    size_t mu;

    /* fn */
    uint8_t fn;

    /* B is divisor of 8! */
    mu = (size_t) (params->ss_size * 8 / params->B);

    len_r_idx = (size_t) (params->h * params->m_bar);
    len_u = (size_t) (params->m_bar * params->d);
    len_b = (size_t) (params->d * params->n_bar);
    len_x = (size_t) (params->n_bar * params->m_bar * params->n);
    len_v = mu;

    sigma = checked_malloc(params->ss_size);
    B = checked_malloc(len_b * sizeof (*B));
    R_idx = checked_malloc(len_r_idx * sizeof (*R_idx));
    U = checked_malloc(len_u * sizeof (*U));
    X = checked_malloc(len_x * sizeof (*X));
    v = checked_malloc(len_v * sizeof (*v));

    /* Unpack received public key into fn, sigma and B */
    unpack_pk(&fn, sigma, B, pk, params->ss_size, len_b, params->p_bits);
    fn = (params->d == params->n) ? 3 : fn;

    len_a = compute_len_a(fn, params);
    A = checked_malloc(len_a * sizeof (*A));
    A_permutation = checked_malloc((size_t) (params->d + 1) * sizeof (*A_permutation));

    /* Create A from sigma */
    create_A(A, A_permutation, fn, sigma, params);
    /* Create R_idx from rho */
    create_R(R_idx, rho, params);

    /* U = A^T * R */
    if (params->d == params->n) {
        compute_B(U, A, A_permutation, R_idx, params);
    } else {
        compute_U(U, A, A_permutation, R_idx, params);
    }

    /* Compress U q_bits -> p_bits */
    compress_matrix(U, (size_t) (params->k * params->m_bar), params->n, params->q_bits, params->p_bits);

    compute_X(X, B, R_idx, params, params->p_bits, params->n_bar, params->m_bar);

    /* v is a matrix of scalars, so we use 1 as the number of coefficients */
    compress_matrix(X, mu, 1, params->p_bits, params->t_bits);

    /* Add message */
    add_msg(v, len_v, X, m, params->B, params->t_bits);

#if defined(ROUND2_INTERMEDIATE) || defined(DEBUG)
    print_hex("encrypt_rho: rho", rho, params->ss_size, 1);
#ifdef DEBUG
    print_hex("encrypt_rho: sigma", sigma, params->ss_size, 1);
    print_hex("encrypt_rho: eu_seed", eu_seed, params->ss_size, 1);
    print_hex("encrypt_rho: ex_seed", ex_seed, params->ss_size, 1);
    print_sage_u_vector_matrix("encrypt_rho: A", A, params->k, params->k, params->n);
    print_sage_u_vector_matrix("encrypt_rho: B", B, params->k, params->n_bar, params->n);
    print_sage_u_vector_matrix("encrypt_rho: U", U, params->k, params->m_bar, params->n);
    print_sage_u_vector_matrix("encrypt_rho: X", X, params->n_bar, params->m_bar, params->n);
#endif
    print_sage_u_vector("encrypt_rho: v", v, mu);
#endif

    /* Pack ciphertext */
    pack_ct(c, U, len_u, params->p_bits, v, mu, params->t_bits);

    free(sigma);
    free(A);
    free(A_permutation);
    free(R_idx);
    free(U);
    free(B);
    free(X);
    free(v);

    return 0;
}

int decrypt(unsigned char *m, const unsigned char *c, const unsigned char *sk, const parameters *params) {
    /* Matrices */
    int16_t *S_T;
    uint16_t *S_idx;
    uint16_t *U;
    uint16_t *v;
    uint16_t *tmp;
    uint16_t *msg_tmp;
    /* Length of matrices */
    size_t len_s;
    size_t len_s_idx;
    size_t len_u;
    size_t len_v;
    size_t len_tmp;
    size_t mu;

    len_s = (size_t) (params->d * params->n_bar);
    len_s_idx = (size_t) (params->h * params->n_bar);
    len_u = (size_t) (params->d * params->m_bar);
    len_tmp = (size_t) (params->n_bar * params->m_bar * params->n);
    mu = (size_t) (params->ss_size * 8 / params->B);
    len_v = mu;

    S_T = checked_malloc(len_s * sizeof (*S_T));
    S_idx = checked_malloc(len_s_idx * sizeof (*S_idx));
    U = checked_malloc(len_u * sizeof (*U));
    v = checked_malloc(len_v * sizeof (*v));
    tmp = checked_malloc(len_tmp * sizeof (*tmp));
    msg_tmp = checked_malloc(mu * sizeof (*msg_tmp));

    unpack_sk(S_T, sk, len_s);
    unpack_ct(U, v, c, len_u, params->p_bits, len_v, params->t_bits);

    transform_to_index(S_idx, S_T, params->n_bar, params);

    /* Decompress v t_bits -> p_bits */
    decompress_matrix(v, len_v, 1, params->p_bits, params->t_bits);
    compute_X_prime(tmp, U, S_idx, params, params->p_bits, params->m_bar, params->n_bar);

#if defined(ROUND2_INTERMEDIATE) || defined(DEBUG)
    print_sage_u_vector("decrypt: v", v, mu);
#ifdef DEBUG
    print_sage_s_vector_matrix("decrypt: S_T", S_T, params->n_bar, params->k, params->n);
    print_sage_u_vector_matrix("decrypt: U", U, params->k, params->m_bar, params->n);
    print_sage_u_vector_matrix("decrypt: tmp", tmp, params->n_bar, params->m_bar, params->n);
#endif
#endif

    /* v - Sample_mu(S^T * U) */
    diff_msg(msg_tmp, mu, v, tmp);
    /* Compress msg_tmp p_bits -> B */
    compress_matrix(msg_tmp, mu, 1, params->p_bits, params->B);

    /* Convert the message to bitstring format */
    msg_to_bitstring(m, msg_tmp, mu, params->B);

    free(S_T);
    free(S_idx);
    free(U);
    free(v);
    free(tmp);
    free(msg_tmp);

    return 0;
}
