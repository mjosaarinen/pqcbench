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
 * Implementation of the parameters, structure, and functions.
 *
 * @author Jose Luis Torre Arce, Hayo Baan
 * @endcond
 */

#include "parameters.h"

#include <stdio.h>
#include <stdlib.h>

#include "pst_api.h"
#include "api_to_internal_parameters.h"
#include "misc.h"

/*******************************************************************************
 * Private functions
 ******************************************************************************/

int check_parameters(const parameters *params) {
    /* n must be either d or 1 and both must be > 0*/
    if (params->n == 0 || params->d == 0 || !(params->n == params->d || params->n == 1)) {
        fprintf(stderr, "Error: Incorrect parameters. ");
        fprintf(stderr, "n and d must be non zero and n must be equal to d or 1.\n");
        fprintf(stderr, "n=%u, d=%u\n", params->n, params->d);
        return 1;
    }
    /* Hamming weight must be even, > 0, and < d */
    if (params->h == 0 || params->h > params->d || params->h & 1) {
        fprintf(stderr, "Error: Incorrect parameter. ");
        fprintf(stderr, "Hamming weight h must be even, greater than, 0, and smaller than d.\n");
        fprintf(stderr, "h=%u, d=%u\n", params->h, params->d);
        return 2;
    }
    /* p, q, and t must be > 0 */
    /* p must be < q */
    /* t must be < p */
    if (params->q == 0 || params->p_bits == 0 || params->t_bits == 0 || (1 << params->p_bits) >= params->q || params->t_bits >= params->p_bits) {
        fprintf(stderr, "Error: Incorrect parameters. ");
        fprintf(stderr, "2^p_bits must be smaller than q, t_bits must be less than p_bits\n");
        fprintf(stderr, "p_bits=%u, q=%u, 2^pbits=%u, t_bits=%u\n", params->p_bits, params->q, (1 << params->p_bits), params->t_bits);
        return 3;
    }
    /* Dimensions must be > 0 */
    if (params->n_bar == 0 || params->m_bar == 0) {
        fprintf(stderr, "Error: Incorrect parameters. ");
        fprintf(stderr, "Dimensions n_bar and m_bar must be greater than 0.\n");
        fprintf(stderr, "n_bar=%u, m_bar=%u\n", params->n_bar, params->m_bar);
        return 4;
    }
    /* B must be > 0 and B must be < p */
    if (params->B == 0 || params->B >= params->p_bits || 8 % params->B) {
        fprintf(stderr, "Error: Incorrect parameter. ");
        fprintf(stderr, "B must be greater than 0, smaller than p_bits, and a divisor of 8.\n");
        fprintf(stderr, "B=%u\n", params->B);
        return 5;
    }
    /* Seed size must be > 0 */
    if (params->ss_size == 0) {
        fprintf(stderr, "Error: Incorrect parameter. ");
        fprintf(stderr, "Seed size must be greater than 0\n");
        fprintf(stderr, "ss_size=%u\n", params->ss_size);
        return 6;
    }

    return 0;
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/

int set_parameters_from_api(parameters *params) {
    const size_t nr_param_sets = sizeof (api_to_internal_parameters) / sizeof (api_to_internal_parameters[0]);
    size_t param_set;
    int err;

    /* Algorithm parameters */
    uint8_t ss_size;
    uint16_t d;
    uint16_t n;
    uint16_t h;
    uint16_t q;
    uint8_t p_bits;
    uint8_t t_bits;
    uint16_t n_bar;
    uint16_t m_bar;
    uint8_t B;

    for (param_set = 0; param_set < nr_param_sets; ++param_set) {
        if (api_to_internal_parameters[param_set][API_SECRET] == CRYPTO_SECRETKEYBYTES &&
                api_to_internal_parameters[param_set][API_PUBLIC] == CRYPTO_PUBLICKEYBYTES &&
                api_to_internal_parameters[param_set][API_CIPHER] == CRYPTO_CIPHERTEXTBYTES &&
                api_to_internal_parameters[param_set][API_BYTES] == CRYPTO_BYTES) {
            break;
        }
    }

    if (param_set >= nr_param_sets) {
        fprintf(stderr, "Error: Unsupported set of API parameters\n");
        return 1;
    } else {
        ss_size = (uint8_t) api_to_internal_parameters[param_set][POS_SS];
        d = (uint16_t) api_to_internal_parameters[param_set][POS_D];
        n = (uint16_t) api_to_internal_parameters[param_set][POS_N];
        h = (uint16_t) api_to_internal_parameters[param_set][POS_H];
        q = (uint16_t) api_to_internal_parameters[param_set][POS_Q];
        p_bits = (uint8_t) api_to_internal_parameters[param_set][POS_P_BITS];
        t_bits = (uint8_t) api_to_internal_parameters[param_set][POS_T_BITS];
        n_bar = (uint16_t) api_to_internal_parameters[param_set][POS_N_BAR];
        m_bar = (uint16_t) api_to_internal_parameters[param_set][POS_M_BAR];
        B = (uint8_t) api_to_internal_parameters[param_set][POS_B];
    }

    err = set_parameters(params, ss_size, d, n, h, q, p_bits, t_bits, n_bar, m_bar, B);
    if (!err) {
        /* Sanity check of derived NIST parameters */
        const int is_cca = (CRYPTO_SECRETKEYBYTES == params->sk_size + params->ss_size + params->pk_size || CRYPTO_CIPHERTEXTBYTES == params->ct_size + params->ss_size);
        const int is_encrypt = CRYPTO_CIPHERTEXTBYTES == 0;
        if (is_cca || is_encrypt) {
            if (CRYPTO_SECRETKEYBYTES != params->sk_size + params->ss_size + params->pk_size) {
                fprintf(stderr, "NIST parameters do not match: CRYPTO_SECRETKEYBYTES(%u) != sk_size(%u) + ss_size(%u) + pk_size(%u) = %u\n",
                        CRYPTO_SECRETKEYBYTES, params->sk_size, params->ss_size, params->pk_size, params->sk_size + params->ss_size + params->pk_size);
                err += 2;
            }
        } else if (CRYPTO_SECRETKEYBYTES != params->sk_size) {
            fprintf(stderr, "NIST parameters do not match: CRYPTO_SECRETKEYBYTES(%u) != sk_size(%u)\n", CRYPTO_SECRETKEYBYTES, params->sk_size);
            err += 2;
        }
        if (CRYPTO_PUBLICKEYBYTES != params->pk_size) {
            fprintf(stderr, "NIST parameters do not match: CRYPTO_PUBLICKEYBYTES(%u) != pk_size(%u)\n", CRYPTO_PUBLICKEYBYTES, params->pk_size);
            err += 4;
        }
        if (is_encrypt) {
            if (CRYPTO_BYTES != params->ct_size + params->ss_size + 16 + 12) {
                fprintf(stderr, "NIST parameters do not match: CRYPTO_BYTES(%u) != ct_size(%u) + ss_size(%u) + 16 + 12 = %u\n",
                        CRYPTO_BYTES, params->ct_size, params->ss_size, params->ct_size + params->ss_size + 16 + 12);
                err += 16;
            }
        } else {
            if (is_cca) {
                if (CRYPTO_CIPHERTEXTBYTES != params->ct_size + params->ss_size) {
                    fprintf(stderr, "NIST parameters do not match: CRYPTO_CIPHERTEXTBYTES(%u) != ct_size(%u) + ss_size(%u) = %u\n",
                            CRYPTO_CIPHERTEXTBYTES, params->ct_size, params->ss_size, params->ct_size + params->ss_size);
                    err += 8;
                }
            } else if (params->ct_size != CRYPTO_CIPHERTEXTBYTES) {
                fprintf(stderr, "NIST parameters do not match: CRYPTO_CIPHERTEXTBYTES(%u) != ct_size(%u)\n", CRYPTO_CIPHERTEXTBYTES, params->ct_size);
                params->ct_size = CRYPTO_CIPHERTEXTBYTES;
                err += 8;
            }
            if (params->ss_size != CRYPTO_BYTES) {
                fprintf(stderr, "NIST parameters do not match: CRYPTO_BYTES(%u) != ss_size(%u)\n", CRYPTO_BYTES, params->ss_size);
                err += 16;
            }
        }
    }
    return err;
}

int set_parameters(parameters *params, const uint8_t ss_size, const uint16_t d, const uint16_t n, const uint16_t h, const uint16_t q, const uint8_t p_bits, const uint8_t t_bits, const uint16_t n_bar, const uint16_t m_bar, const uint8_t B) {
    uint16_t tmp_q = q;
    uint8_t tmp_bits = 0;
    params->ss_size = ss_size;
    params->d = d;
    params->n = n;
    params->h = h;
    params->q = q;
    params->p_bits = p_bits;
    params->t_bits = t_bits;
    params->n_bar = n_bar;
    params->m_bar = m_bar;
    params->B = B;

    /* Derived parameters */
    params->k = (uint16_t) (n ? d / n : 0); /* Avoid arithmetic exception if n = 0 */
    /* Determine log2 of q, but only if q is an exact power of two */
    while (!(tmp_q & 1) && (tmp_q >>= 1)) {
        ++tmp_bits;
    }
    if (tmp_q == 1) {
        params->q_bits = tmp_bits;
    } else {
        params->q_bits = 0;
    }
    params->p = (uint16_t) (1U << p_bits);

    /* Message sizes */
    params->sk_size = (uint16_t) BITS_TO_BYTES(d * n_bar * 2);
    params->pk_size = (uint16_t) (1 + ss_size + BITS_TO_BYTES(d * n_bar * p_bits));
    params->ct_size = (uint16_t) (B ? BITS_TO_BYTES(d * m_bar * p_bits) + (ss_size * t_bits / B) : 0); /* Avoid arithmetic exception if B = 0 */

    return check_parameters(params);
}
