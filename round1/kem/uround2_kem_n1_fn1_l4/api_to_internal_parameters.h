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
 * Provides the mappings from the (NIST) API algorithm parameters
 * `CRYPTO_SECRETKEYBYTES`, `CRYPTO_PUBLICKEYBYTES`, `CRYPTO_BYTES`, and
 * `CRYPTO_CIPHERBYTES` to the internal algorithm parameters.
 *
 * @author Jose Luis Torre Arce, Hayo Baan
 * @endcond
 */

#ifndef API_TO_INTERNAL_PARAMETERS_H
#define API_TO_INTERNAL_PARAMETERS_H

/* Positions of the (NIST) API parameters */

/** The location of API parameter `CRYPTO_SECRETKEYBYTES` in the parameter set.  */
#define API_SECRET   0
/** The location of API parameter `CRYPTO_PUBLICKEYBYTES` in the parameter set.  */
#define API_PUBLIC   1
/** The location of API parameter `CRYPTO_BYTES` in the parameter set (also equals the `ss_size` algorithm parameter). */
#define API_BYTES    2
/** The location of API parameter `CRYPTO_CIPHERETEXTBYTES` in the parameter set.  */
#define API_CIPHER   3

/* Positions of our internal parameters */

/** The location of algorithm parameter `ss_size` in the parameter set */
#define POS_SS       4
/** The location of algorithm parameter `d` in the parameter set */
#define POS_D        5
/** The location of algorithm parameter `n` in the parameter set */
#define POS_N        6
/** The location of algorithm parameter `h` in the parameter set */
#define POS_H        7
/** The location of algorithm parameter `q` in the parameter set */
#define POS_Q        8
/** The location of algorithm parameter `p_bits` in the parameter set */
#define POS_P_BITS   9
/** The location of algorithm parameter `t_bits` in the parameter set */
#define POS_T_BITS  10
/** The location of algorithm parameter `n_bar` in the parameter set */
#define POS_N_BAR   11
/** The location of algorithm parameter `m_bar` in the parameter set */
#define POS_M_BAR   12
/** The location of algorithm parameter `B` in the parameter set */
#define POS_B       13

#ifdef __cplusplus
extern "C" {
#endif

    /** Mapping from the API parameters to our internal parameters */
    static uint16_t api_to_internal_parameters[][14] = {
        /* SK, PK, SS, CT, SS, D, N, H, Q, #P, #T, _N, _M, B */

        /* uround2_kem_n1 */
        {625, 3455, 16, 4837, 16, 500, 1, 74, 16384, 11, 6, 5, 7, 4}, /* NIST1: 128, 64 */
        {1160, 6413, 32, 6428, 32, 580, 1, 116, 32768, 11, 6, 8, 8, 4}, /* NIST2: 256, 86 */
        {945, 5223, 24, 6972, 24, 630, 1, 126, 32768, 11, 7, 6, 8, 4}, /* NIST3: 192, 96 */
        {1965, 10857, 48, 10904, 48, 786, 1, 156, 32768, 11, 8, 10, 10, 4}, /* NIST4: 384, 128 */
        {1572, 8679, 32, 8710, 32, 786, 1, 156, 32768, 11, 8, 8, 8, 4}, /* NIST5: 256, 128 */

        /* uround2_pke_n1 */
        {4096, 3455, 4881, 0, 16, 500, 1, 74, 32768, 11, 6, 5, 7, 4}, /* NIST1: 128, 64 */
        {7670, 6468, 6567, 0, 32, 585, 1, 110, 32768, 11, 9, 8, 8, 4}, /* NIST2: 256, 86 */
        {6319, 5330, 7185, 0, 24, 643, 1, 114, 32768, 11, 10, 6, 8, 4}, /* NIST3: 192, 96 */
        {14710, 12574, 12673, 0, 48, 835, 1, 166, 32768, 12, 6, 10, 10, 4}, /* NIST4: 384, 128 */
        {11755, 10053, 10128, 0, 32, 835, 1, 166, 32768, 12, 6, 8, 8, 4}, /* NIST5: 256, 128 */

        /* uround2_kem_nd */
        {105, 435, 16, 482, 16, 418, 418, 66, 4096, 8, 4, 1, 1, 1}, /* NIST1: 128, 64 */
        {131, 555, 32, 618, 32, 522, 522, 78, 32768, 8, 3, 1, 1, 1}, /* NIST2: 256, 86 */
        {135, 565, 24, 636, 24, 540, 540, 96, 16384, 8, 4, 1, 1, 1}, /* NIST3: 192, 96 */
        {175, 749, 48, 940, 48, 700, 700, 112, 32768, 8, 5, 1, 1, 1}, /* NIST4: 384, 128 */
        {169, 709, 32, 868, 32, 676, 676, 120, 32768, 8, 6, 1, 1, 1}, /* NIST5: 256, 128 */

        /* uround2_pke_nd */
        {558, 437, 560, 0, 16, 420, 420, 62, 1024, 8, 6, 1, 1, 1}, /* NIST1: 128, 64 */
        {808, 641, 764, 0, 32, 540, 540, 96, 8192, 9, 3, 1, 1, 1}, /* NIST2: 256, 86 */
        {856, 685, 784, 0, 24, 586, 586, 104, 8192, 9, 3, 1, 1, 1}, /* NIST3: 192, 96 */
        {1071, 846, 1017, 0, 48, 708, 708, 140, 32768, 9, 3, 1, 1, 1}, /* NIST4: 384, 128 */
        {1039, 830, 953, 0, 32, 708, 708, 140, 32768, 9, 3, 1, 1, 1}, /* NIST5: 256, 128 */

        /* nround2_kem_nd */
        {100, 417, 16, 464, 16, 400, 400, 72, 3209, 8, 4, 1, 1, 1}, /* NIST1: 128, 64 */
        {122, 519, 32, 614, 32, 486, 486, 96, 1949, 8, 4, 1, 1, 1}, /* NIST2: 256, 86 */
        {139, 581, 24, 652, 24, 556, 556, 88, 3343, 8, 4, 1, 1, 1}, /* NIST3: 192, 96 */
        {165, 707, 48, 898, 48, 658, 658, 130, 1319, 8, 5, 1, 1, 1}, /* NIST4: 384, 128 */
        {165, 691, 32, 818, 32, 658, 658, 130, 1319, 8, 5, 1, 1, 1}, /* NIST5: 256, 128 */

        /* nround2_pke_nd */
        {642, 515, 622, 0, 16, 442, 442, 74, 2659, 9, 5, 1, 1, 1}, /* NIST1: 128, 64 */
        {830, 659, 846, 0, 32, 556, 556, 88, 3343, 9, 5, 1, 1, 1}, /* NIST2: 256, 86 */
        {841, 673, 820, 0, 24, 576, 576, 108, 2309, 9, 5, 1, 1, 1}, /* NIST3: 192, 96 */
        {1071, 846, 1113, 0, 48, 708, 708, 140, 2837, 9, 5, 1, 1, 1}, /* NIST4: 384, 128 */
        {1039, 830, 1017, 0, 32, 708, 708, 140, 2837, 9, 5, 1, 1, 1}, /* NIST5: 256, 128 */

    };

#ifdef __cplusplus
}
#endif

#endif /* API_TO_INTERNAL_PARAMETERS_H */
