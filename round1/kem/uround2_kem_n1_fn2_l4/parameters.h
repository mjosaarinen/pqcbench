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
 * Declaration of the algorithm parameters, structure, and functions.
 *
 * @author Jose Luis Torre Arce, Hayo Baan
 */

#ifndef PARAMETERS_H
#define PARAMETERS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Algorithm parameters.
     */
    typedef struct {
        /** @name Main Parameters
         *
         * These parameters define the working of the algorithm.
         * For a reference of their meaning, please see the algorithm
         * documentation.
         *@{*/
        uint8_t ss_size; /**< The size of shared secret, in bytes (API: `CRYPTO_BYTES`) */
        uint16_t d; /**< Dimension parameter __d__ */
        uint16_t n; /**< Dimension parameter __n__ */
        uint16_t h; /**< Hamming weight parameter __h__ */
        uint16_t q; /**< Parameter __q__ */
        uint8_t p_bits; /**< Number of __p__ bits */
        uint8_t t_bits; /**< Number of __t__ bits */
        uint16_t n_bar; /**< Dimension parameter __n̅__ */
        uint16_t m_bar; /**< Dimension parameter __m̅__ */
        uint8_t B; /**< Number of shared bits, parameter __B__ */
        /**@}*/
        /** @name Derived Parameters
         *
         * These parameters can be derived from the main parameters.
         *@{*/
        uint16_t k; /**< Dimension parameter __k__ = _d/n_ */
        uint8_t q_bits; /**< The number of __q__ bits (zero if __q__ is not a power of 2) */
        uint16_t p; /**< Parameter __p__ = _2<sup>p<sub>bits</sub></sup>_ */
        /** @name Derived NIST Parameters
         *
         * These parameters can be derived from the main parameters, or,
         * when using the NIST API macro definitions, the other way around.
         * 
         * Note that for the ENCRYPT (CCA KEM) type functions, the total size of
         * the “secret key” is actually `sk_size` + `ss_size` + `pk_size`, and
         * the total size of the “cipher text” is actually `ct_size` +
         * `ss_size`. The sizes of the API parameters already include the
         * additional bytes so these _are_ the actual sizes.
         *@{*/
        uint16_t sk_size; /**< Size of the secret key, in bytes (API:`CRYPTO_SECRETKEYBYTES`) */
        uint16_t pk_size; /**< Size of the public key, in bytes (API:`CRYPTO_PUBLICKEYBYTES`) */
        uint16_t ct_size; /**< Size of the cipher text, in bytes (API:`CRYPTO_CIPHERTEXTBYTES`) */
        /**@}*/
    } parameters;

    /**
     * Checks the parameters that have been set.
     *
     * @param[in] params the algorithm parameters to check
     * @return __0__ if everything is correct, error code otherwise
     */
    int check_parameters(const parameters *params);

    /**
     * Sets the algorithm parameters according to the values from the (NIST) API setting macros in `api.h`.
     *
     * @param[out] params the algorithm parameters set up according to `api.h`
     * @return __0__ if successful, error code otherwise
     */
    int set_parameters_from_api(parameters *params);

    /**
     * Set the algorithm parameters as specified.
     *
     * @param[out] params the algorithm parameters set up as specified
     * @param[in] ss_size the size of the shared secret, in bytes
     * @param[in] d dimension parameter __d__
     * @param[in] n dimension parameter __n__
     * @param[in] h hamming weight parameter __h__
     * @param[in] q parameter __q__
     * @param[in] p_bits the number of bit of parameter __p__, __p__ is defined as _2<sup>p<sub>bits</sub></sup>_
     * @param[in] t_bits number of bits per element in ciphertext
     * @param[in] n_bar dimension parameter __n̅__
     * @param[in] m_bar dimension parameter __m̅__
     * @param[in] B number of shared bits, parameter __B__
     *
     * @return __0__ if successful, error code otherwise
     */
    int set_parameters(parameters *params, const uint8_t ss_size, const uint16_t d, const uint16_t n, const uint16_t h, const uint16_t q, const uint8_t p_bits, const uint8_t t_bits, const uint16_t n_bar, const uint16_t m_bar, const uint8_t B);

#ifdef __cplusplus
}
#endif

#endif /* PARAMETERS_H */
