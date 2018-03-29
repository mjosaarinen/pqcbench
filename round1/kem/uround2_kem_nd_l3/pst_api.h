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
 * Defines the additional settings required when using the NIST API. Also
 * declares the function to generate the fixed A matrix.
 *
 * @author: Hayo Baan
 */

#ifndef PST_API_H
#define PST_API_H

#include "api.h"
#include "parameters.h"

#ifndef CRYPTO_CIPHERTEXTBYTES
/** The number of bytes in the cipher text. */
/* We define it as zero if not present, i.e. for the PKE protocol, to be able to simplify the code. */
#define CRYPTO_CIPHERTEXTBYTES 0
#endif

#ifndef ROUND2_VARIANT_A
/** Defines the variant to use for the creation of A when using the NIST API. */
#define ROUND2_VARIANT_A 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Function to generate a fixed A matrix from the given seed.
     *
     * @param[in] seed      the seed to use to generate the fixed A matrix
     * @param[in] seed_size the size of the seed
     * @param[in] params    the algorithm parameters for which the fixed A matrix should be generated
     * @return __0__ in case of success
     */
    /* Note: the function itself is defined in `pst_core.c`! */
    int create_A_fixed(const unsigned char *seed, const uint8_t seed_size, const parameters *params);

#ifdef __cplusplus
}
#endif

#endif /* PST_API_H */

