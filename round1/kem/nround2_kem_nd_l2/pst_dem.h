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
 * Declaration of the DEM functions used by the Round2 CCA KEM-based encrypt algorithm.
 *
 * @author Hayo Baan
 */

#ifndef PST_DEM_H
#define PST_DEM_H

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Applies a DEM to the given message using the specified key.
     *
     * @param[out] c2     the encapsulated message
     * @param[out] c2_len the length of the encapsulated message (`m_len` + 16 + 12 bytes)
     * @param[in]  key    the key to use for the encapsulation
     * @param[in]  key_len the length of the key
     * @param[in]  m      the message to encapsulate
     * @param[in]  m_len  the length of the message
     * @return __0__ in case of success
     */
    int round2_dem(unsigned char *c2, unsigned long long *c2_len, const unsigned char *key, const unsigned key_len, const unsigned char *m, const unsigned long long m_len);

    /**
     * Inverses the application of a DEM to a message.
     *
     * @param[out] m       the original message
     * @param[out] m_len   the length of the decapsulated message (`c2_len` - 16 -12)
     * @param[in]  key     the key to use for the encapsulation
     * @param[in]  key_len the length of the key
     * @param[in]  c2      the encapsulated message
     * @param[in]  c2_len  the length of the encapsulated message
     * @return __0__ in case of success
     */
    int round2_dem_inverse(unsigned char *m, unsigned long long *m_len, const unsigned char *key, const unsigned key_len, const unsigned char *c2, unsigned long long c2_len);

#ifdef __cplusplus
}
#endif

#endif /* PST_DEM_H */
