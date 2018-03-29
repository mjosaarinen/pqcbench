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
 * Implementation of the various pack and unpack functions.
 *
 * @author Jose Luis Torre Arce, Hayo Baan
 * @endcond
 */

#include "pack.h"

#include <string.h>
#include "misc.h"

/*******************************************************************************
 * Private functions
 ******************************************************************************/

/**
 * Packs the given vector using the specified number of bits per element.
 *
 * @param[out] packed  the buffer for the packed vector
 * @param[in]  m       the vector to pack
 * @param[in]  els     the number of elements
 * @param[in]  nr_bits the number of significant bits value
 * @return the length of the packed vector in bytes
 */
static size_t pack(unsigned char *packed, const uint16_t *m, size_t els, uint8_t nr_bits) {
    const size_t packed_len = (size_t) (BITS_TO_BYTES(els * nr_bits));
    const uint8_t val_size = (uint8_t) (8 * sizeof (uint16_t));
    size_t idx = 0;
    size_t packed_idx = 0;
    uint8_t filled_bits = 0;
    uint8_t remaining_bits;
    size_t i;
    uint16_t val;
    uint16_t bits;

    memset(packed, 0, packed_len);
    for (i = 0; i < els; ++i) {
        val = m[idx];
        remaining_bits = nr_bits;
        while (remaining_bits > 0) {
            /* Move the bits to use of val to correct position */
            bits = (uint16_t) (val << (val_size - remaining_bits));
            bits = (uint16_t) (bits >> (val_size - 8 + filled_bits));
            packed[packed_idx] = (unsigned char) (packed[packed_idx] | bits);
            if (remaining_bits >= (8 - filled_bits)) {
                remaining_bits = (uint8_t) (remaining_bits - (8 - filled_bits));
                ++packed_idx;
                filled_bits = 0;
            } else {
                filled_bits = (uint8_t) (filled_bits + remaining_bits);
                remaining_bits = 0;
            }
        }
        ++idx;
    }

    return packed_len;
}

/**
 * Unpacks the given vector using the specified number of bits per element.
 *
 * @param[in]  m       unpacked vector
 * @param[in]  packed  the packed vector
 * @param[in]  els     number of elements
 * @param[in]  nr_bits number of significant bits per element
 * @return total number of packed bytes processed
 */
static size_t unpack(uint16_t *m, const unsigned char *packed, const size_t els, const uint8_t nr_bits) {
    const size_t unpacked_len = (size_t) (BITS_TO_BYTES(els * nr_bits));
    size_t idx = 0;
    size_t packed_idx = 0;
    uint8_t used_bits = 0;
    uint8_t remaining_bits;
    unsigned char val;
    unsigned char bits;

    val = packed[packed_idx];
    memset(m, 0, els * sizeof (uint16_t));
    for (idx = 0; idx < els; ++idx) {
        remaining_bits = nr_bits;
        while (remaining_bits > 0) {
            /* Move the bits to use from packed val to correct position */
            bits = (unsigned char) (val << used_bits);
            if (remaining_bits <= (8 - used_bits)) {
                bits = (unsigned char) (bits >> (8 - remaining_bits));
                m[idx] = (uint16_t) (m[idx] << remaining_bits);
                used_bits = (uint8_t) (used_bits + remaining_bits);
                remaining_bits = 0;
            } else {
                bits = (unsigned char) (bits >> used_bits);
                m[idx] = (uint16_t) (m[idx] << (8 - used_bits));
                remaining_bits = (uint8_t) (remaining_bits - (8 - used_bits));
                used_bits = 8;
            }
            m[idx] = (uint16_t) (m[idx] | bits);
            if (used_bits == 8) {
                used_bits = 0;
                val = packed[++packed_idx];
            }
        }
    }

    return unpacked_len;
}

/**
 * Pack a sparse ternary vector.
 *
 * @param[out] packed  the buffer for the packed vector
 * @param[in]  m       vector to pack
 * @param[in]  els     number of elements
 * @return length of the packed vector in bytes
 */
static size_t pack_sptervec(unsigned char *packed, const int16_t *m, size_t els) {
    const size_t packed_len = (size_t) (BITS_TO_BYTES(els * 2));
    size_t i;
    size_t packed_idx;
    uint8_t val;
    size_t shift;

    memset(packed, 0, packed_len);

    for (i = 0; i < els; ++i) {
        val = (m[i] + 1) & 0x3;
        shift = ((i % 4) * 2);
        packed_idx = i / 4;
        packed[packed_idx] = (unsigned char) (packed[packed_idx] | (val << shift));
    }

    return packed_len;
}

/**
 * Pack a sparse ternary vector.
 *
 * @param[out] packed  the buffer for the packed vector
 * @param[in]  m       vector to pack
 * @param[in]  els     number of elements
 * @return processed bytes
 */
static size_t unpack_sptervec(int16_t *m, const unsigned char *packed, size_t els) {
    size_t i;
    size_t packed_idx = 0;

    for (i = 0; i < els; ++i) {
        size_t shift = ((i % 4) * 2);
        packed_idx = i / 4;
        m[i] = (int16_t) (((packed[packed_idx] >> shift) & 0x3) - 1);
    }

    return packed_idx;
}

/*******************************************************************************
 * Public functions
 ******************************************************************************/

size_t pack_pk(unsigned char *packed_pk, const uint8_t fn, const unsigned char *sigma, size_t sigma_len, const uint16_t *B, size_t elements, uint8_t nr_bits) {
    size_t packed_idx = 0;
    
    /* Pack fn */
    packed_pk[packed_idx++] = fn;
    /* Pack sigma */
    memcpy(packed_pk + packed_idx, sigma, sigma_len);
    packed_idx += sigma_len;
    /* Pack B */
    packed_idx += pack((packed_pk + packed_idx), B, elements, nr_bits);

    return packed_idx;
}

size_t pack_sk(unsigned char *packed_sk, const int16_t *sk, size_t elements) {
    return pack_sptervec(packed_sk, sk, elements);
}

size_t unpack_pk(uint8_t *fn, unsigned char *sigma, uint16_t *B, const unsigned char *packed_pk, size_t sigma_len, size_t elements, uint8_t nr_bits) {
    size_t unpacked_idx = 0;

    /* Unpack fn */
    *fn = (uint8_t) packed_pk[unpacked_idx++];
    /* Unpack sigma */
    memcpy(sigma, packed_pk +unpacked_idx, sigma_len);
    unpacked_idx += sigma_len;
    /* Unpack B */
    unpacked_idx += unpack(B, packed_pk + unpacked_idx, elements, nr_bits);

    return unpacked_idx;
}

size_t unpack_sk(int16_t *sk, const unsigned char *packed_sk, size_t elements) {
    return unpack_sptervec(sk, packed_sk, elements);
}

size_t pack_ct(unsigned char *packed_ct, const uint16_t *U, size_t U_els, uint8_t U_bits, const uint16_t *v, size_t v_els, uint8_t v_bits) {
    size_t idx = 0;

    /* Pack U */
    idx += pack(packed_ct, U, U_els, U_bits);
    /* Pack v */
    idx += pack((packed_ct + idx), v, v_els, v_bits);

    return idx;
}

size_t unpack_ct(uint16_t *U, uint16_t *v, const unsigned char *packed_ct, const size_t U_els, const uint8_t U_bits, const size_t v_els, const uint8_t v_bits) {
    size_t idx = 0;

    /* Unpack U */
    idx += unpack(U, packed_ct, U_els, U_bits);
    /* Unpack v */
    idx += unpack(v, (packed_ct + idx), v_els, v_bits);

    return idx;
}
