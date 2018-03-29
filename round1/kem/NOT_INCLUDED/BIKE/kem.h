/******************************************************************************
 * BIKE -- Bit Flipping Key Encapsulation
 *
 * Copyright (c) 2017 Nir Drucker, Shay Gueron, Rafael Misoczki, Tobias Oder, Tim Gueneysu
 * (drucker.nir@gmail.com, shay.gueron@gmail.com, rafael.misoczki@intel.com, tobias.oder@rub.de, tim.gueneysu@rub.de)
 *
 * Permission to use this code for BIKE is granted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * * The names of the contributors may not be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS CORPORATION OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#ifndef __KEM_H_INCLUDED__
#define __KEM_H_INCLUDED__

#include "api.h"
#include "stdlib.h"
#include "string.h"
#include "utilities.h"
#include "FromNIST/rng.h"

enum _seeds_purpose
{
    KEYGEN_SEEDS = 0,
    ENCAPS_SEEDS = 1,
    DECAPS_SEEDS = 2
};

typedef enum _seeds_purpose seeds_purpose_t;

_INLINE_ void get_seeds(OUT double_seed_t* seeds, seeds_purpose_t seeds_type)
{
#ifdef NIST_RAND
    randombytes(seeds->s1.raw, sizeof(double_seed_t));
#else
    for(uint32_t i = 0; i < sizeof(seed_t); ++i)
    {
        seeds->s1.raw[i] = rand(); // not cryptographically secure !
        seeds->s2.raw[i] = rand(); // not cryptographically secure !
    }
#endif
    EDMSG("s1: "); print(seeds->s1.qwords, sizeof(seed_t)*8);
    EDMSG("s2: "); print(seeds->s2.qwords, sizeof(seed_t)*8);
}

////////////////////////////////////////////////////////////////
//Below three APIs (keygen, encaps, decaps) are defined by NIST:
////////////////////////////////////////////////////////////////
//Keygenerate - pk is the public key,
//              sk is the private key,
int crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk);

//Encapsulate - pk is the public key,
//              ct is a key encapsulation message (ciphertext),
//              ss is the shared secret.
int crypto_kem_enc(OUT unsigned char *ct,
        OUT unsigned char *ss,
        IN const unsigned char *pk);

//Decapsulate - ct is a key encapsulation message (ciphertext),
//              sk is the private key,
//              ss is the shared secret
int crypto_kem_dec(OUT unsigned char *ss,
        IN const unsigned char *ct,
        IN const unsigned char *sk);

#endif //__KEM_H_INCLUDED__

