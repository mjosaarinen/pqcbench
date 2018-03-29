/**
 *  kem.c
 *  NTS-KEM
 *
 *  Parameter: NTS-KEM(13, 136)
 *  Platform: Intel 64-bit
 *
 *  This file is part of the optimized implemention of NTS-KEM
 *  submitted as part of NIST Post-Quantum Cryptography
 *  Standardization Process.
 **/

#include <string.h>
#include "api.h"
#include "nts_kem.h"
#include "nts_kem_errors.h"

int crypto_kem_keypair(unsigned char* pk,
                       unsigned char* sk)
{
    int status;
    NTSKEM *nts_kem = NULL;

    status = nts_kem_create(&nts_kem);
    if (status != NTS_KEM_SUCCESS)
        return status;
    
    memcpy(pk, nts_kem->public_key, CRYPTO_PUBLICKEYBYTES);
    memcpy(sk, nts_kem->private_key, CRYPTO_SECRETKEYBYTES);
    
    nts_kem_release(nts_kem);
    
    return status;
}

int crypto_kem_enc(unsigned char *ct,
                   unsigned char *ss,
                   const unsigned char *pk)
{
    return nts_kem_encapsulate(pk, CRYPTO_PUBLICKEYBYTES, ct, ss);
}

int crypto_kem_dec(unsigned char *ss,
                   const unsigned char *ct,
                   const unsigned char *sk)
{
    return nts_kem_decapsulate(sk, CRYPTO_SECRETKEYBYTES, ct, ss);
}
