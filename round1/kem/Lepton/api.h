//
//  modifed from the api.h Created by Bassham, Lawrence E (Fed) on 9/6/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#ifndef API_H
#define API_H


#ifdef LEPTON_CPA /* LETPON_CPA */


#include "lepton_kex.h"

#define CRYPTO_SECRETKEYBYTES CPA_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES CPA_PK_BYTES
#define CRYPTO_CIPHERTEXTBYTES CPA_CT_BYTES
#define CRYPTO_BYTES 32

#define CRYPTO_ALGNAME "Lepton_CPA"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
    return lepton_kex_keygen(pk,sk);
}
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, unsigned char *pk)
{
    return lepton_kex_enc(ct,ss,pk);
}
int crypto_kem_dec(unsigned char *ss, unsigned char *ct, unsigned char *sk)
{
    return lepton_kex_dec(ss,sk,ct);
}




#else /* LETPON_CCA */

#include "lepton_kem.h"

#define CRYPTO_SECRETKEYBYTES CCA_SK_BYTES
#define CRYPTO_PUBLICKEYBYTES CCA_PK_BYTES
#define CRYPTO_CIPHERTEXTBYTES CCA_CT_BYTES
#define CRYPTO_BYTES 32

#define CRYPTO_ALGNAME "Lepton_CCA"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
    return lepton_kem_keygen(pk,sk);
}
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, unsigned char *pk)
{
    return lepton_kem_enc(ct,ss,pk);
}
int crypto_kem_dec(unsigned char *ss, unsigned char *ct, unsigned char *sk)
{
    return lepton_kem_dec(ss,sk,ct);
}
#endif /* LETPON_CCA */

#endif /* API_H */
