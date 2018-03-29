#ifndef API_H
#define API_H

#include "params.h"

#define PublicKey_A (LWE_M * LWE_N * 2)
#define PublicKey_B (LWE_M * LWE_L1 * 2)

#define CRYPTO_SECRETKEYBYTES (LWE_N * LWE_L1) + (LWE_L / 8)
#define CRYPTO_PUBLICKEYBYTES (PublicKey_A + PublicKey_B)
#define CRYPTO_BYTES (LAMBDA / 4)

#ifdef KEM_CATEGORY1_N663
#define CRYPTO_CIPHERTEXTBYTES ((LWE_N * LWE_L2) + (LWE_L1 * LWE_L2) + (LAMBDA / 4))
#endif
#if defined(KEM_CATEGORY1_N536) || defined(KEM_CATEGORY3_N816) || defined(KEM_CATEGORY3_N952) || defined(KEM_CATEGORY5_N1300) || defined(KEM_CATEGORY5_N1088)
#define CRYPTO_CIPHERTEXTBYTES ((LWE_N * LWE_L2 * 2) + (LWE_L1 * LWE_L2 * 2) + (LAMBDA / 4))
#endif

#define CRYPTO_ALGNAME "Lizard.KEM"

int crypto_kem_keypair( unsigned char *pk, unsigned char *sk);

int crypto_kem_enc( unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int crypto_kem_dec( unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif
