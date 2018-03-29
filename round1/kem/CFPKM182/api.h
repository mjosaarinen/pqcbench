#ifndef api_h
#define api_h
#include "KEMheader.h"
#include <math.h>
#define CRYPTO_SECRETKEYBYTES N+SEEDSIZE
#define CRYPTO_PUBLICKEYBYTES PK_LENGTH+SEEDSIZE
#define CRYPTO_BYTES M
#define CRYPTO_CIPHERTEXTBYTES PK_LENGTH+M

#define CRYPTO_ALGNAME "CFPKM-182"

int crypto_kem_enc( unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_keypair( unsigned char *pk, unsigned char *sk);
int crypto_kem_dec( unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif /* api_h */
