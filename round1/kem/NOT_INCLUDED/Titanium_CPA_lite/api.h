/* ****************************** *
 * Titanium_CPA_lite              *
 * Implemented by Raymond K. ZHAO *
 * ****************************** */

#ifndef api_h
#define api_h

#define CRYPTO_SECRETKEYBYTES 32
#define CRYPTO_PUBLICKEYBYTES 13088
#define CRYPTO_BYTES 2976

#define CRYPTO_ALGNAME "Titanium CPA lite"

int crypto_encrypt_keypair(
unsigned char *pk,
unsigned char *sk
);

int crypto_encrypt(
unsigned char *c, unsigned long long *clen,
const unsigned char *m, unsigned long long mlen,
const unsigned char *pk
);

int crypto_encrypt_open(
unsigned char *m, unsigned long long *mlen,
const unsigned char *c, unsigned long long clen,
const unsigned char *sk
);

#endif /* api_h */
