#ifndef api_h
#define api_h

#define D 1156
#define B 1
#define N 11258
#define C 4217

#define K 3
#define P 1408

#define CRYPTO_BYTES 16

#define CRYPTO_SECRETKEYBYTES 1627648
#define CRYPTO_PUBLICKEYBYTES 1626240
#define CRYPTO_CIPHERTEXTBYTES 180224
#define CRYPTO_ALGNAME "ODD_MANHATTAN"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif

