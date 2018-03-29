#ifndef api_h
#define api_h

#define D 1850
#define B 1
#define N 19268
#define C 7973

#define K 4
#define P 2409

#define CRYPTO_BYTES 32
#define CRYPTO_SECRETKEYBYTES 4456650
#define CRYPTO_PUBLICKEYBYTES 4454241
#define CRYPTO_CIPHERTEXTBYTES 616704
#define CRYPTO_ALGNAME "ODD_MANHATTAN"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif

