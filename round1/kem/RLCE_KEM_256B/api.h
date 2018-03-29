#ifndef api_h
#define api_h
#define CRYPTO_SECRETKEYBYTES 1773271
#define CRYPTO_PUBLICKEYBYTES 1232001
#define CRYPTO_BYTES 64
#define CRYPTO_CIPHERTEXTBYTES 2640
#define CRYPTO_SCHEME 4 
#define CRYPTO_PADDING 1 
#define CRYPTO_VERSION "RLCEpad256mediumB"
#define CRYPTO_ALGNAME "RLCEKEM256B"

int randombytes(unsigned char *x,unsigned long long xlen);
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct,unsigned char *ss,const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss,const unsigned char *ct,const unsigned char *sk);
#endif
