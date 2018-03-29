#ifndef api_h
#define api_h
#define CRYPTO_SECRETKEYBYTES 440008
#define CRYPTO_PUBLICKEYBYTES 287371
#define CRYPTO_BYTES 64
#define CRYPTO_CIPHERTEXTBYTES 1238
#define CRYPTO_SCHEME 3 
#define CRYPTO_PADDING 1
#define CRYPTO_VERSION "RLCEpad192mediumA"
#define CRYPTO_ALGNAME "RLCEKEM192A"

int randombytes(unsigned char *x,unsigned long long xlen);
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct,unsigned char *ss,const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss,const unsigned char *ct,const unsigned char *sk);
#endif
