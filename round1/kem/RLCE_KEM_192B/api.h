#ifndef api_h
#define api_h
#define CRYPTO_SECRETKEYBYTES 747393
#define CRYPTO_PUBLICKEYBYTES 450761
#define CRYPTO_BYTES 64
#define CRYPTO_CIPHERTEXTBYTES 1545
#define CRYPTO_SCHEME 2 
#define CRYPTO_PADDING 1 
#define CRYPTO_VERSION "RLCEpad192mediumB"
#define CRYPTO_ALGNAME "RLCEKEM192B"

int randombytes(unsigned char *x,unsigned long long xlen);
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct,unsigned char *ss,const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss,const unsigned char *ct,const unsigned char *sk);
#endif
