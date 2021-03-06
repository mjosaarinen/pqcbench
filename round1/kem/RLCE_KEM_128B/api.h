#ifndef api_h
#define api_h
#define CRYPTO_SECRETKEYBYTES 310116
#define CRYPTO_PUBLICKEYBYTES 188001
#define CRYPTO_BYTES 64
#define CRYPTO_CIPHERTEXTBYTES 988
#define CRYPTO_SCHEME 0 
#define CRYPTO_PADDING 1 
#define CRYPTO_VERSION "RLCEpad128mediumB"
#define CRYPTO_ALGNAME "RLCEKEM128B"

int randombytes(unsigned char *x,unsigned long long xlen);
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct,unsigned char *ss,const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss,const unsigned char *ct,const unsigned char *sk);
#endif
