#define CRYPTO_SECRETKEYBYTES 1238
#define CRYPTO_PUBLICKEYBYTES 1047
#define CRYPTO_CIPHERTEXTBYTES 1175
#define CRYPTO_BYTES 32

#define CRYPTO_ALGNAME "NTRU Prime ntrulpr4591761"

int crypto_kem_keypair( unsigned char *pk, unsigned char *sk);

int crypto_kem_enc( unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int crypto_kem_dec( unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

