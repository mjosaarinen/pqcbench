#define CRYPTO_PUBLICKEYBYTES 1047319
#define CRYPTO_SECRETKEYBYTES 13908
#define CRYPTO_CIPHERTEXTBYTES 226
#define CRYPTO_BYTES 32

#define CRYPTO_ALGNAME "Classic McEliece 6960119"

int crypto_kem_keypair( unsigned char *pk, unsigned char *sk);

int crypto_kem_enc( unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int crypto_kem_dec( unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

