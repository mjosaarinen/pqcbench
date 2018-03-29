#define CRYPTO_SECRETKEYBYTES 98304
#define CRYPTO_PUBLICKEYBYTES 32768
#define CRYPTO_CIPHERTEXTBYTES 32768
#define CRYPTO_BYTES 32

#define CRYPTO_ALGNAME "Post-Quantum RSA Enc - pqrsa15"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

