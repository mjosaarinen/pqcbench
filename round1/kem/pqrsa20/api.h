#define CRYPTO_SECRETKEYBYTES 3145728LL
#define CRYPTO_PUBLICKEYBYTES 1048576LL
#define CRYPTO_CIPHERTEXTBYTES 1048576LL
#define CRYPTO_BYTES 32

#define CRYPTO_ALGNAME "Post-Quantum RSA Enc - pqrsa20"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

