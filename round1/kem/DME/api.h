#ifndef API_H
#define API_H

#define CRYPTO_SECRETKEYBYTES ((12+18+18)*6)
#define CRYPTO_PUBLICKEYBYTES (64*6*6)
#define CRYPTO_BYTES (6*6-3)
#define CRYPTO_CIPHERTEXTBYTES (6*6)

#define CRYPTO_ALGNAME "DME-KEM (N=2, M=3, E=48, S=3)"

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned
  char *pk);

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned
  char *pk);

#endif

