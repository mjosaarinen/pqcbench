/*
 * api.h
 *
 *  Created on: Aug 29, 2017
 *      Author: zhenfei
 */

#ifndef API_H_
#define API_H_

#define TEST_SS_NTRU_KEM

#define CRYPTO_ALGNAME "SS_NTRU_KEM_1024"
#define TEST_PARAM_SET  NTRU_KEM_1024
#define CRYPTO_SECRETKEYBYTES 8194  /* secret key length */
#define CRYPTO_PUBLICKEYBYTES 4097  /* public key length */
#define CRYPTO_BYTES 48             /* shared secret length */
#define CRYPTO_CIPHERTEXTBYTES 4097
#define CRYPTO_RANDOMBYTES 32       /* random input */



/* ebacs API: key gen */
int crypto_encrypt_keypair(
    unsigned char       *pk,
    unsigned char       *sk);

/* ebacs API: encryption */
int crypto_encrypt(
    unsigned char       *c,
    unsigned long long  *clen,
    const unsigned char *m,
    unsigned long long  mlen,
    const unsigned char *pk);

/* ebacs API: decryption */
int crypto_encrypt_open(
    unsigned char       *m,
    unsigned long long  *mlen,
    const unsigned char *c,
    unsigned long long  clen,
    const unsigned char *sk);


int crypto_kem_keypair(
    unsigned char       *pk,
    unsigned char       *sk);

int crypto_kem_enc(
    unsigned char       *ct,
    unsigned char       *ss,
    const unsigned char *pk);

int crypto_kem_dec(
    unsigned char       *ss,
    const unsigned char *ct,
    const unsigned char *sk);


#endif /* API_H_ */
