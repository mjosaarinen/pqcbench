
#ifndef api_h
#define api_h


#include <stdlib.h>
#include <string.h>
#include <stdio.h>



#define N 512
#define modulus_q 120833
#define round_p 7551
#define SIZE_q 17
#define SIZE_p 13
#define sigma_se_512 4.19
#define sigma_f_512 4.92
#define sigma_se_1024 2.6
#define sigma_f_1024 4.72

//  Set these values apropriately for your algorithm
#define SEED_BYTES 16
#define CRYPTO_SECRETKEYBYTES 3*N
#define CRYPTO_PUBLICKEYBYTES 2*N + SEED_BYTES
#define CRYPTO_BYTES N/8
#define CRYPTO_CIPHERTEXTBYTES 2*N + N/8

#define PI 3.141592653589793238462643383279502884197

// Change the algorithm name
#define CRYPTO_ALGNAME "Ding Key Exchange"
	



int
crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

int
crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int
crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif /* api_h */
