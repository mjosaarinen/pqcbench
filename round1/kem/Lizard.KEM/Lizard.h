#ifndef LIZARD_H
#define LIZARD_H

#include <stdint.h>
#include "params.h"
#include "api.h"

#define iter 100		// iteration number for keygen & EncDec test
#define testnum 1000   // repeatetion number of Enc Dec procedure in a single iteration

#define sft (sizeof(size_t) * 4 - 1) 

typedef unsigned char SecretKey[CRYPTO_SECRETKEYBYTES];
typedef unsigned char PublicKey[CRYPTO_PUBLICKEYBYTES];

clock_t start, finish, elapsed1, elapsed2;

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
#endif