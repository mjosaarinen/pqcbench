#ifndef LEPTON_OW_H
#define LEPTON_OW_H
#include "params.h"
#include "poly.h"

//using extern random seed sources
extern int randombytes(unsigned char *x, unsigned long long xlen);

/*
Function: LPN core key generation with a given random seed
Inputs  : a random seed 
Outputs : a pair of public and secret keys (pk,sk)
*/
int lepton_ow_keygen_KAT(uint8_t *cpk, uint8_t *csk, const uint8_t *seed);

/*
Function: LPN core encryption with a given random seed
Inputs  : a public key cpk, a message msg and a random seed
Outputs : a ciphertext cct
*/
int lepton_ow_enc_KAT(uint8_t *cct, const uint8_t *cpk, const uint8_t *msg, const uint8_t *seed);

/*
Function: LPN core decryption
Inputs  : a secret key csk and a ciphertext cct
Outputs : an encrypted message msg
*/
int lepton_ow_dec_KAT(uint8_t *msg, const uint8_t *csk, const uint8_t *cct);
#endif
