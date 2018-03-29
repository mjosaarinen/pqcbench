/*
This file implements the functionalities 
of Lepton.CPA KEM scheme.
*/

#ifndef LEPTON_KEX_H
#define LEPTON_KEX_H
#include "lepton_ow.h"

/*
Function: Lepton.CPA.KeyGen() with a given random seed
Inputs  : a random seed, 
Outputs : a pair of pubic and secret keys (pk,sk)
*/
int lepton_kex_keygen_KAT(uint8_t *pk, uint8_t *sk,const uint8_t *seed);

/*
Function: Lepton.CPA.Encaps(pk) with a given random seed
Inputs  : a public key pk and a random seed
Outputs : a ciphertext ct and an encapsulated session key ss
*/
int lepton_kex_enc_KAT(uint8_t *ct, uint8_t *ss, const uint8_t *pk,const uint8_t *seed);

/*
Function: Lepton.CPA.KeyGen()
Inputs  : 
Outputs : a pair of pubic and secret keys (pk,sk)
*/
int lepton_kex_keygen(uint8_t *pk, uint8_t *sk);

/*
Function: Lepton.CPA.Encaps(pk)
Inputs  : a public key
Outputs : a ciphertext ct and an encapsulated session key ss
*/
int lepton_kex_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/*
Function: Lepton.CPA.Decaps(sk,C)
Inputs  : a secret key sk and a ciphertext ct 
Outputs : an encapsulated session key ss
*/
int lepton_kex_dec(uint8_t *ss, const uint8_t *sk, const uint8_t *ct);


#endif
