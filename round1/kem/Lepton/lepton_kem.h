/*
This file implements the functionalities 
of Lepton.CCA KEM scheme.
*/
#ifndef LEPTON_KEM_H
#define LEPTON_KEM_H
#include "lepton_ow.h"

/*
Function: Lepton.CCA.KeyGen() with a given random seed
Inputs  : a random seed
Outputs : a pair of public and secret keys (pk,sk)
*/
int lepton_kem_keygen_KAT(uint8_t *pk, uint8_t *sk,const uint8_t *seed);

/*
Function: Lepton.CCA.Encaps(pk) with a given random seed
Inputs  : a public key pk and a random seed
Outputs : a ciphertext ct and an encapsulated session key ss
*/
int lepton_kem_enc_KAT(uint8_t *ct, uint8_t *ss, const uint8_t *pk,const uint8_t *seed);


/*
Function: Lepton.CCA.KeyGen()
Inputs  : 
Outputs : a pair of public and secret keys (pk,sk)
*/
int lepton_kem_keygen(uint8_t *pk, uint8_t *sk);

/*
Function: Lepton.CCA.Encaps(pk)
Inputs  : a public key
Outputs : a ciphertext ct and an encapsulated session key ss
*/
int lepton_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);

/*
Function: Lepton.CCA.Decaps(sk,C)
Inputs  : a secret key sk and a ciphertext ct 
Outputs : an encapsulated session key ss
*/
int lepton_kem_dec(uint8_t *ss, const uint8_t *sk, const uint8_t *ct);



#endif
