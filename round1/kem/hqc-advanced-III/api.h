/** @file */
/**
 * \file api.h
 * \brief NIST KEM API used by the HQC_KEM IND-CCA2 scheme
 */

#ifndef API_H
#define API_H


#define CRYPTO_ALGNAME											"HQC_Advanced_III"

#define CRYPTO_SECRETKEYBYTES								5924
#define CRYPTO_PUBLICKEYBYTES								5884
#define CRYPTO_BYTES    										64
#define CRYPTO_CIPHERTEXTBYTES    					11752

int crypto_kem_keypair(unsigned char* pk, unsigned char* sk);
int crypto_kem_enc(unsigned char* ct, unsigned char* ss, const unsigned char* pk);
int crypto_kem_dec(unsigned char* ss, const unsigned char* ct, const unsigned char* sk);
	
#endif