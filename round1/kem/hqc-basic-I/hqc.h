
/**
* \file hqc.h
* \brief Functions of the HQC_PKE IND_CPA scheme
*/

#ifndef HQC_H
#define HQC_H

#include "vector.h"
#include "parsing.h"
#include "tensor.h"

/**
	*\fn void hqc_pke_keygen(unsigned char* pk, unsigned char* sk)
	*\brief Keygen of the HQC_PKE IND_CPA scheme
	*
	* The public key is composed of the syndrome s as well as the seed used to generate the vector h.
	*
	* The secret key is composed of the seed used to generate vectors x and y.
	* As a technicality, the public key is appended to the secret key in order to respect NIST API.
	*
	* \param[out] pk String containing the public key
	* \param[out] sk String containing the secret key
	*/
void hqc_pke_keygen(unsigned char* pk, unsigned char* sk);

/**
	*\fn void hqc_pke_encrypt(vector_u32* u, vector_u32* v, vector_u32* m, unsigned char* theta, const unsigned char* pk)
	*\brief Encryption of the HQC_PKE IND_CPA scheme
	*
	* The cihertext is composed of vectors u and v.
	*
	*
	* \param[out] u Vector u (first part of the ciphertext)
	* \param[out] v Vector v (second part of the ciphertext)
	* \param[in] m Vector representing the message to encrypt
	* \param[in] theta Seed used to derive randomness required for encryption
	* \param[in] pk String containing the public key
	*/
void hqc_pke_encrypt(vector_u32* u, vector_u32* v, vector_u32* m, unsigned char* theta, const unsigned char* pk);

/**
	*\fn void hqc_pke_decrypt(vector_u32* m, vector_u32* u, vector_u32* v, const unsigned char* sk)
	*\brief Decryption of the HQC_PKE IND_CPA scheme
	*
	* \param[out] m Vector representing the decrypted message
	* \param[in] u Vector u (first part of the ciphertext)
	* \param[in] v Vector v (second part of the ciphertext)
	* \param[in] sk String containing the secret key
	*/
void hqc_pke_decrypt(vector_u32* m, vector_u32* u, vector_u32* v, const unsigned char* sk);

#endif