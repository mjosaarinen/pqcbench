/**
 * \file parameters.h
 * \brief Parameters of the HQC_KEM IND-CCA2 scheme
 */

#include "api.h"

#ifndef HQC_PARAMETERS_H
#define HQC_PARAMETERS_H

/*
	#define PARAM_N             			        	Define the parameter n of the scheme	
	#define PARAM_N1		 												Define the parameter n1 of the scheme (length of BCH code)	
	#define PARAM_N2        										Define the parameter n2 of the scheme (length of the repetition code)
	#define PARAM_N1N2      										Define the parameter n1 * n2 of the scheme (length of the tensor code)
	#define PARAM_T         										Define a threshold for decoding repetition code word (PARAM_T = (PARAM_N2 - 1) / 2)
	#define PARAM_OMEGA 												Define the parameter omega of the scheme
	#define PARAM_OMEGA_E 											Define the parameter omega_e of the scheme
	#define PARAM_OMEGA_R 											Define the parameter omega_r of the scheme
	#define PARAM_DELTA													Define the parameter delta of the scheme (correcting capacity of the BCH code)
	#define PARAM_SECURITY 											Define the security level corresponding to the chosen parameters
	#define PARAM_DFR_EXP 											Define the decryption failure rate corresponding to the chosen parameters
	
	#define SECRET_KEY_BYTES     								Define the size of the secret key in bytes
	#define PUBLIC_KEY_BYTES     								Define the size of the public key in bytes
	#define SHARED_SECRET_BYTES  								Define the size of the shared secret in bytes 
	#define CIPHERTEXT_BYTES     								Define the size of the ciphertext in bytes

	#define PARAM_M   													Define a positive integer 
	#define PARAM_GF_MUL_ORDER 									Define the size of the multiplicative group of GF(2^m), i.e 2^m -1
	#define PARAM_POLY 													Define p(x) = 1 + x^3 + x^10 the primitive polynomial of degree 10 in hexadecimal representation
																							We define alpha as the root of p(x), i.e p(alpha) = 0. Then, alpha is a primitive element, 
																						  and the powers of alpha generate all the nonzero elements of GF(2^10)
																							We use this polynomial to build the Galois Field GF(2^10) needed for the BCH code 

	#define PARAM_K	    												Define the size of the information bits of the BCH code 
	#define PARAM_G 														Define the size of the generator polynomial of BCH code
	#define GENERATOR_POLY     									Define the generator polynomial g(x) of the BCH code in hexadecimal representation

	#define UTILS_REJECTION_THRESHOLD   				Define the rejection threshold used to generate given weight vectors 
																							(see vector_u32_fixed_weight function documentation)
	#define UTILS_MASK          								Define a mask used for random vector generation 
																							(see vector_u32_set_random function documentation)
	#define UTILS_VECTOR_ARRAY_SIZE     		    Size of the array used to store by coordinate a PARAM_N sized vector
																							(see vector_u32_init function documentation)
	#define UTILS_VECTOR_ARRAY_BYTES					  Define the size of the array used to store a PARAM_N sized vector in bytes
																							(i.e the number of bytes of UTILS_VECTOR_ARRAY_SIZE)
	#define UTILS_VEC_N_BYTES                   Define the size of a PARAM_N sized vector in bytes
	#define UTILS_VEC_K_ARRAY_SIZE 							Size of the array used to store by coordinate a PARAM_K sized vector
																							(see vector_u32_init function documentation)
	#define UTILS_VEC_K_BYTES 								  Define the size of a PARAM_K sized vector in bytes
	#define UTILS_BCH_CODEWORD_ARRAY_SIZE				Size of the array used to store by coordinate a PARAM_N1 sized vector
																							(see vector_u32_init function documentation)
	#define UTILS_MASK_M1       								Define a mask used for extracting the message (information bits) from a BCH code word
																							(see get_message_from_code word function documentation)
	#define UTILS_MASK_M2        								Define a mask used for extracting the message (information bits) from a BCH code word
																							(see get_message_from_code word function documentation)
	#define UTILS_TENSOR_CODEWORD_ARRAY_SIZE 		Size of the array used to store by coordinate a PARAM_N1N2 sized vector
																							(see vector_u32_init function documentation)
	#define SHA512_BYTES                        Define the size of SHA512 output in bytes
	#define SEED_BYTES                          Define the size of the seed in bytes
	#define SEEDEXPANDER_MAX_LENGTH             Define the seed expander max length
*/


#define PARAM_N                     				43669
#define PARAM_N1		 												766
#define PARAM_N2        										57
#define PARAM_N1N2      										43662
#define PARAM_T         										28
#define PARAM_OMEGA 												101
#define PARAM_OMEGA_E 											117
#define PARAM_OMEGA_R 											117
#define PARAM_DELTA													57
#define PARAM_SECURITY 											192
#define PARAM_DFR_EXP 											128

#define SECRET_KEY_BYTES     								CRYPTO_SECRETKEYBYTES
#define PUBLIC_KEY_BYTES     								CRYPTO_PUBLICKEYBYTES
#define SHARED_SECRET_BYTES  								CRYPTO_BYTES
#define CIPHERTEXT_BYTES     								CRYPTO_CIPHERTEXTBYTES

#define PARAM_POLY 													0x409
#define PARAM_M		   												10
#define PARAM_GF_MUL_ORDER 									1023
#define PARAM_G 														511
#define PARAM_K	    												256
#define GENERATOR_POLY     									"C26D64FCDEF44ED7521EF849C65108B0CD57A6B37D746F784083CD0929AFB5F8BF56337F1E89B2D583FF6BFB627D42F412F81F49A018E6348A8F89B2DC374226"

#define UTILS_REJECTION_THRESHOLD   				16768896
#define UTILS_MASK          								0xFFFFF800
#define UTILS_MASK_M1       								0x00000003
#define UTILS_MASK_M2        								0xFFFFFFFC
#define UTILS_VEC_K_ARRAY_SIZE 							8
#define UTILS_VEC_K_BYTES 								  PARAM_K / 8
#define UTILS_VECTOR_ARRAY_BYTES 						UTILS_VECTOR_ARRAY_SIZE * 4
#define UTILS_VEC_N_BYTES                   ((PARAM_N / 8) + 1)
#define UTILS_BCH_CODEWORD_ARRAY_SIZE				24
#define UTILS_TENSOR_CODEWORD_ARRAY_SIZE 		1365
#define UTILS_VECTOR_ARRAY_SIZE     		    ((PARAM_N / 32) + 1)
#define SHA512_BYTES                        64
#define SEED_BYTES                          40
#define SEEDEXPANDER_MAX_LENGTH             4294967295

#endif