#include "io.h"
#include "polynomial.h"
#include "vector.h"
#include "api.h"
#include "rng.h"
#include <time.h>
#include <stdlib.h>
#include <string.h>
  
// Algorithm 26 in the document
void crypto_kem_keypair_KAT(
		unsigned char * pk,  
		unsigned char * sk, 
		const unsigned char * seed);
		
// Algorithm 27 in the document
void crypto_kem_enc_KAT(
		unsigned char * ct,
		unsigned char * ss, 
		const unsigned char * pk,
		const unsigned char * noise_seed);
		
// Algorithm 26 in the document
int crypto_kem_keypair(unsigned char * pk,  unsigned char * sk)
{
	// initialize the seed to be used in keypair()
    unsigned char seed[MATRIX_SEED_BYTES+NOISE_SEED_BYTES];
    randombytes(seed, MATRIX_SEED_BYTES+NOISE_SEED_BYTES);

    crypto_kem_keypair_KAT(pk, sk, seed);
 
	return 0;
}
 

// Algorithm 27 in the document
int crypto_kem_enc(
		unsigned char * ct,
		unsigned char * ss, 
		const unsigned char * pk)
{
	// initialize the seed to be used in enc()
	unsigned char seed[NOISE_SEED_BYTES];
	randombytes(seed, NOISE_SEED_BYTES);
 
	crypto_kem_enc_KAT(ct, ss, pk, seed);
 
	return 0;
}

// Algorithm 28 in the document
int crypto_kem_dec(
		unsigned char * ss,
		const unsigned char * ct,
		const unsigned char * sk)
{
	Polynomial X1[MLWE_ELL];
	Polynomial Sigma1;
	Polynomial Y2[MLWE_ELL];
	unsigned int Signal[MLWE_N];
	unsigned int Key1[MLWE_N];


	{{ // unpack
		unpack_ct(Y2, Signal, ct);	// unpack ct; ciphertext = (Y2, Signal)
		Vector_detruncate(Y2);
		
		unpack_sk(X1, sk);			// unpack secret key sk
	}}

	
	{{ // computation
		// Line #1, Algorithm 28
		Vector_multiply(&Sigma1, X1, Y2);
		
		// Line #2, Algorithm 28
		Poly_OKCN_Rec(Key1, &Sigma1, Signal);
	}}

	
	{{ // pack the generated key
		pack_key(ss, Key1);
	}}
	
	return 0;
}


// Algorithm 26 in the document
void crypto_kem_keypair_KAT(
		unsigned char * pk,  
		unsigned char * sk, 
		const unsigned char * seed)
{
    unsigned int i;

	unsigned char * matrix_seed  = pk+(TRUNCATED_POLY_BYTES * MLWE_ELL);
	unsigned char noise_seed[NOISE_SEED_BYTES];
	unsigned int nonce = 0;

	Polynomial Y1[MLWE_ELL];
	Polynomial X1[MLWE_ELL];
	Polynomial small_poly;
	Polynomial A[MLWE_ELL][MLWE_ELL];
	
	{{ // initialize the seeds
		memcpy(matrix_seed, seed, MATRIX_SEED_BYTES);
		memcpy(noise_seed, seed+MATRIX_SEED_BYTES, NOISE_SEED_BYTES);	

	}}
	
	{{	// Line #2, Algorithm 26: A := Gen(seed)
		// Note: assume the generated matrix A is already in the NTT form. 
		Get_uniform_matrix(A, matrix_seed, 0);	// 0 implies A, not transpose(A)
	}}
	
	{{  // Line #3, Algorithm 26
		// Note: the small polynomial vector E1[...] will be generated when necessary, in order to save memory space. 
		for(i=0; i<MLWE_ELL; i++)
			Get_small_poly(X1+i, noise_seed, nonce++);
		pack_sk(sk, X1);	// pack the secret key X1
	}}


	{{	// Line #4, Algorithm 26: Y1 = truncate(A*X1+E1)
		Vector_pre_NTT_computation(X1);
		Vector_NTT_transform(X1, 1);
		for(i=0; i<MLWE_ELL; i++)
		{
			Vector_NTT_componentwise_multiply_and_add(Y1+i, A[i], X1);
			Poly_NTT_transform(Y1+i, -1);
			Poly_post_NTT_computation(Y1+i);
			
			Get_small_poly(&small_poly, noise_seed, nonce++);// small_poly = E1[i]
			Poly_add_then_truncate(Y1+i, &small_poly, 1); //Here, addition and truncation are both conducted. 
		}
	}}

	{{	// Line #5, Algorithm 26
		// Note: the seed to generate the matrix A, 
		// and the secret key have already been packed previously. 
		pack_truncated_vector(pk, Y1);
	}}
}

// Algorithm 27 in the document
void crypto_kem_enc_KAT(
		unsigned char * ct,
		unsigned char * ss, 
		const unsigned char * pk,
		const unsigned char * noise_seed)
{
    unsigned char nonce = 0;
	unsigned int i;

	Polynomial A_transpose[MLWE_ELL][MLWE_ELL];
	Polynomial X2[MLWE_ELL], Sigma2;
	Polynomial small_poly;
	Polynomial Y1[MLWE_ELL];
	Polynomial Y2[MLWE_ELL];
	unsigned int Signal[MLWE_N]; 
	unsigned int Key2[MLWE_N];
	
	
	{{ 	// unpack pk = (Y1, seed) -> (Y1, A_transposed)
		// Note: A_transposed is assumed in its NTT form. 
		unpack_truncated_vector(Y1, pk+0);
		Vector_detruncate(Y1);
		
		Get_uniform_matrix(
			A_transpose, 
			pk+(TRUNCATED_POLY_BYTES * MLWE_ELL), 
			1);		// 1 indicates A^t, not A. 
	}}


	{{	// Line #2, Algorithm 27
		// Note: E2[...], and E_sigma are generated when necessary, 
		// so as to save memory space. 
		for(i=0; i < MLWE_ELL; i++)
			Get_small_poly(X2+i, noise_seed, nonce++);
	}}
	
	{{	// Lines #3 & #4, Algorithm 27: 
		// Y2 = truncate(A^transpose * X2 + E2)
		// Sigma2 = 2^t * Y1^T * X2 + E_sigma
		Vector_pre_NTT_computation(Y1);
		Vector_NTT_transform(Y1, 1);
		
		Vector_pre_NTT_computation(X2);
		Vector_NTT_transform(X2, 1);  
		
		for(i=0; i<MLWE_ELL; i++)
		{
			Vector_NTT_componentwise_multiply_and_add(Y2+i, A_transpose[i], X2);
			Poly_NTT_transform(Y2+i, -1);
			Poly_post_NTT_computation(Y2+i);
			
			Get_small_poly(&small_poly, noise_seed, nonce++); // small_poly = E2[i]
			Poly_add_then_truncate(Y2+i, &small_poly, 1);	// 1 indicates truncation operation is necessary. 
		}
		
		Vector_NTT_componentwise_multiply_and_add(&Sigma2, Y1, X2);
		Poly_NTT_transform(&Sigma2, -1);
		Poly_post_NTT_computation(&Sigma2);
		
		Get_small_poly(&small_poly, noise_seed, nonce++); // small_poly = E_sigma
		Poly_add_then_truncate(&Sigma2, &small_poly, 0);
	}}

	{{ // Line #5, Algorithm 27: (Key2, Signal) <- Con(Sigma2)
		unsigned char diversifier[8];
		for(i=0; i<8; i++)
			diversifier[i] = noise_seed[i]/2;
		unsigned char local_seed[NOISE_SEED_BYTES+1];
		
		for(i=0; i<NOISE_SEED_BYTES; i++)
			local_seed[i] = noise_seed[i];
		local_seed[NOISE_SEED_BYTES] = nonce;

		AES_XOF_struct aes_state;
		seedexpander_init(&aes_state, local_seed, diversifier, MLWE_N);
		seedexpander(&aes_state, (unsigned char *) noise_seed, MLWE_N/8);

		Poly_OKCN_Con(Key2, Signal, &Sigma2, local_seed);
	}} 

	{{	// Line #6, Algorithm 27: packing
		pack_ct(ct, Y2, Signal);
		pack_key(ss, Key2);
	}}
}
