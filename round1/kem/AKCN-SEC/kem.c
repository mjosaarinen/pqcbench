
#include <time.h>
#include <stdlib.h>

#include <string.h>

#include "io.h"
#include "polynomial.h"
#include "api.h"
#include "rng.h"
#include "sec.h"

extern const unsigned char diversifier[8];

// Algorithm 16 in the document
int crypto_kem_keypair_KAT(
		unsigned char * pk,  
		unsigned char * sk, 
		const unsigned char * seed);
		
// Algorithm 17 in the document
int crypto_kem_enc_KAT(
		unsigned char * ct,
		unsigned char * ss, 
		const unsigned char * pk,
		const unsigned char * noise_seed);
		
// Algorithm 16 in the document
int crypto_kem_keypair(
		unsigned char * pk, 
		unsigned char * sk)
{
	// initialize the seed
	unsigned char seed[UNIFORM_POLY_SEED_BYTES+SMALL_POLY_SEED_BYTES];
	randombytes(seed, UNIFORM_POLY_SEED_BYTES+SMALL_POLY_SEED_BYTES);
	
	crypto_kem_keypair_KAT(pk, sk, seed);
	
	return 0;
}

// Algorithm 16 in the document
int crypto_kem_keypair_KAT(
		unsigned char * pk, 
		unsigned char * sk,
		const unsigned char * seed)
{	
	unsigned char * uniform_poly_seed = pk + TRUNCATED_POLY_BYTES;
	unsigned int nonce = 0;
	unsigned char small_poly_seed[SMALL_POLY_SEED_BYTES];
	
	Polynomial A;
	Polynomial small_poly;
	Polynomial Y1;
	
	{{ // initialize the seeds
		memcpy(uniform_poly_seed, seed, UNIFORM_POLY_SEED_BYTES);
		memcpy(small_poly_seed, seed+UNIFORM_POLY_SEED_BYTES, SMALL_POLY_SEED_BYTES);
	}}
	
	{{ // Line #2, Algorithm 16: A = Gen(seed)
		Get_uniform_poly(&A, uniform_poly_seed);
	}}
	
	{{ // Line #3, Algorithm 16: X1, E1 <- error_distribution
		// Note: E1 is generated when necessary, so as to save memory space. 
		Get_small_poly(&small_poly, small_poly_seed, nonce++); // small_poly = X1
		
		pack_sk(sk, &small_poly); // pack sk = X1
	}}
	
	{{ // Line #4, Algorithm 16: Y1 = truncate(A * X1 + E1)
		Poly_multiply(&Y1, &A, &small_poly); // Y1 = A*X1
		
		Get_small_poly(&small_poly, small_poly_seed, nonce++); // small_poly = E1
		
		// Y1 = Y1 + E1
		Poly_add_then_truncate(&Y1, &small_poly, 1); // 1 indicates truncation. 
	}}

	{{ // Line #5, Algorithm 16: return (pk, sk)
		// Note: both the matrix_seed in pk and sk=X1 has already been packed previously
		pack_truncated_poly(pk+0, &Y1);
	}}

	return 0;
}


// Algorithm 17 in the document
int crypto_kem_enc(
		unsigned char * ct,
		unsigned char * ss, 
		const unsigned char * pk)
{
	// initialize the seed
	unsigned char small_poly_seed[SMALL_POLY_SEED_BYTES];
	randombytes(small_poly_seed, SMALL_POLY_SEED_BYTES);
 
	crypto_kem_enc_KAT(ct, ss, pk, small_poly_seed);
 
	return 0;
}


// Algorithm 17 in the document
// pk = (Y1, seed); ct = (Y2, Signal, sec_code)
int crypto_kem_enc_KAT(
	unsigned char * ct, 
	unsigned char * ss,
	const unsigned char * pk,
	const unsigned char * small_poly_seed)
{
	unsigned int Signal[RLWE_N];
	unsigned int Key2[RLWE_N];
	unsigned int significant_key2[SEC_SIGNIFICANT_BITS+SEC_PADDING_OF_SIGNIFICANT_BITS];
	
	unsigned int nonce = 0;
	unsigned int i, j, temp, index;
	
	Polynomial A, Y1, Y2, Sigma2;
	Polynomial small_poly;
	
	unsigned char local_seed[SMALL_POLY_SEED_BYTES+1];

	
	{{ // unpack 
		unpack_truncated_poly(&Y1, pk+0);
		Poly_detruncate(&Y1);
		
		Get_uniform_poly(&A, pk + TRUNCATED_POLY_BYTES); // unpack A
	}}

	
	{{	// Lines #3-4, Algorithm 17:
		// Y2 = truncate(a*X2 + E2)
		// Sigma2 = 2^t * Y1 * X2 + E2'
		Get_small_poly(&small_poly, small_poly_seed, nonce++); // small_poly=X2
		Poly_multiply(&Y2, &A, &small_poly);
		Poly_multiply(&Sigma2, &Y1, &small_poly);
		
		Get_small_poly(&small_poly, small_poly_seed, nonce++); // small_poly=E2
		Poly_add_then_truncate(&Y2, &small_poly, 1); // 1 indicates truncation
		
		Get_small_poly(&small_poly, small_poly_seed, nonce++); // small_poly=E2'
		Poly_add_then_truncate(&Sigma2, &small_poly, 0); // 0 indicates no truncation.
	}}
	
	{{ // Lines #5-6, Algorithm 17: 
		AES_XOF_struct aes_state;
		unsigned char random_byte[SEC_BLOCK_NUMBER*2];
		unsigned int sec_key;
		
		memcpy(local_seed, small_poly_seed, SMALL_POLY_SEED_BYTES);
		local_seed[SMALL_POLY_SEED_BYTES] = nonce;
		
		seedexpander_init(&aes_state, &local_seed, diversifier, SEC_BLOCK_NUMBER*4);		
		seedexpander(&aes_state, random_byte, SEC_BLOCK_NUMBER*2);
		
		for(i=index=0; i<SEC_BLOCK_NUMBER; i++)
		{
			sec_key = ((random_byte[2*i+1] & 0x7F)<<8) ^ random_byte[2*i];
			
			for(j=0, temp = sec_key; j<(SEC_N-1); j++, temp>>=1)
				significant_key2[i*(SEC_N-1)+j] = (temp & 0x1);
			
			temp = (SEC_encode(sec_key) & 0xFFFFF);
			for(j=0; j<SEC_BLOCK_SIZE; j++, temp>>=1)
				Key2[index++] = (temp & 0x1);
		}
		for(j=SEC_BLOCK_SIZE*SEC_BLOCK_NUMBER; j<RLWE_N; j++)  // padding
			Key2[j] = 0;
		for(j=0; j<SEC_PADDING_OF_SIGNIFICANT_BITS; j++) // padding
			significant_key2[SEC_SIGNIFICANT_BITS+j] = 0;
	}}

	{{ // Line #7, Algorithm 17: Signal <- Con(Sigma2, Key2)
		Poly_AKCN_Con(Signal, &Sigma2, Key2);
	}}
	
	{{ // pack 
		pack_ct(ct, &Y2, Signal); // ciphertext = (Y2, Signal)
		pack_key(ss, significant_key2);
	}}
	
	return 0;
}


// Algorithm 18 in the document
int crypto_kem_dec(
	unsigned char * ss,
	const unsigned char * ct, 
	const unsigned char * sk)

{
	Polynomial X1;
	Polynomial Y2;
	Polynomial Sigma1;
	
	unsigned int Signal[RLWE_N];
	unsigned int Key1[RLWE_N];
	unsigned int significant_key1[SEC_SIGNIFICANT_BITS + SEC_PADDING_OF_SIGNIFICANT_BITS];
	unsigned int sec_x;
	unsigned int i,j; 

	{{ // unpack 
		unpack_ct(&Y2, Signal, ct);	// ciphertext = (Y2, Signal)
		Poly_detruncate(&Y2);
		
		unpack_sk(&X1, sk);	
	}}

	{{ // Line #1, Algorithm 18: Sigma1 <- 2^t * Y2 * X1
		Poly_multiply(&Sigma1, &Y2, &X1);
	}}
	
	{{ // Line #2, Algorithm 18: Key1 <- Rec(Sigma1, Signal)
		Poly_AKCN_Rec(Key1, &Sigma1, Signal);
	}}
	
	{{ // Line #3, Algorithm 18: significant_key1 <- Decode(Key1)
		for(i=0; i<SEC_BLOCK_NUMBER; i++)
		{
			for(j=sec_x=0; j<SEC_BLOCK_SIZE; j++)
				sec_x = sec_x^((Key1[i*SEC_BLOCK_SIZE+j]&0x1)<<j);
			
			sec_x = SEC_decode(sec_x);
			
			for(j=0; j<(SEC_N-1); j++, sec_x>>=1)
				significant_key1[i*(SEC_N-1)+j] = (sec_x & 0x1);
		}
		for(j=0; j<SEC_PADDING_OF_SIGNIFICANT_BITS; j++) // padding
			significant_key1[SEC_SIGNIFICANT_BITS+j] = 0;
	}}
	
	{{ // Line #4, Algorithm 18: return significant_key1
		pack_key(ss, significant_key1);
	}}	

	return 0;
}


