
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "io.h"
#include "polynomial.h"
#include "api.h"
#include "rng.h"
#include "sec.h"

extern const unsigned char diversifier[8];

// Algorithm 19 in the document
int crypto_kem_keypair_KAT(
		unsigned char * pk,  
		unsigned char * sk, 
		const unsigned char * seed);
		
// Algorithm 20 in the document
int crypto_kem_enc_KAT(
		unsigned char * ct,
		unsigned char * ss, 
		const unsigned char * pk,
		const unsigned char * noise_seed);
	
// Algorithm 19 in the document	
int crypto_kem_keypair(
		unsigned char * pk, 
		unsigned char * sk)
{
	// initialize the seeds. 
	unsigned char seed[UNIFORM_POLY_SEED_BYTES+SMALL_POLY_SEED_BYTES];
	randombytes(seed, UNIFORM_POLY_SEED_BYTES+SMALL_POLY_SEED_BYTES);
	
	crypto_kem_keypair_KAT(pk, sk, seed);
	
	return 0;
}

// Algorithm 19 in the document
int crypto_kem_keypair_KAT(
		unsigned char * pk, 
		unsigned char * sk,
		const unsigned char * seed)
{
	unsigned int i;
	
	unsigned char * uniform_poly_seed = pk + TRUNCATED_POLY_BYTES;
	unsigned int nonce = 0;
	unsigned char small_poly_seed[SMALL_POLY_SEED_BYTES];
	
	Polynomial A;
	Polynomial small_poly;
	Polynomial Y1;
	
	memcpy(uniform_poly_seed, seed, UNIFORM_POLY_SEED_BYTES); 
	memcpy(small_poly_seed, seed+UNIFORM_POLY_SEED_BYTES, SMALL_POLY_SEED_BYTES); 

	{{ // Line #2, Algorithm 19: A =Gen(seed)
		Get_uniform_poly(&A, uniform_poly_seed);
	}}
	
	{{ // Line #3, Algorithm 19: x1, e1 <- error_distribution 
		// Note: both x1, e1 are generated when necessary, so as to save memory space. 
		Get_small_poly(&small_poly, small_poly_seed, nonce++); // small_poly = X1
		pack_sk(sk, &small_poly); // pack sk = X1
	}}
	
	{{ // Line #4, Algorithm 19: y1 = truncate(a*x1+e1);
		// Y1 = A*X1
		Poly_multiply(&Y1, &A, &small_poly); 
	
		Get_small_poly(&small_poly, small_poly_seed, nonce++); // small_poly = E1
		Poly_add_then_truncate(&Y1, &small_poly, 1); // 1 indicates truncation.
	}}

	{{ // Line %5, Algorithm 19: return (pk, sk)
		// Note: both the matrix_seed in pk and sk=X1 has already been packed previously
		pack_truncated_poly(pk+0, &Y1);
	}}	

	return 0;
}


// Algorithm 20 in the document
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


// Algorithm 20 in the document. 
// pk = (Y1, seed); ct = (Y2, Signal, sec_code)
int crypto_kem_enc_KAT(
	unsigned char * ct, 
	unsigned char * ss,
	const unsigned char * pk,
	const unsigned char * small_poly_seed)
{
	unsigned int Signal[RLWE_N];
	unsigned int sec_code[SEC_BLOCK_NUMBER+SEC_PADDING_OF_BLOCK_NUMBER];
	unsigned int Key2[RLWE_N];
	unsigned int nonce = 0;
	unsigned int i,j, temp;
	
	Polynomial A, Y1, Y2, Sigma2;
	Polynomial small_poly;
	
	{{ // unpack 
		unpack_truncated_poly(&Y1, pk+0);
		Poly_detruncate(&Y1);
	}}
	
	// unpack

	Get_uniform_poly(&A, pk + TRUNCATED_POLY_BYTES);
	
	{{	// Lines #3-4, Algorithm 20: 
		// Y2 = truncate(a*X2 + E2)
		// Sigma2 = 2^t * Y1 * X2 + E2'
		Get_small_poly(&small_poly, small_poly_seed, nonce++); // small_poly=X2
		Poly_multiply(&Y2, &A, &small_poly);
		Poly_multiply(&Sigma2, &Y1, &small_poly);
		
		Get_small_poly(&small_poly, small_poly_seed, nonce++); // small_poly=E2
		Poly_add_then_truncate(&Y2, &small_poly, 1);
	
		Get_small_poly(&small_poly, small_poly_seed, nonce++); // small_poly=E2'
		Poly_add_then_truncate(&Sigma2, &small_poly, 0);
	}}
	
	{{ // Line #5, Algorithm 20: [Key2, Signal] <- Con(Sigma2; nonce)
		unsigned char con_error[CON_ERROR_BYTES];
		unsigned char local_seed[SMALL_POLY_SEED_BYTES+1];

		memcpy(local_seed, small_poly_seed, SMALL_POLY_SEED_BYTES);
		local_seed[SMALL_POLY_SEED_BYTES] = nonce;

		AES_XOF_struct aes_state;
		seedexpander_init(&aes_state, &local_seed, diversifier, CON_ERROR_BYTES);
		seedexpander(&aes_state, con_error, CON_ERROR_BYTES);
		
		Poly_OKCN_Con(Key2, Signal, &Sigma2, con_error);
	}}
	
	{{// Lines #6-8, Algorithm 20. 
		unsigned int significant_key2[SEC_BLOCK_NUMBER];
		unsigned int sec_x, sec_key;
		
		for(i=0; i<SEC_BLOCK_NUMBER; i++)
		{
			sec_key = 0;
			for(j=0; j<SEC_BLOCK_SIZE; j++)
				sec_key = (((sec_key<<1) ^ (Key2[i*20+j]&0x1)) & 0xFFFFF);
			sec_x = (sec_key>>4) & 0x7FFF;
			significant_key2[i] = sec_x;
			
			sec_x = (SEC_encode(sec_x)^sec_key) & 0xFFFFF;
			
			sec_code[i] = compress_sec_code(sec_x);
		}
		for(i=0; i<SEC_PADDING_OF_BLOCK_NUMBER; i++) // padding
			sec_code[SEC_BLOCK_NUMBER+i] = 0;
		
		group_compress(
				ct + TRUNCATED_POLY_BYTES+SIGNAL_BYTES, 
				sec_code,
				1+SEC_n, 
				(SEC_BLOCK_NUMBER+SEC_PADDING_OF_BLOCK_NUMBER)/8);
				
		for(i=0; i<SEC_BLOCK_NUMBER; i++)
			for(j=0, temp = significant_key2[i]; j<(SEC_N-1); j++, temp >>= 1)
				Key2[i*(SEC_N-1)+j] = (temp & 0x1);

		for(i=0; i<SEC_PADDING_OF_SIGNIFICANT_BITS; i++) // padding
			Key2[SEC_SIGNIFICANT_BITS+i] = 0;
	}}
	
	{{ // pack
		pack_ct(ct, &Y2, Signal, sec_code); // ciphertext(Y2, Signal, sec_code)
		pack_key(ss, Key2);
	}}
	
	return 0;
}


// Algorithm 21 in the document
int crypto_kem_dec(
	unsigned char * ss,
	const unsigned char * ct, 
	const unsigned char * sk)
{
	Polynomial X1;
	Polynomial Y2;
	unsigned int Signal[RLWE_N];
	Polynomial Sigma1;
	unsigned int Key1[RLWE_N];
	unsigned int sec_code[SEC_BLOCK_NUMBER+5];
	
	unsigned int i,j, temp;

	
	{{ // unpack sk=X1, ct=(Y2, Signal, sec_code)
		unpack_ct(&Y2, Signal, sec_code, ct);
		Poly_detruncate(&Y2);
		
		unpack_sk(&X1, sk);	
	}}

	// Line #1, Algorithm 21: Sigma1 = 2^t * Y2 * X1
	Poly_multiply(&Sigma1, &Y2, &X1);

	// Line #2, Algorithm 21
	Poly_OKCN_Rec(Key1, &Sigma1, Signal);
	
	{{ // Lines #3-5, Algorithm 21. 
		unsigned int sec_x, sec_key; 
		
		for(i=0; i<SEC_BLOCK_NUMBER; i++)
		{
			for(sec_key=0, j=0; j<SEC_BLOCK_SIZE; j++)
				sec_key = ((sec_key<<1)^(Key1[i*SEC_BLOCK_SIZE+j]&0x1));
			
			sec_x = decompress_sec_code(sec_code[i]);
			sec_x = ((sec_x ^ sec_key) & 0xFFFFF);
			temp = SEC_decode(sec_x);
			
			for(j=0; j<(SEC_N-1); j++, temp>>=1)
				Key1[i*(SEC_N-1)+j] = (temp & 0x1);
		}
		for(i=0; i<SEC_PADDING_OF_SIGNIFICANT_BITS; i++) // padding
			Key1[SEC_SIGNIFICANT_BITS+i] = 0;
	}}

	// pack Key1
	pack_key(ss, Key1);

	return 0;
}


