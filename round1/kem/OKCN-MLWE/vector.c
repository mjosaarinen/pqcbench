#include "vector.h"
#include "parameter.h"
#include "polynomial.h"
#include "rng.h"


// It converts every polynomial in vec[] into truncated form.
// Before: every coefficient is in the interval [0, 2q-1].
// After: every coefficient is in the interval [0, q/2^t].
void Vector_truncate(Polynomial vec[MLWE_ELL])
{
	for(uint8_t i=0; i<MLWE_ELL; i++)
		Poly_truncate(vec+i);
}


// It converts every truncated polynomial back.
// Before: every coefficient is in the interval [0, q/2^t].
// After: every coefficient is in the interval [0, q-1].
void Vector_detruncate(Polynomial vec[MLWE_ELL])
{
	for(uint8_t i=0; i<MLWE_ELL; i++)
		Poly_detruncate(vec+i);
}


// It computes the inner product of polynomial vectors a[...], b[...].
// result = a[0]*b[0] + ... + a[MLWE_ELL-1]*b[MLWE_ELL-1]
// Warning: this call changes the contents of a[...] and b[...]. 
void Vector_multiply(
		Polynomial * result, 
		Polynomial a[MLWE_ELL], 
		Polynomial b[MLWE_ELL])
{
	Vector_pre_NTT_computation(a);	// pre-computation on a[...]
	Vector_pre_NTT_computation(b);	// pre-computation on b[...]

	Vector_NTT_transform(a, 1);		// NTT transform on a[...]
	Vector_NTT_transform(b, 1);		// NTT transform on b[...]

	Vector_NTT_componentwise_multiply_and_add(result, a, b);
	
	Poly_NTT_transform(result, -1);	// inverse NTT transform on result
	Poly_post_NTT_computation(result);	// post-computation on result
}


// assume: the seed has already been initialized 
// isTransposed=0/1 is used to decide whether to generate A or transpose(A)
// if isTransposed=0, generate A normally
// otherwise, if isTransposed=1, generate A^T. 
void Get_uniform_matrix(
		Polynomial A[MLWE_ELL][MLWE_ELL],
		const unsigned char * matrix_seed,
		const unsigned int isTransposed)
{

	uint16_t i,j,k;
	uint16_t index = 0;    
	uint16_t temp;
	unsigned char buffer[MATRIX_SEED_EXPAND_BYTES];

 	unsigned char diversifier[8]  = {1,2,3,4,5,6,7,8}; 
	
	Polynomial * ptr; 

	unsigned char local_seed[MATRIX_SEED_BYTES+2];
	for(i=0; i<MATRIX_SEED_BYTES; i++)
		local_seed[i] = matrix_seed[i]; 

	for(i=0; i<MLWE_ELL; i++)
		for(j=0; j<MLWE_ELL; j++)
			{
				//First, decide the correct location 
				if(isTransposed == 0)	// A
					ptr = &(A[i][j]);
				else // A^t
					ptr = &(A[j][i]);
				
				// Then, update the nonce
				local_seed[MATRIX_SEED_BYTES] = (((i&0xF)<<4)^(j&0xF));
				
				AES_XOF_struct aes_state;
				seedexpander_init(&aes_state, local_seed, diversifier,  2048);
				seedexpander(&aes_state, buffer, MATRIX_SEED_EXPAND_BYTES); 
					
				for(k=index=0; k<MLWE_N; )
				{
					temp = (buffer[index])^((buffer[index+1]&0x1F) << 8);
					index += 2;

					if(temp < MLWE_Q)	// find an appropriate uniform value in [0, q-1]
						ptr->coefficients[k++] = (temp+MLWE_Q);
					if (index > MATRIX_SEED_EXPAND_BYTES-2) // buffer is empty
					{
						seedexpander(&aes_state, buffer, MATRIX_SEED_EXPAND_BYTES);
						index = 0;
					}                 
				}
			}
}


// It sets the polynomial sum according to the values of a[...] and b[...] 
// To be exact, we have, for every j, that, sum.coefficients[j] = a[0].coefficients[j]*b[0].coefficients[j] + ... + a[MLWE_ELL-1].coefficients[j]*b[MLWE_ELL-1].coefficients[j]
void Vector_NTT_componentwise_multiply_and_add(
		Polynomial *sum,
		const Polynomial a[MLWE_ELL],
		const Polynomial b[MLWE_ELL])
{	
	Polynomial temp;

	// for every j, sum.coefficients[j] = a[0].coefficients[j]*b[0].coefficients[j]. 
	Poly_NTT_componentwise_multiply(sum, a+0, b+0);
	
	for(uint8_t i=1; i<MLWE_ELL; i++)
	{
		// for every j, temp.coefficients[j] = a[0].coefficients[j]*b[0].coefficients[j]. 
		Poly_NTT_componentwise_multiply(&temp, a+i, b+i);
		
		// sum.coefficients[j] += temp.coefficients[j]
		// Here, 0 indicates no truncation 
		Poly_add_then_truncate(sum, &temp, 0);	
	}
}


// The pre-computation phase in the negative wrapped convolution. 
// Warning: this call changes the contents of vector[...].
void Vector_pre_NTT_computation(Polynomial vector[MLWE_ELL])
{
	for(uint8_t i=0; i<MLWE_ELL; i++)
		Poly_pre_NTT_computation(vector+i);
}


// The post-computation phase in the negative wrapped convolution. 
// Warning: this call changes the contents of vector[...].
void Vector_post_NTT_computation(Polynomial vector[MLWE_ELL])
{
	for(uint8_t i=0; i<MLWE_ELL; i++)
		Poly_post_NTT_computation(vector+i);
}


// It does the NTT transform (when direction=1), and the inverse-NTT transform (when direction=-1) for every polynomial in vector[...]. 
// Warning: this call changes the contents of vector[...].
void Vector_NTT_transform(
		Polynomial vector[MLWE_ELL], 
		const int direction)
{
	for(uint8_t i=0; i<MLWE_ELL; i++)
		Poly_NTT_transform(vector+i, direction);
}
