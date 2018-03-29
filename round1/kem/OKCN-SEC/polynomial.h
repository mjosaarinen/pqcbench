#ifndef POLYNOMIAL_H
#define POLYNOMIAL_H

#include "parameter.h"
#include "reduce.h"

typedef struct{
	unsigned int coefficients[RLWE_N];
} Polynomial;

void Get_small_poly(Polynomial * ptr, unsigned char * seed, unsigned int nonce);
void Get_uniform_poly(Polynomial * A, const unsigned char * seed);

void Poly_multiply(Polynomial * product, const Polynomial * a, const Polynomial * b);
void Poly_pre_NTT_computation(Polynomial * ptr);
void Poly_NTT_transform(Polynomial * ptr, const int direction);
void Poly_NTT_componentwise_multiply(Polynomial * product, const Polynomial * a, const Polynomial * b);
void Poly_post_NTT_computation(Polynomial * ptr);
void Butterfly(unsigned int * X, unsigned int * Y, const unsigned int index);

void Poly_add(Polynomial * sum, const Polynomial * t);

void Poly_truncate(Polynomial * ptr);
void Poly_detruncate(Polynomial * ptr);

void Poly_OKCN_Con(
		unsigned int key[RLWE_N], 
		unsigned int signal[RLWE_N], 
		const Polynomial * ptr,
		const char error[CON_ERROR_BYTES]);
void Poly_OKCN_Rec(
		unsigned int key[RLWE_N], 
		const Polynomial *sigma, 
		const unsigned int signal[RLWE_N]);
#endif
