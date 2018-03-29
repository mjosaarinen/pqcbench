#ifndef VECTOR_H
#define VECTOR_H

#include "parameter.h"
#include "polynomial.h"
#include "reduce.h"

void Vector_truncate(Polynomial vec[MLWE_ELL]);
void Vector_detruncate(Polynomial vec[MLWE_ELL]);
		
void Get_uniform_matrix(
		Polynomial A[MLWE_ELL][MLWE_ELL],
		const unsigned char * matrix_seed,
		const unsigned int isTransposed);
		
void Vector_multiply(
		Polynomial * result, 
		Polynomial a[MLWE_ELL], 
		Polynomial b[MLWE_ELL]);
void Vector_pre_NTT_computation(Polynomial vector[MLWE_ELL]);
void Vector_post_NTT_computation(Polynomial vector[MLWE_ELL]);
void Vector_NTT_transform(
		Polynomial vector[MLWE_ELL], 
		const int direction);
void Vector_NTT_componentwise_multiply_and_add(
		Polynomial product[MLWE_ELL],
		const Polynomial a[],
		const Polynomial b[]);
#endif