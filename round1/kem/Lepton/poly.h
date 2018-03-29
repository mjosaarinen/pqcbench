/*
The file implements the basic polynomial operations
*/
#ifndef POLY_H
#define POLY_H

#include <stdint.h>
#include<string.h>
#include "params.h"

#define RIGHT_ONE(n)  ((1<<n)-1)
#define LEFT_ONE(n)   (RIGHT_ONE(n)<<(32-n))
//define polynomial type
typedef uint32_t poly[POLY_WORDS];
typedef uint16_t poly_noise[PARAM_K];

//transforms between polynomial representations and byte representations
void poly_from_bytes(poly r, const uint8_t *cr);
void poly_to_bytes(uint8_t *cr, const poly r);

/*
Function: Sample_\chi^n algorithm
Inputs  : a random seed, and a nonce
Outputs : r = Sample_chi(seed||nonce)
*/
int poly_getnoise(poly_noise r,const unsigned char *seed, uint16_t nonce);
/*
Function: Sampling random polynomial
Inputs  : a random seed, and a nonce
Outputs : r = Samp(seed||nonce)
*/
void poly_getrandom(poly r,const unsigned char *seed, uint16_t nonce);

/*
Function: multiply a polynomial with a noise polynomial
Inputs  : a polynomial a, and a noise polynomial s
Outputs : r = a * s
*/
void poly_mul(poly r,const poly a,const poly_noise s);

/*
Function: add two polynomials
Inputs  : two polynomials a and b
Outputs : r = a+b
*/
void poly_add(poly r, const poly a, const poly b);

/*
Function: add a polynomial with a noise polynomial
Inputs  : a polynomial a, and a noise polynomial b
Outputs : r = a+b
*/
void poly_addnoise(poly r, const poly a, const poly_noise b);
#endif
