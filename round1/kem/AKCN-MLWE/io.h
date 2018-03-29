#ifndef IO_H
#define IO_H

#include "parameter.h"
#include "polynomial.h"

 
#define unpack_signal(signal, string) group_decompress(signal, string, UNIT_BYTES_IN_SIGNAL)
#define pack_signal(string, signal) group_compress(string, signal, UNIT_BYTES_IN_SIGNAL)

#define pack_key(string, key)		group_compress(string, key, UNIT_BYTES_IN_KEY)
#define unpack_key(key, string)		group_decompress(key, string, UNIT_BYTES_IN_KEY)


void compress(
		unsigned char * string, 
		const unsigned int * value, 
		const unsigned int number_of_bytes);

void decompress(
		unsigned int * value, 
		const unsigned char * string, 
		const unsigned int number_of_bytes);

void group_compress(
		unsigned char * string, 
		const unsigned int * value, 
		const unsigned int number_of_bytes);

void group_decompress(
		unsigned int * value, 
		const unsigned char * string, 
		const unsigned int number_of_bytes);



void pack_small_poly(unsigned char *result, const Polynomial *in);
void unpack_small_poly(Polynomial * result, const unsigned char *in);

void pack_sk(unsigned char * string, const Polynomial *sk);
void unpack_sk(Polynomial *sk, const unsigned char * string);


void pack_truncated_poly(unsigned char * string, const Polynomial *truncated_poly);
void unpack_truncated_poly(Polynomial *truncated_poly, const unsigned char * string);

void pack_truncated_vector(unsigned char * string, const Polynomial truncated_vector[]);
void unpack_truncated_vector(Polynomial truncated_vector[], const unsigned char * string);

void unpack_ct(
		Polynomial * Y2,
		unsigned int Signal[MLWE_N],
		const unsigned char * ct);
		
void pack_ct(
		unsigned char * ct,
		const Polynomial Y2[MLWE_ELL],
		unsigned int Signal[MLWE_N]);


#endif
