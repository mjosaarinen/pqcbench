#ifndef IO_H
#define IO_H

#include "parameter.h"
#include "polynomial.h"


#define unpack_signal(signal, string) group_decompress(signal, string, UNIT_BYTES_IN_SIGNAL,RLWE_N/8)
#define pack_signal(string, signal) group_compress(string, signal, UNIT_BYTES_IN_SIGNAL, RLWE_N/8)


#define pack_key(string, key)		group_compress(string, key, UNIT_BYTES_IN_KEY, (SEC_SIGNIFICANT_BITS + SEC_PADDING_OF_SIGNIFICANT_BITS)/8)
#define unpack_key(key, string)		group_decompress(key, string, UNIT_BYTES_IN_KEY, (SEC_SIGNIFICANT_BITS + SEC_PADDING_OF_SIGNIFICANT_BITS)/8)


#define pack_sk(string, poly_ptr)	pack_small_poly(string, poly_ptr)
#define unpack_sk(poly_ptr, string)	unpack_small_poly(poly_ptr, string)
	

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
		const unsigned int number_of_bytes,
		const unsigned int number_of_groups);
void group_decompress(
		unsigned int * value, 
		const unsigned char * string, 
		const unsigned int number_of_bytes,
		const unsigned int number_of_groups);

		
void pack_small_poly(unsigned char * string, const Polynomial *poly);
void unpack_small_poly(Polynomial * poly, const unsigned char * string);


void pack_truncated_poly(unsigned char * string, const Polynomial *truncated_poly);
void unpack_truncated_poly(Polynomial *truncated_poly, const unsigned char * string);


void pack_ct(
		unsigned char * ct,
		const Polynomial * Y2,
		const unsigned int Signal[RLWE_N]);
		
void unpack_ct(
		Polynomial * Y2,
		unsigned int Signal[RLWE_N],
		const unsigned char * ct);
		
#endif
