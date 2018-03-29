
/**
* \file tensor.c
* \brief Implementation of tensor.c
*/

#include "tensor.h"
#include "parsing.h"

void tensor_code_encode(vector_u32* em, vector_u32* m) {
	vector_u32* tmp = vector_u32_init(UTILS_TENSOR_CODEWORD_ARRAY_SIZE);
	vector_u32* c = vector_u32_init(UTILS_BCH_CODEWORD_ARRAY_SIZE);
	bch_code_encode(c, m);
	repetition_code_encode(tmp, c);
	vector_u32_extend(em, tmp);

	#ifdef VERBOSE
    printf("\n\nBCH code word: "); vector_u32_print(c, PARAM_N1);
    printf("\n\nTensor code word: "); vector_u32_print(tmp, PARAM_N1N2);
  #endif

	em->by_position_flag = 0;
	vector_u32_clear(tmp);
	vector_u32_clear(c);
}

void tensor_code_decode(vector_u32* m, vector_u32* em) {
	vector_u32* c = vector_u32_init(UTILS_BCH_CODEWORD_ARRAY_SIZE);
	c->by_position_flag = 0;
	
	repetition_code_decode(c, em);
	bch_code_decode(m, c);

	#ifdef VERBOSE
    printf("\n\nrepetition decoding result (the input for the BCH decoding algorithm): "); vector_u32_print(c, PARAM_N1);
  #endif
	vector_u32_clear(c);	
}