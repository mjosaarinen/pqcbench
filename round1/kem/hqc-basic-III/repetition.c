
/**
* \file repetition.c
* \brief Implementation of repetition.h
*/

#include <stdlib.h>
#include "repetition.h"

void repetition_code_encode(vector_u32* em, vector_u32* m) {
	uint8_t tmp [PARAM_N1N2];
	memset(tmp, 0 , PARAM_N1N2);
	uint8_t val;
	
	for(uint16_t i = 0; i < (m->dim - 1); ++i)	{
		for(uint8_t j = 0; j < 32; ++j) {
			val = (m->value[i]	>> (31 - j)) & 1;
			if(val){
				uint32_t index = (i * 32 + j) * PARAM_N2; 
				for (uint8_t k = 0; k < PARAM_N2; ++k) {
					tmp[index + k] = 1;
				}
			}
		}	
	}
	
	for(uint8_t j = 0; j < (PARAM_N1 % 32); ++j) {
		uint8_t val = (m->value[m->dim - 1]	>> (31 - j)) & 1;
		if(val){
			uint32_t index = ((m->dim - 1) * 32 + j) * PARAM_N2; 
			for(uint8_t k = 0; k < PARAM_N2; ++k) {
				tmp[index + k] = 1;
			}
		}
	}	
	
	array_to_vector(em, tmp);
}

void array_to_vector(vector_u32* o, uint8_t* v) {
	for(uint16_t i = 0 ; i < (o->dim - 1) ; ++i) {
		for(uint8_t j = 0 ; j < 32 ; ++j) {
			o->value[i] |= v[j + i * 32] << (31 - j);
		}
	}
	
	for(uint8_t j = 0 ; j < PARAM_N1N2 % 32 ; ++j) {
		o->value[o->dim - 1] |= ((uint32_t) v[j + 32 * (o->dim - 1)]) << (31 - j);
	}
}

void repetition_code_decode(vector_u32* m, vector_u32* em) {
	int t = 0;
 	int k = 1;
 	int weight = 0;
 	for(uint16_t i = 0; i < em->dim; ++i) {
   	for(uint8_t j = 0; j < 32; ++j) {
		  if((em->value[i] >> (31 - j )) & 1 ) {
				weight ++;
			}	

			if(!(k % PARAM_N2)) {
				if(weight >= (PARAM_T + 1)) {
					int index = t / 32;
					m->value[index] |= 1 << (31 - (t % 32));
					weight = 0;
					t++;
				} else {
				weight = 0;
				t++;
				}
			}

			k++;
		}
	}
}
