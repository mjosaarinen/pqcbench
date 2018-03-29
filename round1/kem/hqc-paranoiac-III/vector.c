
/**
* \file vector.c
* \brief Implementation of vector.h
*/

#include "vector.h"

vector_u32* vector_u32_init(const uint32_t dim) {
	vector_u32* v = (vector_u32*) malloc(sizeof(vector_u32));
	v->dim = dim;
	v->value = calloc(dim,sizeof(uint32_t));
	v->by_position_flag = -1;
	
	return v;
}

void vector_u32_clear(vector_u32* v) {
	free(v->value);
	free(v);
}

int vector_u32_compare(vector_u32* v1, vector_u32* v2) {
	int res = 1;
	for(int i = 0; i < UTILS_VECTOR_ARRAY_SIZE; ++i) {	
		if(v1->value[i] != v2->value[i]) {
			res = 0;
			return res;
		}
	}
	return res;
}

void vector_u32_fixed_weight(vector_u32* v, const uint16_t weight, AES_XOF_struct* ctx) {
	unsigned long random_bytes_size = 3 * weight;
	unsigned char* rand_bytes = (unsigned char*) calloc(random_bytes_size, sizeof(unsigned char));

	seedexpander(ctx, rand_bytes, random_bytes_size);
	
	unsigned long j =0;
	uint32_t random_data;
	uint8_t exist;

	for(uint32_t i = 0; i < weight ; ++i) {
		exist = 0;
		do {
			if(j == random_bytes_size) {
				seedexpander(ctx, rand_bytes, random_bytes_size);
				j = 0;
			}

		  random_data  = ((uint32_t) rand_bytes[j++]) << 16;
		  random_data |= ((uint32_t) rand_bytes[j++]) << 8;
		  random_data |= rand_bytes[j++];	

		} while(random_data >= UTILS_REJECTION_THRESHOLD);

		random_data = random_data % PARAM_N;

		for(uint32_t k = 0 ; k < i ; k++) {
			if(v->value[k] == random_data) exist = 1;
		}
		if(exist == 1) {
			i--;
		} else {
			v->value[i] = random_data;
		}
	}

	v->by_position_flag = 1;
	free(rand_bytes);

}

void vector_u32_set_random(vector_u32* v, AES_XOF_struct* ctx) {
	uint8_t* rand_bytes = (uint8_t*) malloc(UTILS_VECTOR_ARRAY_BYTES * sizeof(uint8_t));

	seedexpander(ctx, rand_bytes, UTILS_VECTOR_ARRAY_BYTES);

	memcpy(v->value, rand_bytes, UTILS_VECTOR_ARRAY_BYTES);
	v->value[UTILS_VECTOR_ARRAY_SIZE - 1] &= UTILS_MASK;

	v->by_position_flag = 0;
	free(rand_bytes);
}

void vector_u32_set_random_from_randombytes(vector_u32* v) {
	uint32_t vector_bytes_size = (v->dim) * sizeof(uint32_t);
	uint8_t* rand_bytes = (uint8_t*) malloc(vector_bytes_size * sizeof(uint8_t));

	randombytes(rand_bytes, vector_bytes_size);
	memcpy(v->value, rand_bytes, vector_bytes_size);

	free(rand_bytes);
}	

void vector_u32_add(vector_u32* o, vector_u32* v1, vector_u32* v2) {
	if(v1->by_position_flag == 0 && v2->by_position_flag == 0) {
		vector_u32_add_by_coordinate(o, v1, v2);
	} else if(v1->by_position_flag == 1 && v2->by_position_flag == 0) {
		vector_u32_add_by_position_and_coordinate(o, v1, v2);
	} else if(v1->by_position_flag == 0 && v2->by_position_flag == 1) {
		vector_u32_add_by_position_and_coordinate(o, v2, v1);
	}
}

void vector_u32_add_by_coordinate(vector_u32* o, vector_u32* v1, vector_u32* v2) {
	for(uint16_t i = 0; i < o->dim ; ++i)	{
		o->value[i] = v1->value[i] ^ v2->value[i];
	}
}

void vector_u32_add_by_position_and_coordinate(vector_u32* o, vector_u32* v1, vector_u32* v2) {
	vector_u32* tmp = vector_u32_init(UTILS_VECTOR_ARRAY_SIZE);
	memcpy(tmp->value, v2->value, UTILS_VECTOR_ARRAY_BYTES);
	for(uint16_t i = 0 ; i < v1->dim ; ++i)	{
		int index = v1->value[i] / 32;
		tmp->value[index] ^= 1 << (31 - (v1->value[i] % 32));
	}
	memcpy(o->value, tmp->value, UTILS_VECTOR_ARRAY_BYTES);
	vector_u32_clear(tmp);
}

void vector_u32_mul(vector_u32* o, vector_u32* v1, vector_u32* v2) {
  uint32_t* precomputation_array = calloc(PARAM_N, sizeof(uint32_t));
  vector_u32_mul_precompute_rows(precomputation_array, v2->value);

  uint32_t* row = calloc(UTILS_VECTOR_ARRAY_SIZE, sizeof(uint32_t));
  uint32_t position;
  uint32_t index;

  for(uint32_t i = 0 ; i < v1->dim ; ++i) {
    position = v1->value[i];
    for(uint32_t j = 0 ; j < UTILS_VECTOR_ARRAY_SIZE - 1 ; ++j) { 
      index = 32 * j - position;
      if(index > PARAM_N) index += PARAM_N;
      row[j] = precomputation_array[index];
    }
    uint32_t j = UTILS_VECTOR_ARRAY_SIZE - 1;
    index = 32 * j - position;
    row[j] = precomputation_array[(index < PARAM_N ? index : index + PARAM_N)] & UTILS_MASK;
    int k = UTILS_VECTOR_ARRAY_SIZE;

    while(k--) {
      o->value[k] ^= row[k];
    } 
  }

  free(row);
  free(precomputation_array);
  o->by_position_flag = 0;
}

int vector_u32_mul_precompute_rows(uint32_t* o, const uint32_t* v) {
  int var;
  for(int i = 0 ; i < PARAM_N ; ++i) {
    var = 0;
    // All the bits that we need are in the same block
    if(((i % 32) == 0) && (i != PARAM_N - (PARAM_N % 32))) {
      var = 1;
    }
    // Cases where the bits are in before the last block, the last block and the first block 
    if(i > PARAM_N - 32) {
      if(i >= PARAM_N - (PARAM_N % 32)) {
        var = 2;
      }
      else {
        var = 3;
      }
    }

    switch(var) {
      case 0:
      	// Take bits in the last block and the first one
        o[i] = 0;
        o[i] += v[i / 32] << (i % 32);
        o[i] += v[(i / 32) + 1] >> (32 - (i % 32));
        break;

      case 1: 
        o[i] = v[i / 32];
        break;

      case 2: 
        o[i] = 0;
        o[i] += v[i / 32] << (i % 32);
        o[i] += v[0] >> (PARAM_N - i);
        break;

      case 3:
        o[i] = 0;
        o[i] += v[i / 32] << (i % 32);
        o[i] += v[(i / 32) + 1] >> (32 - (i % 32));
        o[i] += v[0] >> (32 - i + (PARAM_N % 32));
        break;

      default: 
        return -1;
    }
  }
  return 0;

}

void vector_u32_extend(vector_u32* o, vector_u32* v) {
	memcpy(o->value, v->value, v->dim * sizeof(uint32_t));
	o->by_position_flag = 0;
}

void vector_u32_print(vector_u32* v, int param) {
	if(param == PARAM_K) {
		for (uint16_t i = 0; i < v->dim; ++i)	{
			print_bytes(v->value[i], 4);
		}
	}

	if(param == PARAM_N || param == PARAM_N1 || param == PARAM_N1N2) {

		for (uint16_t i = 0; i < (v->dim - 1); ++i)	{
			print_bytes(v->value[i], 4);
		}	
		print_bytes(v->value[v->dim - 1], (param % 32) / 8 + 1);
	}

	if(param == PARAM_OMEGA || param == PARAM_OMEGA_R) {
		for(int i = 0; i < param; ++i)	{
			printf("%d ", v->value[i]);
		}
	}
}

void print_bytes(uint32_t value, int size) {
	for(int i = 0; i < size; ++i)	{
		uint8_t tmp = value >> (8 * (3-i));
		printf("%02x", tmp);
	}
}
