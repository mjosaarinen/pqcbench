
/**
* \file parsing.c
* \brief Implementation of parsing.h
*/

#include "parsing.h"

void hqc_secret_key_to_string(unsigned char* sk, const unsigned char* sk_seed, const unsigned char* pk) {
	memcpy(sk, sk_seed, SEED_BYTES);
	memcpy(sk + SEED_BYTES, pk, PUBLIC_KEY_BYTES);
}

void hqc_secret_key_from_string(vector_u32* x, vector_u32* y, unsigned char* pk, const unsigned char* sk) {
	unsigned char sk_seed[SEED_BYTES];
  memcpy(sk_seed, sk, SEED_BYTES);
  AES_XOF_struct* sk_seedexpander = (AES_XOF_struct*) malloc(sizeof(AES_XOF_struct));
  seedexpander_init(sk_seedexpander, sk_seed, sk_seed + 32, SEEDEXPANDER_MAX_LENGTH);

  vector_u32_fixed_weight(x, PARAM_OMEGA, sk_seedexpander);
	vector_u32_fixed_weight(y, PARAM_OMEGA, sk_seedexpander);
	memcpy(pk, sk + SEED_BYTES, PUBLIC_KEY_BYTES);

	free(sk_seedexpander);
}

void hqc_public_key_to_string(unsigned char* pk, const unsigned char* pk_seed, vector_u32* s) {
	int last_vector_bytes = (PARAM_N % 32) / 8 + 1;
	s->value[s->dim - 1] = s->value[s->dim - 1] >> (8 * (4 - last_vector_bytes));

	memcpy(pk, pk_seed, SEED_BYTES);
	memcpy(pk + SEED_BYTES, s->value, UTILS_VEC_N_BYTES);
}

void hqc_public_key_from_string(vector_u32* h, vector_u32* s, const unsigned char* pk) {
	unsigned char pk_seed[SEED_BYTES];
  memcpy(pk_seed, pk, SEED_BYTES);
  AES_XOF_struct* pk_seedexpander = (AES_XOF_struct*) malloc(sizeof(AES_XOF_struct));
  seedexpander_init(pk_seedexpander, pk_seed, pk_seed + 32, SEEDEXPANDER_MAX_LENGTH);
  vector_u32_set_random(h, pk_seedexpander);
  int last_vector_bytes = (PARAM_N % 32) / 8 + 1;

  memcpy(s->value, pk + SEED_BYTES, UTILS_VEC_N_BYTES);
  s->value[s->dim - 1] = s->value[s->dim - 1] << (8 * (4 - last_vector_bytes));

  h->by_position_flag = 0;
  s->by_position_flag = 0;

  free(pk_seedexpander);
}

void hqc_ciphertext_to_string(unsigned char* ct, vector_u32* u, vector_u32* v, const unsigned char* d) {
	int last_vector_bytes = (PARAM_N % 32) / 8 + 1;

	u->value[u->dim - 1] = u->value[u->dim - 1] >> (8 * (4 - last_vector_bytes));
	v->value[v->dim - 1] = v->value[v->dim - 1] >> (8 * (4 - last_vector_bytes));

	memcpy(ct, u->value, UTILS_VEC_N_BYTES);
	memcpy(ct + UTILS_VEC_N_BYTES, v->value, UTILS_VEC_N_BYTES);
	memcpy(ct + 2 * UTILS_VEC_N_BYTES, d, SHA512_BYTES);
}

void hqc_ciphertext_from_string(vector_u32* u, vector_u32* v, unsigned char* d, const unsigned char* ct) {
	int last_vector_bytes = (PARAM_N % 32) / 8 + 1;
	
	memcpy(u->value, ct, UTILS_VEC_N_BYTES);
	memcpy(v->value, ct + UTILS_VEC_N_BYTES, UTILS_VEC_N_BYTES);

	u->value[u->dim - 1] = u->value[u->dim - 1] << (8 * (4 - last_vector_bytes));
	v->value[v->dim - 1] = v->value[v->dim - 1] << (8 * (4 - last_vector_bytes));
	memcpy(d, ct + 2 * UTILS_VEC_N_BYTES, SHA512_BYTES);	

	u->by_position_flag =0;
	v->by_position_flag =0;
}

void hqc_vector_to_string(unsigned char* tab, vector_u32* v) {
	memcpy(tab, v->value, UTILS_VEC_K_BYTES);
}