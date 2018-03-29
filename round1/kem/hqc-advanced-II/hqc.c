
/**
 * \file hqc.c
 * \brief Implementation of hqc.h
 */
 
#include "hqc.h"

void hqc_pke_keygen(unsigned char* pk, unsigned char* sk) {

	// Create seed_expanders for public key and secret key
	unsigned char sk_seed[SEED_BYTES];
	randombytes(sk_seed, SEED_BYTES);
	AES_XOF_struct* sk_seedexpander = (AES_XOF_struct*) malloc(sizeof(AES_XOF_struct));
	seedexpander_init(sk_seedexpander, sk_seed, sk_seed + 32, SEEDEXPANDER_MAX_LENGTH);
		
	unsigned char pk_seed[SEED_BYTES];
	randombytes(pk_seed, SEED_BYTES);
	AES_XOF_struct* pk_seedexpander = (AES_XOF_struct*) malloc(sizeof(AES_XOF_struct));
	seedexpander_init(pk_seedexpander, pk_seed, pk_seed + 32, SEEDEXPANDER_MAX_LENGTH);

	// Compute secret key
	vector_u32* x = vector_u32_init(PARAM_OMEGA);
	vector_u32* y = vector_u32_init(PARAM_OMEGA);

	vector_u32_fixed_weight(x, PARAM_OMEGA, sk_seedexpander);
	vector_u32_fixed_weight(y, PARAM_OMEGA, sk_seedexpander);
	
	// Compute public key
	vector_u32* h = vector_u32_init(UTILS_VECTOR_ARRAY_SIZE);
	vector_u32_set_random(h, pk_seedexpander);
	
	vector_u32* s = vector_u32_init(UTILS_VECTOR_ARRAY_SIZE);

	vector_u32_mul(s, y, h);
	vector_u32_add(s, x, s);
	
	// Parse keys to string	
	hqc_public_key_to_string(pk, pk_seed, s);
	hqc_secret_key_to_string(sk, sk_seed, pk);

	#ifdef VERBOSE
    printf("\n\nsk_seed: "); for(int i = 0 ; i < SEED_BYTES ; ++i) printf("%02x", sk_seed[i]);
    printf("\n\nx: "); vector_u32_print(x, PARAM_OMEGA);
    printf("\n\ny: "); vector_u32_print(y, PARAM_OMEGA);

    printf("\n\npk_seed: "); for(int i = 0 ; i < SEED_BYTES ; ++i) printf("%02x", pk_seed[i]);
    printf("\n\nh: "); vector_u32_print(h, PARAM_N);
    printf("\n\ns: "); vector_u32_print(s, PARAM_N);

    printf("\n\nsk: "); for(int i = 0 ; i < SECRET_KEY_BYTES ; ++i) printf("%02x", sk[i]);
    printf("\n\npk: "); for(int i = 0 ; i < PUBLIC_KEY_BYTES ; ++i) printf("%02x", pk[i]);
  #endif

	free(sk_seedexpander);
	free(pk_seedexpander);
	vector_u32_clear(x);
	vector_u32_clear(y);
	vector_u32_clear(h);
	vector_u32_clear(s);
}

void hqc_pke_encrypt(vector_u32* u, vector_u32* v, vector_u32* m, unsigned char* theta, const unsigned char* pk) {

	// Create seed_expander from theta
	AES_XOF_struct* seedexpander = (AES_XOF_struct*) malloc(sizeof(AES_XOF_struct));
  seedexpander_init(seedexpander, theta, theta + 32, SEEDEXPANDER_MAX_LENGTH);

  // Retrieve public key vector from string
  vector_u32* h = vector_u32_init(UTILS_VECTOR_ARRAY_SIZE);
  vector_u32* s  = vector_u32_init(UTILS_VECTOR_ARRAY_SIZE);
  hqc_public_key_from_string(h, s, pk);
 
 	// Generate r1, r2 and e
  vector_u32* r1 = vector_u32_init(PARAM_OMEGA_R);
  vector_u32* r2 = vector_u32_init(PARAM_OMEGA_R);
  vector_u32* e  = vector_u32_init(PARAM_OMEGA_E);

 	vector_u32_fixed_weight(r1, PARAM_OMEGA_R, seedexpander);
 	vector_u32_fixed_weight(r2, PARAM_OMEGA_R, seedexpander);
 	vector_u32_fixed_weight(e, PARAM_OMEGA_E, seedexpander);
 	
	// Compute u = r1 + r2.h
	vector_u32_mul(u, r2, h);
	vector_u32_add(u, r1, u);

	// Compute v = m.G by encoding the message
 	tensor_code_encode(v, m);

	// Compute v = m.G + s.r2 + e
	vector_u32* tmp  = vector_u32_init(UTILS_VECTOR_ARRAY_SIZE); 	
 	vector_u32_mul(tmp, r2 , s);
 	vector_u32_add(tmp, tmp, e);
 	vector_u32_add(v, tmp, v);

 	#ifdef VERBOSE
    printf("\n\nh: "); vector_u32_print(h, PARAM_N);
    printf("\n\ns: "); vector_u32_print(s, PARAM_N);
    printf("\n\nr1: "); vector_u32_print(r1, PARAM_OMEGA_R);
    printf("\n\nr2: "); vector_u32_print(r2, PARAM_OMEGA_R);
    printf("\n\ne: "); vector_u32_print(e, PARAM_OMEGA_E);

    printf("\n\nu: "); vector_u32_print(u, PARAM_N);
    printf("\n\nv: "); vector_u32_print(v, PARAM_N);
  #endif

 	vector_u32_clear(h);
 	vector_u32_clear(s);
 	vector_u32_clear(r1);
 	vector_u32_clear(r2);
 	vector_u32_clear(e);
 	vector_u32_clear(tmp);
 	free(seedexpander);
}

void hqc_pke_decrypt(vector_u32* m, vector_u32* u, vector_u32* v, const unsigned char* sk) {

	// Retrieve x, y, pk from secret 
	vector_u32* x = vector_u32_init(PARAM_OMEGA);
	vector_u32* y = vector_u32_init(PARAM_OMEGA);
	unsigned char pk[PUBLIC_KEY_BYTES];
	hqc_secret_key_from_string(x, y, pk, sk);
	
	// Compute v - u.y
	vector_u32* tmp  = vector_u32_init(UTILS_VECTOR_ARRAY_SIZE);
	vector_u32_mul(tmp, y, u);
	vector_u32_add(tmp, v, tmp);


  #ifdef VERBOSE
    printf("\n\nu: "); vector_u32_print(u, PARAM_N);
    printf("\n\nv: "); vector_u32_print(v, PARAM_N);
    printf("\n\ny: "); vector_u32_print(y, PARAM_OMEGA);
    printf("\n\nv - u.y: "); vector_u32_print(tmp, PARAM_N);
  #endif

	// Compute m by decoding v - u.y
	tensor_code_decode(m, tmp);

	vector_u32_clear(x);
	vector_u32_clear(y);
	vector_u32_clear(tmp);
}