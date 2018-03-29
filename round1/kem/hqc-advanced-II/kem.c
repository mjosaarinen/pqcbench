
/**
  * \file kem.c
  * \brief Implementation of api.h
  */

#include "api.h"
#include "parameters.h"
#include "hqc.h"

/**
  *\fn int crypto_kem_keypair(unsigned char* pk, unsigned char* sk)
  *\brief Keygen of the HQC_KEM IND_CAA2 scheme
  *
  * The public key is composed of the syndrome s as well as the seed used to generate the vector h.
  *
  * The secret key is composed of the seed used to generate vectors x and y.
  * As a technicality, the public key is appended to the secret key in order to respect NIST API.
  *
  * \param[out] pk String containing the public key
  * \param[out] sk String containing the secret key
  * return 0 if keygen is successful
  */
int crypto_kem_keypair(unsigned char* pk, unsigned char* sk) {
  #ifdef VERBOSE
	 printf("\n\n\n\n### KEYGEN ###");  
  #endif  

  hqc_pke_keygen(pk, sk);  
	return 0;
}

/**
  *\fn int crypto_kem_enc(unsigned char* ct, unsigned char* ss, const unsigned char* pk)
  *\brief Encapsulation of the HQC_KEM IND_CAA2 scheme
  *
  * \param[out] ct String containing the ciphertext
  * \param[out] ss String containing the shared secret
  * \param[in] pk String containing the public key
  * return 0 if encapsulation is successful
  */
int crypto_kem_enc(unsigned char* ct, unsigned char* ss, const unsigned char* pk) {
  #ifdef VERBOSE
   printf("\n\n\n\n### ENCAPS ###");  
  #endif    
	  
  //Computing m
  vector_u32* m   =  vector_u32_init(UTILS_VEC_K_ARRAY_SIZE);
  vector_u32_set_random_from_randombytes(m);
    
  //Generating G function
  unsigned char diversifier_bytes[8];
  for (int i = 0; i < 8; ++i) {
    diversifier_bytes[i] = 0;
  }
  unsigned char seed_G[UTILS_VEC_K_BYTES];
  unsigned char m_bytes[UTILS_VEC_K_BYTES];
  hqc_vector_to_string(m_bytes, m);
  memcpy(seed_G, m_bytes, UTILS_VEC_K_BYTES);
  AES_XOF_struct* G_seedexpander = (AES_XOF_struct*) malloc(sizeof(AES_XOF_struct));
  seedexpander_init(G_seedexpander, seed_G, diversifier_bytes, SEEDEXPANDER_MAX_LENGTH);

  //Computing theta
  unsigned char theta[SEED_BYTES];
  seedexpander(G_seedexpander, theta, SEED_BYTES);

  #ifdef VERBOSE
    printf("\n\npk: "); for(int i = 0 ; i < PUBLIC_KEY_BYTES ; ++i) printf("%02x", pk[i]);
    printf("\n\nm: "); vector_u32_print(m, PARAM_K);
    printf("\n\ntheta: "); for(int i = 0 ; i < SEED_BYTES ; ++i) printf("%02x", theta[i]);
  #endif

  //Encrypting m
  vector_u32* u =  vector_u32_init(UTILS_VECTOR_ARRAY_SIZE);
  vector_u32* v   =  vector_u32_init(UTILS_VECTOR_ARRAY_SIZE);
  hqc_pke_encrypt(u, v, m, theta, pk);
   
  //Computing d
  unsigned char d[SHA512_BYTES];
  sha512(d, m_bytes, UTILS_VEC_K_BYTES);

  //Computing shared secret
  unsigned char mc[UTILS_VEC_K_BYTES + 2 * UTILS_VECTOR_ARRAY_BYTES];
  memcpy(mc, m_bytes, UTILS_VEC_K_BYTES);
  memcpy(mc + UTILS_VEC_K_BYTES, u->value, UTILS_VECTOR_ARRAY_BYTES);
  memcpy(mc + UTILS_VEC_K_BYTES + UTILS_VECTOR_ARRAY_BYTES, v->value, UTILS_VECTOR_ARRAY_BYTES);
  sha512(ss, mc, UTILS_VEC_K_BYTES + 2 * UTILS_VECTOR_ARRAY_BYTES);

  //Computing ciphertext
  hqc_ciphertext_to_string(ct, u, v, d);

  #ifdef VERBOSE
    printf("\n\nd: "); for(int i = 0 ; i < SHA512_BYTES ; ++i) printf("%02x", d[i]);
    printf("\n\nciphertext: "); for(int i = 0 ; i < CIPHERTEXT_BYTES ; ++i) printf("%02x", ct[i]);
    printf("\n\nsecret 1: "); for(int i = 0 ; i < SHARED_SECRET_BYTES ; ++i) printf("%02x", ss[i]);
  #endif

  vector_u32_clear(u);
  vector_u32_clear(v);
  vector_u32_clear(m);
  free(G_seedexpander);

	return 0;
}

/**
  *\fn int crypto_kem_dec(unsigned char* ss, const unsigned char* ct, const unsigned char* sk)
  *\brief Decapsulation of the HQC_KEM IND_CAA2 scheme
  *
  * \param[out] ss String containing the shared secret
  * \param[in] ct String containing the cipĥertext
  * \param[in] sk String containing the secret key
  * return 0 if decapsulation is successful, -1 otherwise
  */
int crypto_kem_dec(unsigned char* ss, const unsigned char* ct, const unsigned char* sk) {
  #ifdef VERBOSE
   printf("\n\n\n\n### DECAPS ###");  
  #endif 
  // Retrieving u, v and d from ciphertext   
	vector_u32* u = vector_u32_init(UTILS_VECTOR_ARRAY_SIZE);
	vector_u32* v = vector_u32_init(UTILS_VECTOR_ARRAY_SIZE);
	unsigned char d[SHA512_BYTES];
	hqc_ciphertext_from_string(u, v , d, ct);

  //Retrieving pk from sk
  unsigned char pk[PUBLIC_KEY_BYTES];
  memcpy(pk, sk + SEED_BYTES, PUBLIC_KEY_BYTES);

  #ifdef VERBOSE
    printf("\n\npk: "); for(int i = 0 ; i < PUBLIC_KEY_BYTES ; ++i) printf("%02x", pk[i]);
    printf("\n\nsk: "); for(int i = 0 ; i < SECRET_KEY_BYTES ; ++i) printf("%02x", sk[i]);
    printf("\n\nciphertext: "); for(int i = 0 ; i < CIPHERTEXT_BYTES ; ++i) printf("%02x", ct[i]);
  #endif

	//Decryting
	vector_u32* m = vector_u32_init(UTILS_VEC_K_ARRAY_SIZE);
	hqc_pke_decrypt(m, u, v, sk);

	//Generating G function
  unsigned char m_bytes[UTILS_VEC_K_BYTES];
  hqc_vector_to_string(m_bytes, m);
  unsigned char diversifier_bytes[8];
  for (int i = 0; i < 8; ++i) {
    diversifier_bytes[i] = 0;
  }
  unsigned char seed_G[UTILS_VEC_K_BYTES];
  memcpy(seed_G, m_bytes, UTILS_VEC_K_BYTES);
  AES_XOF_struct* G_seedexpander = (AES_XOF_struct*) malloc(sizeof(AES_XOF_struct));
  seedexpander_init(G_seedexpander, seed_G, diversifier_bytes, SEEDEXPANDER_MAX_LENGTH);

  //Computing theta
  unsigned char theta[SEED_BYTES];
  seedexpander(G_seedexpander, theta, SEED_BYTES);

  #ifdef VERBOSE
    printf("\n\ntheta: "); for(int i = 0 ; i < SEED_BYTES ; ++i) printf("%02x", theta[i]);
    printf("\n\n## Checking Ciphertext- Begin ##");
  #endif

  //Encrypting m'
  vector_u32* u2 = vector_u32_init(UTILS_VECTOR_ARRAY_SIZE);
  vector_u32* v2   = vector_u32_init(UTILS_VECTOR_ARRAY_SIZE);
  hqc_pke_encrypt(u2, v2, m, theta, pk);

  // Checking that c = c' and abort otherwise
  int abort = 0;
  if(vector_u32_compare(u, u2) == 0) abort = 1;
  if(vector_u32_compare(v, v2) == 0) abort = 1;
  
  // Computing d'
  unsigned char d2[SHA512_BYTES];
  sha512(d2, m_bytes, UTILS_VEC_K_BYTES);

  // Checking that d = d' and abort otherwise
  if(memcmp(d, d2, SHA512_BYTES) != 0) {
    abort = 1;
  }  

  #ifdef VERBOSE
    printf("\n\nu2: "); vector_u32_print(u2, PARAM_N);
    printf("\n\nv2: "); vector_u32_print(v2, PARAM_N);
    printf("\n\nd2: "); for(int i = 0 ; i < SHA512_BYTES ; ++i) printf("%02x", d2[i]);
  #endif

  if(abort == 1) {
    #ifdef VERBOSE
      printf("\n\nCheck result : ABORT");
      printf("\n\n## Checking Ciphertext- End ##");
    #endif

    memset(ss, 0, SHARED_SECRET_BYTES);
   return -1;
  }

  //Computing shared secret
  unsigned char mc[UTILS_VEC_K_BYTES + 2 * UTILS_VECTOR_ARRAY_BYTES];
  memcpy(mc, m_bytes, UTILS_VEC_K_BYTES);
  memcpy(mc + UTILS_VEC_K_BYTES, u->value, UTILS_VECTOR_ARRAY_BYTES);
  memcpy(mc + UTILS_VEC_K_BYTES + UTILS_VECTOR_ARRAY_BYTES, v->value, UTILS_VECTOR_ARRAY_BYTES);
  sha512(ss, mc, UTILS_VEC_K_BYTES + 2 * UTILS_VECTOR_ARRAY_BYTES);

  #ifdef VERBOSE
    printf("\n\nCheck result: SUCCESS");
    printf("\n\nsecret2: "); for(int i = 0 ; i < SHARED_SECRET_BYTES ; ++i) printf("%02x", ss[i]);
    printf("\n\n## Checking Ciphertext- End ##");
  #endif

  vector_u32_clear(u);
  vector_u32_clear(u2);
  vector_u32_clear(v);
  vector_u32_clear(v2);
	vector_u32_clear(m);
	free(G_seedexpander);

	return 0;
}