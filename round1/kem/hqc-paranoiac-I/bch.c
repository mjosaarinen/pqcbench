
/**
* \file bch.c
* \brief Implementation of BCH code
*/

/* Portions of this code are somewhat inspired from the implementation of BCH code found here https://github.com/torvalds/linux/blob/master/lib/bch.c */

#include "bch.h"

int16_t gf_get_antilog(gf_tables* tables, int16_t i) {
	return tables->antilog_tab[i];
}

int16_t gf_get_log(gf_tables* tables, int16_t i) {
	return tables->log_tab[i];
}

int16_t	gf_mod(int16_t i) {
	return (i < PARAM_GF_MUL_ORDER) ? i : i - PARAM_GF_MUL_ORDER; 
}

void bch_code_encode(vector_u32* em, vector_u32* m) {
	uint8_t tmp1[PARAM_K];
	uint8_t tmp2[PARAM_N1];
	uint8_t g [PARAM_G];
	memset(tmp2, 0, PARAM_N1);

	vector_message_to_array(tmp1, m);
	get_generator_poly(g);
	lfsr_encoder(tmp2, g, tmp1);
	codeword_to_vector(em, tmp2);
}

void vector_message_to_array(uint8_t* o, vector_u32* v) { 
	for (uint8_t i = 0 ; i < v->dim ; ++i)	{
		for (uint8_t j = 0 ; j < 32 ; ++j) {
			o[j + i * 32] = v->value[i] >> (31 - j) & 1;
		}
	}
}

void get_generator_poly(uint8_t* g) {
	char* g_poly_string = GENERATOR_POLY, *pos = g_poly_string;
	uint8_t g_bytes_size = (PARAM_G / 8) + 1;
	unsigned char tmp[g_bytes_size];

	for (int i = 0; i < g_bytes_size; ++i)	{
		sscanf(pos, "%2hhx", &tmp[i]);
		pos += 2;
	}

	for (int i = 0; i < (g_bytes_size - 1) ; ++i)	{
		for (int j = 0; j < 8; ++j)	{
			g[j + i*8] = (tmp[i] & (1 << (7 - j))) >> (7 - j);
		}
	}

	for (int j = 0; j < PARAM_G % 8 ; ++j)	{
			g[j + (g_bytes_size - 1) * 8] = (tmp[g_bytes_size - 1] & (1 << (7 - j))) >> (7 - j);
	}
}

void lfsr_encoder(uint8_t* em, uint8_t* g, uint8_t* m) {
	int gate_value = 0;
	// Compute the Parity-check digits
	for (int i = PARAM_K-1; i >= 0; --i) {

		gate_value = m[i] ^ em[PARAM_N1 - PARAM_K - 1];
		
		if (gate_value) {
			for (int j = PARAM_N1 - PARAM_K - 1; j > 0; --j)	{
				em[j] = em[j-1] ^ g[j];				
			}

		} else {
			for (int j = PARAM_N1 - PARAM_K - 1; j > 0; --j)	{
				em[j] = em[j-1];			
			}	
		}

		em[0] = gate_value;	
	}

	// Add the message 
	int index = 0;
	for (int i = PARAM_N1 - PARAM_K ;  i < PARAM_N1 ; ++i) {
		em[i] = m[index];
		index++;
	}
}

void codeword_to_vector(vector_u32* v, uint8_t* c) {
	for (uint8_t i = 0 ; i < (v->dim - 1) ; ++i) {
		for (uint8_t j = 0 ; j < 32 ; ++j) {
			v->value[i] |= c[j + i * 32] << (31 - j);
		}
	}

	for (uint8_t j = 0 ; j < PARAM_N1 % 32 ; ++j) {
		v->value[v->dim - 1] |= ((uint32_t) c[j + 32 * (v->dim - 1)]) << (31 - j);
	}
}

void bch_code_decode(vector_u32* m, vector_u32* em) {
	// Generate Galois Field GF(2^10) using the primitive polynomial defined in PARAM_POLY
	// GF(2^10) is represented by the lookup tables (Log Anti-Log tables)
	gf_tables* tables = gf_tables_init();
 	gf_generation(tables);      

 	// Calculate the 2 * PARAM_DELTA syndromes
	syndrome_set* synd_set = syndrome_init(); 
	syndrome_gen(synd_set, tables, em); 

	// Using the simplified Berlekamp's algorithm we compute the error location polynomial sigma(x)
  sigma_poly* sigma = sigma_poly_init(2 * PARAM_DELTA);
  get_error_location_poly(sigma, tables, synd_set);

  #ifdef VERBOSE
    printf("\n\nsyndromes: "); for(uint16_t i = 0 ; i < synd_set->size ; ++i) printf("%d ", synd_set->tab[i]);
    printf("\n\nerror location polynomial sigma(x) = : "); 
    for(uint16_t i = 0 ; i < sigma->deg ; ++i) printf("%d x^%d + ", sigma->value[i], i);
    printf("%d x^%d", sigma->value[sigma->deg], sigma->deg);
  #endif

  // Compute the error location numbers using the Chien Search algorithm
  uint16_t error_pos [PARAM_DELTA];
 	memset(error_pos, 0, PARAM_DELTA * 2);
 	uint16_t size = 0;
 	chien_search(error_pos, &size, tables, sigma); 
 	#ifdef VERBOSE
    printf("\n\nthe error location numbers: "); for(uint16_t i = 0 ; i < size ; ++i) printf("%d ", error_pos[i]);
  #endif

 	// Compute the error polynomial 
 	vector_u32* e = vector_u32_init(UTILS_BCH_CODEWORD_ARRAY_SIZE);
 	e->by_position_flag = 0;
 	error_poly_gen(e, error_pos, size);

 	#ifdef VERBOSE
    printf("\n\nThe error polynomial e(x) in binary representation: "); vector_u32_print(e, PARAM_N1);
  #endif

 	// Add the error polynomial and the received polynomial 
 	vector_u32* tmp = vector_u32_init(UTILS_BCH_CODEWORD_ARRAY_SIZE);
 	vector_u32_add(tmp, e, em);
 	
 	// Find the message from the decoded code word
	get_message_from_codeword(m, tmp);
	
	gf_tables_clear(tables);  
	syndrome_clear(synd_set);
  sigma_poly_clear(sigma);
  vector_u32_clear(e);
  vector_u32_clear(tmp);
}

void get_message_from_codeword(vector_u32* o, vector_u32* v) {
	int val = PARAM_N1 - PARAM_K;

	for (uint8_t i = 0 ; i < UTILS_VEC_K_ARRAY_SIZE ; ++i)	{
		int index = (val / 32) + i ;
		uint32_t  m1 = (v->value[index] & UTILS_MASK_M1) << (val % 32);
		uint32_t  m2 = (v->value[index + 1] & UTILS_MASK_M2) >> (32 - (val % 32));
		o->value[i] = m1 | m2;
	}
}

sigma_poly* sigma_poly_init(int16_t dim){
	sigma_poly* poly = (sigma_poly*) malloc(sizeof(sigma_poly));
	poly->dim = dim;
	poly->value = calloc(dim,sizeof(int16_t));
	
	return poly;
}

int sigma_poly_clear(sigma_poly* poly){
	free(poly->value);
	free(poly);
	return 0;
}

void sigma_poly_copy(sigma_poly* p1, sigma_poly* p2) {
	for (int i = 0; i <= p2->deg ; ++i)	{
		p1->value[i] = p2->value[i];
	}
	p1->deg = p2->deg;
}

gf_tables* gf_tables_init() {
	gf_tables* tables = (gf_tables*) malloc(sizeof(gf_tables));

	tables->size = PARAM_GF_MUL_ORDER + 1;
	tables->log_tab = (int16_t*) malloc((tables->size) * sizeof(int16_t));
	tables->antilog_tab = (int16_t*) malloc((tables->size) * sizeof(int16_t));
	
	return tables;
}

void gf_tables_clear(gf_tables* gf_tables) {
	free(gf_tables->log_tab);
	free(gf_tables->antilog_tab);
	free(gf_tables);
}

void gf_generation(gf_tables* gf_tables) {
	const uint16_t k 	= 1 << PARAM_M; // k = 2^m = 2^10
	const uint16_t poly = PARAM_POLY; // get the primitive polynomial
	uint16_t val = 1;
	uint16_t alpha = 2; // alpha the root of the primitive polynomial is the primitive element of GF(2^10)

	for(int i = 0 ; i < PARAM_GF_MUL_ORDER ; ++i){
		gf_tables->antilog_tab[i] = val;
		gf_tables->log_tab[val] = i;
		val = val * alpha; // by multiplying by alpha and reducing later if needed we generate all the elements of GF(2^10)
		if(val >= k){ // if val is greater than 2^10
			val ^= poly; // replace alpha^10 by alpha^3 + 1
		}
	}

	gf_tables->antilog_tab[PARAM_GF_MUL_ORDER] = 1; 
	gf_tables->log_tab[0] = -1; // by convention 
}	

syndrome_set* syndrome_init() {
	syndrome_set*	synd_set = (syndrome_set*) malloc(sizeof(syndrome_set));
	synd_set->size = 2 * PARAM_DELTA;
	synd_set->tab =	calloc((synd_set->size), sizeof(int16_t));
	
	return synd_set;
}

void syndrome_clear(syndrome_set* synd_set) {
	free(synd_set->tab);
	free(synd_set);
}

void syndrome_gen(syndrome_set* synd_set, gf_tables* tables, vector_u32* v) {
	uint8_t tmp_array[PARAM_N1];
	// For clarity of computation we separate the coordinates of the vector v by putting each coordinate in an unsigned char.
	for (uint8_t i = 0; i < (v->dim - 1) ; ++i) {
		for (uint8_t j = 0; j < 32; ++j) {
			tmp_array[j + i * 32] = v->value[i] >> (31 - j)	& 1;	
		}
	}

	for (uint8_t i = 0; i < PARAM_N1 % 32 ; ++i)	{
		tmp_array [i + (v->dim - 1) * 32] = v->value[v->dim -1] >> (31 - i)	& 1;
	}

	// Evaluation of the polynomial corresponding to the vector v in alpha^i for i in {1, ..., 2 * PARAM_DELTA}
	for(uint16_t i = 0; i < PARAM_N1 ; ++i) {
		int tmp_value = 0;
		if(tmp_array[i]) {
			for(uint16_t j = 1 ; j < synd_set->size + 1 ; ++j) {			
				tmp_value = gf_mod(tmp_value + i);
				synd_set->tab[j - 1] ^= gf_get_antilog(tables, tmp_value);
			}
		}
	}

}

void get_error_location_poly(sigma_poly* sigma, gf_tables* tables, syndrome_set* synd_set) {
  // Find the error location polynomial via Berlekamp's simplified algorithm as described by
  // Laurie L. Joiner and John J. Komo, the comments are following their terminology

  uint32_t mu, tmp, l, d_rho = 1, d = synd_set->tab[0];
  sigma_poly* sigma_rho = sigma_poly_init(2 * PARAM_DELTA);
  sigma_poly* sigma_copy = sigma_poly_init(2 * PARAM_DELTA);
  int k, pp = -1;
  // initializations
  sigma_rho->deg = 0;
  sigma_rho->value[0] = 1;
  sigma->deg = 0;
  sigma->value[0] = 1;

  for (mu = 0; (mu < PARAM_DELTA) && (sigma->deg <= PARAM_DELTA); mu++) {
    // Step (2) in Joinder and Komo algorithm
	  if (d) {
 		  k = 2*mu-pp;
    	sigma_poly_copy(sigma_copy, sigma);
    	// Compute d_mu * d__rho^(-1)                                
    	tmp = gf_get_log(tables, d) + PARAM_GF_MUL_ORDER - gf_get_log(tables, d_rho);
    	// Compute sigma(mu+1)[x]
    	for (int i = 0; i <= sigma_rho->deg; i++) {
     	 if (sigma_rho->value[i]) {
     	   l = gf_get_log(tables, sigma_rho->value[i]);
     	   sigma->value[i+k] ^= gf_get_antilog(tables, (tmp + l) % PARAM_GF_MUL_ORDER);
     	 }
    	}
    	// Compute l_mu + 1 the degree of sigma(mu+1)[x]
    	// and update the polynomial sigma_rho
    	tmp = sigma_rho->deg + k;
    	if (tmp > sigma->deg) {
     	 sigma->deg = tmp;
     	 sigma_poly_copy(sigma_rho, sigma_copy);
     	 d_rho = d;
     	 pp = 2 * mu;
    	}
  	}
  	// Step (3) in Joinder and Komo algorithm
    // compute discrepancy d_mu+1
    if (mu < PARAM_DELTA - 1) {
      d = synd_set->tab[2*mu + 2];
      for (int i = 1; i <= sigma->deg; i++){
      	int tmp_val = gf_get_log(tables, synd_set->tab[2 * mu + 2 - i]);
      	if((sigma->value[i])  && (tmp_val != -1))
       	d ^= gf_get_antilog(tables, gf_mod(gf_get_log(tables, sigma->value[i]) + tmp_val));
      }	          
    }

  }
  sigma_poly_clear(sigma_rho);
  sigma_poly_clear(sigma_copy);
}

void chien_search(uint16_t* error_pos, uint16_t* size, gf_tables* tables, sigma_poly* sigma) {
	int i = sigma->deg + 1;
	// Put the coordinates of the error location polynomial in the log format. Its better for multiplication.
	while(i--) {
		sigma->value[i] = gf_get_log(tables, sigma->value[i]);
	}
	
	int k = PARAM_GF_MUL_ORDER - PARAM_N1;

	int tmp = 0;

	// Compute sigma(alpha^k)
	for(uint16_t j = 1 ; j < sigma->deg + 1 ; ++j){
		tmp = gf_mod(tmp + k);
		if (sigma->value[j] != -1) {
			sigma->value[j] = gf_mod(sigma->value[j] + tmp);
		}
	}
	// Evaluate sigma in a field element and check if it's a root of sigma
	*size = 0;
	for(int i = k + 1 ; i <= PARAM_GF_MUL_ORDER ; ++i) {
		int sum = 0;
		int j = sigma->deg + 1;
		while(--j) {
			if (sigma->value[j] != -1) {
				sigma->value[j] = gf_mod(sigma->value[j] + j);
				sum ^= gf_get_antilog(tables, sigma->value[j]);
			}
		}
		// Compute the inverse and update the list of error location numbers
		if (sum == 1) {
			error_pos[*size] = PARAM_GF_MUL_ORDER - i;
			++(*size);
		}
	}
}

void error_poly_gen(vector_u32* e, uint16_t* error_pos, uint16_t size) {
	for (int i = 0; i < size; ++i) {
		int index = error_pos[i] / 32;
		e->value[index] ^= 1 << (31 - (error_pos[i] % 32));
	}
}