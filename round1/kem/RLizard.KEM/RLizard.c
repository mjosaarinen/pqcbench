#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "RLizard.h"
#include "randombytes.h"
#include "sha512.h"
#include <libkeccak.a.headers/SP800-185.h>

uint16_t seed[PublicKey_B];
int count = 0;

#ifdef NOISE_D1
#define SAMPLE_DG Sample_D1
const uint16_t CDF_TABLE[4] = { 190, 437, 504, 511 }; // out of [0, 511]
const size_t TABLE_LENGTH = 4;

uint16_t Sample_D1() {
	uint16_t rnd = seed[count == PublicKey_B ? count = 0 : count++] & 0x01ff;
	uint16_t sign = seed[count == PublicKey_B ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif
#ifdef NOISE_D2
#define SAMPLE_DG Sample_D2
const uint16_t CDF_TABLE[6] = { 279, 722, 941, 1009, 1022, 1023 }; // out of [0, 1023]
const size_t TABLE_LENGTH = 6;

uint16_t Sample_D2() {
	uint16_t rnd = seed[count == PublicKey_B ? count = 0 : count++] & 0x03ff;
	uint16_t sign = seed[count == PublicKey_B ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif
#ifdef NOISE_D3
#define SAMPLE_DG Sample_D3
const uint16_t CDF_TABLE[8] = { 407, 1127, 1623, 1889, 2000, 2036, 2045, 2047 }; // out of [0, 2047]
const size_t TABLE_LENGTH = 8;

uint16_t Sample_D3() {
	uint16_t rnd = seed[count == PublicKey_B ? count = 0 : count++] & 0x07ff;
	uint16_t sign = seed[count == PublicKey_B ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif
#ifdef NOISE_D4
#define SAMPLE_DG Sample_D4
const uint16_t CDF_TABLE[10] = { 154, 443, 676, 838, 936, 987, 1010, 1019, 1022, 1023 }; // out of [0, 1023]
const size_t TABLE_LENGTH = 10;

uint16_t Sample_D4() {
	uint16_t rnd = seed[count == PublicKey_B ? count = 0 : count++] & 0x03ff;
	uint16_t sign = seed[count == PublicKey_B ? count = 0 : count++] & 0x01;
	uint16_t sample = 0;
	for (size_t i = 0; i < TABLE_LENGTH - 1; ++i) {
		sample += (CDF_TABLE[i] - rnd) >> 15;
	}
	sample = ((-sign) ^ sample) + sign;
	return sample;
}
#endif

/**
  * @param	pk		[in] public key for encryption. pk = (a, b)
  * @param	sk		[in] private key for decryption sk = (s, t)
  */
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
	int hw = 0, tmp, count1 = 0;
	int neg_start = 0, back_position = HS;

	uint16_t seed1[16];
	
	uint8_t sk_t[LWE_N] = { 0 };
	uint16_t pk_a[LWE_N];
	uint16_t pk_b[LWE_N];

	// Generate a random polynomial a
	randombytes((unsigned char*)pk_a, PublicKey_A);
	for (int i = 0; i < LWE_N; ++i) {
		pk_a[i] <<= _16_LOG_Q;
	}

	randombytes((unsigned char*)seed1, 32);
	// Set a secret polynomial s
	while (hw < HS) {
		tmp = seed1[count1++] & (LWE_N - 1);
		if (sk_t[tmp] == 0) {
			sk_t[tmp] = (seed1[count1++] & 0x02) - 1;
			hw++;
		}
		if (count1 >= 15) {
			randombytes((unsigned char*)seed1, 32);
			count1 = 0;
		}
	}
	// Generate s_idx
	for (int i = 0; i < LWE_N; ++i) {
		if (sk_t[i] == 0x01)
			((uint16_t*)sk)[neg_start++] = i;
		else if (sk_t[i] == 0xff)
			((uint16_t*)sk)[--back_position] = i;
	}
	sk[(HS * 2) + (LWE_N / 8)] = (unsigned char)neg_start;

	// Generate a random vector t
	randombytes(sk + HS * 2, LWE_N / 8);
	
	// Initialize b as an error polynomial e
	randombytes((unsigned char*)seed, PublicKey_B * 2);
	for (int i = 0; i < LWE_N; ++i) {
		pk_b[i] = SAMPLE_DG() << _16_LOG_Q;
	}

	// Add -a * s to b. Resulting b = -a * s + e
	for (int i = 0; i < HS; ++i) {
		uint16_t deg = ((uint16_t*)sk)[i];
		uint16_t branch = (2 * ((i - neg_start) >> sft & 0x1) - 1);
		((uint16_t*)sk)[i] = (sk[i * 2] << 8 | sk[i * 2 + 1]);
		for (int j = 0; j < LWE_N - deg; ++j) { pk_b[deg + j] -= branch * pk_a[j]; }
		for (int j = LWE_N - deg; j < LWE_N; ++j) { pk_b[deg + j - LWE_N] += branch * pk_a[j]; }
	}

	for (int i = 0; i < LWE_N; ++i) {
		pk[i * 2] = pk_a[i] >> 8;
		pk[i * 2 + 1] = pk_a[i] & 0xff;
		pk[PublicKey_A + (i * 2)] = pk_b[i] >> 8;
		pk[PublicKey_A + (i * 2 + 1)] = pk_b[i] & 0xff;
	}

	return 0;
}

/**
  * @param	ct		[out] data to be encrypted. ct = (c1, c2, d)
  * @param	ss		[out] shared secret
  * @param	pk		[in] public key for encryption. pk = (a, b)
  */
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk) {
	start = clock();
	int i, j, hw = 0;
	int neg_start = 0, back_position = HR;

	uint8_t r[LWE_N] = { 0, };

	uint16_t r_idx[HR];
	uint16_t c1[LWE_N] = { 0, };
	uint16_t c2[LWE_N] = { 0, };
	
	uint16_t pk_a[LWE_N];
	uint16_t pk_b[LWE_N];

	uint64_t hash[LAMBDA / 32];
	uint64_t *hash_t = NULL;
	uint64_t delta[LWE_N / 64];

	TupleElement tuple;
	unsigned char *S = "";

	// Generate a polynomial delta
	randombytes((unsigned char*)delta, LWE_N / 8);

	// Compute r = H(delta)
	hash_t = (uint64_t *)calloc(LWE_N / 64, sizeof(uint64_t));
	tuple.input = (unsigned char*)delta;
	tuple.inputBitLen = LWE_N;
	TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_N, S, strlen(S) * 8);

#if defined(RING_CATEGORY1) || defined(RING_CATEGORY3_N1024) 
	i = 0;
	do {
		j = (uint16_t)hash_t[i] & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 10) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 12) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 22) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 24) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 34) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 36) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 46) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 48) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 58) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		i++;
		if (i == LWE_N / 64) {
			i = 0;
			tuple.input = (unsigned char*)hash_t;
			tuple.inputBitLen = LWE_N;
			TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_N, S, strlen(S) * 8);
		}
	} while (hw < HR);
#endif
#if defined(RING_CATEGORY3_N2048) || defined(RING_CATEGORY5)
	i = 0;
	do {
		j = (uint16_t)hash_t[i] & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 11) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 13) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 24) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 26) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 37) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 39) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 50) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		i++;
		if (i == LWE_N / 64) {
			i = 0;
			tuple.input = (unsigned char*)hash_t;
			tuple.inputBitLen = LWE_N;
			TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_N, S, strlen(S) * 8);
		}
	} while (hw < HR);
#endif
	
	// Generate r_idx
	for (j = 0; j < LWE_N; ++j) {
		if (r[j] == 0x01)
			r_idx[neg_start++] = j;
		else if (r[j] == 0xff)
			r_idx[--back_position] = j;

		pk_a[j] = pk[j * 2] << 8 | pk[j * 2 + 1];
		pk_b[j] = pk[PublicKey_A + j * 2] << 8 | pk[PublicKey_A + j * 2 + 1];
	}

	// Compute d = H'(delta)
	sha512((unsigned char*)delta, LAMBDA / 4, (unsigned char*)hash, LAMBDA / 4);
#ifdef RING_CATEGORY1
	for (j = 0; j < 4; ++j) {
		ct[LWE_N + LWE_N + j * 8] = (unsigned char)(hash[j] >> 56);
		ct[LWE_N + LWE_N + j * 8 + 1] = (unsigned char)(hash[j] >> 48);
		ct[LWE_N + LWE_N + j * 8 + 2] = (unsigned char)(hash[j] >> 40);
		ct[LWE_N + LWE_N + j * 8 + 3] = (unsigned char)(hash[j] >> 32);
		ct[LWE_N + LWE_N + j * 8 + 4] = (unsigned char)(hash[j] >> 24);
		ct[LWE_N + LWE_N + j * 8 + 5] = (unsigned char)(hash[j] >> 16);
		ct[LWE_N + LWE_N + j * 8 + 6] = (unsigned char)(hash[j] >> 8);
		ct[LWE_N + LWE_N + j * 8 + 7] = (unsigned char)(hash[j] & 0xff);
	}
#endif
#if defined(RING_CATEGORY3_N1024) || defined(RING_CATEGORY3_N2048) || defined(RING_CATEGORY5)
	for (j = 0; j < LAMBDA / 32; ++j) {
		ct[(LWE_N * 2) + (LWE_N * 2) + j * 8] = (unsigned char)(hash[j] >> 56);
		ct[(LWE_N * 2) + (LWE_N * 2) + j * 8 + 1] = (unsigned char)(hash[j] >> 48);
		ct[(LWE_N * 2) + (LWE_N * 2) + j * 8 + 2] = (unsigned char)(hash[j] >> 40);
		ct[(LWE_N * 2) + (LWE_N * 2) + j * 8 + 3] = (unsigned char)(hash[j] >> 32);
		ct[(LWE_N * 2) + (LWE_N * 2) + j * 8 + 4] = (unsigned char)(hash[j] >> 24);
		ct[(LWE_N * 2) + (LWE_N * 2) + j * 8 + 5] = (unsigned char)(hash[j] >> 16);
		ct[(LWE_N * 2) + (LWE_N * 2) + j * 8 + 6] = (unsigned char)(hash[j] >> 8);
		ct[(LWE_N * 2) + (LWE_N * 2) + j * 8 + 7] = (unsigned char)(hash[j] & 0xff);
	}
#endif

	// Initialize c2 as q/2 * delta
	for (i = 0; i < LWE_N / 64; ++i) { for (j = 0; j < 64; ++j) { c2[64 * i + j] = ((uint16_t)(delta[i] >> j)) << _16_LOG_T; } }

	// Compute a * r, b * r, and then add to c1 and c2, respectively.
	for (i = 0; i < HR; ++i) {
		uint16_t deg = r_idx[i];
		uint16_t branch = (2 * ((i - neg_start) >> sft & 0x1) - 1);
		for (j = 0; j < LWE_N - deg; ++j) {
			c1[deg + j] += branch * pk_a[j];
			c2[deg + j] += branch * pk_b[j];
		}
		for (j = LWE_N - deg; j < LWE_N; ++j) {
			c1[deg + j - LWE_N] -= branch * pk_a[j];
			c2[deg + j - LWE_N] -= branch * pk_b[j];
		}
	}

	// Compute c1 and c2 from mod q to mod p
	// Compute K = G(c1, c2, d, delta)
#ifdef RING_CATEGORY1
	for (i = 0; i < LWE_N; ++i) {
		ct[i] = ((c1[i] + RD_ADD) & RD_AND) >> 8;
		ct[LWE_N + i] = ((c2[i] + RD_ADD) & RD_AND) >> 8;
	}

	hash_t = (uint64_t *)calloc((LWE_N + LWE_N + (LAMBDA / 4) + (LWE_N / 8)) / 8, sizeof(uint64_t));
	memcpy((unsigned char*)hash_t, (unsigned char*)ct, LWE_N + LWE_N + (LAMBDA / 4));
	memcpy((unsigned char*)hash_t + LWE_N + LWE_N + (LAMBDA / 4), (unsigned char*)delta, (LWE_N / 8));
	sha512((unsigned char*)hash_t, LWE_N + LWE_N + (LAMBDA / 4) + (LWE_N / 8), (unsigned char*)hash, (LAMBDA / 4));
#endif
#if defined(RING_CATEGORY3_N1024) || defined(RING_CATEGORY3_N2048) || defined(RING_CATEGORY5)
	for (i = 0; i < LWE_N; ++i) {
		c1[i] = (c1[i] + RD_ADD) & RD_AND;
		ct[i * 2] = c1[i] >> 8;
		ct[i * 2 + 1] = c1[i] & 0xff;
		c2[i] = (c2[i] + RD_ADD) & RD_AND;
		ct[(LWE_N * 2) + i * 2] = c2[i] >> 8;
		ct[(LWE_N * 2) + i * 2 + 1] = c2[i] & 0xff;
	}

	hash_t = (uint64_t *)calloc(((LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4) + (LWE_N / 8)), sizeof(uint64_t));
	memcpy((unsigned char*)hash_t, (unsigned char*)ct, (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4));
	memcpy((unsigned char*)hash_t + (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4), (unsigned char*)delta, (LWE_N / 8));
	sha512((unsigned char*)hash_t, (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4) + (LWE_N / 8), (unsigned char*)hash, (LAMBDA / 4));
#endif
	for (i = 0; i < LAMBDA / 32; ++i) {
		ss[i * 8] = (unsigned char)(hash[i] >> 56);
		ss[i * 8 + 1] = (unsigned char)(hash[i] >> 48);
		ss[i * 8 + 2] = (unsigned char)(hash[i] >> 40);
		ss[i * 8 + 3] = (unsigned char)(hash[i] >> 32);
		ss[i * 8 + 4] = (unsigned char)(hash[i] >> 24);
		ss[i * 8 + 5] = (unsigned char)(hash[i] >> 16);
		ss[i * 8 + 6] = (unsigned char)(hash[i] >> 8);
		ss[i * 8 + 7] = (unsigned char)(hash[i] & 0xff);
	}

	free(hash_t);

	finish = clock();
	elapsed1 += (finish - start);

	return 0;
}

/**
  * @param	ss		[out] shared secret
  * @param	ct		[in] encrypted data  ct = (c1, c2, d)
  * @param	sk		[in] private/public key for decryption. sk = (S, T), pk = (A, B)
  */
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk) {
	start = clock();
	int res = 0;
	int i, j, hw = 0;
	int neg_start = sk[(HS * 2) + (LWE_N / 8)], back_position = HR;

	uint8_t r[LWE_N] = { 0, };

	uint16_t decomp_delta[LWE_N];
	uint16_t c1[LWE_N] = { 0, };
	uint16_t c2[LWE_N] = { 0, };
	uint16_t r_idx[HR];
	
	uint16_t pk_a[LWE_N];
	uint16_t pk_b[LWE_N];

	uint64_t delta[LWE_N / 64] = { 0, };
	uint64_t hash[LAMBDA / 32];
	uint64_t *hash_t = NULL;
	uint64_t d[LAMBDA / 32];

	TupleElement tuple;
	unsigned char *S = "";

#ifdef RING_CATEGORY1
	for (i = 0; i < LWE_N; ++i) { 
		decomp_delta[i] = ct[LWE_N + i] << 8; 	// Initialize delta as c2
		c1[i] = ct[i] << 8;
	}
	// Compute delta = (delta + c1 * s)
	for (i = 0; i < HS; ++i) {
		uint16_t deg = (sk[i * 2] << 8) + sk[i * 2 + 1];
		uint16_t branch = (2 * ((i - neg_start) >> sft & 0x1) - 1);
		for (j = 0; j < LWE_N - deg; ++j) { decomp_delta[deg + j] += branch * c1[j]; }
		for (j = LWE_N - deg; j < LWE_N; ++j) { decomp_delta[deg + j - LWE_N] -= branch * c1[j]; }
	}
#endif
#if defined(RING_CATEGORY3_N1024) || defined(RING_CATEGORY3_N2048) || defined(RING_CATEGORY5)
	for (i = 0; i < LWE_N; ++i) { 
		decomp_delta[i] = ct[(LWE_N * 2) + i * 2] << 8 | ct[(LWE_N * 2) + i * 2 + 1];	// Initialize delta as c2
		c1[i] = ct[i * 2] << 8 | ct[i * 2 + 1];
	}
	// Compute delta = (delta + c1 * s)
	for (i = 0; i < HS; ++i) {
		uint16_t deg = (sk[i * 2] << 8) + sk[i * 2 + 1];
		uint16_t branch = (2 * ((i - neg_start) >> sft & 0x1) - 1);
		for (j = 0; j < LWE_N - deg; ++j) { decomp_delta[deg + j] += branch * c1[j]; }
		for (j = LWE_N - deg; j < LWE_N; ++j) { decomp_delta[deg + j - LWE_N] -= branch * c1[j]; }
	}
#endif

	// Compute delta = 2/p * delta
	for (i = 0; i < LWE_N; ++i) {
		decomp_delta[i] += DEC_ADD;
		decomp_delta[i] >>= _16_LOG_T;
	}
	
	// Set delta
	for (i = 0; i < LWE_N / 64; ++i) {
		for (j = 0; j < 64; ++j) {
			uint64_t a = ((uint64_t)decomp_delta[64 * i + j]) << j;
			delta[i] ^= a;
		}
	}

	// Compute r' = H(delta)
	hash_t = (uint64_t *)calloc(LWE_N / 64, sizeof(uint64_t));
	tuple.input = (unsigned char*)delta;
	tuple.inputBitLen = LWE_N;
	TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_N, S, strlen(S) * 8);

#if defined(RING_CATEGORY1) || defined(RING_CATEGORY3_N1024) 
	i = 0;
	do {
		j = (uint16_t)hash_t[i] & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 10) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 12) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 22) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 24) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 34) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 36) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 46) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 48) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 58) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		i++;
		if (i == LWE_N / 64) {
			i = 0;
			tuple.input = (unsigned char*)hash_t;
			tuple.inputBitLen = LWE_N;
			TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_N, S, strlen(S) * 8);
		}
	} while (hw < HR);
#endif
#if defined(RING_CATEGORY3_N2048) || defined(RING_CATEGORY5)
	i = 0;
	do {
		j = (uint16_t)hash_t[i] & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 11) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 13) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 24) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 26) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 37) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		j = (uint16_t)(hash_t[i] >> 39) & (LWE_N - 1);
		if (r[j] == 0) {
			r[j] = ((uint16_t)(hash_t[i] >> 50) & 0x02) - 1;
			hw++;
			if (hw == HR) {
				i++;
				break;
			}
		}
		i++;
		if (i == LWE_N / 64) {
			i = 0;
			tuple.input = (unsigned char*)hash_t;
			tuple.inputBitLen = LWE_N;
			TupleHash256(&tuple, 1, (unsigned char*)hash_t, LWE_N, S, strlen(S) * 8);
		}
	} while (hw < HR);
#endif

	// Generate r_idx
	neg_start = 0;
	for (j = 0; j < LWE_N; ++j) {
		if (r[j] == 0x01)
			r_idx[neg_start++] = j;
		else if (r[j] == 0xff)
			r_idx[--back_position] = j;

		pk_a[j] = sk[CRYPTO_SECRETKEYBYTES + j * 2] << 8 | sk[CRYPTO_SECRETKEYBYTES + j * 2 + 1];
		pk_b[j] = sk[CRYPTO_SECRETKEYBYTES + PublicKey_A + j * 2] << 8 | sk[CRYPTO_SECRETKEYBYTES + PublicKey_A + j * 2 + 1];
	}

	// Set d
#ifdef RING_CATEGORY1
	for (i = 0; i < LAMBDA / 32; ++i) {
		d[i] = (((uint64_t)(ct[LWE_N + LWE_N + i * 8] & 0xff) << 56) + ((uint64_t)(ct[LWE_N + LWE_N + i * 8 + 1] & 0xff) << 48) + ((uint64_t)(ct[LWE_N + LWE_N + i * 8 + 2] & 0xff) << 40)
			+ ((uint64_t)(ct[LWE_N + LWE_N + i * 8 + 3] & 0xff) << 32) + ((uint64_t)(ct[LWE_N + LWE_N + i * 8 + 4] & 0xff) << 24) + ((uint64_t)(ct[LWE_N + LWE_N + i * 8 + 5] & 0xff) << 16)
			+ ((uint64_t)(ct[LWE_N + LWE_N + i * 8 + 6] & 0xff) << 8) + ((uint64_t)ct[LWE_N + LWE_N + i * 8 + 7] & 0xff));
	}
#endif
#if defined(RING_CATEGORY3_N1024) || defined(RING_CATEGORY3_N2048) || defined(RING_CATEGORY5)
	for (i = 0; i < LAMBDA / 32; ++i) {
		d[i] = (((uint64_t)(ct[(LWE_N * 2) + (LWE_N * 2) + i * 8] & 0xff) << 56) + ((uint64_t)(ct[(LWE_N * 2) + (LWE_N * 2) + i * 8 + 1] & 0xff) << 48)
			+ ((uint64_t)(ct[(LWE_N * 2) + (LWE_N * 2) + i * 8 + 2] & 0xff) << 40) + ((uint64_t)(ct[(LWE_N * 2) + (LWE_N * 2) + i * 8 + 3] & 0xff) << 32)
			+ ((uint64_t)(ct[(LWE_N * 2) + (LWE_N * 2) + i * 8 + 4] & 0xff) << 24) + ((uint64_t)(ct[(LWE_N * 2) + (LWE_N * 2) + i * 8 + 5] & 0xff) << 16)
			+ ((uint64_t)(ct[(LWE_N * 2) + (LWE_N * 2) + i * 8 + 6] & 0xff) << 8) + ((uint64_t)ct[(LWE_N * 2) + (LWE_N * 2) + i * 8 + 7] & 0xff));
	}
#endif

	// Compute d' = H'(M)
	sha512((unsigned char*)delta, LAMBDA / 4, (unsigned char*)hash, LAMBDA / 4);

	// If d ≠ d', the output K = G(c1,c2, d, t)
#ifdef RING_CATEGORY1
	if ((hash[0] != d[0]) || (hash[1] != d[1]) || (hash[2] != d[2]) || (hash[3] != d[3])) {
		hash_t = (uint64_t *)calloc((LWE_N + LWE_N + (LAMBDA / 4) + (LWE_N / 8)) / 8, sizeof(uint64_t));
		memcpy((unsigned char*)hash_t, (unsigned char*)ct, LWE_N + LWE_N + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + LWE_N + LWE_N + (LAMBDA / 4), (unsigned char*)sk + (HS * 2), (LWE_N / 8));
		sha512((unsigned char*)hash_t, LWE_N + LWE_N + (LAMBDA / 4) + (LWE_N / 8), (unsigned char*)hash, (LAMBDA / 4));

		for (j = 0; j < 4; ++j) {
			ss[j * 8] = (unsigned char)(hash[j] >> 56);
			ss[j * 8 + 1] = (unsigned char)(hash[j] >> 48);
			ss[j * 8 + 2] = (unsigned char)(hash[j] >> 40);
			ss[j * 8 + 3] = (unsigned char)(hash[j] >> 32);
			ss[j * 8 + 4] = (unsigned char)(hash[j] >> 24);
			ss[j * 8 + 5] = (unsigned char)(hash[j] >> 16);
			ss[j * 8 + 6] = (unsigned char)(hash[j] >> 8);
			ss[j * 8 + 7] = (unsigned char)(hash[j] & 0xff);
		}

		return res = 1;
	}
#endif
#if defined(RING_CATEGORY3_N1024) || defined(RING_CATEGORY3_N2048)
	if ((hash[0] != d[0]) || (hash[1] != d[1]) || (hash[2] != d[2]) || (hash[3] != d[3]) || (hash[4] != d[4]) || (hash[5] != d[5])) {
		hash_t = (uint64_t *)calloc(((LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4) + (LWE_N / 8)), sizeof(uint64_t));
		memcpy((unsigned char*)hash_t, (unsigned char*)ct, (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4), (unsigned char*)sk + (HS * 2), (LWE_N / 8));
		sha512((unsigned char*)hash_t, (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4) + (LWE_N / 8), (unsigned char*)hash, (LAMBDA / 4));

		for (j = 0; j < 6; ++j) {
			ss[j * 8] = (unsigned char)(hash[j] >> 56);
			ss[j * 8 + 1] = (unsigned char)(hash[j] >> 48);
			ss[j * 8 + 2] = (unsigned char)(hash[j] >> 40);
			ss[j * 8 + 3] = (unsigned char)(hash[j] >> 32);
			ss[j * 8 + 4] = (unsigned char)(hash[j] >> 24);
			ss[j * 8 + 5] = (unsigned char)(hash[j] >> 16);
			ss[j * 8 + 6] = (unsigned char)(hash[j] >> 8);
			ss[j * 8 + 7] = (unsigned char)(hash[j] & 0xff);
		}

		return res = 1;
	}
#endif
#ifdef RING_CATEGORY5
	if ((hash[0] != d[0]) || (hash[1] != d[1]) || (hash[2] != d[2]) || (hash[3] != d[3])
		|| (hash[4] != d[4]) || (hash[5] != d[5]) || (hash[6] != d[6]) || (hash[7] != d[7])) {
		hash_t = (uint64_t *)calloc(((LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4) + (LWE_N / 8)), sizeof(uint64_t));
		memcpy((unsigned char*)hash_t, (unsigned char*)ct, (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4), (unsigned char*)sk + (HS * 2), (LWE_N / 8));
		sha512((unsigned char*)hash_t, (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4) + (LWE_N / 8), (unsigned char*)hash, (LAMBDA / 4));

		for (i = 0; i < 8; ++i) {
			ss[i * 8] = (unsigned char)(hash[i] >> 56);
			ss[i * 8 + 1] = (unsigned char)(hash[i] >> 48);
			ss[i * 8 + 2] = (unsigned char)(hash[i] >> 40);
			ss[i * 8 + 3] = (unsigned char)(hash[i] >> 32);
			ss[i * 8 + 4] = (unsigned char)(hash[i] >> 24);
			ss[i * 8 + 5] = (unsigned char)(hash[i] >> 16);
			ss[i * 8 + 6] = (unsigned char)(hash[i] >> 8);
			ss[i * 8 + 7] = (unsigned char)(hash[i] & 0xff);
		}

		return res = 1;
	}
#endif

	memset(c1, 0, sizeof(uint16_t) * LWE_N);
	// Initialize c2' as q/2 * delta
	for (i = 0; i < LWE_N; ++i) { c2[i] = decomp_delta[i] << _16_LOG_T; }

	// Compute a * r and b * r, and then add to c1' and c2', respectively.
	for (i = 0; i < HR; ++i) {
		uint16_t deg = r_idx[i];
		uint16_t branch = (2 * ((i - neg_start) >> sft & 0x1) - 1);
		for (j = 0; j < LWE_N - deg; ++j) {
			c1[deg + j] += branch * pk_a[j];
			c2[deg + j] += branch * pk_b[j];
		}
		for (j = LWE_N - deg; j < LWE_N; ++j) {
			c1[deg + j - LWE_N] -= branch * pk_a[j];
			c2[deg + j - LWE_N] -= branch * pk_b[j];
		}
	}

	// Compute c1' and c2' from mod q to mod p
	for (i = 0; i < LWE_N; ++i) {
		c1[i] = (c1[i] + RD_ADD) & RD_AND;
		c2[i] = (c2[i] + RD_ADD) & RD_AND;
	}

	// If (c1, c2) ≠ (c1', c2'), the output K = G(c1,c2, d, t)
	// Otherwise, output K = G(c1,c2, d, delta)
#ifdef RING_CATEGORY1
	for (i = 0; i < LWE_N; ++i) {
		if (c1[i] >> 8 != (ct[i] & 0xff)) {
			res = 2;
			break;
		}
		if (c2[i] >> 8 != (ct[LWE_N + i] & 0xff)) {
			res = 2;
			break;
		}
	}

	if (res == 2) {
		hash_t = (uint64_t *)calloc((LWE_N + LWE_N + (LAMBDA / 4) + (LWE_N / 8)) / 8, sizeof(uint64_t));
		memcpy((unsigned char*)hash_t, (unsigned char*)ct, LWE_N + LWE_N + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + LWE_N + LWE_N + (LAMBDA / 4), (unsigned char*)sk + (HS * 2), (LWE_N / 8));
		sha512((unsigned char*)hash_t, LWE_N + LWE_N + (LAMBDA / 4) + (LWE_N / 8), (unsigned char*)hash, (LAMBDA / 4));

		for (i = 0; i < 4; ++i) {
			ss[i * 8] = (unsigned char)(hash[i] >> 56);
			ss[i * 8 + 1] = (unsigned char)(hash[i] >> 48);
			ss[i * 8 + 2] = (unsigned char)(hash[i] >> 40);
			ss[i * 8 + 3] = (unsigned char)(hash[i] >> 32);
			ss[i * 8 + 4] = (unsigned char)(hash[i] >> 24);
			ss[i * 8 + 5] = (unsigned char)(hash[i] >> 16);
			ss[i * 8 + 6] = (unsigned char)(hash[i] >> 8);
			ss[i * 8 + 7] = (unsigned char)(hash[i] & 0xff);
		}
	}
	else {
		hash_t = (uint64_t *)calloc((LWE_N + LWE_N + (LAMBDA / 4) + (LWE_N / 8)) / 8, sizeof(uint64_t));
		memcpy((unsigned char*)hash_t, (unsigned char*)ct, LWE_N + LWE_N + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + LWE_N + LWE_N + (LAMBDA / 4), (unsigned char*)delta, (LWE_N / 8));
		sha512((unsigned char*)hash_t, LWE_N + LWE_N + (LAMBDA / 4) + (LWE_N / 8), (unsigned char*)hash, (LAMBDA / 4));

		for (i = 0; i < 4; ++i) {
			ss[i * 8] = (unsigned char)(hash[i] >> 56);
			ss[i * 8 + 1] = (unsigned char)(hash[i] >> 48);
			ss[i * 8 + 2] = (unsigned char)(hash[i] >> 40);
			ss[i * 8 + 3] = (unsigned char)(hash[i] >> 32);
			ss[i * 8 + 4] = (unsigned char)(hash[i] >> 24);
			ss[i * 8 + 5] = (unsigned char)(hash[i] >> 16);
			ss[i * 8 + 6] = (unsigned char)(hash[i] >> 8);
			ss[i * 8 + 7] = (unsigned char)(hash[i] & 0xff);
		}
	}
#endif
#if defined(RING_CATEGORY3_N1024) || defined(RING_CATEGORY3_N2048) || defined(RING_CATEGORY5)
	for (i = 0; i < LWE_N; ++i) {
		if (c1[i] != ((ct[i * 2] & 0xff) << 8 | ct[i * 2 + 1] & 0xff)) {
			res = 2;
			break;
		}
		if (c2[i] != ((ct[(LWE_N * 2) + i * 2] & 0xff) << 8 | ct[(LWE_N * 2) + i * 2 + 1] & 0xff)) {
			res = 2;
			break;
		}
	}

	if (res == 2) {
		hash_t = (uint64_t *)calloc(((LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4) + (LWE_N / 8)), sizeof(uint64_t));
		memcpy((unsigned char*)hash_t, (unsigned char*)ct, (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4), (unsigned char*)sk + (HS * 2), (LWE_N / 8));
		sha512((unsigned char*)hash_t, (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4) + (LWE_N / 8), (unsigned char*)hash, (LAMBDA / 4));

		for (i = 0; i < LAMBDA / 32; ++i) {
			ss[i * 8] = (unsigned char)(hash[i] >> 56);
			ss[i * 8 + 1] = (unsigned char)(hash[i] >> 48);
			ss[i * 8 + 2] = (unsigned char)(hash[i] >> 40);
			ss[i * 8 + 3] = (unsigned char)(hash[i] >> 32);
			ss[i * 8 + 4] = (unsigned char)(hash[i] >> 24);
			ss[i * 8 + 5] = (unsigned char)(hash[i] >> 16);
			ss[i * 8 + 6] = (unsigned char)(hash[i] >> 8);
			ss[i * 8 + 7] = (unsigned char)(hash[i] & 0xff);
		}
	}
	else {
		hash_t = (uint64_t *)calloc(((LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4) + (LWE_N / 8)), sizeof(uint64_t));
		memcpy((unsigned char*)hash_t, (unsigned char*)ct, (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4));
		memcpy((unsigned char*)hash_t + (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4), (unsigned char*)delta, (LWE_N / 8));
		sha512((unsigned char*)hash_t, (LWE_N * 2) + (LWE_N * 2) + (LAMBDA / 4) + (LWE_N / 8), (unsigned char*)hash, (LAMBDA / 4));

		for (i = 0; i < LAMBDA / 32; ++i) {
			ss[i * 8] = (unsigned char)(hash[i] >> 56);
			ss[i * 8 + 1] = (unsigned char)(hash[i] >> 48);
			ss[i * 8 + 2] = (unsigned char)(hash[i] >> 40);
			ss[i * 8 + 3] = (unsigned char)(hash[i] >> 32);
			ss[i * 8 + 4] = (unsigned char)(hash[i] >> 24);
			ss[i * 8 + 5] = (unsigned char)(hash[i] >> 16);
			ss[i * 8 + 6] = (unsigned char)(hash[i] >> 8);
			ss[i * 8 + 7] = (unsigned char)(hash[i] & 0xff);
		}
	}
#endif

	free(hash_t);

	finish = clock();
	elapsed2 += (finish - start);

	return res;
}
