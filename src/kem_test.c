// kem_test.c
// 2018-03-27  Markku-Juhani O. Saarinen <mjos@iki.fi>

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

#include "api.h"
#include "rng.h"

#ifndef XBENCH_REPS
#define XBENCH_REPS 20
#endif

#ifndef XBENCH_TIMEOUT
#define XBENCH_TIMEOUT 3
#endif

#ifndef CRYPTO_ALGNAME
#define CRYPTO_ALGNAME "UNKNOWN ALGORITHM"
#endif

// Gives roughly 2 microsecond precision on my system

static double clk_now()
{
	struct timespec ts;

	// You may onsider CLOCK_MONOTONIC and CLOCK_MONOTONIC_RAW here too
	if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts) != 0) {
		perror("clock_gettime()");
		exit(-1);
		
	}
	return ((double) ts.tv_sec) + 1E-9 * ((double) ts.tv_nsec);
}


int main(int argc, char **argv)
{
	FILE *fd;
	uint8_t seed[48];
	int i, n, fails;
	double clk1, clk2;

#if (XBENCH_REPS > 1)
	uint8_t *pk[XBENCH_REPS], *sk[XBENCH_REPS], 
			*ct[XBENCH_REPS], *ss[XBENCH_REPS];
#else
#define XBENCH_REPS 1
	uint8_t *pk[1], *sk[1], *ct[1], *ss[2];
#endif

	// init random with random

	memset(seed, 0x00, sizeof(seed));
	if ((fd = fopen("/dev/urandom", "r")) == NULL ||
		fread(seed, 1, 48, fd) != 48)
	{
		perror("/dev/urandom");
		return -1;
	}
	fclose(fd);

	randombytes_init(seed, NULL, 256);

	// multiple of everhthing

	for (i = 0; i < XBENCH_REPS; i++) {
		pk[i] = (uint8_t *) malloc(CRYPTO_PUBLICKEYBYTES);
		sk[i] = (uint8_t *) malloc(CRYPTO_SECRETKEYBYTES);
		ct[i] = (uint8_t *) malloc(CRYPTO_CIPHERTEXTBYTES);
		ss[i] = (uint8_t *) malloc(CRYPTO_BYTES);
	}
	if (XBENCH_REPS == 1) {
		ss[1] = (uint8_t *) malloc(CRYPTO_BYTES);
	}
	
	// test correctness at least once, or loop for a second if fast

	fails = 0;
	n = 0;
	
	n = 0;
	clk1 = clk_now();
	do {
		crypto_kem_keypair(pk[0], sk[0]);
		crypto_kem_enc(ct[0], ss[0], pk[0]);
		crypto_kem_dec(ss[1], ct[0], sk[0]);
	
		if (memcmp(ss[0], ss[1], CRYPTO_BYTES) != 0)
			fails++;
		n++;
		clk2 = clk_now() - clk1;
	} while (clk2 < XBENCH_TIMEOUT);
	
	printf("%18.9f s   KEX Total   [%s]\n", 
		((double) clk2) / ((double) n), CRYPTO_ALGNAME);

	if (fails > 0)
		printf("KEM test failed %d/%d times [%s]\n", 
			fails, n, CRYPTO_ALGNAME);
	
	// time keygen
	
	n = 0;
	clk1 = clk_now();
	do {
		for (i = 0; i < XBENCH_REPS; i++) {
			crypto_kem_keypair(pk[i], sk[i]);
		}
		clk2 = clk_now() - clk1;
		n += XBENCH_REPS;
	} while (clk2 < XBENCH_TIMEOUT);
	
	printf("%18.9f s   KEM KeyGen  [%s]\n", 
		((double) clk2) / ((double) n), CRYPTO_ALGNAME);


	// time Encaps

	n = 0;
	clk1 = clk_now();
	do {
		for (i = 0; i < XBENCH_REPS; i++) {
			crypto_kem_enc(ct[i], ss[i], pk[i]);
		}
		clk2 = clk_now() - clk1;
		n += XBENCH_REPS;
	} while (clk2 < XBENCH_TIMEOUT);
	
	printf("%18.9f s   KEM Encaps  [%s]\n", 
		((double) clk2) / ((double) n), CRYPTO_ALGNAME);

	// time Decaps

	n = 0;
	clk1 = clk_now();
	do {
		for (i = 0; i < XBENCH_REPS; i++) {
			crypto_kem_dec(ss[i], ct[i], sk[i]);
		}
		clk2 = clk_now() - clk1;
		n += XBENCH_REPS;
	} while (clk2 < XBENCH_TIMEOUT);
	
	printf("%18.9f s   KEM Decaps  [%s]\n", 
		((double) clk2) / ((double) n), CRYPTO_ALGNAME);

	// free it 

	for (i = 0; i < XBENCH_REPS; i++) {
		free(pk[i]);
		free(sk[i]);
		free(ct[i]);
		free(ss[i]);
	}	
	return 0;
}
