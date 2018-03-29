/**
 *  PQCgenKAT_kem.c
 *
 *  Created by Bassham, Lawrence E (Fed) on 8/29/17.
 *  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
 *  
 *  - @cjt Added some lines to print out additional header information on rsp file
 *  - @cjt Added some lines to print out additional information for intermediate-values
 *  - @cjt Tiny mods as per djb's pqskeleton
 *
 **/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "random.h"
#include "api.h"

#define KATNUM              100
#define	MAX_MARKER_LEN		50
#define KAT_SUCCESS          0
#define KAT_FILE_OPEN_ERROR -1
#define KAT_DATA_ERROR      -3
#define KAT_CRYPTO_FAILURE  -4

int		FindMarker(FILE *infile, const char *marker);
int		ReadHex(FILE *infile, unsigned char *A, int Length, char *str);
void	fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L);

int
main()
{
    char                fn_req[32], fn_rsp[32];
    FILE                *fp_req, *fp_rsp;
    unsigned char       seed[48];
    unsigned char       entropy_input[48];
    unsigned char       ct[CRYPTO_CIPHERTEXTBYTES], ss[CRYPTO_BYTES], ss1[CRYPTO_BYTES];
    int                 count;
    int                 done;
    unsigned char       pk[CRYPTO_PUBLICKEYBYTES], sk[CRYPTO_SECRETKEYBYTES];
    int                 i, ret_val;
    
    /* Create the REQUEST file */
    sprintf(fn_req, "PQCkemKAT_%d.req", CRYPTO_SECRETKEYBYTES);
    if ( (fp_req = fopen(fn_req, "w")) == NULL ) {
        fprintf(stderr, "Couldn't open <%s> for write\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
    sprintf(fn_rsp, "PQCkemKAT_%d.rsp", CRYPTO_SECRETKEYBYTES);
    if ( (fp_rsp = fopen(fn_rsp, "w")) == NULL ) {
        fprintf(stderr, "Couldn't open <%s> for write\n", fn_rsp);
        return KAT_FILE_OPEN_ERROR;
    }
    
    for (i=0; i<48; i++)
        entropy_input[i] = i;

    randombytes_init(entropy_input, NULL, 256);
    for (i=0; i<KATNUM; i++) {
        fprintf(fp_req, "count = %d\n", i);
        randombytes(seed, 48);
        fprintBstr(fp_req, "seed = ", seed, 48);
        fprintf(fp_req, "pk =\n");
        fprintf(fp_req, "sk =\n");
        fprintf(fp_req, "ct =\n");
        fprintf(fp_req, "ss =\n\n");
    }
    fclose(fp_req);
    
    /* Create the RESPONSE file based on what's in the REQUEST file */
    if ( (fp_req = fopen(fn_req, "r")) == NULL ) {
        fprintf(stderr, "Couldn't open <%s> for read\n", fn_req);
        return KAT_FILE_OPEN_ERROR;
    }
    
    fprintf(fp_rsp, "# %s\n", CRYPTO_ALGNAME);
    fprintf(fp_rsp, "# Scheme: KEM\n");
    fprintf(fp_rsp, "# Description: this file contains %d KAT items of %s algorithm\n", KATNUM, CRYPTO_ALGNAME);    
    fprintf(fp_rsp, "# Public-key size: %d bytes\n", CRYPTO_PUBLICKEYBYTES);
    fprintf(fp_rsp, "# Private-key size: %d bytes\n", CRYPTO_SECRETKEYBYTES);
    fprintf(fp_rsp, "# Ciphertext size: %d bytes\n", CRYPTO_CIPHERTEXTBYTES);
    fprintf(fp_rsp, "# Shared secret size: %d bytes\n\n", CRYPTO_BYTES);
#if defined(INTERMEDIATE_VALUES)
    fprintf(stdout, "# %s Intermediate Values\n", CRYPTO_ALGNAME);
    fprintf(stdout, "# -----------------------------------------\n");
    fprintf(stdout, "# This file contains %d runs of %s key-generation, encapsulation and decapsulation.\n",
        KATNUM, CRYPTO_ALGNAME);
    fprintf(stdout, "# For key-generation, the following intermediate-values are output:\n");
    fprintf(stdout, "#   Step 1. Randomly generated monic Goppa polynomial Gz. Each sampled Goppa polynomial\n");
    fprintf(stdout, "#           is shown, including its status (valid or invalid)\n");
    fprintf(stdout, "#   Step 2. Random permutation vector p\n");
    fprintf(stdout, "#   Step 3. Construct a generator matrix:\n");
    fprintf(stdout, "#     (a) Vector a after permutation by p\n");
    fprintf(stdout, "#     (b) Vector h after permutation by p\n");
    fprintf(stdout, "#     (c) The parity-check matrix H (not in reduced-echelon form)\n");
    fprintf(stdout, "#     (d) The parity-check matrix H (in reduced-echelon form)\n");
    fprintf(stdout, "#     (d) Vectors p, a, h after potential column swapping introduced in (d)\n");
    fprintf(stdout, "#     (e) The matrix Q\n");
    fprintf(stdout, "#   Step 4. The vector a* (labelled a_ast) and h* (labelled h_ast)\n");
    fprintf(stdout, "# For encapsulation, the following intermediate-values are output:\n");
    fprintf(stdout, "#   Step 1-2. Randomly error vector e.\n");
    fprintf(stdout, "#   Step 3. The vector k_e = SHAKE256(e)\n");
    fprintf(stdout, "#   Step 4. The message vector m\n");
    fprintf(stdout, "#   Step 5. The two parts of the ciphertext: c_b and c_c\n");
    fprintf(stdout, "#   Step 6. The vector k_r\n");
    fprintf(stdout, "# For decapsulation, the following intermediate-values are output:\n");
    fprintf(stdout, "#   Step 1(a)-(c). The syndrome vector s\n");
    fprintf(stdout, "#   Step 1(d). The output of Berlekamp-Massey algorithm: sigma and xi\n");
    fprintf(stdout, "#   Step 1(e). The output of multipoint evaluation of sigma with FFT\n");
    fprintf(stdout, "#   Step 1(f). The error vector e_prime\n");
    fprintf(stdout, "#   Step 2. The permuted version of e_prime: vector e\n");
    fprintf(stdout, "#   Step 3. The vector k_e, recovered from ciphertext and vector e\n");
    fprintf(stdout, "#   Step 4. Output of SHAKE256(e) and vector k_r\n");
    fprintf(stdout, "# Note that all random bytes are obtained using AES_CTR_DRBG (SP800-90A section 10.2.1.5.1),\n");
    fprintf(stdout, "# initialised by the per-run 'seed' value as indicated below.\n#\n");
#endif
    done = 0;
    do {
        if ( FindMarker(fp_req, "count = ") ) {
            if (fscanf(fp_req, "%d", &count) < 0) {
				done = 1;
				break;
			}
		} else {
            done = 1;
            break;
        }
        fprintf(fp_rsp, "count = %d\n", count);
        
        if ( !ReadHex(fp_req, seed, 48, "seed = ") ) {
            fprintf(stderr, "ERROR: unable to read 'seed' from <%s>\n", fn_req);
            return KAT_DATA_ERROR;
        }
        fprintBstr(fp_rsp, "seed = ", seed, 48);
  
#if defined(INTERMEDIATE_VALUES)
        fprintf(stdout, "# count = %d\n", count);
        fprintBstr(stdout, "# seed = ", seed, 48);
        fprintf(stdout, "# =====================================================\n");
#endif
        
        randombytes_init(seed, NULL, 256);

#if !defined(INTERMEDIATE_VALUES)
        fprintf(stdout, "."); fflush(stdout);
#endif
        
#if defined(INTERMEDIATE_VALUES)
        fprintf(stdout, "# BEGIN KEY-GEN ----------------------------------------\n");
#endif
        /* Generate the public/private keypair */
        if ( (ret_val = crypto_kem_keypair(pk, sk)) != 0) {
            fprintf(stderr, "crypto_kem_keypair returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        fprintBstr(fp_rsp, "pk = ", pk, CRYPTO_PUBLICKEYBYTES);
        fprintBstr(fp_rsp, "sk = ", sk, CRYPTO_SECRETKEYBYTES);

#if defined(INTERMEDIATE_VALUES)
        fprintf(stdout, "# END KEY-GEN ------------------------------------------\n\n");
#endif
        
#if defined(INTERMEDIATE_VALUES)
        fprintf(stdout, "# BEGIN ENCAPSULATION ----------------------------------\n");
#endif
        if ( (ret_val = crypto_kem_enc(ct, ss, pk)) != 0) {
            fprintf(stderr, "crypto_kem_enc returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        fprintBstr(fp_rsp, "ct = ", ct, CRYPTO_CIPHERTEXTBYTES);
        fprintBstr(fp_rsp, "ss = ", ss, CRYPTO_BYTES);
        
        fprintf(fp_rsp, "\n");

#if defined(INTERMEDIATE_VALUES)
        fprintf(stdout, "# END ENCAPSULATION ------------------------------------\n\n");
#endif
        
#if defined(INTERMEDIATE_VALUES)
        fprintf(stdout, "# BEGIN DECAPSULATION ----------------------------------\n");
#endif
        if ( (ret_val = crypto_kem_dec(ss1, ct, sk)) != 0) {
            fprintf(stderr, "crypto_kem_dec returned <%d>\n", ret_val);
            return KAT_CRYPTO_FAILURE;
        }
        
        if ( memcmp(ss, ss1, CRYPTO_BYTES) ) {
            fprintf(stderr, "crypto_kem_dec returned bad 'ss' value\n");
            return KAT_CRYPTO_FAILURE;
        }

#if defined(INTERMEDIATE_VALUES)
        fprintf(stdout, "# END DECAPSULATION ------------------------------------\n\n");
#endif
        
    } while ( !done );

#if !defined(INTERMEDIATE_VALUES)
    fprintf(stdout, "\n"); fflush(stdout);
#endif
    
    fclose(fp_req);
    fclose(fp_rsp);

    return KAT_SUCCESS;
}



/**
 * ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
 *
 *
 * ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
 **/
int
FindMarker(FILE *infile, const char *marker)
{
	char	line[MAX_MARKER_LEN];
	int		i, len;
	int curr_line;

	len = (int)strlen(marker);
	if ( len > MAX_MARKER_LEN-1 )
		len = MAX_MARKER_LEN-1;

	for ( i=0; i<len; i++ )
	  {
	    curr_line = fgetc(infile);
	    line[i] = curr_line;
	    if (curr_line == EOF )
	      return 0;
	  }
	line[len] = '\0';

	while ( 1 ) {
		if ( !strncmp(line, marker, len) )
			return 1;

		for ( i=0; i<len-1; i++ )
			line[i] = line[i+1];
		curr_line = fgetc(infile);
		line[len-1] = curr_line;
		if (curr_line == EOF )
		    return 0;
		line[len] = '\0';
	}

	/* shouldn't get here */
	return 0;
}

/**
 * ALLOW TO READ HEXADECIMAL ENTRY (KEYS, DATA, TEXT, etc.)
 **/
int
ReadHex(FILE *infile, unsigned char *A, int Length, char *str)
{
	int			i, ch, started;
	unsigned char	ich;

	if ( Length == 0 ) {
		A[0] = 0x00;
		return 1;
	}
	memset(A, 0x00, Length);
	started = 0;
	if ( FindMarker(infile, str) )
		while ( (ch = fgetc(infile)) != EOF ) {
			if ( !isxdigit(ch) ) {
				if ( !started ) {
					if ( ch == '\n' )
						break;
					else
						continue;
				}
				else
					break;
			}
			started = 1;
			if ( (ch >= '0') && (ch <= '9') )
				ich = ch - '0';
			else if ( (ch >= 'A') && (ch <= 'F') )
				ich = ch - 'A' + 10;
			else if ( (ch >= 'a') && (ch <= 'f') )
				ich = ch - 'a' + 10;
            else /* shouldn't ever get here */
                ich = 0;
			
			for ( i=0; i<Length-1; i++ )
				A[i] = (A[i] << 4) | (A[i+1] >> 4);
			A[Length-1] = (A[Length-1] << 4) | ich;
		}
	else
		return 0;

	return 1;
}

void
fprintBstr(FILE *fp, char *S, unsigned char *A, unsigned long long L)
{
	unsigned long long  i;

	fprintf(fp, "%s", S);

	for ( i=0; i<L; i++ )
		fprintf(fp, "%02X", A[i]);

	if ( L == 0 )
		fprintf(fp, "00");

	fprintf(fp, "\n");
}

