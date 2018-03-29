/**
 *  ntskem_test.c
 *  NTS-KEM test
 *
 *  Parameter: NTS-KEM(13, 80)
 *  Platform: Intel 64-bit
 *
 *  This file is part of the optimized implemention of NTS-KEM
 *  submitted as part of NIST Post-Quantum Cryptography
 *  Standardization Process.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "ntskem_test.h"
#include "random.h"

uint8_t* hexstr_to_char(const char* hexstr, int32_t *size)
{
    int i, j;
    uint8_t* buffer = NULL;
    size_t len = strlen(hexstr);
    
    *size = 0;
    if (len & 1)
        return NULL;
    len >>= 1;
    
    if (!(buffer = (unsigned char*)malloc((len+1) * sizeof(uint8_t))))
        return NULL;
    
    for (i=0, j=0; j<len; i+=2, j++)
        buffer[j] = ((((hexstr[i] & 31) + 9) % 25) << 4) + ((hexstr[i+1] & 31) + 9) % 25;
    buffer[len] = '\0';
    *size = (int32_t)len;
    
    return buffer;
}

int testkem_nts(int iterations)
{
    int i, it = 0, status = 1;
    uint8_t *pk, *sk;
    uint8_t *encap_key, *decap_key, *ciphertext;
#if !defined(DETERMINISTIC)
    FILE *fp = NULL;
#endif
    unsigned char entropy_input[] = {
        0xaa, 0xe7, 0xd7, 0x4e, 0x3c, 0x3a, 0x52, 0xdd,
        0x87, 0xc7, 0x2a, 0xa4, 0x38, 0x54, 0x7e, 0x37,
        0x1e, 0x97, 0x29, 0x78, 0x22, 0xa2, 0xcd, 0x83,
        0x43, 0x64, 0x84, 0xcf, 0x77, 0x6b, 0x9e, 0xa5,
        0x53, 0xf3, 0x50, 0xc5, 0xc7, 0x8d, 0x46, 0xb3,
        0xa5, 0xf2, 0xe3, 0x99, 0x63, 0x10, 0x1d, 0x10
    };
    unsigned char nonce[48];
    /*
     unsigned char *nonce = NULL;
     int32_t nonce_size = 48;
     */
    
    fprintf(stdout, "NTS-KEM(%d, %d) Test\n", NTSKEM_M, NTSKEM_T);

    do {
#if defined(DETERMINISTIC)
        /*
        nonce = hexstr_to_char(nonce_str, &nonce_size);
        */
        memset(nonce, 0, sizeof(nonce));
#else
        if ((fp = fopen("/dev/urandom", "r"))) {
            if ((sizeof(entropy_input) != fread(entropy_input, 1, sizeof(entropy_input), fp)) ||
                (sizeof(nonce) != fread(nonce, 1, sizeof(nonce), fp))) {
                status = 0;
                break;
            }
        }
        fclose(fp);
#endif
        memcpy(&entropy_input[48-sizeof(it)], &it, sizeof(it));
        
        fprintf(stdout, "Iteration: %d, Seed: ", it);
        for (i=0; i<sizeof(entropy_input); i++) fprintf(stdout, "%02x", entropy_input[i]);
        fprintf(stdout, "\n"); fflush(stdout);
        
        randombytes_init(entropy_input, nonce, 256);

        pk = (uint8_t *)calloc(CRYPTO_PUBLICKEYBYTES, sizeof(uint8_t));
        sk = (uint8_t *)calloc(CRYPTO_SECRETKEYBYTES, sizeof(uint8_t));
        if (crypto_kem_keypair(pk, sk))
            status = 0;
        
        ciphertext = (uint8_t *)calloc(CRYPTO_CIPHERTEXTBYTES, sizeof(uint8_t));
        encap_key = (uint8_t *)calloc(CRYPTO_BYTES, sizeof(uint8_t));
        decap_key = (uint8_t *)calloc(CRYPTO_BYTES, sizeof(uint8_t));

        if (crypto_kem_enc(ciphertext, encap_key, pk))
            status = 0;
        
        if (crypto_kem_dec(decap_key, ciphertext, sk))
            status = 0;
        
        status &= (0 == memcmp(encap_key, decap_key, CRYPTO_BYTES));
        
        free(decap_key);
        free(encap_key);
        free(ciphertext);
        free(sk);
        free(pk);
        /*
        if (nonce) free(nonce);
        */
    }
    while (status && ++it < iterations);

    return status;
}
