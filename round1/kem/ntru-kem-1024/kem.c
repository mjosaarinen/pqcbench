

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "NTRUEncrypt.h"
#include "param.h"
#include "poly.h"
#include "api.h"
#include "crypto_hash_sha512.h"
#include "fastrandombytes.h"

/* kem and encryption use a same key gen */
int crypto_kem_keypair(
    unsigned char       *pk,
    unsigned char       *sk)
{
    int64_t     *f, *g, *hntt, *buf, *mem;
    PARAM_SET   *param;
    param   = get_param_set_by_id(TEST_PARAM_SET);

    /* memory for 3 ring elements: f, g and h */
    mem     = malloc (sizeof(int64_t)*param->N * 3);
    buf     = malloc (sizeof(int64_t)*param->N * 2);
    if (!mem || !buf)
    {
        printf("malloc error!\n");
        return -1;
    }

    f       = mem;
    g       = f   + param->N;
    hntt    = g   + param->N;

    keygen(f,g,hntt,buf,param);

    /* pack h into pk */
    pack_ring_element(pk, param, hntt);

    /* pack F into sk */
    pack_ring_element(sk, param, f);
    pack_ring_element(sk+param->N*sizeof(int32_t)/sizeof(unsigned char)+1, param, hntt);

    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*2);

    free(mem);
    free(buf);

    return 0;
}



int crypto_kem_enc(
    unsigned char       *ct,
    unsigned char       *ss,
    const unsigned char *pk)
{

    PARAM_SET   *param;
    param   = get_param_set_by_id(pk[0]);

    if (param->id!=NTRU_KEM_1024)
    {
        printf("unsupported parameter sets\n");
        return -1;
    }

    int64_t    *buf, *mem, *hntt, *cpoly;
    unsigned char *shared_secret;


    mem     = malloc(sizeof(int64_t)*param->N*2);
    buf     = malloc(sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
    shared_secret = malloc(CRYPTO_BYTES + LENGTH_OF_HASH);

    if (!mem || !buf || !shared_secret)
    {
        printf("malloc error!\n");
        return -1;
    }

    hntt    = mem;
    cpoly   = hntt  + param->N;


    memset(mem,0, sizeof(int64_t)*param->N*2);
    memset(buf,0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
    memset(shared_secret, 0, CRYPTO_BYTES + LENGTH_OF_HASH);
    memset(ss, 0, CRYPTO_BYTES);


    /* randomly generate a string to be encapsulated */
    fastrandombytes(shared_secret, CRYPTO_BYTES);
    unpack_ring_element (pk,param, hntt);
    encrypt_cca(cpoly, (char*) shared_secret, CRYPTO_BYTES, hntt,  buf, param);
    pack_ring_element (ct, param, cpoly);


    /* ss = Hash (shared_secret | h) */
    crypto_hash_sha512(shared_secret + CRYPTO_BYTES, (unsigned char*)hntt, sizeof(uint64_t)*param->N);
    crypto_hash_sha512(shared_secret, shared_secret, LENGTH_OF_HASH + CRYPTO_BYTES);
    memcpy (ss, shared_secret, CRYPTO_BYTES);


    memset(mem,0, sizeof(int64_t)*param->N*2);
    memset(buf,0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
    memset(shared_secret, 0, CRYPTO_BYTES + LENGTH_OF_HASH);
    free(mem);
    free(buf);
    free(shared_secret);

    return 0;
}


int crypto_kem_dec(
    unsigned char       *ss,
    const unsigned char *ct,
    const unsigned char *sk)
{
    PARAM_SET   *param;

    param   =   get_param_set_by_id(ct[0]);
    if (param->id!=NTRU_KEM_1024)
    {
        printf("unsupported parameter sets\n");
        return -1;
    }

    int64_t     *buf, *mem, *f, *cpoly, *hntt;
    unsigned char *shared_secret;

    mem     = malloc(sizeof(int64_t)*param->N*3);
    buf     = malloc(sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
    shared_secret = malloc(CRYPTO_BYTES + LENGTH_OF_HASH);


    if (!mem || !buf || !shared_secret)
    {
        printf("malloc error!\n");
        return -1;
    }

    f       = mem;
    cpoly   = f     + param->N;
    hntt    = cpoly + param->N;

    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
    memset(shared_secret, 0, CRYPTO_BYTES + LENGTH_OF_HASH);


    /* decrypt the message */
    unpack_ring_element (ct, param, cpoly);
    unpack_ring_element (sk, param, f);
    unpack_ring_element (sk+param->N*sizeof(int32_t)/sizeof(unsigned char)+1, param, hntt);

    if (decrypt_cca((char*) shared_secret, f, hntt, cpoly, buf, param)!=CRYPTO_BYTES)
    {
        memset(mem,0, sizeof(int64_t)*param->N*3);
        memset(buf,0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
        memset(shared_secret, 0, CRYPTO_BYTES + LENGTH_OF_HASH);

        free(mem);
        free(buf);
        free(shared_secret);
        return -1;
    }


    /* ss = Hash (shared_secret | h) */
    crypto_hash_sha512(shared_secret + CRYPTO_BYTES, (unsigned char*)hntt, sizeof(uint64_t)*param->N);
    crypto_hash_sha512(shared_secret, shared_secret, LENGTH_OF_HASH + CRYPTO_BYTES);
    memcpy (ss, shared_secret, CRYPTO_BYTES);


    memset(mem,0, sizeof(int64_t)*param->N*3);
    memset(buf,0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
    memset(shared_secret, 0, CRYPTO_BYTES + LENGTH_OF_HASH);

    free(mem);
    free(buf);
    free(shared_secret);
    return 0;
}


