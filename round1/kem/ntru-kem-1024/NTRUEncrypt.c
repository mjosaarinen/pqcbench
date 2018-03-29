/*
 * NTRUEncrypt.c
 *
 *  Created on: Aug 16, 2017
 *      Author: zhenfei
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "param.h"
#include "poly.h"
#include "fastrandombytes.h"
#include "crypto_hash_sha512.h"

/*
 * input a set of parameters, output keys f, g, h
 * requires buffer memory for 2 ring elements
 */
void
keygen(
          int64_t     *f,       /* output secret key f */
          int64_t     *g,       /* output secret key g */
          int64_t     *hntt,    /* output public key h in NTT form*/
          int64_t     *buf,
    const PARAM_SET   *param)
{

    int16_t i;
    int64_t *fntt, *gntt;

    fntt = buf;
    gntt = buf+param->N;

    /* sample F and g from discrete Gaussian */
    DGS(f,param->N,param->stddev);
    DGS(g,param->N,param->stddev);

    /* f = 2F+1 */
    for(i=0;i<param->N;i++)
    {
        f[i] = f[i]*2;
    }
    f[0] = f[0]+1;

    /* converting to NTT form */
    NTT(g,gntt,param);
    NTT(f,fntt,param);

    /* compute h = g/f mod q */
    for (i=0;i<param->N;i++)
    {
        /* compute f^-1 mod q */
        fntt[i] = InvMod(fntt[i],param->q);
        /* compute h = gf^-1 mod q */
        hntt[i] = 2*gntt[i]*fntt[i] % param->q;
    }
    memset(buf, 0, sizeof(int64_t)*param->N*2);
}

/*
 * optional, check the correctness of the keys;
 * requires buffer memory for 2 ring elements
 */
int
check_keys(
    const int64_t   *f,
    const int64_t   *g,
    const int64_t   *hntt,
          int64_t   *buf,
    const PARAM_SET *param)
{
    int16_t i;
    int64_t *fntt, *gntt, *grec;

    fntt = buf;
    gntt = fntt +param->N;
    grec = gntt +param->N;

    NTT(f,fntt,param);
    for (i=0;i<param->N;i++)
        gntt[i] = modq(fntt[i]*hntt[i], param->q);

    INTT(grec,gntt,param);
    for(i=0;i<param->N;i++)
    {
        if (grec[i]!=g[i]*2)
        {
            printf("checking keys error: %d %lld %lld\n", i, (long long) grec[i], (long long) g[i]);
            memset(buf, 0, sizeof(int64_t)*param->N*3);
            return -1;
        }
    }
    return 0;
}

/*
 * input a message m and a public h, encapsulate m
 * requires buffer memory for 4 ring elements
 */
void
encrypt_kem(
    const int64_t   *m,     /* input binary message */
    const int64_t   *hntt,  /* input public key */
          int64_t   *cntt,  /* output ciphertext */
          int64_t   *buf,
    const PARAM_SET *param)
{
    uint16_t i;

    /* check message is binary */
    for (i=0;i<param->N;i++)
    {
        if (m[i]!=0 && m[i]!=1)
        {
            printf("invalid messages\n");
            return;
        }
    }

    int64_t *e, *entt, *r, *rntt;
    e    = buf;
    entt = e    +param->N;
    r    = entt +param->N;
    rntt = r    +param->N;

    DGS(e,param->N,param->stddev);
    DGS(r,param->N,param->stddev);
    for (i=0;i<param->N;i++)
        e[i] = e[i]*2 + m[i];

    NTT(e, entt, param);
    NTT(r, rntt, param);

    for (i=0;i<param->N;i++)
        cntt[i] = modq(rntt[i]*hntt[i]+entt[i], param->q);

    memset(buf, 0, sizeof(int64_t)*param->N*4);

    return;
}

/*
 * decapsulation function;
 * memory requirements: 2 ring elements;
 */
void
decrypt_kem(
          int64_t   *m,     /* output binary message */
    const int64_t   *f,     /* input secret key */
    const int64_t   *cntt,  /* input ciphertext */
          int64_t   *buf,
    const PARAM_SET *param)
{
    uint16_t    i;
    int64_t     *fntt,*mntt;
    fntt = buf;
    mntt = buf+param->N;

    NTT(f, fntt, param);
    for (i=0;i<param->N;i++)
        mntt[i] = modq(fntt[i]*cntt[i],param->q);

    INTT(m, mntt, param);

    for (i=0;i<param->N;i++)
    {
        if (m[i]>param->q/2)
            m[i] = m[i] - param->q;
        m[i] = modq(m[i],2);
    }
    memset(buf, 0, sizeof(int64_t)*param->N*2);
}

/*
 * check if a message length is valid for ntruencrypt-cca
 * then convert the message into a binary polynomial and
 * pad the message with a random binary string p
 */
int
pad_msg(
          int64_t   *m,     /* output message */
    const char      *msg,   /* input message string */
    const size_t    msg_len,/* input length of the message */
    const PARAM_SET *param)
{
    if (msg_len > param->max_msg_len)
    {
        printf("error: message too long");
        return -1;
    }
    int64_t     *pad;
    uint16_t    i,j;
    char        tmp;
    memset(m, 0, sizeof(int64_t)*param->N);

    /* generate the pad */
    pad =   m + param->N - 256;
    binary_poly_gen(pad, 256);

    /* convert the message length into coefficients */
    pad -= 8;
    tmp = msg_len;
    for(j=0;j<8;j++)
    {
        pad[j] = tmp & 1;
        tmp >>= 1;
    }

    /* form the message binary polynomial */
    for (i=0;i<msg_len;i++)
    {
        tmp = msg[i];
        for(j=0;j<8;j++)
        {
            m[i*8+j] = tmp & 1;
            tmp >>= 1;
        }
    }
    return 0;
}

/*
 * generate a Gaussian r from msg and hntt
 * memory requirement: 2 * LENGTH_OF_HASH
 */
int
generate_r(
          int64_t   *r,     /* output r */
    const int64_t   *msg,   /* input binary message */
    const int64_t   *hntt,  /* input public key */
          int64_t   *buf,
    const PARAM_SET *param)
{
    uint16_t i;
    for (i=0;i<param->N;i++)
    {
        if (msg[i]!=0 && msg[i]!=1)
        {
            printf("invalid messages\n");
            return -1;
        }
    }
    unsigned char *seed = (unsigned char*) buf;

    /* hash message/public key into a string 'seed'*/
    crypto_hash_sha512(seed, (unsigned char*)msg, param->N*8);
    crypto_hash_sha512(seed+LENGTH_OF_HASH, (unsigned char*)hntt, param->N*8);

    /* use the seed to generate r */
    DDGS(r, param->N,param->stddev, seed, LENGTH_OF_HASH*2);
    memset(seed, 0, sizeof(unsigned char)* LENGTH_OF_HASH*2);

    return 0;
}

/*
 * input a message msg, output msg \xor hash(last_bit_of_rh)
 * memory requirements: LENGTH_OF_HASH
 */
int
mask_m(
          int64_t   *msg,   /* in/output binary message */
    const int64_t   *rh,
          int64_t   *buf,
    const PARAM_SET *param)
{
    unsigned char   *seed;
    uint16_t        i,j;
    char            tmp;

    seed  = (unsigned char*) buf;

    /* extract the last bit of rh */
    for (i=0;i<LENGTH_OF_HASH*2;i++)
    {
        seed[i] = (rh[i*8] & 1);

//        for (j=1;j<8;j++)
        {
            seed[i] <<= 1;
            seed[i] += (rh[i*8+j] & 1);
        }
    }

    /* first 512 coefficients */
    crypto_hash_sha512(seed, (unsigned char*)rh, param->N*8);
    for (i=0;i<LENGTH_OF_HASH;i++)
    {
        tmp = seed[i];
        for(j=0;j<8;j++)
        {
            msg[i*8+j] = (msg[i*8+j] + tmp) &1;
            tmp >>= 1;
        }
    }

    crypto_hash_sha512(seed, seed, LENGTH_OF_HASH);
    for (i=0;i<LENGTH_OF_HASH;i++)
    {
        tmp = seed[i];
        for(j=0;j<8;j++)
        {
            msg[512+i*8+j] = (msg[512+i*8+j] + tmp) &1;
            tmp >>= 1;
        }
    }
    memset(buf,0,LENGTH_OF_HASH);
    return 0;
}

/*
 * CCA-2 secure encryption algorithm using NAEP
 * memory requirement: 7 ring elements + LENGTH_OF_HASH*2
 */
void
encrypt_cca(
          int64_t   *cntt,  /* output ciphertext */
    const char      *msg,   /* input binary message */
    const size_t    msg_len,/* input - length of the message */
    const int64_t   *hntt,  /* input public key */
          int64_t   *buf,
    const PARAM_SET *param)
{
    uint16_t i;

    int64_t *e, *entt, *r, *rntt, *m, *c;
    int64_t *hashbuf;

    e    = buf;
    entt = e    + param->N;
    r    = entt + param->N;
    rntt = r    + param->N;
    m    = rntt + param->N;
    c    = m    + param->N;
    hashbuf = m + param->N;

    memset (buf, 0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);

    /* pad the message into a ring element */
    pad_msg(m, msg, msg_len, param);

    /* generate r from hash(m|h) */
    generate_r(r, m, hntt, hashbuf, param);

    /* c = r*h */
    NTT(r, rntt, param);
    for (i=0;i<param->N;i++)
        cntt[i] = modq(rntt[i]*hntt[i], param->q);

    INTT(c,cntt, param);

    /* mask = hash(c);  m = m \xor mask */
    mask_m(c, m, hashbuf, param);

    /* e <-- DGS; e = 2e + m */
    DGS(e,param->N,param->stddev);
    for (i=0;i<param->N;i++)
        e[i] = e[i]*2 + m[i];

    NTT(e, entt, param);
    for (i=0;i<param->N;i++)
        cntt[i] = modq(cntt[i]+entt[i], param->q);

    memset(buf, 0, sizeof(int64_t)*param->N*7 + LENGTH_OF_HASH*2);
    return;
}

/*
 * converting a binary polynomial into a char string
 * return the length of the message string
 */
int
recover_msg(
          char      *msg,   /* output message string */
    const int64_t   *m,     /* input binary message */
    const PARAM_SET *param)
{
    char    tmp;
    int     msg_len;
    uint16_t i,j;

    for (j=0;j<8;j++)
    {
        msg_len += (m[param->N - 256 - 8 + j]<<j);
    }
    if (msg_len > param->max_msg_len)
    {
        printf("error: message too long");
        return -1;
    }

    for (i=0;i<msg_len;i++)
    {
        tmp = 0;
        for (j=0;j<8;j++)
        {
            tmp += (m[i*8+j]<<j);
        }
        msg[i] = (char)tmp;
    }
    return msg_len;
}


/*
 * CCA-2 secure decryption algorithm using NAEP
 * memory requirement: 7 ring elements + LENGTH_OF_HASH*2
 */
int decrypt_cca(
          char      *msg,   /* output message string */
    const int64_t   *f,     /* input secret key */
    const int64_t   *hntt,  /* input public key */
    const int64_t   *cntt,  /* input ciphertext */
          int64_t   *buf,
    const PARAM_SET *param)
{
    uint16_t    i;
    int64_t     *fntt,*mntt, *c,*r, *hashbuf, *rntt, *m;
    int msg_len;
    fntt = buf;
    mntt = fntt + param->N;
    c    = mntt + param->N;
    r    = c    + param->N;
    rntt = r    + param->N;
    m    = rntt + param->N;
    hashbuf = m + param->N;


    /* first, proceed a normal decryption */
    NTT(f, fntt, param);
    for (i=0;i<param->N;i++)
        mntt[i] = modq(fntt[i]*cntt[i],param->q);

    INTT(m, mntt, param);
    for (i=0;i<param->N;i++)
    {
        if (m[i]>param->q/2)
            m[i] = m[i] - param->q;
        m[i] = modq(m[i],2);
    }

    /* then, rebuilt r */
    INTT(c,cntt, param);
    for (i=0;i<param->N;i++)
        c[i] = c[i] - m[i];
    mask_m(c, m, hashbuf, param);

    generate_r(r, m, hntt, hashbuf, param);

    NTT(r,rntt, param);

    /* recover e as the difference between c and r*h */
    for (i=0;i<param->N;i++)
        rntt[i] = modq(rntt[i]*hntt[i]-cntt[i], param->q);

    INTT(c, rntt,param);

    /* check if e is too big */
    if (max_norm(c, param->N) > param->stddev*11)
    {
        printf ("error: e is too big\n");
        memset(buf, 0, sizeof(int64_t)*param->N*7);
        return -1;
    }
    else
    {
        msg_len = recover_msg(msg, m, param);
        memset(buf, 0, sizeof(int64_t)*param->N*7);
        return msg_len;
    }
}


