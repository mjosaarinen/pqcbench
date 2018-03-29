/*
 * NTRUEncrypt.h
 *
 *  Created on: Aug 16, 2017
 *      Author: zhenfei
 */

#ifndef NTRUENCRYPT_H_
#define NTRUENCRYPT_H_

#include "param.h"


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
    const PARAM_SET   *param);

/*
 * input a set of parameters, output keys f, g, h
 * requires buffer memory for 2 ring elements
 */
void
keygen_KAT(
          int64_t   *f,       /* output secret key f */
          int64_t   *g,       /* output secret key g */
          int64_t   *hntt,    /* output public key h in NTT form*/
          int64_t   *buf,
    const PARAM_SET *param,
    unsigned char   *seed);

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
    const PARAM_SET *param);

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
    const PARAM_SET *param);

/*
 * input a message m and a public h, encapsulate m
 * requires buffer memory for 4 ring elements
 */
void
encrypt_kem_KAT(
    const int64_t   *m,     /* input binary message */
    const int64_t   *hntt,  /* input public key */
          int64_t   *cntt,  /* output ciphertext */
          int64_t   *buf,
    const PARAM_SET *param,
    unsigned char   *seed);

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
    const PARAM_SET *param);

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
    const PARAM_SET *param);

/*
 * CCA-2 secure encryption algorithm using NAEP
 * memory requirement: 7 ring elements + LENGTH_OF_HASH*2
 */
void
encrypt_cca_KAT(
          int64_t   *cntt,  /* output ciphertext */
    const char      *msg,   /* input binary message */
    const size_t    msg_len,/* input - length of the message */
    const int64_t   *hntt,  /* input public key */
          int64_t   *buf,
    const PARAM_SET *param,
    unsigned char   *seed);

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
    const PARAM_SET *param);


void
pack_ring_element(
    unsigned char   *str,
    const PARAM_SET *param,
    const int64_t   *ring);

void
unpack_ring_element(
    const unsigned char
                    *str,
    PARAM_SET       *param,
    int64_t         *ring);

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
    const PARAM_SET *param);

/*
 * check if a message length is valid for ntruencrypt-cca
 * then convert the message into a binary polynomial and
 * pad the message with a random binary string p
 */
int
pad_msg_KAT(
          int64_t   *m,     /* output message */
    const char      *msg,   /* input message string */
    const size_t    msg_len,/* input length of the message */
    const PARAM_SET *param,
    unsigned char   *seed);


/*
 * input a message msg, output msg \xor hash(last_bit_of_rh)
 * memory requirements: LENGTH_OF_HASH
 */
int
mask_m(
          int64_t   *msg,   /* in/output binary message */
    const int64_t   *rh,
          int64_t   *buf,
    const PARAM_SET *param);

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
    const PARAM_SET *param);
/*
 * converting a binary polynomial into a char string
 * return the length of the message string
 */
int
recover_msg(
          char      *msg,   /* output message string */
    const int64_t   *m,     /* input binary message */
    const PARAM_SET *param);


#endif /* NTRUENCRYPT_H_ */
