/*
 * param.h
 *
 *  Created on: Aug 16, 2017
 *      Author: zhenfei
 */

#ifndef PARAM_H_
#define PARAM_H_

#include <stdint.h>

#define LENGTH_OF_HASH  64
#define LENGTH_OF_B     256

typedef enum _SSNTRU_PARAM_SET_ID         PARAM_SET_ID;
typedef const struct _SSNTRU_PARAM_SET    PARAM_SET;

enum _SSNTRU_PARAM_SET_ID {
    /* scheme_method - dimension */
    NTRU_KEM_1024,
    NTRU_CCA_1024
};


struct _SSNTRU_PARAM_SET {
    PARAM_SET_ID     id;          /* parameter set id */
    const char       *name;       /* human readable name */
    const uint8_t    OID[3];      /* OID */
    uint8_t          N_bits;      /* ceil(log2(N)) */
    uint8_t          q_bits;      /* ceil(log2(q)) */
    const uint64_t   N;           /* ring degree */
    int8_t           p;           /* message space prime */
    int64_t          q;           /* ring modulus */
    const uint64_t   stddev;      /* standard deviation*/
    int16_t          max_msg_len; /* maximum message length (in bytes) */

};

PARAM_SET *
get_param_set_by_id(PARAM_SET_ID id);


#endif /* PARAM_H_ */
