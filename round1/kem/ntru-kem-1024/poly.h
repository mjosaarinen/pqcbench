/*
 * poly_gen.h
 *
 *  Created on: Aug 16, 2017
 *      Author: zhenfei
 */

#ifndef POLY_POLY_H_
#define POLY_POLY_H_

#include <stdint.h>
#include "param.h"

/* generate a random binary polynomial with degree less than N */
void
binary_poly_gen(
          int64_t  *f,
    const int16_t  N);


/* generate a trinary polynomial with fixed number of +/- 1s */
void
trinary_poly_gen(
          uint64_t  *f,
    const uint16_t  N,
    const uint16_t  d);

/*
 * generate a degree N-1 polynomial whose coefficients
 * follow discrete Gaussian with deviation stdev
 */

void DGS (
          int64_t   *v,
    const uint16_t  N,
    const uint16_t   stdev);



/* deterministic DGS */
void DDGS (      int64_t  *v,
          const uint16_t  dim,
          const uint64_t  stdev,
          unsigned char   *seed,
                uint16_t  seed_len);

/* converting a poly into its NTT form */
void NTT(
    const int64_t     *f,
          int64_t     *f_ntt,
    const PARAM_SET    *param);

/* inverse the NTT conversion */
void INTT(
          int64_t     *f,
    const int64_t     *f_ntt,
    const PARAM_SET    *param);

/* misc functions */

int64_t InvMod(int64_t a, int64_t n);

int64_t modq(int64_t a, int64_t q);

int64_t max_norm(const int64_t *f, const int16_t N);
#endif /* POLY_POLY_H_ */
