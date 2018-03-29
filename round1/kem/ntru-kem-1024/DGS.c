/*
 *  Copyright 2017 Zhenfei Zhang @ onboard security
 *
 *  This file is part of pqNTRUSign signature scheme with bimodal
 *  Gaussian sampler (Gaussian-pqNTRUSign).
 *
 *  This software is released under GPL:
 *  you can redistribute it and/or modify it under the terms of the
 *  GNU General Public License as published by the Free Software
 *  Foundation, either version 2 of the License, or (at your option)
 *  any later version.
 *
 *  You should have received a copy of the GNU General Public License.
 *  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdint.h>
#include <math.h>

#include "fastrandombytes.h"
#include "crypto_hash_sha512.h"

/*
 * Discrete Gaussian sampler using Box-Muller method
 * with 53 bits of precision
 */

void DGS (      int64_t   *v,
          const uint16_t  dim,
          const uint64_t  stdev)
{
    uint16_t d2 = dim/2;
    uint16_t i;
    uint64_t t;

    static double const Pi=3.141592653589793238462643383279502884L;
    static long const bignum = 0xfffffff;
    double r1, r2, theta, rr;

    for (i=0;i<d2;i++)
    {

        rng_uint64(&t);
        r1 = (1+(t&bignum))/((double)bignum+1);
        r2 = (1+((t>>32)&bignum))/((double)bignum+1);
        theta = 2*Pi*r1;
        rr = sqrt(-2.0*log(r2))*stdev;
        v[2*i] = (int64_t) floor(rr*sin(theta) + 0.5);
        v[2*i+1] = (int64_t) floor(rr*cos(theta) + 0.5);

    }

    if (dim%2 == 1)
    {
        rng_uint64(&t);
        r1 = (1+(t&bignum))/((double)bignum+1);
        r2 = (1+((t>>32)&bignum))/((double)bignum+1);
        theta = 2*Pi*r1;
        rr = sqrt(-2.0*log(r2))*stdev;
        v[dim-1] = (int64_t) floor(rr*sin(theta) + 0.5);
    }
}

/* deterministic DGS */
void DDGS (      int64_t  *v,
          const uint16_t  dim,
          const uint64_t  stdev,
          unsigned char   *seed,
                  size_t  seed_len)
{
    uint16_t i,j;
    uint32_t *t;

    static double const Pi=3.141592653589793238462643383279502884L;
    static long const bignum = 0xfffffff;
    double r1, r2, theta, rr;

    unsigned char pool[64];
    crypto_hash_sha512(pool, seed, seed_len);
    t = (uint32_t*) pool;
    for (i=0;i<64;i++)
    {

        for (j=0;j<8;j++)
        {
            r1 = (1+(t[j*2]     &bignum))/((double)bignum+1);
            r2 = (1+(t[j*2+1]   &bignum))/((double)bignum+1);
            theta = 2*Pi*r1;
            rr = sqrt(-2.0*log(r2))*stdev;
            v[i*16+j*2]      = (int64_t) floor(rr*sin(theta) + 0.5);
            v[i*16+j*2+1]    = (int64_t) floor(rr*cos(theta) + 0.5);
        }
        /* update the pool */
        crypto_hash_sha512(pool, pool, 64);
    }

}
