/*
 * poly_algo.c
 *
 *  Created on: Aug 16, 2017
 *      Author: zhenfei
 */
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "param.h"
#include "fastrandombytes.h"
#include "poly.h"


/* generate a random binary polynomial */
void
binary_poly_gen(
          int64_t  *f,
    const int16_t  N)
{
    uint16_t r;
    uint64_t i,j,index;
    for (i=0;i<=N/16;i++)
    {
        rng_uint16(&r);
        for (j=0;j<16;j++)
        {
            index = i*16+j;
            if (index<N)
                f[index] = (r & ( 1 << j)) >> j;
        }
    }
}


/* generate a trinary polynomial with fixed number of +/- 1s */
void
trinary_poly_gen(
          uint64_t  *f,
    const uint16_t  N,
    const uint16_t  d)
{
  uint64_t r;
  int16_t count,i, coeff[6];

  count = 0;
  while(count < d+1)
  {
    rng_uint64(&r);
    for (i =0;i<6;i++)
    {
        coeff[i] = r & 0x3FF;
        r = (r - coeff[i])>>10;
        if (coeff[i]<N)
        {
            if (f[coeff[i]]==0)
            {
                f[coeff[i]]=1;
                count++;
            }
        }
    }
  }
  count = 0;
  while(count < d)
  {
    rng_uint64(&r);
    for (i =0;i<6;i++)
    {
        coeff[i] = r & 0x3FF;
        r = (r - coeff[i])>>10;
        if (coeff[i]<N)
        {
            if (f[coeff[i]]==0)
            {
                f[coeff[i]]=-1;
                count++;
            }
        }

    }
  }
  return;
}


