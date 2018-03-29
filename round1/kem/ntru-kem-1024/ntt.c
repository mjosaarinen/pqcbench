/*
 * ntt.c
 *
 *  Created on: Aug 16, 2017
 *      Author: zhenfei
 */


#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ntt.h"
#include "param.h"

/* return a mod q within the interval 0 and q */
int64_t modq(
          int64_t     a,
          int64_t     q)
{
    int64_t     b = a%q;
    if (b<0)
        return q+b;
    else
        return b;
}

/* lift an NTT polynomial into integers */
void INTT(
          int64_t     *f,
    const int64_t     *f_ntt,
    const PARAM_SET    *param)
{
    uint16_t    i,j;
    int64_t     base;

    memset(f, 0, sizeof(int64_t)*param->N);
    for (j=0;j<param->N;j++)
    {
        base = 1;
        for (i=0;i<param->N;i++)
        {

            f[i] = modq(f[i]+f_ntt[j]*base,param->q);
            base = modq(base*inv_roots[j], param->q);
        }
    }
    for (i=0;i<param->N;i++)
    {
        f[i] = modq(f[i]*one_over_N,param->q);
        if(f[i]>param->q/2)
            f[i] = f[i]-param->q;
    }

}

/* converting a polynomial f into its NTT form */

void NTT(
    const int64_t     *f,
          int64_t     *f_ntt,
    const PARAM_SET    *param)
{
    uint16_t    i,j;
    int64_t     odd,even, base;
    int64_t     tmp;

    for (i=0;i<param->N/2;i++)
    {
        odd  = f[0];
        even = f[0];
        base = 1;
        for (j=1;j<param->N;j++)
        {
            base = base*roots[i];
            base = modq(base,param->q);

            tmp = modq(f[j],param->q)*base;
            tmp = modq(tmp, param->q);

            even = even + tmp;
            if (j%2==0)
                odd = odd + tmp;
            else
                odd = odd + param->q - tmp;
        }
        f_ntt[i]= modq(even, param->q);
        f_ntt[param->N-1-i] = modq(odd, param->q);
    }
}

/* xgcd algorithm */
static int64_t
zz_gcd(
    const int64_t a,
    const int64_t b,
    int64_t       *u_ptr,
    int64_t       *v_ptr)
{
  int64_t d = a;
  int64_t u = 1;
  int64_t v = 0;
  int64_t v1, v3, t1, t3;
  if(b != 0) {
    v1 = 0;
    v3 = b;
    do {
      t1 = d / v3;
      t3 = d % v3;
      t1 = u - (t1*v1);

      u = v1;
      d = v3;
      v1 = t1;
      v3 = t3;
    } while(v3 != 0);
    v = (d - a*u)/b;
  }
  if(u_ptr != NULL) *u_ptr = u;
  if(v_ptr != NULL) *v_ptr = v;
  return d;
}

/* compute a^-1 mod n */
int64_t
InvMod(
    int64_t       a,
    const int64_t p)
{
  int64_t r;
  int64_t t = ((int64_t)(a > 0) - (int64_t)(a < 0));
  a *= t;

  if(zz_gcd(a,p,&r,NULL) == 1)
  {
    r *= t;
    return (r > 0) ? r : p + r;
  }
  return 0;
}

/* xgcd algorithm */
int64_t* extendedEuclid (int64_t a, int64_t b)
{
    int64_t array[3];
    int64_t *dxy = array;

    if (b ==0){
        dxy[0] =a; dxy[1] =1; dxy[2] =0;

        return dxy;
    }
    else{
        int64_t t, t2;
        dxy = extendedEuclid(b, (a %b));
        t   = dxy[1];
        t2  = dxy[2];
        dxy[1] =dxy[2];
        dxy[2] = t - a/b *t2;

        return dxy;
    }
}

