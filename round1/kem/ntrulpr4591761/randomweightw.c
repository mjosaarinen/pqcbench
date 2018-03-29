/* See https://ntruprime.cr.yp.to/software.html for detailed documentation. */

#include "params.h"
#include "randombytes.h"
#include "int32_sort.h"
#include "small.h"
//#include "crypto_stream_aes256ctr.h"
#include <string.h>
#include "rng.h"

//static const unsigned char n[16] = {0};

void small_seeded_weightw(small *f,const unsigned char *k)
{
  crypto_int32 r[P];
  int i;

  AES_XOF_struct ctx;
  
  //  old code: crypto_stream_aes256ctr((unsigned char *) r,sizeof r,n,k);
  seedexpander_init(&ctx, (unsigned char *) k, 
  		(unsigned char *) "12345678", 0x7FFFFFFF);
  // make seedexpander work like the original function by zeroing countter
  memset(ctx.ctr, 0, 16);
  seedexpander(&ctx, (unsigned char *) r, sizeof(r));


  for (i = 0; i < P; ++i) r[i] ^= 0x80000000;

  for (i = 0; i < W; ++i) r[i] &= -2;
  for (i = W; i < P; ++i) r[i] = (r[i] & -3) | 1;
  int32_sort(r, P);
  
  for (i = 0; i < P; ++i) f[i] = ((small) (r[i] & 3)) - 1;
}

void small_random_weightw(small *f)
{
  unsigned char k[32];
  randombytes(k,32);
  small_seeded_weightw(f,k);
}
