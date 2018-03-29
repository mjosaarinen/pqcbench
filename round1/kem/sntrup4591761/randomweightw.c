/* See https://ntruprime.cr.yp.to/software.html for detailed documentation. */

#include "params.h"
#include "randombytes.h"
#include "int32_sort.h"
#include "small.h"

void small_random_weightw(small *f)
{
  crypto_int32 r[P];
  int i;

  for (i = 0;i < P;++i) r[i] = small_random32();
  for (i = 0;i < W;++i) r[i] &= -2;
  for (i = W;i < P;++i) r[i] = (r[i] & -3) | 1;
  int32_sort(r, P);
  for (i = 0;i < P;++i) f[i] = ((small) (r[i] & 3)) - 1;
}
