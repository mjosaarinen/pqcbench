/* See https://ntruprime.cr.yp.to/software.html for detailed documentation. */

#include "params.h"
#include "mod3.h"
#include "r3.h"

void r3_mult(small *h,const small *f,const small *g)
{
  small fg[P + P - 1];
  small result;
  int i, j;

  for (i = 0;i < P;++i) {
    result = 0;
    for (j = 0;j <= i;++j)
      result = mod3_plusproduct(result,f[j],g[i - j]);
    fg[i] = result;
  }
  for (i = P;i < P + P - 1;++i) {
    result = 0;
    for (j = i - P + 1;j < P;++j)
      result = mod3_plusproduct(result,f[j],g[i - j]);
    fg[i] = result;
  }

  for (i = P + P - 2;i >= P;--i) {
    fg[i - P] = mod3_sum(fg[i - P],fg[i]);
    fg[i - P + 1] = mod3_sum(fg[i - P + 1],fg[i]);
  }

  for (i = 0;i < P;++i)
    h[i] = fg[i];
}
