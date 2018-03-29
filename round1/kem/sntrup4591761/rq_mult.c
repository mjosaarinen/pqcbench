/* See https://ntruprime.cr.yp.to/software.html for detailed documentation. */

#include "params.h"
#include "rq.h"

void rq_mult(modq *h,const modq *f,const small *g)
{
  modq fg[P + P - 1];
  modq result;
  int i, j;

  for (i = 0; i < P; ++i) {
    result = 0;
    for (j = 0;j <= i;++j)
      result = modq_plusproduct(result,f[j],g[i - j]);
    fg[i] = result;
  }
  for (i = P;i < P + P - 1;++i) {
    result = 0;
    for (j = i - P + 1;j < P;++j)
      result = modq_plusproduct(result,f[j],g[i - j]);
    fg[i] = result;
  }

  for (i = P + P - 2;i >= P;--i) {
    fg[i - P] = modq_sum(fg[i - P],fg[i]);
    fg[i - P + 1] = modq_sum(fg[i - P + 1],fg[i]);
  }

  for (i = 0;i < P;++i)
    h[i] = fg[i];
}
