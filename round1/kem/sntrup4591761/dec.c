/* See https://ntruprime.cr.yp.to/software.html for detailed documentation. */

#ifdef KAT
#include <stdio.h>
#endif

#include "params.h"
#include "small.h"
#include "mod3.h"
#include "rq.h"
#include "r3.h"
//#include "crypto_hash_sha512.h"
//#include "crypto_verify_32.h"
#include "crypto_kem.h"

#include <openssl/sha.h>

int crypto_kem_dec(
  unsigned char *k,
  const unsigned char *cstr,
  const unsigned char *sk
)
{
  small f[P];
  modq h[P];
  small grecip[P];
  modq c[P];
  modq t[P];
  small t3[P];
  small r[P];
  modq hr[P];
  unsigned char rstr[small_encode_len];
  unsigned char hash[64];
  int i;
  int result = 0;
  int weight;

  small_decode(f,sk);
  small_decode(grecip,sk + small_encode_len);
  rq_decode(h,sk + 2 * small_encode_len);

  rq_decoderounded(c,cstr + 32);

  rq_mult(t,c,f);
  for (i = 0;i < P;++i) t3[i] = mod3_freeze(modq_freeze(3*t[i]));

  r3_mult(r,t3,grecip);

#ifdef KAT
  {
    int j;
    printf("decrypt r:");
    for (j = 0;j < P;++j)
      if (r[j] == 1) printf(" +%d",j);
      else if (r[j] == -1) printf(" -%d",j);
    printf("\n");
  }
#endif

  weight = 0;
  for (i = 0;i < P;++i) weight += (1 & r[i]);
  weight -= W;

  result |= modq_nonzero_mask(weight); /* XXX: puts limit on p */

  rq_mult(hr,h,r);
  rq_round3(hr,hr);
  for (i = 0;i < P;++i) result |= modq_nonzero_mask(hr[i] - c[i]);

  small_encode(rstr,r);
//  crypto_hash_sha512(hash,rstr,sizeof rstr);
  SHA512(rstr, sizeof(rstr), hash);

//  result |= crypto_verify_32(hash,cstr);

  for (i = 0; i < 32; i++) {
  	result |= (hash[i] == cstr[i] ? 0 : -1);
  }

  for (i = 0;i < 32;++i) k[i] = (hash[32 + i] & ~result);
  return result;
}
