/* See https://ntruprime.cr.yp.to/software.html for detailed documentation. */

#ifdef KAT
#include <stdio.h>
#endif

#include <string.h>
#include "params.h"
#include "small.h"
#include "rq.h"
//#include "crypto_hash_sha512.h"
#include "crypto_kem.h"

#include <openssl/sha.h>

int crypto_kem_enc(
  unsigned char *cstr,
  unsigned char *k,
  const unsigned char *pk
)
{
  small r[P];
  modq h[P];
  modq c[P];
  unsigned char rstr[small_encode_len];
  unsigned char hash[64];

  small_random_weightw(r);

#ifdef KAT
  {
    int i;
    printf("encrypt r:");
    for (i = 0;i < p;++i)
      if (r[i] == 1) printf(" +%d",i);
      else if (r[i] == -1) printf(" -%d",i);
    printf("\n");
  }
#endif

  small_encode(rstr,r);
// crypto_hash_sha512(hash,rstr,sizeof rstr);
  SHA512(rstr, sizeof(rstr), hash);

  rq_decode(h,pk);
  rq_mult(c,h,r);
  rq_round3(c,c);

  memcpy(k,hash + 32,32);
  memcpy(cstr,hash,32);
  rq_encoderounded(cstr + 32,c);

  return 0;
}
