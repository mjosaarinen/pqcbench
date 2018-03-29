/* See https://ntruprime.cr.yp.to/software.html for detailed documentation. */

//#include "crypto_stream_aes256ctr.h"
#include <string.h>
#include "rng.h"

#include "rq.h"
#include "params.h"

// static const unsigned char n[16] = {0};

void rq_fromseed(modq *h,const unsigned char *K)
{
  crypto_uint32 buf[P];
  int i;

//  crypto_stream_aes256ctr((unsigned char *) buf,sizeof buf,n,K);
  AES_XOF_struct ctx;
  seedexpander_init(&ctx, (unsigned char *) K, 
	(unsigned char *) "12345678", 0x7FFFFFFF);
  // make seedexpander work like the original function by zeroing countter
  memset(ctx.ctr, 0, 16);
  seedexpander(&ctx, (unsigned char *) buf, sizeof(buf));

  
  for (i = 0; i < P; ++i)
    h[i] = modq_fromuint32(buf[i]);
}
