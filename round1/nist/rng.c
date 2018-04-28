//  rng.c
//  2018-04-28  Markku-Juhani O. Saarinen <mjos@iki.fi>
//              Simple AES-256 CTR Generator

#include <string.h>
#include <openssl/aes.h>

#include "rng.h"

// state for randombytes

static AES_XOF_struct rb_state;

/*
 seedexpander_init()
 ctx            - stores the current state of an instance of the seed expander
 seed           - a 32 byte random value
 diversifier    - an 8 byte diversifier
 maxlen         - maximum number of bytes (less than 2**32) generated under this seed and diversifier
 */
int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen)
{
    AES_set_encrypt_key(seed, 256, &ctx->key);

    memcpy(ctx->ctr, diversifier, 8);
    ctx->ctr[11] = maxlen & 0xFF;
    ctx->ctr[10] = (maxlen >> 8) & 0xFF;
    ctx->ctr[9] = (maxlen >> 16) & 0xFF;
    ctx->ctr[8] = (maxlen >> 24) & 0xFF;
    memset(ctx->ctr+12, 0x00, 4);

    ctx->ptr = 16;

    return RNG_SUCCESS;
}

/*
 seedexpander()
    ctx  - stores the current state of an instance of the seed expander
    x    - returns the XOF data
    xlen - number of bytes to return
 */
int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen)
{
    int j;
    size_t i;

    for (i = 0; i < xlen; i++) {
        if (ctx->ptr >= 16) {
            // increase counter
            for (j = 15; j >= 0; j--) {
                if (ctx->ctr[j] == 0xFF) {
                    ctx->ctr[j] = 0x00;
                } else {
                    ctx->ctr[j]++;
                    break;
                }
            }
            AES_encrypt(ctx->ctr, ctx->buf, &ctx->key);
            ctx->ptr = 0;
        }
        x[i] = ctx->buf[ctx->ptr++];
    }

    return RNG_SUCCESS;
}


void randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength)
{
    int i;
    unsigned char seed[48];

    memcpy(seed, entropy_input, 48);
    if (personalization_string != NULL) {
        for (int i=0; i < 48; i++) {
            seed[i] ^= personalization_string[i];
        }
    }
    seedexpander_init(&rb_state, seed, seed + 32, 0xFFFFFFFF);
}

int randombytes(unsigned char *x, unsigned long long xlen)
{
    return seedexpander(&rb_state, x, xlen);
}



