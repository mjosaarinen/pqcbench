/* ****************************** *
 * Titanium_CPA_toy               *
 * Implemented by Raymond K. ZHAO *
 *                                *
 * Packing/Unpacking              *
 * ****************************** */

#include "pack.h"
#include "param.h"
#include "littleendian.h"
#include <stdint.h>

#define Q_BITS_PACK 9 /* pack/unpack each 9 bytes */

/* convert a polynomial to a binary string */
void poly_encode(unsigned char *b, const uint32_t *p, uint32_t len)
{
	uint32_t i;
	unsigned char *bb;
	uint32_t pp[4];
	
	/* pack 4 18-bit coordinates to 9 bytes */
	for (i = 0; i < len; i += 4)
	{
		/* make sure each coordinate is smaller than Q */
		pp[0] = p[i] % Q;
		pp[1] = p[i + 1] % Q;
		pp[2] = p[i + 2] % Q;
		pp[3] = p[i + 3] % Q;
		
		bb = b + (i / 4) * Q_BITS_PACK;
		bb[0] = pp[0];
		bb[1] = pp[0] >> 8;
		bb[2] = (pp[0] >> 16) | ((pp[1] & 0x3f) << 2);
		bb[3] = pp[1] >> 6;
		bb[4] = (pp[1] >> 14) | ((pp[2] & 0x0f) << 4);
		bb[5] = pp[2] >> 4;
		bb[6] = (pp[2] >> 12) | ((pp[3] & 0x03) << 6);
		bb[7] = pp[3] >> 2;
		bb[8] = pp[3] >> 10;
	}
}

/* convert a binary string to a polynomial */
void poly_decode(uint32_t *p, const unsigned char *b, uint32_t len)
{
	uint32_t i;
	unsigned char *bb;
	
	/* unpack 9 bytes to 4 18-bit coordinates */
	for (i = 0; i < len; i += 4)
	{
		bb = b + (i / 4) * Q_BITS_PACK;

		p[i] = ((uint32_t)bb[0]) | (((uint32_t)bb[1]) << 8) | ((((uint32_t)bb[2]) & 0x03) << 16);
		p[i + 1] = (((uint32_t)bb[2]) >> 2) | (((uint32_t)bb[3]) << 6) | ((((uint32_t)bb[4]) & 0x0f) << 14);
		p[i + 2] = (((uint32_t)bb[4]) >> 4) | (((uint32_t)bb[5]) << 4) | ((((uint32_t)bb[6]) & 0x3f) << 12);
		p[i + 3] = (((uint32_t)bb[6]) >> 6) | (((uint32_t)bb[7]) << 2) | (((uint32_t)bb[8]) << 10);		
	}
}

/* convert a polynomial to a binary string (with compression) */
void poly_encode_c2(unsigned char *b, const uint32_t *p, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
	{
		/* each coordinate will become 1 bytes after compression */
		STORE_C2(b + i * C2_COMPRESSION_BYTE, (p[i] % Q) >> C2_COMPRESSION_BITS);
	}
}

/* convert a binary string to a polynomial (with compression) */
void poly_decode_c2(uint32_t *p, const unsigned char *b, uint32_t len)
{
	uint32_t i;
	
	for (i = 0; i < len; i++)
	{
		/* shift the compressed coordinates back */
		p[i] = ((uint32_t)(LOAD_C2(b + i * C2_COMPRESSION_BYTE))) << C2_COMPRESSION_BITS;
	}
}

