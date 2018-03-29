
#include "sec.h"

// It computes H * x^T.
// For the full detail, see Section 8.3.1 in the document. 
uint8_t parity(uint16_t x)
{
    uint16_t c , p;
    c = (x >> 4) ^ x;
    c = (c >> 2) ^ c;
    p = ((c >> 1) ^ c) & 1;
    x = (x >> 8) ^ x;
    c = (x >> 2) ^ x;
    p = (((c >> 1) ^ c) & 1) | (p << 1);
    x = (x >> 4) ^ x;
    p = ((( x >> 1) ^ x ) & 1) | (p << 1);
    x = (x >> 2) ^ x;
    p = (x & 1) | (p << 1);
    p = ((x ^ (x>>1)) & 1) | (p << 1);
    return (p>>1);
}


// It computes Encode(x); 
// Note: the MSB of x is always 0
// For the full detail, see Algorithm 14 in the document
uint32_t SEC_encode(uint16_t x)
{
	x = 0x7FFF & x;
	
	uint32_t c;
	unsigned int i;
	uint16_t temp = x;
	uint8_t p = parity(x);
	
	for(i=c=0;i<15; i++)
	{
		c = c ^ (temp & 0x1);
		temp = temp>>1;
	}
	c = (c<<15) ^ x;
	c = (c<<4) ^ (p&0xF);
	
	return (c & 0xFFFFF);
}

// It computes Decode(c)
// For the full detail, see Algorithm 15 in the document. 
uint16_t SEC_decode(uint32_t c)
{	
	uint32_t temp;
	
	uint8_t b;
	uint16_t x = (c>>4) & 0x7FFF;
	
	unsigned int i;
	
	for(i=b=0, temp=(c>>4) ; i<16; i++, temp >>= 1)
		b ^= (temp&0x1);
	
	if(b == 0) return x;
	
	uint8_t p = c & (0xF);
	p = (~p) & 0xF;
	
	uint8_t q = parity(x);
	q = (~q) & 0xF;
	i = p^q;
	x = x ^ (1<<(15-i));
	
	return (x & 0x7FFF);
}

