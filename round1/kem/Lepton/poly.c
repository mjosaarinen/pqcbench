#include <stdio.h>
#include "poly.h"
#include "fips202.h"

void poly_from_bytes(poly r, const uint8_t *cr)
{
	int i=0,j=0,k=(POLY_BYTES>>2);
	
	for(i=0;i<k;i++)
	{
		r[i] = (((uint32_t)cr[j])<<24) | (((uint32_t)cr[j+1])<<16)| (((uint32_t)cr[j+2])<<8)|((uint32_t)cr[j+3]);
		j += 4;
	}
	
	i = POLY_BYTES & 0x3;
	if(i!=0)
	{
	     r[POLY_WORDS-1] = 0; 
		for(k=0;k<i;k++)
			r[POLY_WORDS-1] |= ((uint32_t)cr[j++])<<((3-k)*8);
	}
}
void poly_to_bytes(uint8_t *cr, const poly r)
{
	int i=0,j=0,k=(POLY_BYTES>>2);
	for(i=0;i<k;i++)
	{
		cr[j++] = (r[i]>>24) & 0xff;
		cr[j++] = (r[i]>>16) & 0xff;
		cr[j++] = (r[i]>>8) & 0xff;
		cr[j++] = r[i] & 0xff;
	}
	i = POLY_BYTES & 0x3;
	if(i!=0)
	{
		for(k=0;k<i;k++)
			cr[j++] = (r[POLY_WORDS-1]>>((3-k)*8)) & 0xff;
	}
}
/*
Function: Sample_\chi^n algorithm
Inputs  : a random seed, and a nonce 
Outputs : r = Sample_chi(seed||nonce)
*/
int poly_getnoise(poly_noise r,const unsigned char *seed, uint16_t nonce)
{
	unsigned char flag[PARAM_N]={0};
	uint16_t buf[PARAM_3K];
	uint16_t next=0;
	int i=0,j=0;

	uint16_t modN = (1<<PARAM_LOGN) - 1;
	cshake128_simple((uint8_t*)buf,2*PARAM_3K,nonce,seed,SEED_BYTES);
	while(i<PARAM_K && j<PARAM_3K)
	{
		next = buf[j++] & modN;
		if(next >= PARAM_N || flag[next]==1)
			continue;
		flag[next]=1;
		r[i++] = next;
	}
	if(j>=PARAM_3K)
	{
		return -1;
		printf("error happens in generating noises!\n");
	}
	return 0;
}

/*
Function: Sampling random polynomial
Inputs  : a random seed, and a nonce
Outputs : r = Samp(seed||nonce)
*/
void poly_getrandom(poly r,const unsigned char *seed, uint16_t nonce)
{
	cshake128_simple((uint8_t*)r,4*POLY_WORDS,nonce,seed,SEED_BYTES);
	int leftbits = PARAM_N & 0x1f;
	if(leftbits)
		r[POLY_WORDS-1] &= LEFT_ONE(leftbits);
}

/*
Function: multiply a polynomial with a noise polynomial
Inputs  : a polynomial a, and a noise polynomial s
Outputs : r = a * s
*/
/*Attention: only works when 2*PARAM_M < 64 << PARAM_N, and t%32 != 0
both conditions always hold for our setting */
void poly_mul(poly r, const poly a, const poly_noise s)
{
	int j=0,k=0,t=PARAM_N & 0x1f,rt=32-t;
	int p1=0,p2=0,p3=0;

	uint32_t b[POLY2_WORDS]={0},c[POLY_WORDS]={0};

	for(k=0;k<PARAM_K;k++)//multiplication over F_2[X]
	{
		p1 = s[k]>>5;
		p2 = s[k]&0x1f;

		if(p2!=0)
		{
			p3 = 32-p2;

			b[p1] ^= (a[0]>>p2);
			for(j=1;j<POLY_WORDS;j++)
				b[p1+j] ^= ((a[j-1]<<p3) | (a[j]>>p2));
			b[POLY_WORDS + p1] ^= (a[j-1]<<p3);
		}
		else
		{
			b[p1] ^= a[0];
			for(j=1;j<POLY_WORDS;j++)
				b[p1+j] ^= a[j];
		}
	}
	//modulo the irreducible polynomial g = X^n + X^m +1
	// the following assuming 0<2*PARAM_M < 64 << PARAM_N  and and t%32 != 0
	p2 = PARAM_M;
	p3 = 32 - p2;

	for(j=0;j<POLY_WORDS;j++)
	{
		c[j] = (b[POLY_WORDS+ j -1]<< t) | (b[POLY_WORDS+j]>>rt);
		r[j] = b[j] ^ c[j];
	}

	b[0] = (c[0]>>p2);
	for(j=1;j<POLY_WORDS;j++)
		b[j] = (c[j-1]<<p3) | (c[j]>>p2);
	b[j] = (c[j-1]<<p3);

	for(j=0;j<POLY_WORDS;j++)
		r[j] ^= b[j];

	c[0] = (b[POLY_WORDS-1]<< t) | (b[POLY_WORDS]>>rt);
	c[1] = (b[POLY_WORDS]<< t);
	r[0] ^= c[0];
	r[1] ^= c[1];

	r[0] ^= (c[0]>>p2);
	r[1] ^= ((c[0]<<p3) | (c[1]>>p2));
	r[2] ^= (c[1]<<p3);

	r[POLY_WORDS-1] &= LEFT_ONE(t);
}

/*
Function: add two polynomials
Inputs  : two polynomials a and b
Outputs : r = a+b
*/
void poly_add(poly r, const poly a, const poly b)
{
	int i;
	for(i=0;i<POLY_WORDS;i++)
		r[i] = a[i]^b[i];
}

/*
Function: add a polynomial with a noise polynomial
Inputs  : a polynomial a, and a noise polynomial b
Outputs : r = a+b
*/
void poly_addnoise(poly r, const poly a, const poly_noise e)
{
	int i;
	int p1,p2;

	memcpy(r,a,4*POLY_WORDS);
	for(i=0;i<PARAM_K;i++)
	{
		p1=e[i]>>5;
		p2=e[i]&0x1f;

		r[p1]^=(1<<(31-p2));
	}
}
