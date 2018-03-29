#include "api.h"

#include <NTL/ZZ.h>
#include <NTL/RR.h>
#include <NTL/ZZ_p.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/ZZ_pX.h>


#if N == 512
	const long CDT_length = 11;
	const unsigned long CDT[22] = {0, 4402564254475628998UL, 11764982215938697676UL, 16069007141612633800UL, 17828139942285597337UL, 18330820414912403750UL, 18431248444640379412UL, 18445276175012283164UL, 18446646076749434596UL, 18446739608909152776UL, 0, 0, 14371828625661980934UL, 4718557133137876784UL, 11277549837058342664UL, 11589062832341743150UL, 11926477327048184144UL, 3913014129104688847UL, 2742149467003257727UL, 4527561242905591802UL, 14730590305512100561UL, 0};
	const long CDT_inv_min[256] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 5};
	const long CDT_inv_max[256] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 6};
#else
	const long CDT_length = 7;
	const unsigned long CDT[14] = {0, 7094901854892740860UL, 16010399019983881949UL, 18221726696665494136UL, 18438247182874980419UL, 18446616369313222554UL, 0, 0, 1132165336062584669UL, 8115838531820800606UL, 8387848400301917718UL, 11300671729619518355UL, 17590659254897005002UL, 0};
	const long CDT_inv_min[256] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3};
	const long CDT_inv_max[256] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4};
#endif


static unsigned char filter[8] = {1, 2, 4, 8, 16, 32, 64, 128};
static int bias[17] = {0, 445, 888, 1333, 1776, 2221, 2666, 3109, 3554, 3997, 4442, 4885, 5330, 5775, 6218, 6663, 7106};
unsigned long step = sizeof(unsigned long)*8;


int randombytes(unsigned char *x, unsigned long long xlen);



// Input: ZZ type variable
// Output: Length of the variable
long EstimateLen(NTL::ZZ &a)
{
	long m=NumBits(a);
	long l=m/4;
	
	if(m%4!=0)
	l++;
	return l;
}



// Input: ZZ type variable and length
// Output: unsigned char array representation
long ZZToHex(unsigned char *a, const NTL::ZZ &b, long ll, long n)
{
	long index=0;
	if(b==0)
		a[index++]='0';
	else
	{
		NTL::ZZ tb;
		if(b<0)
		{
			a[index++]='-';
			tb=-b;
		}
		else
			tb=b;

		NTL::ZZ filter, t;

		filter=15;
		long l=EstimateLen(tb);
		if(n>0 && n<l) 
		{
			tb=tb >> (4*(l-n));
			l=n;
		}
		else
			if(n<0 && -n<l)
				l=-n;

		long i=0;

		for(;i < ll-l;i++)
			a[i]=(unsigned char)('0');
			
		for(;i<ll;i++)
		{
			t=filter << (4*(ll-i-1));
			t=(tb & t) >> (4*(ll-i-1));
			long tt=to_int(t);
			if(tt<10)
				a[i]=(unsigned char)('0'+tt);
			else
				a[i]=(unsigned char)('A'+tt-10);
		}
		a[i] = '\0';
		index=i;
	}
	return index;
}



// Input: ZZ_p type variable and length
// Output: unsigned char array representation
long ZZpToChar(unsigned char *a, const NTL::ZZ_p &b, long ll, long n)
{
	NTL::ZZ t;
	conv(t, b);
	return ZZToHex(a, t, ll, n);
}



// Input: unsigned char array in hexadecimal
// Output: ZZ type representation
long HexToZZ(NTL::ZZ &a, const unsigned char *b, long n)
{
	long i=0;
	a=0;
	long temp=0;
	if(b[0]=='-')
		i=1;

	while(i<n)
	{
		long t;
		if(b[i]>='0' && b[i]<='9')
			t=b[i]-'0';
		else
			if(b[i]>='A' && b[i]<='F')
				t=b[i]-'A'+10;
			else 
				if(b[i]>='a' && b[i]<='f')
					t=b[i]-'a'+10;
			else
				break;

		a=(a<<4)+t;
		i++;
	}
	if(a!=0 && b[0]=='-')
		a=-a;
	return i;
}



// Input: unsigned char array
// Output: ZZ_p type representation
long CharToZZp(NTL::ZZ_p &a, const unsigned char *b)
{
	long m;
	NTL::ZZ t;
	long n=strlen((char*)b);
	m=HexToZZ(t, b, n);
	conv(a, t);
	return m;
}



// Input: number needs rounding
// Output: rounded number
void Round(unsigned long &ret, unsigned long num)
{
	int rounded = floor(num*round_p*1.0/modulus_q);

	if((num % 2 == 1) && (rounded % 2 == 0))
		rounded++;
	else if((num % 2 == 0) && (rounded % 2 == 1))
		rounded++;

	// Remove Bias
	int pos = -1;

	for(int i = 0; i < 17; i++)
	{
		if(rounded == bias[i])
		{
			pos = i;
			break;
		}
	}

	if(pos != -1)
	{
		long flag = NTL::RandomBnd(2);
		if(flag % 2 == 1)
			rounded += 2;
	}
	ret = rounded;
}



// Input: number needs recovering
// Output: recovered number
void Recover(unsigned long &ret, unsigned long num)
{
	int recover = floor(modulus_q*1.0*num/round_p);

	if((num % 2 == 1) && (recover % 2 == 0))
		recover++;
	else if ((num % 2 == 0) && (recover % 2 == 1))
		recover++;
		
	ret = recover;
}



// Input: Variables needed to be converted to unsigned char array and parameters
// Output: Converted variables
void round2uchar(long n, NTL::vec_ZZ_p &pk_ZZp, NTL::vec_ZZ_p &pk_rounded, int l_p, unsigned char *pk, unsigned char *attach, int flag)
{
	int pos_pk_str = 0;

	unsigned char *pk_temp = (unsigned char*)malloc(sizeof(unsigned char) * CRYPTO_PUBLICKEYBYTES);
	unsigned char p[l_p];

	for(int i = 0; i < n; i++)
 	{
		// Round as+2e
		unsigned long val = 0, rounded = 0;
		conv(val, pk_ZZp[i]);
		Round(rounded, val);
		conv(pk_rounded[i], rounded);

		memset(p, 0, l_p);
		ZZpToChar(p, pk_rounded[i], l_p, 0);

		// Packing rounded public key to unsigned char*
		unsigned char p0[3], p1[3];
		memset(p0, 0, 3);
		memset(p1, 0, 3);
		memcpy(p0, p, 2);
		memcpy(p1, p+2, 2);
		const char *p0_const = (char*)p0;
		const char *p1_const = (char*)p1;

		unsigned char b0 = (unsigned char)strtol(p0_const, NULL, 16);
		unsigned char b1 = (unsigned char)strtol(p1_const, NULL, 16);


		pk_temp[pos_pk_str] = b0;
		pos_pk_str++;
		pk_temp[pos_pk_str] = b1;
		pos_pk_str++;
 	}
 
	memcpy(pk, pk_temp, pos_pk_str);

	if(flag == 1)
		memcpy(pk + pos_pk_str, attach, SEED_BYTES);
	
	delete [] pk_temp;
}



// Input: Private key needed to be converted to unsigned char array and parameters
// Output: Converted private key
void save2uchar(long n, NTL::vec_ZZ_p &sk_ZZp, int l_q, unsigned char *sk)
{
	int pos_str = 0;
	
	unsigned char *sk_temp = (unsigned char*)malloc(sizeof(unsigned char) * CRYPTO_SECRETKEYBYTES);
	unsigned char p[l_q+1];
	
	// Pack private key to unsigned char*
	for(int i = 0; i < n; i++)
 	{
		unsigned long val = 0, rounded = 0;
		conv(val, sk_ZZp[i]);

		memset(p, 0, l_q+1);
		ZZpToChar(p, sk_ZZp[i], l_q+1, 0);

		unsigned char p0[3], p1[3], p2[3];
		memset(p0, 0, 3);
		memset(p1, 0, 3);
		memset(p2, 0, 3);
		memcpy(p0, p, 2);
		memcpy(p1, p+2, 2);
		memcpy(p2, p+4, 2);
		const char *p0_const = (char*)p0;
		const char *p1_const = (char*)p1;
		const char *p2_const = (char*)p2;

		unsigned char b0 = (unsigned char)strtol(p0_const, NULL, 16);
		unsigned char b1 = (unsigned char)strtol(p1_const, NULL, 16);
		unsigned char b2 = (unsigned char)strtol(p2_const, NULL, 16);

		sk_temp[pos_str] = b0;
		pos_str++;
		sk_temp[pos_str] = b1;
		pos_str++;
		sk_temp[pos_str] = b2;
		pos_str++;
 	}

 	memcpy(sk, sk_temp, pos_str);
	delete [] sk_temp;
}



// Input: unsigned char array and parameters
// Output: ZZ_p type variables
void uchar2ZZp(const unsigned char *uchar, NTL::vec_ZZ_p &ret, int l, int i_start, int i_end)
{
	unsigned char temp[l];
	int b_val;
	char conv_to_hex[3];
	memset(conv_to_hex, 0, 3);
	int nBytes = l/2;
	for(int i=i_start; i<i_end; i+=nBytes)
	{
		memset(temp, 0, l);
		for(int j=0; j<nBytes; j++)
		{
			b_val = (int)uchar[i+j];
			sprintf(conv_to_hex, "%.2X", b_val);
			memcpy(temp+2*j, conv_to_hex, 2);
		}
		CharToZZp(ret[i/nBytes], temp);
	}
}




// Input: sigma and flag
// Output: sampled values
void Sample(NTL::vec_ZZ_p &ret, NTL::RR sigma, int flag)
{
	/*
		CDT Computation.
		In our implementation, we precompute and fix such values according to our parameters.
		One can verify the values using following code:


		long CDT_length;
		unsigned long* CDT;
		long CDT_inv_min[256];
		long CDT_inv_max[256];
		long tau=6;


		NTL::RR f, ff;

		mul(f, sigma, sigma);
		f = 2.0*f;

		conv(CDT_length, tau * sigma + 1.0);
		CDT = new unsigned long[CDT_length *2];


		// Compute CDT
		NTL::RR t, z;
		t=0;
		for(long i=1; i<CDT_length; i++)
		{
			conv(z, i-1);
			mul(z, z, -z);
			div(z, z, f);
			exp(z, z);
			if(i==1)
				z/=2.0;
			add(t, t, z);
		}

		NTL::RR y, tt;

		power2(tt, step);
		y=0;

		NTL::ZZ temp;

		for(long i=1; i<CDT_length; i++)
		{
			conv(z, i-1);
			mul(z, z, -z);
			div(z, z, f);
			exp(z, z);
			if(i==1)
				z/=2.0;

			div(z, z, t);
			add(y, y, z);

			z = y;

			for(long j=0; j<2; j++) 
			{
				mul(z, z, tt);
				FloorToZZ(temp, z);
				conv(CDT[i+j*CDT_length], z);
				sub(z, z, CDT[i+j*CDT_length]);
			}
		}

		for(long j=0; j<2; j++)
			CDT[j*CDT_length] = 0;


		long min=0, max = 0;
		unsigned long val;
		unsigned long mask = 0xFF << (step-8);


		for(long i=0;i<256;i++)
		{
			val = ((unsigned long) i) << (step-8);

			while(CDT[min+1]<val)
				min++;

			while((max+1 < CDT_length) && ((CDT[max] & mask) <= val))
				max++;

			CDT_inv_min[i]=min;
			CDT_inv_max[i]=max;
		}
	*/


	// Sampling
	// flag = 1, return 1 time of sampled value; flag = 2, return 2 times of sampled value
	for(int zz = 0; zz < N; zz++)
	{
		long r0, min, max;
		unsigned char ch;

		r0 = NTL::RandomBits_ulong(8);

		min = CDT_inv_min[r0];
		max = CDT_inv_max[r0];

		if (max-min < 2)
		{
			long val = (NTL::RandomBits_ulong(1)) ? min : -min;
			conv(ret[zz], flag*val);
			continue;
		}

		unsigned long r1;
		unsigned long cur;
		unsigned long mask_index;
		unsigned long r2;


		mask_index = step - 8;
		r1 = ((unsigned long) r0) << mask_index;
		r2 = (0xFF << mask_index);
		cur = (min+max)/2;

		while(true)
		{
			if(r1 > CDT[cur])
				min = cur;
			else if(r1 < (CDT[cur] & r2))
				max = cur;
			else
			{
				if(!mask_index)
					break;
				mask_index-= 8;

				r2 |= 0xFF << mask_index;
				r1 |= NTL::RandomBits_ulong(8) << mask_index;
			}
			if(max-min < 2)
			{
				long val = (NTL::RandomBits_ulong(1)) ? min : -min;
				conv(ret[zz], flag*val);
				continue;
			}
			cur = (min+max)/2;
		}

		r2 = NTL::RandomBits_ulong(step);
		while(true)
		{
			if (r1 < CDT[cur] || ((r1 == CDT[cur]) && (r2 < CDT[cur+CDT_length])))
				max = cur;
			else
				max = cur;
			cur = (min+max)/2;
			if(max-min < 2)
			{
				long val = (NTL::RandomBits_ulong(1)) ? min : -min;
				conv(ret[zz], val);
				continue;
			}
		}
	}
}



// NIST's API
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
 	NTL::ZZ_p::init(NTL::to_ZZ(modulus_q));
	int i;
	long n = N;

	
	// Generate 128-bit seed
	unsigned char seed_nist[SEED_BYTES];
	memset(seed_nist, 0, SEED_BYTES);
	randombytes(seed_nist, SEED_BYTES);
	
	unsigned char seed_exg[SEED_BYTES];
	memset(seed_exg, 0, SEED_BYTES);
	memcpy(seed_exg, seed_nist, SEED_BYTES);
	
	unsigned char t;
	for(i=0;i<SEED_BYTES/2;i++)
	{
		t = seed_exg[i];
		seed_exg[i] = seed_exg[SEED_BYTES-1-i];
		seed_exg[SEED_BYTES-1-i] = t;
	}
	

	NTL::ZZ seed;
	ZZFromBytes(seed, seed_exg, SEED_BYTES);
	SetSeed(seed);
	
	// Generate a using seed
	NTL::ZZ_pX a_px;
	random(a_px, n);

	NTL::RR sigma;
	NTL::vec_ZZ_p s_ZZp(NTL::INIT_SIZE, n), e_ZZp(NTL::INIT_SIZE, n);
	
	if(n == 512)
		sigma = NTL::to_RR(sigma_se_512);
	else if(n == 1024)
		sigma = NTL::to_RR(sigma_se_1024);
	else
	{
		std::cout << "Error. Please check the dimension n." << std::endl;
		exit (0);
	}
		

	// Sample s, e
	NTL::div(sigma, sigma, sqrt(2*PI));	// sigma /= sqrt(2*pi)

	Sample(s_ZZp, sigma, 1);
	Sample(e_ZZp, sigma, 2);


	// Compute as+2e
	NTL::ZZ_pX s_px, temp_px;
	s_px = to_ZZ_pX(s_ZZp);


	NTL::ZZ_pX u;
	u.SetMaxLength(N);
	SetCoeff(u, 0, 1);
	SetCoeff(u, N, 1);
	NTL::ZZ_pXModulus F(u);

	NTL::MulMod(temp_px, a_px, s_px, F);
		
	NTL::vec_ZZ_p pk_ZZp(NTL::INIT_SIZE, n);
	conv(pk_ZZp, VectorCopy(temp_px, n));
	add(pk_ZZp, pk_ZZp, e_ZZp);

	
	// Round Ipk
	NTL::vec_ZZ_p Ipk_rounded(NTL::INIT_SIZE, n);
	long l_p = 4, l_q = 5;


	round2uchar(n, pk_ZZp, Ipk_rounded, l_p, pk, seed_nist, 1);
	save2uchar(n, s_ZZp, l_q, sk);

	return 0;
}



// NIST's API
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{
	NTL::ZZ_p::init(NTL::to_ZZ(modulus_q));
		
	long n = N;	
	int i;
	NTL::ZZ ta;
	NTL::vec_ZZ_p key;
	NTL::vec_ZZ_p Ipk_rounded(NTL::INIT_SIZE, n);
	
	// Unpack public key
	uchar2ZZp(pk, Ipk_rounded, 4, 0, 2*n);	
	
	unsigned char seed_exg[SEED_BYTES];
	memcpy(seed_exg, pk+2*N, SEED_BYTES);

	unsigned char t;
	for(i=0;i<SEED_BYTES/2;i++){
		t = seed_exg[i];
		seed_exg[i] = seed_exg[SEED_BYTES-1-i];
		seed_exg[SEED_BYTES-1-i] = t;
	}
	
	NTL::ZZ seed;
	ZZFromBytes(seed, seed_exg, SEED_BYTES);
	SetSeed(seed);

	// Generate a using seed
	NTL::ZZ_pX a_px;
	random(a_px, n);

	NTL::RR sigma;
	NTL::vec_ZZ_p s_ZZp(NTL::INIT_SIZE, n), e_ZZp(NTL::INIT_SIZE, n);
	
	if(n == 512)
		sigma = NTL::to_RR(sigma_se_512);
	else if(n == 1024)
		sigma = NTL::to_RR(sigma_se_1024);
	else
	{
		std::cout << "Error. Please check the dimension n." << std::endl;
		exit (0);
	}


	// Sample s, e
	div(sigma, sigma, sqrt(2*PI));	// sigma /= sqrt(2*pi)

	NTL::SetSeed(seed+1);
	Sample(s_ZZp, sigma, 1);
	Sample(e_ZZp, sigma, 2);


	// Compute as+2e
	NTL::ZZ_pX s_px, temp_px;
	s_px = to_ZZ_pX(s_ZZp);

	NTL::ZZ_pX u;
	u.SetMaxLength(N);
	SetCoeff(u, 0, 1);
	SetCoeff(u, N, 1);
	NTL::ZZ_pXModulus F(u);

	MulMod(temp_px, a_px, s_px, F);


	NTL::vec_ZZ_p pk_ZZp(NTL::INIT_SIZE, n);

	conv(pk_ZZp, VectorCopy(temp_px, n));
	add(pk_ZZp, pk_ZZp, e_ZZp);
		

	// Round Rpk
	NTL::vec_ZZ_p Rpk_rounded(NTL::INIT_SIZE, n);
	long l_p = 4, l_q = 5, k;


	unsigned char null_char[0];
	round2uchar(n, pk_ZZp, Rpk_rounded, l_p, ct, null_char, 0);
	

	// Recover Ipk_rounded
	NTL::vec_ZZ_p Ipk_recovered(NTL::INIT_SIZE, n);
	for(int i = 0; i < n; i++)
	{
		unsigned long val = 0, recovered = 0;
		conv(val, Ipk_rounded[i]);
		Recover(recovered, val);
		conv(Ipk_recovered[i], recovered);
	}


	NTL::ZZ_pX I_px;
	I_px = to_ZZ_pX(Ipk_recovered);

	MulMod(I_px, I_px, s_px, F);
	conv(key, VectorCopy(I_px, n));


	// Error reconciliation
	NTL::ZZ hq = (NTL::ZZ_p::modulus()>>1);

	long flag = IsOdd(hq);

	long lb = 0, ub = 0;
	lb = modulus_q/4;
	ub = modulus_q*3/4;


	k = n>>3;
	unsigned char *signal = new unsigned char[k];
	unsigned char *sk_j = new unsigned char[k];
	
	memset(signal, 0, k);
	memset(sk_j, 0, k);
	
	
	for(long i = 0;i < k;i++)
	{
		for(long j = 0;j < 8;j++)
		{
			ta = rep(key[i*8+j]);
			long lb1 = lb, ub1 = ub;
			long flag1 = NTL::RandomBnd(2);
			if(flag1 % 2 == 1)
			{
				lb1++;
				ub1++;
			}


			if(ta < lb1)
			{
				signal[i]|=filter[j];
				if(IsOdd(ta)^flag)
					sk_j[i]|=filter[j];
			}
			else if(ta > ub1)
			{
				signal[i]|=filter[j];
				if(!(IsOdd(ta)^flag))
					sk_j[i]|=filter[j];
			}
			else if(IsOdd(ta))
				sk_j[i]|=filter[j];
		}
	}

	memcpy(ss, sk_j, n/8);	
	memcpy(ct+2*n, signal, n/8);

	delete [] sk_j;
 
	return 0;
}



// NIST's API
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
	NTL::ZZ_p::init(NTL::to_ZZ(modulus_q));
	 			
	NTL::ZZ ta;
	NTL::vec_ZZ_p key;
	long n = N;
	NTL::vec_ZZ_p Rpk_rounded(NTL::INIT_SIZE, n);
	int i;
	

	uchar2ZZp(ct, Rpk_rounded, 4, 0, 2*n);	


 	long k = n>>3;
	unsigned char *signal = new unsigned char[k];
	memcpy(signal, ct+2*n, k);

	NTL::vec_ZZ_p s(NTL::INIT_SIZE, n);
	uchar2ZZp(sk, s, 6, 0, 3*n);

	
	// Recover Rpk_rounded
	NTL::vec_ZZ_p Rpk_recovered(NTL::INIT_SIZE, n);
	for(i = 0; i < n; i++)
	{
		unsigned long val = 0, recovered = 0;
		conv(val, Rpk_rounded[i]);
		Recover(recovered, val);
		conv(Rpk_recovered[i], recovered);
	}


	NTL::ZZ_pX R_px, s_px;
	R_px = to_ZZ_pX(Rpk_recovered);
	s_px = to_ZZ_pX(s);
	
	NTL::ZZ_pX u;
	u.SetMaxLength(N);
	SetCoeff(u, 0, 1);
	SetCoeff(u, N, 1);
	NTL::ZZ_pXModulus F(u);

	MulMod(R_px, R_px, s_px, F);
	conv(key, VectorCopy(R_px, n));



	// Error reconciliation
	NTL::ZZ hq= (NTL::ZZ_p::modulus()>>1);

	long flag = IsOdd(hq);
	k = n >> 3;
	unsigned char *sk_i = new unsigned char[k];
	memset(sk_i, 0, k);

	for(long i=0;i<k;i++)
	{
		for(long j=0;j<8;j++)
		{
			ta = rep(key[i*8+j]);
			if(signal[i] & filter[j])
			{
				if(ta>hq)
				{
					if(!(IsOdd(ta)^flag))
						sk_i[i] |= filter[j];
				}
				else if(IsOdd(ta)^flag)
					sk_i[i] |= filter[j];
			}
			else if(IsOdd(ta))
				sk_i[i] |= filter[j];
		}
	}
	
	memcpy(ss, sk_i, n/8);
	delete [] sk_i;

	return 0;
}
