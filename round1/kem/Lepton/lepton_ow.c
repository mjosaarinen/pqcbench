#include "lepton_ow.h"
#include "bch_codec.h"
#include "fips202.h"
#include "precomp9-30-256.c.inc"
#include <stdio.h>

//define the inner type of public key
typedef struct {
	uint8_t seed[SEED_BYTES];
	poly b;
} pubkey;

//define the inner type of secret key
typedef struct {
	poly_noise s;
} seckey;

//define the inner type of ciphertext
typedef struct {
	poly u;
	uint32_t v[CT2_WORDS];
} cipher;

//transform a public key from the inner type to byte representation
static inline void pk_to_bytes(uint8_t *cpk, pubkey *pk)
{
	memcpy(cpk,pk->seed,SEED_BYTES);
	poly_to_bytes(&cpk[SEED_BYTES],pk->b);
}

//transform a public key from byte representation to the inner type
static inline void pk_from_bytes(pubkey *pk, const uint8_t *cpk)
{
	memcpy(pk->seed,cpk,SEED_BYTES);
	poly_from_bytes(pk->b,&cpk[SEED_BYTES]);	
}

//transform a secret key from the inner type to byte representation
static inline void sk_to_bytes(uint8_t * csk, seckey*sk)
{
	int i=0,j=0;
	for(i=0;i<PARAM_K;i++,j+=2)
	{
		csk[j] = (sk->s[i]>>8) & 0xff;
		csk[j+1] = sk->s[i] & 0xff;
	}
}

//transform a secret key from byte representation to the inner type
static inline void sk_from_bytes(seckey *sk,const uint8_t *csk)
{
	int i=0,j=0;
	for(i=0;i<PARAM_K;i++,j+=2)
		sk->s[i] = (((uint16_t)csk[j])<<8) | ((uint16_t)csk[j+1]);
}

//transform a ciphertext from the inner type to byte representation
static inline void cipher_to_bytes(uint8_t *cct, cipher *ct)
{
	int i = CT1_BYTES & 0x3,j=0,k=0;
	uint32_t v=0;
	
	poly_to_bytes(cct,ct->u);
	j = CT1_BYTES;
	
	k=(CT2_BYTES>>2);
	for(i=0;i<k;i++)
	{
		v = ct->v[i];
		cct[j++] = (v>>24) & 0xff;
		cct[j++] = (v>>16) & 0xff;
		cct[j++] = (v>>8) & 0xff;
		cct[j++] = v & 0xff;
	}
	i = CT2_BYTES & 0x3;
	if(i!=0)
	{
		v = ct->v[CT2_WORDS-1];
		for(k=0;k<i;k++)
			cct[j++] = (v>>((3-k)*8)) & 0xff;
	}
	i = CT2_BITS & 0x7;
	if(i!=0)
		cct[j-1] &= ((1<<i)-1)<<(8-i); //clearing the last unused bits
}

//transform a ciphertext from byte representation to the inner type
static inline void cipher_from_bytes(cipher*ct, const uint8_t *cct)
{
	int i = CT1_BYTES & 0x3,j=0,k=0;
	poly_from_bytes(ct->u,cct);
	j = CT1_BYTES;
	
	k=(CT2_BYTES>>2);
	
	for(i=0;i<k;i++)
	{
		ct->v[i] = (((uint32_t)cct[j])<<24) | (((uint32_t)cct[j+1])<<16)| (((uint32_t)cct[j+2])<<8)|((uint32_t)cct[j+3]);
		j += 4;
	}
	i = CT2_BYTES & 0x3;
	if(i!=0)
	{
		ct->v[CT2_WORDS-1] = 0;
		for(k=0;k<i;k++)
			ct->v[CT2_WORDS-1] |= ((uint32_t)cct[j++])<<((3-k)*8);
	}
}

/*
Function: encode algorithm of the repetition encode REP(*,*)
Inputs  : a message in and the bit length ilen of the input message
Outputs : a set out of repetition codewords
//attention: out should be initialized as zeros
*/
static inline void repeated_encode(uint32_t *out, uint8_t *in, int ilen)
{
    int nbytes = (ilen>>3);
    uint8_t filter[8]={0x80,0x40,0x20,0x10,0x8,0x4,0x2,0x1};
    int i,j,len;
    int p1=0,p2=0;
    for(i=0;i<nbytes;i++)
    {
        for(j=0;j<8;j++)
        {
            len = PARAM_RCN;
            if(in[i]&filter[j])
            {
                if(len<p2)
                {
                    p2 -= len;
                    out[p1] |= (RIGHT_ONE(len)<<p2);
                }
                else
                {
                    if(p2!=0)
                    {
                        out[p1++] |= (RIGHT_ONE(p2));
                        len -= p2;
                        p2 = 0;
                    }
                    if(len>0)
                    {
                        p2 = 32 - len;
                        out[p1] = (RIGHT_ONE(len) <<p2);
                    }
                }
            }
            else
            {
                if(len<p2)
                    p2 -= len;
                else
                {
                    if(p2!=0)
                    {
                        p1++;
                        len -= p2;
                        p2 = 0;
                    }
                    if(len>0)
                        p2 = 32 - len;
                }
            }
        }
    }
    
    for(j=0;j<(ilen & 7);j++)
    {
        len = PARAM_RCN;
        if(in[i]&filter[j])
        {
            if(len<p2)
            {
                p2 -= len;
                out[p1] |= (RIGHT_ONE(len)<<p2);
            }
            else
            {
                if(p2!=0)
                {
                    out[p1++] |= RIGHT_ONE(p2);
                    len -= p2;
                    p2 = 0;
                }
                if(len>0)
                {
                    p2 = 32-len;
                    out[p1] = (RIGHT_ONE(len)<<p2);
                }
            }
        }
        else
        {
            if(len<p2)
                p2 -= len;
            else
            {
                if(p2!=0)
                {
                    p1++;
                    len -= p2;
                    p2 = 0;
                }
                if(len>0)
                    p2 = 32 - len;
            }
        }
    }
}
/*
Function: decode a single noised repetition codeword
Inputs  : a single noised codeword v
Outputs : return a single bit decoded message
*/
static inline int rc_decode(uint32_t v)
{
    int c;
    //the following computing the number of 1's in the bit representations of v
    v = v - ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    c = (((v + (v >> 4)) & 0xf0f0f0f) * 0x1010101) >> 24;
    
    if(c>PARAM_RCT)//compare with the threshold PARAM_RCT
        return 1;
    else
        return 0;
}
/*
Function: decode algorithm of the repetition encode REP(*,*)
Inputs  : a message length olen, and a set of noised codewords
Outputs : a set of messages decoded from in
*/
static inline void repeated_decode(uint8_t *out, int olen, uint32_t *in)
{
    int nbytes = (olen>>3);
    uint32_t word;
    int p1=0,p2=0;
    int i,j,len;
    
    for(i=0;i<nbytes;i++)
    {
        out[i]=0;
        for(j=0;j<8;j++)
        {
            len = PARAM_RCN;
            word = 0;
            if(len<p2)
            {
                p2 -= len;
                word = (in[p1]>>p2)& RIGHT_ONE(len);
            }
            else
            {
                if(p2!=0)
                {
                    word = in[p1++] & RIGHT_ONE(p2);
                    len -= p2;
                    p2 = 0;
                }
                if(len>0)
                {
                    p2 = 32 -len;
                    word = (word<<len) | in[p1]>>p2;
                }
                
            }
            out[i] = (out[i]<<1) | rc_decode(word);
        }
    }
    j = olen&7;
    if(j!=0)
    {
        out[i]=0;
        while(j--)
        {
            len = PARAM_RCN;
            word = 0;
            if(len<p2)
            {
                p2 -= len;
                word = (in[p1]>>p2)& RIGHT_ONE(len);
            }
            else
            {
                if(p2!=0)
                {
                    word = in[p1++] & RIGHT_ONE(p2);
                    len -= p2;
                    p2 = 0;
                }
                if(len>0)
                {
                    p2 = 32-len;
                    word = (word<<len) | in[p1]>>p2;
                }
                
            }
            out[i] = (out[i]<<1) | rc_decode(word);
        }
        out[i]<<= (8-(olen&7));
    }
}

/*
Function: LPN core key generation with a given random seed
Inputs  : a random seed 
Outputs : a pair of public and secret keys (pk,sk)
*/
int lepton_ow_keygen_KAT(uint8_t *cpk, uint8_t *csk, const uint8_t *seed)
{	  
    poly_noise e;
    poly a;
    pubkey pk;
    seckey sk;
    
    uint8_t buf[2*SEED_BYTES];
    
    cshake128_simple(buf,2*SEED_BYTES,0,seed,SEED_BYTES); //(rho,sigma) = G(eta,2) 
    memcpy(pk.seed,&buf[SEED_BYTES],SEED_BYTES);
    poly_getrandom(a,pk.seed,0);//a = Samp(sigma)
    
    if(poly_getnoise(sk.s,buf,0)|| poly_getnoise(e,buf,1)) //(s,e) = F(rho,2)
    	return -1;//error happens
    
    //b = a*s + e
    poly_mul(pk.b,a,sk.s);
    poly_addnoise(pk.b,pk.b,e);
    
    pk_to_bytes(cpk,&pk);
    sk_to_bytes(csk,&sk);
    return 0;
}

/*
Function: LPN core encryption with a given random seed
Inputs  : a public key cpk, a message msg and a random seed
Outputs : a ciphertext cct
*/
int lepton_ow_enc_KAT(uint8_t *cct, const uint8_t *cpk, const uint8_t *msg, const uint8_t *seed)
{
    poly_noise x,e1,e2;
    poly a,t;
    pubkey pk;
    cipher ct;
    
    uint8_t becc[BCH_CODEBYTES]={0};
    uint32_t recc[CT2_WORDS]={0};
    int i;
    
    pk_from_bytes(&pk,cpk);
    poly_getrandom(a,pk.seed,0);// a = Samp(sigma)
    
    //(x,e1,e2) = F(seed,3)
    if(poly_getnoise(x,seed,0) || poly_getnoise(e1,seed,1) || poly_getnoise(e2,seed,2))
    	return -1;//error happens
    
    //u = a*x + e1
    poly_mul(ct.u,a,x);
    poly_addnoise(ct.u,ct.u,e1);
    
    //t = b*x + e2
    poly_mul(t,pk.b,x);
    poly_addnoise(t,t,e2);
    
    //computing ECC(msg) = REP(BCH(msg),PARAM_RCN)
    //bch encode
    encode_bch(&bch,msg,SEED_BYTES,&becc[SEED_BYTES]);
    
    memcpy(becc,msg,SEED_BYTES);
    
    //repetition encode
    repeated_encode(recc,becc,ECC_BITS + SEED_BITS);
    
    //Trunc(t,CT2_BITS) + ECC(msg)
    for(i=0;i<CT2_WORDS;i++)
        ct.v[i] = t[i]^recc[i];  
    cipher_to_bytes(cct,&ct);
    
    return 0;
}

/*
Function: LPN core decryption
Inputs  : a secret key csk and a ciphertext cct
Outputs : a decrypted message msg
*/
int lepton_ow_dec_KAT(uint8_t *msg, const uint8_t *csk, const uint8_t *cct)
{
    poly t;
    uint32_t recc[CT2_WORDS]={0};
    uint8_t becc[BCH_CODEBYTES]={0};
		seckey sk;
    cipher ct;
    int i=0;
    
    
    sk_from_bytes(&sk,csk);
    
    cipher_from_bytes(&ct,cct);  
    poly_mul(t,ct.u,sk.s);//t = c1*s
    
    //c2 - Trunc(t,CT2_BITS)
    for(i=0;i<CT2_WORDS;i++)
        recc[i] = t[i]^ct.v[i];
     
    //decode the message 
    //repitition decode
    repeated_decode(becc,ECC_BITS + SEED_BITS,recc);
    
    uint16_t errLocOut[PARAM_BCT];
    //bch decode
    int nerr = decode_bch(&bch, becc, SEED_BYTES,&becc[SEED_BYTES],errLocOut);
    
    if(nerr<0)
    	return -1;//error happens
    
    correct_bch(becc,SEED_BYTES,errLocOut,nerr);
    memcpy(msg,becc,SEED_BYTES);
    
    return 0;   
}

