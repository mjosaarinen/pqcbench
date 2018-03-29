#include <stdio.h>
#include <time.h>
#include "rng.h"
#include "fips202.h"
#include "api.h"

#define NTESTS 10000

#if defined(__i386__)

static __inline__ unsigned long long cpucycles(void)
{
    unsigned long long int x;
    __asm__ volatile (".byte 0x0f, 0x31" : "=A" (x));
    return x;
}

#elif defined(__x86_64__)

static __inline__ unsigned long long cpucycles(void)
{
    unsigned hi, lo;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ( (unsigned long long)lo)|( ((unsigned long long)hi)<<32 );
}

#endif

static unsigned long long average(unsigned long long *t, size_t tlen)
{
    unsigned long long acc=0;
    size_t i;
    for(i=0;i<tlen;i++)
        acc += t[i];
    return acc/(tlen);
}

static unsigned long long print_results(const char *s, unsigned long long *t, size_t tlen)
{
    unsigned long long res = average(t, tlen);
    printf("%s: %lld\n", s,res);
    return res;
}


int main()
{
    long long bt,et;
    unsigned long long cput1[NTESTS],cput2[NTESTS],cput3[NTESTS];
    unsigned long long hcput[5][NTESTS];
    
    uint8_t cpk[CRYPTO_PUBLICKEYBYTES];
    uint8_t csk[CRYPTO_SECRETKEYBYTES];
    uint8_t cct[CRYPTO_CIPHERTEXTBYTES];
    uint8_t buf[SEED_BYTES + CRYPTO_CIPHERTEXTBYTES];
    
    
    uint8_t ss[SEED_BYTES],rss[SEED_BYTES],seed[SEED_BYTES];
    uint8_t entropy_input[48];
    int i=0;
    
    bt = clock();
    for (i=0; i<48; i++)
        entropy_input[i] = i & bt;
    randombytes_init(entropy_input, NULL, 256);
    
      
    printf("N = %d ||",PARAM_N);
    printf("K = %d ||",PARAM_K);
    printf("RCN = %d \n",PARAM_RCN);
    printf("PK Bytes = %d   ||",CRYPTO_PUBLICKEYBYTES);
    printf("SK Bytes = %d   ||",CRYPTO_SECRETKEYBYTES);
    printf("CT Bytes = %d\n\n",CRYPTO_CIPHERTEXTBYTES);
    
    
    int nerr=0,flag;
    int trial;
    double num[5],den[3],t;
    for (trial=0;trial < NTESTS;++trial)
    {
        bt = cpucycles();
        flag = crypto_kem_keypair(cpk,csk);
        et = cpucycles();
        cput1[trial] = et - bt;
        
        
        bt = cpucycles();
        flag |= crypto_kem_enc(cct,ss,cpk);
        et = cpucycles();
        cput2[trial] = et - bt;

        bt = cpucycles();
        flag |= crypto_kem_dec(rss,cct,csk);
        et = cpucycles();
        cput3[trial] = et - bt;
        if(memcmp(ss,rss,SEED_BYTES)!=0 || flag)
        {
        	nerr++;
        	printf("error!\n");
        }
        
        //testing the time used for hashing... 
        randombytes(seed,SEED_BYTES);
        
        //for get_random
        bt = cpucycles();
	   cshake128_simple(buf,4*POLY_WORDS,0,seed,SEED_BYTES);
        et = cpucycles();
        hcput[0][trial] = et - bt;
	   
	   //for get_noise
	   bt = cpucycles(); 
        cshake128_simple(buf,2*PARAM_3K,0,seed,SEED_BYTES);
        et = cpucycles();
        hcput[1][trial] = et - bt;

	   //for keygen
	   bt = cpucycles();  
	   cshake128_simple(buf,2*SEED_BYTES,0,seed,SEED_BYTES);
	   et = cpucycles();
        hcput[2][trial] = et - bt;
        
	   //for encryption
	   memcpy(buf,seed,SEED_BYTES);
	   memcpy(&buf[SEED_BYTES],cpk,CRYPTO_PUBLICKEYBYTES);
	   bt = cpucycles();
#ifdef LEPTON_CPA	   
	   shake128(buf,2*SEED_BYTES,buf,SEED_BYTES + CRYPTO_PUBLICKEYBYTES);
#else
	   shake128(buf,3*SEED_BYTES,buf,SEED_BYTES + CRYPTO_PUBLICKEYBYTES);
#endif
	   et = cpucycles();
	   hcput[3][trial] = et - bt;

	   //for decryption
	   memcpy(buf,seed,SEED_BYTES);
	   memcpy(&buf[SEED_BYTES],cct,CRYPTO_CIPHERTEXTBYTES);
	   bt = cpucycles();
        shake128(buf,SEED_BYTES,buf,SEED_BYTES + CRYPTO_CIPHERTEXTBYTES);
        et = cpucycles();
        hcput[4][trial] = et - bt;
        
    }
    printf("number  of  errors in %d runs:  %d\n",NTESTS,nerr);
    printf("average cpu cycles in %d runs:\n",NTESTS);
    den[0] = print_results("keygen :", cput1,NTESTS);
    den[1] = print_results("encrypt:", cput2,NTESTS);
    den[2] = print_results("decrypt:", cput3,NTESTS);
    
    num[0] = average(hcput[0],NTESTS);
    num[1] = average(hcput[1],NTESTS);
    num[2] = average(hcput[2],NTESTS);
    num[3] = average(hcput[3],NTESTS);
    num[4] = average(hcput[4],NTESTS);
    
    //all hashing time 
    t = num[0] + 2*num[1] + num[2];  
    printf("hashing in keygen :%f %%\n",t/den[0] *100);
    
    t = num[0] + 3*num[1] + num[3] + num[4];
    printf("hashing in encrypt:%f %%\n",t/den[1] *100);
    
#ifdef LEPTON_CPA	   
    t = num[4];
#endif
    printf("hashing in decrypt:%f %%\n", t/den[2] * 100);
    
    //hashing for multi-protection: 
    t = num[3] + num[4] - 2*num[2];
    printf("hashing for multi-protection in encrypt:%f %%\n",t/den[1] *100);
    
#ifdef LEPTON_CPA	   
    t = num[4] - num[2];
#endif
    printf("hashing for multi-protection in decrypt:%f %%\n", t/den[2] * 100);
    
    return 0;
}
