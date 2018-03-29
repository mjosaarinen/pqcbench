#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "KEMheader.h"
#include "rng.h"
//#include "randombytes.h"



void allocatemem(Pol *f, int n,int m){
	 
	int i;
	for(i =0;i<m;i++)
	{
		f[i].QD = malloc((n*n) * sizeof(long));            /* allocating memory for the coefficients of each polynomial to be stored in*/
		f[i].L = malloc(n * sizeof(long));

	}


}


void freealloc(Pol *f, int m)
{
	int i;
	for(i=0;i<m;i++)               /* freeing the allocated memory*/
	{
		free(f[i].QD);
		free(f[i].L);

	}

}


void polgen(Pol *f, int m, int n )
{                                                              /* generates a system of m polynomials over n variables */
	int i,l;
	
	long *out=malloc(sizeof( long));

	for(i=0; i< m; i++)
	{	
		
		
		long cofval[(N*(N+1)/2) + N+1];
		
		
		for (l=0;l< ((N*(N+1)/2) + N+1);l++)
		{
			randombytes((unsigned char*)(&out), 4);
			cofval[l]=((long)out)%(COFSIZE);
		}
        
		int j,k,count=0;
		
		for(j=0; j<n; j++) 
		{
			for(k=0; k<n; k++) 
			{
				
				if(k > j) 
					f[i].QD[(k*n+j)] = 0;
				else 
					{						
					f[i].QD[(k*n+j)] = cofval[count]%(COFSIZE);
					count++;
					}
			}
		}		
		
		for(j=0; j<n; j++)
		{
			f[i].L[j] = cofval[count]%(COFSIZE) ;
			count++;
		}
	
		f[i].C = cofval[count]%(COFSIZE) ; 
		

	}
	
}





unsigned long long evaluate_poly(Pol unPoly,  unsigned char *pValue, int n)
{
	int i, j;
	unsigned long long result1 = 0, result2 = 0;                               /* evaluates f over a value, like f(sa)*/
	unsigned long long tabResult1[n];
/*for quad */	
	for(j=0; j<n; j++)
	{
		tabResult1[j] =0;
		for(i=0; i<n; i++)
		{
			tabResult1[j] = tabResult1[j]+ ((unsigned long)pValue[i] * unPoly.QD[i*n + j]) ;
			
			
			
		}
		result1 = (result1 + tabResult1[j] * (unsigned long)pValue[j]) ; 	
	}
/*for linear*/
	for(i=0; i<n; i++)
	{
		
		result2 = (result2 + unPoly.L[i] * (unsigned long)pValue[i]) ;
	}

	result1 = (result1 + result2 + unPoly.C);

	return result1;
}

void Eval_sys(Pol *pSyst, unsigned char* pValue, int m, int n,unsigned long long *result)
{
	int i;                                                                                    /*evaluates a system of polynomials over a provided value, calls the evaluate_poly function for each polynomial*/
	for(i=0; i<M; i++)
		result[i] = evaluate_poly(pSyst[i], pValue, N);
	
}




unsigned char kem_crossround1( unsigned long long in){
	unsigned char out;
	unsigned long long rem = in >> (B_BAR-1);                  /*CrossRound function to give the CrossRound bit of a value*/
	out =(unsigned char) (rem%2);
	return out;
}

unsigned char rounding(unsigned long long in)
{
	unsigned char out;
	unsigned long long rem =( in + (2^(B_BAR-1)));             /*Rounding function to give the rounded value*/
	unsigned long long rem2 = (rem % Q);
	out = (unsigned char)((rem2 >> B_BAR));

	return out; 

}

void kem_crossround2(unsigned char *out,  unsigned  long long *in) {
	int i;
                                                                      /*CrossRound function over a vector*/
	for (i = 0; i < M; i++) {
		unsigned long long rem = in[i] >> (B_BAR-1);
		out[i] = (unsigned char)(rem%2);
	}

}

	
void kem_rounding(unsigned char *out,  unsigned long long *in) {
	int i;
	for (i=0 ; i < M ; i++)											/*Rounding function over a vector*/
	{
		unsigned long long rem = (in[i] + (2^(B_BAR-1)));
		unsigned long long rem2 = (rem % Q); 
		out[i] = (unsigned char)((rem2 >> B_BAR));
	}
	
}

void kem_rec(unsigned char *key,  unsigned long long *w, unsigned char *c){
	int i;
	unsigned long long w1,w2;
	unsigned char hint;
	for (i =0; i < M;i++){														/*Red function from the article*/
		int flag=0;
		hint= kem_crossround1(w[i]);
		if (hint==c[i])
		{
			key[i] = rounding(w[i]);
			flag=1;
		}
		if (flag==0)
		{
			w1 = (w[i] + (2^(B_BAR-2))-1) ;
			hint= kem_crossround1(w1);
			if (hint==c[i]){
				key[i] = rounding(w1);	
			}
			else{
				w2 =(w[i] - (2^(B_BAR-2))+1) ;
				hint= kem_crossround1(w2);
				if (hint==c[i]){
					key[i] = rounding(w2);	
				}
				else key[i]=0;
			}
		}
	}
	
}

void pack_sk(unsigned char *sk, unsigned char *sa, unsigned char *seed){

	int i;																	/* makes SK=(seed||sa)*/
	for(i=0;i<  SEEDSIZE;i++)
		{sk[i]=seed[i];}
	for(i=0;i < N;i++)
		sk[SEEDSIZE+i]=sa[i];	
}
void unpack_sk(unsigned char *sa, unsigned char *seed, const unsigned char *sk){

	int i;
	for(i=0;i< SEEDSIZE;i++)												/*unpacks SK to give out seed and sa*/
		{seed[i]=sk[i];}
	for(i=0;i < N;i++)
		sa[i]=sk[SEEDSIZE+i];
		

}
void pack_pk(unsigned char *pk,unsigned  long long *b1, unsigned char *seed){
	

	int i,j;
	for(i=0 ;i <SEEDSIZE;i++)
		{pk[i]=seed[i];}
	unsigned char temp;
	unsigned char mask=255;												/* makes PK=(seed||b1)*/
	for(i =0;i<M;i++)
		{for(j=7;j>-1;j--)
			{temp=(b1[i] & mask);
			b1[i]=b1[i]>>8;
			pk[SEEDSIZE+i*8+j]=temp;
		}
	}

}
void unpack_pk(unsigned long long *b1, unsigned char *seed, const unsigned char *pk){
	int i,j;
	for(i=0;i<SEEDSIZE;i++)
		seed[i]=pk[i];
	unsigned char temp;
	for(i=0;i<M;i++)
		b1[i]=0; 
	for(i=0;i<M;i++)
		{																/*unpacks PK to give out seed and the public vector b1*/
			for(j=0;j<7;j++)
				{
				temp = pk[i*8+j+SEEDSIZE];
				b1[i]=b1[i]+temp;
				b1[i]=b1[i]<<8;
				}
			b1[i]=b1[i]+pk[i*8+7+SEEDSIZE];	
		}
	

}
void pack_ct(unsigned char *ct, unsigned long long *b2,unsigned char *c){


	int  i,j;
	for (i=0;i < M;i++)
		ct[i]=c[i];
																		/*makes ct=(c||b2)*/
	unsigned char temp;
	unsigned char mask=255;
	for(i =0;i<M;i++)
		{for(j=7;j>-1;j--)
			{temp=(unsigned char)(b2[i] & mask);
			b2[i]=b2[i]>>8;
			ct[M+i*8+j]=temp;
		}
	}
			
			

	
}
void unpack_ct(unsigned long long *b2,unsigned  char *c, const unsigned char *ct){

	int  i,j;
	for (i=0;i < M;i++)
		c[i]=ct[i];
	
	unsigned char temp;
	for(i=0;i<M;i++)												/*unpacks ct to give out the hint vector c and b2*/
		b2[i]=0; 
	for(i=0;i<M;i++)
		{	
			for(j=0;j<7;j++)
				{
				temp = ct[i*8+j+M];
				b2[i]=b2[i]+temp;
				b2[i]=b2[i]<<8;
				}
			b2[i]=b2[i]+ct[i*8+7+M];	
		}

}


int crypto_kem_keypair(unsigned char *pk, unsigned char *sk){
	
	unsigned char *seed=malloc(SEEDSIZE*sizeof(unsigned char));if (seed==NULL) {printf("EXIT");return 0;}
	randombytes(seed,SEEDSIZE);

	
	Pol *f1 = malloc(M * sizeof(Pol));	
	allocatemem(f1,N,M);

	randombytes_init(seed,NULL,256);
	polgen(f1,M,N);
    
	int i;

	unsigned char *sa=malloc(N*sizeof(unsigned char));if (sa==NULL) {printf("EXIT");return 0;}


	randombytes(sa,N*SECRETVAL_LENGTH);

	unsigned char *e1=malloc(M*sizeof(unsigned char));if (e1==NULL) {printf("EXIT");return 0;}
	randombytes(e1,M*ERROR_LENGTH);


	for(i=0;i < N;i++)	
		sa[i]=(unsigned char)((sa[i])%RANGE);


	for(i=0;i < M;i++)
		{e1[i]=(unsigned char)((e1[i])%RANGE);	}


	unsigned long long *b1=malloc(M*sizeof(unsigned long long));if (b1==NULL) {printf("EXIT");return 0;}
	Eval_sys(f1,sa,M,N,b1);
	for (i =0;i <M ;i++)
	{
		b1[i] = (b1[i] + e1[i]) ;
		

	}	
	
	pack_sk(sk,sa,seed);

	pack_pk(pk,b1,seed);
	
 
	return 0;
}

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk){
	int i;
	unsigned long long *b1=malloc(M*sizeof(unsigned long long));
	unsigned char *seed=malloc(SEEDSIZE*sizeof(unsigned char));
	unpack_pk(b1, seed, pk);
	
	
	Pol *f2 = malloc(M*sizeof(Pol));
	allocatemem(f2,N,M);

	randombytes_init(seed,NULL,256);
	polgen(f2,M,N);



	unsigned char *seed1=malloc(SEEDSIZE*sizeof(unsigned char));
	randombytes(seed1,SEEDSIZE);

	randombytes_init(seed1,NULL,256);
	unsigned char *sb=malloc(N*sizeof(unsigned char));
	unsigned char *e2=malloc(M*sizeof(unsigned char));if (e2==NULL) {printf("EXIT");return 0;}
	unsigned char *e3=malloc(M*sizeof(unsigned char));if (e3==NULL) {printf("EXIT");return 0;}
	
	randombytes(sb, N*SECRETVAL_LENGTH);
		
	randombytes(e2,M*ERROR_LENGTH);
	randombytes(e3,M*ERROR_LENGTH);

	for(i=0;i < N;i++)
		{sb[i]=(unsigned char)((sb[i])%RANGE);}
			
		
	for(i=0;i < M;i++)	
		{e2[i]=(unsigned char)((e2[i])%RANGE);
		e3[i]=(unsigned char)((e3[i])%RANGE);	}
		
			
			
	unsigned long long *b2=malloc(M*sizeof(unsigned long long));if (b2==NULL) {printf("EXIT");return 0;}
	unsigned long long *b3=malloc(M*sizeof(unsigned long long));if (b3==NULL) {printf("EXIT");return 0;}
	
	Eval_sys(f2,sb,M,N,b2);
    	
	for  (i =0;i<M;i++){
		b3[i] = (b2[i]*b1[i] + e3[i]);
		b2[i] = (b2[i] + e2[i]);
        		
        }

	kem_rounding(ss, b3);
	
	unsigned char *c=malloc(M*sizeof(unsigned char));
	kem_crossround2(c, b3);
	pack_ct(ct, b2, c);

	return 0;
}


int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk){
	int i;
	unsigned char *sa=malloc(N*sizeof(unsigned char));
	unsigned char *seed=malloc(SEEDSIZE*sizeof(unsigned char));
	unpack_sk(sa,seed,sk);
	unsigned long long *b2=malloc(M*sizeof(unsigned long long));
	unsigned char *c=malloc(M*sizeof(unsigned char));

	unpack_ct(b2,c,ct);
	Pol *f = (Pol*)malloc(M*sizeof(Pol));
	allocatemem(f,N,M);

	randombytes_init(seed,NULL,256);
	polgen(f,M,N);
		
	unsigned long long *w = malloc(M*sizeof(unsigned long long));
	Eval_sys(f,sa,M,N,w);
	for (i=0;i < M;i++)
		{	
			w[i]=(w[i]*b2[i]) ;}
			
			
				
			
	kem_rec(ss, w, c);
	
	return 0;
}
