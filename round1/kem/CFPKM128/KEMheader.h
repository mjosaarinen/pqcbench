#ifndef _HEAD_
#define _HEAD_
#include <stdint.h>
#include <math.h>

#define LAMBDA 256
#define SEEDSIZE 48
#define LOG2_Q 50 /* log_2 q.*/ 
#define N 80      /* number of variables.*/
#define B 6/* Number of bits extracted from a element.*/
#define M 81    /*the number of equations*/   

#define Q 1125899906842624 

#define COFSIZE 4096  /*bound on the bitsize of the coeffeicients of the polynomials*/
#define SECRETVAL_LENGTH 1
#define SHAREDKEYSIZE (M*B/8)
#define ERROR_LENGTH 1
#define PK_LENGTH (M*8)
#define RANGE 7
#define B_BAR  (LOG2_Q-B)
typedef struct {
		long *QD;
		long *L;
		long C;
	}Pol;


void allocatemem(Pol *f, int n,int m);
void freealloc(Pol *f, int m);
void polgen(Pol *f, int m, int n );
unsigned long long evaluate_poly(Pol unPoly, unsigned char *pValue, int n);
void Eval_sys(Pol *pSyst, unsigned char* pValue, int m, int n,unsigned long long*result);
unsigned char rounding(unsigned long long in);
void kem_rounding(unsigned char *out,  unsigned long long *in);
void kem_rec(unsigned char *key,  unsigned long long *b, unsigned char *c);

int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);



unsigned char kem_crossround1( unsigned long long in);
void kem_crossround2(unsigned char *out, unsigned long long *in);
void pack_sk(unsigned char *sk, unsigned char *sa, unsigned char *seed);
void unpack_sk(unsigned char *sa, unsigned char *seed,const unsigned char *sk);
void pack_pk(unsigned char *pk,unsigned long long *b1, unsigned char *seed);
void unpack_pk(unsigned long long *b1, unsigned char *seed,const unsigned char *pk);
void pack_ct(unsigned char *ct,unsigned long long *b2, unsigned char *c);
void unpack_ct( unsigned long long *b2, unsigned  char *c, const unsigned char *ct);
#endif
