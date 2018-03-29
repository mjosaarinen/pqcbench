#ifndef PARAMS_H
#define PARAMS_H


#ifdef LIGHT_I /*Light I Parameter Set*/
#define PARAM_N ((1<<13)-92) // X^N + X^M +1  irreducible polynomial
#define PARAM_M 9
#define PARAM_K 16 //noise Hamming weight
#define PARAM_LOGN 13 //ceil(log_2 N)
#define PARAM_RCN 9 //repeated codes


#elif defined(LIGHT_II) /*Light II Parameter Set*/
#define PARAM_N ((1<<13)-92)
#define PARAM_M 9
#define PARAM_K 20
#define PARAM_LOGN 13
#define PARAM_RCN 15


#elif defined(MODER_I) /*Moderate I Parameter Set*/
#define PARAM_N ((1<<14)-231) // X^N + X^M +1  irreducible polynomial
#define PARAM_M 10
#define PARAM_K 19 //noise Hamming weight
#define PARAM_LOGN 14 //ceil(log_2 N)
#define PARAM_RCN 7 //repeated codes


#elif defined(MODER_II) /*Moderate II Parameter Set*/
#define PARAM_N ((1<<14)-231)
#define PARAM_M 10
#define PARAM_K 24
#define PARAM_LOGN 14
#define PARAM_RCN 11


#elif defined(MODER_III) /*Moderate III Parameter Set*/
#define PARAM_N ((1<<14)-231)
#define PARAM_M 10
#define PARAM_K 28
#define PARAM_LOGN 14
#define PARAM_RCN 15


#elif defined(MODER_IV) /*Moderate IV Parameter Set*/
#define PARAM_N ((1<<14)-231)
#define PARAM_M 10
#define PARAM_K 37
#define PARAM_LOGN 14
#define PARAM_RCN 31


#elif defined(PARAN_I) /*Paranoid I¡¡Parameter Set*/
#define PARAM_N ((1<<15)- 1) // X^N + X^M +1  irreducible polynomial
#define PARAM_M 1
#define PARAM_K 35 //noise Hamming weight
#define PARAM_LOGN 15 //ceil(log_2 N)
#define PARAM_RCN 19 //repeated codes


#else /*Paranoid II¡¡Parameter Set*/
#define PARAM_N ((1<<15) - 1)
#define PARAM_M 1
#define PARAM_K 40
#define PARAM_LOGN 15
#define PARAM_RCN 23
#endif /* end of choosing parameter sets*/

#define PARAM_BCT 30  //the maximum number of error bits that BCH can handle
#define SEED_BITS 256
#define ECC_BITS 252 //BCH ecc bits

#define PARAM_RCT  (PARAM_RCN>>1) //repetition decode threshold
#define POLY_BYTES ((PARAM_N+7)>>3)
#define POLY_WORDS ((PARAM_N+31)>>5)
#define POLY2_WORDS (2*POLY_WORDS)

#define PARAM_3K (3*PARAM_K)
#define SEED_BYTES (SEED_BITS>>3)
#define ECC_BYTES ((ECC_BITS + 7)>>3)  //BCH ECC bytes
#define BCH_CODEBYTES (SEED_BYTES + ECC_BYTES)
#define CT1_BYTES POLY_BYTES //c1 length
#define CT1_WORDS ((CT1_BYTES+3)>>2)
#define CT2_BITS (PARAM_RCN*(ECC_BITS + SEED_BITS)) //c2 length
#define CT2_BYTES ((CT2_BITS+7)>>3) 
#define CT2_WORDS  ((CT2_BITS+31)>>5)

#define CPA_PK_BYTES (SEED_BYTES + POLY_BYTES) //CPA public key length
#define CPA_SK_BYTES (2*PARAM_K) //CPA secret key length
#define CPA_CT_BYTES (CT1_BYTES + CT2_BYTES) //CCA ciphertext length
#define CPA_BUF_BYTES (CPA_CT_BYTES + SEED_BYTES)

#define CCA_PK_BYTES CPA_PK_BYTES //CCA public key length
#define CCA_SK_BYTES (CCA_PK_BYTES + CPA_SK_BYTES) //CCA secret key length
#define CCA_CT_BYTES (CPA_CT_BYTES + SEED_BYTES) //CCA ciphertext length, adding a tag
#define CCA_BUF_BYTES (CCA_CT_BYTES + SEED_BYTES)
#endif
