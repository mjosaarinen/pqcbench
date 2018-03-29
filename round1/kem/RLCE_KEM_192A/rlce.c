/* rlce.c
 *
 * Code was written: November 19, 2016-February 8, 2017
 *
 * rlce.c implements crypto oprations 
 * for RLCE scheme that is part of the package 
 * RLCE.tar - Random Linear Code Encryption Scheme
 *
 * Copyright (C) 2016-2017 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 */

#include "rlce.h"
int RLCEspad(unsigned char bytes[],unsigned int BLen,
	     unsigned char padded[], unsigned int paddedLen,
	     RLCE_public_key_t pk,
	     unsigned char randomness[], unsigned int randLen,
	     unsigned char e0[], unsigned int e0Len);
int RLCEspadDecode(unsigned char encoded[],unsigned int encodedLen,
		   unsigned char message[], unsigned long long *mlen,
		   RLCE_private_key_t sk,
		   unsigned char e0[], unsigned int e0Len);

int RLCEpad(unsigned char bytes[],unsigned int bytesLen,
	    unsigned char padded[], unsigned int paddedLen,
	    RLCE_public_key_t pk,
	    unsigned char randomness[], unsigned int randLen,
	    unsigned char e0[], unsigned int e0Len);
int RLCEpadDecode(unsigned char encoded[],unsigned int encodedLen,
		  unsigned char message[], unsigned long long *mlen,
		  RLCE_private_key_t sk,
		  unsigned char e0[], unsigned int e0Len);
int rangeadd(unsigned char bytes1[], unsigned char bytes2[], int bytesize);
poly_t genPolyTable(int deg);

int getRLCEparameters(unsigned int para[], unsigned int scheme, unsigned int padding) {
  para[9]=padding;  /* 0 for RLCEspad-mediumEncoding
                        1 for RLCEpad-mediumEncoding
                        2 for RLCEspad-basicEncoding
                        3 for RLCEpad-basicEncoding
                        4 for RLCEspad-advancedEncoding
                        5 for RLCEpad-advancedEncoding*/
  para[10]=scheme;   /* scheme ID */
  switch (scheme) {
  case 0:
    para[0]=630; /* n */
    para[1]=470; /* k */
    para[2]=160; /* w */
    para[3]=10;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=80;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=128; /* kappa-128 */
    para[15]=200; /* u: used for un-recovered msg symbols by RS */
    para[16]=988; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=310116; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=192029; /* sk bytes for decoding algorithm 2*/
    para[18]=188001; /* pk bytes */
    para[19]=32; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=5500; /*mLen for mediumEncoding */
      para[6]=171;  /* k1 for mediumEncoding */
      para[7]=171;  /* k2 for mediumEncoding */
      para[8]=346; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=5500; /*mLen for mediumEncoding */
      para[6]=624;  /* k1 for mediumEncoding */
      para[7]=32;  /* k2 for mediumEncoding */
      para[8]=32; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=4700; /*mLen bEncoding */
      para[6]=146; /* k1 for basicEncoding */
      para[7]=146; /* k2 for basidEncoding */
      para[8]=296;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=4700; /*mLen bEncoding */
      para[6]=524; /* k1 for basicEncoding */
      para[7]=32; /* k2 for basidEncoding */
      para[8]=32;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=5869; /*mLen for advancedEncoding */
      para[6]=183; /* k1 for advancedEncoding */
      para[7]=183; /* k2 for advancedEncoding */
      para[8]=368; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=5869; /*mLen for advancedEncoding */      
      para[6]=670; /* k1 for advancedEncoding */
      para[7]=32; /* k2 for advancedEncoding */
      para[8]=32;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }          
    break;    
  case 1:
    para[0]=532; /* n */
    para[1]=376; /* k */
    para[2]=96; /* w */
    para[3]=10;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=78;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=128; /* kappa-128 */
    para[15]=123; /* u: used for un-recovered msg symbols by RS */
    para[16]=785; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=179946; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=121666; /* sk bytes for decoding algorithm 2*/
    para[18]=118441; /* pk bytes */
    para[19]=32; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=4540; /*mLen for mediumEncoding */
      para[6]=141;  /* k1 for mediumEncoding */
      para[7]=141;  /* k2 for mediumEncoding */
      para[8]=286; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=4540; /*mLen for mediumEncoding */
      para[6]=504;  /* k1 for mediumEncoding */
      para[7]=32;  /* k2 for mediumEncoding */
      para[8]=32; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=3760; /*mLen bEncoding */
      para[6]=117; /* k1 for basicEncoding */
      para[7]=117; /* k2 for basidEncoding */
      para[8]=236;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=3760; /*mLen bEncoding */
      para[6]=406; /* k1 for basicEncoding */
      para[7]=32; /* k2 for basidEncoding */
      para[8]=32;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=4875; /*mLen for advancedEncoding */
      para[6]=152; /* k1 for advancedEncoding */
      para[7]=152; /* k2 for advancedEncoding */
      para[8]=306; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=4875; /*mLen for advancedEncoding */      
      para[6]=546; /* k1 for advancedEncoding */
      para[7]=32; /* k2 for advancedEncoding */
      para[8]=32;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }             
    break;
  case 2:
    para[0]=1000; /* n */
    para[1]=764; /* k */
    para[2]=236; /* w */
    para[3]=10;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=118;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=192; /* kappa-192 */
    para[15]=303; /* u: used for un-recovered msg symbols by RS */
    para[16]=1545; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=747393; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=457073; /* sk bytes for decoding algorithm 2*/
    para[18]=450761; /* pk bytes */
    para[19]=40; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=8820; /*mLen for mediumEncoding */
      para[6]=275;  /* k1 for mediumEncoding */
      para[7]=275;  /* k2 for mediumEncoding */
      para[8]=553; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=8820; /*mLen for mediumEncoding */
      para[6]=1007;  /* k1 for mediumEncoding */
      para[7]=48;  /* k2 for mediumEncoding */
      para[8]=48; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=7640; /*mLen bEncoding */
      para[6]=238; /* k1 for basicEncoding */
      para[7]=238; /* k2 for basidEncoding */
      para[8]=479;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=7640; /*mLen bEncoding */
      para[6]=859; /* k1 for basicEncoding */
      para[7]=48; /* k2 for basidEncoding */
      para[8]=48;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=9377; /*mLen for advancedEncoding */
      para[6]=293; /* k1 for advancedEncoding */
      para[7]=293; /* k2 for advancedEncoding */
      para[8]=587; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=9377; /*mLen for advancedEncoding */      
      para[6]=1077; /* k1 for advancedEncoding */
      para[7]=48; /* k2 for advancedEncoding */
      para[8]=48;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }     
    break;
  case 3:
    para[0]=846; /* n */
    para[1]=618; /* k */
    para[2]=144; /* w */
    para[3]=10;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=114;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=192; /* kappa-192 */
    para[15]=190; /* u: used for un-recovered msg symbols by RS */
    para[16]=1238; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=440008; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=292461; /* sk bytes for decoding algorithm 2*/
    para[18]=287371; /* pk bytes */
    para[19]=40; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=7320; /*mLen for mediumEncoding */
      para[6]=228;  /* k1 for mediumEncoding */
      para[7]=228;  /* k2 for mediumEncoding */
      para[8]=459; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=7320; /*mLen for mediumEncoding */
      para[6]=819;  /* k1 for mediumEncoding */
      para[7]=48;  /* k2 for mediumEncoding */
      para[8]=48; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=6180; /*mLen bEncoding */
      para[6]=193; /* k1 for basicEncoding */
      para[7]=193; /* k2 for basidEncoding */
      para[8]=387;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=6180; /*mLen bEncoding */
      para[6]=677; /* k1 for basicEncoding */
      para[7]=48; /* k2 for basidEncoding */
      para[8]=48;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=7825; /*mLen for advancedEncoding */
      para[6]=244; /* k1 for advancedEncoding */
      para[7]=244; /* k2 for advancedEncoding */
      para[8]=491; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=7825; /*mLen for advancedEncoding */      
      para[6]=883; /* k1 for advancedEncoding */
      para[7]=48; /* k2 for advancedEncoding */
      para[8]=48;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }       
    break;
  case 4:
    para[0]=1360; /* n */
    para[1]=800;  /* k */
    para[2]=560;  /* w */
    para[3]=11;   /* GF size */
    para[4]=2;    /* hash type */
    para[11]=280;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=256; /* kappa-256 */
    para[15]=482; /* u: used for un-recovered msg symbols by RS */
    para[16]=2640; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=1773271; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=1241971; /* sk bytes for decoding algorithm 2*/
    para[18]=1232001; /* pk bytes */
    para[19]=48; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=11880; /*mLen for mediumEncoding */
      para[6]=371;  /* k1 for mediumEncoding */
      para[7]=371;  /* k2 for mediumEncoding */
      para[8]=743; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=11880; /*mLen for mediumEncoding */
      para[6]=1365;  /* k1 for mediumEncoding */
      para[7]=60;  /* k2 for mediumEncoding */
      para[8]=60; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=8800; /*mLen bEncoding */
      para[6]=275; /* k1 for basicEncoding */
      para[7]=275; /* k2 for basidEncoding */
      para[8]=550;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=8800; /*mLen bEncoding */
      para[6]=980; /* k1 for basicEncoding */
      para[7]=60; /* k2 for basidEncoding */
      para[8]=60;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=13025; /*mLen for advancedEncoding */
      para[6]=407; /* k1 for advancedEncoding */
      para[7]=407; /* k2 for advancedEncoding */
      para[8]=815; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=13205; /*mLen for advancedEncoding */      
      para[6]=1509; /* k1 for advancedEncoding */
      para[7]=60; /* k2 for advancedEncoding */
      para[8]=60;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }    
    break;
  case 5:
    para[0]=1160; /* n */
    para[1]=700; /* k */
    para[2]=311; /* w */
    para[3]=11;  /* GFsize */
    para[4]=2;   /* hash type */
    para[11]=230;   /* t */
    para[12]=0;   /* omega for list-decoding */
    para[13]=0;   /* L_omega: for list-decoding only */
    para[14]=256; /* kappa-256 */
    para[15]=309; /* u: used for un-recovered msg symbols by RS */
    para[16]=2023; /* cipher len in bytes*/
    if (DECODINGMETHOD!=2) {
      para[17]=1048176; /* sk bytes for decodingalgorithm 0,1*/
    } else para[17]=749801; /* sk bytes for decoding algorithm 2*/
    para[18]=742089; /* pk bytes */
    para[19]=48; /* random input bytes*/
    switch (padding) {
    case 0: /* 0:RLCEspad */
      para[5]=10230; /*mLen for mediumEncoding */
      para[6]=319;  /* k1 for mediumEncoding */
      para[7]=319;  /* k2 for mediumEncoding */
      para[8]=641; /* k3 for mediumEncoding */
      break;
    case 1: /* 1:RLCEpad  */
      para[5]=10230; /*mLen for mediumEncoding */
      para[6]=1159;  /* k1 for mediumEncoding */
      para[7]=60;  /* k2 for mediumEncoding */
      para[8]=60; /* k3 for mediumEncoding */
      break;
    case 2:
      para[5]=7700; /*mLen bEncoding */
      para[6]=240; /* k1 for basicEncoding */
      para[7]=240; /* k2 for basidEncoding */
      para[8]=483;/* k3 for basicEncoding */
      break;
    case 3:
      para[5]=7700; /*mLen bEncoding */
      para[6]=843; /* k1 for basicEncoding */
      para[7]=60; /* k2 for basidEncoding */
      para[8]=60;/* k3 for basicEncoding */
      break;
    case 4:
      para[5]=11145; /*mLen for advancedEncoding */
      para[6]=348; /* k1 for advancedEncoding */
      para[7]=348; /* k2 for advancedEncoding */
      para[8]=698; /* k3 for advancedEncoding */
      break;
    case 5:
      para[5]=11145; /*mLen for advancedEncoding */      
      para[6]=1274; /* k1 for advancedEncoding */
      para[7]=60; /* k2 for advancedEncoding */
      para[8]=60;/* k3 for advancedEncoding */
      break;
    default:
      return RLCEPADDINGNOTDEFINED;
    }  
    break;
  default:
    return RLCEIDPARANOTDEFINED;
  }
  return 0;
}


RLCE_private_key_t RLCE_private_key_init (unsigned int para[]) {
  RLCE_private_key_t key;
  key= (RLCE_private_key_t) malloc(sizeof (struct RLCE_private_key));
  key->para = malloc(PARASIZE * sizeof(unsigned int));
  int i;
  for (i=0; i<PARASIZE; i++) (key->para[i])=para[i];
  key->perm1 =vec_init(para[0]);
  key->perm2 =vec_init(para[0]+para[2]); /* n+w */
  key->A =matrixA_init(para[2]);
  if (DECODINGMETHOD!=2) key->S = matrix_init(para[1], para[15]+1);
  key->grs = vec_init(para[0]);
  key->G = matrix_init(para[1], para[0]+para[2]-para[1]); /* k\times (n+w)-k */
  return key;
}

void RLCE_free_sk(RLCE_private_key_t sk) {
  free(sk->para);
  if (DECODINGMETHOD!=2) matrix_free(sk->S);
  vector_free(sk->perm1);
  vector_free(sk->perm2);
  matrixA_free(sk->A);
  vector_free(sk->grs);
  if (sk->G !=NULL) matrix_free(sk->G);
  free(sk);
  sk=NULL;
}

RLCE_public_key_t RLCE_public_key_init (unsigned int para[]) {
  RLCE_public_key_t pk;
  int i;
  pk= (RLCE_public_key_t) malloc(sizeof (struct RLCE_public_key));
  pk->para = malloc(PARASIZE * sizeof(unsigned int));
  for (i=0; i<PARASIZE; i++) (pk->para[i])=para[i];
  pk->G = matrix_init(para[1], para[0]+para[2]-para[1]); /* k\times (n+w)-k */
  return pk;
}

void RLCE_free_pk(RLCE_public_key_t pk) {
  free(pk->para);
  if (pk->G != NULL) matrix_free(pk->G);
  free(pk);
  pk=NULL;
}

int pk2B (RLCE_public_key_t pk, unsigned char pkB[], unsigned int *blen) {
  int i, ret;
  if (blen[0]<pk->para[18]) return KEYBYTE2SMALL;
  pkB[0]= (pk->para[10])|(pk->para[9]<<4);
  unsigned int nplusw=pk->para[0]+pk->para[2];
  unsigned int k=pk->para[1];
  unsigned int pkLen=k*(nplusw-k);
  vector_t FE=vec_init(pkLen);
  for (i=0;i<k;i++) memcpy(&(FE->data[i*(nplusw-k)]),(pk->G)->data[i],(nplusw-k)*sizeof(field_t));
  blen[0] = (pkLen*(pk->para[3]))/8;
  if ((pkLen*(pk->para[3]))%8 > 0) blen[0]++;
  if ((pk->para[3])==10) ret=FE2B10(FE, &pkB[1], blen[0]);
  if ((pk->para[3])==11) ret=FE2B11(FE, &pkB[1], blen[0]);
  if (ret<0) return ret;
  vector_free(FE);
  blen[0]++;
  return 0;
}

int sk2B (RLCE_private_key_t sk, unsigned char skB[], unsigned int *blen) {
  unsigned int sklen =sk->para[17];
  if (blen[0]<sklen) return KEYBYTE2SMALL;
  int i,j,ret;
  int n=sk->para[0];
  int k=sk->para[1];
  int w=sk->para[2];
  skB[0]= (sk->para[10])|(sk->para[9]<<4);
  j=1;
  for (i=0;i<n;i++) {
    skB[j]=(((sk->perm1)->data[i])>>8);
    skB[j+1]=(sk->perm1)->data[i];
    j=j+2;
  }
  j=1+2*n;
  for (i=0;i<n+w;i++) {
    skB[j]=(((sk->perm2)->data[i])>>8);
    skB[j+1]=(sk->perm2)->data[i];
    j=j+2;
  }
  j=0;
  unsigned int invSLen=0;
  if (DECODINGMETHOD!=2) invSLen= ((sk->S)->numR) *  ((sk->S)->numC);
  unsigned int totalFELen=2*w+invSLen+n+k*(n+w-k);
  vector_t FE=vec_init(totalFELen);
  for (i=0; i<w; i++) {
    FE->data[j]=((sk->A)->A[i])->data[0][0];
    FE->data[j+1]=((sk->A)->A[i])->data[1][0];
    j=j+2;
  }
  if (invSLen>0) {
    for (i=0;i<(sk->S)->numR; i++) {
      memcpy(&(FE->data[j]),(sk->S)->data[i],((sk->S)->numC)*sizeof(field_t));
      j=j+(sk->S)->numC;
    }
  }
  memcpy(&(FE->data[j]),(sk->grs)->data,n*sizeof(field_t));
  j=j+n;
  for (i=0;i<sk->para[1]; i++) {
    memcpy(&(FE->data[j]),(sk->G)->data[i],(n+w-k)*sizeof(field_t));
    j=j+n+w-k;  
  }
  int byteLen = totalFELen*(sk->para[3])/8;
  if ((totalFELen*(sk->para[3]))%8 > 0) byteLen++;
  if (sklen != (4*n+2*w+1+byteLen)) return SKWRONG;
  if ((sk->para[3])==10) ret=FE2B10(FE, &skB[4*n+2*w+1], byteLen);
  if ((sk->para[3])==11) ret=FE2B11(FE, &skB[4*n+2*w+1], byteLen);
  if (ret<0) return ret;    
  vector_free(FE);
  return 0;
}

RLCE_public_key_t B2pk(const unsigned char binByte[], unsigned long long blen) {
  int i,ret=0;
  unsigned int scheme=binByte[0] & 0x0F;
  unsigned int padding=binByte[0]>>4;
  unsigned int para[PARASIZE];
  ret=getRLCEparameters(para, scheme,padding);
  if (ret<0) return NULL;
  RLCE_public_key_t pk = RLCE_public_key_init(para);
  unsigned int nplusw=pk->para[0]+pk->para[2];
  unsigned int k=pk->para[1];
  unsigned int pkLen=k*(nplusw-k);
  vector_t FE=vec_init(pkLen);
  int byteLen = (pkLen*(pk->para[3]))/8;
  if ((pkLen*(pk->para[3]))%8 > 0) byteLen++;
  if (byteLen>blen-1) return NULL;
  if ((pk->para[3])==10) ret=B2FE10((unsigned char*)&(binByte[1]), byteLen,FE);
  if ((pk->para[3])==11) ret=B2FE11((unsigned char*)&(binByte[1]), byteLen,FE);
  if (ret<0) return NULL;
  for (i=0;i<k;i++) memcpy((pk->G)->data[i], &(FE->data[i*(nplusw-k)]),(nplusw-k)*sizeof(field_t));
  vector_free(FE);
  return pk;
}

RLCE_private_key_t B2sk(const unsigned char binByte[], unsigned long long blen) {
  unsigned int scheme=binByte[0] & 0x0F;
  unsigned int padding=binByte[0]>>4;
  unsigned int para[PARASIZE];  
  getRLCEparameters(para, scheme,padding);
  RLCE_private_key_t sk = RLCE_private_key_init (para);
  int sklen =sk->para[17];
  if (blen<sklen) {
    RLCE_free_sk(sk);
    return NULL;
  }
  int i,j,ret;
  int n=sk->para[0];
  int k=sk->para[1];
  int w=sk->para[2];
  int SnumR=0, SnumC=0;
  if (DECODINGMETHOD!=2) {
    SnumR=k;
    SnumC=sk->para[15]+1;
  }  
  unsigned int invSLen=0;
  if (DECODINGMETHOD!=2) invSLen= SnumR * SnumC;
  unsigned int totalFELen=2*w+invSLen+n+k*(n+w-k);
  vector_t FE=vec_init(totalFELen);
  int permByteLen=4*n+2*w;
  j=1;  
  for (i=0;i<sk->para[0];i++) {
    (sk->perm1)->data[i]=binByte[j];
    (sk->perm1)->data[i]=((sk->perm1)->data[i]<<8);
    (sk->perm1)->data[i]= (binByte[j+1] | (sk->perm1)->data[i]);
    j=j+2;
  }
  j=2*n+1;
  for (i=0;i<n+w;i++) {
    (sk->perm2)->data[i]=binByte[j];
    (sk->perm2)->data[i]=((sk->perm2)->data[i]<<8);
    (sk->perm2)->data[i]=((sk->perm2)->data[i]|binByte[j+1]);
    j=j+2;
  }
  (sk->perm1)->size=n;
  (sk->perm2)->size=n+w;
  
  int byteLen = totalFELen*(sk->para[3])/8;
  if ((totalFELen*(sk->para[3]))%8 > 0) byteLen++;
  if (byteLen>blen-permByteLen-1) return NULL;  
  if ((sk->para[3])==10) ret=B2FE10((unsigned char*)&(binByte[permByteLen+1]), byteLen,FE);
  if ((sk->para[3])==11) ret=B2FE11((unsigned char*)&(binByte[permByteLen+1]), byteLen,FE);
  if (ret<0) return NULL;
  j=0;
  for (i=0; i<w; i++) {
    ((sk->A)->A[i])->data[0][0]=FE->data[j];
    ((sk->A)->A[i])->data[1][0]=FE->data[j+1];
    j=j+2;
  }
  j=2*w;
  if (invSLen>0) {
    for (i=0;i<SnumR; i++) {
      memcpy((sk->S)->data[i],&(FE->data[j]),SnumC*sizeof(field_t));
      j=j+SnumC;
    }
  }
  j=2*w+invSLen;
  memcpy((sk->grs)->data,&(FE->data[j]),n*sizeof(field_t));
  j=2*w+invSLen+n;
  for (i=0;i<k;i++) {
    memcpy((sk->G)->data[i],&(FE->data[j]),(n+w-k)*sizeof(field_t));
    j=j+n+w-k;  
  }  
  vector_free(FE);
  return sk;
}

int RLCE_key_setup (unsigned char entropy[], int entropylen,
		    unsigned char nonce[], int noncelen,
		    RLCE_public_key_t pk, RLCE_private_key_t sk) {
  int ret=0;
  int m=sk->para[3];
  int n=sk->para[0];
  int k= sk->para[1];
  int w=sk->para[2];
  int nplusw=n+w;
  int nminusw=n-w;
  int i,j;
  int nRE=n+(4+k)*w+25;
  int nRBforRE =(m*nRE)/8;
  if ((m*nRE)%8 >0) nRBforRE++;

  int nRB = nRBforRE +4*n+2*w;
  unsigned char *randomBytes=calloc(nRB, sizeof(unsigned char));  

  unsigned char pers[] ="PostQuantumCryptoRLCEversion2017";
  int perlen = sizeof(pers)-1;
  unsigned char addS[]="GRSbasedPostQuantumENCSchemeRLCE";
  int addlen = sizeof(addS)-1;  
  if (DRBG==0) {  
    char noncehex[] = "5e7d69e187577b0433eee8eab9f77731";
    unsigned char newnonce[16];
    if (noncelen==0) {
      hex2char(noncehex, newnonce, 16);
      noncelen=16;
      if (nonce != NULL) free(nonce);
      nonce=newnonce;
    }  
    hash_drbg_state_t drbgState;
    drbgState=drbgstate_init(sk->para[4]);
    drbg_Input_t drbgInput;
    drbgInput=drbgInput_init(entropy,entropylen,nonce,noncelen,pers,perlen,addS,addlen);
    ret=hash_DRBG(drbgState,drbgInput,randomBytes, nRB);
    free_drbg_state(drbgState);
    free_drbg_input(drbgInput);
    if (ret<0) return ret;
  }
  if (DRBG==1) { 
    ctr_drbg_state_t drbgState;
    drbgState=ctr_drbgstate_init(sk->para[14]);
    drbg_Input_t drbgInput;
    drbgInput=drbgInput_init(entropy,entropylen,nonce,0,pers,perlen,addS,addlen);
    ret=ctr_DRBG(drbgState,drbgInput,randomBytes, nRB);
    free_ctr_drbg_state(drbgState);
    free_drbg_input(drbgInput);
    if (ret<0) return ret;   
  }
  if (DRBG==2) {
    int mgfseedLen=entropylen+perlen+addlen;
    unsigned char *mgfseed=calloc(mgfseedLen, sizeof(unsigned char));
    memcpy(mgfseed, entropy, entropylen*sizeof(unsigned char));
    memcpy(&mgfseed[entropylen], pers, perlen*sizeof(unsigned char));
    memcpy(&mgfseed[entropylen+perlen], addS, addlen*sizeof(unsigned char));
    RLCE_MGF512(mgfseed,mgfseedLen,randomBytes, nRB);     
  }

  field_t randE[nRE];  
  ret=randomBytes2FE(randomBytes, nRBforRE, randE,nRE,m);
  if (ret<0) return ret;
  vector_t per1 =getPermutation(n,n-1, &randomBytes[nRBforRE], 2*n-2);
  vector_t per1inv=permu_inv(per1);
  vector_copy(per1inv, sk->perm1);

  int done=0;
  unsigned short errorClearedNumber=0;
  vector_t per2,per2inv;
  unsigned short remDim;
  unsigned short *unknownIndex=calloc(k, sizeof(unsigned short));
  unsigned short *knownIndex=calloc(k, sizeof(unsigned short));
  unsigned short index1=0;
  unsigned short index2=0;    
  while (done >=0 ){
    errorClearedNumber=0;
    index1=0;
    index2=0;
    per2 =getPermutation(nplusw,nplusw-1,&randomBytes[nRBforRE+2*n-2+done], 2*nplusw-2);
    if (per2==NULL) return GETPERERROR;
    for (i=0; i<k; i++) {
      if (per2->data[i]<nminusw) {
	knownIndex[index2]=i;
	index2++;
	errorClearedNumber++;
      } else {
	unknownIndex[index1]=i;
	index1++;
      }
    }
    remDim=k-errorClearedNumber;
    if (remDim <=sk->para[15]) {
      per2inv=permu_inv(per2);
      vector_copy(per2inv, sk->perm2);
      done=-1;
    } else done++;
  }
  free(randomBytes);
  
  field_t *grsvec=calloc(n, sizeof(field_t));
  j=0;
  for (i=0;i<n; i++) {
    while (randE[j]==0) j++;
    grsvec[i]=randE[j];
    j++;
  }
  
  GF_vecinverse(grsvec,(sk->grs)->data,n, m);
  matrixA_t A=matrixA_init(w);
  ret=getMatrixAandAinv(A,sk->A,&randE[n+5],4*w+20,m);
  if(ret<0) return ret;

  poly_t generator=poly_init(n);
  generator=genPolyTable(n-k); 
  matrix_t G2= NULL;
  matrix_t optG = matrix_init(nplusw, k);
  GF_rsgenerator2optG(optG, generator,grsvec, m);
    field_t **tmprow;
    tmprow=calloc(n, sizeof(int*));
    for (i=0;i<n;i++) tmprow[i]=optG->data[i];	   
    for (i=0;i<n;i++) optG->data[i]=tmprow[per1->data[i]];
    free(tmprow);
    tmprow=calloc(2*w, sizeof(int*));
    for (i=0;i<2*w;i++) tmprow[i]=optG->data[nminusw+i];
    
    for (i=0;i<w;i++) {
      optG->data[nminusw+2*i]=tmprow[i];
      optG->data[nminusw+2*i+1]=tmprow[w+i];
      memcpy(optG->data[nminusw+2*i+1], &(randE[n+4*w+25+k*i]), k*sizeof(field_t));
    }
    free(tmprow);
    matrix_opt_mul_A(optG, A, nminusw, m);
    tmprow=calloc(nplusw, sizeof(int*));
    for (i=0;i<nplusw;i++) tmprow[i]=optG->data[i];		 
    for (i=0;i<nplusw;i++) optG->data[i]=tmprow[per2->data[i]];
    free(tmprow);
    G2=matrix_init(k, nplusw);
    for (i=0;i<k;i++) for (j=0;j<nplusw;j++) G2->data[i][j]=optG->data[j][i];
    matrix_free(optG);
  free(grsvec);
  poly_free(generator);
  vector_free(per2inv);
  vector_free(per2);

  if (DECODINGMETHOD==0){
    for (i=0; i<G2->numR; i++)
      //memcpy((sk->S)->data[i],(G2->data)[i],(G2->numR)*sizeof(field_t));
      for (j=0; j<remDim; j++)
	(sk->S)->data[i][j]=(G2->data)[i][unknownIndex[j]];
  }
  ret=matrix_echelon(G2, m);
  if (ret<0) return ECHELONFAIL;
  for (i=0; i<k; i++) {
    memcpy((sk->G)->data[i], &(G2->data[i][k]), (nplusw-k)*sizeof(field_t));
    memcpy((pk->G)->data[i], &(G2->data[i][k]), (nplusw-k)*sizeof(field_t));
  }
  if (DECODINGMETHOD==1) {
    matrix_t W=matrix_init(remDim, 2*remDim);
    for (i=0; i<remDim; i++) W->data[i][remDim+i]=1;
    int workingIndexBase=0;
    int workingIndex=0;
    int listCtr=0;
    int test=1;
    int notdone = 1;
    int ti=0;
    while (notdone) {
      workingIndex = workingIndexBase;
      for (i=0; i<remDim; i++) {
	test = 1;
	while (test) {
	  if  ((sk->perm2)->data[workingIndex]<k) {
	    workingIndex++;
	    if (workingIndex >n-w-1) return DECODING2NOTINVERTIBLE;
	  } else test=0;
	}
	(sk->S)->data[listCtr][remDim]=workingIndex;
	listCtr++;
	ti=(sk->perm2)->data[workingIndex]-k;
	for (j=0; j<remDim; j++)
	  W->data[j][i]=(sk->G)->data[unknownIndex[j]][ti];
	for (j=0; j<errorClearedNumber; j++)
	  (sk->S)->data[remDim+j][i]=(sk->G)->data[knownIndex[j]][ti];
	workingIndex++;
      }
      ret= matrix_echelon(W, m);
      if (ret<0) {
	workingIndexBase++;
	listCtr=0;
	for (i=0; i<remDim; i++) {
	  memset(&(W->data[i][remDim]), 0, remDim*sizeof(field_t));
	  W->data[i][remDim+i]=1;
	}
      } else notdone=0;
    }
    for (i=0; i<remDim;i++)
      memcpy((sk->S)->data[i], &W->data[i][remDim], remDim*sizeof(field_t));
    matrix_free(W);
  }  
  free(unknownIndex);
  free(knownIndex);
  matrix_free(G2);
  vector_free(per1inv);
  vector_free(per1);  
  matrixA_free(A);
  return 0;
}

int RLCE_encrypt(unsigned char msg[], unsigned long long msgLen,
                 unsigned char entropy[], unsigned int entropylen,
		 unsigned char nonce[], unsigned int noncelen,
                 RLCE_public_key_t pk, unsigned char cipher[], unsigned long long *clen){
  unsigned char pers[] ="PQENCRYPTIONRLCEver1";
  int perslen = sizeof(pers)-1;
  unsigned char add[]="GRSbasedPQEncryption0";
  int addlen = sizeof(add)-1;
  add[addlen-1]=0x00;
  int n=pk->para[0];
  int k=pk->para[1];
  int w=pk->para[2];
  int t = pk->para[11];
  int m=pk->para[3];
  int nplusw=n+w;
  unsigned int kPlust=k+t; 
  vector_t errValue=vec_init(t);
  field_t errLocation[t];
  vector_t FE_vec;

  int CTRPADDRBG=1; /* 0 for SHA-512, 1 for AES */
  if (pk->para[14]>192) CTRPADDRBG=0;

  /* pk->para[9]: 0,1 -> mediumEncoding */
  /* pk->para[9]: 2,3 -> basicEncoding */
  if ((pk->para[9] == 0) || (pk->para[9] == 1)) { 
    FE_vec =vec_init(kPlust);
  } else if ((pk->para[9] == 2) || (pk->para[9] == 3)) { 
    FE_vec =vec_init(k);
  } else return NOTIMPLEMENTEDYET;

  int ret=0, i,j;
  int nRB0=0, nRB1=0,nRB=0;
  nRB0=pk->para[8]+2*t;
  if ((pk->para[9] == 2) || (pk->para[9] == 3)) {
    nRB1 =(m*(t+10))/8;
    if ((m*(t+10))%8 >0) nRB1++;
  }
  nRB=nRB0+nRB1;
  unsigned char * randBytes;
  randBytes = (unsigned char *) calloc(nRB, sizeof(unsigned char));
  unsigned char * padrand;
  padrand =  (unsigned char *) calloc(pk->para[8], sizeof(unsigned char));
  hash_drbg_state_t drbgState=NULL;
  ctr_drbg_state_t ctrdrbgState=NULL;
  drbg_Input_t drbgInput=NULL;

  if ((CTRPADDRBG==0)&&(DRBG!=2)){
    unsigned char nonceAppend[]="RLCEencNonceVer1";
    int nonceAppendlen = sizeof(nonceAppend)-1;
    unsigned char noncenew[noncelen+nonceAppendlen];
    if (noncelen >0) memcpy(noncenew, nonce, noncelen);
    memcpy(&noncenew[noncelen], nonceAppend, nonceAppendlen);
    noncelen=noncelen+nonceAppendlen;
    drbgState=drbgstate_init(pk->para[4]);
    drbgInput=drbgInput_init(entropy,entropylen,noncenew,noncelen,pers,perslen,add,addlen);    
    ret=hash_DRBG_Instantiate(drbgState, drbgInput);
    if (ret<0) return ret;
  }
  if ((CTRPADDRBG==1)&&(DRBG!=2)){
    ctrdrbgState=ctr_drbgstate_init(pk->para[14]);
    drbgInput=drbgInput_init(entropy,entropylen,nonce,0,pers,perslen,add,addlen);
    ret=ctr_DRBG_Instantiate_algorithm(ctrdrbgState, drbgInput);
    if (ret<0) return ret;
  }
  int mgfseedLen=entropylen+perslen+addlen;
  unsigned char *mgfseed=calloc(mgfseedLen, sizeof(unsigned char));
  if (DRBG==2) {
    memcpy(mgfseed, entropy, entropylen*sizeof(unsigned char));
    memcpy(&mgfseed[entropylen], pers, perslen*sizeof(unsigned char));
    memcpy(&mgfseed[entropylen+perslen], add, addlen*sizeof(unsigned char));
  }
  unsigned int ctr=0;
  unsigned short repeat = 1;
  int paddedLen= paddedLen=pk->para[6]+pk->para[7]+pk->para[8];
  unsigned char *paddedMSG=calloc(paddedLen, sizeof(unsigned char));
  while (repeat) { /* this loop makes sure that errors will not be zero */
    repeat = 0;    
    if ((CTRPADDRBG==0)&&(DRBG!=2)) hash_DRBG_Generate(drbgState, drbgInput,randBytes,nRB);
    if ((CTRPADDRBG==1)&&(DRBG!=2)) ctr_DRBG_Generate(ctrdrbgState,drbgInput,randBytes,nRB);    
    if (DRBG==2) {
      memcpy(&mgfseed[entropylen+perslen], add, addlen*sizeof(unsigned char));
      RLCE_MGF512(mgfseed,mgfseedLen,randBytes, nRB);
    }
    ctr++;
    add[addlen-1]=(ctr & 0xFF);
    memcpy(padrand, randBytes, pk->para[8]);
    /* BEGIN get positions for t-errors */   
    vector_t per =getPermutation(nplusw,t,&randBytes[pk->para[8]], 2*t);
    memcpy(errLocation, per->data, t * sizeof(field_t));
    vector_free(per);
    /*BEGIN sort errLocation */
    field_t *tempArray=calloc(nplusw, sizeof(field_t));
    for (i=0; i<t; i++) tempArray[errLocation[i]]=1;
    /* if error locations are: l_0<l_1<...<l_{t-1} then
     * e0=l_0||l_1||...||l_t where each l_i is two bytes*/
    int tmpidx =0;
    int e0Len = 4*t;
    unsigned char e0[e0Len];
    int usede0Len = 2*t; /*  mediumPadding: usede0Len = 2*t */
    for (i=0; i<nplusw; i++) {
      if (tempArray[i]==1) {
	errLocation[tmpidx]=i;
	e0[2*tmpidx]= (i>>8) & 0xFF;
	e0[2*tmpidx+1]= i & 0xFF;
	tmpidx++;
      }
    }
    free(tempArray);
    /* END get positions for t-errors */

    /* if basic Encoding, error values within e0 */
    if ((pk->para[9] == 2)||(pk->para[9] == 3)) {
      usede0Len = 4*t; /* basicPadding: usede0Len = 4*t */
      field_t bEncErr[t+10];
      ret=randomBytes2FE(&randBytes[nRB0], nRB1, bEncErr,t+10,m);
      if (ret<0) return ret;
      j=0;
      for (i=0; i<t+10; i++) {
	if ((bEncErr[i] != 0) && (j<t)) {
	  errValue->data[j]=bEncErr[i];
	  e0[2*(t+j)]= (bEncErr[i]>>8); 
	  e0[2*(t+j)+1]= bEncErr[i]; 
	  j++;
	}
      }
      repeat=0;
      if (j<t) repeat = 1;
    }
    if ((pk->para[9] == 2) || (pk->para[9] == 0)) { /* RLCEspad  */
	ret=RLCEspad(msg, pk->para[6],paddedMSG,paddedLen,pk,padrand,pk->para[8], e0, usede0Len);
	if (ret<0) return ret;
    } else { /* RLCEpad ((pk->para[9] == 1) || (pk->para[9] == 3)) */
      ret=RLCEpad(msg, pk->para[6],paddedMSG,paddedLen,pk,padrand,pk->para[8],e0,usede0Len);
      if (ret<0) return ret;
    }
    if (m==10) ret=B2FE10(paddedMSG,paddedLen, FE_vec);
    if (m==11) ret=B2FE11(paddedMSG,paddedLen, FE_vec);
    if (ret<0) return ret;
    
    if ((pk->para[9] == 0) || (pk->para[9] == 1)) {
      memcpy(errValue->data, &(FE_vec->data[k]), t*sizeof(field_t));
      for (i=0; i<t; i++) {
	if (errValue->data[i]==0) repeat=1;
      }
    }
  }

    
  free(paddedMSG);
  free(randBytes);
  if (drbgState !=NULL) free_drbg_state(drbgState);
  if (ctrdrbgState != NULL) free_ctr_drbg_state(ctrdrbgState);
  free(mgfseed);
  free_drbg_input(drbgInput);
  free(padrand);

  vector_t cipherFE=vec_init(nplusw);
  memcpy(cipherFE->data, FE_vec->data, k * sizeof(field_t));
  matrix_vec_mat_mul(FE_vec->data,k,pk->G,&(cipherFE->data[k]),nplusw-k,m);
  for (i=0; i<t; i++) cipherFE->data[errLocation[i]] ^= errValue->data[i];
  vector_free(FE_vec);
  vector_free(errValue);
  
  if (cipher==NULL) return CIPHERNULL;
  if (clen==NULL) return CIPHERNULL;
  if (clen[0]<pk->para[16]) return CIPHER2SMALL;
  if ((pk->para[3])==10) ret=FE2B10(cipherFE, cipher, clen[0]);
  if ((pk->para[3])==11) ret=FE2B11(cipherFE, cipher, clen[0]);
  vector_free(cipherFE);
  return 0;
}

int recoverRem(int ex, field_t eLocationIndicator[],field_t dest[],RLCE_private_key_t sk) {
  int n=sk->para[0];
  int k=sk->para[1];
  int w=sk->para[2];
  int m=sk->para[3];
  int i,j,ret;
  int errClearPos=0;
  if (ex>0) {
    for (i=0; i<k;i++) if (eLocationIndicator[i]<3) errClearPos++;
  } else {
    for (i=0; i<k;i++) if (eLocationIndicator[i]<2) errClearPos++;
  }
  int remDim=k-errClearPos;
  unsigned short unknownIndex[remDim];
  unsigned short knownIndex[errClearPos];
  unsigned short index1=0, index2=0;
  if (ex>0) {
    for (i=0; i<k;i++) {
      if (eLocationIndicator[i]>2){
	unknownIndex[index1++]=i;
      } else knownIndex[index2++]=i;
    }
    int ctr=0;
    for (i=k; i<n+w-1;i++) if (eLocationIndicator[i]<3) ctr++;
    if (ctr-remDim<ex) ex=ctr-remDim;
  } else {
    for (i=0; i<k;i++) {
      if (eLocationIndicator[i]>1){
	unknownIndex[index1++]=i;
      } else knownIndex[index2++]=i;
    }
  }
  
  field_t *clearedmsg=calloc(errClearPos, sizeof(field_t)); 
  for (i=0;i<errClearPos; i++) clearedmsg[i]=dest[knownIndex[i]];
  matrix_t W=matrix_init(remDim+ex, remDim+1);
  matrix_t U=matrix_init(1+errClearPos, remDim+ex);  
  index1=k;
  int test=1;
  int notdone = 1;
  while (notdone) {
    index2 = index1;
    for (i=0; i<W->numR; i++) {
      test = 1;
      while (test) {
	if (eLocationIndicator[index2]>1) {
	  if (index2++>n+w-1) return NOTENOUGHGOODCOL;
	} else test=0;
      }
      for (j=0;j<remDim;j++) W->data[i][j]=(sk->G)->data[unknownIndex[j]][index2-k];
      for (j=0;j<errClearPos;j++) U->data[j][i]=(sk->G)->data[knownIndex[j]][index2-k];
      U->data[errClearPos][i]=dest[index2++];
    }
    for (j=0;j<U->numR-1;j++) {
      GF_mulvec(clearedmsg[j], U->data[j],NULL,U->numC,m);
    }
    for (j=0;j<U->numR-1;j++) GF_addvec(U->data[j],U->data[j+1],NULL,U->numC);
    for (j=0;j<U->numC;j++) W->data[j][remDim]=U->data[errClearPos][j];
    ret=matrix_echelon(W,m);
    if (ex>0) {
      if ((ret<0) && (ret >-remDim)) {
	index1++;
      } else notdone=0;
    } else {
      if (ret<0) {
	index1++;
      } else notdone=0;
    }
  }
  if (ex>0) {
    if (ret ==-remDim) {
      for (i=0;i<remDim;i++) dest[unknownIndex[i]]=W->data[i][remDim];
      ret = 0;
    }
  } else {
    for (i=0;i<remDim;i++) dest[unknownIndex[i]]=W->data[i][remDim];
  }
  free(clearedmsg);
  matrix_free(U);
  matrix_free(W);
  return ret;
}

int RLCE_decrypt(unsigned char cipher[], unsigned long long clen, RLCE_private_key_t sk, unsigned char msg[],
		 unsigned long long *mlen){
  if (sk==NULL) return SKNULL;
  int n=sk->para[0];
  int k=sk->para[1];
  int w=sk->para[2];
  int m=sk->para[3];
  int t=sk->para[11];
  int codeLen = (1u<< m) -1;
  int zeroLen = codeLen - n;
  int codeDim = k+zeroLen;
  int nplusw = n+w;
  int nminusw = n-w;
  int i, j, ii, ret;
  vector_t cipherFE=vec_init(nplusw);
  if ((sk->para[3])==10) ret=B2FE10(cipher, clen, cipherFE);
  if ((sk->para[3])==11) ret=B2FE11(cipher, clen, cipherFE);
  if (ret<0) return CIPHERSIZEWRONG;  
    
  field_t *cp=calloc(nplusw, sizeof(field_t));
  for (j=0; j<nplusw; j++) cp[j]=cipherFE->data[(sk->perm2)->data[j]];
  field_t *C1=calloc(n, sizeof(field_t));
  memcpy(C1, cp, nminusw*sizeof(field_t));
  GF_mulAinv(&(cp[nminusw]), sk->A, &(C1[nminusw]), m);
  /* cp task done, now we use it for other purpose. only n elements used */
  for (j=0; j<n; j++) cp[j]=C1[(sk->perm1)->data[j]];
  free(C1);
  GF_vecvecmul((sk->grs)->data,cp,NULL,(sk->grs)->size,m);
  poly_t decodedWord=NULL;
  field_t *eLocation=calloc(n-k, sizeof(field_t));
    poly_t code=NULL;
    code=poly_init(codeLen); 
    memcpy(&(code->coeff[zeroLen]), cp, n * sizeof(field_t));
    poly_deg(code);
    decodedWord=rs_decode(DECODER, code, codeLen, codeDim, eLocation,m);
    poly_free(code);
  free(cp);
  field_t *eLocationIndicator=calloc(nplusw, sizeof(field_t));
  int numRoots=0;
  for (i=0; i<n-k; i++) {
    if (eLocation[i]>=zeroLen) {
      eLocationIndicator[eLocation[i]-zeroLen]=1;
      numRoots++;
    }
  }
  free(eLocation);
  
  field_t *dest=calloc(nplusw, sizeof(field_t)); /* dest contains field elements that were encrypted */
  field_t *eLocationAfterP1=calloc(n, sizeof(field_t));
  field_t *cipherB4A=calloc(nminusw, sizeof(field_t));
  field_t *decodedGRS;
  field_t *grsinv=calloc(n, sizeof(field_t));
  decodedGRS=grsinv;
  GF_vecinverse((sk->grs)->data, grsinv, n, m);
  GF_vecvecmul(&decodedWord->coeff[zeroLen],grsinv,decodedGRS,n,m);
  for (i=0; i<n; i++)
    if ((sk->perm1)->data[i]<nminusw) cipherB4A[(sk->perm1)->data[i]]=decodedGRS[i];
  free(grsinv);
  for (i=0;i<n;i++) eLocationAfterP1[(sk->perm1)->data[i]]=eLocationIndicator[i];
  memset(eLocationIndicator, 0, nplusw*sizeof(field_t));
  
  vector_t perm2=permu_inv(sk->perm2);
  unsigned short errClearPos=0;
  int remDim;
  unsigned short *unknownIndex=NULL;
  unsigned short *knownIndex=NULL;
  for (i=0;i<nminusw;i++) {
    dest[(sk->perm2)->data[i]]=cipherB4A[i];
    eLocationIndicator[(sk->perm2)->data[i]]=eLocationAfterP1[i];
    if ((sk->perm2)->data[i]<k) errClearPos++;
  }
  for (i=0; i<w; i++) {
    eLocationIndicator[(sk->perm2)->data[nminusw+2*i]]=2+eLocationAfterP1[nminusw+i];
    eLocationIndicator[(sk->perm2)->data[nminusw+2*i+1]]=2+eLocationAfterP1[nminusw+i];
  }

  field_t *tmpvec=NULL;
  if (DECODINGMETHOD != 2) {
    unsigned short index1=0;
    unsigned short index2=0;
    remDim=k-errClearPos;
    unknownIndex =calloc(remDim, sizeof(unsigned short));
    knownIndex =calloc(errClearPos, sizeof(unsigned short));
    for (i=0; i<k; i++) {
      if (perm2->data[i]<nminusw) {
	knownIndex[index2]=i;
	index2++;
      } else {
	unknownIndex[index1]=i;
	index1++;
      }
    }
    tmpvec=calloc(remDim, sizeof(field_t));
  }  
  if (DECODINGMETHOD==0) {
    poly_t q=poly_init(codeLen);
    poly_t generator=genPolyTable(n-k);
    ret=poly_quotient(decodedWord, generator, q, m);
    poly_free(generator);
    if (ret<0) return ret;
    matrix_vec_mat_mul(&(q->coeff[zeroLen]),k,sk->S,tmpvec,remDim, m);
    for (i=0; i<remDim; i++) dest[unknownIndex[i]]=tmpvec[i];
    poly_free(q);    
  }  
  poly_free(decodedWord);
  
  if (DECODINGMETHOD==1) {
    matrix_t W=matrix_init(remDim, remDim);
    matrix_t X=matrix_init(errClearPos, remDim);
    for (i=0;i<remDim;i++) memcpy(W->data[i], (sk->S)->data[i], remDim*sizeof(field_t));
    for (i=0;i<errClearPos;i++) 
      memcpy(X->data[i], (sk->S)->data[remDim+i], remDim*sizeof(field_t));    
    field_t *tmp2vec;
    field_t *knownvec;
    tmp2vec=calloc(remDim, sizeof(field_t));
    knownvec=calloc(errClearPos, sizeof(field_t));
    for (i=0; i<errClearPos; i++) knownvec[i]=dest[knownIndex[i]];
    matrix_vec_mat_mul(knownvec,errClearPos,X, tmpvec,remDim, m);
    for (i=0; i<remDim; i++) tmpvec[i] ^= cipherB4A[(sk->S)->data[i][remDim]];
    matrix_vec_mat_mul(tmpvec,remDim, W, tmp2vec,remDim,m);
    for (i=0;i<remDim; i++) dest[unknownIndex[i]]=tmp2vec[i];
    free(knownvec);
    free(tmp2vec);
    matrix_free(W);
    matrix_free(X);
  }
  
  if (unknownIndex!=NULL) free(unknownIndex);
  if (knownIndex!=NULL) free(knownIndex);
  if (tmpvec !=NULL) free(tmpvec);
  
  if (DECODINGMETHOD==2) {
    for (i=0;i<k;i++) if (eLocationIndicator[i]==2) dest[i]=cipherFE->data[i];
    ret=recoverRem(t-numRoots,eLocationIndicator,dest,sk);
    if (ret!=0) ret=recoverRem(0,eLocationIndicator,dest,sk);
    if (ret<0) return ret;
  }

  /* Errors and error locations */
  unsigned int errLocation[t];
  memset(errLocation, 0, t*sizeof(unsigned int));
  vector_t errValue=vec_init(t);
    field_t sum=0;
    int tmpidxP=0;
    field_t *errValueTemp=calloc(nplusw-k, sizeof(field_t));
    for (i=0; i<k;i++) {
      if ((cipherFE->data[i])!=(dest[i])) {
	if (tmpidxP>=t) return TOOMANYERRORS;
	errLocation[tmpidxP]=i;
	errValue->data[tmpidxP]= (cipherFE->data[i]) ^ (dest[i]);
	tmpidxP++;
      }
    }
    int tmpidxPk=tmpidxP;
    matrix_t GE;
    int errCandidateNo=0;
    for (i=k; i<nplusw; i++) if (eLocationIndicator[i]==3) errCandidateNo++;
    GE=matrix_init(k, errCandidateNo);
    ii=0;
    for (j=k; j<nplusw;j++) {
      if (eLocationIndicator[j]==3) {
	for (i=0; i<k;i++) GE->data[i][ii]=(sk->G)->data[i][j-k];
	ii++;
      }
    }
    GF_mulvec(dest[k-1], GE->data[k-1], NULL,GE->numC, m);
    for (i=0;i<k-1;i++) {
      GF_mulvec(dest[i], GE->data[i],NULL,GE->numC, m);
      GF_addvec(GE->data[i],GE->data[k-1],NULL,GE->numC);
    }
    ii=0;
    for (j=k;j<nplusw;j++){
      if (eLocationIndicator[j]==1) {
	if (tmpidxP>=t) return TOOMANYERRORS;
	errLocation[tmpidxP]=j;
	errValue->data[tmpidxP]= cipherFE->data[j] ^ cipherB4A[perm2->data[j]];
	errValueTemp[j-k]=errValue->data[tmpidxP];
	tmpidxP++;
      }
      if (eLocationIndicator[j]==3) {
	if (GE->data[k-1][ii] != cipherFE->data[j]) {
	  if (tmpidxP>=t) return TOOMANYERRORS;
	  errLocation[tmpidxP]=j;
	  errValue->data[tmpidxP]=(GE->data[k-1][ii])^(cipherFE->data[j]);
	  errValueTemp[j-k]=errValue->data[tmpidxP];
	  tmpidxP++;
	}
	ii++;
      }
    }
    matrix_free(GE);
    if (tmpidxP<t) {
      tmpidxP=tmpidxPk;
      errCandidateNo=0;
      for (i=k; i<nplusw; i++) if (eLocationIndicator[i]==2) errCandidateNo++;
      matrix_t tmpG=matrix_init(k,errCandidateNo);
      int tmpnumC=0;
      for (j=k;j<nplusw;j++){
	if (eLocationIndicator[j]== 2) {
	  for (i=0; i<k;i++) tmpG->data[i][tmpnumC]=(sk->G)->data[i][j-k];
	  tmpnumC++;
	}
      }
      field_t *tmpVV=calloc(tmpnumC, sizeof(field_t));
      ret=matrix_vec_mat_mul(dest,k,tmpG, tmpVV,tmpnumC,m);
      int ttmm = 0;
      for (i=k;i<nplusw;i++){
	if (eLocationIndicator[i]==2) {
	  sum = cipherFE->data[i] ^ tmpVV[ttmm];
	  ttmm++;
	  if (sum != 0) {
	    if (tmpidxP>t-1) return TOOMANYERRORS;
	    errLocation[tmpidxP]=i;
	    errValue->data[tmpidxP]= sum;
	    tmpidxP++;
	  }
	} else {
	  if (errValueTemp[i-k]!=0) {
	    if (tmpidxP>=t) return TOOMANYERRORS;
	    errLocation[tmpidxP]=i;
	    errValue->data[tmpidxP]= errValueTemp[i-k];
	    tmpidxP++;
	  }
	}
      }
      free(tmpVV);
      matrix_free(tmpG);
    }
    free(errValueTemp);
  vector_free(cipherFE);
  vector_free(perm2);

  
  /* BEGIN convert feildElement vector to padded message bytes of k1+k2+k3 */
  unsigned short kPlust=k+t; 
  vector_t FE_vec;
  int paddedLen=sk->para[6]+sk->para[7]+sk->para[8];
  if ((sk->para[9] == 0)||(sk->para[9] == 1)) {
    FE_vec=vec_init(kPlust);
    memcpy(FE_vec->data, dest, k*sizeof(field_t));
    memcpy(&(FE_vec->data[sk->para[1]]),errValue->data,t*sizeof(field_t));
  } else if  ((sk->para[9] == 2)||(sk->para[9] == 3)) {
    FE_vec=vec_init(sk->para[1]);
    memcpy(FE_vec->data, dest,k*sizeof(field_t));
  } else if ((sk->para[9] == 4)||(sk->para[9] == 5)) {
    return NOTIMPLEMENTEDYET;
  }
  free(eLocationAfterP1); 
  free(eLocationIndicator);
  free(cipherB4A);
  free(dest);
  unsigned char paddedMSG[paddedLen]; /* padded msg k1+k1+k2 bytes */
  if ((sk->para[3])==10) ret=FE2B10(FE_vec, paddedMSG,paddedLen);
  if ((sk->para[3])==11) ret=FE2B11(FE_vec, paddedMSG,paddedLen);
  if (ret<0) return ret;  
  vector_free(FE_vec);
  /* END convert feildElement vector to padded message bytes */
  
  /* BEGIN message de-padding */
  int e0Len = 4*t;
  unsigned char e0[e0Len];/* bytes used for padding purpose */
  for (i=0; i<t; i++) {
    e0[2*i]= errLocation[i]>>8;
    e0[2*i+1]= errLocation[i];
  }

  if ((sk->para[9] == 2) || (sk->para[9] == 3)) { /* bEncoding */
    for (i=0; i<t; i++) {
      e0[2*(t+i)]= (errValue->data[i]>>8);
      e0[2*(t+i)+1]= errValue->data[i];
    }
    if (sk->para[9] == 2) { /* RLCEspad  */
      ret=RLCEspadDecode(paddedMSG,paddedLen, msg, mlen, sk, e0, e0Len);
      if (ret<0) return ret;
    } else if (sk->para[9] == 3) { /* RLCEpad */
      ret=RLCEpadDecode(paddedMSG,paddedLen, msg, mlen, sk, e0, e0Len);
      if (ret<0) return ret;
    }
	
  } else if ((sk->para[9] == 0) || (sk->para[9] == 1)) { /* mEncoding */
    if (sk->para[9] == 0) { /* RLCEspad  */
      ret=RLCEspadDecode(paddedMSG,paddedLen, msg, mlen, sk, e0, 2*t);
      if (ret<0) return ret;
    } else if (sk->para[9] == 1) { /* RLCEpad */
      ret=RLCEpadDecode(paddedMSG,paddedLen, msg, mlen, sk, e0, 2*t);
      if (ret<0) return ret;
    }
  } else if ((sk->para[9] == 2)||(sk->para[9] == 3)) { /* aEncoding */
    return NOTIMPLEMENTEDYET;
  }
  vector_free(errValue);
  return 0;
}

int rlceWriteFile(char* filename, unsigned char bytes[], unsigned long long blen, int hex) {
  FILE *f = fopen(filename, "w"); /* r or w */
  if (f == NULL) return FILEERROR;
  int i;
  if (hex==1) for (i=0; i<blen; i++) fprintf(f, "%02x", bytes[i]);
  if (hex==0) fwrite(bytes,1,blen,f);
  fclose(f);
  return 0;
}

unsigned char* rlceReadFile(char* filename, unsigned long long *blen, int hex) {
  FILE *f = fopen(filename, "rb");
  if (f==NULL) return NULL;
  fseek (f,0,SEEK_END);
  blen[0]=ftell(f);
  rewind(f);  
  char *buffer=calloc(blen[0]+1, sizeof(char)); 
  fread(buffer, 1,blen[0],f);
  fclose(f);
  if (hex==0) return (unsigned char*) buffer;
  if ((blen[0]%2)>0) return NULL;
  blen[0] = blen[0]/2;
  char buf[10];
  unsigned char *hexBin=NULL; 
  hexBin=calloc(blen[0], sizeof(unsigned char));
  int count;
  for(count = 0; count<blen[0]; count++) {
    sprintf(buf, "0x%c%c", buffer[2*count], buffer[2*count+1]);
    hexBin[count] = strtol(buf, NULL, 0);
  }
  free(buffer);
  return hexBin;
}

int writeSK(char* filename, RLCE_private_key_t sk, int hex) {
  int ret=0;
  unsigned int sklen=sk->para[17];
  unsigned char *skB=calloc(sklen, sizeof(unsigned char));
  ret=sk2B(sk, skB, &sklen);
  if (ret<0) return ret;
  ret=rlceWriteFile(filename,skB,sklen, hex);
  free(skB);
  return ret;
}

RLCE_private_key_t readSK(char* filename, int hex) {
  unsigned long long blen=0;
  unsigned char* binByte=rlceReadFile(filename, &blen, hex);
  if (binByte==NULL) return NULL;  
  RLCE_private_key_t sk=B2sk(binByte, blen);
  free(binByte);
  return sk;
}

int writePK(char* filename,  RLCE_public_key_t pk, int hex) {
  int ret;  
  unsigned int pklen =pk->para[18];
  unsigned char *pkB=calloc(pklen, sizeof(unsigned char));
  ret=pk2B(pk,pkB,&pklen);
  if (ret<0) return ret;
  ret=rlceWriteFile(filename,pkB,pklen, hex);
  free(pkB);
  return ret;
}

RLCE_public_key_t readPK(char* filename, int hex) {
  unsigned long long blen=0;
  unsigned char* binByte=rlceReadFile(filename, &blen, hex);
  if (binByte==NULL) return NULL;
  RLCE_public_key_t pk=B2pk(binByte, blen);
  free(binByte);
  return pk;
}

int RLCEspad(unsigned char bytes[],unsigned int bytesLen,
	     unsigned char padded[], unsigned int paddedLen,
	     RLCE_public_key_t pk,
	     unsigned char randomness[], unsigned int randLen,
	     unsigned char e0[], unsigned int e0Len) {
  int k1=pk->para[6];
  int k2=pk->para[7];
  int k3=pk->para[8]; 
  if ((bytesLen!= k1)||(randLen!= k3)||(paddedLen!=k1+k2+k3))
    return SPADPARAERR;
  unsigned int alpha=8*(k1+k2+k3)-pk->para[5];
  unsigned char mask = 0xFF << alpha;
  randomness[k3-1] &= mask; /* set the last alpha bits as zero */  
  unsigned char re0[k3+e0Len];
  memcpy(re0, randomness, k3);
  if (e0Len !=0) memcpy(&re0[k3], e0, e0Len);
  unsigned char mre0[k1+k3+e0Len];
  memcpy(mre0, bytes, k1);
  memcpy(&mre0[k1], re0, k3+e0Len);
  unsigned char h1mre0[k2]; 
  RLCE_MGF512(mre0, k1+k3+e0Len, h1mre0, k2);
  unsigned char h2re0[k1+k2]; 
  RLCE_MGF512(re0, k3+e0Len, h2re0,k1+k2);
  memcpy(padded, bytes, k1);
  memcpy(&padded[k1], h1mre0,k2);
  memcpy(&padded[k1+k2],randomness, k3);
  rangeadd(h2re0, padded,k1+k2);
  return 0;
}

int RLCEspadDecode(unsigned char encoded[],unsigned int encodedLen,
		   unsigned char message[], unsigned long long *mlen,
		   RLCE_private_key_t sk,
		   unsigned char e0[], unsigned int e0Len) {
  int i= 0;
  int k1=sk->para[6];
  int k2=sk->para[7];
  int k3=sk->para[8];
  if (encodedLen!=(k1+k2+k3)) return SPADPARAERR;
  if ((mlen==NULL) || (message==NULL)) return MSGNULL;
  if (mlen[0]< k1) return SMG2SMALL;
  unsigned char randomness[k3];
  memcpy(randomness, &encoded[k1+k2],k3);
  unsigned int alpha=8*(k1+k2+k3)-sk->para[5]; 
  unsigned char mask = 0xFF << alpha;
  randomness[k3-1] &= mask; /* set the last alpha bits as zero */
  unsigned char re0[k3+e0Len];
  memcpy(re0, randomness,k3);
  if (e0Len !=0) memcpy(&re0[k3], e0, e0Len);
  unsigned char h2re0[k1+k2]; 
  RLCE_MGF512(re0,k3+e0Len, h2re0,k1+k2);
  rangeadd(h2re0, encoded,k1+k2);
  memcpy(message, encoded, k1);
  unsigned char h1mre0[k2];
  unsigned char mre0[k1+k3+e0Len];
  memcpy(mre0, message, k1);
  memcpy(&mre0[k1], re0, k3+e0Len);
  RLCE_MGF512(mre0, k1+k3+e0Len, h1mre0,k2);
  for (i=k1;i<k1+k2;i++) if (h1mre0[i-k1]!=encoded[i]) return DESPADDINGFAIL;
  return 0;
}

int RLCEpad(unsigned char bytes[],unsigned int bytesLen,
	    unsigned char padded[], unsigned int paddedLen,
	    RLCE_public_key_t pk,
	    unsigned char randomness[], unsigned int randLen,
	    unsigned char e0[], unsigned int e0Len) {
  int k1=pk->para[6];
  int k2=pk->para[7];
  int k3=pk->para[8]; 
  if ((bytesLen!=k1)||(randLen!=k3)||(paddedLen!=(k1+k2+k3))) return PADPARAERR;
  unsigned int alpha=8*(k1+k2+k3)-pk->para[5];
  unsigned char mask = 0xFF << alpha;
  randomness[k3-1] &= mask; /* set the last alpha bits as zero */
  unsigned char re0[k3+e0Len];
  memcpy(re0, randomness, k3);
  if (e0Len !=0) memcpy(&re0[k3], e0, e0Len);
  unsigned char mre0[k1+k3+e0Len];
  memcpy(mre0, bytes, k1);
  memcpy(&mre0[k1], re0, k3+e0Len);
  unsigned char h1mre0[k2]; 
  RLCE_MGF512(mre0, k1+k3+e0Len, h1mre0,k2);
  unsigned char h2re0[k1+k2];
  RLCE_MGF512(re0, k3+e0Len, h2re0,k1+k2);
  memcpy(padded, bytes, k1);
  memcpy(&padded[k1], h1mre0,k2);
  memcpy(&padded[k1+k2],randomness,k3);
  rangeadd(h2re0, padded, pk->para[6]+pk->para[7]);
  unsigned char mh1Ph2[k1+k2]; 
  memcpy(mh1Ph2, padded, k1+k2);
  unsigned char h3mh1Ph2[k3];
  RLCE_MGF512(mh1Ph2,k1+k2, h3mh1Ph2,k3);
  rangeadd(h3mh1Ph2, &(padded[k1+k2]),k3);
  return 0;
}

int RLCEpadDecode(unsigned char encoded[],unsigned int encodedLen,
		  unsigned char message[], unsigned long long *mlen,
		  RLCE_private_key_t sk,
		  unsigned char e0[], unsigned int e0Len) {
  int k1=sk->para[6];
  int k2=sk->para[7];
  int k3=sk->para[8]; 
  int i = 0;
  if (encodedLen!=(k1+k2+k3)) return PADPARAERR;
  if ((mlen==NULL) || (message==NULL)) return MSGNULL;
  if (mlen[0]< k1) return SMG2SMALL;  
  unsigned char mh1Ph2[k1+k2];
  memcpy(mh1Ph2, encoded, k1+k2);
  unsigned char h3mh1Ph2[k3];
  RLCE_MGF512(mh1Ph2,k1+k2, h3mh1Ph2,k3);
  unsigned char randomness[k3];
  memcpy(randomness, &encoded[k1+k2], k3);
  rangeadd(h3mh1Ph2, randomness, sk->para[8]);
  unsigned int alpha=8*(k1+k2+k3)-sk->para[5]; 
  unsigned char mask = 0xFF << alpha;
  randomness[k3-1] &= mask; /* set the last alpha bits as zero */
  unsigned char re0[k3+e0Len];
  memcpy(re0, randomness, k3);
  if (e0Len !=0) memcpy(&re0[k3], e0, e0Len);
  unsigned char h2re0[k1+k2];
  RLCE_MGF512(re0,k3+e0Len,h2re0,k1+k2);
  rangeadd(h2re0, encoded,k1+k2);
 
  memcpy(message, encoded, k1);
  unsigned char h1mre0[k2];
  unsigned char mre0[k1+k3+e0Len];
  memcpy(mre0, message, k1);
  memcpy(&mre0[k1],re0, k3+e0Len);
  RLCE_MGF512(mre0, k1+k3+e0Len,h1mre0, k2);
  for (i=k1;i<k1+k2;i++) if (h1mre0[i-k1]!=encoded[i]) return DEPADDINGFAIL;
  return 0;
}

void hex2char(char hex[], unsigned char hexChar[], int charlen){
  int i=0;
  char buf[8];
  for(i = 0; i < charlen; i++) {
    sprintf(buf, "0x%c%c", hex[2*i], hex[2*i+1]);
    hexChar[i] = strtol(buf, NULL, 0);
    /* sscanf(pos, "%2hhx", &hexChar[i]);*/
  }
}

int rangeadd(unsigned char bytes1[], unsigned char bytes2[], int bytesize){
  int i;
    if (sizeof(long)==8) {
      unsigned int size=bytesize/8;
      long* longvec1=(long*) bytes1;
      long* longvec2=(long*) bytes2;
      for (i=0; i<size; i++) longvec2[i] ^= longvec1[i];
      for (i=8*size; i<bytesize; i++) bytes2[i] ^= bytes1[i];      
    } else {
      for (i=0; i<bytesize; i++) bytes2[i] ^= bytes1[i];
    }
  return 0;
}

poly_t genPolyTable(int deg) {
  poly_t p=poly_init(deg+1);
  if (deg==156) {
    field_t coeff[]={0x019c,0x011b,0x00b5,0x004e,0x0377,0x020c,0x0255,0x0159,0x0134,0x0396,0x0188,0x020c,0x0323,0x00d6,0x033e,0x0344,0x0274,0x030b,0x020d,0x03a3,0x03ec,0x03d1,0x02ed,0x0272,0x03d3,0x007c,0x01fd,0x037c,0x020e,0x0133,0x03dc,0x00f0,0x007b,0x00cb,0x02b7,0x0052,0x0138,0x00e7,0x02ca,0x01ee,0x0063,0x03d2,0x00e0,0x027d,0x0092,0x02ca,0x0382,0x00d1,0x018a,0x00b6,0x0257,0x022f,0x0185,0x01a3,0x00a0,0x030c,0x02f2,0x01ae,0x0055,0x028a,0x0378,0x026b,0x0308,0x035e,0x0169,0x03da,0x0358,0x0058,0x03c0,0x02e9,0x0337,0x0093,0x0267,0x0351,0x0045,0x027d,0x02b2,0x013f,0x024c,0x0327,0x0206,0x034a,0x0104,0x03db,0x025a,0x00e2,0x01db,0x012e,0x0273,0x028d,0x03c1,0x03ae,0x038e,0x036a,0x022c,0x0096,0x0357,0x0188,0x00db,0x0297,0x02b4,0x01b8,0x0270,0x0124,0x01b6,0x0134,0x0270,0x017b,0x0386,0x02a9,0x03fb,0x00da,0x0360,0x0325,0x014b,0x0153,0x01b2,0x0014,0x036b,0x036e,0x0064,0x02e1,0x001e,0x0150,0x00e6,0x0089,0x029c,0x0088,0x020d,0x0194,0x025a,0x02cd,0x02de,0x02f2,0x0369,0x0078,0x0205,0x030e,0x0166,0x0260,0x00dd,0x036d,0x02c2,0x0221,0x03a9,0x0112,0x016b,0x0058,0x0204,0x01e2,0x02e0,0x030c,0x024e,0x009e,0x03e4,0x03e1,0x0001};
    memcpy(p->coeff, coeff, (deg+1)*sizeof(field_t));
    p->deg= deg;
  }
  if (deg==160) {
    field_t coeff[]={0x03d5,0x03a1,0x01de,0x0268,0x03e1,0x0009,0x0140,0x0012,0x0181,0x037d,0x01f4,0x01de,0x013b,0x02f3,0x0060,0x0076,0x02d1,0x0100,0x0135,0x0108,0x00d8,0x0077,0x01c5,0x023a,0x02bb,0x029f,0x0270,0x0384,0x0367,0x03c9,0x0352,0x0288,0x01b4,0x0060,0x030c,0x00ab,0x015b,0x00f9,0x0035,0x028b,0x033d,0x0191,0x00a3,0x0276,0x02d9,0x03d6,0x031f,0x039b,0x0209,0x0061,0x0113,0x01a8,0x0244,0x006f,0x01f6,0x025c,0x03ff,0x0267,0x02d2,0x028a,0x0160,0x00b9,0x0265,0x013e,0x0110,0x036a,0x01d4,0x0032,0x022a,0x0383,0x0066,0x025f,0x01e1,0x0153,0x0185,0x0198,0x0175,0x0096,0x0238,0x02d2,0x00c4,0x01f8,0x026f,0x0115,0x019b,0x034f,0x00f8,0x01b5,0x03a2,0x00a8,0x006b,0x0255,0x0138,0x035f,0x0165,0x01cf,0x02a2,0x02f4,0x02d8,0x0178,0x00fa,0x0287,0x02c8,0x03bb,0x0005,0x00c4,0x03c2,0x0347,0x03ee,0x0263,0x0243,0x032c,0x0282,0x0379,0x0194,0x0038,0x0394,0x02f3,0x0039,0x0157,0x013f,0x0032,0x00c2,0x020d,0x03ed,0x0371,0x02fa,0x0170,0x0184,0x010a,0x0245,0x03a1,0x01f9,0x0180,0x00fb,0x0086,0x01bf,0x0192,0x0195,0x03db,0x026d,0x026a,0x01a3,0x0336,0x0264,0x00e7,0x02e2,0x01e7,0x03d2,0x0213,0x0212,0x01ca,0x03f3,0x00e6,0x0290,0x0116,0x00b9,0x0293,0x0384,0x0279,0x0001};
    memcpy(p->coeff, coeff, (deg+1)*sizeof(field_t));
    p->deg= deg;
  }

    if (deg==228) {
    field_t coeff[]={0x031a,0x0014,0x0192,0x02b9,0x03b8,0x0301,0x0343,0x0135,0x000a,0x0004,0x00a8,0x0063,0x0107,0x013c,0x03f9,0x039f,0x0023,0x03af,0x03e4,0x026d,0x022e,0x03fd,0x030b,0x0044,0x0231,0x0001,0x0085,0x0213,0x038f,0x02d1,0x02f7,0x01fc,0x03d4,0x0059,0x0119,0x0098,0x01ef,0x0100,0x0014,0x00c3,0x00ae,0x001f,0x01ed,0x0359,0x0298,0x03bf,0x00a6,0x00be,0x01f2,0x0080,0x00f4,0x02e8,0x038d,0x005b,0x005a,0x02a7,0x00dc,0x013c,0x0138,0x039b,0x007f,0x0397,0x0375,0x0181,0x0270,0x00fa,0x006e,0x0257,0x03c9,0x01e7,0x01da,0x0199,0x01f3,0x02cc,0x030d,0x01c8,0x0230,0x0105,0x0396,0x0032,0x02b8,0x03c3,0x01e5,0x028c,0x0027,0x019c,0x028b,0x0386,0x0247,0x0075,0x0004,0x017d,0x0396,0x01b8,0x004e,0x0133,0x0340,0x013f,0x01cb,0x017d,0x01f1,0x01ea,0x02df,0x037a,0x03e2,0x013d,0x0277,0x009a,0x0352,0x03c0,0x038d,0x030a,0x00a8,0x01e8,0x0334,0x004b,0x0301,0x01df,0x0191,0x031d,0x029d,0x007d,0x0332,0x00cd,0x00ff,0x0102,0x0159,0x01a7,0x01a1,0x0085,0x0053,0x024e,0x0239,0x03b6,0x0126,0x0287,0x00b3,0x039e,0x02d4,0x038d,0x007c,0x03bb,0x00a2,0x023e,0x010c,0x0337,0x01a6,0x00a3,0x0165,0x00b1,0x02ae,0x0173,0x0281,0x0190,0x0313,0x02f6,0x01d5,0x0112,0x02bb,0x0173,0x033b,0x0247,0x02d6,0x0116,0x02ca,0x019a,0x016f,0x00db,0x00b9,0x03e5,0x000e,0x0260,0x00f6,0x0103,0x0363,0x0202,0x0020,0x02d8,0x02f3,0x02b2,0x025c,0x02f8,0x035a,0x0210,0x00c2,0x03d5,0x00cd,0x001b,0x0160,0x0220,0x03b1,0x014e,0x0345,0x015a,0x0088,0x0052,0x010d,0x0311,0x0066,0x028e,0x00a8,0x01d9,0x00c7,0x000c,0x0242,0x0307,0x0237,0x0128,0x0137,0x0198,0x01d2,0x00b2,0x0284,0x0045,0x008c,0x03f2,0x01a2,0x023d,0x03a3,0x0246,0x0384,0x03bf,0x006a,0x0032,0x00ca,0x013c,0x00f2,0x02fa,0x0001};
    memcpy(p->coeff, coeff, (deg+1)*sizeof(field_t));
    p->deg= deg;
  }
      if (deg==236) {
    field_t coeff[]={0x02cb,0x008f,0x02c9,0x0195,0x0108,0x0192,0x01ed,0x01a8,0x02fc,0x00a0,0x03d3,0x029c,0x0383,0x01e9,0x03bd,0x0171,0x019f,0x00c9,0x00df,0x03a3,0x023c,0x0089,0x03b9,0x0190,0x0373,0x0228,0x0283,0x0246,0x0058,0x03a4,0x005b,0x01c6,0x0129,0x026b,0x003f,0x00e3,0x005f,0x0010,0x0340,0x025e,0x0108,0x024b,0x03dc,0x0329,0x0131,0x033e,0x00d7,0x01c1,0x02bb,0x03b9,0x0373,0x03d0,0x0159,0x036d,0x0148,0x0366,0x0287,0x039a,0x0356,0x023b,0x010d,0x0173,0x0307,0x0122,0x01d9,0x02ac,0x031d,0x014a,0x01a4,0x012f,0x0350,0x0122,0x00f1,0x027b,0x02f2,0x0110,0x0323,0x0205,0x01ec,0x00d1,0x0174,0x018a,0x00ed,0x0054,0x01f3,0x00ae,0x0016,0x03c9,0x00e4,0x0190,0x0342,0x0318,0x02ad,0x0055,0x0241,0x01c8,0x01a2,0x016b,0x0276,0x02fa,0x0134,0x028a,0x01f2,0x0101,0x03cf,0x00bd,0x0329,0x03d9,0x0151,0x03b8,0x011d,0x02a6,0x03d1,0x014f,0x00d9,0x0194,0x0113,0x0162,0x0336,0x009e,0x0145,0x023b,0x035c,0x0268,0x037b,0x0299,0x0016,0x0028,0x004e,0x02d4,0x02b7,0x0107,0x0004,0x008e,0x0310,0x0389,0x0365,0x0159,0x0071,0x01c7,0x0038,0x00f8,0x0332,0x0061,0x036e,0x0189,0x02d5,0x0124,0x0358,0x010e,0x00dd,0x03fe,0x03b9,0x017e,0x024c,0x0188,0x01e2,0x0102,0x0201,0x0235,0x02a8,0x038c,0x00ef,0x00ac,0x014f,0x035a,0x0050,0x01a8,0x00f9,0x0382,0x02de,0x0029,0x015d,0x0062,0x009e,0x0135,0x011b,0x0031,0x02fe,0x021f,0x0042,0x03a4,0x00b8,0x0092,0x01a9,0x03b7,0x02df,0x0142,0x0283,0x02a5,0x033b,0x003e,0x02d4,0x036c,0x03df,0x01d6,0x033f,0x0189,0x0006,0x03b8,0x02f8,0x031d,0x0359,0x018b,0x02ff,0x0097,0x0054,0x017d,0x009c,0x0296,0x01c7,0x0336,0x02f9,0x0224,0x022b,0x00d2,0x0288,0x0242,0x01a8,0x0231,0x039e,0x004b,0x018e,0x023d,0x02e1,0x032a,0x0272,0x0135,0x02ca,0x00f1,0x007e,0x0019,0x0265,0x0275,0x0368,0x02b9,0x0001};
    memcpy(p->coeff, coeff, (deg+1)*sizeof(field_t));
    p->deg= deg;
  }
        if (deg==460) {
    field_t coeff[]={0x072e,0x01fe,0x03ca,0x0784,0x0588,0x05e0,0x0214,0x02d7,0x04c6,0x07d2,0x0373,0x043d,0x079d,0x006e,0x0705,0x034e,0x0504,0x0682,0x0563,0x04d5,0x059e,0x0265,0x0397,0x069d,0x07f8,0x00c8,0x06c1,0x0650,0x031f,0x061b,0x0452,0x078a,0x0345,0x056b,0x0624,0x0675,0x05e5,0x0547,0x02e0,0x0645,0x01d9,0x0298,0x0260,0x066b,0x022b,0x0557,0x05f3,0x049a,0x05a4,0x0355,0x01b6,0x0438,0x01c4,0x04f5,0x0732,0x07f9,0x0443,0x022a,0x067f,0x0307,0x057d,0x030c,0x05ed,0x0160,0x0539,0x06df,0x06a9,0x0727,0x0562,0x04cf,0x034b,0x0463,0x058f,0x05f3,0x009c,0x063d,0x039f,0x04bc,0x050c,0x0086,0x07d5,0x03f3,0x0528,0x05ac,0x0352,0x0652,0x0176,0x04fc,0x0125,0x028d,0x069f,0x0126,0x038a,0x0689,0x067e,0x07c5,0x0508,0x071d,0x005c,0x0743,0x031e,0x03f0,0x0094,0x0594,0x0365,0x07b8,0x0412,0x06f6,0x0155,0x0175,0x072f,0x078b,0x02e9,0x00ea,0x03ce,0x0210,0x0640,0x063b,0x038d,0x071c,0x05f2,0x034f,0x0193,0x008c,0x002e,0x012a,0x0510,0x07ce,0x0327,0x003c,0x0274,0x0136,0x0127,0x05e4,0x0334,0x0361,0x0673,0x03b4,0x0315,0x01d7,0x0705,0x0123,0x073a,0x0088,0x00b4,0x0528,0x0295,0x0106,0x03cf,0x0471,0x0361,0x04dd,0x0280,0x0335,0x0246,0x06ec,0x062b,0x01db,0x03b6,0x0479,0x065f,0x04d6,0x01e9,0x0606,0x0723,0x0432,0x00ee,0x0598,0x0464,0x02cd,0x0220,0x03e9,0x0163,0x0345,0x06bb,0x02a7,0x06e6,0x02a4,0x004e,0x02e9,0x069f,0x054f,0x00d6,0x0737,0x029d,0x0462,0x06e6,0x0542,0x06e6,0x062a,0x0594,0x0291,0x04c9,0x015d,0x00b7,0x00b1,0x044c,0x01ea,0x026a,0x02d7,0x0216,0x0575,0x003b,0x02f8,0x0531,0x0126,0x0095,0x037d,0x05e3,0x0013,0x0624,0x05cb,0x031d,0x002d,0x04ad,0x0193,0x0079,0x0654,0x03ba,0x045d,0x0789,0x056c,0x032f,0x0334,0x0529,0x00d0,0x018f,0x02f5,0x05ab,0x02a4,0x07b6,0x0643,0x06a7,0x0616,0x07f2,0x0372,0x04ef,0x0374,0x07fc,0x04ff,0x029d,0x0682,0x038f,0x0575,0x05e8,0x0139,0x0149,0x02cc,0x073d,0x072e,0x0441,0x035f,0x05d1,0x0329,0x01ae,0x010c,0x026e,0x0215,0x0014,0x0325,0x043c,0x0431,0x03d0,0x002d,0x070b,0x04b3,0x04a4,0x06ac,0x0114,0x0240,0x002e,0x044e,0x01f4,0x01d8,0x026a,0x00ee,0x05a7,0x0001,0x01c4,0x03f5,0x0448,0x02fe,0x07f7,0x012a,0x0137,0x0618,0x0036,0x023d,0x004b,0x02fe,0x0783,0x054d,0x0131,0x0665,0x0341,0x0386,0x0395,0x0206,0x0310,0x02b3,0x03bd,0x05e2,0x0625,0x01cf,0x01a6,0x0717,0x0085,0x04e7,0x00d2,0x0723,0x071f,0x0458,0x000f,0x0354,0x03b8,0x0301,0x0528,0x04e3,0x07e2,0x0429,0x0227,0x043b,0x0314,0x0371,0x057c,0x024c,0x03bb,0x0739,0x0513,0x0722,0x0579,0x0741,0x0141,0x01b5,0x0472,0x05cb,0x0777,0x022b,0x0603,0x073c,0x01d3,0x01f6,0x0116,0x0134,0x0295,0x071b,0x01f9,0x0199,0x0263,0x034a,0x0515,0x07b6,0x02fd,0x0679,0x0411,0x043d,0x0430,0x0601,0x04a6,0x02bb,0x0168,0x0582,0x016b,0x031d,0x0108,0x046a,0x0468,0x0399,0x0209,0x05bc,0x03eb,0x0130,0x0325,0x00d4,0x0330,0x0356,0x0320,0x045c,0x067f,0x0179,0x0449,0x015f,0x05ab,0x07a3,0x0784,0x05b6,0x02fc,0x01f6,0x0070,0x01fb,0x02e9,0x007e,0x0099,0x04e3,0x0184,0x026e,0x0629,0x02b5,0x0399,0x013a,0x0341,0x02da,0x0316,0x0641,0x07cb,0x01a5,0x042b,0x03c0,0x046e,0x05c0,0x000e,0x02c6,0x0603,0x0793,0x0098,0x0019,0x0494,0x0250,0x076b,0x056b,0x00a4,0x00aa,0x0477,0x05c4,0x00dc,0x051b,0x07b5,0x002d,0x01be,0x065f,0x0004,0x014d,0x01af,0x067f,0x00c7,0x03c3,0x0791,0x0302,0x0662,0x026d,0x01eb,0x005d,0x0643,0x04c2,0x0410,0x0756,0x0210,0x069c,0x0734,0x04dc,0x05fa,0x03b5,0x04f8,0x02e9,0x0172,0x05d1,0x0658,0x074a,0x07d2,0x03b5,0x0001};
    memcpy(p->coeff, coeff, (deg+1)*sizeof(field_t));
    p->deg= deg;
  }
	  if (deg==560) {
    field_t coeff[]={0x0036,0x0789,0x03ff,0x07bb,0x0542,0x073a,0x05f0,0x011f,0x07de,0x0152,0x07f1,0x0411,0x0436,0x0140,0x0128,0x022a,0x035c,0x023f,0x034f,0x06c0,0x0232,0x00cc,0x0373,0x04d7,0x01fa,0x07dc,0x06ad,0x04f1,0x0266,0x0714,0x01cb,0x0108,0x005d,0x0599,0x01d0,0x0374,0x02bd,0x0689,0x02d6,0x00f3,0x0537,0x0044,0x04ec,0x04ea,0x0023,0x0483,0x028b,0x0059,0x0049,0x06d8,0x0136,0x04af,0x010e,0x0404,0x0580,0x026b,0x075a,0x0252,0x047b,0x070b,0x020e,0x0172,0x0106,0x0653,0x0044,0x00bc,0x056e,0x05d5,0x028a,0x001d,0x0534,0x060e,0x064d,0x07fe,0x06b0,0x0393,0x01c7,0x04bb,0x06d5,0x030e,0x0253,0x00aa,0x06ae,0x023f,0x0134,0x05a7,0x0536,0x043a,0x00c2,0x0537,0x0024,0x01c8,0x0524,0x025a,0x0236,0x030f,0x0128,0x0292,0x04c1,0x022b,0x01ca,0x011f,0x031d,0x0061,0x0499,0x03af,0x069d,0x0571,0x00d6,0x043a,0x0283,0x035a,0x02d5,0x07b8,0x05b0,0x05f6,0x04f3,0x0664,0x05cd,0x0715,0x030b,0x0755,0x0032,0x03bc,0x077d,0x072b,0x0414,0x05c2,0x06ee,0x0464,0x04ff,0x0600,0x026d,0x0350,0x05d0,0x0080,0x05cb,0x0234,0x0018,0x06bf,0x06b7,0x02b7,0x044a,0x0127,0x05e0,0x0635,0x067f,0x04bb,0x03c2,0x0498,0x04f3,0x056f,0x0229,0x0423,0x05b4,0x0782,0x06d4,0x0142,0x05b2,0x0157,0x0714,0x015b,0x0073,0x02c4,0x0644,0x06fe,0x03ba,0x0252,0x04a1,0x02f6,0x002c,0x0749,0x05a0,0x021a,0x0107,0x0701,0x04c0,0x03ba,0x0772,0x07b8,0x04e0,0x07d8,0x0707,0x0610,0x0681,0x0682,0x0788,0x0577,0x0435,0x055b,0x030a,0x0419,0x0598,0x0637,0x0627,0x018d,0x033b,0x0753,0x06f7,0x070f,0x024a,0x07bc,0x02ce,0x005e,0x066a,0x051d,0x0670,0x00c5,0x05a2,0x04dc,0x0673,0x07e6,0x075c,0x059e,0x0001,0x0749,0x075d,0x013d,0x04ca,0x06f0,0x005a,0x059f,0x0017,0x04fd,0x0036,0x05b1,0x057d,0x02fa,0x0158,0x0672,0x0641,0x06fe,0x031f,0x06cb,0x003b,0x06d7,0x00da,0x07ed,0x07d3,0x024a,0x001c,0x043f,0x012d,0x04dc,0x0113,0x009d,0x07c1,0x00b6,0x0568,0x03ce,0x07e9,0x0597,0x075d,0x05de,0x03ba,0x032a,0x0285,0x03a8,0x04c8,0x03ac,0x0006,0x0698,0x0382,0x0214,0x0128,0x03b4,0x042d,0x0027,0x04f7,0x0450,0x0534,0x010a,0x0720,0x01d5,0x03ab,0x07ee,0x024b,0x0792,0x0189,0x009f,0x04fb,0x0671,0x07b4,0x0587,0x0008,0x02cc,0x0573,0x0756,0x0622,0x047b,0x0181,0x033a,0x035e,0x07e6,0x038f,0x0404,0x0429,0x0355,0x07c9,0x03ed,0x0202,0x0594,0x0279,0x01e7,0x04d4,0x0449,0x0506,0x0148,0x07d3,0x07bf,0x03df,0x0284,0x00dc,0x01a3,0x0407,0x01ae,0x0452,0x04fd,0x02d4,0x00e0,0x012d,0x012c,0x0513,0x0508,0x049a,0x0134,0x01b4,0x07a7,0x0529,0x0389,0x036a,0x043b,0x0799,0x07bf,0x004d,0x0526,0x035f,0x0544,0x00b6,0x01f3,0x0373,0x0065,0x02c3,0x0017,0x00f8,0x03fa,0x01d5,0x002b,0x0497,0x0422,0x0024,0x06b3,0x00e7,0x05f2,0x0182,0x046c,0x03e7,0x036e,0x067d,0x012a,0x06a5,0x0053,0x042b,0x057a,0x06cb,0x022c,0x0760,0x0488,0x05a1,0x06f2,0x0546,0x01c0,0x0628,0x0798,0x024d,0x05a1,0x0247,0x062a,0x046b,0x0671,0x04b1,0x0197,0x0433,0x02f5,0x0083,0x0263,0x00e1,0x04a3,0x052b,0x012d,0x0325,0x07de,0x0539,0x048c,0x04d7,0x03e2,0x021d,0x0598,0x02f0,0x025d,0x06a2,0x02b2,0x029b,0x0640,0x023d,0x03fb,0x0168,0x039a,0x0183,0x0580,0x0681,0x04e6,0x0229,0x07c7,0x01a5,0x036c,0x0464,0x044e,0x07f9,0x01ca,0x0120,0x01f1,0x051d,0x0605,0x04d5,0x0473,0x05da,0x007d,0x073d,0x0755,0x022a,0x06fc,0x03f9,0x0002,0x046c,0x0372,0x0035,0x0607,0x0390,0x0691,0x0090,0x00dc,0x0403,0x03cd,0x03b6,0x03fe,0x0359,0x074f,0x0110,0x0296,0x05d9,0x031e,0x02d5,0x035f,0x0369,0x0771,0x06b1,0x0735,0x0523,0x03c1,0x0133,0x00ad,0x0771,0x04ce,0x0284,0x03a9,0x050e,0x07f5,0x0185,0x0203,0x07bf,0x0108,0x0685,0x04b6,0x020e,0x0300,0x014d,0x04ef,0x0440,0x014e,0x05c3,0x0228,0x06ce,0x07cb,0x03ac,0x00d3,0x01b0,0x07fd,0x07a4,0x0100,0x00f3,0x00cd,0x0678,0x052a,0x00b6,0x00fe,0x004d,0x0647,0x028d,0x03cc,0x0625,0x0648,0x05a5,0x0273,0x040a,0x01e6,0x0001,0x074b,0x00b5,0x0666,0x008b,0x04c3,0x00e5,0x02b9,0x0274,0x0720,0x0771,0x05c0,0x03d1,0x0780,0x0074,0x07c3,0x062a,0x0184,0x044e,0x02df,0x0522,0x02ed,0x03e5,0x0239,0x03ee,0x030d,0x049c,0x07d8,0x077a,0x03d4,0x0428,0x00ec,0x0570,0x04b0,0x0458,0x06ea,0x075d,0x01e0,0x07e0,0x0333,0x0651,0x0056,0x0756,0x04f2,0x0206,0x05ad,0x05db,0x016a,0x00dd,0x010d,0x0551,0x02e9,0x03a9,0x0527,0x0001};
    memcpy(p->coeff, coeff, (deg+1)*sizeof(field_t));
    p->deg= deg;
  }
  
  return p;
}
