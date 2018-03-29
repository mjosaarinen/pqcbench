/* fieldMatrix.c
 * Yongge Wang 
 *
 * Code was written: November 10, 2016-
 *
 * fieldMatrix.c implements matrix operations 
 * for RLCE scheme that is part of the package 
 * RLCE.tar - Random Linear Code Encryption Scheme
 *
 * Copyright (C) 2016 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 */


#include "rlce.h"

matrix_t matrix_init(int row, int column) {
  matrix_t mat;
  int i;
  mat = (matrix_t) malloc(sizeof (struct matrix));
  mat->numR = row;
  mat->numC = column;
  mat->data = calloc(row, sizeof(int*));
  for (i=0; i<row; i++) {
    mat->data[i]= (field_t *) calloc(column, sizeof(field_t));
  }
  return mat;
}

void matrix_free(matrix_t A){
  int i;
  for (i=0; i<A->numR; i++) free(A->data[i]);
  free(A->data);
  free(A);
  return;
}

int vector_copy(vector_t v, vector_t dest) {
  dest->size = v->size;
  memcpy(dest->data, v->data, (v->size) * sizeof (field_t));
  return 0;
}

int matrix_vec_mat_mul_standard(field_t V[], int vsize, matrix_t B, field_t dest[], int dsize, unsigned int m) {
  if ((vsize>B->numR)||(B->numC<dsize)) return VECMATRIXMULERROR;
  int i;
  field_t *X;
  X=calloc(dsize, sizeof(field_t));
  memset(dest, 0, dsize*sizeof(field_t));
  for (i=0; i<vsize; i++) {
    if (V[i] !=0) {
      GF_mulvec(V[i],B->data[i],X,dsize, m);
      GF_addvec(X,dest,NULL,dsize);
    }
  }
  free(X);
  return 0;
}

int matrix_standard_mul(matrix_t A, matrix_t B, matrix_t C, int m) {
  if ((A->numC!=B->numR)||(A->numR!=C->numR)||(B->numC!=C->numC))
    return MATRIXMULERROR;
  int i;
  for (i=0;i<C->numR;i++)
    matrix_vec_mat_mul_standard(A->data[i],A->numC,B,C->data[i],B->numC, m);
  return 0;
}

matrixA_t matrixA_init(int size) {
  matrixA_t matA;
  matA = (matrixA_t) malloc(sizeof (struct matrixA));
  matA->size = size;
  matA->A = malloc(size * sizeof(int*));
  int i;
  for (i=0; i<size; i++) matA->A[i]= matrix_init(2, 2);
  return matA;
}

void matrixA_free(matrixA_t A){
  int i;
  for (i=0; i<A->size; i++) {
    matrix_free(A->A[i]);
    A->A[i]=NULL;
  }
  free(A->A);
  A->A=NULL;
  free(A);
  A=NULL;
  return;
}

int matrix_col_permutation(matrix_t A, vector_t per) {
  /* per should contain a permutation of 
     0, 1, ..., A->numC */
  if (per->size != A->numC) return MATRIXCOLPERERROR;
  field_t tmp[A->numC];
  int i,j;
  for (i=0; i<A->numR; i++) {
    memcpy(tmp, A->data[i], (A->numC) * sizeof(field_t));
    for (j=0; j<A->numC; j++) A->data[i][j]=tmp[per->data[j]];
  }
  return 0;
}


int matrix_inv_standard(matrix_t G, matrix_t result, int m) {
  /* Gauss-Jordan elimination */
  int n= G->numR;
  int i,ret;
  matrix_t mat; /* mat = [G, I] */
  mat = matrix_init(n, 2*n);
  for (i=0;i<n;i++) memcpy(mat->data[i], G->data[i], n*sizeof(field_t));
  for(i=0;i<n; i++) mat->data[i][n+i]=1;
  ret=matrix_echelon(mat, m);
  for (i=0;i<n;i++) memcpy(result->data[i], &(mat->data[i][n]), n*sizeof(field_t));
  matrix_free(mat);
  return ret;
}

int matrix_echelon(matrix_t G, int m) {
  /* Gauss-Jordan elimination */
  int n= G->numR;
  if (G->numC <n) n=G->numC;
  int temp, i, j;
  field_t *tmp;
  field_t c;
  field_t *tmprow=calloc(G->numC, sizeof(field_t)); 
  for(j=0; j<n; j++) { /* converting first half to I */
    if (G->data[j][j] == 0) {
      temp=j;
      while  ((temp<G->numR) && (G->data[temp][j] == 0)) temp ++;
      if (temp == n) {
	free(tmprow);
	return -j;
      }
      tmp=G->data[j];
      G->data[j] = G->data[temp];
      G->data[temp]= tmp;
    }
    GF_vecdiv(G->data[j][j], &(G->data[j][j]), NULL,G->numC-j,m);
    //for (k=j;k<G->numC;k++) G->data[j][k]=GF_mul(G->data[j][k],c,m);
    for(i=0; i<n; i++) {
      if (i !=j) {
	c = G->data[i][j];
	if (c!=field_zero()){
	  GF_mulvec(c,&(G->data[j][j]),tmprow,(G->numC)-j,m);
	  GF_addvec(tmprow, &(G->data[i][j]),NULL,(G->numC)-j);
	  //for (k=j;k<G->numC;k++) G->data[i][k]^=GF_mul(G->data[j][k],c,m);
	}
      }
    }
  }
  free(tmprow);
  return n;
}


vector_t vec_init(int n) {
  vector_t v;
  v = (vector_t) malloc(sizeof (struct vector));
  v->size = n;
  v->data = (field_t *) calloc(n, sizeof (field_t));
  return v;
}

void vector_free(vector_t v) {
  free(v->data);
  v->data=NULL;
  free(v);
  v=NULL;
}

vector_t permu_inv(vector_t p) {
  int i;
  vector_t result;
  result = vec_init(p->size);
  for (i=0; i<p->size; i++) {
    result->data[p->data[i]]=i;
  }
  return result;
}


vector_t getPermutation(int persize, int t, unsigned char randBytes[], int nRB) {
  /* this implements Fisher–Yates shuffle 
     in Knuth "Algorithm P" of The Art of Computer Programming */
  /* if t=persize, return a permutation of 0,...,persize-1. otherwise
   * only return the first t elements of the permutation*/
  vector_t permutation = vec_init(persize);
  int i;
  for (i=0; i<persize; i++) permutation->data[i]=i;

  unsigned short randomShortIntegers[t];
  int ret=getShortIntegers(randBytes, nRB, randomShortIntegers,t);
  if (ret <0) return NULL;
  
  unsigned short swapi;
  field_t tmp;
  for (i=0; i<t; i++) {
    swapi = randomShortIntegers[i] % (persize -i);
    swapi += i;
    tmp = permutation->data[i];
    permutation->data[i]=permutation->data[swapi];
    permutation->data[swapi]=tmp;    
  }
  return permutation;  
}

int randomBytes2FE(unsigned char randomBytes[], int nRB,
		   field_t output[], int outputSize, int m) {
  vector_t Vec;
  Vec =vec_init(outputSize);
  int ret = 0;
  switch (m) {
  case 10:
    ret=B2FE10(randomBytes,nRB, Vec);
    if (ret<0) return ret;
    break;
  case 11:
    ret=B2FE11(randomBytes,nRB, Vec);
    if (ret<0) return ret;
    break;
  default:
    return B2FEORFE2BNOTDEFINED;
  }
  memcpy(output, Vec->data, outputSize *sizeof(field_t));
  vector_free(Vec);
  return 0; 	 
}

int getShortIntegers(unsigned char randB[], int nRB,unsigned short output[], int outputSize) {
  int i;
  for (i=0; i<outputSize; i++) {
    output[i]=randB[2*i];
    output[i]= (output[i]<<8);
    output[i]= output[i] | randB[2*i+1];
  }
  return 0; 	 
}

int getRandomBytes(unsigned char seed[], int seedSize,
		   unsigned char pers[], int persSize,
		   unsigned char output[], int outputlen,int cryptotype) {
  int ret=0;
  if (cryptotype <3) {
    hash_drbg_state_t drbgState;
    drbgState=drbgstate_init(cryptotype);
    unsigned char nonce[8]={0xff, 0xf1, 0xc6, 0x64, 0x5f, 0x19, 0x23, 0x1f};
    unsigned char add[1];
    drbg_Input_t drbgInput;  
    drbgInput=drbgInput_init(seed,seedSize,nonce, 8, pers,persSize,add, 0);
    ret= hash_DRBG(drbgState, drbgInput, output, outputlen);
    free_drbg_state(drbgState);
    free_drbg_input(drbgInput);
  } else {
    ctr_drbg_state_t drbgState;
    drbgState=ctr_drbgstate_init(cryptotype);
    unsigned char nonce[1];
    unsigned char add[1];
    drbg_Input_t drbgInput;
    unsigned char newseed[drbgState->seedlen];
    memset(newseed, 0, drbgState->seedlen);
    int seedlen = seedSize;
    if (seedlen > drbgState->seedlen) seedlen = drbgState->seedlen;
    memcpy(newseed, seed, seedlen);
    drbgInput=drbgInput_init(seed,seedlen,nonce, 0, pers,persSize,add, 0);
    ret= ctr_DRBG(drbgState, drbgInput, output, outputlen);
    free_ctr_drbg_state(drbgState);
    free_drbg_input(drbgInput);
  } 
  return ret;  
}

void I2BS (unsigned int X, unsigned char S[], int slen) {
  int i;
  for (i=slen-1; i>=0; i--) S[i]=(0xFF & (X>>((slen-1-i)*8)));
}

int BS2I (unsigned char S[], int slen) {
  unsigned int i, X=0;
  for (i=0; i<slen; i++) X=(X<<8)^S[i];
  return X;
}

int RLCE_MGF512(unsigned char mgfseed[], int mgfseedLen,
	     unsigned char mask[], int maskLen) {
  unsigned char seed[mgfseedLen+4];  
  memcpy(seed, mgfseed, mgfseedLen);
  int i,j,m,r;
  unsigned long hash512[8];
  m=maskLen/64;
  r=maskLen%64;
  for (i=0; i<m;i++){
    for (j=3; j>=0; j--) seed[mgfseedLen+j]=(0xFF & (i>> ((3-j)*8)));
    sha512_md(seed, mgfseedLen+4, hash512);
    for (j=0;j<64;j++) mask[i*64+j]=(hash512[j/8]>>(56-(j%8)*8))&0xFF;
  }  
  if (r>0) {
    for (j=3; j>=0; j--) seed[mgfseedLen+j]=(0xFF & (m>>((3-j)*8)));
    sha512_md(seed, mgfseedLen+4, hash512);
    for (j=0;j<r;j++) mask[m*64+j]=(hash512[j/8]>>(56-(j%8)*8))&0xFF;
  }
  return 0;  
}

int RLCE_MGF(unsigned char mgfseed[], int mgfseedLen,
	     unsigned char mask[], int maskLen, int shatype) {
  unsigned char seed[mgfseedLen+4];  
  memcpy(seed, mgfseed, mgfseedLen);
  int hashSize=0; /* hashLen = 4*hashSize */
  void (*sha)(unsigned char[], int, unsigned int[]);

  if (shatype ==0) {
    hashSize = 5;
    sha = sha1_md;
  } else if (shatype == 1) {
    hashSize = 8;
    sha = sha256_md;
  } else if (shatype == 2) {
    hashSize = 8;
  } else {
    return SHATYPENOTSUPPORTED;
  }
  unsigned int hash[hashSize];
  int i,j, m,r;
  if  ((shatype==0) || (shatype==1)) {
    m=maskLen/(4*hashSize);
    r=maskLen%(4*hashSize);
    for (i=0; i<m;i++){
      for (j=3; j>=0; j--) seed[mgfseedLen+j]=(0xFF & i>>((3-j)*8));
      (*sha)(seed, mgfseedLen+4, hash);
      for (j=0;j<(4*hashSize);j++) mask[i*(4*hashSize)+j]=(hash[i/4]>>(24-(i%4)*8)) & 0xFF;
    }
    if (r>0) {
      for (j=3; j>=0; j--) seed[mgfseedLen+j]=(0xFF & m>>((3-j)*8));
      (*sha)(seed, mgfseedLen+4, hash);
      for (j=0;j<r;j++) mask[m*(4*hashSize)+j]=(hash[i/4]>>(24-(i%4)*8)) & 0xFF; 
    }
  } else if (shatype ==2 ) {
    unsigned long hash512[8];
    m=maskLen/64;
    r=maskLen%64;
    for (i=0; i<m;i++){
      for (j=3; j>=0; j--) seed[mgfseedLen+j]=(0xFF & i>> ((3-j)*8));
      sha512_md(seed, mgfseedLen+4, hash512);
      for (j=0;j<64;j++) mask[i*64+j]=(hash512[j/8]>>(56-(j%8)*8))&0xFF;
    }
    if (r>0) {
      for (j=3; j>=0; j--) seed[mgfseedLen+j]=(0xFF & m>> ((3-j)*8));
      sha512_md(seed, mgfseedLen+4, hash512);
      for (j=0;j<r;j++) mask[m*64+j]=(hash512[j/8]>>(56-(j%8)*8))&0xFF;
    }
  }
  return 0;  
}

int B2FE10 (unsigned char bytes[], unsigned int BLen, vector_t FE) {
  int vecLen =FE->size;  
  if (10*vecLen>8*BLen) {
    return BYTEVECTORTOOSMALL;
  }
  int j=0;
  int i;
  int used = 0;

  unsigned char bits = 0x00;
  for (i=0; i<vecLen; i++) {

    switch (used) {
    case 0:
      FE->data[i]=bytes[j];
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xC0);
      bits = bits >>6;
      FE->data[i]=(FE->data[i]) | bits;
      used = 2;
      break;
    case 2:
      FE->data[i]= (bytes[j]<< 2) & 0x00FF;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xF0);
      bits = bits >>4;
      FE->data[i]=(FE->data[i]) | bits;
      used = 4;
      break;
    case 4:
      FE->data[i]= (bytes[j]<< 4) & 0x00FF;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xFC);
      bits = bits >>2;
      FE->data[i]=(FE->data[i]) | bits;
      used = 6;
      break;
    case 6:
      FE->data[i]= (bytes[j]<< 6) & 0x00FF;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xFF);
      FE->data[i]=(FE->data[i]) | bits;
      j++;
      used = 0;
      break;
    default:
      return -1;
    }
  }
  return 0;
}

int FE2B10 (vector_t FE, unsigned char bytes[], unsigned int BLen) {
  int vecLen =FE->size;
  if ((8*BLen) < (vecLen *10)) {
    return BYTEVECTORTOOSMALL;
  }
  int used = 0;
  int j=0;
  int i;
  bytes[j]=0x00;
  unsigned char bits = 0x00;

  for (i=0;i<vecLen;i++){
    switch (used) {
    case 0:
      bytes[j]=(FE->data[i])>>2;
      j++;
      bits = FE->data[i] & 0x0003;
      bytes[j]= bits <<6;
      used = 2;
      break;
    case 2:
      bytes[j]=(((FE->data[i])>>4) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x000F;
      bytes[j]= bits<<4;
      used = 4;      
      break;
    case 4:
      bytes[j]=(((FE->data[i])>>6) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x003F;
      bytes[j]= bits<<2;
      used = 6;      
      break;
    case 6:
      bytes[j]=(((FE->data[i])>>8) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x00FF;
      bytes[j]= bits;
      used = 0;
      j++;
      break;      
    default:
      return -1;
    }
  }
  return 0;  
}




int B2FE11 (unsigned char bytes[], unsigned int BLen, vector_t FE) {
  int vecLen =FE->size;  
  if (11*vecLen>8*BLen) {
    return BYTEVECTORTOOSMALL;
  }
  int j=0;
  int i;
  int used = 0;

  unsigned char bits = 0x00;
  for (i=0; i<vecLen; i++) {

    switch (used) {
    case 0:
      FE->data[i]=bytes[j];
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xE0);
      bits = bits >>5;
      FE->data[i]=(FE->data[i]) | bits;
      used = 3;
      break;
    case 3:
      FE->data[i]= (bytes[j]<< 3) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xFC);
      bits = bits >>2;
      FE->data[i]=(FE->data[i]) | bits;
      used = 6;
      break;
    case 6:
      FE->data[i]= (bytes[j]<< 6) & 0x00FF;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xFF);
      FE->data[i]=(FE->data[i]) | bits;
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0x80);
      bits = bits >>7;
      FE->data[i]=(FE->data[i]) | bits;     
      used = 1;
      break;
    case 1:
      FE->data[i]= (bytes[j]<< 1) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xF0);
      bits = bits >>4;
      FE->data[i]=(FE->data[i]) | bits;
      used = 4;
      break;
    case 4:
      FE->data[i]= (bytes[j]<< 4) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xFE);
      bits = bits >>1;
      FE->data[i]=(FE->data[i]) | bits;
      used = 7;
      break;
    case 7:
      FE->data[i]= (bytes[j]<< 7) & 0x00FF;
      FE->data[i]=FE->data[i]<<1;
      j++;
      bits = (bytes[j] & 0xFF);
      FE->data[i]=(FE->data[i]) | bits;
      FE->data[i]=FE->data[i]<<2;
      j++;
      bits = (bytes[j] & 0xC0);
      bits = bits >>6;      
      FE->data[i]=(FE->data[i]) | bits;
      used = 2;
      break;
    case 2:
      FE->data[i]= (bytes[j]<< 2) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xF8);
      bits = bits >>3;
      FE->data[i]=(FE->data[i]) | bits;
      used = 5;
      break;      
    case 5:
      FE->data[i]= (bytes[j]<< 5) & 0x00FF;
      FE->data[i]=FE->data[i]<<3;
      j++;
      bits = (bytes[j] & 0xFF);
      FE->data[i]=(FE->data[i]) | bits;
      j++;
      used = 0;
      break;
    default:
      return -1;
    }
  }
  return 0;
}

int FE2B11 (vector_t FE, unsigned char bytes[], unsigned int BLen) {
  int vecLen =FE->size;
  if ((8*BLen) < (vecLen *11)) {
    return BYTEVECTORTOOSMALL;
  }
  int used = 0;
  int j=0;
  int i;
  bytes[j]=0x00;
  unsigned char bits = 0x00;

  for (i=0;i<vecLen;i++){
    switch (used) {
    case 0:
      bytes[j]=(FE->data[i])>>3;
      j++;
      bits = FE->data[i] & 0x0007;
      bytes[j]= bits <<5;
      used = 3;
      break;
    case 3:
      bytes[j]=(((FE->data[i])>>6) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x003F;
      bytes[j]= bits<<2;
      used = 6;      
      break;
    case 6:
      bytes[j]=(((FE->data[i])>>9) | bytes[j]);
      j++;
      bytes[j] = (FE->data[i]>>1) & 0x00FF;
      j++;
      bits = FE->data[i] & 0x0001;
      bytes[j]= bits<<7;
      used = 1;      
      break;
    case 1:
      bytes[j]=(((FE->data[i])>>4) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x000F;
      bytes[j]= bits<<4;
      used = 4;
      break;
    case 4:
      bytes[j]=(((FE->data[i])>>7) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x007F;
      bytes[j]= bits<<1;
      used = 7;
      break;
    case 7:
      bytes[j]=(((FE->data[i])>>10) | bytes[j]);
      j++;
      bytes[j] = (FE->data[i]>>2) & 0x00FF;
      j++;
      bits = FE->data[i] & 0x0003;
      bytes[j]= bits<<6;
      used = 2;      
      break;
    case 2:
      bytes[j]=(((FE->data[i])>>5) | bytes[j]);
      j++;
      bits = FE->data[i] & 0x001F;
      bytes[j]= bits<<3;
      used = 5;
      break;
    case 5:
      bytes[j]=(((FE->data[i])>>8) | bytes[j]);
      j++;
      bytes[j] = (FE->data[i]) & 0x00FF;
      j++;
      used = 0;      
      break;      
    default:
      return -1;
    }
  }
  return 0;  
}


int matrix_add(matrix_t A, matrix_t B, matrix_t C) {
  int i;
  for (i=0; i<A->numR; i++) {
    GF_addvec(A->data[i], B->data[i], C->data[i], C->numC);
  }
  return 0;
}

int matrix_mul_strassen (matrix_t A, matrix_t B, matrix_t C,int m) {
  int i,ret;
  int row=A->numR;
  int col=C->numC;
  int midRC=A->numC;
  if ((midRC != B->numR) ||(row != C->numR) ||(B->numC != col) ) {
    return MATRIXROWCOLUMNNOTMATCH;
  }
  if ((row <STRASSENCONST)||(col<STRASSENCONST)||(midRC<STRASSENCONST)) {
    return  matrix_standard_mul(A, B, C, m);
  }

  matrix_t A11, A12, A21, A22, B11, B12, B21, B22;
  matrix_t M1, M2, M3, M4, M5, M6, M7, Mt1, Mt2;
  
  int rowHalf = row/2;
  int rowRem = row %2;
  
  int midRCHalf = midRC/2;
  int midRCRem = midRC%2;
  
  int colHalf = col/2;
  int colRem = col%2;

  int rowHf = rowHalf+rowRem;
  int midRCf=midRCHalf+midRCRem;
  int colHf = colHalf+colRem;
  
  A11 = matrix_init(rowHf, midRCf);
  A12 = matrix_init(rowHf, midRCf);
  A21 = matrix_init(rowHf, midRCf);
  A22 = matrix_init(rowHf, midRCf);
  B11 = matrix_init(midRCf, colHf);
  B12 = matrix_init(midRCf, colHf);
  B21 = matrix_init(midRCf, colHf);
  B22 = matrix_init(midRCf, colHf);
  M1=matrix_init(rowHf, colHf);
  M2=matrix_init(rowHf, colHf);
  M3=matrix_init(rowHf, colHf);
  M4=matrix_init(rowHf, colHf);
  M5=matrix_init(rowHf, colHf);
  M6=matrix_init(rowHf, colHf);
  M7=matrix_init(rowHf, colHf);
  Mt1=matrix_init(rowHf, midRCf);
  Mt2=matrix_init(midRCf, colHf);
  
  for (i=0; i<rowHf; i++) {
    memcpy(A11->data[i], A->data[i], midRCf*sizeof(field_t));
    memcpy(A12->data[i], &(A->data[i][midRCf]), (midRCf-midRCRem)*sizeof(field_t));
  }
  for (i=0; i<rowHf-rowRem; i++) {
    memcpy(A21->data[i], A->data[rowHf+i], midRCf*sizeof(field_t));
    memcpy(A22->data[i], &(A->data[rowHf+i][midRCf]), (midRCf-midRCRem)*sizeof(field_t));
  }   
  for (i=0; i<midRCf; i++) {
    memcpy(B11->data[i], B->data[i], colHf*sizeof(field_t));    
    memcpy(B12->data[i], &(B->data[i][colHf]), (colHf-colRem)*sizeof(field_t));
  }
  for (i=0; i<midRCf-midRCRem; i++) {
    memcpy(B21->data[i], B->data[midRCf+i], colHf*sizeof(field_t));
    memcpy(B22->data[i], &(B->data[midRCf+i][colHf]), (colHf-colRem)*sizeof(field_t));
  }
  
  matrix_add(A11, A22, Mt1);
  matrix_add(B11, B22, Mt2);
  ret=matrix_mul_strassen (Mt1, Mt2, M1, m);
  if (ret <0) return ret;
  matrix_add(A21, A22, Mt1);
  ret=matrix_mul_strassen (Mt1, B11, M2, m);
  if (ret <0) return ret;
  matrix_add(B12, B22, Mt2);
  ret=matrix_mul_strassen (A11, Mt2, M3, m);
  if (ret <0) return ret;
  matrix_add(B21, B11, Mt2);
  ret=matrix_mul_strassen (A22, Mt2, M4, m);
  if (ret <0) return ret;
  matrix_add(A11, A12, Mt1);
  ret=matrix_mul_strassen (Mt1, B22, M5, m);
  if (ret <0) return ret;
  matrix_add(A21, A11, Mt1);
  matrix_add(B11, B12, Mt2);
  ret=matrix_mul_strassen (Mt1, Mt2, M6, m);
  if (ret <0) return ret;
  matrix_add(A12, A22, Mt1);
  matrix_add(B21, B22, Mt2);  
  ret=matrix_mul_strassen (Mt1, Mt2, M7, m);
  if (ret <0) return ret;
  
  for (i=0; i<rowHf; i++) {
    GF_addvec(M1->data[i], M4->data[i], C->data[i], colHf);
    GF_addvec(M5->data[i], C->data[i], NULL,colHf);
    GF_addvec(M7->data[i], C->data[i], NULL,colHf);
    GF_addvec(M3->data[i], M5->data[i], &(C->data[i][colHf]), colHf-colRem);
  }
  for (i=0; i<rowHf-rowRem; i++) {
    GF_addvec(M2->data[i], M4->data[i], C->data[rowHf+i], colHf);
    GF_addvec(M1->data[i], M2->data[i], &(C->data[rowHf+i][colHf]), colHf-colRem);
    GF_addvec(M3->data[i], &(C->data[rowHf+i][colHf]),NULL, colHf-colRem);
    GF_addvec(M6->data[i], &(C->data[rowHf+i][colHf]),NULL, colHf-colRem);    
  }
  
  matrix_free(A11);
  matrix_free(A12);
  matrix_free(A21);
  matrix_free(A22);
  matrix_free(B11);
  matrix_free(B12);
  matrix_free(B21);
  matrix_free(B22);
  matrix_free(M1);
  matrix_free(M2);
  matrix_free(M3);
  matrix_free(M4);
  matrix_free(M5);
  matrix_free(M6);
  matrix_free(M7);
  matrix_free(Mt1);
  matrix_free(Mt2);
  return 0;
}

int matrix_inv_strassen (matrix_t A, matrix_t dest, int m) {
  int i, ret=0;
  int row = A->numR;
  if ((row != dest->numR) ||(row != dest->numC) || (row != A->numC )) {
    return MATRIXROWCOLUMNNOTMATCH;
  }
  if (row<STRAINVCONST) return matrix_inv_standard(A,dest,m);

  matrix_t A11, A12, A21, A22;
  matrix_t M1, M3, M4;
  
  int rowHalf = row/2;
  int rowRem = row%2;
  int rowHf = rowHalf+rowRem;
  
  A11 = matrix_init(rowHf, rowHf);
  A12 = matrix_init(rowHf, rowHf);
  A21 = matrix_init(rowHf, rowHf);
  A22 = matrix_init(rowHf, rowHf);
  M1=matrix_init(rowHf, rowHf);
  M3=matrix_init(rowHf, rowHf);
  M4=matrix_init(rowHf, rowHf);

  for (i=0; i<rowHf; i++) {
    memcpy(A11->data[i], A->data[i], rowHf*sizeof(field_t));
    memcpy(A12->data[i], &(A->data[i][rowHf]), (rowHf-rowRem)*sizeof(field_t));
  }
  for (i=0; i<rowHf-rowRem; i++) {
    memcpy(A21->data[i], A->data[rowHf+i], rowHf*sizeof(field_t));
    memcpy(A22->data[i], &(A->data[rowHf+i][rowHf]), (rowHf-rowRem)*sizeof(field_t));
  }
  if (rowRem >0) A22->data[rowHf-1][rowHf-1]=1;
  ret=matrix_inv_strassen(A11, M1, m);
  if (ret <0) return ret;
  ret=matrix_mul_strassen(A21, M1, A11, m); /* A11 is used as M2*/
  if (ret <0) return ret;
  ret=matrix_mul_strassen(M1, A12, M3, m);
  if (ret <0) return ret;
  ret=matrix_mul_strassen(A21, M3, M4, m);
  if (ret <0) return ret;
  ret=matrix_add(M4, A22, A21); /* A21 is used as M5*/
  if (ret <0) return ret;
  ret=matrix_inv_strassen(A21, A22, m); /* A22 is used as M6*/
  if (ret <0) return ret;
  ret=matrix_mul_strassen(M3, A22, A21, m); /* A21 is used as C12*/
  if (ret <0) return ret;
  ret=matrix_mul_strassen(A22, A11, M4, m); /* M4 is used as C21 */
  if (ret <0) return ret;
  ret=matrix_mul_strassen(M3, M4, A11, m); /* A11 is used as M7 */
  if (ret <0) return ret;
  for (i=0; i<rowHf; i++) {
    GF_addvec(M1->data[i], A11->data[i], dest->data[i], rowHf);
    memcpy(&(dest->data[i][rowHf]), A21->data[i], (rowHf-rowRem)*sizeof(field_t));
  }
  for (i=0; i<rowHf-rowRem; i++) {
    memcpy(dest->data[rowHf+i], M4->data[i], rowHf*sizeof(field_t));
    memcpy(&(dest->data[rowHf+i][rowHf]), A22->data[i], (rowHf-rowRem)*sizeof(field_t));    
  }
  matrix_free(A11);
  matrix_free(A12);
  matrix_free(A21);
  matrix_free(A22);
  matrix_free(M1);
  matrix_free(M3);
  matrix_free(M4);
  return 0;
}

int matrix_vec_mat_mul(field_t V[], int vsize, matrix_t B, field_t dest[],int dsize, int m){
  switch(WINOGRADVEC) {
  case 0:
    return matrix_vec_mat_mul_standard(V,vsize, B, dest, dsize,m);
    break;
  case 1:
    return matrix_vec_mat_mul_standard(V,vsize, B, dest, dsize,m);
    break;
  default:
      return matrix_vec_mat_mul_standard(V,vsize, B, dest, dsize,m);
    break;
  }
  return 0;
}

int matrix_mul(matrix_t A, matrix_t B, matrix_t C, int m) {
  switch(MATRIXMUL) {
  case 0:
    return matrix_standard_mul(A,B,C,m);
    break;
  case 1:
    return matrix_mul_strassen(A,B,C,m);
    break;
  case 2:
    return matrix_standard_mul(A,B,C,m);
    break;
  default:
    return matrix_standard_mul(A,B,C,m);
    break;
  }
  return 0;
}

int matrix_inv(matrix_t G, matrix_t Ginv, int m){
  switch(MATINV) {
  case 1:
    return matrix_inv_strassen(G,Ginv,m); 
    break;
  default:
    return matrix_inv_standard(G,Ginv, m);
    break;
  }
  return 0;
}
