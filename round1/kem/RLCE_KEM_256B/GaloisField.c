/* GaloisField.c
 * Yongge Wang 
 *
 * Code was written: November 1, 2016-December 1, 2016
 *
 * galois.c implements the field arithmetics 
 * for RLCE scheme that is part of the package 
 * RLCE.tar - Random Linear Code Encryption Scheme
 *
 * Copright (C) 2016 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 Primitive polynomials are used for Galois field
 For GF(2^m), we use a primitive polynomial of degree m
 List of primitive polynomials from the  paper: 
        Stahnke, Wayne. "Primitive binary polynomials." 
        Math. of Comput. 27.124 (1973): 977-980.
 A tuple (9,4,0) represents the polynomial g(x)=x^9+x^4+1
 We can also denote a polynomial using it coefficients.
 e.g., (9, 4, 0) is written as  0000 0010 0001 0001 

 (8, 6, 5, 1, 0)     or  0000 0001 0110 0011 or 0x0163 or 0435
 (9, 4, 0)           or  0000 0010 0001 0001 or 0x0211 or 01021
 (10, 3, 0)          or  0000 0100 0000 1001 or 0x0409 or 02011
 (11, 2, 0)          or  0000 1000 0000 0101 or 0x0805 or 04005
 (12, 7, 4, 3, 0)    or  0001 0000 1001 1001 or 0x1099 or 010123
 (13, 4, 3, 1, 0)    or  0010 0000 0001 1011 or 0x2129 or 020033
 (14, 12, 11, 1, 0)  or  0101 1000 0000 0011 or 0x5803 or 042103
 (15, 1, 0)          or  1000 0000 0000 0011 or 0x8003 or 0100003
 (16, 5, 3, 2, 0)    or 10000 0000 0010 1101 or 0x002D or 0210013
 for GF(2^16), the primitive polynomial should be 0x1002D
 but we will ignore the most important bit
 This implementation only includes GF(2^8), .., GF(2^16)
 for GF(2^8) we may use uint8_t as the data type
 */

#include "rlce.h"
int poly[17] = {0,0,0,0,0,0,0,0,0x0163,0x0211,0x0409,0x0805,0x1099,0x2129,0x5803,0x8003,0x002D};  
int fieldSize[17]={0,0,0,0,0,0,0,0,(1u<<8), (1u<<9),(1u<<10),(1u<<11),(1u<<12),(1u<<13),(1u<<14),(1u<<15),(1u<<16)};
int fieldOrder[17]={0,0,0,0,0,0,0,0,(1u<<8)-1,(1u<<9)-1,(1u<<10)-1,(1u<<11)-1,(1u<<12)-1,(1u<<13)-1,(1u<<14)-1,(1u<<15)-1,(1u<<16)-1};
short *GFlogTable[17]={NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
short *GFexpTable[17]={NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
short **GFmulTable[17]={NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};
short **GFdivTable[17]={NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL};

int GF_init_logexp_table(int m) {
  field_t j,fE=1;
  if (GFlogTable[m] != NULL) return 0;
  GFlogTable[m] = (short *) calloc(fieldSize[m], sizeof(short)); 
  if (GFlogTable[m] == NULL) return GFTABLEERR; 
  GFexpTable[m] = (short *)calloc(3*fieldSize[m], sizeof(short)); 
  if (GFexpTable[m] == NULL) { 
    free(GFlogTable[m]);
    GFlogTable[m] = NULL;
    return GFTABLEERR ;
  } 
  for (j=0;j<fieldSize[m];j++) GFlogTable[m][j]=fieldOrder[m];
  GFexpTable[m][0] = 1;
  GFexpTable[m][fieldOrder[m]] = 1;
  for (j = 0; j < fieldOrder[m]; j++) {
    GFlogTable[m][fE] = j; 
    GFexpTable[m][j] = fE;
    fE = fE << 1; 
    if (fE & fieldSize[m]) fE = (fE ^ poly[m]) & (fieldOrder[m]);
  }
  memcpy(&GFexpTable[m][fieldOrder[m]],GFexpTable[m], fieldOrder[m]*sizeof(short));
  memcpy(&GFexpTable[m][2*fieldOrder[m]],GFexpTable[m], fieldOrder[m]*sizeof(short));
  GFexpTable[m] +=fieldOrder[m];
  return 0;
}

int GF_init_mult_table(int m) {
  int ret, i, j;
  if (GFmulTable[m] != NULL) return 0;
  GFmulTable[m]=calloc(fieldSize[m], sizeof(int*));
  for (i=0;i<fieldSize[m]; i++)
    GFmulTable[m][i]=(short *) calloc(fieldSize[m], sizeof(short));
  ret=GF_init_logexp_table(m);
  if (ret<0) return ret;
  for (i=1;i<fieldSize[m]; i++) {
    for (j=1; j<fieldSize[m]; j++) 
      GFmulTable[m][i][j]=GFexpTable[m][GFlogTable[m][i]+GFlogTable[m][j]];
  }  
  return 0;
}

int GF_init_div_table(int m) {
  int ret, i, j;
  if (GFdivTable[m] != NULL) return 0;
  GFdivTable[m]=calloc(fieldSize[m], sizeof(int*));
  for (i=0;i<fieldSize[m]; i++)
    GFdivTable[m][i]=(short *) calloc(fieldSize[m], sizeof(short));
  ret=GF_init_logexp_table(m);
  if (ret<0) return ret;
  for (i=1;i<fieldSize[m]; i++) {
    for (j=1; j<fieldSize[m]; j++)
      GFdivTable[m][i][j]=GFexpTable[m][GFlogTable[m][i]-GFlogTable[m][j]];
  }  
  return 0;
}

field_t GF_add(field_t x, field_t y) {return x^y;}

int GF_addvec(field_t vec1[], field_t vec2[],field_t vec3[], int vecSize){
  int i, longsize;
  longsize = sizeof(unsigned long long);
  if (vec3==NULL) vec3=vec2;
  unsigned int size=(sizeof(field_t)*vecSize)/longsize;
  unsigned long long* longvec1=(unsigned long long*) vec1;
  unsigned long long* longvec2=(unsigned long long*) vec2;
  unsigned long long* longvec3=(unsigned long long*) vec3;
  for (i=0; i<size; i++) longvec3[i]= longvec2[i] ^ longvec1[i];
  for (i=(longsize*size)/sizeof(field_t); i<vecSize; i++) vec3[i] =vec2[i]^vec1[i];
  return 0;
}

int GF_addF2vec(field_t x, field_t vec2[],field_t vec3[], int vecSize){
  int i, longsize;
  longsize = sizeof(unsigned long long);
  field_t vec1[longsize/sizeof(field_t)];
  for (i=0;i<longsize/sizeof(field_t); i++) vec1[i]=x;
  if (vec3==NULL) vec3=vec2;
  unsigned int size=(sizeof(field_t)*vecSize)/longsize;
  unsigned long long* longvec1=(unsigned long long*) vec1;
  unsigned long long* longvec2=(unsigned long long*) vec2;
  unsigned long long* longvec3=(unsigned long long*) vec3;
  for (i=0; i<size; i++) longvec3[i]= longvec2[i] ^ longvec1[0];
  for (i=(longsize*size)/sizeof(field_t); i<vecSize; i++) vec3[i] =vec2[i]^x;
  return 0;
}

field_t GF_tablediv(field_t x, field_t y, int m) {
  GF_init_div_table(m);
  return GFdivTable[m][x][y];
}

field_t GF_fexp(field_t x, int y, int m) {
  int result;
  GF_init_logexp_table(m);
  if (x == field_zero()) return 0;
  if (y==0) return x;
  result = (GFlogTable[m][x] + y); 
  return GFexpTable[m][result];
}

void GF_vecinverse(field_t vec1[], field_t vec2[], int vecsize, int m) {
  int i;
  GF_init_logexp_table(m);
  if (vec2==NULL) vec2=vec1;
  for (i=0; i<vecsize; i++) vec2[i]=GFexpTable[m][fieldOrder[m]-GFlogTable[m][vec1[i]]];
  return;
}

void GF_vec_winograd(field_t x,field_t V[],matrix_t B,matrix_t tmp,unsigned int m) {
  int i,j;
  field_t z1, z2;
  if (GFMULTAB==1) {
    GF_init_mult_table(m);
    for (i=0;i<B->numC; i++) {
      for (j=0; j<(B->numR)/2; j++) {
	z1= (V[2*j])^(B->data[2*j+1][i]);
	z2= (V[2*j+1])^(B->data[2*j][i]);
	tmp->data[j][i]=GFmulTable[m][z1][z2]; 
      }
      tmp->data[0][i] ^= x;
    }
    return;
  }
  GF_init_logexp_table(m);
  for (i=0;i<B->numC; i++) {
    for (j=0; j<(B->numR)/2; j++) {
      z1= (V[2*j])^(B->data[2*j+1][i]);
      z2= (V[2*j+1])^(B->data[2*j][i]);
      if ((z1==0) || (z2==0)) {
	tmp->data[j][i]=0;
      } else {
	tmp->data[j][i]=GFexpTable[m][GFlogTable[m][z1]+GFlogTable[m][z2]];
      }
    }
    tmp->data[0][i] ^= x;
  }    
  return;
}

void GF_mulvec(field_t x, field_t vec[], field_t dest[],int dsize, unsigned int m) {
  /* multiply each element in a range of memory by x  */
  int i;
  if (dest==NULL) dest=vec;
  if (GFMULTAB==1) {
    GF_init_mult_table(m);
    for (i=0; i<dsize; i++) dest[i]=GFmulTable[m][x][vec[i]];
    return;
  } 
  unsigned int xlog, tmp;
  GF_init_logexp_table(m);
  if (x == field_zero()) {
    memset(vec, 0, dsize*sizeof(field_t));
    return;
  }
  xlog = GFlogTable[m][x];
  for (i=0; i<dsize; i++) {
    if(vec[i]==0) {
      dest[i]=0;
    } else {
      tmp=xlog+GFlogTable[m][vec[i]];
      dest[i]= GFexpTable[m][tmp];
    }
  }
  return;
}

void GF_vecdiv(field_t x, field_t vec[], field_t dest[],int dsize, unsigned int m) {
  /* dest[i]= vec[i]/x */
  int i;
  if (dest==NULL) dest=vec;
  if (GFMULTAB==1) {
    GF_init_mult_table(m);
    field_t xinverse=GFexpTable[m][fieldOrder[m]-GFlogTable[m][x]];
    for (i=0; i<dsize; i++) dest[i]=GFmulTable[m][xinverse][vec[i]];
    return;
  } 
  int xlog, tmp;
  GF_init_logexp_table(m);
  if (x == field_zero()) {
    memset(vec, 0, dsize*sizeof(field_t));
    return;
  }
  xlog = GFlogTable[m][x];
  for (i=0; i<dsize; i++) {
    if(vec[i]==0) {
      dest[i]=0;
    } else {
      tmp=GFlogTable[m][vec[i]]+fieldOrder[m]-xlog; 
      dest[i]= GFexpTable[m][tmp];
    }
  }
  return;
}

void GF_divvec(field_t vec1[],field_t vec2[], int vsize, unsigned int m) {
  /* return vec1[i]=vec1[i]/vec2[i] */
  int i;
  if (GFMULTAB==1) {
    GF_init_mult_table(m);
    for (i=0;i<vsize;i++) vec1[i]=GFmulTable[m][vec1[i]][GFexpTable[m][-GFlogTable[m][vec2[i]]]];
    return;
  }
  GF_init_logexp_table(m);
  for (i=0;i<vsize;i++)
    vec1[i]=GFexpTable[m][GFlogTable[m][vec1[i]]+fieldOrder[m]-GFlogTable[m][vec2[i]]];
  return;
}

int GF_vecreversemul(field_t vec1[],field_t vec2[],int vsize,int m) {
  int i, d=0;
  if (GFMULTAB==1) {
    GF_init_mult_table(m);
    for (i=0; i< vsize; i++) d ^= GFmulTable[m][vec1[i]][vec2[vsize-1-i]];
    return d;
  }
  GF_init_logexp_table(m);
  for (i=0; i< vsize; i++) {
    if ((vec1[i]!=0) && (vec2[vsize-1-i]!=0)) {
      d ^= GFexpTable[m][(GFlogTable[m][vec1[i]]+GFlogTable[m][vec2[vsize-1-i]])];
    }
  }   
  return d;
}

int getMatrixAandAinv(matrixA_t mat, matrixA_t matInv,
			    field_t randomElements[], int randBytes,int m) {
  int i, j=0,randB=0; 
  field_t a;
  for (i=0;i<randBytes; i++) {
    if (randomElements[i]!=0) {
      randomElements[randB]=randomElements[i];
      randB++;
    }
  } 
  if (GFMULTAB==1) {
    GF_init_mult_table(m);
    for (i=0; i< mat->size; i++) {
      field_t det=0;
      while (det==0) {
	a= GFmulTable[m][randomElements[j]][randomElements[j+3]];
	det=a^ GFmulTable[m][randomElements[j+1]][randomElements[j+2]];
	if (det==0) j++;
	if (j+4 >randB) return NEEDNEWRANDOMSEED;
      }
      memcpy((mat->A[i])->data[0], &(randomElements[j]), 2*sizeof(field_t));
      memcpy((mat->A[i])->data[1], &(randomElements[j+2]), 2*sizeof(field_t));
      a=GFexpTable[m][fieldOrder[m]-GFlogTable[m][det]];
      (matInv->A[i])->data[0][0] = GFmulTable[m][randomElements[j+3]][a];
      (matInv->A[i])->data[1][0] = GFmulTable[m][randomElements[j+2]][a]; 
      j=j+4;
    }    
    return 0;
  } 
  GF_init_logexp_table(m);
  for (i=0; i< mat->size; i++) {
    field_t det=0, detinv;
    while (det==0) {
      a=GFexpTable[m][GFlogTable[m][randomElements[j]]+GFlogTable[m][randomElements[j+3]]];     
      det = a^GFexpTable[m][GFlogTable[m][randomElements[j+1]]+GFlogTable[m][randomElements[j+2]]]; 
      if (det==0) j++; 
      if (j+4 >randB) return NEEDNEWRANDOMSEED;
    }
    memcpy((mat->A[i])->data[0], &(randomElements[j]), 2*sizeof(field_t));
    memcpy((mat->A[i])->data[1], &(randomElements[j+2]), 2*sizeof(field_t));
    detinv=fieldOrder[m]-GFlogTable[m][det];
    (matInv->A[i])->data[0][0] = GFexpTable[m][GFlogTable[m][randomElements[j+3]]+detinv];
    (matInv->A[i])->data[1][0] = GFexpTable[m][GFlogTable[m][randomElements[j+2]]+detinv];
    j=j+4;
  }
  return 0;
};

void GF_expvec(field_t vec[], int size, int m) {
  GF_init_logexp_table(m);
  int i;
  for (i=0;i<size;i++) vec[i]=GFexpTable[m][vec[i]];
}

void GF_logmulvec(int xlog, field_t vec[], field_t dest[],int dsize, unsigned int m) {
  /* multiply each element in a range of memory by \alpha^xlog  */
  int i;
  field_t x;
  if (GFMULTAB==1) {
     GF_init_mult_table(m);
     x= GFexpTable[m][xlog];
     for (i=0; i<dsize; i++) dest[i]=GFmulTable[m][x][vec[i]];
     return;
  }
  unsigned int  tmp;
  GF_init_logexp_table(m);
  memset(dest,0,dsize*sizeof(field_t));
  for (i=0; i<dsize; i++) {
    if(vec[i]!=0) {
      tmp= xlog+GFlogTable[m][vec[i]];  
      dest[i]= GFexpTable[m][tmp];
    }    
  }
  return;
}

void GF_vecvecmul(field_t v1[], field_t v2[], field_t v3[], int vsize, unsigned int m)  {
  int i;
  if (v3==NULL) v3=v2;
  if (GFMULTAB==1) {
    GF_init_mult_table(m);
    for (i=0;i<vsize;i++) v3[i]=GFmulTable[m][v1[i]][v2[i]];
    return;
  }
  GF_init_logexp_table(m);
  for (i=0;i<vsize;i++) {
    if ((v1[i]!=0) && (v2[i]!=0)) {
      v3[i]=GFexpTable[m][(GFlogTable[m][v1[i]]+GFlogTable[m][v2[i]])];
    } else v3[i]=0;
  }
}

void GF_mulexpvec2(field_t x, field_t vec[], field_t dest[],int dsize, unsigned int m) {
  /* multiply vec[i] by x^i  */
  unsigned int xlog, tmp;
  int i;
  GF_init_logexp_table(m);
  memset(dest, 0, dsize*sizeof(field_t));
  if (x == 0) return;
  xlog = GFlogTable[m][x];
  for (i=0; i<dsize; i++) {
    if(vec[i]!=0) {
      tmp=(i*xlog+GFlogTable[m][vec[i]])%fieldOrder[m];
      dest[i]= GFexpTable[m][tmp];
    }    
  }
  return;
}

void GF_evalpoly(int log, poly_t p, field_t input[], field_t output[], int size, int m) {
  int i,j;
  field_t *inpute;
  GF_init_logexp_table(m);
  if (log==1) {
    inpute=input;
  } else {
    inpute=calloc(size, sizeof(field_t));
    for (i=0; i<size; i++) inpute[i]=GFlogTable[m][input[i]];
  }
  field_t *row=calloc(size, sizeof(field_t));
  field_t tmp;
  for (j=0; j<size; j++) output[j]=p->coeff[0];
  for (i=1; i<1+p->deg; i++) {
    if (p->coeff[i] !=0) {      
      tmp=GFlogTable[m][p->coeff[i]];
      for (j=0; j<size; j++)
	row[j]=GFexpTable[m][(tmp+i*inpute[j]) % fieldOrder[m]];
      GF_addvec(row, output,NULL,size);
    }
  }
  free(row);
  if (log==0) free(inpute);
  return;
}

void GF_rsgenerator2optG(matrix_t optG, poly_t generator, field_t grsE[], int m) {
  int i,j;
  if (GFMULTAB==1) {
    GF_init_mult_table(m);
    for (i=0; i<optG->numC; i++) {
      for (j=i; j<i+1+generator->deg; j++) {
	optG->data[j][i]=GFmulTable[m][generator->coeff[j-i]][grsE[j]];
      }
    }
    return;
  }
  for (i=0; i<optG->numC; i++) {
    for (j=i; j<i+1+generator->deg; j++) {
      if (generator->coeff[j-i] !=0) {
	optG->data[j][i]=
	  GFexpTable[m][GFlogTable[m][generator->coeff[j-i]]+GFlogTable[m][grsE[j]]];
      }
    }
  }
  return;
}

int matrix_opt_mul_A(matrix_t G, matrixA_t A, int startP, int m) {
  /* return ((G^T)*A)^T starting from column "startP" of G^T */
  int i,j;
  field_t *tmp1=calloc(G->numC, sizeof(field_t));
  field_t *tmp2=calloc(G->numC, sizeof(field_t));
  field_t *tmp3=calloc(G->numC, sizeof(field_t));
  field_t *tmp4=calloc(G->numC, sizeof(field_t));  
  if (GFMULTAB==1) {
     GF_init_mult_table(m);
     for (j=0; j<A->size; j++) {
       for (i=0; i<G->numC; i++) {
	 tmp1[i]=GFmulTable[m][G->data[startP+2*j][i]][(A->A[j])->data[0][0]];
	 tmp2[i]=GFmulTable[m][G->data[startP+2*j][i]][(A->A[j])->data[0][1]];
	 tmp3[i]=GFmulTable[m][G->data[startP+2*j+1][i]][(A->A[j])->data[1][0]];
	 tmp4[i]=GFmulTable[m][G->data[startP+2*j+1][i]][(A->A[j])->data[1][1]];
       }
       GF_addvec(tmp1, tmp3, G->data[startP+2*j], G->numC);
       GF_addvec(tmp2, tmp4, G->data[startP+2*j+1], G->numC);
     }
     free(tmp1);
     free(tmp2);
     free(tmp3);
     free(tmp4);
     return 0;
  }
  GF_init_logexp_table(m);
  for (j=0; j<A->size; j++) {
    memset(tmp1,0,(G->numC)*sizeof(field_t));
    memset(tmp2,0,(G->numC)*sizeof(field_t));
    memset(tmp3,0,(G->numC)*sizeof(field_t));
    memset(tmp4,0,(G->numC)*sizeof(field_t));
    for (i=0; i<G->numC; i++) {
      if (G->data[startP+2*j][i]!=0) {
	tmp1[i]=GFexpTable[m][GFlogTable[m][G->data[startP+2*j][i]]+GFlogTable[m][(A->A[j])->data[0][0]]];
	tmp2[i]=GFexpTable[m][GFlogTable[m][G->data[startP+2*j][i]]+GFlogTable[m][(A->A[j])->data[0][1]]];
      }
      if (G->data[startP+2*j+1][i]!=0) {
	tmp3[i]=GFexpTable[m][GFlogTable[m][G->data[startP+2*j+1][i]] + GFlogTable[m][(A->A[j])->data[1][0]]];
	tmp4[i]=GFexpTable[m][GFlogTable[m][G->data[startP+2*j+1][i]] + GFlogTable[m][(A->A[j])->data[1][1]]];
      }
    }
    GF_addvec(tmp1, tmp3, G->data[startP+2*j], G->numC);
    GF_addvec(tmp2, tmp4, G->data[startP+2*j+1], G->numC);
  }
  free(tmp1);
  free(tmp2);
  free(tmp3);
  free(tmp4);
  return 0;
}

void rootsLocation(field_t roots[],int nRoots,field_t eLocation[],field_t rootsLog[],int m) {
  int i;
  for (i=0; i<nRoots; i++) {
    if (roots[i] != 0) {
	rootsLog[i]=GFlogTable[m][roots[i]];
	if (rootsLog[i] == 0){
	  eLocation[i]= 0;
	} else {
	  eLocation[i]= fieldOrder[m]-rootsLog[i];
	}
    }
  }
  return;
}

void GF_mulAinv(field_t cp[], matrixA_t A, field_t C1[], int m) {
  int j;
  if (GFMULTAB==1) {
    GF_init_mult_table(m);
    for (j=0; j<A->size; j++) C1[j]=GFmulTable[m][cp[2*j]][(A->A[j])->data[0][0]] ^GFmulTable[m][cp[2*j+1]][(A->A[j])->data[1][0]];
    return;
  }
  field_t b1, b2;
  for (j=0; j<A->size; j++) {
    b1=0;
    b2=0;
    if (cp[2*j]!=0)
      b1=GFexpTable[m][GFlogTable[m][cp[2*j]]+GFlogTable[m][(A->A[j])->data[0][0]]];
    if (cp[2*j+1]!=0)
      b2=GFexpTable[m][GFlogTable[m][cp[2*j+1]]+GFlogTable[m][(A->A[j])->data[1][0]]];
    C1[j]=b1 ^ b2;
  }
  return;
}


void GF_x2px(field_t vec[], field_t dest[], int size, int m) {
  int i;
  if (GFMULTAB==1) {
    GF_init_mult_table(m);
    for (i=0;i<size; i++) dest[i]= vec[i] ^ GFmulTable[m][vec[i]][vec[i]];
    return;
  }
  for (i=0;i<size; i++)
    dest[i]= vec[i] ^ GFexpTable[m][GFlogTable[m][vec[i]]+GFlogTable[m][vec[i]]];
  return;
}


field_t GF_mul(field_t x, field_t y, int m) {  
  int result;
  if (GFMULTAB==1) {
    GF_init_mult_table(m);
    return GFmulTable[m][x][y];
  } 
  GF_init_logexp_table(m);
  if (x == field_zero() || y == field_zero()) return 0;
  result = GFlogTable[m][x] + GFlogTable[m][y];
  return GFexpTable[m][result];
  
}

