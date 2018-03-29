/* fieldPoly.c
 * Yongge Wang 
 *
 * Code was written: November 4, 2016-
 *
 * fieldPoly.c implements polynomial arithmetics 
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

poly_t poly_init(int n) {
  poly_t p;
  p = (poly_t) malloc(sizeof (struct polynomial));
  p->deg = -1;
  p->size = n;
  p->coeff = (field_t *) calloc(n, sizeof (field_t));
  return p;
}

void poly_zero(poly_t p) {
  p->deg = -1;
  memset(p->coeff, 0, (p->size)*sizeof(field_t));
}

void poly_copy(poly_t p, poly_t q) {
  memset(q->coeff, 0, (q->size)*sizeof(field_t));
  q->deg = p->deg;
  memcpy(q->coeff, p->coeff, (p->size) * sizeof (field_t));
}


void poly_free(poly_t p) {
  free(p->coeff);
  p->coeff=NULL;
  free(p);
  p=NULL;
}

field_t poly_eval(poly_t p, field_t a, int m) {
  field_t result;
  int i;
  int d = p->deg;
  if (d<0) return 0;
  if ((d==0)||(a==0)) return p->coeff[0];
  result=p->coeff[d];
  for (i=d-1; i>=0; i--) {
    if (result != field_zero()) {
      result = GF_mul(result, a, m) ^ p->coeff[i];
    } else {
      result = p->coeff[i];
    }
  }
  return result; 
}



field_t poly_evalopt(poly_t p, field_t a, int m) {
  field_t result=0;
  int i;
  int d = p->deg;
  if (d<0) return 0;
  if ((d==0)||(a==0)) return p->coeff[0];
  field_t *dest;
  dest = calloc(d+1, sizeof(field_t));
  GF_mulexpvec2(a, p->coeff,  dest, d+1, m);
  for (i=0; i<d+1; i++) result ^= dest[i];
  free(dest);
  return result; 
}


int poly_deg(poly_t p) {
  int i;
  for (i=(p->size - 1); i>=0; i--) {
    if (p->coeff[i] != field_zero()) {
      p->deg = i;
      return i;
    }
  }
  p->deg= -1;
  return -1;
}


int poly_mul_karatsuba(poly_t f, poly_t g, poly_t r, int m) {  
  int d= f->deg + g->deg; 
  if (d >= r->size) return POLYMULTERRR;
  int maxdeg =0;
  int mindeg=0;
  int middeg=0;
  if ((f->deg) > (g->deg)) {
    maxdeg = f->deg;
    mindeg = g->deg;
  } else {
    maxdeg = g->deg;
    mindeg = f->deg;
  }
  if (mindeg <35) return poly_mul_standard(f,g, r, m);
  middeg = 1+maxdeg/2;

  poly_t f1 = poly_init(middeg);
  poly_t f2 = poly_init(middeg);
  poly_t g1 = poly_init(middeg);
  poly_t g2 = poly_init(middeg);
  poly_t h1 = poly_init(2*middeg);
  poly_t h2 = poly_init(2*middeg);
  poly_t h3 = poly_init(2*middeg);
  if ((1+f->deg - middeg)>0)
    memcpy(f1->coeff, &(f->coeff[middeg]), (1+f->deg - middeg)*sizeof(field_t));  
  memcpy(f2->coeff, f->coeff, middeg *sizeof(field_t));  
  if ((1+g->deg - middeg)>0)
    memcpy(g1->coeff, &(g->coeff[middeg]), (1+g->deg - middeg)*sizeof(field_t));
  memcpy(g2->coeff, g->coeff, middeg *sizeof(field_t));
  poly_deg(f1);
  poly_deg(g1);

  if ((f1->deg >= 0) && (g1->deg >= 0)) {
    poly_mul_karatsuba(f1, g1, h1, m);
    poly_deg(h1);
    memcpy(&(r->coeff[2*middeg]), h1->coeff, (h1->deg+1)*sizeof(field_t));
  }
  poly_deg(f2);
  poly_deg(g2);
  if ((f2->deg>=0) && (g2->deg >=0)) {
    poly_mul_karatsuba(f2, g2, h3, m);
    memcpy(r->coeff, h3->coeff, (1+h3->deg)*sizeof(field_t));
  }

  GF_addvec(f1->coeff, f2->coeff, NULL,f1->size);
  GF_addvec(g1->coeff, g2->coeff, NULL,g1->size);
  poly_deg(f2);
  poly_deg(g2);
  if ((f2->deg>=0) && (g2->deg >=0)) {
    poly_mul_karatsuba(f2, g2, h2, m);
  }
  GF_addvec(h1->coeff, h2->coeff,NULL, h1->size);
  GF_addvec(h3->coeff, h2->coeff,NULL, h3->size);

  poly_deg(h2);
  GF_addvec(h2->coeff, &(r->coeff[middeg]),NULL, 1+h2->deg);
  
  poly_deg(r);  
  poly_free(f1);
  poly_free(f2);
  poly_free(g1);
  poly_free(g2);
  poly_free(h1);
  poly_free(h2);
  poly_free(h3);
  return 0;
}
    
int poly_mul_standard(poly_t p, poly_t q, poly_t r, int m) {
  /* multiplication is done over field GF(2^m), r contains result */
  int d1, d2,i;
  d1=p->deg;
  d2=q->deg;
  if (p->deg + q->deg >=r->size) return POLYMULTERRR;
  poly_zero(r);
  field_t *tmp;
  tmp = calloc(d2+1, sizeof(field_t));
  for (i=0; i<=d1; i++) {    
    if (p->coeff[i] !=field_zero()){
      GF_mulvec(p->coeff[i], q->coeff, tmp, d2+1, m);
      GF_addvec(tmp, &r->coeff[i],NULL, d2+1);
    }
  }
  poly_deg(r);
  free(tmp);
  return 0;
}


int poly_add(poly_t p, poly_t q, poly_t r) {
  poly_zero(r);
  int i=1;
  int d1=p->deg;
  int d2=q->deg;
  int d=d1;
  if (d2<d) {
    d=d2;
    i=2;
  }
  GF_addvec(p->coeff,q->coeff, r->coeff, d+1);
  if (i==1) {
    memcpy(&(r->coeff[d+1]), &(q->coeff[d+1]), (d2-d)*sizeof(field_t));
  } else {
    memcpy(&(r->coeff[d+1]), &(p->coeff[d+1]), (d1-d)*sizeof(field_t));
  }
  poly_deg(r);
  return 0;
}

int poly_div(poly_t p, poly_t d, poly_t q, poly_t r, int m) {
  /* input: p, d; output: p(x)=d(x)q(x)+r(x) */
  poly_copy(p,r);
  poly_zero(q);
  int dDegree = poly_deg(d);
  int rDegree = poly_deg(r);
  int j;
  if(dDegree<0) return 0;
  field_t *tmp;
  tmp=calloc(1+dDegree, sizeof(field_t));
  field_t bb;
  j = rDegree-dDegree;
  q->deg = j>0?j:0;
  for(; j>=0; j--) {
    if (r->coeff[j+dDegree] !=0) {
      bb=GF_div(r->coeff[j+dDegree],d->coeff[dDegree],m);
      GF_mulvec(bb,d->coeff,tmp,dDegree+1,  m);
      GF_addvec(tmp, &(r->coeff[j]),NULL,1+dDegree);
      q->coeff[j] = bb;
    }
  }
  free(tmp);
  poly_deg(r);
  return 0;
}

int poly_quotient (poly_t p, poly_t d, poly_t q, int m) {
  /* input: p, d; output: p(x)=d(x)q(x) */
  poly_t r=poly_init(p->size);
  poly_deg(p);
  poly_deg(d);
  
  poly_div(p, d, q, r, m);
  if (r->deg == -1) {
    poly_free(r);
    return 0;
  } else {
    poly_free(r);
    return POLYNOTFULLDIV;
  }
}

int poly_gcd(poly_t p1, poly_t p2, poly_t gcd, int m) {
  if (poly_deg(p2) == -1) {
    poly_copy(p1, gcd);
    return 0;
  } else {
    poly_t tmpQ=poly_init(p1->size);
    poly_t tmpR=poly_init(p1->size);
    poly_div(p1, p2, tmpQ, tmpR, m);
    poly_copy(tmpR, p1);
    poly_free(tmpQ);
    poly_free(tmpR);
    poly_gcd(p2, p1, gcd, m);
  }
  return 0;
}

int find_roots_exhaustive (poly_t p, field_t roots[], int m) {
  int i, j=0;
  field_t result;
  for (i=0; i<= fieldSize(m)-1; i++) {
    result = poly_evalopt(p,i,m);
    if (result == field_zero()) {
      roots[j]=i;
      j++;
    }
  }
  return j;
}

int find_roots_Chien (poly_t lambda, field_t lambdaRoots[], field_t eLocation[], int m) {  
  int i, j;
  matrix_t mat=matrix_init(1+lambda->deg, fieldSize(m));
  for (j=0;j<fieldSize(m);j++) mat->data[0][j]=lambda->coeff[0];  
  for (i=1;i<mat->numR;i++) mat->data[i][0]=lambda->coeff[i];
  for (i=1;i<mat->numR;i++) {
    GF_logmulvec(i,mat->data[i], &(mat->data[i][1]), mat->numC-1, m);
    GF_addvec(mat->data[i-1], mat->data[i],NULL, fieldSize(m));
  }
  i=0;
  for (j=0;j<fieldSize(m); j++) {
    if ((mat->data[lambda->deg][j])==field_zero()) {
      lambdaRoots[i]=j;
      if (j==0) {
	eLocation[i]=0;
      } else {
	eLocation[i]=fieldSize(m)-1-j;
      }
      i++;
    }
  }
  GF_expvec(lambdaRoots,i, m);
  matrix_free(mat);
  return i;
}

int find_roots_FFT(poly_t f, field_t roots[], int m) {
  int ret, i, j=0;
  vector_t base;
  base=vec_init(m);
  for (i=0; i<m;i++) base->data[i]=i;
  GF_expvec(base->data,m, m);
  vector_t output;
  output = vec_init(fieldSize(m));
  ret=FFT(f,output,base,m);
  if (ret<0) return ret;
  for (i=1; i<output->size; i++) { 
    if (output->data[i]==0) {
      roots[j]=i;
      j++;
    }
  }
  vector_free(base);
  vector_free(output);
  return j;
}

int find_roots (poly_t p, field_t roots[], field_t eLocation[], int m) {
  int numRoots;
  if (p->deg <=4) {
    numRoots = find_roots_BTA(p,roots,m);
  } else {
    if (ROOTFINDING==0) return numRoots= find_roots_Chien(p, roots, eLocation, m);
    if (ROOTFINDING==1) numRoots= find_roots_exhaustive(p, roots, m);
    if (ROOTFINDING==2) numRoots = find_roots_BTA(p,roots,m);
    if (ROOTFINDING==3) numRoots= find_roots_FFT(p,roots, m);
  }
  field_t* rootsLog=calloc(numRoots, sizeof(field_t));
  rootsLocation(roots, numRoots, eLocation, rootsLog,m);
  free(rootsLog);
  return numRoots;
}

int poly_mul(poly_t p, poly_t q, poly_t r, int m) {
  int mindeg=0;
  if ((p->deg) > (q->deg)) {
    mindeg = q->deg;
  } else {
    mindeg = p->deg;
  }
  if (mindeg <115) return poly_mul_standard(p, q, r, m);  
  if (KARATSUBA ==0) return poly_mul_standard(p, q, r, m);
  if (KARATSUBA ==1) return poly_mul_karatsuba(p, q, r, m);
  if (KARATSUBA ==2) return poly_mul_FFT(p, q, r, m);
  return 0;
}
