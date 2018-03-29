/* bta.c
 * Yongge Wang 
 *
 * Code was written:  May 30, 2017 
 *
 * bta.c implements Berlekamp Trace Algorithm 
 * for RLCE scheme that is part of the package 
 * RLCE.tar - Random Linear Code Encryption Scheme
 * 
 * This process uses Berlekamp Trace algorithm (BTA) to 
 * factor the polyonmial until degree four. Then it uses 
 * affine polynomials in Chapter 11 of the following book
 * to find the roots. 
   @article{berlekamp1968algebraic,
   title={Algebraic coding theory},
   author={Berlekamp, Elwyn R},
   year={1968},
   publisher={McGraw-Hill}
   }
 *
 * Copyright (C) 2017 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 */

#include "rlce.h"

static int *BTATable = NULL;

/* p=p1*p2 */
static void factor_poly(poly_t p,  poly_t p1, poly_t p2, poly_t tracectr, int m) {
  poly_t f, g;
  f=poly_init(p->size);
  g=poly_init(p->size);  
  if (tracectr->deg > 0) {
    poly_copy(p,f);
    poly_copy(tracectr, g);
    if (f->deg>g->deg) {
      poly_gcd(f,g,p1,m);
    } else {
      poly_gcd(g,f,p1,m);
    }
    if (p1->deg < p->deg) {
      poly_quotient(p,p1,p2,m);
    }
  } else {
    poly_copy(p,p1);
  }
        
  poly_free(f);
  poly_free(g);
}

/* out=Tr(alpha^ctr X) mod f */
static int trace_mod(int ctr, poly_t f, poly_t trace[], poly_t tracectr, int m) {
  int i;
  poly_t q=poly_init(f->size);
  poly_t r=poly_init(f->size);
  if (ctr>m) return -1;
  field_t tmp[f->size];
  memset(tmp, 0, (f->size)*sizeof(field_t));
  unsigned short a;
  for (i=0; i<m; i++) {
    a = (ctr* (1 << i)) % (fieldSize(m)-1);
    GF_logmulvec(a,(trace[i])->coeff, tmp,1+(trace[i])->deg, m);
    GF_addvec(tmp, tracectr->coeff, NULL,1+(trace[i])->deg);    
  }
  poly_deg(tracectr);
  if (tracectr->deg >= f->deg) {
    poly_div(tracectr, f, q, r, m);
    poly_copy(r, tracectr);
  }   
  poly_free(q);
  poly_free(r);
  return 0;
}


static int find_deg1_roots(poly_t p, field_t pRoots[], int m) {
  if ((p->coeff[1]) !=0) {
    pRoots[0]=GF_div(p->coeff[0],p->coeff[1],m);
    return 1;
  }
  return 0;
}

field_t trace(field_t a, int m) {
  int i;
  field_t alpha=GF_exp(1, m);
  field_t ret=alpha;
  for (i=1; i<m; i++) {
    alpha =GF_mul(alpha,alpha,m);
    ret ^= alpha;
  }
  return ret;
}

int find_deg2_roots_rt(poly_t p, field_t pRoots[], int m) {
  /* this implementation does not pre-compute the inverse matrix coefficients 
   * the coeffs are computed in real time */
  field_t rows[m]; /* rows[i] contains the i-th row of m x (m+1) binary matrix */
  field_t ej=0;
  int i,j;
  memset(rows, 0, m*sizeof(field_t));
  
  unsigned int a = GF_log(p->coeff[2], m);
  unsigned int b = GF_log(p->coeff[1], m);
  unsigned int c = GF_log(p->coeff[0], m);
  /* using x=(b/a)*y z=(a/b)*X, transform aX^2+bX+c to z^2+z+u (u=ac/b^2) */
  unsigned int ulog = (a +c +2*(fieldSize(m)-1 -b)) % (fieldSize(m)-1) ;
  field_t u=GF_exp(ulog,m);
  field_t tr = trace(u,m);  
  if (tr) return 0;
  /* e_j = alpha^{j} + alpha^{2j} */
  for (j=0; j<=m; j++) {
    if (j<m) {
      ej=GF_exp(j,m) ^ GF_exp((j+j) %(fieldSize(m)-1), m);
    } else ej=u;
    for (i=0; i<m; i++) rows[i] ^= (((ej>>i) & 0x0001) << (m-j));
  }
  
  /* Gauss elimination */
  int temp, k;
  field_t tmp;
  int ctr=0;
  unsigned short positions[m];
  memset(positions, 0, m*sizeof(unsigned short));
  for(j=0; j<m; j++) { /* get reduced echelon format */
    if ((rows[j-ctr]>>(m-j)) !=1) {
      temp=m;
      for(i=j-ctr+1; i<m; i++) if ((rows[i]>>(m-j)) ==1) temp=i;
      if (temp == m) {
	  positions[j]=m; /* column j is defect */
	  ctr++;
      } else {
	tmp=rows[j-ctr];
	rows[j-ctr]=rows[temp];
	rows[temp]=tmp;
      }
    }
    if (positions[j] != m) {
      positions[j]=j-ctr;
      for(k=0; k<m; k++) {
	if ((k !=j-ctr) && (((rows[k]>>(m-j)) & 0x0001) ==1)) {
	  rows[k] ^=rows[j-ctr];
	}
      }
    }
  }
  if (ctr>1) {
    printf("i have more errors to deal with here\n");
    return 0;
  }
  field_t rows0[m],rows1[m];
  memcpy(rows0, rows, m*sizeof(field_t)); /* for 0 */
  memcpy(rows1, rows, m*sizeof(field_t)); /* for 1 */  
  memset(pRoots, 0, 2*sizeof(field_t));
  unsigned int pos0;
  for (i=0; i<m; i++) if (positions[i]==m) pos0=i;  
  for (i=0;i<m;i++) rows1[i] ^= ((rows[i] >>(m-pos0)) & 0x0001);
  for (i=m-1;i>=0;i--) {
    if (i==pos0) {
      pRoots[0] = (pRoots[0]<<1);
      pRoots[1] = (pRoots[1]<<1) ^ 0x0001;
    } else {
      pRoots[0] = (pRoots[0]<<1) ^ (0x0001 & rows[positions[i]]);
      pRoots[1] = ((pRoots[1]<<1) ^ (0x0001 & rows1[positions[i]]));
    }
  }
  /* use z=a/bx to get root x=br/a and x=b(r+1)/a */
  pRoots[0] = GF_fexp(pRoots[0],(b+fieldSize(m)-1-a)% (fieldSize(m)-1),m); 
  pRoots[1] = GF_fexp(pRoots[1],(b+fieldSize(m)-1-a)% (fieldSize(m)-1),m); 
  return 2;
}


int find_deg2_roots(poly_t p, field_t pRoots[], int m) {
  /* this process uses pre-computed matrix coefficients for 
   * when m = 10 or m = 11. For other m, it will call find_deg2_roots_rt */
  if (p->coeff[0] == 0) {
    pRoots[0] = GF_div(p->coeff[1], p->coeff[2], m);
    pRoots[1] = 0;
    return 2;
  } 
  if (p->coeff[1] == 0) {
    int a = GF_log(p->coeff[2], m);
    int c = GF_log(p->coeff[0], m);
    c = (c+fieldSize(m)-1-a)%(fieldSize(m)-1);
    c = c*(1 << (m-1))%(fieldSize(m)-1);
    pRoots[0] = GF_exp(c,m);
    return 1;    
  }
  if ((m!=10)||(m!= 11)) return find_deg2_roots_rt(p, pRoots, m);

  field_t rows[m]; 
  field_t ubit[m];
  int i;
  memset(ubit, 0, m*sizeof(field_t));
  memset(rows, 0, m*sizeof(field_t));
  
  unsigned int a = GF_log(p->coeff[2], m);
  unsigned int b = GF_log(p->coeff[1], m);
  unsigned int c = GF_log(p->coeff[0], m);
  /* using x=(b/a)*y z=(a/b)*X, transform aX^2+bX+c to z^2+z+u (u=ac/b^2) */
  unsigned int ulog = (a +c +2*(fieldSize(m)-1 -b)) % (fieldSize(m)-1) ;
  field_t u=GF_exp(ulog,m);
  
  for (i=0;i<m;i++) ubit[i]= ((u>>i) & 0x0001);
  if (m==10) {
    field_t ubit356 = ubit[3] ^ ubit[5] ^ ubit[6]; 
    pRoots[0]  = (ubit356 ^ ubit[9])<<1;
    pRoots[0] ^= ubit356;
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^= (ubit[0] ^ ubit[1] ^ ubit[2] ^ubit[4] ^ ubit[5] ^ ubit[8] ^ubit[9]);
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^= (ubit[0] ^ ubit[5]);
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^= (ubit[0]);
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^= (ubit[8] ^ ubit[9]);
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^= (ubit[0] ^ ubit[3]);
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^= (ubit[0] ^ubit[1] ^ ubit[2]^ ubit[3]^ubit[6] ^ ubit[9]);
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^= (ubit[1] ^ ubit356 ^ ubit[9]);
    pRoots[0] = pRoots[0]<<1;
    pRoots[1] = pRoots[0] ^ 0x0001;
 
  }
  if (m==11) {
    field_t ubit345 = ubit[3] ^ubit[4]^ubit[5];
    pRoots[0]  = ubit[9]<<1;
    pRoots[0] ^= (ubit[5] ^ ubit[7]^ubit[9] ^ubit[10]);
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^= (ubit[3]^ubit[5] ^ ubit[6] ^ ubit[9] ^ ubit[10]);
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^= (ubit[3] ^ ubit[6]);
    pRoots[0] = pRoots[0]<<1;
    field_t u123456810 = (ubit[1]  ^ ubit[2] ^  ubit345 ^ ubit[6] ^ ubit[8] ^ubit[10]);
    pRoots[0] ^= u123456810;
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^= (ubit[9] ^ ubit[10]);
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^= (ubit[3]^ubit[5] ^ ubit[6] ^ ubit[8]^ubit[9] ^ubit[10]);
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^= (u123456810 ^ ubit[6]); 
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^=  (ubit345 ^ubit[6] ^ubit[8]^ubit[9]^ ubit[10]);
    pRoots[0] = pRoots[0]<<1;
    pRoots[0] ^=  (u123456810 ^ubit[1]);  
    pRoots[0] = pRoots[0]<<1;
    pRoots[1] = pRoots[0] ^ 0x0001;
  }
  /* use z=a/bx to get root x=br/a and x=b(r+1)/a */
  pRoots[0] = GF_fexp(pRoots[0],(b+fieldSize(m)-1-a)% (fieldSize(m)-1),m); 
  pRoots[1] = GF_fexp(pRoots[1],(b+fieldSize(m)-1-a)% (fieldSize(m)-1),m); 
  return 2;
}

int find_deg2_roots_table(poly_t p, field_t pRoots[], int m) {
  /* use a pre-computed table to look up the roots */

  unsigned short i, index;
  field_t element, element1;
  if  (BTATable == NULL) {
    BTATable = (int *) malloc(sizeof(int)*fieldSize(m));
    memset(BTATable, 0, sizeof(int)*fieldSize(m));
    for (i=0; i<fieldSize(m) -1 ; i++) {
      index = (i+i) % (fieldSize(m)-1);
      element1=GF_exp(i, m);
      element = GF_exp(index, m) ^ element1;
      BTATable[element]=element1;
    }
  }
  
  if (p->coeff[1] == 0) {
    pRoots[0]=GF_div(p->coeff[0],p->coeff[2],m);
    pRoots[0]=GF_fexp(pRoots[0], 1<<(m-1), m);
    return 1;    
  } else if (p->coeff[0] == 0) {
    pRoots[0] = GF_div(p->coeff[1], p->coeff[2], m);
    return 1;
  } else  {
    unsigned int a = GF_log(p->coeff[2], m);
    unsigned int b = GF_log(p->coeff[1], m);
    unsigned int c = GF_log(p->coeff[0], m);
    /* using z=a/bX, transform aX^2+bX+c into z^2+z+u (u=ac/b^2) */
    unsigned int ulog = (a +c +2*(fieldSize(m)-1 -b)) % (fieldSize(m)-1) ;
    field_t u=GF_exp(ulog,m);
    field_t r=BTATable[u];
    if (r !=0 ) {
      /* use z=a/bx to get root x=br/a and x=b(r+1)/a */
      pRoots[0] = GF_fexp(r,(b+fieldSize(m)-1-a)% (fieldSize(m)-1),m);
      pRoots[1] = GF_fexp(r^0x0001,(b+fieldSize(m)-1-a)% (fieldSize(m)-1),m);  
      return 2;
    } else {
      return 0;
    }
  }
  return 0;
}


/*  find the roots for X^4+aX^2+bX+c over GF(2^m). */
static int affine4_roots(field_t a, field_t b, field_t c, field_t *roots, int m) {
  field_t rows[m]; /* rows[i] contains the i-th row of m x (m+1) binary matrix */
  field_t ej=0;
  int i,j;
  memset(rows, 0, m*sizeof(field_t));
  /* e_j = b*alpha^{j} + a*alpha^{2j} + alpha^{4j}  */
  for (j=0; j<=m; j++) {
    if (j<m) {
      ej=GF_fexp(b, j,m) ^ GF_fexp(a, (2*j)%(fieldSize(m)-1),m) ^ GF_exp((4*j) %(fieldSize(m)-1),m);
    } else {
      ej=c;
    }
    for (i=0; i<m; i++) {
      rows[i] ^= (((ej>>i) & 0x0001) << (m-j)) ;
    }
  }

  /* Gauss elimination */
  int temp, k;
  field_t tmp;
  int ctr=0;
  unsigned short positions[m];
  memset(positions, 0, m*sizeof(unsigned short));
  for(j=0; j<m; j++) { /* get reduced echelon format */
    if ((rows[j-ctr]>>(m-j)) !=1) {
      temp=m;
      for(i=j-ctr+1; i<m; i++) {
	if ((rows[i]>>(m-j)) ==1 ) {
	  temp=i;
	}
      }
      if (temp == m) {
	  positions[j]=m; /* column j is defect */
	  ctr++;
      } else {
	  tmp=rows[j-ctr];
	  rows[j-ctr]=rows[temp];
	  rows[temp]=tmp;
      }
    }
    if (positions[j] != m) {
      positions[j]=j-ctr;
      for(k=0; k<m; k++) {
	if ((k !=j-ctr) && (((rows[k]>>(m-j)) & 0x0001) ==1)) {
	  rows[k] ^=rows[j-ctr];
	}
      }
    }
  }
  for (i=1; i<m; i++) {
    if (rows[i]==1) {
      //printf("DEBUG INFO: irreducible poly\n");
      return 0;
    }
  }
  
  if (ctr>2) {
    //printf("DEBUG INFO: more errors to deal with\n");
    return 0;
  }

  if (ctr==0) {
    roots[0]=0;
    for (i=m-1;i>=0;i--) {
      roots[0] = (roots[0]<<1) ^ (0x0001 & rows[i]);
    }
    return 1;
  }
  memset(roots, 0, 4*sizeof(field_t));
  unsigned int pos0, pos1;
  unsigned int flag = 0;
  field_t rows0[m],rows1[m];
  memcpy(rows0, rows, m*sizeof(field_t)); /* for 00 or 0 (ctr=1) */
  memcpy(rows1, rows, m*sizeof(field_t)); /* for 01 or 1 (ctr=1) */

  if (ctr==1) {
    for (i=0; i<m; i++) if (positions[i]==m) pos0=i;
    for (i=0;i<m;i++) rows1[i] ^= ((rows1[i] >>(m-pos0)) & 0x0001);    
    for (i=m-1;i>=0;i--) {
      if (i==pos0) {
	roots[0] = (roots[0]<<1);
	roots[1] = (roots[1]<<1) ^ 0x0001;
      } else {
	roots[0] = (roots[0]<<1) ^ (0x0001 & rows[positions[i]]);
	roots[1] = ((roots[1]<<1) ^ (0x0001 & rows1[positions[i]]));
      }
    }
    return 2;
  }
  
  field_t  rows2[m], rows3[m];
  memcpy(rows2, rows, m*sizeof(field_t)); /* for 10 or not used (ctr=1)*/
  memcpy(rows3, rows, m*sizeof(field_t)); /* for 11 or not used (ctr=1)*/

  if (ctr==2) {
    for (i=0; i<m; i++) {
      if ((positions[i]==m)&& (flag ==0)) {
	pos0=i;
	flag = 1;
      } else if ((positions[i]==m)&&(flag ==1)) {
	pos1=i;
      }
    }
    for (i=0;i<m;i++) {      
      rows1[i] ^= ((rows1[i] >>(m-pos1)) & 0x0001);
      rows2[i] ^= ((rows1[i] >>(m-pos0)) & 0x0001);
      rows3[i] ^= ((rows1[i] >>(m-pos0)) & 0x0001);
      rows3[i] ^= ((rows1[i] >>(m-pos1)) & 0x0001);
    }
    
    for (i=m-1;i>=0;i--) {
      if (i==pos0) {
	roots[0] = (roots[0]<<1);
	roots[1] = (roots[1]<<1);
	roots[2] = (roots[2]<<1) ^ 0x0001;
	roots[3] = (roots[3]<<1)^ 0x0001;
      } else if (i==pos1) {
	roots[0] = (roots[0]<<1);
	roots[1] = (roots[1]<<1) ^ 0x0001;
	roots[2] = (roots[2]<<1);
	roots[3] = (roots[3]<<1) ^ 0x0001;
      } else {
	roots[0] = (roots[0]<<1) ^ (0x0001 & rows[positions[i]]);
	roots[1] = ((roots[1]<<1) ^ (0x0001 & rows1[positions[i]]));
	roots[2] = ((roots[2]<<1) ^ (0x0001 & rows2[positions[i]]));
	roots[3] = ((roots[3]<<1) ^ (0x0001 & rows3[positions[i]]));
      }
    }
    return 4;
  }
  return 0;
}

static int find_deg3_roots(poly_t p, field_t pRoots[], int m) {
  int i;
  if (p->coeff[0] == 0) {
    p->coeff[0]=p->coeff[1];
    p->coeff[1]=p->coeff[2];
    p->coeff[2]=p->coeff[3];
    p->deg = 2;
    return find_deg2_roots(p, pRoots, m);
  }
  if (p->coeff[3] !=1) { /* transform p to monic x^3 + a1*x^2 + b1*x + c1 */
    p->coeff[0]=GF_div(p->coeff[0],p->coeff[3], m);
    p->coeff[1]=GF_div(p->coeff[1],p->coeff[3], m);
    p->coeff[2]=GF_div(p->coeff[2],p->coeff[3], m);
    p->coeff[3]=1;
  }
  /* (X+a1)(X^3+a1X^2+b1X+c1) = X^4+aX^2+bX+c */
  field_t a,b,c;
  if (p->coeff[2]==0) {/* a1=0 */
    a=p->coeff[1];
    b=p->coeff[0];
    c=0;
  } else {
    c = GF_mul(p->coeff[0],p->coeff[2], m);                 /* c = a1c1      */
    b = GF_mul(p->coeff[1],p->coeff[2], m) ^ p->coeff[0];   /* b = a1b1 + c1 */
    a = GF_mul(p->coeff[2],p->coeff[2], m) ^ p->coeff[1];   /* a = a1^2 + b1 */
  }

  int ret;
  field_t roots[4];
  memset(roots, 0, 4*sizeof(field_t));
  ret = affine4_roots(a,b,c, roots, m);
  int ctr=0;
  for (i=0; i<ret; i++) {
    if (roots[i] != p->coeff[2]) {
      pRoots[ctr]=roots[i];
      ctr++;
    }
  }
  return ctr;
}

int find_deg4_roots(poly_t p, field_t pRoots[], int m) {
  int i, ret;
  if (p->coeff[0] == 0) {
    p->coeff[0]=p->coeff[1];
    p->coeff[1]=p->coeff[2];
    p->coeff[2]=p->coeff[3];
    p->coeff[3]=p->coeff[4];
    p->deg = 3;
    pRoots[0]=0;
    return 1+find_deg3_roots(p, pRoots+1, m);
  }

  field_t a,b,c,d,e, a1,b1,c1;
  a= p->coeff[3];
  b= p->coeff[2];
  c= p->coeff[1];
  d= p->coeff[0];
  if (p->coeff[4] == 0) {
    p->deg= 3;
    return find_deg3_roots(p, pRoots, m);
  } else if (p->coeff[4] !=1) { /* transform p to x^4+a*x^3+b*x^2+c*x+d */
    d=GF_div(d,p->coeff[4], m);
    c=GF_div(c,p->coeff[4], m);
    b=GF_div(b,p->coeff[4], m);
    a=GF_div(a,p->coeff[4], m);
  } 

  if (a==0) {
    ret = affine4_roots(b,c,d,pRoots, m);
    return ret;
  }

  unsigned int alog, clog, elog;
  field_t roots[4];
  memset(roots, 0, 4*sizeof(field_t));
  if (c !=0 ) {
    /* compute square root of e^2=c/a */
    /*    e=GF_div(c,a,m);
    elog=GF_log(e,m);
    elog = (elog*(1 << (m-1))) % (fieldSize(m)-1);
    e=GF_exp(elog, m);
    */    
    alog = GF_log(a, m);
    clog = GF_log(c, m);
    elog = (clog + (fieldSize(m)-1-alog));
    elog = (elog*(1 << (m-1))) % (fieldSize(m)-1);
    e=GF_exp(elog, m);
    /* let x=z+e, so
     * p(z+e)= z^4+e^4 + a(z^3+ez^2+e^2z+e^3) + b(z^2+e^2) +cz+ce+d
     * = z^4 + az^3 + (ae+b)z^2 + e^4+be^2+d
     * = z^4 + az^3 +     b'z^2 + d'
     */
    
    d ^= (GF_exp((elog*4)%(fieldSize(m)-1),m)^GF_fexp(b,(2*elog)%(fieldSize(m)-1),m));
    b ^= GF_mul(a,e,m);
  } else e=0;
  if (d==0) {
    pRoots[0]=GF_exp(elog, m);
    p->deg = 2;
    p->coeff[2]=1;
    p->coeff[1]=a;
    p->coeff[0]= (GF_exp((elog*2)%(fieldSize(m)-1), m) ^ b ^ GF_fexp(a,elog,m));
    return 1+find_deg2_roots(p, pRoots+1, m);
  }
  /* let z=1/y so p(e + 1/y)=y^4 + b/d *y^2 + a/d * y + 1/d */
  c1=GF_div(1, d,m);
  b1=GF_div(a,d,m);
  a1=GF_div(b,d,m);
  ret = affine4_roots(a1,b1,c1,roots, m);
  
  if (ret ==0) return 0;
  for (i = 0; i < ret; i++) pRoots[i]=GF_div(1,roots[i],m)^e;
  return ret;
}

static int find_roots_BTA_aux(poly_t trace[], poly_t p, unsigned int ctr, field_t pRoots[], int m) {
  int numRoots=0, ret;
  poly_t p1, p2, tracectr;
  if (p->deg <=0) return 0;
  switch (p->deg) {
  case 1:
    return find_deg1_roots(p, pRoots, m);
  case 2:
    return find_deg2_roots(p, pRoots, m);
  case 3:
    return find_deg3_roots(p, pRoots, m);
  case 4:
    return find_deg4_roots(p, pRoots, m); 
  default:
    break;
  }
  tracectr=poly_init(p->size);
  ret=trace_mod(ctr, p, trace,tracectr, m);
  if (ret<0) return 0;
  p1=poly_init(p->size);
  p2=poly_init(p->size);
  factor_poly(p, p1, p2, tracectr,m);
  poly_free(tracectr);
  if (p1->deg >0) {
    ret = find_roots_BTA_aux(trace,p1,ctr+1,pRoots, m);
    numRoots += ret;
  }
  poly_free(p1);
  if (p2->deg > 0) {
    ret = find_roots_BTA_aux(trace,p2,ctr+1,pRoots+numRoots, m);
    numRoots += ret;
  }
  poly_free(p2);
  return numRoots;
}

int find_roots_BTA(poly_t p, field_t pRoots[], int m) {
  if ((p->deg) == 1) return find_deg1_roots(p, pRoots, m);
  if ((p->deg) == 2) return find_deg2_roots(p, pRoots, m);
  if ((p->deg) == 3) return find_deg3_roots(p, pRoots, m);
  if ((p->deg) == 4) return find_deg4_roots(p, pRoots, m);
  int i, index,j;
  int numRoots;
  poly_t * trace;
  trace = malloc(m*sizeof(poly_t));
  for (i=0; i<m; i++) {
    //trace[i]=poly_init(p->size);
    trace[i]=poly_init(1<<m);
  }
  poly_t q=poly_init(1<<m);
  poly_t r=poly_init(1<<m);
  //poly_t q=poly_init(p->size);
  //poly_t r=poly_init(p->size);
  
  for (i=0; i<m; i++) {
    /* first let trace[i]=x^{2^i}, then do trace[i] mod p  
     * also note trace[i+1] mod p = (trace[i] mod p)^2 mod p */
    index = (1 << i);
    if (index < p->deg) {
      trace[i]->deg = index;
      trace[i]->coeff[index]=1;
    } else {
      /* following is for: poly_mul(trace[i-1], trace[i-1], trace[i], m); */
      for (j=trace[i-1]->deg; j>=0; j--) {
	trace[i]->coeff[2*j]=GF_mul(trace[i-1]->coeff[j], trace[i-1]->coeff[j], m);
      }
      trace[i]->deg = 2* (trace[i-1]->deg);
      if (trace[i]->deg >= p->deg) {
	poly_div(trace[i], p, q, r, m);
	poly_copy(r, trace[i]);
      }
    }   
  }
  poly_free(q);
  poly_free(r);
  numRoots = find_roots_BTA_aux(trace, p, 0, pRoots, m);
  for (i=0; i<m; i++) poly_free(trace[i]);
  free(trace);
  return numRoots;
}

