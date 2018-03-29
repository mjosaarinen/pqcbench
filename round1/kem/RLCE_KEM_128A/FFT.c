/* FFT.c
 * Yongge Wang 
 *
 * Code was written:  June 29, 2017 
 *
 * FFT.c implements Fast Fourier Transform over GF(2^m)
 * for RLCE scheme that is part of the package 
 * RLCE.tar - Random Linear Code Encryption Scheme
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

void taylor(poly_t g, poly_t series[]) {
  if (g->deg <0) return;
  if (g->deg <2) {
    series[0]->deg = g->deg;
    memcpy(series[0]->coeff, g->coeff, (1+g->deg)*sizeof(field_t));
    return;
  }
  poly_t h0, h1, h2;
  int l=0, p2l, num;
  while ((1+g->deg)>(1<<(l+2))) l++;
  h0=poly_init(g->size);
  h1=poly_init(g->size);
  h2=poly_init(g->size);  
  p2l = (1<<l);
  memcpy(h0->coeff, g->coeff, (p2l*2)*sizeof(field_t));
  num= (1+g->deg)- p2l*2;
  if (num>p2l) num=p2l;
  memcpy(h1->coeff, &(g->coeff[p2l*2]),num*sizeof(field_t));
  num= (1+g->deg)- p2l*3;
  if (num>0) memcpy(h2->coeff, &(g->coeff[p2l*3]),num*sizeof(field_t));
  GF_addvec(h1->coeff, &(h0->coeff[p2l]), NULL,p2l);
  GF_addvec(h2->coeff, &(h0->coeff[p2l]), NULL,p2l);
  poly_deg(h0);
  taylor(h0, series);
  poly_free(h0);
  GF_addvec(h2->coeff, h1->coeff, NULL, p2l);
  GF_addvec(h2->coeff, &(h1->coeff[p2l]), NULL,p2l);
  poly_deg(h1);
  taylor(h1, &(series[p2l]));
  poly_free(h1);
  poly_free(h2);
  return;  
}


int verifyTaylor(poly_t g, poly_t series[], int numSeries, int m) {
  poly_t unit=poly_init(3);
  poly_t temp1=poly_init(g->size);
  poly_t temp2=poly_init(g->size);  
  unit->deg = 2;
  unit->coeff[1]=1;
  unit->coeff[2]=1;
  int i;
  poly_copy(series[numSeries-1], temp1);
  for (i=numSeries-2; i>=0; i--) {
    poly_mul(temp1, unit, temp2, m);
    poly_add(temp2, series[i], temp1);
    poly_deg(temp1);
  }
  int ret=0;
  for (i=0; i<= g->deg; i++) if (g->coeff[i] != temp1->coeff[i]) ret=-1;
  if (ret ==0) {
    printf("Taylor Series verified\n");
  } else printf("Taylor Series not verified\n");
  poly_free(unit);
  poly_free(temp1);
  poly_free(temp2);
  return ret;
}

int testoutput(poly_t g, vector_t output, vector_t base, int m) {
  int d=base->size;
  int p2dm1 = 1<<d;
  field_t tt, res;
  int ret=0;
  unsigned short i,j;
  for (i=0; i<p2dm1; i++) {
    tt=0;
    for (j=0; j<d; j++) if (((i>>j)&0x0001)>0) tt ^= base->data[j];
    res=poly_eval(g, tt, m);
    if (res!= (output->data[i])){
      ret++;
    }
  }
  return ret;
}

int FFT(poly_t f, vector_t output, vector_t base, int m) {
  if (f->size <=0) return 0;
  if (f->deg <0) return 0;
  int d = base->size;
  if (output->size != (1<<d)) return FFTOUTPUTERR;
  unsigned short i,j;
  field_t fE;
  int log;
  if ((f->deg)==0) {
    for (i=0; i<output->size; i++) output->data[i]=f->coeff[0];
    return 0;
  }
  if ((f->deg)==1) {
    log=GF_log(f->coeff[1], m);
    field_t coeff0[output->size];
    for (i=0; i<output->size; i++) coeff0[i]=f->coeff[0];
    for (i=0; i<output->size; i++) {
      fE=0;
      for (j=0;j<d;j++) if (((i>>j)&0x0001)>0) fE ^= base->data[j];
      output->data[i]=GF_fexp(fE,log,m);
    }
    GF_addvec(coeff0, output->data,NULL,output->size);
    return 0;
  }  
  if (d<4) {
    for (i=0;i<output->size; i++) {
      fE=0;
      for (j=0;j<d;j++) if (((i>>j)&0x0001)>0) fE ^= base->data[j];
      output->data[i]=poly_evalopt(f, fE, m);
    }
  }  
  poly_t g=poly_init(f->size);
  g->coeff[0]=f->coeff[0];
  GF_mulexpvec2(base->data[d-1], f->coeff, g->coeff,1+f->deg, m);
  poly_deg(g);
  int l= ((1+g->deg)%2)+(1+g->deg)/2;
  poly_t * series;
  series = malloc(l*sizeof(poly_t));
  for (i=0; i<l; i++) series[i]=poly_init(2);
  taylor(g, series);
  poly_t g0=poly_init(l);
  poly_t g1=poly_init(l);
  for (i=0; i<l; i++) {
    g0->coeff[i]=series[i]->coeff[0];
    g1->coeff[i]=series[i]->coeff[1];
  }
  for (i=0; i<l; i++) poly_free(series[i]);
  free(series);
  poly_deg(g0);
  poly_deg(g1);

  vector_t gamma, delta;
  gamma =vec_init(d-1);
  delta =vec_init(d-1);

  GF_vecdiv(base->data[d-1],base->data,gamma->data,d-1, m);
  GF_x2px(gamma->data, delta->data, d-1, m);
  vector_t g0output, g1output;
  g0output =vec_init(1<<(d-1));
  g1output =vec_init(1<<(d-1));
  FFT(g0,g0output,delta,m);
  FFT(g1,g1output,delta,m);
  int p2dm1=(1<<(d-1));
  field_t *Gi=calloc(p2dm1, sizeof(field_t));;
  for (i=0;i<p2dm1;i++) for (j=0;j<d-1;j++) if (((i>>j)&0x0001)>0) Gi[i]^=gamma->data[j];
  GF_vecvecmul(g1output->data, Gi,NULL,p2dm1,m);
  GF_addvec(g0output->data, Gi,output->data,p2dm1);
  GF_addvec(g1output->data,output->data,&(output->data[p2dm1]),p2dm1);
  free(Gi);
  vector_free(g0output);
  vector_free(g1output);
  vector_free(gamma);
  vector_free(delta);
  poly_free(g0);
  poly_free(g1);
  poly_free(g);
  return 0;
}



int verifyGGIFFT(int i,vector_t base, field_t beta,vector_t output, poly_t r, int m){
  int j,jj, ret=0;
  field_t tt,res;
  for (j=0;j<output->size;j++) {
    tt=beta;
    for (jj=0; jj<=i; jj++) if (((j>>jj)&0x0001)>0) tt ^= base->data[jj];
    res=poly_eval(r, tt, m);
    if (res!= (output->data[j])) ret++;
  }
  return ret;
}

int GGIFFT(int i,vector_t base, field_t beta,vector_t output,poly_t r,matrix_t smat, int m){
  int ret,j,jj;
  poly_zero(r);
  if (i==0) {
    if(output->data[0]==output->data[1]) {
      r->coeff[0]=output->data[0];
      r->deg=0;
    } else {
      r->coeff[1]= output->data[0] ^ output->data[1];
      r->coeff[0]=output->data[0] ^ GF_mul(r->coeff[1],beta, m);
      r->deg=1;
    }      
    return 0;
  }

  if (i==1) {
    poly_t f0,f1;
    f0=poly_init(2);
    f1=poly_init(2);
    if(output->data[0]==output->data[1]) {
      f0->coeff[0]=output->data[0];
      f0->deg=0;
    } else {
      f0->coeff[1]= output->data[0] ^ output->data[1];
      f0->coeff[0]=output->data[0] ^ GF_mul(f0->coeff[1],beta, m);
      f0->deg=1;
    }

    if(output->data[2]==output->data[3]) {
      f1->coeff[0]=output->data[2];
      f1->deg=0;
    } else {
      f1->coeff[1]= output->data[2] ^ output->data[3];
      f1->coeff[0]=output->data[2] ^ GF_mul(f1->coeff[1],beta ^ 0x0002, m);
      f1->deg=1;
    }
    f1->coeff[0] ^=f0->coeff[0];
    f1->coeff[1] ^=f0->coeff[1];
    field_t ttt=GF_mul(0x0002, 0x0003, m);
    f1->coeff[0]=GF_div(f1->coeff[0], ttt,m);
    f1->coeff[1]=GF_div(f1->coeff[1], ttt,m);
    poly_deg(f1);
    poly_t f3=poly_init(3);
    f3->coeff[2]=1;
    f3->coeff[1]=1;
    f3->coeff[0]=GF_mul(beta, beta^0x0001, m);
    poly_deg(f3);
    poly_mul_standard(f1,f3, r,m);
    r->coeff[0] ^= f0->coeff[0];
    r->coeff[1] ^= f0->coeff[1];
    poly_deg(r);
    poly_free(f0);
    poly_free(f1);
    
    return 0;
  }

  
  field_t beta1=beta ^ base->data[i];
  vector_t output0, output1;
  int outputsize=(output->size)/2;
  output0=vec_init(outputsize);
  output1=vec_init(outputsize);
  memcpy(output0->data, output->data,outputsize*sizeof(field_t));
  memcpy(output1->data, &(output->data[outputsize]),outputsize*sizeof(field_t));
  poly_t r0,r1, ptmp;
  r0=poly_init(r->size);
  r1=poly_init(r->size);
  ret=GGIFFT(i-1,base,beta,output0,r0,smat,m);
  ret=GGIFFT(i-1,base,beta1,output1,r1,smat,m);
  vector_free(output0);
  vector_free(output1);
  GF_addvec(r0->coeff,r1->coeff,NULL,1<<i);
  poly_deg(r1);
  unsigned short betailog=GF_log(base->data[i],m);
  unsigned short betalog;
  if (beta !=0) betalog=GF_log(beta,m);
  field_t sbeta=0, sbetai=0;
  field_t s[i+1];
  memcpy(s,smat->data[i-1],(i+1)*sizeof(field_t));
  if (beta!=0) {
    for(j=0;j<=i;j++) sbeta^=GF_exp(((1<<j)*betalog+s[j])%(fieldSize(m)-1),m);
  } else {
    sbeta=0;
  }
  for(j=0;j<=i;j++) sbetai^=GF_exp(((1<<j)*betailog+s[j])%(fieldSize(m)-1),m);
  
  unsigned short sbetailog,sbetalog;
  sbetailog=fieldSize(m)-1-GF_log(sbetai,m);
  if (beta!=0) sbetalog=GF_log(sbeta,m);
  
  for (j=0;j<=i;j++) s[j]= (s[j]+sbetailog)%(fieldSize(m)-1);
  if (beta !=0) {
    poly_copy(r1,r);
    for (j=0;j<=r->deg;j++)
      r->coeff[j]=GF_fexp(r->coeff[j],(sbetailog+sbetalog)%(fieldSize(m)-1),m);
  } 
  ptmp=poly_init(1+r1->deg);
  for (j=0;j<=i;j++) {
    for (jj=0;jj<=r1->deg;jj++) ptmp->coeff[jj]=GF_fexp(r1->coeff[jj],s[j],m);
    GF_addvec(ptmp->coeff,&(r->coeff[1<<j]),NULL,1+r1->deg);
  }
  GF_addvec(r0->coeff,r->coeff,NULL,(1+r0->deg));
  poly_deg(r);
  poly_free(r0);
  poly_free(r1);
  poly_free(ptmp);
  return ret;
}

