#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

typedef uint_least64_t fq_elem;
typedef uint_least64_t u128[2];
typedef uint_least64_t u192[3];

#include "setup1.h"

/* Arithmetic in Fq */
fq_elem fq_add(fq_elem a, fq_elem b)
{
  return a ^ b;
}

fq_elem fq_mul(fq_elem a, fq_elem b)
{
  int i;
  fq_elem c;
  c = 0;
  for (i=0; i<48; i++)
  {
    c <<= 1;
    b <<= 1;
    if (c & (UINT64_C(1) << 48)) c ^= min_poly;
    if (b & (UINT64_C(1) << 48)) c ^= a;
  }
  return c;
}

fq_elem fq_inv(fq_elem a)
{
  int i, j;
  fq_elem t, r, b, a2, b2;
  if (!a)
  {
    fprintf(stderr, "error: division by zero in Fq!\n");
    exit(-1);
  }
  t = 0;
  r = min_poly;
  b = 1;
  while (a)
  {
    for (i=1; a>>i; i++);
    for (j=1; r>>j; j++);
    b2 = (j>=i) ? t ^ (b << (j-i)) : t;
    a2 = (j>=i) ? r ^ (a << (j-i)) : r;
    t = b;
    r = a;
    b = b2;
    a = a2;
  }
  if (t & (UINT64_C(1) << 48)) t ^= min_poly;
  return t;
}

fq_elem fq_pow(fq_elem a, uint_least64_t n)
{
  fq_elem b;
  if (!n) return 1;
  b = fq_pow(a, n>>1);
  b = fq_mul(b, b);
  if (n & 1) b = fq_mul(b, a);
  return b;
}

fq_elem fq_pow_2exp(fq_elem a, unsigned int n)
{
  unsigned int i;
  fq_elem b;
  b = a;
  for (i=0; i<n; i++)
    b = fq_mul(b, b);
  return b;
}

fq_elem fq_rnd(void)
{
  fq_elem a;
  a  = (uint_least64_t)(rand() & 0xffff);
  a <<= 16;
  a += (uint_least64_t)(rand() & 0xffff);
  a <<= 16;
  a += (uint_least64_t)(rand() & 0xffff);
  return a;
}

void fq_matrix_multiply(fq_elem *a, const fq_elem *b, const fq_elem *c, int n, int m, int l)
{
  int i, j, k;
  fq_elem tmp;
  for (i=0; i<n; i++)
  {
    for (j=0; j<l; j++)
    {
      tmp = 0;
      for (k=0; k<m; k++)
        tmp = fq_add(tmp, fq_mul(b[i*m+k], c[k*l+j]));
      a[i*l+j] = tmp;
    }
  }
}

int fq_matrix_inverse(fq_elem *a, const fq_elem *b, int n)
{
  int i, j, k;
  fq_elem tmp;
  fq_elem c[64][128];

  memset(c, 0, 64*128*sizeof(fq_elem));
  for (i=0; i<n; i++)
  {
    for (j=0; j<n; j++)
      c[i][j] = b[i*n+j];
    c[i][i+n] = 1;
  }

  for (j=0; j<n; j++)
  {
    /* Find pivot in j-th column */
    for (i=j; i<n && !c[i][j]; i++);
    if (i==n)
      return -1;
    /* Swap i-th and j-th rows */
    for (k=j; k<2*n; k++)
    {
      tmp = c[i][k];
      c[i][k] = c[j][k];
      c[j][k] = tmp;
    }
    /* Multiply j-th row by C(j,j)^(-1) */
    tmp = fq_inv(c[j][j]);
    for (k=j; k<2*n; k++)
      c[j][k] = fq_mul(tmp, c[j][k]);
    /* Eliminate all non-zero entries below (j,j) */
    for (i=j+1; i<n; i++)
    {
      if (!c[i][j]) continue;
      for (k=j+1; k<2*n; k++)
        c[i][k] = fq_add(c[i][k], fq_mul(c[i][j], c[j][k]));
      c[i][j] = 0;
    }
  }

  for (j=n-1; j>=0; j--)
  {
    for (i=0; i<j; i++)
    {
      if (!c[i][j]) continue;
      for (k=0; k<j-1; k++)
        c[i][k] = fq_add(c[i][k], fq_mul(c[i][j], c[j][k]));
      for (k=n; k<2*n; k++)
        c[i][k] = fq_add(c[i][k], fq_mul(c[i][j], c[j][k]));
      c[i][j] = 0;
    }
  }

  for (i=0; i<n; i++)
    for (j=0; j<n; j++)
      a[i*n+j] = c[i][j+n];

  return 0;
}

fq_elem M1[64][64];
fq_elem M1_inverse[64][64];
fq_elem M2[64][64];
fq_elem M2_inverse[64][64];
fq_elem pt_sec2pub[64][6];

void compute_monomials(fq_elem *vec, const fq_elem *pt)
{
  int i, j;
  fq_elem pt_pow[6][2], row1[8], row2[8], tmp1, tmp2, tmp3, tmp4;
  pt_pow[0][0] = fq_pow_2exp(pt[0], E11 % 48);
  pt_pow[0][1] = fq_pow_2exp(pt[0], E21 % 48);
  pt_pow[1][0] = fq_pow_2exp(pt[1], E11 % 48);
  pt_pow[1][1] = fq_pow_2exp(pt[1], E21 % 48);
  pt_pow[2][0] = fq_pow_2exp(pt[2], E12 % 48);
  pt_pow[2][1] = fq_pow_2exp(pt[2], E32 % 48);
  pt_pow[3][0] = fq_pow_2exp(pt[3], E12 % 48);
  pt_pow[3][1] = fq_pow_2exp(pt[3], E32 % 48);
  pt_pow[4][0] = fq_pow_2exp(pt[4], E23 % 48);
  pt_pow[4][1] = fq_pow_2exp(pt[4], E33 % 48);
  pt_pow[5][0] = fq_pow_2exp(pt[5], E23 % 48);
  pt_pow[5][1] = fq_pow_2exp(pt[5], E33 % 48);
  row1[0] = fq_mul(pt_pow[0][0], pt_pow[2][0]);
  row1[1] = fq_mul(pt_pow[1][0], pt_pow[2][0]);
  row1[2] = fq_mul(pt_pow[0][0], pt_pow[3][0]);
  row1[3] = fq_mul(pt_pow[1][0], pt_pow[3][0]);
  row1[4] = row2[0] = fq_mul(pt_pow[0][1], pt_pow[4][0]);
  row1[5] = row2[1] = fq_mul(pt_pow[1][1], pt_pow[4][0]);
  row1[6] = row2[2] = fq_mul(pt_pow[0][1], pt_pow[5][0]);
  row1[7] = row2[3] = fq_mul(pt_pow[1][1], pt_pow[5][0]);
  row2[4] = fq_mul(pt_pow[2][1], pt_pow[4][1]);
  row2[5] = fq_mul(pt_pow[3][1], pt_pow[4][1]);
  row2[6] = fq_mul(pt_pow[2][1], pt_pow[5][1]);
  row2[7] = fq_mul(pt_pow[3][1], pt_pow[5][1]);
  for (i=0; i<8; i++)
  {
    tmp1 = fq_pow_2exp(row1[i], F11 % 48);
    tmp3 = fq_pow_2exp(row1[i], F21 % 48);
    for (j=0; j<8; j++)
    {

      tmp2 = fq_pow_2exp(row2[j], F12 % 48);
      tmp4 = fq_pow_2exp(row2[j], F22 % 48);
      vec[8*i+j] = fq_mul(tmp1, tmp2);
      vec[8*i+j+64] = fq_mul(tmp3, tmp4);
    }
  }
}

void find_m1_m2(void)
{
  int i, j, done;
  fq_elem vec[2][64];
  done = 0;
  while (!done)
  {
    for (i=0; i<64; i++)
    {
      do
      {
        for (j=0; j<6; j++)
          pt_sec2pub[i][j] = fq_rnd();
      }
      while (!pt_sec2pub[i][1] || !pt_sec2pub[i][3] || !pt_sec2pub[i][5]);
      compute_monomials(&vec[0][0], &pt_sec2pub[i][0]);
      for (j=0; j<64; j++)
      {
        M1[j][i] = vec[0][j];
        M2[j][i] = vec[1][j];
      }
    }
    if (!fq_matrix_inverse(&M1_inverse[0][0], &M1[0][0], 64) &&
        !fq_matrix_inverse(&M2_inverse[0][0], &M2[0][0], 64)) done = 1;
  }
}

int main(void)
{
  int i, j;
  find_m1_m2();
  printf("const fq_elem M1_inverse[64][64] = {\n");
  for (i=0; i<64; i++)
  {
    printf("  {\n");
    for (j=0; j<64; j++)
    {
      printf("    UINT64_C(0x%012" PRIxLEAST64 ")", M1_inverse[i][j]);
      if (j != 63) printf(",");
      printf("\n");
    }
    printf("  }");
    if (i != 63) printf(",");
    printf("\n");
  }
  printf("};\n\n");

  printf("const fq_elem M2_inverse[64][64] = {\n");
  for (i=0; i<64; i++)
  {
    printf("  {\n");
    for (j=0; j<64; j++)
    {
      printf("    UINT64_C(0x%012" PRIxLEAST64 ")", M2_inverse[i][j]);
      if (j != 63) printf(",");
      printf("\n");
    }
    printf("  }");
    if (i != 63) printf(",");
    printf("\n");
  }
  printf("};\n\n");

  printf("const fq_elem pt_sec2pub[64][6] = {\n");
  for (i=0; i<64; i++)
  {
    printf("  {\n");
    for (j=0; j<6; j++)
    {
      printf("    UINT64_C(0x%012" PRIxLEAST64 ")", pt_sec2pub[i][j]);
      if (j != 5) printf(",");
      printf("\n");
    }
    printf("  }");
    if (i != 63) printf(",");
    printf("\n");
  }
  printf("};\n\n");

  return 0;
}

