#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

int max(int a, int b) { return (a>b) ? a : b; }
int min(int a, int b) { return (a<b) ? a : b; }

typedef uint_least64_t fq_elem;
typedef fq_elem fq2_elem[2];
typedef fq_elem fq3_elem[3];

/* Arithmetic in Fq */
const uint_least64_t min_poly = UINT64_C(0x1000018000003);

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

void fq_poly_multiply(fq_elem *a, fq_elem *b, fq_elem *c, int deg_b, int deg_c)
{
  int i, j;
  for (i=0; i<=deg_b+deg_c; i++)
  {
    a[i] = 0;
    for (j=max(0,i-deg_c); j<=min(i,deg_b); j++)
      a[i] = fq_add(a[i], fq_mul(b[j], c[i-j]));
  }
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

/* Arithmetic in Fq[T]/<T^2+min_poly_a*T+min_poly_b> */
fq_elem min_poly_a;
fq_elem min_poly_b;

void fq2_add(fq2_elem a, fq2_elem b, fq2_elem c)
{
  a[0] = fq_add(b[0], c[0]);
  a[1] = fq_add(b[1], c[1]);
}

void fq2_mul(fq2_elem a, fq2_elem b, fq2_elem c)
{
  fq_elem tmp[3];
  fq_poly_multiply(tmp, b, c, 1, 1);
  a[1] = fq_add(tmp[1], fq_mul(tmp[2], min_poly_a));
  a[0] = fq_add(tmp[0], fq_mul(tmp[2], min_poly_b));
}

/* Arithmetic in Fq[S]/<S^3+min_poly_c*S^2+min_poly_d*S+min_poly_e> */
fq_elem min_poly_c;
fq_elem min_poly_d;
fq_elem min_poly_e;

void fq3_add(fq3_elem a, fq3_elem b, fq3_elem c)
{
  a[0] = fq_add(b[0], c[0]);
  a[1] = fq_add(b[1], c[1]);
  a[2] = fq_add(b[2], c[2]);
}

void fq3_mul(fq3_elem a, fq3_elem b, fq3_elem c)
{
  fq_elem tmp[5];
  fq_poly_multiply(tmp, b, c, 2, 2);
  tmp[3] = fq_add(tmp[3], fq_mul(tmp[4], min_poly_c));
  tmp[2] = fq_add(tmp[2], fq_mul(tmp[4], min_poly_d));
  tmp[1] = fq_add(tmp[1], fq_mul(tmp[4], min_poly_e));
  a[2] = fq_add(tmp[2], fq_mul(tmp[3], min_poly_c));
  a[1] = fq_add(tmp[1], fq_mul(tmp[3], min_poly_d));
  a[0] = fq_add(tmp[0], fq_mul(tmp[3], min_poly_e));
}

int main(void)
{
  int i;
  fq_elem m2[3][3], m2i[3][3];
  fq_elem m3[5][5], m3i[5][5];
  fq2_elem x;
  fq3_elem y;

  /* Send min_poly to stdout (which will be redirected to the file setup.h) */
  printf("const uint_least64_t min_poly = UINT64_C(0x%013" PRIxLEAST64 ");\n",
            min_poly);

  /* This loop choose random values for min_poly_a and min_poly_b until an */
  /* irreducible polynomial T^2+min_poly_a*T+min_poly_b in Fq[T] is found. */
  /* Irreducibility of f(T) is equivalent to gcd(T^(2^48)-T, f) = 1, since */
  /* deg(f) = 2.                                                           */
  while (1)
  {
    /* Random min_poly_a, min_poly_b */
    min_poly_a = fq_rnd();
    min_poly_b = fq_rnd();
    /* Set x = T */
    x[0] = 0;
    x[1] = 1;
    /* Compute x = T^(2^48) by repeated squaring */
    for (i=0; i<48; i++)
      fq2_mul(x, x, x);
    /* Compute x = T^(2^48)-T (note that the result has already been reduced */
    /* modulo f(T), since that is the way the arithmetic in Fq[T] is done.   */
    x[1] = fq_add(x[1], 1);
    /* Compute Res_T(x(T), f(T)) to check that x(T) and f(T) have no common  */
    /* roots in Fq.                                                          */
    memset(m2, 0, 9*sizeof(fq_elem));
    m2[0][0] = min_poly_b;
    m2[1][0] = min_poly_a;
    m2[2][0] = 1;
    m2[0][2] = m2[1][1] = x[0];
    m2[1][2] = m2[2][1] = x[1];
    /* Check that the resultant matrix is invertible (and break the loop) */
    if (!fq_matrix_inverse(&m2i[0][0], &m2[0][0], 3)) break;
  }
  /* Send min_poly_a and min_poly_b to stdout (redirected to setup.h) */
  printf("const fq_elem min_poly_a = UINT64_C(0x%012" PRIxLEAST64 ");\n",
            min_poly_a);
  printf("const fq_elem min_poly_b = UINT64_C(0x%012" PRIxLEAST64 ");\n",
            min_poly_b);

  /* Do the same for Fq[S]/<S^3+min_poly_c*S^2+min_poly_d*S+min_poly_e> */
  while (1)
  {
    min_poly_c = fq_rnd();
    min_poly_d = fq_rnd();
    min_poly_e = fq_rnd();
    y[0] = 0;
    y[1] = 1;
    y[2] = 0;
    for (i=0; i<48; i++)
      fq3_mul(y, y, y);
    y[1] = fq_add(y[1], 1);
    memset(m3, 0, 25*sizeof(fq_elem));
    m3[0][1] = m3[1][0] = min_poly_e;
    m3[1][1] = m3[2][0] = min_poly_d;
    m3[2][1] = m3[3][0] = min_poly_c;
    m3[3][1] = m3[4][0] = 1;
    m3[0][4] = m3[1][3] = m3[2][2] = y[0];
    m3[1][4] = m3[2][3] = m3[3][2] = y[1];
    m3[2][4] = m3[3][3] = m3[4][2] = y[2];
    if (!fq_matrix_inverse(&m3i[0][0], &m3[0][0], 5)) break;
  }
  printf("const fq_elem min_poly_c = UINT64_C(0x%012" PRIxLEAST64 ");\n",
            min_poly_c);
  printf("const fq_elem min_poly_d = UINT64_C(0x%012" PRIxLEAST64 ");\n",
            min_poly_d);
  printf("const fq_elem min_poly_e = UINT64_C(0x%012" PRIxLEAST64 ");\n",
            min_poly_e);
  printf("\n");

  return 0;
}

