#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include "rng.h"
#include "dme.h"

/* Constants (some hardcoded and some precomputed) */
#include "setup.h"

/* Basic functions */
int max(int a, int b) { return (a>b) ? a : b; }
int min(int a, int b) { return (a<b) ? a : b; }

/* Arithmetic in Fq */
/* Elements in Fq (with q=2^48) are represented internally by integers    */
/* in [0,2^48-1], which clearly fit in a uint_least64_t provided by the   */
/* C99 standard (stdint.h).                                               */
/* Algebraically, elements of Fq can be regarded as equivalence classes   */
/* of polynomials (with binary coefficients) modulo a certain irreducible */
/* polynomial f(x) of degree 48 (in F2[x]). Each equivalence class has a  */
/* unique representative of degree <= 47, say a0+a1*x+...+a47*x^47. This  */
/* element is mapped to the integer a0+2*a1+4*a2+.. +2^47*a47.            */
/* We have chosen f(x)=x^48 + x^28 + x^27 + x + 1, which is also mapped to*/
/* the integer min_poly = UINT64_C(0x1000018000003).                      */

/* Returns a+b in Fq */
fq_elem fq_add(fq_elem a, fq_elem b)
{
  return a ^ b;
}

/* Returns a*b in Fq */
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

/* Returns a^(-1) in Fq; exits if a=0 */
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

/* Returns a^n in Fq; 0<=n<2^64 */
fq_elem fq_pow(fq_elem a, uint_least64_t n)
{
  fq_elem b;
  if (!n) return 1;
  b = fq_pow(a, n>>1);
  b = fq_mul(b, b);
  if (n & 1) b = fq_mul(b, a);
  return b;
}

/* Returns a^(2^n) in Fq */
fq_elem fq_pow_2exp(fq_elem a, unsigned int n)
{
  unsigned int i;
  fq_elem b;
  b = a;
  for (i=0; i<n; i++)
    b = fq_mul(b, b);
  return b;
}

/* Computes the product of the polynomials b[0]+b[1]*x+...+b[deg_b]*x^deg_b */
/* and c[0]+c[1]*x+...+c[deg_c]*x^deg_c, and puts the coefficients of the   */
/* result in the array a[0],...,a[deg_b+deg_c] */
void fq_poly_multiply(fq_elem *a, const fq_elem *b, const fq_elem *c, int deg_b,
int deg_c)
{
  int i, j;
  for (i=0; i<=deg_b+deg_c; i++)
  {
    a[i] = 0;
    for (j=max(0,i-deg_c); j<=min(i,deg_b); j++)
      a[i] = fq_add(a[i], fq_mul(b[j], c[i-j]));
  }
}

/* Computes the product of the matrices b (size nxm) and c (size mxl), and */
/* puts the result in a (size nxl). Matrices are linearized in row-major   */
/* order */
void fq_matrix_multiply(fq_elem *a, const fq_elem *b, const fq_elem *c, int n,
int m, int l)
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

/* Computes the inverse of matrix b (size nxn) and puts the result in a.   */
/* Both matrices (a and b) are linearized in row-major order. Returns 0    */
/* if b in invertible and -1 otherwise (in which case a is left untouched).*/
/* n must be <= 64 */
int fq_matrix_inverse(fq_elem *a, const fq_elem *b, int n)
{
  int i, j, k;
  fq_elem tmp;
  fq_elem c[64][128];

  /* Fill c with a copy of (b|Id_n) */
  memset(c, 0, 64*128*sizeof(fq_elem));
  for (i=0; i<n; i++)
  {
    for (j=0; j<n; j++)
      c[i][j] = b[i*n+j];
    c[i][i+n] = 1;
  }

  /* Eliminate the non-zero entries below the main diagonal (of c), pivoting */
  /* when necessary. */
  for (j=0; j<n; j++)
  {
    /* Find pivot in j-th column */
    for (i=j; i<n && !c[i][j]; i++);
    /* If no-pivot was found, the matrix is not invertible. */
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

  /* Eliminate the non-zero entries above the main diagonal (no-pivoting is */
  /* is necessary, since we already have 1's in the diagonal. */
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

  /* At this point the matrix c contains (Id_n|b^-1), so we copy the second */
  /* block to array a (linearized in row-major order). */
  for (i=0; i<n; i++)
    for (j=0; j<n; j++)
      a[i*n+j] = c[i][j+n];

  return 0;
}

/* Arithmetic in Fq2 = Fq[T]/<T^2+min_poly_a*T+min_poly_b> */
/* Elements in Fq2 are represented internally as a pair (r,s) of elements  */
/* in Fq. The pair (r,s) corresponds to the equivalence class of r+s*T mod */
/* the irreducible polynomial T^2+min_poly_a*T+min_poly_b in Fq[T].        */
/* In memory, the "r" component is stored at the locaction with lower      */
/* address, followed by the "s" component. This is consistent with our     */
/* convention for polynomials in the function fq_polynomial_multiply()     */
/* described above. Another reason why this is convenient is that the      */
/* isomorphism (Fq)^2 --> Fq2 that is used all along the algorithms does   */
/* not require to move anything in memory.                                 */

/* Computes b+c in Fq2 and stores the result in a (which is equivalent to  */
/* a coordinate-wise addition of elements in Fq).                          */
void fq2_add(fq2_elem a, const fq2_elem b, const fq2_elem c)
{
  a[0] = fq_add(b[0], c[0]);
  a[1] = fq_add(b[1], c[1]);
}

/* Computes b*c in Fq2 and stores the result in a (which is done by        */
/* multipying the polynomials b[0]+b[1]*T and c[0]+c[1]*T, and reducing the*/
/* resulting polynomial modulo T^2+min_poly_a*T+min_poly_b).               */
void fq2_mul(fq2_elem a, const fq2_elem b, const fq2_elem c)
{
  fq_elem tmp[3];
  fq_poly_multiply(tmp, b, c, 1, 1);
  a[1] = fq_add(tmp[1], fq_mul(tmp[2], min_poly_a));
  a[0] = fq_add(tmp[0], fq_mul(tmp[2], min_poly_b));
}

/* Computes b^n (with 0<=n<2^128) in Fq2 and stores the result in a. */
void fq2_pow(fq2_elem a, const fq2_elem b, const u128 n)
{
  int i, j;
  a[0] = 1;
  a[1] = 0;
  if (n[0] || n[1])
  {
    for (i=1; i>=0; i--)
      for (j=63; j>=0; j--)
      {
        fq2_mul(a, a, a);
        if ((n[i] >> j) & 1) fq2_mul(a, a, b);
      }
  }
}

/* Returns 1 if a=0 in Fq2, and 0 otherwise. */
int fq2_is0(fq2_elem a)
{
  return (!a[0] && !a[1]);
}

/* Arithmetic in Fq3 = Fq[S]/<S^3+min_poly_c*S^2+min_poly_d*S+min_poly_e>  */
/* Elements in Fq3 are triples (r,s,t) of elements in Fq, representing the */
/* equivalence class of r+s*S+t*S^2 modulo the irreducible polynomial      */
/* S^3+min_poly_c*S^2+min_poly_d*S+min_poly_e.....                         */

/* Computes b+c in Fq3 and stores the result in a.                         */
void fq3_add(fq3_elem a, const fq3_elem b, const fq3_elem c)
{
  a[0] = fq_add(b[0], c[0]);
  a[1] = fq_add(b[1], c[1]);
  a[2] = fq_add(b[2], c[2]);
}

/* Computes b*c in Fq3 and stores the result in a. */
void fq3_mul(fq3_elem a, const fq3_elem b, const fq3_elem c)
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

/* Computes b^n (with 0<=n<2^192) and stores the result in a. */
void fq3_pow(fq3_elem a, const fq3_elem b, const u192 n)
{
  int i, j;
  a[0] = 1;
  a[1] = 0;
  a[2] = 0;
  if (n[0] || n[1] || n[2])
  {
    for (i=2; i>=0; i--)
      for (j=63; j>=0; j--)
      {
        fq3_mul(a, a, a);
        if ((n[i] >> j) & 1) fq3_mul(a, a, b);
      }
  }
}

/* Returns 1 if a=0 in Fq3, and 0 otherwise. */
int fq3_is0(fq3_elem a)
{
  return (!a[0] && !a[1] && !a[2]);
}

/* API (internal) */
/* The cryptosystem is based on a polynomial map from P: (Fq)^6 --> (Fq)^6. */
/* This map is constructed as the composition P = L3 o G2 o L2 o G1 o L1,   */
/* where L1, L2, L3: (Fq)^6 --> (Fq)^6 are linear maps, and the other two   */
/* G1 : (Fq2)^3 --> (Fq2)^3 and G2 : (Fq3)^2 --> (Fq3)^2 are exponential    */
/* maps with fixed exponents (setup.h).                                     */
/* L1 has three 2x2 blocks, L2 and L3 have each two 3x3 blocks, and together*/
/* define the secret key.                                                   */
/* G1 and G2 require first to decide isomorphisms (Fq)^6 --> (Fq2)^3 and    */
/* (Fq)^6 --> (Fq3)^2. These are induced by the natural maps (Fq)^2 --> Fq2 */
/* such that (r,s) |--> equivalence class of (r+sT), and (Fq)^3 --> Fq3 such*/
/* that (r,s,t) |--> equivalence class of (r+sS+tS^2). With our internal    */
/* data representation of elements in Fq, Fq2, Fq3, these isomorphisms are  */
/* indeed the identity map (in memory).                                     */
/* It can be proven that (for G1 and G2 of a particular form), the map P has*/
/* a particular structure: the six polynomials have each 64 monomials. Also,*/
/* the first three polynomials share these monomials, and the same goes for */
/* the last three polynomials. The 64*6 coefficients of P define the public */
/* key.                                                                     */

/* Compute ct = P(pt) for the polynomial map defined by the secret key skey.*/
/* That is, compute ct = (L3 o G2 o L2 o G1 o L1)(pt), where pt, ct are     */
/* vectors in (Fq)^6.                                                       */
/* Returns -1 if the plaintext is invalid (pt[1]=0 or pt[3]=0 or pt[5]=0),  */
/* and 0 otherwise.                                                         */ 
/* Although this function is not usually necessary for a public-key system, */
/* it will be used here to reconstruct the coefficients of the public key   */
/* for a given secret key.                                                  */
int fq_encrypt_with_skey(fq_elem *ct, const fq_elem *pt, const secret_key *skey)
{
  fq_elem y[6], z[6], w[6], v[6];
  fq2_elem tmp1, tmp2, tmp3, tmp4, tmp5, tmp6;
  fq3_elem aux1, aux2, aux3, aux4;

  if (!pt[1] || !pt[3] || !pt[5]) return -1;

  /* L1 */
  fq_matrix_multiply(&y[0], &skey->L1[0][0][0], &pt[0], 2, 2, 1);
  fq_matrix_multiply(&y[2], &skey->L1[1][0][0], &pt[2], 2, 2, 1);
  fq_matrix_multiply(&y[4], &skey->L1[2][0][0], &pt[4], 2, 2, 1);

  /* G1 */
  fq2_pow(tmp1, &y[0], G1[0][0]);
  fq2_pow(tmp2, &y[2], G1[0][1]);
  fq2_pow(tmp3, &y[0], G1[1][0]);
  fq2_pow(tmp4, &y[4], G1[1][2]);
  fq2_pow(tmp5, &y[2], G1[2][1]);
  fq2_pow(tmp6, &y[4], G1[2][2]);
  fq2_mul(&z[0], tmp1, tmp2);
  fq2_mul(&z[2], tmp3, tmp4);
  fq2_mul(&z[4], tmp5, tmp6);

  /* L2 */
  fq_matrix_multiply(&w[0], &skey->L2[0][0][0], &z[0], 3, 3, 1);
  fq_matrix_multiply(&w[3], &skey->L2[1][0][0], &z[3], 3, 3, 1);

  /* G2 */
  fq3_pow(aux1, &w[0], G2[0][0]);
  fq3_pow(aux2, &w[3], G2[0][1]);
  fq3_pow(aux3, &w[0], G2[1][0]);
  fq3_pow(aux4, &w[3], G2[1][1]);
  fq3_mul(&v[0], aux1, aux2);
  fq3_mul(&v[3], aux3, aux4);

  /* L3 */
  fq_matrix_multiply(&ct[0], &skey->L3[0][0][0], &v[0], 3, 3, 1);
  fq_matrix_multiply(&ct[3], &skey->L3[1][0][0], &v[3], 3, 3, 1);

  return 0;
}

/* Compute pt = P^(-1)(ct) for the map defined by a given secret key skey,   */
/* i.e. pt = (L1^(-1) o G1^(-1) o L2^(-1) o G2^(-1) o L3^(-1))(ct), where L1,*/
/* L2, L3 are the secret key.                                                */
/* Returns -1 if the ciphertext ct does not produce a valid plaintext pt, and*/
/* 0 otherwise.                                                              */
int fq_decrypt(fq_elem *pt, const fq_elem *ct, const secret_key *skey)
{
  fq_elem y[6], z[6], w[6], v[6];
  fq2_elem tmp1, tmp2, tmp3, tmp4, tmp5, tmp6, tmp7, tmp8, tmp9;
  fq3_elem aux1, aux2, aux3, aux4;

  /* L3^(-1) */
  fq_matrix_multiply(&v[0], &skey->L3_inverse[0][0][0], &ct[0], 3, 3, 1);
  fq_matrix_multiply(&v[3], &skey->L3_inverse[1][0][0], &ct[3], 3, 3, 1);

  /* G2^(-1) */
  if (fq3_is0(&v[0]) || fq3_is0(&v[3])) return -1;
  fq3_pow(aux1, &v[0], G2_inverse[0][0]);
  fq3_pow(aux2, &v[3], G2_inverse[0][1]);
  fq3_pow(aux3, &v[0], G2_inverse[1][0]);
  fq3_pow(aux4, &v[3], G2_inverse[1][1]);
  fq3_mul(&w[0], aux1, aux2);
  fq3_mul(&w[3], aux3, aux4);

  /* L2^(-1) */
  fq_matrix_multiply(&z[0], &skey->L2_inverse[0][0][0], &w[0], 3, 3, 1);
  fq_matrix_multiply(&z[3], &skey->L2_inverse[1][0][0], &w[3], 3, 3, 1);

  /* G1^(-1) */
  if (fq2_is0(&z[0]) || fq2_is0(&z[2]) || fq2_is0(&z[4])) return -1;
  fq2_pow(tmp1, &z[0], G1_inverse[0][0]);
  fq2_pow(tmp2, &z[2], G1_inverse[0][1]);
  fq2_pow(tmp3, &z[4], G1_inverse[0][2]);
  fq2_pow(tmp4, &z[0], G1_inverse[1][0]);
  fq2_pow(tmp5, &z[2], G1_inverse[1][1]);
  fq2_pow(tmp6, &z[4], G1_inverse[1][2]);
  fq2_pow(tmp7, &z[0], G1_inverse[2][0]);
  fq2_pow(tmp8, &z[2], G1_inverse[2][1]);
  fq2_pow(tmp9, &z[4], G1_inverse[2][2]);
  fq2_mul(&y[0], tmp1, tmp2);
  fq2_mul(&y[0], &y[0], tmp3);
  fq2_mul(&y[2], tmp4, tmp5);
  fq2_mul(&y[2], &y[2], tmp6);
  fq2_mul(&y[4], tmp7, tmp8);
  fq2_mul(&y[4], &y[4], tmp9);

  /* L1^(-1) */
  fq_matrix_multiply(&pt[0], &skey->L1_inverse[0][0][0], &y[0], 2, 2, 1);
  fq_matrix_multiply(&pt[2], &skey->L1_inverse[1][0][0], &y[2], 2, 2, 1);
  fq_matrix_multiply(&pt[4], &skey->L1_inverse[2][0][0], &y[4], 2, 2, 1);

  if (!pt[1] || !pt[3] || !pt[5]) return -1;
  return 0;
}

/* Compute the 64 monomials for the first three polynomials of P and the 64 */
/* monomials for the last three polynomials, as a function of the plaintext */
/* pt in (Fq)^6. The 128 values are stored consecutively in the array vec.  */
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

/* Compute ct = P(pt) for the polynomial map defined by a public key pkey.   */
/* Basically, it computes the monomials and the uses the coefficients stored */
/* in the public key pkey to evaluate P. Returns 0 (always).                 */
int fq_encrypt(fq_elem *ct, const fq_elem *pt, const public_key *pkey)
{
  fq_elem vec[2][64];
  if (!pt[1] || !pt[3] || !pt[5]) return -1;
  compute_monomials(&vec[0][0], pt);
  fq_matrix_multiply(&ct[0], &pkey->coeffs1[0][0], &vec[0][0], 3, 64, 1);
  fq_matrix_multiply(&ct[3], &pkey->coeffs2[0][0], &vec[1][0], 3, 64, 1);
  return 0;
}

/* Computes the public key pkey corresponding to a given secret key skey.   */
/* This is done by solving computing P() of 64 hardcoded plaintexts (which  */
/* can be found in pt_sec2pub), and then interpolating the coefficients of  */
/* the six polynomials. This actually requires inverting two fixed 64x64    */
/* matrices (which have been precomputed in setup.h).                       */
int fq_skey_to_pkey(public_key *pkey, const secret_key *skey)
{
  int i, j;
  fq_elem CT1[3][64];
  fq_elem CT2[3][64];
  fq_elem ct[6];
  for (i=0; i<64; i++)
  {
    fq_encrypt_with_skey(ct, &pt_sec2pub[i][0], skey);
    for (j=0; j<3; j++)
    {
      CT1[j][i] = ct[j];
      CT2[j][i] = ct[j+3];
    }
  }
  fq_matrix_multiply(&pkey->coeffs1[0][0], &CT1[0][0], &M1_inverse[0][0], 3, 64, 64);
  fq_matrix_multiply(&pkey->coeffs2[0][0], &CT2[0][0], &M2_inverse[0][0], 3, 64, 64);
  return 0;
}

/* Serialization */
/* Elements in Fq are internally represented by integers in [0, 2^48-1].     */
/* These integers can be written as x0 + x1*2^8 + ... + x5*2^40, in base 2^8,*/
/* i.e. x0,...,x5 in [0, 255]. We define the serialization of an element of  */
/* Fq as the sequence of bytes (x5,x4,...,x0).                               */

/* Serialize an element a of Fq, and store the result in the memory location */
/* pointed by *p. Also increase *p by 6.                                     */
void serialize_fq_elem(unsigned char **p, fq_elem a)
{
  int i;
  for (i=5; i>=0; i--)
    *((*p)++) = (a >> (8*i)) & 0xff;
}

/* Serialize a secret key skey and store the result in the array p. The     */
/* relevant entries of L1, L2, L3 are linearized and stored sequencially.   */
/* In total, a secret key occupies (12+18+18)*6 bytes.                      */
void serialize_skey(unsigned char *p, const secret_key *skey)
{
  int i, j, k;
  for (i=0; i<3; i++)
    for (j=0; j<2; j++)
      for (k=0; k<2; k++)
        serialize_fq_elem(&p, skey->L1[i][j][k]);
  for (i=0; i<2; i++)
    for (j=0; j<3; j++)
      for (k=0; k<3; k++)
        serialize_fq_elem(&p, skey->L2[i][j][k]);
  for (i=0; i<2; i++)
    for (j=0; j<3; j++)
      for (k=0; k<3; k++)
        serialize_fq_elem(&p, skey->L3[i][j][k]);
}

/* Serialize a public key pkey and store the result in the array p. The 64  */
/* coefficients of the 6 polynomials are linearized and stored sequencially.*/
/* In total, a public key occupies 64*6*6 bytes.                            */
void serialize_pkey(unsigned char *p, const public_key *pkey)
{
  int i, j;
  for (i=0; i<3; i++)
    for (j=0; j<64; j++)
      serialize_fq_elem(&p, pkey->coeffs1[i][j]);
  for (i=0; i<3; i++)
    for (j=0; j<64; j++)
      serialize_fq_elem(&p, pkey->coeffs2[i][j]);
}

/* Serialize a vector text in (Fq)^6, entry by entry. The result occupies   */
/* 6*6 bytes, and it is stored in the array p.                              */
void serialize_text(unsigned char *p, const fq_elem *text)
{
  int i;
  for (i=0; i<6; i++)
    serialize_fq_elem(&p, text[i]);
}

/* Returns the element of Fq whose serialization is located at *p. It also  */
/* increases *p by 6.                                                       */
fq_elem parse_fq_elem(const unsigned char **p)
{
  int i;
  fq_elem a;
  a = 0;
  for (i=0; i<6; i++)
  {
    a <<= 8;
    a += (unsigned char) *((*p)++);
  }
  return a;
}

/* Reconstructs the secret key whose serialization is located at p. Returns */
/* 0 if the matrices L1, L2, L3 are invertible, and -1 otherwise.           */
int parse_skey(secret_key *skey, const unsigned char *p)
{
  int i, j, k;
  for (i=0; i<3; i++)
  {
    for (j=0; j<2; j++)
      for (k=0; k<2; k++)
        skey->L1[i][j][k] = parse_fq_elem(&p);
    if (fq_matrix_inverse(&skey->L1_inverse[i][0][0], &skey->L1[i][0][0], 2))
      return -1;
  }
  for (i=0; i<2; i++)
  {
    for (j=0; j<3; j++)
      for (k=0; k<3; k++)
        skey->L2[i][j][k] = parse_fq_elem(&p);
    if (fq_matrix_inverse(&skey->L2_inverse[i][0][0], &skey->L2[i][0][0], 3))
      return -1;
  }
  for (i=0; i<2; i++)
  {
    for (j=0; j<3; j++)
      for (k=0; k<3; k++)
        skey->L3[i][j][k] = parse_fq_elem(&p);
    if (fq_matrix_inverse(&skey->L3_inverse[i][0][0], &skey->L3[i][0][0], 3))
      return -1;
  }
  return 0;
}

/* Reconstructs the public key whose serialization is located at p. It always */
/* returns 0.                                                                 */
int parse_pkey(public_key *pkey, const unsigned char *p)
{
  int i, j;
  for (i=0; i<3; i++)
    for (j=0; j<64; j++)
      pkey->coeffs1[i][j] = parse_fq_elem(&p);
  for (i=0; i<3; i++)
    for (j=0; j<64; j++)
      pkey->coeffs2[i][j] = parse_fq_elem(&p);
  return 0;
}

/* Reconstructs the vector in (Fq)^6 whose serialization is located at p. */
void parse_text(fq_elem *text, const unsigned char *p)
{
  int i;
  for (i=0; i<6; i++)
    text[i] = parse_fq_elem(&p);
}

/* API (external) */
/* Create a keypair (and serializes it), so pk must have enough space for */
/* CRYPTO_PUBLICKEYBYTES, and sk for CRYPTO_SECRETKEYBYTES.               */
/* Since the secret key is just generated at random, there is a tiny      */
/* probability that one of the matrices L1, L2, L3 is not invertible. In  */
/* those cases, the function returns -1, and it should be called again to */
/* get a proper keypair. When there are no errors, it returns 0.          */
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
  secret_key skey;
  public_key pkey;
  randombytes(sk, CRYPTO_SECRETKEYBYTES);
  if (parse_skey(&skey, sk)) return -1;
  if (fq_skey_to_pkey(&pkey, &skey)) return -1;
  serialize_pkey(pk, &pkey);
  return 0;
}

/* Creates a random shared secret ss (an array of CRYPTO_BYTES bytes), and */
/* encrypts it with a given public key pk. The resulting ciphertext (which */
/* encapsulates the shared secret) is put in ct (which is an array of      */
/* CRYPTO_CIPHERTEXTBYTES bytes). It always returns 0.                     */
/* To be able to use our function fq_encrypt(), the shared secret is padded*/
/* with 3 bytes = 1 (actually these are inserted at the 11th, 22nd, 33rd   */
/* bytes of ss) to always produce a valid plaintext.                       */
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned
char *pk)
{
  int i;
  unsigned char pt[6*6];
  fq_elem ct_q[6], pt_q[6];
  public_key pkey;
  randombytes(ss, CRYPTO_BYTES);
  for (i=0; i<11; i++)
  {
    pt[i] = ss[i];
    pt[i+12] = ss[i+11];
    pt[i+24] = ss[i+22];
  }
  pt[11] = pt[23] = pt[35] = 1;
  parse_text(pt_q, pt);
  if (parse_pkey(&pkey, pk) || fq_encrypt(ct_q, pt_q, &pkey)) return -1;
  serialize_text(ct, ct_q);
  return 0;

}

/* Recovers the shared secret ss that in encapsulated within ct, by using   */
/* the appropriate secret key sk. Basically, it is a call to our fq_decrypt */
/* followed by a removal of the padding that was added by the function      */
/* crypto_kem_enc(). It returns -1 if decryption failed, or if the secret   */
/* key is invalid, or if the padding is not exactly the three bytes = 1 at  */
/* the correct location. Otherwise, it returns 0.                           */
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned
char *sk)
{
  int i;
  unsigned char pt[6*6];
  fq_elem ct_q[6], pt_q[6];
  secret_key skey;
  parse_text(ct_q, ct);
  if (parse_skey(&skey, sk) || fq_decrypt(pt_q, ct_q, &skey)) return -1;
  serialize_text(pt, pt_q);
  if (pt[11] != 1 || pt[23] != 1 || pt[35] != 1) return -1;
  for (i=0; i<11; i++)
  {
    ss[i] = pt[i];
    ss[i+11] = pt[i+12];
    ss[i+22] = pt[i+24];
  }
  return 0;
}

