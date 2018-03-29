#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "bigint.h"

/* a = b */
void bigint_set(bigint a, bigint b)
{
  memcpy(a, b, 4*NDIG);
}

/* a = x */
void bigint_seti(bigint a, int32_t x)
{
  a[0] = x;
  memset(a+1, (x<0) ? -1 : 0, 4*(NDIG-1));
}

/* a = b + c */
void bigint_add(bigint a, bigint b, bigint c)
{
  int i;
  int64_t r = 0;
  for (i=0; i<NDIG; i++)
  {
    r += b[i];
    r += c[i];
    a[i] = r;
    r >>= 32;
  }
}

/* a = b + x */
void bigint_addi(bigint a, bigint b, int32_t x)
{
  int i;
  int64_t r = x;
  for (i=0; i<NDIG; i++)
  {
    r += b[i];
    a[i] = r;
    r >>= 32;
  }
}

/* a = b - c */
void bigint_sub(bigint a, bigint b, bigint c)
{
  int i;
  int64_t r = 0;
  for (i=0; i<NDIG; i++)
  {
    r += b[i];
    r -= c[i];
    a[i] = r;
    r >>= 32;
  }
}

/* a = b - x */
void bigint_subi(bigint a, bigint b, int32_t x)
{
  int i;
  int64_t r = -(int64_t)x;
  for (i=0; i<NDIG; i++)
  {
    r += b[i];
    a[i] = r;
    r >>= 32;
  }
}

/* a = x - b */
void bigint_isub(bigint a, int32_t x, bigint b)
{
  int i;
  int64_t r = x;
  for (i=0; i<NDIG; i++)
  {
    r -= b[i];
    a[i] = r;
    r >>= 32;
  }
}

/* returns the sign of a */
int bigint_sgn(bigint a)
{
  int i;
  if ((int32_t) a[NDIG-1] < 0) return -1;
  for (i=NDIG-1; i>=0; i--)
    if (a[i]) return 1;
  return 0;
}

/* returns the sign of b-c */
int bigint_cmp(bigint b, bigint c)
{
  int i;
  if ((int32_t) b[NDIG-1] < (int32_t) c[NDIG-1]) return -1;
  if ((int32_t) b[NDIG-1] > (int32_t) c[NDIG-1]) return 1;
  for (i=NDIG-2; i>=0; i--)
  {
    if (b[i] < c[i]) return -1;
    if (b[i] > c[i]) return 1;
  }
  return 0;
}

/* returns the sign of b-x */
int bigint_cmpi(bigint b, int32_t x)
{
  int i;
  int32_t sx = (x < 0) ? -1 : 0;
  if ((int32_t) b[NDIG-1] < sx) return -1;
  if ((int32_t) b[NDIG-1] > sx) return 1;
  for (i=NDIG-2; i>=1; i--)
  {
    if (b[i] < (uint32_t) sx) return -1;
    if (b[i] > (uint32_t) sx) return 1;
  }
  if (b[0] < (uint32_t) x) return -1;
  if (b[0] > (uint32_t) x) return 1;
  return 0;
}

/* a = b * c */
void bigint_mul(bigint a, bigint b, bigint c)
{
  int i, j;
  uint64_t r;
  bigint d;
  bigint_seti(d, 0);
  for (i=0; i<NDIG; i++)
  {
    r = 0;
    for (j=0; j<NDIG-i; j++)
    {
      r += (uint64_t) b[i] * c[j] + d[i+j];
      d[i+j] = r;
      r >>= 32;
    }
  }
  bigint_set(a, d);
}

/* ah:al = b * c */
void bigint_mul2(bigint ah, bigint al, bigint b, bigint c)
{
  int i, j;
  uint64_t r;
  uint32_t d[2*NDIG];
  memset(d, 0, 8*NDIG);
  for (i=0; i<NDIG; i++)
  {
    r = 0;
    for (j=0; j<NDIG; j++)
    {
      r += (uint64_t) b[i] * c[j] + d[i+j];
      d[i+j] = r;
      r >>= 32;
    }
    d[i+j] = r;
  }
  if ((int32_t) b[NDIG-1] < 0) bigint_sub(d+NDIG, d+NDIG, c);
  if ((int32_t) c[NDIG-1] < 0) bigint_sub(d+NDIG, d+NDIG, b);
  memcpy(al, d, 4*NDIG);
  memcpy(ah, d+NDIG, 4*NDIG);
}

/* a = b * x */
void bigint_muli(bigint a, bigint b, int32_t x)
{
  int i;
  int64_t r = 0;
  for (i=0; i<NDIG; i++)
  {
    r += b[i] * (int64_t)x;
    a[i] = r;
    r >>= 32;
  }
}

/* a = b/x and return b%x */
int32_t bigint_divi(bigint a, bigint b, int32_t x)
{
  int i, sx = 0, sb = 0;
  int64_t r;
  if (!x)
  {
    fprintf(stderr, "error: division by zero!\n");
    exit(-1);
  }
  if (x < 0) { x = -x; sx = 1; }
  if ((int32_t) b[NDIG-1] < 0)
  {
    bigint_isub(a, 0, b);
    sb = 1;
  }
  else
    bigint_set(a, b);
  r = a[NDIG-1];
  for (i=NDIG-1; i>0; i--)
  {
    a[i] = r / x;
    r %= x;
    r <<= 32;
    r += a[i-1];
  }
  a[0] = r / x;
  r %= x;
  if (sx ^ sb) bigint_isub(a, 0, a);
  if (sb) r = -r;
  return r;
}

/* q = x/y, r = x%y */
void bigint_qr(bigint q, bigint r, bigint x, bigint y)
{
  int l, s, i, j, sx = 0, sy = 0;
  uint64_t p, quot, rem, c1, c2;
  uint32_t qr[NDIG+1], y2[NDIG];
  if ((int32_t) x[NDIG-1] < 0)
  {
    sx = 1;
    bigint_isub(qr, 0, x);
  }
  else
    bigint_set(qr, x);
  if ((int32_t) y[NDIG-1] < 0)
  {
    sy = 1;
    bigint_isub(y2, 0, y);
  }
  else
    bigint_set(y2, y);
  for (l=NDIG-1; l>=0 && !y2[l]; l--);
  if (l < 0)
  {
    fprintf(stderr, "error: division by zero!\n");
    exit(-1);
  }
  for (s=0; !(y2[l] >> (31-s)); s++);
  c1 = c2 = 0;
  for (i=0; i<NDIG; i++)
  {
    p = ((uint64_t) y2[i] << s) + c1;
    y2[i] = p;
    c1 = p >> 32;
    p = ((uint64_t) qr[i] << s) + c2;
    qr[i] = p;
    c2 = p >> 32;
  }
  qr[NDIG] = c2;
  for (i=NDIG-l-1; i>=0; i--)
  {
    if (qr[i+l+1] >= y2[l])
      quot = 0xffffffff;
    else
    {
      p = ((uint64_t) qr[i+l+1] << 32) + qr[i+l];
      if (!p) continue;
      quot = p / y2[l];
      rem = p % y2[l];
      if (l >= 1 && quot*y2[l-1] > (rem << 32) + qr[i+l-1])
      {
        quot--;
        rem += y2[l];
        if ((rem >> 32) == 0 && quot*y2[l-1] > (rem << 32) + qr[i+l-1])
          quot--;
      }
    }
    c1 = 0;
    for (j=0; j<=l; j++)
    {
      p = (uint64_t) qr[i+j] - quot * y2[j] - c1;
      qr[i+j] = p;
      c1 = (0xffffffff-p) >> 32;
    }
    qr[i+l+1] -= c1;
    if (qr[i+l+1])
    {
      quot--;
      c1 = 0;
      for (j=0; j<=l; j++)
      {
        p = (uint64_t) qr[i+j] + (uint64_t) y2[j] + c1;
        qr[i+j] = p;
        c1 = p >> 32;
      }
    }
    qr[i+l+1] = quot;
  }
  for (i=0; i<NDIG-l; i++) q[i] = qr[i+l+1];
  for (; i<NDIG; i++) q[i] = 0;
  for (i=0; i<=l; i++) r[i] = qr[i];
  for (; i<NDIG; i++) r[i] = 0;
  c1 = 0;
  for (i=NDIG-1; i>=0; i--)
  {
    p = (c1 << 32) + r[i];
    r[i] = p >> s;
    c1 = p & ((1<<s)-1);
  }
  if (sy ^ sx) bigint_isub(q, 0, q);
  if (sx) bigint_isub(r, 0, r);
}

/* r = xh:xl % y */
void bigint_mod2(bigint r, bigint xh, bigint xl, bigint y)
{
  int l, s, i, j, sx = 0;
  uint64_t p, quot, rem, c1, c2;
  int64_t w;
  uint32_t qr[2*NDIG+1], y2[NDIG];
  bigint_set(qr, xl);
  bigint_set(qr+NDIG, xh);
  if ((int32_t) xh[NDIG-1] < 0)
  {
    sx = 1;
    w = 0;
    for (i=0; i<2*NDIG; i++)
    {
      w -= qr[i];
      qr[i] = w;
      w >>= 32;
    }
  }
  if ((int32_t) y[NDIG-1] < 0)
    bigint_isub(y2, 0, y);
  else
    bigint_set(y2, y);
  for (l=NDIG-1; l>=0 && !y2[l]; l--);
  if (l < 0)
  {
    fprintf(stderr, "error: division by zero!\n");
    exit(-1);
  }
  for (s=0; !(y2[l] >> (31-s)); s++);
  c1 = c2 = 0;
  for (i=0; i<NDIG; i++)
  {
    p = ((uint64_t) y2[i] << s) + c1;
    y2[i] = p;
    c1 = p >> 32;
  }
  for (i=0; i<2*NDIG; i++)
  {
    p = ((uint64_t) qr[i] << s) + c2;
    qr[i] = p;
    c2 = p >> 32;
  }
  qr[2*NDIG] = c2;
  for (i=2*NDIG-l-1; i>=0; i--)
  {
    if (qr[i+l+1] >= y2[l])
      quot = 0xffffffff;
    else
    {
      p = ((uint64_t) qr[i+l+1] << 32) + qr[i+l];
      if (!p) continue;
      quot = p / y2[l];
      rem = p % y2[l];
      if (l >= 1 && quot*y2[l-1] > (rem << 32) + qr[i+l-1])
      {
        quot--;
        rem += y2[l];
        if ((rem >> 32) == 0 && quot*y2[l-1] > (rem << 32) + qr[i+l-1])
          quot--;
      }
    }
    c1 = 0;
    for (j=0; j<=l; j++)
    {
      p = (uint64_t) qr[i+j] - quot * y2[j] - c1;
      qr[i+j] = p;
      c1 = (0xffffffff-p) >> 32;
    }
    qr[i+l+1] -= c1;
    if (qr[i+l+1])
    {
      quot--;
      c1 = 0;
      for (j=0; j<=l; j++)
      {
        p = (uint64_t) qr[i+j] + (uint64_t) y2[j] + c1;
        qr[i+j] = p;
        c1 = p >> 32;
      }
    }
  }
  for (i=0; i<=l; i++) r[i] = qr[i];
  for (; i<NDIG; i++) r[i] = 0;
  c1 = 0;
  for (i=NDIG-1; i>=0; i--)
  {
    p = (c1 << 32) + r[i];
    r[i] = p >> s;
    c1 = p & ((1<<s)-1);
  }
  if (sx) bigint_isub(r, 0, r);
}

void bigint_print(bigint a, int base)
{
  bigint b;
  int32_t r;
  bigint_set(b, a);
  if ((int32_t) b[NDIG-1] < 0)
  {
    printf("-");
    bigint_isub(b, 0, b);
  }
  if (bigint_cmpi(b, base) >= 0)
  {
    r = bigint_divi(b, b, base);
    bigint_print(b, base);
  }
  else
    r = b[0];
  printf("%c", (r<10) ? r+'0' : r+'a'-10);
}

void bigint_parse(bigint a, const char *s, int base)
{
  char c;
  int sa;
  sa = 0;
  if (*s == '-') { sa=1; s++; }
  bigint_seti(a, 0);
  while ((c = *s++))
  {
    bigint_muli(a, a, base);
    bigint_addi(a, a, (c>='0' && c<='9') ? c-'0' : c-'a'+10);
  }
  if (sa) bigint_isub(a, 0, a);
}

/* a = gcd(b,c) >= 0 */
void bigint_gcd(bigint a, bigint b, bigint c)
{
  bigint b2, c2, q, r;
  bigint_set(b2, b);
  bigint_set(c2, c);
  while (bigint_sgn(c2))
  {
    bigint_qr(q, r, b2, c2);
    bigint_set(b2, c2);
    bigint_set(c2, r);
  }
  if ((int32_t) b2[NDIG-1] < 0)
    bigint_isub(a, 0, b2);
  else
    bigint_set(a, b2);
}

/* a = gcd(b,c) = b*x+c*y >= 0 */
void bigint_extgcd(bigint a, bigint x, bigint y, bigint b, bigint c)
{
  bigint s, t, r, s2, t2, r2, q, r3;
  bigint_seti(s, 0);
  bigint_seti(t, 1);
  bigint_set(r, b);
  bigint_seti(s2, 1);
  bigint_seti(t2, 0);
  bigint_set(r2, c);
  while (bigint_sgn(r))
  {
    bigint_qr(q, r3, r2, r);
    bigint_set(r2, r);
    bigint_set(r, r3);
    bigint_mul(r3, q, s);
    bigint_sub(r3, s2, r3);
    bigint_set(s2, s);
    bigint_set(s, r3);
    bigint_mul(r3, q, t);
    bigint_sub(r3, t2, r3);
    bigint_set(t2, t);
    bigint_set(t, r3);
  }
  if ((int32_t) r2[NDIG-1] < 0)
  {
    bigint_isub(x, 0, t2);
    bigint_isub(y, 0, s2);
    bigint_isub(a, 0, r2);
  }
  else
  {
    bigint_set(x, t2);
    bigint_set(y, s2);
    bigint_set(a, r2);
  }
}

/* a = b^(-1) mod m */
void bigint_invmod(bigint a, bigint b, bigint m)
{
  bigint g, y;
  bigint_extgcd(g, a, y, b, m);
  if (bigint_cmpi(g, 1))
  {
    fprintf(stderr, "error: no multiplicative inverse!\n");
    exit(-1);
  }
}

/* a = b^e mod m */
void bigint_powmod(bigint a, bigint b, bigint e, bigint m)
{
  int l, s;
  bigint t, ph, pl, b2, e2;
  bigint_seti(t, 1);
  if ((int32_t) e[NDIG-1] < 0)
  {
    bigint_isub(e2, 0, e);
    bigint_invmod(b2, b, m);
  }
  else
  {
    bigint_set(e2, e);
    bigint_set(b2, b);
  }
  for (l=NDIG-1; l>=0 && !e2[l]; l--);
  if (l>=0)
  {
    for (s=31; !((e2[l]>>s)&1); s--);
    bigint_mul2(ph, pl, t, b2);
    bigint_mod2(t, ph, pl, m);
    s--;
    while (l>=0)
    {
      for (; s>=0; s--)
      {
        bigint_mul2(ph, pl, t, t);
        bigint_mod2(t, ph, pl, m);
        if ((e2[l] >> s) & 1)
        {
          bigint_mul2(ph, pl, t, b2);
          bigint_mod2(t, ph, pl, m);
        }
      }
      l--;
      s = 31;
    }
  }
  bigint_set(a, t);
}

/* a = b^e */
void bigint_powi(bigint a, int32_t b, uint32_t e)
{
  uint32_t i;
  bigint_seti(a, 1);
  for (i=0; i<e; i++)
    bigint_muli(a, a, b);
}

/* Computes a[nxn] = b[nxn]^(-1) in Z/mZ */
int bigint_matrix_inverse(bigint *a, bigint *b, bigint m, int n)
{
  int i, j, k;
  bigint tmp, h, l;
  bigint c[64][128];

  memset(c, 0, 64*128*sizeof(bigint));
  for (i=0; i<n; i++)
  {
    for (j=0; j<n; j++)
      bigint_set(c[i][j], b[i*n+j]);
    bigint_seti(c[i][i+n], 1);
  }

  for (j=0; j<n; j++)
  {
    /* Find pivot in j-th column */
    for (i=j; i<n; i++)
    {
      bigint_gcd(tmp, c[i][j], m);
      if (!bigint_cmpi(tmp, 1)) break;
    }
    if (i == n)
      return -1;
    /* Swap i-th and j-th rows */
    for (k=j; k<2*n; k++)
    {
      bigint_set(tmp, c[i][k]);
      bigint_set(c[i][k], c[j][k]);
      bigint_set(c[j][k], tmp);
    }
    /* Multiply j-th row by C(j,j)^(-1) */
    bigint_invmod(tmp, c[j][j], m);
    for (k=j; k<2*n; k++)
    {
      bigint_mul2(h, l, tmp, c[j][k]);
      bigint_mod2(c[j][k], h, l, m);
    }
    /* Eliminate all non-zero entries below (j,j) */
    for (i=j+1; i<n; i++)
    {
      if (!bigint_sgn(c[i][j])) continue;
      for (k=j+1; k<2*n; k++)
      {
        bigint_mul2(h, l, c[i][j], c[j][k]);
        bigint_mod2(tmp, h, l, m);
        bigint_sub(c[i][k], c[i][k], tmp);
        bigint_qr(tmp, c[i][k], c[i][k], m);
      }
      bigint_seti(c[i][j], 0);
    }
  }

  for (j=n-1; j>=0; j--)
  {
    for (i=0; i<j; i++)
    {
      if (!bigint_sgn(c[i][j])) continue;
      for (k=0; k<j-1; k++)
      {
        bigint_mul2(h, l, c[i][j], c[j][k]);
        bigint_mod2(tmp, h, l, m);
        bigint_sub(c[i][k], c[i][k], tmp);
        bigint_qr(tmp, c[i][k], c[i][k], m);
      }
      for (k=n; k<2*n; k++)
      {
        bigint_mul2(h, l, c[i][j], c[j][k]);
        bigint_mod2(tmp, h, l, m);
        bigint_sub(c[i][k], c[i][k], tmp);
        bigint_qr(tmp, c[i][k], c[i][k], m);
      }
      bigint_seti(c[i][j], 0);
    }
  }

  for (i=0; i<n; i++)
    for (j=0; j<n; j++)
      bigint_set(a[i*n+j], c[i][j+n]);

  return 0;
}

