#ifndef BIGINT_H
#define BIGINT_H

#include <stdint.h>

#define NDIG 12

typedef uint32_t bigint[NDIG];

void bigint_set(bigint a, bigint b);
void bigint_seti(bigint a, int32_t x);
void bigint_add(bigint a, bigint b, bigint c);
void bigint_addi(bigint a, bigint b, int32_t x);
void bigint_sub(bigint a, bigint b, bigint c);
void bigint_subi(bigint a, bigint b, int32_t x);
void bigint_isub(bigint a, int32_t x, bigint b);
int bigint_sgn(bigint a);
int bigint_cmp(bigint b, bigint c);
int bigint_cmpi(bigint b, int32_t x);
void bigint_mul(bigint a, bigint b, bigint c);
void bigint_muli(bigint a, bigint b, int32_t x);
void bigint_qr(bigint q, bigint r, bigint x, bigint y);
int32_t bigint_divi(bigint a, bigint b, int32_t x);
void bigint_print(bigint a, int base);
void bigint_parse(bigint a, const char *s, int base);
void bigint_mul2(bigint ah, bigint al, bigint b, bigint c);
void bigint_mod2(bigint r, bigint xh, bigint xl, bigint y);
void bigint_gcd(bigint a, bigint b, bigint c);
void bigint_extgcd(bigint a, bigint x, bigint y, bigint b, bigint c);
void bigint_invmod(bigint a, bigint b, bigint m);
void bigint_powmod(bigint a, bigint b, bigint e, bigint m);
void bigint_powi(bigint a, int32_t b, uint32_t e);
int bigint_matrix_inverse(bigint *a, bigint *b, bigint m, int n);

#endif

