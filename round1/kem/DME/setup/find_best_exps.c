#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "bigint.h"

bigint G1[3][3], G1_inverse[3][3];
bigint G2[2][2], G2_inverse[2][2];
bigint EXPS1[64][6], EXPS2[64][6];

int init_constants(int E11, int E12, int E21, int E23, int E32, int E33,
                    int F11, int F12, int F21, int F22)
{
  int i, j, k;
  bigint ROW1[8][6], ROW2[8][6], tmp1, tmp2, q1m1, q2m1, q3m1;
  /* G1 */
  if (E11 < 0 || E12 < 0 || E21 < 0 || E23 < 0 || E32 < 0 || E33 < 0) exit(-1);
  bigint_powi(G1[0][0], 2, E11 % 96);
  bigint_powi(G1[0][1], 2, E12 % 96);
  bigint_seti(G1[0][2], 0);
  bigint_powi(G1[1][0], 2, E21 % 96);
  bigint_seti(G1[1][1], 0);
  bigint_powi(G1[1][2], 2, E23 % 96);
  bigint_seti(G1[2][0], 0);
  bigint_powi(G1[2][1], 2, E32 % 96);
  bigint_powi(G1[2][2], 2, E33 % 96);
  /* G1_inverse */
  bigint_powi(q2m1, 2, 96);
  bigint_subi(q2m1, q2m1, 1);
  if (bigint_matrix_inverse(&G1_inverse[0][0], &G1[0][0], q2m1, 3))
    return -1;
  for (i=0; i<3; i++)
    for (j=0; j<3; j++)
      if (bigint_sgn(G1_inverse[i][j]) < 0)
        bigint_add(G1_inverse[i][j], G1_inverse[i][j], q2m1);
  /* G2 */
  if (F11 < 0 || F12 < 0 || F21 < 0 || F22 < 0) exit(-1);
  bigint_powi(G2[0][0], 2, F11 % 144);
  bigint_powi(G2[0][1], 2, F12 % 144);
  bigint_powi(G2[1][0], 2, F21 % 144);
  bigint_powi(G2[1][1], 2, F22 % 144);
  /* G2_inverse */
  bigint_powi(q3m1, 2, 144);
  bigint_subi(q3m1, q3m1, 1);
  if (bigint_matrix_inverse(&G2_inverse[0][0], &G2[0][0], q3m1, 2))
    return -1;
  for (i=0; i<2; i++)
    for (j=0; j<2; j++)
      if (bigint_sgn(G2_inverse[i][j]) < 0)
        bigint_add(G2_inverse[i][j], G2_inverse[i][j], q3m1);
  /* ROW1 */
  memset(ROW1, 0, 8*6*sizeof(bigint));
  bigint_set(ROW1[0][0], G1[0][0]);
  bigint_set(ROW1[1][1], G1[0][0]);
  bigint_set(ROW1[2][0], G1[0][0]);
  bigint_set(ROW1[3][1], G1[0][0]);
  bigint_set(ROW1[0][2], G1[0][1]);
  bigint_set(ROW1[1][2], G1[0][1]);
  bigint_set(ROW1[2][3], G1[0][1]);
  bigint_set(ROW1[3][3], G1[0][1]);
  bigint_set(ROW1[4][0], G1[1][0]);
  bigint_set(ROW1[5][1], G1[1][0]);
  bigint_set(ROW1[6][0], G1[1][0]);
  bigint_set(ROW1[7][1], G1[1][0]);
  bigint_set(ROW1[4][4], G1[1][2]);
  bigint_set(ROW1[5][4], G1[1][2]);
  bigint_set(ROW1[6][5], G1[1][2]);
  bigint_set(ROW1[7][5], G1[1][2]);
  /* ROW2 */
  memset(ROW2, 0, 8*6*sizeof(bigint));
  bigint_set(ROW2[0][0], G1[1][0]);
  bigint_set(ROW2[1][1], G1[1][0]);
  bigint_set(ROW2[2][0], G1[1][0]);
  bigint_set(ROW2[3][1], G1[1][0]);
  bigint_set(ROW2[0][4], G1[1][2]);
  bigint_set(ROW2[1][4], G1[1][2]);
  bigint_set(ROW2[2][5], G1[1][2]);
  bigint_set(ROW2[3][5], G1[1][2]);
  bigint_set(ROW2[4][2], G1[2][1]);
  bigint_set(ROW2[5][3], G1[2][1]);
  bigint_set(ROW2[6][2], G1[2][1]);
  bigint_set(ROW2[7][3], G1[2][1]);
  bigint_set(ROW2[4][4], G1[2][2]);
  bigint_set(ROW2[5][4], G1[2][2]);
  bigint_set(ROW2[6][5], G1[2][2]);
  bigint_set(ROW2[7][5], G1[2][2]);
  /* EXPS1 and EXPS2 */
  bigint_powi(q1m1, 2, 48);
  bigint_subi(q1m1, q1m1, 1);
  for (i=0; i<8; i++)
    for (j=0; j<8; j++)
      for (k=0; k<6; k++)
      {
        bigint_mul(tmp1, G2[0][0], ROW1[i][k]);
        bigint_mul(tmp2, G2[0][1], ROW2[j][k]);
        bigint_add(EXPS1[8*i+j][k], tmp1, tmp2);
        if (bigint_sgn(EXPS1[8*i+j][k]))
        {
          bigint_qr(tmp1, EXPS1[8*i+j][k], EXPS1[8*i+j][k], q1m1);
          if (!bigint_sgn(EXPS1[8*i+j][k]))
            bigint_set(EXPS1[8*i+j][k], q1m1);
        }
        bigint_mul(tmp1, G2[1][0], ROW1[i][k]);
        bigint_mul(tmp2, G2[1][1], ROW2[j][k]);
        bigint_add(EXPS2[8*i+j][k], tmp1, tmp2);
        if (bigint_sgn(EXPS2[8*i+j][k]))
        {
          bigint_qr(tmp1, EXPS2[8*i+j][k], EXPS2[8*i+j][k], q1m1);
          if (!bigint_sgn(EXPS2[8*i+j][k]))
            bigint_set(EXPS2[8*i+j][k], q1m1);
        }
      }
  return 0;
}

int num_bits(bigint a)
{
  int i, j, n;
  n = 0;
  for (i=NDIG-1; i>=0; i--)
    for (j=31; j>=0; j--)
      if ((a[i] >> j) & 1) n++;
  return n;
}

int main(void)
{
  int i, j, k, l, ok;
  int E11, E12, E21, E23, E32, E33, F11, F12, F21, F22, val;
  int best_E11, best_E12, best_E21, best_E23, best_E32, best_E33;
  int best_F11, best_F12, best_F21, best_F22, best;
  bigint base, r;

  best_E11 = best_E12 = best_E21 = best_E23 =  best_E32 = best_E33 = 0;
  best_F11 = best_F12 = best_F21 = best_F22 = 0;
  best = 0;
  for (i=0; i<100000; i++)
  {
    E11 = rand() % 96;
    E12 = rand() % 96;
    E21 = rand() % 96;
    E23 = rand() % 96;
    E32 = rand() % 96;
    E33 = rand() % 96;
    F11 = rand() % 144;
    F12 = rand() % 144;
    F21 = rand() % 144;
    F22 = rand() % 144;
    val = init_constants(E11, E12, E21, E23, E32, E33, F11, F12, F21, F22);
    if (val == -1) continue;
    ok = 1;
    for (j=0; j<64 && ok; j++)
    {
      for (k=j+1; k<64; k++)
      {
        for (l=0; l<6; l++)
          if (bigint_cmp(EXPS1[j][l], EXPS1[k][l])) break;
        if (l == 6) ok = 0;
      }
    }
    if (!ok) continue;
    ok = 1;
    for (j=0; j<64 && ok; j++)
    {
      for (k=j+1; k<64; k++)
      {
        for (l=0; l<6; l++)
          if (bigint_cmp(EXPS2[j][l], EXPS2[k][l])) break;
        if (l == 6) ok = 0;
      }
    }
    if (!ok) continue;
    val = 0;
    for (j=0; j<3; j++)
      for (k=0; k<3; k++)
        val += num_bits(G1_inverse[j][k]);
    for (j=0; j<2; j++)
      for (k=0; k<2; k++)
        val += num_bits(G2_inverse[j][k]);
    if (val > best)
    {
      best = val;
      best_E11 = E11;
      best_E12 = E12;
      best_E21 = E21;
      best_E23 = E23;
      best_E32 = E32;
      best_E33 = E33;
      best_F11 = F11;
      best_F12 = F12;
      best_F21 = F21;
      best_F22 = F22;
    }
  }

  printf("const unsigned int E11 = %d;\n", best_E11);
  printf("const unsigned int E12 = %d;\n", best_E12);
  printf("const unsigned int E21 = %d;\n", best_E21);
  printf("const unsigned int E23 = %d;\n", best_E23);
  printf("const unsigned int E32 = %d;\n", best_E32);
  printf("const unsigned int E33 = %d;\n", best_E33);
  printf("const unsigned int F11 = %d;\n", best_F11);
  printf("const unsigned int F12 = %d;\n", best_F12);
  printf("const unsigned int F21 = %d;\n", best_F21);
  printf("const unsigned int F22 = %d;\n", best_F22);
  printf("\n");

  init_constants(best_E11, best_E12, best_E21, best_E23, best_E32, best_E33,
                 best_F11, best_F12, best_F21, best_F22);

  bigint_powi(base, 2, 64);

  printf("const u128 G1[3][3] =\n{\n  ");
  for (i=0; i<3; i++)
  {
    printf("{\n    ");
    for (j=0; j<3; j++)
    {
      printf("{ ");
      printf("UINT64_C(0x");
      bigint_qr(G1[i][j], r, G1[i][j], base);
      bigint_print(r, 16);
      printf("), ");
      printf("UINT64_C(0x");
      bigint_qr(G1[i][j], r, G1[i][j], base);
      bigint_print(r, 16);
      printf(") ");
      printf("}");
      if (j<2) printf(",\n    ");
    }
    printf("\n  }");
    if (i<2) printf(",\n  ");
  }
  printf("\n};\n\n");

  printf("const u128 G1_inverse[3][3] =\n{\n  ");
  for (i=0; i<3; i++)
  {
    printf("{\n    ");
    for (j=0; j<3; j++)
    {
      printf("{ ");
      printf("UINT64_C(0x");
      bigint_qr(G1_inverse[i][j], r, G1_inverse[i][j], base);
      bigint_print(r, 16);
      printf("), ");
      printf("UINT64_C(0x");
      bigint_qr(G1_inverse[i][j], r, G1_inverse[i][j], base);
      bigint_print(r, 16);
      printf(") ");
      printf("}");
      if (j<2) printf(",\n    ");
    }
    printf("\n  }");
    if (i<2) printf(",\n  ");
  }
  printf("\n};\n\n");

  printf("const u192 G2[2][2] =\n{\n  ");
  for (i=0; i<2; i++)
  {
    printf("{\n    ");
    for (j=0; j<2; j++)
    {
      printf("{ ");
      printf("UINT64_C(0x");
      bigint_qr(G2[i][j], r, G2[i][j], base);
      bigint_print(r, 16);
      printf("), ");
      printf("UINT64_C(0x");
      bigint_qr(G2[i][j], r, G2[i][j], base);
      bigint_print(r, 16);
      printf("), ");
      printf("UINT64_C(0x");
      bigint_qr(G2[i][j], r, G2[i][j], base);
      bigint_print(r, 16);
      printf(") ");
      printf("}");
      if (j<1) printf(",\n    ");
    }
    printf("\n  }");
    if (i<1) printf(",\n  ");
  }
  printf("\n};\n\n");

  printf("const u192 G2_inverse[2][2] =\n{\n  ");
  for (i=0; i<2; i++)
  {
    printf("{\n    ");
    for (j=0; j<2; j++)
    {
      printf("{ ");
      printf("UINT64_C(0x");
      bigint_qr(G2_inverse[i][j], r, G2_inverse[i][j], base);
      bigint_print(r, 16);
      printf("), ");
      printf("UINT64_C(0x");
      bigint_qr(G2_inverse[i][j], r, G2_inverse[i][j], base);
      bigint_print(r, 16);
      printf("), ");
      printf("UINT64_C(0x");
      bigint_qr(G2_inverse[i][j], r, G2_inverse[i][j], base);
      bigint_print(r, 16);
      printf(") ");
      printf("}");
      if (j<1) printf(",\n    ");
    }
    printf("\n  }");
    if (i<1) printf(",\n  ");
  }
  printf("\n};\n\n");

  printf("const uint_least64_t EXPS1[64][6] =\n{\n  ");
  for (i=0; i<64; i++)
  {
    printf("{\n    ");
    for (j=0; j<6; j++)
    {
      printf("UINT64_C(0x");
      bigint_print(EXPS1[i][j], 16);
      printf(")");
      if (j<5) printf(",\n    ");
    }
    printf("\n  }");
    if (i<63) printf(",\n  ");
  }
  printf("\n};\n\n");

  printf("const uint_least64_t EXPS2[64][6] =\n{\n  ");
  for (i=0; i<64; i++)
  {
    printf("{\n    ");
    for (j=0; j<6; j++)
    {
      printf("UINT64_C(0x");
      bigint_print(EXPS2[i][j], 16);
      printf(")");
      if (j<5) printf(",\n    ");
    }
    printf("\n  }");
    if (i<63) printf(",\n  ");
  }
  printf("\n};\n\n");

  return 0;
}

