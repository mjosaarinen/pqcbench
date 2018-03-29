#ifndef PARAMETER_H
#define PARAMETER_H

#include <stdint.h>

#define CLK_TCK CLOCKS_PER_SEC

#define LOG2N		8
#define MLWE_N		256
#define MLWE_Q		7681
#define MLWE_ETA	2
#define MLWE_G		32
#define MLWE_T		4
#define MLWE_ELL	3
#define MLWE_M		2
#define MLWE_QPRIME 15362  		// = lcm(q,m)
#define MLWE_ALPHA	2			// = q_prime/q
#define MLWE_BETA	7681		// = q_prime/m


#define LOG2R_IN_REDC			18			/* used in REDC algorithm */
#define MLWE_R_IN_REDC			262144		/* used in REDC algorithm */
#define QPRIME_IN_REDC			7679
#define K_IN_BARRETT_REDUCE		18			/* used in Barrett_reduce algorithm */
#define M_IN_BARRETT_REDUCE		34			/* m should be floor(2^k/q) */


#define K_IN_BUTTERFLY			16


#define	Z_SEED_BYTES		32
#define	MATRIX_SEED_BYTES	32
#define	NOISE_SEED_BYTES	31

#define	MATRIX_SEED_EXPAND_BYTES	128         //	/*the length after expanding */
#define NOISE_SEED_EXPAND_BYTES 128


#define MLWE_BASE_FOR_SMALL_POLY       4

/* 1+ceiling(log2(q)) - g */
#define UNIT_BYTES_IN_TRUNCATED_POLY	10
#define UNIT_BYTES_IN_SMALL_POLY		3
#define UNIT_BYTES_IN_KEY				1
#define UNIT_BYTES_IN_SIGNAL			5


#define TRUNCATED_POLY_BYTES	((MLWE_N/8) * UNIT_BYTES_IN_TRUNCATED_POLY)
#define SMALL_POLY_BYTES		((MLWE_N/8) * UNIT_BYTES_IN_SMALL_POLY)
#define KEY_BYTES				((MLWE_N/8) * UNIT_BYTES_IN_KEY)
#define SIGNAL_BYTES			((MLWE_N/8) * UNIT_BYTES_IN_SIGNAL)

#define CIPHERTEXT_BYTES		((TRUNCATED_POLY_BYTES * MLWE_ELL) + SIGNAL_BYTES)
#define SECRETKEY_BYTES			(SMALL_POLY_BYTES * MLWE_ELL)
#define PUBLICKEY_BYTES			(MATRIX_SEED_BYTES + (TRUNCATED_POLY_BYTES * MLWE_ELL))

#define ModQ(x)			(((x)>=MLWE_Q)?((x)-MLWE_Q):(x))
#define Mod2Q(x)		(((x)>=2*MLWE_Q)?((x)-2*MLWE_Q):(x))

#endif
