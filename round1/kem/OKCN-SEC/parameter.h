#ifndef PARAMETER_H
#define PARAMETER_H

#include <inttypes.h>
#define PERTURBATION 0


#define CLK_TCK CLOCKS_PER_SEC

#define LOG2N		10
#define RLWE_N 		1024
#define RLWE_Q		12289
#define	RLWE_ETA	12
#define	RLWE_G		4
#define	RLWE_T		2
#define	RLWE_M		2
#define	LOG2M		1
#define LOG2G		2


#define LOG2R_IN_REDC			15	
#define R_IN_REDC				32768
#define QPRIME_IN_REDC			12287

#define K_IN_BUTTERFLY			16

#define ModQ(x)			(((x)>=RLWE_Q)?((x)-RLWE_Q):(x))
#define Mod2Q(x)		(((x)>=2*RLWE_Q)?((x)-2*RLWE_Q):(x))


#define SEC_n				4
#define SEC_N				16
#define	SEC_BLOCK_SIZE		(SEC_n+SEC_N)	// = 20
#define	SEC_BLOCK_NUMBER	(RLWE_N/SEC_BLOCK_SIZE)	// = 51
#define SEC_SIGNIFICANT_BITS	(SEC_BLOCK_NUMBER*(SEC_N-1))	//51*15
#define SEC_CODE_BYTES		((1+SEC_n)*7)	// = 35
#define SEC_PADDING_OF_BLOCK_NUMBER	(8-(SEC_BLOCK_NUMBER%8))	// = 5
#define	SEC_PADDING_OF_SIGNIFICANT_BITS	(8-(SEC_SIGNIFICANT_BITS%8))	// =3


#define compress_sec_code(sec_x)	((((((sec_x) & 0x80000)>>19)<<4) ^ ((sec_x) & 0xF)) & 0x1F)	// 15bits -> 5bits
#define decompress_sec_code(sec_x)	((((((sec_x) & 0x10)>>4)<<19) ^ ((sec_x) & 0x0F)) & 0xFFFFF)	// 5bits -> 15bits



#define UNIFORM_POLY_SEED_BYTES				32
#define SMALL_POLY_SEED_BYTES				31
#define	UNIFORM_POLY_SEED_EXPAND_BYTES		512
#define	SMALL_POLY_SEED_EXPAND_BYTES		768

// 1+ceiling(log2(q)) - t
#define	UNIT_BYTES_IN_TRUNCATED_POLY	13	
#define	UNIT_BYTES_IN_SMALL_POLY		5	// ...
#define	UNIT_BYTES_IN_KEY				LOG2M
#define	UNIT_BYTES_IN_SIGNAL			LOG2G

#define TRUNCATED_POLY_BYTES	((RLWE_N/8) * UNIT_BYTES_IN_TRUNCATED_POLY)
#define SMALL_POLY_BYTES		((RLWE_N/8) * UNIT_BYTES_IN_SMALL_POLY)
#define KEY_BYTES				((RLWE_N/8) * UNIT_BYTES_IN_KEY)
#define SIGNAL_BYTES			((RLWE_N/8) * UNIT_BYTES_IN_SIGNAL)

#define RLWE_BASE_FOR_SMALL_POLY		15     

#define CON_ERROR_BYTES		(RLWE_N/8)

#define PUBLICKEY_BYTES				(TRUNCATED_POLY_BYTES + UNIFORM_POLY_SEED_BYTES)
#define SECRETKEY_BYTES				(TRUNCATED_POLY_BYTES)
#define	CIPHERTEXT_BYTES			(TRUNCATED_POLY_BYTES + SIGNAL_BYTES + SEC_CODE_BYTES)


#endif
