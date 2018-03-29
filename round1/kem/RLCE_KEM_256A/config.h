/* config.h
 * Code was written: June 1, 2017
 * Copyright (C) 2017 Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 */
#ifndef _CONFIGH_
#define _CONFIGH_

#define DECODINGMETHOD 1 /* 0:include S; 1: W^{-1}; 2: no help matrix  */
/* FOLLOWING PARAMETER HAS BEEN OPTIMIZED FOR 64-BIT CPUS.                 *
 * DO NOT CHANGE UNLESS YOU ARE USING 32-BITS OR 16-BITS CPUS              */
#define GFMULTAB 1        /* 0: No Mul-TABLE; 1: GF multiplication-table   */
#define DRBG 0            /* 0: SHA512_DRBBG; 1: CTR-AES DRBBG; 2:MGF512   */
#define DECODER 0         /* 0: BM-decoder, 1: Euclidean Decoder           */
#define ROOTFINDING 0     /* 0: Chien; 1: Exhaustive; 2: BAT; 3: FFT       */
#define KARATSUBA 1       /* 0: standard poly-mul; 1: karatsuba; 2: FFT    */
#define WINOGRADVEC 0     /* 0: standard; 1: winograd vec*matrix multi     */
#define MATRIXMUL 0       /* 0: standard mat*mat; 1: strassen; 2: Winograd */
#define MATINV 0          /* 0: standard mat-inv; 1: strassen              */
#define STRASSENCONST 750 /* mat-dim below this use standard multi.        */
#define STRAINVCONST 500  /* mat-dim below this use standard inverse       */
#define PARASIZE 20       /* plese do not change!!!!!                      */
#endif 
