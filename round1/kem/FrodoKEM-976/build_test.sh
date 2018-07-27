#!/bin/bash

$CC $CFLAGS -o $XKEM_BIN \
	-D_OPTIMIZED_GENERIC_ \
	-D_AMD64_ -D_AES128_FOR_A_\
	-DUSING_OPENSSL=_USE_OPENSSL_\
	-DUSE_GENERATION_A=_AES128_FOR_A_\
	-I. -I../../nist \
	../../nist/rng.c $XKEM_SRC *.c -lcrypto
