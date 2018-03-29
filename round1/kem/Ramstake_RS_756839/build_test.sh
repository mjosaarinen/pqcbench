#!/bin/bash

$CC $CFLAGS -o $XKEM_BIN -DXBENCH_REPS=1 -I. \
	-I../../../KeccakCodePackage/bin/generic64 \
	-I../../nist \
	../../nist/rng.c $XKEM_SRC *.c \
	../../../KeccakCodePackage/bin/generic64/libkeccak.a -lgmp -lcrypto
