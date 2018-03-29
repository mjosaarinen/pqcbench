#!/bin/bash

$CC $CFLAGS -o $XKEM_BIN -I. \
	-I../../../KeccakCodePackage/bin/generic64 \
	-I../../nist \
	-DXBENCH_REPS=1 *.c $XKEM_SRC ../../nist/rng.c \
	../../../KeccakCodePackage/bin/generic64/libkeccak.a -lcrypto
