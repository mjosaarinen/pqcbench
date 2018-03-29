#!/bin/bash

$CC $CFLAGS -DXBENCH_REPS=1 -DXBENCH_NOTEST \
	-o $XKEM_BIN -I. \
	-I../../../KeccakCodePackage/bin/generic64 \
	-I../../nist \
	-DXBENCH_REPS=1 ../../nist/rng.c $XKEM_SRC *.c \
	../../../KeccakCodePackage/bin/generic64/libkeccak.a -lcrypto
