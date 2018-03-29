#!/bin/bash

$CC $CFLAGS -DXBENCH_REPS=1 -DXBENCH_NOTEST \
	-o $XKEM_BIN -I. \
	-I../../../KeccakCodePackage/bin/generic64 \
	-I../../nist \
	../../nist/rng.c -DXBENCH_REPS=1 $XKEM_SRC *.c \
	../../../KeccakCodePackage/bin/generic64/libkeccak.a -lcrypto
