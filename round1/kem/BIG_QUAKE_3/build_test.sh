#!/bin/bash

$CC $CFLAGS -DXBENCH_REPS=1 -o $XKEM_BIN -I. \
	-I../../nist \
	-DXBENCH_REPS=1 ../../nist/rng.c $XKEM_SRC *.c -lcrypto
