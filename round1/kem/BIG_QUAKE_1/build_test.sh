#!/bin/bash

gcc -g -o $XKEM_BIN -I. \
	-I../../nist \
	-DXBENCH_REPS=5 ../../nist/rng.c $XKEM_SRC *.c -lcrypto
