#!/bin/bash

$CC $CFLAGS -o $XKEM_BIN -I. \
	-I../../../KeccakCodePackage/bin/generic64 \
	-I../../nist \
	../../nist/rng.c $XKEM_SRC *.c \
	../../../KeccakCodePackage/bin/generic64/libkeccak.a -lcrypto
