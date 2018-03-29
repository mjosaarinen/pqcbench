#!/bin/bash

$CC $CFLAGS -o $XKEM_BIN -I. \
	-I../../nist -I../../../include \
	../../nist/rng.c $XKEM_SRC *.c ../../../libcrypto.a
