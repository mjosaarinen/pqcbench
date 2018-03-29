#!/bin/bash

$CC $CFLAGS -o $XKEM_BIN -I. \
	-I../../nist \
	../../nist/rng.c $XKEM_SRC *.c -lcrypto -lgmp
