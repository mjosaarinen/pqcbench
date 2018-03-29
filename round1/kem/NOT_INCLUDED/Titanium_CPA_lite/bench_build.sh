#!/bin/bash

gcc -Ofast -o xkem_bench -I. \
	-I../../../KeccakCodePackage/bin/generic64 \
	-I../../nist \
	../../nist/rng.c ../xkem_bench.c *.c \
	../../../KeccakCodePackage/bin/generic64/libkeccak.a -lcrypto
