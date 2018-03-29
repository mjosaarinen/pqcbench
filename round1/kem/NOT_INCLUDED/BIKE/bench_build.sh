#!/bin/bash

gcc -Ofast -o xkem_bench -I. \
	-I../../nist \
	../../nist/rng.c ../xkem_bench.c *.c *.cpp -lcrypto
