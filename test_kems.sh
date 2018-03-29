#!/bin/bash

if [ "$#" -ne 2 ]; then
	echo "Usage: test_kem.sh <kem implementation list file> <output report file>"
    exit
fi

export CC='gcc'
export CFLAGS='-Ofast'
export XKEM_BIN='./xkem_test'
export XKEM_SRC='../../../src/kem_test.c'

for x in `cat $1 | tr '\n' ' '` 
do
	kem=`basename $x`
	base_dir=`pwd`
	echo -n "== $kem ==  "
	date
	cd $x
	rm -f $XKEM_BIN build.err
	./build_test.sh 2> build.err
	$XKEM_BIN | tee /dev/tty >> $base_dir/$2
	rm -f $XKEM_BIN
	cd $base_dir
done

