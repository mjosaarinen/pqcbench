CC = gcc

CFLAGS=-O3 -fomit-frame-pointer -msse2avx -mavx2 -march=native -std=c99

all :
	$(CC) $(CFLAGS) -c Lizard.c main.c randombytes.c sha512.c 
	$(CC) $(CFLAGS) -o Lizard Lizard.o main.o randombytes.o sha512.o -lkeccak
	
run : all
	./Lizard

clean :
	rm -f *.o
	rm -f Lizard

new :
	make clean
	make all
	./Lizard
