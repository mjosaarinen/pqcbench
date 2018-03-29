CC = gcc

CFLAGS=-O3 -fomit-frame-pointer -msse2avx -mavx2 -march=native -std=c99

all :
	$(CC) $(CFLAGS) -c RLizard.c main.c randombytes.c sha512.c 
	$(CC) $(CFLAGS) -o RLizard RLizard.o main.o randombytes.o sha512.o -lkeccak
	
run : all
	./RLizard

clean :
	rm -f *.o
	rm -f RLizard

new :
	make clean
	make all
	./RLizard
