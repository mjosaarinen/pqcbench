# Project: shrivastava
# Makefile created by ouzdeville
CC       = gcc
OBJ      = gf.o poly.o matrix.o fichier.o key_gen.o encapsulation.o decapsulation.o util.o decoding.o kem.o rng.o PQCgenKAT_kem.o  
LINKOBJ  = gf.o poly.o matrix.o fichier.o key_gen.o encapsulation.o decapsulation.o util.o decoding.o kem.o rng.o PQCgenKAT_kem.o
LIBS     = -L/usr/lib -L. -lssl -lcrypto -lkeccak
INCS     = 
CXXINCS  = 
BIN      = PQCgenKAT_kem
LFLAGS=
CFLAGS=-march=native -mtune=native -c -Wall -I. 
RM       = rm -f

.PHONY: all all-before all-after clean clean-custom

all: all-before $(BIN) all-after

clean: clean-custom
	${RM} $(OBJ) $(BIN)

$(BIN): $(OBJ)
	$(CC) -O3 -march=native -mtune=native $(LINKOBJ) -o $(BIN) $(LIBS)

gf.o: gf.c
	$(CC) -c gf.c -o gf.o $(CFLAGS)

key_gen.o: key_gen.c
	$(CC) -c key_gen.c -o key_gen.o $(CFLAGS)

util.o: util.c
	$(CC) -c util.c -o util.o $(CFLAGS)

encapsulation.o: encapsulation.c
	$(CC) -c encapsulation.c -o encapsulation.o $(CFLAGS)

decapsulation.o: decapsulation.c
	$(CC) -c decapsulation.c -o decapsulation.o $(CFLAGS)

kem.o: kem.c
	$(CC) -c kem.c -o kem.o $(CFLAGS)

rng.o: rng.c
	$(CC) -c rng.c -o rng.o $(CFLAGS)

matrix.o: matrix.c
	$(CC) -c matrix.c -o matrix.o $(CFLAGS)

fichier.o: fichier.c
	$(CC) -c fichier.c -o fichier.o $(CFLAGS)

poly.o: poly.c
	$(CC) -c poly.c -o poly.o $(CFLAGS)

decoding.o: decoding.c
	$(CC) -c decoding.c -o decoding.o $(CFLAGS)

PQCgenKAT_kem.o: PQCgenKAT_kem.c
	$(CC) -c PQCgenKAT_kem.c -o PQCgenKAT_kem.o $(CFLAGS)

