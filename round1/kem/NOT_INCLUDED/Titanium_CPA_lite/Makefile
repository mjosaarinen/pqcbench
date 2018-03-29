CC=gcc
CFLAGS=-O3 -march=native -Wall
OBJS=PQCgenKAT_encrypt.o encrypt.o fastrandombytes.o ntt.o pack.o rng.o sampler.o
PROGRAM=titanium

all: $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) $(OBJS) -o $(PROGRAM) -lkeccak -lcrypto

clean:;
	rm -f *.o $(PROGRAM)

