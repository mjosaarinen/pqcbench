all: dme.o kat

dme.o: dme.c dme.h rng.h api.h setup
	gcc -c dme.c -I./setup -Wall -Wextra -std=c99 -O3

rng.o: rng.h
	gcc -c rng.c

PQCgenKAT_kem.o: PQCgenKAT_kem.c rng.h api.h
	gcc -c PQCgenKAT_kem.c

PQCgenKAT_kem: PQCgenKAT_kem.o dme.o rng.o
	gcc -o PQCgenKAT_kem PQCgenKAT_kem.o dme.o rng.o -Wall -Wextra -O3 -lcrypto

setup:
	make -C ./setup

kat: PQCgenKAT_kem
	./PQCgenKAT_kem

clean:
	make -C ./setup clean
	rm -f dme.o rng.o PQCgenKAT_kem.o PQCgenKAT_kem
	rm -f PQCkemKAT_288.req PQCkemKAT_288.rsp

.PHONY: clean setup kat

