CC=/usr/bin/gcc
LDFLAGS=-lcrypto

SOURCES = cbd.c fips202.c ntrukem.c owcpa.c poly.c verify.c PQCgenKAT_kem.c rng.c
HEADERS = api.h cbd.h owcpa.h params.h poly.h rng.h verify.h rng.h

PQCgenKAT_kem: $(HEADERS) $(SOURCES)
	$(CC) -o $@ $(SOURCES) $(LDFLAGS)

.PHONY: clean

clean:
	-rm PQCgenKAT_kem

