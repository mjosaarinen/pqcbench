


CFLAGS    = -g -Wall  -O3  
 


all: akcn-mlwe   

SOURCES =   kem.c polynomial.c  reduce.c io.c akcn.c vector.c
HEADERS =   polynomial.h  parameter.h  reduce.h  io.h akcn.h vector.h

akcn-mlwe: $(SOURCES) $(HEADERS)   akcn-mlwe.c rng.c rng.h
	gcc $(CFLAGS) -o $@ $(SOURCES) rng.c akcn-mlwe.c -lcrypto


PQCgenKAT_kem: $(SOURCES) $(HEADERS)  PQCgenKAT_kem.c rng.c rng.h
	$(CC) $(CFLAGS) -o $@ $(SOURCES) -I. rng.c PQCgenKAT_kem.c -lcrypto


akcn-mlwe-KATgen: $(SOURCES) $(HEADERS)  akcn-mlwe-KATgen.c rng.c rng.h
	$(CC) $(CFLAGS) -o $@ $(SOURCES) -I. rng.c akcn-mlwe-KATgen.c -lcrypto



akcn-mlwe-intermediate-gen: $(SOURCES) $(HEADERS)  akcn-mlwe-intermediate-gen.c rng.c rng.h
	$(CC) $(CFLAGS) -o $@ $(SOURCES) -I. rng.c akcn-mlwe-intermediate-gen.c -lcrypto


speed: $(SOURCES) $(HEADERS)  speed.c  rng.c rng.h
	$(CC) $(CFLAGS) -o $@ $(SOURCES) rng.c   speed.c -lcrypto



	
.PHONY: clean test

test: 
	.akcn-mlwe

clean:
	-$(RM) *.o
	-$(RM) -r akcn-mlwe
	
