


CFLAGS    = -g -Wall  -O3  
 


all: akcn-sec   

SOURCES =   kem.c polynomial.c  reduce.c io.c akcn.c sec.c
HEADERS =   polynomial.h  parameter.h  reduce.h  io.h akcn.h sec.h

akcn-sec: $(SOURCES) $(HEADERS)   akcn-sec.c rng.c rng.h
	gcc $(CFLAGS) -o $@ $(SOURCES) rng.c akcn-sec.c -lcrypto


PQCgenKAT_kem: $(SOURCES) $(HEADERS)  PQCgenKAT_kem.c rng.c rng.h
	$(CC) $(CFLAGS) -o $@ $(SOURCES) -I. rng.c PQCgenKAT_kem.c -lcrypto


speed: $(SOURCES) $(HEADERS)  speed.c  rng.c rng.h
	$(CC) $(CFLAGS) -o $@ $(SOURCES) rng.c   speed.c -lcrypto


akcn-sec-KATgen: $(SOURCES) $(HEADERS)  akcn-sec-KATgen.c rng.c rng.h
	$(CC) $(CFLAGS) -o $@ $(SOURCES) -I. rng.c akcn-sec-KATgen.c -lcrypto


	
.PHONY: clean test

test: 
	.akcn-sec

clean:
	-$(RM) *.o
	-$(RM) -r akcn-sec
	
