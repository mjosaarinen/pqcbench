CC = gcc

ifndef PARAM # set the default parameter set
	#PARAM = -DLIGHT_I
	PARAM = -DMODER_I
	#PARAM = -DPARAN_I
endif

ifndef ALGOR # set the default algorithm set
  #ALGOR = -DLEPTON_CPA
	ALGOR = -DLEPTON_CCA
endif

ifndef INC # set the default path to openssl
INC = -I/usr/local/include
endif

ifndef LIB # set the default path to openssl
LIB = -L/usr/local/lib
endif

CFLAGS +=  -g -Wall -std=c99 -Wextra -O3 -fomit-frame-pointer -march=native -DNDEBUG
CFLAGS += $(PARAM)
CFLAGS += $(ALGOR)

LPNOBJECTS = \
  rng.o\
	fips202.o\
	poly.o\
	bch_codec.o\
  lepton_ow.o\
  lepton_kem.o\
  lepton_kex.o\
  
KATOBJECTS = \
  rng.o\
	fips202.o\
	poly.o\
	bch_codec.o\
  lepton_ow.o\
  lepton_kem.o\
  lepton_kex.o\

all: kem_test kem_kat


bch.o: ./bch.c  ./bch.h
	$(CC) -o bch.o -c ./bch.c $(CFLAGS)

fips202.o: ./fips202.c ./fips202.h
	$(CC) -o fips202.o -c ./fips202.c $(CFLAGS)
	
poly.o: ./poly.c ./poly.h ./fips202.h ./params.h
	$(CC) -o poly.o -c ./poly.c $(CFLAGS)

bch_codec.o: ./bch_codec.c ./bch_codec.h
	$(CC) -o bch_codec.o -c ./bch_codec.c $(CFLAGS)
		
lepton_ow.o: ./lepton_ow.c ./lepton_ow.h ./bch_codec.h ./poly.h ./params.h
	$(CC) -o lepton_ow.o -c ./lepton_ow.c $(CFLAGS)
	
lepton_kem.o: ./lepton_kem.c ./lepton_kem.h ./lepton_ow.h
	$(CC) -o lepton_kem.o -c ./lepton_kem.c $(CFLAGS)

lepton_kex.o: ./lepton_kex.c ./lepton_kex.h ./lepton_ow.h
	$(CC) -o lepton_kex.o -c ./lepton_kex.c $(CFLAGS)

rng.o: ./rng.c ./rng.h
	$(CC) -o rng.o -c ./rng.c $(CFLAGS)

kem_test: ./test.c ./rng.h $(LPNOBJECTS)
	@echo "building..."
	$(CC) -o kem_test $(LPNOBJECTS) test.c $(INC) $(LIB) $(CFLAGS) -lcrypto

kem_kat: ./PQCgenKAT_kem.c ./api.h ./rng.h $(KATOBJECTS)
	@echo "building..."
	$(CC) -o kem_kat $(KATOBJECTS) PQCgenKAT_kem.c $(INC) $(LIB) $(CFLAGS) -lcrypto


.PHONY: test kat clean

test: 
	@echo "test..."
	./kem_test
	
kat: 
	@echo "generate kat..."
	./kem_kat	

clean:
	@echo "cleaning..."
	rm *.o
	rm ./kem_test
	rm ./kem_kat
