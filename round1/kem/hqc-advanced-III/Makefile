
CC:=gcc
CFLAGS:=-O3 -std=c99 -pedantic

HASH_SRC:=lib/hash/hash.c
HASH_INCLUDE:=-I lib/hash -lcrypto

RNG_SRC:=lib/rng/rng.c
RNG_INCLUDE:=-I lib/rng
 
SRC:=src/
INCLUDE:=-I src/
LIB:=$(HASH_INCLUDE) $(RNG_INCLUDE)

MAIN_HQC:=src/main_hqc.c
MAIN_KAT:=src/main_kat.c

HQC_OBJS:=vector.o repetition.o bch.o tensor.o parsing.o hqc.o kem.o
HQC_OBJS_VERBOSE:=vector.o repetition.o bch-verbose.o tensor-verbose.o parsing.o hqc-verbose.o kem-verbose.o 
LIB_OBJS:= hash.o rng.o

BIN:=bin
BUILD:=bin/build


folders:
	@echo -e "\n### Creating folders\n"
	mkdir -p $(BUILD)

hash.o: folders
	@echo -e "\n### Compiling $@ (wrapper around openssl SHA512 implementation)\n"	
	$(CC) $(CFLAGS) -c $(HASH_SRC) $(HASH_INCLUDE) -o $(BUILD)/$@

rng.o: folders
	@echo -e "\n### Compiling NIST rng.o\n"	
	$(CC) -O3 -c $(RNG_SRC) $(RNG_INCLUDE) -o $(BUILD)/$@



%.o: $(SRC)/%.c | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(CFLAGS) -c $< $(INCLUDE) $(LIB) -o $(BUILD)/$@ 

%-verbose.o: $(SRC)/%.c | folders
	@echo -e "\n### Compiling $@ (verbose mode)\n"
	$(CC) $(CFLAGS) -c $< $(INCLUDE) $(LIB) -D VERBOSE -o $(BUILD)/$@



hqc-advanced-III: $(HQC_OBJS) $(LIB_OBJS)
	@echo -e "\n### Compiling HQC-advanced-III\n"	
	$(CC) $(CFLAGS) $(MAIN_HQC) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@ 

hqc-advanced-III-kat: $(HQC_OBJS) $(LIB_OBJS)
	@echo -e "\n### Compiling HQC-advanced-III KAT\n"	
	$(CC) $(CFLAGS) $(MAIN_KAT) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@

hqc-advanced-III-verbose: $(HQC_OBJS_VERBOSE) $(LIB_OBJS)
	@echo -e "\n### Compiling HQC-advanced-III (verbose mode)\n"	
	$(CC) $(CFLAGS) $(MAIN_HQC) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -D VERBOSE -o $(BIN)/$@ 



clean:
	rm -f PQCkemKAT_*
	rm -f vgcore.*
	rm -rf ./bin

