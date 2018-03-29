CC = gcc
OPENSSLDIR = /usr/local/opt/openssl
LIBCRYPTO = $(OPENSSLDIR)/lib/libcrypto.a

MAKELIB = libtool -static -o $@ $^
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	OPENSSLDIR = /usr
    MAKELIB = ar cru $@ $^ && ranlib $@
	CFLAGS += -DLINUX -D_POSIX_C_SOURCE=200112L
	LIBCRYPTO = -lcrypto
	#LIBS += -lbsd
endif

INCLUDES = -I. -Ibit-slice -Inist -I$(OPENSSLDIR)/include
LIBS += $(LIBCRYPTO) -ldl 

CFLAGS += -DNIST_DRBG_AES 
CFLAGS += -O3 -ansi -std=c99 -fomit-frame-pointer -fwrapv -Wpedantic -Wall -Werror $(INCLUDES)

LIBTARGET = lib
BINTARGET = bin

_ODIR = .obj
_ODIRKAT = .objkat
ODIR = lib bin $(_ODIR) $(_ODIRKAT) 

all : $(BINTARGET)/ntskem-13-80-opt-test $(BINTARGET)/ntskem-13-80-opt-kat

default : all

_DEPS = 
DEPS = $(patsubst %,$(INCLUDEDIR)/%,$(_DEPS))

_OBJS = bit-slice/bitslice_bma_64.o bit-slice/bitslice_fft_64.o bit-slice/vector_utils.o \
		ff.o keccak.o kem.o m4r.o matrix_ff2.o nts_kem.o polynomial.o random.o \
		nist/aes_drbg.o 
OBJS = $(patsubst %,$(_ODIR)/%,$(_OBJS))
OBJSKAT = $(patsubst %,$(_ODIRKAT)/%,$(_OBJS))

$(ODIR):
	mkdir -p lib
	mkdir -p bin
	mkdir -p .obj/bit-slice
	mkdir -p .obj/nist
	mkdir -p .objkat/bit-slice
	mkdir -p .objkat/nist

$(_ODIR)/%.o: %.c $(_ODIR) $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $< 

$(_ODIRKAT)/%.o: %.c $(_ODIRKAT) $(DEPS)
	$(CC) $(CFLAGS) -DINTERMEDIATE_VALUES=2 -c -o $@ $< 

$(LIBTARGET)/libntskem-13-80-opt.a: $(OBJS)
	$(MAKELIB)

$(BINTARGET)/ntskem-13-80-opt-test: test/main.c test/ntskem_test.c $(LIBTARGET)/libntskem-13-80-opt.a 
	$(CC) $(CFLAGS) -DNTSKEM_M=13 -DNTSKEM_T=80 -o $@ $(LDFLAGS) $^ $(LIBS) 

$(BINTARGET)/ntskem-13-80-opt-kat: nist/PQCgenKAT_kem.c $(LIBTARGET)/libntskem-13-80-opt.a
	$(CC) $(CFLAGS) -o $@ $(LDFLAGS) $^ $(LIBS)

.PHONY: clean

clean:
	rm -rf $(ODIR)
