SHELL = /bin/sh
RM=/bin/rm -f
CXX=g++

PROGNAME=a.out

INCLUDES = -I.

LIBS= -lntl -lgmp -lssl -lcrypto

DEFINES=$(INCLUDES) $(DEFS)

XFLAGS = -Ofast -march=native

SRCS = kem.c ../KAT/rng.c ../KAT/PQCgenKAT_kem.c

OBJNAMES = $(SRCS:.cpp=.o)

X_EXE = $(PROGNAME)

all: $(X_EXE)

%.o: %.cpp
	$(CXX) $(XFLAGS) $(DEFINES) -o$@ -c $<

$(X_EXE): $(OBJNAMES)
	$(CXX) $(XFLAGS) $(DEFINES) -o $@ $(OBJNAMES) $(LIBS)

clean:
	$(RM) *.o ../KAT/*.o $(PROGNAME) *.req *.rsp
