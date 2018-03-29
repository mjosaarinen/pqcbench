LOCAL="/usr/local"
#LOCAL=/home/oliverafa/Documents/Programs/local/

HEAD=$(wildcard include/*.h*)
SRC=$(wildcard src/*.c*)
OBJS=$(SRC:.c*=.o)

CC=gcc
LDFLAGS=-lcrypto -ldl -lpthread
CFLAGS=-ansi -Wall -O4 -I include/ -I $(LOCAL)/include -L $(LOCAL)/lib

all : PQCgenKAT_kem


PQCgenKAT_kem : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
%.o : %.c*
	$(CC) $(CFLAGS) -o $@ -c $<


clean:
	rm -f PQCgenKAT_kem
