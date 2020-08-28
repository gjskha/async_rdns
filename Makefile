CC=gcc
CFLAGS=-ludns -g
ILIB=/usr/include

all: 
	$(CC) -o async_rdns async_rdns.c -I$(ILIB) $(CFLAGS)

clean:
	rm async_rdns
