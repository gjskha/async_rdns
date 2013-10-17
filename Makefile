CC=gcc
CFLAGS=-lfiredns -lfirestring
ILIB=/usr/include

all: 
	$(CC) -o firelookup rdns.c -I$(ILIB) $(CFLAGS)

clean:
	rm firelookup
