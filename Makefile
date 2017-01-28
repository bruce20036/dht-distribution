all:dht_main

CC = gcc
CFLAGS = -g -Wall -std=c99
LDLIBS = -lcrypto

dht_main:dht_main.o dht.o

dht.o: dht.h
	$(CC) -c dht.c $(CFLAGS) 

clean:
	-rm -f dht_main dht_main.o dht.id dht.o *.txt *~ core
