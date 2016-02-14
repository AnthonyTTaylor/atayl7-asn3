CC      = gcc
CFLAGS  = -g -O0 -Wall -std=gnu11 -lz
LDFLAGS = -L.

.PHONY : all test clean

all: client

libhdb.a: hdb.o
	ar rcs libhdb.a hdb.o

hdb.o: hdb.c hdb.h
	$(CC) $(CFLAGS) -o $@ -c $<

testlibhdb: libhdb.a testlibhdb.o
	$(CC) -o $@ $^ $(LDFLAGS) -lhdb -lcheck -lhiredis -lm -lpthread -lrt -lz

testlibhdb.o: testlibhdb.c hdb.h
	$(CC) $(CFLAGS) -o $@ -c $<

test: testlibhdb
	./testlibhdb

client: udp_sockets.o udp_client.o
	$(CC) -D_GNU_SOURCE $(CFLAGS) client.c -o $@ $^ -lhmdp -lhdb -lhfs

udp_sockets.o: ../common/udp_sockets.c ../common/udp_sockets.h
			$(CC) $(CFLAGS) -o $@ -c $<

udp_client.o: ../common/udp_client.c ../common/udp_client.h ../common/udp_sockets.h
			$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f *.o *.a client
