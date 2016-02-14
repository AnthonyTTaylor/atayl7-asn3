CC      = gcc
CFLAGS  = -g -O0 -Wall  -std=gnu11 -lz
LDFLAGS = -L.

.PHONY : all test clean

all: hftpd

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

client: client.c
	$(CC)  $(CFLAGS) -o $@ client.c -lz

hftpd: hftpd.c udp_sockets.o udp_server.o
	$(CC) -D_GNU_SOURCE $(CFLAGS) -o $@ $^ -lhdb

udp_sockets.o: ../common/udp_sockets.c ../common/udp_sockets.h
		$(CC) $(CFLAGS) -o $@ -c $<

udp_server.o: ../common/udp_server.c ../common/udp_server.h ../common/udp_sockets.h
		$(CC) $(CFLAGS) -o $@ -c $<

clean:
	rm -f *.o *.a hftpd
